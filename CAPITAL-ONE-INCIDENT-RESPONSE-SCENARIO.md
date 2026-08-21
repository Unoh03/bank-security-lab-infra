# Capital One 기반 침해 대응 시나리오

> **상태:** CURRENT DECISION — 2026-08-20 설계로 재정렬
> **대응 의미 정본:** 이 문서
> **구축·검증 Gate:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)
> **최종 촬영:** [`CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md`](./CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md)

이 문서는 공격·탐지·Containment·Investigation·Remediation·Recovery의 의미만
정의한다. Source 존재나 과거 테스트 성공은 현재 Runtime 완료를 뜻하지 않는다.

---

## 1. 최종 시나리오

```text
통제된 DVWA Command Injection
→ Rule 100103 조기 이상 징후
→ CloudTrail 보호 대상 GetObject 성공
→ 엄격한 S3 고신뢰 Rule
→ Shuffle 사전 승인 자동 격리
→ Wazuh Alert 중심 사건 조사
→ 관제자 승인 Remediation·Recovery
→ 동일 공격 실패·정상 기능 성공 확인
```

핵심 경계는 다음 두 Rule의 역할을 섞지 않는 것이다.

| 신호 | 의미 | 자동 조치 |
|---|---|---|
| Rule `100103` | `command.execution + ec2_imds + succeeded` 조기 이상 징후 | 없음. Alert·Evidence만 보존 |
| Rule `100104` (Level 12) | 승인 범위의 `validation/* GetObject` 성공을 정상 흐름과 구분한 고신뢰 침해 확인 | 사전 승인된 좁고 가역적인 격리 |

Rule `100104` (Level 12)를 이번 시나리오의 고신뢰 자동 조치용 ID로 고정한다.
기존 Rule `100100`의 양성 Runtime은 역사적 Evidence로만 보존하며 자동 조치용으로
재사용하지 않는다.

---

## 2. 단계별 대응

### Phase 0 — Preparation

- 새 `TAKE_ID`와 시작 UTC를 발급한다.
- Account·Region·가짜 Object·`validation/*` 범위를 고정한다.
- DVWA는 `low`, Argo CD는 예상 Revision의 `Synced + Healthy` 상태여야 한다.
- Wazuh·Shuffle·5개 로그 Source가 READY여야 한다.
- 이전 TAKE의 Credential·임시 조치·활성 실행이 남아 있으면 공격하지 않는다.
- TAKE_ID는 Evidence Bundle을 묶는 외부 식별자이며 CloudTrail Event 필드라고 주장하지 않는다.
- TAKE_ID는 CloudTrail·Wazuh·Shuffle Payload에 삽입하지 않는다. 단일 만료 전 Active
  TAKE와 Event Time·Account·Region·Role·Bucket·Key가 모호성 없이 일치할 때만 외부
  Evidence Control Metadata로 연결하고, 그렇지 않으면 원본 CloudTrail `eventID`만
  상관·Dedupe 식별자로 사용한다.

### Phase 1 — Early Detection

```text
DVWA 안전 Audit
→ CloudWatch Logs
→ Lambda/SQS/Local Bridge
→ Wazuh Rule 100103
```

Rule `100103`은 IMDS를 겨냥한 명령 실행 성공을 조기에 알린다. 이 시점에는
Credential 획득이나 S3 접근 성공을 확정하지 않으며 자동 격리를 시작하지 않는다.

성공 판단:

- 각 TAKE에서 실제로 발생한 Event N과 Alert N이 같은 `event_id`로 일대일 연결된다.
- 정상 Route·Resource·Result 대조군은 Alert를 만들지 않는다.
- Offline 재수집이 같은 `event_id`의 중복 Alert를 만들지 않는다.

### Phase 2 — High-confidence Confirmation

```text
S3 GetObject
→ CloudTrail Data Event
→ 기존 S3 Archive
→ Wazuh 수집
→ 고신뢰 S3 Rule
```

고신뢰 Rule은 최소한 다음을 함께 확인한다.

- `eventSource=s3.amazonaws.com`
- `eventName=GetObject`
- 승인 Account·Region·Bucket
- `validation/*` 보호 Prefix
- 공격 시나리오에서 예상한 Principal 또는 Role Session
- `errorCode` 없음과 성공 응답
- 정상 Principal Allowlist 불일치

단순 `GetObject` 하나나 Rule `100103`만으로 이 단계를 통과하지 않는다. 공격
Positive와 정상·비대상·실패 Negative Control을 Runtime으로 통과하기 전에는 Shuffle
Write를 연결하지 않는다.

### Phase 3 — Automatic Containment

고신뢰 S3 Alert가 발생한 뒤 Wazuh Integrator가 최소 필드만 인증된 Shuffle Webhook으로
보낸다. Shuffle은 Schema·Account·Rule·Resource Allowlist와 CloudTrail `eventID`
Dedupe를 통과한 경우에만 다음 조치를 한 번 실행한다. Dedupe 10회 Stress는 먼저
side-effect-free 검증으로 Action 1회를 증명한 뒤, exact dispatch만 실제 조치로 승격한다.
GT-04의 Alert→Execution Transport 검증은 외부 Side Effect 0으로 유지하고, 실제 임시
Quarantine과 `validation/*` 제한은 GT-05에서만 실행한다.

1. 고정된 DVWA Workload를 Quarantine한다.
2. 공유 Node Role 전체가 아니라 `validation/*` 추가 접근 또는 사전 승인된 전용
   Principal만 제한한다.
3. Action·Execution·정책 UID/Revision과 Rollback 정보를 보존한다.

자동 조치 금지:

- 공유 Karpenter Node Role 전체 `DenyAll`
- Alert가 제공한 임의 Namespace·Selector·CIDR·Repository 실행
- Alert 원문이나 `full_log`를 Shell Input으로 사용
- IAM 최소 권한·IMDS·Node 교체·애플리케이션 패치를 무승인 실행

자동 격리는 S3 API 호출 순간이 아니라 CloudTrail Event가 Wazuh의 고신뢰 Alert가 된
직후 시작된다고 표현한다.

### Phase 4 — Investigation

고신뢰 S3 Alert를 Seed로 다음 키를 읽어 미리 만든 Wazuh View에서 관련 로그를 좁힌다.

```text
Event Time window
CloudTrail eventID
Principal / Role Session
Source IP
Bucket / Key
URI / Method
Rule ID
```

CloudFront·WAF·ALB·DVWA·CloudTrail을 같은 TAKE의 연속 시간창에서 보여준다. 모든
Source를 관통하는 공통 ID와 Pod→IMDS 직접 네트워크 Event가 없다는 관측 공백도 함께
표시한다. 이 화면은 자동 인과 그래프나 AI 진단이 아니다.

### Phase 5 — Human-approved Remediation and Recovery

자동 격리 뒤 관제자가 Evidence와 Runbook을 보고 다음 조치를 결정·승인한다.

1. DVWA `defaultSecurityLevel: low → impossible` 보안 설정 패치
2. 정확한 GitHub Commit SHA와 Argo CD Revision 배포 확인
3. 동일 공격과 정상 기능 재검증
4. 조건 충족 뒤 임시 격리 해제와 Incident 종료

`low → impossible`은 애플리케이션 Remediation이다. Workload 격리나 Credential
폐기가 아니다.
IAM 최소 권한·IMDSv2·Hop Limit·Node 교체 Apply는 이 촬영 Goal의 범위에서 제외하며,
적용한 것처럼 말하지 않는다. 필요하면 별도 승인된 Future Work로 다룬다.

### Phase 6 — Retest and Closure

완료 조건:

```text
동일 공격: FAIL
기존 공격 문맥의 validation/* 추가 접근: DENIED
정상 로그인·승인 기능: PASS
새 보호 대상 GetObject 성공 Event·Alert: 0
임시 조치 해제 주체·UTC: 기록됨
```

---

## 3. 상태 전이와 중복 방지

```text
UNASSESSED
→ Rule 100103: SUSPECTED
→ 고신뢰 S3 Rule: CONFIRMED
→ Shuffle 격리 성공: CONTAINED
→ Wazuh 조사: INVESTIGATING
→ 사람 승인 조치: REMEDIATING
→ 재검증 통과: RECOVERED / CLOSED
```

- Rule `100103`은 `SUSPECTED`만 만든다.
- 고신뢰 S3 Rule만 자동 Containment를 시작할 수 있다.
- Dedupe Key는 Wazuh Alert ID가 아니라 원본 CloudTrail `eventID`다.
- 같은 `eventID` 재수집은 Timeline을 보강할 수 있지만 조치를 반복하지 않는다.
- 잘못된 Header·Rule·Account·Prefix·Principal은 Incident나 Write를 만들지 않는다.

---

## 4. Containment와 Blast Radius

Workload Quarantine은 고정 Namespace와 Label만 선택한다. NetworkPolicy YAML 존재가
아니라 실제 Egress 차단과 정상 Health·관측 경로 유지를 Runtime으로 증명한다.

Resource/Permission 제한은 `validation/*` 또는 전용 Lab Principal에만 적용한다.
다른 Namespace·Object Prefix·정상 서비스에 영향이 생기면 자동 조치 Gate는 실패다.

모든 자동 조치는 Idempotent하고 Rollback 가능해야 한다. Rollback은 촬영 재시도 편의를
위한 무조건 원복이 아니라, 실패 시 안전 상태로 복구하기 위한 별도 검증 대상이다.

---

## 5. 재촬영 Reset

Reset은 Incident Recovery가 아니라 취약한 Lab을 다시 여는 촬영 전용 역방향 절차다.

1. 실패 TAKE를 `FAILED` 또는 `CLOSED`로 표시하고 Event·Alert·Execution을 보존한다.
2. Quarantine을 유지한 채 `impossible → low` Reset Commit을 배포한다.
3. `validation/*` 임시 Deny 또는 전용 Lab 권한을 승인된 범위로 복원한다.
4. 새 Pod·Argo Revision·Wazuh·Shuffle·로그 Source READY를 확인한다.
5. 이전 Credential과 실행 상태를 제거하고 새 TAKE_ID를 발급한다.
6. Quarantine을 마지막에 해제한다.
7. 새 촬영은 `SC-00`부터 다시 시작한다.

기존 로그·실패 Evidence·Git History는 삭제하지 않는다.

---

## 6. 주장 경계

금지:

```text
Rule 100103으로 S3 침해를 확정했다.
Rule 100103이 자동 격리를 시작했다.
S3 API 호출 순간 즉시 격리했다.
GetObject 하나만 보고 공격으로 판정했다.
Wazuh가 모든 로그의 인과관계를 자동 분석했다.
low → impossible로 Credential을 폐기했다.
```

권장:

```text
Rule 100103은 조기 이상 징후다.
엄격한 보호 대상 S3 성공 접근 Rule이 자동 격리 Trigger다.
고신뢰 Alert 직후 사전 승인된 좁은 격리를 자동 실행했다.
Alert의 시간·Principal·Bucket/Key로 저장된 관련 로그를 좁혀 조사했다.
관제자가 Evidence와 Runbook을 보고 근본 대응을 승인했다.
```

구축·Runtime 완료 판정과 촬영 순서는 `CAPITAL-ONE-SOC-DEMO-PLAN.md`의
`GT-00~GT-10 → GT-11A → Recording → GT-11B`를 따른다. `GT-08` 사용성 Test와
`GT-11A` Rehearsal은 사람이 확인하는 Checkpoint이며 자동 PASS 처리하지 않는다.
