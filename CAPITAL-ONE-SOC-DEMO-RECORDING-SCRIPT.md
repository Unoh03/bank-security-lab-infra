# Capital One SOC 시연 녹화 대본

> **상태:** CURRENT DRAFT — 대응 흐름 확정, 각 장면의 Runtime Gate는 촬영 직전 재검증
>
> **대상:** 프로젝트 평가자·팀원에게 탐지부터 Recovery까지 한 Incident로 설명하는 본편
>
> **대응 의미 정본:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
>
> **촬영 전 Gate:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)
>
> **Interface·상태 계약:** [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](./CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)

이 문서는 무엇을 구현할지 정하는 계획서가 아니다. 이미 Gate를 통과한 기능을 어떤 화면에서
어떤 말로 증명할지 정하는 실제 녹화 대본이다. 대본에 장면이 있다는 사실은 Source 존재나
Runtime 완료를 뜻하지 않는다.

---

## 0. 본편 완료 기준

본편은 다음 한 문장을 실제 Runtime Evidence로 증명해야 한다.

> 통제된 DVWA 침투를 저지연으로 탐지해 Workload와 실습 데이터 접근 영향을 먼저 제한하고,
> 느린 Evidence로 침해를 확인한 뒤 보안 설정 패치와 근본 원인 복구를 배포해 같은 공격은
> 실패하지만 정상 기능은 유지되는 것을 확인했다.

다음 조건을 지키지 못하면 `전체 침해 대응 E2E 완료`라고 제목 붙이지 않는다.

- 한 공격 시나리오의 Source Event·Alert·조치·Commit·Argo Revision이 같은 `TAKE_ID`로 연결됨
- Containment, 침해 확인, Remediation, Recovery를 서로 다른 Evidence로 보여줌
- 계획이나 Source가 아니라 실제 적용 결과를 보여줌
- 재공격 실패 원인이 NetworkPolicy인지 애플리케이션 패치인지 구분됨
- 정상 로그인과 허용 기능이 계속 동작함
- Secret과 실제 개인정보가 화면·음성·자막에 없음

영구 대응 Runtime이 준비되지 않았다면 Scene 7에서 본편을 끝내고 다음 문장을 사용한다.

> 여기까지는 탐지·Containment·조사·애플리케이션 Remediation의 검증 결과입니다.
> IAM·IMDS·Node 영구 복구와 Recovery는 아직 완료로 주장하지 않습니다.

이 경우 영상 제목에도 `Recovery 완료`나 `전체 E2E 완료`를 사용하지 않는다.

---

## 1. 촬영 공통값

촬영 시작 전에 아래 값을 한 곳에 적고 모든 구간에서 같은 값을 사용한다.

```text
FINAL_TAKE_ID=<촬영용 새 TAKE_ID>
START_UTC=<UTC ISO 8601>
BASELINE_DVWA_REVISION=<촬영 전 main SHA>
REMEDIATION_REVISION=<촬영 중 생성될 SHA>
RECOVERY_EVIDENCE=<촬영 중 확정될 Evidence ID 또는 SHA>
```

화면에 항상 전체 값을 노출할 필요는 없지만, 대조 가능한 앞·뒤 일부와 UTC는 남긴다.

공통 화면 규칙:

- AWS Credential, Session Token, Cookie, Authorization Header, Webhook URL·Key, PAT을 숨긴다.
- Account ID, Bucket, Client IP는 공개본 규칙에 맞게 Masking한다.
- Wazuh·AWS·GitHub·Argo 화면의 시간대가 다르면 UTC로 환산한 자막을 붙인다.
- 10분 Poll이나 배포 대기는 편집할 수 있지만, 전환 자막에 실제 경과시간과 같은 TAKE임을 표시한다.
- 서로 다른 TAKE의 장면을 하나의 Incident처럼 이어 붙이지 않는다.
- 실패한 장면을 성공처럼 편집하지 않는다.

---

## 2. 본편 녹화 대본

### Scene 0 — 촬영 Slate와 PREPARED 상태

**화면**

- 제목 Slate
- 새 `TAKE_ID`와 시작 UTC
- DVWA `defaultSecurityLevel=low`
- Wazuh Manager·Indexer·Dashboard READY
- Bridge PID·Heartbeat READY
- Argo CD 현재 Revision `Synced + Healthy`
- 이전 TAKE Credential 환경변수 없음

**운영자 조작**

1. Secret이 가려진 Preflight 결과를 한 화면에 배치한다.
2. `TAKE_ID`, UTC, DVWA Baseline Revision을 천천히 가리킨다.
3. 화면을 3초 이상 고정한다.

**내레이션**

> 지금부터 교육용 DVWA 환경에서 Capital One 침해 과정을 단순화한 SOC 시연을 시작합니다.
> 이 실행에는 새 TAKE ID를 발급했고, DVWA는 의도적으로 취약한 low 상태입니다.
> Wazuh와 빠른 전달 Bridge, Argo CD의 시작 상태를 먼저 확인했습니다.

**필수 Evidence**

- `TAKE_ID`
- 시작 UTC
- `low`
- Wazuh·Bridge READY
- 정확한 Baseline Git SHA와 Argo Revision

**중단 조건**

READY 항목 하나라도 실패하거나 이전 Credential이 남아 있으면 공격하지 않는다.

---

### Scene 1 — 시나리오와 주장 범위

**화면**

- 공격 흐름을 표시한 단순 도식
- `DVWA → IMDS → 임시 Role Credential → validation/* 가짜 데이터` 범위
- 실제 개인정보가 아닌 Lab 데이터 표시

**내레이션**

> 실제 Capital One 사고를 그대로 재현하는 것이 아니라, DVWA Command Injection으로
> IMDS를 조회하고 제한된 가짜 S3 데이터에 접근하는 교육용 각색입니다.
> 빠른 경로는 초기 Containment를 위한 신호이고, 느린 AWS 로그는 성공 여부와 공격 경로를
> 확인하는 조사 Evidence로 사용합니다.

**필수 Evidence**

- Lab 전용 Scope
- `validation/*` 제한
- 실제 SSRF 재현이 아니라는 설명

---

### Scene 2 — 통제된 공격 시나리오 1회

**화면**

- 승인된 공격 Runner
- 같은 `TAKE_ID`가 적용됐다는 표시
- Credential 원문을 제거한 공격 결과

**운영자 조작**

1. 명령과 Target이 승인된 Lab 범위인지 마지막으로 확인한다.
2. 공격 Runner를 한 번 실행한다.
3. 성공·실패 Exit와 Source Event 시각을 보존한다.

**내레이션**

> 공격 시나리오는 한 번 실행합니다. 현재 Runner는 IMDS Role 이름과 임시 Credential을
> 각각 조회하므로 서로 다른 command.execution 감사 Event 두 건이 생깁니다.
> 두 Event는 하나의 Incident이며, 두 번의 침해로 세지 않습니다.

**필수 Evidence**

- 공격 실행 1회
- 서로 다른 Source `event_id` 2개
- 같은 `TAKE_ID`
- Credential 원문 미노출

**중단 조건**

허용되지 않은 Target, 실제 데이터, 형식이 다른 TAKE가 확인되면 즉시 중단한다.

---

### Scene 3 — 빠른 Wazuh 탐지

**화면**

- Wazuh Rule `100103` Alert
- `TAKE_ID`, 각 `event_id`, Source UTC, Alert UTC
- Event별 지연시간
- 정상 대조군 Alert 0 Evidence

**내레이션**

> DVWA 감사 Event는 CloudWatch Logs에서 Push 경로를 거쳐 Wazuh Rule 100103으로
> 탐지됐습니다. 두 Alert는 같은 TAKE의 서로 다른 명령 Event라서 Wazuh에는 모두
> 보존합니다. 이 시점에 확정할 수 있는 것은 IMDS를 겨냥한 명령 실행이며,
> S3 접근 성공까지 확정된 것은 아닙니다.

**필수 Evidence**

- Rule `100103`
- 원본 Event 2·Alert 2
- 누락 0·동일 `event_id` 중복 0
- Source → Wazuh 실제 지연
- 정상 대조군 Alert 0

**중단 조건**

실제 AWS Event와 Wazuh Alert를 ID·UTC로 연결하지 못하면 합성 Alert로 대신하지 않는다.

---

### Scene 4 — 즉시·가역적 Containment

**화면**

- Shuffle의 Schema·Allowlist·TAKE 검증
- 첫 Alert의 Containment Outcome과 두 번째 Alert의 중복 억제
- DVWA 고정 Label을 선택한 Quarantine NetworkPolicy
- 실제 Ingress·Egress Deny와 필요한 관측 경로 Allow 결과
- 공유 Role이면 `validation/*` 영향 차단 또는 `IAM_APPROVAL_REQUIRED`

**내레이션**

> 첫 Alert는 사전 허용된 TAKE와 고정 Target을 통과해 대응 대상으로 판정됐습니다.
> 두 번째 Alert는 원본 Evidence로 보존하지만 같은 Incident의 Containment는 다시 실행하지
> 않습니다. 먼저 DVWA Workload를 가역적으로 격리했고, 공유 Node Role 전체가 아니라
> 허용된 실습 데이터 범위의 추가 접근 영향만 제한했습니다.

> 이것은 유출 Credential 전체 폐기를 의미하지 않습니다. 현재 Incident의 확신도는
> SUSPECTED이며, 느린 Evidence로 침해 성공 여부를 계속 조사합니다.

**필수 Evidence**

- 허용된 TAKE·Account·Region·Scenario
- Containment orchestration 1회
- 실제 NetworkPolicy enforcement
- 대상 Label·정책 UID·Argo Revision
- 다른 Namespace 영향 0
- IAM 조치의 정확한 Scope 또는 승인 대기 상태
- Rollback 가능성

**중단 조건**

NetworkPolicy가 실제 강제되지 않거나 공유 Role 전체 Deny만 가능하면 `observe_only`로
종료한다. 그 영상을 Containment 완료로 편집하지 않는다.

---

### Scene 5 — 느린 5-Source 조사와 침해 확인

**화면**

- Wazuh의 같은 Incident Timeline
- DVWA 원본 감사 Event
- WAF 요청 검사 결과
- ALB·CloudFront 외부 요청 경로
- CloudTrail `validation/* GetObject` Event와 Rule `100100`
- 각 Source UTC와 상관관계 근거

**내레이션**

> 빠른 경로로 먼저 확산을 제한한 뒤, 기존의 꼼꼼한 수집 경로로 사건을 조사합니다.
> DVWA, WAF, ALB, CloudFront는 외부 요청과 애플리케이션 실행 경로를 보여주고,
> CloudTrail의 예상 Role과 validation 경로 GetObject 성공으로 침해를 확인합니다.
> 늦게 도착한 확인 Event는 확신도를 CONFIRMED로 바꾸지만 이미 수행한 Containment를
> 다시 실행하지 않습니다.

**필수 Evidence**

- 실제 동일 Incident의 5 Source
- CloudTrail 원본 `eventID`와 Rule `100100`
- 예상 Role·허용된 가짜 Object
- 서로 다른 날짜의 로그를 조합하지 않았다는 UTC 연속성

**중단 조건**

CloudTrail 성공을 확인하지 못하면 `침해 확인` 대신 `침해 의심 조사 중`으로 표현한다.

---

### Scene 6 — 애플리케이션 Remediation 배포

**화면**

- GitHub의 Remediation Workflow Run
- `deploy/dvwa/values.yaml` 정확한 Diff
- `defaultSecurityLevel: low → impossible`
- Remediation Commit SHA와 Artifact
- Argo CD `OutOfSync/Syncing → Synced + Healthy`
- `status.sync.revision=<Remediation SHA>`와 새 Pod

**내레이션**

> 증거와 영향 범위를 확인한 뒤 취약 동작을 제거합니다. 이 변경은 격리가 아니라
> DVWA의 보안 설정을 low에서 impossible로 바꾸는 애플리케이션 Remediation입니다.
> Git에는 이 한 값만 변경됐고, Argo CD가 정확한 Commit SHA를 새 Pod로 배포했습니다.

**필수 Evidence**

- 변경 파일 1개·값 1개
- 예상하지 않은 Diff 0
- GitHub Run·Artifact·Commit SHA
- Argo exact SHA·`Synced + Healthy`
- 새 Pod UID 또는 Template Hash

**중단 조건**

예상 밖 파일·값이 바뀌거나 Argo Revision이 Commit과 다르면 배포 성공으로 표현하지 않는다.

---

### Scene 7 — 패치 효과와 정상 기능 검증

**화면**

- 필요한 Test 경로만 제한적으로 허용한 상태
- 같은 Payload의 애플리케이션 계층 실패
- IMDS Marker·새 Rule `100103` 위협 Event 증가 없음
- 정상 로그인과 승인된 기능 성공
- NetworkPolicy 차단 Test와 애플리케이션 Patch Test의 분리 결과

**내레이션**

> 이제 격리 때문에 막힌 것인지 설정 패치로 취약 동작이 제거된 것인지 구분해 검증합니다.
> 제한된 Test 경로에서 같은 Payload는 애플리케이션 계층에서 실패했고,
> 정상 로그인과 허용 기능은 계속 동작합니다. 따라서 단순 서비스 중단이 아니라
> 취약 동작을 제거한 결과임을 확인했습니다.

**필수 Evidence**

- 동일 Payload 실패
- 실패 계층이 애플리케이션이라는 근거
- 정상 기능 성공
- 새 IMDS Marker·위협 Alert 증가 0

**중단 조건**

실패 원인을 NetworkPolicy와 Patch 사이에서 구분하지 못하거나 정상 기능이 깨지면
Remediation 성공으로 판정하지 않는다.

---

### Scene 8 — 근본 원인 복구와 Recovery 종료

이 Scene은 실제 영구 대응 Runtime이 있을 때만 본편에 포함한다. Terraform Plan이나 문서만
보여주고 Recovery 완료라고 말하지 않는다.

**화면**

- 실제 적용된 IAM 최소 권한 상태
- IMDSv2 강제·Hop Limit과 필요한 Node 교체 결과
- 기존 Credential의 `validation/*` 접근 `AccessDenied`
- 임시 IAM Deny·Quarantine 해제 Evidence
- 정상 기능·관찰창·새 위협 Event 0
- 최종 Incident 상태 `RECOVERED` 또는 `CLOSED`

**내레이션**

> 마지막으로 공격이 가능했던 근본 조건을 복구했습니다. 실습 IAM 권한을 최소화하고,
> IMDS 경로와 필요한 Node 상태를 목표 설정으로 변경했습니다. 기존 Credential의 추가
> 접근은 거부되고, 정상 기능과 관측 경로가 유지되는 것을 확인한 뒤 임시 격리를
> 해제했습니다.

> 이번 시연은 빠른 탐지, 가역적 Containment, 느린 조사, 애플리케이션 Remediation,
> 근본 원인 복구와 Recovery를 서로 다른 Evidence로 검증했습니다.

**필수 Evidence**

- 실제 적용 전후 Diff와 승인 기록
- Post-Apply 목표 상태
- 기존 Credential `AccessDenied`
- Quarantine·임시 Deny 해제 주체와 UTC
- 정상 기능·관찰창 결과
- 최종 상태와 Evidence Index

**중단 조건**

영구 대응이 Plan-only이거나 기존 Credential 접근 실패를 검증하지 못하면 Scene 8을
촬영하지 않고 Scene 7의 제한된 종료 문장을 사용한다.

---

## 3. 편집과 구간 연결 규칙

- 본편의 모든 Runtime 장면은 같은 `TAKE_ID`를 사용한다.
- 느린 Poll 대기 구간은 잘라도 되지만 `실제 경과시간`, `전환 전후 UTC`, `같은 TAKE`를
  자막으로 남긴다.
- GitHub·Argo 화면은 Run ID·Commit SHA·Revision이 읽히는 길이로 고정한다.
- 빠른 Alert와 느린 CloudTrail Event가 같은 시각에 온 것처럼 편집하지 않는다.
- `SUSPECTED → CONFIRMED`와 `DETECTED → CONTAINED`를 같은 Status처럼 표현하지 않는다.
- Containment를 `차단`, Remediation을 `보안 설정 패치`, Recovery를 `정상 운영 복귀`로
  일관되게 설명한다.
- 실패한 TAKE의 일부 화면을 다른 TAKE의 성공 결과와 합쳐 하나의 E2E처럼 만들지 않는다.

권장 전환 자막:

```text
같은 TAKE_ID — 10분 Poll 결과 대기
같은 TAKE_ID — GitHub/Argo 배포 경과시간 실제 N분
SUSPECTED → CloudTrail Evidence로 CONFIRMED
Containment 유지 중 Remediation 검증
```

---

## 4. 실패와 재촬영 처리

장면 하나가 실패하면 다음 순서로 처리한다.

1. 해당 TAKE를 `FAILED` 또는 `CLOSED`로 표시한다.
2. 원본 Event·Alert·Hash·실패 이유를 삭제하지 않는다.
3. 자동으로 Reset하거나 같은 외부 Write를 재전송하지 않는다.
4. 수동 Reset Gate를 통과한 뒤 새 `TAKE_ID`를 발급한다.
5. 새 TAKE의 본편은 Scene 0부터 다시 시작한다.

부분 재촬영이 필요해도 서로 다른 TAKE를 같은 Incident처럼 숨기지 않는다. 교육용 편집 영상으로
여러 TAKE를 사용해야 한다면 각 구간에 TAKE와 날짜가 다르다는 자막을 명시하고 `단일 E2E
Runtime 증명`이라고 부르지 않는다.

---

## 5. 선택 사항 — Reset 별도 영상 대본

Reset은 본편 Recovery가 아니라 다음 촬영을 위해 취약 Lab을 다시 여는 운영 절차다.
본편에 붙이지 않고 필요할 때만 별도 영상으로 촬영한다.

**화면**

- 이전 TAKE `CLOSED`
- Evidence 보존 완료
- Quarantine 유지
- `impossible → low` Reset Commit과 Argo exact SHA
- Lab IAM 권한 복원
- 새 Pod·Wazuh·Bridge READY
- 새 TAKE 발급
- Quarantine 마지막 해제

**내레이션**

> 이 절차는 사고 복구를 되돌리는 자동 대응이 아니라 재촬영을 위한 Lab 전용 Reset입니다.
> 기존 Evidence와 Git History는 보존하고, Quarantine을 유지한 상태에서 설정과 Lab 권한을
> 복원했습니다. 새 Pod와 관측 경로, 새 TAKE를 확인한 뒤 Quarantine을 마지막에 해제합니다.

Reset 실패나 통제권 상실 시 `low`를 공개 상태로 두지 않고 다시 격리하거나 Daily Runtime을
종료한다.

---

## 6. 공개 전 최종 검수

- [ ] 영상 제목이 실제 완료 범위를 과장하지 않는다.
- [ ] 모든 본편 Runtime 장면의 `TAKE_ID`가 같다.
- [ ] Source Event·Wazuh Alert·Shuffle Outcome·GitHub Run·Argo Revision을 대조했다.
- [ ] `command.execution` 2건을 Incident 2건으로 설명하지 않는다.
- [ ] 빠른 탐지만으로 S3 접근 성공을 주장하지 않는다.
- [ ] Lab Prefix Deny를 Credential 폐기로 설명하지 않는다.
- [ ] `low → impossible`을 Containment라고 부르지 않는다.
- [ ] Plan-only 항목을 Runtime 완료로 말하지 않는다.
- [ ] 재공격 실패와 정상 기능 성공을 함께 보여준다.
- [ ] Reset을 Recovery라고 부르지 않는다.
- [ ] Secret·실제 개인정보·전체 식별자가 음성·화면·자막에 없다.
- [ ] 실패 TAKE나 다른 날짜의 Evidence를 하나의 Incident처럼 합치지 않는다.
