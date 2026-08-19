# Capital One 기반 SOC 자동화 E2E Blueprint

> 상태: **CURRENT TARGET — 대응 계약 정합성 확정, E2E 미완료**
>
> 기준 시각: 2026-08-18 KST
>
> 대응 의미 정본:
> [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
>
> READY의 DLQ 검사는 Wazuh Reader Role의 상태 조회 최소 권한만 사용한다. 구조 Schema와
> 운영 Allowlist를 분리하고, `observe_only`는 대응 Dedupe를 소비하지 않고 종료한다.
> 즉시 Containment는 DVWA Workload Quarantine과 허용된 IAM 영향 차단이며,
> `low → impossible`은 별도 Remediation이다. NetworkPolicy enforcement와 Blast Radius를
> Runtime으로 증명하기 전에는 `observe_only`만 허용한다.
>
> 이 문서는 대표 시연의 Hop별 Target 계약과 실패 경계를 정의한다. Target은 Source
> 존재나 Runtime 완료를 뜻하지 않는다. 실제 Source와 Runtime Evidence가 충돌하면
> Source·Runtime을 우선하고 이 문서를 고친다.

---

## 0. 이 문서의 권위와 사용법

### 0.1 단일 구현 기준

문서 역할은 다음처럼 고정한다.

- `CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`: 대응 의미와 순서의 정본
- `CAPITAL-ONE-SOC-DEMO-PLAN.md`: 전체 Gate·완료 조건·현재 우선순위
- `CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md`: 촬영 범위·화면·조작·내레이션·필수 Evidence
- 이 문서: Hop별 Interface·상태·Evidence Target
- `CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md`: AWS Source·영구 복구 실행 경계
- `observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`: AWS→Wazuh 전달 계약

현재 정본은 Containment·Remediation·Reset을 별도 계약으로 취급한다. 각 계약이 해당
Runtime Gate를 통과하기 전에는 활성 대응 경로로 사용하지 않는다.

### 0.2 사실 상태 표기

| 표기 | 의미 |
|---|---|
| Source 확인 | 파일에 구현이 존재한다. 실행 성공을 뜻하지 않는다. |
| Runtime 확인 | 실제 실행 출력이나 보존 로그로 동작을 확인했다. |
| Target | 앞으로 구현할 설계다. |
| 미검증 | 구현 여부와 무관하게 완료 Evidence가 없다. |
| 사용자 결정 필요 | 구현 전 사용자가 선택해야 한다. |

### 0.3 이번 Blueprint의 경계

포함:

- 노트북이 켜진 시연 시간 동안의 닫힌 SOC 자동화 흐름
- DVWA Command Injection 기반 Capital One 각색 시나리오
- Rule 100103 저지연 탐지
- Wazuh에서 Shuffle로 전달할 최소 Alert 계약
- TAKE_ID 검증과 중복 대응 차단
- DVWA Workload Quarantine과 허용된 IAM 영향 차단
- `low → impossible` 보안 설정 Remediation
- Argo CD의 각 정확한 Commit 배포 확인
- 격리/패치 분리 검증, 정상 기능 유지, 수동 Reset
- 보고서용 Evidence

제외:

- WAF, CloudTrail, ALB, CloudFront의 Push 전환
- 노트북이 꺼진 동안의 탐지와 Offline Catch-up
- 24시간 운영과 고가용성
- Wazuh의 AWS 이전
- 두 번째 공격 시나리오
- 공유 Karpenter Node Role 전체 자동 Deny
- 전용 Principal 없이 Credential 전체 자동 폐기를 주장하는 것
- 추가 Dashboard 미관 개선
- 실제 기업의 범용 치료 코드를 가장하는 것

---

## 1. 동결할 사용자 장면

### 1.1 한 문장 목표

노트북에서 SOC를 한 번 시작한 뒤, 교육용 DVWA 침투가 저지연으로 탐지되고,
Workload·IAM 영향을 먼저 제한한 다음 느린 Evidence로 조사하고, 검토된 설정 패치와
영구 복구를 배포해 같은 공격은 실패하지만 정상 기능은 유지되는 장면을 재현한다.

### 1.2 최종 장면

    사용자: Start-SocLab 1회 실행
      → Wazuh, Bridge, Shuffle 연동, GitHub, Argo 사전 상태 확인
      → READY + ACTIVE_TAKE_ID
    사용자: 승인된 Capital One 실습 공격 실행
      → DVWA가 2개의 command.execution 감사 Event 생성
      → CloudWatch Logs → Lambda → SQS → Local Bridge
      → Wazuh Rule 100103 Alert 2건
      → Shuffle은 같은 TAKE_ID를 한 사건으로 분류
      → 고정 DVWA Quarantine 요청 1회
      → 공유 Role이면 validation/* IAM 영향 차단 또는 사람 승인 대기
      → 느린 CloudTrail·WAF·ALB·CloudFront로 Incident 확인·보강
      → 별도 Remediation에서 values.yaml의 low만 impossible로 변경
      → Argo CD가 각 예상 Commit SHA를 Synced + Healthy로 배포
      → 격리 효과와 설정 패치 효과를 분리해 동일 공격 실패 확인
      → 정상 로그인과 허용 기능 유지
    사용자: 필요할 때 별도 Reset Workflow 수동 실행
      → Quarantine을 유지한 채 impossible을 low로 복원
      → Lab IAM 권한·새 Pod·새 TAKE·Wazuh READY 확인
      → Quarantine을 마지막에 해제

### 1.3 완료로 인정하지 않는 것

- 파일이나 Workflow가 존재하는 것
- Wazuh Rule 정적 Test만 성공한 것
- Shuffle Webhook이 한 번 호출된 것
- GitHub Commit만 생성된 것
- Argo CD가 단순히 Healthy인 것
- 과거 서로 다른 날짜의 로그를 한 Timeline처럼 조합한 것

실제 사용자 장면 전체가 한 TAKE_ID와 정확한 Commit SHA로 연결돼야 완료다.

---

## 2. 핵심 설계 판단

### 2.1 빠른 경로와 조사 경로를 분리한다

| 경로 | 목적 | Source |
|---|---|---|
| 빠른 대응 경로 | 수초 단위 탐지와 좁고 가역적인 Containment | DVWA Push → Rule 100103 |
| 조사·보존 경로 | 사건 전후의 원본 확인과 보고서 Evidence | 기존 5-Source 10분 Poll |

기존 CloudTrail, WAF, ALB, CloudFront, DVWA Poll은 제거하지 않는다. 다만 대표 자동
대응의 시작 신호로 사용하지 않는다. CloudTrail eventID는 사후 상관분석 Evidence이며
빠른 사건 키가 아니다.

### 2.2 자동 대응 키는 사전 허용된 TAKE_ID다

- TAKE_ID는 Start-SocLab이 발급한다.
- 발급된 TAKE_ID는 Shuffle Datastore에 허용 상태와 만료 시각을 사전 등록한다.
- 공격 Runner는 X-SOC-TAKE-ID Header로 전달한다.
- DVWA는 엄격한 형식만 감사 Event에 기록한다.
- Rule 100103 탐지는 TAKE_ID가 없어도 발생한다.
- Shuffle 자동 대응은 사전 등록된 유효 TAKE_ID가 없으면 거부한다.
- TAKE_ID는 인증 수단이 아니라 Lab 실행 상관관계와 자동 대응 허용 표식이다.

권장 형식:

    ^capital-one-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$

### 2.3 한 TAKE에는 Alert 2건, 대응 1건이 정상이다

현재 Baseline Runner는 DVWA Command Injection을 두 번 사용한다.

1. IMDS Role 이름 조회
2. 해당 Role의 임시 Credential 조회

따라서 정상 Cardinality는 다음과 같다.

| 단위 | 기대 수 |
|---|---:|
| command.execution 원본 Event | 2 |
| Rule 100103 Alert | 2 |
| Shuffle 실행 | 2까지 허용 |
| 신규 사건 판정 | 1 |
| Containment orchestration | 1 |
| Workload Quarantine 적용 | 1 |
| IAM 영향 차단 | 0 또는 1; 공유 Role 안전 조건 미충족 시 승인 대기 |
| low → impossible Remediation Commit | 1 |

두 Alert를 중복이라고 삭제하면 안 된다. 서로 다른 Source Event지만 동일한 사건이므로
Wazuh에는 둘 다 보존하고, Shuffle의 Containment orchestration만 TAKE_ID로 한 번 수행한다.

### 2.4 Wazuh 기본 Shuffle 연동 대신 Custom Integration을 사용한다

Wazuh 기본 name=shuffle 연동은 Rule 필터링은 가능하지만 Wazuh Alert 전체를 Webhook으로
보낸다. 이 프로젝트는 외부로 나가는 필드를 명시적으로 제한해야 하므로 다음을 사용한다.

- Wazuh Integrator의 custom-shuffle-soc
- ossec.conf의 rule_id=100103
- Custom Script에서 필수 필드를 재검증
- 허용된 필드만 새 JSON으로 생성
- Shuffle Webhook 인증 Header 추가
- full_log, Credential, Cookie, Token, 원본 Command와 응답은 전송 금지

### 2.5 Shuffle은 이중 안전장치 중 첫 번째다

정확히 한 번의 대응은 단일 제품의 보장으로 주장하지 않는다.

1. Shuffle Datastore에서 TAKE_ID 중복 차단
2. 각 실행 계층에서 고정 Target·현재 상태·변경 Diff·Rollback을 다시 검증

Shuffle 공식 API는 Set Cache 응답에서 기존 Key 여부를 반환한다. 그러나 동시 실행의
원자적 exactly-once 보장은 문서만으로 확정하지 않는다. 같은 Payload 10개를 동시에
보내 GitHub 호출 1회를 Runtime으로 증명하기 전에는 완료가 아니다.

### 2.6 Reset은 SOAR가 호출하지 않는다

Reset은 SOAR·Wazuh Alert가 호출할 수 없다. 별도 수동 진입점과 정확한 확인 문자열을
사용하며, Quarantine을 유지한 채 `impossible → low`와 Lab IAM 권한을 복원한다. 새 Pod,
Alarm 실제 `OK`, Wazuh·Bridge READY, 새 TAKE를 확인한 뒤 Quarantine을 마지막에 해제한다.
현재 Private + GitHub Free 저장소에서는 Environment Required Reviewer를 강제할 수 없으므로
`environment:`만 승인 장치로 쓰지 않는다.

---

## 3. As-built Snapshot

아래는 2026-08-18 현재 Source와 이번 세션의 읽기 전용 Runtime 확인을 분리한 상태다.

| 영역 | 확인 상태 | 근거와 의미 |
|---|---|---|
| Daily Runtime | 현재 재확인 필요 | 각 실행의 Active Session과 Watchdog Deadline을 다시 읽어야 함 |
| Foundation Push | Source/과거 Runtime 확인 | DVWA 1 Source, safe allowlist, SQS/DLQ/Lambda와 Rule `100102` 3회 Evidence |
| 5-Source Poll | Source/과거 Runtime 확인 | CloudTrail, ALB, WAF, DVWA, CloudFront 10분 Evidence 경로 |
| Wazuh | Runtime 확인 | 4.14.7 Manager·Indexer·Dashboard 실행, Port `127.0.0.1` 바인딩 |
| Wazuh 입력·Integration | Runtime 확인 | Push JSONL localfile과 `custom-shuffle-soc`가 현재 Manager 설정에 존재 |
| Rule `100103` | 부분 Runtime 확인 | 합성 Alert 여러 건과 과거 실제 Alert 1건; 실제 AWS 3 TAKE 저지연 검증 아님 |
| Local Bridge | Source/Runtime 재확인 필요 | Ledger·Live JSONL·Heartbeat Source 존재; 현재 정확한 Host Process·Mount를 Gate에서 재확인 |
| DVWA 감사 Event | Source 확인 | 엄격한 `X-SOC-TAKE-ID` 검증과 `take_id` 감사 필드 존재 |
| Baseline Runner | Source 확인 | 모든 공격 POST에 `X-SOC-TAKE-ID`를 전달 |
| Shuffle | Source/부분 Runtime | Validator·Dispatcher·Workflow 계약과 검증 Evidence 존재; Production 대응은 미완료 |
| Response Workflows | Target | Workload Containment·Remediation·Reset의 분리된 Source·Runtime 검증 필요 |
| Workload Containment | 미구현 | DVWA Quarantine NetworkPolicy Source·enforcement Evidence 없음 |
| IAM Impact Containment | 미구현 | 현재 실습 권한은 공유 Primary Karpenter Node Role에 연결 |
| Argo CD | Source/과거 Runtime 확인 | main auto-sync, prune, selfHeal과 정확한 SHA 검증 기반 존재 |

### 3.1 Rule 100103의 정확한 현재 Evidence

과거 실제 Alert 1건에서 확인된 시각:

- Source Event: 2026-08-17 13:41:54Z
- Bridge 수신: 2026-08-17 14:20:58Z
- Wazuh Alert 처리: 2026-08-17 14:20:59Z

이는 Rule `100103`이 실제 Event 의미를 탐지할 수 있다는 증거다. Bridge가 공격 뒤 늦게
수신했고 당시 Event에는 현재 TAKE 계약이 완성되지 않았으므로 저지연 E2E 증거로 사용하지
않는다. 현재 Manager에는 합성 `command.execution` Alert도 있지만 실제 AWS 전달 증거를
대신하지 않는다.

### 3.2 현재 주요 공백

- Start-SocLab 통합 시작점 없음
- Bridge의 1시간 STS Session 자동 갱신 없음
- Bridge Heartbeat와 READY 계약 없음
- TAKE_ID가 DVWA Event에 들어가지 않음
- Wazuh → Shuffle Sanitizer와 Webhook 없음
- 실제 AWS `command.execution → Rule 100103` 독립 3 TAKE 없음
- Offline Catch-up·DLQ·DVWA Poll Rollback Runtime 없음
- NetworkPolicy enforcing·Quarantine Positive/Negative Test 없음
- 공유 Node Role에 안전한 IAM 영향 차단·Rollback 없음
- Shuffle observe-only와 Containment Target 계약 Runtime 없음
- `low → impossible`을 Remediation으로 호출하는 별도 Workflow·E2E 없음
- 새 Reset 순서와 격리/패치 분리 검증 없음

---

## 4. Target Topology

    ┌────────────────────────── Laptop / Student SOC ──────────────────────────┐
    │ Start-SocLab ─ READY/ACTIVE_TAKE ─ Capital One Runner                    │
    │      ├─ Docker Wazuh Manager/Indexer/Dashboard                           │
    │      ├─ Local Bridge + Heartbeat + STS Session                           │
    │      ├─ Wazuh Custom Integration ── sanitized HTTPS ─────────────┐        │
    │      └─ E2E Evidence Collector                                  │        │
    └─────────────────────────────────────────────────────────────────┼────────┘
                                                                      ▼
    User → CloudFront/WAF/ALB → EKS/DVWA → CWL → Lambda → SQS → Rule 100103
                                                                      │
                                                                      ▼
                                                    Shuffle validate/allow/dedupe
                                                        │             │
                                              Workload Quarantine     IAM impact
                                              fixed NetworkPolicy     bounded action
                                                        │             │
                                                        └──────┬──────┘
                                                               ▼
                                                confidence=SUSPECTED

    조사·확인 경로:
    CloudTrail + WAF + ALB + CloudFront + DVWA
      → 기존 S3/CloudWatch 원본 → Wazuh 10분 Poll
      → 같은 Incident Timeline → CloudTrail 성공 시 confidence=CONFIRMED

    Remediation·Recovery 경로:
    low → impossible 보안 설정 Patch → Git Commit → Argo exact SHA
      → 새 Pod → 격리/패치 분리 Test → Terraform IAM·IMDS 복구
      → 임시 격리 해제 → RECOVERED

---

## 5. Runtime Sequence

### 5.1 시작과 TAKE 발급

1. 사용자가 Start-SocLab을 정확히 한 번 실행한다.
2. Script는 Daily Runtime을 생성하지 않고 현재 상태만 검사한다.
3. Wazuh 3개 Service를 기동하고 Health를 확인한다.
4. Wazuh Rule과 Custom Integration 설정을 정적 검사한다.
5. Bridge를 단일 Background Process로 기동한다.
6. Bridge가 SQS 접근, Spool 쓰기, Heartbeat 생성을 성공해야 한다.
7. Rule 100102 안전 Probe 1건으로 AWS → Wazuh 전달을 확인한다.
8. Shuffle observe-only Workflow와 모든 대응 Dispatch의 비활성 상태를 확인한다.
9. DVWA의 현재 값이 low인지 확인한다.
10. 새 TAKE_ID를 생성하고 Shuffle Allowlist에 만료 시각과 함께 등록한다.
11. READY JSON과 사람이 읽을 한 줄을 출력한다.

### 5.2 탐지와 대응

1. Runner는 Active TAKE를 읽고 모든 공격 POST에 X-SOC-TAKE-ID를 넣는다.
2. DVWA는 형식을 검증한 뒤 take_id를 감사 Event에 추가한다.
3. 기존 Lambda는 take_id를 허용 필드로 Queue에 전달한다.
4. Bridge는 Event별 Ledger를 먼저 보존하고 Live JSONL에 기록한 뒤 SQS에서 삭제한다.
5. Wazuh는 두 Event를 Rule 100103으로 각각 Alert화한다.
6. Custom Integration은 각 Alert를 최소 Schema로 재작성해 Shuffle에 보낸다.
7. Shuffle은 Account, Scenario, Rule, TAKE Allowlist, 만료를 검증한다.
8. 첫 Alert만 Dedup Key 신규가 되어 Containment orchestration을 진행한다.
9. 두 번째 Alert는 DUPLICATE_SUPPRESSED로 종료한다.
10. NetworkPolicy enforcement와 IAM Blast Radius가 미검증이면 `OBSERVE_ONLY`로 종료한다.
11. 조건이 충족되면 고정 DVWA Quarantine만 적용하고 정확한 Argo Revision을 확인한다.
12. 공유 Role에서는 `validation/*` 임시 Deny 또는 사람 승인만 허용한다.
13. 느린 Source는 Incident를 보강하되 Containment를 다시 실행하지 않는다.

### 5.3 배포와 검증

1. Containment 적용 결과와 느린 Incident Evidence를 보존한다.
2. 별도 Remediation Workflow가 `low → impossible` 정확한 한 전이만 Commit한다.
3. Workflow Run·Artifact·Commit SHA·TAKE_ID를 검증한다.
4. Argo Application을 Hard Refresh한다.
5. Synced, Healthy, status.sync.revision=Commit SHA를 동시에 확인한다.
6. Deployment Rollout 완료와 새 Pod UID/Template Hash를 확인한다.
7. 필요한 Test 경로만 제한적으로 복구해 NetworkPolicy 차단과 설정 패치 효과를 분리한다.
8. Pod의 DEFAULT_SECURITY_LEVEL이 impossible인지 확인한다.
9. 같은 Payload가 애플리케이션 계층에서 실패하고 IMDS Marker가 없음을 확인한다.
10. 정상 로그인과 승인 기능은 계속 성공해야 한다.
11. Terraform 영구 복구 뒤 기존 Credential의 `validation/*` 접근 실패를 확인한다.
12. 관찰창 동안 Rule 100103·Shuffle 조치·GitHub Run이 예상 Cardinality를 유지해야 한다.
13. 임시 격리 해제와 결과를 기록한 뒤에만 `RECOVERED`로 전이한다.

### 5.4 수동 Reset

1. 운영자가 정확한 확인 문자열로 시작하고 기존 TAKE를 `CLOSED`로 만든다.
2. Script는 배타적 Lock, Manifest·Hash, 정확한 Containment·Remediation Run을 검증한다.
3. Quarantine을 유지한 채 `impossible → low`만 새 Commit으로 허용한다.
4. Argo가 정확한 Reset SHA를 배포하고 새 Pod가 `low`인지 확인한다.
5. Lab Prefix 임시 Deny 또는 전용 Lab 권한만 복원한다.
6. 공격·Reset Process의 AWS Credential 환경변수 잔존 없음과 Alarm 실제 `OK`를 확인한다.
7. Wazuh·Bridge READY 뒤 새 TAKE를 발급한다.
8. Quarantine을 마지막에 해제하고 해제 시각·정책 UID·주체를 기록한다.
9. 각 단계의 Intent·Run·Transition·Argo·IAM·Policy Evidence를 Journal로 보존한다.
10. 성공 여부가 불명확한 외부 Write는 자동 재전송하지 않고 운영자가 원격 상태를 대조한다.
11. 준비 실패나 통제권 상실 시 다시 격리하거나 Daily Runtime을 종료한다.

---

## 6. TAKE_ID와 상태 수명주기

### 6.1 서로 독립적인 세 상태 축

사건 확신도와 대응 단계를 한 `status` 필드에 섞지 않는다.

```text
take_status
ISSUED → READY → ATTACK_STARTED → ACTIVE → E2E_SUCCEEDED 또는 E2E_FAILED

incident_confidence
UNASSESSED → SUSPECTED → CONFIRMED
                     └→ DISPROVED (조사로 공격 가설 기각)

response_phase
NOT_STARTED → DETECTED → CONTAINMENT_DISPATCHED → CONTAINED → INVESTIGATING
             → REMEDIATION_DISPATCHED → REMEDIATED → RECOVERY_VALIDATED
```

`incident_confidence=CONFIRMED`는 CloudTrail Rule `100100`의 예상 `GetObject` 성공
Evidence를 뜻한다. Rule `100103`만으로 `SUSPECTED`와 Containment를 시작할 수 있지만
Credential 탈취·S3 접근 성공을 확정하지 않는다. 늦은 확인은 `response_phase`를 뒤로
돌리거나 Containment를 다시 실행하지 않는다. `observe_only`에서는 `response_phase`가
`DETECTED` 또는 `INVESTIGATING`을 넘지 않는다.

Reset은 `take_status`만 다음처럼 전이하고, 별도 Evidence로 Quarantine·IAM·설정 상태를
검증한다.

```text
E2E_SUCCEEDED 또는 E2E_FAILED
  → RETAKE_APPROVED
  → RESET_REMEDIATION_REVERSED
  → RESET_IAM_RESTORED
  → RESET_READY
  → RESET_QUARANTINE_RELEASED
  → CLOSED

어느 E2E 단계에서든 실패 → E2E_FAILED
Reset 실패 → RESET_FAILED, Quarantine 유지
```

Runtime 구현이 이 세 상태 축을 지원하기 전에는 단일 `status` 파일을 Production 대응
완료 Evidence로 사용하지 않는다.

### 6.2 Active TAKE 계약

로컬 Active TAKE 파일:

    %LOCALAPPDATA%\aws-topology\soc-runtime\active-take.json

필수 필드:

| 필드 | 규칙 |
|---|---|
| schema_version | 2 |
| take_id | 엄격한 정규식 |
| scenario_id | CAPITAL-ONE |
| response_mode | observe_only 또는 contain; contain은 안전 Gate 통과 뒤에만 허용 |
| issued_at_utc | UTC ISO 8601 |
| expires_at_utc | 발급 뒤 최대 2시간 |
| take_status | TAKE 실행·성공·실패·Reset·종료 상태 |
| incident_confidence | `UNASSESSED`, `SUSPECTED`, `CONFIRMED`, `DISPROVED` 중 하나 |
| response_phase | 탐지·Containment·조사·Remediation·Recovery 진행 상태 |
| account_alias | primary-lab |
| expected_rule_id | 100103 |

실제 Account ID, Token, Webhook, Cookie, Credential은 이 파일에 넣지 않는다.

### 6.3 Event ID와 TAKE_ID의 역할

| 값 | 역할 |
|---|---|
| CloudWatch logEvent ID 기반 event_id | 서로 다른 원본 Event 식별 |
| Wazuh Alert ID | Wazuh Alert 식별 |
| TAKE_ID | 한 시연 사건과 대응 묶음 식별 |
| CloudTrail eventID | 늦게 도착하는 AWS API Evidence 식별 |
| Quarantine Commit SHA | Workload 격리 Git 상태 식별 |
| Remediation Commit SHA | `low → impossible` 설정 패치 식별 |
| Reset Commit SHA | 촬영용 역방향 설정 패치 식별 |
| Argo Revision | 실제 배포된 Git 상태 식별 |

서로 대체하지 않는다.

---

## 7. Hop별 Interface Contract

### 7.1 Runner → DVWA

추가 Header:

    X-SOC-TAKE-ID: <active take_id>

규칙:

- Runner가 Role 조회와 Credential 조회의 두 POST에 모두 넣는다.
- Login과 일반 조회에는 넣어도 되지만 감사 Event에 필요한 공격 POST만 필수다.
- Header 값이 정규식과 맞지 않으면 DVWA는 take_id를 기록하지 않는다.
- Header는 권한 부여에 사용하지 않는다.
- Runner는 Header, Cookie, Command 원문을 콘솔이나 Evidence에 출력하지 않는다.

### 7.2 DVWA 감사 Event

기존 안전 필드에 다음 하나만 추가한다.

    "take_id": "capital-one-YYYYMMDDTHHMMSSZ-xxxxxxxx"

Rule 100103에 필요한 기존 필드:

- event_type=command.execution
- result=succeeded
- route=/vulnerabilities/exec/
- context.action=shell_command
- context.resource=ec2_imds
- context.security_level=low

금지 필드:

- request_body
- command
- command_output
- credential
- access_key
- secret
- session_token
- cookie
- authorization

### 7.3 CloudWatch → Lambda → SQS

현재 safe_allowlist를 유지한다.

- Subscription은 DVWA Log Group의 전체 Event를 Forward한다.
- Lambda만 허용 필드를 남긴다.
- 원본 Message는 저장하지 않고 SHA-256만 남긴다.
- take_id는 이미 SAFE_PAYLOAD_FIELDS에 있으므로 DVWA가 기록하면 전달할 수 있다.
- 다른 네 Source를 이 Push에 추가하지 않는다.

### 7.4 SQS → Local Bridge

목표 보강:

- 최대 1시간 STS Session을 만료 5분 전에 자동 갱신한다.
- 갱신 실패 시 새 Message를 삭제하지 않고 DEGRADED로 전환한다.
- Event Ledger와 Live JSONL Flush 뒤에만 SQS Message를 삭제한다.
- 단일 Writer Lock을 유지한다.
- 10초마다 Heartbeat JSON을 원자적으로 갱신한다.
- Queue ApproximateAgeOfOldestMessage와 DLQ Count를 READY에 포함한다.
- 종료 시 임시 AWS 환경변수와 Lock을 정리한다.
- 콘솔에는 Event Hash와 상태만 출력한다.

Heartbeat 필수 필드:

    schema_version, pid, state, started_at_utc, heartbeat_at_utc,
    session_expires_at_utc, last_event_hash, queue_visible, dlq_visible

### 7.5 Wazuh Rule 100103

탐지 조건은 기존 조건을 유지하고 take_id 존재를 Rule 조건에 추가하지 않는다.

이유:

- 실제 공격자가 Lab Header를 보내지 않아도 탐지는 되어야 한다.
- take_id 부재는 SOAR 자동 대응을 거부할 이유이지 탐지를 버릴 이유가 아니다.

연속 3회 검증의 정확한 기대:

| Test | TAKE 수 | 공격 Event | Rule 100103 | 정상 대조군 Rule 100103 |
|---|---:|---:|---:|---:|
| Detect-1 | 1 | 2 | 2 | 0 |
| Detect-2 | 1 | 2 | 2 | 0 |
| Detect-3 | 1 | 2 | 2 | 0 |

각 Alert의 event_id는 고유하고 TAKE_ID는 Take 내부에서 같아야 한다.

### 7.6 Wazuh → Shuffle Sanitized Alert

Custom Integration이 보내는 유일한 Body:

    {
      "schema_version": 1,
      "source_system": "wazuh",
      "sent_at_utc": "<UTC>",
      "account_alias": "primary-lab",
      "aws_account_id": "<expected account>",
      "aws_region": "ap-northeast-2",
      "scenario_id": "CAPITAL-ONE",
      "rule": {
        "id": "100103",
        "level": 10
      },
      "incident": {
        "take_id": "<validated TAKE_ID>",
        "event_id": "<CloudWatch-derived event_id>",
        "wazuh_alert_id": "<Wazuh alert id>",
        "event_time_utc": "<source event UTC>",
        "result": "succeeded",
        "route": "/vulnerabilities/exec/"
      },
      "integrity": {
        "raw_message_sha256": "<sha256>",
        "body_sha256": "<canonical body sha256>"
      }
    }

전송 전 Script 검증:

- Rule ID가 문자열 100103
- Rule Level이 10
- Source가 dvwa
- Transport가 push
- Scenario와 Route가 고정값
- Account와 Region이 고정 Allowlist
- TAKE_ID 형식이 정확함
- event_id, alert_id, timestamp, SHA 형식이 유효함
- 허용되지 않은 최상위 필드가 생성되지 않음

Header:

    Content-Type: application/json
    X-SOC-Webhook-Key: <runtime secret>

Webhook URL과 Header Key는 Git, Wazuh Alert, Evidence, 화면 캡처에 남기지 않는다.

### 7.7 Shuffle Workflow

Workflow 이름:

    CAPITAL-ONE-SOC-RESPONSE-v2

노드 순서:

1. Wazuh Alerts Webhook
2. Required Header 검증
3. 고정 Private Validator App에서 정확한 Schema와 Body SHA-256 검증
4. Account, Region, Scenario, Rule Allowlist
5. TAKE Allowlist 조회
6. 만료와 response_mode 확인
7. observe_only면 Outcome Evidence 후 종료
8. contain이면 NetworkPolicy enforcement와 고정 Response Profile 확인
9. 안전 조건 불충족이면 `SAFETY_GATE_BLOCKED`로 종료
10. 안전 조건 충족 시 TAKE Dedup Key 생성
11. Set Cache raw `keys_existed`의 정확한 Key와 existed 분기
12. 신규 TAKE면 고정 Workload Quarantine Workflow만 호출
13. 공유 Role IAM 조치는 `IAM_APPROVAL_REQUIRED`로 별도 Outcome 기록
14. GitHub가 반환한 정확한 Run ID 기록
15. 결과를 Evidence API/로컬 Collector가 조회할 수 있게 보존

Shuffle은 Dispatch 수락까지만 판정한다. GitHub Run 완료, 정확한 Commit SHA, Argo CD
배포 완료는 로컬 E2E Orchestrator가 같은 Run ID와 TAKE_ID로 이어서 검증한다. 이 경계로
Shuffle Action을 장시간 Poll 상태에 두지 않으면서도 전체 자동화 검증은 유지한다.

Shuffle outgoing branch는 자동 `else`가 아니므로 `observe_only`와 `contain` 조건을
각각 명시한다. `observe_only`는 Dedupe Key를 소비하지 않는다.

Datastore Key:

    Allow: soc:v2:allow:primary-lab:CAPITAL-ONE:<take_id>
    Dedupe: soc:v2:containment:primary-lab:CAPITAL-ONE:<take_id>
    Outcome: soc:v2:outcome:<take_id>:<raw_message_sha256>

실행 결과:

| 결과 | 의미 | GitHub 호출 |
|---|---|---:|
| REJECTED_SCHEMA | 계약 불일치 | 0 |
| REJECTED_ALLOWLIST | 허용 대상 아님 | 0 |
| REJECTED_TAKE | 미등록 또는 만료 | 0 |
| OBSERVE_ONLY | 탐지 반복 검증 | 0 |
| SAFETY_GATE_BLOCKED | NetworkPolicy·Target·Rollback 미검증 | 0 |
| DUPLICATE_SUPPRESSED | 같은 TAKE의 후속 Alert | 0 |
| CONTAINMENT_DISPATCHED | 고정 Workload Quarantine 요청 | 1 |
| IAM_APPROVAL_REQUIRED | 공유 Role의 Lab Prefix Deny 승인 대기 | 추가 자동 호출 0 |
| RESPONSE_FAILED | Dispatch 수락 여부 미확정 | 확인된 성공 0, 자동 재호출 금지 |

Wazuh HTTP 재시도와 Shuffle Workflow 재실행이 있어도 동일 TAKE의 GitHub 호출은
증가하면 안 된다.
`github_dispatch_count`는 GitHub REST API `2026-03-10`의 HTTP 200 응답에서 받은 양의
`workflow_run_id`로 확인된 성공 Dispatch만 센다. 고정된 현재 Request·Response Schema 외
Parameter를 보내지 않는다. 네트워크 오류처럼 요청 수락 여부를 확정할 수 없는 실패는
0으로 기록하고 자동 재호출하지 않으며, 해당 TAKE 전체를 실패로 종료해 운영자가 GitHub
Run을 별도로 대조한다.

### 7.8 Shuffle → GitHub

즉시 자동 호출 대상은 다음 한 개로 고정한다.

    Repository: Unoh03/Uns-DVWA
    Workflow: .github/workflows/soc-quarantine-dvwa.yml
    Ref: main

허용 Input:

- take_id
- scenario_id=CAPITAL-ONE
- rule_id=100103
- alert_body_sha256

Namespace, Label Selector, NetworkPolicy Path, Role ARN, Policy ARN, CIDR, 목표 값은
Input으로 받지 않는다. 모두 검토된 Source와 `CAPITAL-ONE` Response Profile에 고정한다.
Shuffle은 Run ID를 Outcome에 기록하고, E2E Orchestrator가 이후 GitHub·Argo 상태를
검증한다.

`soc-quarantine-dvwa.yml` Source와 NetworkPolicy enforcement Gate가 완성되기 전에는
Containment Dispatcher나 Production Credential을 연결하지 않는다.

금지:

- 임의 Repository
- 임의 Workflow 파일
- 임의 Ref
- 수정할 Path나 목표 값을 Input으로 받는 것
- Shell Command를 Input으로 받는 것
- Role ARN·Policy Document·Namespace·Selector·CIDR을 Input으로 받는 것

Shuffle Credential:

- 한 Repository로 제한된 Fine-grained PAT
- Repository Actions: write
- 짧은 만료일과 회수 절차
- Contents: write를 Shuffle Token에 주지 않음
- 실제 GitOps 파일 쓰기는 Workflow의 GITHUB_TOKEN contents: write만 사용
- Generic HTTP Header에 PAT을 직접 쓰지 않음
- Target `AWS Topology SOC GitHub Dispatcher 2.0.0`의 App Authentication으로 암호화 저장
- API Version `2026-03-10`, HTTP 200, 양의 `workflow_run_id`, 고정 Repository Run URL만 수락
- Dispatcher는 현재 API 계약만 허용하고 제거된 Parameter나 응답 형식을 수락하지 않음
- Private Dispatcher App 내부에서 Repository, Workflow, Ref, API URL을 고정
- Cloud Binding 검증은 Authentication 목록에서 App·Org·Active·Encrypted·Field Key만
  사용하고 Value를 출력·저장하지 않는다. 다만 Shuffle 공식 API에는 metadata-only
  Authentication endpoint가 없으므로 목록 응답 자체를 secret-bearing으로 취급한다.

### 7.9 Containment Workflow

Target 파일:

    D:\DVWA\.github\workflows\soc-quarantine-dvwa.yml

Trigger:

    workflow_dispatch only

불변 조건:

- main에서만 실행
- 입력 정규식과 고정값 재검증
- 변경 가능 대상은 검토된 DVWA Quarantine NetworkPolicy 상태 하나
- Namespace는 `dvwa`, Selector는 `app.kubernetes.io/name=dvwa`와
  `app.kubernetes.io/instance=dvwa`로 고정
- 정책 적용 전 EKS Network Policy enforcing Evidence 확인
- 이미 격리 상태면 변경 없이 성공
- 다른 Namespace·Selector·CIDR·파일 Diff가 있으면 실패
- Force Push와 History Rewrite 금지
- Commit Message에는 TAKE_ID만 넣고 원본 Alert나 비밀은 넣지 않음
- 결과 Artifact에 before_sha, quarantine_commit_sha, take_id, alert_body_sha256,
  policy_name, selector_hash, diff_sha256 저장
- Argo exact SHA 뒤 실제 차단과 필요한 관측 경로 유지 Test

동시 실행:

    concurrency group: dvwa-soc-response-transition
    cancel-in-progress: false

IAM 영향 차단은 이 GitOps Workflow에 임의 Policy 입력으로 섞지 않는다. 현재 공유 Primary
Karpenter Node Role에서는 `validation/*` 임시 Explicit Deny만 별도 사람 승인 대상으로
허용한다. 전용 DVWA Principal이 생기기 전에는 Role 전체 자동 Containment가 Target이 아니다.

### 7.10 Remediation Workflow

Remediation Workflow는 `low → impossible` 전이만 수행하고, Containment와 다른 이름·Artifact·
상태 의미를 사용한 뒤 별도 Runtime Gate를 통과해야 한다.

Target 파일:

    D:\DVWA\.github\workflows\soc-remediate-dvwa.yml

불변 조건:

- Containment Evidence가 존재하는 승인 TAKE에서만 실행
- 변경 가능 파일은 `deploy/dvwa/values.yaml` 하나
- 변경 가능 값은 `defaultSecurityLevel: low → impossible` 하나
- 이미 `impossible`이면 0-change 성공, 다른 값이면 실패
- 정확한 Diff와 `remediation_commit_sha` Artifact 보존
- Argo exact SHA·새 Pod·애플리케이션 Negative Test 확인
- NetworkPolicy 차단과 설정 패치 실패 원인을 분리해 검증
- Credential 폐기나 IAM Containment 완료로 표현하지 않음

### 7.11 Reset Workflow

파일:

    D:\DVWA\.github\workflows\soc-reset-dvwa.yml

Trigger:

    workflow_dispatch only

필수 입력:

- 종료할 TAKE_ID
- 정확한 확인 문자열 RESET DVWA TO LOW

불변 조건:

- impossible → low만 허용
- 이미 low면 변경 없이 성공
- 다른 값이면 실패
- 모든 SOC 상태 변경과 같은 concurrency group
- Force Push와 History Rewrite 금지
- Shuffle, Wazuh, 외부 Webhook이 호출할 수 없음
- Private Free에서 강제되지 않는 Environment Reviewer에 의존하지 않음
- 운영자의 Reset Script 직접 실행과 정확한 확인 문자열이 사람 승인 경계
- Quarantine이 적용된 상태에서 설정과 Lab IAM 권한을 먼저 복원
- 새 Pod·Alarm `OK`·Wazuh·Bridge·새 TAKE 확인 뒤 Quarantine을 마지막에 해제
- 기존 TAKE Evidence와 Alert는 삭제하지 않음

설정 복원만으로는 Reset 전체 계약을 충족하지 않는다. 격리·IAM·새 Pod·관측 준비·새 TAKE·
Quarantine 마지막 해제까지 확장·검증하기 전에는 재촬영 준비 완료로 표현하지 않는다.

### 7.12 GitHub → Argo CD → EKS

현재 Argo Application의 main 자동 Sync, prune, selfHeal을 재사용한다.

완료 조건은 네 항목을 동시에 만족해야 한다.

- status.sync.status=Synced
- status.health.status=Healthy
- status.sync.revision=<현재 단계의 exact commit SHA>
- Error Condition 없음

추가:

- kubectl rollout status deployment/dvwa 성공
- 변경 전 Pod UID와 변경 후 Pod UID가 다름
- 새 Pod Ready
- Quarantine 단계: 예상 NetworkPolicy와 실제 차단·허용 결과
- Remediation 단계: Deployment Env `DEFAULT_SECURITY_LEVEL=impossible`
- Reset 단계: `low`, 새 TAKE READY 뒤 Quarantine 해제

daily-up.ps1의 기존 Hard Refresh와 정확한 Revision 대기 로직을 공통 함수로 추출하거나
동일 계약의 전용 Verifier에서 재사용한다. 단순히 최신 main을 읽어 추측하지 않는다.

---

## 8. Start-SocLab 설계

### 8.1 명령

목표 사용법:

    Set-Location D:\terraform\aws_terraform_build_code
    .\tools\Start-SocLab.ps1 -ConfirmStart 'START SOC LAB'

이 한 명령 뒤에는 다른 터미널에서 Bridge를 별도로 켤 필요가 없어야 한다.

### 8.2 수행 범위

Start-SocLab이 하는 것:

- 현재 Daily Runtime과 capital-one-lab 확인
- DVWA low와 Application URL 확인
- Wazuh Compose 기동
- Wazuh Config와 Rule Test
- Runtime Secret 복호화와 임시 Read-only Mount 준비
- Bridge Background Process 기동
- Heartbeat 확인
- SQS와 DLQ 상태 확인
- Rule 100102 안전 Probe
- Shuffle Workflow/API 읽기 확인
- contain 모드면 Production Export, 고정 Quarantine Target, NetworkPolicy enforcement,
  Rollback Evidence, Dispatcher Authentication, 최신 Gate B5 Manifest 검증
- GitHub Quarantine·Remediation·Reset Workflow의 Source/활성 상태를 역할별 확인
- Argo 현재 Revision과 Health 확인
- Active TAKE 발급과 Shuffle Allow 등록
- READY Evidence 생성

하지 않는 것:

- Terraform Apply 또는 Destroy
- Daily Runtime 생성
- 실제 공격
- GitHub 파일 변경
- Reset
- 비밀 출력

### 8.3 READY 조건

모두 참이어야 READY:

| 검사 | 기준 |
|---|---|
| Daily | minimal + capital-one-lab |
| DVWA | low, HTTPS 응답, Login 가능 |
| Wazuh | Manager, Indexer, Dashboard running |
| Rule | 100102와 100103 Load 성공 |
| Bridge | 단일 PID, Heartbeat 30초 이내 |
| AWS Session | Wazuh Reader Role, 남은 시간 10분 이상 |
| Queue | DLQ 0, 오래된 미처리 Message 없음 |
| Safe Probe | Rule 100102 1건, 제한 시간 이내 |
| Shuffle | Workflow/API·App Binding·고정 Quarantine Target; Gate 전 대응 Dispatch 비활성 |
| GitHub | Quarantine·Remediation·Reset 역할이 분리되고 각 Target이 고정됨 |
| NetworkPolicy | EKS enforcement, 고정 대상, 실제 Deny/Allow와 Rollback Evidence |
| IAM | 공유 Role 모드는 Lab Prefix 승인 대기, 전용 Principal만 자동 Containment |
| Argo | Synced, Healthy, 현재 main SHA와 일치 |
| TAKE | 등록 성공, 만료 전, 로컬/Shuffle 값 일치 |

출력:

    SOC_LAB_READY=yes
    ACTIVE_TAKE_ID=<safe id>
    RESPONSE_MODE=<observe_only|contain>
    READY_EVIDENCE=<sanitized path>

### 8.4 중지

별도 Stop-SocLab은 Bridge를 정상 종료하고 Runtime Secret 평문과 Lock을 정리한다.
Wazuh Docker와 Daily Runtime 종료 여부는 명시적 Option으로 분리한다. Stop-SocLab이
Terraform Destroy를 암묵적으로 실행하면 안 된다.

---

## 9. 보안, 비밀, 신뢰 경계

### 9.1 비밀 저장

Git 밖의 DPAPI 암호화 원본:

    %LOCALAPPDATA%\aws-topology\soc-secrets\

Runtime 동안만 존재하는 평문:

    %LOCALAPPDATA%\aws-topology\soc-runtime\<session_id>\

원칙:

- 현재 Windows 사용자와 SYSTEM만 Host ACL 허용
- Wazuh Container에는 필요한 파일만 Read-only Mount
- Stop-SocLab이 Runtime 평문 삭제
- 콘솔, Transcript, GitHub Artifact, Obsidian, Evidence에 값 미출력
- Shuffle의 GitHub PAT는 Shuffle App Authentication에 저장
- Secret Scanner로 Git Diff와 Evidence 검사

### 9.2 외부 전송

Shuffle Cloud를 쓰면 외부로 나가는 것은 7.6의 Sanitized Alert뿐이다.

전송 금지:

- Wazuh full_log
- 원본 CloudWatch Message
- Source IP
- User ID
- Command와 응답
- Credential
- Cookie와 Token
- Bucket 이름과 Object 내용

### 9.3 현재 Local Wazuh 안전 공백

조사 시 Wazuh Dashboard, Indexer, Manager 관련 Port가 0.0.0.0으로 Published되어 있었고
Compose에는 교체가 필요한 초기 Credential 설정이 있다. 실제 값은 이 문서에 남기지 않는다.

Shuffle/GitHub Credential을 등록하기 전 Gate:

- 사용하지 않는 Port 제거 또는 127.0.0.1 Bind
- 필요한 Port의 Windows Firewall 범위 확인
- 초기 Credential 교체
- Compose와 Config에 실제 Secret이 Git 추적되지 않는지 확인

이 Hardening은 대표 E2E 논리를 확장하기 위한 기능이 아니라 새 Credential을 넣기 전의
안전 조건이다.

---

## 10. Shuffle 배치 결정

### 10.1 확정: Shuffle Cloud

대표 E2E v2의 SOAR 배치는 **Shuffle Cloud로 확정한다.**

- 결정일: 2026-08-18
- 결정 주체: 사용자
- 적용 범위: 대표 Capital One 기반 시나리오 1개

근거:

- 이미 Local Docker에 Wazuh와 OpenSearch가 실행 중이다.
- Shuffle Self-hosted도 OpenSearch를 포함하고 공식 최소 권장은 2 vCPU, RAM 8GB,
  SSD 100GB 이상이다.
- 이 시연은 Workflow 하나와 Sanitized Alert만 필요하다.
- Local Shuffle 설치와 두 번째 OpenSearch 운영은 핵심 E2E보다 구축·복구 부담이 크다.
- 노트북이 켜진 동안만 동작한다는 목표와도 충돌하지 않는다. Wazuh와 Bridge는 Local이고
  Shuffle만 관리형 Workflow Engine으로 사용한다.

Trade-off:

- Sanitized Alert가 외부 서비스로 전송된다.
- 계정, Region, 현재 Plan과 사용량 제한을 확인해야 한다.
- 인터넷과 Shuffle Cloud 장애에 의존한다.

### 10.2 보류 대안: Local Docker Shuffle

Cloud 계정 기능, Plan, Region 또는 외부 전송 정책이 실제 구현을 막는 경우에만
Blueprint를 다시 검토한 뒤 선택한다. 자동 Fallback으로 설치하지 않는다.

추가 비용은 AWS가 아니라 노트북 CPU, RAM, Disk와 운영 복잡도다. 선택하면 Wazuh와
Shuffle의 OpenSearch Resource Limit, 기동 순서, Volume Backup을 별도 설계해야 한다.

### 10.3 구현 전 안전 경계

Cloud 선택은 다음 외부 작업의 자동 승인이 아니다. 각 작업은 구현 Gate와 정확한
사용자 승인 뒤에만 수행한다.

- Shuffle 설치
- Shuffle 계정 생성이나 Region 선택
- Wazuh Webhook 등록
- GitHub PAT 등록
- 실제 Alert 외부 전송

---

## 11. 비용 경계

이번 Target은 새로운 AWS Push Source나 새 AWS Service를 추가하지 않는다.

유지되는 비용 요인:

- 기존 DVWA CloudWatch Logs Subscription
- 기존 Lambda 호출과 Log
- 기존 SQS/DLQ
- 기존 Daily Runtime
- 기존 5-Source 원본 저장과 Poll API

변경하지 않는 것:

- Subscription은 현재처럼 DVWA 전체 Event를 Forward
- Lambda safe_allowlist
- Queue 4일, DLQ 14일 보존

검증:

- 구현 전후 Lambda Invocations, Duration, Errors
- SQS Sent, Received, Deleted, Empty Receives
- CloudWatch Logs 수집량
- 한 E2E TAKE의 Event 수와 예상 월간 실행 횟수
- Shuffle Cloud Plan/Usage

비용을 확인하지 않고 “무료”라고 표현하지 않는다.

---

## 12. 실패 처리 표

| 실패 | 탐지 | 자동 대응 | Queue/Event | 사용자 출력 |
|---|---|---|---|---|
| Wazuh 미기동 | 불가 | 금지 | SQS 보존 | READY 실패 |
| Bridge 미기동 | 지연 | 금지 | SQS 보존 | READY 실패 |
| STS 갱신 실패 | 지연 | 금지 | Message 삭제 안 함 | DEGRADED |
| DLQ Message 존재 | 불확실 | 금지 | DLQ 보존 | READY 실패 |
| take_id 없음/오류 | Alert 가능 | 거부 | Alert 보존 | REJECTED_TAKE |
| Shuffle Webhook 실패 | Alert 보존 | 미실행 | Wazuh Retry 후 실패 기록 | RESPONSE_FAILED |
| 동일 TAKE 재수신 | Alert 보존 | 추가 호출 금지 | Datastore 기록 | DUPLICATE_SUPPRESSED |
| NetworkPolicy 미강제 | Alert 보존 | 변경 금지 | Safety Evidence | SAFETY_GATE_BLOCKED |
| 공유 Role 전체 Deny 요구 | Alert 보존 | 승인 대기 | Incident 보존 | IAM_APPROVAL_REQUIRED |
| GitHub Token 오류 | Alert 보존 | 미실행 | Shuffle Evidence | RESPONSE_FAILED |
| Quarantine Target 불일치 | Alert 보존 | Workflow 실패 | Git 변경 없음 | SCOPE_VIOLATION |
| Remediation 값이 low/impossible 외 | Alert 보존 | Workflow 실패 | Git 변경 없음 | INVALID_STATE |
| 예상 외 파일 Diff | Alert 보존 | Workflow 실패 | Git 변경 없음 | SCOPE_VIOLATION |
| Push 충돌 | Alert 보존 | Workflow 실패 | Force 금지 | PUSH_CONFLICT |
| Argo Revision 불일치 | Commit 존재 | 다음 단계 중단 | Git 보존 | DEPLOY_MISMATCH |
| Pod Ready 실패 | Commit 존재 | 재공격 금지 | K8s Evidence | ROLLOUT_FAILED |
| 재공격 성공 | E2E 실패 | 자동 추가 변경 금지 | Evidence 보존 | REMEDIATION_FAILED |
| Reset 실패 | Quarantine 유지 | 다음 TAKE 금지 | Evidence 보존 | RESET_FAILED |

재시도는 같은 TAKE로 Containment Workflow를 자동 재호출하지 않는다. 운영자가 Evidence를
확인하고 새 TAKE 또는 수동 복구를 결정한다. Reset은 `reset-dispatch-intent.json`,
`reset-transition.json`, `reset-deploy.json`, `reset-allow-removed.json`이 입증하는 기존
단계를 재사용한다. 재개할 때마다 저장 JSON만 믿지 않고 정확한 GitHub Run과 Artifact를
다시 조회한다. 기존 Run이 확인되지 않는 Dispatch Intent는 자동 재전송하지 않으며,
명시 재시도도 동일 TAKE Run 부재를 사람이 확인한 뒤에만 허용한다.

E2E Script의 일반 오류는 `E2E_FAILED`와 Sanitized Evidence로 닫힌다. 그러나 Process를
강제 종료해 `ATTACK_STARTED` 같은 중간 상태만 남긴 경우에는 공격이 일부 실행됐는지
자동으로 단정할 수 없으므로 범용 자동 재개를 보증하지 않는다. 이때 Runtime 상태와
Evidence를 보존하고 원격 Shuffle·GitHub 상태를 운영자가 확인한 뒤 복구 방향을 정한다.

---

## 13. 계획된 파일 변경 장부

이 절은 Target과 구현 추적표다. 파일 존재와 정적 Test 통과는 Runtime Gate 완료와
구분하며, 체크되지 않은 Gate를 구현 완료로 해석하지 않는다.

### 13.1 Terraform Repository

| 파일 | 예정 작업 |
|---|---|
| CAPITAL-ONE-SOC-E2E-BLUEPRINT.md | 이 설계 기준 |
| tools/Start-SocLab.ps1 | 통합 시작, READY, TAKE 발급 |
| tools/Stop-SocLab.ps1 | Process와 Runtime Secret 정리 |
| tools/Start-WazuhPushShadowBridge.ps1 | STS 갱신, Heartbeat, 상태 출력 보강 |
| foundation/wazuh.tf | Reader Role에 Push DLQ 상태 조회만 허용 |
| foundation/outputs.tf | 비민감 Primary Push DLQ URL Output |
| observability/scenarios/Invoke-CapitalOneBaseline.ps1 | X-SOC-TAKE-ID, 공격/차단 기대 모드 |
| observability/scenarios/Test-CapitalOneContainment.ps1 | Workload·IAM 영향 차단과 격리 Rollback 검사로 재설계 |
| observability/scenarios/Invoke-CapitalOneSocE2E.ps1 | Containment·조사·Remediation·Recovery Orchestration으로 재설계 |
| observability/wazuh/integrations/custom-shuffle-soc | Sanitized Alert Sender |
| observability/wazuh/templates/shuffle-integration.xml | Secret 없는 Rule 100103 Filter |
| observability/wazuh/*.schema.json | Alert, READY, Evidence Schema |
| observability/shuffle/apps/aws-topology-soc-validator/1.0.0 | 입력을 Code로 실행하지 않는 조직 전용 Validator App |
| observability/shuffle/apps/aws-topology-soc-github-dispatcher/2.0.0 | Target: API 2026-03-10의 HTTP 200 Run Details 계약과 고정 대상 Dispatcher |
| tools/Build-ShuffleSocAppBundle.ps1 | 두 Private App 단위 Test 후 Hash Manifest와 Upload ZIP 생성 |
| tools/Install-ShuffleSocAppBundle.ps1 | 명시적 승인과 DPAPI API Key로 두 App을 조직에 Upload |
| tests/*soc* | 정적 계약, Secret, 중복, 실패 경계 Test |

Gate B4를 닫기 전 Terraform Resource 변경:

- 새 Resource 추가 없음
- 기존 Reader IAM Policy에 DLQ 상태 조회 2개 Action만 추가
- 기존 Foundation Output에 DLQ URL 추가
- 기존 Foundation Push Resource 재사용
- 다른 Source Push 전환 금지

Gate B6 이후 별도 검토 대상:

- EKS VPC CNI Network Policy enforcing 설정과 Rollback
- 공유 Role의 `validation/*` 임시 Deny 실행 경계 또는 DVWA 전용 Role·Node
- 어떠한 Apply도 Fresh Plan과 명시적 사용자 승인 없이 실행하지 않음

### 13.2 DVWA Repository

| 파일 | 예정 작업 |
|---|---|
| dvwa/includes/dvwaAudit.inc.php | 검증된 TAKE_ID 감사 필드 |
| tests/test_audit_log.php | 허용/거부, Secret 비기록 Test |
| .github/workflows/soc-quarantine-dvwa.yml | Target: 고정 DVWA NetworkPolicy Containment |
| .github/workflows/soc-remediate-dvwa.yml | Target: low → impossible 설정 Remediation |
| .github/workflows/soc-reset-dvwa.yml | Target: 설정·IAM·Quarantine 순서를 포함한 수동 Reset orchestration |
| .github/scripts/update-dvwa-security-level.py | 정확한 단일 값 전이 |
| deploy/dvwa/templates/*networkpolicy* | Target: 고정 Label의 가역적 Quarantine |

### 13.3 Local Wazuh Host

| 위치 | 예정 작업 |
|---|---|
| config/wazuh_cluster/wazuh_manager.conf | custom integration Rule 100103 Filter |
| config/wazuh_cluster/integrations/ | versioned Script 배치 |
| Docker Compose SOC override | Integration과 Runtime Secret Read-only Mount |
| capital_one_rules.xml | TAKE_ID를 조건으로 요구하지 않고 기존 탐지 유지 |

### 13.4 Evidence

    C:\Users\Unoh\Documents\aws-topology-evidence\<take_id>\

예정 구조:

    source/
      client/
        capital-one-baseline.json
    soc/
      00-ready.json
      01-attack.json
      02-wazuh-alerts.json
      03-shuffle-executions.json
      04-containment.json
      05-incident-timeline.json
      06-remediation-run.json
      07-remediation-transition.json
      08-argocd-deploy.json
      09-reattack.json
      10-normal-function.json
      11-recovery.json
      12-reset.json
      manifest.json
      SHA256SUMS

모든 파일은 Sanitized Schema를 사용한다. 자동 생성 manifest와 SHA256SUMS는 `soc/`
직속 파일만이 아니라 TAKE 전체를 상대 경로와 SHA-256으로 연결한다. 최종 Secret
Scan도 TAKE 전체를 대상으로 한다. 화면 캡처는 별도 report-assets에 두므로 이 자동
manifest의 범위가 아니며, 보고서 채택 시 별도 Asset Index에서 출처와 Hash를 관리한다.

---

## 14. 구현 Gate

### Gate B0 — Current Response Contract

- [x] `low → impossible`을 Remediation으로 재분류 — 2026-08-18
- [x] Workload·IAM 영향 Containment와 느린 조사 분리 — 2026-08-18
- [x] 공유 Role 전체 자동 Deny 금지·Reset 순서 확정 — 2026-08-18
- [x] Shuffle Cloud 배치 결정 — 2026-08-18
- [x] 기존 미커밋·미추적 파일 보존 확인 — 2026-08-18

### Gate B1 — Local Safety

- [x] Wazuh Port Local-only 확인 — 2026-08-18 Runtime
- [ ] 초기 Credential 교체
- [ ] Secret 저장·복호화·삭제 Test
- [ ] Git과 Evidence Secret Scan

### Gate B2 — TAKE Contract

- [ ] Runner Header
- [ ] DVWA 감사 Event
- [ ] Lambda 전달
- [ ] Rule 100103은 TAKE 없이도 탐지
- [ ] 잘못된 TAKE의 자동 대응 거부

### Gate B3 — One-command READY

- [ ] Start-SocLab 1회
- [ ] Bridge STS 자동 갱신
- [ ] Heartbeat
- [ ] Rule 100102 Safe Probe
- [ ] READY/DEGRADED/FAILED 상태

### Gate B4 — Rule 100103 반복 검증

- [ ] observe_only TAKE 3회
- [ ] Take별 공격 Event 2, Alert 2
- [ ] 정상 숫자 IP 대조군 Alert 0
- [ ] Source Event → Wazuh Alert 지연 기록
- [ ] 누락 0, 동일 event_id 중복 0

### Gate B5 — Shuffle Dry Run

- [ ] Sanitized Schema Capture
- [ ] 금지 필드 0
- [ ] 잘못된 Account/Scenario/Rule/TAKE 거부
- [ ] Webhook Required Header 정상값 수락·잘못된 값 거부
- [ ] 같은 Execution Argument를 Execute API로 동시 10회 Stress
- [ ] raw keys_existed에 정확한 Dedupe Key 10개
- [ ] 신규 Claim 1, 기존 Claim 9
- [ ] GitHub Stub 호출 정확히 1회
- [ ] 실제 GitHub 호출 0
- [ ] Datastore 원자성 Runtime 판정
- [ ] 실제 GitHub Response Dispatch 0

### Gate B6 — Workload Containment

- [ ] EKS Network Policy enforcing Runtime 확인
- [ ] 고정 Namespace·DVWA Label 외 Target 거부
- [ ] Quarantine 정확한 Diff·Commit·Argo Revision
- [ ] 공격 경로 차단·필요 관측 경로 유지
- [ ] 다른 Namespace·Workload 영향 0
- [ ] Idempotency·Rollback Runtime

### Gate B7 — IAM Impact Containment

- [ ] 공유 Role Blast Radius와 현재 Permission Inventory
- [ ] `validation/*` 임시 Explicit Deny의 정확한 Target·Rollback
- [ ] 다른 Karpenter/EKS 동작 영향 없음
- [ ] 기존 Credential의 Lab Object 추가 접근 실패
- [ ] 전용 Principal이 아니면 전체 자동 Containment 거부
- [ ] 적용·해제 주체·시각·Policy Hash Evidence

### Gate B8 — Remediation and Recovery

- [ ] `low → impossible` 정확한 한 Diff와 Remediation Artifact
- [ ] 정확한 Commit SHA Synced·Healthy·새 Pod Ready
- [ ] NetworkPolicy와 무관한 애플리케이션 Negative Test
- [ ] 정상 로그인·허용 기능 유지
- [ ] Terraform IAM·IMDS 영구 복구와 기존 Credential `AccessDenied`
- [ ] 임시 격리 해제와 관찰창 무재발

### Gate B9 — Retake Reset

- [ ] 수동 Workflow만 실행 가능
- [ ] Quarantine 유지 중 impossible → low
- [ ] low이면 0-change
- [ ] 정확한 Reset SHA 배포
- [ ] Lab IAM 권한만 복원
- [ ] 공격·Reset Process의 임시 AWS Credential 환경변수 잔존 없음
- [ ] 이번 TAKE의 Alarm `ALARM → OK` History와 현재 `OK`
- [ ] 새 Pod·Wazuh·Bridge·새 TAKE READY 뒤 Quarantine 마지막 해제
- [ ] 기존 TAKE Evidence 보존·새 TAKE 독립성

### Gate B10 — 최종 E2E

- [ ] 촬영 장면 처음부터 끝까지 1회 성공
- [ ] 실패 지점 없음
- [ ] 모든 주요 지연시간 기록
- [ ] 각 단계의 Dispatch·Commit Cardinality가 계약과 일치
- [ ] Quarantine·Remediation Commit SHA=각 Argo Revision
- [ ] Containment·Investigation·Remediation·Recovery를 구분한 재공격 실패와 정상 기능 유지
- [ ] Evidence Manifest와 SHA256SUMS

---

## 15. 사용자 완료 조건 Traceability

| 사용자 조건 | 설계 위치 | 완료 Evidence |
|---|---|---|
| Start-SocLab 1회와 READY | 8, Gate B3 | 00-ready.json |
| Rule 100103 3회, 누락/중복 없음 | 7.5, Gate B4 | 02-wazuh-alerts.json |
| 빠른 키는 TAKE_ID | 2.2, 6 | Active TAKE + Alert |
| Rule 100103만 Sanitized 전달 | 2.4, 7.6 | Payload Capture + Secret Scan |
| 허용값과 TAKE 중복 차단 | 7.7, Gate B5 | Shuffle Execution 10회 Stress |
| Workload 격리 | 7.9, Gate B6 | Policy·Argo·Deny/Allow·Rollback Evidence |
| 공유 Role 영향 제한 | 7.9, Gate B7 | IAM Diff·AccessDenied·Blast Radius Evidence |
| low → impossible Remediation | 7.10, Gate B8 | Git Diff·Argo Revision·App Negative Test |
| 수동 Reset만 허용 | 7.11, Gate B9 | Reset Journal·새 TAKE·Quarantine release |
| E2E 지연·SHA·결과 기록 | 13.4, Gate B10 | manifest.json |
| 실제 사용자 장면만 완료 | 1.3, Gate B10 | 최종 Rehearsal Bundle |

---

## 16. 확정 결정과 구현 전 확인

### Decision D1 — Shuffle 배치

상태:

    CONFIRMED — Shuffle Cloud — 2026-08-18

확정 근거와 Local 대안의 차이:

| 선택 | 장점 | 비용/위험 |
|---|---|---|
| Cloud | 설치가 작고 E2E에 집중 | 외부 전송, 계정/Plan/인터넷 의존 |
| Local | Alert가 노트북 밖으로 안 나감 | 두 번째 OpenSearch, RAM/Disk, 복구 부담 |

이 결정만으로 Production Dispatch를 활성화하지 않는다. Sanitized Payload와 Gate B5,
고정 Quarantine Target, NetworkPolicy enforcement를 확인한 뒤에만 연결한다.

### 이미 확정된 결정

- 대표 시나리오: Capital One 기반 DVWA Command Injection 각색
- 즉시 Containment: DVWA Workload Quarantine
- IAM: 공유 Role은 `validation/*` 영향 차단 또는 사람 승인, 전용 Principal만 전체 Containment
- Remediation: `defaultSecurityLevel low → impossible` 보안 설정 패치
- Reset: 별도 수동 절차, Quarantine 마지막 해제
- 빠른 탐지: Rule 100103
- 빠른 사건 키: 사전 허용된 TAKE_ID
- 다른 네 Source: 기존 10분 Poll 유지
- 노트북 Off, 24시간 운영: 범위 밖

---

## 17. 현행 정합성 Checklist

다음 설계 조건을 확인해 현행 Target을 정리했다. Runtime 성공 여부는 Gate B1~B10의
미완료 체크박스로 별도 관리한다.

- [x] 이 설계가 사용자가 촬영하려는 장면과 같다.
- [x] Rule Alert 2건과 대응 1건의 설명 기준이 명시됐다.
- [x] 빠른 Push와 5-Source 조사 Poll의 역할이 분리됐다.
- [x] Containment와 `low → impossible` Remediation이 분리됐다.
- [x] Workload와 IAM 영향 차단의 Target·Blast Radius가 분리됐다.
- [x] 공유 Node Role 전체 자동 Deny를 금지했다.
- [x] CloudTrail eventID를 빠른 대응 키로 기다리지 않는다.
- [x] Wazuh는 전체 Alert가 아니라 최소 Schema만 외부로 보낸다.
- [x] Shuffle Exactly-once를 문서만 믿지 않고 Stress Test한다.
- [x] 각 실행 계층이 고정 Target과 상태 전이를 다시 검증한다.
- [x] Argo Healthy뿐 아니라 정확한 Commit SHA를 확인한다.
- [x] Reset이 자동 대응에서 분리됐다.
- [x] Reset은 Quarantine을 마지막에 해제하고 Evidence를 보존한다.
- [x] 실제 E2E 전에는 완료라고 표현하지 않는다.

---

## 18. 공식 근거

현재 확인, 명시적 게시일이 없는 문서는 제품 동작이 바뀔 수 있으므로 구현 시 다시
확인한다.

- [Wazuh External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
  - Rule ID 필터, Shuffle Webhook, Custom Integration Script
- [Wazuh integration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
  - rule_id, timeout, retries, custom- 이름 규칙
- [Shuffle Workflows](https://shuffler.io/docs/workflows)
  - Webhook, 노드, 조건, 실행 구조
- [Shuffle Triggers](https://shuffler.io/docs/triggers)
  - Webhook과 Required Header
- [Shuffle Datastore API](https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md)
  - Persistent Cache와 keys_existed 응답
- [Shuffle Configuration](https://github.com/Shuffle/Shuffle-docs/blob/master/docs/configuration.md)
  - Self-hosted 최소 2 vCPU, RAM 8GB, SSD 100GB와 OpenSearch 부담
- [GitHub Create a workflow dispatch event — API 2026-03-10](https://docs.github.com/en/rest/actions/workflows?apiVersion=2026-03-10#create-a-workflow-dispatch-event)
  - 고정 Workflow/Ref/Input, Fine-grained Token Actions write
- [GitHub workflow concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
  - 동일 상태 변경의 동시 실행 제한
- [GitHub deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
  - Private Repository의 Required Reviewer Plan 제한
- [AWS CLI describe-alarm-history](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/describe-alarm-history.html)
  - StateUpdate 시간창 조회와 `HistoryData`의 이전·새 Alarm 상태
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  - Detect·Respond·Recover를 조직 위험 관리에 통합
- [CISA Incident Response Playbook](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
  - Containment, 증거 보존, Eradication·Recovery와 재진입 모니터링
- [AWS EKS Incident response and forensics](https://docs.aws.amazon.com/eks/latest/best-practices/incident-response-and-forensics.html)
  - Pod·Node 격리, NetworkPolicy, Credential 대응과 증거 보존
- [AWS Security Incident Response — Contain](https://docs.aws.amazon.com/security-ir/latest/userguide/contain.html)
  - 단계적·가역적 Containment와 운영 영향 고려
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
  - NetworkPolicy를 강제하는 네트워크 구현이 없으면 정책이 효과를 내지 않음
- [EKS VPC CNI Network Policy](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html)
  - EKS Network Policy 기능의 명시 구성·검증
- [Argo CD Automated Sync](https://argo-cd.readthedocs.io/en/latest/user-guide/auto_sync/)
  - Git 변경 기반 자동 Sync
- [Argo CD app wait](https://argo-cd.readthedocs.io/en/latest/user-guide/commands/argocd_app_wait/)
  - Sync와 Health 대기

---

## 19. 다음 행동

대응 정합성 정리는 완료됐다. 다음 구현 순서는 다음 하나에서 재개한다.

1. 현재 Git·Wazuh·Bridge·Daily Runtime을 다시 확인한다.
2. 실제 AWS `command.execution → Rule 100103` 3 TAKE를 `observe_only`로 검증한다.
3. Offline Catch-up·DLQ·DVWA Poll Rollback을 검증한다.
4. 그 뒤에만 Shuffle·NetworkPolicy·IAM·Remediation Gate로 이동한다.

Gate를 건너뛰거나, 개별 구성요소 존재만으로 다음 Gate를 완료 처리하지 않는다.
