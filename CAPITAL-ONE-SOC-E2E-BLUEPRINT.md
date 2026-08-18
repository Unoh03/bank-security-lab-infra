# Capital One 기반 SOC 자동화 E2E Blueprint

> 상태: **FROZEN v1.2 — 구현 기준, E2E 미완료**
>
> 기준 시각: 2026-08-18 KST
>
> Freeze 기록: 사용자가 전체 흐름 검토와 Shuffle Cloud 결정을 마친 뒤
> 2026-08-18의 명시적 진행 지시로 동결했다.
>
> v1.1 보정: READY의 DLQ=0 검사를 광범위한 Bootstrap 권한으로 우회하지 않도록,
> 기존 Wazuh Reader Role에 Primary Push DLQ의 `GetQueueAttributes/GetQueueUrl`만
> 추가하고 DLQ URL을 비민감 Output으로 제공한다. 수신·삭제 권한은 추가하지 않는다.
>
> v1.2 보정: 구조 Schema와 운영 Allowlist를 분리하고, `observe_only`는 Dedupe 전에
> 종료한다. Gate B5 원자성 Stress는 공식 Execute API로 수행하고 Webhook Header는
> 별도 Smoke로 검증한다. GitHub Artifact에는 최초 Dispatch Alert의
> `alert_body_sha256`를 보존한다.
>
> 이 문서는 대표 시연의 구성요소, 계약, 실패 경계, 검증 Evidence를 동결한 단일
> 구현 기준이다. 동결은 설계 승인이지 구현 완료가 아니다. 현재 Runtime은 이 문서에
> 고정되지 않으므로 각 Gate에서 다시 검증하며, 별도 다음 작업 전에는 Goal 생성,
> Shuffle 연동, GitHub Workflow 추가, Terraform Apply, 실제 공격을 시작하지 않는다.

---

## 0. 이 문서의 권위와 사용법

### 0.1 단일 구현 기준

이 문서가 동결된 뒤에는 다음 문서를 구현의 직접 지시서로 사용하지 않는다.

- CAPITAL-ONE-SOC-DEMO-PLAN.md
- CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md
- observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md

위 문서는 결정 과정과 과거 Gate의 근거로 보존한다. 서로 충돌하면 이 Blueprint가
대표 E2E의 최신 기준이다. 단, 실제 Source와 Runtime Evidence가 이 문서와 충돌하면
Source와 Runtime이 우선하며 Blueprint를 먼저 수정한다.

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
- GitHub의 제한된 low → impossible 변경
- Argo CD의 정확한 Commit 배포 확인
- 재공격 실패, 정상 기능 유지, 수동 Reset
- 보고서용 Evidence

제외:

- WAF, CloudTrail, ALB, CloudFront의 Push 전환
- 노트북이 꺼진 동안의 탐지와 Offline Catch-up
- 24시간 운영과 고가용성
- Wazuh의 AWS 이전
- 두 번째 공격 시나리오
- 광범위한 IAM 격리나 AWS 자원 자동 차단
- 추가 Dashboard 미관 개선
- 실제 기업의 범용 치료 코드를 가장하는 것

---

## 1. 동결할 사용자 장면

### 1.1 한 문장 목표

노트북에서 SOC를 한 번 시작한 뒤, 교육용 DVWA 침투가 저지연으로 탐지되고,
허용된 자동 대응만 GitOps로 배포되어 같은 공격은 실패하지만 정상 기능은 유지되는
장면을 처음부터 끝까지 재현한다.

### 1.2 최종 장면

    사용자: Start-SocLab 1회 실행
      → Wazuh, Bridge, Shuffle 연동, GitHub, Argo 사전 상태 확인
      → READY + ACTIVE_TAKE_ID
    사용자: 승인된 Capital One 실습 공격 실행
      → DVWA가 2개의 command.execution 감사 Event 생성
      → CloudWatch Logs → Lambda → SQS → Local Bridge
      → Wazuh Rule 100103 Alert 2건
      → Shuffle은 같은 TAKE_ID를 한 사건으로 분류
      → GitHub containment Workflow 호출은 정확히 1회
      → deploy/dvwa/values.yaml의 low만 impossible로 변경
      → 일반 Push로 main에 새 Commit 생성
      → Argo CD가 그 Commit SHA를 Synced + Healthy로 배포
      → 새 Pod Ready
      → 동일 공격 재시도 실패
      → 정상적인 숫자 IP Ping과 로그인은 유지
    사용자: 필요할 때 별도 Reset Workflow 수동 실행
      → impossible만 low로 복원

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
| 빠른 대응 경로 | 수초 단위 탐지와 자동 Containment | DVWA Push → Rule 100103 |
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
| GitHub containment dispatch | 1 |
| low → impossible Commit | 1 |

두 Alert를 중복이라고 삭제하면 안 된다. 서로 다른 Source Event지만 동일한 사건이므로
Wazuh에는 둘 다 보존하고, Shuffle의 대응만 TAKE_ID로 한 번 수행한다.

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
2. GitHub Workflow에서 상태 전이와 변경 파일을 다시 검증

Shuffle 공식 API는 Set Cache 응답에서 기존 Key 여부를 반환한다. 그러나 동시 실행의
원자적 exactly-once 보장은 문서만으로 확정하지 않는다. 같은 Payload 10개를 동시에
보내 GitHub 호출 1회를 Runtime으로 증명하기 전에는 완료가 아니다.

### 2.6 Reset은 SOAR가 호출하지 않는다

Reset은 별도 workflow_dispatch만 허용한다. 현재 Private + GitHub Free 저장소에서는
Environment Required Reviewer를 강제할 수 없으므로 `environment:`를 승인 장치로 쓰지
않는다. 사용자의 Reset Script 직접 실행과 정확한 확인 문자열, impossible → low 전이
검증을 현재 승인 경계로 삼는다.

---

## 3. As-built Snapshot

아래는 2026-08-18 조사 시점의 상태다. 이후에는 다시 확인해야 한다.

| 영역 | 확인 상태 | 근거와 의미 |
|---|---|---|
| Daily Runtime | Runtime 확인 | minimal + capital-one-lab, Terraform State에 Daily 자원 존재 |
| Watchdog | Runtime 확인 | Active, On, 해당 Session Hard Deadline은 2026-08-18 03:47 KST |
| Foundation Push | Runtime/State 확인 | DVWA 1 Source, safe_allowlist, raw message 미저장, SQS/DLQ/Lambda 활성 |
| 5-Source Poll | Source 확인 | CloudTrail, ALB, WAF, DVWA, CloudFront를 10분 주기로 구성 |
| Wazuh | Runtime 확인 | Manager, Indexer, Dashboard 4.14.7 실행 중 |
| Wazuh Rule | Source 확인 | 100101, 100102, 100103, 100100 존재 |
| Rule 100103 | 부분 Runtime 확인 | 1 Alert 확인. 3회 연속 저지연 검증은 아님 |
| Local Bridge | 부분 Runtime 확인 | Spool/Ledger/Live JSONL과 SQS 삭제 후 보존 구현. STS 자동 갱신 없음 |
| DVWA 감사 Event | Source 확인 | 안전 필드와 request_id는 있으나 take_id를 생성하지 않음 |
| Baseline Runner | Source/Runtime 확인 | 공격 성공과 가짜 S3 read 확인. HTTP Header로 TAKE_ID를 보내지 않음 |
| Shuffle | 미구현 | 설치·계정·Workflow·Credential 없음 |
| GitHub containment/reset | 미구현 | 현재 해당 Workflow 없음 |
| Argo CD | Source/과거 Runtime 확인 | main 자동 Sync, prune, selfHeal. 정확한 SHA 확인 로직은 daily-up에 존재 |

### 3.1 Rule 100103의 정확한 현재 Evidence

보존 Alert 1건에서 확인된 시각:

- Source Event: 2026-08-17 13:41:54Z
- Bridge 수신: 2026-08-17 14:20:58Z
- Wazuh Alert 처리: 2026-08-17 14:20:59Z

이는 Rule 100103이 실제 Event를 탐지할 수 있다는 증거다. Bridge가 공격 뒤 늦게
수신했으므로 저지연 E2E 증거로 사용하지 않는다.

### 3.2 현재 주요 공백

- Start-SocLab 통합 시작점 없음
- Bridge의 1시간 STS Session 자동 갱신 없음
- Bridge Heartbeat와 READY 계약 없음
- TAKE_ID가 DVWA Event에 들어가지 않음
- Wazuh → Shuffle Sanitizer와 Webhook 없음
- Shuffle의 Allowlist, Dedup, GitHub 호출 없음
- GitHub의 제한된 Containment와 Reset 없음
- 정확한 Commit을 기다리는 전용 E2E Verifier 없음
- 재공격 실패와 정상 기능 유지 자동 판정 없음

---

## 4. Target Topology

    ┌──────────────────────────── Laptop / Student SOC ────────────────────────────┐
    │                                                                              │
    │  Start-SocLab ── READY/ACTIVE_TAKE ── Capital One Runner                     │
    │       │                                      │ X-SOC-TAKE-ID                 │
    │       ├─ Docker Wazuh Manager/Indexer/Dashboard                              │
    │       ├─ Local Bridge + Heartbeat + STS Rotation                             │
    │       ├─ Wazuh Custom Integration ───────────────┐                           │
    │       └─ E2E Evidence Collector                  │ sanitized HTTPS            │
    └─────────────────────────────────────────────────┼────────────────────────────┘
                                                      ▼
    User → CloudFront/WAF/ALB → EKS/DVWA → CloudWatch Logs
                                      │
                                      ▼
                         Subscription → Lambda Allowlist
                                      │
                                      ▼
                               SQS + DLQ
                                      │
                                      ▼
                         Local Bridge → Wazuh Rule 100103
                                                      │
                                                      ▼
                                         Shuffle Webhook / Workflow
                                      validate → allow → dedupe
                                                      │ exactly once
                                                      ▼
                                         GitHub workflow_dispatch
                                      values.yaml low → impossible
                                                      │ normal commit/push
                                                      ▼
                                         Argo CD main auto-sync
                                                      │
                                                      ▼
                                           EKS new Pod Ready

    조사·보존 경로:
    CloudTrail + WAF + ALB + CloudFront + DVWA
      → 기존 S3/CloudWatch 원본
      → Wazuh 10분 Poll
      → 사후 상관분석과 보고서 Evidence

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
8. Shuffle Workflow 활성, GitHub Workflow 존재, Argo 현재 상태를 읽기 전용 확인한다.
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
8. 첫 Alert만 Dedup Key 신규가 되어 containment를 진행한다.
9. 두 번째 Alert는 DUPLICATE_SUPPRESSED로 종료한다.
10. GitHub는 지정 Workflow와 main만 호출받는다.
11. Workflow는 low → impossible 외의 변경을 거부하고 일반 Push한다.

### 5.3 배포와 검증

1. workflow_dispatch의 Run ID를 기록한다.
2. Workflow 완료와 결과 Artifact를 조회한다.
3. Artifact의 Commit SHA와 TAKE_ID를 검증한다.
4. Argo Application을 Hard Refresh한다.
5. Synced, Healthy, status.sync.revision=Commit SHA를 동시에 확인한다.
6. Error Condition이 없어야 한다.
7. Deployment Rollout 완료와 새 Pod UID/Template Hash를 확인한다.
8. Pod의 DEFAULT_SECURITY_LEVEL이 impossible인지 확인한다.
9. 같은 Payload를 다시 보내 invalid IP가 반환되고 IMDS Marker가 없음을 확인한다.
10. 숫자 IP Ping과 로그인은 계속 성공해야 한다.
11. 재공격과 정상 Ping 뒤 최소 120초 동안 같은 TAKE의 Rule 100103 Alert가 정확히
    기존 2개로 유지되는지 확인한다.
12. 같은 관찰창 뒤 Shuffle Outcome은 기존 2개 그대로이고 GitHub containment Run도
    기존 1개뿐인지 다시 확인한 뒤에만 `REATTACK_BLOCKED`로 전이한다.

### 5.4 수동 Reset

1. 사용자가 `Invoke-SocLabReset.ps1`에 정확한 확인 문자열을 입력해 시작한다.
2. Script는 해당 TAKE의 배타적 Lock을 획득하고 이전 E2E Manifest·SHA256SUMS와
   GitHub의 정확한 Containment Run·Artifact를 다시 검증한다.
3. Workflow는 impossible → low만 허용한다.
4. 이미 low면 변경 없이 성공한다.
5. 새 Reset Commit도 일반 Push한다.
6. Argo가 정확한 Reset SHA를 배포한 뒤에만 다음 TAKE를 발급한다.
7. Dispatch Intent, 정확한 Run·Transition, Argo 배포, Allow 제거를 단계별 Evidence로
   저장한다. TAKE 상태와 Active Session 상태 사이에는 Journal을 먼저 기록하므로 한쪽만
   갱신된 채 종료돼도 재실행 시 같은 전이를 완성한다.
8. 진행 중인 containment/Reset 상태에서는 Stop-SocLab이 Runtime 복구 상태 삭제를
   거부한다. Stop도 같은 TAKE Lock과 상태 일치·Journal 부재를 확인한 뒤에만 Runtime을
   정리한다. 운영자가 마지막 Evidence를 확인해 Reset 재개 또는 수동 복구를 결정한다.
9. `gh workflow run`의 성공 여부가 불명확한 중단에서는 자동 재전송하지 않는다. 동일
   TAKE Run 부재를 운영자가 GitHub에서 확인한 경우에만
   `-ConfirmRetryUndispatched 'RETRY UNDISPATCHED RESET'`으로 한 번 명시 재시도한다.
10. 공격 Evidence에서 임시 AWS Credential 환경변수 정리를 확인하고 Reset Process에도
    같은 환경변수가 없는지 재검사한다. 값은 출력하거나 Evidence에 저장하지 않는다.
11. 단순 현재 상태 조회가 아니라 이번 공격 시작 이후 Alarm History의 `ALARM → OK`와
    현재 `OK`를 함께 확인한다. `SetAlarmState`로 상태를 강제하지 않는다.
12. Reset은 기존 TAKE를 `CLOSED`로 끝낼 뿐 새 TAKE를 발급하지 않는다. 즉시 재촬영할 때는
    `Stop-SocLab -StopWazuh`로 기존 Runtime을 정리하고 `Start-SocLab`을 다시 실행한다.

---

## 6. TAKE_ID와 상태 수명주기

### 6.1 상태

    ISSUED
      → READY
      → ATTACK_STARTED
      → DETECTED
      → RESPONSE_DISPATCHED
      → COMMITTED
      → DEPLOYED
      → REATTACK_BLOCKED
      → E2E_SUCCEEDED

실패 시:

    어느 상태에서든 → E2E_FAILED

Reset:

    E2E_SUCCEEDED 또는 E2E_FAILED
      → RESET_REQUESTED
      → RESET_COMMITTED
      → RESET_DEPLOYED
      → CLOSED

### 6.2 Active TAKE 계약

로컬 Active TAKE 파일:

    %LOCALAPPDATA%\aws-topology\soc-runtime\active-take.json

필수 필드:

| 필드 | 규칙 |
|---|---|
| schema_version | 1 |
| take_id | 엄격한 정규식 |
| scenario_id | CAPITAL-ONE |
| response_mode | observe_only 또는 contain |
| issued_at_utc | UTC ISO 8601 |
| expires_at_utc | 발급 뒤 최대 2시간 |
| status | 위 상태 중 하나 |
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
| Git Commit SHA | 대응 코드 상태 식별 |
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

    CAPITAL-ONE-SOC-CONTAINMENT-v1

노드 순서:

1. Wazuh Alerts Webhook
2. Required Header 검증
3. 고정 Private Validator App에서 정확한 Schema와 Body SHA-256 검증
4. Account, Region, Scenario, Rule Allowlist
5. TAKE Allowlist 조회
6. 만료와 response_mode 확인
7. observe_only면 Outcome Evidence 후 종료
8. contain일 때만 TAKE Dedup Key 생성
9. Set Cache raw `keys_existed`의 정확한 Key와 existed 분기
10. contain이고 신규 TAKE면 고정 GitHub Workflow 호출
11. GitHub가 반환한 정확한 Run ID 기록
12. 결과를 Evidence API/로컬 Collector가 조회할 수 있게 보존

Shuffle은 Dispatch 수락까지만 판정한다. GitHub Run 완료, 정확한 Commit SHA, Argo CD
배포 완료는 로컬 E2E Orchestrator가 같은 Run ID와 TAKE_ID로 이어서 검증한다. 이 경계로
Shuffle Action을 장시간 Poll 상태에 두지 않으면서도 전체 자동화 검증은 유지한다.

Shuffle outgoing branch는 자동 `else`가 아니므로 `observe_only`와 `contain` 조건을
각각 명시한다. `observe_only`는 Dedupe Key를 소비하지 않는다.

Datastore Key:

    Allow: soc:v1:allow:primary-lab:CAPITAL-ONE:<take_id>
    Dedupe: soc:v1:response:primary-lab:CAPITAL-ONE:<take_id>
    Outcome: soc:v1:outcome:<take_id>:<raw_message_sha256>

실행 결과:

| 결과 | 의미 | GitHub 호출 |
|---|---|---:|
| REJECTED_SCHEMA | 계약 불일치 | 0 |
| REJECTED_ALLOWLIST | 허용 대상 아님 | 0 |
| REJECTED_TAKE | 미등록 또는 만료 | 0 |
| OBSERVE_ONLY | 탐지 반복 검증 | 0 |
| DUPLICATE_SUPPRESSED | 같은 TAKE의 후속 Alert | 0 |
| RESPONSE_DISPATCHED | 첫 유효 Alert | 1 |
| RESPONSE_FAILED | GitHub Dispatch 응답 실패, 수락 여부 미확정 | 확인된 성공 0, 자동 재호출 금지 |

Wazuh HTTP 재시도와 Shuffle Workflow 재실행이 있어도 동일 TAKE의 GitHub 호출은
증가하면 안 된다.
`github_dispatch_count`는 `return_run_details=true`로 요청해 받은 양의
`workflow_run_id`로 확인된 성공 Dispatch만 센다. 네트워크
오류처럼 요청 수락 여부를 확정할 수 없는 실패는 0으로 기록하고 자동 재호출하지 않으며,
해당 TAKE 전체를 실패로 종료해 운영자가 GitHub Run을 별도로 대조한다.

### 7.8 Shuffle → GitHub

호출 대상은 다음 한 개로 고정한다.

    Repository: Unoh03/Uns-DVWA
    Workflow: .github/workflows/soc-contain-dvwa.yml
    Ref: main

허용 Input:

- take_id
- scenario_id=CAPITAL-ONE
- rule_id=100103
- alert_body_sha256

GitHub API `2026-03-10`의 Dispatch는 `ref`와 고정 Input만 받고 200 응답으로 Run ID와
Run URL을 돌려준다. Shuffle은 이 Run ID를 Outcome에 기록하고, E2E Orchestrator가
이후 GitHub·Argo 상태를 검증한다.

금지:

- 임의 Repository
- 임의 Workflow 파일
- 임의 Ref
- 수정할 Path나 목표 값을 Input으로 받는 것
- Shell Command를 Input으로 받는 것

Shuffle Credential:

- 한 Repository로 제한된 Fine-grained PAT
- Repository Actions: write
- 짧은 만료일과 회수 절차
- Contents: write를 Shuffle Token에 주지 않음
- 실제 파일 쓰기는 Workflow의 GITHUB_TOKEN contents: write만 사용
- Generic HTTP Header에 PAT을 직접 쓰지 않음
- `AWS Topology SOC GitHub Dispatcher 1.0.0`의 App Authentication으로 암호화 저장
- Private Dispatcher App 내부에서 Repository, Workflow, Ref, API URL을 고정
- Cloud Binding 검증은 Authentication 목록에서 App·Org·Active·Encrypted·Field Key만
  사용하고 Value를 출력·저장하지 않는다. 다만 Shuffle 공식 API에는 metadata-only
  Authentication endpoint가 없으므로 목록 응답 자체를 secret-bearing으로 취급한다.

### 7.9 Containment Workflow

파일:

    D:\DVWA\.github\workflows\soc-contain-dvwa.yml

Trigger:

    workflow_dispatch only

불변 조건:

- main에서만 실행
- 입력 정규식과 고정값 재검증
- 변경 가능 파일은 deploy/dvwa/values.yaml 하나
- 변경 가능 값은 defaultSecurityLevel: low → impossible 하나
- 이미 impossible이면 변경 없이 성공
- 다른 값이면 실패
- 변경 전후 Byte 비교에서 정확히 한 전이 외 차이가 있으면 실패
- git diff --name-only가 목표 파일 하나가 아니면 실패
- Force Push와 History Rewrite 금지
- Commit Message에는 TAKE_ID만 넣고 원본 Alert나 비밀은 넣지 않음
- 결과 Artifact에 before_sha, commit_sha, take_id, alert_body_sha256, changed,
  diff_sha256 저장

동시 실행:

    concurrency group: dvwa-security-level-transition
    cancel-in-progress: false

### 7.10 Reset Workflow

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
- Containment와 같은 concurrency group
- Force Push와 History Rewrite 금지
- Shuffle, Wazuh, 외부 Webhook이 호출할 수 없음
- Private Free에서 강제되지 않는 Environment Reviewer에 의존하지 않음
- 운영자의 Reset Script 직접 실행과 정확한 확인 문자열이 사람 승인 경계

### 7.11 GitHub → Argo CD → EKS

현재 Argo Application의 main 자동 Sync, prune, selfHeal을 재사용한다.

완료 조건은 네 항목을 동시에 만족해야 한다.

- status.sync.status=Synced
- status.health.status=Healthy
- status.sync.revision=<containment commit SHA>
- Error Condition 없음

추가:

- kubectl rollout status deployment/dvwa 성공
- 변경 전 Pod UID와 변경 후 Pod UID가 다름
- 새 Pod Ready
- Deployment Env DEFAULT_SECURITY_LEVEL=impossible

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
- contain 모드면 Production Export, Upload한 두 Private App의 Cloud ID/Binding,
  Active·Encrypted Dispatcher Authentication, 최신 Gate B5 Manifest 검증
- GitHub 지정 Workflow 존재 확인
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
| Shuffle | Workflow 활성, API 인증, Upload App ID/Binding, Dispatcher Authentication 상태·소속 검증 |
| GitHub | containment와 reset Workflow 존재 |
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

대표 E2E v1의 SOAR 배치는 **Shuffle Cloud로 확정한다.**

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
| GitHub Token 오류 | Alert 보존 | 미실행 | Shuffle Evidence | RESPONSE_FAILED |
| values가 low/impossible 외 | Alert 보존 | Workflow 실패 | Git 변경 없음 | INVALID_STATE |
| 예상 외 파일 Diff | Alert 보존 | Workflow 실패 | Git 변경 없음 | SCOPE_VIOLATION |
| Push 충돌 | Alert 보존 | Workflow 실패 | Force 금지 | PUSH_CONFLICT |
| Argo Revision 불일치 | Commit 존재 | 다음 단계 중단 | Git 보존 | DEPLOY_MISMATCH |
| Pod Ready 실패 | Commit 존재 | 재공격 금지 | K8s Evidence | ROLLOUT_FAILED |
| 재공격 성공 | E2E 실패 | 자동 추가 변경 금지 | Evidence 보존 | CONTAINMENT_FAILED |
| Reset 실패 | 기존 상태 유지 | 다음 TAKE 금지 | Evidence 보존 | RESET_FAILED |

재시도는 같은 TAKE로 GitHub Workflow를 자동 재호출하지 않는다. 운영자가 Evidence를
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
| observability/scenarios/Test-CapitalOneContainment.ps1 | 재공격 실패와 정상 기능 검사 |
| observability/scenarios/Invoke-CapitalOneSocE2E.ps1 | Workflow, Argo, Evidence 상태 Orchestration |
| observability/wazuh/integrations/custom-shuffle-soc | Sanitized Alert Sender |
| observability/wazuh/templates/shuffle-integration.xml | Secret 없는 Rule 100103 Filter |
| observability/wazuh/*.schema.json | Alert, READY, Evidence Schema |
| observability/shuffle/apps/aws-topology-soc-validator/1.0.0 | 입력을 Code로 실행하지 않는 조직 전용 Validator App |
| observability/shuffle/apps/aws-topology-soc-github-dispatcher/1.0.0 | GitHub 대상과 입력을 코드로 고정한 조직 전용 Dispatcher App |
| tools/Build-ShuffleSocAppBundle.ps1 | 두 Private App 단위 Test 후 Hash Manifest와 Upload ZIP 생성 |
| tools/Install-ShuffleSocAppBundle.ps1 | 명시적 승인과 DPAPI API Key로 두 App을 조직에 Upload |
| tests/*soc* | 정적 계약, Secret, 중복, 실패 경계 Test |

Terraform Resource 변경:

- 새 Resource 추가 없음
- 기존 Reader IAM Policy에 DLQ 상태 조회 2개 Action만 추가
- 기존 Foundation Output에 DLQ URL 추가
- 기존 Foundation Push Resource 재사용
- 다른 Source Push 전환 금지

### 13.2 DVWA Repository

| 파일 | 예정 작업 |
|---|---|
| dvwa/includes/dvwaAudit.inc.php | 검증된 TAKE_ID 감사 필드 |
| tests/test_audit_log.php | 허용/거부, Secret 비기록 Test |
| .github/workflows/soc-contain-dvwa.yml | low → impossible |
| .github/workflows/soc-reset-dvwa.yml | 수동 impossible → low |
| .github/scripts/update-dvwa-security-level.py | 정확한 단일 값 전이 |

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
      04-github-run.json
      05-git-transition.json
      06-argocd-deploy.json
      07-reattack.json
      08-normal-function.json
      09-reset.json
      manifest.json
      SHA256SUMS

모든 파일은 Sanitized Schema를 사용한다. 자동 생성 manifest와 SHA256SUMS는 `soc/`
직속 파일만이 아니라 TAKE 전체를 상대 경로와 SHA-256으로 연결한다. 최종 Secret
Scan도 TAKE 전체를 대상으로 한다. 화면 캡처는 별도 report-assets에 두므로 이 자동
manifest의 범위가 아니며, 보고서 채택 시 별도 Asset Index에서 출처와 Hash를 관리한다.

---

## 14. 구현 Gate

### Gate B0 — Blueprint Freeze

- [x] 사용자가 이 문서의 흐름을 검토하고 승인 — 2026-08-18
- [x] Shuffle Cloud 배치 결정 — 2026-08-18
- [x] 원래 요청과 역대조하여 미포함 범위 유지 확인 — 2026-08-18
- [x] 기존 미커밋·미추적 파일 보존 확인 — 2026-08-18

### Gate B1 — Local Safety

- [ ] Wazuh Port Local-only 확인
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

### Gate B6 — GitHub 제한 변경

- [ ] Dry-run에서 정확한 Diff
- [ ] low → impossible 1회
- [ ] impossible이면 0-change 성공
- [ ] 다른 파일/값/Ref 거부
- [ ] Force/History Rewrite 없음
- [ ] Result Artifact와 Commit SHA

### Gate B7 — Argo와 재공격

- [ ] 정확한 Commit SHA Synced
- [ ] Healthy, Error 없음
- [ ] 새 Pod Ready
- [ ] 동일 공격 실패
- [ ] 숫자 IP Ping과 로그인 유지

### Gate B8 — Reset

- [ ] 수동 Workflow만 실행 가능
- [ ] impossible → low
- [ ] low이면 0-change
- [ ] 정확한 Reset SHA 배포
- [ ] 공격·Reset Process의 임시 AWS Credential 환경변수 잔존 없음
- [ ] 이번 TAKE의 Alarm `ALARM → OK` History와 현재 `OK`
- [ ] 기존 TAKE `CLOSED` 후 새 Start로 새 TAKE 발급 가능

### Gate B9 — 최종 E2E

- [ ] 촬영 장면 처음부터 끝까지 1회 성공
- [ ] 실패 지점 없음
- [ ] 모든 주요 지연시간 기록
- [ ] GitHub 호출 1회
- [ ] Commit SHA=Argo Revision
- [ ] 재공격 실패와 정상 기능 유지
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
| low → impossible만 허용 | 7.9, Gate B6 | Git Diff + Workflow Artifact |
| 정확한 Commit 배포 후 재공격 실패 | 7.11, Gate B7 | Argo Revision + 07-reattack.json |
| 수동 Reset만 허용 | 7.10, Gate B8 | Reset Run + Commit |
| E2E 지연·SHA·결과 기록 | 13.4, Gate B9 | manifest.json |
| 실제 사용자 장면만 완료 | 1.3, Gate B9 | 최종 Rehearsal Bundle |

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

이 결정만으로 Shuffle 계정 생성, Region 선택, Webhook 생성, GitHub PAT 등록,
Wazuh 외부 전송을 시작하지 않는다. 해당 작업은 Blueprint Freeze 뒤 Gate별로 승인받는다.

### 이미 확정된 결정

- 대표 시나리오: Capital One 기반 DVWA Command Injection 각색
- 자동 대응: defaultSecurityLevel low → impossible
- Reset: 별도 수동 Workflow
- 빠른 탐지: Rule 100103
- 빠른 사건 키: 사전 허용된 TAKE_ID
- 다른 네 Source: 기존 10분 Poll 유지
- 노트북 Off, 24시간 운영: 범위 밖

---

## 17. Freeze Checklist

다음 설계 조건을 모두 확인해 v1.0을 동결했다. Runtime 성공 여부는 Gate B1~B9의
미완료 체크박스로 별도 관리한다.

- [x] 이 설계가 사용자가 촬영하려는 장면과 같다.
- [x] Rule Alert 2건과 대응 1건의 설명 기준이 명시됐다.
- [x] 빠른 Push와 5-Source 조사 Poll의 역할이 분리됐다.
- [x] CloudTrail eventID를 빠른 대응 키로 기다리지 않는다.
- [x] Wazuh는 전체 Alert가 아니라 최소 Schema만 외부로 보낸다.
- [x] Shuffle Exactly-once를 문서만 믿지 않고 Stress Test한다.
- [x] GitHub가 변경 대상과 상태 전이를 다시 검증한다.
- [x] Argo Healthy뿐 아니라 정확한 Commit SHA를 확인한다.
- [x] Reset이 자동 대응에서 분리됐다.
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
- [GitHub Create a workflow dispatch event](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)
  - 고정 Workflow/Ref/Input, Fine-grained Token Actions write
- [GitHub workflow concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
  - 동일 상태 변경의 동시 실행 제한
- [GitHub deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
  - Private Repository의 Required Reviewer Plan 제한
- [AWS CLI describe-alarm-history](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/describe-alarm-history.html)
  - StateUpdate 시간창 조회와 `HistoryData`의 이전·새 Alarm 상태
- [Argo CD Automated Sync](https://argo-cd.readthedocs.io/en/latest/user-guide/auto_sync/)
  - Git 변경 기반 자동 Sync
- [Argo CD app wait](https://argo-cd.readthedocs.io/en/latest/user-guide/commands/argocd_app_wait/)
  - Sync와 Health 대기

---

## 19. 다음 행동

Blueprint v1.0 Freeze는 완료됐다.

다음 별도 작업에서만 다음 순서로 진행한다.

1. 하나의 Goal을 생성한다.
2. 시작 시점의 Git, Wazuh, Daily Runtime, Shuffle Cloud 계정 상태를 다시 확인한다.
3. Gate B1 Local Safety부터 순서대로 구현한다.
4. 각 Gate의 Runtime Evidence가 없으면 다음 Gate를 완료 처리하지 않는다.

Gate를 건너뛰거나, 개별 구성요소 존재만으로 다음 Gate를 완료 처리하지 않는다.
