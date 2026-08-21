# Capital One 기반 SOC 시연 녹화 대본 v2

> **촬영 가능 조건:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)의
> 시연 시작조건을 실제 Runtime으로 모두 통과한 뒤
>
> **활성 Rule:** 조기탐지 `100110`, S3 침해확정 직접 탐지 Rule `100111`
>
> Rule `100103`은 일반 IMDS 관측용이며 본편 자동화 경로에 사용하지 않는다.
> Rule `100100/100104/100105/100109`는 활성 Rule에서 폐기됐다.

---

## 1. 영상이 증명할 것

> **공격의 Credential 접근 징후를 조기에 탐지해 Workload를 자동 격리하고, 뒤이어
> 보호 S3 Object 접근 성공을 별도 Rule로 확정해 자동으로 `low → impossible`을
> 배포한다. 관제자는 Dashboard에서 전체 공격 흐름을 조사해 최초 HTTP 진입점에 좁은
> WAF 차단을 적용하고, 같은 Payload의 재공격이 Edge에서 종료되어 신규 조기탐지 Event가
> 발생하지 않음을 정상·Health 대조군과 함께 확인한다.**

영상의 주인공은 공격 Shell이나 GitOps 화면이 아니라 관제 시스템과 운영자의 판단이다.

```text
조기탐지
→ 자동 Workload 격리
→ S3 침해확정
→ 자동 low→impossible
→ 사람의 Timeline 조사
→ 사람 승인 WAF 차단
→ 동일 Payload 재공격 차단
→ 정상 기능·수집 Health 확인
```

---

## 2. 촬영 공통값

촬영 시작 전에 아래 값을 한 화면에 고정한다.

```text
FINAL_TAKE_ID=<capital-one-...>
REATTACK_ID=<capital-one-reattack-...>
START_UTC=<UTC ISO 8601>
EARLY_RULE_ID=100110
CONFIRMED_RULE_ID=100111
EARLY_EVENT_ID=<Push event_id>
CLOUDTRAIL_EVENT_ID=<UUID>
ISOLATION_EXECUTION_ID=<ID>
HARDENING_EXECUTION_ID=<ID>
HARDENING_COMMIT_SHA=<40 hex>
WAF_RULE_ID=<고정 Rule ID>
```

시간은 가능한 한 UTC로 표시하고 KST가 필요하면 자막에서 병기한다.

---

## 3. 화면·편집 원칙

### 화면에 보여줄 것

- Rule ID·Level·Description
- 안전한 Stage·Action·Resource·Result
- Push `event_id`, CloudTrail `eventID`, 대응 Execution ID
- GitHub Commit SHA와 Argo Revision
- WAF Action·Label·terminating Rule
- 실제 Event 시각과 Alert·Action 시각
- 정상·Health 대조 결과

### 화면에 절대 보여주지 않을 것

- AWS Access Key·Secret Key·Session Token
- Cookie·CSRF Token·Authorization Header
- Webhook URI·Header Secret·Shuffle API Key·PAT
- 공격 Command 원문과 Credential 응답 본문
- 공개본의 전체 Account ID·Bucket·ARN·Client IP

### 편집 규칙

- CloudTrail 전달 대기는 축약할 수 있지만 실제 지연값을 자막에 남긴다.
- 서로 다른 TAKE를 한 Incident처럼 이어 붙이지 않는다.
- 실패한 실행은 성공 장면으로 편집하지 않는다.
- Runtime이 없는 Source·정적 Test·계획 화면을 실제 결과 대신 사용하지 않는다.

---

## 4. 장면 요약

### 현재 촬영 준비 상태 — 2026-08-21

| 구간 | 현재 상태 |
|---|---|
| DVWA Stage→Push→Rule `100110` | Fresh Runtime PASS |
| Rule `100111` 직접 탐지 | Matrix PASS, Fresh 예약 수집 Runtime PASS |
| `100110 → 자동 격리` | 미연결·미검증 |
| `100111 → low → impossible` | 미연결·미검증, 사전 조사 전 동결 |
| Timeline Dashboard | Source·Live Runtime PASS, 자동 행동은 `NOT CONNECTED` |
| WAF 조치·재공격 | 미검증 |

따라서 아래 문장은 현재 완료 보고가 아니라 **최종 촬영 계약**이다. 자동 행동 두 개의
실제 Runtime Evidence가 생기기 전에는 본편을 촬영하지 않는다.

### 장면 구성

| Scene | 제목 | 핵심 주장 | 계획 단계 |
|---|---|---|---|
| `SC-00` | 정상 관제 READY | 수집·대응·정상 상태가 준비됐다 | `P5` |
| `SC-01` | 최초 공격 진입 | WAF가 공격 요청을 식별하지만 최초에는 `COUNT/ALLOW`한다 | `P5` |
| `SC-02` | 조기탐지와 자동 격리 | Credential endpoint 단계에서 `100110`이 발생하고 DVWA가 실제 격리된다 | `P2`, `P3` |
| `SC-03` | S3 침해확정 | 고정 Object의 실제 바이트 반환 성공을 `100111`이 직접 탐지하고 Timeline에 앞선 `100110`과 함께 표시한다 | `P2`, `P5` |
| `SC-04` | 자동 `low → impossible` | `100111` 사건이 고정 GitOps 변경을 한 번 실행한다 | `P3` |
| `SC-05` | 사람의 Incident 조사 | Dashboard에서 진입부터 두 자동 대응까지 설명한다 | `P4` |
| `SC-06` | 사람 승인 WAF 조치 | 관제 근거로 좁은 Edge 차단을 적용한다 | `P4`, `P5` |
| `SC-07` | 동일 Payload 재공격 | WAF `BLOCK/403`에서 공격이 끝난다 | `P4`, `P5` |
| `SC-08` | Downstream 0과 정상 대조 | 신규 조기 Rule 0이 선차단 결과임을 증명한다 | `P5` |
| `SC-09` | 결론 | 자동 대응과 사람 대응의 역할을 구분한다 | `P6` |

---

# 5. 본편 녹화 대본

## SC-00 — 정상 관제 READY

### 보여줄 화면

- `FINAL_TAKE_ID`, `START_UTC`
- Wazuh Manager·Indexer·Dashboard READY
- Push Bridge Health 최신 성공 Event
- CloudFront·WAF·ALB·DVWA·CloudTrail Source 검색 가능
- DVWA Baseline `security=low`
- 이전 Quarantine·임시 WAF 차단·활성 Incident 없음
- GitHub/Argo Baseline Revision

### 운영자 조작

1. 전체 현황 화면을 연다.
2. 시간 범위를 새 TAKE 시작 직전으로 맞춘다.
3. Push Health Event 한 건을 확인한다.
4. 이전 TAKE의 Alert와 자동 대응이 새 TAKE에 포함되지 않음을 확인한다.

### 내레이션

> 평상시 AWS Edge, 애플리케이션, CloudTrail 로그가 Wazuh에 수집되고 있습니다. 지금은
> 새로운 TAKE를 시작하기 전이며 DVWA는 교육용 취약 Baseline인 low, 이전 격리와 대응
> Incident는 없는 상태입니다.

### 필수 Evidence

- READY 시각
- 최신 Push Health Event ID
- Baseline Git·Argo Revision
- 이전 활성 Incident 0

### 중단조건

- Wazuh·Bridge·필수 Source 중 하나라도 READY가 아님
- 이전 자동 대응 또는 Credential 상태가 남아 있음
- DVWA가 `low`가 아님

---

## SC-01 — 최초 공격 진입

### 보여줄 화면

- 승인된 공격 Runner와 고정 가짜 Object 설명
- WAF의 `POST /vulnerabilities/exec/`
- Managed Label `EC2MetaDataSSRF_Body`
- 최초 WAF Action `COUNT/ALLOW`
- Credential 원문을 제거한 단계별 Runner 결과

### 운영자 조작

1. Account alias·Target·Object Key를 확인한다.
2. 공격 Runner를 한 번 실행한다.
3. 동일 TAKE의 WAF Event 두 건을 연다.
4. WAF가 공격성 Payload를 식별했지만 관찰 모드라 통과시킨 상태를 보여준다.

### 내레이션

> 교육용 DVWA Command Injection을 통해 먼저 IMDS Role endpoint를 조회하고, 이어서 해당
> Role의 Credential endpoint를 조회합니다. WAF Managed Rule은 요청 본문을 SSRF 관련
> Label로 식별했지만 현재는 COUNT 모드라 요청을 허용합니다.

### 자막

```text
Initial WAF action: COUNT / ALLOW
Entry: POST /vulnerabilities/exec/
Managed label: EC2MetaDataSSRF_Body
```

### 필수 Evidence

- 공격 Runner 시작 UTC
- WAF Action·Label·Method·Path
- 같은 TAKE의 두 요청
- 실제 Credential·응답 원문 노출 0

### 중단조건

- 공격 요청이 승인된 Host·Path·Object 범위를 벗어남
- 최초 WAF가 이미 BLOCK하여 Baseline 공격이 진행되지 않음
- Credential 또는 Command 원문이 화면에 노출됨

---

## SC-02 — Rule 100110 조기탐지와 자동 Workload 격리

### 보여줄 화면

- 첫 Event `stage=imds_role_discovery`
- 두 번째 Event `stage=imds_credential_fetch`
- 두 번째 Event에만 발생한 Rule `100110`
- Push `event_id`와 Wazuh Alert
- 자동 대응 Execution
- 고정 DVWA Quarantine Policy UID/Revision
- 실제 금지 Egress 실패와 비대상 영향 0

### 운영자 조작

1. 두 Push Event를 시간순으로 펼친다.
2. `imds_role_discovery`에는 `100110`이 없음을 보여준다.
3. `imds_credential_fetch + succeeded + output_returned` Event와 `100110`을 연결한다.
4. 자동 격리 Execution과 Runtime Read-back을 연다.

### 내레이션

> 첫 Event는 Role 이름 조회 단계라 자동 격리 Rule이 발생하지 않습니다. 두 번째 Event는
> DVWA low 화면에서 IMDS Credential endpoint를 대상으로 한 명령이 출력을 반환한
> 단계입니다. Rule 100110이 이를 조기에 탐지하고, 사전 승인된 고정 DVWA Workload만
> 자동으로 격리합니다.

> 이 Alert만으로 Credential 원문이나 S3 접근 성공을 확정하지는 않습니다. 다만 보호
> Object 접근 직전의 고위험 단계이므로 긴급 Workload 격리를 허용합니다.

### 자막

```text
Early detection — Rule 100110
Stage: imds_credential_fetch
Automatic action: fixed DVWA workload quarantine
```

### 필수 Evidence

- Source `event_id` ↔ Rule `100110` 일대일
- Event→Alert 지연
- Alert→Isolation 지연
- Quarantine 실제 효과
- 동일 `event_id` 재전달 추가 조치 0
- 다른 Namespace 영향 0

### 중단조건

- Role 조회 Event에도 `100110`이 발생함
- Credential endpoint Event가 두 번 Alert됨
- Policy가 생성됐지만 실제 격리 효과를 확인하지 못함
- 고정 DVWA 이외의 Target이 변경됨

---

## SC-03 — Rule 100111 S3 침해확정

### 보여줄 화면

- 고정 가짜 Object 읽기 성공을 기록한 Runner Summary
- CloudTrail 원본 `GetObject`
- `eventID`, Role, Bucket alias, Key, HTTP 200, `bytesTransferredOut > 0`
- 같은 시간창의 앞선 Rule `100110` Alert
- Rule `100111` Alert와 원본 CloudTrail 근거

### 운영자 조작

1. 보호 Object의 CloudTrail Event를 연다.
2. 정확한 Role·Object·성공 조건을 보여준다.
3. Timeline에서 앞선 `100110`과 뒤의 `100111` 순서를 보여준다.
4. Event 시각과 Wazuh 도착·Alert 시각의 차이를 표시한다.

### 내레이션

> 이미 획득된 짧은 수명의 임시 Credential로 고정 가짜 S3 Object 읽기가 성공했습니다.
> CloudTrail Event는 승인 Account, 고정 Role, Bucket과 Object, 성공 상태를 만족합니다.
> Rule 100111은 이 CloudTrail 원본 Event만으로 실제 바이트 반환 성공을 직접 탐지했습니다.
> 앞선 Rule 100110과 같은 공격 흐름이라는 판단은 두 Rule의 의존조건이 아니라, Timeline의
> Event 시각과 식별자를 함께 본 관제자의 조사 결과입니다.

> 자동 대응은 S3 API 호출 순간이 아니라 이 CloudTrail Event가 Wazuh에 도착해 Rule이
> 발생한 뒤 시작됩니다.

### 자막

```text
Confirmed incident — Rule 100111
Protected GetObject: SUCCESS
Timeline: Rule 100110 → Rule 100111
```

### 필수 Evidence

- CloudTrail 원본 `eventID` ↔ Rule `100111` 일대일
- 예약 10분 수집으로 들어온 실제 CloudTrail Event와 Alert 시각
- 같은 TAKE의 앞선 `100110`을 Timeline에 함께 표시
- 정상 Principal·다른 Object·실패 요청은 `100111` 0

### 중단조건

- 다른 Role·Object·실패 요청에 `100111`이 발생함
- 서로 다른 TAKE를 하나의 공격 흐름으로 설명함
- 원본 `eventID`와 Alert를 연결하지 못함

---

## SC-04 — 자동 low → impossible

### 보여줄 화면

- Rule `100111`의 자동 대응 Execution
- 고정 Target·Schema·Dedupe Validator PASS
- 고정 GitHub Workflow Run
- `DEFAULT_SECURITY_LEVEL: low → impossible` 단일 Diff
- Commit SHA
- Argo CD exact Revision·`Synced + Healthy`
- 새 Pod·새 Session의 `security=impossible`

### 운영자 조작

1. `100111` Alert에서 대응 Execution으로 이동한다.
2. Target Allowlist와 CloudTrail `eventID` Dedupe를 확인한다.
3. GitHub Diff와 Commit SHA를 연다.
4. Argo Revision과 새 DVWA Session을 확인한다.

### 내레이션

> Rule 100111 사건은 사전 승인된 고정 Workflow를 한 번 실행합니다. 변경 대상은 DVWA의
> 기본 보안 수준 하나이며, GitHub와 Argo CD를 통해 low에서 impossible로 자동 배포됩니다.
> 같은 CloudTrail eventID가 다시 수집돼도 Commit과 Rollout은 반복되지 않습니다.

### 자막

```text
Automatic application hardening
DVWA: low → impossible
Dedupe key: CloudTrail eventID
```

### 필수 Evidence

- Wazuh Alert ↔ Execution ↔ GitHub Run ↔ Commit ↔ Argo Revision
- 예상 Diff 하나
- 새 Session `impossible`
- 동일 `eventID` 추가 Commit·Rollout 0

### 중단조건

- 사람의 수동 승인 없이는 실행되지 않아 “자동” 주장을 충족하지 못함
- 예상 외 파일·Repository·Branch가 변경됨
- Argo가 exact Commit을 배포하지 않음
- 새 Session이 여전히 `low`

---

## SC-05 — 사람이 Incident Timeline 조사

### 보여줄 화면

`Capital One Incident Timeline v2` Dashboard에서 다음을 시간순으로 표시한다.

1. WAF `COUNT/ALLOW`와 `EC2MetaDataSSRF_Body`
2. DVWA `imds_role_discovery`
3. DVWA `imds_credential_fetch`
4. Rule `100110`과 자동 Quarantine
5. CloudTrail `GetObject`
6. Rule `100111`
7. 자동 `low → impossible`

### 운영자 조작

1. `FINAL_TAKE_ID`와 Incident 시간창을 선택한다.
2. 각 Source의 시각과 식별자를 차례로 펼친다.
3. 이미 자동으로 끝난 조치와 사람이 추가로 해야 할 조치를 구분한다.
4. 최초 관측 가능한 악성 HTTP 진입점이 WAF였음을 확인한다.

### 내레이션

> 관제자는 새 탐지 방법을 즉석에서 발명하지 않습니다. Dashboard가 고정 상관 키와
> 시간창으로 Edge 요청, 애플리케이션 Event, S3 Evidence, 자동 대응을 한 Timeline으로
> 좁혀 보여줍니다. 여기서 최초 악성 HTTP 진입 요청이 WAF를 통과했고, 같은 유형의 재진입을
> Edge에서 차단할 수 있음을 판단합니다.

### 자막

```text
Human investigation
Entry → Credential risk → S3 confirmation → Automatic responses
Next action: narrow WAF virtual patch
```

### 필수 Evidence

- 서로 다른 날짜 Event가 섞이지 않은 단일 Incident 시간창
- Rule·Event·Execution ID Drill-down
- 자동 조치와 사람 조치 구분
- 알려진 관측 공백 표시

### 중단조건

- Push 표만으로 전체 Timeline을 설명함
- 다른 TAKE Event가 섞임
- 구현하지 않은 자동 인과 그래프나 AI 진단을 주장함

---

## SC-06 — 사람 승인 WAF 조치

### 보여줄 화면

- 사전 준비된 WAF IaC/Runbook Diff
- 조건:
  `EC2MetaDataSSRF_Body + POST + /vulnerabilities/exec/`
- 전체 Managed Rule Set은 계속 기존 모드임을 보여주는 Diff
- 사람 승인 기록
- 적용 결과와 WAF Rule Read-back

### 운영자 조작

1. Dashboard Evidence와 Runbook을 함께 검토한다.
2. 고정 WAF Rule Diff를 승인한다.
3. 승인된 Apply 경로를 실행한다.
4. Rule 상태와 적용 시각을 Read-back한다.

### 내레이션

> 자동 긴급 대응과 애플리케이션 완화 뒤, 관제자가 추가 재발 방지를 결정합니다. 전체
> Managed Rule을 차단 모드로 바꾸지 않고, 실제 공격에서 확인한 Label과 Method, Path를
> 함께 만족하는 요청만 BLOCK하도록 좁은 가상 패치를 적용합니다.

### 자막

```text
Human-approved WAF mitigation
EC2MetaDataSSRF_Body + POST + exact path → BLOCK
```

### 필수 Evidence

- 승인된 Diff
- Apply 성공
- WAF Rule ID·Priority·Action Read-back
- Rollback 경로

### 중단조건

- Console에서 출처 불명 임시 Rule을 직접 작성함
- 전체 Common Rule Set을 일괄 BLOCK함
- 정상 Ping까지 차단하는 넓은 조건임
- Apply 결과를 Read-back하지 못함

---

## SC-07 — 동일 Payload 재공격

### 보여줄 화면

- 새 `REATTACK_ID`와 시작 UTC
- 전용 Reattack Runner
- 최초 공격과 동일한 IMDS role-discovery Payload라는 안전한 Hash/Stage 표시
- HTTP `403`
- WAF `action=BLOCK`
- SC-06에서 적용한 terminating Rule ID

### 운영자 조작

1. WAF Rule 활성 상태를 마지막으로 확인한다.
2. 전용 Runner로 동일 공격 Payload를 한 번 보낸다.
3. WAF Event와 HTTP 결과를 연다.
4. ALB·DVWA로 내려가기 전에 Edge에서 종료됐음을 확인한다.

### 내레이션

> 같은 공격 Payload를 다시 전송했습니다. 이번에는 사람이 적용한 고정 WAF Rule이
> 요청을 BLOCK했고, 응답은 403입니다. HTTP 상태만 보는 것이 아니라 WAF terminating
> Rule과 downstream Event 부재를 함께 확인합니다.

### 자막

```text
Same payload reattack
WAF: BLOCK
HTTP: 403
Stopped at Edge
```

### 필수 Evidence

- 새 `REATTACK_ID`
- WAF Action·terminating Rule
- HTTP 403
- 요청 시각과 WAF Event 시각

### 중단조건

- 기존 Baseline Runner가 `security!=low` 사전 검사에서 멈춰 악성 POST를 보내지 않음
- 403만 있고 WAF terminating Rule을 확인하지 못함
- Payload가 최초 공격과 다름

---

## SC-08 — Downstream 0·정상 기능·수집 Health

### 보여줄 화면

- 재공격 시간창의 CloudFront/WAF Event
- ALB 신규 공격 요청 0
- DVWA 신규 `command.execution` 0
- Push 신규 공격 Event 0
- Rule `100110` 신규 Alert 0
- 보호 Object 신규 `GetObject` 0
- Rule `100111` 신규 Alert 0
- 추가 자동 대응 0
- 정상 로그인·홈·Numeric IP Ping 성공
- 재공격 뒤 생성한 Push Health Event 성공

### 운영자 조작

1. `REATTACK_ID`와 고정 관찰 시간창으로 downstream을 조회한다.
2. 각 Source와 Rule의 신규 건수가 0임을 보여준다.
3. 정상 사용자 흐름을 실행한다.
4. 안전한 Push Health Event를 보내 Wazuh 수집이 살아 있음을 확인한다.

### 내레이션

> 재공격은 WAF에서 종료돼 ALB와 DVWA에 도달하지 않았고, 따라서 Rule 100110도 새로
> 발생하지 않았습니다. 이는 탐지 장애가 아닙니다. 정상 애플리케이션 요청이 성공하고,
> 별도 Health Event가 같은 Push 경로를 통해 Wazuh에 도착한 것을 함께 확인했습니다.

### 자막

```text
Reattack downstream: 0
New Rule 100110: 0
New protected GetObject / Rule 100111: 0
Normal function: PASS
Push health: PASS
```

### 필수 Evidence

- 고정 관찰 시간창
- downstream·Rule 신규 건수 0
- 정상 기능 성공
- Health Event 성공
- 추가 GitHub Commit·Argo Rollout 0

### 중단조건

- 정상 기능이 실패함
- Health Event가 도착하지 않음
- downstream Event 또는 신규 Rule이 하나라도 발생함
- Alert 0만으로 차단 성공을 선언함

---

## SC-09 — 결론

### 보여줄 화면

- 최종 Incident Timeline
- 두 자동 대응의 성공 상태
- 사람 승인 WAF Rule
- 재공격·정상·Health 결과 요약

### 내레이션

> 이번 시연은 DVWA의 Credential 접근 징후를 조기에 탐지해 Workload를 자동 격리했고,
> 보호 S3 Object 접근 성공을 별도 Rule로 확정해 애플리케이션을 자동으로 impossible로
> 변경했습니다. 이후 관제자가 전체 흐름을 조사해 좁은 WAF 차단을 승인했고, 같은 공격은
> Edge에서 차단됐습니다. 정상 기능과 수집 경로는 유지됐습니다.

> 자동화는 미리 승인된 반복 대응을 수행했고, 사람은 사건 전체를 해석해 추가 방어 위치와
> 범위를 결정했습니다.

### 최종 자막

```text
Early detection: PASS
Automatic workload isolation: PASS
Confirmed S3 object access: PASS
Automatic low → impossible: PASS
Human-approved WAF mitigation: PASS
Same-payload reattack blocked at Edge: PASS
Normal function / telemetry health: PASS
```

---

## 6. 실패·재촬영 규칙

- 필수 Evidence가 하나라도 없으면 해당 TAKE를 성공본으로 사용하지 않는다.
- 실패 원인을 고친 뒤 새 `FINAL_TAKE_ID` 또는 `REATTACK_ID`를 사용한다.
- 다른 TAKE의 Alert·Execution·Commit을 끼워 넣지 않는다.
- CloudTrail 전달 대기 때문에 편집한 경우 실제 지연값을 표시한다.
- 자동 대응이 사람 조작을 필요로 했다면 `자동`이라고 말하지 않는다.
- WAF가 아닌 DVWA `impossible`에서만 차단됐다면 `WAF 선차단`이라고 말하지 않는다.

---

## 7. 공개 전 최종 검수

- [ ] Rule `100110/100111`만 활성 v2 Rule로 설명한다.
- [ ] Rule `100103/100100/100104/100105/100109` 과거 Event가 본편 Timeline에 섞이지 않는다.
- [ ] `100110`을 Credential 원문 탈취 확정으로 과장하지 않는다.
- [ ] `100111`은 S3 성공을 직접 탐지하고, 앞선 `100110`과의 흐름은 Timeline에서 사람이 조사한다고 설명한다.
- [ ] 자동 Workload 격리와 자동 `low → impossible`을 구분한다.
- [ ] 사람의 WAF 조치를 Root Cause 패치로 표현하지 않는다.
- [ ] 재공격은 실제 악성 POST를 보냈으며 WAF terminating Rule을 확인한다.
- [ ] downstream 0·정상 기능·Health Event를 모두 보여준다.
- [ ] TAKE·Event·Execution·Commit·WAF Rule 식별자가 앞뒤로 연결된다.
- [ ] Secret·Credential·Cookie·Token·전체 공개 금지 식별자 노출이 0이다.
