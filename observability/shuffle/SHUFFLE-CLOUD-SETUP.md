# Shuffle Cloud SOC Workflow Legacy v1 절차 — 현재 실행 금지

> **SUPERSEDED / 실행 금지:** 이 문서는 `CAPITAL-ONE-SOC-CONTAINMENT-v1`의 역사 기록이다.
> Gate B5의 Stub·Dedupe 검증 아이디어는 참고할 수 있지만, Private App Upload와
> Production Dispatch는 현재 실행하지 않는다. 현재 대응 의미는
> [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](../../CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md),
> v2 계약은 [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](../../CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)가 정본이다.

v1의 `.github/workflows/soc-contain-dvwa.yml`은 `low → impossible`을 Containment로
취급하므로 현재 계약에 맞지 않는다. v2 Target은 Workload Quarantine과 제한된 IAM 영향
차단을 먼저 수행하고, `low → impossible`은 느린 증거 확인 뒤 별도 GitOps Remediation으로
수행한다.

이 문서는 Shuffle 화면을 대충 따라 만드는 설명서가 아니라, 당시
`CAPITAL-ONE-SOC-CONTAINMENT-v1`을 검증 가능한 두 단계로 만들려던 절차를 보존한다.

기준 파일:

- `sanitized-alert.schema.json`: Wazuh가 보낼 수 있는 필드
- `shuffle-soc-workflow-contract.json`: 노드·분기·고정 대상·Evidence 계약
- `soc_gate_b5_payload.py`: Gate B5 정상/거부 Payload 생성기
- `apps/aws-topology-soc-validator/1.0.0/`: 조직 전용 고정 Validator App
- `apps/aws-topology-soc-github-dispatcher/1.0.0/`: 대상이 고정된 GitHub Dispatcher App
- `Build-ShuffleSocAppBundle.ps1`: 두 App 검증 후 Hash Manifest와 ZIP 생성
- `Install-ShuffleSocAppBundle.ps1`: 명시적 승인 뒤 두 App을 조직에 Upload

`shuffle-soc-workflow-contract.json`은 Shuffle Import 파일이 아니다. 실제 Cloud
Workflow를 만든 뒤 Export와 실행 결과가 이 계약을 만족하는지 검사하는 기준이다.

## 왜 바로 GitHub를 연결하지 않는가

중복 차단 노드가 화면상 존재해도 동시에 같은 Alert가 들어왔을 때 원자적으로
한 건만 통과한다고 증명되지는 않는다. 따라서 GitHub Credential을 넣기 전에
`dispatch_github_containment`를 안전한 Stub으로 두고 같은 Execution Argument
10개를 Shuffle Execute API로 동시에 보내 다음 결과를 먼저 확인한다. Webhook
Required Header는 별도의 성공/실패 Smoke로 검증한다.

```text
같은 Payload 10개
→ TAKE Allowlist 검증 10개
→ Dedupe Claim 신규 1개 / 기존 9개
→ Stub 실행 1개
→ 실제 GitHub 호출 0개
```

이 Runtime 결과가 Gate B5다. 통과한 뒤에만 같은 노드의 구현을 고정 GitHub
Workflow 호출로 교체한다.

## 1. 사용자가 준비할 것

Shuffle Cloud 로그인 후 다음 값만 확인한다. 비밀값은 채팅, Git, 스크린샷,
Evidence에 붙이지 않는다.

- Organization ID
- 새 Private Workflow ID
- Webhook Trigger ID와 URL
- Shuffle API Key
- Webhook Required Header 값

GitHub Fine-grained PAT은 Gate B5가 통과하기 전에는 만들거나 등록하지 않는다.

### Private App 두 개 준비

Shuffle Tools의 `execute_python`은 공식 구현에서 입력받은 Code를 `exec`로 실행한다.
Webhook 값을 Code 문자열에 삽입하는 방법은 이번 자동 대응 경로에서 금지한다. 대신
입력을 함수 인자로 받는 고정 Private Validator App을 사용한다. GitHub Production
호출도 Generic HTTP App의 Header에 PAT을 직접 조립하지 않는다. 별도 Private
Dispatcher App의 Authentication 필드로 PAT을 암호화 저장하고, App Source에서
Repository·Workflow·Ref·API URL을 고정한다.

먼저 두 App Package와 Hash Manifest를 한 번에 만든다.

```powershell
.\tools\Build-ShuffleSocAppBundle.ps1 `
  -ConfirmBuild 'BUILD SHUFFLE SOC APPS'
```

이 단계는 ZIP 두 개와 Manifest를 만들 뿐 Cloud에 쓰지 않는다. `shuffle_api_key`와
공개 식별자를 등록한 뒤 출력된 Manifest 경로로 조직에 Upload한다.

```powershell
.\tools\Install-ShuffleSocAppBundle.ps1 `
  -ManifestPath '<방금 출력된 BUNDLE_MANIFEST 경로>' `
  -ConfirmUpload 'UPLOAD SHUFFLE SOC APPS'
```

Upload 결과에는 App ID와 Package SHA-256만 남고 API Key는 남기지 않는다. GitHub
PAT은 아직 만들거나 등록하지 않는다. Dispatcher App Upload와 App Authentication
등록은 서로 다른 단계다.

## 2. Workflow 기본 골격

Workflow 이름은 정확히 다음과 같이 만든다.

```text
CAPITAL-ONE-SOC-CONTAINMENT-v1
```

공유 범위는 Private으로 두고 Webhook Trigger는 정확히 하나만 활성화한다.
Trigger Authentication에는 다음 Header를 요구한다.

```text
X-SOC-Webhook-Key: <runtime-only secret>
```

Workflow의 Action Label은 계약 파일의 `required_action_labels`와 문자까지
같아야 한다. Label 존재만으로 성공 판정하지 않으며, Export에서 연결·조건·고정
파라미터도 다시 읽는다.

## 3. 분기 순서

아래 순서를 유지한다.

1. `validate_payload`: `AWS Topology SOC Validator 1.0.0`의
   `validate_sanitized_alert`에 `$exec` 전체를 전달
2. Validator의 `valid=true`일 때만 Account·Region·Scenario·Rule 고정 Allowlist 검증
3. `get_take_allow`: `soc:v1:allow:...:<take_id>` 조회
4. TAKE 만료·Scenario·Rule·`response_mode` 일치 확인
5. `observe_only`면 `write_observe_only` Outcome을 남기고 종료
6. `contain`일 때만 `claim_take_dispatch`: TAKE 단위 Dedupe Claim
7. 기존 Claim이면 `write_duplicate_suppressed` Outcome을 남기고 종료
8. 신규 Claim이면 `dispatch_github_containment`
9. Production 성공은 `write_response_dispatched`, 실패는 `write_response_failed`

Shuffle의 여러 outgoing branch는 자동 `else`가 아니므로 `observe_only`와
`contain` 조건을 각각 명시한다. `observe_only`를 Dedupe 뒤에 두면 두 Alert 중
하나가 Duplicate로 바뀌어 Gate B4 계약을 깨므로 반드시 Dedupe 전에 종료한다.

거부 분기는 각각 다음 Label로 종료한다.

- Schema/Hash 실패: `write_rejected_schema`
- 고정 Allowlist 실패: `write_rejected_allowlist`
- TAKE 실패: `write_rejected_take`

`validate_payload`의 정확한 설정:

```text
App: AWS Topology SOC Validator
Version: 1.0.0
Action: validate_sanitized_alert
input_data: $exec
Authentication: 없음
```

Validator는 추가 필드, 중복 JSON Key, 잘못된 Type/Pattern, `body_sha256` 불일치를
`REJECTED_SCHEMA`로 반환한다. 성공 시에도 원본 Payload 전체를 되돌려주지 않고
Shuffle 분기에 필요한 Account·Region·Scenario·Rule·TAKE·Event·Hash만 반환한다.
Account·Scenario·Rule 값 자체의 허용 여부는 이 App이 아니라 다음 Allowlist 분기가
판정한다. 이 분리가 있어야 `REJECTED_SCHEMA`와 `REJECTED_ALLOWLIST`를 혼동하지 않는다.

## 4. Gate B5용 Stub

`dispatch_github_containment`의 **Label은 그대로 유지**하고 구현만 다음으로 둔다.

```text
App: Shuffle Tools
Action: repeat_back_to_me
Fixed value: GATE_B5_GITHUB_STUB
```

GitHub App, PAT, HTTP GitHub 호출은 이 단계에 없어야 한다. Workflow를 저장·활성화한
뒤 Export를 받아 Stub 단계임을 검사하고 Gate B5 Harness를 실행한다. Stub 다음에는
`write_response_dispatched`를 연결하지 않는다. Gate B5는 실제 GitHub 호출이 아니기
때문에 Production Dispatch 결과를 기록해서는 안 된다.

Gate B5 완료 조건:

- 유효한 동일 JSON Execution Argument 10개를 Execute API로 동시 전송
- Webhook Required Header 정상값 수락, 잘못된 값 거부
- 완료된 Execution 10개와 서로 다른 Execution ID 10개
- 정확한 Dedupe Key의 raw `keys_existed`: 신규 1개, 기존 9개
- Stub 실행 1개
- 실제 GitHub 호출 0개
- 잘못된 Account/Scenario/Rule/TAKE/Body Hash 각각 거부
- 모든 거부 분기에서 Claim·Stub·GitHub 0개
- 저장 Evidence의 Secret Scan 통과

Webhook 응답에는 Execution ID가 보장되지 않으므로 동시성 판정은 공식적으로
`execution_id`와 `authorization`을 반환하는 Execute API를 사용한다. 이는 Webhook
인증 시험이 아니라 Dedupe 원자성 시험이며, Webhook 인증은 위 Smoke로 분리한다.

Shuffle Datastore Action의 이름이나 문서 설명만으로 원자성을 확정하지 않는다.
위 동시 실행 결과가 정확히 맞을 때만 통과다.

## 5. Legacy v1 Production Dispatch — 현재 실행 금지

아래 절은 폐기된 v1 계약의 기록이다. Gate B5가 통과해도 현재는
`dispatch_github_containment`를 GitHub 호출로 교체하지 않는다.

> **현재 공식 계약 정정:** GitHub REST API `2026-03-10`은 Workflow Dispatch 응답을 항상
> HTTP 200과 Run Details로 반환하며 `return_run_details` Parameter를 제거했다. 아래 v1
> Dispatcher 계약은 이 API 버전과 충돌하므로 재사용하지 않는다.

```text
Repository: Unoh03/Uns-DVWA
Workflow: .github/workflows/soc-contain-dvwa.yml
Ref: main
GitHub API version: 2026-03-10
Legacy request: return_run_details=true (현재 API에서는 제거됨)
Response: HTTP 200 + workflow_run_id, run_url, html_url
```

현재 Target은 `return_run_details` 없이 API `2026-03-10`을 호출하고 HTTP 200의
`workflow_run_id`, `run_url`, `html_url`을 검증해야 한다. 기존 Private App Source는 이
Boolean을 고정해 보내므로 수정·새 Version·새 Bundle 검증 전에는 Binding하지 않는다.

허용 Input은 네 개뿐이다.

- `take_id`
- `scenario_id=CAPITAL-ONE`
- `rule_id=100103`
- `alert_body_sha256`

Repository, Workflow, Ref, Path, 목표값, Shell Command를 Webhook Payload에서
받아 호출 대상으로 쓰면 안 된다.

Production에서는 다음 Private App Action 하나만 외부 GitHub API를 호출한다.

```text
dispatch_github_containment
  App: AWS Topology SOC GitHub Dispatcher
  Version: 1.0.0
  Action: dispatch_containment
  take_id: $validate_payload.take_id
  scenario_id: $validate_payload.scenario_id
  rule_id: $validate_payload.rule_id
  alert_body_sha256: $validate_payload.body_sha256
  Authentication: GitHub Fine-grained PAT App Authentication
```

`write_response_dispatched`가 Datastore에 쓰는 Outcome은 다음 값을 반드시 함께
보존한다. `raw_message_sha256`는 Outcome 조회 Key와 Wazuh 원본 Event를 연결하고,
`body_sha256`와 `workflow_run_id`는 Dispatcher가 실제로 보낸 Alert와 GitHub Run을
로컬 E2E가 정확히 이어 붙이는 값이다.

```text
schema_version: 1
take_id: $validate_payload.take_id
raw_message_sha256: $validate_payload.raw_message_sha256
body_sha256: $validate_payload.body_sha256
account_alias: primary-lab
scenario_id: CAPITAL-ONE
rule_id: 100103
result: RESPONSE_DISPATCHED
github_dispatch_count: 1
workflow_run_id: $dispatch_github_containment.workflow_run_id
completed_at_utc: <Shuffle UTC completion time>
```

나머지 Outcome도 같은 11개 필드를 정확히 사용하되 `github_dispatch_count=0`,
`workflow_run_id=0`으로 기록한다. 추가 필드가 있거나 `body_sha256`가 없으면 로컬
E2E가 실패한다. 이 제한은 같은 TAKE 이름을 가진 수동 GitHub Run을 자동 대응 Run으로
오인하지 않게 한다.

PAT을 Action Parameter, Header, Workflow Variable에 평문으로 쓰지 않는다. Dispatcher
App의 `github_token` Authentication 하나만 만들고 Action에서 그 Authentication을
선택한다. `Authorization`, `Accept`, `Content-Type`, API Version, URL, ref는 App Source에
고정돼 있다. Generic GitHub/HTTP Action이나 두 번째 Dispatcher가 하나라도 있으면
Production 검증은 실패한다.

`authentication_id`는 그 자체로 Bearer Header를 만드는 값이 아니다. Shuffle은 이
ID로 선택한 App Authentication의 `github_token`을 실행 시 함수 인자로 주입하고,
Dispatcher가 고정 Header를 만든다. Cloud Export 버전에 따라 `github_token`의
`configuration=true` Placeholder가 보이거나 생략될 수 있으므로 Export 검증은 두
형태를 허용하되, 평문 Token과 다른 Configuration Parameter는 모두 거부한다.

PAT은 `Unoh03/Uns-DVWA` 한 Repository의 Actions Write만 허용하고 Contents Write는
주지 않는다. 실제 `values.yaml` Commit은 호출된 Workflow의 제한된
`GITHUB_TOKEN`이 수행한다.

전환 후 다시 Export를 읽어 다음을 확인한다.

- Stub Action이 남아 있지 않음
- Validator와 Dispatcher Action의 `app_id`가 Upload Evidence의 App ID와 정확히 일치
- 현재 Organization의 App 목록에도 같은 ID·이름·`1.0.0`이 각각 하나만 존재
- Repository/Workflow/Ref가 고정값
- 허용 Input이 정확히 네 개
- GitHub API 2026-03-10의 200 응답에서 양의 Run ID와 고정 Repository Run URL만 수락
- Secret 값이 Export에 평문으로 없음
- Dispatcher가 선택한 Authentication이 현재 Organization에서 Active·Encrypted이고,
  Upload한 Dispatcher App에 속하며 필드 Key가 `github_token` 하나뿐임
- Required Action Label과 분기 연결이 유지됨
- Gate B5 때 저장한 `workflow_core_sha256`와 Production Core Hash가 같음

Core Hash는 Stub을 Dispatcher로 바꾸는 자리와 그 Action에서 나가는 성공·실패
Branch만 제외하고 Trigger, Header 인증 존재, `fresh claim → dispatch` 입력 Branch,
나머지 Action·Parameter·Branch 조건을 묶는다. Production 검사는 Dispatcher에서
`write_response_dispatched`와 `write_response_failed`로 나가는 서로 다른 조건의 Branch
두 개도 별도로 요구한다.
따라서 전환 과정에서 다른 노드나 조건이 함께 바뀌면 `Start-SocLab contain` 전에
실패한다. 추가 Action과 Workflow Variable도 허용하지 않는다.

`Start-SocLab -ResponseMode contain`은 여기서 네 가지를 모두 요구한다.

1. 현재 Cloud Export가 위 Production 고정 계약을 만족함
2. Workflow Action의 App ID가 로컬 Upload Evidence와 현재 Cloud App 목록에 모두 일치함
3. Dispatcher Authentication이 현재 Organization에서 Active·Encrypted이고 정확한
   Dispatcher App과 `github_token` Key에 묶여 있음
4. 같은 Workflow ID로 수행한 최신 Gate B5 Runtime Evidence가 10회 중 신규 1·중복
   9를 증명하며 Manifest Hash가 변하지 않음

하나라도 없으면 Wazuh와 Bridge를 기동하기 전에 실패한다. 즉 Stub 원자성 검증을
생략한 채 Production 자동 대응으로 바로 들어갈 수 없다.

App Authentication 조회는 값 확인용으로 사용하지 않는다. 현재 Shuffle 공식 서버
구현은 마스킹된 복사본을 만들고도 원 응답 배열을 직렬화하는 경로가 있으므로, 이 API의
응답은 잠재적인 Secret-bearing Response로 취급한다. 로컬 검증기는 Field Value를 읽거나
출력·Evidence에 저장하지 않고 Key와 상태만 검사하며, HTTP verbose/debug trace도 켜지
않는다. 다만 서버가 응답 본문을 네트워크로 전송하는 사실 자체까지 로컬 코드가 없앨 수
있는 것은 아니다.

## 6. Legacy v1 로컬 설정 — 현재 실행 금지

Cloud 값이 준비되면 공개 식별자는 다음 도구로 저장한다.
Shuffle Cloud는 계정 지역별 API Origin이 다를 수 있으므로 `/admin` 지역 표시와 현재
브라우저 Host를 확인해 Origin만 입력한다. `/api/v1` 경로는 붙이지 않는다.

```powershell
.\tools\Set-SocLabConfiguration.ps1 `
  -ShuffleOrgId '<ORG_UUID>' `
  -ShuffleWorkflowId '<WORKFLOW_UUID>' `
  -ShuffleWebhookId '<WEBHOOK_UUID>' `
  -ShuffleApiBase '<예: https://uk.shuffler.io/>' `
  -ConfirmWrite 'WRITE SOC LAB CONFIG'
```

비밀값은 각 명령의 보안 입력창에만 넣는다.

```powershell
.\tools\Set-SocLabExternalSecret.ps1 `
  -Name shuffle_api_key `
  -ConfirmStore 'STORE SOC EXTERNAL SECRET'
.\tools\Set-SocLabExternalSecret.ps1 `
  -Name shuffle_webhook_url `
  -ConfirmStore 'STORE SOC EXTERNAL SECRET'
```

Webhook Header 값은 `Initialize-SocLabSecrets.ps1`이 만든 DPAPI CurrentUser Record를
Shuffle Trigger Authentication에 사용한다. `Copy-SocLabWebhookHeader.ps1`을 사용자가
명시적으로 실행해 `X-SOC-Webhook-Key` 값에만 붙여 넣는다. 이 도구는 값을 출력하거나
파일에 쓰지 않고, Windows의 `ExcludeClipboardContentFromMonitorProcessing` 형식으로
History·Cloud 동기화를 제외한 뒤 기본 120초 후 아직 같은 값일 때만 Clipboard를 비운다.

## 7. Legacy v1 완료 판정 — 현재 완료 기준 아님

다음은 완료가 아니다.

- Workflow 화면에 노드가 보임
- Action Label이 존재함
- 개별 테스트 Payload 한 건이 성공함
- GitHub Workflow가 수동으로 한 번 성공함

최종 완료는 Gate B5 동시성 검증 후 Production Export 검증, 실제 Rule 100103
Alert 두 건에서 GitHub Dispatch 정확히 한 번, 정확한 Commit SHA의 Argo 배포,
재공격 실패와 정상 기능 유지가 하나의 E2E Evidence로 연결된 상태다.

## 공식 근거와 아직 Runtime으로 확인할 것

- Shuffle 공식 App API는 `src/app.py`, `api.yaml`, `Dockerfile`,
  `requirements.txt` ZIP Upload를 지원한다.
- Shuffle Tools 1.2.0 공식 Source의 `execute_python`은 `exec(code, ...)`를 호출하므로
  이번 입력 검증에는 사용하지 않는다.
- Shuffle 공식 App Authentication은 `api.yaml`의 Authentication Parameter를 암호화해
  실행 시에만 주입한다.
- 현재 공식 Authentication 조회 구현은 마스킹 객체가 아닌 원 배열을 응답하는 경로가
  있어, 로컬 검증은 값에 접근하지 않더라도 해당 응답을 잠재적 Secret-bearing으로
  취급한다.
- GitHub 공식 Workflow Dispatch API는 Fine-grained PAT의 Repository Actions Write를
  지원하고 Run ID를 반환한다.
- Microsoft Win32 Clipboard 문서는
  `ExcludeClipboardContentFromMonitorProcessing` 형식이 Clipboard History 포함과 다른
  장치 동기화를 막는 용도임을 정의한다.
- App API의 Cloud `hash`와 로컬 Upload ZIP SHA-256은 같은 종류의 Hash가 아니므로,
  API 읽기만으로 Cloud 실행 Source가 로컬 ZIP과 byte-for-byte 같다고 주장하지 않는다.
  App ID·이름·버전·Workflow Binding을 확인하고 최종 Source 동작은 Gate/E2E Runtime으로
  검증한다.
- Datastore Set의 원자성, Cloud Export의 Authentication 표현, 실제 Branch 내부값은
  문서만으로 완료 판정하지 않고 Gate B5/Production Runtime에서 확인한다.

공식 참고:

- https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats
