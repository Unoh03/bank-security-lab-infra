# Capital One SOC E2E Blueprint

> **상태:** CURRENT TARGET INTERFACE — 2026-08-20 재작성, E2E Runtime 미완료
> **상위 정본:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)
> **대응 의미:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
> **촬영:** [`CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md`](./CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md)

이 문서는 CURRENT PLAN을 구현할 때 Hop 사이에서 반드시 지켜야 하는 Interface·Schema·
Cardinality·실패 계약만 정의한다. 과거 Rule `100103 → Shuffle → Containment`
실험 경로는 최종 시연 경로가 아니다.

---

## 1. 최종 E2E

```text
Controlled DVWA attack
  ├─ DVWA safe audit
  │    → CloudWatch Logs → Lambda → SQS → Local Bridge
  │    → Wazuh Rule 100103
  │    → EARLY WARNING / OBSERVE ONLY
  │
  └─ protected validation/* GetObject
       → CloudTrail Data Event → S3 Archive → Wazuh aws-s3 wodle
       → Rule 100104 (Level 12) strict high-confidence Rule
       → wazuh-integratord → authenticated Shuffle Webhook
       → Validator → eventID Dedupe
       → Workload Quarantine + bounded validation/* restriction
       → Wazuh investigation view
       → human-approved Remediation / Recovery
       → attack and normal-function retest
```

불변조건:

- Rule `100103`은 조기 경보이며 자동 Write를 일으키지 않는다.
- 고신뢰 S3 Rule만 Shuffle 자동 Containment Trigger다.
- 기존 CloudTrail S3→Wazuh Poll 경로를 유지한다.
- `repeat_back_to_me`는 인증·전달 G2 Scaffold일 뿐 최종 Action이 아니다.
- 실제 Alert↔Execution과 실제 격리 효과가 없으면 E2E 완료가 아니다.

---

## 2. As-built와 Target

| 영역 | As-built Evidence | Target |
|---|---|---|
| 공격 | Node Role 임시 Credential로 고정 가짜 Object 읽기 성공 | 새 TAKE 3회 반복·공개본 |
| Rule `100103` | Rule·Push·Integrator 설정과 무해 Probe 확인 | 독립 3 TAKE의 실제 Event N↔Alert N, 정상 0, 자동 Write 0 |
| Rule `100100` | 보호 대상 `GetObject` 양성 Alert 1건 | 역사적 Evidence로만 보존·자동 조치 제외 |
| Rule `100104` | Pre-Runtime 고신뢰 Source 계약·Level 12·합성 Matrix | 실제 공격·전체 대조군 Runtime |
| Shuffle | Private Webhook·Header·`repeat_back_to_me/$exec` G0~G2 Legacy Scaffold | 별도 `CAPITAL-ONE-SOC-CONTAINMENT-v2` 고신뢰 S3 Alert Schema·Validator·Dedupe·Containment |
| Wazuh→Shuffle | Rule `100103` OBSERVE_ONLY G3 Scaffold | 최종 고신뢰 S3 Rule actual Alert→Execution |
| Containment | Source·Test 후보 | 실제 적용·효과·Blast Radius·Rollback |
| Dashboard | Saved Object 후보 | Seed Alert 중심 동일 TAKE Investigation View |
| Remediation | Source 후보 | 사람 승인 Diff·GitHub SHA·Argo Revision·Runtime |

이 표의 As-built 항목은 재사용 가능한 기반이다. 최종 Target을 대신하지 않는다.

---

## 3. Hop 계약

### H0 — TAKE와 공격 Runner

- `TAKE_ID=capital-one-yyyyMMddTHHmmssZ-xxxxxxxx`
- TAKE_ID는 Runner·Evidence Bundle·촬영 구간을 묶는 외부 Metadata다.
- TAKE_ID는 CloudTrail·Wazuh·Shuffle Payload에 넣지 않는다. 단일 만료 전 Active
  TAKE와 Event Time·Account·Region·Role·Bucket·Key가 모호성 없이 일치할 때만 외부
  Evidence Control Metadata로 연결하며, 그 외에는 원본 CloudTrail `eventID`만
  상관·Dedupe 식별자로 사용한다.
- Account·Region·Target URL·Object Key·공격 단계는 고정 Allowlist다.
- 공격은 한 TAKE에서 한 번만 실행한다.
- Credential은 Memory에서만 사용하고 화면·로그·Evidence에 쓰지 않는다.
- 시작·종료 UTC, 가짜 Object Hash, 성공 단계만 보존한다.

실패 시 같은 TAKE에서 공격을 반복하지 않는다.

### H1 — DVWA Push → Rule 100103

GT-02·GT-03 Runtime은 `scope=detection_only` 세션에서 실행하며, 이 구간의
`custom-shuffle-soc` Integration은 비활성 상태여야 한다. Shuffle Containment Write는
GT-03 Runtime PASS 전까지 0이다.

승인 Event 의미:

```text
source=dvwa
transport=push
payload.event_type=command.execution
payload.result=succeeded
payload.context.action=shell_command
payload.context.resource=ec2_imds
payload.context.security_level=low
payload.route=/vulnerabilities/exec/
```

필수 식별자:

- Source `event_id`
- Event UTC
- `raw_message_sha256`
- Wazuh Alert ID·Alert UTC

계약:

- 각 TAKE의 Event N = Rule `100103` Alert N
- 동일 `event_id` 중복 Alert 0
- 정상 Route·Resource·Result Alert 0
- Shuffle Containment Write 0

### H2 — CloudTrail → 고신뢰 S3 Rule

최소 판정 조건:

```text
aws.source=cloudtrail
aws.eventSource=s3.amazonaws.com
aws.eventName=GetObject
aws.recipientAccountId=<approved account>
aws.awsRegion=<approved region>
aws.requestParameters.bucketName=<approved bucket>
aws.requestParameters.key startsWith validation/
aws.userIdentity.sessionContext.sessionIssuer.userName=<approved attack role>
aws.errorCode absent
aws.additionalEventData.httpStatusCode=200
normal principal allowlist mismatch
```

Rule `100104` (Level 12)를 이 계약의 고신뢰 Rule로 고정한다. 기존 Rule `100100`의
양성 Runtime은 역사적 Evidence이며 이 계약이나 자동 조치용 Trigger로 재사용하지 않는다.

이 Runtime Matrix는 `runtime_profile=minimal`과
`security_scenario_profile=capital-one-lab`에서만 실행한다. Terraform이 제공하는
secondary control Bucket은 `other_bucket`용, Terraform-managed same-account
negative-control Role은 `other_principal`용 고정 Fixture다. 관련 Terraform output이
없거나 모호하면 임의 Bucket·Principal을 사용하지 않고 fail closed한다.

필수 Runtime Matrix:

| Case | 예상 |
|---|---|
| 공격 Role·보호 Prefix·성공 `GetObject` 3회 | Alert 3 |
| 정상 `terra-user` 3회 | Alert 0 |
| 다른 Bucket | Alert 0 |
| Primary의 Terraform-managed harmless control Object를 Node Role로 성공 조회하는 다른 Prefix | Alert 0 |
| 다른 Principal | Alert 0 |
| 동일 Node Role·동일 Primary Bucket/Key의 wrong `If-Match` 실패 | Alert 0 |
| 같은 CloudTrail `eventID` 재수집 | 새 자동 조치 0 |

이 Matrix가 PASS하기 전 H3의 Wazuh Integration을 활성화하지 않는다.

### H3 — Wazuh Integrator → Shuffle Webhook

Wazuh:

- Custom integration 이름은 `custom-`으로 시작한다.
- 실제 설치 위치는 `/var/ossec/integrations`다.
- Script는 `root:wazuh`, mode `750`, Shebang, `argv[1]` Alert JSON 계약을 지킨다.
- `<alert_format>json</alert_format>`
- `<rule_id>`는 H2에서 Runtime PASS한 최종 고신뢰 Rule `100104` 하나다.
- Webhook URI와 Header Key는 Runtime Secret file에서만 읽는다.

전송:

- HTTPS `shuffler.io` Allowlist
- `X-SOC-Webhook-Key` exact match
- Redirect·임의 Host·평문 Secret·Raw `full_log` 금지
- Bounded timeout·bounded response read

Cardinality:

```text
Actual high-confidence Wazuh Alert 1
→ authenticated Webhook request 1
→ new Shuffle Execution 1
→ terminal FINISHED / SUCCESS, external Side Effect 0
```

wrong/missing Header, 미등록 Rule·Account·Prefix는 신규 Execution 0이어야 한다.

GT-04 Evidence에는 Wazuh Alert UTC, Shuffle Execution UTC와
`Alert → Execution` 실제 latency를 함께 기록한다.

### H4 — Sanitized S3 Alert Schema

최종 Payload는 다음 의미만 가진다. 정본 JSON Schema는
`observability/shuffle/sanitized-alert.schema.json`에 `schema_version=2`로 고정되어
있으며 Validator와 함께 검증한다.

```json
{
  "schema_version": 2,
  "source_system": "wazuh",
  "sent_at_utc": "<UTC>",
  "account_alias": "primary-lab",
  "aws_account_id": "<approved account>",
  "aws_region": "ap-northeast-2",
  "scenario_id": "CAPITAL-ONE",
  "rule": {
    "id": "100104",
    "level": 12,
    "role": "high_confidence_s3_access"
  },
  "incident": {
    "cloudtrail_event_id": "<eventID>",
    "wazuh_alert_id": "<alert id>",
    "event_time_utc": "<UTC>",
    "event_source": "s3.amazonaws.com",
    "event_name": "GetObject",
    "principal_role_name": "<approved role>",
    "principal_session_id_sha256": "<hash>",
    "bucket_alias": "primary-application-data",
    "object_key": "validation/capital-one-demo.csv",
    "result": "success"
  },
  "integrity": {
    "raw_message_sha256": "<sha256>",
    "body_sha256": "<sha256>"
  }
}
```

금지:

- Credential·Session Token·Cookie·Authorization·Webhook URI/Key
- Command 원문·IMDS Credential 응답
- `full_log`
- 임의 추가 필드
- Alert가 정한 Namespace·Repository·Ref·Policy Document

`body_sha256`는 해당 필드를 제외한 canonical UTF-8 JSON의 SHA-256으로 계산하고,
canonicalization 규칙을 Evidence에 기록한다.

### H5 — Shuffle Validator와 Dedupe

Validator는 다음을 모두 exact match한다.

- Schema version
- Scenario·Account·Region
- 최종 Rule ID와 Role
- Event source/name
- 승인 Principal Role
- Bucket alias·고정 승인 Object `validation/capital-one-demo.csv`
- `result=success`
- Hash와 timestamp 형식

Dedupe Key:

```text
CAPITAL-ONE:<aws_account_id>:<cloudtrail_event_id>
```

- Validation이 PASS한 뒤에만 Dedupe를 소비한다.
- `observe_only` Test는 Containment Dedupe를 소비하지 않는다.
- 같은 Key 10회 전달에 대한 Action 1회는 먼저 side-effect-free Dedupe Stress에서
  증명한다. 이후 exact dispatch만 실제 Containment으로 승격한다.
- Validator 오류·Datastore 오류·Dedupe 불명확은 Fail Closed다.

### H6 — Automatic Containment

허용 Action은 두 개뿐이다.

1. 고정 DVWA Workload Quarantine
2. `validation/*` 추가 접근 제한 또는 사전 승인된 전용 Principal 제한

GT-05는 위 두 가지 임시 제한만 exact dispatch로 실행하고, GT-06은 그 효과와
비대상 영향·Rollback을 별도로 검증한다. GT-04에서는 이 Action을 실행하지 않는다.

입력은 Alert 원문이 아니라 Repository에 고정된 Allowlist 식별자다. 실제 Target,
NetworkPolicy enforcement, Resource policy/IAM Diff, Action UID/Revision, 실행 UTC와
Rollback 계약을 Evidence로 남긴다.

금지:

- 공유 Karpenter Node Role 전체 Deny
- 임의 Namespace·Selector·CIDR
- Shell interpolation
- 미승인 GitHub Repository·Workflow·Ref

### H7 — Investigation View

Seed는 고신뢰 S3 Alert다. View는 다음을 표시한다.

- 사건 요약과 Detection Rationale
- 같은 TAKE 시간창의 CloudFront·WAF·ALB·DVWA·CloudTrail
- 자동 격리 결과
- 공통 ID 부재와 Pod→IMDS 직접 관측 부재
- Rule별 Runbook과 승인 필요 조치
- Raw Event drill-down

시간·Principal·IP·URI·Bucket/Key 상관은 조사 근거이지 자동 인과 확정이 아니다.

### H8 — Human Remediation·Recovery

- `low → impossible`은 별도 `workflow_dispatch`와 정확한 파일·값 Allowlist를 사용한다.
- GitHub Commit SHA와 Argo CD Revision이 일치해야 한다.
- IAM 최소 권한·IMDSv2·Hop Limit·Node 교체 Apply는 이 Goal에서 제외한다. 적용한
  것처럼 말하지 않으며, 필요하면 별도 승인된 Future Work로 남긴다.
- 동일 공격 실패, 정상 기능 성공, 새 고신뢰 S3 성공 Alert 0을 확인한다.
- 임시 격리 해제 주체와 UTC를 남긴다.

---

## 4. 실행 상태와 실패 계약

### 상태

```text
READY
→ ATTACK_STARTED
→ EARLY_ALERTED
→ HIGH_CONFIDENCE_ALERTED
→ CONTAINED
→ INVESTIGATING
→ REMEDIATING
→ RECOVERED
→ CLOSED
```

`FAILED`는 어느 단계에서도 가능하다.

### 공통 실패 원칙

- 뒤 Gate를 실행하지 않는다.
- 실패 Event·Alert·Execution을 삭제하지 않는다.
- 같은 TAKE에서 외부 Write를 반복하지 않는다.
- Secret이 의심되면 공개 Evidence 생성을 중단한다.
- 자동 조치 일부 적용 뒤 실패하면 안전 상태를 유지하고 별도 Rollback Gate로 간다.
- DLQ가 0이 아니면 삭제하거나 우회하지 않고 중단한다.

---

## 5. Evidence

기본 기록은 각 Gate의 체크박스와 짧은 Runtime 결과다. 모든 Gate에 대형 Bundle을
만들지 않는다. Durable JSON은 다음 세 묶음만 허용한다.

1. `GT04 alert-execution`: CloudTrail `eventID`, Wazuh Alert ID, Shuffle Execution ID,
   상태·타임스탬프·필요한 Hash와 일대일 Cardinality
2. `GT05-06 containment`: Validator/Dedupe 결과, 고정 Target, Action·정책 UID/Revision,
   실제 enforcement, 중복 횟수, 공격 DENIED·비대상 영향·Rollback
3. `GT09-10 recovery-retest`: 승인된 파일 Diff, GitHub Run/Commit SHA, Argo Revision/Health,
   `low → impossible` 배포, 동일 공격·정상 기능·새 `100104` 성공 Alert 0

외부 `take_id`는 Evidence Metadata로만 사용할 수 있고 Payload에는 넣지 않는다. 단일
Active TAKE에 안전하게 결속하지 못하면 CloudTrail `eventID`만 사용한다. Account ID·Bucket·
Client IP·ARN은 공개본에서 Masking하며 Secret·Credential 원문은 어떤 Evidence에도 저장하지 않는다.

---

## 6. 활성 Entry Point 경계

- `Start-SocLab.ps1`은 Wazuh·Bridge·Secret Mount·READY를 만드는 시작 Helper일 수
  있지만 그 성공만으로 어느 E2E Gate도 완료되지 않는다.
- `Invoke-SocRule100103DynamicObserveOnly.ps1`과
  `Invoke-SocRule100103ThreeTakeRehearsal.ps1`은 Rule `100103` 조기 경보·과거
  OBSERVE_ONLY Scaffold 진단용이다. 최종 Shuffle·Containment 촬영 경로로 실행하지 않는다.
- 기존 `CAPITAL-ONE-SOC-CONTAINMENT-v1` `repeat_back_to_me` Workflow는 H3
  Transport 검증용 Legacy Scaffold로 보존한다. H3 이후 별도
  `CAPITAL-ONE-SOC-CONTAINMENT-v2` Target을 생성·검증하며, v1을 교체·삭제하지
  않는다.
- 새 통합 Orchestrator는 `GT-00~GT-10`의 선행 Gate를 건너뛰지 않고, 각 외부 Write
  전에 해당 Gate의 Runtime Evidence를 읽어야 한다.

---

## 7. 구현 순서

```text
GT-00 attack reproducibility
→ GT-01 same-TAKE five-source timeline
→ GT-02 Rule 100103 early warning / no automatic write
→ GT-03 strict S3 high-confidence rule and controls
→ GT-04 actual high-confidence Alert → Shuffle
→ GT-05/06 containment and blast radius
→ GT-07/08 investigation view and runbook
→ GT-09 remediation and recovery
→ GT-10 retest
→ GT-11A Final Recording Baseline (human checkpoint)
→ Recording Script
→ GT-11B post-record review
```

현재 Runtime 재개점은 같은 독립 공격 TAKE를 사용하는 GT-02·GT-03이다. Rule
`100103 → Shuffle → Containment`의 과거 순서로 되돌아가지 않는다.
