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
       → Rule 100100 or new strict high-confidence Rule
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
| Rule `100100` | 보호 대상 `GetObject` 양성 Alert 1건 | 엄격한 조건과 전체 대조군 Runtime |
| Shuffle | Private Webhook·Header·`repeat_back_to_me/$exec` G0~G2 | 고신뢰 S3 Alert Schema·Validator·Dedupe·Containment |
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
- Account·Region·Target URL·Object Key·공격 단계는 고정 Allowlist다.
- 공격은 한 TAKE에서 한 번만 실행한다.
- Credential은 Memory에서만 사용하고 화면·로그·Evidence에 쓰지 않는다.
- 시작·종료 UTC, 가짜 Object Hash, 성공 단계만 보존한다.

실패 시 같은 TAKE에서 공격을 반복하지 않는다.

### H1 — DVWA Push → Rule 100103

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

Rule `100100`의 실제 Decoded Field가 이 계약과 일치하는지 먼저 확인한다. 필드가 없거나
조건 의미가 다르면 새 Rule ID를 만든다.

필수 Runtime Matrix:

| Case | 예상 |
|---|---|
| 공격 Role·보호 Prefix·성공 `GetObject` 3회 | Alert 3 |
| 정상 `terra-user` 3회 | Alert 0 |
| 다른 Bucket | Alert 0 |
| 다른 Prefix | Alert 0 |
| 다른 Principal | Alert 0 |
| 실패 `GetObject` | Alert 0 |
| 같은 CloudTrail `eventID` 재수집 | 새 자동 조치 0 |

이 Matrix가 PASS하기 전 H3의 Wazuh Integration을 활성화하지 않는다.

### H3 — Wazuh Integrator → Shuffle Webhook

Wazuh:

- Custom integration 이름은 `custom-`으로 시작한다.
- 실제 설치 위치는 `/var/ossec/integrations`다.
- Script는 `root:wazuh`, mode `750`, Shebang, `argv[1]` Alert JSON 계약을 지킨다.
- `<alert_format>json</alert_format>`
- `<rule_id>`는 H2에서 Runtime PASS한 최종 고신뢰 Rule 하나다.
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
→ terminal FINISHED / Action SUCCESS
```

wrong/missing Header, 미등록 Rule·Account·Prefix는 신규 Execution 0이어야 한다.

### H4 — Sanitized S3 Alert Schema

최종 Payload는 다음 의미만 가진다. 정확한 JSON Schema는 구현 시 버전을 올려 별도
파일로 고정한다.

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
    "id": "<high-confidence rule>",
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
    "object_key": "validation/<approved object>",
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
- Bucket alias·`validation/*` Object
- `result=success`
- Hash와 timestamp 형식

Dedupe Key:

```text
CAPITAL-ONE:<aws_account_id>:<cloudtrail_event_id>
```

- Validation이 PASS한 뒤에만 Dedupe를 소비한다.
- `observe_only` Test는 Containment Dedupe를 소비하지 않는다.
- 같은 Key 10회 전달 시 Containment Action은 정확히 1회다.
- Validator 오류·Datastore 오류·Dedupe 불명확은 Fail Closed다.

### H6 — Automatic Containment

허용 Action은 두 개뿐이다.

1. 고정 DVWA Workload Quarantine
2. `validation/*` 추가 접근 제한 또는 사전 승인된 전용 Principal 제한

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
- IAM·IMDS·Node 조치는 Fresh Plan과 사람 승인을 요구한다.
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

## 5. Evidence Bundle

모든 Final TAKE Evidence는 최소 다음을 가진다.

```text
take_id
started_at_utc / finished_at_utc
baseline_dvwa_revision
high_confidence_rule_id
source event IDs and hashes
Wazuh alert IDs and timestamps
CloudTrail eventID
Shuffle execution ID and terminal status
containment target / UID / revision / outcome
GitHub run / commit SHA
Argo revision / health
retest results
secret_scan_result
```

Account ID·Bucket·Client IP·ARN은 공개본에서 Masking한다. Secret·Credential 원문은
비공개 Evidence에도 저장하지 않는다.

---

## 6. 활성 Entry Point 경계

- `Start-SocLab.ps1`은 Wazuh·Bridge·Secret Mount·READY를 만드는 시작 Helper일 수
  있지만 그 성공만으로 어느 E2E Gate도 완료되지 않는다.
- `Invoke-SocRule100103DynamicObserveOnly.ps1`과
  `Invoke-SocRule100103ThreeTakeRehearsal.ps1`은 Rule `100103` 조기 경보·과거
  OBSERVE_ONLY Scaffold 진단용이다. 최종 Shuffle·Containment 촬영 경로로 실행하지 않는다.
- `repeat_back_to_me` Workflow는 H3 Transport 검증 뒤 최종 Workflow로 교체한다.
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
→ GT-11 rehearsal and recording
```

다음 구현 재개점은 GT-00이다. Rule `100103 → Shuffle → Containment`의 과거 순서로
되돌아가지 않는다.
