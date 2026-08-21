# Shuffle Cloud SOC Workflow 설정 기준

> **상태:** CURRENT TARGET — 고신뢰 S3 Alert 기반 E2E·Containment Runtime 미완료
> **상위 Gate:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](../../CAPITAL-ONE-SOC-DEMO-PLAN.md)
> **Interface:** [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](../../CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)

과거 Rule `100103 → repeat_back_to_me` 경로는 Webhook 인증과 전달 Scaffold를 검증한
기반이다. 최종 시연의 자동 조치 Trigger가 아니다.

---

## 1. 역할

```text
Rule 100103
→ EARLY WARNING
→ 자동 Write 0

GT-03을 통과한 S3 고신뢰 Rule
→ custom-shuffle-soc S3 Sanitizer
→ authenticated Webhook
→ Validator
→ CloudTrail eventID Dedupe
→ bounded Containment
```

`repeat_back_to_me/$exec`는 새 Schema의 인증·왕복을 확인할 때만 사용한다. G2가
통과하면 기존 v1을 수정하지 않고 별도 `CAPITAL-ONE-SOC-CONTAINMENT-v2`
Validator·Dedupe·Containment Target을 생성·검증한다. v1은 v2 검증 전까지
Legacy Scaffold·Rollback 용도로 보존한다.

---

## 2. 선행 Gate

다음이 모두 PASS하기 전 Shuffle의 외부 Write Action을 연결하지 않는다.

- Rule `100103` 독립 3 TAKE의 실제 Event N↔Alert N, 정상 대조군 0, 자동 Write 0
- 최종 S3 Rule 공격 Positive 3/3
- 정상 `terra-user`·다른 Bucket·다른 Prefix harmless Object·다른 Principal·wrong `If-Match`
  실패 응답 Alert 0
- 원본 CloudTrail `eventID`↔Wazuh Alert 일대일
- Sanitizer allowlist와 Runtime Secret 경로 확정
- GT-02·GT-03은 `scope=detection_only`에서 실행하며 `custom-shuffle-soc`
  Integration은 비활성 상태다. GT-03 Runtime PASS 전 Shuffle Containment Write는 0이다.
- `runtime_profile=minimal`과 `security_scenario_profile=capital-one-lab`에서
  Terraform-managed secondary control Bucket·negative-control Role output을 확인한다.
  출력이 없거나 모호하면 임의 Fixture를 사용하지 않고 fail closed한다.

---

## 3. Workflow 최소 구조

### Transport 검증

```text
Authenticated Webhook
→ repeat_back_to_me($exec)
```

- 외부 Side Effect Action 0
- 정상 Header: 신규 Execution 1, `FINISHED/SUCCESS`
- wrong/missing Header: 신규 Execution 0
- Request = Execution Argument = Result의 parsed JSON semantic equality

### 최종 Workflow Target (현재 B5 Stub/Placeholder; Runtime 미완료)

```text
Authenticated Webhook
→ Validate S3 Alert v2
→ Claim Dedupe(eventID)
├─ rejected / duplicate: Outcome only
└─ new approved incident
   → Quarantine fixed DVWA workload
   → Restrict fixed validation/* access
   → Persist outcome and rollback reference
```

Outgoing Branch는 명시적 조건만 사용하며 암묵적 `else`에 의존하지 않는다.

위 구조는 GT05/GT06의 Target 계약이다. 현재 Gate B5에서 실제로 검증하는 것은
외부 Side Effect가 없는 `repeat_back_to_me` Stub과 Validator·Dedupe Branch다.
고정 DVWA Quarantine과 `validation/*` 제한은 별도 Containment Runtime에서
구현·검증해야 하며, 이 Target 구조만으로 완료를 주장하지 않는다.

---

## 4. Validator 계약

필수 exact match:

- `schema_version=2`
- 정본 Schema: `observability/shuffle/sanitized-alert.schema.json`
- `scenario_id=CAPITAL-ONE`
- 승인 Account·Region
- 최종 고신뢰 Rule ID·Level·Role
- `event_source=s3.amazonaws.com`
- `event_name=GetObject`
- 승인 Principal Role
- 승인 Bucket alias
- 고정 승인 Object `object_key=validation/capital-one-demo.csv`
- `result=success`
- timestamp·SHA-256·CloudTrail eventID 형식

금지:

- Alert 원문·`full_log`
- Credential·Token·Cookie·Authorization
- Webhook URL·Header Key·PAT
- Command 원문
- 임의 Namespace·Selector·Repository·Ref·Policy
- Schema에 없는 필드

---

## 5. Dedupe와 Outcome

Dedupe Key:

```text
CAPITAL-ONE:<aws_account_id>:<cloudtrail_event_id>
```

Validation PASS 뒤에만 Claim한다. 같은 Key 10회 전달 시 Containment Action은 1회다.

| Outcome | 의미 | 외부 Write |
|---|---|---:|
| `REJECTED_SCHEMA` | Schema·Hash 거부 | 0 |
| `REJECTED_ALLOWLIST` | Rule·Account·Resource 거부 | 0 |
| `DUPLICATE_SUPPRESSED` | 같은 CloudTrail Event 재수집 | 0 |
| `SAFETY_GATE_BLOCKED` | Target·Rollback·enforcement 불확정 | 0 |
| `CONTAINMENT_SUCCEEDED` | 두 승인 조치와 증명 완료 | 1 logical incident |
| `CONTAINMENT_FAILED` | 일부 또는 전체 실패 | 자동 재호출 금지 |

Timeout으로 요청 수락 여부가 불명확하면 같은 Event를 자동 재호출하지 않고 Execution과
대상 Runtime을 대조한다.

---

## 6. Containment 경계

허용:

1. 고정 DVWA Workload Quarantine
2. `validation/*` 추가 접근 제한 또는 전용 Lab Principal 제한

금지:

- 공유 Karpenter Node Role 전체 `DenyAll`
- Alert 값으로 임의 Target 선택
- Shell 문자열 조립
- 미승인 GitHub Workflow·Ref
- 사람 승인 없는 IAM·IMDS·Remediation

NetworkPolicy Resource 생성만으로 성공하지 않는다. 실제 공격 Egress 실패, 정상
Health·관측 경로, 다른 Namespace와 비대상 Resource 영향을 함께 확인한다.

---

## 7. Secret과 Evidence

- Webhook URI·Header Key·Shuffle API Key·PAT은 Runtime Secret에서만 읽는다.
- Workflow Export·Source·Git·Evidence·로그·Shell History에 Secret 값을 남기지 않는다.
- Evidence에는 Hash, Rule ID, CloudTrail eventID, Wazuh Alert ID, Execution ID, Outcome,
  UTC, Target alias, Policy UID/Revision, Rollback 결과만 남긴다.
- Cloud API Read-back은 필요한 필드만 추출하며 전체 JSON을 Dump하지 않는다.

---

## 8. 완료 판정

Shuffle 단계 완료는 다음을 모두 뜻한다.

```text
actual strict S3 Wazuh Alert 1
= authenticated Webhook request 1
= new Shuffle Execution 1
= successful containment incident 1

wrong/missing header execution 0
unregistered rule/account/prefix write 0
duplicate eventID action 0
unexpected side effect 0
secret exposure 0
```

최종 경로의 Workflow는 `CAPITAL-ONE-SOC-CONTAINMENT-v2`다. 기존 v1은
rollback-only로 보존하며 최종 경로에서 사용하지 않는다.

합성 Payload 왕복, Rule `100103` OBSERVE_ONLY, Source·Workflow 존재는 이 완료 판정을
대신하지 않는다.
