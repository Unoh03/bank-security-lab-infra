# Shuffle Cloud SOC Workflow 설정 기준

> **상태:** CURRENT TARGET — Wazuh → Shuffle E2E Runtime 미완료
>
> 이 문서는 현행 Cloud Workflow의 설정·검증 기준만 다룬다. 이전 절차 전문은 Git commit
> `5c20848`에 보존했으며 현재 실행 기준으로 사용하지 않는다.
>
> 대응 의미는 [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](../../CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md),
> 필드와 상태 계약은 [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](../../CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)가 정본이다.

## 1. 현재 목표

첫 목표는 Wazuh Rule `100103` Alert를 최소 필드로 Shuffle에 보내고 `observe_only` Outcome을
남기는 것이다. 이 단계에서는 GitHub·Argo·NetworkPolicy·IAM 변경을 호출하지 않는다.

```text
Wazuh Rule 100103
→ Custom Integration Sanitizer
→ HTTPS Webhook + Required Header
→ Schema·Allowlist·TAKE 검증
→ OBSERVE_ONLY Outcome
→ 실제 외부 대응 호출 0
```

실제 AWS `command.execution → Rule 100103` 독립 3 TAKE가 먼저 끝나야 한다. 빠른 탐지
Runtime이 미완료인 상태에서 Shuffle 조립을 전체 대응 완료로 세지 않는다.

## 2. 책임 경계

| 구성요소 | 책임 | 책임이 아닌 것 |
|---|---|---|
| Wazuh Integration | Rule Filter, 최소 Schema, HTTPS 전송 | 대응 정책 결정 |
| Shuffle Validator | Schema·Hash·Account·Region·Scenario·TAKE 검증 | 임의 명령 실행 |
| Shuffle Workflow | Outcome, Allowlist, 안전 Gate, Dedupe | GitHub Run·Argo 완료 판정 |
| GitHub Workflow | 고정된 승인 대상 변경 | 임의 Repository·파일·값 변경 |
| Local E2E Orchestrator | GitHub Run·Commit·Argo·EKS Runtime 대조 | Secret 보존 |

## 3. Wazuh가 보낼 유일한 Body

```json
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
```

Webhook Header:

```text
Content-Type: application/json
X-SOC-Webhook-Key: <runtime secret>
```

원본 Wazuh Alert 전체, 공격 명령, Credential, Cookie, Authorization Header, Webhook URL과
Header Key는 전송하거나 Evidence에 남기지 않는다.

## 4. Workflow 순서

Workflow 이름은 `CAPITAL-ONE-SOC-RESPONSE-v2`로 고정한다.

1. Wazuh Webhook 수신
2. Required Header 검증
3. 정확한 Schema와 Body SHA-256 검증
4. Account·Region·Scenario·Rule Allowlist 검증
5. Active TAKE Allowlist와 만료 시각 확인
6. `response_mode` 확인
7. `observe_only`이면 Outcome을 남기고 즉시 종료
8. `contain`이면 NetworkPolicy·Target·Rollback 안전 Gate 확인
9. 안전 조건 불충족이면 `SAFETY_GATE_BLOCKED`로 종료
10. 안전 조건 충족 뒤에만 TAKE Dedupe를 Claim
11. 신규 TAKE만 고정 Workload Quarantine Workflow 호출
12. 공유 Role IAM 조치는 자동 실행하지 않고 `IAM_APPROVAL_REQUIRED` 기록

`observe_only`는 Containment Dedupe Key를 소비하지 않는다. 여러 outgoing branch를
자동 `else`로 가정하지 말고 각 조건을 명시한다.

## 5. 필수 Outcome

| Outcome | 의미 | GitHub 호출 |
|---|---|---:|
| `REJECTED_SCHEMA` | Schema·Hash 불일치 | 0 |
| `REJECTED_ALLOWLIST` | Account·Region·Scenario·Rule 거부 | 0 |
| `REJECTED_TAKE` | TAKE 미등록·만료 | 0 |
| `OBSERVE_ONLY` | 탐지 전달 확인 | 0 |
| `SAFETY_GATE_BLOCKED` | 대응 안전 조건 미충족 | 0 |
| `DUPLICATE_SUPPRESSED` | 같은 TAKE의 후속 Alert | 0 |
| `CONTAINMENT_DISPATCHED` | 고정 Workload Quarantine 요청 | 1 |
| `IAM_APPROVAL_REQUIRED` | 공유 Role 영향 차단 승인 대기 | 0 |
| `RESPONSE_FAILED` | Dispatch 수락 여부 미확정 | 자동 재호출 금지 |

HTTP Timeout이나 네트워크 오류로 요청 수락 여부를 확정할 수 없으면 같은 TAKE를 자동
재호출하지 않는다. 실패 Outcome을 남기고 GitHub Run을 별도로 대조한다.

## 6. 단계별 Gate

### S0 — Local Contract

- [ ] Custom Integration은 Rule `100103`만 수락
- [ ] 허용 필드 외 전송 0
- [ ] Secret 정적 검사 통과
- [ ] 실패 시 Wazuh Alert와 로컬 Evidence 보존

### S1 — Webhook Smoke

- [ ] 정상 Required Header 수락
- [ ] 누락·오류 Header 거부
- [ ] 정상 Schema Outcome 1
- [ ] GitHub 호출 0

### S2 — Observe-only E2E

- [ ] 실제 Rule `100103` 독립 3 TAKE 수신
- [ ] TAKE별 `OBSERVE_ONLY` Outcome
- [ ] Source Event·Wazuh Alert·Shuffle Execution의 ID와 UTC 연결
- [ ] 금지 필드·누락·동일 Event 중복 0
- [ ] GitHub 호출 0

### S3 — Dedupe Stress

- [ ] 안전한 Stub으로 동일 TAKE 동시 10회 실행
- [ ] 신규 Claim 1, 중복 억제 9
- [ ] 원자성 결과를 Runtime으로 확인
- [ ] 실제 GitHub 호출 0

### S4 — Containment 연결

다음 조건을 모두 충족한 뒤 별도 승인으로 진행한다.

- [ ] EKS NetworkPolicy enforcing Runtime 확인
- [ ] 고정 Namespace·Label 외 Target 거부
- [ ] 실제 Deny·Allow·Rollback Test 통과
- [ ] 공유 Role Blast Radius 검토 완료
- [ ] 고정 GitHub Workflow와 최소 권한 Authentication 검증
- [ ] 정확한 Run ID·Commit SHA·Argo Revision 대조 가능

이 Gate 전에는 `response_mode=contain`이나 Production Credential을 활성화하지 않는다.

## 7. Secret과 Evidence

- Webhook URL·Header Key·API Key·PAT은 Git에 저장하지 않는다.
- Shuffle Authentication 값은 화면·Export·로그에 노출하지 않는다.
- Evidence에는 Hash, Execution ID, Outcome, UTC, TAKE_ID, 확인된 Dispatch 수만 남긴다.
- Workflow Export는 Secret 값이 없는지 검사한 뒤 Hash와 함께 보존한다.
- 문서·정적 Test·HTTP 200만으로 전체 대응 성공을 선언하지 않는다.

## 8. 완료 판정

Wazuh → Shuffle의 첫 완료점은 S2다. 즉, 실제 Rule `100103` Alert 3개가 Sanitized Body로
전달되고 각 TAKE가 `OBSERVE_ONLY`로 종료되며 GitHub 호출이 0임을 Runtime Evidence로
확인한 상태다. Containment·Remediation·Recovery는 각각 뒤 Gate로 별도 판정한다.
