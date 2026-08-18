# SOC Lab 운영 인계 — 현행 기준

> **상태:** CURRENT INDEX — Runtime 상태는 매 실행에서 다시 확인
>
> 이전 운영 절차 전문은 Git commit `5c20848`에만 보존한다. 현재 작업 트리에서는 이
> 문서를 현행 정본의 읽기 순서와 재개점 확인에만 사용한다.

## 1. 정본 읽기 순서

1. [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
   — Containment·Investigation·Remediation·Recovery의 의미
2. [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](CAPITAL-ONE-SOC-DEMO-PLAN.md)
   — 전체 Gate, 촬영 범위, 현재 우선순위
3. [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)
   — Hop별 Interface·상태·Evidence 계약
4. [`CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md`](CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md)
   — AWS Source와 영구 복구의 Terraform 경계
5. [`observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`](observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)
   — 빠른 AWS → Wazuh 전달 계약

문서보다 실제 Source와 Runtime Evidence가 우선한다. Source 존재, 과거 Evidence, 현재
활성 상태, Target을 서로 대신 사용하지 않는다.

## 2. 현재 재개점

가장 먼저 닫을 Gate는 실제 AWS `command.execution → Wazuh Rule 100103`이다.

- 독립된 `TAKE_ID` 3개
- 각 TAKE의 Source Event와 Wazuh Alert 대조
- 지연, 누락, 동일 `event_id` 중복 기록
- 정상 대조군 Alert 0
- 이 단계의 Shuffle은 `observe_only`

이 Gate 전에는 Workload 격리, IAM 영향 차단, `low → impossible` Remediation, Reset을
Runtime 완료로 표현하지 않는다.

## 3. 이후 실행 순서

```text
Fast AWS → Wazuh 실제 3 TAKE
→ Offline Catch-up·DLQ·DVWA Poll Rollback
→ Wazuh → Shuffle sanitized observe_only
→ Workload Quarantine Runtime
→ 제한된 IAM 영향 차단 Runtime
→ low → impossible Remediation와 Argo exact SHA
→ 영구 IAM·IMDS 복구와 Recovery
→ 필요할 때만 수동 Retake Reset
```

앞 Gate의 Runtime Evidence가 없으면 뒤 Gate의 Source나 정적 Test로 대체하지 않는다.

## 4. 운영 안전 경계

- Terraform Apply·Destroy는 Fresh Plan과 명시적 사용자 승인 없이는 실행하지 않는다.
- 실제 공격, 외부 Webhook 쓰기, GitHub Dispatch, IAM 변경은 해당 Gate의 승인 범위에서만
  수행한다.
- 공유 Karpenter Node Role 전체 자동 Deny는 금지한다.
- NetworkPolicy Resource 존재만으로 격리 성공을 선언하지 않는다.
- Secret, Webhook URL, Header Key, PAT, Credential을 Git·Alert·Evidence에 남기지 않는다.
- 실패한 TAKE도 원본 Event·Alert·Hash를 삭제하지 않는다.
- Reset은 SOAR Trigger가 아니라 운영자의 별도 수동 절차다.

## 5. 인계 시 남길 최소 Evidence

- 현재 Git HEAD와 dirty file 목록
- Daily Runtime Profile·Session·Deadline
- Wazuh Manager·Indexer·Dashboard 상태
- Bridge PID·Heartbeat·Queue·DLQ 상태
- Active `TAKE_ID`와 만료 시각
- 마지막 Source Event ID·Wazuh Alert ID·각 UTC 시각
- Shuffle Outcome과 실제 GitHub 호출 수
- 완료 Gate, 실패 Gate, 다음 한 가지

상태가 바뀔 때마다 이 문서에 시각별 로그를 누적하지 않는다. 실행 Evidence는 전용
Evidence 경로에 보존하고, 이 문서는 현행 재개 순서만 유지한다.
