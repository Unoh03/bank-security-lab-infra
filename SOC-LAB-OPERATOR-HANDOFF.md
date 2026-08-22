# SOC Lab 운영 인계 — 현행 기준

> **상태:** CURRENT INDEX — Runtime 상태는 매 실행에서 다시 확인
>
> 이전 운영 절차 전문은 Git commit `5c20848`에만 보존한다. 현재 작업 트리에서는 이
> 문서를 현행 정본의 읽기 순서와 재개점 확인에만 사용한다.

## 1. 정본 읽기 순서

1. [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
   — Containment·Investigation·Remediation·Recovery의 의미
2. [`시연_계획.md`](시연_계획.md)
   — 전체 Gate, 완료 조건, 현재 우선순위
3. [`촬영_기술_계약.md`](촬영_기술_계약.md)
   — 촬영 범위, 화면, 조작, 내레이션, 필수 Evidence
4. [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)
   — Hop별 Interface·상태·Evidence 계약
5. [`구현_계획.md`](구현_계획.md)
   — AWS Source와 영구 복구의 Terraform 경계
6. [`observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`](observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)
   — 빠른 AWS → Wazuh 전달 계약

문서보다 실제 Source와 Runtime Evidence가 우선한다. Source 존재, 과거 Evidence, 현재
활성 상태, Target을 서로 대신 사용하지 않는다.

## 2. 현재 재개점

`시연_계획.md`의 `GT-00`부터 순서대로 재개한다.

- 공격·가짜 Object·TAKE·공개 마스킹 계약 고정
- 통제 공격 3회 반복성과 Credential 비저장 확인
- 같은 TAKE의 5-Source Timeline
- Rule `100103` 독립 3 TAKE의 실제 Event N↔Alert N, 정상 0, 자동 Write 0
- 엄격한 S3 고신뢰 Rule과 전체 대조군

Rule `100103`은 자동 격리 Trigger가 아니다. 고신뢰 S3 Rule이 `GT-03`을 통과하기
전에는 최종 Shuffle Write나 Containment를 연결하지 않는다.

## 3. 이후 실행 순서

```text
GT-00 공격 반복성
→ GT-01 동일 TAKE 5-Source
→ GT-02 Rule 100103 조기 경보
→ GT-03 S3 고신뢰 Rule
→ GT-04 고신뢰 Alert → Shuffle
→ GT-05/06 자동 격리·영향 범위
→ GT-07/08 조사 View·Runbook
→ GT-09 Remediation·Recovery
→ GT-10 재검증
→ GT-11 Rehearsal·촬영
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
