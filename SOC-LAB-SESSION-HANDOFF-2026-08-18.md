# SOC Lab 세션 인수인계 — 2026-08-18

> **상태:** CURRENT POINTER — 시각별 Runtime Snapshot이나 실행 절차를 보관하지 않음
>
> 이전 세션 전문은 복구 지점인 Git commit `5c20848`에 보존했다. 현재 작업 트리에서는
> 오래된 상태와 명령이 현행 계획으로 섞이지 않도록 제거했다.

## 현행 정본

1. [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)
2. [`시연_계획.md`](./시연_계획.md)
3. [`촬영_기술_계약.md`](./촬영_기술_계약.md)
4. [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](./CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)
5. [`SOC-LAB-OPERATOR-HANDOFF.md`](./SOC-LAB-OPERATOR-HANDOFF.md)

## 재개점

`시연_계획.md`의 `GT-00`부터 순서대로 진행한다. Rule `100103`은
조기 경보로만 검증하고, 엄격한 S3 고신뢰 Rule이 `GT-03`을 통과한 뒤에만 최종
Wazuh→Shuffle과 Containment를 연결한다.

현재 상태는 이 파일의 날짜를 근거로 추정하지 않는다. 반드시 Git 상태, 실행 중 Process,
Wazuh·Bridge·AWS Runtime 출력과 보존 Evidence를 다시 읽고 판단한다.

## 기록 원칙

- Source 존재, Runtime 검증, 현재 활성, 보존 Evidence, Target을 구분한다.
- 수집 성공을 탐지·대응·Dashboard 완료로 확대하지 않는다.
- 이전 절차가 필요하면 현재 작업 트리에 복사하지 말고 `5c20848`을 읽기 전용으로 조회한다.
- 새 인계가 필요하면 현행 Gate와 실제 Evidence만 기록하고 오래된 명령을 누적하지 않는다.
