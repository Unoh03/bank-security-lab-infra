# Capital One 기반 SOC 시연 구축·검증 계획

> **상태:** CURRENT PLAN — 완성형 촬영 대본을 실현하기 위한 요구사항·작업·Gate 정본  
> **촬영 대본:** [`CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md`](./CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md)  
> **공격·대응 의미:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)

이 문서는 촬영 장면의 내레이션을 반복하지 않는다. 무엇을 구현·검증해야 해당 장면을 사실대로 촬영할 수 있는지 관리한다.

---

## 0. 확정한 시연 설계

### 0.1 주인공

주인공은 처음부터 끝까지 **Wazuh·Shuffle을 중심으로 한 관제 시스템**이다.

```text
평소 로그 중앙화
→ 조기 이상 징후 탐지
→ 보호 대상 S3 접근 성공 고신뢰 탐지
→ Shuffle 자동 격리
→ Alert 중심 관련 로그 조사
→ 관제자의 후속 조치 결정
→ Remediation·Recovery
→ 동일 공격·정상 기능 재검증
```

### 0.2 탐지 Rule 역할

```text
Rule 100103
= command.execution + ec2_imds + succeeded
= 조기 이상 징후
= Credential 탈취·S3 접근 가능성
= 자동 격리 Trigger 아님

Rule 100104
= 보호 대상 validation/* GetObject 성공
+ 승인 Account
+ 공격 시나리오 Principal/Role Session
+ errorCode 없음
+ 정상 Allowlist 제외
= 고신뢰 침해 확인 Alert
= Shuffle 자동 격리 Trigger
```

현재 Rule `100100`이 위 계약을 정확히 충족하면 재사용한다. 부족하면 기존 의미를 조용히 바꾸지 않고 새 Rule ID를 만든다.

### 0.3 고신뢰의 의미

`GetObject`라는 API 이름 하나만으로는 고신뢰가 아니다. 이 Lab에서 다음 불변조건을 함께 만족해야 한다.

- 정상 DVWA 동작은 `validation/*`를 읽지 않는다.
- 정상 운영 Principal은 자동 조치 Rule에서 제외된다.
- 공격 시나리오에서 예상한 Node Role 또는 상관 가능한 Role Session이다.
- Object 읽기가 실제 성공했다.
- Account·Region·Bucket·Prefix가 사전 승인 범위다.

이 조건과 정상 대조군을 Runtime으로 검증한 뒤에만 자동 Write를 허용한다.

### 0.4 자동 조치 시점

현재 핵심안은 CloudTrail S3 Data Event가 기존 S3→Wazuh 수집 경로로 도착하는 방식을 유지한다.

```text
실제 S3 GetObject
→ CloudTrail Event 생성·전달
→ S3 Archive
→ Wazuh 수집
→ 고신뢰 Rule Alert
→ Shuffle 자동 격리
```

따라서 목표는:

> **S3 침해 Evidence가 Wazuh에 탐지되는 즉시 자동 격리**

이다. `S3 API 호출 순간 즉시 격리`라고 표현하지 않는다. 촬영에서는 실제 Event→Alert 지연과 Alert→Action 지연을 따로 표시한다.

CloudTrail의 별도 저지연 Route 전환은 촬영 필수 조건이 아니다. 구현 부담과 재검증 비용이 낮을 때만 후속 개선으로 다룬다.

### 0.5 사건 조사 방식

완전 자동 거미줄·AI Incident Graph는 필수 조건이 아니다.

촬영 필수안:

```text
고신뢰 S3 Alert
→ Event Time·Principal·Bucket/Key·Source IP 추출
→ 미리 만든 Wazuh Saved View/Dashboard
→ 같은 시간창의 관련 CloudFront·WAF·ALB·DVWA·CloudTrail 표시
→ 자동 조치 결과·관측 공백·다음 조치 Runbook 표시
```

즉 **Alert 중심의 안내형 Incident Investigation View**를 만든다. 검색 문법을 모르는 팀원도 3분 안에 사건·영향·근거·다음 조치를 설명할 수 있어야 한다.

### 0.6 자동화와 사람 판단의 경계

```text
자동
- Alert 인증·Schema·Allowlist 검증
- 중복 조치 차단
- 좁고 가역적인 Workload 격리
- validation/* 추가 접근 제한
- Evidence·Execution 기록

사람 판단 또는 명시적 승인
- Credential/Session 영향 범위 확정
- IAM 최소 권한 변경
- IMDSv2·Hop Limit·Node 복구
- 애플리케이션 Remediation
- 격리 해제와 Incident 종료
```

---

## 1. 문서 역할과 변경 경계

| 문서 | 역할 |
|---|---|
| `CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md` | 공격·Containment·Remediation·Recovery의 의미 |
| `CAPITAL-ONE-SOC-DEMO-PLAN.md` | 촬영을 위한 요구사항·남은 작업·Gate·현재 상태 |
| `CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md` | 완성된 시스템을 실제로 찍는 화면·조작·내레이션·자막 |
| `CAPITAL-ONE-SOC-E2E-BLUEPRINT.md` | Hop별 Interface·Schema·실패 계약 |
| `OBSERVABILITY-CURRENT-STATUS.md` | 실제 최신 Runtime 상태 |

이번 설계로 기존 Blueprint·Scenario의 `Rule 100103 → Containment` 표현이 충돌하면,
구현 전에 해당 정본을 보정한다. 두 촬영 문서를 기준으로 활성 지원 문서도 같은 계약으로
정렬하되, 과거 Runtime Evidence와 Git 이력은 삭제하지 않는다.

---

## 2. 촬영 완료 정의

다음이 모두 실제 Runtime Evidence로 확인돼야 최종 촬영을 시작한다.

- [ ] 통제된 공격 한 TAKE에서 Command Injection→IMDS→보호 대상 S3 접근 성공을 재현
- [ ] Rule `100103` 실제 조기 Alert와 정상 대조군 0
- [ ] 보호 대상 S3 성공 접근 고신뢰 Rule과 정상 대조군 0
- [ ] CloudTrail 원본 `eventID`와 고신뢰 Wazuh Alert 일대일 연결
- [ ] 실제 고신뢰 Wazuh Alert와 Shuffle Execution 일대일 연결
- [ ] 같은 CloudTrail `eventID` 재수집·중복 Alert가 조치를 반복하지 않음
- [ ] Workload·Resource/Permission 격리가 승인 범위에 실제 적용
- [ ] 추가 `validation/*` 접근 실패
- [ ] 비대상 Namespace·정상 서비스 영향 0
- [ ] Alert 중심 사건 조사 View에서 관련 로그·관측 공백·자동 조치·Runbook 확인
- [ ] 다른 팀원의 3분 무검색 사용성 Test 통과
- [ ] 사람이 선택한 Remediation·Recovery가 승인된 Diff로 적용
- [ ] 동일 공격 실패, 정상 기능 성공, 새 보호 대상 S3 성공 Alert 0
- [ ] 모든 장면의 TAKE·UTC·Event ID·Execution ID·Commit SHA가 대조 가능
- [ ] Secret·Credential·실제 개인정보가 Evidence와 영상에 없음

---

## 3. 현재 Baseline — 2026-08-20 기준

아래 상태는 Source 존재와 Runtime 검증을 구분한다.

| 영역 | 현재 확인된 Evidence | 현재 판정 | 새 시연에서 남은 핵심 |
|---|---|---|---|
| 공격 Baseline | Node Role 임시 자격증명으로 `validation/*` 가짜 Object 읽기 성공·CloudTrail Event 존재 | Runtime 확인 | 새 TAKE 반복성·촬영용 공개본 |
| 5-Source 수집 | CloudFront·WAF·ALB·DVWA·CloudTrail의 Wazuh Raw/Index 연결 | Source별 Runtime 확인 | 동일 TAKE Timeline |
| Rule `100100` | 보호 대상 S3 `GetObject` Alert와 CloudTrail `eventID` 연결 | 양성 Runtime 확인 | 엄격한 자동 조치 계약·Wazuh 정상 대조군 |
| Rule `100103` | Rule·Push·Integrator 설정 G3 strict PASS, 무해 Rule `100102` N=3 | 부분 확인 | 실제 공격 Event→Rule `100103` Alert·정상 대조군 |
| Shuffle G0 | Private Workflow·Webhook·Header·Shape Snapshot | PASS | 최종 Rule/Action 계약 갱신 |
| Shuffle G1 | `repeat_back_to_me`가 `$exec`를 읽는 구조 Read-back | PASS | 실제 Containment Workflow로 교체 |
| Shuffle G2 | 정상 Header 1 Execution FINISHED, wrong/missing Header 신규 Execution 0 | PASS | 실제 Wazuh Alert Payload 검증 |
| Wazuh/Shuffle G3 | Integrator·Rule `100103`·Secret Mount·Daemon strict Runtime | PASS | 최종 Trigger를 S3 고신뢰 Rule로 전환·재검증 |
| 실제 Alert→Execution | G3 범위 밖 | 미완료 | 고신뢰 S3 Alert G4 |
| 자동 Containment | Source·Test 후보 존재 | 미완료 | 실제 적용·효과·Rollback·Blast Radius |
| 관제 Dashboard | 한글 Dashboard·Saved View·Drill-down 존재 | 부분 확인 | Seed Alert 중심 View·동일 TAKE·3분 Test |
| Remediation·Recovery | `low → impossible`, Terraform 보안 Profile Source 후보 | 미완료 | 승인 Workflow·Runtime·재공격·정상 기능 |

### 현재 Evidence를 잘못 확대하지 않는다

- G2 합성 Payload 왕복은 실제 Wazuh Alert E2E가 아니다.
- G3 strict PASS는 실제 Rule Alert→Shuffle Execution 증거가 아니다.
- Rule `100100` 양성 1건은 자동 차단 안전성 전체를 증명하지 않는다.
- 보존된 여러 날짜의 5-Source Event는 동일 Incident Timeline이 아니다.
- Dashboard 존재는 다른 사람이 쉽게 읽을 수 있다는 증거가 아니다.

---

## 4. Requirement ID

| ID | 촬영 필수 능력 | Recording Scene |
|---|---|---|
| `RQ-ATTACK` | 통제된 공격과 가짜 S3 Object 접근 재현 | `SC-01`, `SC-02` |
| `RQ-INGEST` | 5개 Source를 Wazuh에 보존·검색 | `SC-00`, `SC-07` |
| `RQ-EARLY` | Rule `100103` 조기 이상 징후 | `SC-03` |
| `RQ-S3-HC` | 보호 대상 S3 성공 접근 고신뢰 Rule | `SC-04` |
| `RQ-SOAR` | 실제 고신뢰 Alert→Shuffle Execution | `SC-05` |
| `RQ-CONTAIN` | 좁고 가역적인 자동 격리 | `SC-05`, `SC-06` |
| `RQ-INVESTIGATE` | Alert 중심 Incident Investigation View | `SC-07` |
| `RQ-RUNBOOK` | 현재 사실·자동 조치·다음 조치 안내 | `SC-07`, `SC-08` |
| `RQ-REMEDIATE` | 사람 승인 후 Remediation·Recovery | `SC-08` |
| `RQ-RETEST` | 동일 공격 실패·정상 기능 성공 | `SC-09` |
| `RQ-EVIDENCE` | TAKE·UTC·ID·SHA·마스킹·재촬영 | 전 Scene |

---

# 5. Gate

## 공통 검증 기록 원칙

- 기본 완료 기록은 각 Gate의 체크박스와 짧은 Runtime 결과다. 모든 Gate마다 별도 Bundle·Manifest·
  SHA 파일을 만들지는 않는다.
- 별도 Evidence 파일은 최종 영상의 핵심 Runtime 주장, Alert↔Execution 일대일, 실제 자동 조치·
  복구처럼 나중에 다시 확인해야 하는 항목에만 만든다.
- 합성 Test·Preflight·Catch-up/Drain은 `TEST`, `PRE-RUNTIME`, `PRECONDITION`으로 구분하며
  뒤 Gate의 PASS를 대신하지 않는다. Stale backlog는 개별 메시지를 Evidence 목적으로 보존하지 않는다.
- 기록을 남길 때도 실제 Credential·Token·Cookie·Webhook URI·원문 Secret은 저장하지 않는다.

### 현재 핵심 Evidence 참고 — 2026-08-20

| Gate | 현재 판정 | 정본 Evidence |
|---|---|---|
| `GT-00` | `PASS` | `C:\Users\Unoh\Documents\aws-topology-evidence\gt00\gt00-three-take-index-20260820T102636Z.json` / `b4b0bf0df457d454e59370b0b2bc274e53a16adcd0504f05c39c23c29b6512ee` |
| `GT-01` | `PASS` | `C:\Users\Unoh\Documents\aws-topology-evidence\capital-one-20260820T092407Z-a5bca9cd\gt01-wazuh-timeline.json` / `fc7c7ec3991002d529f25c153c9038d9a5935866b32e1eb6c7d8b256497e8a98` |
| `GT-02` | `NOT RUN` | 없음. Stale backlog Drain은 별도 `PRECONDITION` Evidence로만 보존한다. |
| `GT-03` | `PRE-RUNTIME PASS`, Gate 미통과 | `C:\Users\Unoh\Documents\aws-topology-evidence\gt03-pre-runtime\gt03-wazuh-rule-matrix-20260820T102542Z.json` / `81e4caf545cd25906abc313fcf3a4d1961225aadc1da87f4afcec35860a7d365` |
| `GT-04`~`GT-11` | `NOT RUN` | 없음 |

## GT-00 — 공격·Lab Scope·공개본

### 목적

공격을 동일 조건으로 반복하고 공개 가능한 Evidence를 만든다.

### 해야 할 일

- [x] 촬영용 새 `TAKE_ID` 발급 계약 고정
- [x] Account·Region·Bucket·`validation/*` 고정
- [x] 가짜 Object 내용·Hash 고정
- [x] 실제 Credential 원문 비저장 확인
- [x] 공격 Runner 3회 Rehearsal
- [x] 실패 시 Credential 제거·환경 원복
- [x] 공개 화면용 마스킹 Profile 확정

### PASS Evidence

- 3회 중 3회 같은 공격 단계 재현
- 실제 데이터 0
- Credential 노출 0
- 시작·종료 UTC·Object Hash·TAKE 기록

### Runtime Result — 2026-08-20

- 독립 TAKE 3개에서 IMDS Role 발견→임시 Credential Memory 사용→고정 가짜
  `validation/capital-one-demo.csv` 읽기 3/3 성공
- 고정 가짜 Object SHA-256:
  `625dad237e31a1ba4c6de1b0bf0153c2f62e56f5b6a18d97242d4c41665a4d9e`
- TAKE:
  - `capital-one-20260820T092251Z-238b87c3`
  - `capital-one-20260820T092331Z-93e0af3c`
  - `capital-one-20260820T092407Z-a5bca9cd`
- 세 Evidence 모두 임시 Credential 환경 제거와 Credential 원문 비저장을 기록
- 세 TAKE Evidence와 현재 변경 파일 Secret Scan: 0 findings
- 공개 마스킹 계약:
  `observability/scenarios/capital-one-public-masking.json`
- 3-TAKE Evidence Index:
  `C:\Users\Unoh\Documents\aws-topology-evidence\gt00\gt00-three-take-index-20260820T102636Z.json`
- Evidence SHA-256:
  `b4b0bf0df457d454e59370b0b2bc274e53a16adcd0504f05c39c23c29b6512ee`
- 첫 두 TAKE는 원본 `capital-one-baseline.json`만 보존됐고 전체 Manifest Bundle은 없다.
  Index는 세 원본 파일을 SHA-256으로 결속하지만 당시 수집되지 않은 파일을 복구하지는 않는다.

---

## GT-01 — Wazuh 로그 Coverage와 동일 TAKE Timeline

### 목적

평소 축적된 로그가 실제 사건 조사에 사용 가능한지 확인한다.

### 필수 Source

```text
CloudFront
WAF
ALB
DVWA 안전 Audit
CloudTrail S3 Data Event
```

### 해야 할 일

- [x] 새 공격 TAKE에서 5개 Source 수집
- [x] 각 Source Event Time·필드·Index 확인
- [x] 동일 TAKE와 다른 날짜 보존 Event 분리
- [x] Source별 관측 의미와 한계 기록
- [x] Pod→IMDS 네트워크 직접 관측 공백 표시
- [x] 모든 Source를 관통하는 공통 ID가 없음을 Evidence에 표시

### PASS Evidence

한 TAKE의 연속 시간창에서 각 Source가 실제로 검색되고, 다음 상관 기준을 설명할 수 있다.

| 연결 | 기준 |
|---|---|
| CloudFront ↔ WAF | Edge Request ID 또는 시간·Method·Path |
| WAF ↔ ALB ↔ DVWA | 시간·Method·Path·Client/Target 문맥 |
| DVWA ↔ CloudTrail | 시간·Role·Bucket/Key·공격 단계 |

### Runtime Result — 2026-08-20

- TAKE: `capital-one-20260820T092407Z-a5bca9cd`
- Wazuh archive와 `wazuh-archives-4.x-2026.08.20` Index에서 같은 사건 시간창 확인
  - CloudFront `2`, WAF `2`, ALB `2`, DVWA 안전 Audit `2`, CloudTrail S3 Data Event `1`
- CloudFront↔WAF: Edge Request ID `2/2` exact match
- ALB↔DVWA: ALB Trace ID와 DVWA Request ID `2/2` exact match
- WAF↔ALB: 같은 Method·Path와 요청 시작 시각 차이 `3ms`, `4ms`
- 마지막 DVWA Event에서 보호 대상 CloudTrail `GetObject`까지 `4초`
- 공통 전역 ID가 없으며 Pod→IMDS 네트워크를 직접 관측하지 않는다는 한계를 보존
- Evidence:
  `C:\Users\Unoh\Documents\aws-topology-evidence\capital-one-20260820T092407Z-a5bca9cd\gt01-wazuh-timeline.json`
- Evidence SHA-256:
  `fc7c7ec3991002d529f25c153c9038d9a5935866b32e1eb6c7d8b256497e8a98`

---

## GT-02 — Rule 100103 조기 이상 징후

### 목적

S3 침해 확정 전 조기 징후를 실제 Push Alert로 보여준다.

### 해야 할 일

- [ ] 실제 공격 독립 `TAKE` 3회
- [ ] 각 TAKE에서 실제 발생한 `command.execution` Event N→Rule `100103` Alert N 일대일
- [ ] `event_id`, Event Time, Alert Time 보존
- [ ] 정상 Route·Resource·Result 대조군 Alert 0
- [ ] Offline Catch-up과 동일 `event_id` 중복 Alert 0
- [ ] Rule `100103`을 자동 격리 Trigger에서 제거하거나 observe-only로 고정

### PASS Evidence

```text
독립 공격 TAKE 3
실제 공격 Event N
Rule 100103 Alert N
누락 0
동일 event_id 중복 0
정상 대조군 Alert 0
```

`N`은 공격 Runner가 실제로 만든 승인 Event 수로 정한다. 한 공격이 여러 IMDS 단계
Event를 만들 수 있으므로 TAKE당 1건이나 총 3건으로 하드코딩하지 않는다.

---

## GT-03 — 보호 대상 S3 고신뢰 Rule

### 목적

자동 조치에 사용할 수 있는 엄격한 S3 침해 확인 Alert를 만든다.

### 최소 의미 조건

```text
eventSource = s3.amazonaws.com
eventName = GetObject
recipientAccountId = 승인 Account
requestParameters.bucketName = 승인 Bucket
requestParameters.key starts with validation/
errorCode 없음
Principal/Role Session = 공격 시나리오 승인 대상
정상 Allowlist 불일치
```

### 해야 할 일

- [x] 현재 Rule `100100`의 실제 Decoded Field·조건 재검토
- [x] 부족하면 새 Rule ID 생성
- [x] Rule Level·Group·Description 확정
- [ ] Alert에 CloudTrail `eventID`, Principal, Bucket/Key, 성공 여부 포함
- [ ] 공격 Positive 3회
- [ ] 정상 `terra-user` Negative Control 3회
- [ ] 다른 Bucket·Prefix·Principal·실패 응답 대조군
- [ ] 재수집 동일 `eventID` 중복 처리 확인
- [ ] Event→Wazuh Alert 실제 지연 측정

### PASS 기준

```text
공격 3/3 Alert
정상 대조군 0 Alert
비대상 Prefix 0 Alert
실패 GetObject 0 Alert
원본 eventID ↔ Alert 1:1
```

Rule이 이 기준을 통과하기 전에는 Shuffle Write를 연결하지 않는다.

### 2026-08-20 Pre-Runtime 결과

- 기존 Rule `100100`은 정상 성공 Event를 탐지하지만, 합성
  `errorCode=AccessDenied + HTTP 200`도 탐지해 자동 조치용 fail-closed 계약에는 부족하다.
- 신규 고신뢰 Source 계약은 Rule `100104` Level 12로 고정했다. 현재 Wazuh `4.14.7`의
  `aws-eventnames` CDB에는 `GetObject`가 없으므로 부모는 `80202`가 아니라 `80200`을 사용한다.
- Rule `100104`는 Account·Region·`AssumedRole`·Node Role·현재 승인 Bucket·고정 Object Key·
  HTTP 200·UUID `eventID`를 모두 exact 조건으로 확인한다.
- Rule `100105` Level 0 child는 `errorCode`가 존재하는 모순 Event를 억제한다.
- `wazuh-analysisd -t`와 합성 `wazuh-logtest` Matrix는 통과했다. Positive는 `100104/12`,
  `errorCode + HTTP 200`은 `100105/0`, 나머지 비대상·누락 조건은 `100104`가 발생하지 않았다.
- Pre-Runtime Evidence:
  `C:\Users\Unoh\Documents\aws-topology-evidence\gt03-pre-runtime\gt03-wazuh-rule-matrix-20260820T102542Z.json`
- Evidence SHA-256:
  `81e4caf545cd25906abc313fcf3a4d1961225aadc1da87f4afcec35860a7d365`
- 이는 Source/Rule 단위 Test이며 GT-03 Runtime PASS가 아니다. Manager 적용 후 실제 공격 Positive
  3회, 정상·비대상 Negative, 원본 `eventID` 일대일, 실제 지연은 아직 남아 있다.

---

## GT-04 — 고신뢰 Wazuh Alert → Shuffle 실제 E2E

### 목적

멘토가 요구한 `어떤 Rule → Shuffle이 어떤 행위`를 실제 Runtime으로 증명한다.

### 해야 할 일

- [ ] `<integration>` 대상 Rule을 최종 고신뢰 S3 Rule로 변경 또는 별도 등록
- [ ] `custom-shuffle-soc`가 CloudTrail Alert 필드를 Sanitizer에 포함
- [ ] Secret·원본 Credential·불필요한 Request 원문 제거
- [ ] Webhook Header exact match 유지
- [ ] 정상 실제 Alert→신규 Execution 1개
- [ ] wrong/missing Header→Execution 0
- [ ] 미등록 Rule·Account·Prefix→Write 0
- [ ] Wazuh Alert·CloudTrail eventID·Shuffle Execution ID 연결
- [ ] Retry·Timeout·오류 로그 확인

### Dedupe Key

CloudTrail 확인 Event는 재수집 때 달라질 수 있는 Wazuh Alert ID가 아니라 원본 `eventID`를 사용한다.

### PASS Evidence

```text
Actual Wazuh Rule Alert: 1
New Shuffle Execution: 1
Execution terminal: FINISHED/SUCCESS
Wrong/missing header execution: 0
Unexpected action: 0
```

---

## GT-05 — 자동 Containment

### 목적

사전 승인된 좁은 범위의 대응만 자동 실행한다.

### 필수 자동 조치

```text
1. DVWA Workload Quarantine
2. validation/* 추가 접근 제한
   또는 사전 승인된 전용 Principal 제한
```

### 금지

- 공유 Karpenter Node Role 전체 `DenyAll`
- 임의 Namespace·Selector·CIDR·Repository 입력
- Alert 원문을 그대로 Shell/Workflow Input에 사용
- 관제자가 확인하지 않은 광범위 IAM 변경

### 해야 할 일

- [ ] 고정 Target·Allowlist 계약
- [ ] NetworkPolicy enforcement 실제 확인
- [ ] Resource/Permission Deny 대상 고정
- [ ] Workflow Idempotency
- [ ] 같은 CloudTrail eventID 10회 전달 시 Action 1회
- [ ] 실패 시 DLQ/오류 상태 또는 명시적 승인 대기
- [ ] Rollback Workflow·사람 승인 경계
- [ ] 다른 Namespace·Object Prefix 영향 Test

### PASS Evidence

- Shuffle 검증·Containment Outcome
- NetworkPolicy UID/Commit/Revision
- Resource Policy/IAM 변경 Diff
- Action 1회·중복 0
- 비대상 영향 0
- Rollback 성공

---

## GT-06 — Containment 효과와 Blast Radius

### 목적

차단이 실제로 공격 경로를 끊었고 정상 범위를 보존했는지 검증한다.

### 해야 할 일

- [ ] 동일 Credential/Session의 `validation/*` 추가 접근 실패
- [ ] DVWA Workload의 공격용 Egress 실패
- [ ] 정상 Health/관측 경로 유지
- [ ] 다른 Namespace 정상
- [ ] 비대상 S3 Object/서비스 영향 확인
- [ ] 실패 원인이 Containment임을 구분

### PASS Evidence

```text
공격 경로: DENIED
비대상 Namespace: PASS
정상 서비스: PASS
예상하지 않은 영향: 0
```

---

## GT-07 — Alert 중심 Incident Investigation View

### 목적

완전 자동 Graph 없이도 최초 Alert에서 관련 로그를 쉽게 읽게 한다.

### 필수 화면 영역

1. **Incident Summary**
   - Rule·위험도·Event Time
   - Principal/Role Session
   - Bucket/Key
   - 자동 조치 결과
2. **Detection Rationale**
   - 왜 고신뢰인지
   - 어떤 조건이 일치했는지
3. **Evidence Timeline**
   - CloudFront·WAF·ALB·DVWA·CloudTrail
4. **Observed Gaps**
   - 공통 ID 부재
   - Pod→IMDS 직접 네트워크 로그 부재
5. **Actions Taken**
   - Shuffle Execution·Containment
6. **Next Actions**
   - Rule별 Runbook
7. **Raw Drill-down**
   - 원본 Event·Alert 상세

### 구현 최소안

- 기존 Wazuh Dashboard/Saved Search를 재사용한다.
- Seed Alert에서 다음 필드를 읽어 미리 만든 View에 적용한다.

```text
Event Time window
CloudTrail eventID
Principal / Role Session
Source IP
Bucket / Key
URI / Method
Rule ID
```

- 1-click Deep Link가 어려우면 2단계 절차를 허용한다.
  1. Alert 상세에서 필드 확인
  2. `Capital One Incident Investigation` Saved View 열기
- 별도 자동 Graph Engine은 만들지 않는다.

### 해야 할 일

- [ ] 기존 `SOC-LIVE-OVERVIEW.ndjson`·Saved Objects 재검토
- [ ] 기존 `security-log-investigation.json`에서 재사용 가능한 Query 확인
- [ ] 새 TAKE 5-Source Timeline으로 Dashboard 갱신
- [ ] Rule `100104` Seed View 고정
- [ ] 자동 조치 결과 표시
- [ ] 관측 공백 표시
- [ ] 공개본 마스킹 View 분리
- [ ] Raw Drill-down 링크 확인

### 사용성 PASS

검색 문법을 모르는 팀원이 3분 안에 다음을 설명해야 한다.

```text
무슨 일이 발생했는가
왜 고신뢰 Alert인가
어떤 자산과 Principal이 관련됐는가
무엇이 자동으로 차단됐는가
어떤 Evidence가 공격 경로를 지지하는가
무엇은 아직 보이지 않는가
다음에 무엇을 확인·조치해야 하는가
```

---

## GT-08 — Rule별 Runbook·의사결정 지원

### 목적

관제자가 로그를 읽고 다음 조치를 쉽게 구상하도록 한다.

### 필수 내용

```text
확인된 사실
추정 또는 미확정
이미 수행한 자동 조치
영향 자산
관측 공백
추가 조사 항목
후속 대응 후보
승인 필요 조치
```

### S3 고신뢰 Rule Runbook 후보

1. 같은 Principal/Role Session의 다른 S3 접근 확인
2. 다른 AWS API·Resource 접근 확인
3. Credential/Session 재사용 여부 확인
4. 최초 침투 Workload와 URI 확인
5. IAM 최소 권한 검토
6. DVWA 취약 설정 패치
7. IMDSv2·Hop Limit·Node 영향 검토
8. 임시 격리 유지·해제 조건 확인

### 구현 방법

- Dashboard Markdown/Description 또는 별도 Saved View
- Rule ID별 고정 Runbook 링크
- 필요하면 Shuffle 결과에 다음 조치 요약 포함
- LLM이 새로운 대응을 생성하는 기능은 필수 아님

### PASS 기준

다른 팀원이 Dashboard만 보고 승인해야 할 다음 조치와 자동으로 이미 끝난 조치를 구분한다.

---

## GT-09 — Remediation·Recovery

### 목적

자동 격리 뒤 사람이 근본 대응을 결정·승인한다.

### 최소 촬영 대응

```text
DVWA defaultSecurityLevel: low → impossible
```

이는 애플리케이션 보안 설정 패치다.

### 완성형 Recovery 후보

- IAM 최소 권한
- `validation/*` 실습 권한 제거 또는 축소
- IMDSv2 강제
- Hop Limit 검토·보강
- 필요 시 Node 교체
- 임시 IAM Deny·Quarantine 해제

### 해야 할 일

- [ ] Containment와 Remediation Workflow 분리
- [ ] 허용 파일·값 1개 계약
- [ ] GitHub `workflow_dispatch` 고정
- [ ] 예상하지 않은 Diff 0
- [ ] Argo exact Commit SHA 배포
- [ ] 새 Pod·새 세션에서 `impossible`
- [ ] IAM/IMDS Apply는 Fresh Plan·사람 승인·Post-Apply 확인
- [ ] 격리 해제 순서·주체·UTC 기록

### PASS Evidence

- 승인 기록
- GitHub Run·Commit SHA
- Argo Revision·Healthy
- 실제 IAM/IMDS Runtime
- 임시 조치 해제 Evidence

---

## GT-10 — 동일 공격·정상 기능 재검증

### 목적

서비스 중단이 아니라 공격 경로 제거를 증명한다.

### 해야 할 일

- [ ] 동일 Payload 재실행
- [ ] 애플리케이션 계층 실패 확인
- [ ] 기존 Credential/Session의 보호 대상 접근 실패
- [ ] 정상 로그인 성공
- [ ] 승인 기능 성공
- [ ] 새 Rule `100103` 조기 위협 Event·Rule `100104` 고신뢰 S3 성공 Alert 증가 없음
- [ ] 관찰 시간창 고정

### PASS 기준

```text
동일 공격: FAIL
보호 대상 S3 추가 접근: DENIED
정상 기능: PASS
새 고신뢰 S3 성공 Alert: 0
```

---

## GT-11 — 촬영 준비·Rehearsal·공개본

### 해야 할 일

- [ ] 모든 Gate Evidence Index 작성
- [ ] Secret Scan
- [ ] 공개 마스킹 확인
- [ ] 화면 배치·브라우저 탭·폰트 크기 고정
- [ ] UTC·TAKE·Rule·Event·Execution·SHA 표시 확인
- [ ] 실제 대기시간 측정
- [ ] 편집 자막 Template 준비
- [ ] 실패 TAKE 처리·수동 Reset Rehearsal
- [ ] 팀원별 내레이션 담당 확정
- [ ] 본편 전체 2회 무중단 Rehearsal
- [ ] 최종 촬영 파일 열기·재생 확인

### 촬영 시작 조건

`GT-00~GT-10`의 미완료 항목이 0이어야 한다. Plan-only나 합성 Payload 성공으로 대체하지 않는다.

---

# 6. 구현 Workstream과 순서

## WS-1 — Rule 계약 확정

1. Rule `100100` 현재 조건·Decoded Field 재검토
2. 정상·비대상 대조군 추가
3. 재사용 또는 새 Rule ID 결정
4. Alert Field·Description·Level 고정
5. GT-03 Runtime

## WS-2 — Wazuh→Shuffle Trigger 전환

1. 기존 Rule `100103` Integration을 early-warning/observe-only로 정리
2. 고신뢰 S3 Rule용 Integration 추가
3. CloudTrail Sanitizer Schema 확장
4. `eventID` Dedupe
5. 실제 Alert→Execution GT-04

## WS-3 — Containment

1. Workload Quarantine Target 고정
2. `validation/*` Resource/Permission 제한 방식 결정
3. Validator·Dispatcher Allowlist
4. Dry Run
5. 실제 Apply·Rollback
6. GT-05·GT-06

## WS-4 — Incident Investigation View

1. 동일 TAKE 5-Source 수집
2. Seed Alert Field 선정
3. Saved View·Dashboard 구성
4. Runbook·관측 공백·자동 조치 표시
5. Raw Drill-down
6. 3분 사용성 Test
7. GT-07·GT-08

## WS-5 — Remediation·Recovery

1. `low → impossible` 별도 Workflow
2. GitHub/Argo Runtime
3. IAM·IMDS 영구 대응
4. 동일 공격·정상 기능 Test
5. GT-09·GT-10

## WS-6 — 촬영

1. 공개본·Masking
2. Scene별 Evidence 배치
3. 대기시간·자막 확정
4. Rehearsal 2회
5. 최종 촬영

### 권장 의존 순서

```text
GT-00
→ GT-01
→ GT-02
→ GT-03
→ GT-04
→ GT-05
→ GT-06
→ GT-07·GT-08
→ GT-09
→ GT-10
→ GT-11
→ 촬영
```

뒤 Gate의 성공으로 앞 Gate를 대체하지 않는다.

---

# 7. 촬영 필수에서 제외한 것

다음은 구현되면 좋지만 촬영 완료 조건은 아니다.

- 모든 AWS Source의 저지연 Push 전환
- CloudTrail S3 Route를 새 Streaming Route로 교체
- 완전 자동 Incident Graph
- 모든 Source를 관통하는 공통 Trace ID
- LLM 자동 분석·자동 보고서
- 두 번째 공격 시나리오
- GuardDuty Finding 강제 생성
- 24시간 HA SOC
- 여러 SIEM 동시 구축

기존 S3 Archive·Poll Route는 실패 구조가 아니다. 이번 시연에서는 고신뢰 S3 Event의 탐지 Source와 평소 축적 로그의 조사 경로로 사용한다.

---

# 8. 금지 표현

```text
Rule 100103으로 S3 침해를 확정했다.
S3 API 호출과 동시에 격리했다.
GetObject 하나만 보고 무조건 공격으로 판정했다.
Wazuh가 모든 로그의 인과관계를 자동으로 완벽히 분석했다.
Wazuh가 AI처럼 정답 조치를 새로 만들어줬다.
공유 Node Role 전체를 안전하게 자동 폐기했다.
low → impossible이 Credential을 폐기했다.
보존된 다른 날짜의 로그가 같은 Incident다.
합성 Webhook Test로 실제 Wazuh→Shuffle E2E를 완료했다.
```

권장 표현:

```text
Rule 100103은 조기 이상 징후다.
엄격한 보호 대상 S3 성공 접근 Rule을 고신뢰 자동 조치 Trigger로 사용했다.
CloudTrail Event가 Wazuh에 탐지된 직후 사전 승인된 격리를 자동 실행했다.
Alert의 시간·Principal·Bucket/Key를 중심으로 저장된 관련 로그를 좁혀 조사했다.
Wazuh는 근거·관측 공백·Runbook을 보여주고, 관제자가 근본 대응을 승인했다.
```

---

# 9. 최종 Stop Condition

다음 수치가 모두 0이면 문서 검토를 끝내고 촬영한다.

```text
미완료 Gate = 0
정상 대조군 오탐 = 0
실제 Alert↔Execution 미연결 = 0
중복 자동 조치 = 0
비대상 영향 = 0
같은 TAKE에서 빠진 필수 Evidence = 0
Secret 노출 = 0
설명할 수 없는 관측 공백 = 0
```

그 이후의 개선점은 촬영 완료를 막지 않고 Future Work로 이동한다.
