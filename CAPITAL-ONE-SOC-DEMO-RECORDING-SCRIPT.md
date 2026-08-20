# Capital One 기반 SOC 시연 녹화 대본

> **상태:** TARGET RECORDING SCRIPT — 모든 촬영 Gate가 PASS한 완성형 관제 시스템을 전제로 함  
> **촬영 가능 조건:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)의 `GT-00~GT-10`과 `GT-11A` PASS
> **공격·대응 의미:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)

이 문서는 촬영 당일 펼쳐놓는 실제 대본이다. 구현 방법과 남은 작업은 시연 계획에서 관리한다.

---

## 0. 영상이 증명할 것

본편은 다음 한 문장을 실제 Runtime Evidence로 증명한다.

> **평소 Wazuh에 축적되는 AWS·애플리케이션 로그를 이용해 공격의 조기 징후와 보호 대상 S3 접근 성공을 탐지하고, 고신뢰 Alert가 발생하면 Shuffle이 사전 승인된 격리를 자동 실행하며, 관제자는 해당 Alert를 중심으로 관련 로그와 이미 수행된 조치를 쉽게 읽고 근본 대응을 결정한 뒤 동일 공격 실패와 정상 기능 유지를 확인했다.**

영상의 주인공은 공격 도구나 GitOps Pipeline이 아니라 **관제 시스템**이다.

본편이 반드시 보여줘야 하는 관제 능력:

```text
평상시 로그 중앙화
→ 조기 이상 징후 탐지
→ 보호 대상 S3 접근 성공 고신뢰 탐지
→ 사전 승인된 자동 격리
→ Alert 중심 사건 조사
→ 관제자의 후속 조치 결정
→ Remediation·Recovery
→ 동일 공격과 정상 기능 재검증
```

### 정확한 주장 경계

- Rule `100103`은 `command.execution + ec2_imds + succeeded` 조기 이상 징후다.
- Rule `100103`만으로 Credential 탈취나 S3 접근 성공을 확정하지 않는다.
- 보호 대상 `validation/*`의 성공한 `GetObject`를 엄격한 조건으로 탐지한 Rule `100104`를 고신뢰 자동 조치용으로 사용한다.
- Rule `100104`의 `GT-03` 탐지, `GT-04` Wazuh→Shuffle, `GT-05` Containment Runtime이 모두 PASS하지 않으면 이 대본으로 촬영하지 않는다.
- `GetObject` 성공은 보호 대상 Object 읽기 성공을 뜻한다. 외부 반출 전체를 별도로 증명하지 않았다면 `대규모 유출 완료`라고 말하지 않는다.
- 자동 격리는 **S3 API 호출 순간**이 아니라 해당 CloudTrail Event가 Wazuh에 도착해 고신뢰 Alert가 발생한 직후 시작된다.
- Wazuh의 사건 조사 화면은 저장된 로그를 미리 정의한 상관 키로 좁혀 보여주는 화면이다. 실제로 구현하지 않은 자동 인과 그래프나 AI 진단으로 과장하지 않는다.

---

## 1. 촬영 공통값

촬영 시작 전에 한 곳에 기록한다.

```text
FINAL_TAKE_ID=<새 촬영 ID>
START_UTC=<UTC ISO 8601>
BASELINE_DVWA_REVISION=<공격 전 main SHA>
HIGH_CONFIDENCE_RULE_ID=100104
REMEDIATION_REVISION=<촬영 중 생성될 SHA>
RECOVERY_EVIDENCE_ID=<최종 검증 Evidence ID>
```

모든 장면은 같은 `FINAL_TAKE_ID`를 사용한다. AWS Event에 TAKE_ID가 자동으로 들어간다고 설명하지 않으며, TAKE_ID는 Runner·Evidence Bundle·촬영 구간을 묶는 외부 식별자다.

## 2. 화면·편집·자막 공통 규칙

### 화면

- Wazuh, Shuffle, GitHub, Argo CD, Terminal 시간을 가능한 한 UTC로 맞춘다.
- Rule ID, Event ID, Principal, Bucket/Key, Shuffle Execution ID, Commit SHA는 앞·뒤 일부가 대조 가능하게 보인다.
- Credential, Session Token, Cookie, Authorization Header, Webhook URL·Key, PAT은 절대 노출하지 않는다.
- 공개본에서는 Account ID, Bucket 이름, Client IP, 전체 ARN을 규칙에 따라 마스킹한다.
- Command 원문과 IMDS Credential 응답 원문은 화면에 띄우지 않는다.

### 자막

각 전환에는 다음 형식을 사용한다.

```text
[같은 TAKE_ID: <앞 8자>]
[Event 발생 → Wazuh Alert: 실제 N분 N초]
[Wazuh Alert → Shuffle Execution: 실제 N초]
[자동 격리 적용 완료: UTC]
[같은 TAKE — CloudTrail/S3 수집 대기 구간 편집]
```

`즉시`, `실시간`이라는 자막은 실제 측정 구간을 함께 표시할 때만 사용한다.

### 편집

- CloudTrail 전달·S3 Poll·배포 대기 구간은 편집할 수 있다.
- 편집 전후 UTC, 실제 경과시간, 동일 TAKE임을 자막에 남긴다.
- 다른 TAKE나 다른 날짜의 로그를 하나의 Incident처럼 붙이지 않는다.
- 실패 장면을 성공처럼 편집하지 않는다.
- 자동화가 실행된 장면과 사람이 선택한 장면을 구분한다.

---

## 3. 본편 장면 요약

| Scene | 장면 | 관제 관점의 핵심 주장 | 필수 Gate |
|---|---|---|---|
| `SC-00` | Slate·평상시 관제 | 로그가 평소부터 Wazuh에 축적되고 시스템이 READY다 | `GT-00`, `GT-01`, `GT-11A` |
| `SC-01` | 공격 범위 설명 | Capital One 기반 Lab 각색이며 보호 대상은 `validation/*`다 | `GT-00` |
| `SC-02` | 공격 1회 | Command Injection → IMDS → 임시 자격증명 → S3 접근을 한 TAKE로 실행한다 | `GT-00` |
| `SC-03` | 조기 이상 징후 | Rule `100103`은 S3 침해 확정 전 조기 경보다 | `GT-02` |
| `SC-04` | S3 고신뢰 탐지 | 보호 대상 `GetObject` 성공을 엄격한 Rule로 탐지한다 | `GT-03` |
| `SC-05` | Shuffle 자동 격리 | 고신뢰 Alert가 사전 승인된 격리를 한 번 실행한다 | `GT-04`, `GT-05` |
| `SC-06` | 격리 효과 | 추가 접근은 실패하고 정상 영향 범위는 보존된다 | `GT-06` |
| `SC-07` | Alert 중심 사건 조사 | 관련 로그·관측 공백·이미 수행된 조치를 쉽게 읽는다 | `GT-07`, `GT-08` |
| `SC-08` | 관제자 후속 조치 | 자동 대응 이후 사람이 근본 조치를 결정·승인한다 | `GT-09` |
| `SC-09` | 재검증·종료 | 동일 공격 실패, 정상 기능 성공, 새 S3 성공 Event 없음 | `GT-10` |

---

# 4. 본편 녹화 대본

## SC-00 — 촬영 Slate와 평상시 관제

### 보여줄 화면

- `FINAL_TAKE_ID`, 시작 UTC
- Wazuh Manager·Indexer·Dashboard READY
- Shuffle Webhook/Workflow READY
- Wazuh Reader와 로그 수집 상태 READY
- Argo CD `Synced + Healthy`
- Wazuh 전체 현황 Dashboard
- 최근 정상 Event가 각 Source에서 수집되는 모습

### 운영자 조작

1. Secret이 제거된 Preflight를 실행한다.
2. Wazuh 전체 현황 Dashboard를 연다.
3. CloudFront·WAF·ALB·DVWA·CloudTrail Source가 검색 가능한 상태를 짧게 보여준다.
4. TAKE_ID와 시작 UTC를 3초 이상 고정한다.

### 내레이션

> 이 환경은 AWS와 애플리케이션에 흩어진 로그를 Wazuh로 중앙화해 평상시부터 관제합니다. 지금은 공격 전 정상 상태이며, 이번 실행을 구분할 새 TAKE ID와 UTC를 기록했습니다. Wazuh, Shuffle, 로그 수집 계층과 배포 상태가 모두 준비됐습니다.

### 자막

```text
정상 상태 — Wazuh 중앙 관제 READY
CloudFront · WAF · ALB · DVWA · CloudTrail 수집
TAKE_ID=<앞 8자> / START_UTC=<시각>
```

### 필수 Evidence

- 5개 Source 검색 가능
- Wazuh 3개 Service 정상
- Shuffle Workflow·Webhook 활성
- Baseline Git SHA와 Argo Revision
- 이전 TAKE Credential 잔존 없음

### 중단 조건

READY 항목 하나라도 실패하거나 이전 Credential이 남아 있으면 공격하지 않는다.

---

## SC-01 — 공격 시나리오와 주장 범위

### 보여줄 화면

- 단순 공격 도식
- `DVWA Command Injection → IMDS → Node Role Credential → validation/* GetObject`
- 가짜 Lab Object임을 나타내는 화면

### 내레이션

> 실제 Capital One 사고의 SSRF를 그대로 재현한 것은 아닙니다. 교육용 DVWA Command Injection을 진입점으로 사용해 IMDS의 Node Role 임시 자격증명에 접근하고, 제한된 가짜 S3 Object를 읽는 공격 경로를 각색했습니다. 보호 대상은 `validation/*`로 한정됩니다.

### 자막

```text
Capital One 기반 교육용 각색
실제 개인정보 없음 / Lab Scope: validation/*
```

### 필수 Evidence

- 공격 Target·Account·Region·Object Prefix 고정
- 실제 데이터가 아닌 가짜 데이터
- 실제 SSRF 재현이 아니라는 설명

---

## SC-02 — 통제된 공격 1회

### 보여줄 화면

- 승인된 공격 Runner
- 같은 TAKE_ID
- Credential 원문이 제거된 단계별 결과
- S3 가짜 Object 읽기 성공 여부

### 운영자 조작

1. Target과 Prefix를 마지막으로 확인한다.
2. 공격 Runner를 한 번만 실행한다.
3. Source Event 시각과 Exit Status를 보존한다.
4. Credential은 화면·파일에 출력하지 않는다.

### 내레이션

> 공격은 승인된 Lab 범위에서 한 번 실행합니다. 애플리케이션 명령 실행, IMDS 접근, 임시 자격증명 사용과 보호 대상 S3 Object 읽기를 같은 TAKE로 기록합니다.

### 자막

```text
통제된 공격 1회
Credential 원문 비저장
S3 보호 대상 Object 읽기: SUCCESS
```

### 필수 Evidence

- 공격 실행 1회
- Runner 시작·종료 UTC
- 가짜 Object Hash 또는 승인된 식별값
- Credential 원문 미노출

### 중단 조건

허용되지 않은 Target, 실제 데이터, 다른 TAKE가 확인되면 즉시 중단한다.

---

## SC-03 — Rule 100103 조기 이상 징후

### 보여줄 화면

- Wazuh Rule `100103` Alert
- 원본 Push `event_id`
- `event_type=command.execution`
- `result=succeeded`
- `resource=ec2_imds`
- Source UTC와 Alert UTC

### 내레이션

> 애플리케이션 감사 Event는 저지연 전달 경로를 통해 Wazuh Rule 100103으로 탐지됐습니다. 이 경보는 IMDS를 겨냥한 명령 실행 성공이라는 조기 이상 징후입니다. 아직 이 시점에서는 S3 Object 접근 성공까지 확정하지 않습니다.

### 자막

```text
조기 이상 징후 — Rule 100103
IMDS 대상 명령 실행 성공
현재 판단: Credential 탈취·S3 접근 가능성, 미확정
```

### 필수 Evidence

- 실제 Event와 Alert의 동일 `event_id`
- Rule `100103`
- Source → Wazuh 실제 지연
- 정상 대조군 Alert 0

### 중단 조건

실제 Event와 Alert를 ID·UTC로 연결하지 못하면 합성 Alert로 대신하지 않는다.

---

## SC-04 — 보호 대상 S3 접근 고신뢰 탐지

### 보여줄 화면

- CloudTrail S3 Data Event 원본
- 고신뢰 Wazuh Alert
- Rule ID·Level·Description
- `GetObject`
- 성공 여부
- Principal/Role Session
- Bucket·`validation/*` Key
- CloudTrail `eventID`

### 내레이션

> 이후 현재 CloudTrail과 S3 수집 경로를 통해 보호 대상 Object의 성공한 GetObject가 Wazuh에 도착했습니다. 이 Rule은 승인 Account, 보호 Prefix, 예상하지 않은 Principal 또는 공격 시나리오 Principal, 성공 응답을 함께 확인합니다. 이 통제된 Lab에서는 정상 흐름에 없어야 하는 행위이므로 자동 조치를 허용하는 고신뢰 Alert로 사용합니다.

> 자동 조치는 S3 API 호출 순간이 아니라 이 고신뢰 Alert가 Wazuh에 발생한 직후 시작됩니다.

### 자막

```text
고신뢰 침해 확인 — Rule 100104
Protected S3 GetObject: SUCCESS
CloudTrail 도착·Wazuh 탐지까지 실제 N분 N초
```

### 필수 Evidence

- 실제 CloudTrail `eventID`
- Wazuh Alert와 원본 Event의 동일 `eventID`
- 성공 `GetObject`
- 승인된 Bucket·`validation/*`
- 공격 문맥의 Principal/Role Session
- 정상 Principal 대조군 Alert 0

### 중단 조건

- 단순 `GetObject`만으로 Rule이 울림
- 정상 대조군도 같은 Alert를 만듦
- 원본 Event와 Alert를 연결하지 못함

위 조건 중 하나라도 발생하면 자동 조치 Trigger로 사용하지 않는다.

---

## SC-05 — Shuffle 자동 격리

### 보여줄 화면

- Wazuh Alert의 Integrator 전달
- 인증된 Shuffle Webhook
- Validator·Allowlist·중복 방지 결과
- 정확히 한 개의 신규 Shuffle Execution
- Workload 격리 결과
- `validation/*` 추가 접근 제한 또는 승인된 Principal 제한 결과

### 운영자 조작

운영자가 별도 차단 버튼을 누르지 않는다. 고신뢰 Alert 이후 자동으로 생긴 Execution을 열어 결과를 확인한다.

### 내레이션

> 고신뢰 S3 Alert는 Wazuh Integrator를 통해 Shuffle로 전달됩니다. Shuffle은 Account, Scenario, Rule, Resource와 중복 여부를 검증한 뒤 사전 승인된 범위만 격리합니다. 같은 CloudTrail eventID의 재수집이나 중복 Alert는 조치를 반복하지 않습니다.

> 이 시연에서는 DVWA Workload를 격리하고, 공유 Node Role 전체가 아니라 `validation/*` Lab 범위의 추가 접근 영향만 제한합니다.

### 자막

```text
Wazuh Alert → Shuffle 자동 대응
Validation: PASS
Containment Execution: 1회
Duplicate Action: 0
```

### 필수 Evidence

- 실제 Wazuh Alert ↔ Shuffle Execution 일대일 연결
- Webhook 인증 성공
- 잘못된 Header·미등록 Target 거절
- 원본 CloudTrail `eventID` 기반 중복 조치 0
- 실제 Workload/Resource 제한 적용
- 다른 Namespace와 비대상 Resource 영향 0
- Rollback 가능

### 중단 조건

- 합성 Payload만 성공
- 실제 Alert와 Execution을 연결하지 못함
- 동일 Event가 조치를 반복함
- 공유 Role 전체를 광범위하게 차단함

이 경우 `자동 격리 완료`라고 촬영하지 않는다.

---

## SC-06 — 자동 격리 효과 확인

### 보여줄 화면

- 동일 Credential 또는 동일 공격 문맥의 추가 `validation/*` 접근 실패
- DVWA Workload 통신 제한 결과
- 비대상 Namespace·정상 서비스 성공
- 격리 정책·정책 UID 또는 Commit/Revision

### 내레이션

> 자동 격리 뒤 동일한 공격 문맥의 추가 S3 접근은 거부됐습니다. 동시에 비대상 Namespace와 정상 서비스는 유지됩니다. 따라서 전체 환경을 중단한 것이 아니라 사전에 고정한 공격 경로만 제한한 결과입니다.

### 자막

```text
추가 validation/* 접근: ACCESS DENIED
비대상 Namespace·정상 기능: 정상
Blast Radius: 사전 승인 범위
```

### 필수 Evidence

- 추가 접근 실패
- 실패 원인이 적용한 Containment임을 확인
- 정상 대조군 성공
- 정책 적용 전후 상태

---

## SC-07 — Alert를 중심으로 사건 조사

이 장면이 관제 시스템의 핵심 장면이다.

### 보여줄 화면

고신뢰 S3 Alert에서 `Capital One Incident Investigation` Saved View/Dashboard로 이동한다.

화면은 최소한 다음 영역을 가진다.

```text
사건 요약
- 보호 대상 S3 GetObject 성공
- Principal / Role Session
- Bucket / Key
- 위험도
- 자동 격리 결과

관련 Evidence Timeline
- CloudFront: 외부 요청 진입
- WAF: 검사 Action·Label
- ALB: DVWA Target 전달
- DVWA: command.execution·IMDS 조기 징후
- CloudTrail: 보호 대상 GetObject 성공

관측 공백
- 모든 Source를 관통하는 공통 Request ID 없음
- Pod → IMDS 네트워크 Event 직접 미수집

이미 수행한 조치
- Workload 격리
- validation/* 추가 접근 제한

추가 확인·대응 후보
- 다른 Object 접근 여부
- Credential/Session 재사용 여부
- 다른 AWS Resource 접근 여부
- IAM 최소 권한
- DVWA 보안 설정 패치
- IMDSv2·Hop Limit 보강
```

### 운영자 조작

1. Seed Alert의 Event Time, Principal, Bucket/Key를 확인한다.
2. 미리 만든 사건 조사 Dashboard를 연다.
3. 해당 시간창과 Entity Filter가 적용된 관련 Event만 확인한다.
4. 각 Source가 무엇을 증명하는지 한 줄씩 설명한다.
5. 관측 공백을 숨기지 않는다.

### 내레이션

> 이제 최초 고신뢰 Alert를 중심으로 평소 Wazuh에 축적된 관련 로그를 좁혀 조사합니다. CloudFront, WAF, ALB는 외부 요청의 진입 경로를, DVWA는 명령 실행과 IMDS 접근 징후를, CloudTrail은 실제 보호 대상 Object 접근 성공을 보여줍니다.

> 모든 Source에 공통 ID가 있는 것은 아니므로 시간창, Method, Path, Principal, Bucket과 Key를 이용해 연결합니다. 이 화면은 자동 인과 그래프가 아니라 관제자가 사건을 빠르게 읽도록 미리 구성한 조사 View입니다.

### 자막

```text
Seed Alert → 관련 Evidence 확장
상관 기준: 시간 · Principal · IP · URI · Bucket/Key
자동 인과관계 확정이 아닌 다중 Evidence 기반 조사
```

### 필수 Evidence

- 동일 TAKE·연속 UTC의 관련 Source
- 각 Source의 상관 근거
- 탐지 근거와 자동 조치 결과
- 관측 공백 표시
- Raw Event Drill-down
- 검색 문법 없이 3분 내 사건 설명 가능

### 중단 조건

서로 다른 날짜의 보존 Event를 한 사건처럼 합치거나, 구현하지 않은 자동 Correlation을 주장하지 않는다.

---

## SC-08 — 관제자의 후속 조치 결정과 실행

### 보여줄 화면

- Rule별 Runbook/다음 조치 카드
- 현재 확인된 사실
- 이미 실행된 자동 조치
- 사람이 선택해야 하는 근본 대응
- 승인된 Remediation Workflow
- GitHub Diff·Commit SHA
- Argo CD `Synced + Healthy`
- 필요 시 IAM·IMDS 복구 결과 요약

### 내레이션

> 반복적이고 즉시 실행해도 안전한 격리는 SOAR가 자동으로 처리했습니다. 이제 관제자는 수집된 Evidence와 영향 범위를 바탕으로 근본 대응을 선택합니다. 이번 사건에서는 DVWA의 취약 설정을 `low`에서 `impossible`로 변경하고, IAM 최소 권한과 IMDS 보강을 승인된 절차로 적용합니다.

> Wazuh가 새로운 대응 방법을 임의로 발명한 것이 아니라, 사건 유형별 Runbook과 Evidence를 제공해 사람이 다음 조치를 쉽게 결정하도록 지원합니다.

### 자막

```text
자동: 사전 승인된 Containment
사람 승인: Remediation · IAM/IMDS Recovery
low → impossible = 애플리케이션 보안 설정 패치
```

### 필수 Evidence

- Runbook과 실제 사건 조건의 연결
- 승인 주체·UTC
- 예상한 파일·값만 변경
- 정확한 GitHub Commit SHA
- Argo exact Revision
- IAM/IMDS 조치를 적용했다면 실제 Runtime 상태

---

## SC-09 — 동일 공격·정상 기능 재검증과 종료

### 보여줄 화면

- 동일 공격 Payload 재실행
- 애플리케이션 계층 실패
- 기존 Credential 또는 공격 문맥의 S3 접근 실패
- 정상 로그인·허용 기능 성공
- 새로운 보호 대상 `GetObject` 성공 Alert 없음
- 최종 Incident Summary와 Evidence Index

### 내레이션

> 같은 공격을 다시 실행한 결과 취약 동작은 애플리케이션 계층에서 실패하고, 기존 공격 문맥의 보호 대상 S3 접근도 거부됩니다. 정상 로그인과 허용 기능은 계속 동작합니다. 마지막으로 Wazuh에서 새로운 보호 대상 GetObject 성공 Alert가 발생하지 않았음을 확인했습니다.

> 이 시연은 로그 중앙화, 조기 징후, 고신뢰 S3 탐지, 자동 격리, Alert 중심 조사, 관제자 후속 판단과 재검증을 하나의 Incident로 증명했습니다.

### 자막

```text
동일 공격: FAIL
보호 대상 S3 추가 접근: DENIED
정상 기능: PASS
새 고신뢰 S3 성공 Alert: 0
Incident: RECOVERED / CLOSED
```

### 필수 Evidence

- 동일 Payload 실패
- 정상 기능 성공
- 실패 원인 구분
- 새 S3 성공 Event·Alert 0
- 임시 Containment 해제 여부와 주체
- 최종 Evidence Index

---

# 5. 실패·재촬영 규칙

1. 장면 하나가 실패하면 TAKE를 `FAILED` 또는 `CLOSED`로 표시한다.
2. 실패 Event·Alert·Execution과 이유를 삭제하지 않는다.
3. 같은 TAKE에서 외부 Write를 반복해 성공 장면만 만들지 않는다.
4. 수동 Reset Gate를 통과한 뒤 새 TAKE_ID를 발급한다.
5. 새 TAKE 본편은 SC-00부터 다시 시작한다.
6. 여러 TAKE를 사용한 편집본은 `단일 E2E Runtime 증명`이라고 부르지 않는다.

Reset은 본편 Recovery가 아니라 재촬영을 위해 취약 Lab을 다시 여는 별도 운영 절차다.

---

# 6. 공개 전 최종 검수 — GT-11B 정본

- [ ] 최종 촬영 파일이 처음부터 끝까지 정상적으로 열리고 재생된다.

- [ ] 영상 제목이 실제 완료 범위를 과장하지 않는다.
- [ ] 모든 Runtime 장면의 TAKE와 UTC가 연결된다.
- [ ] Rule `100103`을 S3 침해 확정 Rule로 설명하지 않는다.
- [ ] 고신뢰 S3 Rule 조건과 정상 대조군을 보여준다.
- [ ] `S3 접근 순간 즉시`가 아니라 `Wazuh 고신뢰 Alert 직후` 자동 격리라고 설명한다.
- [ ] Wazuh Alert와 Shuffle Execution이 실제 일대일로 연결된다.
- [ ] 중복 Alert가 자동 조치를 반복하지 않는다.
- [ ] 조사 View의 상관 기준과 관측 공백을 설명한다.
- [ ] 구현하지 않은 자동 그래프·AI 분석을 주장하지 않는다.
- [ ] Workload 격리, Resource/Permission 제한, Credential 대응을 구분한다.
- [ ] `low → impossible`을 Credential 폐기나 Workload 격리로 설명하지 않는다.
- [ ] Plan·Source 존재를 Runtime 완료로 말하지 않는다.
- [ ] 동일 공격 실패와 정상 기능 성공을 함께 보여준다.
- [ ] Secret·실제 개인정보·전체 식별자가 화면·음성·자막에 없다.
- [ ] 다른 날짜·다른 TAKE의 Evidence를 하나의 Incident처럼 합치지 않는다.
