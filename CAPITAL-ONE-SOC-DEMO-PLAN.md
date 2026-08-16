# Capital One 기반 보안 관제·자동 대응 시연 계획

> **상태:** Draft v1.4 — Gate 4 공격 로그 5/5 Source Runtime 확인, 안전 Audit·초보자용 화면 대기
> **기준 시점:** 2026-08-16
> **현재 절차 Gate:** Gate 4 — 5-Source 중앙 수집 확인, 안전 Audit·사건 Timeline·초보자 사용성 검증 중
> **최근 Runtime Evidence:** CloudFront/DVWA 무해 Probe 2건이 같은 경로로 Wazuh Archives Index에서 검색됨
> **Terraform 진행:** T1·T2 Source, T3 Plan-only, T4 탐지·대조군·Alert 필드와 CloudFront Hot Copy Runtime 검증 완료
> **번호 구분:** `T0~T6`는 Terraform 구현 순서이고 `Gate 0~8`은 시연 Evidence 검증 순서다. 같은 번호끼리 같은 작업이 아니다.
> **기존 구현 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)
> **기존 관측성 계획:** [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)
> **Terraform 실행 계획:** [`CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md`](./CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md)
> **기존 제한 시나리오:** [`observability/scenarios/README.md`](./observability/scenarios/README.md)

이 문서는 기존 관측성 구현을 폐기하거나 다시 설명하기 위한 문서가 아니다.
이미 구축한 로그·탐지·GitOps 기반을 이용해 다음 한 장면을 끝까지 완성하기 위한
새 기준 계획서다.

```text
공격 성공과 가짜 개인정보 유출
→ 공격으로 인한 로그·경보 발생
→ 중앙 관제 화면에서 분석·분류
→ 자동 대응 Workflow 실행
→ GitHub에 검토된 보안 설정 Commit
→ Argo CD가 새 설정 배포
→ 동일 공격 재시도 실패
→ 최종 촬영 확인 뒤 Terraform 영구 복구
```

---

## 0. 초보자용 한눈에 보기

### 0.1 한 문장 목표

> 공격을 성공시킨 뒤 그 흔적으로 경보를 만들고, 검증된 자동 대응을 GitOps로
> 배포한 다음, 같은 공격이 실패하는 것까지 증명한다.

### 0.2 최종 시연 흐름

```text
공격 성공
→ 로그 확인
→ 탐지 경보
→ SOAR 대응 요청
→ GitHub 보안 설정 변경
→ Argo CD 배포
→ 같은 공격 재시도 실패
```

### 0.3 도구별 역할

| 도구·계층 | 이 계획에서 하는 일 |
|---|---|
| WAF·애플리케이션 로그·CloudTrail | 공격과 AWS 활동의 흔적을 기록한다. |
| GuardDuty·탐지 규칙 | 수집된 흔적이 공격 조건에 맞는지 판단해 경보를 만든다. |
| Wazuh SIEM | 여러 원본 로그를 한곳에서 조회·분석하고 Custom Rule로 Alert를 만든다. |
| Shuffle SOAR | Wazuh Alert를 검증하고 사전에 허용된 대응 절차를 요청한다. |
| GitHub Actions | 허용된 보안 설정 한 가지를 검증·변경해 Commit한다. |
| Argo CD | GitHub의 변경을 감지해 EKS에 새 설정을 배포한다. |
| Terraform | IAM·IMDS·Node 같은 근본 원인을 사람 승인 후 복구한다. |

### 0.4 Gate를 쉽게 읽는 법

```text
Gate 0  공개 가능한 실습 자료 정리
Gate 1  동일 공격 재현
Gate 2  실제로 남은 로그 확인
Gate 3  경보를 울릴 탐지 조건 결정
Gate 4  관제 화면에 경보 표시
Gate 5  변경 없는 자동 대응 모의 실행
Gate 6  GitHub 보안 설정 자동 변경
Gate 7  Argo CD 배포 후 재공격 실패 확인
Gate 7-R  촬영 실패 시 사람 승인으로 재촬영 상태 복원
Gate 8  근본 원인 복구와 팀 전체 연습
```

Gate는 별개의 기능 목록이 아니라 앞 단계의 결과를 확인하고 다음 단계로 넘어가기
위한 중간 완료 조건이다. Gate 1~3에서 공격 재현, 로그 Coverage, 정탐·정상 대조군,
Alert 필드 Runtime 검증까지 닫았다. Gate 0의 공개본 위생 체크는 최종 촬영 전 다시
확정한다. 중앙 관제 제품은 Wazuh로 선택했고, 새 통제 Event에서 CloudTrail Raw Event와
Rule `100100`·Level 12 Alert가 동일 `eventID`로 연결되는 것까지 확인했다. 다음은
새 DVWA 안전 Audit Runtime, 초보자용 관제 화면, 정상 접근의
Wazuh 오탐 검증이다.

### 0.5 빠른 차단과 영구 대응의 차이

```text
DVWA 보안 레벨 변경
= 교육용 환경에서 새로운 공격 진입을 빠르게 막는 시연용 Containment

IAM 최소 권한·IMDSv2 강제·Node 교체·애플리케이션 수정
= 실제 원인을 제거하는 실무형 영구 대응
```

빠른 차단만으로 이미 유출된 자격증명이 무효화됐다고 주장하지 않는다. 최종 시연은
두 대응의 목적과 한계를 구분해 설명한다.

### 0.6 촬영·재촬영 상태 수명주기

촬영 실패를 Git History 삭제나 Terraform 재적용으로 복구하지 않는다. 촬영 중에는
취약한 Infrastructure Profile을 유지하고 DVWA의 애플리케이션 상태만 앞으로 가는
새 Commit으로 전환한다.

```text
PREPARED
capital-one-lab + DVWA low + Alarm OK + 새 TAKE_ID·ExperimentId
        │
        ▼
CONTAINED
DVWA impossible + Argo Synced·Healthy + 동일 Payload 실패
        │
        ├─ 촬영 승인 → FINALIZE → Terraform hardened
        │
        └─ 촬영 실패 → MANUAL RETAKE RESET
                         impossible → low 새 Commit
                         → Argo 새 Pod
                         → 새 세션·새 ID·Alarm OK 확인
                         → PREPARED
```

수동 Reset은 이미 노출된 임시 자격증명을 폐기하거나 IAM·IMDS를 복구하지 않는다.
오직 다음 촬영을 위해 DVWA의 교육용 취약 상태를 다시 여는 작업이다. 같은 촬영
시간창을 벗어나거나 노트북을 떠나야 하면 `low`로 Reset해 두지 않고 Daily Runtime을
내리거나 승인된 `hardened` 복구를 수행한다.

---

## 1. 최종 목표

### 1.1 프로젝트 질문

> 흩어진 AWS·EKS 보안 신호를 하나의 사건으로 연결하고, 탐지 결과를 실제
> GitOps 대응과 재검증까지 이어갈 수 있는가?

### 1.2 대표 시나리오 명칭

```text
Capital One 사고 기반 EKS 노드 IAM 자격증명 탈취·자동 대응 시나리오
```

실제 Capital One 사고를 그대로 재현했다고 표현하지 않는다.

```text
실제 사건 진입점: SSRF
현재 실습 진입점: DVWA Command Injection

공통 검증 경로:
서버 측 명령·요청 실행
→ EC2 IMDS 접근
→ Node IAM Role 임시 자격증명 노출
→ Private S3 접근
```

### 1.3 시연 완료 정의

다음 항목이 모두 Runtime Evidence로 확인돼야 완료다.

- [ ] 통제된 취약 설정에서 동일 공격을 반복할 수 있다.
- [x] 노드 역할 임시 자격증명으로 가짜 S3 자료 접근이 성공한다.
- [x] 공격과 직접 연결되는 원본 로그가 보존된다.
- [ ] SIEM 또는 중앙 탐지 계층에서 경보가 발생한다.
- [ ] 경보 근거와 공격 Timeline을 사람이 설명할 수 있다.
- [ ] 자동 대응이 사전에 정한 GitHub Workflow만 실행한다.
- [ ] GitHub Commit 후 Argo CD가 변경을 자동 배포한다.
- [ ] 새 세션에서 같은 공격을 반복하면 IMDS 자격증명 획득이 실패한다.
- [ ] 수동 Reset으로 새 촬영을 준비하고 동일 흐름을 다시 시작할 수 있다.
- [ ] 최종 촬영 확인 뒤 Terraform으로 IAM·IMDS의 근본 원인을 복구한다.
- [ ] DVWA 전용 시연 조치와 실제 환경의 대응 방법을 명확히 구분한다.

---

## 2. 범위와 제외 범위

### 2.1 핵심 범위

```text
대표 공격 1개
탐지 규칙 1개
자동 대응 Workflow 1개
수동 재촬영 Reset Workflow 1개
GitOps 보안 설정 변경 1개
재공격 검증 1회
재촬영 준비 Rehearsal 1회
팀원 전원 반복 실습
최종 시연 영상
```

### 2.2 핵심 완료 전 하지 않을 것

```text
CNAPP·Trend Micro 도입
n8n 기반 AI 분석·자동 보고서
여러 SIEM 동시 구축
모든 AWS·EKS 로그 통합
여러 공격 시나리오 병렬 구현
핵심 E2E 완료 전 별도 SSRF 모듈 구현
DR 고도화
LLM이 임의 보안 코드를 생성·Push하는 구조
SOAR에 광범위한 AWS·GitHub 관리자 권한 부여
```

### 2.3 핵심 완료 후 확장 순서

```text
1. Command Injection 대체 진입점을 실제 SSRF 모듈로 교체
2. 두 번째 대표 시나리오
3. 기존 탈취 자격증명까지 무효화하는 AWS 측 자동 격리
4. Shuffle SOAR 고도화
5. n8n·AI 분석 보조
6. CNAPP 조사
```

---

## 3. 현재 확인된 기반과 미검증 경계

### 3.1 현재 Source에서 확인된 기반

```text
CloudTrail
→ Management Event 기본 수집
→ enable_project_s3_data_events 선택 시 프로젝트 S3 Data Event 수집
→ CAPITAL-ONE 성공 GetObject Metric Filter·Alarm Source 구현

GuardDuty
→ Detector 활성화
→ Finding EventBridge 수신
→ CloudWatch Logs 보존
→ SNS 경보

DVWA GitOps
→ main Source 변경 시 GitHub Actions
→ ECR Immutable Image
→ deploy/dvwa/values.yaml Image Tag 자동 Commit
→ Argo CD Auto Sync·Prune·Self Heal

Security Scenario
→ hardened 기본값
→ capital-one-lab에서만 Primary IMDS 완화·validation/* 읽기
→ DR은 항상 hardened
```

### 3.2 현재 GitOps에서 바로 재사용 가능한 사실

현재 DVWA Chart에는 다음 값이 있다.

```yaml
defaultSecurityLevel: low
```

Deployment는 이를 `DEFAULT_SECURITY_LEVEL` 환경변수로 전달한다.
DVWA의 `impossible` Command Injection 구현은 입력을 IPv4 네 옥텟으로 제한하므로,
기존 `; curl ...` Payload가 실행되지 않는다.

현재 GitHub Actions는 `deploy/dvwa/values.yaml`만 변경된 Commit을 Image Build
대상에서 제외한다. 따라서 자동 대응은 새 Image를 만들지 않고 다음처럼 구성할 수
있다.

```text
검토된 대응 Workflow
→ defaultSecurityLevel: low → impossible
→ GitHub Bot Commit
→ Argo CD가 Helm 값 변경 감지
→ Deployment Rollout
```

### 3.3 아직 증명되지 않은 것

```text
외부 PC의 Node Role 사용이 CloudTrail에 실제 기록됐는가
GuardDuty가 실제 Credential Exfiltration Finding을 생성했는가
S3 Data Event가 실습 시점에 활성화돼 있었는가
어떤 Event Field가 가장 안정적인 탐지 조건인가
선택한 SIEM이 현재 로그를 안정적으로 수집하는가
SOAR에서 GitHub Workflow 호출까지 필요한 최소 권한이 무엇인가
Argo 배포 후 기존 세션이 아닌 새 세션에서 차단이 재현되는가
수동 Reset 뒤 Alarm이 실제 OK로 돌아가 두 번째 경보를 만들 수 있는가
```

---

## 4. 목표 구조

```text
[공격자·통제된 실습 PC]
          │
          ▼
CloudFront·WAF → ALB → DVWA Pod
                         │
                         ▼
                 Karpenter Node IMDS
                         │
                         ▼
                 Node Role Credential
                         │
                         ▼
                  Private S3 validation/*

WAF·ALB·Application·CloudTrail·GuardDuty
                         │
                         ▼
                  SIEM·중앙 탐지 계층
                         │
              Alert + Incident Context
                         │
                         ▼
                  SOAR 대응 Workflow
                         │
                         ▼
        제한된 GitHub Actions Dispatch
                         │
                         ▼
       values.yaml 보안 값 변경·Bot Commit
                         │
                         ▼
                Argo CD Auto Sync
                         │
                         ▼
               새 DVWA Pod 배포
                         │
                         ▼
                 동일 공격 재시도 실패
```

---

## 5. 대응을 두 단계로 분리한다

### 5.1 자동 대응: 즉시 Containment

첫 구현은 애플리케이션의 취약 기능을 GitOps로 잠근다.

```text
defaultSecurityLevel: low
→ defaultSecurityLevel: impossible
```

> **중요:** 이 방법은 DVWA가 교육용으로 제공하는 `defaultSecurityLevel` 기능을
> 이용한 **시연 전용 Containment**다. 일반 애플리케이션이나 실제 운영 환경에는
> 같은 스위치가 존재하지 않으므로, 이를 실무의 보편적인 자동 대응 방법이라고
> 설명하지 않는다.

이 대응이 보장하는 것은 다음이다.

```text
새 Pod·새 세션에서 동일 Command Injection Payload 실행 차단
→ 새로운 IMDS 자격증명 탈취 경로 차단
```

이 대응만으로 이미 유출된 임시 자격증명이 즉시 무효화됐다고 주장하지 않는다.

### 5.2 영구 대응: Terraform 보안 복구

다음 항목은 Argo CD가 아니라 Terraform의 책임이다.

```text
httpTokens: required
httpPutResponseHopLimit: 1
security_scenario_profile: hardened
Node Role S3 실습 권한 제거
필요 시 취약 Karpenter Node 교체
NetworkPolicy·IMDS egress 통제 검토
```

`security_scenario_profile`의 Source와 Guard는 구현·로컬 검증됐다. 실제 AWS
Runtime의 Node Metadata·IAM Policy와 복구 후 Negative Test는 아직 미검증이며,
적용 순서는 Terraform 실행 계획을 따른다.

영구 대응은 다음 흐름을 유지한다.

```text
Source Diff
→ terraform fmt·validate
→ terraform plan
→ 사람 승인
→ apply
→ 기존 자격증명 AccessDenied·재공격 Test
```

### 5.3 실무 환경에서 필요한 대응

실제 환경에서는 취약점 화면의 보안 레벨을 바꾸는 대신, 사고 범위와 서비스 영향에
따라 다음 대응을 조합해야 한다.

```text
1. 의심 Workload·Pod·Node 격리
2. 유출된 Role Session과 Credential 영향 차단
3. 과도한 IAM 권한 제거·최소 권한 적용
4. IMDSv2 강제와 Metadata 접근 경로 제한
5. Pod egress·NetworkPolicy·Runtime 통제 보강
6. 취약 애플리케이션 코드 또는 Image 수정
7. 검토된 CI/CD·GitOps 절차로 Patch 배포
8. 동일 공격·정상 기능 Regression 재검증
9. 로그·증거 보존과 Incident 기록
```

이 계획의 DVWA 자동 조치는 위 항목 중 `취약 애플리케이션 기능의 즉시 차단`을
작게 모형화한 것이다. 자격증명 무효화와 IAM·IMDS·NetworkPolicy 보강은 별도
영구 대응으로 검증한다.

발표에서는 다음처럼 설명한다.

> 이번 자동 조치는 DVWA에 내장된 교육용 보안 레벨을 GitOps로 전환해 새로운
> 공격 진입을 차단한 시연입니다. 실제 환경에서는 동일한 스위치가 없으므로,
> 워크로드 격리와 자격증명 무효화, IAM 최소 권한, IMDSv2 강제, 애플리케이션
> Patch를 조직의 승인 절차에 따라 수행해야 합니다.

---

## 6. 단계별 Gate

### Gate 0 — 시나리오·Evidence 위생

목적: 공격 성공 자료를 공개 가능한 실습 Evidence로 만든다.

- [ ] 시나리오 명칭에서 ‘동일 사고 재현’ 표현 제거
- [x] Command Injection을 대체 진입점으로 명시
- [x] IMDS 주소를 `169.254.169.254` link-local로 보정
- [ ] `Access Key로 SSH 가능` 표현 제거
- [ ] Session Token·Access Key·Account ID·버킷명 공개본 마스킹
- [ ] 취약 설정과 복구 설정을 정확히 기록
- [x] 가짜 개인정보만 사용했음을 명시

남은 위생 작업:

- 조원이 제공한 과거 Notion Export Markdown에 세션 토큰 형태의 원문이 포함돼 있다.
  원본 ZIP과 Screenshot은 공개 Evidence로 사용하지 않고, 값을 제거한 별도 공개본을
  만들어야 한다.
- 새 Runner의 client JSON에는 Credential 원문·Account ID·Bucket 이름을 남기지
  않았다. 내부 조사용 Bundle은 CloudTrail 상관분석을 위해 ARN·Bucket·Source IP·
  Request ID를 보존하므로 공개본이 아니다. 별도 공개본에서 다시 마스킹해야 하며,
  이것이 과거 자료까지 자동으로 정제했다는 뜻도 아니다.

완료 Evidence:

```text
정제된 공격 흐름
민감정보 없는 Screenshot
실습 전·후 설정 Matrix
```

### Gate 1 — 공격 Baseline 재현

목적: 자동화 전에 동일 공격을 안정적으로 반복한다.

```text
Vulnerable Profile 확인
→ DVWA Command Injection
→ IMDS Metadata 목록
→ Node Role Credential 경로
→ 외부 PC STS Identity
→ validation/* 목록·가짜 CSV 읽기
```

완료 조건:

- [x] 임의 Target을 허용하지 않는 제한된 실행 절차
- [x] 시작·종료 UTC Timestamp 기록
- [x] 실제 Credential 원문 미저장
- [x] 실습 후 환경변수 Credential 제거
- [x] 공격 실패 시에도 환경을 원복할 수 있음

2026-08-12 Baseline Evidence:

```text
ExperimentId / TAKE_ID: capital-one-20260812T025054Z
IMDS Role: 예상 Primary Karpenter Node Role과 일치
Credential: 획득 성공, 값은 출력·파일 저장하지 않음
S3: validation/capital-one-demo.csv 가짜 5행 읽기·SHA-256 일치
Alarm: 같은 실행 뒤 새 ALARM 전환
CloudTrail: GetObject 1행, Role·Object·성공·시간창·조사 필드 일치
```

이 실행은 한 번의 안정된 Baseline이다. Alarm `OK` 복귀와 새 TAKE로 반복 실행하기
전까지 ‘반복 촬영 검증 완료’로 확대하지 않는다.

### Gate 2 — 공격 로그 Coverage

목적: 공격 단계별로 무엇이 보이고 무엇이 안 보이는지 확정한다.

2026-08-12 Baseline `capital-one-20260812T025054Z` 판정:

| 공격 단계 | 실제 Evidence | 판정 | 같은 사건을 묶는 기준·한계 |
|---|---|---|---|
| CloudFront → WAF | WAF Event 2건 | **관측됨** | Runner의 두 CloudFront Request ID와 정확히 일치. `POST /vulnerabilities/exec/`, `EC2MetaDataSSRF_Body` Label, `COUNT`·`ALLOW` 확인 |
| WAF → DVWA | Apache Access 2건 | **부분 관측** | 같은 시간창·Method·Path·건수로 연결. 두 요청 모두 HTTP 200이지만 WAF와 공유하는 Request ID는 현재 로그에 없음 |
| DVWA 명령 실행 | BANK Audit | **미수집** | Login 성공 Event만 구조화됨. `exec` Route는 Command Body·실행 결과·IMDS 응답을 Audit Log에 남기지 않음 |
| Pod → IMDS | Runner 결과 + VPC Flow Logs | **결과 관측 / 네트워크 미수집** | Role·Credential 응답 성공은 Runner가 확인. VPC Flow Logs에는 0건이며, AWS가 `169.254.169.254` 메타데이터 트래픽을 수집 제외함 |
| Node Role → S3 | CloudTrail S3 Data Event 1행 | **관측됨** | 실행 시간창·Assumed Role·고정 Object Key·성공·Source IP·User Agent·Request ID로 연결 |
| GuardDuty | Detector API + EventBridge Log Group | **탐지 없음** | TAKE 시작 약 49분 뒤 재확인: Finding 0건·전달 Event 0건. `S3_DATA_EVENTS` Protection이 꺼져 있어 대표 탐지기로 사용하지 않음 |
| 확정 경보 | Metric Filter → Alarm | **탐지됨** | 위 CloudTrail 1행이 Rule 조건과 일치하고 같은 TAKE에서 Alarm이 새 `ALARM`으로 전환 |

VPC Flow Logs의 IMDS 제외 근거는 AWS 공식 문서의
[Flow log limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)이다.
따라서 이 구간의 0건은 공격이 없었다는 뜻이 아니라 **현재 수집 방식으로는 직접 볼 수
없는 구간**이라는 뜻이다.

`TAKE_ID`는 우리 Runner와 Evidence Bundle을 묶는 외부 식별자이며 AWS Event 자체에
자동 삽입되지 않는다. 현재 가장 강한 연결은 WAF의 CloudFront Request ID 두 개와
CloudTrail의 시간·Role·고정 Key·성공 조건이다.

완료 조건:

- [x] `enable_project_s3_data_events` 실제 Runtime 값 확인
- [x] 외부 사용 시점 CloudTrail Event 확인
- [x] GuardDuty Finding 발생 여부 확인 — TAKE 시작 이후 0건
- [x] 보이지 않는 구간을 ‘미탐’ 또는 ‘미수집’으로 명시
- [x] 동일 사건을 묶는 최소 Field 선정

### Gate 3 — 확정 탐지 경로 Runtime 검증

대표 탐지는 T2에서 다음 경로로 결정했다.

```text
성공 GetObject
+ Primary Karpenter Node Role
+ validation/*
+ errorCode 없음
→ CloudWatch Logs Metric Filter
→ CloudWatch Alarm
→ SNS
```

GuardDuty Finding과 WAF·Application Event는 발생하면 조사 Timeline을 보강하지만
확정 경보의 필수 입력으로 두지 않는다. 실제 공격과 무관한 Sample Finding으로
성공을 주장하지 않는다.

완료 조건:

- [x] 탐지 Rule 입력 Source 확정
- [x] Rule 조건과 제외 조건 문서화
- [x] 정상 접근으로 오탐 Test
- [x] 공격 접근으로 정탐 Test
- [x] Alert에 시간·Role·행위·Severity 포함 — `StateChangeTime` + Runtime Description 확인

Runtime 정탐 결과는 Metric Filter의 새 `ALARM` 전환과 같은 시간창의 CloudTrail
`GetObject` 1행으로 확인했다. 첫 Evidence Query가 0행이었던 원인은 공격이나 AWS
로그 부재가 아니라 Windows PowerShell 5.1의 native argument 인용 손실이었다.
Collector가 CWLI를 UTF-8 `file://`로 전달하도록 고쳤고, CAPITAL-ONE에만 최소 1행과
제한된 전달 재조회를 적용한 뒤 Bundle을 다시 생성해 1행을 확인했다.

2026-08-12 Negative Control Evidence:

```text
ExperimentId: capital-one-negative-20260812T034935Z
Caller: 고정 정상 terra-user, ARN 비저장
S3: 같은 고정 가짜 CSV 5행·SHA-256 일치
CloudTrail: 성공 GetObject 정확히 1행, Node Role 불일치, 실행 시간창 일치
Alarm: OK 유지, State Updated Timestamp 불변
Bundle: SHA256SUMS 50개 일치
```

Negative Control의 시간 계약은 다음과 같다. S3 읽기는 수초지만 CloudTrail Event의
CloudWatch Logs 전달은 평균 약 5분이며 보장 시간은 아니다. Runner는 전달·Query를
약 10분까지만 기다리고, Event를 확인한 뒤 Alarm 비전환을 120초 관찰한다.

```text
S3 읽기·가짜 데이터 검증: 수초
CloudTrail 전달·Query: 최대 약 10분, 30초 간격 진행률 출력
Alarm 비전환 관찰: 120초
Timeout: 같은 GetObject 반복 금지 → 기존 ExperimentId로 Resume
```

Runner는 별도 CWLI 실행기를 두지 않고 Evidence Collector의 UTF-8 Query 정규화,
Delivery Grace, `event_time` 재필터, 제한 재시도를 그대로 사용한다. Client Record에는
현재 Invocation과 세 단계의 소요시간을 남긴다.

현재 SNS Alarm 메시지는 기본 Schema의 `StateChangeTime`과 `AlarmDescription`을 사용한다.
Source와 AWS Runtime의 Description에는 다음 고정 필드가 들어 있다.

```text
scenario=CAPITAL-ONE
severity=HIGH
action=s3:GetObject
actor=aws-topology-primary-karpenter-node
object=validation/*
verdict=success
```

기존 Plan Snapshot은 실행하지 않았다. 2026-08-12 Source·State 기준 Fresh Plan을 다시
만들어 해당 Alarm의 `alarm_description` **1개 in-place update**, Create·Delete·Replace
0건과 Terraform Check 10/10 통과를 확인한 뒤 승인된 Plan만 Apply했다. AWS
`describe-alarms`에서 여섯 필드, SNS Action, 현재 `OK` 상태를 확인했고 Terraform
State와 실제 Description도 일치했다. 같은 입력의 Post-Apply Fresh Plan은
`create=0, update=0, delete=0, replace=0`이다.

CloudWatch Alarm은 SIEM 입력으로 재전송하지 않는다. 기존 경로는 AWS Native 탐지와
사람 알림을 증명하는 독립 경로로 유지한다.

```text
CloudTrail → CloudWatch Logs Metric Filter → CloudWatch Alarm → SNS
```

### Gate 4 — SIEM·중앙 관제 계층

중앙 관제 제품은 **Wazuh**로 확정한다. Elastic Security와 별도 ELK Stack을 함께
구축하지 않는다. Wazuh가 이미 수집·분석·Indexer·Dashboard·Custom Rule을 담당하므로
두 Stack을 동시에 운영하면 핵심 시연과 무관한 중복 구축이 된다.

Gate 4의 목적은 Wazuh를 설치했다는 사실을 보여주는 것이 아니다. 다음 두 질문에
Runtime Evidence로 답할 수 있어야 한다.

```text
1. 대표 공격 시나리오가 만드는 필수 로그가 빠짐없이 Wazuh에 들어오는가
2. 검색 문법을 모르는 사람도 한 화면에서 사건과 다음 조치를 이해할 수 있는가
```

따라서 Gate 4는 **Source 완전성**과 **초보자 사용성**을 서로 다른 완료 조건으로
검증한다. Raw Event가 들어온 것만으로 탐지·분석·관제 화면까지 완료했다고 판정하지
않는다.

#### 4.1 원본 로그 입력 계약

여기서 “모든 로그”는 AWS 계정의 모든 로그가 아니라, **서울 Primary에서 실행하는
Capital One 기반 대표 공격의 요청·실행·AWS API 사용을 설명하는 다섯 Source**를 뜻한다.

```text
CloudFront Access Log ─┐
WAF Log ───────────────┤
ALB Access Log ────────┼→ Wazuh → 사건 Timeline·Custom Alert·초보자용 Dashboard
DVWA·Apache·Audit Log ─┤                                      ↓
CloudTrail STS·S3 ─────┘                                   Shuffle
```

다섯 Source와 Wazuh 입력의 대응은 다음과 같다. `현재 상태`는 설정 존재가 아니라 실제
Record 도착과 탐지 단계까지 구분한다.

| 순서 | Source | 현재 저장 위치 | Gate 4 수집 방식 | 역할 | 현재 상태 |
|---:|---|---|---|---|---|
| 1 | CloudFront | Foundation Security Log S3 `AWSLogs/<ACCOUNT_ID>/CloudFront/` | 3일 병렬 CloudWatch Logs Destination → Wazuh `cloudwatchlogs` | 요청이 CDN Edge에 도착한 사실 | Raw Archive·JSON Field·Archives Index Runtime 확인 |
| 2 | WAF | `aws-waf-logs-aws-topology-edge`, `us-east-1` | Wazuh `service type="cloudwatchlogs"` | 요청 검사 결과·Action·Rule Label | Raw Archive Runtime 확인 |
| 3 | Primary ALB | Security Log S3 `alb/primary/AWSLogs/.../elasticloadbalancing/ap-northeast-2/` | Wazuh `bucket type="alb"` + `path` | 요청이 Load Balancer를 거쳐 Target에 도달한 사실 | Raw Archive·ALB Field Parsing Runtime 확인 |
| 4 | DVWA·Apache·안전 Audit | `/aws/eks/aws-topology-primary/dvwa`, `ap-northeast-2` | Wazuh `service type="cloudwatchlogs"` | 요청 도달·Pod 출력·Command Injection 실행 결과 분류 | 기존 Pod Log 수집 완료, 새 Audit Runtime 전 |
| 5 | CloudTrail | Foundation Security Log S3 `AWSLogs/<ACCOUNT_ID>/CloudTrail/` | Wazuh `bucket type="cloudtrail"` | 탈취 Role의 STS·S3 API 사용과 `GetObject` 확정 근거 | Raw·Rule `100100` Alert Runtime 확인 |

CloudFront Standard Logging v2 JSON은 설치된 Wazuh `custom` Bucket Loader가 기대하는
`detail` 구조와 맞지 않고 Wazuh 4.14.7의 S3 Bucket Type에도 CloudFront 전용 Type이 없어
S3 Direct 입력으로 처리하지 않는다. 기존 S3·Athena Evidence는 유지한다. 같은 CloudFront
Delivery Source에 `us-east-1`의 JSON CloudWatch Logs Destination을 하나 더 연결하고,
전용 Log Group은 3일 보존하며 `capital-one-lab`에서만 Delivery를 만든다. 2026-08-16
Terraform Source·정적 Test·Foundation Plan에서 Create 2·Update 1·Delete 0을 확인한 뒤
Apply했고, 같은 입력의 Post-Apply Fresh Plan은 0 change였다. Daily
`minimal + capital-one-lab`에서 S3·CWL 두 Delivery와
`cloudfront_wazuh_logging_enabled=true`를 확인했다. 무해한 고유 `404` 요청은 CloudWatch
Logs와 Wazuh Raw Archive·Archives Index에 도착했다. CloudFront Standard Log는 지연될 수
있어 실시간 탐지 Trigger가 아니라 Edge 보조 Evidence로 사용한다.

ALB는 Wazuh가 공식 `alb` Bucket Type으로 지원하며, 2026-08-16 실제 Record의
`source=alb`, Request·Status·Client/Target IP·`trace_id` Parsing을 확인했다.

#### 4.1.1 Gate 4에서 제외하거나 다른 Gate로 보내는 Source

다섯 Source 밖의 로그를 잊은 것이 아니라 시나리오 역할에 따라 다음처럼 분류한다.

| Source·구간 | Gate 4 판정 | 이유·대체 Evidence |
|---|---|---|
| EKS Control Plane `api`·`audit`·`authenticator` | Gate 7 대응 Evidence | 공격 요청 자체보다 Argo CD의 Kubernetes API 호출·Deployment Rollout을 설명한다. |
| Pod → IMDS `169.254.169.254` | 명시적 관측 공백 | EKS Control Plane·CloudTrail 대상이 아니며 VPC Flow Logs도 IMDS Traffic을 수집하지 않는다. 안전 Audit 분류와 Runner 결과만 사용한다. |
| VPC REJECT | 보조 Evidence, Gate 4 비차단 | IMDS 구간을 메우지 못하고 대표 공격의 확정 근거도 아니다. |
| GuardDuty Finding | 탐지 결과 0건 기록 | 이번 Baseline에서는 Finding이 없었다. 발생하지 않은 Finding을 Sample로 대체하지 않는다. |
| DR DVWA | 범위 제외 | 대표 시나리오는 서울 Primary에서만 실행하며 도쿄 DR은 공격 경로가 아니다. |
| Metric Filter·Alarm·SNS | Gate 3 독립 탐지 출력 | Wazuh 원본 입력으로 중복 전송하지 않고 AWS Native 탐지·사람 알림 Evidence로 유지한다. |

Gate 7에서는 Shuffle 실행 기록, GitHub Actions·Commit, Argo CD Sync·Health, EKS Control
Plane Audit, 새 Pod 생성을 대응 Timeline으로 확인한다. 이 결과를 Gate 4 공격 로그 다섯
Source와 혼합해 Gate 4 완료 조건을 불필요하게 늘리지 않는다.

#### 4.1.2 공격 단계와 현재 Wazuh 가시성

공격이 여러 계층을 통과한다는 사실과 Wazuh가 현재 그 로그를 모두 읽는다는 주장을
혼동하지 않는다.

| 공격 단계 | 관련 로그·증거 | 현재 Wazuh 상태 |
|---|---|---|
| CloudFront 통과 | CloudFront Access Log | 3일 CloudWatch Hot Copy → Raw Archive·JSON Field·Archives Index Runtime 확인 |
| WAF 검사 | 현재 Filter가 보존하는 `COUNT`·`BLOCK` Event | CloudWatch Logs → Raw Archive 실제 요청 Record 확인 |
| ALB 통과 | Primary ALB Access Log | S3 → Wazuh Raw Archive 수집과 Request·Status·Client/Target IP·`trace_id` Parsing Runtime 확인 |
| DVWA 요청·Command Injection | Apache·DVWA Log → CloudWatch Logs | 기존 Pod Record 수집 완료. 안전 Audit 코드는 정적 검증만 완료하고 Image 배포 전 |
| DVWA → IMDS | Runner의 Role·Credential 획득 결과 | CloudTrail 대상이 아니며 현재 네트워크 로그로 직접 증명하지 못함 |
| 탈취 Credential로 STS 호출 | CloudTrail Management Event | CloudTrail 입력 범위지만 시나리오 전용 Alert 없음 |
| 탈취 Credential로 S3 읽기 | CloudTrail S3 Data Event | **Raw 수집·Rule `100100`·Level 12 Runtime 검증 완료** |
| AWS Native 탐지 결과 | CloudWatch Metric Filter → Alarm → SNS | Wazuh와 독립된 탐지·사람 알림 경로 |

Runner는 DVWA를 통해 IMDS Credential을 획득한 뒤, 그 값을 Process Memory의 환경
변수에만 넣고 **Runner가 실행되는 노트북의 AWS CLI**로 `STS GetCallerIdentity`와
`S3 GetObject`를 호출한다. 따라서 해당 CloudTrail Event의 Source IP와 User Agent는
DVWA Pod가 아니라 노트북 실행 환경을 가리킨다. Credential 값은 출력·Evidence에
저장하지 않는다.

현재 완료된 Wazuh 시연 범위는 다음이다.

> CloudTrail·WAF·DVWA 세 Source의 실제 Raw Event를 수집하고, CloudTrail을 근거로 탈취
> Node Role의 보호 대상 S3 접근을 탐지해 동일 Event의 Raw 문서와 Custom Alert를
> 중앙 화면에서 대조한다.

아직 완료되지 않은 전체 관제 범위는 다음이다.

> CloudFront·WAF·ALB·DVWA·CloudTrail 다섯 Source를 한곳에서 조회해 공격 Timeline을
> 구성하고, 검색 문법 없이 사람이 사건·위험도·다음 조치를 이해한다.

첫 구현에서는 새 Firehose, S3→SQS, EventBridge→Wazuh Target을 만들지 않는다. 기존
Source를 Wazuh가 Read-only로 Polling한다. WAF를 S3로 바꾸면 현재 Live Viewer와
Grafana CloudWatch 경로를 깨뜨릴 수 있으므로 변경하지 않는다.

첫 수집을 시작하기 전에 S3와 CloudWatch Logs 입력 모두 `only_logs_after=2026-AUG-12`,
승인 Account, Source별 Region과 Prefix를 고정한다. WAF·CloudFront 병렬 Log Group은
`us-east-1`, ALB·DVWA·CloudTrail 조사 기준은 `ap-northeast-2`다. CloudFront 병렬
Destination은 3일 보존·`capital-one-lab` 전용으로 확정했다. 이는 이미 확보한 Baseline Event를 놓치지
않으면서 프로젝트 밖의 오래된 로그를 불필요하게 읽지 않기 위한 시작 경계다. 첫 수집
뒤 시작일을 뒤늦게 바꾸거나 무작정 `reparse`하지 않는다. 필요한 과거 Event 재처리는
중복 Alert 가능성을 기록한 별도 시험으로 수행한다.

#### 4.2 배치와 보존

- Wazuh는 노트북의 Local Docker single-node Stack으로 시작한다.
- 2026-08-12 확인값은 16 Logical Processor, RAM 31.3 GB, D Drive 여유 634.7 GB로
  공식 single-node 최소값 4 Core·8 GB RAM·50 GB Disk를 충족한다.
- Docker Daemon, WSL 2의 `vm.max_map_count=262144`, Docker 16 CPU·약 15.25 GiB를
  확인했고 Wazuh 4.14.7 Manager·Indexer·Dashboard가 모두 기동됐다.
- 이는 Local Stack 기동 Evidence이며 AWS 원본 로그 수집 성공을 의미하지 않는다.
- Manager·Indexer·Dashboard의 Named Volume과 Host-mounted 설정 파일을 유지하여
  `docker compose down/up` 뒤 설정·Alert·원본 Event가 남는지 검증한다.
- 규칙에 걸리지 않은 원본 Event 검색을 위해 `wazuh-archives-*`를 활성화하되, 프로젝트
  Source만 수집하고 짧은 보존 정책은 실제 Index 크기를 측정한 뒤 고정한다.
- 2026-08-15까지 CloudTrail·WAF·DVWA에 `only_logs_after=2026-AUG-12`, 승인 Account와
  Source별 Region을 적용하고 실제 Raw Record를 확인했다.
- Dashboard 시간 범위 검색은 Local Wazuh Indexer 조회다. 과거 Event 확인을 위해
  검색 범위를 넓히는 것만으로 AWS Query 비용이 발생하지 않는다.
- 수집 DB 초기화·무계획 `reparse`는 S3 재조회와 중복 Alert를 만들 수 있으므로 기존
  Index 검색과 Marker 확인 뒤에만 별도 승인한다.

#### 4.3 IAM·Credential 경계

- Terraform은 Wazuh 전용 Read-only Role과 Policy만 만든다.
- Security Log Bucket은 필요한 Key 목록 조회와 승인된 CloudTrail·ALB Prefix의
  `s3:GetObject`만 허용한다. CloudFront S3 Direct 입력은 현재 사용하지 않는다.
- WAF·Primary DVWA와 CloudFront Wazuh Log Group은 `logs:DescribeLogStreams`,
  `logs:GetLogEvents`만 허용한다.
- `s3:DeleteObject`, `logs:DeleteLogStream`, Put·Write 권한은 주지 않는다.
- `aws_iam_user`, `aws_iam_access_key`와 장기 Credential을 Terraform으로 만들지 않는다.
- 최종 방식은 기존 광범위 Profile을 Container에 그대로 노출하지 않고, Host에서 발급한
  Wazuh Reader Role의 임시 STS Session Profile을 Git 밖의 임시 파일로 Read-only Mount한다.
- Credential 원문, Shuffle Webhook, Wazuh Password는 Source·Evidence·영상에 남기지 않는다.

2026-08-13 최초 Runtime 연결은 반복적인 STS 갱신 없이 로컬 실습을 진행하기 위해
Terraform 밖에서 만든 전용 IAM User `aws-topology-wazuh-local-reader`와 장기 Access
Key를 사용했다. Key는 Git 밖의 전용 Profile에만 저장하고 Manager에 Read-only로
Mount했으며, 프로젝트 종료 후 비활성화·삭제한다. 이는 계획서의 임시 STS Reader Role
기본안과 다른 **로컬 실습용 예외**다.

또한 설치된 Wazuh 4.14.7은 실제 Prefix 조회 전에 Bucket 최상위
`ListObjectsV2(Prefix="")`를 실행한다. 수동 Reader Policy는 이를 반영해 Bucket의
`s3:ListBucket`만 허용하고, Object 내용은 CloudTrail Prefix의 `s3:GetObject`로 계속
제한했다. 현재 Terraform Reader Role의 Prefix 조건은 이 Runtime 요구와 일치하지
않으므로 Source 보정·Fresh Plan·승인된 Apply 전에는 검증된 Wazuh 실행 경로로 주장하지
않는다.

#### 4.4 탐지와 분석 계약

Wazuh Custom Rule은 최소한 다음 **의미 조건**을 함께 확인한다. 아래 표기는
CloudTrail 원본 JSON 기준이며, Wazuh Rule의 `<field name="...">` 경로로 미리 확정한
값이 아니다.

```text
eventSource = s3.amazonaws.com
eventName = GetObject
recipientAccountId = 승인 Account
userIdentity.sessionContext.sessionIssuer.userName = Primary Karpenter Node Role
requestParameters.bucketName = 현재 Primary Application Bucket
requestParameters.key starts with validation/
errorCode 없음
```

대표 Event를 먼저 수집한 뒤 `wazuh-logtest` Phase 2와 `wazuh-archives-*` JSON에서 실제
Decoded Field 경로를 확인하고 Custom Rule에 고정한다. 즉 `aws.*` 또는 Index의
`data.aws.*`처럼 보일 것이라고 추측해 Rule을 먼저 작성하지 않는다.

완성된 Alert에서는 원본 `CloudTrail eventID`, Event 시간, Rule ID·Level, Role,
Bucket·Key, 성공 여부를 확인할 수 있어야 한다. Shuffle의 중복 제거 기준도 재수집 때
달라질 수 있는 Wazuh Alert ID가 아니라, Runtime에서 확인한 Decoded Field의 원본
`CloudTrail eventID`를 사용한다.

Wazuh가 현재 관측 공백을 자동으로 메우지는 않는다. DVWA Command Body·실행 결과와
Pod→IMDS 네트워크 Event는 계속 미수집이며, WAF와 Apache에는 공통 Request ID도 없다.
따라서 Gate 4의 다중 Source 분석은 같은 시간창·Method·Path·Role·Object를 이용한
Timeline 조사로 설명하고, 완전한 인과 상관분석으로 과장하지 않는다.

다섯 Source의 Timeline에는 가능한 범위에서 다음 Field를 사용한다.

| Source | Timeline 핵심 Field |
|---|---|
| CloudFront | 시각·Method·Path·Status·Edge Request ID |
| WAF | 시각·Method·Path·Action·Rule Label·Client IP |
| ALB | 시각·Method·Path·ELB Status·Target Status·Client IP |
| DVWA | 시각·Pod·`event_type`·`result`·`resource`·`action`·`status` |
| CloudTrail | `eventTime`·`eventID`·`eventName`·Role·Object·성공 여부 |

모든 Source를 관통하는 공통 Request ID는 없다. CloudFront와 WAF는 Edge Request ID,
WAF·ALB·DVWA는 시간창·Method·Path, DVWA 결과와 CloudTrail은 시간창·Role·고정 Object를
이용해 연결하고 그 한계를 Dashboard에 표시한다.

#### 4.5 초보자용 관제 화면 계약

초보자용 Dashboard는 Raw JSON을 보기 좋게 배열한 화면이 아니다. 사용자가 WQL·DQL
검색식을 입력하지 않고도 다음 질문에 답할 수 있어야 한다.

```text
무슨 일이 발생했는가
언제 발생했는가
위험도는 무엇인가
어떤 요청·Role·Resource가 관련됐는가
어느 계층에서 관측됐고 어디는 보이지 않는가
왜 이 사건이 Alert가 됐는가
현재 대응 상태와 다음 조치는 무엇인가
필요할 때 어떤 원본 Event로 내려갈 수 있는가
```

화면은 최소한 다음 영역을 가진다.

- **사건 요약:** 한글 사건명·발생 시각·위험도·탐지 상태
- **공격 경로:** CloudFront → WAF → ALB → DVWA → CloudTrail의 관측 상태
- **시간순 Timeline:** Source·행위·결과·상관 기준·관측 공백
- **탐지 근거:** Rule `100100`·Level·Role·Object·성공 여부
- **대응 상태:** 미조치·Shuffle 검증 중·Containment 완료 중 하나
- **다음 조치:** 승인된 Playbook 또는 조사 Runbook
- **원본 Drill-down:** 필요할 때만 Raw Event와 Alert 상세로 이동

사용성 합격 시험은 다음과 같다.

> 검색 문법을 모르는 다른 조원이 별도 설명 없이 Dashboard를 열고 3분 안에 사건 내용,
> 위험도, 영향 대상, 탐지 근거, 관측 공백, 다음 조치를 설명할 수 있어야 한다.

Account ID·Bucket·Client IP·Request ID는 내부 조사 화면에서만 필요 최소한으로 사용하고,
공개 Screenshot·영상에서는 마스킹한다. Credential·Cookie·Command 원문·응답 원문은
Dashboard에 넣지 않는다.

#### 4.6 완료 조건

Source 완전성:

- [x] CloudTrail S3 원본 Event와 Rule `100100` Alert Runtime 확인
- [x] WAF CloudWatch Logs의 실제 요청 Record를 Wazuh Raw Archive에서 확인
- [x] ALB S3 Access Log를 Wazuh `alb` 입력으로 연결하고 실제 Record·주요 Field 확인
- [x] DVWA CloudWatch Logs의 실제 Pod Record를 Wazuh Raw Archive에서 확인
- [ ] 새 DVWA 안전 Audit Image를 배포하고 실행 결과 Event의 Wazuh 도착 확인
- [x] CloudFront 병렬 CloudWatch Logs를 3일 보존·`capital-one-lab` 전용으로 확정하고 비파괴 Foundation Plan 확인
- [x] CloudFront 실제 요청 Record를 Wazuh Raw Archive·Archives Index에서 확인
- [x] 다섯 필수 Source 모두 Wazuh에서 검색 가능

탐지·분석:

- [x] 첫 실행 전 Account·Region·`only_logs_after` 경계를 설정하고 실제 수집 범위를 기록
- [x] Capital One CloudTrail Custom Rule을 `wazuh-logtest`와 실제 수집 Event로 검증
- [x] 공격 Event에서 Rule `100100`·Level 12 Wazuh Alert 생성
- [ ] 정상 `terra-user` 대조군이 같은 Custom Alert를 만들지 않음
- [x] Alert와 Raw Archive에서 동일 `CloudTrail eventID` 확인
- [ ] 다섯 Source를 같은 시간창의 사건 Timeline으로 구성
- [ ] 정탐·오탐·미판정·관측 공백 분류 기록

초보자 사용성:

- [ ] 검색식 없이 사건을 확인하는 한글 Saved View·Dashboard 구현
- [ ] 사건 요약·공격 경로·Timeline·탐지 근거·대응 상태·다음 조치 표시
- [ ] Raw Event·Alert Drill-down 제공
- [ ] 다른 조원의 3분 무검색 사용성 Test 통과
- [ ] 새 Alert가 `amazon` Group 적용 뒤 AWS 전용 Events 화면에 표시됨

운영·보존·위생:

- [x] Custom Rule Host 원본·Bind Mount·Hash 일치·문법 검사
- [ ] Wazuh 재시작 뒤 설정·Rule·수집 Event 보존
- [ ] Archive 하루 증가량 측정 뒤 7일 Retention 적용·검증
- [ ] Credential·Webhook·기본 Password가 Repository와 Evidence에 없음

#### 4.7 Gate 4와 이후 Gate의 경계

Gate 4는 공격·탐지 로그와 사람이 읽을 수 있는 사건 화면까지 닫는다. Dashboard의
`다음 조치`가 Shuffle을 가리키는 것만으로 자동 대응이 완료된 것은 아니다.

```text
Gate 4  공격 Source 5개 + 사건 Timeline + 초보자용 Dashboard
Gate 5  Wazuh Alert → Shuffle 검증·중복 차단 Dry Run
Gate 6  승인된 GitHub 한 줄 변경
Gate 7  Argo CD·EKS 배포 Evidence + 재공격 실패
```

### Gate 5 — SOAR Dry Run

SOAR는 처음부터 GitHub를 변경하지 않는다.

```text
Wazuh Alert 수신
→ CloudTrail eventID·Rule ID·Role·Account·Lab Prefix 검증
→ 같은 CloudTrail eventID 중복 실행 차단
→ ‘실행했을 GitHub Workflow’ Preview
→ 아무것도 변경하지 않고 종료
```

완료 조건:

- [ ] 허용한 Account·Role·Scenario만 통과
- [ ] 같은 CloudTrail eventID 재수신 시 중복 실행 없음
- [ ] Credential·원본 Log를 GitHub로 전달하지 않음
- [ ] 실패·Timeout·재시도 기록

### Gate 6 — GitOps 자동 Containment

권장 구조:

```text
SOAR
→ 제한된 workflow_dispatch 또는 repository_dispatch
→ 사전 검토된 GitHub Actions
→ deploy/dvwa/values.yaml 한 값만 검증·변경
→ Bot Commit to main
→ Argo CD Auto Sync
```

금지:

```text
SOAR가 임의 파일·임의 Branch를 수정
LLM이 생성한 Patch를 무검토 Push
Terraform Apply를 GitHub Commit처럼 취급
Alert 하나만으로 광범위한 IAM 관리자 작업 수행
```

Workflow 안전 조건:

- [ ] 변경 전 값이 정확히 `low`인지 확인
- [ ] 변경 후 값이 정확히 `impossible`인지 확인
- [ ] 다른 파일 Diff가 있으면 실패
- [ ] 이미 `impossible`이면 성공으로 종료하는 Idempotency
- [ ] Commit에 Incident/Finding 식별자 포함, 민감정보 제외
- [ ] 자동 Containment와 Reset이 같은 `concurrency` 그룹을 사용

재촬영 Reset은 자동 대응 Workflow에 역방향 옵션을 추가하지 않고 별도의 수동
Workflow로 만든다.

```text
workflow_dispatch만 허용
→ GitHub Environment 사람 승인
→ TAKE_ID + 정확한 확인문 검증
→ 현재 값이 impossible인지 확인
→ deploy/dvwa/values.yaml의 한 값만 low로 변경
→ 새 Reset Commit을 main에 Push
→ Argo CD Auto Sync
```

Reset 안전 조건:

- [ ] `impossible → low` 외의 변경을 거부
- [ ] 이미 `low`이면 변경 없이 성공 종료
- [ ] 임의 Branch·파일·값 입력을 받지 않음
- [ ] 과거 Containment Commit을 삭제·강제 Push·History Rewrite하지 않음
- [ ] Commit에 `TAKE_ID`를 넣고 Credential·원본 Event는 넣지 않음

### Gate 7 — Argo CD 배포·재공격 검증

관찰 순서:

```text
GitHub Commit
→ Argo CD OutOfSync 또는 새 Revision 감지
→ Syncing
→ EKS Control Plane Audit에서 배포 API Event 확인
→ Deployment Rollout
→ Healthy·Synced
→ 새 Pod·새 세션 확인
→ 동일 Payload 재시도
```

완료 조건:

- [ ] Argo가 예상 Commit SHA를 배포
- [ ] EKS Control Plane `audit`에서 Argo 배포 관련 API Event를 같은 시간창으로 확인
- [ ] Pod Template의 `DEFAULT_SECURITY_LEVEL=impossible`
- [ ] 새 Pod Ready
- [ ] 동일 Command Injection Payload가 실행되지 않음
- [ ] 정상 로그인·페이지 접근 Regression 통과
- [ ] 차단 사실과 기존 Credential 무효화를 혼동하지 않음
- [ ] DVWA 전용 조치임을 시연 화면과 설명에서 명시

### Gate 7-R — 실패한 촬영의 수동 재준비

이 Gate는 정상 운영의 자동 복구가 아니라 같은 통제 실습을 다시 촬영하기 위한
선택적 절차다. 첫 촬영이 승인되면 실행하지 않는다.

```text
촬영 실패 판정·TAKE_ID 종료 기록
→ 수동 Reset 승인
→ impossible → low Reset Commit
→ Argo CD가 Reset Commit 배포
→ 새 Pod Ready·Synced·Healthy
→ 새 브라우저 세션에서 low 확인
→ 공격자 PC의 이전 AWS 임시 Credential 제거
→ Alarm의 실제 OK 복귀 확인
→ 새 TAKE_ID·ExperimentId·UTC 시간창 발급
→ 다음 촬영 시작
```

CloudWatch Alarm Action은 보통 상태 전환 때 실행되므로 계속 `ALARM`인 상태에서
다시 공격하면 두 번째 자동 조치가 시작되지 않을 수 있다. 데모를 맞추기 위해
`SetAlarmState`로 강제 OK 처리하지 않고 실제 평가로 `OK`가 된 것을 확인한다.

완료 조건:

- [ ] Reset Commit만으로 새 Image Build 없이 Rollout됐다.
- [ ] 새 Pod·새 세션의 기본값이 `low`다.
- [ ] 이전 AWS Credential 환경변수가 공격자 PC에 남아 있지 않다.
- [ ] 이전 로그는 삭제하지 않고 실패한 `TAKE_ID`로 구분했다.
- [ ] Alarm이 실제 `OK`이며 AWS Native SNS 경로가 다음 TAKE를 받을 수 있다.
- [ ] 새 CloudTrail `eventID`가 독립된 두 번째 Wazuh Alert·대응을 만들 수 있다.
- [ ] `TAKE_ID`는 촬영·Evidence 묶음 표식이며 보안 Event 고유 ID를 대신하지 않는다.

### Gate 8 — 영구 대응·전체 Rehearsal

- [ ] 최종 사용할 영상 구간이 열리고 재생되는지 먼저 확인
- [ ] 최종 촬영 승인 뒤에는 수동 Reset을 실행하지 않음
- [ ] Terraform 보안 설정 복구 Plan 검토
- [ ] 승인된 Apply 후 IMDS·S3 Negative Test
- [ ] 네 명 모두 공격·탐지·대응 흐름 반복
- [ ] 각자 정탐 근거와 한계를 설명
- [ ] 전체 소요시간 측정
- [ ] 실패 시 수동 복구 Runbook 검증
- [ ] 촬영을 중단하거나 자리를 비우면 취약 Runtime을 `low`로 방치하지 않음

---

## 7. 시연 영상 Storyboard

영상은 한 번에 끊김 없이 촬영해야 성공하는 시험으로 만들지 않는다. 각 구간 시작에
같은 `TAKE_ID`와 UTC 시각을 보여주고, 지연이 있는 AWS 로그·Alarm·Argo 단계는
Timestamp와 구간 전환을 명시한다.

| 장면 | 화면 | 반드시 보여줄 Evidence |
|---:|---|---|
| 0 | 촬영 Slate | `TAKE_ID`·UTC 시작·DVWA low·Alarm OK |
| 1 | 시나리오·취약 Profile | 실습 범위와 가짜 데이터 |
| 2 | DVWA 공격 | 통제된 Payload 실행 |
| 3 | IMDS·S3 결과 | Credential 원문 없이 Role·가짜 CSV 접근 성공 |
| 4 | 원본 로그 | 공격 시각·Role·S3 Event |
| 5 | SIEM Alert | Rule·Severity·정탐 근거 |
| 6 | SOAR 실행 | 검증·중복 차단·GitHub Dispatch |
| 7 | GitHub | Bot Commit과 한 줄 Diff |
| 8 | Argo CD | Revision·Syncing·Healthy·새 Pod |
| 9 | 재공격 | 같은 Payload 실패 |
| 10 | 결과 | DVWA 전용 자동 Containment와 실제 환경의 영구 대응 구분 |

장면 0~9가 모두 유효한지 확인하기 전에는 Terraform 영구 복구 장면을 촬영하지
않는다. 중간 장면이 실패하면 해당 `TAKE_ID`를 실패로 표시하고 Gate 7-R로 돌아간다.
최종 사용할 구간을 확인한 뒤에만 영구 복구를 수행하고 장면 10에 연결한다.

공개 영상 금지 항목:

```text
AWS Access Key·Secret·Session Token
전체 Account ID·버킷명
GitHub Token·Webhook Secret
전체 Client IP·Request ID·Cookie·Authorization Header
개인정보처럼 보이는 실제 데이터
```

---

## 8. 잠정 7일 실행 순서

정확한 마감과 팀 가용시간을 확인한 후 날짜를 고정한다.

| 일차 | 목표 | 종료 Gate |
|---:|---|---|
| 1 | 시나리오 정제·Credential 제거·공격 재현 | Gate 0·1 |
| 2 | CloudTrail·GuardDuty·WAF·Application Coverage | Gate 2 |
| 3 | 탐지 규칙·SIEM Alert | Gate 3·4 |
| 4 | SOAR 수신·Dry Run·중복 방지 | Gate 5 |
| 5 | GitHub 자동 Containment·수동 Reset·Argo 검증 | Gate 6·7·7-R |
| 6 | E2E Rehearsal·재촬영 Reset 연습·팀원 교대 실습 | Gate 7-R |
| 7 | 최종 영상 확인 → Terraform 영구 복구 → Evidence 정리 | Gate 8·최종 완료 |

어느 Gate가 닫히지 않았으면 뒤 단계의 성공으로 앞 단계를 대체하지 않는다.

---

## 9. 팀 공통 이해 확인

모든 팀원은 다음 질문에 답할 수 있어야 한다.

```text
왜 이것을 Capital One ‘기반’ 시나리오라고 부르는가
Command Injection과 SSRF의 차이는 무엇인가
Pod가 왜 Node Role Credential에 도달했는가
Public S3가 아닌데 왜 데이터가 읽혔는가
어떤 Event가 실제 탐지 근거인가
SIEM과 SOAR의 역할 차이는 무엇인가
왜 SOAR가 임의 코드를 Push하면 안 되는가
Argo CD가 담당한 것과 Terraform이 담당한 것은 무엇인가
자동 Containment가 막은 것과 아직 막지 못한 것은 무엇인가
수동 Reset이 되돌린 것과 되돌리지 않은 것은 무엇인가
왜 다음 촬영 전에 Alarm의 OK 복귀와 새 세션이 필요한가
동일 공격 실패를 어떻게 검증했는가
```

---

## 10. 결정 및 대기 목록

다음 항목은 계획서 존재만으로 결정하지 않는다. 앞 Gate의 Evidence를 본 뒤 하나씩
확정한다.

| 결정 | 후보 | 결정 시점 |
|---|---|---|
| 대표 탐지 신호 | **CloudTrail GetObject Custom Rule 확정·Runtime 정탐 검증** | 2026-08-12 완료 |
| 중앙 관제 제품 | **Wazuh 확정, 별도 ELK 미구축** | 2026-08-12 사용자 결정 |
| SIEM 위치 | **Local Docker single-node** | Wazuh 4.14.7 세 Service 기동·CloudTrail Dashboard 집계 확인 |
| Gate 4 필수 AWS→SIEM 입력 | **CloudFront + WAF + ALB + DVWA + CloudTrail** | 5/5 Raw Runtime 확인, 탐지·Timeline·사용성은 별도 대기 |
| EKS Control Plane Log | **Gate 7 배포·대응 Evidence** | `api`·`audit`·`authenticator` 활성, Argo 배포 시간창 Runtime 대기 |
| Wazuh Runtime Credential | **로컬 전용 IAM User 장기 Key 예외** | Git 밖 Profile·Read-only Mount, 종료 후 비활성화·삭제 |
| Terraform Reader Role | Source·Apply 존재, 현재 Runtime 경로는 아님 | Wazuh Bucket 최상위 List 요구 반영 뒤 재검증 |
| SOAR 제품 | **Shuffle 확정** | Wazuh 공식 Webhook 연동, Gate 5 Runtime 전 |
| GitHub 호출 방식 | `workflow_dispatch` / `repository_dispatch` | 권한 설계 후 |
| 자동 대응 값 | **`defaultSecurityLevel=impossible` 확정** | DVWA 전용 시연 Containment |
| 재촬영 Reset | **수동 `workflow_dispatch`, `impossible → low`만 허용** | Gate 6 구현 |
| 실제 SSRF 모듈 | 핵심 E2E 이후 선택적 Upgrade | 현재 보류 |
| AWS 측 자동 격리 | 미구현 / 제한된 별도 단계 | 핵심 완료 후 |
| 두 번째 시나리오 | S3 공개 설정 / SQLi | 핵심 완료 후 |

---

## 11. 지금 바로 할 한 가지

Gate 3과 Wazuh Local Docker Preflight, Reader Terraform Apply·AssumeRole·Post-Apply
0-change, CloudTrail 중앙 수집·Custom Alert, WAF·ALB·DVWA·CloudFront Raw Archive 연결을
완료했다.
TAKE `capital-one-20260813T082735Z`에서 S3 `GetObject` 원본과 Rule `100100`·Level 12
Alert를 동일한 CloudTrail `eventID`로 확인했다. 즉 CloudTrail 기반 양성 탐지 장면은
촬영 가능하고 필수 5-Source도 중앙 수집되지만, 이 결과를 사건 Timeline·탐지·초보자용
Dashboard 완료로 확대하지 않는다.

```text
Gate 3: 정탐 + 정상 대조군 + Alert Runtime 필드 + Post-Apply 0-change 완료
→ Wazuh single-node Preflight 완료
→ 로컬 전용 Reader + Read-only Mount + CloudTrail S3 수집 완료
→ 기존 Baseline GetObject 검색 0건·기본 Rule 목록/Archive 비활성 원인 확인
→ Gate 3 Sanitized Event로 Custom Rule 작성·wazuh-logtest 완료
→ Raw Archive 활성화·새 통제 Event Custom Alert 완료
→ WAF·DVWA CloudWatch Logs 입력·실제 Record 확인 완료
→ ALB Reader Policy 재조회·Wazuh `alb` 입력·실제 Record Parsing 완료
→ CloudFront 병렬 CloudWatch Logs 3일·Lab 전용 Source·비파괴 Foundation Plan 완료
→ Foundation Apply·Daily `capital-one-lab` Delivery·Wazuh CloudFront Record 확인 완료
→ 새 DVWA 안전 Audit Image 배포·Wazuh Event 확인
→ 필수 5-Source 사건 Timeline·한글 Dashboard 구현
→ 다른 조원의 3분 무검색 사용성 Test
→ 다음 새 Alert에서 amazon Group 화면 노출·정상 대조군 오탐 검증
→ Archive 증가량 측정 뒤 7일 Retention 검증
```

현재 확인된 범위는 `Command Injection → IMDS → Node Role Credential → 고정 가짜 S3
GetObject → CloudTrail → Metric Filter → Alarm`과 같은 TAKE의 WAF·DVWA·GuardDuty
Coverage 판정, `CloudFront·WAF·ALB·DVWA·CloudTrail → Wazuh Raw Archive`, CloudTrail
Custom Alert다. Pod→IMDS 직접 네트워크 로그는 현재 방식으로 수집되지 않는다. 새 DVWA
안전 Audit Runtime, 필수 5-Source Timeline, 초보자용 관제 화면, Wazuh
정상 대조군, SOAR, GitHub 변경, Argo CD·EKS 배포 Evidence, 재공격 실패는 아직 구현하거나
검증하지 않았다.
Watchdog Hard Deadline은 각 `daily-up.ps1` Session의 실제 출력과 Session State를 기준으로
확인한다. 작업을 중단하면 과거 문서의 예약 시각을 믿고 기다리지 말고
`daily-down.ps1`로 Daily Runtime을 종료한다.
