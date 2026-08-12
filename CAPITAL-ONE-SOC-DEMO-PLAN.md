# Capital One 기반 보안 관제·자동 대응 시연 계획

> **상태:** Draft v0.6 — 공격·CloudTrail·확정 Alarm 검증 완료, SIEM·SOAR·GitHub 자동화 미검증
> **기준 시점:** 2026-08-12
> **현재 절차 Gate:** Gate 2 — S3 CloudTrail 확인 완료, 나머지 공격 로그 Coverage 확인 중
> **현재 Runtime 상태:** T4 BASELINE OBSERVED — `minimal + capital-one-lab`, 자동 Containment 실행 전
> **Terraform 진행:** T1·T2 Source, T3 Plan-only, Foundation·Daily Apply와 Post-Apply 0-change 검증 완료
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
| SIEM | 여러 로그와 경보를 한 화면에서 조회·분석한다. |
| SOAR | 경보를 검증하고 사전에 허용된 대응 절차를 요청한다. |
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
위한 중간 완료 조건이다. 현재는 새 제품을 설치하기 전에 Gate 0~2에서 공격 재현과
실제 로그 존재 여부를 먼저 확인한다.

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

| 공격 단계 | 후보 Source | 확인할 내용 |
|---|---|---|
| DVWA 공격 요청 | WAF·ALB·DVWA Log | 요청 시각·경로·Source·Rule Match |
| Pod의 IMDS 접근 | Application·Runtime·Network 후보 | 현재 구성에서 실제 관측 가능한지 |
| Node Role 외부 사용 | CloudTrail·GuardDuty | Role·Source IP·User Agent·Finding |
| S3 객체 읽기 | CloudTrail S3 Data Event | `GetObject`·Role·Prefix·성공/거부 |

완료 조건:

- [x] `enable_project_s3_data_events` 실제 Runtime 값 확인
- [x] 외부 사용 시점 CloudTrail Event 확인
- [ ] GuardDuty Finding 발생 여부 확인
- [ ] 보이지 않는 구간을 ‘미탐’ 또는 ‘미수집’으로 명시
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
- [ ] 정상 접근으로 오탐 Test
- [x] 공격 접근으로 정탐 Test
- [ ] Alert에 시간·Role·행위·Severity 포함

Runtime 정탐 결과는 Metric Filter의 새 `ALARM` 전환과 같은 시간창의 CloudTrail
`GetObject` 1행으로 확인했다. 첫 Evidence Query가 0행이었던 원인은 공격이나 AWS
로그 부재가 아니라 Windows PowerShell 5.1의 native argument 인용 손실이었다.
Collector가 CWLI를 UTF-8 `file://`로 전달하도록 고쳤고, CAPITAL-ONE에만 최소 1행과
제한된 전달 재조회를 적용한 뒤 Bundle을 다시 생성해 1행을 확인했다.

### Gate 4 — SIEM·중앙 관제 계층

후보는 하나만 선택한다.

```text
Wazuh
또는
Elastic Security
```

선택 기준:

- 현재 CloudTrail·GuardDuty Source 연동 시간
- 필요한 Field Parsing 가능 여부
- Custom Rule과 Alert 표현력
- 팀원 네 명이 직접 조회·설명 가능한가
- 로컬 자원·AWS 비용
- 재설치·복구 가능성

완료 조건:

- [ ] Raw Event 검색
- [ ] Detection Rule 실행
- [ ] Alert 생성
- [ ] Alert에서 원본 Event로 이동
- [ ] 정탐·오탐·미판정 분류 기록

### Gate 5 — SOAR Dry Run

SOAR는 처음부터 GitHub를 변경하지 않는다.

```text
Alert 수신
→ Finding ID·Type·Role·Account·Lab Prefix 검증
→ 중복 Finding 차단
→ ‘실행했을 GitHub Workflow’ Preview
→ 아무것도 변경하지 않고 종료
```

완료 조건:

- [ ] 허용한 Account·Role·Scenario만 통과
- [ ] 같은 Finding ID 재수신 시 중복 실행 없음
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
→ Deployment Rollout
→ Healthy·Synced
→ 새 Pod·새 세션 확인
→ 동일 Payload 재시도
```

완료 조건:

- [ ] Argo가 예상 Commit SHA를 배포
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
- [ ] Alarm이 실제 `OK`이며 SOAR 중복 방지가 Alarm 이름만으로 고정되지 않았다.
- [ ] 새 AWS Event·Alarm 상태 전환 ID가 독립된 두 번째 대응을 만들 수 있다.
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

## 10. 결정 대기 목록

다음 항목은 계획서 존재만으로 결정하지 않는다. 앞 Gate의 Evidence를 본 뒤 하나씩
확정한다.

| 결정 | 후보 | 결정 시점 |
|---|---|---|
| 대표 탐지 신호 | **CloudTrail GetObject Custom Rule 확정·Runtime 정탐 검증** | 2026-08-12 완료 |
| 중앙 관제 제품 | Wazuh / Elastic Security | Source 연동 검토 후 |
| SOAR 제품 | Shuffle 우선 검토 / 다른 Workflow 도구 | Gate 4 종료 |
| GitHub 호출 방식 | `workflow_dispatch` / `repository_dispatch` | 권한 설계 후 |
| 자동 대응 값 | **`defaultSecurityLevel=impossible` 확정** | DVWA 전용 시연 Containment |
| 재촬영 Reset | **수동 `workflow_dispatch`, `impossible → low`만 허용** | Gate 6 구현 |
| 실제 SSRF 모듈 | 핵심 E2E 이후 선택적 Upgrade | 현재 보류 |
| AWS 측 자동 격리 | 미구현 / 제한된 별도 단계 | 핵심 완료 후 |
| 두 번째 시나리오 | S3 공개 설정 / SQLi | 핵심 완료 후 |

---

## 11. 지금 바로 할 한 가지

Baseline과 확정 탐지는 끝났다. 공격을 다시 실행하거나 Terraform을 다시 Apply하지
않고, 같은 TAKE의 Gate 2 Coverage Matrix를 먼저 완성한다.

```text
WAF·DVWA에서 Command Injection 요청 흔적 확인
→ Pod→IMDS 구간이 현재 로그에서 보이는지/안 보이는지 판정
→ GuardDuty 실제 Finding 발생 여부 확인
→ CloudTrail 확정 1행과 최소 상관 Field 정리
→ Gate 3의 정상 GetObject 오탐 Test와 Alert 필드 보강
→ 그 뒤 중앙 관제 제품 한 개 선택
```

현재 확인된 범위는 `Command Injection → IMDS → Node Role Credential → 고정 가짜 S3
GetObject → CloudTrail → Metric Filter → Alarm`이다. SIEM 화면, SOAR, GitHub 변경,
Argo CD Containment, 재공격 실패는 아직 구현하거나 검증하지 않았다. Active Session의
Watchdog Hard Deadline은 2026-08-12 22:00 KST, 실패 재시도 창은 자정까지다. 작업을
중단하면 예약 시각을 기다리지 말고 `daily-down.ps1`로 Daily Runtime을 종료한다.
