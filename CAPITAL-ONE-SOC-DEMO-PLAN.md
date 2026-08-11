# Capital One 기반 보안 관제·자동 대응 시연 계획

> **상태:** Draft v0.2 — DVWA 전용 자동 Containment 방식 확정, 제품·탐지 규칙·자동화 구현은 미확정
> **기준 시점:** 2026-08-11
> **현재 Gate:** Gate 0 — 시나리오 명세·Evidence·비밀정보 정리
> **기존 구현 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)
> **기존 관측성 계획:** [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)
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
```

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

다음 여덟 항목이 모두 Runtime Evidence로 확인돼야 완료다.

- [ ] 통제된 취약 설정에서 동일 공격을 반복할 수 있다.
- [ ] 노드 역할 임시 자격증명으로 가짜 S3 자료 접근이 성공한다.
- [ ] 공격과 직접 연결되는 원본 로그가 보존된다.
- [ ] SIEM 또는 중앙 탐지 계층에서 경보가 발생한다.
- [ ] 경보 근거와 공격 Timeline을 사람이 설명할 수 있다.
- [ ] 자동 대응이 사전에 정한 GitHub Workflow만 실행한다.
- [ ] GitHub Commit 후 Argo CD가 변경을 자동 배포한다.
- [ ] 새 세션에서 같은 공격을 반복하면 IMDS 자격증명 획득이 실패한다.
- [ ] DVWA 전용 시연 조치와 실제 환경의 대응 방법을 명확히 구분한다.

---

## 2. 범위와 제외 범위

### 2.1 핵심 범위

```text
대표 공격 1개
탐지 규칙 1개
자동 대응 Workflow 1개
GitOps 보안 설정 변경 1개
재공격 검증 1회
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
DR 고도화
LLM이 임의 보안 코드를 생성·Push하는 구조
SOAR에 광범위한 AWS·GitHub 관리자 권한 부여
```

### 2.3 핵심 완료 후 확장 순서

```text
1. 두 번째 대표 시나리오
2. 기존 탈취 자격증명까지 무효화하는 AWS 측 자동 격리
3. Shuffle SOAR 고도화
4. n8n·AI 분석 보조
5. CNAPP 조사
```

---

## 3. 현재 확인된 기반과 미검증 경계

### 3.1 현재 Source에서 확인된 기반

```text
CloudTrail
→ Management Event 기본 수집
→ enable_project_s3_data_events 선택 시 프로젝트 S3 Data Event 수집

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
enable_iam01_imds_s3_lab: false
Node Role S3 실습 권한 제거
필요 시 취약 Karpenter Node 교체
NetworkPolicy·IMDS egress 통제 검토
```

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
- [ ] Command Injection을 대체 진입점으로 명시
- [ ] IMDS 주소를 `169.254.169.254` link-local로 보정
- [ ] `Access Key로 SSH 가능` 표현 제거
- [ ] Session Token·Access Key·Account ID·버킷명 공개본 마스킹
- [ ] 취약 설정과 복구 설정을 정확히 기록
- [ ] 가짜 개인정보만 사용했음을 명시

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

- [ ] 임의 Target을 허용하지 않는 제한된 실행 절차
- [ ] 시작·종료 UTC Timestamp 기록
- [ ] 실제 Credential 원문 미저장
- [ ] 실습 후 환경변수 Credential 제거
- [ ] 공격 실패 시에도 환경을 원복할 수 있음

### Gate 2 — 공격 로그 Coverage

목적: 공격 단계별로 무엇이 보이고 무엇이 안 보이는지 확정한다.

| 공격 단계 | 후보 Source | 확인할 내용 |
|---|---|---|
| DVWA 공격 요청 | WAF·ALB·DVWA Log | 요청 시각·경로·Source·Rule Match |
| Pod의 IMDS 접근 | Application·Runtime·Network 후보 | 현재 구성에서 실제 관측 가능한지 |
| Node Role 외부 사용 | CloudTrail·GuardDuty | Role·Source IP·User Agent·Finding |
| S3 목록·객체 읽기 | CloudTrail S3 Data Event | `ListBucket`·`GetObject` Event |

완료 조건:

- [ ] `enable_project_s3_data_events` 실제 Runtime 값 확인
- [ ] 외부 사용 시점 CloudTrail Event 확인
- [ ] GuardDuty Finding 발생 여부 확인
- [ ] 보이지 않는 구간을 ‘미탐’ 또는 ‘미수집’으로 명시
- [ ] 동일 사건을 묶는 최소 Field 선정

### Gate 3 — 탐지 경로 선택

다음 순서로 판단한다.

```text
1순위: 실제 GuardDuty Credential Exfiltration Finding
2순위: CloudTrail S3 Data Event 기반 Custom Rule
3순위: WAF·Application 초기 침투 경보와 S3 Event 상관 규칙
```

최종 시연에서 실제 공격과 무관한 Sample Finding만으로 성공을 주장하지 않는다.

완료 조건:

- [ ] 탐지 Rule 입력 Source 확정
- [ ] Rule 조건과 제외 조건 문서화
- [ ] 정상 접근으로 오탐 Test
- [ ] 공격 접근으로 정탐 Test
- [ ] Alert에 시간·Role·행위·Severity 포함

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
- [ ] 전용 Reset은 수동 실행만 허용

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

### Gate 8 — 영구 대응·전체 Rehearsal

- [ ] Terraform 보안 설정 복구 Plan 검토
- [ ] 승인된 Apply 후 IMDS·S3 Negative Test
- [ ] 네 명 모두 공격·탐지·대응 흐름 반복
- [ ] 각자 정탐 근거와 한계를 설명
- [ ] 전체 소요시간 측정
- [ ] 실패 시 수동 복구 Runbook 검증

---

## 7. 시연 영상 Storyboard

영상은 한 번에 끊김 없이 촬영해야 성공하는 시험으로 만들지 않는다. 지연이 있는
AWS 로그·GuardDuty·Argo 단계는 Timestamp를 표시하고 구간 전환을 명시한다.

| 장면 | 화면 | 반드시 보여줄 Evidence |
|---:|---|---|
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
| 5 | GitHub Workflow·Argo 자동 Containment | Gate 6·7 |
| 6 | 영구 대응·전체 E2E·팀원 교대 실습 | Gate 8 |
| 7 | 실패 보정·영상 촬영·Evidence 정리 | 최종 완료 |

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
동일 공격 실패를 어떻게 검증했는가
```

---

## 10. 결정 대기 목록

다음 항목은 계획서 존재만으로 결정하지 않는다. 앞 Gate의 Evidence를 본 뒤 하나씩
확정한다.

| 결정 | 후보 | 결정 시점 |
|---|---|---|
| 대표 탐지 신호 | GuardDuty Finding / CloudTrail Custom Rule | Gate 2 종료 |
| 중앙 관제 제품 | Wazuh / Elastic Security | Source 연동 검토 후 |
| SOAR 제품 | Shuffle 우선 검토 / 다른 Workflow 도구 | Gate 4 종료 |
| GitHub 호출 방식 | `workflow_dispatch` / `repository_dispatch` | 권한 설계 후 |
| 자동 대응 값 | **`defaultSecurityLevel=impossible` 확정** | DVWA 전용 시연 Containment |
| AWS 측 자동 격리 | 미구현 / 제한된 별도 단계 | 핵심 완료 후 |
| 두 번째 시나리오 | S3 공개 설정 / SQLi | 핵심 완료 후 |

---

## 11. 지금 바로 할 한 가지

새 제품을 설치하지 않는다. 먼저 기존 공격 시각을 기준으로 다음을 확인한다.

```text
외부 PC에서 Node Role Credential을 사용한 시간
→ CloudTrail Management Event
→ CloudTrail S3 Data Event
→ GuardDuty Finding
```

결과를 다음 세 값 중 하나로 기록한다.

```text
Observed
NotObserved
NotCollected
```

이 결과가 Gate 3 탐지 방식과 Gate 4 SIEM 선택을 결정한다.
