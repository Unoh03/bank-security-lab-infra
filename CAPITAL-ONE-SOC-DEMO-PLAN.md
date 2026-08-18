# Capital One 기반 보안 관제·자동 대응 시연 계획

> **상태:** Draft v2.0 — 대응 시나리오 정합성 확정, DVWA 저지연 Trigger Runtime 검증 중
> **기준 시점:** 2026-08-18
> **현재 절차 Gate:** Gate 4 — 10분 Evidence 경로는 유지하고, 실제 DVWA `command.execution`의 저지연 Rule `100103`을 먼저 검증한다.
> **최근 Runtime Evidence:** Wazuh Dashboard 2·Visualization 14·Saved Search 2와 필수 Evidence 6개 조건의 읽기 전용 Preflight 통과
> **Terraform 진행:** T1·T2 Source, T3 Plan-only, T4 탐지·대조군·Alert 필드와 CloudFront Hot Copy Runtime 검증 완료
> **번호 구분:** `T0~T6`는 Terraform 구현 순서이고 `Gate 0~8`은 시연 Evidence 검증 순서다. 같은 번호끼리 같은 작업이 아니다.
> **기존 구현 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)
> **기존 관측성 계획:** [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)
> **Terraform 실행 계획:** [`CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md`](./CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md)
> **저지연 전달 설계:** [`observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`](./observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)
> **기존 제한 시나리오:** [`observability/scenarios/README.md`](./observability/scenarios/README.md)
> **침해 대응 정본:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)

> [!IMPORTANT]
> 빠른 Containment는 `DVWA Workload Quarantine + 허용된 IAM 영향 차단`이다.
> `low → impossible`은 그 뒤에 배포하는 **애플리케이션 보안 설정 패치(Remediation)** 다.
> 현재 공유 Karpenter Node Role에는 전체 Deny를 자동 적용하지 않으며, Lab Prefix 임시
> Deny 또는 전용 Principal처럼 Blast Radius가 고정된 경우만 허용한다. 대응 구현은 실제
> `command.execution → Rule 100103` Gate를 닫은 뒤 시작한다.

이 문서는 기존 관측성 구현을 폐기하거나 다시 설명하기 위한 문서가 아니다.
이미 구축한 로그·탐지·GitOps 기반을 이용해 다음 한 장면을 끝까지 완성하기 위한
새 기준 계획서다.

```text
공격 성공과 가짜 개인정보 접근
→ Rule 100103 저지연 탐지
→ Workload·IAM 영향의 좁고 가역적인 Containment
→ 느린 Evidence로 공격 경로·성공 여부 조사
→ low → impossible 보안 설정 패치와 Argo 배포
→ 동일 공격 실패·정상 기능 검증
→ Terraform 영구 복구와 Recovery
```

---

## 0. 초보자용 한눈에 보기

### 0.1 한 문장 목표

> 공격을 저지연으로 탐지해 침해 확산을 먼저 제한하고, 느린 Evidence로 범위를 조사한
> 뒤 검증된 설정 패치와 영구 복구를 배포해 같은 공격이 실패하는 것까지 증명한다.

### 0.2 최종 시연 흐름

```text
공격 성공
→ Rule 100103 저지연 경보
→ DVWA Workload Quarantine
→ 허용된 범위의 IAM 영향 차단
→ 5-Source Timeline 조사
→ low → impossible 보안 설정 패치
→ Argo CD 배포
→ 격리와 패치 효과를 분리한 재검증
```

### 0.3 도구별 역할

| 도구·계층 | 이 계획에서 하는 일 |
|---|---|
| WAF·애플리케이션 로그·CloudTrail | 공격과 AWS 활동의 흔적을 기록한다. |
| GuardDuty·탐지 규칙 | 수집된 흔적이 공격 조건에 맞는지 판단해 경보를 만든다. |
| Wazuh SIEM | 여러 원본 로그를 한곳에서 조회·분석하고 Custom Rule로 Alert를 만든다. |
| Shuffle SOAR | Wazuh Alert를 검증하고 사전 허용된 격리·조사·Remediation 절차를 조정한다. |
| GitHub Actions | 고정된 Workload 격리와 `low → impossible` 설정 패치를 별도 변경으로 검증·Commit한다. |
| Argo CD | 검토된 NetworkPolicy·애플리케이션 설정 변경을 EKS에 배포한다. |
| AWS IAM 대응 | 공유 Role이면 Lab Prefix 영향만 차단하고, 전용 Principal일 때만 사전 승인된 격리를 수행한다. |
| Terraform | IAM 최소 권한·IMDSv2·Node 같은 근본 원인을 사람 승인 후 복구한다. |

### 0.4 Gate를 쉽게 읽는 법

```text
Gate 0  공개 가능한 실습 자료 정리
Gate 1  동일 공격 재현
Gate 2  실제로 남은 로그 확인
Gate 3  경보를 울릴 탐지 조건 결정
Gate 4  관제 화면에 경보 표시
Gate 5  변경 없는 자동 대응 모의 실행
Gate 6  Workload·IAM 영향 Containment 검증
Gate 7  설정 패치·Argo 배포·Recovery 검증
Gate 7-R  촬영 실패 시 사람 승인으로 재촬영 상태 복원
Gate 8  근본 원인 복구와 팀 전체 연습
```

Gate는 별개의 기능 목록이 아니라 앞 단계의 결과를 확인하고 다음 단계로 넘어가기
위한 중간 완료 조건이다. Gate 1~3에서 공격 재현, 로그 Coverage, 정탐·정상 대조군,
Alert 필드 Runtime 검증까지 닫았다. Gate 0의 공개본 위생 체크는 최종 촬영 전 다시
확정한다. 중앙 관제 제품은 Wazuh로 선택했고, CloudTrail Raw Event와 Rule `100100`이
동일 `eventID`로 연결되는 것과 DVWA Push Rule `100102` 무해 전달 3회를 확인했다. 현재
다음 한 가지는 실제 `command.execution → Rule 100103` 반복 검증이다.

### 0.5 빠른 차단과 영구 대응의 차이

```text
Workload Quarantine + 허용된 IAM 영향 차단
= 공격 확산과 추가 접근을 줄이는 즉시·가역적 Containment

DVWA low → impossible
= 취약 동작을 닫는 애플리케이션 보안 설정 패치(Remediation)

IAM 최소 권한·IMDSv2 강제·Node 교체·코드 수정
= 근본 원인을 제거하고 정상 상태로 복구하는 영구 대응
```

Lab Prefix 임시 Deny는 이미 유출된 자격증명 전체를 무효화하지 않는다. 공유 Node Role
전체를 자동 Deny하지 않으며, 세 단계의 목적과 한계를 각각 설명한다.

### 0.6 촬영·재촬영 상태 수명주기

촬영 실패를 Git History 삭제나 Terraform 재적용으로 복구하지 않는다. Reset은 자동
대응의 역방향이 아니라 통제된 Lab을 새 TAKE용으로 다시 여는 수동 절차다.

확신도와 대응 단계를 한 Status에 섞지 않는다.

```text
사건 확신도
UNASSESSED → SUSPECTED(Rule 100103) → CONFIRMED(예상 CloudTrail GetObject 성공)
                                └──→ DISPROVED(조사로 공격 가설 기각)

대응 단계
PREPARED → DETECTED → CONTAINED → INVESTIGATING → REMEDIATED → RECOVERED → CLOSED
                         │
                         └─ 재촬영 결정 → MANUAL RETAKE RESET
                                            Quarantine 유지 중 impossible → low
                                            → Lab IAM 권한 복원
                                            → 새 Pod·Wazuh READY·새 TAKE
                                            → Quarantine을 마지막에 해제 → PREPARED
```

`CONFIRMED`가 늦게 도착해도 이미 `CONTAINED`인 사실을 덮어쓰거나 Containment를 다시
실행하지 않는다. 최종 촬영 승인 뒤에는 Terraform hardened 복구와 Recovery 검증을 거쳐
`CLOSED`로 끝낸다.

수동 Reset은 이전 Credential을 재사용하지 않고 기존 Evidence를 삭제하지 않는다.
오직 다음 촬영을 위해 격리·Lab 권한·DVWA 설정을 승인된 순서로 복원한다. 같은 촬영
시간창을 벗어나거나 노트북을 떠나야 하면 `low`를 공개 상태로 두지 않고 다시 격리하거나
Daily Runtime을 내린다.

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
- [ ] 자동 대응이 DVWA Workload와 승인된 IAM 영향 범위만 가역적으로 격리한다.
- [ ] `low → impossible` 설정 패치가 별도 Remediation Commit으로 배포된다.
- [ ] Argo CD가 각 예상 Commit SHA를 자동 배포한다.
- [ ] 격리 효과와 설정 패치 효과를 분리해 같은 공격 실패를 확인한다.
- [ ] 수동 Reset으로 새 촬영을 준비하고 동일 흐름을 다시 시작할 수 있다.
- [ ] 최종 촬영 확인 뒤 Terraform으로 IAM·IMDS의 근본 원인을 복구한다.
- [ ] DVWA 전용 시연 조치와 실제 환경의 대응 방법을 명확히 구분한다.

---

## 2. 범위와 제외 범위

### 2.1 핵심 범위

```text
대표 공격 1개
탐지 규칙 1개
Workload Containment 1개
제한된 IAM 영향 차단 1개
애플리케이션 설정 패치 1개
수동 재촬영 Reset 1개
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
3. 공유 Node Role을 DVWA 전용 Role·Node 경계로 분리
4. Lab Prefix 차단을 실제 Principal·Session Containment로 확장
5. Shuffle SOAR 고도화
6. n8n·AI 분석 보조
7. CNAPP 조사
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
대상에서 제외한다. 따라서 이 기능은 새 Image를 만들지 않는 **Remediation 배포**에
재사용할 수 있다.

```text
검토된 Remediation Workflow
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
       ┌─────────────────┴──────────────────┐
       │ Rule 100103 빠른 Trigger          │ 5-Source 느린 Evidence
       ▼                                    ▼
SOAR Allowlist·중복 차단              Incident 조사·확인
       │
       ├─ DVWA Workload Quarantine
       ├─ 허용된 IAM 영향 차단
       └─ Incident confidence=SUSPECTED
                         │
                         ▼
              low → impossible Remediation
                         │
                         ▼
                 GitHub Commit·Argo Sync
                         │
                         ▼
             격리/패치 분리 검증·Recovery
                         │
                         ▼
               Terraform 영구 원인 복구
```

---

## 5. 대응을 세 단계로 분리한다

세부 조건과 Reset 순서는
[`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md)를
정본으로 사용한다.

### 5.1 즉시 대응: 좁고 가역적인 Containment

Rule `100103`의 첫 유효 Alert는 다음 두 영향만 제한한다.

```text
1. 고정 Label의 DVWA Workload Quarantine NetworkPolicy
2. validation/* Lab 데이터 접근의 임시 Explicit Deny
   또는 DVWA 전용 Principal의 사전 승인된 Containment
```

현재 DVWA 권한은 공유 Primary Karpenter Node Role에 붙어 있으므로 Role 전체 Deny를
자동화하지 않는다. 공유 Role 상태에서는 `validation/*` 영향 차단까지만 자동화하고,
Credential 전체 무효화라고 표현하지 않는다. NetworkPolicy도 EKS CNI가 실제로 강제하고
Positive/Negative Test가 통과하기 전에는 `observe_only`로 유지한다.

### 5.2 취약 동작 제거: 애플리케이션 Remediation

증거를 보존하고 범위를 확인한 뒤 GitOps로 다음 보안 설정 패치를 배포한다.

```text
defaultSecurityLevel: low
→ defaultSecurityLevel: impossible
```

이는 새 Pod·새 세션에서 동일 Command Injection 실행을 막는 **DVWA 전용 보안 설정
패치**다. NetworkPolicy 격리, 유출 Credential 폐기, IAM Principal 차단과는 다른 조치다.
재공격 검증에서는 격리 때문에 실패한 것과 이 설정 패치 때문에 실패한 것을 구분한다.

### 5.3 영구 대응과 Recovery: Terraform 보안 복구

다음 항목은 임시 격리나 애플리케이션 설정 패치가 아니라 Terraform과 승인된 운영
절차의 책임이다.

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

### 5.4 실무 환경에서 필요한 대응

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

이 계획은 Workload와 Identity 영향을 먼저 제한하고, `low → impossible` 설정 패치와
영구 IAM·IMDS 복구를 뒤이어 수행하는 축소형 Incident Response다. 모든 자동화는 Lab
대상·가역성·Blast Radius 검증을 전제로 한다.

발표에서는 다음처럼 설명한다.

> Rule 100103 뒤에는 DVWA Workload와 Lab 데이터 접근 영향을 먼저 제한했습니다.
> 이후 `low → impossible`은 취약 동작을 닫는 애플리케이션 보안 설정 패치로 배포했고,
> IAM 최소 권한·IMDSv2·Node 복구는 별도 영구 대응으로 검증했습니다. 공유 Role 전체를
> 무조건 자동 차단하거나 설정 패치를 Credential 폐기로 과장하지 않았습니다.

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

CloudTrail Rule `100100`은 보호 대상 S3 접근 성공을 확인하는 **침해 확인·Evidence
경보**로 유지한다. DVWA Push Rule `100103`은 `command.execution + ec2_imds`라는
고신뢰 공격 시도를 빠르게 알리고, 좁고 가역적인 DVWA Containment를 시작하는 별도
Trigger다. 이 Trigger만으로 Credential 탈취나 S3 접근 성공까지 확인됐다고 주장하지
않는다. GuardDuty Finding과 WAF Event는 조사 Timeline을 보강하지만 자동 Containment의
단독 Trigger로 사용하지 않는다.

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

| 순서 | Source | 현재 저장 위치 | 현재 As-built 수집 방식 | 역할 | 현재 상태 |
|---:|---|---|---|---|---|
| 1 | CloudFront | Foundation Security Log S3 `AWSLogs/<ACCOUNT_ID>/CloudFront/` | 3일 병렬 CloudWatch Logs Destination → Wazuh `cloudwatchlogs` | 요청이 CDN Edge에 도착한 사실 | Raw Archive·JSON Field·Archives Index Runtime 확인 |
| 2 | WAF | `aws-waf-logs-aws-topology-edge`, `us-east-1` | Wazuh `service type="cloudwatchlogs"` | 요청 검사 결과·Action·Rule Label | Raw Archive Runtime 확인 |
| 3 | Primary ALB | Security Log S3 `alb/primary/AWSLogs/.../elasticloadbalancing/ap-northeast-2/` | Wazuh `bucket type="alb"` + `path` | 요청이 Load Balancer를 거쳐 Target에 도달한 사실 | Raw Archive·ALB Field Parsing Runtime 확인 |
| 4 | DVWA·Apache·안전 Audit | `/aws/eks/aws-topology-primary/dvwa`, `ap-northeast-2` | Wazuh `service type="cloudwatchlogs"` | 요청 도달·Pod 출력·Command Injection 실행 결과 분류 | 새 Audit Image 배포·CloudWatch·Wazuh Raw·Index Runtime 확인 |
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
| DVWA 요청·Command Injection | Apache·DVWA Log → CloudWatch Logs | 새 안전 Audit Image 배포와 `command.execution`·`ec2_imds` Wazuh Runtime 확인 |
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

> CloudFront·WAF·ALB·DVWA·CloudTrail 다섯 Source의 실제 Raw Event와 DVWA 안전 Audit를
> 수집하고, CloudTrail을 근거로 탈취 Node Role의 보호 대상 S3 접근을 Rule `100100`·
> Level 12로 탐지했다. 일반 현황과 사건 상세 Dashboard를 구현해 검색식 없이 요약
> Panel과 안전한 탐지 근거까지 이동할 수 있다.

아직 완료되지 않은 전체 관제 범위는 다음이다.

> 보존 Event 기반 안내형 실습과 다른 조원의 3분 무검색 Test로 실제 사용성을 검증하고,
> 새 대표 시나리오 한 번에서 다섯 Source를 같은 시간창으로 다시 모아 현재의 다중 실행
> Evidence와 구분한다.

2026-08-16에 5/5 Raw 수집을 닫은 첫 구현은 새 Firehose·S3→SQS·EventBridge Target을
만들지 않고 기존 Source를 Wazuh가 Read-only로 Polling했다. 이는 **현재 As-built와 보존
Evidence**로 유지한다. WAF 원본 Log Group도 Live Viewer·Grafana CloudWatch 경로가 쓰므로
S3로 바꾸지 않는다.

그러나 최초 의심 탐지 지연을 줄이기 위해 전역 Poll 주기를 `10m → 1m`으로 바꾸는 실험을
검토한 결과, 현재 CloudWatch 입력 상태 DB의 추적 Stream 48개를 매분 반복 조회하게 된다.
최소 `GetLogEvents`만 약 69,120회/일·2,073,600회/30일이고, 여기에 Log Group 조회와 S3
List가 더해진다. 실행 가능 여부와 좋은 운영 설계는 다르므로 1분 Poll은 채택하지 않았고
Host·Container 원본을 `10m`으로 복구했다.

#### 4.1.3 Target — 저지연 Push 전달

Target Architecture는 모든 Evidence Source를 실시간으로 복제하는 구조가 아니다.
**빠른 Containment Trigger·대응 경로**와 **느리고 꼼꼼한 Evidence 경로**를 분리한다. 상세 구현 이력과
전달 계약은
[`WAZUH-PUSH-TRANSPORT-DESIGN.md`](./observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)를
참고하되, 그 문서의 5-Source Push 확장 P3는 핵심 시연 이후 선택 작업으로 보낸다. 최종
시연 범위와 Source 역할은 이 계획을 우선한다.

```text
빠른 Trigger와 Containment
  DVWA 안전 Audit CWL
  → Subscription → Primary Lambda → Primary SQS → Local Bridge
  → Wazuh Rule 100103 → Shuffle
  → DVWA Workload Quarantine + 허용된 IAM 영향 차단

느리고 꼼꼼한 Evidence
  WAF·CloudFront·CloudTrail·ALB
  → 기존 CloudWatch Logs·Security Log S3 보존
  → Wazuh 10분 Poll → Timeline·침해 확인·사후 조사

Remediation·Recovery
  low → impossible 설정 패치 → Argo 정확한 SHA
  → 격리/패치 분리 검증 → IAM·IMDS 영구 복구
```

DVWA Queue는 노트북이 꺼져도 Event를 보존하고, Bridge는 Host Ledger·Live JSONL 기록
성공 뒤에만 메시지를 삭제한다. `event_id` Ledger가 정상 재전달을 건너뛰지만, JSONL Flush
직후 비정상 종료 시 한 건 중복 가능성이 있으므로 exactly-once를 주장하지 않는다.

Push의 전달 조건은 `위험 Event인가`가 아니라 승인된 DVWA Log Group인가다. 해당 Log
Group의 전체 Event를 Lambda로 전달하고, 위험 여부는 Wazuh Rule에서 판정한다. 다만
Queue·로컬에는 Credential·Cookie·Command 원문과 응답을 복제하지 않고 안전 감사 필드만
Allowlist한다. 전체 원문 비교·재분석과 나머지 네 Source는 기존 CloudWatch Logs·S3
Archive와 10분 Poll이 담당한다.

Source 역할은 다음처럼 고정한다.

- DVWA 의미 조건: Poll Rule `100101`, Push Rule `100103`. 빠른 의심 Trigger의 Stretch
  60초, 완료 기준 180초 이내
- WAF: 요청 검사·Label을 설명하는 보조 Evidence. 단독 Containment Trigger로 사용하지 않음
- CloudTrail Rule `100100`: 실제 S3 접근 성공을 확인하는 침해 확인 Evidence
- ALB·CloudFront: 경로 복원 Evidence. 최초 실시간 Trigger로 사용하지 않음

DVWA만 Poll과 Push의 이중 Alert를 피한다. Shadow Spool에서 실제 공격 전달·중복·Offline
Catch-up을 검증한 뒤 DVWA Poll 입력만 끄고, DVWA의 기존 `10m` 설정은 수동 Rollback
경로로 보존한다. WAF·CloudTrail·ALB·CloudFront Poll은 Evidence 경로로 계속 사용한다.

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

CloudTrail Rule `100100` Alert에서는 원본 `CloudTrail eventID`, Event 시간, Rule ID·Level,
Role, Bucket·Key, 성공 여부를 확인할 수 있어야 한다. DVWA Rule `100103` Alert에서는 원본
Push `event_id`, Event 시간, `command.execution`, `resource=ec2_imds`, Route와 Lab 경계를
확인할 수 있어야 한다.

Shuffle은 Source별 Event 중복 제거와 Incident 상관관계를 구분한다. DVWA Trigger는 원본
Push `event_id`, CloudTrail 확인 Event는 원본 `CloudTrail eventID`로 각각 중복을 제거한다.
재수집 때 달라질 수 있는 Wazuh Alert ID는 사용하지 않는다. 두 Source는 Scenario·관련
Entity·Resource·제한된 시간창으로 같은 Incident에 연결하며, 모든 Source를 관통하는 가짜
공통 ID가 있다고 주장하지 않는다.

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
현재 사건 확신도와 대응 단계, 다음 조치는 무엇인가
필요할 때 어떤 원본 Event로 내려갈 수 있는가
```

화면은 최소한 다음 영역을 가진다.

- **사건 요약:** 한글 사건명·발생 시각·위험도·탐지 상태
- **공격 경로:** CloudFront → WAF → ALB → DVWA → CloudTrail의 관측 상태
- **시간순 Timeline:** Source·행위·결과·상관 기준·관측 공백
- **탐지 근거:** Rule `100100`·Level·Role·Object·성공 여부
- **사건 확신도:** `UNASSESSED`·`SUSPECTED`·`CONFIRMED`·`DISPROVED`
- **대응 단계:** `DETECTED`·`CONTAINMENT_DISPATCHED`·`CONTAINED`·`INVESTIGATING`·
  `REMEDIATED`·`RECOVERY_VALIDATED`
- **다음 조치:** 승인된 Playbook 또는 조사 Runbook
- **원본 Drill-down:** 필요할 때만 Raw Event와 Alert 상세로 이동

사용성 합격 시험은 다음과 같다.

> 검색 문법을 모르는 다른 조원이 별도 설명 없이 Dashboard를 열고 3분 안에 사건 내용,
> 위험도, 영향 대상, 탐지 근거, 관측 공백, 다음 조치를 설명할 수 있어야 한다.

Account ID·Bucket·Client IP·Request ID는 내부 조사 화면에서만 필요 최소한으로 사용하고,
공개 Screenshot·영상에서는 마스킹한다. Credential·Cookie·Command 원문·응답 원문은
Dashboard에 넣지 않는다.

#### 4.5.1 보존 Event 기반 안내형 미니 실습

다른 조원의 3분 합격 시험 전에 운호가 Dashboard 읽는 법을 배우는 안내형 실습을 한 번
진행한다. 이 단계는 Dashboard 사용법 학습이며 새 공격·AWS Apply·Rule 수정은 하지 않는다.

```text
Local Wazuh 3개 Service와 Saved Object Preflight
→ AWS 보안관제 현황을 Last 7 days로 조회
→ 중요 경보와 최근 경보에서 조사 시작
→ AWS 보안 사건 상세를 Last 7 days로 조회
→ Workload·보호 데이터 접근·5-Source Evidence 확인
→ Rule 100100의 Service·API·Object Key 설명
→ 관측 공백과 자동 대응 미연결을 포함해 한 문장으로 사건 설명
```

Preflight는 `observability/wazuh/Test-WazuhMiniDrill.ps1`로 고정한다. 이 Script는 Stack을
선택적으로 시작하고, Dashboard 2개·Visualization 14개·Saved Search 2개, 안전한 Saved
Search Field·정렬, ALB 코드 정렬, 보존 Evidence 존재를 읽기 전용으로 확인한다.

현재 보존 건수는 Edge 6, WAF 8, ALB 12, Workload 2, AWS 데이터 접근 1, Rule `100100`
Alert 1건이다. 그러나 AWS 데이터 접근은 8월 13일, Edge·Workload 대표 Record는 8월
16일에 생성됐다. 따라서 이 실습은 **화면 사용법과 Evidence 해석 연습**이며, 동일한 한
요청이 다섯 Source를 모두 만들었다는 Runtime 상관 증거로 사용하지 않는다.

#### 4.6 완료 조건

Source 완전성:

- [x] CloudTrail S3 원본 Event와 Rule `100100` Alert Runtime 확인
- [x] WAF CloudWatch Logs의 실제 요청 Record를 Wazuh Raw Archive에서 확인
- [x] ALB S3 Access Log를 Wazuh `alb` 입력으로 연결하고 실제 Record·주요 Field 확인
- [x] DVWA CloudWatch Logs의 실제 Pod Record를 Wazuh Raw Archive에서 확인
- [x] 새 DVWA 안전 Audit Image를 배포하고 실행 결과 Event의 Wazuh 도착 확인
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

- [x] 검색식 없이 사건을 확인하는 한글 Saved View·Dashboard 구현
- [x] 사건 요약·공격 경로·수집 흐름·탐지 근거·사건 확신도·대응 단계·다음 조치 표시
- [x] Raw Event·Alert Drill-down 제공
- [ ] 다른 조원의 3분 무검색 사용성 Test 통과
- [ ] 새 Alert가 `amazon` Group 적용 뒤 AWS 전용 Events 화면에 표시됨

저지연 전달:

- [x] `1m` Poll 후보의 Stream 수·최소 호출량을 계산하고 영구안에서 제외
- [x] Wazuh Host·Container AWS Wodle을 `10m`으로 복구
- [x] Rule `100101`의 양성·Resource 대조군·Route 대조군 정적 Test
- [x] DVWA Push Schema·IAM·Queue/DLQ·기본 Toggle Off 정적 계약
- [x] DVWA Push OFF AWS Resource 0-change와 ON `9 add / 1 update / 0 destroy` 비파괴 Plan
- [x] 안전 Payload Allowlist Lambda Apply·Post-Apply 0-change
- [x] DVWA Push → Live JSONL → Rule `100102` 무해 Event 3회 누락·정상 실행 중복 0, 최대 6.439초
- [ ] DVWA 실제 Push Rule `100103` Alert 3회에서 완료 기준 180초 이내
- [ ] 노트북 10분 Off 뒤 Queue Catch-up과 중복 Alert 0
- [ ] 실제 공격·복구 검증 뒤 DVWA Poll 입력만 비활성화하고 수동 Rollback 확인
- [x] WAF·CloudTrail·ALB·CloudFront는 10분 Evidence 경로로 유지하고 Push 완료 조건에서 제외

운영·보존·위생:

- [x] Custom Rule Host 원본·Bind Mount·Hash 일치·문법 검사
- [x] Wazuh 재시작 뒤 설정·Rule·수집 Event·Saved Object 보존
- [ ] Archive 하루 증가량 측정 뒤 7일 Retention 적용·검증
- [ ] Credential·Webhook·기본 Password가 Repository와 Evidence에 없음

#### 4.7 Gate 4와 이후 Gate의 경계

Gate 4는 공격·탐지 로그와 사람이 읽을 수 있는 사건 화면까지 닫는다. Dashboard의
`다음 조치`가 Shuffle을 가리키는 것만으로 자동 대응이 완료된 것은 아니다.

```text
Gate 4  공격 Source 5개 Evidence + DVWA 저지연 Trigger + 사건 Timeline + 초보자용 Dashboard
Gate 5  Wazuh Alert → Shuffle 검증·중복 차단·조치 Preview
Gate 6  Workload Quarantine + 허용된 IAM 영향 차단
Gate 7  low → impossible Remediation + Argo·Recovery 검증
```

### Gate 5 — SOAR Dry Run

SOAR는 처음부터 GitHub·Kubernetes·IAM을 변경하지 않는다. 먼저 빠른 Trigger와 늦은
침해 확인을 서로 다른 Event로 처리하되 하나의 Incident로 연결하고, 실제로 실행할 고정
Target과 Rollback을 Preview하는 Dry Run을 통과한다.

```text
빠른 Trigger / Containment Preview Branch
  DVWA Rule 100103 수신
  → Push event_id·command.execution·resource=ec2_imds·Route·Lab 경계 검증
  → 같은 Push event_id 중복 실행 차단
  → Incident를 suspected로 생성
  → ‘실행했을 DVWA Quarantine NetworkPolicy’ Preview
  → 공유 Role이면 ‘validation/* 임시 Deny’ Preview
  → 전용 Principal이면 사전 승인된 IAM Containment Preview

침해 확인 Branch
  CloudTrail Rule 100100 수신
  → CloudTrail eventID·Role·Account·validation/*·성공 조건 검증
  → 같은 CloudTrail eventID 중복 확인 차단
  → 관련 Entity·Resource·시간창으로 기존 Incident를 confirmed로 갱신
  → Containment Workflow는 다시 실행하지 않음

WAF 단독 Event
  → Incident Context만 보강하고 Containment Preview를 만들지 않음
```

완료 조건:

- [ ] 허용한 DVWA Event 의미·Route·Lab Scenario만 빠른 Branch 통과
- [ ] 같은 DVWA Push `event_id` 재수신 시 Containment Preview 중복 없음
- [ ] NetworkPolicy Namespace·Selector·예외·Rollback이 고정돼 있음
- [ ] IAM 조치가 공유 Role 전체 Deny인지 Lab Prefix 영향 차단인지 명시됨
- [ ] NetworkPolicy 미강제·IAM Blast Radius 미확정이면 `observe_only`로 실패 안전하게 종료
- [ ] 허용한 CloudTrail Account·Role·Object·성공 조건만 확인 Branch 통과
- [ ] 같은 CloudTrail `eventID` 재수신 시 확인 Event 중복 없음
- [ ] 늦은 CloudTrail 확인이 기존 Containment를 다시 실행하지 않음
- [ ] WAF 단독 Event가 Containment Preview를 만들지 않음
- [ ] Credential·원본 Log를 GitHub로 전달하지 않음
- [ ] 실패·Timeout·재시도 기록

### Gate 6 — 제한된 자동 Containment

권장 구조:

```text
SOAR
→ 고정된 DVWA Workload Quarantine 요청
→ 사전 검토된 NetworkPolicy만 GitOps Commit
→ Argo CD가 정확한 Commit SHA 배포
→ 별도 고정 Branch에서 IAM 영향 차단
   - 공유 Role: validation/* 임시 Explicit Deny
   - 전용 Principal: 사전 승인된 Principal Containment
```

금지:

```text
SOAR가 임의 Namespace·Selector·Role·Policy·파일·Branch를 입력
LLM이 생성한 NetworkPolicy·IAM Policy를 무검토 적용
NetworkPolicy YAML 존재만으로 격리 성공 선언
공유 Karpenter Node Role 전체에 자동 Deny
Alert 하나만으로 Terraform Apply나 광범위한 IAM 관리자 작업 수행
```

Containment 안전 조건:

- [ ] NetworkPolicy Controller·EKS VPC CNI enforcing 상태를 Runtime으로 확인
- [ ] 대상은 `namespace=dvwa`, `app.kubernetes.io/name=dvwa`,
      `app.kubernetes.io/instance=dvwa`로 고정
- [ ] 공격 Egress가 차단되고 다른 Namespace·정상 관측 경로가 유지됨
- [ ] 적용 전후 Commit·Argo Revision·정책 UID·Test 결과를 보존
- [ ] 공유 Role IAM 조치는 `validation/*`에만 영향
- [ ] 전용 Principal이 아니면 Principal 전체 자동 Containment 금지
- [ ] 같은 TAKE 재수신 시 NetworkPolicy·IAM 조치 중복 없음
- [ ] 모든 임시 조치에 정확한 역방향 Rollback과 사람 승인 경계 존재

현재 Source의 `soc-contain-dvwa.yml`은 `low → impossible` 옛 계약이므로 이 Gate의
Containment 구현으로 사용하지 않는다. 새 계약으로 교체·검증하기 전 Production Dispatch를
연결하지 않는다.

### Gate 7 — Remediation·Argo CD·Recovery 검증

관찰 순서:

```text
Containment Evidence 보존
→ low → impossible Remediation Commit
→ Argo CD OutOfSync 또는 새 Revision 감지
→ Syncing
→ EKS Control Plane Audit에서 배포 API Event 확인
→ Deployment Rollout
→ Healthy·Synced
→ 새 Pod·새 세션 확인
→ 필요한 Test 경로만 제한적으로 복구
→ 동일 Payload와 정상 기능 재검증
→ Terraform 영구 복구 뒤 임시 격리 해제
```

완료 조건:

- [ ] Argo가 예상 Commit SHA를 배포
- [ ] EKS Control Plane `audit`에서 Argo 배포 관련 API Event를 같은 시간창으로 확인
- [ ] Pod Template의 `DEFAULT_SECURITY_LEVEL=impossible`
- [ ] 새 Pod Ready
- [ ] NetworkPolicy 격리와 무관하게 `impossible` 설정에서 동일 Payload가 실행되지 않음
- [ ] 정상 로그인·페이지 접근 Regression 통과
- [ ] IAM 임시 Deny 또는 영구 복구 상태에서 기존 Credential의 `validation/*` 접근이 실패
- [ ] Workload Containment·IAM 영향 차단·애플리케이션 Remediation을 구분
- [ ] 임시 격리 해제 시각·주체·정상 기능 결과를 Evidence에 보존
- [ ] DVWA 전용 설정 패치임을 시연 화면과 설명에서 명시

### Gate 7-R — 실패한 촬영의 수동 재준비

이 Gate는 정상 운영의 자동 복구가 아니라 같은 통제 실습을 다시 촬영하기 위한
선택적 절차다. 첫 촬영이 승인되면 실행하지 않는다.

```text
촬영 실패 판정·TAKE_ID 종료 기록
→ 수동 Reset 승인
→ 기존 Quarantine 유지
→ impossible → low Reset Commit과 Argo 배포
→ Lab Prefix IAM 임시 Deny 또는 전용 Lab 권한 복원
→ 새 Pod Ready·Synced·Healthy·low 확인
→ 공격 Process의 임시 AWS Credential 정리 Evidence + 현재 Reset Process 잔존 없음 확인
→ 이번 TAKE 뒤 Alarm의 ALARM → 실제 OK 복귀 History 확인
→ 기존 TAKE CLOSED
→ Wazuh·Bridge READY와 새 TAKE_ID·UTC 시간창 발급
→ Quarantine을 마지막에 해제
→ 다음 촬영 시작
```

CloudWatch Alarm은 AWS Native 탐지·사람 알림 Evidence이며 Shuffle Containment의
Trigger가 아니다. 계속 `ALARM`이면 다음 TAKE의 독립된 Native Alarm 전환 Evidence를
만들 수 없으므로, `SetAlarmState`로 강제 OK 처리하지 않고 실제 평가로 `OK`가 된 것을
확인한다. DVWA Rule `100103`의 빠른 Containment는 이 Alarm 상태에 의존하지 않는다.

완료 조건:

- [ ] Reset Commit만으로 새 Image Build 없이 Rollout됐다.
- [ ] 새 Pod·새 세션의 기본값이 `low`다.
- [ ] IAM 복원 대상이 `validation/*` 또는 전용 Lab Principal로 한정됐다.
- [ ] Quarantine 해제 전 Wazuh·Bridge·새 TAKE가 READY다.
- [ ] 공격 Process가 임시 AWS Credential 환경변수를 지웠고 Reset Process에도 남아 있지 않다.
- [ ] 이전 로그는 삭제하지 않고 실패한 `TAKE_ID`로 구분했다.
- [ ] 이번 TAKE 이후 Alarm History에 `ALARM → OK`가 있고 현재도 실제 `OK`다.
- [ ] 새 DVWA Push `event_id`가 독립된 두 번째 Rule `100103` Alert·대응을 만들 수 있다.
- [ ] 새 CloudTrail `eventID`가 그 TAKE의 독립된 확인 Alert가 되고 대응을 중복 실행하지 않는다.
- [ ] `TAKE_ID`는 촬영·Evidence 묶음 표식이며 보안 Event 고유 ID를 대신하지 않는다.

### Gate 8 — 영구 대응·전체 Rehearsal

- [ ] 최종 사용할 영상 구간이 열리고 재생되는지 먼저 확인
- [ ] 최종 촬영 승인 뒤에는 수동 Reset을 실행하지 않음
- [ ] Terraform 보안 설정 복구 Plan 검토
- [ ] 승인된 Apply 후 IMDS·S3 Negative Test
- [ ] 임시 IAM Deny와 Quarantine을 영구 통제 확인 뒤 해제
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
| 0 | 촬영 Slate | `TAKE_ID`·UTC 시작·DVWA low·Alarm OK·Wazuh/Bridge READY |
| 1 | 시나리오·취약 Profile | 실습 범위와 가짜 데이터 |
| 2 | DVWA 공격 | 통제된 Payload 실행 |
| 3 | IMDS·S3 결과 | Credential 원문 없이 Role·가짜 CSV 접근 성공 |
| 4 | 원본 로그 | 공격 시각·Role·S3 Event |
| 5 | SIEM Alert | Rule·Severity·정탐 근거 |
| 6 | SOAR·Containment | 검증·중복 차단·Workload Quarantine·허용된 IAM 영향 차단 |
| 7 | 느린 조사 | WAF·ALB·CloudFront·CloudTrail Timeline과 Incident 확인 |
| 8 | Remediation | `low → impossible` 설정 Patch Commit과 정확한 Diff |
| 9 | Argo CD | Revision·Syncing·Healthy·새 Pod |
| 10 | 재공격·정상 기능 | 격리와 Patch 효과를 구분한 실패·Regression |
| 11 | 결과 | Containment·Remediation·영구 대응·Recovery 구분 |

장면 0~10이 모두 유효한지 확인하기 전에는 Terraform 영구 복구 장면을 촬영하지
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
| 5 | Workload·IAM 영향 Containment·Remediation·Argo 검증 | Gate 6·7 |
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
Workload Containment와 IAM 영향 차단이 각각 막은 것은 무엇인가
`low → impossible` 설정 패치가 격리와 다른 이유는 무엇인가
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
| 대표 신호 역할 | **DVWA Rule `100103`은 빠른 Containment Trigger / CloudTrail Rule `100100`은 침해 확인** | CloudTrail Runtime 완료, DVWA 실제 공격 Runtime 대기 |
| 중앙 관제 제품 | **Wazuh 확정, 별도 ELK 미구축** | 2026-08-12 사용자 결정 |
| SIEM 위치 | **Local Docker single-node** | Wazuh 4.14.7 세 Service 기동·CloudTrail Dashboard 집계 확인 |
| Gate 4 필수 AWS→SIEM 입력 | **CloudFront + WAF + ALB + DVWA + CloudTrail** | 5/5 Raw·Custom Alert·Dashboard 구현, 안내형·3분 사용성 Test 대기 |
| AWS→SIEM 전달 방식 | **5-Source 10m Evidence + DVWA 저지연 Trigger** | DVWA Rule `100102` 3회 완료, 실제 Rule `100103`·DVWA Poll Cutover 대기; 나머지 4개 Source는 Poll 유지 |
| EKS Control Plane Log | **Gate 7 배포·대응 Evidence** | `api`·`audit`·`authenticator` 활성, Argo 배포 시간창 Runtime 대기 |
| Wazuh Runtime Credential | **로컬 전용 IAM User 장기 Key 예외** | Git 밖 Profile·Read-only Mount, 종료 후 비활성화·삭제 |
| Terraform Reader Role | Source·Apply 존재, 현재 Runtime 경로는 아님 | Wazuh Bucket 최상위 List 요구 반영 뒤 재검증 |
| SOAR 제품·입력 역할 | **Shuffle 확정, Rule `100103`은 Containment Trigger·Rule `100100`은 확인** | Wazuh 공식 Webhook 연동, Gate 5 Runtime 전 |
| Workload Containment | **DVWA 전용 Quarantine NetworkPolicy** | CNI enforcement·실제 차단·Rollback 검증 뒤 활성 |
| IAM 영향 차단 | **공유 Role은 `validation/*` 임시 Deny, 전용 Principal만 전체 Containment** | Blast Radius·Rollback 검증 뒤 활성 |
| Remediation | **`defaultSecurityLevel=low → impossible` 보안 설정 패치** | Containment와 분리된 GitOps Workflow로 재검증 |
| GitHub 호출 방식 | 고정 `workflow_dispatch`; 임의 Target Input 금지 | 각 대응 계약 확정 뒤 |
| 재촬영 Reset | **수동 전용, Quarantine을 마지막에 해제** | Gate 7-R 구현 |
| 실제 SSRF 모듈 | 핵심 E2E 이후 선택적 Upgrade | 현재 보류 |
| 공유 Role 전체 자동 격리 | **금지** | 전용 Role·Node 경계가 생기면 재검토 |
| 두 번째 시나리오 | S3 공개 설정 / SQLi | 핵심 완료 후 |

---

## 11. 지금 바로 할 한 가지

Gate 3과 Wazuh Local Docker Preflight, Reader Terraform Apply·AssumeRole·Post-Apply
0-change, CloudTrail 중앙 수집·Custom Alert, WAF·ALB·DVWA·CloudFront Raw Archive 연결,
DVWA 안전 Audit와 초보자용 Dashboard 구현을 완료했다. DVWA Push는 AWS Resource,
안전 Payload Allowlist, Local Bridge·Live JSONL, 무해 Rule `100102` 3회까지 완료했다.
다음 한 가지는 **실제 `command.execution`을 Push Rule `100103`으로 검증하는 것**이다.
TAKE `capital-one-20260813T082735Z`에서 S3 `GetObject` 원본과 Rule `100100`·Level 12
Alert를 동일한 CloudTrail `eventID`로 확인했다. CloudTrail 기반 양성 탐지와 필수
5-Source 중앙 수집, 화면 구현은 확인됐지만, 사람이 실제로 설명할 수 있다는 사용성은
내일 안내형 실습과 이후 다른 조원의 3분 Test로 별도 검증한다.

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
→ 필수 5-Source Filter·한글 Dashboard 구현·읽기 전용 Preflight 완료
→ 1m Poll 후보 폐기·10m 복구·Push Target 설계 완료
→ P0 Event Schema·IAM·Queue/DLQ·기본 Toggle Off 정적 계약 완료
→ DVWA P1 Shadow Transport 비파괴 Plan 완료
→ DVWA P1 Apply·안전 Allowlist·Live JSONL·Rule 100102 무해 Event 3회 완료
→ [다음] 실제 command.execution → Push Rule 100103 3회
→ Offline Catch-up·장애 중복 검증 뒤 DVWA Poll Cutover 결정
→ 보존 Event 기반 운호 안내형 미니 실습
→ 다른 조원의 3분 무검색 사용성 Test
→ 다음 새 Alert에서 amazon Group 화면 노출·정상 대조군 오탐 검증
→ Archive 증가량 측정 뒤 7일 Retention 검증
```

현재 확인된 범위는 `Command Injection → IMDS → Node Role Credential → 고정 가짜 S3
GetObject → CloudTrail → Metric Filter → Alarm`과 같은 TAKE의 WAF·DVWA·GuardDuty
Coverage 판정, `CloudFront·WAF·ALB·DVWA·CloudTrail → Wazuh Raw Archive`, CloudTrail
Custom Alert와 안전 Audit Runtime, 초보자용 관제 화면이다. Pod→IMDS 직접 네트워크 로그는
현재 방식으로 수집되지 않는다. 동일한 한 실행의 필수 5-Source Timeline, 안내형·3분
사용성 Test, Wazuh 정상 대조군, SOAR, GitHub 변경, Argo CD·EKS 배포 Evidence, 재공격
실패는 아직 구현하거나 검증하지 않았다.
Watchdog Hard Deadline은 각 `daily-up.ps1` Session의 실제 출력과 Session State를 기준으로
확인한다. 작업을 중단하면 과거 문서의 예약 시각을 믿고 기다리지 말고
`daily-down.ps1`로 Daily Runtime을 종료한다.
