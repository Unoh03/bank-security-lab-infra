# Capital One SOC 시연 Terraform 단계별 실행 계획

> **상태:** Draft v1.9 — 5-Source Polling As-built 완료, DVWA Push Shadow Source·검증·Plan 완료
> **기준 시점:** 2026-08-17
> **현재 단계:** Gate 4 Terraform 지원 — DVWA Push 비파괴 Plan 완료, 비용 검토·명시적 Apply 대기
> **번호 구분:** 이 문서의 `T0~T6`는 Terraform 구현 단계다. 상위 계획의 `Gate 0~8`은 시연 Evidence 단계이며 같은 번호끼리 같은 작업이 아니다.
> **상위 계획:** [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)
> **저지연 전달 정본:** [`observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`](./observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)
> **기존 관측성 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)

이 문서는 전체 SOC 시연 중 **Terraform이 책임질 부분만** 실제 파일과 실행 순서로
내린 계획서다. 이 문서가 생겼다는 것만으로 구현이나 Runtime 검증이 끝난 것은
아니다.

```text
Terraform의 책임
= 통제된 취약 실습 환경
+ 공격 흔적 수집 기반
+ CloudTrail 기반 확정 탐지 경로
+ Wazuh가 승인된 원본 로그를 읽는 최소 권한 IAM
+ CloudFront Edge 로그의 3일 CloudWatch Hot Copy
+ 최소 권한
+ 근본 원인 복구

Terraform 밖의 책임
= SIEM 탐지 규칙
+ SOAR Workflow
+ GitHub Bot Commit
+ Argo CD Sync
+ DVWA low → impossible
```

---

## 0. 초보자용 한눈에 보기

### 0.1 Terraform으로 만들 세 가지 상태

```text
1. 기본 상태: hardened
   IMDSv2 강제·Pod의 Node Metadata 접근 제한·실습용 Node S3 권한 없음

2. 통제된 실습 상태: capital-one-lab
   Primary Karpenter Node만 의도적으로 약화
   validation/* 가짜 자료에만 읽기 권한 부여

3. 사고 후 복구 상태: hardened
   실습 권한 제거·Node 설정 복구·취약 Node 교체·재공격 실패 확인
```

기본값은 항상 `hardened`다. 취약 상태는 사용자가 정확한 확인문을 입력한 한 번의
실습에서만 허용한다.

### 0.2 전체 순서

```text
현재 Runtime 확인
→ 안전한 실습 Profile 구현
→ 로그 수집 기능 확인·보강
→ 탐지 방식 결정
→ Foundation·통제된 취약 Profile Plan·Apply
→ 공격·로그·경보·자동 Containment Evidence
→ 촬영 실패 시 DVWA만 수동 Reset하고 새 TAKE 반복
→ 최종 사용할 영상 확인
→ Terraform hardened Fresh Plan
→ 사람 승인 후 Apply
→ 기존 Node 교체
→ IMDS·S3 재공격 실패 확인
```

### 0.3 가장 중요한 구분

```text
GitHub의 DVWA 보안 레벨 변경
= 새 공격을 빠르게 막는 시연용 Containment

Terraform의 IAM·IMDS 복구
= 공격의 인프라 원인을 제거하는 영구 대응
```

둘은 서로 대체하지 않는다.

### 0.4 Terraform과 재촬영 Reset의 경계

```text
수동 재촬영 Reset
= D:\DVWA의 defaultSecurityLevel impossible → low 새 Commit
= Terraform·IAM·IMDS·Node를 변경하지 않음

Terraform hardened 복구
= 최종 촬영 확인 뒤 실습 IAM·IMDS 원인을 제거
= 실행 뒤 단순 DVWA Reset만으로는 공격을 재현할 수 없음
```

따라서 같은 촬영 시간창의 재시도 중에는 `capital-one-lab` Runtime을 유지한다.
촬영이 중단되거나 자리를 비우는 경우에는 재촬영 편의보다 안전을 우선해 Daily
Runtime을 내리거나 승인된 `hardened` 복구를 수행한다.

---

## 1. 현재 Source에서 확인된 사실

### 1.1 이미 구현된 기반

| 영역 | 현재 Source | 판정 |
|---|---|---|
| CloudTrail Management Event | `foundation/observability.tf` | 구현됨 |
| 프로젝트 S3 Data Event | `enable_project_s3_data_events` | 구현됨·기본 `false` |
| S3 Data Event API | `GetObject`, `PutObject`, `DeleteObject` | 현재 Selector에만 포함 |
| GuardDuty Detector | Primary Region | 구현됨 |
| GuardDuty Finding 보존 | EventBridge → CloudWatch Logs | 구현됨 |
| GuardDuty 알림 | EventBridge → SNS | 구현됨 |
| GuardDuty S3 Protection | `S3_DATA_EVENTS` | 명시적 `DISABLED` |
| Karpenter NodeClass | Helm Chart와 SSM Template | Profile별 `metadataOptions` Source 구현·실습 Runtime 검증 |
| Karpenter Node Role 실습 권한 | `validation/*` 전용 Policy | `capital-one-lab` Runtime·허용/거부 범위 검증 |
| Capital One 확정 탐지 | CloudTrail Metric Filter → Alarm → SNS | Source 구현·기본 `false`·실습 Runtime 정탐 검증 |

### 1.2 현재 계획서와 Source의 불일치

상위 계획서가 사용했던 다음 이름은 아직 실제 Terraform 변수가 아니다.

```text
enable_iam01_imds_s3_lab
```

Git History에서도 이 변수의 Terraform 구현은 확인되지 않았다. 이 문서에서는 이를
그대로 만들지 않고, 비용 Profile과 보안 Profile을 구분하는 다음 설계를 사용한다.

```text
security_scenario_profile = "hardened"         # 기본값
security_scenario_profile = "capital-one-lab" # 명시적 실습
```

### 1.3 Source만으로 확정할 수 없는 Runtime

다음은 과거 조원 실습 당시 자료만으로는 확정할 수 없던 항목이다. 2026-08-12의 새
통제 Baseline은 별도 Runtime Evidence로 확인했으며 과거 실행의 증거를 소급해
대체하지 않는다.

```text
실제 EC2NodeClass의 metadataOptions
과거 공격 Pod가 실행된 Node 종류와 Instance ID
당시 Node Role에 붙어 있던 실제 S3 Policy
외부 PC 사용 시각의 CloudTrail Event
해당 시각의 GuardDuty Finding
Foundation의 실제 S3 Data Event 활성 상태
```

과거 공격 성공과 현재 Source가 다르면 `Source 오류`로 단정하지 않고 먼저
`Source–Runtime 불일치`로 기록한다.

---

## 2. 설계 원칙과 안전 경계

### 2.1 불변 조건

- 기본 Profile은 `hardened`다.
- 취약 Profile은 Primary Region의 통제된 실습에만 적용한다.
- DR Karpenter Node에는 실습용 IAM 권한을 부여하지 않는다.
- Node Role 권한은 프로젝트 Application Bucket의 `validation/*` 읽기로 제한한다.
- 실제 개인정보·Credential·Token·Account ID를 Source, Plan, GitHub Log에 남기지 않는다.
- `aws_iam_access_key`로 SIEM용 장기 Access Key를 만들지 않는다.
- Foundation과 Daily Runtime의 State·수명주기를 섞지 않는다.
- `terraform apply`는 Source Diff·Validate·Saved Plan·사람 승인 뒤에만 수행한다.
- 취약 Profile Apply와 hardened 복구 Apply 모두 별도 승인을 받는다.
- 재촬영 Reset Workflow는 Terraform State·Profile·IAM·NodeClass를 변경하지 않는다.
- 최종 사용할 영상 구간을 확인하기 전에는 정상 절차로 hardened 복구를 시작하지 않는다.
- 촬영을 중단하거나 통제권을 잃으면 영상 편의와 무관하게 Daily Down 또는 긴급 복구한다.

### 2.2 Terraform State 경계

```text
foundation/
→ CloudTrail·GuardDuty·CloudWatch·SNS처럼 계속 남는 수집·탐지 기반

Repository Root
→ EKS·Karpenter NodeClass·Node Role 실습 권한처럼 Daily Runtime에 속하는 자원
```

Foundation 변경은 `daily-up.ps1`가 대신 적용하지 않는다. Foundation은 별도 Plan과
Apply를 사용한다.

### 2.3 공개 Evidence 경계

공개 가능한 값:

```text
Profile 이름
Resource 종류
마스킹한 Role 이름
Event 이름
성공·실패 판정
UTC Timestamp
Plan Resource Count
```

공개하지 않을 값:

```text
Access Key·Secret·Session Token
전체 Account ID·Bucket 이름
전체 Source IP·Request ID
tfstate·tfplan·terraform.tfvars
IAM Policy의 환경 고유 전체 ARN
```

---

## 3. 목표 Source 구조

### 3.1 보안 Scenario Profile

구현된 변수 계약:

```hcl
variable "security_scenario_profile" {
  description = "Security posture for the Daily Runtime. hardened is the safe default; capital-one-lab is an explicitly approved vulnerable lab."
  type        = string
  default     = "hardened"

  validation {
    condition = contains([
      "hardened",
      "capital-one-lab",
    ], var.security_scenario_profile)
    error_message = "security_scenario_profile must be hardened or capital-one-lab."
  }
}
```

구현된 Local 계약:

```hcl
locals {
  capital_one_lab_enabled = var.security_scenario_profile == "capital-one-lab"

  primary_karpenter_metadata_options = {
    httpEndpoint            = "enabled"
    httpProtocolIPv6        = "disabled"
    httpPutResponseHopLimit = local.capital_one_lab_enabled ? 2 : 1
    httpTokens              = local.capital_one_lab_enabled ? "optional" : "required"
  }
}
```

위 코드는 구현 방향을 고정하기 위한 예시다. 실제 작성 때 현재 Terraform·Helm
표현에 맞게 다시 검토한다.

### 3.2 Karpenter NodeClass

같은 `metadataOptions`가 두 배포 경로에 모두 반영돼야 한다.

```text
기본 SSM 경로
cluster-addons-ssm.tf
→ templates/install-cluster-addons.sh.tpl
→ EC2NodeClass

선택적 Local Helm 경로
eks.tf
→ charts/karpenter-node-config/values.yaml
→ charts/karpenter-node-config/templates/nodeclass.yaml
→ EC2NodeClass
```

한쪽만 바꾸면 Source와 Runtime이 다시 어긋난다. 첫 구현에서는 두 경로를 함께
수정하고, 동일 값 렌더링 Test를 추가한다. 중복 제거 Refactor는 핵심 시연 뒤의
후속 작업으로 둔다.

목표 값:

| Profile | `httpTokens` | `httpPutResponseHopLimit` | 목적 |
|---|---|---:|---|
| `hardened` | `required` | 1 | Pod의 Node IMDS 접근 제한 |
| `capital-one-lab` | `optional` | 2 | 통제된 자격증명 탈취 실습 |

### 3.3 Node Role의 제한된 S3 실습 권한

새 파일 `security-scenario.tf`에 Primary Karpenter Node Role용 조건부 Inline Policy를
둔다.

허용 범위:

```text
s3:ListBucket
→ Primary Application Bucket
→ s3:prefix가 validation/*일 때만

s3:GetObject
→ Primary Application Bucket/validation/*
```

허용하지 않을 것:

```text
s3:PutObject
s3:DeleteObject
다른 Bucket
DR Bucket
security-log Bucket
IAM·STS 관리 API
```

가짜 CSV 내용은 Terraform Resource로 만들지 않는다. Terraform State에 실습 데이터가
들어가지 않도록 별도의 제한된 Bootstrap 절차로 준비한다.

### 3.4 Foundation의 S3 Data Event

기존 변수는 재사용한다.

```text
enable_project_s3_data_events = false # 비용 안전 기본값
enable_project_s3_data_events = true  # 승인된 실습 시간에만
```

현재 Selector는 `GetObject`, `PutObject`, `DeleteObject`를 기록하며 IAM-01과 공유한다.
T2에서는 Selector를 넓히지 않고 대표 시나리오의 성공 판정을 `GetObject` 하나로
고정했다. 목록 조회 Event는 T4 Runtime에서 실제 필요성이 확인되기 전까지 추가하지
않는다. Selector 변경 전후의 비용 범위와 실제 Event 수는 Runtime Evidence로 남긴다.

### 3.5 대표 탐지 결정

이번 시연의 확정 탐지는 GuardDuty S3 Protection이 아니다. 다음처럼 입력과 판정
조건이 분명한 CloudTrail Custom Rule을 사용한다.

```text
CloudTrail S3 Data Event
+ eventName=GetObject
+ Primary Karpenter Node Role
+ key=validation/*
+ errorCode 없음
→ CloudWatch Logs Metric Filter
→ 1분 합계 1건 이상이면 CloudWatch Alarm
→ 기존 Security Alert SNS
```

`enable_capital_one_s3_detection`은 기본 `false`이며,
`enable_project_s3_data_events=true` 없이 활성화할 수 없다. 실습 시에는 두 기능과
별도 확인문을 함께 사용한다.

```text
GuardDuty S3 Protection
→ 이번 T2에서 계속 DISABLED
→ 실제 Finding이 생기면 보조 Evidence로만 사용
→ Sample Finding은 공격 성공 Evidence로 사용하지 않음
```

### 3.6 As-built — Wazuh가 기존 원본 Source를 직접 읽는다

SIEM은 **Wazuh**, 배치는 **Local Docker single-node**로 결정했다. 별도 Elastic
Security·ELK Stack과 AWS상의 Wazuh EC2를 함께 만들지 않는다. 2026-08-16 현재 Wazuh
4.14.7 Manager·Indexer·Dashboard가 Local Docker에서 모두 기동됐고 Docker·WSL
사전 조건도 확인했다. CloudTrail·WAF·Primary ALB·DVWA·CloudFront 다섯 Source의 실제
Record를 Raw Archive에서 확인했고, CloudTrail `GetObject`는 Custom Alert까지 확인했다.

첫 구현의 입력 계약:

| Wazuh 입력 | 현재 Source | Region | Terraform 변경 |
|---|---|---|---|
| CloudTrail 원본 Event | Foundation Security Log S3 `AWSLogs/<ACCOUNT_ID>/CloudTrail/` | Multi-Region Trail, Gate 4 분석은 Primary | 기존 Source 유지·Reader 권한만 추가 |
| WAF 원본 Event | `aws-waf-logs-${local.name}-edge` | `us-east-1` | 기존 Log Group 유지·Reader 권한만 추가 |
| Primary ALB 원본 Event | Foundation Security Log S3 `alb/primary/AWSLogs/.../elasticloadbalancing/ap-northeast-2/` | `ap-northeast-2` | 기존 Source 유지·Reader Object 권한 추가 |
| DVWA·Apache 원본 Event | `/aws/eks/${local.name}-primary/dvwa` | `ap-northeast-2` | 기존 Fluent Bit·Log Group 유지·Reader 권한만 추가 |
| CloudFront 원본 Event | 기존 S3 Archive + `aws-topology-cloudfront-access-wazuh` | `us-east-1` | 같은 Delivery Source에 3일 CloudWatch Logs Destination 추가, `capital-one-lab`에서만 Delivery |

이 표는 Terraform이 보존하고 Reader 권한을 제공하는 **목표 Source 계약**이다. Terraform은
Wazuh Server·Rule·Dashboard를 관리하지 않는다. 실제 Local Wazuh 입력은 2026-08-16 현재
CloudTrail·WAF·Primary ALB·DVWA·CloudFront 5/5가 완료됐다. CloudFront는 Terraform의
Foundation·Daily Delivery와 Terraform 밖의 로컬 Reader·Wazuh 영구 설정을 함께 Runtime
검증했다. 공격 단계별 로그와
현재 Wazuh 가시성은 상위 [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md)에서
추적한다.

첫 Daily Preview는 기존 Preflight가 모든 Log Group을 서울·30일로 가정해
`us-east-1`·3일 CloudFront Log Group을 찾지 못하고 안전하게 중단됐다. Foundation Output에
CloudFront 보존일을 추가하고 `daily-common.ps1`이 Source별 Region·Retention을 검증하도록
수정한 뒤 PowerShell Parser, Terraform Validate, Wazuh Foundation Contract Test와 Runtime
Profile Test를 통과했다.

2026-08-16에 5/5 Runtime을 닫은 초기 경로는 S3→SQS, Firehose, EventBridge API
Destination을 추가하지 않았다. Wazuh의 공식 `bucket type="cloudtrail"`·`bucket
type="alb"`와 `service type="cloudwatchlogs"` Polling을 사용했고, CloudFront만 기존 S3
Evidence와 병렬인 3일 CloudWatch Logs Destination을 추가했다. CloudWatch Alarm은 기존
SNS 사람 알림에 남겼다. 이 내용은 **당시 As-built와 Runtime Evidence**로 계속 유효하다.

다만 이는 빠른 최초 탐지의 Target Architecture는 아니다. 2026-08-17 Wazuh 입력 상태를
다시 대조한 결과 CloudWatch Log Stream 48개를 추적하고 있었다. 전역 `1m` Poll은 최소
`GetLogEvents` 약 69,120회/일·2,073,600회/30일에 Log Group 조회와 S3 List를 더하므로
채택하지 않았고, AWS Wodle 원본과 Runtime을 `10m`으로 복구했다.

구현한 Terraform Resource는 다음으로 제한한다.

```text
foundation/variables.tf
→ enable_wazuh_log_reader = false 기본값
→ wazuh_reader_trusted_principal_arn = null 기본값
→ cloudfront_wazuh_log_retention_days = 3 기본값

foundation/observability.tf
→ us-east-1 CloudFront Wazuh Log Group + JSON Delivery Destination

foundation/wazuh.tf
→ 명시된 Bootstrap Principal만 Assume 가능한 aws_iam_role.wazuh_log_reader
→ Bucket Key List + CloudTrail·Primary ALB Object Read + CloudFront·WAF·Primary DVWA Log Group Read-only Policy
→ Toggle이 true인데 같은 계정의 Principal ARN이 없으면 실패하는 Resource Precondition

foundation/outputs.tf
→ Reader Role ARN
→ 비민감 Source 이름·Region·Prefix 계약

observability.tf
→ 기존 CloudFront Delivery Source를 재사용하는 Lab 전용 두 번째 Delivery
```

2026-08-12 초기 Reader Source 검증 결과:

```text
정적 계약 Test + terraform validate: 통과
기본 비활성 Plan: AWS Resource 0건
활성 Plan: Reader Role + Inline Policy 2 Add, 0 Change, 0 Destroy
Principal 누락 Plan: Resource Precondition 실패
승인 Saved Plan Apply: 2 Add, 0 Change, 0 Destroy
AWS 실제 Policy Action: s3:ListBucket, s3:GetObject, logs:DescribeLogStreams, logs:GetLogEvents
15분 AssumeRole: 성공, Credential 원문 미출력·미저장
Post-Apply Fresh Plan: 0 change
```

2026-08-16 CloudFront·ALB Reader 확장 검증 결과:

```text
terraform fmt·Foundation/Root validate·정적 계약 Test: 통과
Foundation Plan: CloudFront Log Group·Destination Create 2
Reader Inline Policy: Update 1
Delete·Replace: 0
Daily CloudFront Delivery: Foundation Apply 뒤 capital-one-lab Plan에서 검증 예정
```

Terraform Reader Role의 현재 최소 권한 경계:

- Wazuh 4.14.7의 실제 Root Listing 사전 동작 때문에 Security Log Bucket의 Key 목록
  `s3:ListBucket`은 Bucket 범위로 허용한다. Object 내용 읽기 권한은 아니다.
- `s3:GetObject`는 CloudTrail과 Primary ALB 두 Prefix로 제한한다.
- CloudWatch Logs는 CloudFront Wazuh, WAF, Primary DVWA 세 Log Group의 `logs:DescribeLogStreams`,
  `logs:GetLogEvents`만 허용한다.
- `s3:DeleteObject`, `logs:DeleteLogStream`, Put·Write, 광범위 `s3:*`, `logs:*`는 금지한다.
- `aws_iam_user`, `aws_iam_access_key`와 Credential 값은 Terraform State에 만들지 않는다.

2026-08-13 Runtime에서 설치된 Wazuh 4.14.7이 CloudTrail Prefix 조회 전에 Bucket
최상위 `ListObjectsV2(Prefix="")`를 수행한다는 사실을 확인했다. 2026-08-16 Source에서
Bucket Key 목록 조회를 허용하고 Object 내용은 CloudTrail·Primary ALB Prefix로 제한하도록
보정했다. Source·비파괴 Foundation Plan은 확인했지만 Terraform Reader Role을 이용한
새 Runtime 수집은 아직 재검증하지 않았다.

Host의 광범위 AWS Profile을 Wazuh Container에 그대로 Mount하지 않는다. 설계 기본안은
Host가 Wazuh Reader Role의 임시 STS Session을 발급하는 방식이었지만, 실제 최초
Runtime은 반복적인 Session 갱신 없이 로컬 실습을 진행하기 위해 Terraform 밖에서 만든
전용 IAM User의 장기 Key를 Git 밖 Profile에 저장하고 Read-only로 Mount했다. 해당
Policy는 Bucket 전체 `ListBucket`, CloudTrail·Primary ALB Prefix `GetObject`, 승인
WAF·DVWA Log Group Read만 허용한다. CloudFront Log Group은 Foundation Apply 뒤 추가한다.
이 경로는 로컬 프로젝트용 예외이며 종료 후 Key를
비활성화·삭제한다. Wazuh Stack·Named Volume, `ossec.conf`, Archives, Custom Rule,
Shuffle Webhook은 계속 Terraform 밖의 Gate 4·5 작업이다.

`ossec.conf`의 첫 AWS 수집 전에 `only_logs_after=2026-AUG-12`, 승인 Account ID와
Source별 Region을 고정한다. 이 값은 Terraform Resource가 아니라 Wazuh 수집 경계지만,
기존 Baseline 누락·프로젝트 밖 과거 로그 과수집·무계획 `reparse`로 인한 중복 Alert를
막는 Gate 4 필수 검증값이다.

AWS에 SIEM 서버를 배포하면 EC2·EBS·Network·Backup까지 범위가 커지므로 핵심 시연의
기본안으로 채택하지 않는다.

### 3.7 Target — 리전별 Event-driven Push + Local Queue Bridge

원본 Archive와 AWS Native Alarm을 유지하면서, AWS Log 도착 뒤 Wazuh Poll 대기만 없애는
구조로 전환한다. 상세 Schema·IAM·중복·장애·비용 계약은
[`WAZUH-PUSH-TRANSPORT-DESIGN.md`](./observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md)를
정본으로 사용한다.

```text
us-east-1
  WAF·CloudFront CWL → Subscription → Edge Lambda → Edge SQS → DLQ

ap-northeast-2
  DVWA·CloudTrail CWL → Subscription → Primary Lambda → Primary SQS → DLQ
  ALB S3 ObjectCreated ────────────────────────────────→ Primary SQS

Local Docker Host
  Queue별 Long Poll → Event Ledger + 안정 Live JSONL → Wazuh localfile(JSON)
```

Terraform은 Foundation에서 다음 지속 Resource만 책임진다.

- 기본 `false`인 `enable_wazuh_push_transport`
- 서울·버지니아 Standard SQS와 각 DLQ·Queue Policy
- 서울·버지니아 Forwarder Lambda·실행 Role·Log Group
- 승인된 네 CloudWatch Log Group의 Subscription Filter와 Lambda Permission
- Security Log S3의 `alb/primary/` ObjectCreated Notification
- Local Consumer의 Queue Read/Delete와 ALB Prefix Object Read Role
- Queue Backlog·DLQ·Lambda Error Alarm과 비민감 Output

CloudWatch Logs Subscription은 Log Group과 같은 Region의 Forwarder를 사용한다. S3 Event
Notification의 Queue도 Bucket과 같은 서울 Region에 둔다. Local Bridge는 Queue마다 별도
20초 Long Poll Worker를 두며, Host Spool 쓰기 성공 뒤에만 메시지를 삭제한다.

Subscription Filter는 `command.execution`·`GetObject` 같은 탐지 조건으로 Event를
잘라내지 않는다. 승인된 Log Group의 전체 Event를 Lambda로 보내되, Queue Payload는
안전한 감사 필드 Allowlist만 보존하고 원문은 SHA-256으로만 식별한다. 위험 판정은 Wazuh
Rule이 담당한다. Terraform의 Filter 경계는 Source ARN·Region·ALB Prefix이고, 탐지
경계는 Wazuh `100100`·`100101`·`100103` 및 이후 Custom Rule이다.

Push와 Poll을 같은 Source에 동시에 Live 입력하지 않는다. DVWA Shadow Spool로 먼저
누락·중복·Offline Catch-up을 검증하고, Source별 Cutover 때 해당 Poll 입력만 끈다. 기존
`10m` 설정은 수동 Rollback 계약으로 보존한다.

이 전환은 `Foundation Source를 한 번에 전부 Apply`하는 작업이 아니다. DVWA만 P1에서
측정한 뒤 WAF → CloudTrail → ALB → CloudFront 순서로 확장한다. 각 단계는 기본 Toggle
Off 0-change, 비파괴 Saved Plan, 명시적 Apply 승인, Runtime 3회 Evidence를 별도로 가진다.

2026-08-17 DVWA 1-Source 구현·검증 결과:

- 기본 `enable_wazuh_push_transport = false`에서 AWS Resource 변경 `0`
- 활성 Plan은 `9 add / 1 in-place update / 0 destroy`
- 생성 범위는 서울 SQS·DLQ·Queue Policy, Lambda·Role·Policy·Log Group,
  DVWA Subscription·Lambda Permission뿐이다.
- 기존 Wazuh Reader Policy 갱신은 Primary Queue의 Receive/Delete 권한만 추가한다.
- Forwarder 단위 Test 4개, Push 정적 계약, 기존 Wazuh Foundation 계약,
  `terraform fmt -check`, `terraform validate`, `git diff --check`를 통과했다.
- 초기 Resource Apply 뒤 Payload Allowlist Lambda만 `0 add / 1 update / 0 destroy`로
  갱신했고, 같은 활성 입력의 Post-Apply Plan은 `No changes`였다.
- Local Bridge·Wazuh Live JSONL·Rule `100102`를 연결하고 무해 Event 3회 모두 Alert를
  확인했다. 총 지연은 6.439초·3.427초·3.761초이며 각 Take ID는 JSONL·Alert에서 1건이다.
- 실제 `command.execution → Rule 100103`, Offline Catch-up·장애 중복, 기존 DVWA Poll
  Cutover와 나머지 4개 Source는 아직 수행하지 않았다.

---

## 4. 파일별 변경 장부

| 파일 | 계획된 변경 | 적용 시점 |
|---|---|---|
| `variables.tf` | `security_scenario_profile` 추가 | T1 |
| `security-scenario.tf` | Profile Local·Primary Node Role 제한 Policy·Check | T1 |
| `eks.tf` | Local Helm 경로에 `metadataOptions` 전달 | T1 |
| `cluster-addons-ssm.tf` | SSM Template에 동일 Metadata 값 전달 | T1 |
| `templates/install-cluster-addons.sh.tpl` | 기본 경로 EC2NodeClass에 `metadataOptions` 렌더링 | T1 |
| `charts/karpenter-node-config/values.yaml` | Metadata 기본값 추가 | T1 |
| `charts/karpenter-node-config/templates/nodeclass.yaml` | Metadata 렌더링 | T1 |
| `outputs.tf` | Profile·기대 Metadata·실습 Policy 상태 Output | T1 |
| `daily-up.ps1` | Profile 인자·확인문·기존 Runtime 일치 Guard | T1 |
| `daily-common.ps1` 또는 Automation 설정 | Session에 보안 Profile 기록 | T1 |
| `tests/test-karpenter-security-profiles.ps1` | 기본값·IAM 범위·확인문·SSM/Helm 연결 Test | T1 |
| `tests/test-daily-session-watchdog.ps1` | Session Profile 기록·활성 Profile 변경 차단 Test | T1 |
| `foundation/variables.tf` | 기본 `false`인 Capital One Detector Toggle 추가 | T2 |
| `foundation/detection.tf` | 성공 `GetObject` Metric Filter·1분 Alarm·기존 SNS 연결 | T2 |
| `foundation/observability.tf` | 기존 Project S3 Selector 재사용·Source 변경 없음 | T2 |
| `foundation/outputs.tf` | Detector 상태·이름·Role·Prefix 계약 Output | T2 |
| `setup-foundation.ps1` | S3 Data Event·Detector Switch와 별도 확인문; Wazuh Reader 활성값·명시적 신뢰 Principal 전달 | T2·Gate 4 Terraform 지원 |
| `automation/project.psd1` | `CAPITAL-ONE` 필수 Evidence Query 등록 | T2 |
| `observability/queries/cloudwatch/13_capital_one_validation_getobject.cwli` | 성공·거부 Event 조사 필드 | T2 |
| `observability/queries/README.md` | Query와 Runtime 미검증 경계 | T2 |
| `observability/scenarios/README.md` | IAM-01과 구분한 탐지 계약 | T2 |
| `DAILY-CICD-RUNBOOK.md` | 취약 실습·Foundation 수집·복구 절차 | T1·T2 |
| `tests/test-observability-detection.ps1` | Detector·Wrapper·Query 정적 계약 Test | T2 |
| `foundation/variables.tf` | Wazuh Reader Toggle·명시적 Bootstrap Principal·CloudFront Hot Copy 3일 Retention 입력 | Gate 4 Terraform 지원 |
| `foundation/observability.tf` | `us-east-1` CloudFront Wazuh Log Group·JSON Delivery Destination | Gate 4 Terraform 지원 |
| `foundation/wazuh.tf` | CloudTrail·Primary ALB S3 Object와 CloudFront·WAF·Primary DVWA Log Group 전용 Read-only Role·Policy | Gate 4 Terraform 지원 |
| `foundation/outputs.tf` | Wazuh Reader Role ARN·CloudFront Destination ARN·비민감 5-Source 계약 Output | Gate 4 Terraform 지원 |
| `observability.tf` | 기존 CloudFront Delivery Source를 재사용하는 `capital-one-lab` 전용 두 번째 Delivery | Gate 4 Terraform 지원 |
| `outputs.tf` | 선택한 Profile의 CloudFront Wazuh Delivery 활성 여부 Output | Gate 4 Terraform 지원 |
| `tests/test-wazuh-foundation-contract.ps1` | 기본 비활성·No Access Key·No Delete·5-Source·Lab 전용 Delivery 정적 Test | Gate 4 Terraform 지원 |
| `foundation/main.tf`·`.terraform.lock.hcl` | Lambda Package를 위한 `hashicorp/archive` Provider 고정 | Push P0 |
| `foundation/variables.tf` | 기본 `false`인 DVWA Push Toggle | Push P0 |
| `foundation/wazuh-push.tf` | 현재 Primary DVWA용 서울 Queue·DLQ·Policy, Forwarder Lambda·Subscription. 나머지 Source·Alarm은 후속 | Push P0~P3 |
| `foundation/lambda/wazuh_push_forwarder.py` | CWL gzip/base64 해제·안전 필드 Allowlist 정규화·원문 SHA-256·과대 Event 격리 | Push P1~P3 |
| `foundation/outputs.tf` | Queue URL·ARN, Source별 Push 상태의 비민감 계약 | Push P0~P3 |
| `foundation/wazuh.tf` | Push 활성 시 기존 Reader Role에 Primary Queue Receive/Delete 최소 권한 추가 | Push P1 |
| `setup-foundation.ps1` | Push 활성화와 Apply에 별도 정확한 확인문 요구 | Push P1 |
| `tools/Start-WazuhPushShadowBridge.ps1` | 임시 STS·Queue Long Poll·단일 Writer·Event ID Ledger·안정 Live JSONL·내구 기록 성공 뒤 Delete | Push P1~P2 |
| `tests/test-wazuh-push-contract.ps1` | Default Off·리전·IAM·재귀 방지·DLQ·No Public Inbound 계약 | Push P0 |
| `tests/test_wazuh_push_forwarder.py` | 전체 Event 운반, 안전 Payload Allowlist, Source Guard, 안정 Event ID, Control Message 무시 | Push P1 |

자동 Containment와 수동 Reset Workflow는 `D:\DVWA` 저장소의 책임이다. 이 문서에서
그 상태 전환 순서는 고정하지만 Terraform Resource로 구현하거나 Terraform Apply로
대신하지 않는다. Wazuh Stack·Rule·Dashboard·Shuffle 연동도 Terraform Resource가
아니며, Terraform은 기존 AWS Source의 최소 Read 권한까지만 책임진다.

---

## 5. 단계별 실행 Gate

### T0 — Source·Runtime 대조

목적: 과거 공격 성공 환경과 현재 Source가 왜 다른지 확정한다.

Read-only 확인:

```text
Terraform Root Output과 State 주소
Foundation Output
Kubernetes EC2NodeClass YAML
공격 Pod가 배치된 Node와 EC2 Instance MetadataOptions
Primary Karpenter Node Role의 Inline·Attached Policy 목록
CloudTrail Event Selector
GuardDuty Detector Feature 상태
```

완료 Evidence:

| 항목 | Source | Runtime | 판정 |
|---|---|---|---|
| NodeClass `httpTokens` |  |  | 일치/불일치/미확인 |
| NodeClass Hop Limit |  |  | 일치/불일치/미확인 |
| Node Role `validation/*` |  |  | 일치/불일치/미확인 |
| S3 Data Event | `false` 기본 |  | Observed/Disabled/Unknown |
| GuardDuty S3 Protection | Disabled Source |  | Enabled/Disabled/Unknown |

Gate:

- [ ] Credential 원문 없이 Runtime 설정을 수집했다.
- [ ] 과거 공격 Node 종류를 확인했다.
- [ ] Source–Runtime 차이를 설명할 수 있다.
- [ ] 실제 Event Timestamp 범위를 확보했다.

2026-08-12 결정: 삭제된 과거 Runtime과 Timestamp를 복원하는 작업은 T1의 선행
조건에서 제외했다. 현재 Daily State가 비어 있고 Foundation의 현재 상태를 확인한
것으로 안전 사전 확인을 종료한다. 과거 실습 자료는 구조 참고용이며 탐지 성공
Evidence로 재사용하지 않는다. Node·Event·Finding은 T4 통제 재실행에서 새로
수집한다.

### T1 — 안전한 Profile Source 구현

목적: 수동 수정 없이 같은 Source에서 취약 상태와 복구 상태를 재현한다.

구현 순서:

```text
변수·Validation
→ Metadata Local
→ SSM·Helm 두 렌더링 경로
→ 조건부 Node Role Policy
→ Output
→ daily-up Guard
→ 정적 Test
```

`daily-up.ps1` 안전 조건:

```text
기본값은 hardened
capital-one-lab은 정확한 별도 확인문 필수
활성 Daily Runtime의 보안 Profile을 몰래 변경하지 않음
다른 Profile이면 먼저 Daily Down 또는 전용 승인 절차 요구
Session Record에 적용 Profile 저장
```

Gate:

- [ ] 기본 Plan은 취약 IAM Policy를 만들지 않는다.
- [ ] 잘못된 Profile 이름은 Validate에서 실패한다.
- [ ] 확인문 없는 취약 Profile 실행은 Apply 전에 중단한다.
- [ ] SSM·Helm 렌더링 결과가 동일하다.
- [ ] DR에는 실습 Policy·약한 Metadata가 적용되지 않는다.

2026-08-12 T1 Source 결과:

- [x] `security_scenario_profile`의 기본값을 `hardened`로 추가했다.
- [x] Primary SSM·Local Helm 경로에 같은 선택 Metadata를 전달했다.
- [x] DR SSM·Local Helm 경로를 항상 hardened로 고정했다.
- [x] `capital-one-lab`에서만 Primary Node Role에 `validation/*` 읽기 Policy가 생긴다.
- [x] `daily-up.ps1`에 별도 확인문과 활성 Profile 변경 차단을 추가했다.
- [x] Session 상태에 Security Scenario를 기록한다.
- [x] Terraform Validate와 관련 PowerShell 회귀 테스트를 통과했다.
- [ ] Helm CLI가 없어 실제 `helm template` 렌더링은 아직 수행하지 않았다.
- [x] Daily `capital-one-lab` Saved Plan의 주소와 Action을 검토했다.
- [ ] AWS Apply와 Runtime 검증은 수행하지 않았다.

### T2 — Foundation 수집·탐지 선택

목적: 실제 공격을 설명할 최소 로그와 경보만 활성화한다.

구현 순서:

```text
기존 Project S3 Selector 범위 확인
→ 성공 GetObject를 확정 탐지 Event로 선택
→ Opt-in Metric Filter·Alarm·SNS 연결
→ 성공·AccessDenied Evidence Query
→ Foundation Wrapper의 비용·확인 Guard
→ 정적 Test와 AWS Filter 문법 Test
```

Gate:

- [x] CloudTrail Selector가 프로젝트 Bucket Prefix와 세 Object API로 제한됐다.
- [x] 확정 탐지 조건은 성공 `GetObject`·Primary Node Role·`validation/*`로 제한됐다.
- [x] 비용 경고와 실습 종료 후 Selector·Detector 비활성 절차를 기록했다.
- [x] GuardDuty S3 Protection은 계속 `DISABLED`이며 확정 탐지로 사용하지 않는다.
- [x] Sample Finding과 실제 공격 Finding을 구분한다.
- [x] Foundation Plan에 영구 Log Bucket·Trail·Detector 삭제가 없다.

2026-08-12 T2 Source 결과:

- [x] Detector와 S3 Data Event는 각각 기본 `false`다.
- [x] Detector만 켜고 S3 Data Event를 끄면 Terraform Precondition과 Wrapper가 중단한다.
- [x] 성공 Event만 Alarm Metric으로 만들고, Query는 성공과 `AccessDenied`를 함께 보존한다.
- [x] AWS `test-metric-filter`에서 가짜 성공 Event 1건은 Match, `AccessDenied`는 0건이었다.
- [x] Root·Foundation Terraform Validate와 PowerShell 회귀 Test 13개를 통과했다.
- [x] Foundation Saved Plan을 생성해 주소와 Action을 검토했다.
- [ ] AWS Apply는 수행하지 않았다.
- [ ] 실제 CloudTrail Event·Alarm·SNS·Evidence Query Runtime은 T4에서 검증한다.

### T3 — Plan-only 검토

목적: 각 AWS 변경 직전에 실제 State를 기준으로 Diff를 검토한다.

필수 Saved Plan과 생성 시점:

```text
실습 시작 전
1. Foundation 관측 Plan
2. Daily capital-one-lab Plan

실습 Runtime 생성 뒤·복구 Apply 전
3. Daily hardened 복구 Plan
```

아직 취약 Runtime이 없는 현재 State에서 만든 `hardened` Plan은 실제 복구 Diff가
아니다. 복구 Plan은 `capital-one-lab`이 실제 적용된 뒤 Fresh Plan으로 만든다.

허용되는 `capital-one-lab` Plan:

```text
기존 Daily Runtime이 있을 때
→ Primary Node Role 제한 Inline Policy 생성
→ Primary EC2NodeClass Metadata 변경을 위한 SSM Document 갱신
→ 관련 Output 갱신

Daily State가 비어 있을 때
→ minimal Daily Runtime 전체 생성
→ 그 안에 위 실습 전용 Policy·Primary Metadata 계약 포함
```

현재 Root State는 리소스 0개이므로 두 번째 경우다. 따라서 이번 Daily Plan의 123개
생성은 기존 Runtime에 123개를 추가하는 변경이 아니라 **Daily Runtime을 처음 만드는
Bootstrap**이다. 실습 전용 범위는 전체 생성 목록 안에서 별도로 검토한다.

허용되지 않는 Plan:

```text
Foundation S3 Bucket·CloudTrail·GuardDuty Detector 삭제·교체
ECR·OIDC Provider 삭제
DR Node Role 권한 추가
Application Bucket 전체 읽기
IAM·Network의 무관한 변경
Secret 또는 실습 Credential 출력
```

Gate:

- [x] 사전 Runtime Foundation·Daily Saved Plan의 모든 Resource Action을 전수 검사했다.
- [x] 사용자가 Saved Plan 요약을 확인하고 Apply를 승인했다.
- [ ] 취약 Runtime 생성 뒤 Fresh `hardened` 복구 Plan을 만들고 검토한다.
- [ ] 취약화와 복구가 서로 반대 방향의 최소 Diff다.
- [x] Saved Plan은 `.gitignore`의 `.plans/` 규칙으로 Git에서 제외됐다.
- [x] Apply 전 사용자 승인을 받았다.

2026-08-12 T3 사전 Runtime Plan 결과:

- 검증 위치는 개인 사전 검증 계정이며, 팀 계정 배포 증거가 아니다.
- Foundation State는 48개, Daily Root State는 0개였고 둘 다 `default` Workspace였다.
- 첫 Foundation 후보는 직접 실행 시 `domain_name`을 누락해 ACM 관련 삭제 3건이
  포함됐다. 적용 후보에서 제외하고
  `REJECTED-capital-one-t3-foundation-missing-domain.tfplan`로 격리했다.
- `setup-foundation.ps1`과 같은 입력으로 다시 만든 Foundation Plan은
  `aws_cloudwatch_log_metric_filter.capital_one_validation_getobject[0]`와
  `aws_cloudwatch_metric_alarm.capital_one_validation_getobject[0]` 생성 2건뿐이다.
  삭제·교체·업데이트는 없다. S3 Data Event Selector는 Refresh된 State와 같아
  Plan Action이 없었다.
- ACM Certificate의 `renewal_eligibility` Drift 1건은 관측됐지만 Terraform이 수행할
  Action은 없었다.
- Daily `minimal + capital-one-lab` Plan은 관리 리소스 생성 123건과 Data Source 조회
  8건이다. 업데이트·삭제·교체와 Foundation 소유 리소스 변경은 없다.
- Daily Plan Output은 `runtime_profile=minimal`,
  `security_scenario_profile=capital-one-lab`이며 Primary 실습 Policy 생성은 1건,
  DR 실습 Policy는 0건이다.
- 생성 전 SSM Document 본문과 Inline Policy JSON은 Plan에서 `unknown`이다. 대신 같은
  Terraform local은 Primary `httpTokens=optional`·Hop Limit `2`, hardened 기준은
  `required`·`1`로 평가됐고, Policy Source는 Primary Bucket의 `validation/*`에 대한
  `ListBucket`·`GetObject`만 허용한다. 실제 렌더링과 Node 설정은 T4 Runtime Gate다.
- 세 Plan 파일은 모두 `.plans/` 아래에 있어 Git Status에 나타나지 않는다. 이 중
  `REJECTED-*` 파일은 진단 증거일 뿐 절대 Apply하지 않는다.
- 이 단계에서는 AWS Apply를 수행하지 않았다.

### T4 — 통제된 취약 Runtime·반복 촬영 검증

목적: 의도한 취약점만 열리고 Evidence가 수집되는지 확인한다.

순서:

```text
Foundation 수집 설정 Apply
→ capital-one-lab Apply
→ 기존 Node가 아니라 새 Karpenter Node 설정 확인
→ 촬영 Preflight
→ 통제된 공격·자동 Containment·재공격 실패
→ 촬영 결과 판정
→ 실패하면 DVWA만 수동 Reset하고 새 TAKE 반복
→ 성공하면 Reset하지 않고 T5 영구 복구로 이동
```

촬영별 Preflight:

```text
capital-one-lab Runtime 일치
+ DVWA defaultSecurityLevel=low
+ Argo CD Synced·Healthy·새 Pod Ready
+ Capital One Alarm=OK
+ 공격자 PC의 이전 AWS Credential 환경변수 없음
+ 새 TAKE_ID·ExperimentId·UTC 시작 시각
```

실패한 촬영의 Reset 범위:

```text
허용: D:\DVWA values.yaml의 impossible → low Commit과 Argo Rollout
금지: Terraform 재Apply·State 조작·IAM 확대·Alarm 강제 OK·CloudTrail Log 삭제
```

CloudWatch Alarm Action은 상태 전환 때 실행되므로 다음 촬영은 실제 `OK` 복귀 뒤
시작한다. 실패한 TAKE의 로그를 지우지 않고 새 ID와 시간창으로 분리한다. SOAR의
중복 방지도 Alarm 이름 하나가 아니라 AWS Event·Alarm 상태 전환·Incident 식별자를
사용한다. `TAKE_ID`는 촬영과 Evidence를 묶는 표식이며 보안 Event 고유 ID를
대신하지 않는다.

Gate:

- [x] 새 Node의 실제 MetadataOptions가 실습 목표와 일치한다.
- [x] Node Role은 `validation/*`만 읽을 수 있다.
- [x] 같은 Bucket의 다른 Prefix와 다른 Bucket은 IAM 평가에서 `implicitDeny`다.
- [x] Credential 원문 없이 공격 성공을 증명한다.
- [x] 공격 종료 UTC 시각을 기록한다.
- [ ] Containment Commit·Argo Revision·새 Pod·동일 Payload 실패를 같은 TAKE로 연결한다.
- [ ] 수동 Reset 후 새 Pod·새 세션·Alarm OK로 두 번째 TAKE를 준비할 수 있다.
- [ ] Reset이 IAM·IMDS·기존 탈취 Credential을 복구하지 않음을 설명한다.

2026-08-12 T4 공격 전 Runtime 결과:

- 사용자 승인 뒤 Fresh Foundation Plan을 다시 만들었고 탐지 Metric Filter·Alarm 생성
  2건만 확인한 후 Apply했다. Foundation State는 48개에서 50개로 증가했다.
- Data Event 수집은 활성 상태이고 Metric Filter 1개·SNS Action이 연결된 Alarm 1개가
  실제 존재한다. 공격 전 Alarm은 `OK`다.
- Fresh Daily Plan은 관리 리소스 생성 123건·Data Source 조회 8건이며 업데이트·삭제·
  교체는 없었다. Apply 결과도 `123 added, 0 changed, 0 destroyed`다.
- SSM Add-on 설치, 기존 ECR Image 확인, DB·Kubernetes Secret Bootstrap, Argo CD
  `Synced / Healthy`, DVWA Pod `Running / Ready`를 확인했다.
- DVWA Pod는 서울의 `default` Karpenter Node에 배치됐다. 실제 EC2와
  `EC2NodeClass/default` 모두 `httpTokens=optional`, Hop Limit `2`다.
- Managed System Node는 `httpTokens=required`, Hop Limit `1`이며 실습 취약화 대상이
  아니다. Karpenter Instance Profile은 Primary Karpenter Node Role과 연결된다.
- Runtime Inline Policy는 `validation/*`의 `ListBucket`·`GetObject`만 허용한다. IAM
  Policy Simulator에서 `validation/*` 읽기는 `allowed`, 같은 Bucket의 다른 Prefix와
  다른 Bucket 읽기는 `implicitDeny`였다. 실제 S3 요청 결과는 공격 단계에서 별도로
  검증한다.
- 비용 영향이 큰 Daily Runtime은 서울에만 존재한다. 서울에는 EKS 1·RDS 1·NAT 1·
  ALB 1과 Bastion·Managed System Node·Karpenter Node EC2 3대가 있고, 도쿄에는 해당
  리소스와 Valkey·EFS가 0개다. CloudFront·WAF 등 Global/Foundation 비용은 별도다.
- Active Daily Session과 Watchdog Scheduled Task가 등록됐다. 현재 세션만
  Soft Deadline 21:00·Hard Deadline 22:00 KST·Retry Until 자정으로 연장했다.
  Scheduled Task의 다음 실행도 22:00이며 Source 기본 6시간 제한은 변경하지 않았다.
- Foundation과 Daily 모두 같은 입력의 Post-Apply Fresh Plan이 `0 change`였다.
- `Prepare-CapitalOneDemoData.ps1`로 `FAKE_TRAINING_DATA` 5행의 고정
  `validation/capital-one-demo.csv`를 준비하고 SHA-256을 Metadata와 대조했다.
- `Invoke-CapitalOneBaseline.ps1`은 임의 URL·Bucket·Object·Command를 받지 않고,
  Active Session·`minimal + capital-one-lab`·IMDS `optional/2`·제한 Node Role·
  Data Event·Alarm `OK`를 확인한 뒤에만 실행됐다.
- Baseline `capital-one-20260812T025054Z`에서 IMDS Role 발견, 임시 Credential 획득,
  외부 STS Role 일치, 고정 가짜 S3 5행 읽기와 SHA-256 일치를 확인했다. Credential
  값은 출력·파일 저장하지 않았고 Process 환경변수는 `finally`에서 복구했다.
- 같은 실행 뒤 Capital One Alarm이 새 `ALARM`으로 전환됐다. CloudTrail Query 1행은
  `GetObject`, 예상 Node Role, 고정 Object Key, 성공 상태와 실행 UTC 시간창이 모두
  일치했다.
- Windows PowerShell 5.1이 inline CWLI의 따옴표를 AWS CLI 전달 중 잃어 첫 Bundle이
  0행이 되는 문제를 찾았다. Collector를 UTF-8 `file://` 전달로 수정하고,
  CAPITAL-ONE에만 최소 1행·제한 재조회를 적용해 최종 Bundle 1행을 확인했다.
- 자동 Containment·GitHub Commit·Argo Rollout·재공격 실패·수동 Reset은 아직
  실행하거나 검증하지 않았다.
- 같은 TAKE의 WAF Event 2건은 Runner가 저장한 두 CloudFront Request ID와 정확히
  일치했고, `POST /vulnerabilities/exec/` Body에 `EC2MetaDataSSRF_Body` Label이 붙었지만
  Managed Rule은 `COUNT`라 요청은 `ALLOW`됐다.
- DVWA Apache Access에는 같은 시간창의 `POST /vulnerabilities/exec/` 2건과 HTTP 200이
  남았다. BANK 구조화 Audit에는 Login 성공만 있고 Command Body·실행 결과·IMDS 응답은
  남지 않아 애플리케이션 실행 단계는 미수집이다.
- VPC Flow Logs에는 `169.254.169.254`가 0건이다. AWS 공식 제한상 IMDS 트래픽은
  VPC Flow Logs 수집 대상이 아니므로, 이는 공격 부재가 아니라 직접 관측 공백이다.
- TAKE 시작 약 49분 뒤 GuardDuty API와 EventBridge 보존 Log Group을 다시 조회했으나
  실제 Finding과 전달 Event는 모두 0건이었다. `S3_DATA_EVENTS` Protection은 계속
  `DISABLED`이고, 이번 대표 탐지는 CloudTrail Custom Rule이다.
- Negative Control `capital-one-negative-20260812T034935Z`에서 정상 `terra-user`가
  같은 고정 가짜 Object를 한 번 읽었다. CloudTrail 성공 Event는 정확히 1행이었고,
  Primary Karpenter Node Role 조건이 달라 Alarm은 `OK`·상태 변경 시각 불변이었다.
- 첫 후속 Query 실패 뒤 동일 GetObject를 반복하지 않도록 Resume 경계를 추가했다.
  Runner의 별도 CWLI 구현은 제거하고 Evidence Collector의 UTF-8 Query 정규화,
  Delivery Grace, 제한 재시도, `event_time` 실행 창 재필터를 함께 사용한다.
- 시간 계약은 S3 읽기 수초, CloudTrail 전달·Query 최대 약 10분, Event 확인 뒤 Alarm
  비전환 120초다. Query는 30초 간격으로 진행률을 보이고 Client Record에 현재
  Invocation과 단계별 소요시간을 남긴다.
- 내부 Bundle의 Client Record는 Bucket·Caller ARN·Credential을 저장하지 않았고,
  CloudTrail Query 1행과 SHA-256 50개를 확인했다.
- Alert Description Source에 `scenario=CAPITAL-ONE`, `severity=HIGH`,
  `action=s3:GetObject`, Actor·Object·Verdict를 추가했다.
- 기존 Saved Plan은 실행하지 않았다. Commit `f2ab2dd`와 현재 State로 만든 Fresh
  Foundation Plan에서 해당 Alarm Description 1개 in-place update, Create·Delete·Replace
  0건과 Terraform Check 10/10 통과를 확인한 뒤 검토한 Plan만 Apply했다.
- AWS `describe-alarms`에서 여섯 Description 필드, SNS Alarm·OK Action, 현재
  `OK` 상태를 확인했다. Terraform State와 AWS 실제 Description이 일치했고, 같은
  입력의 Post-Apply Fresh Plan도 `0 change`였다.

### T5 — Terraform 영구 복구

목적: 취약 상태를 제거하고 이미 탈취한 권한의 영향을 차단한다.

정상 실행 조건은 최종 사용할 촬영 구간이 열리고 재생되는지 확인한 뒤다. 단,
실습 통제권 상실·촬영 중단·자리 비움 같은 안전 사유가 생기면 영상 상태와 무관하게
긴급 종료 또는 복구를 우선한다.

순서:

```text
security_scenario_profile=hardened
→ Fresh Plan
→ Node Role 실습 Policy 제거 확인
→ Metadata required·Hop 1 확인
→ 사람 승인
→ Apply
→ Karpenter 취약 Node 교체
→ 새 Node Runtime 확인
→ 기존 Credential S3 Negative Test
→ Pod IMDS Negative Test
```

중요:

```text
EC2NodeClass Source 변경
≠ 기존 Karpenter Node가 즉시 교체됐다는 뜻
```

Karpenter가 만든 EC2 Instance는 Terraform이 직접 소유하지 않는다. 따라서 Node
교체는 별도의 승인된 운영 절차로 수행하고, 새 Instance의 실제 MetadataOptions를
다시 확인한다.

Gate:

- [ ] 실습용 Inline Policy가 실제 Role에서 제거됐다.
- [ ] 새 Node가 `httpTokens=required`, Hop Limit 1이다.
- [ ] 기존 탈취 Credential의 `validation/*` 접근이 `AccessDenied`다.
- [ ] 새 Pod에서 Node IMDS 자격증명 경로가 실패한다.
- [ ] 정상 DVWA·Argo CD 기능이 유지된다.
- [ ] 최종 복구 뒤 재촬영 Reset Workflow를 실행하지 않는다.

### T6 — 반복 가능성·종료 검증

목적: T4에서 재촬영 준비를 실제 연습하고 T5에서 안전하게 종료했음을 증명한다.
T5 뒤에 이 체크리스트를 충족하려고 취약 Profile을 다시 열지는 않는다.

- [ ] 네 명 모두 같은 Profile 이름과 위험을 설명한다.
- [ ] T5 전에 최소 한 번 수동 Reset과 두 번째 TAKE 준비를 연습했다.
- [ ] 취약화·공격·Containment·Reset·영구 복구 순서를 Runbook만 보고 수행한다.
- [ ] 중간 실패 시 hardened로 돌아가는 복구 절차가 있다.
- [ ] Foundation과 Daily Runtime 종료 책임이 구분된다.
- [ ] 최종 채택 TAKE와 폐기 TAKE가 ID·시간창으로 구분된다.
- [ ] Evidence Bundle에 `manifest.json`과 Hash가 남는다.

### Push P0~P5 — Gate 4 저지연 전달 전환

이 단계는 기존 T0~T6 공격·복구 순서를 다시 실행하는 것이 아니다. 이미 검증한 5-Source
Polling을 As-built로 두고, Gate 4의 **전달 지연만 Source별로 교체**한다.

| 단계 | Terraform 범위 | Runtime Gate |
|---|---|---|
| P0 | Toggle·Schema·IAM·Queue/DLQ·Alarm 정적 계약, Default Off Plan | AWS 변경 없음 |
| P1 | 서울 Queue·DLQ·DVWA Forwarder·전체 Event Subscription·안전 Payload Allowlist | Local Bridge·Live JSONL·Rule `100102` 3회, 총 3.427~6.439초 완료 |
| P2 | Local Consumer·최소 Reader 권한·운영 Alarm | 실제 Rule `100103` 3회, Offline Catch-up 뒤 DVWA Poll Cutover |
| P3 | WAF·CloudTrail·ALB·CloudFront Resource를 한 Source씩 추가 | Source별 Field·Dashboard·기존 Rule 호환 뒤 Poll Off |
| P4 | 사용하지 않는 Poll Reader 권한 축소·운영 Alarm | 5개 Source Push 상태표·Rollback Drill |
| P5 | Terraform 범위 밖 Wazuh Alert Output | Shuffle Dry Run·`event_id` 중복 대응 차단 |

P1 이후의 각 Apply는 이전 단계의 비용·지연·실패 Evidence를 통과한 뒤 별도 승인한다.
CloudWatch Logs Subscription은 보통 Log 수신 뒤 수분 안에 전달되지만 at-least-once이므로,
속도만 확인하고 중복·DLQ·노트북 Offline 복구를 생략하지 않는다.

---

## 6. 검증 명령 계층

### 6.1 Source 검증

```text
terraform fmt -check
terraform -chdir=foundation fmt -check
terraform validate
terraform -chdir=foundation validate
Helm hardened 렌더링
Helm capital-one-lab 렌더링
PowerShell Parser·기존 Guard Test
git diff --check
```

### 6.2 Plan 검증

```text
terraform show -json <saved-plan>
→ Resource Action Summary
→ 허용 주소 목록
→ Foundation 삭제 여부
→ DR 권한 변경 여부
→ 민감 Output 여부
```

### 6.3 Runtime 검증

```text
kubectl get ec2nodeclass default
kubectl get node·pod 배치 관계
EC2 describe-instances MetadataOptions
IAM Role Policy 목록
STS Caller Identity의 예상 Role 비교
S3 validation/* Allow
다른 Prefix Deny
CloudTrail Event
GuardDuty 실제 Finding
복구 후 동일 Negative Test
```

Runtime 출력은 공개본을 만들기 전에 Account ID·IP·ARN·Request ID를 마스킹한다.

---

## 7. 상위 SOC Gate와의 연결

| Terraform Gate | 상위 시연 Gate | 제공하는 결과 |
|---|---|---|
| T0 | Gate 0·1·2 | 과거 공격과 현재 Runtime의 실제 상태 |
| T1 | Gate 1 | 반복 가능한 취약·복구 Profile |
| T2 | Gate 2·3 | 실제 공격 로그와 탐지 입력 Source |
| T3 | 모든 변경 전제 | 승인 가능한 최소 Plan |
| T4 | Gate 1~7·7-R | 공격·경보·Containment·재촬영 Reset Evidence |
| T5 | Gate 8 | IAM·IMDS 근본 복구와 Negative Test |
| T6 | Gate 8·최종 영상 | 반복 가능한 팀 Runbook과 안전 종료 Evidence |

Gate 4의 SIEM, Gate 5의 SOAR, Gate 6·7의 GitHub·Argo 구현은 별도 작업이다.

---

## 8. 확정 및 대기 항목

다음은 앞 Gate의 Evidence를 본 뒤 결정한다.

| 결정 | 후보 | 결정 조건 |
|---|---|---|
| S3 Event 이름 | Detector는 `GetObject`; 기존 Selector의 세 API 유지 | T2 결정·T4 Runtime 확인 |
| GuardDuty S3 Protection | `DISABLED` 유지·보조 Evidence만 허용 | T2 결정 |
| 대표 탐지 | CloudTrail Metric Filter → Alarm → SNS | T2 결정 |
| SIEM | **Wazuh 확정, 별도 ELK 미구축** | 2026-08-12 사용자 결정 |
| SIEM 위치 | **Local Docker single-node** | 세 Service 기동·CloudTrail Dashboard 집계 확인 |
| AWS→SIEM 전달 As-built | **CloudTrail·Primary ALB S3 + CloudFront·WAF·DVWA CloudWatch Logs 10m 직접 Read** | 다섯 Source Raw Runtime 확인 |
| AWS→SIEM 전달 Target | **리전별 CWL Subscription·Lambda·SQS + ALB S3 Notification + Local Bridge** | 1m Poll 호출량 검토 뒤 P0~P4 단계 전환 결정 |
| Wazuh Runtime Credential | **로컬 전용 IAM User 장기 Key 예외** | Git 밖 Profile·Read-only Mount, 종료 후 폐기 |
| Terraform Reader Role | Source·Apply 존재, 현재 Wazuh Runtime 경로는 아님 | Bucket 최상위 List 요구 반영 뒤 재검증 |
| S3→SQS | **ALB `alb/primary/` ObjectCreated에만 단계 도입** | DVWA·WAF·CloudTrail 선행 Push 검증 뒤 P3 |
| Firehose·EventBridge API Destination | **미사용 유지** | 현재 5-Source·Local Wazuh 범위에는 추가 이점보다 운영 복잡도가 큼 |
| Node 교체 | Karpenter Drift / 승인된 수동 절차 | 현재 Runtime 동작 확인 |

결정된 Wazuh 경로 외의 SIEM 후보나 전달 경로를 동시에 Terraform에 추가하지 않는다.

---

## 9. Definition of Done

Terraform 부분은 다음이 모두 충족돼야 완료다.

- [x] 기본 Source가 `hardened`다.
- [x] 취약 Profile은 명시적 확인문 없이는 실행되지 않는다.
- [x] 취약화 범위가 Primary Node와 `validation/*` 읽기로 제한된다.
- [ ] SSM·Helm 두 Karpenter 경로가 같은 Metadata를 만든다.
- [x] 공격과 직접 연결된 CloudTrail Event 또는 실제 GuardDuty Finding이 있다.
- [x] SIEM에 필요한 AWS 권한이 최소 범위이고 장기 Access Key를 Terraform으로 만들지 않는다.
- [x] Wazuh Reader Role에 S3·CloudWatch Write/Delete 권한이 없다.
- [x] Wazuh가 비활성인 기본 Foundation Plan에는 Reader Resource가 없다.
- [x] 초기 Reader 확장은 EventBridge·SQS·Firehose를 만들지 않고, 승인된 CloudFront 3일 Hot Copy용 Log Group·Destination만 추가했다.
- [x] Foundation CloudFront Wazuh Resource를 승인된 Plan으로 Apply하고 Post-Apply 0-change를 확인한다.
- [x] Daily `capital-one-lab`이 기존 CloudFront Delivery Source를 두 번째 Destination에 연결한다.
- [x] CloudFront 실제 요청 Record를 Wazuh Raw Archive에서 확인해 5/5 Runtime을 닫는다.
- [x] 1분 Poll 후보의 48 Stream 최소 호출량을 계산하고 Wazuh 원본·Runtime을 10분으로 복구한다.
- [x] Push Toggle 기본 Off Plan이 0-change이고, P1 DVWA Resource에 Delete·Replace가 없다.
- [x] 무해 DVWA Push Event 3회에서 누락 0·Rule `100102`·최대 6.439초를 확인한다.
- [ ] 실제 `command.execution` Push Rule `100103` 3회와 완료 기준 180초 이내를 확인한다.
- [ ] 노트북 Offline Catch-up·DLQ·Source별 Poll Rollback을 검증한다.
- [ ] WAF → CloudTrail → ALB → CloudFront를 Source별로 전환하고 사용하지 않는 Reader 권한을 축소한다.
- [ ] 수동 Reset은 DVWA 한 값만 되돌리고 Terraform·IAM·IMDS를 변경하지 않는다.
- [ ] Reset 후 새 세션·Alarm OK·새 TAKE로 재촬영을 시작할 수 있다.
- [ ] 복구 Plan이 실습 Policy 제거와 hardened Metadata를 명확히 보여준다.
- [ ] 최종 채택 영상을 확인한 뒤 hardened 복구를 수행한다.
- [ ] 새 Node Runtime에서 hardened 설정을 확인한다.
- [ ] 기존 Credential과 새 Pod의 재공격이 실패한다.
- [ ] 정상 애플리케이션 Regression이 통과한다.
- [x] Source·Plan·Runtime·Evidence 상태를 서로 구분해 기록한다.

---

## 10. 다음 작업

Foundation·Daily Apply, 공격 정탐, Gate 2 Coverage, 정상 GetObject 대조군, Alert
Description Runtime 적용과 Post-Apply 0-change까지 끝났다. Gate 3을 위해 같은 공격이나
GetObject를 다시 실행할 필요는 없다.

중앙 관제 제품은 Wazuh로 결정했고 As-built 입력 계약은 CloudTrail·Primary ALB의 S3
직접 Read와 CloudFront·WAF·Primary DVWA의 CloudWatch Logs 직접 Read다. Local Stack과 로컬
전용 Reader를 이용해 CloudTrail·WAF·Primary ALB·DVWA·CloudFront 5/5 Source의 실제
Record를 Raw Archive에서 확인했다. TAKE `capital-one-20260813T082735Z`의 실제 `GetObject`는 Rule
`100100`·Level 12 Alert가 됐고 Alert와 Raw 문서의 CloudTrail `eventID`도 일치했다.
WAF·ALB·DVWA·CloudFront는 현재 수집·Parsing 확인이며 전용 탐지 완료를 뜻하지 않는다.
무해 Probe의 같은 시각·경로가 CloudFront Edge JSON과 DVWA Pod Log 두 건으로
`wazuh-archives-4.x-2026.08.16`에서 검색됐다. 이 5/5 수집과 공격 전체 Timeline·관제 화면
완료를 구분한다.

```text
Local Docker·WSL Preflight·Wazuh Stack 기동 완료
→ Reader Source·Test·Apply·AssumeRole·Post-Apply 0-change 완료
→ 로컬 전용 Reader Profile·Read-only Mount 완료
→ CloudTrail wodle·실제 Object 처리·Dashboard 집계 완료
→ 기존 Baseline GetObject 0건·기본 Rule 목록/Archive 비활성 원인 확인
→ Gate 3 Sanitized Event로 Custom Rule 작성·wazuh-logtest 완료
→ Raw Archive 활성화·새 통제 Event Custom Alert 완료
→ WAF·Primary ALB·DVWA 실제 Record 수집·Parsing 확인
→ CloudFront 3일 Hot Copy Source·정적 Test·비파괴 Foundation Plan 완료
→ Foundation Apply·Post-Apply 0-change 확인 완료
→ Daily capital-one-lab Delivery Apply·로컬 Reader 권한·Wazuh 입력 추가 완료
→ 실제 CloudFront Record 확인으로 5/5 Runtime 완료
→ 초보자용 Saved View·Dashboard 구현
→ 새 Alert amazon Group 화면 노출·정상 대조군 오탐 검증
→ Archive 증가량 측정·7일 Retention 검증
```

다음 작업은 기존 5/5 수집이나 완료한 P1 전송 검증을 다시 만드는 것이 아니다. `10m`
Fallback을 유지한 채 실제 `command.execution`을 Push Rule `100103`으로 확인하고,
Offline Catch-up·장애 중복·Queue 비용 경계를 검증한다. 그 결과로 DVWA Poll Cutover 여부를
결정한다. 해당 Gate를 통과하기 전에는 WAF·CloudTrail·ALB·CloudFront Push Resource를
추가하지 않는다.

Containment 구현 전에는 Alarm이 실제 `OK`로 복귀했는지 확인하고 새 TAKE를 사용한다.
취약 Runtime의 영구 복구는 최종 촬영 확인 전에는 수행하지 않되, 통제권 상실·자리
비움·Watchdog Deadline에는 영상 편의보다 Daily Down 또는 긴급 hardened 복구를
우선한다. Saved Plan은 State나 Source가 바뀌면 폐기하고 Fresh Plan으로 다시 검토하며,
명시적 사용자 승인 전에는 어떤 Plan도 Apply하지 않는다.

---

## 11. 공식 참고 자료

- Karpenter EC2NodeClass `metadataOptions`: <https://karpenter.sh/v1.0/concepts/nodeclasses/>
- AWS CloudTrail Advanced Event Selector: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/filtering-data-events.html>
- Amazon CloudWatch Alarm Action 상태 전환: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-actions.html>
- Amazon GuardDuty S3 Protection: <https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html>
- GuardDuty `InstanceCredentialExfiltration.OutsideAWS`: <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html>
- Terraform AWS Provider `aws_guardduty_detector_feature` 6.0.0: <https://registry.terraform.io/providers/hashicorp/aws/6.0.0/docs/resources/guardduty_detector_feature>
