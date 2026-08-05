# Grafana Cloud·S3 로그·Pod Identity Codex 실행 계획

> 상태: **구현 레시피 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 결정 근거: [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)

Codex는 아래 Task를 순서대로 수행한다. 이번 첫 Pass에서는 Source·Test·Plan까지만 진행하고 `terraform apply`와 `kubectl` 변경은 하지 않는다.

## 목표 구조

```text
Grafana Cloud Free
├─ Athena Data Source
│  └─ Security Log S3: CloudFront, ALB, VPC REJECT
└─ CloudWatch Data Source
   └─ WAF, EKS, DVWA, GuardDuty

Grafana Cloud
→ STS AssumeRole + Grafana External ID
→ aws-topology-grafana-cloud-read
```

## 이번 범위에서 하지 않음

```text
Amazon Managed Grafana
IAM Identity Center·AWS Organizations
Grafana용 EC2·EKS 설치
AWS Access Key 발급
CloudWatch Log의 S3 이중 저장
기존 Glue Table의 Terraform 전환
Foundation Security Log Bucket 변경
Node Group·Karpenter IMDS 설정 변경
```

---

# Task 0 — Grafana Cloud 입력 확보

사용자가 Grafana Cloud Free Stack을 생성한다.

Grafana Cloud에서 다음 두 Connection을 열고 `Grafana Assume Role`을 선택한다.

```text
Amazon Athena
Amazon CloudWatch
```

각 화면에 표시되는 값을 기록한다.

```text
Grafana Stack URL
Grafana AWS Account ID
Grafana External ID
```

판정:

- Athena와 CloudWatch의 Account ID·External ID가 같으면 IAM Role 하나를 공유한다.
- 다르면 작업을 중단하고 Data Source별 Role 두 개로 계획을 보정한다.
- 값은 `tfvars`, State, Git에 Commit하지 않는다.

첫 Codex Pass는 실제 값이 없어도 변수와 Plan Gate까지 작성할 수 있다.

---

# Task 1 — Log Source Map

생성:

```text
observability/log-source-map.json
```

필수 S3 Source:

| ID | Prefix | Athena Table | Dashboard |
|---|---|---|---:|
| `cloudfront` | `AWSLogs/433048100798/CloudFront/` | `cloudfront_access` | 필수 |
| `alb-primary` | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `alb_primary_access` | 필수 |
| `vpc-reject-primary` | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `vpc_reject` | 필수 |
| `cloudtrail` | `AWSLogs/433048100798/CloudTrail/` | `null` | 후속 |

필수 CloudWatch Source:

| ID | Region | Log Group |
|---|---|---|
| `waf-edge` | `us-east-1` | `aws-waf-logs-aws-topology-edge` |
| `eks-control-primary` | `ap-northeast-2` | `/aws/eks/aws-topology-primary/cluster` |
| `dvwa-primary` | `ap-northeast-2` | `/aws/eks/aws-topology-primary/dvwa` |
| `dvwa-dr` | `ap-northeast-1` | `/aws/eks/aws-topology-dr/dvwa` |
| `guardduty` | `ap-northeast-2` | `/aws/events/aws-topology-guardduty-findings` |

공통 필드:

```text
id, service, storage, region, retention_days
```

S3 전용 필드:

```text
bucket_output, prefix, athena_database, athena_table, dashboard_required
```

CloudWatch 전용 필드:

```text
log_group
```

검증:

- S3 Prefix가 `foundation/observability.tf` Bucket Policy와 일치
- Athena Table `LOCATION`이 `00_create_security_log_tables.sql`과 일치
- `retention_days = 30`

---

# Task 2 — `analytics/aws` Terraform 작성

생성:

```text
analytics/aws/versions.tf
analytics/aws/providers.tf
analytics/aws/variables.tf
analytics/aws/main.tf
analytics/aws/iam.tf
analytics/aws/outputs.tf
analytics/aws/README.md
```

## Provider

```text
Terraform >= 1.8.0
hashicorp/aws ~> 6.0
```

- Region: `var.primary_region`
- Profile: `var.aws_profile`
- `data.aws_caller_identity.current`로 Account Check
- Default Tags:
  - `Project = var.project_name`
  - `ManagedBy = Terraform`
  - `Lifecycle = optional-analytics`

## Variables

| 이름 | 기본값 |
|---|---|
| `aws_profile` | `terra-user` |
| `expected_account_id` | `433048100798` |
| `primary_region` | `ap-northeast-2` |
| `project_name` | `aws-topology` |
| `foundation_state_path` | `../../foundation/terraform.tfstate` |
| `athena_database_name` | `aws_topology_security` |
| `athena_workgroup_name` | `aws-topology-grafana-cloud` |
| `athena_scan_cutoff_bytes` | `104857600` |
| `query_result_retention_days` | `7` |
| `grafana_aws_account_id` | 필수 입력 |
| `grafana_external_id` | 필수 입력 |

Validation:

```text
grafana_aws_account_id = 12자리 숫자
grafana_external_id = 빈 문자열 금지
athena_scan_cutoff_bytes >= 10485760
1 <= query_result_retention_days <= 30
```

`grafana_external_id`는 `sensitive = true`로 표시한다. External ID는 Password는 아니지만 Stack 전용값이므로 기본 출력에 노출하지 않는다.

## Foundation 참조

```text
data.terraform_remote_state.foundation
```

읽을 Output:

```text
security_log_bucket_name
security_log_bucket_arn
```

Foundation State는 Read-only로 사용한다.

## Athena Result Bucket

Resource:

```text
aws_s3_bucket.athena_results
aws_s3_bucket_ownership_controls.athena_results
aws_s3_bucket_public_access_block.athena_results
aws_s3_bucket_server_side_encryption_configuration.athena_results
aws_s3_bucket_lifecycle_configuration.athena_results
```

설정:

```text
bucket_prefix = aws-topology-athena-results-
force_destroy = true
Object Ownership = BucketOwnerEnforced
Public Access Block = 모두 true
Encryption = AES256
Current Object 만료 = 7일 기본값
Incomplete Multipart Upload = 1일
```

이 Bucket에는 원본 로그를 저장하지 않는다.

## Athena Workgroup

Resource:

```text
aws_athena_workgroup.grafana_cloud
```

설정:

```text
name = var.athena_workgroup_name
engine = Athena engine version 3
result = s3://<RESULT_BUCKET>/results/
enforce_workgroup_configuration = true
publish_cloudwatch_metrics_enabled = true
bytes_scanned_cutoff_per_query = var.athena_scan_cutoff_bytes
```

## Grafana Cloud IAM Role

Resource:

```text
aws_iam_role.grafana_cloud_read
aws_iam_role_policy.grafana_cloud_read
```

Trust:

```text
Principal.AWS = arn:aws:iam::<grafana_aws_account_id>:root
Action = sts:AssumeRole
Condition.StringEquals.sts:ExternalId = var.grafana_external_id
```

Role 이름:

```text
aws-topology-grafana-cloud-read
```

### Athena API

```text
athena:ListDatabases
athena:ListDataCatalogs
athena:ListWorkGroups
athena:GetDatabase
athena:GetDataCatalog
athena:GetQueryExecution
athena:GetQueryResults
athena:GetTableMetadata
athena:GetWorkGroup
athena:ListTableMetadata
athena:StartQueryExecution
athena:StopQueryExecution
```

Resource는 Athena API 특성상 `*`를 사용한다.

### Glue Read

```text
glue:GetDatabase
glue:GetDatabases
glue:GetTable
glue:GetTables
glue:GetPartition
glue:GetPartitions
glue:BatchGetPartition
```

첫 Pass는 `Resource = "*"`로 시작하고, 정상 동작 후 Catalog ARN 제한 가능성을 후속 검토한다.

### Security Log S3 Read

Bucket Action:

```text
s3:GetBucketLocation
s3:ListBucket
```

`ListBucket` Prefix Condition:

```text
AWSLogs/433048100798/CloudFront/
AWSLogs/433048100798/CloudFront/*
alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/
alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/*
vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/
vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/*
AWSLogs/433048100798/CloudTrail/
AWSLogs/433048100798/CloudTrail/*
```

Object Action:

```text
s3:GetObject
```

Object ARN은 위 Prefix로 제한한다.

### Athena Result S3

Bucket:

```text
s3:GetBucketLocation
s3:ListBucket
s3:ListBucketMultipartUploads
```

Object:

```text
s3:GetObject
s3:PutObject
s3:AbortMultipartUpload
s3:ListMultipartUploadParts
```

대상은 Result Bucket과 `/results/*`로 제한한다.

### CloudWatch Logs Read

```text
logs:DescribeLogGroups
logs:GetLogGroupFields
logs:StartQuery
logs:StopQuery
logs:GetQueryResults
logs:GetLogEvents
```

첫 Pass는 Grafana 공식 Logs-only 예제와 동일하게 `Resource = "*"`를 사용한다. CloudWatch Metrics·EC2·Tag·Performance Insights 권한은 추가하지 않는다.

금지:

```text
Security Log Bucket Write·Delete
Application Bucket 접근
IAM 변경
EC2·EKS 변경
CloudWatch Metrics 조회
```

## Outputs

```text
grafana_cloud_role_arn
athena_workgroup_name
athena_result_bucket_name
athena_database_name
security_log_bucket_name
```

External ID는 Output하지 않는다.

## 검증

```powershell
terraform -chdir=analytics/aws fmt -check
terraform -chdir=analytics/aws init
terraform -chdir=analytics/aws validate
terraform -chdir=analytics/aws plan -out=analytics-aws.tfplan
```

중단:

- Account 불일치
- Foundation State·Output 없음
- Foundation·Daily Resource 변경
- Security Log Bucket 변경
- Grafana Account ID·External ID 없음

첫 Codex Pass에서는 Apply하지 않는다. `*.tfplan`은 Commit하지 않는다.

---

# Task 3 — Static Test 작성

생성:

```text
tests/test-grafana-cloud-contract.ps1
```

검사:

- Amazon Managed Grafana Resource가 없음
- IAM Identity Center·Organizations Resource가 없음
- Grafana IAM User·Access Key Resource가 없음
- Trust에 Grafana Account ID와 `sts:ExternalId` Condition이 있음
- Result Bucket이 Source Bucket과 분리됨
- Result 7일 Lifecycle
- Security Log 30일 기존값을 변경하지 않음
- Athena·Glue·S3·CloudWatch Logs 이외 변경 권한 없음
- Security Log Bucket Write·Delete 권한 없음
- CloudWatch Metrics 권한 없음
- `terraform apply` 자동 실행 없음

실행:

```powershell
.\tests\test-grafana-cloud-contract.ps1
```

---

# Task 4 — AWS Apply와 Grafana Cloud 연결

이 Task는 사용자가 Plan을 검토한 뒤 별도로 수행한다.

## AWS Apply

```powershell
terraform -chdir=analytics/aws apply analytics-aws.tfplan
```

확인:

```text
Result Bucket 존재
Workgroup 존재
IAM Role Trust의 Account ID·External ID 일치
Role Policy에 변경 권한 없음
```

## Athena Data Source

Grafana Cloud UI:

```text
Connections
→ Amazon Athena
→ Authentication Provider: Grafana Assume Role
→ Assume Role ARN: terraform output grafana_cloud_role_arn
→ Region: ap-northeast-2
→ Catalog: AwsDataCatalog
→ Database: aws_topology_security
→ Workgroup: aws-topology-grafana-cloud
→ Output Location: 비움
→ Save & test
```

Workgroup이 Result Location을 강제하므로 Output Location은 비운다.

## CloudWatch Data Source

```text
Connections
→ Amazon CloudWatch
→ Authentication Provider: Grafana Assume Role
→ 동일 Role ARN
→ Default Region: ap-northeast-2
→ Save & test
```

확인 결과:

```text
CloudWatch Metrics API 성공 여부는 권한 범위에 따라 실패할 수 있음
CloudWatch Logs Query는 성공해야 함
```

CloudWatch Plugin의 `Save & test`가 Metrics 권한까지 필수로 요구한다면, 실패 내용을 확인한 뒤 필요한 최소 Metrics 조회 권한만 추가하는 별도 보정을 제출한다. 처음부터 Metrics 권한을 넓히지 않는다.

---

# Task 5 — Dashboard 초안

생성:

```text
analytics/dashboard/
├─ README.md
├─ cloudfront-requests.sql
├─ alb-errors.sql
├─ vpc-reject.sql
└─ security-overview.json
```

필수 Panel:

1. CloudFront 요청·4xx·5xx Time Series
2. ALB 4xx·5xx Top Source
3. VPC REJECT Top Source·Destination Port
4. WAF·EKS·DVWA·GuardDuty 중 최소 1개 CloudWatch Logs Panel

공통:

```text
기본 Time Range = 최근 6시간
Auto Refresh = Off
모든 Query에 Time Filter
전체 기간 Scan 금지
Cookie·Authorization·Query String·Body 미표시
```

첫 검증은 UI에서 Dashboard를 구성한 뒤 JSON을 Export하여 `security-overview.json`에 저장한다. Grafana Provider 자동화는 Data Source와 Dashboard가 실제 동작한 뒤 후속 Task로 진행한다.

---

# Task 6 — S3·Athena Runtime 검증 Script

생성:

```text
observability/Test-SecurityLogSources.ps1
```

입력:

```text
AwsProfile, ExpectedAccountId, FoundationRoot,
MapPath, StartUtc, EndUtc, EvidenceRoot
```

각 필수 S3 Source에서 확인:

```text
S3 Object >= 1
Athena Database 존재
Table 존재
Table LOCATION = Map Prefix
제한 시간 Query SUCCEEDED
QueryExecutionId·Rows·DataScannedInBytes 기록
```

출력:

```text
<evidence>/s3-log-source-verification.json
```

Object가 없으면 `NotObserved`로 기록하고 원인을 추측하지 않는다.

---

# Task 7 — Pod Identity Inventory·Runtime Script

생성:

```text
observability/Export-PodIdentityMatrix.ps1
observability/Test-PodIdentityRuntime.ps1
tests/test-pod-identity-contract.ps1
```

첫 Pass에서는 기존 Role·Association을 변경하지 않는다.

## Inventory

수집:

```text
EKS Pod Identity Association
IAM Role Trust
Managed·Inline Policy
Kubernetes ServiceAccount
Pod별 ServiceAccount
```

Matrix 필드:

```text
cluster, namespace, service_account,
association_id, role_arn, policies, status
```

상태:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
NoAssociationExpected
```

## Runtime Test

첫 Pass에서는 Script만 작성하고 실행하지 않는다.

```text
Association 확인
→ 실제 Pod ServiceAccount 확인
→ 같은 ServiceAccount의 임시 AWS CLI Pod
→ sts get-caller-identity
→ 예상 Role ARN
→ 대표 허용 Read API 성공
→ iam:ListUsers AccessDenied
→ 임시 Pod 삭제
```

Association 없는 ServiceAccount에서도 `sts get-caller-identity`를 실행한다.

- Credential 없음: 통과
- Node Role 반환: 격리 미충족, 별도 Hardening Plan 작성

기존 Controller·Node를 교체하거나 Trust Policy를 일괄 수정하지 않는다.

---

# Task 8 — 첫 Codex Pass 종료 조건

필수:

```text
Log Source Map 작성
analytics/aws Source 작성
Static Test 성공
terraform fmt·validate 성공
Fresh Plan 생성
Pod Identity Inventory·Runtime Test Script 작성
AWS Apply 없음
Kubernetes 변경 없음
```

보고:

```text
변경 파일
Test 결과
Plan Resource 목록
예상 비용 Resource
Grafana Cloud에서 사람이 입력할 값
Apply 전 미확정 항목
Runtime에서만 확인 가능한 항목
```

## Codex 시작 Prompt

```text
Repository: Unoh03/bank-security-lab-infra
Base: main

OBSERVABILITY-IAM-DECISIONS.md와
OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 읽고 Task 0~3, 6~8의
첫 Pass만 구현하라.

금지:
- terraform apply/destroy
- AWS Resource 변경
- kubectl mutation
- Amazon Managed Grafana
- IAM Identity Center·Organizations
- AWS Access Key 생성
- Existing Foundation·Daily State 수정
- tfstate, tfplan, tfvars, Token, External ID Commit

종료 시 Source, Plan, Runtime 미검증을 구분하여 보고하라.
```
