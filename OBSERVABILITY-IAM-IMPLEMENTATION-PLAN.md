# Observability·Pod Identity Codex 실행 계획

> 상태: **구현 레시피 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 설계 근거와 불확실성은 [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)를 따른다.

이 문서는 Codex가 위에서 아래로 실행하기 위한 작업 순서다. 배경 설명을 다시 확장하지 말고, 확정된 파일·Resource·검증 명령만 구현한다.

## 고정 범위

### Grafana 대상

```text
CloudFront Access Log
Primary ALB Access Log
Primary VPC REJECT Flow Log
```

```text
S3 Security Log Bucket
→ Athena Existing Database·Tables
→ Grafana 전용 Workgroup
→ Amazon Managed Grafana
```

### 이번 범위에서 하지 않음

- WAF·EKS·DVWA·GuardDuty Log의 S3 이중 저장
- Existing Athena Table의 Terraform Resource 전환
- Foundation Security Log Bucket 교체
- IAM Identity Center·AWS Organizations 자동 활성화
- Node Group·Karpenter IMDS 설정 변경
- `terraform apply`의 무승인 실행

---

# Task 0 — 구현 전 확인

## 확인할 값

| 값 | 기준 |
|---|---|
| AWS Account | `433048100798` |
| Primary Region | `ap-northeast-2` |
| AWS Profile | `terra-user` |
| Project | `aws-topology` |
| Foundation State | `foundation/terraform.tfstate` |
| Athena Database | `aws_topology_security` |

## 사람 Gate

다음이 없으면 Source·Plan까지만 하고 Workspace Apply를 중단한다.

- Amazon Managed Grafana 비용 승인
- IAM Identity Center 사용 승인
- IAM Identity Center Admin User ID 또는 Group ID

금지:

```text
Organizations 활성화
IAM Identity Center 활성화
Directory User·Group 생성
```

---

# Task 1 — 현재 Source Mapping 작성

## 생성 파일

```text
observability/log-source-map.json
```

## 내용

다음 네 S3 Source를 기록한다.

| ID | Prefix | Athena Table | Grafana |
|---|---|---|---:|
| `cloudfront` | `AWSLogs/433048100798/CloudFront/` | `cloudfront_access` | Yes |
| `alb-primary` | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `alb_primary_access` | Yes |
| `vpc-reject-primary` | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `vpc_reject` | Yes |
| `cloudtrail` | `AWSLogs/433048100798/CloudTrail/` | `null` | No |

각 항목 필드:

```text
id, service, region, bucket_output, prefix,
athena_database, athena_table, grafana_enabled, retention_days
```

## 검증

- `foundation/observability.tf`의 Bucket Policy Resource와 일치
- `observability/queries/athena/00_create_security_log_tables.sql`의 `LOCATION`과 일치

---

# Task 2 — `analytics/aws` Terraform Root 작성

## 생성 파일

```text
analytics/aws/versions.tf
analytics/aws/providers.tf
analytics/aws/variables.tf
analytics/aws/main.tf
analytics/aws/outputs.tf
```

## `versions.tf`

- Terraform: `>= 1.8.0`
- AWS Provider: `~> 6.0`

## `providers.tf`

- Region: `var.primary_region`
- Profile: `var.aws_profile`
- `aws_caller_identity`로 Account Check
- 공통 Tag:
  - `Project = var.project_name`
  - `ManagedBy = Terraform`
  - `Lifecycle = optional-analytics`

## `variables.tf`

| Variable | Default |
|---|---|
| `aws_profile` | `terra-user` |
| `expected_account_id` | `433048100798` |
| `primary_region` | `ap-northeast-2` |
| `project_name` | `aws-topology` |
| `foundation_state_path` | `../../foundation/terraform.tfstate` |
| `athena_database_name` | `aws_topology_security` |
| `athena_workgroup_name` | `aws-topology-grafana` |
| `athena_scan_cutoff_bytes` | `104857600` |
| `query_result_retention_days` | `7` |
| `grafana_workspace_name` | `aws-topology-security` |
| `grafana_admin_user_ids` | `[]` |
| `grafana_admin_group_ids` | `[]` |

Validation:

```text
athena_scan_cutoff_bytes >= 10485760
1 <= query_result_retention_days <= 30
Admin User ID와 Group ID 합계가 1개 이상
```

## `main.tf` Resource

### Foundation 참조

```text
data.terraform_remote_state.foundation
```

읽을 Output:

```text
security_log_bucket_name
security_log_bucket_arn
```

Foundation Resource는 수정하지 않는다.

### Athena Result Bucket

```text
aws_s3_bucket.athena_results
aws_s3_bucket_ownership_controls.athena_results
aws_s3_bucket_public_access_block.athena_results
aws_s3_bucket_server_side_encryption_configuration.athena_results
aws_s3_bucket_lifecycle_configuration.athena_results
```

설정:

- `bucket_prefix = "grafana-athena-query-results-"`
- `force_destroy = true`
- Bucket owner enforced
- Public Access Block 전부 `true`
- SSE-S3
- Object `var.query_result_retention_days` 후 만료
- Multipart Upload 1일 후 중단

### Athena Workgroup

```text
aws_athena_workgroup.grafana
```

설정:

- Name: `var.athena_workgroup_name`
- Engine Version 3
- Result Location: `s3://<RESULT_BUCKET>/results/`
- `enforce_workgroup_configuration = true`
- `publish_cloudwatch_metrics_enabled = true`
- `bytes_scanned_cutoff_per_query = var.athena_scan_cutoff_bytes`
- Tag: `GrafanaDataSource = "true"`

### Workspace IAM Role

```text
aws_iam_role.grafana_workspace
aws_iam_role_policy_attachment.grafana_athena
aws_iam_role_policy.grafana_source_read
```

Trust:

```text
Principal Service = grafana.amazonaws.com
Action = sts:AssumeRole
```

Managed Policy:

```text
arn:aws:iam::aws:policy/service-role/AmazonGrafanaAthenaAccess
```

Inline Source Read Policy:

Bucket Action:

```text
s3:GetBucketLocation
s3:ListBucket
```

`ListBucket` Condition은 다음 Prefix와 Prefix 하위만 허용한다.

```text
AWSLogs/433048100798/CloudFront/
AWSLogs/433048100798/CloudFront/*
alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/
alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/*
vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/
vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/*
```

Object Action:

```text
s3:GetObject
```

Object ARN도 위 세 Prefix로 제한한다.

금지:

```text
Security Log Bucket s3:PutObject
Security Log Bucket s3:DeleteObject
Application Bucket 접근
CloudTrail Prefix 접근
```

### Amazon Managed Grafana

```text
aws_grafana_workspace.security
aws_grafana_role_association.admin
```

Workspace 설정:

```text
name                     = aws-topology-security
account_access_type      = CURRENT_ACCOUNT
authentication_providers = [AWS_SSO]
permission_type          = CUSTOMER_MANAGED
role_arn                 = aws_iam_role.grafana_workspace.arn
data_sources             = [ATHENA]
grafana_version          = 12.4
pluginAdminEnabled       = true
```

VPC Configuration은 작성하지 않는다.

Role Association:

- `role = ADMIN`
- 입력된 IAM Identity Center User ID·Group ID 사용
- IAM User Name·ARN 사용 금지

## `outputs.tf`

```text
grafana_workspace_id
grafana_workspace_endpoint
grafana_workspace_role_arn
athena_workgroup_name
athena_result_bucket_name
athena_database_name
security_log_bucket_name
```

Token·Password는 Output하지 않는다.

## 검증

```powershell
terraform -chdir=analytics/aws fmt -check
terraform -chdir=analytics/aws init
terraform -chdir=analytics/aws validate
terraform -chdir=analytics/aws plan -out=analytics-aws.tfplan
```

중단 조건:

- Account 불일치
- Foundation State·Output 없음
- 기존 Security Log Bucket 변경
- Foundation 또는 Daily Resource 변경
- Admin Identity Center ID 없음

첫 Codex Pass는 여기서 Apply하지 않는다.

---

# Task 3 — `analytics/grafana` Terraform Root 작성

## 생성 파일

```text
analytics/grafana/versions.tf
analytics/grafana/providers.tf
analytics/grafana/variables.tf
analytics/grafana/main.tf
analytics/grafana/security-overview.json
```

## Provider

- Grafana Provider: `grafana/grafana ~> 4.42`
- 인증은 환경변수만 사용

```text
GRAFANA_URL
GRAFANA_AUTH
```

Token을 Provider Block·tfvars·Output에 기록하지 않는다.

## Resource

```text
grafana_data_source.athena
grafana_folder.security
grafana_dashboard.security_overview
```

### Athena Data Source

```text
name = AWS Topology Athena
uid  = aws-topology-athena
type = grafana-athena-datasource
```

`json_data_encoded`:

```json
{
  "authType": "default",
  "defaultRegion": "ap-northeast-2",
  "catalog": "AwsDataCatalog",
  "database": "aws_topology_security",
  "workgroup": "aws-topology-grafana"
}
```

Access Key·Secret Key는 사용하지 않는다.

### Folder·Dashboard

Folder:

```text
Title = AWS Topology Security
UID   = aws-topology-security
```

Dashboard:

```text
Title = AWS Topology Security Overview
UID   = aws-topology-security-overview
Default Range = 최근 6시간
Auto Refresh = Off
```

필수 Panel 3개:

1. CloudFront 요청량·4xx·5xx Time Series
2. ALB 4xx·5xx Top Source Table 또는 Bar Chart
3. VPC REJECT Top Source·Destination Port Table 또는 Bar Chart

공통 조건:

- Grafana Time Filter 사용
- CloudFront Time Series는 시간 오름차순
- 전체 기간 Scan 금지
- Cookie, Authorization, Query String, Body 표시 금지

Request Trace Panel은 선택 사항이다.

## 검증

```powershell
terraform -chdir=analytics/grafana fmt -check
terraform -chdir=analytics/grafana init
terraform -chdir=analytics/grafana validate
```

Grafana Provider Plan은 Workspace·임시 Token 생성 이후 실행한다.

---

# Task 4 — Analytics Wrapper 작성

## 생성 파일

```text
analytics/setup-analytics.ps1
analytics/destroy-analytics.ps1
analytics/README.md
```

## `setup-analytics.ps1`

기본 동작은 Preview다.

순서:

```text
AWS Identity 확인
→ analytics/aws fmt·init·validate·plan
→ Plan 요약 출력
→ 승인 없으면 종료
→ analytics/aws apply
→ Workspace ACTIVE 대기
→ AWS CLI로 임시 ADMIN Service Account 생성
→ TTL 3600초 Token 생성
→ GRAFANA_URL·GRAFANA_AUTH 설정
→ Athena Plugin 상태 확인
→ 필요할 때만 grafana-athena-datasource 설치
→ analytics/grafana init·validate·plan·apply
→ Data Source Health와 Dashboard UID 확인
→ finally에서 Token 삭제
→ finally에서 Service Account 삭제
```

승인 문구:

```text
APPLY ANALYTICS
```

Token 생성에는 다음 AWS API 계열을 사용한다.

```text
CreateWorkspaceServiceAccount
CreateWorkspaceServiceAccountToken
DeleteWorkspaceServiceAccountToken
DeleteWorkspaceServiceAccount
```

Terraform의 `aws_grafana_workspace_service_account_token` Resource는 사용하지 않는다.

## `destroy-analytics.ps1`

순서:

```text
임시 Service Account·Token 생성
→ analytics/grafana destroy
→ Token·Service Account 삭제
→ analytics/aws destroy
```

승인 문구:

```text
DESTROY ANALYTICS
```

Foundation·Daily State를 읽거나 변경하지 않는다.

---

# Task 5 — S3·Athena 검증 작성

## 생성 파일

```text
observability/Test-SecurityLogSources.ps1
```

## 입력

```text
AwsProfile
ExpectedAccountId
FoundationRoot
MapPath
StartUtc
EndUtc
EvidenceRoot
```

## 검증

각 Grafana 대상 Source에 대해:

```text
S3 Prefix Object 1개 이상
→ Athena Database 존재
→ Table 존재
→ Table LOCATION과 Prefix 일치
→ 제한 시간 Query 성공
→ QueryExecutionId·Rows·DataScannedInBytes 기록
```

출력:

```text
<evidence>/s3-log-source-verification.json
```

Object 0건이면 원인을 추측하지 말고 `NotObserved`로 기록한다.

---

# Task 6 — Pod Identity Trust와 Matrix 작성

## 생성 파일

```text
pod-identity-trust.tf
observability/Export-PodIdentityMatrix.ps1
observability/Test-PodIdentityRuntime.ps1
```

## Custom Role Trust 보정

현재 공용 `data.aws_iam_policy_document.pod_identity_assume_role` 대신 Scope Map과 `for_each` Trust Document를 만든다.

필수 Scope:

| Key | Namespace | ServiceAccount |
|---|---|---|
| `primary-fluent-bit` | `amazon-cloudwatch` | `aws-for-fluent-bit` |
| `dr-fluent-bit` | `amazon-cloudwatch` | `aws-for-fluent-bit` |
| `primary-efs-csi` | `kube-system` | `efs-csi-controller-sa` |
| `dr-efs-csi` | `kube-system` | `efs-csi-controller-sa` |
| `primary-web-s3` | `var.web_namespace` | `var.web_service_account` |
| `dr-web-s3` | `var.web_namespace` | `var.web_service_account` |

Trust Statement:

```text
Principal.Service = pods.eks.amazonaws.com
Action = sts:AssumeRole, sts:TagSession
Condition aws:RequestTag/kubernetes-namespace
Condition aws:RequestTag/kubernetes-service-account
```

수정 대상:

```text
observability.tf
storage-access.tf
eks.tf의 EFS Add-on Role 참조
```

## Module Role

대상:

```text
AWS Load Balancer Controller
ExternalDNS
Karpenter
```

규칙:

- 현재 설치된 Module Source·Version을 먼저 확인
- `trust_policy_conditions` 지원 시 LBC·ExternalDNS에 Namespace·ServiceAccount 조건 추가
- 조건 추가만을 위한 Module Upgrade·Fork 금지
- Karpenter는 첫 Pass에서 Source와 Runtime Inventory만 작성

## Matrix 필드

```text
cluster
namespace
service_account
association_id
role_arn
managed_policies
inline_policies
status
```

상태:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
```

---

# Task 7 — Pod Identity Runtime 검증

활성 Workload만 검사한다.

공통 흐름:

```text
Association 확인
→ Pod의 ServiceAccount 확인
→ 동일 ServiceAccount의 임시 AWS CLI Pod 실행
→ sts get-caller-identity
→ 예상 Role ARN 비교
→ 대표 허용 Read API 성공
→ iam:ListUsers AccessDenied
→ 임시 Pod 삭제
```

대표 허용 Probe:

| Workload | Probe |
|---|---|
| AWS LBC | `elasticloadbalancing:DescribeLoadBalancers` |
| ExternalDNS | 지정 Zone `route53:ListResourceRecordSets` |
| Fluent Bit | 지정 Group `logs:DescribeLogStreams` |
| EFS CSI | `elasticfilesystem:DescribeFileSystems` |
| Web S3 | 지정 Bucket `s3:GetBucketLocation` |
| Karpenter | Module Policy의 Read Action 1개 |

Write Canary는 별도 승인 없이는 실행하지 않는다.

```text
RUN POD IDENTITY S3 CANARY
```

Association 없는 ServiceAccount의 `sts get-caller-identity` 결과도 기록한다. Node Role이 보이면 Hardening Gap으로 보고하되, 첫 Pass에서 Node·Karpenter Metadata Option을 변경하지 않는다.

출력:

```text
<evidence>/pod-identity-matrix.json
<evidence>/pod-identity-runtime.json
```

Credential 값은 기록하지 않는다.

---

# Task 8 — Static Test

## 생성 파일

```text
tests/test-analytics-contract.ps1
tests/test-pod-identity-contract.ps1
```

## Analytics Test

검사:

- Result Bucket 이름·암호화·Public Block·Lifecycle
- Workgroup Result Location 강제·Scan Cutoff·Tag
- Workspace `AWS_SSO`, `CURRENT_ACCOUNT`, `CUSTOMER_MANAGED`, Grafana `12.4`
- Workspace Role에 `AmazonGrafanaAthenaAccess`
- Source S3 Read가 세 Prefix로 제한
- Security Source Bucket Write·Delete 없음
- Terraform Source에 Grafana Token Resource 없음
- Data Source·Folder·Dashboard UID 고정
- 필수 Panel 3개에 Time Filter 존재

## Pod Identity Test

검사:

- Custom Trust에 Service Principal·두 STS Action·두 Request Tag 조건
- Fluent Bit Log Group 범위
- Web S3 `web/*` 범위
- ExternalDNS Hosted Zone 범위
- 휴면 Toggle 기본값 `false`
- Runtime Script가 승인 없이 Write Canary를 실행하지 않음
- Diagnostic Image에 `latest` 없음
- Credential 출력 금지

---

# Task 9 — Codex 첫 Pass 종료 조건

Codex 첫 Pass는 다음까지만 한다.

```text
Source 작성
Static Test
terraform fmt
terraform validate
analytics/aws Fresh Plan
```

금지:

```text
terraform apply
IAM Identity Center·Organizations 변경
AWS Resource Mutation
kubectl Mutation
실제 S3 Write Canary
Secret·Token·State·Plan Commit
```

보고 항목:

```text
변경 파일
fmt·validate·test 결과
analytics/aws Plan Resource 목록
기존 Foundation·Daily 변경 0건 여부
Module Trust Condition 지원 여부
Apply 전 사람 Gate
Runtime에서만 확인 가능한 항목
```

## Codex 시작 Prompt

```text
Repository: Unoh03/bank-security-lab-infra
Base: main
Branch: codex/observability-iam

먼저 OBSERVABILITY-IAM-DECISIONS.md와
OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 읽어라.

IMPLEMENTATION PLAN의 Task 1, 2, 3, 4, 5, 6, 8을 Source 수준에서 구현하라.
Task 7은 실행하지 말고 안전한 Script만 작성하라.
Task 9의 금지사항을 지켜라.

끝나면 변경 파일, Test 결과, Fresh Plan, 기존 Resource 영향,
사람 Gate와 Runtime 검증 항목을 분리해서 보고하라.
```
