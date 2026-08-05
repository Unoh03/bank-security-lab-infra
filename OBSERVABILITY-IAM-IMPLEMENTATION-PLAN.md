# Observability·Pod Identity Codex 실행 계획

> 상태: **구현 레시피 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 결정 근거: [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)

Codex는 이 문서를 위에서 아래로 실행한다. 아키텍처를 다시 확장하지 않고, 파일·Resource·검증·중단 조건만 따른다.

## 고정 범위

```text
CloudFront Access Log
Primary ALB Access Log
Primary VPC REJECT Flow Log
→ 기존 Security Log S3 Bucket
→ 기존 Athena Database·Tables
→ Grafana 전용 Athena Workgroup
→ Amazon Managed Grafana
```

이번 Pass에서 하지 않는다.

```text
WAF·EKS·DVWA·GuardDuty Log의 S3 복제
기존 Glue Table의 Terraform 전환
Foundation Security Log Bucket 변경
Organizations·IAM Identity Center 활성화
Node Group·Karpenter IMDS 설정 변경
terraform apply
kubectl mutation
```

---

# Task 0 — Preflight

확인값:

| 항목 | 값 |
|---|---|
| Account | `433048100798` |
| Region | `ap-northeast-2` |
| Profile | `terra-user` |
| Project | `aws-topology` |
| Foundation State | `foundation/terraform.tfstate` |
| Athena Database | `aws_topology_security` |

Workspace Apply 전 사람 Gate:

- Amazon Managed Grafana 비용 승인
- IAM Identity Center 사용 승인
- IAM Identity Center Admin User ID 또는 Group ID 확보

Gate가 없으면 Source·Test·Plan까지만 수행한다.

---

# Task 1 — Log Source Map

생성:

```text
observability/log-source-map.json
```

필수 항목:

| ID | Prefix | Table | Grafana |
|---|---|---|---:|
| `cloudfront` | `AWSLogs/433048100798/CloudFront/` | `cloudfront_access` | true |
| `alb-primary` | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `alb_primary_access` | true |
| `vpc-reject-primary` | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `vpc_reject` | true |
| `cloudtrail` | `AWSLogs/433048100798/CloudTrail/` | `null` | false |

필드:

```text
id, service, region, bucket_output, prefix,
athena_database, athena_table, grafana_enabled, retention_days
```

검증:

- `foundation/observability.tf` Bucket Policy 경로와 일치
- `observability/queries/athena/00_create_security_log_tables.sql`의 `LOCATION`과 일치

---

# Task 2 — `analytics/aws`

생성:

```text
analytics/aws/versions.tf
analytics/aws/providers.tf
analytics/aws/variables.tf
analytics/aws/main.tf
analytics/aws/outputs.tf
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
Admin User ID와 Group ID 합계 >= 1
```

## Foundation 참조

```text
data.terraform_remote_state.foundation
```

읽을 Output:

```text
security_log_bucket_name
security_log_bucket_arn
```

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
bucket_prefix = grafana-athena-query-results-
force_destroy = true
Object Ownership = BucketOwnerEnforced
Public Access Block = 모두 true
Encryption = AES256
Current Object 만료 = var.query_result_retention_days
Incomplete Multipart Upload = 1일
```

## Athena Workgroup

Resource:

```text
aws_athena_workgroup.grafana
```

설정:

```text
name = var.athena_workgroup_name
engine = Athena engine version 3
result = s3://<RESULT_BUCKET>/results/
enforce_workgroup_configuration = true
publish_cloudwatch_metrics_enabled = true
bytes_scanned_cutoff_per_query = var.athena_scan_cutoff_bytes
tag GrafanaDataSource = true
```

## Workspace Role

Resource:

```text
aws_iam_role.grafana_workspace
aws_iam_role_policy_attachment.grafana_athena
aws_iam_role_policy.grafana_source_read
```

Trust:

```text
Service = grafana.amazonaws.com
Action = sts:AssumeRole
```

Managed Policy:

```text
arn:aws:iam::aws:policy/service-role/AmazonGrafanaAthenaAccess
```

Inline Source Read:

```text
s3:GetBucketLocation
s3:ListBucket
s3:GetObject
```

허용 Prefix:

```text
AWSLogs/433048100798/CloudFront/*
alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/*
vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/*
```

`ListBucket`에는 Prefix 자체와 `*` 하위를 모두 넣는다. Security Log Bucket의 Write·Delete, CloudTrail Prefix, Application Bucket은 허용하지 않는다.

## Workspace

Resource:

```text
aws_grafana_workspace.security
aws_grafana_role_association.admin
```

설정:

```hcl
account_access_type      = "CURRENT_ACCOUNT"
authentication_providers = ["AWS_SSO"]
permission_type          = "CUSTOMER_MANAGED"
role_arn                 = aws_iam_role.grafana_workspace.arn
grafana_version          = "12.4"
configuration = jsonencode({
  plugins = {
    pluginAdminEnabled = true
  }
})
```

작성하지 않음:

```text
data_sources
vpc_configuration
network_access_control
```

Admin Association:

```text
role = ADMIN
user_ids = var.grafana_admin_user_ids
group_ids = var.grafana_admin_group_ids
```

IAM User Name·ARN은 넣지 않는다.

## Outputs

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

중단:

- Account 불일치
- Foundation State·Output 없음
- 기존 Foundation·Daily Resource 변경
- Security Log Bucket 변경
- Admin Identity Center ID 없음

첫 Pass에서는 Apply하지 않는다.

---

# Task 3 — `analytics/grafana`

생성:

```text
analytics/grafana/versions.tf
analytics/grafana/providers.tf
analytics/grafana/variables.tf
analytics/grafana/main.tf
analytics/grafana/security-overview.json
```

## Provider

```text
grafana/grafana ~> 4.40.0
```

인증은 환경변수만 사용한다.

```text
GRAFANA_URL
GRAFANA_AUTH
```

Token을 HCL·tfvars·Output에 기록하지 않는다.

## Resource

```text
grafana_data_source.athena
grafana_folder.security
grafana_dashboard.security_overview
```

Athena Data Source:

```text
name = AWS Topology Athena
uid = aws-topology-athena
type = grafana-athena-datasource
```

```json
{
  "authType": "default",
  "defaultRegion": "ap-northeast-2",
  "catalog": "AwsDataCatalog",
  "database": "aws_topology_security",
  "workgroup": "aws-topology-grafana"
}
```

Folder:

```text
Title = AWS Topology Security
UID = aws-topology-security
```

Dashboard:

```text
Title = AWS Topology Security Overview
UID = aws-topology-security-overview
Default Range = 최근 6시간
Auto Refresh = Off
```

필수 Panel:

1. CloudFront 요청·4xx·5xx Time Series
2. ALB 4xx·5xx Top Source
3. VPC REJECT Top Source·Destination Port

공통:

- Grafana Time Filter 필수
- 전체 기간 Scan 금지
- Cookie·Authorization·Query String·Body 미표시

Request Trace Panel은 선택이다.

검증:

```powershell
terraform -chdir=analytics/grafana fmt -check
terraform -chdir=analytics/grafana init
terraform -chdir=analytics/grafana validate
```

Grafana Plan은 Workspace와 임시 Token 생성 후 실행한다.

---

# Task 4 — Wrapper

생성:

```text
analytics/setup-analytics.ps1
analytics/destroy-analytics.ps1
analytics/README.md
```

## Setup

기본은 Preview다.

```text
AWS Identity 확인
→ analytics/aws fmt·init·validate·plan
→ Plan 요약
→ 승인 없으면 종료
→ analytics/aws apply
→ Workspace ACTIVE 대기
→ 임시 ADMIN Service Account 생성
→ TTL 3600초 Token 생성
→ GRAFANA_URL·GRAFANA_AUTH 설정
→ grafana-athena-datasource Plugin 확인·필요 시 설치
→ analytics/grafana init·validate·plan·apply
→ Data Source Health·Dashboard UID 확인
→ finally에서 Token 삭제
→ finally에서 Service Account 삭제
```

승인 문구:

```text
APPLY ANALYTICS
```

AWS API:

```text
CreateWorkspaceServiceAccount
CreateWorkspaceServiceAccountToken
DeleteWorkspaceServiceAccountToken
DeleteWorkspaceServiceAccount
```

`aws_grafana_workspace_service_account_token` Resource는 사용하지 않는다.

## Destroy

```text
임시 Token 생성
→ analytics/grafana destroy
→ Token·Service Account 삭제
→ analytics/aws destroy
```

승인 문구:

```text
DESTROY ANALYTICS
```

Foundation·Daily State를 변경하지 않는다.

---

# Task 5 — S3·Athena 검증

생성:

```text
observability/Test-SecurityLogSources.ps1
```

입력:

```text
AwsProfile, ExpectedAccountId, FoundationRoot,
MapPath, StartUtc, EndUtc, EvidenceRoot
```

각 Grafana Source에서 확인:

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

# Task 6 — Pod Identity Trust·Matrix

생성:

```text
pod-identity-trust.tf
observability/Export-PodIdentityMatrix.ps1
observability/Test-PodIdentityRuntime.ps1
```

## Custom Role Trust

대상:

| Key | Namespace | ServiceAccount |
|---|---|---|
| `primary-fluent-bit` | `amazon-cloudwatch` | `aws-for-fluent-bit` |
| `dr-fluent-bit` | `amazon-cloudwatch` | `aws-for-fluent-bit` |
| `primary-efs-csi` | `kube-system` | `efs-csi-controller-sa` |
| `dr-efs-csi` | `kube-system` | `efs-csi-controller-sa` |
| `primary-web-s3` | `var.web_namespace` | `var.web_service_account` |
| `dr-web-s3` | `var.web_namespace` | `var.web_service_account` |

Trust:

```text
Principal.Service = pods.eks.amazonaws.com
Action = sts:AssumeRole, sts:TagSession
StringEquals aws:RequestTag/kubernetes-namespace
StringEquals aws:RequestTag/kubernetes-service-account
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

- 현재 Module Version의 Schema 확인
- 지원하면 LBC·ExternalDNS에 `trust_policy_conditions` 추가
- 조건 추가만을 위한 Module Upgrade·Fork 금지
- Karpenter는 첫 Pass에서 Inventory만 작성

## Matrix

필드:

```text
cluster, namespace, service_account, association_id,
role_arn, managed_policies, inline_policies, status
```

상태:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
```

---

# Task 7 — Pod Identity Runtime Script

첫 Pass에서는 Script만 작성하고 실행하지 않는다.

활성 Workload 검증:

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

대표 허용 Probe:

| Workload | Probe |
|---|---|
| AWS LBC | `elasticloadbalancing:DescribeLoadBalancers` |
| ExternalDNS | `route53:ListResourceRecordSets` |
| Fluent Bit | `logs:DescribeLogStreams` |
| EFS CSI | `elasticfilesystem:DescribeFileSystems` |
| Web S3 | `s3:GetBucketLocation` |
| Karpenter | Module Policy의 Read Action 1개 |

Write Canary 승인 문구:

```text
RUN POD IDENTITY S3 CANARY
```

No-Association ServiceAccount에서도 `sts get-caller-identity`를 실행한다.

- Credential 없음: 격리 확인
- Node Role 반환: IAM 최소 권한 미완료, 별도 IMDS 보정 Plan 필요

첫 Pass에서 Node·Karpenter Metadata Option은 변경하지 않는다.

출력:

```text
<evidence>/pod-identity-matrix.json
<evidence>/pod-identity-runtime.json
```

Access Key·Secret·Session Token은 기록하지 않는다.

---

# Task 8 — Static Test

생성:

```text
tests/test-analytics-contract.ps1
tests/test-pod-identity-contract.ps1
```

Analytics Test:

- Result Bucket Prefix·암호화·Public Block·Lifecycle
- Workgroup Result Location·Scan Cutoff·`GrafanaDataSource=true`
- Workspace `AWS_SSO`, `CURRENT_ACCOUNT`, `CUSTOMER_MANAGED`, `12.4`
- Workspace Configuration의 Plugin Management
- Workspace Resource에 `data_sources` 없음
- Role에 `AmazonGrafanaAthenaAccess`
- Source Read가 세 Prefix로 제한
- Security Bucket Write·Delete 없음
- Terraform Source에 Token Resource 없음
- Grafana Provider `~> 4.40.0`
- Data Source·Folder·Dashboard UID 고정
- 필수 Panel 3개에 Time Filter

Pod Identity Test:

- Custom Trust의 Service Principal·두 STS Action·두 Request Tag Condition
- Fluent Bit Log Group 범위
- Web S3 `web/*` 범위
- ExternalDNS Hosted Zone 범위
- 휴면 Toggle 기본값 `false`
- 승인 없이 Write Canary 실행 금지
- Diagnostic Image에 `latest` 없음
- Credential 출력 금지

---

# Task 9 — 첫 Codex Pass 종료

수행:

```text
Task 1~6, 8 Source 작성
Task 7 Script 작성만 수행
PowerShell Parser·Static Test
terraform fmt
terraform validate
analytics/aws Fresh Plan
```

금지:

```text
terraform apply
AWS Resource Mutation
Organizations·IAM Identity Center 변경
kubectl Mutation
S3 Write Canary
Secret·Token·tfstate·tfplan Commit
```

보고:

```text
변경 파일
Provider Schema·선택 Version
fmt·validate·test 결과
analytics/aws Plan Resource 목록
Foundation·Daily 변경 0건 여부
Module Trust Condition 지원 여부
사람 Gate
Runtime 검증 항목
```

## Codex 시작 Prompt

```text
Repository: Unoh03/bank-security-lab-infra
Base: main
Branch: codex/observability-iam

OBSERVABILITY-IAM-DECISIONS.md와
OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 먼저 읽어라.

IMPLEMENTATION PLAN의 Task 1~6과 Task 8을 구현하라.
Task 7은 안전한 Script만 작성하고 실행하지 마라.
Task 9의 금지사항을 지켜라.

끝나면 변경 파일, Provider Version·Schema 확인, Test 결과,
Fresh Plan, 기존 Resource 영향, 사람 Gate, Runtime 검증 항목을
분리해서 보고하라.
```
