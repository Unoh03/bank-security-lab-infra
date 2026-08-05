# S3 로그 분석·Grafana·EKS Pod Identity 구현 계획

> 상태: **구현 설계 완료 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 대상 저장소: `Unoh03/bank-security-lab-infra`  
> 대상 Account: `433048100798`  
> Primary Region: `ap-northeast-2`  
> DR Region: `ap-northeast-1`

이 문서는 다음 세 요구사항을 구현 가능한 계약으로 고정하고, 이후 Codex가 저장소를 수정할 때 사용하는 단일 인수인계서이자 완료 체크리스트다.

1. S3에 저장된 보안 로그를 Athena로 분석하고 Amazon Managed Grafana에서 시각화한다.
2. AWS API를 호출하는 EKS Workload별로 EKS Pod Identity를 적용하고 최소 권한을 검증한다.
3. S3 보안 로그를 Log Source별 경로로 분리하고, 실제 Object와 Athena Table의 연결을 검증한다.

Terraform Source가 존재한다는 이유만으로 완료 처리하지 않는다.

```text
요구사항 정의
→ Source 구현
→ Terraform Plan 검토
→ 승인된 AWS Apply
→ Runtime 검증
→ Evidence 수집
→ Dashboard 시연과 설명
```

---

## 1. 요구사항 계약

### OBS-01 — S3 보안 로그 분석 및 Grafana 시각화

CloudFront, Primary ALB, Primary VPC REJECT Flow Logs를 전용 S3 보안 로그 Bucket에 저장한다. 각 Log Source를 Athena External Table로 조회하고, Amazon Managed Grafana의 Athena Data Source와 연결하여 요청량, 오류 상태 및 거부 Network Traffic을 Dashboard로 시각화한다.

완료 조건:

- S3에 세 Log Source의 실제 Object가 존재한다.
- Athena Database와 세 External Table이 존재한다.
- 각 Table의 제한된 시간창 Query가 실제 행을 반환한다.
- 별도 Athena Workgroup이 Grafana Query 결과 위치와 Scan 제한을 강제한다.
- Amazon Managed Grafana Workspace가 Athena Data Source를 정상 조회한다.
- 최소 Dashboard 1개와 Panel 4개가 생성된다.
- 승인된 실험 요청이 Athena Query와 Dashboard에 모두 나타난다.
- Screenshot, Query 결과, Resource Inventory를 Evidence로 보존한다.

### IAM-01 — EKS Workload별 Pod Identity

AWS API를 호출하는 각 EKS Workload에 전용 Kubernetes ServiceAccount를 할당하고, 해당 ServiceAccount를 최소 권한 IAM Role과 EKS Pod Identity Association으로 연결한다.

`Pod 하나마다 Role 하나`를 생성하는 요구사항이 아니다. Association 단위는 다음이다.

```text
EKS Cluster + Namespace + Kubernetes ServiceAccount
→ EKS Pod Identity Association
→ IAM Role
→ 해당 ServiceAccount를 사용하는 Pod의 Temporary Credential
```

완료 조건:

- AWS API를 호출하는 모든 Workload가 Inventory에 기록된다.
- 각 Workload의 Cluster, Namespace, ServiceAccount, IAM Role, 허용 Action, 허용 Resource가 식별된다.
- Association과 ServiceAccount가 Runtime에서 일치한다.
- 진단 Pod에서 예상 Role Session을 확인한다.
- 대표 허용 Read API가 성공한다.
- 대표 비허용 Read API가 `AccessDenied`로 실패한다.
- Association이 없는 ServiceAccount가 Node Role을 획득하지 못한다.
- AWS API가 필요 없는 Workload에는 Association을 만들지 않는다.

### LOG-01 — S3 Log Source 분리

Application Data와 분리된 전용 S3 보안 로그 Bucket을 사용한다. 각 S3 Log Source는 서로 겹치지 않는 Prefix 또는 AWS Service 고유 Subtree로 구분한다.

완료 조건:

- Source, Region, Bucket, Prefix, 작성 Principal, Retention, Athena Table을 기계 판독 가능한 Mapping으로 기록한다.
- 각 Source Prefix에서 실제 Object를 최소 1개 확인한다.
- 각 Athena Table의 `LOCATION`이 Mapping의 Prefix와 일치한다.
- Grafana Workspace Role은 Dashboard에 필요한 Source Prefix만 읽을 수 있다.
- Security Log Bucket과 Application Bucket을 혼용하지 않는다.

### DEMO-01 — 구성 결과 시연

다음 내용을 화면과 Runtime 출력으로 설명할 수 있어야 한다.

- Log가 생성되어 S3 Prefix에 도착하는 흐름
- S3 Object를 Athena Table이 읽는 흐름
- Grafana가 Workspace IAM Role로 Athena Query를 실행하는 흐름
- ServiceAccount가 Pod Identity를 통해 IAM Role을 획득하는 흐름
- 허용 API와 비허용 API의 차이

---

## 2. 현재 Source 기준 감사 결과

### 2.1 이미 존재하는 S3·Athena 기반

Persistent Foundation에는 다음이 존재한다.

- 전용 S3 Security Log Bucket
- Versioning
- SSE-S3 (`AES256`)
- S3 Public Access Block
- 30일 Lifecycle
- CloudTrail S3 Delivery
- CloudFront Standard Logging v2 Destination
- Primary ALB Access Log Prefix 허용
- Primary VPC REJECT Flow Log Prefix 허용

현재 경로 계약:

| Source | Region | S3 Prefix Template | Athena Table |
|---|---|---|---|
| CloudFront | Global | `AWSLogs/<ACCOUNT_ID>/CloudFront/` | `cloudfront_access` |
| Primary ALB | `ap-northeast-2` | `alb/primary/AWSLogs/<ACCOUNT_ID>/elasticloadbalancing/ap-northeast-2/` | `alb_primary_access` |
| Primary VPC REJECT | `ap-northeast-2` | `vpc-flow/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/ap-northeast-2/` | `vpc_reject` |
| CloudTrail | Multi-Region | `AWSLogs/<ACCOUNT_ID>/CloudTrail/` | Phase 1 Grafana 대상 아님 |

기존 Athena 구성:

- Database 기본값: `aws_topology_security`
- 기존 Query Pack: `observability/Invoke-AthenaQueryPack.ps1`
- 기존 DDL: `observability/queries/athena/00_create_security_log_tables.sql`
- 기존 Query:
  - ALB 4xx·5xx
  - VPC REJECT
  - CloudFront Request Trace
  - ALB Trace ID Correlation
  - ALB Security Window

주의:

- DDL Source와 Query Pack이 존재하는 것과 AWS Glue/Athena Runtime에 Table이 실제 존재하는 것은 다르다.
- 현재 DDL 주석에는 Athena 실행이 승인 대기 상태로 기록돼 있다.
- 구현 전 `get-database`, `get-table-metadata`, 제한 Query로 Runtime 상태를 다시 확인한다.

### 2.2 현재 CloudWatch Logs 전용 Source

다음은 Phase 1에서 S3가 아니라 CloudWatch Logs에 유지한다.

| Source | Log Group |
|---|---|
| CloudTrail 복제 | `/aws/cloudtrail/aws-topology-security` |
| Primary EKS Control Plane | `/aws/eks/aws-topology-primary/cluster` |
| Primary DVWA | `/aws/eks/aws-topology-primary/dvwa` |
| DR DVWA | `/aws/eks/aws-topology-dr/dvwa` |
| WAF | `aws-waf-logs-aws-topology-edge` |
| GuardDuty Finding | `/aws/events/aws-topology-guardduty-findings` |

이 Source들을 S3로 이중 보존하는 Firehose·Lambda·Subscription Filter는 이번 범위에 포함하지 않는다.

의사결정 Gate:

> 교육 요구사항이 `S3에 저장되는 로그를 Source별로 분리`인지, `모든 Resource 로그를 반드시 S3에 저장`인지 확인한다. 후자라는 명시적 확인이 있을 때만 CloudWatch Logs → S3 장기 보존 경로를 별도 설계한다.

### 2.3 현재 Pod Identity 기반

현재 Source에서 확인되는 Association 대상:

| Workload | Primary | DR | 조건 |
|---|---:|---:|---|
| Karpenter Controller | 있음 | 조건부 있음 | EKS Module 관리 |
| AWS Load Balancer Controller | 있음 | 조건부 있음 | DR Runtime 활성 시 |
| ExternalDNS | Domain 사용 시 | 조건부 있음 | DR ExternalDNS Toggle 필요 |
| AWS for Fluent Bit | 있음 | 조건부 있음 | DVWA Log Collection 활성 시 |
| EFS CSI Controller | 조건부 있음 | 조건부 있음 | `enable_efs=true` |
| DVWA Web S3 | 휴면 | 휴면 | `enable_web_s3_pod_identity=true` |

현재 Source만으로 확정할 수 없는 부분:

- AWS Runtime에 Association이 실제 존재하는가
- 실제 Pod의 ServiceAccount가 예상값인가
- Pod 내부 Credential이 예상 Role인가
- 비허용 API가 거부되는가
- Association 없는 Pod가 EC2 Node Role을 획득할 수 없는가

---

## 3. 핵심 Architecture 결정

### 3.1 Analytics를 Foundation과 Daily에서 분리

Amazon Managed Grafana는 다음 이유로 별도 Lifecycle을 사용한다.

- Daily Runtime처럼 매일 생성·삭제할 대상이 아니다.
- Foundation처럼 반드시 영구 보존해야 하는 핵심 경계도 아니다.
- Active User, Athena Scan, Query Result Storage 비용이 발생하는 선택 기능이다.
- Grafana Content는 AWS Resource와 다른 Provider·Credential Lifecycle을 사용한다.

목표 구조:

```text
foundation/
└─ Persistent Security Log Bucket·CloudTrail·Log Groups

Repository Root
└─ Daily VPC·EKS·ALB·CloudFront·Flow Logs

analytics/aws/
├─ Amazon Managed Grafana Workspace
├─ Workspace IAM Role
├─ Athena Workgroup
└─ Athena Query Result Bucket

analytics/grafana/
├─ Athena Data Source
├─ Dashboard Folder
└─ Security Dashboard
```

State 경계:

| Root | State | Destroy 정책 |
|---|---|---|
| `foundation/` | 기존 별도 Local State | 일반 Daily Down에서 보존 |
| Repository Root | 기존 Daily State | `daily-down.ps1` 대상 |
| `analytics/aws/` | 신규 별도 State | 명시적 Analytics Down만 허용 |
| `analytics/grafana/` | 신규 별도 State | Workspace Content만 관리 |

`daily-down.ps1`은 Analytics State를 읽거나 삭제하지 않는다.

### 3.2 IAM User와 Grafana Login을 분리

Amazon Managed Grafana Workspace 사용자 인증은 IAM Identity Center 또는 SAML을 사용한다. 현재 생성한 조원 IAM User를 Grafana Workspace User로 직접 할당할 수 없다.

따라서 Phase 0에서 다음 중 하나를 사람이 결정해야 한다.

- `AWS_SSO`: IAM Identity Center Integrated Directory에 사용자·그룹 생성
- `SAML`: 별도 IdP 연동

이번 구현안은 `AWS_SSO`를 기본 경로로 설계한다.

중요:

- IAM Identity Center·AWS Organizations 활성화는 Account 수준 결정이다.
- Codex나 Terraform이 임의로 활성화하지 않는다.
- 최소 한 명의 IAM Identity Center User ID 또는 Group ID가 확보될 때까지 Grafana Apply를 중단한다.

### 3.3 기존 Athena Table 소유권을 즉시 Terraform으로 이전하지 않음

기존 DDL은 `CREATE ... IF NOT EXISTS` 방식이다. 이미 생성됐을 수 있는 Glue Table을 신규 `aws_glue_catalog_table` Resource로 바로 선언하면 Import·State Migration 문제가 생긴다.

Phase 1 원칙:

- 기존 SQL DDL과 Query Pack을 유지한다.
- Runtime에 Table이 없을 때만 승인된 `-CreateSchema` 실행으로 생성한다.
- Table Terraform화는 별도 Migration 작업으로 분리한다.

---

## 4. 목표 파일 구조

Codex는 다음 구조를 기준으로 구현한다.

```text
analytics/
├─ README.md
├─ aws/
│  ├─ versions.tf
│  ├─ providers.tf
│  ├─ main.tf
│  ├─ storage.tf
│  ├─ athena.tf
│  ├─ iam.tf
│  ├─ grafana.tf
│  ├─ variables.tf
│  └─ outputs.tf
├─ grafana/
│  ├─ versions.tf
│  ├─ providers.tf
│  ├─ variables.tf
│  ├─ data-source.tf
│  └─ dashboards.tf
├─ dashboards/
│  └─ security-log-overview.json
└─ scripts/
   ├─ setup-analytics.ps1
   └─ destroy-analytics.ps1

observability/
├─ log-source-map.json
├─ pod-identity/
│  ├─ Export-PodIdentityMatrix.ps1
│  └─ Test-PodIdentityRuntime.ps1
└─ s3/
   └─ Test-SecurityLogSources.ps1

tests/
├─ test-analytics-contract.ps1
└─ test-pod-identity-contract.ps1
```

첫 구현 Pass에서는 기존 파일의 대규모 재배치를 하지 않는다.

---

## 5. `analytics/aws` Terraform 계약

### 5.1 Provider와 기본값

- Terraform: 기존 저장소와 동일하게 `>= 1.8.0`
- AWS Provider: 기존 Foundation과 동일 Major인 `~> 6.0`
- Region: `ap-northeast-2`
- AWS Profile 기본값: `terra-user`
- Expected Account 기본값: `433048100798`
- 공통 Tag:
  - `Project = aws-topology`
  - `ManagedBy = Terraform`
  - `Lifecycle = optional-analytics`

모든 Plan 전에 `aws_caller_identity` Check로 Account를 검증한다.

### 5.2 변수 계약

| Variable | Type | Default | Validation·의미 |
|---|---|---|---|
| `aws_profile` | string | `terra-user` | 빈 값이면 기본 Credential Chain |
| `expected_account_id` | string | `433048100798` | 실제 Account와 불일치 시 실패 |
| `primary_region` | string | `ap-northeast-2` | Analytics Region |
| `project_name` | string | `aws-topology` | Resource Naming |
| `foundation_state_path` | string | `../../foundation/terraform.tfstate` | Security Bucket Output Source |
| `athena_database_name` | string | `aws_topology_security` | 기존 Database 재사용 |
| `athena_workgroup_name` | string | `aws-topology-grafana` | Grafana 전용 Workgroup |
| `athena_scan_cutoff_bytes` | number | `104857600` | 100 MiB, 최소 10 MB 이상 |
| `query_result_retention_days` | number | `7` | 1~30일 |
| `grafana_workspace_name` | string | `aws-topology-security` | Workspace 이름 |
| `grafana_admin_user_ids` | list(string) | `[]` | 최소 Admin 1명 필요 |
| `grafana_admin_group_ids` | list(string) | `[]` | User 또는 Group 중 하나 이상 필요 |
| `grafana_editor_user_ids` | list(string) | `[]` | 선택 |
| `grafana_viewer_user_ids` | list(string) | `[]` | 선택 |
| `tags` | map(string) | `{ Environment = "training" }` | 공통 Tag 확장 |

Precondition:

```text
length(grafana_admin_user_ids) + length(grafana_admin_group_ids) >= 1
```

### 5.3 Athena Query Result Bucket

Resource 이름 예시:

```text
aws_s3_bucket.grafana_athena_results
```

계약:

- Bucket Prefix: `grafana-athena-query-results-`
- Object Ownership: Bucket owner enforced
- Public Access Block: 전부 `true`
- Encryption: SSE-S3
- Versioning: 불필요, 기본 비활성
- Lifecycle:
  - Current Object 7일 후 만료
  - Incomplete Multipart Upload 1일 후 중단
- Application Data나 Security Source Log를 저장하지 않는다.
- 이 Bucket은 Athena Query Result 전용이다.
- Analytics 명시적 Destroy를 위해 `force_destroy=true`를 허용할 수 있다.
- 기존 `foundation.aws_s3_bucket.security_logs`에는 어떤 변경도 하지 않는다.

### 5.4 Athena Workgroup

Resource 이름 예시:

```text
aws_athena_workgroup.grafana
```

계약:

- Name: `aws-topology-grafana`
- State: `ENABLED`
- Engine: Athena Engine Version 3
- Result Location: `s3://<RESULT_BUCKET>/results/`
- Encryption: `SSE_S3`
- `enforce_workgroup_configuration = true`
- `publish_cloudwatch_metrics_enabled = true`
- `bytes_scanned_cutoff_per_query = 104857600`
- Tag: `GrafanaDataSource = true`

의도:

- Grafana Query가 임의 Result Location을 사용하지 못하게 한다.
- Query 하나가 100 MiB보다 많이 Scan하면 취소한다.
- Dashboard 기본 시간 범위를 짧게 유지한다.

### 5.5 Grafana Workspace IAM Role

Trust:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "grafana.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}
```

연결 정책:

1. AWS Managed Policy

```text
arn:aws:iam::aws:policy/service-role/AmazonGrafanaAthenaAccess
```

2. Customer Managed Inline Policy — Source Log Read

Bucket Level:

- `s3:GetBucketLocation`
- `s3:ListBucket`

`ListBucket`은 `s3:prefix` Condition으로 다음만 허용한다.

```text
AWSLogs/<ACCOUNT_ID>/CloudFront/*
alb/primary/AWSLogs/<ACCOUNT_ID>/elasticloadbalancing/ap-northeast-2/*
vpc-flow/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/ap-northeast-2/*
```

Object Level:

- `s3:GetObject`

대상도 위 세 Prefix Object ARN으로 제한한다.

명시적으로 제외:

- Application Bucket
- CloudTrail Prefix
- 다른 Region의 Log
- `s3:PutObject` on Security Source Bucket
- `s3:DeleteObject`
- IAM·EC2·EKS 변경 권한

AWS Managed `AmazonGrafanaAthenaAccess`가 Query Result Bucket Naming과 Athena·Glue 기본 권한을 담당하더라도, 원본 S3 Log 읽기 권한은 이 Custom Policy에서 별도로 부여한다.

### 5.6 Amazon Managed Grafana Workspace

Resource 이름 예시:

```text
aws_grafana_workspace.security
```

계약:

- Name: `aws-topology-security`
- Account Access: `CURRENT_ACCOUNT`
- Authentication Provider: `AWS_SSO`
- Permission Type: `CUSTOMER_MANAGED`
- Workspace Role: 위 전용 IAM Role
- Data Source 선언: Athena
- Plugin Management: 활성
- VPC Attachment: Phase 1에서는 사용하지 않음
- Network Allow List: Phase 1에서는 별도 제한하지 않음

Codex는 실제 구현 전에 현재 설치된 AWS Provider의 `terraform providers schema -json`과 공식 Resource 문서를 대조한다. Provider Schema와 이 계약이 충돌하면 임의로 필드를 추측하지 말고 Plan 문서에 차이를 기록한다.

### 5.7 Workspace Role Association

Resource:

```text
aws_grafana_role_association.admin
aws_grafana_role_association.editor
aws_grafana_role_association.viewer
```

- Admin: 최소 1개 User ID 또는 Group ID 필수
- Editor·Viewer: 값이 있을 때만 생성
- 기존 IAM User 이름이나 ARN을 넣지 않는다.
- 입력값은 IAM Identity Center Directory User ID·Group ID다.

### 5.8 Output 계약

최소 Output:

- `grafana_workspace_id`
- `grafana_workspace_arn`
- `grafana_workspace_endpoint`
- `grafana_workspace_version`
- `grafana_workspace_role_arn`
- `athena_workgroup_name`
- `athena_result_bucket_name`
- `athena_database_name`
- `security_log_bucket_name`

Secret이나 Token은 Output하지 않는다.

---

## 6. `analytics/grafana` Terraform 계약

### 6.1 Provider Authentication

Grafana Provider는 다음 Environment Variable로만 인증한다.

```text
GRAFANA_URL
GRAFANA_AUTH
```

Provider Block이나 `tfvars`에 Token을 기록하지 않는다.

권장 자동화:

```text
AWS CLI로 임시 ADMIN Service Account 생성
→ TTL 3600초 Token 생성
→ GRAFANA_URL·GRAFANA_AUTH를 현재 Process 환경에만 설정
→ terraform apply
→ finally에서 Token 삭제
→ finally에서 임시 Service Account 삭제
```

다음 Resource는 Analytics Terraform State에 선언하지 않는다.

- `aws_grafana_workspace_api_key`
- `aws_grafana_workspace_service_account_token`
- 장기 Grafana Token

이유:

- 발급된 Token 값이 Terraform State에 남을 수 있다.
- 자동화 Token은 1시간 이하의 임시 Credential이면 충분하다.

Service Account와 Token 삭제는 성공·실패 여부와 무관하게 `finally`에서 실행한다.

### 6.2 Plugin Gate

Athena Plugin ID:

```text
grafana-athena-datasource
```

Setup Script는 다음 순서로 처리한다.

1. Workspace Grafana Version 확인
2. Plugin 설치 상태 조회
3. 미설치 시 Plugin Management API 또는 AWS 지원 경로로 설치
4. 설치 완료 Polling
5. 그 뒤에만 Grafana Terraform Apply

Plugin이 설치되지 않았는데 Data Source Apply를 시도하지 않는다.

### 6.3 Athena Data Source

Resource:

```text
grafana_data_source.athena_security
```

고정 식별자:

- Name: `AWS Topology Athena`
- UID: `aws-topology-athena`
- Type: `grafana-athena-datasource`

`json_data_encoded` 계약:

```json
{
  "authType": "default",
  "defaultRegion": "ap-northeast-2",
  "catalog": "AwsDataCatalog",
  "database": "aws_topology_security",
  "workgroup": "aws-topology-grafana"
}
```

Codex는 설치된 Plugin Version의 Schema를 확인해 정확한 Key 이름을 검증한다. 인증 Key·Secret은 Data Source에 저장하지 않는다. Workspace IAM Role의 Default Credential을 사용한다.

### 6.4 Folder와 Dashboard

Folder:

- Title: `AWS Topology Security`
- UID: `aws-topology-security`

Dashboard:

- Title: `AWS Topology Security Overview`
- UID: `aws-topology-security-overview`
- Tags: `aws`, `security`, `athena`, `training`
- Time Zone: Browser
- 기본 Time Range: 최근 6시간
- 자동 Refresh: 비활성
- `overwrite = true`

Dashboard JSON은 `analytics/dashboards/security-log-overview.json`에 보존한다.

---

## 7. Dashboard Panel 계약

### Panel 1 — CloudFront 요청량과 Status Class

Type: Time series

필수 Series:

- Total Requests
- 4xx
- 5xx

Query Shape:

```sql
WITH base AS (
  SELECT
    from_iso8601_timestamp(concat(date, 'T', time, 'Z')) AS event_time,
    CAST("sc-status" AS integer) AS status
  FROM aws_topology_security.cloudfront_access
)
SELECT
  date_trunc('minute', event_time) AS time,
  count(*) AS total_requests,
  sum(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS http_4xx,
  sum(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END) AS http_5xx
FROM base
WHERE $__timeFilter(event_time)
GROUP BY 1
ORDER BY 1 ASC
```

완료 판정:

- Time Column이 Timestamp로 반환된다.
- Numeric Series 3개가 렌더링된다.
- Query Inspector의 확장 SQL을 Evidence로 저장한다.

### Panel 2 — ALB 4xx·5xx Top Source

Type: Bar chart 또는 Table

필드:

- `client_ip`
- `error_count`
- `elb_4xx`
- `elb_5xx`
- `target_5xx`

제한:

- Time Filter 필수
- Status 400 이상만 대상
- 상위 10개
- Source IP를 외부 공개 산출물에 그대로 포함할지 검토하고 필요 시 Masking

### Panel 3 — VPC REJECT Top Source·Destination Port

Type: Table 또는 Bar chart

필드:

- `srcaddr`
- `dstport`
- `protocol`
- `reject_count`
- `bytes`

제한:

- `action = 'REJECT'`
- `from_unixtime(start)` 기준 Time Filter
- 상위 20개

### Panel 4 — 최근 CloudFront Request Trace

Type: Table

필드:

- Event Time
- Client IP
- Method
- Path
- Status
- Protocol
- Edge Request ID
- Time Taken

제한:

- 최근 100행
- 시간 역순
- Cookie, Query String, Authorization Header, Request Body 미표시

### Dashboard 비용 제어

- 기본 Auto Refresh 없음
- 기본 범위 최근 6시간
- Panel마다 Time Filter 필수
- Query Result Reuse는 Plugin·Athena Engine 3 확인 후 선택 적용
- Workgroup 100 MiB Scan Cutoff 유지
- 전체 기간 Scan을 유도하는 Dashboard Variable 금지

---

## 8. S3 Log Source Mapping 계약

`observability/log-source-map.json`은 다음 Schema를 사용한다.

```json
{
  "schema_version": 1,
  "account_id": "433048100798",
  "sources": [
    {
      "id": "cloudfront",
      "service": "CloudFront",
      "region": "global",
      "storage": "s3",
      "bucket_output": "security_log_bucket_name",
      "prefix": "AWSLogs/433048100798/CloudFront/",
      "athena_database": "aws_topology_security",
      "athena_table": "cloudfront_access",
      "grafana_phase_1": true,
      "retention_days": 30
    }
  ]
}
```

필수 Source:

- `cloudfront`
- `alb-primary`
- `vpc-reject-primary`
- `cloudtrail`
- `waf-cloudwatch`
- `eks-control-primary-cloudwatch`
- `dvwa-primary-cloudwatch`
- `dvwa-dr-cloudwatch`
- `guardduty-findings-cloudwatch`

S3 Source는 `prefix`, `athena_table` 또는 `athena_table=null`을 가져야 한다. CloudWatch Source는 `log_group`을 사용하고 `grafana_phase_1=false`로 기록한다.

### `Test-SecurityLogSources.ps1`

입력:

- `AwsProfile`
- `ExpectedAccountId`
- `FoundationRoot`
- `StartUtc`
- `EndUtc`
- `MapPath`

검증 순서:

1. Caller Account 확인
2. Foundation Output에서 실제 Bucket 이름 확인
3. Map의 S3 Prefix별 `list-objects-v2 --max-items 1`
4. Object 0건이면 `NotObserved`로 기록하고 실패 원인을 추측하지 않음
5. Glue Database와 Table Metadata 확인
6. Table Location이 Map Prefix와 일치하는지 확인
7. 제한 시간창 `SELECT ... LIMIT` 실행
8. Query State, Rows, Scanned Bytes, Execution ID 기록
9. Security Log Bucket 외 Bucket은 읽지 않음

결과 파일:

```text
<evidence>/source/aws/s3-log-source-inventory.json
<evidence>/results/s3-log-source-verification.json
```

완료 조건은 세 Grafana 대상 Source가 모두 `ObjectObserved=true`, `TableLocationMatch=true`, `QuerySucceeded=true`인 것이다.

---

## 9. Pod Identity Inventory 계약

### 9.1 기대 Matrix

| ID | Cluster | Namespace | ServiceAccount | 역할 | 조건 |
|---|---|---|---|---|---|
| `primary-karpenter` | `aws-topology-primary` | `kube-system` | Module에서 확인 | Node Provisioning | 항상 |
| `dr-karpenter` | `aws-topology-dr` | `kube-system` | Module에서 확인 | DR Node Provisioning | DR Runtime |
| `primary-aws-lbc` | Primary | `kube-system` | `aws-load-balancer-controller` | ELB·EC2 Controller | 항상 |
| `dr-aws-lbc` | DR | `kube-system` | `aws-load-balancer-controller` | DR ELB·EC2 Controller | DR Runtime |
| `primary-external-dns` | Primary | `external-dns` | `external-dns` | 지정 Hosted Zone Upsert | Domain 사용 |
| `dr-external-dns` | DR | `external-dns` | `external-dns` | Failover DNS | DR + Toggle |
| `primary-fluent-bit` | Primary | `amazon-cloudwatch` | `aws-for-fluent-bit` | Primary DVWA Log Group 쓰기 | Log Collection |
| `dr-fluent-bit` | DR | `amazon-cloudwatch` | `aws-for-fluent-bit` | DR DVWA Log Group 쓰기 | DR + Log Collection |
| `primary-efs-csi` | Primary | `kube-system` | `efs-csi-controller-sa` | EFS CSI | EFS Toggle |
| `dr-efs-csi` | DR | `kube-system` | `efs-csi-controller-sa` | DR EFS CSI | DR + EFS Toggle |
| `primary-web-s3` | Primary | `dvwa` | `web-app` | Application Bucket `web/*` | IAM-01 Toggle |
| `dr-web-s3` | DR | `dvwa` | `web-app` | DR Bucket `web/*` | DR + IAM-01 Toggle |

AWS API가 필요 없는 대표 Workload는 `NoAssociationExpected`로 별도 기록한다.

- CoreDNS
- kube-proxy
- Argo CD 구성요소
- 기본 DVWA Pod (`enable_web_s3_pod_identity=false`)
- Application Redis 초기화 Pod 등

### 9.2 `Export-PodIdentityMatrix.ps1`

수집 대상:

- `aws eks list-pod-identity-associations`
- 각 Association의 `describe-pod-identity-association`
- IAM Role의 Trust Policy
- 연결 Managed Policy
- Inline Policy Name과 Document
- Private EKS API에 접근 가능한 Bastion에서:
  - `kubectl get serviceaccount -A`
  - `kubectl get pods -A -o json`
  - Pod별 ServiceAccount

출력:

```text
<evidence>/source/aws/pod-identity-associations.json
<evidence>/source/aws/pod-identity-role-policies.json
<evidence>/source/kubernetes/pod-service-account-inventory.json
<evidence>/results/pod-identity-matrix.json
<evidence>/results/pod-identity-matrix.md
```

Matrix 상태:

- `ConfiguredAndObserved`
- `ConfiguredButRuntimeAbsent`
- `RuntimeUnexpected`
- `DisabledByDesign`
- `NoAssociationExpected`

### 9.3 Trust Policy 검증

Custom Pod Identity Role은 최소 다음 Trust를 가져야 한다.

```text
Principal.Service = pods.eks.amazonaws.com
Action includes sts:AssumeRole
Action includes sts:TagSession
```

가능하면 Request Tag Condition으로 Cluster·Namespace·ServiceAccount를 제한한다. Terraform Module이 생성하는 Role은 현재 Module Version이 지원하는 Condition 설정을 먼저 조사한다. Module 내부를 임의로 Fork하지 않는다.

---

## 10. Pod Identity Runtime 검증 계약

### 10.1 진단 Pod 원칙

Controller Image에 AWS CLI를 설치하거나 기존 Pod를 수정하지 않는다. 동일 ServiceAccount를 사용하는 임시 Diagnostic Pod를 생성한다.

요구사항:

- AWS CLI Image Tag와 Digest를 고정한다.
- `latest` 금지
- Command 종료 후 Pod 삭제
- Secret, Access Key, Session Token 출력 금지
- `aws sts get-caller-identity`의 ARN·Account만 보존
- Private Cluster이므로 Bastion SSM Command에서 `kubectl` 실행

### 10.2 공통 검증 흐름

```text
Association 존재 확인
→ ServiceAccount 존재 확인
→ 동일 ServiceAccount Diagnostic Pod 생성
→ sts get-caller-identity
→ 예상 Role Session ARN 비교
→ 대표 허용 Read API
→ 대표 비허용 iam:ListUsers
→ 결과 저장
→ Diagnostic Pod 삭제
```

`iam:ListUsers`는 변경을 일으키지 않는 공통 Deny Probe다. 예상 밖 성공 시 즉시 실패 처리하고 상위 Policy·Node Credential 노출을 조사한다.

### 10.3 Workload별 대표 허용 Probe

| Workload | 대표 허용 Probe | 기대 결과 |
|---|---|---|
| Karpenter | `ec2:DescribeInstanceTypes` 또는 Module Policy의 Read Action | 성공 |
| AWS LBC | `elasticloadbalancing:DescribeLoadBalancers` | 성공 |
| ExternalDNS | 지정 Zone `route53:ListResourceRecordSets` | 성공 |
| Fluent Bit | 지정 Log Group `logs:DescribeLogStreams` | 성공 |
| EFS CSI | `elasticfilesystem:DescribeFileSystems` | 성공 |
| Web S3 | 지정 Bucket `s3:GetBucketLocation` | 성공 |

Write Action은 일반 검증에서 실행하지 않는다.

Web S3 Put/Get/Delete Canary는 다음 명시적 승인에서만 실행한다.

```text
RUN POD IDENTITY S3 CANARY
```

대상 Key는 반드시 다음 임시 Prefix 아래로 제한한다.

```text
web/canary/<EXPERIMENT_ID>/probe.txt
```

### 10.4 Node Role 격리 Negative Test

Association이 없는 전용 ServiceAccount를 만든다.

```text
Namespace: pod-identity-test
ServiceAccount: no-aws-role
```

Diagnostic Pod에서 `aws sts get-caller-identity`를 실행한다.

기대 결과:

```text
Credential을 찾지 못해 실패
```

실패 판정:

```text
Node Instance Profile Role ARN이 반환됨
```

이 경우 Pod Identity 자체가 동작하더라도 Credential Isolation 요구사항은 미충족이다.

후속 보정 후보:

- Managed Node Group Launch Template의 IMDSv2 강제
- `http_tokens = required`
- Container에서 Node IMDS에 도달하지 못하도록 Hop Limit 검토
- Karpenter `EC2NodeClass.spec.metadataOptions`에 동일 정책 적용
- `hostNetwork` Pod는 별도 예외로 기록

IMDS 설정 변경은 Node 교체를 일으킬 수 있으므로 Codex 첫 Pass에서 Apply하지 않는다. Fresh Plan과 교체 범위를 먼저 제시한다.

---

## 11. PowerShell Wrapper 계약

### `setup-analytics.ps1`

기본 동작은 Preview다.

```powershell
.\analytics\scripts\setup-analytics.ps1
```

순서:

1. `terraform fmt -check`
2. `terraform init`
3. Account·Foundation Output 확인
4. IAM Identity Center Admin ID 입력 확인
5. `analytics/aws` Plan 저장
6. 변경 Resource 요약
7. 비용 Resource 목록 출력
8. 확인 문구가 없으면 종료

실제 Apply 확인 문구:

```text
APPLY ANALYTICS
```

Apply 이후:

1. Athena Database·Table Runtime 확인
2. 없을 때만 기존 Query Pack의 승인된 Schema 생성
3. Workspace가 Active가 될 때까지 제한 Polling
4. 임시 Grafana Service Account·Token 생성
5. Plugin 확인·설치
6. `analytics/grafana` Plan·Apply
7. Data Source Health 확인
8. Dashboard UID 확인
9. `finally`에서 Token·Service Account 삭제

### `destroy-analytics.ps1`

명시적 확인 문구:

```text
DESTROY ANALYTICS
```

삭제 대상:

- Grafana Dashboard·Folder·Data Source State
- Amazon Managed Grafana Workspace
- Workspace IAM Role
- Grafana 전용 Athena Workgroup
- Query Result Bucket

보존 대상:

- Foundation Security Log Bucket
- CloudTrail
- Foundation Log Groups
- Daily Runtime State
- Existing Athena Database·Table
- Local Evidence

---

## 12. 구현 순서와 Stop Gate

### Phase 0 — 사람의 결정

- [ ] Amazon Managed Grafana 비용 사용 승인
- [ ] IAM Identity Center 또는 SAML 선택
- [ ] IAM Identity Center Admin User·Group ID 확보
- [ ] `모든 로그 S3 저장` 여부에 대한 교육 요구사항 확인
- [ ] Analytics Lifecycle을 Daily와 분리하는 결정 승인

Phase 0이 완료되지 않으면 Grafana Workspace Apply를 하지 않는다.

### Phase 1 — Source Inventory와 정적 계약

- [ ] 새 Directory·문서·Mapping File 생성
- [ ] 현재 S3 Prefix와 SQL `LOCATION` 대조
- [ ] 현재 Pod Identity Source Inventory 생성
- [ ] Static Test 작성
- [ ] `terraform fmt -check`
- [ ] `terraform validate`
- [ ] AWS 변경 없음

### Phase 2 — Analytics AWS Plan

- [ ] Result Bucket Source 작성
- [ ] Workgroup Source 작성
- [ ] Workspace IAM Role·Policy 작성
- [ ] Workspace·Role Association Source 작성
- [ ] Output 작성
- [ ] Fresh Plan 생성
- [ ] Security Log Bucket 변경 0건 확인
- [ ] Foundation State 변경 0건 확인
- [ ] Apply 금지, Plan과 Diff만 보고

### Phase 3 — 승인된 AWS Apply

- [ ] Account 확인
- [ ] Identity Center ID 확인
- [ ] Plan이 Phase 2 검토본과 동일한지 확인
- [ ] `APPLY ANALYTICS` 승인
- [ ] Workspace Active
- [ ] Workgroup·Result Bucket·IAM Role Runtime 확인

### Phase 4 — Grafana Content

- [ ] 임시 Service Account 생성
- [ ] TTL 3600초 Token 생성
- [ ] Athena Plugin 설치 확인
- [ ] Data Source Apply
- [ ] `Save & Test` 성공
- [ ] Folder·Dashboard Apply
- [ ] Dashboard 4개 Panel Query 성공
- [ ] Token·Service Account 삭제 확인

### Phase 5 — S3·Athena Runtime 검증

- [ ] CloudFront Object 관찰
- [ ] ALB Object 관찰
- [ ] VPC REJECT Object 관찰
- [ ] Table Location 일치
- [ ] 제한 Query 성공
- [ ] Scanned Bytes 기록
- [ ] Grafana와 Query 결과 대조

### Phase 6 — Pod Identity Runtime 검증

- [ ] Association Matrix 생성
- [ ] ServiceAccount·Pod Runtime 대조
- [ ] Role Session ARN 확인
- [ ] 허용 Probe 성공
- [ ] `iam:ListUsers` Deny
- [ ] No-Association SA Credential 실패
- [ ] IMDS 보정 필요 여부 판정

### Phase 7 — Evidence와 시연

- [ ] Resource Inventory JSON
- [ ] Terraform Plan Summary
- [ ] S3 Prefix Object Evidence
- [ ] Athena Query Metadata·Result
- [ ] Grafana Data Source Health
- [ ] Dashboard Screenshot
- [ ] Pod Identity Matrix
- [ ] Allowed·Denied Runtime 결과
- [ ] 최종 발표용 흐름도와 설명

---

## 13. Static Test 계약

### `tests/test-analytics-contract.ps1`

다음을 검사한다.

- Analytics가 별도 Root·State를 사용함
- Security Source Bucket을 생성·변경하지 않음
- Result Bucket Prefix가 `grafana-athena-query-results-`
- Result Bucket Public Block·Encryption·Lifecycle 존재
- Workgroup Tag `GrafanaDataSource=true`
- Workgroup Result Location 강제
- Scan Cutoff 최소 10 MB, 기본 100 MiB
- Workspace가 `AWS_SSO`, `CURRENT_ACCOUNT`, Customer Managed Role 사용
- 최소 Admin Role Association Validation
- Workspace Role이 `AmazonGrafanaAthenaAccess` 사용
- Source S3 Policy가 세 승인 Prefix만 읽음
- Source Bucket `PutObject`·`DeleteObject` 권한 없음
- Grafana Token Resource가 Terraform Source에 없음
- Dashboard UID·Data Source UID가 고정됨
- Dashboard 네 Query에 Time Filter가 있음
- Dashboard Auto Refresh가 비활성

### `tests/test-pod-identity-contract.ps1`

다음을 검사한다.

- 모든 Custom Trust Policy에 `pods.eks.amazonaws.com`
- `sts:AssumeRole`, `sts:TagSession`
- Expected Matrix와 Terraform Association 대조
- Fluent Bit Role이 지정 Log Group으로 제한됨
- Web S3 Role이 지정 Bucket `web/*`로 제한됨
- ExternalDNS가 지정 Hosted Zone으로 제한됨
- 휴면 Feature Toggle의 기본값이 `false`
- Runtime Test Script가 exact confirmation 없이 Write Canary를 실행하지 않음
- Diagnostic Pod Image에 `latest`가 없음
- Evidence에 Access Key·Secret·Session Token을 기록하지 않음

---

## 14. Definition of Done

### OBS-01

- [ ] Source 구현
- [ ] Static Test 성공
- [ ] Terraform Plan 검토
- [ ] Workspace Apply 성공
- [ ] Athena Data Source Health 성공
- [ ] Dashboard Panel 4개 렌더링
- [ ] 실험 시간창 데이터 표시
- [ ] Screenshot·Query Evidence 보존

### IAM-01

- [ ] Workload Inventory 완성
- [ ] Expected·Actual Association 차이 0건
- [ ] 대표 허용 API 성공
- [ ] 대표 비허용 API 거부
- [ ] No-Association Pod가 Node Role을 획득하지 못함
- [ ] Diagnostic Pod 제거
- [ ] Credential 미노출

### LOG-01

- [ ] Machine-readable Source Map 작성
- [ ] CloudFront Prefix Object 확인
- [ ] ALB Prefix Object 확인
- [ ] VPC REJECT Prefix Object 확인
- [ ] Athena Table Location 일치
- [ ] Grafana Role Source Read 범위 일치
- [ ] Application Bucket과 혼용 없음

### DEMO-01

- [ ] 구성 흐름을 5분 이내에 설명 가능
- [ ] Dashboard에서 실험 결과 확인 가능
- [ ] Pod Identity 허용·거부 결과 제시 가능
- [ ] Source와 Runtime Evidence를 구분해 설명 가능

---

## 15. Codex 첫 실행 지시문

아래 내용을 새 Codex Thread의 첫 Prompt로 사용한다.

```text
Repository: Unoh03/bank-security-lab-infra
Base branch: main

먼저 OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 전부 읽고 현재 Source와 대조하라.
작업 Branch는 codex/observability-iam-plan 으로 만든다.

이번 첫 Pass의 범위:
1. analytics/aws와 analytics/grafana의 Terraform Source 초안 작성
2. observability/log-source-map.json 작성
3. Pod Identity Matrix Export·Runtime Test Script의 안전한 초안 작성
4. test-analytics-contract.ps1과 test-pod-identity-contract.ps1 작성
5. README와 Wrapper Preview 경로 작성
6. terraform fmt -check, terraform validate, PowerShell Parser·Static Test 실행
7. Analytics AWS Fresh Plan 생성 가능 여부 확인

금지:
- terraform apply
- AWS Resource 생성·변경·삭제
- IAM Identity Center 또는 AWS Organizations 활성화
- 기존 Foundation·Daily State 수정
- Security Log Bucket 변경
- 실제 Pod Identity Write Canary 실행
- Token, Password, Access Key, Session Token, tfstate, tfplan Commit
- current Runtime에 kubectl mutation

첫 Pass 종료 시 보고:
- 변경 파일 목록
- 설계 문서와 달라진 점
- Provider Schema 확인 결과
- fmt/validate/test 결과
- Plan Resource 목록과 비용 발생 Resource
- Apply 전에 사람이 결정해야 하는 항목
- Runtime 검증이 필요한 항목

추측으로 완료 처리하지 말고 Source, Plan, Runtime, Evidence를 분리해서 표기하라.
```

---

## 16. 공식 참고 자료

- Amazon Managed Grafana IAM Identity Center 인증  
  <https://docs.aws.amazon.com/grafana/latest/userguide/authentication-in-AMG-SSO.html>
- Amazon Managed Grafana Athena Data Source  
  <https://docs.aws.amazon.com/grafana/latest/userguide/Athena-using-the-data-source.html>
- Athena Data Source Prerequisites  
  <https://docs.aws.amazon.com/grafana/latest/userguide/Athena-prereq.html>
- AWS Managed Policy `AmazonGrafanaAthenaAccess`  
  <https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonGrafanaAthenaAccess.html>
- EKS Pod Identity Association  
  <https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html>
- EKS Pod Identity IAM Role Trust Policy  
  <https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html>
- EKS Pod Identity 동작과 Credential 격리  
  <https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html>
- S3 Prefix  
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html>
- Terraform AWS Provider `aws_grafana_workspace`  
  <https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/grafana_workspace>
- Terraform AWS Provider `aws_grafana_role_association`  
  <https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/grafana_role_association>
- Terraform Grafana Provider  
  <https://registry.terraform.io/providers/grafana/grafana/latest/docs>

---

## 17. 현재 최종 판정

| 요구사항 | Source | Runtime | 시연 | 현재 판정 |
|---|---:|---:|---:|---|
| S3 Log Delivery | 상당 부분 존재 | 일부 과거 Evidence, 현재 재검증 필요 | 미완료 | 부분 충족 |
| Athena Schema·Query Pack | 존재 | 현재 재검증 필요 | 미완료 | 부분 충족 |
| Amazon Managed Grafana | 없음 | 없음 | 없음 | 미충족 |
| Pod Identity 구성 | 상당 부분 존재 | IAM-01 일부 외 전체 미검증 | 미완료 | 상당 부분 충족 |
| S3 Source 분리 | Prefix 설계 존재 | Object·Table 일괄 검증 필요 | 미완료 | 대부분 설계됨 |

가장 큰 빈칸은 Amazon Managed Grafana Workspace·Athena Data Source·Dashboard다. 그다음은 기존 Pod Identity와 S3 Prefix를 새로 늘리는 것이 아니라, Expected Matrix와 Runtime을 대조하고 허용·거부·Object 도착을 증명하는 작업이다.
