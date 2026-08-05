# Observability·Pod Identity 설계 결정

> 상태: **Grafana Cloud 경로 확정 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 실행 순서: [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)

## 최종 선택

```text
Grafana Cloud Free
├─ Athena Data Source
│  └─ S3: CloudFront, Primary ALB, Primary VPC REJECT, CloudTrail
└─ CloudWatch Data Source
   └─ WAF, EKS Control Plane, DVWA, GuardDuty
```

Amazon Managed Grafana는 이번 구현에서 제외하고 후속 학습 과제로 남긴다.

## 결정표

| ID | 결정 | 판정 | 결론 |
|---|---|---|---|
| D01 | Grafana 운영 방식 | 사용자 결정 | Grafana Cloud Free를 사용한다. Grafana용 EC2와 Amazon Managed Grafana Workspace는 만들지 않는다. |
| D02 | AWS 인증 | 기술 제약 | Grafana Cloud의 `Grafana Assume Role`을 사용한다. 장기 AWS Access Key를 저장하지 않는다. |
| D03 | Trust 입력 | 기술 제약 | Grafana Cloud 화면이 제공하는 AWS Account ID와 External ID를 IAM Role Trust에 사용한다. 값을 추측하거나 Repository에 고정하지 않는다. |
| D04 | 사용자 인증 | 확정 | Grafana Cloud Account로 로그인한다. IAM Identity Center와 AWS Organizations는 필요 없다. |
| D05 | S3 분석 Source | 프로젝트 선택 | CloudFront, Primary ALB, Primary VPC REJECT를 1차 Dashboard 대상으로 한다. CloudTrail은 조회 가능하게 두되 필수 Panel에서는 제외한다. |
| D06 | CloudWatch Source | 프로젝트 선택 | WAF, EKS, DVWA, GuardDuty는 S3에 복제하지 않고 CloudWatch Data Source에서 직접 조회한다. |
| D07 | 로그 분리 | 프로젝트 선택 | 기존 Security Log Bucket 하나를 유지하고 Source별 Prefix로 구분한다. Source별 Bucket은 추가하지 않는다. |
| D08 | 원본 로그 보존 | 사용자 결정 | S3 Security Log와 CloudWatch Log Group을 30일 보존한다. 기존 Foundation 기본값 `30`을 유지한다. |
| D09 | Athena 결과 보존 | 프로젝트 선택 | Query Result는 원본 로그가 아니므로 별도 Bucket에서 7일 보존한다. |
| D10 | Athena 권한 | 기술 제약 | Grafana Cloud용 Custom IAM Policy를 사용한다. Amazon Managed Grafana 전용 `AmazonGrafanaAthenaAccess`는 사용하지 않는다. |
| D11 | CloudWatch 권한 | 기술 제약 + 프로젝트 선택 | `Save & test`가 Metrics와 Logs API를 모두 확인하므로 Logs와 최소 Metrics Read를 허용한다. EC2 Tag·Performance Insights 권한은 제외한다. |
| D12 | Grafana as Code | 프로젝트 선택 | 첫 검증은 Grafana Cloud UI에서 Data Source를 연결한다. 연결 성공 후 Dashboard JSON 또는 Grafana Provider 자동화를 별도 단계로 진행한다. |
| D13 | Pod Identity 단위 | 기술 제약 | `Cluster + Namespace + ServiceAccount → IAM Role` 단위로 관리한다. Pod 개별 Role은 만들지 않는다. |
| D14 | Pod Identity 검증 | Runtime Gate | 예상 Role, 허용 Read API, 비허용 Read API를 실제 Pod에서 검증한다. |
| D15 | Node Role 노출 | Runtime Gate | Association 없는 Pod가 Node Role을 얻는지 검사한다. Node 교체가 필요한 보정은 별도 Plan으로 분리한다. |

## 공식 검증 결과

### Grafana Cloud 비용

Grafana Cloud Free는 항상 무료이며 카드가 필요 없고, Grafana Visualization은 월 최대 3명의 Active User를 지원한다. Athena와 CloudWatch를 외부 Data Source로 조회하는 경우 Grafana Cloud에 로그를 적재하지 않으므로, 원본 보존 기간은 AWS S3·CloudWatch의 30일 설정이 결정한다.

### Grafana Assume Role

Grafana Assume Role은 Grafana Cloud의 Amazon CloudWatch와 Amazon Athena Data Source에서 사용할 수 있다.

```text
Grafana Cloud AWS Account
→ sts:AssumeRole
→ aws-topology-grafana-cloud-read
→ Athena·Glue·S3·CloudWatch 조회
```

Trust Policy에는 Grafana Cloud 화면이 제공하는 다음 값이 필요하다.

```text
Grafana AWS Account ID
Grafana External ID
```

External ID는 Grafana가 선택하며 사용자가 임의로 만들지 않는다.

Athena와 CloudWatch 화면에 표시된 Account ID·External ID가 동일하면 Role 하나를 공유한다. 다르면 Data Source별 Role을 분리한다.

### Athena 최소 권한

Grafana 공식 최소 예제를 기준으로 다음 API가 필요하다.

```text
Athena:
  ListDatabases, ListDataCatalogs, ListWorkGroups,
  GetDatabase, GetDataCatalog, GetQueryExecution,
  GetQueryResults, GetTableMetadata, GetWorkGroup,
  ListTableMetadata, StartQueryExecution, StopQueryExecution

Glue:
  GetDatabase, GetDatabases, GetTable, GetTables,
  GetPartition, GetPartitions, BatchGetPartition
```

S3 권한은 분리한다.

- Security Log Bucket: 승인된 Prefix의 `ListBucket`, `GetObject`
- Athena Result Bucket: Query 결과 작성·조회·Multipart 정리
- CloudFront·ALB·VPC REJECT와 후속 CloudTrail Prefix만 허용
- Application Bucket과 지정되지 않은 Prefix는 제외

Lake Formation은 현재 프로젝트에서 사용하지 않으므로 `lakeformation:GetDataAccess`는 추가하지 않는다.

### CloudWatch 최소 권한

Grafana CloudWatch Data Source의 `Save & test`는 Metrics API와 Logs API를 모두 확인한다. 따라서 다음 Read 권한을 1차 Role에 포함한다.

```text
CloudWatch Metrics:
  cloudwatch:DescribeAlarmsForMetric
  cloudwatch:DescribeAlarmHistory
  cloudwatch:DescribeAlarms
  cloudwatch:ListMetrics
  cloudwatch:GetMetricData
  cloudwatch:GetInsightRuleReport

CloudWatch Logs:
  logs:DescribeLogGroups
  logs:GetLogGroupFields
  logs:StartQuery
  logs:StopQuery
  logs:GetQueryResults
  logs:GetLogEvents
```

EC2 Tag·Instance 조회, Resource Groups Tagging API, Performance Insights는 Dashboard에서 실제 필요성이 확인될 때만 추가한다.

### 30일과 7일의 차이

```text
원본 Security Log: 30일
Athena Query Result: 7일
```

원본이 30일 남아 있으므로 Query Result가 만료돼도 Athena Query를 다시 실행할 수 있다. 발표용 결과는 Evidence Bundle에 별도 보존한다.

## 현재 Source 연결

| 영역 | 현재 파일 |
|---|---|
| Security Log Bucket·30일 보존 | `foundation/observability.tf`, `foundation/variables.tf` |
| CloudFront·VPC REJECT·Fluent Bit | `observability.tf` |
| Athena DDL·S3 LOCATION | `observability/queries/athena/00_create_security_log_tables.sql` |
| Athena Query Runner | `observability/Invoke-AthenaQueryPack.ps1` |
| LBC·ExternalDNS Pod Identity | `cluster-controllers.tf` |
| EFS CSI·Web S3 Pod Identity | `storage-access.tf`, `eks.tf` |
| Karpenter Pod Identity | `eks.tf` |

## 남은 사용자 입력

Grafana Cloud Stack 생성 후 다음 값을 확보한다.

```text
Grafana Stack URL
Grafana AWS Account ID
Grafana External ID
```

Grafana Cloud를 Terraform Provider로 관리할 때만 다음 값이 추가로 필요하다.

```text
Grafana Cloud Service Account Token
```

Token, External ID, Access Key, Password, Terraform State는 Commit하지 않는다.

## 후속 학습

Amazon Managed Grafana는 별도 실습으로 남긴다.

- IAM Identity Center 인증
- Workspace IAM Role
- AWS Managed Workspace Lifecycle
- Amazon Managed Grafana 요금 구조

이번 Grafana Cloud 구현과 섞지 않는다.

## 공식 자료

- Grafana Cloud Pricing: https://grafana.com/pricing/
- Grafana AWS Authentication: https://grafana.com/docs/grafana/latest/datasources/aws-cloudwatch/aws-authentication/
- Athena Data Source: https://grafana.com/docs/plugins/grafana-athena-datasource/latest/configure/
- CloudWatch Data Source: https://grafana.com/docs/grafana/latest/datasources/aws-cloudwatch/configure/
- EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
