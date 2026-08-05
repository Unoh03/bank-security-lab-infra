# Observability·Pod Identity 설계 결정 검증

> 상태: **공식 검증 반영 / AWS 변경 미실행**  
> 기준 시점: 2026-08-05  
> 실행 순서는 [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)를 따른다.

이 문서는 무엇이 기술적 제약이고 무엇이 프로젝트 선택인지 구분한다. 구체적으로 적혀 있다는 이유만으로 모든 결정을 정답으로 취급하지 않는다.

## 판정

- **기술 제약**: 공식 문서·Provider Schema가 결정한다.
- **프로젝트 선택**: 다른 구현도 가능하지만 현재 범위에 맞춰 선택했다.
- **사람 Gate**: 비용·Account·교육 범위에 영향을 주므로 사용자가 승인한다.
- **Runtime Gate**: Source나 Plan만으로 확정할 수 없으며 실제 실행 결과가 필요하다.

## 결정표

| ID | 결정 | 판정 | 결론 |
|---|---|---|---|
| D01 | 분석 경로 | 기술 제약 | S3 로그는 Athena로 조회하고 Amazon Managed Grafana의 Athena Data Source에서 시각화한다. |
| D02 | 1차 시각화 Source | 프로젝트 선택 | 기존 S3 Source인 CloudFront, Primary ALB, Primary VPC REJECT만 대상으로 한다. |
| D03 | S3 분리 방식 | 프로젝트 선택 | 기존 Security Log Bucket 하나를 유지하고 Source별 Prefix로 구분한다. Source별 Bucket은 추가하지 않는다. |
| D04 | CloudWatch Logs의 S3 이중 저장 | 프로젝트 선택 | WAF·EKS·DVWA·GuardDuty는 이번 범위에서 CloudWatch Logs에 유지한다. |
| D05 | Analytics 수명주기 | 프로젝트 선택 | Foundation·Daily와 별도 State로 관리하고 `daily-down.ps1` 대상에 넣지 않는다. |
| D06 | AWS와 Grafana Terraform Root | 프로젝트 선택 | Provider Bootstrap을 단순화하기 위해 `analytics/aws`와 `analytics/grafana`로 분리한다. |
| D07 | Grafana 사용자 인증 | 사람 Gate + 기술 제약 | IAM User 3명은 Workspace 사용자로 직접 사용할 수 없다. IAM Identity Center 또는 SAML 중 사람이 선택한다. |
| D08 | Workspace Permission | 기술 제약 | Terraform/API 생성은 `CUSTOMER_MANAGED`, `CURRENT_ACCOUNT`, 전용 Workspace Role을 사용한다. |
| D09 | Grafana Version·Plugin·Network | 프로젝트 선택 + 기술 제약 | Grafana `12.4`, Plugin Management 활성화를 사용한다. Seoul에서는 Workspace VPC 연결을 만들지 않는다. |
| D10 | Athena Workgroup·Result Bucket | 기술 제약 | `AmazonGrafanaAthenaAccess`를 사용하므로 Workgroup Tag와 규칙에 맞는 Result Bucket을 만든다. 원본 S3 Read는 별도 Policy로 부여한다. |
| D11 | Scan·Retention 값 | 프로젝트 선택 | Query당 100 MiB, Result 7일을 기본값으로 두고 변수화한다. |
| D12 | Athena Table 소유권 | 프로젝트 선택 | 기존 SQL DDL·Query Pack을 유지하고 첫 Pass에서 Glue Table을 Terraform으로 이전하지 않는다. |
| D13 | Dashboard 최소 범위 | 프로젝트 선택 | 필수 Panel은 CloudFront, ALB 오류, VPC REJECT의 3개다. Request Trace는 선택이다. |
| D14 | Pod Identity 단위 | 기술 제약 | `Cluster + Namespace + ServiceAccount → IAM Role` 단위로 관리한다. Pod 개별 Role은 만들지 않는다. |
| D15 | Pod Identity Trust 조건 | 프로젝트 선택 | 기본 Service Trust에 Namespace·ServiceAccount Request Tag 조건을 추가해 Custom Role 범위를 좁힌다. |
| D16 | Pod Identity 기능 검증 | Runtime Gate | 예상 Role ARN, 대표 허용 Read API, 대표 비허용 Read API를 확인한다. |
| D17 | Node Role 노출 | Runtime Gate | Association 없는 Pod가 Node Role을 얻으면 기능은 동작해도 최소 권한 완료로 판정하지 않는다. 보정은 별도 교체 Plan으로 진행한다. |
| D18 | Grafana 자동화 Token | 프로젝트 선택 | 짧은 수명의 Service Account Token을 Wrapper가 생성·삭제하고 Terraform State에는 보존하지 않는다. |

## 검증 과정에서 수정한 오류

### 1. 존재하지 않는 Grafana Provider Version

초기 문서의 다음 제약은 잘못됐다.

```text
grafana/grafana ~> 4.42
```

2026-08-05 확인 시 최신 공개 Version은 `4.40.1`이다. 실행 계획은 다음으로 수정한다.

```text
grafana/grafana ~> 4.40.0
```

Codex는 `terraform init`이 선택한 Version과 Lock File을 보고한다.

### 2. Workspace의 `data_sources = ["ATHENA"]`

Terraform AWS Provider에는 `data_sources` 인자가 노출돼 있지만, AWS `CreateWorkspace` API는 `workspaceDataSources`를 내부용이며 사용하지 말라고 명시한다.

이번 구성은 `CUSTOMER_MANAGED` Workspace Role과 Grafana Provider로 Athena Data Source를 직접 만든다. 따라서 Workspace Resource에서 `data_sources`를 지정하지 않는다.

### 3. Plugin Management 표현

다음은 독립 HCL 인자가 아니다.

```text
pluginAdminEnabled = true
```

Workspace의 정확한 표현은 다음 JSON Configuration이다.

```hcl
configuration = jsonencode({
  plugins = {
    pluginAdminEnabled = true
  }
})
```

### 4. 두 Terraform Root의 성격

`analytics/aws`와 `analytics/grafana` 분리는 AWS의 필수 구조가 아니다. 다음 문제를 피하기 위한 프로젝트 선택이다.

- Grafana Provider Endpoint와 Token은 Workspace 생성 후에 생긴다.
- Provider 설정은 Apply 전에 알려진 값만 사용할 수 있다.
- AWS Provider의 Service Account Token Resource는 Token Key를 State에 저장할 수 있다.

하나의 Root에서 Target Apply를 반복하는 방식도 가능하지만, 현재 프로젝트에서는 두 Root가 더 단순하다.

### 5. Pod Identity Trust 조건의 성격

다음은 Pod Identity의 필수 Service Trust다.

```text
Principal.Service = pods.eks.amazonaws.com
Action = sts:AssumeRole, sts:TagSession
```

Namespace·ServiceAccount Request Tag 조건은 공식적으로 지원되는 추가 제한이다. 필수 문법은 아니며 현재 프로젝트의 최소 권한 선택이다.

## 기술 근거 요약

### Athena와 Workspace Role

`AmazonGrafanaAthenaAccess` 사용 조건:

- Athena Workgroup Tag: `GrafanaDataSource=true`
- Query Result Bucket 이름: `grafana-athena-query-results-` Prefix
- 원본 S3 Data Read는 관리형 Policy에 포함되지 않으므로 별도 허용

따라서 Query Result Bucket과 원본 Security Log Bucket을 분리한다.

### Grafana 인증

Amazon Managed Grafana Workspace 사용자는 IAM Identity Center 또는 SAML로 인증한다. IAM User·Role은 Workspace 내부 사용자 권한 할당 대상이 아니다.

IAM Identity Center는 AWS Organizations 활성화가 필요할 수 있다. 다음 작업은 사람 승인 전 금지한다.

```text
Organizations 활성화
IAM Identity Center 활성화
Directory User·Group 생성
```

### Workspace 생성

AWS API·CLI·CloudFormation으로 Workspace를 만들 때는 `CUSTOMER_MANAGED` Permission Type과 직접 관리하는 Workspace Role을 사용해야 한다. Terraform도 AWS API를 사용하므로 동일하게 적용한다.

### Seoul VPC 제약

Amazon Managed Grafana의 Data Source용 Workspace VPC 연결은 현재 `ap-northeast-2`에서 제공되지 않는다. 이번 Data Source는 Athena·Glue·S3의 AWS Endpoint를 사용하므로 VPC Configuration을 만들지 않는다.

### Grafana 자동화 Token

Grafana 12에서는 Service Account Token으로 Terraform과 Grafana HTTP API를 인증한다. Service Account는 과금상 사용자로 취급되므로 자동화가 끝나면 Token과 Service Account를 삭제한다.

### Pod Identity

EKS Pod Identity Association은 Cluster 안의 Namespace·ServiceAccount와 IAM Role을 연결한다. 같은 ServiceAccount를 사용하는 Pod가 해당 Role의 임시 Credential을 받는다.

IMDS 접근을 제한하지 않으면 Pod가 Node IAM Role Credential을 얻을 수 있다. 따라서 No-Association Pod Test는 필수지만, Node 교체를 일으킬 수 있는 보정은 별도 Plan으로 분리한다.

## 현재 Source 연결

| 영역 | 현재 파일 |
|---|---|
| Security Log Bucket·CloudTrail·CloudFront Destination | `foundation/observability.tf` |
| CloudFront·WAF·VPC REJECT·Fluent Bit Pod Identity | `observability.tf` |
| Athena DDL·LOCATION | `observability/queries/athena/00_create_security_log_tables.sql` |
| Athena Query Runner | `observability/Invoke-AthenaQueryPack.ps1` |
| AWS LBC·ExternalDNS Pod Identity | `cluster-controllers.tf` |
| EFS CSI·Web S3 Pod Identity | `storage-access.tf`, `eks.tf` |
| Karpenter Pod Identity | `eks.tf`의 Karpenter Module |

## 남은 사람 Gate

### G1 — 비용

- Amazon Managed Grafana Workspace 생성 승인
- 실제 사용자와 임시 Service Account의 과금 가능성 인지

### G2 — 인증

현재 별도 SAML IdP가 없다면 IAM Identity Center를 선택한다. 활성화와 사용자 생성은 Terraform 구현 범위 밖에서 사람이 승인한다.

### G3 — 교육 요구사항 해석

현재 범위는 다음 해석을 사용한다.

> S3에 저장되는 로그를 Source별 Prefix로 구분하고 Athena·Grafana로 분석한다.

모든 WAF·EKS·Application Log까지 S3 복제가 필요하다는 명시적 지시가 확인될 때만 별도 Phase를 추가한다.

## 공식 근거

- Amazon Managed Grafana IAM Identity Center  
  https://docs.aws.amazon.com/grafana/latest/userguide/authentication-in-AMG-SSO.html
- Amazon Managed Grafana Workspace 생성 API  
  https://docs.aws.amazon.com/grafana/latest/APIReference/API_CreateWorkspace.html
- Amazon Managed Grafana Workspace Configuration  
  https://docs.aws.amazon.com/grafana/latest/userguide/AMG-configure-workspace.html
- Amazon Managed Grafana Athena Prerequisites  
  https://docs.aws.amazon.com/grafana/latest/userguide/Athena-prereq.html
- Amazon Managed Grafana Service Accounts  
  https://docs.aws.amazon.com/grafana/latest/userguide/v12-authenticating-grafana-apis.html
- Terraform AWS Provider `aws_grafana_workspace`  
  https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/grafana_workspace
- Terraform Grafana Provider  
  https://registry.terraform.io/providers/grafana/grafana/latest
- Terraform Provider Configuration  
  https://developer.hashicorp.com/terraform/language/block/provider
- Terraform Sensitive Data  
  https://developer.hashicorp.com/terraform/language/manage-sensitive-data
- EKS Pod Identity  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- EKS Pod Identity Association  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html
- EKS Pod Identity Trust Policy  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html
