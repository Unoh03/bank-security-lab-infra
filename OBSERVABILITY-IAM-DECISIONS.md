# Observability·Pod Identity 설계 결정 검증

> 상태: **검증 완료 항목과 사람 승인 항목 분리**  
> 기준 시점: 2026-08-05  
> 이 문서는 설계 근거를 보존한다. Codex는 실제 구현 순서만 필요하면 `OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`를 먼저 읽는다.

## 판정 기호

- **확정**: 공식 문서와 현재 Source가 지지하며 구현 레시피에 사용한다.
- **프로젝트 결정**: 기술적 정답은 아니지만 현재 범위에 맞게 선택했다. 변경 가능하다.
- **사람 승인 필요**: Account·비용·교육 범위에 영향을 주므로 자동 진행하지 않는다.
- **후속 Hardening**: 중요하지만 이번 기능의 1차 완료 조건과 분리한다.

## 결정표

| ID | 결정 | 판정 | 구현 결론 |
|---|---|---|---|
| D01 | 분석 경로 | 확정 | `S3 → Athena → Amazon Managed Grafana`를 사용한다. |
| D02 | 1차 시각화 Source | 프로젝트 결정 | 기존 S3 Source인 CloudFront, Primary ALB, Primary VPC REJECT만 대상으로 한다. |
| D03 | S3 분리 방식 | 확정 | 기존 Security Log Bucket 하나를 유지하고 Source별 Prefix로 분리한다. 새 Source별 Bucket은 만들지 않는다. |
| D04 | CloudWatch Logs의 S3 이중 저장 | 프로젝트 결정 | WAF·EKS·DVWA·GuardDuty는 이번 범위에서 CloudWatch Logs에 유지한다. |
| D05 | Analytics Lifecycle | 확정 | Foundation·Daily와 다른 `analytics/` State를 사용하며 `daily-down.ps1` 대상에 넣지 않는다. |
| D06 | AWS Resource와 Grafana Content | 확정 | `analytics/aws`와 `analytics/grafana`의 2단계 Terraform Root로 나눈다. |
| D07 | Grafana 사용자 인증 | 사람 승인 필요 | 기본 후보는 IAM Identity Center다. IAM User 3명은 Workspace 사용자로 직접 사용할 수 없다. Organizations·Identity Center를 자동 활성화하지 않는다. |
| D08 | Workspace Permission | 확정 | API/Terraform 생성은 `CUSTOMER_MANAGED`, `CURRENT_ACCOUNT`, 전용 Workspace Role을 사용한다. |
| D09 | Grafana Version·Network | 확정 | Grafana `12.4`를 고정하고 Plugin Management를 켠다. Seoul에서는 Workspace VPC 연결을 사용하지 않는다. |
| D10 | Athena Workgroup·Result Bucket | 확정 | Grafana 전용 Workgroup과 `grafana-athena-query-results-` Result Bucket을 만든다. Workgroup에 `GrafanaDataSource=true` Tag를 붙인다. |
| D11 | Workspace IAM Permission | 확정 | `AmazonGrafanaAthenaAccess` + 승인된 세 S3 Prefix의 Read Policy만 부여한다. |
| D12 | Scan·Retention 숫자 | 프로젝트 결정 | Query당 100 MiB, Result 7일을 기본값으로 두되 변수로 변경 가능하게 한다. |
| D13 | Athena Table 소유권 | 프로젝트 결정 | 기존 SQL DDL·Query Pack을 유지한다. 첫 Pass에서 Glue Table을 Terraform Resource로 이전하지 않는다. |
| D14 | Dashboard 최소 범위 | 프로젝트 결정 | 필수 Panel은 CloudFront, ALB 오류, VPC REJECT의 3개다. Request Trace는 선택 Panel이다. |
| D15 | Pod Identity 단위 | 확정 | `Cluster + Namespace + ServiceAccount → IAM Role` 단위로 관리한다. Pod 개별 Role은 만들지 않는다. |
| D16 | Pod Identity Trust | 확정 | Custom Role은 `pods.eks.amazonaws.com`, `sts:AssumeRole`, `sts:TagSession`과 Namespace·ServiceAccount Request Tag 조건을 사용한다. |
| D17 | Module Role Trust 보정 | 프로젝트 결정 | 현재 Module이 지원하면 조건을 추가한다. 조건 추가만을 위해 Module Upgrade·Fork를 하지 않는다. |
| D18 | Pod Identity Runtime 검증 | 확정 | 예상 Role ARN, 대표 허용 Read API, 대표 비허용 Read API를 검증한다. |
| D19 | Node Role IMDS 격리 | 후속 Hardening | Association 없는 Pod의 Credential Source를 검사하지만 1차 기능 완료 Gate와 분리한다. Node 교체가 필요한 보정은 별도 Plan으로 제출한다. |
| D20 | 자동화 Token | 확정 | 짧은 수명의 Grafana Service Account Token을 Wrapper에서 생성·삭제한다. Token Resource와 Key를 Terraform State에 보존하지 않는다. |

## 핵심 검증 결과

### D01·D10·D11 — Athena 연결

Amazon Managed Grafana의 Athena Data Source는 Athena SQL과 Grafana Time Macro를 지원한다. AWS 관리형 `AmazonGrafanaAthenaAccess`를 사용할 때는 다음 조건이 필요하다.

- Athena Workgroup Tag: `GrafanaDataSource=true`
- Query Result Bucket 이름: `grafana-athena-query-results-` Prefix
- 원본 S3 Data 읽기 권한은 관리형 Policy에 포함되지 않으므로 별도 부여

따라서 기존 Security Log Bucket에는 Read 권한만 추가하고, Query Result는 별도 Bucket에 쓴다.

### D06·D20 — Terraform Root 분리

Terraform Provider 설정은 Apply 전에 알려진 값만 참조할 수 있다. 새 Workspace Endpoint와 새 Service Account Token은 AWS Resource 생성 뒤에 얻는다.

또한 Provider Resource가 반환하는 Token Key를 Terraform Resource로 관리하면 민감값이 State에 저장될 수 있다.

따라서 다음 두 단계가 가장 단순하다.

```text
analytics/aws apply
→ Workspace Endpoint 생성
→ Wrapper가 임시 Service Account·Token 생성
→ analytics/grafana apply
→ Token·Service Account 삭제
```

이는 디렉터리를 많이 나누기 위한 선택이 아니라 Provider Bootstrap 순서를 분리하기 위한 것이다.

### D07·D08 — 사용자 인증과 Workspace Role

Amazon Managed Grafana Workspace 내부 사용자는 IAM Identity Center 또는 SAML로 인증한다. IAM User·IAM Role은 Workspace 사용자 권한 할당 대상으로 사용할 수 없다.

IAM Identity Center를 사용하려면 AWS Organizations가 필요할 수 있으므로 다음은 사람 승인 전 금지한다.

- Organizations 자동 활성화
- IAM Identity Center 자동 활성화
- Directory User·Group 자동 생성

Terraform/API로 Workspace를 생성할 때는 `CUSTOMER_MANAGED` Permission Type을 사용하고 기존 Role을 지정한다.

### D09 — Seoul Network 제약

현재 Amazon Managed Grafana의 Workspace VPC 연결은 `ap-northeast-2`에서 제공되지 않는다. 이번 Data Source는 Public AWS API Endpoint인 Athena·Glue·S3를 사용하므로 VPC Configuration을 만들지 않는다.

### D15·D16 — Pod Identity

EKS Pod Identity Association은 Cluster 안의 Namespace·ServiceAccount와 IAM Role을 연결한다. 해당 ServiceAccount를 사용하는 Pod에 임시 Credential이 공급된다.

Custom Role의 Trust 기본값:

```json
{
  "Principal": { "Service": "pods.eks.amazonaws.com" },
  "Action": ["sts:AssumeRole", "sts:TagSession"]
}
```

현재 프로젝트는 Workload별 Role을 따로 사용하므로 Namespace와 ServiceAccount Request Tag 조건을 추가해 Role 재사용 범위를 좁힌다.

### D19 — IMDS 격리의 위치

AWS는 IMDS 접근이 제한되지 않으면 Pod가 Node IAM Role Credential에도 접근할 수 있다고 설명한다. 이는 중요한 보안 검증이지만 다음 변경은 Node 교체를 유발할 수 있다.

- Managed Node Group Launch Template Metadata Option
- Karpenter EC2NodeClass Metadata Option
- IMDS Hop Limit 변경

따라서 첫 Pass에서는 조회·Negative Test만 하고, 보정은 별도 Fresh Plan으로 분리한다.

## 현재 Source와 직접 연결되는 위치

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

### G1 — Amazon Managed Grafana 비용

- Workspace를 실제 생성할지 승인한다.
- 사용자와 Service Account가 과금 사용자로 취급될 수 있음을 인지한다.

### G2 — 인증 방식

현재 별도 SAML IdP가 없다면 IAM Identity Center를 선택한다.

승인 전에는 Codex가 다음을 하지 않는다.

- Organizations 활성화
- IAM Identity Center 활성화
- User·Group 생성

### G3 — 교육 요구사항 해석

현재 구현 범위는 다음 해석을 사용한다.

> S3에 저장되는 로그를 Source별 Prefix로 구분하고 Athena·Grafana로 분석한다.

강사가 모든 WAF·EKS·Application Log까지 S3에 복제하라고 명시한 경우에만 별도 Phase를 추가한다.

## 공식 근거

- Amazon Managed Grafana IAM Identity Center  
  https://docs.aws.amazon.com/grafana/latest/userguide/authentication-in-AMG-SSO.html
- Amazon Managed Grafana Permission Modes  
  https://docs.aws.amazon.com/grafana/latest/userguide/AMG-manage-permissions.html
- Amazon Managed Grafana Athena Prerequisites  
  https://docs.aws.amazon.com/grafana/latest/userguide/Athena-prereq.html
- Amazon Managed Grafana Athena Data Source  
  https://docs.aws.amazon.com/grafana/latest/userguide/Athena-using-the-data-source.html
- `AmazonGrafanaAthenaAccess`  
  https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonGrafanaAthenaAccess.html
- Amazon Managed Grafana Service Accounts  
  https://docs.aws.amazon.com/grafana/latest/userguide/v12-authenticating-grafana-apis.html
- Terraform Provider Configuration  
  https://developer.hashicorp.com/terraform/language/block/provider
- Terraform Sensitive Data and State  
  https://developer.hashicorp.com/terraform/language/manage-sensitive-data
- EKS Pod Identity  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- EKS Pod Identity Association  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html
- EKS Pod Identity Trust Policy  
  https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html
