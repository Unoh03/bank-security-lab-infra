# S3 로그 분석·Grafana 시각화·Pod Identity 단계별 실행 계획

> 상태: **기준 재정립 / 현재 상태부터 재검증 / 자동 변경 금지**  
> 기준 시점: 2026-08-06  
> 결정 근거: [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)

이 계획은 처음 전달받은 네 요구사항을 처음부터 다시 밟는다.

```text
1. S3 로그 분석과 Grafana 시각화
2. EKS Workload별 Pod Identity
3. 리소스별 S3 로그 저장 구분
4. 구성 결과 설명과 실제 화면·Runtime 증명
```

기존 Grafana Cloud 중심 계획은 폐기한다. 현재 실제로 성공한 로컬 Docker Grafana를 출발점으로 사용하되, 이미 성공했다고 확인한 범위와 아직 검증하지 않은 범위를 분리한다.

---

## 0. 실행 원칙

### 0.1 단계 Gate

각 단계는 다음 네 상태를 구분한다.

```text
SourceConfigured   Terraform·Script·Manifest가 존재
Planned            Plan 또는 예상 변경이 검토됨
RuntimeObserved    실제 AWS·Kubernetes·Grafana에서 확인
EvidenceSaved      재현 가능한 결과와 화면이 보존됨
```

`SourceConfigured`만으로 완료라고 보고하지 않는다.

### 0.2 변경 통제

첫 Pass는 Read-only Inventory와 Runtime 조회까지만 수행한다.

금지:

```text
terraform apply / destroy
kubectl apply / patch / delete
새 S3 Bucket 생성
새 Grafana 서비스 생성
IAM Role·Policy 변경
Pod Identity Association 변경
Node Group·Karpenter 교체
Secret·Access Key·tfstate·tfplan Commit
```

변경이 필요하면 Source Diff와 Plan을 먼저 만들고 사용자 승인 뒤 별도 Pass에서 적용한다.

### 0.3 범위 통제

핵심 요구를 완료하기 전 다음 항목으로 확장하지 않는다.

```text
Grafana Cloud 재시도
Amazon Managed Grafana
CloudWatch 기반 근실시간 Dashboard
EventBridge·SNS Alert
자동 대응
별도 Athena Result Bucket
Grafana Provider 자동화
```

---

## 1. 현재 Checkpoint

| 항목 | 현재 상태 | 다음 Gate |
|---|---|---|
| Local Docker Grafana | 실행·접속 성공 | 재현 정보 유지 |
| Athena Data Source | `Data source is working` 확인 | 실제 Source Table 행 조회 |
| Athena Catalog·Database | `AwsDataCatalog`, `aws_topology_security` 확인 | Table Metadata·LOCATION 확인 |
| Athena Table 목록 | 세 Table 확인 | 각 Table 실제 행 확인 |
| CloudFront S3 로그 | Source·Prefix 정의 | 최신 Object 존재 확인 |
| ALB S3 로그 | Source·Prefix 정의 | 최신 Object 존재 확인 |
| VPC REJECT S3 로그 | Source·Prefix 정의 | 최신 Object 존재 확인 |
| Grafana Dashboard | 미구성 | 세 필수 Panel 작성 |
| Pod Identity Source | 여러 Workload 정의 | AWS·Kubernetes Inventory |
| Pod Identity Runtime | 전체 재검증 안 됨 | 예상 Role·허용·거부 Test |
| 최종 Evidence | 일부 Screenshot·노트만 존재 | 통합 Evidence Bundle |

현재 Table 목록 조회만으로는 S3 원본 로그가 정상 파싱된다고 판정하지 않는다.

---

# Phase 1 — 합격 기준 고정

## 목표

원래 요구사항의 모호한 두 항목을 아키텍처 변경 전에 분리한다.

### Gate A — S3 구분

```text
A안: Security Log Bucket 하나 + Source별 Prefix
B안: Source별 별도 Bucket
```

현재 Source는 A안이다. 평가자가 B안을 명시하지 않았다면 A안을 유지하고, Prefix·Bucket Policy·Athena LOCATION으로 분리됨을 증명한다.

### Gate B — Grafana 제품

```text
현재: Local Docker Grafana + AWS Athena
미확정: Amazon Managed Grafana가 필수인지
```

Amazon Managed Grafana가 명시적 필수 조건이 아니라면 현재 로컬 Grafana 경로를 사용한다. 이 Gate가 해결되기 전 Managed Grafana Workspace를 만들지 않는다.

## 산출물

`OBSERVABILITY-IAM-DECISIONS.md`의 A01·A02에 최종 판정을 기록한다.

---

# Phase 2 — 현재 Source와 Runtime Inventory

## 목표

코드를 바꾸기 전에 현재 정의와 실제 AWS 상태가 무엇인지 확정한다.

## 2.1 Source Inventory

확인 파일:

```text
foundation/observability.tf
foundation/variables.tf
observability.tf
observability/queries/athena/00_create_security_log_tables.sql
observability/Invoke-AthenaQueryPack.ps1
cluster-controllers.tf
storage-access.tf
eks.tf
```

기록할 항목:

```text
Security Log Bucket Output
Retention
Bucket Policy Principal·Resource
Source별 Prefix
Athena Database·Table·LOCATION
Pod Identity Role
Cluster·Namespace·ServiceAccount
조건부 Count·Feature Flag
```

## 2.2 AWS Read-only Inventory

확인:

```powershell
aws sts get-caller-identity --profile terra-user
terraform -chdir=foundation output
aws athena list-data-catalogs --profile terra-user --region ap-northeast-2
aws athena list-table-metadata --profile terra-user --region ap-northeast-2 --catalog-name AwsDataCatalog --database-name aws_topology_security
```

중단 조건:

- AWS Account가 `433048100798`이 아님
- Foundation State Output을 읽을 수 없음
- 예상하지 않은 Bucket·Database를 대상으로 하게 됨

## 산출물

다음 Matrix를 결과 보고에 포함한다.

```text
Source 정의
AWS 실제 Resource
일치 여부
Runtime 관측 여부
남은 검증
```

첫 Pass에서는 별도 Inventory 파일을 만들 필요가 있을 때만 생성한다. 문서 수를 늘리기 전에 기존 Evidence 구조를 확인한다.

---

# Phase 3 — S3 로그 저장·분리 Runtime 검증

## 목표

세 필수 Source가 실제로 각 Prefix에 Object를 저장하고 있는지 확인한다.

## 필수 Source

| ID | Prefix |
|---|---|
| `cloudfront` | `AWSLogs/433048100798/CloudFront/` |
| `alb-primary` | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` |
| `vpc-reject-primary` | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` |

CloudTrail은 보조 Source로 별도 기록한다.

## 검증 순서

1. Foundation Output에서 실제 Bucket 이름을 읽는다.
2. 각 Prefix의 Object Count와 최신 Object 시각을 조회한다.
3. 최신 Object 하나의 Key·Size·LastModified를 기록한다.
4. Object가 없으면 `NotObserved`로 기록한다.
5. 원인을 추측하지 말고 로그 생성 조건과 Runtime 활성 상태를 별도 확인한다.

PowerShell 예시:

```powershell
$bucket = terraform -chdir=foundation output -raw security_log_bucket_name

aws s3api list-objects-v2 `
  --profile terra-user `
  --bucket $bucket `
  --prefix 'AWSLogs/433048100798/CloudFront/' `
  --max-items 10
```

같은 방식으로 ALB와 VPC Prefix를 확인한다.

## 분리 판정

다음을 모두 만족하면 Prefix 기반 분리가 기술적으로 확인된 것이다.

```text
Source별 Prefix가 겹치지 않음
Bucket Policy의 Write Resource가 Source별 Prefix로 제한됨
Athena LOCATION이 해당 Prefix와 일치
실제 Object가 예상 Prefix에 존재
```

## 완료 Gate

| Source | Object 존재 | 최신 시각 | Prefix 일치 | 판정 |
|---|---:|---|---:|---|
| CloudFront |  |  |  |  |
| ALB |  |  |  |  |
| VPC REJECT |  |  |  |  |

---

# Phase 4 — Athena 실제 데이터 검증

## 목표

Table 이름만 존재하는 상태에서 실제 S3 로그가 파싱되는 상태로 넘어간다.

## 4.1 Metadata 검증

각 Table의 `LOCATION`, Column, SerDe를 DDL과 대조한다.

```text
cloudfront_access
alb_primary_access
vpc_reject
```

## 4.2 제한 Query

처음에는 최근 데이터 일부만 조회한다. 전체 기간 Scan을 금지한다.

### CloudFront

```sql
SELECT *
FROM aws_topology_security.cloudfront_access
ORDER BY date DESC, time DESC
LIMIT 10;
```

### ALB

```sql
SELECT *
FROM aws_topology_security.alb_primary_access
ORDER BY time DESC
LIMIT 10;
```

### VPC REJECT

```sql
SELECT *
FROM aws_topology_security.vpc_reject
ORDER BY start DESC
LIMIT 10;
```

Table에 데이터가 많아지면 기존 `observability/Invoke-AthenaQueryPack.ps1`의 최대 6시간 제한 Query를 우선 사용한다.

## 4.3 결과 기록

각 Query마다 기록:

```text
QueryExecutionId
State
실행 시각
Returned Rows
DataScannedInBytes
Result S3 URI
대표 Column 값
```

민감 정보는 Screenshot과 Repository에 포함하지 않는다.

## 완료 Gate

- 세 Table이 `SUCCEEDED`
- 실제 로그 행 반환 또는 Source가 실제로 비어 있음을 Evidence로 확인
- 주요 Column이 전부 NULL이 아님
- Table LOCATION과 실제 Object Prefix가 일치

Schema 오류가 있으면 DDL 수정안을 작성하되 즉시 실행하지 않는다.

---

# Phase 5 — 로컬 Grafana S3 로그 시각화

## 목표

이미 연결된 Athena Data Source를 사용해 핵심 세 Source를 실제 Panel로 보여준다.

## 현재 Data Source

```text
Authentication Provider: Credentials file
Credentials Profile Name: terra-user
Region: ap-northeast-2
Catalog: AwsDataCatalog
Database: aws_topology_security
Workgroup: primary
Output Location: s3://<SECURITY_LOG_BUCKET>/athena-results/grafana/
```

Data Source를 새로 만들지 않는다. 현재 연결이 사라졌을 때만 Obsidian 재현 노트를 기준으로 복구한다.

## 필수 Panel

### Panel 1 — CloudFront 요청 상태

```text
시간별 요청 수
4xx 수
5xx 수
```

### Panel 2 — ALB 오류 Source

```text
4xx·5xx 요청 수
Top Client IP
Top Request URL 또는 Path
```

### Panel 3 — VPC REJECT

```text
Top Source IP
Top Destination Port
시간대별 REJECT 수
```

## 공통 기준

```text
기본 Time Range: 최근 6시간
Query마다 시간 제한
Cookie·Authorization·Body 미표시
광범위한 SELECT * Dashboard Query 금지
S3 로그 전달 주기를 고려해 Auto Refresh는 검증 중 Off
필요 시 최종 Dashboard에서 5분 이상으로 설정
```

## 산출물

```text
analytics/dashboard/security-overview.json
Panel별 SQL
Dashboard 전체 Screenshot
Panel별 정상 데이터 Screenshot
```

`analytics/dashboard/`가 아직 없으므로 실제 Dashboard가 동작한 뒤 생성한다. 빈 JSON이나 추정 Query를 먼저 Commit하지 않는다.

## 완료 Gate

- 세 Panel 모두 실제 데이터 표시
- Grafana Time Range 변경이 Query에 반영
- Dashboard JSON Export 성공
- Screenshot과 Query가 같은 시점을 가리킴

---

# Phase 6 — Pod Identity Source·AWS·Kubernetes Inventory

## 목표

현재 Source에 정의된 Association과 실제 Runtime을 Workload별로 정리한다.

## 예상 Workload

```text
Primary / DR AWS Load Balancer Controller
Primary / 조건부 DR ExternalDNS
Primary / DR EFS CSI Controller
Primary / 조건부 DR Web S3 Workload
Primary / 조건부 DR Fluent Bit
Primary / 조건부 DR Karpenter
```

## Inventory 수집

AWS:

```text
EKS Pod Identity Association
Association ID
IAM Role ARN
Role Trust
Managed Policy
Inline Policy
```

Kubernetes:

```text
Namespace
ServiceAccount
Pod
Pod가 사용하는 ServiceAccount
Workload Ready 상태
```

## Matrix 필드

```text
cluster
namespace
service_account
workload
association_id
role_arn
policy_summary
source_status
runtime_status
```

## 상태값

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
NoAssociationExpected
```

조건부 Resource가 비활성 상태면 실패가 아니라 `DisabledByDesign`으로 기록한다.

## 완료 Gate

- Source의 모든 Association 후보가 Matrix에 존재
- AWS Association과 Kubernetes ServiceAccount가 연결됨
- 실제 Pod가 없는 항목은 이유와 Feature Flag를 기록
- 예상하지 않은 Association을 별도 표시

---

# Phase 7 — Pod Identity Runtime 권한 검증

## 목표

Role이 존재하는지만 보지 않고 실제 Pod가 어떤 AWS Identity와 권한을 받는지 확인한다.

## 사전 조건

```text
EKS Cluster Up
Pod Identity Agent Ready
대상 ServiceAccount 존재
대상 Workload 또는 임시 Test Pod 실행 가능
사용자 승인
```

## Test 절차

각 ServiceAccount에 대해:

```text
1. Association 확인
2. 실제 Pod의 ServiceAccount 확인
3. 같은 ServiceAccount를 사용하는 임시 AWS CLI Pod 실행
4. sts:GetCallerIdentity 실행
5. 예상 Role ARN과 비교
6. 대표 허용 Read API 실행
7. iam:ListUsers 실행
8. AccessDenied 확인
9. 임시 Pod 삭제
```

대표 허용 API 예시:

| Workload | 안전한 대표 검증 |
|---|---|
| AWS Load Balancer Controller | ELBv2 Describe 계열 |
| ExternalDNS | Route 53 List·Get 계열 |
| EFS CSI | EFS Describe 계열 |
| Web S3 | 승인된 Bucket·`web/` Prefix의 List 또는 Get |
| Fluent Bit | 대상 Log Group Describe 계열 |
| Karpenter | 정책에 포함된 Describe·Get 계열 |

실제 Policy를 읽은 뒤 허용 API를 선택한다. 일반 지식으로 Action을 추측하지 않는다.

## Negative Test

```text
iam:ListUsers → AccessDenied
승인되지 않은 S3 Bucket·Prefix → AccessDenied
```

Write API는 별도 통제된 Test가 없으면 실행하지 않는다.

## Node Role 노출 Test

Association 없는 전용 ServiceAccount로 `sts:GetCallerIdentity`를 실행한다.

판정:

```text
Credential 없음 → 통과
Node Role 반환 → 격리 미충족
다른 Role 반환 → RuntimeUnexpected
```

Node Role이 반환되면 Node 교체·IMDS 변경을 즉시 실행하지 않고 별도 Hardening Plan을 작성한다.

## 완료 Gate

- 예상 Role 일치
- 대표 허용 API 성공
- 비허용 API 거부
- 임시 Pod 제거 확인
- Association 없는 Pod가 Node Role을 획득하지 않음

---

# Phase 8 — Evidence와 최종 설명

## 목표

`구성된 결과를 듣고 보는 것`을 재현 가능한 증거로 완성한다.

## 필수 Evidence

### S3·Athena

```text
Source별 Prefix와 최신 Object
Athena Table Metadata
QueryExecutionId
Returned Rows
DataScannedInBytes
```

### Grafana

```text
Data Source 성공 화면
Dashboard 전체 화면
CloudFront Panel
ALB Panel
VPC REJECT Panel
Export한 Dashboard JSON
```

### Pod Identity

```text
Workload Matrix
Association ID·Role ARN
Pod ServiceAccount
STS Caller Identity
허용 API 결과
AccessDenied 결과
Node Role 노출 Test
```

## 결과 보고 형식

| 요구사항 | Source | Runtime | Evidence | 최종 판정 |
|---|---|---|---|---|
| S3 로그 분석 |  |  |  |  |
| Grafana 시각화 |  |  |  |  |
| Pod Identity |  |  |  |  |
| S3 로그 분리 |  |  |  |  |

`NotObserved`, `DisabledByDesign`, `Failed`, `NotRun`을 성공과 구분한다.

---

# Phase 9 — 핵심 완료 후 선택 범위

핵심 네 요구사항을 완료한 뒤에만 판단한다.

```text
CloudWatch Data Source
WAF·EKS·DVWA·GuardDuty Dashboard
GuardDuty → EventBridge → SNS
Grafana Alert Rule
Amazon Managed Grafana 학습
Grafana Cloud Plugin 재검증
별도 Athena Result Bucket과 7일 Lifecycle
Source별 별도 S3 Bucket Migration
```

이 항목은 관제 품질을 높일 수 있지만 현재 핵심 완료 조건에는 포함하지 않는다.

---

# Codex Pass 계획

## Pass 1 — Read-only Baseline Audit

목표:

```text
현재 Source Inventory
실제 S3 Prefix Object 확인
Athena Metadata와 제한 Query 확인
Pod Identity AWS·Kubernetes Inventory
Gap Report
```

금지:

```text
Source 수정
terraform apply/destroy
kubectl Mutation
새 Resource 생성
IAM 변경
```

종료 보고:

```text
직접 확인한 사실
Source에서만 확인한 사실
Runtime 미관측
요구사항별 Gap
다음 Pass에서 필요한 최소 변경
```

## Pass 2 — 필요한 최소 보정 Source·Test

Pass 1 결과에서 실제 결함이 확인된 항목만 수정한다.

```text
잘못된 Athena Schema·LOCATION
누락된 Pod Identity Test Script
누락된 Evidence 수집
Dashboard Query
```

`terraform fmt`, `validate`, Static Test, Plan까지 수행하고 Apply하지 않는다.

## Pass 3 — 사용자 승인 Runtime 적용·검증

검토된 Plan만 적용하고 Phase 3~8의 Runtime Gate를 수행한다.

---

## Codex Pass 1 시작 Prompt

```text
Repository: Unoh03/bank-security-lab-infra
Base: main

OBSERVABILITY-IAM-DECISIONS.md와
OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 기준으로 Pass 1만 수행하라.

목표:
1. 원래 네 요구사항별 현재 Source와 Runtime 상태를 다시 Inventory한다.
2. Foundation Security Log Bucket의 CloudFront, ALB, VPC REJECT Prefix를 Read-only로 검증한다.
3. Athena Database·Table Metadata와 제한된 실제 Query를 검증한다.
4. 현재 EKS Pod Identity Association·IAM Role·ServiceAccount·Pod Matrix를 만든다.
5. SourceConfigured, RuntimeObserved, EvidenceSaved를 분리한 Gap Report를 작성한다.

금지:
- Source 수정
- terraform apply/destroy
- kubectl apply/patch/delete
- AWS Resource 변경
- IAM Role·Policy 변경
- 새 S3 Bucket·Grafana Resource 생성
- Secret, Access Key, tfstate, tfplan, tfvars Commit

Account 433048100798과 예상 Region을 먼저 검증하라.
Object나 Pod가 없으면 NotObserved 또는 DisabledByDesign으로 기록하고 원인을 추측하지 마라.
종료 시 다음 Pass에서 필요한 최소 변경만 제안하라.
```
