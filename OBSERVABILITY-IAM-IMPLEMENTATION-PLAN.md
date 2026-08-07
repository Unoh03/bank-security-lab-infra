# 근실시간 관제·S3 로그 분석·Pod Identity 단계별 실행 계획

> **상태:** S3 Prefix Runtime 완료 / CloudFront·ALB Athena 완료 / VPC 결과 확인 전  
> **기준 시점:** 2026-08-07  
> **현재 실행 단계:** Phase 3 — Athena 실제 데이터 검증  
> **결정 근거:** [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)  
> **진행 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)

이 계획은 다음 요구사항을 완성한다.

```text
1. 공격 중 자동으로 나타나는 근실시간 관제 화면
2. S3 로그의 상세 분석과 Grafana 시각화
3. EKS Workload별 Pod Identity 검증
4. 리소스별 로그 저장 구분과 구성 결과 설명
```

추가 목표로 현재 탐지 중심인 WAF를 검증된 규칙부터 단계적으로 차단 모드로 보강한다.

Codex 사용 가능 여부와 무관하게 진행할 수 있도록 Runtime 검증 명령과 완료 Gate를 Repository 문서에 남긴다.

---

## 0. 실행 원칙

### 0.1 상태 구분

```text
SourceConfigured   Terraform·Script·Manifest가 존재
Planned            변경안·Plan이 검토됨
RuntimeObserved    실제 AWS·Kubernetes·Grafana에서 확인
EvidenceSaved      재현 가능한 결과가 보존됨
```

Source가 존재하는 것만으로 완료라고 보고하지 않는다.

### 0.2 변경 통제

Read-only Test와 관측이 먼저다.

```text
금지:
- 필요성 확인 전 Terraform 수정
- 사용자 승인 없는 terraform apply / destroy
- 사용자 승인 없는 kubectl apply / patch / delete
- IAM Role·Policy의 즉석 변경
- WAF 규칙을 관측 없이 일괄 BLOCK 전환
- 새 S3 Bucket·Managed Grafana Resource 생성
- Secret·Access Key·tfstate·tfplan·tfvars Commit
```

변경이 필요하면:

```text
Source Diff
→ terraform fmt·validate
→ terraform plan
→ 사용자 검토·승인
→ 제한된 Runtime 적용
→ 허용·거부·회귀 Test
→ Evidence
```

### 0.3 관제·분석 역할 분리

```text
CloudWatch Live Tail + Local Viewer
→ Polling 없는 즉시성 우선 Event Feed

Grafana + CloudWatch Logs Insights
→ 근실시간 WAF Event Table·집계

S3 + Athena + Grafana
→ 사후 조사·상관분석·Evidence
```

Athena를 5초 단위 실시간 관제처럼 사용하지 않는다.

### 0.4 현재 WAF 성격

현재 WAF는 운영 차단 정책이 아니라 훈련 애플리케이션을 유지하는 관찰 모드다.

```text
Web ACL Default Action: ALLOW
AWSManagedRulesCommonRuleSet: Rule Group 결과 COUNT Override
AWSManagedRulesSQLiRuleSet: Rule Group 결과 COUNT Override
Logging Filter: COUNT·BLOCK만 KEEP
Redaction: Authorization·Cookie
Login Rate Rule: 변수로 명시적으로 켤 때만 생성
```

`COUNT → ALLOW`는 탐지 실패가 아니라 탐지 후 의도적으로 통과시킨 상태다.

---

## 1. 현재 Checkpoint

| 영역 | 현재 상태 | 다음 Gate |
|---|---|---|
| Local WAF Viewer | Runtime·종료·보안·README 검증 완료 | 새 기능 추가 안 함 |
| Grafana CloudWatch WAF | XSS·SQLi 자동 표시 성공 | Dashboard 저장·JSON Export |
| Security Log S3 | 세 Source 최신 Object 확인 | 완료 |
| Bucket Policy | Runtime Policy 확인 | CloudFront 범위 정밀화는 후속 후보 |
| Glue `LOCATION` | 세 Table 실제 Prefix와 일치 | 완료 |
| CloudFront Athena | 34행·주요 Column 정상 | 완료 |
| ALB Athena | 29행·주요 Column 정상 | 완료 |
| VPC REJECT Athena | Query Pack 완료 | Row 수·Column 파싱 확인 |
| Grafana Athena | Data Source 연결 성공 | 조사 Dashboard 구성 |
| Pod Identity | Source 정의 존재 | AWS·Kubernetes Inventory·Runtime Test |
| WAF Hardening | 계획 존재 | 핵심 4개 요구 완료 뒤 수행 |

---

## 2. 실제 실행 순서

```text
Phase 1  WAF Live Viewer Baseline                  완료
Phase 2  S3 Source별 Prefix Runtime                완료
Phase 3  Athena 실제 데이터                       진행 중
Phase 4  Grafana 시각화                            다음
Phase 5  Pod Identity Inventory·Runtime            미착수
Phase 6  WAF 단계적 보강                           후속
Phase 7  최종 Evidence·시연                        후속
```

Phase를 건너뛰어 새 기능을 추가하지 않는다.

---

# Phase 1 — WAF Live Viewer Baseline

## 상태

**완료**

## 구현

```text
CloudFront WAF
→ CloudWatch Logs
→ aws logs start-live-tail --mode print-only
→ PowerShell JSON Parser
→ 127.0.0.1:8787 Local Viewer
```

Repository:

```text
tools/waf-live-viewer/Start-WafLiveViewer.ps1
tools/waf-live-viewer/README.md
```

## 확인 완료

- XSS·SQLi 분류
- 일반 ALLOW Request 무표시
- COUNT와 최종 ALLOW 구분
- 최신 Event 여러 건
- XSS·SQLi·BLOCK Filter
- Filter별 Clear
- Pause·Resume와 Pause 중 Event 보존
- IP 마스킹
- Request ID·JA3·JA4·Cookie·전체 Header 미표시
- Raw Event 미저장
- `Ctrl+C` 후 Live Tail 자식 Process 미잔존
- TCP `8787` Listener 미잔존
- README와 Source Commit·Push

지연:

```text
Sample: 20, 17, 21, 20, 15, 20, 14초
최소: 14초
최대: 21초
평균: 약 18.1초
```

## 종료 조건

이 Phase는 다시 열지 않는다. 다음은 Phase 4의 Grafana WAF Dashboard Export만 남아 있다.

---

# Phase 2 — S3 Source별 Prefix Runtime

## 상태

**핵심 완료**

## Security Log Bucket

```text
aws-topology-security-logs-e10b7e4f152e9420159dba755d
```

## 실제 Prefix와 최신 Object

| Source | Prefix | 최신 Runtime Object |
|---|---|---|
| CloudFront | `AWSLogs/433048100798/CloudFront/` | `2026-08-07T02:04:13Z`, 560 bytes |
| Primary ALB | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `2026-08-07T02:00:11Z`, 396 bytes |
| Primary VPC REJECT | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `2026-08-07T02:04:17Z`, 5,138 bytes |

## Glue `LOCATION`

```text
cloudfront_access
→ s3://<bucket>/AWSLogs/433048100798/CloudFront

alb_primary_access
→ s3://<bucket>/alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2

vpc_reject
→ s3://<bucket>/vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2
```

실제 Prefix와 일치한다.

## Bucket Policy 판정

```text
VendedLogWrite
- delivery.logs.amazonaws.com
- AWSLogs/433048100798/*
- vpc-flow/AWSLogs/433048100798/*

PrimaryAlbAccessLogWrite
- logdelivery.elasticloadbalancing.amazonaws.com
- alb/primary/AWSLogs/433048100798/*
```

판정:

- Source별 실제 저장 분리: 완료
- ALB Prefix Write 제한: 확인
- VPC Flow Prefix Write 제한: 확인
- CloudFront 실제 Prefix: 확인
- CloudFront Policy Resource: 실제 `/CloudFront/` Prefix보다 넓으므로 최소 권한 정밀화 후보

CloudFront Policy 범위는 현재 기능 실패가 아니며, 핵심 구현을 멈추고 즉시 재설계하지 않는다.

---

# Phase 3 — Athena 실제 데이터 검증

## 상태

**진행 중**

## 공통 기준

- 6시간 이하의 제한된 시간창
- Query Pack 사용
- QueryExecutionId·State·DataScannedInBytes 기록
- Data Row 수 확인
- 주요 Column의 NULL·파싱 상태 확인
- 공개 화면의 IP 마스킹
- Athena Result와 Local Evidence 경로 보존

## 3.1 CloudFront

**완료**

실행 중 기존 Glue Table에 `cs-protocol`이 없음을 발견했다.

승인된 `-CreateSchema` 실행으로:

```text
CREATE TABLE IF NOT EXISTS
→ 기존 S3 Object 유지
→ ALTER TABLE ADD COLUMNS (`cs-protocol` string)
→ SELECT 실행
```

결과:

| 항목 | 값 |
|---|---|
| Experiment ID | `athena-cloudfront-trace-20260807T021410Z` |
| State | `SUCCEEDED` |
| QueryExecutionId | `f86c0bbe-5c1b-478d-ae08-e64b44dece32` |
| Data scanned | `343,161 bytes` |
| Data rows | `34` |

정상 확인 Column:

```text
date, time, source_ip, method, path, status,
edge_request_id, protocol, time_taken
```

`cs-protocol`의 `http`·`https`는 HTTP Version이 아니라 Request Scheme이다.

Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-cloudfront-trace-20260807T021410Z
```

## 3.2 Primary ALB

**완료**

결과:

| 항목 | 값 |
|---|---|
| Experiment ID | `athena-alb-window-20260807T022221Z` |
| State | `SUCCEEDED` |
| Data scanned | `573,530 bytes` |
| Data rows | `29` |

정상 확인 Column:

```text
event_time, source_ip, method, route,
elb_status_code, target_status_code, trace_id
```

CloudFront 뒤 ALB의 `source_ip`를 곧바로 외부 원본 Client IP로 단정하지 않는다.

Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-alb-window-20260807T022221Z
```

## 3.3 Primary VPC REJECT

**현재 작업**

실행:

```text
Experiment ID: athena-vpc-reject-20260807T022621Z
Query Pack: completed
```

Query Pack은 Athena State가 `SUCCEEDED`가 아니면 완료 전에 예외를 발생시키므로 실행 성공까지는 확인됐다.

남은 검증:

```text
DataScannedInBytes
Data Row 수
srcaddr
dstaddr
dstport
protocol
rejected_flows
rejected_packets
IP 마스킹 Sample
```

Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-vpc-reject-20260807T022621Z
```

## 바로 다음 명령

```powershell
$root = 'C:\Users\Unoh\Documents\aws-topology-evidence\athena-vpc-reject-20260807T022621Z'

$summary = Get-Content `
  "$root\results\athena\athena-run-summary.json" `
  -Raw | ConvertFrom-Json

$summary.Executions |
  Select-Object Label, State, DataScannedInBytes, EngineExecutionTimeInMillis, QueryExecutionId |
  Format-Table -AutoSize

$result = Get-Content `
  "$root\results\athena\vpc-reject-results.json" `
  -Raw | ConvertFrom-Json

"Returned data rows: $(@($result.ResultSet.Rows).Count - 1)"
```

## Phase 3 완료 Gate

- CloudFront·ALB·VPC Query 모두 `SUCCEEDED`
- 세 Table 모두 실제 Data Row 반환 또는 0행의 원인을 Runtime으로 설명
- 주요 Column 파싱 정상
- DataScannedInBytes 기록
- Local Evidence 보존

---

# Phase 4 — Grafana 시각화

## 상태

**Phase 3 완료 후 진행**

## 4.1 S3/Athena 조사 Dashboard

목적:

> S3에 보존된 CloudFront·ALB·VPC 로그를 필요할 때 조사하고 시각적으로 설명한다.

Data Source:

```text
Amazon Athena
Catalog: AwsDataCatalog
Database: aws_topology_security
Workgroup: primary
```

최소 Panel:

### CloudFront

```text
최근 Request Table
Status별 요청 수
Top Path
```

### ALB

```text
Route·ELB Status·Target Status Table
4xx·5xx 건수
Trace ID 확인
```

### VPC REJECT

```text
Top Source
Top Destination Port
Rejected Flow·Packet 수
```

공통 기준:

- 시간 범위를 제한한다.
- Dashboard Query에서 광범위한 무제한 `SELECT *`를 사용하지 않는다.
- Athena 자동 갱신은 Off 또는 긴 간격으로 둔다.
- IP·Request ID의 공개 범위를 검토한다.
- 실제 동작한 뒤 Dashboard JSON을 Export한다.

산출물:

```text
analytics/dashboard/security-log-investigation.json
Panel SQL
Dashboard Screenshot
Query State·Scan량
```

완료 Gate:

- CloudFront·ALB·VPC Panel에 실제 값 표시
- Time Range가 Query에 반영
- Dashboard JSON Export
- Screenshot과 SQL 보존

## 4.2 WAF 근실시간 Dashboard

목적:

> Local Viewer는 즉시 Event Feed, Grafana는 표·건수·추세를 담당한다.

최소 Panel:

```text
최근 WAF 탐지 Event Table
최근 COUNT·BLOCK 건수
XSS·SQLi 분류
Top URI 또는 Country
```

기준:

```text
Data Source: CloudWatch
Region: us-east-1
Log Group: aws-waf-logs-aws-topology-edge
Auto Refresh: 5s 또는 비용 검토 후 10s
Time Range: 최근 5~15분
```

완료 Gate:

- 새 XSS·SQLi Event 자동 표시
- Raw JSON 없이 핵심 Field 확인
- Dashboard JSON Export
- Local Viewer와 역할 차이 설명

---

# Phase 5 — Pod Identity Inventory·Runtime

## 5.1 Inventory

대상 Workload:

```text
AWS Load Balancer Controller
ExternalDNS
EFS CSI Controller
Web S3 Workload
Fluent Bit
Karpenter
```

Matrix:

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

상태값:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
NoAssociationExpected
```

## 5.2 Runtime Test

각 ServiceAccount에 대해:

```text
Association 확인
실제 Pod ServiceAccount 확인
같은 ServiceAccount의 승인된 Test Pod
sts:GetCallerIdentity
예상 Role 비교
대표 허용 Read API
비허용 API AccessDenied
Test Pod 삭제
```

Association 없는 ServiceAccount:

```text
Credential 없음 → 통과
Node Role 반환 → 격리 미충족
다른 Role 반환 → RuntimeUnexpected
```

완료 Gate:

- Source와 Runtime Association 일치
- 예상 IAM Role 획득
- 허용 API 성공
- 비허용 API 거부
- Node Role Negative Test 통과
- 임시 Resource 제거

---

# Phase 6 — WAF 단계적 보강

## 상태

**핵심 4개 요구 완료 후 진행**

## 목표

현재 관찰 모드를 유지하면서 오탐과 정상 기능 영향을 확인하고, 검증된 규칙부터 실제 차단으로 전환한다.

정확한 현재 표현:

> AWS Managed Rules를 COUNT 모드로 배치해 공격을 차단하지 않고 탐지·관제 기준선을 수집하고 있다. 정상 트래픽과 오탐을 확인한 뒤 검증된 규칙부터 단계적으로 BLOCK으로 전환한다.

## Mode

```text
training
- Common Rule Set: COUNT
- SQLi Rule Set: COUNT
- Login Rate Rule: disabled 또는 COUNT

protection-test
- 검증된 XSS·SQLi Rule: BLOCK
- 오탐 후보 Rule: COUNT 유지
- Login Rate Rule: COUNT → BLOCK
- 정상 기능 Regression 필수
```

## 전환 순서

1. COUNT Event를 Rule ID·URI·Method별로 수집
2. 정상 로그인·조회·검색·정적 Asset Regression Baseline
3. 하위 Rule별 오탐 확인
4. 필요 시 Rule Group 전체 Override를 개별 Rule Override로 세분화
5. BLOCK 후보 지정
6. `terraform plan`
7. 사용자 승인
8. 제한된 `protection-test`
9. 공격 차단·정상 기능 동시 Test
10. 문제 발생 시 COUNT Rollback

추가 후보:

```text
AWSManagedRulesKnownBadInputsRuleSet
AWSManagedRulesAmazonIpReputationList
```

새 Group은 COUNT로 먼저 관측한다. Bot Control·ATP·Anti-DDoS 등 별도 요금 기능은 별도 판단한다.

---

# Phase 7 — 최종 Evidence·시연

## 근실시간 관제

```text
CloudWatch Data Source
Grafana WAF Dashboard
Live Tail CLI
Local Viewer
XSS·SQLi Event
지연 측정
```

## S3·Athena

```text
Source별 Prefix와 최신 Object
Bucket Policy
Glue LOCATION
CloudFront·ALB·VPC Query Summary
Rows·DataScannedInBytes
Grafana Athena Dashboard
```

## Pod Identity

```text
Workload Matrix
Association·Role ARN
Pod ServiceAccount
STS Identity
허용·거부 API
Node Role Negative Test
```

최종 판정표:

| 요구사항 | Source | Runtime | Evidence | 판정 |
|---|---|---|---|---|
| 근실시간 관제 |  |  |  |  |
| S3 로그 분석·Grafana |  |  |  |  |
| S3 로그 저장 구분 |  |  |  |  |
| Pod Identity |  |  |  |  |
| WAF 단계적 보강 |  |  |  |  |

---

## 지금 하지 않을 것

```text
VPC 결과 확인 전 Dashboard 추정 작성
WAF 전체 BLOCK 전환
새 Managed Rule Group 즉시 추가
Grafana Cloud 재시도
Amazon Managed Grafana
EventBridge·SNS Alert
자동 격리·자동 차단
Source별 S3 Bucket 재설계
Pod Identity 즉석 수정
Viewer 기능 추가
```

---

## 공식 참고

- CloudWatch Logs Live Tail: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_LiveTail.html
- AWS CLI `start-live-tail`: https://docs.aws.amazon.com/cli/latest/reference/logs/start-live-tail.html
- Amazon Athena: https://docs.aws.amazon.com/athena/latest/ug/what-is.html
- Athena CloudFront JSON Table: https://docs.aws.amazon.com/athena/latest/ug/create-cloudfront-table-manual-json.html
- Athena ALB Access Logs: https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html
- Athena VPC Flow Logs: https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html
- Testing and tuning AWS WAF protections: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html
- WAF Rule Group Action Override: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-group-override-options.html
- Amazon EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
