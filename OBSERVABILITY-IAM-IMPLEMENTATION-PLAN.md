# 근실시간 관제·S3 로그 분석·Pod Identity 단계별 실행 계획

> **상태:** S3 Prefix Runtime 완료 / Athena 3 Source 완료 / Grafana Athena 핵심 완료·JSON Export 전  
> **기준 시점:** 2026-08-07  
> **현재 실행 단계:** Phase 4 — Grafana 시각화 마감  
> **결정 근거:** [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)  
> **진행 현황:** [`OBSERVABILITY-CURRENT-STATUS.md`](./OBSERVABILITY-CURRENT-STATUS.md)  
> **보고서 Evidence:** [`report/OBSERVABILITY-EVIDENCE-INDEX.md`](./report/OBSERVABILITY-EVIDENCE-INDEX.md)

이 계획은 다음 요구사항을 완성한다.

```text
1. 공격 중 자동으로 나타나는 근실시간 관제 화면
2. S3 로그의 상세 분석과 Grafana 시각화
3. EKS Workload별 Pod Identity 검증
4. 리소스별 로그 저장 구분과 구성 결과 설명
```

추가 목표로 현재 탐지 중심인 WAF를 검증된 규칙부터 단계적으로 차단 모드로 보강한다.

---

## 0. 실행 원칙

### 0.1 상태 구분

```text
SourceConfigured   Terraform·Script·Manifest가 존재
Planned            변경안·Plan이 검토됨
RuntimeObserved    실제 AWS·Kubernetes·Grafana에서 확인
EvidenceSaved      재현 가능한 결과가 보존됨
```

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
→ 즉시성 우선 Event Feed

Grafana + CloudWatch Logs Insights
→ 근실시간 WAF Event Table·집계

S3 + Athena + Grafana
→ 사후 조사·상관분석·Evidence
```

Athena를 5초 단위 실시간 관제처럼 사용하지 않는다.

---

## 1. 현재 Checkpoint

| 영역 | 현재 상태 | 다음 Gate |
|---|---|---|
| Local WAF Viewer | Runtime·종료·보안·README 완료 | 닫음 |
| Grafana CloudWatch WAF | XSS·SQLi 자동 표시 성공 | Dashboard JSON Export |
| Security Log S3 | 세 Source 최신 Object 확인 | 완료 |
| Bucket Policy | Runtime Policy 확인 | CloudFront 정밀화는 후속 후보 |
| Glue `LOCATION` | 세 Table 실제 Prefix와 일치 | 완료 |
| CloudFront Athena | 34행·343,161 B·주요 Column 정상 | 완료 |
| ALB Athena | 29행·573,530 B·주요 Column 정상 | 완료 |
| VPC REJECT Athena | 999행 이상·3,608,387 B·주요 Column 정상 | 완료 |
| Grafana Athena Overview | VPC·CloudFront·ALB 실제 값 표시 | 완료 |
| Grafana 시간 범위 연동 | Overview 3 Panel 연동 | 완료 |
| Grafana Drill-down | 정상 CSS 사례·WordPress Probe 사례 | 완료 |
| Grafana Athena Export | 미실행 | **현재 Gate** |
| Pod Identity | Source 정의 존재 | Inventory·Runtime Test |
| WAF Hardening | 계획 존재 | 핵심 4개 요구 완료 뒤 수행 |

---

## 2. 실제 실행 순서

```text
Phase 1  WAF Live Viewer Baseline                  완료
Phase 2  S3 Source별 Prefix Runtime                완료
Phase 3  Athena 실제 데이터                       완료
Phase 4  Grafana 시각화                            마감 중
Phase 5  Pod Identity Inventory·Runtime            미착수
Phase 6  WAF 단계적 보강                           후속
Phase 7  최종 Evidence·시연                        후속
```

---

# Phase 1 — WAF Live Viewer Baseline

## 상태

**완료**

구조:

```text
CloudFront WAF
→ CloudWatch Logs
→ aws logs start-live-tail --mode print-only
→ PowerShell JSON Parser
→ 127.0.0.1:8787 Local Viewer
```

확인 완료:

- XSS·SQLi 분류
- 일반 ALLOW Request 무표시
- COUNT와 최종 ALLOW 구분
- Filter별 Clear
- Pause·Resume와 Pause 중 Event 보존
- IP 마스킹
- Raw Event 미저장
- `Ctrl+C` 후 Live Tail 자식 Process 미잔존
- TCP `8787` Listener 미잔존
- README·Source Commit

지연:

```text
Sample: 20, 17, 21, 20, 15, 20, 14초
최소: 14초
최대: 21초
평균: 약 18.1초
```

---

# Phase 2 — S3 Source별 Prefix Runtime

## 상태

**완료**

Security Log Bucket:

```text
aws-topology-security-logs-e10b7e4f152e9420159dba755d
```

| Source | Prefix | 최신 Runtime Object |
|---|---|---|
| CloudFront | `AWSLogs/433048100798/CloudFront/` | `2026-08-07T02:04:13Z`, 560 B |
| Primary ALB | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `2026-08-07T02:00:11Z`, 396 B |
| Primary VPC REJECT | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `2026-08-07T02:04:17Z`, 5,138 B |

Glue `LOCATION`은 실제 Prefix와 일치했다.

CloudFront Bucket Policy Resource는 실제 `/CloudFront/` Prefix보다 넓으므로 최소 권한 정밀화 후보로 남긴다.

---

# Phase 3 — Athena 실제 데이터 검증

## 상태

**완료**

공통 완료 Gate:

- CloudFront·ALB·VPC Query 모두 `SUCCEEDED`
- 세 Table 모두 실제 Data Row 반환
- 주요 Column 파싱 정상
- `DataScannedInBytes` 기록
- Local Evidence 보존

## 3.1 CloudFront

```text
Experiment: athena-cloudfront-trace-20260807T021410Z
State: SUCCEEDED
QueryExecutionId: f86c0bbe-5c1b-478d-ae08-e64b44dece32
Data scanned: 343,161 B
Rows: 34
```

정상 Column:

```text
date, time, source_ip, method, path, status,
edge_request_id, protocol, time_taken
```

기존 Glue Table의 `cs-protocol` 누락은 승인된 `-CreateSchema` 실행으로 보정했다.

## 3.2 Primary ALB

```text
Experiment: athena-alb-window-20260807T022221Z
State: SUCCEEDED
Data scanned: 573,530 B
Rows: 29
```

정상 Column:

```text
event_time, source_ip, method, route,
elb_status_code, target_status_code, trace_id
```

## 3.3 Primary VPC REJECT

```text
Experiment: athena-vpc-reject-20260807T022621Z
State: SUCCEEDED
QueryExecutionId: af6b95f6-5a2f-4512-ad77-cadadda84105
Data scanned: 3,608,387 B
Rows: 999+
```

정상 Column:

```text
srcaddr, dstaddr, dstport, protocol,
rejected_flows, rejected_packets
```

`999+`는 Query Pack 결과 취득 상한 1000행에서 Header를 제외한 값이다.

---

# Phase 4 — Grafana 시각화

## 상태

**핵심 기능 완료 / JSON Export 전**

## 4.1 S3/Athena 조사 Dashboard

Dashboard:

```text
S3 Security Log Overview
```

핵심 Panel:

```text
VPC REJECT - Top Destination Ports
CloudFront - Top Requested Paths
ALB - Top Requested Routes
CloudFront - /dvwa/css/ Request Trace
```

세 Overview Panel은 Dashboard 시간 선택기를 실제 Athena Query 범위에 반영한다.

```text
VPC REJECT → epoch start 필터
CloudFront → date + time 범위
ALB → ISO-8601 time 범위
```

### Drill-down 사례 A — 정상 요청 판정

```text
/dvwa/css/login.css
/dvwa/css/theme.css
```

동일 Source Timeline에서 `/`, `/login.php`, favicon, CSS 요청이 약 1초 내 연속 발생했다.

판정:

```text
로그인 페이지 렌더링에 수반된 정상 정적 리소스 요청 가능성 높음
```

### Drill-down 사례 B — 의심 요청 판정

```text
/wp-admin/install.php
```

여러 Source에서 반복 요청됐고 다수의 경우:

```text
HTTP  GET /wp-admin/install.php → 301
HTTPS GET /wp-admin/install.php → 404
```

동일 Source 전후 ±60초에서는 다른 관리·설정 Path 순회가 확인되지 않았다.

판정:

```text
반복 WordPress 설치 경로 Probe / 자동화 스캔 후보
다중 경로 정찰·침해 성공으로 확대해석하지 않음
```

상세 보고서 문구와 Screenshot 규칙은 `report/OBSERVABILITY-EVIDENCE-INDEX.md`에 기록한다.

## 4.2 현재 마감 Gate

```text
Dashboard JSON Export
→ analytics/dashboard/security-log-investigation.json

최종 Screenshot 파일 정리
Panel SQL 보존
```

완료 후 S3/Athena/Grafana Workstream을 닫는다.

## 4.3 Grafana WAF Dashboard

기능은 이미 성공했다. 별도 마감 작업:

```text
최근 WAF 탐지 Event Table
COUNT·BLOCK 건수
XSS·SQLi 구분
Dashboard JSON Export
```

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
승인된 Test Pod 또는 기존 Pod
sts:GetCallerIdentity
예상 Role 비교
대표 허용 Read API
비허용 API AccessDenied
Test Resource 제거
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

현재 관찰 모드를 유지하면서 오탐과 정상 기능 영향을 확인하고 검증된 규칙부터 실제 차단으로 전환한다.

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

전환 순서:

```text
COUNT Baseline
→ 정상 기능 Regression Baseline
→ 하위 Rule별 오탐 확인
→ BLOCK 후보 지정
→ terraform plan
→ 사용자 승인
→ 제한된 protection-test
→ 공격 차단·정상 기능 동시 Test
→ 문제 시 COUNT Rollback
```

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

## S3·Athena·Grafana

```text
Source별 Prefix와 최신 Object
Bucket Policy
Glue LOCATION
CloudFront·ALB·VPC Query Summary
Rows·DataScannedInBytes
S3 Security Log Overview
정상 CSS Drill-down
WordPress Probe Drill-down
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

---

## 지금 하지 않을 것

```text
Grafana Athena Panel 추가 확장
/wp-admin/install.php를 공격 성공으로 단정
WAF 전체 BLOCK 전환
새 Managed Rule Group 즉시 추가
Source별 S3 Bucket 재설계
Pod Identity 즉석 수정
```
