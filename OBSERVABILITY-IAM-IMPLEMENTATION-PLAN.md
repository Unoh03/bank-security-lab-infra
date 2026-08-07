# 근실시간 관제·S3 로그 분석·Pod Identity 단계별 실행 계획

> **상태:** S3 Prefix·Athena 3 Source·Grafana Athena Overview·Drill-down·JSON Export 완료  
> **기준 시점:** 2026-08-07  
> **현재 실행 단계:** Phase 5 — Pod Identity Inventory·Runtime  
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

Source 존재만으로 완료라고 보고하지 않는다.

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
| Grafana Athena Export | `analytics/dashboard/security-log-investigation.json` | 완료 |
| Pod Identity | Source 정의 존재 | **Inventory·Runtime Test** |
| WAF Hardening | 계획 존재 | 핵심 4개 요구 완료 뒤 수행 |

---

## 2. 실제 실행 순서

```text
Phase 1  WAF Live Viewer Baseline                  완료
Phase 2  S3 Source별 Prefix Runtime                완료
Phase 3  Athena 실제 데이터                       완료
Phase 4  Grafana Athena 시각화·Export              완료
Phase 5  Pod Identity Inventory·Runtime            현재
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

| Source | State | Data scanned | Rows | 주요 Parsing |
|---|---:|---:|---:|---|
| CloudFront | SUCCEEDED | 343,161 B | 34 | 정상 |
| ALB | SUCCEEDED | 573,530 B | 29 | 정상 |
| VPC REJECT | SUCCEEDED | 3,608,387 B | 999+ | 정상 |

CloudFront의 기존 Glue Table에서 누락됐던 `cs-protocol`은 승인된 `-CreateSchema` 실행으로 보정했다.

`999+`는 Query Pack 결과 취득 상한 1000행에서 Header를 제외한 값이다.

Local Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-cloudfront-trace-20260807T021410Z
C:\Users\Unoh\Documents\aws-topology-evidence\athena-alb-window-20260807T022221Z
C:\Users\Unoh\Documents\aws-topology-evidence\athena-vpc-reject-20260807T022621Z
```

---

# Phase 4 — Grafana Athena 시각화·Export

## 상태

**완료**

Dashboard:

```text
S3 Security Log Overview
```

Repository Export:

```text
analytics/dashboard/security-log-investigation.json
```

최종 Panel:

```text
VPC REJECT - Top Destination Ports
CloudFront - Top Requested Paths
ALB - Top Requested Routes
CloudFront - /dvwa/css/ Request Trace
CloudFront - /wp-admin/install.php Request Trace
```

완료 Gate:

- VPC·CloudFront·ALB Panel에 실제 값 표시
- 각 Overview Panel이 올바른 Athena Table을 조회
- Dashboard Time Range가 Query에 반영
- Drill-down SQL에서 Client IPv4 마지막 Octet 마스킹
- Credential·Raw Client IP·Request ID 하드코딩 없음
- Dashboard JSON Repository 저장

Athena Data Source UID:

```text
efubxj2vag7i8b
```

이는 AWS Credential이 아니라 현재 Grafana 인스턴스의 Data Source 식별자다. 다른 인스턴스로 Import할 때 Athena Data Source 재연결이 필요할 수 있다.

### Drill-down 사례 A — 정상 요청

```text
/dvwa/css/login.css
/dvwa/css/theme.css
```

동일 Source Timeline에서 `/`, `/login.php`, favicon, CSS 요청이 약 1초 내 연속 발생했다.

```text
로그인 페이지 렌더링에 수반된 정상 정적 리소스 요청 가능성 높음
```

### Drill-down 사례 B — 의심 요청

```text
/wp-admin/install.php
```

여러 Source에서 반복 요청됐고 다수의 경우:

```text
HTTP  GET /wp-admin/install.php → 301
HTTPS GET /wp-admin/install.php → 404
```

동일 Source 전후 ±60초에서는 다른 관리·설정 Path 순회가 확인되지 않았다.

```text
반복 WordPress 설치 경로 Probe / 자동화 스캔 후보
다중 경로 정찰·침해 성공으로 확대해석하지 않음
```

이 Phase는 닫는다. 새 Athena Panel을 추가하지 않는다.

---

# Phase 5 — Pod Identity Inventory·Runtime

## 상태

**현재 작업**

## 5.1 Inventory

예상 대상 Workload:

```text
AWS Load Balancer Controller
ExternalDNS
EFS CSI Controller
Web S3 Workload
Fluent Bit
Karpenter
```

먼저 다음 Matrix를 Read-only로 작성한다.

| Cluster | Namespace | Workload | ServiceAccount | Association ID | Role ARN | Source 상태 | Runtime 상태 |
|---|---|---|---|---|---|---|---|

상태값:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
NoAssociationExpected
```

Inventory Evidence:

```text
AWS EKS Pod Identity Association 목록
Kubernetes Workload → ServiceAccount 연결
ServiceAccount 실제 존재
IAM Role·Policy Summary
Terraform Source 정의
```

Source와 Runtime이 다르면 즉시 수정하지 않고 `RuntimeUnexpected` 또는 `ConfiguredButRuntimeAbsent`로 기록한다.

## 5.2 Runtime STS Test

Inventory가 확정된 ServiceAccount부터 검증한다.

```text
Association 확인
→ 실제 Pod ServiceAccount 확인
→ 기존 Pod 또는 승인된 임시 Test Pod
→ sts:GetCallerIdentity
→ 예상 Role ARN 비교
```

기존 Workload Container에 AWS CLI가 없거나 운영 동작을 방해할 위험이 있으면, 같은 ServiceAccount를 사용하는 제한된 Test Pod를 별도로 사용한다. `kubectl apply`가 필요하면 Source·Manifest·제거 절차를 먼저 검토하고 사용자 승인을 받는다.

## 5.3 허용·거부 API Test

각 Role마다 최소 한 개씩 검증한다.

```text
대표 허용 Read API → 성공
비허용 API         → AccessDenied
```

예시 범위는 실제 Policy를 읽은 뒤 정한다. 권한을 추측해 임의 API를 호출하지 않는다.

## 5.4 Node Role Negative Test

Association 없는 ServiceAccount 또는 명시적 Negative Test 대상에서:

```text
Credential 없음 → 통과
Node Role 반환   → 격리 미충족
다른 Role 반환   → RuntimeUnexpected
```

## 5.5 완료 Gate

- Source와 Runtime Association 일치
- 실제 Pod가 예상 ServiceAccount 사용
- `sts:GetCallerIdentity`가 예상 Pod Identity Role 반환
- 허용 API 성공
- 비허용 API `AccessDenied`
- Association 없는 대상이 Node Role을 획득하지 않음
- 임시 Test Resource 제거
- Evidence Matrix 저장

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
Dashboard JSON Export
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
