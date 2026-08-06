# 근실시간 관제·S3 로그 분석·Pod Identity 단계별 실행 계획

> 상태: **WAF Grafana Runtime 확인 / Live Tail Viewer 다음 작업 / 자동 변경 금지**  
> 기준 시점: 2026-08-06  
> 결정 근거: [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)

이 계획은 다음 네 요구사항을 완성한다.

```text
1. 공격 중 자동으로 나타나는 근실시간 관제 화면
2. S3 로그의 상세 분석과 Evidence
3. EKS Workload별 Pod Identity 검증
4. 리소스별 로그 저장 구분과 결과 설명
```

특정 Grafana 제품은 필수가 아니다. 현재 Local Docker Grafana와 AWS CloudWatch·Athena를 사용한다.

---

## 0. 실행 원칙

### 0.1 단계 상태

```text
SourceConfigured   Terraform·Script·Manifest가 존재
Planned            변경안·Plan이 검토됨
RuntimeObserved    실제 AWS·Kubernetes·Grafana에서 확인
EvidenceSaved      재현 가능한 결과가 보존됨
```

Source가 존재하는 것만으로 완료라고 보고하지 않는다.

### 0.2 변경 통제

Read-only Test가 먼저다.

```text
금지:
- 필요성 확인 전 Terraform 수정
- terraform apply / destroy
- kubectl apply / patch / delete
- IAM Role·Policy의 즉석 변경
- 새 S3 Bucket·Managed Grafana Resource 생성
- Secret·Access Key·tfstate·tfplan·tfvars Commit
```

Live Tail CLI Test가 성공하면 Terraform을 수정하지 않는다. `AccessDenied`일 때만 Credential 관리 경계를 확인하고 최소 권한 Source·Plan을 작성한다.

### 0.3 역할 분리

```text
Grafana + CloudWatch Logs Insights
→ 읽기 쉬운 근실시간 Dashboard

CloudWatch Live Tail
→ Polling 없는 즉시성 우선 Event Feed

S3 + Athena
→ 사후 조사·상관분석·Evidence
```

---

## 1. 현재 Checkpoint

| 항목 | 현재 상태 | 다음 Gate |
|---|---|---|
| Local Docker Grafana | 실행·접속 성공 | 재현 정보 유지 |
| Athena Data Source | `Data source is working` | 실제 Table 행·Schema 검증 |
| Athena Table 목록 | 3개 확인 | S3 Object·실제 행 확인 |
| CloudWatch Data Source | Metrics·Logs API 연결 성공 | Dashboard 정리 |
| WAF Log Group | `us-east-1/aws-waf-logs-aws-topology-edge` 조회 성공 | Field 정규화 |
| XSS Test | COUNT Event 확인 | Evidence 유지 |
| SQLi Test | Event 자동 표시 확인 | 하위 Rule Field 확인 |
| Grafana Auto Refresh | `5s` | Dashboard 저장·지연 반복 측정 |
| 관측된 표시 지연 | 대략 10초 | Live Tail과 비교 |
| CloudWatch Live Tail | 미실행 | Permission·Runtime Smoke Test |
| Readable Live Tail Viewer | 미구현 | Codex 구현 |
| Pod Identity Source | 여러 Workload 정의 | AWS·Kubernetes Inventory |
| Pod Identity Runtime | 전체 재검증 안 됨 | STS·허용·거부 Test |

현재 Grafana Runtime Evidence는 다음 Obsidian Note에 있다.

```text
10_학습 노트/클라우드/Grafana 로컬 Docker에서 CloudWatch WAF 근실시간 관제.md
10_학습 노트/클라우드/Grafana 로컬 Docker에서 Athena 연결.md
```

---

# Phase 1 — 현재 WAF Grafana 관제 Baseline 고정

## 목표

이미 성공한 Grafana 경로를 추정이 아니라 재현 가능한 Baseline으로 남긴다.

## 현재 Query

```sql
fields
    @timestamp,
    action,
    terminatingRuleId,
    httpRequest.country,
    httpRequest.clientIp,
    httpRequest.httpMethod,
    httpRequest.host,
    httpRequest.uri,
    httpRequest.args
| sort @timestamp desc
| limit 50
```

## 수행

1. Dashboard와 Panel 이름을 의미 있게 지정한다.
2. Auto Refresh를 `5s`로 유지한다.
3. XSS와 SQLi Request를 각각 다시 1회 실행한다.
4. Request 시각, WAF Event `@timestamp`, Grafana 표시 시각을 기록한다.
5. 동일 조건에서 3회 이상 측정해 최소·최대·대략적 평균을 기록한다.
6. Dashboard JSON과 Screenshot을 보존한다.

## 읽기 쉬운 출력 기준

```text
Timestamp
탐지 Rule 또는 Rule Group
COUNT / BLOCK
최종 Action
Country
Source IP
Method
Host
URI
Args
```

WAF 중첩 JSON에서 탐지 Rule이 단순 Field Query로 나오지 않으면 Dashboard Transform 또는 별도 Query를 검증한다. 컴파일되지 않은 `jsonParse` Query를 확정본으로 저장하지 않는다.

## 완료 Gate

- 사용자 입력 없이 새 Event 자동 표시
- XSS·SQLi Event 구분 가능
- 실제 지연 측정값 보존
- Raw JSON을 열지 않아도 핵심 요청 정보를 읽을 수 있음

---

# Phase 2 — CloudWatch Live Tail Permission·Runtime Smoke Test

## 목표

Terraform을 건드리기 전에 현재 `terra-user`로 Live Tail이 실행되는지 확인한다.

## 사전 확인

```powershell
aws --version
aws sts get-caller-identity --profile terra-user
aws logs describe-log-groups `
  --profile terra-user `
  --region us-east-1 `
  --log-group-name-prefix 'aws-waf-logs-aws-topology-edge' `
  --query 'logGroups[].{name:logGroupName,class:logGroupClass,arn:arn}' `
  --output table
```

판정:

- Account는 `433048100798`
- Log Group은 `STANDARD`
- Live Tail Identifier에는 ARN 끝의 `:*`를 포함하지 않음

## CLI Test

```powershell
aws logs start-live-tail `
  --profile terra-user `
  --region us-east-1 `
  --log-group-identifiers `
  arn:aws:logs:us-east-1:433048100798:log-group:aws-waf-logs-aws-topology-edge `
  --mode interactive
```

Test 중 통제된 XSS Request를 1회 발생시킨다. 종료는 `Ctrl+C`다.

## 판정

### 성공

```text
Terraform 변경 없음
IAM 변경 없음
Live Tail RuntimeObserved
Phase 3 Viewer 구현으로 진행
```

### `AccessDenied`

다음만 수행한다.

1. 현재 Principal과 연결된 Policy Source를 확인한다.
2. `logs:StartLiveTail`, 필요 시 `logs:StopLiveTail`의 최소 권한안을 작성한다.
3. WAF Log Group ARN으로 Resource를 제한할 수 있는지 검토한다.
4. Terraform 또는 기존 IAM 관리 방식의 Source Diff와 Plan만 만든다.
5. 사용자 승인 전 Apply하지 않는다.

### 기타 실패

```text
CLI Version
ARN `:*` 포함 여부
Region
Log Group Class
Network·Proxy
SDK/CLI Streaming 지원
```

을 구분한다. 권한 문제로 추측하지 않는다.

## Evidence

```text
시작 시각
종료 시각
Session 지속 시간
수신 Event 시각
Request → Live Tail 표시 지연
명령 Exit 상태
오류 전문 또는 성공 Screenshot
```

---

# Phase 3 — Readable WAF Live Tail Viewer 구현

## 목표

CloudWatch Live Tail Raw JSON을 관제자가 즉시 읽을 수 있는 한 줄 Event로 변환한다.

## 구현 선택

Codex는 Repository와 로컬 환경을 확인한 뒤 다음 중 가장 단순하고 재현 가능한 방식을 선택한다.

```text
PowerShell Wrapper
Python/boto3 Streaming Viewer
작은 Local Web UI
```

Terraform은 구현 수단이 아니다. 현재 Credential로 Live Tail이 성공하면 Local Source만 추가한다.

## 필수 출력

| 표시 항목 | WAF Field 예시 |
|---|---|
| Event Time | `timestamp` 또는 수신 Event 시각 |
| Detection | Matching Rule ID |
| Detection Mode | `COUNT` / `BLOCK` |
| Final Action | `ALLOW` / `BLOCK` |
| Country | `httpRequest.country` |
| Source IP | `httpRequest.clientIp` |
| Method | `httpRequest.httpMethod` |
| Host | `httpRequest.host` |
| URI | `httpRequest.uri` |
| Args | `httpRequest.args` |

## 동작 요구

```text
새 Event를 Streaming으로 지속 수신
한 Event를 한 행 또는 한 Card로 표시
XSS·SQLi·Rate Rule을 구분
COUNT와 최종 ALLOW를 혼동하지 않음
Ctrl+C 또는 종료 동작으로 Session 종료
자동 재시작은 기본 비활성
원본 JSON 저장은 기본 비활성
```

## 보안 요구

- Access Key·Secret Key를 Source나 Output에 기록하지 않는다.
- WAF Cookie Redaction을 유지한다.
- Evidence 저장 시 Client IP, Request ID, JA3·JA4 전체 값의 공개 여부를 별도 검토한다.
- Viewer가 Log를 별도 파일에 무기한 저장하지 않는다.
- Session 시작·종료 시각을 표시해 사용 시간을 통제한다.

## Test

```text
XSS Query Argument
SQL Injection Query Argument
일반 ALLOW Request
동시에 여러 Event
Ctrl+C 종료
3시간 전에 수동 종료
```

WAF Logging Filter 때문에 일반 ALLOW Request가 저장되지 않을 수 있다. 이 경우 `NoEventExpected`로 기록한다.

## 산출물 예시

```text
observability/live-tail/
├─ README.md
├─ Start-WafLiveTail.ps1 또는 viewer.py
└─ tests/
```

정확한 파일 구조는 기존 Repository 관례를 우선한다.

## 완료 Gate

- Live Tail Event가 Polling 없이 수신
- 주요 Field가 읽기 쉬운 형태로 표시
- XSS·SQLi 구분
- Session 정상 종료
- 설치·실행 절차 재현
- AWS Resource 변경 없음 또는 승인된 최소 IAM 변경만 존재

---

# Phase 4 — Grafana 근실시간 Dashboard 정리

## 목표

Live Tail은 즉시성, Grafana는 집계와 상황판을 담당하도록 역할을 분리한다.

## Panel 후보

```text
최근 WAF 탐지 Event Table
최근 5분 COUNT·BLOCK 수
XSS·SQLi·Rate Rule별 건수
Country별 탐지 수
Top URI
최종 ALLOW·BLOCK 비율
```

## 공통 기준

```text
Auto Refresh: 5s 또는 비용 검토 후 10s
Time Range: 최근 5~15분
Query Window 최소화
Raw @message 기본 숨김
Cookie·Authorization·Body 미표시
```

Dashboard는 Live Tail Viewer를 대체하지 않는다. 약 10초의 현재 지연을 허용하는 읽기 쉬운 관제 화면으로 사용한다.

## 산출물

```text
analytics/dashboard/waf-realtime-overview.json
Panel Query
Dashboard Screenshot
측정된 표시 지연
```

빈 Dashboard JSON을 먼저 Commit하지 않는다. 실제 동작한 뒤 Export한다.

---

# Phase 5 — S3 로그 저장·분리 Runtime 검증

## 목표

사후 분석 Source가 실제로 각 Prefix에 저장되는지 확인한다.

| ID | Prefix |
|---|---|
| `cloudfront` | `AWSLogs/433048100798/CloudFront/` |
| `alb-primary` | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` |
| `vpc-reject-primary` | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` |

수행:

1. Foundation Output에서 실제 Bucket 이름을 읽는다.
2. 각 Prefix의 Object Count와 최신 Object를 확인한다.
3. Bucket Policy Write Resource와 실제 Prefix를 대조한다.
4. Object가 없으면 `NotObserved`로 기록한다.

완료 조건:

```text
Source별 Prefix가 겹치지 않음
Bucket Policy가 Source별 Prefix로 제한됨
Athena LOCATION이 Prefix와 일치
실제 Object가 예상 Prefix에 존재
```

---

# Phase 6 — Athena 실제 데이터 검증

## 대상

```text
cloudfront_access
alb_primary_access
vpc_reject
```

수행:

- Table Metadata·LOCATION·SerDe 대조
- 제한된 시간 범위 Query
- QueryExecutionId, Row, DataScannedInBytes 기록
- 주요 Column의 NULL·Parsing 상태 확인

Athena는 실시간 관제 경로가 아니다. 필요할 때 상세 조사하고 `daily-down.ps1 -EvidenceOnly` 결과와 상호 보완한다.

---

# Phase 7 — Pod Identity Inventory

## 예상 Workload

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

상태:

```text
ConfiguredAndObserved
ConfiguredButRuntimeAbsent
RuntimeUnexpected
DisabledByDesign
NoAssociationExpected
```

---

# Phase 8 — Pod Identity Runtime 권한 검증

각 ServiceAccount에 대해:

```text
Association 확인
실제 Pod ServiceAccount 확인
같은 ServiceAccount의 임시 AWS CLI Pod
sts:GetCallerIdentity
예상 Role 비교
대표 허용 Read API
비허용 API AccessDenied
임시 Pod 삭제
```

Association 없는 ServiceAccount도 STS를 실행한다.

```text
Credential 없음 → 통과
Node Role 반환 → 격리 미충족
다른 Role 반환 → RuntimeUnexpected
```

---

# Phase 9 — Evidence와 최종 설명

## 근실시간 관제

```text
Grafana CloudWatch 연결 성공
WAF Dashboard와 Auto Refresh
XSS·SQLi Event
Grafana 표시 지연
Live Tail CLI Test
Readable Viewer 화면
Live Tail 표시 지연
```

## S3·Athena

```text
Source별 Prefix와 최신 Object
Athena Metadata
QueryExecutionId
Rows·DataScannedInBytes
```

## Pod Identity

```text
Workload Matrix
Association·Role ARN
Pod ServiceAccount
STS Identity
허용·거부 API 결과
Node Role Negative Test
```

최종 보고:

| 요구사항 | Source | Runtime | Evidence | 판정 |
|---|---|---|---|---|
| 근실시간 관제 |  |  |  |  |
| S3 로그 분석 |  |  |  |  |
| S3 로그 분리 |  |  |  |  |
| Pod Identity |  |  |  |  |

---

# Phase 10 — 핵심 완료 후 선택 범위

```text
GuardDuty → EventBridge → SNS
Grafana Alert Rule
자동 격리·자동 차단
Amazon Managed Grafana
Grafana Cloud
별도 Athena Result Bucket
Source별 S3 Bucket Migration
```

---

# Codex Pass 계획

## Pass 1 — Live Tail Feasibility·Viewer 설계

목표:

```text
현재 Account·CLI·Log Group Class 확인
Live Tail Permission·Runtime Smoke Test
Terraform 필요 여부 판정
Local Viewer 구현 방식 결정
Source·Test·README 작성
```

규칙:

- CLI Test 성공 시 IAM·Terraform을 수정하지 않는다.
- AccessDenied일 때만 최소 권한 Diff와 Plan을 작성한다.
- 사용자 승인 없이 Apply하지 않는다.
- Raw WAF JSON을 사람이 읽을 수 있는 Event로 변환한다.

## Pass 2 — Grafana Dashboard·S3·Athena Baseline

```text
WAF Dashboard Export
표시 지연 반복 측정
S3 Prefix Object 확인
Athena 실제 행·Schema 확인
```

## Pass 3 — Pod Identity Runtime

검토된 Inventory와 Test Script를 이용해 사용자 승인 후 Runtime을 검증한다.

---

## Codex Pass 1 시작 Prompt

```text
Repository: Unoh03/bank-security-lab-infra
Base: main

OBSERVABILITY-IAM-DECISIONS.md와
OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md를 읽고 Live Tail 관련 Pass 1만 수행하라.

현재 사실:
- Local Docker Grafana의 CloudWatch Data Source 연결 성공
- WAF Log Group: us-east-1 / aws-waf-logs-aws-topology-edge
- Grafana Auto Refresh 5s에서 XSS·SQLi Event 자동 표시
- 실제 전체 표시 지연은 대략 10초
- Raw JSON보다 읽기 쉬운 즉시 Event Feed가 필요함

목표:
1. Account 433048100798과 terra-user Identity를 확인한다.
2. WAF Log Group Class와 ARN을 Read-only로 확인한다.
3. `aws logs start-live-tail` Permission·Runtime을 검증한다.
4. 성공하면 Terraform을 수정하지 않는다.
5. WAF Live Tail JSON을 Timestamp, Detection, COUNT/BLOCK, Final Action,
   Country, Source IP, Method, Host, URI, Args로 표시하는 Local Viewer를 구현한다.
6. Ctrl+C 또는 정상 종료로 Session이 닫히는지 Test한다.
7. README와 Test 결과를 작성한다.

AccessDenied일 때만:
- 현재 Credential의 IAM 관리 경계를 찾는다.
- logs:StartLiveTail 및 필요 시 logs:StopLiveTail 최소 권한 Diff·Plan을 작성한다.
- Apply하지 않는다.

금지:
- terraform apply/destroy
- kubectl Mutation
- 새 AWS Resource 생성
- 임의 IAM 변경
- Access Key·Secret·tfstate·tfplan·tfvars Commit
- 원본 WAF Log의 민감 Field를 공개 Evidence에 저장

종료 시 다음을 구분해 보고하라:
- 직접 확인한 Runtime 사실
- Source 변경
- Test 결과
- IAM·Terraform 변경 필요 여부
- 실제 Live Tail 표시 지연
- 남은 제한사항
```

---

## 공식 참고

- CloudWatch Logs Live Tail: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_LiveTail.html
- AWS CLI `start-live-tail`: https://docs.aws.amazon.com/cli/latest/reference/logs/start-live-tail.html
- CloudWatch Logs IAM: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-identity-based-access-control-cwl.html
