# 근실시간 관제·WAF 보강·S3 로그 분석·Pod Identity 단계별 실행 계획

> 상태: **WAF Live Tail·Local Viewer Runtime 확인 / WAF 단계적 보강 계획 추가 / 자동 변경 금지**  
> 기준 시점: 2026-08-06  
> 결정 근거: [`OBSERVABILITY-IAM-DECISIONS.md`](./OBSERVABILITY-IAM-DECISIONS.md)

이 계획은 다음 요구사항을 완성한다.

```text
1. 공격 중 자동으로 나타나는 근실시간 관제 화면
2. S3 로그의 상세 분석과 Evidence
3. EKS Workload별 Pod Identity 검증
4. 리소스별 로그 저장 구분과 결과 설명
```

추가 목표로, 현재 탐지 중심인 WAF를 검증된 규칙부터 단계적으로 차단 모드로 보강한다.

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

Read-only Test와 관측이 먼저다.

```text
금지:
- 필요성 확인 전 Terraform 수정
- terraform apply / destroy
- kubectl apply / patch / delete
- IAM Role·Policy의 즉석 변경
- WAF 규칙을 관측 없이 일괄 BLOCK 전환
- 새 S3 Bucket·Managed Grafana Resource 생성
- Secret·Access Key·tfstate·tfplan·tfvars Commit
```

WAF 보강은 반드시 `COUNT 기준선 → 오탐 검증 → 제한적 BLOCK → 정상 기능 회귀 Test` 순서로 수행한다. 변경이 필요하면 Source Diff와 `terraform plan`을 먼저 만들고 사용자 승인 뒤 적용한다.

### 0.3 역할 분리

```text
Grafana + CloudWatch Logs Insights
→ 읽기 쉬운 근실시간 Dashboard와 집계

CloudWatch Live Tail + Local Viewer
→ Polling 없는 즉시성 우선 Event Feed

S3 + Athena
→ 사후 조사·상관분석·Evidence
```

### 0.4 현재 WAF의 정확한 성격

현재 WAF는 운영용 차단 정책이 아니라 **훈련 애플리케이션을 계속 사용할 수 있게 유지한 관찰 모드**다.

```text
Web ACL Default Action: ALLOW
AWSManagedRulesCommonRuleSet: Rule Group 결과를 COUNT로 Override
AWSManagedRulesSQLiRuleSet: Rule Group 결과를 COUNT로 Override
로그 보존: COUNT·BLOCK만 KEEP, 일반 ALLOW는 DROP
로그 Redaction: Authorization·Cookie
로그인 Rate Rule: 변수로 명시적으로 켤 때만 생성
```

따라서 `COUNT → ALLOW`는 WAF가 공격을 놓쳤다는 뜻이 아니라, 패턴을 탐지한 뒤 의도적으로 통과시켰다는 뜻이다. 반대로 WAF Event가 없으면 현재 Rule 범위 밖이거나 검사 조건에 매칭되지 않은 요청일 수 있다.

---

## 1. 현재 Checkpoint

| 항목 | 현재 상태 | 다음 Gate |
|---|---|---|
| Local Docker Grafana | 실행·접속 성공 | Dashboard 이름·JSON Export |
| Athena Data Source | `Data source is working` | 실제 Table 행·Schema 검증 |
| Athena Table 목록 | `cloudfront_access`, `alb_primary_access`, `vpc_reject` 확인 | S3 Object·실제 행 확인 |
| CloudWatch Data Source | Metrics·Logs API 연결 성공 | WAF Panel 정리 |
| WAF Log Group | `us-east-1/aws-waf-logs-aws-topology-edge` 조회 성공 | Field·Rule별 집계 보강 |
| XSS Test | Common Rule Set의 XSS Match, COUNT → ALLOW 확인 | 반복 측정·BLOCK 전환 Test 후보 |
| SQLi Test | 요청과 WAF Event 자동 표시 확인 | SQLi 하위 Rule ID 검증 |
| Grafana Auto Refresh | `5s` | 최소·최대·평균 표시 지연 기록 |
| Grafana 표시 지연 | 대략 10초 관측 | 반복 측정 |
| CloudWatch Live Tail | `print-only` Mode 성공 | 반복 지연 측정·사용 시간 관리 |
| AWS CLI Interactive Mode | Windows에서 Event Loop 오류 | 사용하지 않고 `print-only` 유지 |
| Readable Live Tail Viewer | PowerShell 7 Local Web UI Runtime 성공 | Source 검토·README·Commit·반복 측정 |
| Viewer 보안 처리 | `127.0.0.1` Bind, IP 마스킹, Raw Log 미저장 | 공개 Evidence 재검토 |
| WAF 보호 수준 | Common·SQLi Rule Group 전체 COUNT Override | 단계적 Hardening Plan 수행 |
| Pod Identity Source | 여러 Workload 정의 | AWS·Kubernetes Inventory |
| Pod Identity Runtime | 전체 재검증 안 됨 | STS·허용·거부 Test |

현재 관련 Obsidian Note:

```text
10_학습 노트/클라우드/Grafana 로컬 Docker에서 CloudWatch WAF 근실시간 관제.md
10_학습 노트/클라우드/Grafana 로컬 Docker에서 Athena 연결.md
```

---

# Phase 1 — 현재 WAF Grafana 관제 Baseline 고정

## 목표

이미 성공한 Grafana 경로를 재현 가능한 Baseline으로 남긴다.

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
3. XSS와 SQLi Request를 각각 3회 이상 실행한다.
4. Request 시각, WAF Event `@timestamp`, Grafana 표시 시각을 기록한다.
5. 최소·최대·대략적 평균 지연을 기록한다.
6. Dashboard JSON과 Screenshot을 보존한다.
7. Raw JSON을 열지 않아도 Rule·Action·URI·Args를 읽을 수 있게 한다.

## 완료 Gate

- 사용자 입력 없이 새 Event 자동 표시
- XSS·SQLi Event 구분 가능
- `COUNT`와 최종 `ALLOW`를 혼동하지 않음
- 실제 지연 측정값 보존
- Dashboard JSON Export 성공

---

# Phase 2 — CloudWatch Live Tail Runtime Baseline 고정

## 현재 확인 결과

다음 경로가 실제로 성공했다.

```text
WAF Log Group
→ aws logs start-live-tail --mode print-only
→ JSON Event Streaming
```

`interactive` Mode는 Windows AWS CLI에서 다음 오류가 발생했다.

```text
There is no current event loop in thread 'MainThread'.
```

따라서 Windows 기준 경로는 `print-only`로 고정한다.

## 재현 명령

```powershell
aws logs start-live-tail `
  --profile terra-user `
  --region us-east-1 `
  --log-group-identifiers `
  "arn:aws:logs:us-east-1:433048100798:log-group:aws-waf-logs-aws-topology-edge" `
  --mode print-only
```

종료는 `Ctrl+C`다.

## Evidence

```text
시작·종료 시각
Session 지속 시간
Request 시각
WAF timestamp
Local 수신 시각
Request → Live Tail 표시 지연
명령 Exit 상태
오류 또는 성공 Screenshot
```

## 완료 Gate

- Terraform·IAM 변경 없이 Live Tail 수신
- XSS·SQLi Event 수신
- 반복 Test의 지연 분포 기록
- `Ctrl+C`로 Session 종료
- 세션을 실험·발표 중에만 실행

---

# Phase 3 — Readable WAF Live Tail Viewer 정리

## 현재 구현

로컬 PowerShell 7에서 다음 구조가 Runtime 성공했다.

```text
AWS CLI start-live-tail --mode print-only
→ PowerShell JSON Parser
→ localhost HTTP Server
→ http://127.0.0.1:8787
→ WAF Live Monitor
```

현재 로컬 경로:

```text
tools/waf-live-viewer/Start-WafLiveViewer.ps1
```

## 표시 항목

```text
WAF timestamp
Local received timestamp
End-to-end delay
XSS / SQLi / OTHER
Managed Rule·Rule Group
COUNT / BLOCK
Final ALLOW / BLOCK
Country
Masked Client IP
Method
Host
URI
URL-decoded Args
```

## 보안 기준

- `127.0.0.1`에만 Bind한다.
- AWS Credential을 Source나 브라우저에 전달하지 않는다.
- Client IP는 마스킹한다.
- Request ID, JA3, JA4, Cookie, 전체 Header를 표시하지 않는다.
- Raw Event를 기본적으로 디스크에 저장하지 않는다.
- 실제 공격 로그를 공개 Repository에 Commit하지 않는다.
- Viewer 종료 시 AWS CLI 자식 프로세스도 종료한다.

## 남은 작업

1. Script를 정적 검토한다.
2. `Ctrl+C` 종료 후 `aws` 자식 Process가 남지 않는지 확인한다.
3. XSS·SQLi·일반 요청·동시 Event를 Test한다.
4. Viewer에서 측정되는 지연을 5회 이상 기록한다.
5. README에 PowerShell 7, 실행, 종료, 비용 주의사항을 작성한다.
6. 실제 Runtime 검증 뒤 Source와 README만 Commit한다.

## 완료 Gate

- Live Tail Event가 Polling 없이 수신
- 주요 Field가 읽기 쉬운 Card로 표시
- XSS·SQLi 구분
- 최근 Event 수 제한
- Pause·Clear·Filter 정상 동작
- Session 정상 종료
- AWS Resource 변경 없음

---

# Phase 4 — Grafana 근실시간 Dashboard 정리

## 목표

Live Tail Viewer는 즉시 Event Feed, Grafana는 집계와 상황판을 담당한다.

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

Dashboard는 Live Tail Viewer를 대체하지 않는다. 현재 약 10초의 지연을 허용하는 읽기 쉬운 관제 화면으로 사용한다.

## 산출물

```text
analytics/dashboard/waf-realtime-overview.json
Panel Query
Dashboard Screenshot
측정된 표시 지연
```

빈 Dashboard JSON을 먼저 Commit하지 않는다.

---

# Phase 5 — WAF 단계적 보강 및 차단 검증

## 목표

현재 `관찰 모드`를 유지하면서 오탐과 정상 기능 영향을 확인하고, 검증된 규칙부터 실제 차단으로 전환한다.

현재 상태를 단순히 `WAF로 보호 중`이라고 보고하지 않는다. 현재 표현은 다음으로 고정한다.

> AWS Managed Rules를 COUNT 모드로 배치해 공격을 차단하지 않고 탐지·관제 기준선을 수집하고 있다. 정상 트래픽과 오탐을 확인한 뒤 검증된 규칙부터 단계적으로 BLOCK으로 전환한다.

## 5.1 현재 Rule 동작 Inventory

Source와 Runtime에서 다음을 확인한다.

```text
Web ACL Default Action
Rule Priority
Managed Rule Group Version
Rule Group Return Action Override
개별 Rule Action Override
Rate Rule Mode·Limit·Evaluation Window
WCU 사용량
Logging Filter
Redacted Field
```

특히 현재 `override_action { count {} }`는 Rule Group이 반환한 결과만 COUNT로 바꾼다. Rule Group 내부의 첫 Terminating Rule 이후 평가는 종료될 수 있으므로, 세부 튜닝 단계에서는 **Rule Group 전체 COUNT Override와 개별 Rule Action Override를 구분**한다.

## 5.2 운영 모드 분리 설계

훈련 환경을 파괴하지 않도록 최소 두 Mode를 설계한다.

```text
training
- Common Rule Set: COUNT
- SQLi Rule Set: COUNT
- 로그인 Rate Rule: disabled 또는 COUNT
- 취약점 공격·관제 실습 가능

protection-test
- 검증된 XSS·SQLi Rule: BLOCK
- 오탐 후보 Rule: COUNT 유지
- 로그인 Rate Rule: COUNT → BLOCK 단계 전환
- 정상 기능 Regression Test 필수
```

Mode 전환은 Terraform Variable 또는 명시적인 Source 설정으로 관리하며 Console에서 임의 변경하지 않는다. 실제 변수명과 구현 방식은 Source Diff 검토 뒤 결정한다.

## 5.3 단계적 전환 순서

1. 현재 COUNT Event를 Rule ID·URI·Method별로 수집한다.
2. 정상적인 로그인·조회·검색·회원 기능을 Regression Baseline으로 기록한다.
3. XSS·SQLi 하위 Rule별 오탐 여부를 확인한다.
4. Rule Group 전체 Override 대신 필요한 경우 개별 Rule Action Override로 세분화한다.
5. 오탐이 확인되지 않은 XSS·SQLi Rule부터 BLOCK 후보로 지정한다.
6. `terraform plan`에서 변경 Rule·Priority·WCU를 확인한다.
7. 사용자 승인 뒤 제한된 시간 동안 `protection-test` Mode를 적용한다.
8. 통제된 공격과 정상 기능을 동시에 Test한다.
9. 이상이 있으면 즉시 COUNT Mode로 Rollback한다.
10. 결과를 기준으로 유지할 BLOCK Rule과 COUNT 예외 Rule을 확정한다.

## 5.4 추가 보강 후보

현재 Common·SQLi 두 Group 외에 다음 AWS Managed Rule Group을 후보로 검토한다.

```text
AWSManagedRulesKnownBadInputsRuleSet
AWSManagedRulesAmazonIpReputationList
```

추가 시 바로 BLOCK하지 않는다.

```text
후보 Group을 COUNT로 추가
→ Match·오탐·WCU·비용 관측
→ 필요성 입증
→ 검증된 Rule만 BLOCK
```

Bot Control, ATP, Anti-DDoS 등 별도 요금·애플리케이션 설정이 수반될 수 있는 기능은 핵심 범위 완료 후 별도로 판단한다.

## 5.5 로그인 Rate Rule

현재 `/login.php`의 `POST` 요청을 IP 단위로 집계하는 Rate Rule Source가 있다. 변수로 비활성화되어 있을 수 있으므로 Runtime 존재부터 확인한다.

검증 순서:

```text
disabled
→ COUNT로 활성화
→ 정상 로그인·자동화 공격의 Request Rate 관측
→ Limit·Evaluation Window 조정
→ BLOCK 적용
→ 정상 사용자 영향 확인
```

Rate Rule 설정 변경은 추적 Counter를 초기화할 수 있으므로 Test 시각과 전환 시점을 Evidence에 남긴다.

## 5.6 차단 Test

### 공격 요청

```text
XSS Query Argument
SQL Injection Query Argument
로그인 반복 요청
```

### 기대 결과

| Mode | WAF Event | HTTP 결과 | Viewer 표시 |
|---|---|---|---|
| `training` | COUNT | 애플리케이션까지 전달 | `COUNT → ALLOW` |
| `protection-test` | BLOCK | 기본적으로 403 | `BLOCK → BLOCK` |

### 정상 기능 Regression

```text
홈 접근
정상 로그인
회원 조회·검색
정상 Query String
정적 Asset
필수 POST 요청
```

정상 기능 실패가 발생하면 해당 Rule을 BLOCK 완료로 판정하지 않는다.

## 5.7 WAF 한계 명시

- WAF Match는 공격 패턴 탐지이며 실제 취약점 성공 여부를 증명하지 않는다.
- XSS 실행 성공은 브라우저·응답, SQLi 성공은 애플리케이션·DB 결과로 별도 확인한다.
- IDOR, 권한 우회, 업무 로직 악용은 일반 Managed Rule만으로 완전 탐지할 수 없다.
- Request Body·Header·Cookie 검사에는 크기와 개수 제한이 있다.
- WAF는 애플리케이션 보안 코딩·인증·인가 검증을 대체하지 않는다.

## 산출물

```text
현재 Rule·Action Inventory
COUNT Match Baseline
정상 기능 Regression Matrix
WAF Hardening Source Diff
terraform fmt·validate·plan 결과
COUNT 전·후 Viewer Screenshot
BLOCK 전·후 HTTP 응답 Evidence
Rollback 절차
최종 BLOCK·COUNT 예외 Matrix
```

## 완료 Gate

- 현재 관찰 모드와 보강 모드를 명확히 구분
- 검증된 공격 요청이 `protection-test`에서 BLOCK
- 정상 주요 기능이 계속 동작
- 오탐 Rule은 COUNT 예외로 관리
- Source와 Runtime 상태 일치
- 즉시 COUNT로 되돌릴 수 있는 Rollback 경로 존재
- 사용자 승인 없이 Apply하지 않음

---

# Phase 6 — S3 로그 저장·분리 Runtime 검증

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

# Phase 7 — Athena 실제 데이터 검증

대상:

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

# Phase 8 — Pod Identity Inventory

예상 Workload:

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

# Phase 9 — Pod Identity Runtime 권한 검증

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

# Phase 10 — Evidence와 최종 설명

## 근실시간 관제·WAF

```text
Grafana CloudWatch 연결 성공
WAF Dashboard와 Auto Refresh
XSS·SQLi Event
Grafana 표시 지연
Live Tail CLI Test
Readable Viewer 화면
Live Tail·Viewer 표시 지연
COUNT → ALLOW와 BLOCK → BLOCK 비교
정상 기능 Regression
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
| WAF 단계적 보강 |  |  |  |  |
| S3 로그 분석 |  |  |  |  |
| S3 로그 분리 |  |  |  |  |
| Pod Identity |  |  |  |  |

---

# Phase 11 — 핵심 완료 후 선택 범위

```text
GuardDuty → EventBridge → SNS
Grafana Alert Rule
자동 격리·자동 차단
Amazon Managed Grafana
Grafana Cloud
별도 Athena Result Bucket
Source별 S3 Bucket Migration
Bot Control·ATP·Anti-DDoS Managed Rule Group
```

---

# 실행 Pass 계획

## Pass 1 — Live Tail Viewer 마무리

```text
Script 정적 검토
Process 종료 Test
XSS·SQLi 반복 수신
실제 표시 지연 측정
README 작성
Source Commit
```

Terraform·IAM·AWS Resource는 변경하지 않는다.

## Pass 2 — Grafana·WAF Hardening Plan

```text
WAF Dashboard Export
COUNT Match Baseline
정상 기능 Regression Baseline
Rule별 Action Inventory
training / protection-test Mode Source Diff
Known Bad Inputs·IP Reputation 후보 검토
terraform fmt·validate·plan
```

Apply하지 않는다.

## Pass 3 — 사용자 승인 WAF Runtime Test

검토된 Plan만 제한된 시간에 적용한다.

```text
COUNT → BLOCK 전환
통제된 XSS·SQLi·Rate Test
정상 기능 Regression
Viewer·HTTP Evidence
필요 시 즉시 COUNT Rollback
```

## Pass 4 — S3·Athena Baseline

```text
S3 Prefix Object 확인
Athena 실제 행·Schema 확인
Grafana 조사 Panel
```

## Pass 5 — Pod Identity Runtime

검토된 Inventory와 Test Script를 이용해 사용자 승인 후 Runtime을 검증한다.

---

## 공식 참고

- CloudWatch Logs Live Tail: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_LiveTail.html
- AWS CLI `start-live-tail`: https://docs.aws.amazon.com/cli/latest/reference/logs/start-live-tail.html
- Testing and tuning AWS WAF protections: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html
- WAF Rule Group Action Override: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-group-override-options.html
- AWS Managed Rules 목록: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
- Rate-based Rule: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
- Amazon EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
