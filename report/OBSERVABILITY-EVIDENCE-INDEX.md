# Observability Report Evidence Index

> **용도:** 최종 보고서·발표 자료에 재사용할 Observability / S3 / Athena / Grafana 증거를 한곳에서 추적한다.  
> **기준 시점:** 2026-08-12
> **진행 상태:** 기존 Observability Evidence + Capital One 정탐·Gate 2·정상 대조군 검증 완료
> **관련 현황:** [`../OBSERVABILITY-CURRENT-STATUS.md`](../OBSERVABILITY-CURRENT-STATUS.md)  
> **실행 계획:** [`../OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](../OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)

이 문서는 원본 Evidence 자체를 공개 Repository에 모으는 파일이 아니다. 보고서에 사용할 수 있는 **증거의 위치·의미·판정·스크린샷 후보**를 기록한다.

공개 Repository에는 다음 값을 포함한 Raw Screenshot·Raw Log를 그대로 Commit하지 않는다.

```text
전체 Client IP
Request ID / Edge Request ID
JA3 / JA4
Cookie
Authorization
전체 Header
AWS Credential
```

---

## 1. 보고서 요구사항 매핑

원래 지시:

```text
1. S3 로그 분석 (Grafana를 활용해서 시각화)
2. EKS 각각의 POD들의 IAM 권한 설정 (Pod Identity)
3. 리소스별로 로그저장 S3 구분
4. 구성하고 구성된 결과를 듣고 보는 것
```

현재 Evidence 기준:

| 요구사항 | 현재 Evidence | 현재 판정 |
|---|---|---|
| 1. S3 로그 분석·Grafana 시각화 | CloudFront·ALB·VPC REJECT Athena Runtime, Grafana 3 Source Overview, 정상·의심 Drill-down, JSON Export | **완료** |
| 2. Pod Identity | Source 구성 존재, Runtime STS·허용·거부 Test 전 | **미완료** |
| 3. 리소스별 S3 로그 저장 구분 | Source별 Prefix·최신 Object·Glue LOCATION 확인 | **핵심 완료** |
| 4. 구성 결과 확인·시연 | WAF Viewer·S3·Athena·Grafana Drill-down까지 시연 가능 | **진행 중 / Pod Identity 후 통합 마감** |

---

# 2. Evidence 분류

보고서용 로컬 자산은 다음 구조를 권장한다.

```text
C:\Users\Unoh\Documents\aws-topology-evidence\report-assets\observability\
├─ 01_waf\
├─ 02_s3\
├─ 03_athena\
├─ 04_grafana\
├─ 05_pod-identity\
└─ 06_capital-one\
```

이 디렉터리는 **로컬 보고서 자산 저장소**다. 공개 Git Repository에 그대로 Commit하지 않는다.

---

# 3. WAF 근실시간 관제 Evidence

## 3.1 확인 완료

```text
WAF Event
→ CloudWatch Logs
→ CloudWatch Live Tail
→ Local WAF Viewer
```

확인 항목:

- XSS 분류 성공
- SQLi 분류 성공
- 일반 ALLOW Request는 Logging Filter 때문에 Viewer에 나타나지 않음
- `COUNT → ALLOW` 구분
- Filter별 Clear
- Pause / Resume와 Pause 중 Event 보존
- `Ctrl+C` 종료 후 `aws start-live-tail` 자식 Process 미잔존
- TCP `8787` Listener 미잔존
- localhost 전용 Bind
- Client IP 마스킹
- Raw Event 기본 미저장

Viewer 지연 실측:

```text
Sample: 20, 17, 21, 20, 15, 20, 14초
최소: 14초
최대: 21초
평균: 약 18.1초
```

Source / 재현 문서:

```text
tools/waf-live-viewer/Start-WafLiveViewer.ps1
tools/waf-live-viewer/README.md
```

보고서 Screenshot 후보:

```text
01_waf\01_WAF_XSS_COUNT_ALLOW.png
01_waf\02_WAF_SQLi_COUNT_ALLOW.png
01_waf\03_WAF_Live_Viewer.png
```

---

# 4. 리소스별 S3 로그 분리 Evidence

Security Log Bucket:

```text
aws-topology-security-logs-e10b7e4f152e9420159dba755d
```

## 4.1 Runtime 확인 결과

| Source | Prefix | 확인된 최신 Runtime Object |
|---|---|---|
| CloudFront | `AWSLogs/433048100798/CloudFront/` | `2026-08-07T02:04:13Z`, 560 bytes |
| Primary ALB | `alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2/` | `2026-08-07T02:00:11Z`, 396 bytes |
| Primary VPC REJECT | `vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2/` | `2026-08-07T02:04:17Z`, 5,138 bytes |

판정:

```text
CloudFront Object 실제 존재     ✅
ALB Object 실제 존재            ✅
VPC REJECT Object 실제 존재     ✅
세 Source 최신 Runtime 전달     ✅
Source별 Prefix 분리            ✅
```

## 4.2 Glue / Athena LOCATION

```text
cloudfront_access
→ s3://<bucket>/AWSLogs/433048100798/CloudFront

alb_primary_access
→ s3://<bucket>/alb/primary/AWSLogs/433048100798/elasticloadbalancing/ap-northeast-2

vpc_reject
→ s3://<bucket>/vpc-flow/AWSLogs/433048100798/vpcflowlogs/ap-northeast-2
```

실제 Runtime Prefix와 일치한다.

## 4.3 Bucket Policy 판정

```text
Primary ALB
→ alb/primary/AWSLogs/433048100798/*
→ 전용 Prefix Write 범위 확인

VPC Flow
→ vpc-flow/AWSLogs/433048100798/*
→ 전용 Prefix 포함 확인

CloudFront
→ AWSLogs/433048100798/*
→ 기능은 정상이나 실제 /CloudFront/ Prefix보다 Policy 범위가 넓음
```

CloudFront Policy 범위는 향후 최소 권한 정밀화 후보로 기록하고, 현재 S3 로그 분리 Runtime 완료 판정을 뒤집지는 않는다.

---

# 5. Athena 실제 로그 분석 Evidence

## 5.1 CloudFront

```text
Experiment: athena-cloudfront-trace-20260807T021410Z
State: SUCCEEDED
QueryExecutionId: f86c0bbe-5c1b-478d-ae08-e64b44dece32
Data scanned: 343,161 bytes
Data rows: 34
```

정상 Parsing:

```text
date, time, source_ip, method, path, status,
edge_request_id, protocol, time_taken
```

기존 Glue Table에 `cs-protocol`이 없었으며 승인된 `-CreateSchema` 실행으로 Column을 보정한 뒤 정상 Query를 확인했다.

## 5.2 Primary ALB

```text
Experiment: athena-alb-window-20260807T022221Z
State: SUCCEEDED
Data scanned: 573,530 bytes
Data rows: 29
```

정상 Parsing:

```text
event_time, source_ip, method, route,
elb_status_code, target_status_code, trace_id
```

CloudFront 뒤 ALB의 `source_ip`는 곧바로 외부 원본 Client IP로 해석하지 않는다.

## 5.3 Primary VPC REJECT

```text
Experiment: athena-vpc-reject-20260807T022621Z
State: SUCCEEDED
QueryExecutionId: af6b95f6-5a2f-4512-ad77-cadadda84105
Data scanned: 3,608,387 bytes
반환 확인: 999행 이상
```

정상 Parsing:

```text
srcaddr, dstaddr, dstport, protocol,
rejected_flows, rejected_packets
```

`999`는 Query Pack의 결과 취득 상한 `MaxResultRows = 1000`에서 Header 1행을 제외한 값이므로 전체 결과가 정확히 999개라는 뜻이 아니라 **최소 999개의 집계 행이 반환된 것**으로 기록한다.

## 5.4 보고서용 요약표

| Source | State | Data scanned | Rows | 주요 Parsing |
|---|---:|---:|---:|---|
| CloudFront | SUCCEEDED | 343,161 B | 34 | 정상 |
| ALB | SUCCEEDED | 573,530 B | 29 | 정상 |
| VPC REJECT | SUCCEEDED | 3,608,387 B | 999+ | 정상 |

---

# 6. Grafana S3 / Athena 시각화 Evidence

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

## 6.1 Dashboard 시간 범위 연동

세 Overview Panel 모두 Grafana Dashboard의 시간 선택기를 실제 Athena Query에 반영한다.

```text
VPC REJECT
→ $__unixEpochFilter(start)

CloudFront
→ date + time 문자열을 Dashboard raw time 범위와 비교

ALB
→ ISO-8601 time Column을 Dashboard 시간 범위와 비교
```

따라서 `Last 1 hour`, `Last 3 hours`, `Last 6 hours` 등 Dashboard 선택 범위와 실제 Athena 분석 범위가 일치한다.

## 6.2 정상 요청 Drill-down — `/dvwa/css/`

동일 Source의 요청 Timeline:

```text
06:30:40  GET /                    → 302
06:30:40  GET /login.php           → 200
06:30:41  GET /favicon.ico         → 200
06:30:41  GET /dvwa/css/login.css  → 200
06:30:41  GET /dvwa/css/theme.css  → 200
```

판정:

> 동일 Source에서 로그인 페이지와 정적 리소스 요청이 약 1초 내 연속 발생했으므로, `/dvwa/css/` 요청은 독립적인 공격 행위보다는 로그인 페이지 렌더링에 수반된 정상 정적 리소스 요청일 가능성이 높은 것으로 판단했다.

주의:

- CloudFront `time`이 초 단위이므로 같은 초 내부의 정확한 선후관계는 단정하지 않는다.
- Dashboard SQL에서 Client IPv4의 마지막 Octet을 `.xxx`로 마스킹한다.

## 6.3 의심 요청 Drill-down — `/wp-admin/install.php`

확인된 사실:

- 여러 Source에서 동일 Path 반복 요청
- `GET /wp-admin/install.php`
- 다수의 경우 `http → 301` 직후 `https → 404`
- 요청이 성공한 증거는 없음
- 같은 Source의 전후 ±60초 Timeline에서 다른 관리·설정 Path 순회는 확인되지 않음

판정:

> 현재 DVWA 서비스와 직접 관련성이 낮은 WordPress 설치 경로에 대한 반복 Probe가 여러 Source에서 확인되었다. HTTP 요청 후 HTTPS Redirect를 따라가 404를 확인하는 패턴이 반복되어 자동화 스캔 후보로 분류할 수 있으나, 다른 관리·설정 경로를 순회한 증거는 확인되지 않았다. 따라서 **다중 경로 정찰 또는 침해 성공으로 확대해석하지 않고, 반복 WordPress 설치 경로 Probe / 자동화 스캔 후보 수준으로 보수적으로 판정**한다.

보고서에 쓰지 말아야 할 표현:

```text
공격 성공
침해 성공
공격자 확정
다중 경로 스캐닝 확인
```

## 6.4 JSON Export 검토

확인 사항:

```text
Dashboard Title: S3 Security Log Overview
Panel 수: 5
Overview Source 매핑: VPC / CloudFront / ALB 정상
Dashboard 시간 Macro 포함
Drill-down IP 마스킹 SQL 포함
Credential 하드코딩 없음
Raw Client IP 하드코딩 없음
Request ID 하드코딩 없음
```

Athena Data Source UID:

```text
efubxj2vag7i8b
```

이는 AWS Credential이 아니라 현재 Grafana 인스턴스의 Data Source 식별자다. 다른 Grafana 인스턴스로 Import할 경우 Athena Data Source를 다시 연결해야 할 수 있다.

## 6.5 권장 Screenshot 파일명

```text
04_grafana\01_S3_Security_Log_Overview_FINAL.png
04_grafana\02_CloudFront_DVWA_CSS_Request_Trace_FINAL.png
04_grafana\03_CloudFront_WordPress_Install_Probe_FINAL.png
```

---

# 7. Screenshot 캡처 규칙

각 Screenshot에는 다음 중 하나의 의미가 있어야 한다.

```text
구성 성공
Runtime 전달 성공
탐지·분석 성공
정상/의심 판정 근거
권한 허용·거부 증명
최종 시연 화면
```

캡처 전 확인:

- 전체 Client IP가 보이면 마스킹
- Request ID / Edge Request ID가 불필요하면 숨김
- Cookie / Authorization / Header 미노출
- AWS Access Key·Credential 미노출
- Browser 탭·주소창의 불필요한 민감정보 확인

---

# 8. 보고서 작성 시 추천 서술 흐름

```text
1. CloudFront / ALB / VPC Flow Log를 Source별 S3 Prefix에 분리 저장
2. 실제 최신 Object와 Glue LOCATION을 Runtime으로 검증
3. Athena External Table로 각 Source를 구조화
4. CloudFront 34행, ALB 29행, VPC REJECT 999행 이상을 실제 Query
5. 주요 Column Parsing 정상 확인
6. Grafana Athena Dashboard에서 Source별 주요 지표를 시각화
7. 관심 Path를 Drill-down하여 정상 요청과 반복 Probe를 구분
8. Dashboard JSON을 Repository에 보존해 재현 가능한 산출물로 마감
9. WAF는 별도 CloudWatch Live Tail / Local Viewer로 근실시간 관제
10. Pod Identity Runtime Evidence를 후속 단계에서 추가
```

---

# 9. 다음 Evidence 추가 지점

## 9.1 Capital One Baseline — 내부 조사 Bundle

```text
C:\Users\Unoh\Documents\aws-topology-evidence\capital-one-20260812T025054Z\
├─ source\client\capital-one-baseline.json
├─ results\cloudwatch\capital-one-validation-getobject.json
├─ manifest.json
├─ manifest.json.sha256
└─ SHA256SUMS.txt
```

확인된 Claim:

```text
Command Injection은 SSRF 대체 진입점
IMDS 예상 Primary Karpenter Node Role 일치
Credential 값 비노출 상태에서 고정 가짜 CSV 5행 읽기 성공
준비·다운로드 SHA-256 일치
같은 TAKE로 새 CloudWatch Alarm 전환
CloudTrail GetObject 1행의 Role·Object·성공·시간창 일치
WAF 2건과 Runner의 두 CloudFront Request ID 정확히 일치
DVWA Apache에 같은 시간창의 exec POST 2건·HTTP 200
Pod→IMDS 직접 VPC Flow Log는 AWS 제한상 수집되지 않음
GuardDuty는 TAKE 시작 약 49분 뒤 Finding 0건·EventBridge 전달 Event 0건
```

이 Bundle은 CloudTrail의 ARN·Bucket·Source IP·Request ID 같은 조사 필드를 포함하는
내부 Evidence다. 공개 Repository나 발표 자료에 그대로 넣지 않는다. 보고서용
`06_capital-one` 자산은 이 Claim을 유지하면서 Account ID·Bucket·IP·Request ID·
Credential 관련 값을 다시 마스킹해 별도로 만든다.

아직 이 Bundle이 증명하지 않는 것:

```text
실제 SSRF
DVWA Command Body·명령 실행 결과·IMDS 응답의 애플리케이션 로그
Pod→IMDS의 직접 네트워크 로그
GuardDuty Finding 발생
SIEM·SOAR
GitHub·Argo Containment
재공격 실패·Terraform 영구 복구
```

Gate 2 판정에서 `미수집`과 `탐지 없음`을 구분한다. Pod→IMDS는 공격 결과가 Runner에서
확인됐지만 VPC Flow Logs가 IMDS 주소를 원래 수집하지 않아 직접 로그가 없는 경우다.
GuardDuty는 Detector를 직접 조회했지만 같은 TAKE 이후 Finding 자체가 0건인 경우다.
둘 다 CloudTrail Custom Rule의 정탐 성공을 뒤집지 않는다.

## 9.2 Capital One 정상 대조군 — 내부 조사 Bundle

```text
C:\Users\Unoh\Documents\aws-topology-evidence\capital-one-negative-20260812T034935Z\
├─ source\client\capital-one-negative-control.json
├─ results\cloudwatch\capital-one-negative-control.json
├─ manifest.json
├─ manifest.json.sha256
└─ SHA256SUMS.txt
```

확인된 Claim:

```text
고정 정상 terra-user가 가짜 CSV 한 객체를 GetObject
가짜 5행·준비 SHA-256 일치
CloudTrail 성공 GetObject 정확히 1행
Primary Karpenter Node Role이 아님
실행 Event는 시작 0.868초 뒤·읽기 종료 0.629초 전
Capital One Alarm은 OK·State Updated Timestamp 불변
Client Record에 Bucket·Caller ARN·Credential Pattern 없음
SHA256SUMS 50개 모두 일치
```

이 Bundle도 CloudTrail 내부 조사 필드를 포함하므로 공개본이 아니다. 첫 Query 실패는
GetObject 실패가 아니라 Query 파일 인코딩과 전달 지연 Scan Window 오류였고, Resume
모드가 동일 S3 읽기를 반복하지 않고 기존 Event만 재검증했다.

보고서에 사용할 검증 목적·시간 해석·시행착오·재발 방지·주장 한계는
[`CAPITAL-ONE-GATE3-VALIDATION-LESSONS.md`](./CAPITAL-ONE-GATE3-VALIDATION-LESSONS.md)에
분리해 정리했다.

## 9.3 기존 Pod Identity 후속

```text
Pod Identity Association
→ Pod ServiceAccount
→ sts:GetCallerIdentity
→ 허용 API
→ 비허용 API AccessDenied
→ Node Role Negative Test
```

후속:

```text
Grafana WAF Dashboard Export
WAF protection-test
→ COUNT / BLOCK 비교
→ 정상 기능 Regression
```
