# Observability Report Evidence Index

> **용도:** 최종 보고서·발표 자료에 재사용할 Observability / S3 / Athena / Grafana 증거를 한곳에서 추적한다.  
> **기준 시점:** 2026-08-07  
> **진행 상태:** S3 로그 분리·Athena 3 Source Runtime 검증 완료 / Grafana Athena Dashboard·Drill-down 검증 완료 / JSON Export 전  
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
| 1. S3 로그 분석·Grafana 시각화 | CloudFront·ALB·VPC REJECT Athena Runtime 완료, Grafana 3 Source Overview + Drill-down 성공 | **핵심 완료 / JSON Export 전** |
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
└─ 04_grafana\
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
- Pause / Resume
- Pause 중 Event 보존
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

## 3.2 Source / 재현 문서

```text
tools/waf-live-viewer/Start-WafLiveViewer.ps1
tools/waf-live-viewer/README.md
```

## 3.3 보고서 Screenshot 후보

| 권장 파일명 | 내용 | 보고서에서 증명하는 것 |
|---|---|---|
| `01_WAF_XSS_COUNT_ALLOW.png` | XSS Event Card 또는 Grafana WAF Event | Managed Rule 탐지 후 COUNT→ALLOW |
| `02_WAF_SQLi_COUNT_ALLOW.png` | SQLi Event Card | SQLi 분류·Rule 표시 |
| `03_WAF_Live_Viewer.png` | Viewer 전체 화면 | 근실시간 Event Feed 구현 |

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

CloudFront Policy 범위는 **향후 최소 권한 정밀화 후보**로 기록하고, 현재 S3 로그 분리 Runtime 완료 판정을 뒤집지는 않는다.

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

`999`는 Query Pack의 결과 취득 상한 `MaxResultRows = 1000`에서 Header 1행을 제외한 값이므로 **전체 결과가 정확히 999개라는 뜻이 아니라 최소 999개의 집계 행이 반환된 것**으로 기록한다.

## 5.4 Athena 보고서용 요약표

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

현재 구성된 핵심 Panel:

```text
VPC REJECT - Top Destination Ports
CloudFront - Top Requested Paths
ALB - Top Requested Routes
CloudFront - /dvwa/css/ Request Trace
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

## 6.2 정상 요청 Drill-down 사례 — `/dvwa/css/`

Overview의 CloudFront Top Path에서 다음 요청을 발견했다.

```text
/dvwa/css/login.css
/dvwa/css/theme.css
```

동일 Source의 요청 Timeline을 확인한 결과:

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
- 보고서 화면에서는 `source_ip`를 `x.x.x.xxx` 형태로 마스킹한다.

권장 Screenshot:

```text
04_grafana\02_CloudFront_DVWA_CSS_Request_Trace_FINAL.png
```

## 6.3 의심 요청 Drill-down 사례 — `/wp-admin/install.php`

CloudFront 및 ALB Overview에서 현재 DVWA 애플리케이션과 직접 관련성이 낮은 다음 Path가 반복 관찰됐다.

```text
/wp-admin/install.php
```

CloudFront 상세 Trace에서 확인한 사실:

- 여러 Source Prefix에서 동일 Path 반복 요청
- `GET /wp-admin/install.php`
- 다수의 경우 `http → 301` 직후 `https → 404`
- 요청이 성공한 증거는 없음
- 같은 Source의 전후 ±60초 Timeline을 추가 조회했으나 다른 관리·설정 Path 순회는 확인되지 않음

관찰 패턴 예시:

```text
HTTP   GET /wp-admin/install.php → 301
HTTPS  GET /wp-admin/install.php → 404
```

판정:

> 현재 DVWA 서비스와 직접 관련성이 낮은 WordPress 설치 경로에 대한 반복 Probe가 여러 Source에서 확인되었다. HTTP 요청 후 HTTPS Redirect를 따라가 404를 확인하는 패턴이 반복되어 자동화 스캔 후보로 분류할 수 있으나, 동일 Source의 전후 요청에서 `/wp-login.php`, `/xmlrpc.php`, `/.env` 등 다른 관리·설정 경로를 순회한 증거는 확인되지 않았다. 따라서 **다중 경로 정찰 또는 침해 시도 성공으로 확대해석하지 않고, 반복적인 WordPress 설치 경로 Probe / 자동화 스캔 후보 수준으로 보수적으로 판정**한다.

보고서에 쓰지 말아야 할 표현:

```text
공격 성공
침해 성공
공격자 확정
다중 경로 스캐닝 확인
```

권장 Screenshot:

```text
04_grafana\03_CloudFront_WordPress_Install_Probe_FINAL.png
```

Screenshot에는 전체 Source IP를 노출하지 않는다.

## 6.4 보고서에서 보여줄 분석 흐름

```text
Overview Dashboard
→ 관심 Path 발견
→ Path 상세 Trace
→ 동일 Source Timeline
→ 정상 / 추가 조사 필요 판정
```

두 사례를 함께 사용하면 다음 차이를 설명할 수 있다.

```text
/dvwa/css/*
→ Drill-down 결과 정상 페이지 로딩 패턴

/wp-admin/install.php
→ 반복 Probe 확인
→ 추가 Path 순회 미확인
→ 자동화 스캔 후보로 보수적 판정
```

이는 Grafana를 단순 시각화 화면이 아니라 **보안 로그의 1차 탐색과 상세 조사 진입점**으로 사용했음을 보여준다.

## 6.5 현재 남은 Grafana 산출물

```text
Dashboard JSON Export
최종 Dashboard Screenshot 파일 정리
Panel SQL 보존
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
8. WAF는 별도 CloudWatch Live Tail / Local Viewer로 근실시간 관제
9. Pod Identity Runtime Evidence는 후속 단계에서 추가
```

---

# 9. 다음 Evidence 추가 지점

현재:

```text
Dashboard JSON Export
→ 최종 Grafana Screenshot 정리
```

그다음:

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
WAF protection-test
→ COUNT / BLOCK 비교
→ 정상 기능 Regression
```

Pod Identity Evidence는 후속 작업 시 별도 `05_pod-identity` 로컬 폴더를 추가한다.
