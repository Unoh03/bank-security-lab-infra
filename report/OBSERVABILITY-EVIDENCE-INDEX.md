# Observability Report Evidence Index

> **용도:** 최종 보고서·발표 자료에 재사용할 Observability / S3 / Athena / Grafana 증거를 한곳에서 추적한다.  
> **기준 시점:** 2026-08-07  
> **진행 상태:** S3 로그 분리·Athena 3 Source Runtime 검증 완료 / Grafana Athena Dashboard 구성 중  
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
| 1. S3 로그 분석·Grafana 시각화 | CloudFront·ALB·VPC REJECT Athena Runtime 성공, Grafana 3 Panel 구성 | **후반 진행 중** |
| 2. Pod Identity | Source 구성 존재, Runtime STS·허용·거부 Test 전 | **미완료** |
| 3. 리소스별 S3 로그 저장 구분 | Source별 Prefix·최신 Object·Glue LOCATION 확인 | **핵심 완료** |
| 4. 구성 결과 확인·시연 | WAF Viewer·S3·Athena·Grafana 일부 시연 가능 | **진행 중** |

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

PowerShell 생성 명령:

```powershell
$reportRoot = "$HOME\Documents\aws-topology-evidence\report-assets\observability"

@(
    '01_waf',
    '02_s3',
    '03_athena',
    '04_grafana'
) | ForEach-Object {
    New-Item -ItemType Directory -Force -Path (Join-Path $reportRoot $_) | Out-Null
}

$reportRoot
```

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

기존 Obsidian 학습 Note:

```text
10_학습 노트/클라우드/Grafana 로컬 Docker에서 CloudWatch WAF 근실시간 관제.md
```

## 3.3 보고서 Screenshot 후보

| 권장 파일명 | 내용 | 보고서에서 증명하는 것 | 상태 |
|---|---|---|---|
| `01_WAF_XSS_COUNT_ALLOW.png` | XSS Event Card 또는 Grafana WAF Event | Managed Rule 탐지 후 COUNT→ALLOW | 기존 Evidence 재사용 후보 |
| `02_WAF_SQLi_COUNT_ALLOW.png` | SQLi Event Card | SQLi 분류·Rule 표시 | 확보 확인 필요 |
| `03_WAF_Live_Viewer.png` | Viewer 전체 화면 | 근실시간 Event Feed 구현 | 확보 확인 필요 |

스크린샷에는 전체 IP, Request ID, JA3/JA4, Cookie, Authorization을 노출하지 않는다.

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

## 4.4 보고서 Screenshot 후보

S3 Console Screenshot은 세 Prefix가 한 화면에 잘 보이지 않을 수 있으므로, 필요하면 CLI 결과를 표로 옮기는 편이 낫다.

| 권장 파일명 | 내용 | 상태 |
|---|---|---|
| `01_S3_CloudFront_Prefix.png` | CloudFront Prefix·Object | 선택 |
| `02_S3_ALB_Prefix.png` | ALB Prefix·Object | 선택 |
| `03_S3_VPC_REJECT_Prefix.png` | VPC Flow Prefix·Object | 선택 |

보고서 본문에는 Screenshot 3장을 모두 넣기보다 **Prefix 비교 표 + 대표 Screenshot 1장**을 우선한다.

---

# 5. Athena 실제 로그 분석 Evidence

## 5.1 CloudFront

Experiment:

```text
athena-cloudfront-trace-20260807T021410Z
```

Local Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-cloudfront-trace-20260807T021410Z
```

결과:

| 항목 | 값 |
|---|---|
| State | `SUCCEEDED` |
| QueryExecutionId | `f86c0bbe-5c1b-478d-ae08-e64b44dece32` |
| Data scanned | `343,161 bytes` |
| Data rows | `34` |

정상 Parsing 확인:

```text
date
time
source_ip
method
path
status
edge_request_id
protocol
time_taken
```

Schema 보정 이력:

```text
기존 Glue Table에 cs-protocol 누락
→ 승인된 -CreateSchema 실행
→ ALTER TABLE ADD COLUMNS (`cs-protocol` string)
→ 기존 S3 Object 유지
→ Query 정상 성공
```

주의:

```text
cs-protocol = http / https
```

는 HTTP Version이 아니라 Request Scheme이다.

---

## 5.2 Primary ALB

Experiment:

```text
athena-alb-window-20260807T022221Z
```

Local Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-alb-window-20260807T022221Z
```

결과:

| 항목 | 값 |
|---|---|
| State | `SUCCEEDED` |
| Data scanned | `573,530 bytes` |
| Data rows | `29` |

정상 Parsing 확인:

```text
event_time
source_ip
method
route
elb_status_code
target_status_code
trace_id
```

주의:

CloudFront 뒤 ALB의 `source_ip`는 곧바로 외부 원본 Client IP로 해석하지 않는다.

---

## 5.3 Primary VPC REJECT

Experiment:

```text
athena-vpc-reject-20260807T022621Z
```

Local Evidence:

```text
C:\Users\Unoh\Documents\aws-topology-evidence\athena-vpc-reject-20260807T022621Z
```

결과:

| 항목 | 값 |
|---|---|
| State | `SUCCEEDED` |
| QueryExecutionId | `af6b95f6-5a2f-4512-ad77-cadadda84105` |
| Data scanned | `3,608,387 bytes` |
| 반환 확인 | **999행 이상** |

정상 Parsing 확인:

```text
srcaddr
dstaddr
dstport
protocol
rejected_flows
rejected_packets
```

샘플에서 `protocol = 6`인 TCP REJECT가 여러 Destination Port에 집계되는 것을 확인했다.

`999`는 전체 결과가 정확히 999개라는 뜻이 아니다. Query Pack의 결과 취득 상한 `MaxResultRows = 1000`에서 Header 1행을 제외해 **최소 999개의 집계 행이 반환된 것**으로 기록한다.

---

## 5.4 Athena 보고서용 요약표

| Source | State | Data scanned | Rows | 주요 Parsing |
|---|---:|---:|---:|---|
| CloudFront | SUCCEEDED | 343,161 B | 34 | 정상 |
| ALB | SUCCEEDED | 573,530 B | 29 | 정상 |
| VPC REJECT | SUCCEEDED | 3,608,387 B | 999+ | 정상 |

보고서에서는 이 표 하나와 Grafana Screenshot을 연결하면 `S3 → Athena → 시각화` 흐름을 간결하게 설명할 수 있다.

---

# 6. Grafana S3 / Athena 시각화 Evidence

Dashboard:

```text
S3 Security Log Overview
```

현재 구성된 Panel:

```text
VPC REJECT - Top Destination Ports
CloudFront - Top Requested Paths
ALB - Top Requested Routes
```

## 6.1 현재 확인된 의미

### VPC REJECT - Top Destination Ports

```text
VPC Flow Log
→ S3
→ Athena vpc_reject
→ Destination Port별 REJECT 집계
→ Grafana Horizontal Bar Chart
```

현재 Dashboard의 시간 선택기와 일치시키기 위해 다음 조건을 적용했다.

```sql
AND $__unixEpochFilter(start)
```

따라서 현재 Panel은 Dashboard가 `Last 6 hours`일 때 **최근 6시간 VPC REJECT**만 집계한다.

### CloudFront - Top Requested Paths

```text
CloudFront Standard Log
→ S3
→ Athena cloudfront_access
→ Path별 요청 수
→ Grafana Horizontal Bar Chart
```

### ALB - Top Requested Routes

```text
ALB Access Log
→ S3
→ Athena alb_primary_access
→ Route별 요청 수
→ Grafana Horizontal Bar Chart
```

## 6.2 현재 중요한 미완료

현재 Dashboard Screenshot을 최종 보고서에 바로 쓰기 전 다음을 마감한다.

```text
VPC Panel      → Dashboard 시간 범위 연동 완료
CloudFront     → Dashboard 시간 범위 연동 필요
ALB            → Dashboard 시간 범위 연동 필요
Dashboard JSON Export 필요
최종 Screenshot 필요
```

즉 현재 3-Panel 화면은 **중간 Evidence**로는 유효하지만, 최종 보고서 Screenshot은 CloudFront·ALB 시간 필터까지 맞춘 뒤 다시 캡처한다.

## 6.3 Screenshot 파일명

현재 3-Panel 중간 화면:

```text
04_grafana\01_S3_Security_Log_Overview_3panels_INTERIM.png
```

최종 시간 범위 연동 후:

```text
04_grafana\02_S3_Security_Log_Overview_FINAL.png
```

필요하면 Panel별 확대 Screenshot:

```text
04_grafana\03_VPC_REJECT_Top_Destination_Ports.png
04_grafana\04_CloudFront_Top_Requested_Paths.png
04_grafana\05_ALB_Top_Requested_Routes.png
```

보고서에는 전체 Dashboard Screenshot 1장을 기본으로 하고, 특정 분석을 설명할 때만 Panel 확대 이미지를 추가한다.

---

# 7. Screenshot 캡처 규칙

스크린샷은 단순히 화면이 보인다는 이유로 저장하지 않는다.

각 Screenshot에는 다음 중 하나의 의미가 있어야 한다.

```text
구성 성공
Runtime 전달 성공
탐지·분석 성공
조치 전·후 비교
권한 허용·거부 증명
최종 시연 화면
```

캡처 전 확인:

- 전체 Client IP가 보이면 마스킹
- Request ID / Edge Request ID가 불필요하면 숨김
- Cookie / Authorization / Header 미노출
- AWS Access Key·Credential 미노출
- Browser 탭·주소창에 불필요한 민감정보가 없는지 확인
- 보고서에서 무엇을 증명하는 Screenshot인지 파일명으로 구분

---

# 8. 보고서 작성 시 추천 서술 흐름

```text
1. CloudFront / ALB / VPC Flow Log를 Source별 S3 Prefix에 분리 저장
2. 실제 최신 Object와 Glue LOCATION을 Runtime으로 검증
3. Athena External Table로 각 Source를 구조화
4. CloudFront 34행, ALB 29행, VPC REJECT 999행 이상을 실제 Query
5. 주요 Column Parsing 정상 확인
6. Grafana Athena Dashboard에서 Source별 주요 지표를 시각화
7. WAF는 별도 CloudWatch Live Tail / Local Viewer로 근실시간 관제
8. Pod Identity Runtime Evidence는 후속 단계에서 추가
```

이 흐름을 사용하면 `근실시간 관제`와 `S3 사후 분석`의 역할을 혼동하지 않고 설명할 수 있다.

---

# 9. 다음 Evidence 추가 지점

다음부터는 새 Evidence가 생길 때 이 문서의 해당 섹션만 추가한다.

```text
현재:
Grafana CloudFront / ALB 시간 범위 연동
→ Dashboard JSON Export
→ 최종 Dashboard Screenshot

그다음:
Pod Identity Association
→ Pod ServiceAccount
→ sts:GetCallerIdentity
→ 허용 API
→ 비허용 API AccessDenied
→ Node Role Negative Test

후속:
WAF protection-test
→ COUNT / BLOCK 비교
→ 정상 기능 Regression
```

Pod Identity Evidence는 후속 작업 시 별도 `05_pod-identity` 로컬 폴더를 추가한다.
