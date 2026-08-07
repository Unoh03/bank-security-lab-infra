# WAF Live Viewer

CloudWatch Logs Live Tail의 AWS WAF JSON Event를 로컬 브라우저에서 읽기 쉬운 Card 형태로 보여주는 PowerShell 7 Viewer다.

이 도구는 AWS Resource를 생성하거나 변경하지 않는다. 기존 WAF Log Group과 `aws logs start-live-tail --mode print-only`를 사용한다.

## 역할

```text
CloudFront WAF
→ CloudWatch Logs
→ CloudWatch Live Tail
→ Start-WafLiveViewer.ps1
→ http://127.0.0.1:8787
```

Viewer는 WAF가 이미 탐지한 Event를 정규화·분류·마스킹·시각화한다. 자체적으로 공격을 탐지하지 않는다.

현재 WAF Logging Filter는 COUNT·BLOCK Event만 보존하므로 일반 ALLOW Request는 Viewer에 나타나지 않을 수 있다.

## 요구사항

- Windows PowerShell이 아니라 **PowerShell 7 이상**
- AWS CLI v2
- 사용할 AWS Profile
- 대상 CloudWatch Log Group에 대한 Live Tail 권한

현재 기본값:

```text
Profile: terra-user
Region: us-east-1
Log Group: arn:aws:logs:us-east-1:433048100798:log-group:aws-waf-logs-aws-topology-edge
Port: 8787
Max Events: 200
```

Credential은 Source에 저장하지 않는다. AWS CLI Profile을 그대로 사용한다.

## 실행

Repository Root에서:

```powershell
pwsh -File .\tools\waf-live-viewer\Start-WafLiveViewer.ps1
```

정상 실행 시 브라우저가 자동으로 열린다.

```text
http://127.0.0.1:8787
```

브라우저 자동 실행을 원하지 않으면:

```powershell
pwsh -File .\tools\waf-live-viewer\Start-WafLiveViewer.ps1 -NoBrowser
```

다른 Profile이나 Port를 사용할 수도 있다.

```powershell
pwsh -File .\tools\waf-live-viewer\Start-WafLiveViewer.ps1 `
  -Profile terra-user `
  -Port 8787
```

## 화면 항목

Viewer는 다음 값만 추출해 표시한다.

```text
WAF timestamp
Local received timestamp
End-to-end delay
XSS / SQLi / OTHER
Managed Rule / Rule Group
COUNT / BLOCK
Final ALLOW / BLOCK
Country
Masked Client IP
HTTP Method
Host
URI
URL-decoded Args
```

다음 값은 기본 화면에 표시하지 않는다.

```text
전체 Client IP
Request ID
JA3 / JA4 Fingerprint
Cookie
Authorization
전체 HTTP Header
AWS Credential
Raw WAF JSON
```

Raw Event를 자동으로 디스크에 저장하지 않는다.

## UI 동작

### Filter

`ALL`, `XSS`, `SQLi`, `OTHER`, `BLOCK` 기준으로 현재 Event를 필터링한다.

### Pause / Resume

Pause는 Live Tail 수집 자체를 중지하지 않는다.

```text
Pause
→ AWS Live Tail 수집 계속
→ Memory에 Event 보존
→ 화면 Rendering만 중지

Resume
→ Pause 중 수신된 Event까지 다시 표시
```

### 화면 지우기

현재 선택된 Filter에 보이는 Event만 숨긴다.

예:

```text
XSS 1건 + SQLi 1건
→ SQLi Filter
→ 화면 지우기
→ SQLi만 숨김
→ ALL에는 XSS 1건만 남음
```

`ALL`에서 실행하면 현재 표시 가능한 모든 Event를 숨긴다. 새로 들어오는 Event는 다시 표시된다.

## 종료

Viewer를 실행한 PowerShell에서:

```text
Ctrl+C
```

종료 시 다음 두 항목이 함께 정리되어야 한다.

```text
aws logs start-live-tail 자식 Process
127.0.0.1:8787 Listener
```

검증:

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    $_.Name -eq 'aws.exe' -and
    $_.CommandLine -match 'start-live-tail'
  } |
  Select-Object ProcessId, CommandLine

Get-NetTCPConnection `
  -LocalPort 8787 `
  -State Listen `
  -ErrorAction SilentlyContinue
```

둘 다 출력이 없으면 정상 종료다.

## Runtime 검증 결과

2026-08-07 기준 실제 환경에서 다음을 확인했다.

```text
XSS 분류                       성공
SQLi 분류                      성공
일반 ALLOW 무표시              확인
Filter                         성공
Filter별 Clear                 성공
Pause / Resume                 성공
Pause 중 Event 보존            성공
Ctrl+C 후 aws 자식 Process     미잔존
Ctrl+C 후 TCP 8787 Listener    미잔존
```

Live Tail Viewer의 7회 지연 측정값:

```text
20, 17, 21, 20, 15, 20, 14초
최소: 14초
최대: 21초
평균: 약 18.1초
```

이 값은 AWS가 보장하는 SLA가 아니라 현재 프로젝트 Runtime에서 직접 관측한 결과다. WAF → CloudWatch Logs 수집 지연과 Live Tail 전달 시간이 포함된다.

## Windows AWS CLI 주의사항

현재 Windows 환경에서 다음 명령의 `interactive` Mode는 실패했다.

```powershell
aws logs start-live-tail ... --mode interactive
```

오류:

```text
There is no current event loop in thread 'MainThread'.
```

따라서 Viewer는 검증된 `print-only` Mode를 자식 Process로 사용한다.

## 비용 주의

Live Tail은 Session 사용 시간에 따라 비용이 발생할 수 있다. 실험·발표·장애 분석 등 실제 필요한 시간에만 실행하고 사용 후 `Ctrl+C`로 종료한다. 현재 가격과 Free Tier는 AWS 공식 가격표를 기준으로 다시 확인한다.

## 범위 밖

이 Viewer는 다음을 대체하지 않는다.

```text
Grafana Dashboard와 집계
S3 + Athena 사후 분석
SIEM Alerting
WAF Rule 자체의 탐지·차단
```

프로젝트 역할 분리는 다음과 같다.

```text
Live Tail Viewer
→ 즉시 Event Feed

Grafana + CloudWatch Logs Insights
→ 읽기 쉬운 근실시간 Dashboard와 집계

S3 + Athena
→ 사후 조사·상관분석·Evidence
```
