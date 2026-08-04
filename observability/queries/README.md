# Security Query Pack

이 Directory의 Query는 Evidence Bundle의 `queries/`에 복사된다.

- `cloudwatch/`: CloudWatch Logs Insights
- `athena/`: Foundation S3 Access/Flow Log용 Athena SQL

Query의 존재는 탐지 검증을 의미하지 않는다. 실제 Log Field와 Table
Schema를 Runtime에서 확인한 뒤 각 파일의 `Runtime verification` 항목을
갱신한다.

Collector는 Query Pack을 Evidence Bundle의 `queries/`에 복사한다.
`daily-down.ps1 -RunEvidenceQueries`를 사용하면 Scenario에 매핑된
CloudWatch Logs Insights Query를 시간창 안에서 실행하고 결과를 함께
보존한다. Athena Query는 아직 자동 실행하지 않지만,
`athena/00_create_security_log_tables.sql`에 현재 Foundation S3 Prefix와
실제 Runtime Format을 위한 최소 External Table DDL을 준비했다. DDL은
AWS Glue/Athena Catalog를 변경하므로 Placeholder를 현재 Output으로
치환하고 사용자 승인을 받은 뒤 실행한다.

권장 이름은 다음과 같다.

| Placeholder | 권장 값 |
|---|---|
| `${database}` | `aws_topology_security` |
| `${cloudfront_table}` | `cloudfront_access` |
| `${alb_table}` | `alb_primary_access` |
| `${vpc_flow_table}` | `vpc_reject` |

Bucket·Account·Region은 Foundation Output과
`aws sts get-caller-identity`에서 가져오며 문서에 실제 값을 고정하지 않는다.

AWS를 변경하지 않고 실행할 DDL을 먼저 렌더링할 수 있다.

```powershell
$bucket = terraform -chdir=foundation output -raw security_log_bucket_name
$account = aws sts get-caller-identity --query Account --output text

.\observability\render-athena-schema.ps1 `
  -SecurityLogBucket $bucket `
  -AccountId $account `
  -PrimaryRegion ap-northeast-2 `
  -OutputPath "$env:TEMP\aws-topology-athena-schema.sql"
```

이 Script는 Local SQL 파일만 만들며 Athena를 호출하지 않는다. 생성된 DDL의
실행은 AWS Glue/Athena Catalog 변경이므로 현재 Account·Bucket·Region과
영향을 확인한 뒤 승인 Gate를 거친다.

승인 뒤에는 `Invoke-AthenaQueryPack.ps1`이 임의 SQL 대신 아래 네 Query만
실행한다.

- `alb-errors`
- `vpc-reject`
- `cloudfront-trace`
- `alb-trace`
- `alb-window`

시간 기반 Query는 최대 6시간으로 제한한다. `-CreateSchema`는 검토된 Database와
External Table 3개를 `IF NOT EXISTS`로 등록하고, 모든 실행은 Foundation Bucket의
`athena-results/<experiment-id>/`에 SSE-S3 결과를 쓴다. 로컬에는 SQL, 실행 상태,
Scan Byte, 최대 1,000행 결과를 Evidence 하위에 보존한다. DDL은 Glue Catalog를
변경하고 SELECT는 Scan 비용이 있으므로 정확한 승인 문구 없이는 Preview에서
중단한다.

```powershell
.\observability\Invoke-AthenaQueryPack.ps1 `
  -QueryName cloudfront-trace `
  -StartUtc '2026-08-02T08:58:00Z' `
  -EndUtc '2026-08-02T09:00:00Z' `
  -CreateSchema

# Preview가 확인한 범위를 승인받은 뒤에만 추가
# -ConfirmRun 'RUN ATHENA QUERY PACK'
```

## 현재 Log Group

| Source | Region | Log Group |
|---|---|---|
| EKS control plane | `ap-northeast-2` | `/aws/eks/aws-topology-primary/cluster` |
| BANK DVWA | `ap-northeast-2` | `/aws/eks/aws-topology-primary/dvwa` |
| WAF | `us-east-1` | `aws-waf-logs-aws-topology-edge` |
| CloudTrail | `ap-northeast-2` | `/aws/cloudtrail/aws-topology-security` |
| GuardDuty Finding | `ap-northeast-2` | `/aws/events/aws-topology-guardduty-findings` |

## 사용 원칙

1. 실험의 UTC 시작·종료 시각을 먼저 고정한다.
2. 정상 Baseline과 동일한 시간 폭으로 공격 구간을 조회한다.
3. 결과가 0건이어도 삭제하지 않고 “로그 없음”을 증거로 보존한다.
4. IP·User ID는 보고서 반출 전에 필요한 범위만 Masking한다.
5. Cookie, Password, Token, Authorization, Session 값은 Query 결과에
   포함하지 않는다.

## 관측 검증 후보 연결

아래 ID는 팀이 확정한 공격·실습 프로젝트가 아니라 Query와 Evidence
Pipeline을 시험하기 위한 후보다. 실제 본편 시나리오가 정해지면 필요한
Query만 재사용하거나 매핑을 교체한다.

| Scenario | 주요 Query | 현재 경계 |
|---|---|---|
| WEB-01 반복 로그인 실패 | `01_repeated_login_failures.cwli`, `02_waf_count_matches.cwli`, `06_waf_login_rate_limit.cwli`, `03_cloudfront_request_trace.sql`, `04_alb_trace_id_correlation.sql` | `before/count/block`에서 Application 실패 Event 각 20건. `COUNT` Match 2건, `BLOCK` 0건·HTTP 403 0건으로 관측 성공·차단 미검증. Alarm `OK → ALARM → OK`와 Athena 4개 Query Runtime 확인 |
| IAM-01 Pod Identity S3 권한 | `03_kubectl_exec_and_secret_access.cwli`, `07_pod_identity_and_s3_activity.cwli` | 조치 전 Pod Identity와 Canary S3 Put/Get/Delete, 조치 후 Credential 없음·S3 Object API 0건 확인. Foundation S3 Data Events는 활성 상태를 유지하고 Daily Pod Identity 기본값은 비활성 |
| F2 GuardDuty Finding 전달 | `12_guardduty_findings.cwli` | AWS Sample Finding으로 GuardDuty → EventBridge → CloudWatch Logs·SNS와 Finding ID 기반 조사 흐름을 검증한다. Sample은 실제 공격 증거가 아님 |

`04_cloudtrail_security_changes.cwli`는 2026-08-02 Daily Up 시간창에서
76행을 반환했다. 72행은 `terra-user`, 4행은 EKS Service Role의
Provisioning 활동이므로 현재 공격 증거가 아니라 Infrastructure 변경
Baseline이다.

`04_alb_trace_id_correlation.sql`의 Join Key는 기존 Sanitized Bundle에서
BANK `authorization.access.denied` 2건의 `request_id`와 ALB `trace_id`가
1:1로 일치해 Local Evidence 수준으로 확인했다. 2026-08-02 Athena Runtime에서
`alb-errors`, `vpc-reject`, `cloudfront-trace`, `alb-trace` 4개 Query가 모두
`SUCCEEDED`였고 `alb-trace` 1행이 Sanitized BANK `request_id`와 연결됐다.

각 Query의 `Runtime verification: pending`은 실제 Log에서 실행해 Field와
결과를 확인하기 전까지 제거하지 않는다. 0행도 실행 성공과 Field 호환을
증명할 수 있지만 공격·탐지 Threshold 검증을 의미하지는 않는다.

## 범용 관제 Review

`SOC-REVIEW`는 팀이 확정한 공격 시나리오명이 아니다. 조원이 알려준 정확한
공격 시간과 선택적 Source IP를 입력해 다음을 한 번에 만드는 범용 분석
경로다.

- `08_review_application_events.cwli`: BANK 보안 의미 Event
- `09_review_waf_requests.cwli`: WAF 요청과 Rule Action
- 기존 Kubernetes·CloudTrail 보안 Query 재사용
- `03_cloudfront_request_trace.sql`: Edge 요청
- `05_alb_security_window.sql`: ALB 요청·Status·Trace ID

`Review-SecurityWindow.ps1`이 결과를 공통 Timeline으로 정규화하고, 자동 판정을
`NeedsAnalystReview` 상태로 남긴다. Query 성공과 사건 정탐 판정을 혼동하지
않는다.
