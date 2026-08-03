# Daily Automation extension contract

`daily-up.ps1` and `daily-down.ps1` are entry points. Project-specific facts live
in `project.psd1`; reusable orchestration and evidence collection live in
`Daily.Automation.psm1`.

## Change boundary

- A Terraform-only service normally requires no PowerShell change.
- A new application that follows the existing GitHub Actions, Argo CD, and
  health-check contract is added to `Applications`.
- A new evidence source that matches an existing collector type is added to
  `Evidence.Collectors`.
- A genuinely new bootstrap, collector, or verification protocol requires one
  new typed implementation. Do not add service-specific commands directly to
  `daily-up.ps1` or `daily-down.ps1`.

`project.psd1` must not contain credentials, private keys, database values,
Terraform state, or kubeconfig content.

The current application runner implements the `MariaDbDvwa` database contract.
Adding another application with the same deployment contract is declarative;
adding PostgreSQL, a queue, or a different bootstrap protocol requires a new
typed handler and its focused test rather than another inline branch in the
entry-point scripts.

## Evidence failure policy

- `Stop`: the source belongs to Daily Runtime and will disappear during
  destroy. Collection failure blocks destroy.
- `Warn`: the source is in Persistent Foundation and remains available for the
  configured retention period. Destroy may continue, and collection can be
  retried within that period.

`daily-down.ps1` collects before destroy and once again after Terraform state
becomes empty. The first pass protects disappearing Daily evidence; the second
copies persistent CloudTrail objects delivered during the long teardown.

Raw evidence stays outside the Terraform source tree. GitHub receives only
sanitized reports, not raw CloudTrail or application logs.

## Security window review

`Review-SecurityWindow.ps1`은 Raw Log를 추가로 저장하는 도구가 아니라, 이미
수집된 CloudWatch·S3 Log를 관제 업무 단위로 압축하는 진입점이다.

```powershell
# Preview: AWS Query를 실행하지 않는다.
.\Review-SecurityWindow.ps1 `
  -StartKst '2026-08-03 14:00' `
  -EndKst '2026-08-03 14:20' `
  -SourceIp '203.0.113.10' `
  -Label 'sqli-check'

# 확인한 시간창을 실제 조회한다.
.\Review-SecurityWindow.ps1 `
  -StartKst '2026-08-03 14:00' `
  -EndKst '2026-08-03 14:20' `
  -SourceIp '203.0.113.10' `
  -Label 'sqli-check' `
  -ConfirmRun 'RUN SECURITY REVIEW'
```

최대 조회 범위는 6시간이다. `-SkipAthena`는 CloudWatch만 빠르게 확인할 때
사용한다. Athena External Table이 없는 최초 1회에만 검토 후
`-CreateAthenaSchema`를 추가한다.

결과는 기존 Evidence Bundle에 다음 세 파일로 추가된다.

- `review/summary.md`: 사람이 읽는 Triage와 Timeline Preview
- `review/timeline.csv`: Source별 정규화 Event
- `review/triage.json`: Incident ID, Suggested Severity, 판정 대기 항목

자동 결과는 최종 정탐·오탐 판정이 아니다. `request_id`/`trace_id`가 실제로
일치하면 `exact`, IP·Route·2초 범위만 맞으면 `strong_inference`, 시간창만
관련되면 `time_window_association`으로 구분한다.

구현 패턴은 AWS 공식 CloudWatch Logs Insights·Athena 예제와 Incident
Response Jupyter Playbook을 참고했다. 탐지 규칙과 Event Field는 Sigma와
OCSF의 최소 형태만 차용하고, 별도 SIEM이나 Schema 전체를 도입하지 않는다.

- https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-examples.html
- https://docs.aws.amazon.com/athena/latest/ug/query-alb-access-logs-examples.html
- https://github.com/aws-samples/jupyter-notebook-for-incident-response
- https://sigmahq.io/docs/basics/rules.html
- https://github.com/ocsf
