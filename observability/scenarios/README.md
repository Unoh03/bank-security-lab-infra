# Controlled observability scenarios

These scripts are bounded validation tools, not general attack automation and
not yet the team's final project scenarios. They refuse arbitrary targets and
require an exact confirmation string before generating traffic or changing a
temporary Kubernetes object.

## WEB-01 — repeated BANK login failures

`Invoke-WEB01.ps1` always resolves the current `application_url` and CloudFront
distribution from the Daily Terraform state. It sends a bounded number of
synthetic invalid logins to `/login.php`, preserves only status/timing metadata,
and prints the exact Evidence Collector command for the same UTC window.

The three phases are:

1. `before`: the dedicated login rate rule is `disabled`.
2. `count`: the same rule observes matching POST requests without blocking.
3. `block`: the same inputs are repeated after an explicitly approved WAF
   blocking change.

Terraform defaults to `disabled`. Changing `waf_login_rate_rule_mode` to
`count` or `block` requires a reviewed Plan and runtime approval. AWS WAF rate
tracking is approximate. Changing a rate setting resets the rate counters, and
creating the rule after `disabled` starts a new tracker. The script currently
enforces a 90-second propagation wait and at least 50 seconds of bounded traffic
for the `count` and `block` phases, but this is a safety floor rather than a
guarantee that mitigation will begin within the run.

The 2026-08-02 20-request rerun waited 90 seconds and generated traffic for
about 57 seconds in each active phase. `count` matched only the final two
requests and `block` matched none, so the application path was observable but
rate blocking was not proven. A future run must keep the exact approved request
bound while giving WAF enough post-threshold requests to demonstrate the
action; do not label an HTTP 200-only run as a successful block.

After the Foundation detector has been applied, one approved phase can also
prove the application-alarm transition:

```powershell
.\observability\scenarios\Invoke-WEB01.ps1 `
  -Phase before `
  -AttemptCount 10 `
  -ValidateLoginFailureAlarm `
  -ConfirmRun 'RUN WEB-01'
```

Alarm validation is opt-in. It refuses an alarm that was already in `ALARM`,
waits at most eight minutes for a new state transition, and records only the
number and protocol of confirmed SNS subscriptions. It never writes a
subscription email endpoint to the client Evidence. A confirmed subscription
still requires the recipient to verify actual message delivery separately.

References:

- <https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html>
- <https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html>

## IAM-01 — EKS Pod Identity S3 canary

`Invoke-IAM01.ps1` creates one temporary AWS CLI Pod using the existing
`dvwa/web-app` ServiceAccount identity, touches exactly one object below
`web/experiment-<id>/`, verifies the expected allow or deny result, and cleans
up the object, Pod, and any ServiceAccount that the script created.

It refuses to run unless:

- the AWS account matches;
- the image is pinned by `@sha256:<digest>`;
- Foundation S3 Data Events are enabled;
- the exact `RUN IAM-01` confirmation is supplied.

The canary does not print container credentials and does not use the RDS or
application secrets. Removing or narrowing the Pod Identity permission is a
separate reviewed remediation; this script only proves the resulting behavior.

Reference:

- <https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html>

## CAPITAL-ONE — Karpenter Node Role validation read

이 ID는 `capital-one-lab` Profile에서 재현할 대표 시나리오다. 기존 IAM-01은
Pod Identity 권한 검증이므로 서로 같은 공격으로 설명하지 않는다.

다음 세 Script가 Target과 데이터를 고정한다.

- `Prepare-CapitalOneDemoData.ps1`: Primary Application Bucket의
  `validation/capital-one-demo.csv` 한 객체만 만든다. 모든 행은
  `FAKE_TRAINING_DATA`로 표시되고 Bucket 이름은 출력·Evidence에 남기지 않는다.
- `Invoke-CapitalOneBaseline.ps1`: Terraform의 `application_url`에서만 DVWA
  Command Injection을 실행한다. URL·Bucket·Object Key·Command·Payload를 외부
  입력으로 받지 않는다.
- `Invoke-CapitalOneNegativeControl.ps1`: 고정 `terra-user` 정상 운영자 Identity로
  같은 가짜 Object를 한 번 읽는다. CloudTrail에는 1행이 남되 Node Role 조건이 달라
  Alarm은 계속 `OK`여야 한다.

Preview와 실제 실행은 각각 분리돼 있다.

```powershell
.\observability\scenarios\Prepare-CapitalOneDemoData.ps1
.\observability\scenarios\Prepare-CapitalOneDemoData.ps1 `
  -ConfirmRun 'PREPARE CAPITAL ONE DATA'

.\observability\scenarios\Invoke-CapitalOneBaseline.ps1
.\observability\scenarios\Invoke-CapitalOneBaseline.ps1 `
  -ConfirmRun 'RUN CAPITAL ONE BASELINE'

.\observability\scenarios\Invoke-CapitalOneNegativeControl.ps1
.\observability\scenarios\Invoke-CapitalOneNegativeControl.ps1 `
  -ConfirmRun 'RUN CAPITAL ONE NEGATIVE CONTROL'
```

Negative Control은 같은 `ExperimentId`의 기록이 이미 있으면 새 GetObject를 거부한다.
S3 읽기 뒤 CloudTrail 조회만 실패한 경우에는 다음 Resume 확인문으로 기존 1건을
재사용한다.

```powershell
.\observability\scenarios\Invoke-CapitalOneNegativeControl.ps1 `
  -ExperimentId '<existing-id>' `
  -ResumeAfterRead `
  -ConfirmRun 'RESUME CAPITAL ONE NEGATIVE CONTROL'
```

정상 실행의 예상 시간은 다음과 같다.

```text
S3 읽기·가짜 데이터 검증: 수초
CloudTrail 전달·Query: 최대 약 10분, 30초 간격 진행률 출력
Alarm 비전환 관찰: 120초
```

CloudTrail Timeout이 발생해도 새 GetObject를 만들지 않는다. 같은 `ExperimentId`와
Resume 확인문으로 기존 Event만 다시 조회한다. Runner는 Evidence Collector의 공용
CWLI 실행기를 사용하므로 UTF-8 정규화, Delivery Grace, `event_time` 재필터와 재시도
규칙을 별도로 복제하지 않는다. Sanitized Record에는 Invocation·단계별 소요시간도
남는다.

실제 Runner는 `minimal + capital-one-lab`, Active Daily Session, Primary IMDS
`optional/2`, 제한 Node Role Policy, Pod Identity 비활성, S3 Data Event,
Alarm `OK`, 이전 AWS Credential 환경변수 없음부터 확인한다. DVWA 기본 실습 계정으로
새 로그인하므로 기존 브라우저의 admin Session은 무효화될 수 있다.

임시 Node Role Credential은 PowerShell Process 메모리에서만 AWS CLI에 전달하고
`finally`에서 원래 환경변수 상태로 복구한다. Response Body, Access Key, Secret,
Session Token, Account ID, Bucket 이름은 출력하거나 JSON에 기록하지 않는다. 남기는
값은 UTC 구간, TAKE, Role 일치 여부, 고정 가짜 CSV의 행 수·SHA-256, Alarm 전환과
CloudFront Response ID뿐이다.

입력·탐지 계약은 다음과 같다.

```text
CloudTrail S3 Data Event
+ eventName=GetObject
+ Primary Karpenter Node Role
+ object key=validation/*
+ errorCode 없음
→ CapitalOneValidationGetObject Metric
→ 1분 합계 1건 이상
→ CloudWatch Alarm
→ 기존 Security Alert SNS Topic
```

`13_capital_one_validation_getobject.cwli`는 성공 Event뿐 아니라 복구 뒤의
`AccessDenied`도 같은 열로 조회한다. Windows PowerShell 5.1의 native argument
인용 손실을 피하기 위해 Evidence Collector는 CWLI를 UTF-8 임시 파일의 `file://`
인수로 전달한다. CAPITAL-ONE Query는 최소 1행을 요구하고, 로그 인덱싱 지연에
대해서만 제한된 재조회를 수행한다. 0행이 정상인 다른 Query에는 이 조건을 적용하지
않는다.

2026-08-12 Runtime Baseline `capital-one-20260812T025054Z`에서 다음을 확인했다.

- IMDS가 예상 Primary Karpenter Node Role을 반환했다.
- Credential 원문 없이 고정 가짜 CSV 5행을 읽고 준비 시 SHA-256과 일치시켰다.
- 같은 실행으로 Capital One Alarm이 새 `ALARM` 상태로 전환됐다.
- CloudTrail Query 1행에서 `GetObject`, 예상 Role, 고정 Object Key, 성공 상태,
  실행 시간창과 조사 필드가 모두 일치했다.

Negative Control `capital-one-negative-20260812T034935Z`에서는 정상 운영자 GetObject
1행이 같은 고정 Key와 실행 시간창에 남았지만, Primary Karpenter Node Role이 아니어서
Alarm이 `OK`를 유지하고 State Updated Timestamp도 바뀌지 않았다. Client Record에는
Bucket·Caller ARN·Credential을 남기지 않았고 Bundle의 SHA-256 50개를 모두 대조했다.

첫 후속 Query는 한글 주석을 AWS CLI `file://`에 직접 넘기고 전달 지연 시간을 Scan
Window에 포함하지 않아 실패했다. Runner의 별도 Query 구현을 제거하고 검증된 Evidence
Collector를 재사용하도록 고쳤으며, Resume 모드로 S3 읽기를 반복하지 않은 채 같은
Event를 검증했다.

이 결과는 Command Injection을 대체 진입점으로 사용한 공격 경로와 확정 탐지까지의
증거다. SSRF 자체, SIEM, SOAR, GitHub Containment, Argo 재배포, 재공격 실패는 아직
증명하지 않는다.

## T1 — temporary HTTP observation and HTTPS restoration

`Invoke-T1.ps1` is the only approved exception to the normal Daily wrapper
rule that prevents changing HTTP behavior in an active Runtime. It starts only
from `enable_https_redirect=true`, requires an Active Daily Session and the
exact `RUN T1 HTTP` confirmation, and accepts no arbitrary target URL.

The reviewed sequence is:

1. prove that HTTP redirects to HTTPS while HTTPS still reaches CloudFront;
2. apply a saved Terraform Plan that updates only
   `aws_cloudfront_distribution.this` to `allow-all`;
3. repeat bounded HTTP and HTTPS header-only probes;
4. restore `redirect-to-https` in `finally`;
5. prove the restored redirect before reporting either success or failure.

Probe bodies, cookies, sessions, and request headers are not persisted. Each
request uses a fixed `/t1-observability/<experiment>/` path and records only
status, redirect location, timing, and the CloudFront response ID. The script
prints separate commands for CloudWatch Evidence collection and the delayed
CloudFront Athena trace. CloudFront S3 delivery can lag behind the experiment,
so client evidence alone is not proof that the log pipeline was verified.

References:

- <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html>
- <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html>

## Evidence

The scenario tools write their client-side record into:

```text
%USERPROFILE%\Documents\aws-topology-evidence\<experiment-id>\source\client\
```

Run the printed `daily-down.ps1 -EvidenceOnly -RunEvidenceQueries ...` command
after log delivery has had time to settle. The existing collector then adds AWS
logs, query results, `manifest.json`, and `SHA256SUMS.txt` to the same bundle.
