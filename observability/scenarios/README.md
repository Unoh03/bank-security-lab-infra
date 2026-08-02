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

## Evidence

Both tools write their client-side record into:

```text
%USERPROFILE%\Documents\aws-topology-evidence\<experiment-id>\source\client\
```

Run the printed `daily-down.ps1 -EvidenceOnly -RunEvidenceQueries ...` command
after log delivery has had time to settle. The existing collector then adds AWS
logs, query results, `manifest.json`, and `SHA256SUMS.txt` to the same bundle.
