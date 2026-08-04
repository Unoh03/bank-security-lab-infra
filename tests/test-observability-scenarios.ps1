#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$webScriptPath = Join-Path $root 'observability\scenarios\Invoke-WEB01.ps1'
$iamScriptPath = Join-Path $root 'observability\scenarios\Invoke-IAM01.ps1'
$t1ScriptPath = Join-Path $root 'observability\scenarios\Invoke-T1.ps1'
$configPath = Join-Path $root 'automation\project.psd1'
$variablesPath = Join-Path $root 'variables.tf'
$observabilityPath = Join-Path $root 'observability.tf'
$outputsPath = Join-Path $root 'outputs.tf'
$foundationOutputsPath = Join-Path $root 'foundation\outputs.tf'
$wafCountQueryPath = Join-Path $root 'observability\queries\cloudwatch\02_waf_count_matches.cwli'
$wafBlockQueryPath = Join-Path $root 'observability\queries\cloudwatch\06_waf_login_rate_limit.cwli'
$podIdentityQueryPath = Join-Path $root 'observability\queries\cloudwatch\07_pod_identity_and_s3_activity.cwli'
$t1WafQueryPath = Join-Path $root 'observability\queries\cloudwatch\10_t1_waf_requests.cwli'
$t1ApplicationQueryPath = Join-Path $root 'observability\queries\cloudwatch\11_t1_application_requests.cwli'

function Assert-Contains {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

foreach ($path in @(
    $webScriptPath,
    $iamScriptPath,
    $t1ScriptPath,
    $configPath,
    $variablesPath,
    $observabilityPath,
    $outputsPath,
    $foundationOutputsPath,
    $wafCountQueryPath
    $wafBlockQueryPath
    $podIdentityQueryPath
    $t1WafQueryPath
    $t1ApplicationQueryPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required observability scenario file is missing: $path"
    }
}

foreach ($path in @($webScriptPath, $iamScriptPath, $t1ScriptPath)) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -gt 0) {
        throw "PowerShell parser rejected $path`: $($errors[0].Message)"
    }
}

$variables = Get-Content -LiteralPath $variablesPath -Raw
$observability = Get-Content -LiteralPath $observabilityPath -Raw
$outputs = Get-Content -LiteralPath $outputsPath -Raw
$foundationOutputs = Get-Content -LiteralPath $foundationOutputsPath -Raw
$wafCountQuery = Get-Content -LiteralPath $wafCountQueryPath -Raw
$wafBlockQuery = Get-Content -LiteralPath $wafBlockQueryPath -Raw
$podIdentityQuery = Get-Content -LiteralPath $podIdentityQueryPath -Raw
$webScript = Get-Content -LiteralPath $webScriptPath -Raw
$iamScript = Get-Content -LiteralPath $iamScriptPath -Raw
$t1Script = Get-Content -LiteralPath $t1ScriptPath -Raw
$t1WafQuery = Get-Content -LiteralPath $t1WafQueryPath -Raw
$t1ApplicationQuery = Get-Content -LiteralPath $t1ApplicationQueryPath -Raw
$config = Import-PowerShellDataFile -LiteralPath $configPath

Assert-Contains $variables 'variable\s+"waf_login_rate_rule_mode"[\s\S]*?default\s*=\s*"disabled"' `
    'The WEB-01 WAF rule must remain disabled by default.'
Assert-Contains $variables 'contains\(\["disabled",\s*"count",\s*"block"\]' `
    'The WEB-01 WAF mode allowlist is missing.'
Assert-Contains $variables 'waf_login_rate_limit\s*>?=\s*10' `
    'The WEB-01 rate limit does not enforce the AWS minimum.'
Assert-Contains $observability 'aggregate_key_type\s*=\s*"IP"' `
    'The WEB-01 WAF rule is not scoped per source IP.'
Assert-Contains $observability 'search_string\s*=\s*"/login\.php"' `
    'The WEB-01 WAF rule is not scoped to /login.php.'
Assert-Contains $observability 'search_string\s*=\s*"POST"' `
    'The WEB-01 WAF rule is not scoped to POST requests.'
Assert-Contains $observability 'dynamic\s+"count"[\s\S]*?dynamic\s+"block"' `
    'The WEB-01 WAF rule cannot represent both observation and remediation.'
Assert-Contains $observability 'name\s*=\s*"bank-login-rate"' `
    'The WEB-01 WAF rule name must stay stable across COUNT and BLOCK phases.'
if ($observability -match 'bank-login-rate-\$\{rule\.value\}') {
    throw 'The WEB-01 WAF rule still creates a separate rate tracker per action.'
}
Assert-Contains $wafCountQuery 'bank-login-rate' `
    'The WEB-01 COUNT query is not scoped to the dedicated login rate rule.'
Assert-Contains $wafBlockQuery 'terminatingRuleId\s*=\s*"bank-login-rate"' `
    'The WEB-01 BLOCK query is not scoped to the dedicated login rate rule.'

Assert-Contains $webScript "ConfirmRun -cne 'RUN WEB-01'" `
    'WEB-01 lacks its exact execution confirmation.'
Assert-Contains $webScript '\[ValidateRange\(10,\s*60\)\]' `
    'WEB-01 request count is not bounded.'
Assert-Contains $webScript '\[ValidateRange\(60,\s*300\)\][\s\S]*?RulePropagationWaitSeconds\s*=\s*90' `
    'WEB-01 does not reserve a bounded propagation wait after a Web ACL update.'
Assert-Contains $webScript 'plannedRateObservationSeconds\s*-lt\s*50' `
    'WEB-01 can end before the usual AWS WAF rate mitigation lag.'
Assert-Contains $webScript 'Start-Sleep\s+-Seconds\s+\$RulePropagationWaitSeconds' `
    'WEB-01 does not wait for the updated CloudFront Web ACL to propagate.'
Assert-Contains $webScript '\[switch\]\$ValidateLoginFailureAlarm' `
    'WEB-01 cannot opt in to the minimal login failure alarm validation.'
Assert-Contains $webScript '\[ValidateRange\(60,\s*900\)\][\s\S]*?AlarmWaitSeconds\s*=\s*480' `
    'WEB-01 alarm validation lacks a bounded wait.'
Assert-Contains $webScript "'output', '-raw', 'dvwa_login_failure_alarm_name'" `
    'WEB-01 does not discover its alarm from Foundation state.'
Assert-Contains $webScript "'sns', 'list-subscriptions-by-topic'" `
    'WEB-01 does not report whether the alert topic has a confirmed recipient.'
Assert-Contains $webScript 'StateValue\s*-ceq\s*''ALARM''[\s\S]*?StateUpdatedTimestamp[\s\S]*?\$startedAt' `
    'WEB-01 does not require a new alarm transition caused by the current run.'
Assert-Contains $webScript 'ConfirmedSubscriptionCount' `
    'WEB-01 client evidence does not record confirmed notification coverage.'
if ($webScript -match '\.Endpoint|security_alert_email') {
    throw 'WEB-01 must not print or persist an alert subscription endpoint.'
}
Assert-Contains $webScript "'output', '-raw', 'application_url'" `
    'WEB-01 does not derive its target from Terraform state.'
if ($webScript -match '(?m)^\s*\[string\]\$BaseUrl') {
    throw 'WEB-01 permits an arbitrary target URL.'
}
Assert-Contains $webScript 'phase/mode mismatch' `
    'WEB-01 can label evidence with a phase that differs from the applied WAF mode.'
Assert-Contains $webScript 'EvidenceEndUtc ''\$\(\$finishedAt\.ToString\(''o''\)\)'' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 5' `
    'WEB-01 does not separate its exact event window from delivery grace.'

Assert-Contains $iamScript "ConfirmRun -cne 'RUN IAM-01'" `
    'IAM-01 lacks its exact execution confirmation.'
Assert-Contains $iamScript '@sha256:\[a-f0-9\]\{64\}' `
    'IAM-01 does not require an immutable AWS CLI image digest.'
Assert-Contains $iamScript "'project_s3_data_events_enabled'" `
    'IAM-01 does not require S3 Data Event evidence.'
Assert-Contains $iamScript "'web_s3_pod_identity_enabled'" `
    'IAM-01 does not bind expected allow or deny behavior to Terraform state.'
Assert-Contains $iamScript 'web/experiment-\$ExperimentId/canary\.txt' `
    'IAM-01 is not restricted to its canary object prefix.'
Assert-Contains $iamScript 'trap cleanup EXIT' `
    'IAM-01 lacks bounded cleanup for temporary runtime objects.'
Assert-Contains $iamScript 'aws s3api delete-object' `
    'IAM-01 does not remove the canary object.'
if ($iamScript -match '--body\s+/dev/null') {
    throw 'IAM-01 still uses a special device as the upload body.'
}
Assert-Contains $iamScript "put_status='technical-error'" `
    'IAM-01 does not distinguish client failures from authorization denial.'
Assert-Contains $iamScript 'AccessDenied' `
    'IAM-01 does not recognize an explicit S3 authorization denial.'
Assert-Contains $iamScript 'Unable to locate credentials' `
    'IAM-01 does not recognize the disabled Pod Identity no-credential state.'
Assert-Contains $iamScript 'EvidenceEndUtc ''\$\(\$finishedAt\.ToString\(''o''\)\)'' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 5' `
    'IAM-01 does not separate its exact event window from delivery grace.'
Assert-Contains $podIdentityQuery 'fields\s+@timestamp,\s*eventTime' `
    'IAM-01 CloudTrail query cannot filter delayed delivery by the original event time.'
if ($iamScript -match '(?i)--no-verify-ssl|:latest|AKIA[A-Z0-9]{16}') {
    throw 'IAM-01 contains an unsafe TLS bypass, moving image tag, or access key.'
}

Assert-Contains $t1Script "ConfirmRun -cne 'RUN T1 HTTP'" `
    'T1 lacks its exact temporary HTTP confirmation.'
Assert-Contains $t1Script 'Read-DailySessionState' `
    'T1 does not require an active bounded Daily Session.'
Assert-Contains $t1Script 'T1 must start from the safe HTTPS redirect state' `
    'T1 does not fail closed unless HTTPS redirect is initially enabled.'
Assert-Contains $t1Script 'update`taws_cloudfront_distribution\.this' `
    'T1 does not restrict its Terraform plan to the CloudFront distribution.'
Assert-Contains $t1Script 'finally\s*\{[\s\S]*?EnableHttpsRedirect\s+\$true' `
    'T1 does not restore HTTPS from a finally block.'
Assert-Contains $t1Script 'ResponseHeadersRead' `
    'T1 downloads a response body instead of collecting header-only evidence.'
Assert-Contains $t1Script 'X-Amz-Cf-Id' `
    'T1 does not retain the CloudFront request correlation ID.'
Assert-Contains $t1Script '/t1-observability/\$ExperimentId/' `
    'T1 requests lack a fixed experiment path for cross-log correlation.'
Assert-Contains $t1Script "ScenarioId 'T1'" `
    'T1 does not print the mapped CloudWatch Evidence command.'
Assert-Contains $t1Script 'QueryName cloudfront-trace' `
    'T1 does not print the CloudFront Athena trace command.'
if ($t1Script -match '(?m)^\s*\[string\]\$BaseUrl|GetStringAsync|ReadAsStringAsync') {
    throw 'T1 permits an arbitrary target or downloads a response body.'
}
if ($t1Script -match '(?i)--no-verify-ssl|AKIA[A-Z0-9]{16}|Authorization|Cookie') {
    throw 'T1 contains a TLS bypass, access key, or sensitive request field.'
}
Assert-Contains $t1WafQuery 't1-observability' `
    'T1 WAF query is not scoped to the fixed probe route.'
if (($t1WafQuery -replace '(?m)^\s*#.*$', '') -match '(?i)headers|cookie|requestbody') {
    throw 'T1 WAF query exposes headers, cookies, or request bodies.'
}
Assert-Contains $t1ApplicationQuery 't1-observability' `
    'T1 application query is not scoped to the fixed probe route.'
$t1Queries = @($config.Evidence.Queries | Where-Object {
    'T1' -in @($_.ScenarioIds)
})
if ($t1Queries.Count -ne 2 -or
    @($t1Queries | Where-Object { -not [bool]$_.Required }).Count -ne 0) {
    throw 'T1 must map exactly two required CloudWatch evidence queries.'
}

Assert-Contains $outputs 'output\s+"primary_application_bucket_name"' `
    'The IAM-01 application bucket output is missing.'
Assert-Contains $variables 'variable\s+"enable_web_s3_pod_identity"[\s\S]*?default\s*=\s*false' `
    'The IAM-01 Pod Identity path must remain disabled by default after the denied-state validation.'
Assert-Contains $outputs 'output\s+"web_s3_pod_identity_enabled"' `
    'The IAM-01 Pod Identity state output is missing.'
Assert-Contains $foundationOutputs 'output\s+"project_s3_data_events_enabled"' `
    'The IAM-01 Data Event state output is missing.'

Write-Host 'Observability scenario static tests passed.'
