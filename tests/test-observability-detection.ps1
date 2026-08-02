#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$detectionPath = Join-Path $root 'foundation\detection.tf'
$variablesPath = Join-Path $root 'foundation\variables.tf'
$outputsPath = Join-Path $root 'foundation\outputs.tf'

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

foreach ($path in @($detectionPath, $variablesPath, $outputsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required observability detection file is missing: $path"
    }
}

$detection = Get-Content -LiteralPath $detectionPath -Raw
$variables = Get-Content -LiteralPath $variablesPath -Raw
$outputs = Get-Content -LiteralPath $outputsPath -Raw

Assert-Contains $detection 'resource\s+"aws_cloudwatch_log_metric_filter"\s+"dvwa_login_failures"' `
    'The minimal WEB-01 metric filter is missing.'
Assert-Contains $detection 'pattern\s*=\s*"\{\s*\$\.data\.event_type\s*=\s*\\"auth\.login\.failed\\"\s*\}"' `
    'The WEB-01 metric filter is not bound to the verified BANK audit event.'
Assert-Contains $detection 'default_value\s*=\s*0' `
    'The WEB-01 metric does not publish a zero default when logs are ingested without a match.'
if ($detection -match 'dimensions\s*=|data\.source_ip') {
    throw 'The minimal metric filter must not create unbounded source-IP custom metric dimensions.'
}

Assert-Contains $detection 'period\s*=\s*300' `
    'The WEB-01 alarm must evaluate the agreed five-minute window.'
Assert-Contains $detection 'statistic\s*=\s*"Sum"' `
    'The WEB-01 alarm must count all matching login failure events.'
Assert-Contains $detection 'treat_missing_data\s*=\s*"notBreaching"' `
    'Missing application logs must not be reported as an attack alarm.'
Assert-Contains $detection 'alarm_actions\s*=\s*\[aws_sns_topic\.security_alerts\.arn\]' `
    'The WEB-01 alarm is not connected to the persistent SNS topic.'

Assert-Contains $variables 'variable\s+"dvwa_login_failure_alarm_threshold"[\s\S]*?default\s*=\s*5' `
    'The WEB-01 alarm threshold must default to five events.'
Assert-Contains $variables 'variable\s+"enable_security_alert_email_subscription"[\s\S]*?default\s*=\s*false' `
    'Email delivery must remain opt-in because it requires a recipient and confirmation.'
Assert-Contains $variables 'variable\s+"security_alert_email"[\s\S]*?sensitive\s*=\s*true' `
    'The optional alert email input must be redacted from routine Terraform output.'

Assert-Contains $detection 'resource\s+"aws_sns_topic"\s+"security_alerts"' `
    'The persistent alert topic is missing.'
Assert-Contains $detection 'prevent_destroy\s*=\s*true' `
    'Persistent detection resources lack a Foundation destruction guard.'
Assert-Contains $outputs 'output\s+"security_alert_topic_arn"' `
    'The alert topic ARN output is missing.'
Assert-Contains $outputs 'output\s+"dvwa_login_failure_alarm_name"' `
    'The WEB-01 alarm name output is missing.'

Write-Host 'Observability detection static tests passed.'
