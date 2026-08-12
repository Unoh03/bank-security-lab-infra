#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$detectionPath = Join-Path $root 'foundation\detection.tf'
$variablesPath = Join-Path $root 'foundation\variables.tf'
$outputsPath = Join-Path $root 'foundation\outputs.tf'
$setupFoundationPath = Join-Path $root 'setup-foundation.ps1'
$configPath = Join-Path $root 'automation\project.psd1'
$capitalOneQueryPath = Join-Path $root 'observability\queries\cloudwatch\13_capital_one_validation_getobject.cwli'

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
    $detectionPath,
    $variablesPath,
    $outputsPath,
    $setupFoundationPath,
    $configPath,
    $capitalOneQueryPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required observability detection file is missing: $path"
    }
}

$detection = Get-Content -LiteralPath $detectionPath -Raw
$variables = Get-Content -LiteralPath $variablesPath -Raw
$outputs = Get-Content -LiteralPath $outputsPath -Raw
$setupFoundation = Get-Content -LiteralPath $setupFoundationPath -Raw
$capitalOneQuery = Get-Content -LiteralPath $capitalOneQueryPath -Raw
$config = Import-PowerShellDataFile -LiteralPath $configPath

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

Assert-Contains $variables 'variable\s+"enable_capital_one_s3_detection"[\s\S]*?default\s*=\s*false' `
    'Capital One detection must remain opt-in.'
Assert-Contains $detection 'resource\s+"aws_cloudwatch_log_metric_filter"\s+"capital_one_validation_getobject"[\s\S]*?count\s*=\s*var\.enable_capital_one_s3_detection\s*\?\s*1\s*:\s*0' `
    'The opt-in Capital One CloudTrail metric filter is missing.'
foreach ($requiredPattern in @(
    'eventSource = \\"s3\.amazonaws\.com\\"',
    'eventName = \\"GetObject\\"',
    'primary-karpenter-node',
    'requestParameters\.key = \\"validation/\*\\"',
    'errorCode NOT EXISTS'
)) {
    Assert-Contains $detection $requiredPattern `
        "The Capital One detector is missing a required match term: $requiredPattern"
}
Assert-Contains $detection 'precondition\s*\{[\s\S]*?condition\s*=\s*var\.enable_project_s3_data_events' `
    'Capital One detection must fail before Plan when S3 Data Events are disabled.'
Assert-Contains $detection 'resource\s+"aws_cloudwatch_metric_alarm"\s+"capital_one_validation_getobject"[\s\S]*?period\s*=\s*60[\s\S]*?threshold\s*=\s*1' `
    'The Capital One alarm must fire on one matching event in a one-minute metric window.'
Assert-Contains $detection 'CapitalOneValidationGetObject[\s\S]*?alarm_actions\s*=\s*\[aws_sns_topic\.security_alerts\.arn\]' `
    'The Capital One metric and alarm are not connected to the persistent SNS topic.'
Assert-Contains $outputs 'output\s+"capital_one_s3_detection"[\s\S]*?expected_role_name[\s\S]*?object_prefix' `
    'The Capital One detector state and non-sensitive match contract are not exported.'

Assert-Contains $setupFoundation '\[switch\]\$EnableProjectS3DataEvents' `
    'Foundation setup must expose the chargeable S3 Data Event opt-in.'
Assert-Contains $setupFoundation '\[switch\]\$EnableCapitalOneDetection' `
    'Foundation setup must expose the Capital One detector opt-in.'
Assert-Contains $setupFoundation 'Capital One detection requires -EnableProjectS3DataEvents' `
    'Foundation setup must reject a detector with no CloudTrail input.'
Assert-Contains $setupFoundation '-var=enable_project_s3_data_events=\$enableProjectS3DataEventsValue' `
    'Foundation setup does not pass the reviewed S3 Data Event state to Terraform.'
Assert-Contains $setupFoundation '-var=enable_capital_one_s3_detection=\$enableCapitalOneDetectionValue' `
    'Foundation setup does not pass the reviewed detector state to Terraform.'
Assert-Contains $setupFoundation 'ConfirmCapitalOneDetection\s+-cne\s+''ENABLE CAPITAL ONE DETECTION''[\s\S]*?''apply''' `
    'The separate Capital One confirmation must occur before Foundation Apply.'

$capitalOneQueries = @($config.Evidence.Queries | Where-Object {
    'CAPITAL-ONE' -in @($_.ScenarioIds)
})
if ($capitalOneQueries.Count -ne 1 -or
    [string]$capitalOneQueries[0].Name -cne 'capital-one-validation-getobject' -or
    -not [bool]$capitalOneQueries[0].Required -or
    [string]$capitalOneQueries[0].EventTimeField -cne 'event_time' -or
    [int]$capitalOneQueries[0].MinimumRows -ne 1 -or
    [int]$capitalOneQueries[0].MaxDeliveryAttempts -lt 2) {
    throw 'CAPITAL-ONE must map exactly one required event-time-aware CloudTrail query.'
}
foreach ($field in @(
    'event_time',
    'role_arn',
    'caller_arn',
    'source_ip',
    'user_agent',
    'bucket_name',
    'object_key',
    'error_code',
    'request_id'
)) {
    Assert-Contains $capitalOneQuery ([regex]::Escape($field)) `
        "The Capital One investigation query is missing field: $field"
}
Assert-Contains $capitalOneQuery 'eventName\s*=\s*"GetObject"' `
    'The Capital One investigation query is not restricted to GetObject.'
Assert-Contains $capitalOneQuery 'primary-karpenter-node\$/' `
    'The Capital One investigation query is not restricted to the Primary Karpenter Node Role suffix.'
Assert-Contains $capitalOneQuery 'requestParameters\.key\s+like\s+/\^validation' `
    'The Capital One investigation query is not restricted to validation/.'
if ($capitalOneQuery -match '@message|(?i)accessKey|secret|sessionToken|authorization') {
    throw 'The Capital One investigation query includes raw messages or credential-bearing fields.'
}

Write-Host 'Observability detection static tests passed.'
