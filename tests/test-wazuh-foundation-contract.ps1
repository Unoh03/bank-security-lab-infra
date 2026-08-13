#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Read-RequiredFile {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Wazuh contract artifact is missing: $RelativePath"
    }
    return Get-Content -LiteralPath $path -Raw
}

function Assert-Match {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

function Assert-NotMatch {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -match $Pattern) {
        throw $Message
    }
}

$variables = Read-RequiredFile 'foundation\variables.tf'
$wazuh = Read-RequiredFile 'foundation\wazuh.tf'
$outputs = Read-RequiredFile 'foundation\outputs.tf'
$xml = Read-RequiredFile 'observability\wazuh\cloudtrail-ossec.example.xml'
$readme = Read-RequiredFile 'observability\wazuh\README.md'

Assert-Match $variables 'variable\s+"enable_wazuh_log_reader"[\s\S]*?default\s*=\s*false' `
    'The Wazuh reader must be disabled by default.'
Assert-Match $variables 'variable\s+"wazuh_reader_trusted_principal_arn"[\s\S]*?default\s*=\s*null' `
    'The Wazuh bootstrap principal must not have a committed default ARN.'
Assert-Match $wazuh 'resource\s+"aws_iam_role"\s+"wazuh_log_reader"[\s\S]*?precondition\s*\{' `
    'The Wazuh reader lacks a fail-closed resource precondition.'
Assert-Match $wazuh 'split\(":",\s*local\.wazuh_reader_trusted_principal_arn\)\[4\][\s\S]*?data\.aws_caller_identity\.current\.account_id' `
    'The Wazuh bootstrap principal is not restricted to the active account.'

Assert-Match $wazuh 'resource\s+"aws_iam_role"\s+"wazuh_log_reader"[\s\S]*?count\s*=\s*var\.enable_wazuh_log_reader\s*\?\s*1\s*:\s*0' `
    'The optional Wazuh role is not controlled by the default-off toggle.'
Assert-Match $wazuh 'principals[\s\S]*?identifiers\s*=\s*\[local\.wazuh_reader_assume_principal_arn\]' `
    'The Wazuh role trust is not limited to the explicit bootstrap principal.'
Assert-Match $wazuh 'actions\s*=\s*\["s3:ListBucket"\][\s\S]*?variable\s*=\s*"s3:prefix"[\s\S]*?wazuh_cloudtrail_prefix' `
    'CloudTrail ListBucket is not restricted by the project CloudTrail prefix.'
Assert-Match $wazuh 'actions\s*=\s*\["s3:GetObject"\][\s\S]*?security_logs\.arn}/\$\{local\.wazuh_cloudtrail_prefix}\*' `
    'CloudTrail GetObject is not restricted to the project CloudTrail prefix.'
Assert-Match $wazuh 'actions\s*=\s*\["logs:DescribeLogStreams"\]' `
    'The approved CloudWatch sources lack DescribeLogStreams.'
Assert-Match $wazuh 'actions\s*=\s*\["logs:GetLogEvents"\]' `
    'The approved CloudWatch sources lack GetLogEvents.'
Assert-Match $wazuh 'waf\s*=\s*\{[\s\S]*?aws_cloudwatch_log_group\.waf_edge' `
    'The Reader source contract does not include the WAF log group.'
Assert-Match $wazuh 'dvwa\s*=\s*\{[\s\S]*?aws_cloudwatch_log_group\.dvwa_primary' `
    'The Reader source contract does not include the Primary DVWA log group.'
Assert-NotMatch $wazuh 's3:(PutObject|DeleteObject)|logs:(PutLogEvents|DeleteLogStream)|resource\s+"aws_iam_(user|access_key)"|s3:\*|logs:\*' `
    'The Wazuh Reader grants write/delete/wildcard access or creates a long-lived IAM identity.'
Assert-NotMatch $wazuh 'aws_(sqs|kinesis_firehose|cloudwatch_event)' `
    'The initial Wazuh Reader must not add SQS, Firehose, or EventBridge resources.'

Assert-Match $outputs 'output\s+"wazuh_log_reader_role_arn"' `
    'The optional Wazuh Reader Role ARN output is missing.'
Assert-Match $outputs 'output\s+"wazuh_log_sources"[\s\S]*?cloudtrail[\s\S]*?cloudwatch' `
    'The non-sensitive Wazuh source contract output is missing.'

Assert-Match $xml '<bucket\s+type="cloudtrail">' `
    'The first Wazuh configuration is not scoped to CloudTrail.'
Assert-Match $xml '<aws_profile>wazuh-reader</aws_profile>' `
    'The Wazuh configuration does not use the temporary reader profile.'
Assert-Match $xml '<only_logs_after>2026-AUG-12</only_logs_after>' `
    'The first-ingestion date boundary is missing.'
Assert-Match $xml '<remove_from_bucket>no</remove_from_bucket>' `
    'The Wazuh configuration does not explicitly preserve source objects.'
Assert-NotMatch $xml '<(access_key|secret_key|iam_role_arn)>' `
    'The Wazuh XML must not contain credentials or re-assume the already assumed Reader Role.'
Assert-Match $readme 'CloudTrail 하나만 사용' `
    'The first Runtime source is not documented as CloudTrail-only.'
Assert-Match $readme 'Server management → Settings' `
    'The GUI configuration route is missing.'

Write-Host 'Wazuh Foundation contract static tests passed.'
