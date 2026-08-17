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
$foundationObservability = Read-RequiredFile 'foundation\observability.tf'
$wazuh = Read-RequiredFile 'foundation\wazuh.tf'
$outputs = Read-RequiredFile 'foundation\outputs.tf'
$dailyObservability = Read-RequiredFile 'observability.tf'
$setupFoundation = Read-RequiredFile 'setup-foundation.ps1'
$dailyCommon = Read-RequiredFile 'daily-common.ps1'
$xml = Read-RequiredFile 'observability\wazuh\cloudtrail-ossec.example.xml'
$readme = Read-RequiredFile 'observability\wazuh\README.md'

Assert-Match $variables 'variable\s+"enable_wazuh_log_reader"[\s\S]*?default\s*=\s*false' `
    'The Wazuh reader must be disabled by default.'
Assert-Match $variables 'variable\s+"wazuh_reader_trusted_principal_arn"[\s\S]*?default\s*=\s*null' `
    'The Wazuh bootstrap principal must not have a committed default ARN.'
Assert-Match $variables 'variable\s+"cloudfront_wazuh_log_retention_days"[\s\S]*?default\s*=\s*3' `
    'The CloudFront Wazuh hot copy must default to three-day retention.'
Assert-Match $foundationObservability 'resource\s+"aws_cloudwatch_log_group"\s+"cloudfront_wazuh"[\s\S]*?provider\s*=\s*aws\.global[\s\S]*?retention_in_days\s*=\s*var\.cloudfront_wazuh_log_retention_days' `
    'The short-retention CloudFront Wazuh log group is missing from Foundation.'
Assert-Match $foundationObservability 'resource\s+"aws_cloudwatch_log_delivery_destination"\s+"cloudfront_wazuh"[\s\S]*?destination_resource_arn\s*=\s*aws_cloudwatch_log_group\.cloudfront_wazuh\.arn' `
    'The CloudFront Wazuh CloudWatch Logs delivery destination is missing.'
Assert-Match $wazuh 'resource\s+"aws_iam_role"\s+"wazuh_log_reader"[\s\S]*?precondition\s*\{' `
    'The Wazuh reader lacks a fail-closed resource precondition.'
Assert-Match $wazuh 'split\(":",\s*local\.wazuh_reader_trusted_principal_arn\)\[4\][\s\S]*?data\.aws_caller_identity\.current\.account_id' `
    'The Wazuh bootstrap principal is not restricted to the active account.'

Assert-Match $wazuh 'resource\s+"aws_iam_role"\s+"wazuh_log_reader"[\s\S]*?count\s*=\s*var\.enable_wazuh_log_reader\s*\?\s*1\s*:\s*0' `
    'The optional Wazuh role is not controlled by the default-off toggle.'
Assert-Match $wazuh 'principals[\s\S]*?identifiers\s*=\s*\[local\.wazuh_reader_assume_principal_arn\]' `
    'The Wazuh role trust is not limited to the explicit bootstrap principal.'
Assert-Match $wazuh 'sid\s*=\s*"ListSecurityLogBucketKeys"[\s\S]*?actions\s*=\s*\["s3:ListBucket"\][\s\S]*?resources\s*=\s*\[aws_s3_bucket\.security_logs\.arn\]' `
    'Wazuh requires bucket-level key listing before it can process the approved object prefixes.'
Assert-Match $wazuh 'actions\s*=\s*\["s3:GetObject"\][\s\S]*?wazuh_cloudtrail_prefix[\s\S]*?wazuh_alb_prefix' `
    'Object reads must be restricted to the approved CloudTrail and Primary ALB prefixes.'
Assert-Match $wazuh 'actions\s*=\s*\["logs:DescribeLogStreams"\]' `
    'The approved CloudWatch sources lack DescribeLogStreams.'
Assert-Match $wazuh 'actions\s*=\s*\["logs:GetLogEvents"\]' `
    'The approved CloudWatch sources lack GetLogEvents.'
Assert-Match $wazuh 'waf\s*=\s*\{[\s\S]*?aws_cloudwatch_log_group\.waf_edge' `
    'The Reader source contract does not include the WAF log group.'
Assert-Match $wazuh 'dvwa\s*=\s*\{[\s\S]*?aws_cloudwatch_log_group\.dvwa_primary' `
    'The Reader source contract does not include the Primary DVWA log group.'
Assert-Match $wazuh 'cloudfront\s*=\s*\{[\s\S]*?aws_cloudwatch_log_group\.cloudfront_wazuh' `
    'The Reader source contract does not include the CloudFront Wazuh log group.'
Assert-NotMatch $wazuh 's3:(PutObject|DeleteObject)|logs:(PutLogEvents|DeleteLogStream)|resource\s+"aws_iam_(user|access_key)"|s3:\*|logs:\*' `
    'The Wazuh Reader grants write/delete/wildcard access or creates a long-lived IAM identity.'
Assert-NotMatch $wazuh 'resource\s+"aws_(sqs|kinesis_firehose|cloudwatch_event)' `
    'The Reader policy file must not define SQS, Firehose, or EventBridge resources.'

Assert-Match $outputs 'output\s+"wazuh_log_reader_role_arn"' `
    'The optional Wazuh Reader Role ARN output is missing.'
Assert-Match $outputs 'output\s+"wazuh_log_sources"[\s\S]*?cloudtrail[\s\S]*?cloudwatch' `
    'The non-sensitive Wazuh source contract output is missing.'
Assert-Match $outputs 'output\s+"cloudfront_wazuh_log_delivery_destination_arn"' `
    'The Daily root cannot discover the CloudFront Wazuh delivery destination.'
Assert-Match $outputs 'output\s+"cloudfront_wazuh_log_retention_days"[\s\S]*?var\.cloudfront_wazuh_log_retention_days' `
    'The Daily preflight cannot verify the CloudFront Wazuh short-retention contract.'
Assert-Match $dailyObservability 'cloudfront_wazuh_logging_enabled\s*=\s*var\.enable_edge_access_logging\s*&&\s*local\.capital_one_lab_enabled' `
    'The CloudFront Wazuh copy is not restricted to the approved lab profile.'
Assert-Match $dailyObservability 'resource\s+"aws_cloudwatch_log_delivery"\s+"cloudfront_wazuh"[\s\S]*?delivery_source_name\s*=\s*aws_cloudwatch_log_delivery_source\.cloudfront_access\[0\]\.name' `
    'The CloudFront Wazuh delivery must reuse the existing single delivery source.'
Assert-Match $setupFoundation '\[switch\]\$EnableWazuhLogReader[\s\S]*?\[string\]\$WazuhReaderTrustedPrincipalArn' `
    'Foundation setup does not expose the optional Wazuh Reader contract.'
Assert-Match $setupFoundation '-var=enable_wazuh_log_reader=\$enableWazuhLogReaderValue' `
    'Foundation setup does not pass the reviewed Wazuh Reader state to Terraform.'
Assert-Match $setupFoundation '-var=wazuh_reader_trusted_principal_arn=\$WazuhReaderTrustedPrincipalArn' `
    'Foundation setup does not pass the explicit Wazuh bootstrap principal to Terraform.'
Assert-Match $setupFoundation 'Wazuh log reader requires -WazuhReaderTrustedPrincipalArn' `
    'Foundation setup must reject an enabled Reader with no explicit trusted principal.'
Assert-Match $setupFoundation 'WazuhReaderTrustedPrincipalArn was provided without -EnableWazuhLogReader' `
    'Foundation setup must reject an unused trusted-principal input.'
Assert-Match $dailyCommon "entry\.Key\s+-in\s+@\('cloudfront',\s*'waf'\)[\s\S]*?'us-east-1'" `
    'Daily preflight must inspect the global CloudFront and WAF log groups in us-east-1.'
Assert-Match $dailyCommon "entry\.Key\s+-ceq\s+'cloudfront'[\s\S]*?cloudFrontWazuhRetentionDays" `
    'Daily preflight must verify CloudFront against its short-retention contract.'

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
