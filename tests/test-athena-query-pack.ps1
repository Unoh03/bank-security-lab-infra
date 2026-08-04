#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'observability\Invoke-AthenaQueryPack.ps1'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Athena Query Pack runner is missing: $scriptPath"
}

$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -gt 0) {
    throw "PowerShell parser rejected the Athena runner: $($errors[0].Message)"
}

$script = Get-Content -LiteralPath $scriptPath -Raw

function Assert-Contains {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )
    if ($script -notmatch $Pattern) {
        throw $Message
    }
}

Assert-Contains '\[ValidateSet\(''alb-errors'',\s*''vpc-reject'',\s*''cloudfront-trace'',\s*''alb-trace'',\s*''alb-window''\)\]' `
    'Athena execution is not restricted to the approved Query Pack.'
Assert-Contains "'alb-window'\s*=\s*@\{[\s\S]*?05_alb_security_window\.sql" `
    'The generic ALB security-window query is not registered.'
if ($script -match '(?m)^\s*\[string\]\$QueryFile') {
    throw 'Athena execution permits an arbitrary query file.'
}
Assert-Contains "ConfirmRun\s+-cne\s+'RUN ATHENA QUERY PACK'" `
    'Athena execution lacks its exact cost and catalog-change confirmation.'
Assert-Contains 'TotalHours\s+-gt\s+6' `
    'Athena evidence queries are not limited to the Daily Session window.'
Assert-Contains "'security_log_bucket_name'" `
    'Athena does not derive its result and source bucket from Foundation state.'
Assert-Contains 'ExpectedBucketOwner\s*=\s*\[string\]\$identity\.Account' `
    'Athena results do not enforce the expected S3 bucket owner.'
Assert-Contains '\[ValidateSet\(''primary''\)\][\s\S]*?WorkGroup\s*=\s*''primary''' `
    'Athena permits an unreviewed workgroup with an overriding result location.'
Assert-Contains "'athena',\s*'get-work-group'" `
    'Athena does not inspect the workgroup override before execution.'
Assert-Contains 'overrides results to an unapproved bucket' `
    'Athena does not reject a workgroup result override outside the Foundation bucket.'
Assert-Contains "EncryptionOption\s*=\s*'SSE_S3'" `
    'Athena results do not request S3 server-side encryption.'
Assert-Contains "'--client-request-token'" `
    'Athena execution does not use an idempotency token.'
Assert-Contains '\[ValidateRange\(10,\s*120\)\][\s\S]*?MaxPollAttempts\s*=\s*60' `
    'Athena polling is not bounded.'
Assert-Contains "'SUCCEEDED',\s*'FAILED',\s*'CANCELLED'" `
    'Athena polling does not recognize all terminal states.'
Assert-Contains 'Expected four bounded Athena DDL statements' `
    'Athena schema execution does not enforce the reviewed DDL scope.'
Assert-Contains "'athena',\s*'get-table-metadata'" `
    'Athena does not inspect the existing CloudFront Glue schema.'
Assert-Contains 'ADD COLUMNS \(`cs-protocol` string\)' `
    'Athena cannot migrate an existing CloudFront table for T1 protocol evidence.'
Assert-Contains 'CloudFront protocol column is missing\. Re-run the approved query with -CreateSchema' `
    'CloudFront trace does not fail closed when the protocol column is absent.'
Assert-Contains 'Join-Path\s+\$localRoot\s+''results\\athena''' `
    'Athena results are not written into the Local Evidence bundle.'
Assert-Contains 'DataScannedInBytes' `
    'Athena Evidence does not record billed scan volume.'
if ($script -match '(?i)--no-verify-ssl|AKIA[A-Z0-9]{16}|\.Endpoint') {
    throw 'Athena runner contains a TLS bypass, access key, or subscription endpoint.'
}

$rendererPath = Join-Path $root 'observability\render-athena-schema.ps1'
$renderedPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-athena-contract-{0}.sql' -f [guid]::NewGuid().ToString('N')
)
try {
    & $rendererPath `
        -SecurityLogBucket 'example-security-log-bucket' `
        -AccountId '123456789012' `
        -PrimaryRegion 'ap-northeast-2' `
        -OutputPath $renderedPath | Out-Null
    $rendered = [System.IO.File]::ReadAllText($renderedPath)
    $statements = @(
        [regex]::Split($rendered, ';\s*(?:\r?\n|$)') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
    if ($statements.Count -ne 4) {
        throw "Rendered Athena schema must contain exactly four statements; found $($statements.Count)."
    }
    foreach ($expected in @(
        'CREATE DATABASE IF NOT EXISTS aws_topology_security',
        'CREATE EXTERNAL TABLE IF NOT EXISTS aws_topology_security.cloudfront_access',
        'CREATE EXTERNAL TABLE IF NOT EXISTS aws_topology_security.alb_primary_access',
        'CREATE EXTERNAL TABLE IF NOT EXISTS aws_topology_security.vpc_reject',
        '`cs-protocol` string',
        'x-edge-request-id,cs-protocol,time-taken'
    )) {
        if (-not $rendered.Contains($expected)) {
            throw "Rendered Athena schema is missing: $expected"
        }
    }
}
finally {
    Remove-Item -LiteralPath $renderedPath -Force -ErrorAction SilentlyContinue
}

$cloudFrontQueryPath = Join-Path $root 'observability\queries\athena\03_cloudfront_request_trace.sql'
$cloudFrontQuery = Get-Content -LiteralPath $cloudFrontQueryPath -Raw
if ($cloudFrontQuery -notmatch '"cs-protocol"\s+AS\s+protocol') {
    throw 'CloudFront trace query does not return the viewer protocol for T1.'
}

Write-Host 'Athena Query Pack static tests passed.'
