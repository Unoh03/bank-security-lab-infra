[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')]
    [string]$SecurityLogBucket,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d{12}$')]
    [string]$AccountId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z]{2}(?:-gov)?-[a-z]+-\d$')]
    [string]$PrimaryRegion,

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$Database = 'aws_topology_security',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$CloudFrontTable = 'cloudfront_access',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$AlbTable = 'alb_primary_access',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$VpcFlowTable = 'vpc_reject',

    [Parameter(Mandatory)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$templatePath = Join-Path $PSScriptRoot 'queries\athena\00_create_security_log_tables.sql'
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    throw "Athena schema template is unavailable: $templatePath"
}

$rendered = [System.IO.File]::ReadAllText($templatePath)
$replacements = [ordered]@{
    '${database}'            = $Database
    '${security_log_bucket}' = $SecurityLogBucket
    '${account_id}'          = $AccountId
    '${primary_region}'      = $PrimaryRegion
    '${cloudfront_table}'    = $CloudFrontTable
    '${alb_table}'           = $AlbTable
    '${vpc_flow_table}'      = $VpcFlowTable
}

foreach ($entry in $replacements.GetEnumerator()) {
    $rendered = $rendered.Replace([string]$entry.Key, [string]$entry.Value)
}

$unresolved = @(
    [regex]::Matches($rendered, '\$\{[^}]+\}') |
        ForEach-Object { $_.Value } |
        Sort-Object -Unique
)
if ($unresolved.Count -gt 0) {
    throw "Athena schema contains unresolved placeholders: $($unresolved -join ', ')"
}

$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $resolvedOutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

[System.IO.File]::WriteAllText(
    $resolvedOutputPath,
    $rendered,
    (New-Object System.Text.UTF8Encoding($false))
)

[pscustomobject]@{
    OutputPath = $resolvedOutputPath
    Database   = $Database
    Tables     = @($CloudFrontTable, $AlbTable, $VpcFlowTable)
    AwsChanged = $false
}
