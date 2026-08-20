#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\capital-one-public-masking.json'
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw 'The Capital One public masking profile is missing.'
}

$raw = Get-Content -LiteralPath $path -Raw
$profile = $raw | ConvertFrom-Json
if ([int]$profile.schema_version -ne 1 -or
    [string]$profile.profile_id -cne 'capital-one-final-recording-public-v1' -or
    [string]$profile.scope -cne 'final-recording-evidence-and-screen') {
    throw 'The Capital One public masking profile identity is not frozen.'
}

$requiredRules = @(
    'aws_account_id',
    'bucket_name',
    'client_ipv4',
    'arn',
    'cloudtrail_event_id',
    'wazuh_alert_id',
    'shuffle_execution_id',
    'git_commit_sha'
)
$actualRules = @($profile.rules.PSObject.Properties.Name)
if (@($requiredRules | Where-Object { $_ -notin $actualRules }).Count -ne 0 -or
    @($actualRules | Where-Object { $_ -notin $requiredRules }).Count -ne 0) {
    throw 'The public masking rule set is not exact.'
}

$requiredRemovedKeys = @(
    'accesskeyid',
    'secretaccesskey',
    'sessiontoken',
    'authorization',
    'cookie',
    'password',
    'command',
    'full_log',
    'webhook_url',
    'webhook_key',
    'api_key',
    'pat'
)
foreach ($name in $requiredRemovedKeys) {
    if ($name -cnotin @($profile.remove_keys_case_insensitive)) {
        throw "The public masking profile does not remove: $name"
    }
}

if ($raw -match '(?i)433048100798|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|https://[^\s"]+/api/v1/hooks') {
    throw 'The public masking profile contains a real identifier or secret-like value.'
}
if (@($profile.required_visible_fields).Count -ne 12) {
    throw 'The public masking profile visible-field contract is incomplete.'
}

Write-Host 'Capital One public masking profile tests passed.'
