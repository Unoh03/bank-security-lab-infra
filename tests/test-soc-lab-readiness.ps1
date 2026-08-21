#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'tools\Test-SocLabReadiness.ps1'
$text = Get-Content -LiteralPath $path -Raw
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile(
    $path,[ref]$tokens,[ref]$errors
)
if (@($errors).Count -ne 0) {
    throw "Parser errors in $path`: $(@($errors.Message) -join '; ')"
}
foreach ($pattern in @(
    'SOC_STATIC_READY=',
    'SOC_CLOUD_READY=',
    'Get-ShuffleSocAppUploadEvidence',
    'IncludeLegacyChecks',
    'dvwa-local-scope',
    '--porcelain=v1',
    '$staticCheckNames',
    'github-remote-runtime',
    'Assert-ShuffleSocGateB5Evidence',
    'Assert-ShuffleSocProductionWorkflow',
    'Get-ShuffleSocCloudProvenance',
    'Get-ShuffleSocCoreContractSha256',
    'no secret values printed',
    'currentV2Paths',
    "-Name 'v2-contracts'",
    'legacy-v1-boundary',
    'EXCLUDED/NOT_CURRENT',
    'Current=$Current',
    "-Current `$false"
)) {
    if ($text -notmatch [regex]::Escape($pattern)) {
        throw "The readiness script lacks a required boundary: $pattern"
    }
}
if ($text -match 'Write-Host[^\r\n]*\$(?:apiKey|value)') {
    throw 'The readiness script may print a decrypted secret variable.'
}
Write-Host 'SOC lab readiness static tests passed.'
