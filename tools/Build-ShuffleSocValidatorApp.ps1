#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$ConfirmBuild = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$bundleBuilder = Join-Path $PSScriptRoot 'Build-ShuffleSocAppBundle.ps1'
if (-not (Test-Path -LiteralPath $bundleBuilder -PathType Leaf)) {
    throw 'The canonical Shuffle SOC App bundle builder is missing.'
}
if (-not $OutputDirectory) {
    if (-not $env:USERPROFILE) {
        throw 'USERPROFILE is unavailable; specify -OutputDirectory explicitly.'
    }
    $OutputDirectory = Join-Path $env:USERPROFILE `
        'Documents\aws-topology-evidence\shuffle-packages'
}
$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)

Write-Host 'Shuffle SOC Validator package preview'
Write-Host 'App: AWS Topology SOC Validator 1.0.0'
Write-Host "Output directory: $resolvedOutput"
Write-Host 'Packaging delegates to the canonical four-file SOC App bundle builder.'
if ($ConfirmBuild -cne 'BUILD SHUFFLE VALIDATOR') {
    throw "Preview only. Re-run with -ConfirmBuild 'BUILD SHUFFLE VALIDATOR'."
}

$bundleOutput = & $bundleBuilder `
    -OutputDirectory $resolvedOutput `
    -ConfirmBuild 'BUILD SHUFFLE SOC APPS' 6>&1 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "The canonical Shuffle SOC App bundle builder failed: $($bundleOutput -join ' ')"
}
$manifestLine = @($bundleOutput | ForEach-Object { [string]$_ } | Where-Object {
    $_.StartsWith('BUNDLE_MANIFEST=', [StringComparison]::Ordinal)
}) | Select-Object -Last 1
if (-not $manifestLine) {
    throw 'The canonical Shuffle SOC App bundle builder did not report its manifest.'
}
$manifestPath = $manifestLine.Substring('BUNDLE_MANIFEST='.Length)
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
$apps = @($manifest.apps)
if ($apps.Count -ne 1 -or
    [string]$apps[0].name -cne 'AWS Topology SOC Validator' -or
    [bool]$apps[0].current_v2 -ne $true -or
    (@($apps[0].entries | Sort-Object) -join ',') -cne
        ((@('Dockerfile','api.yaml','requirements.txt','src/app.py') | Sort-Object) -join ',')) {
    throw 'The canonical builder did not produce exactly one four-file current Validator package.'
}

Write-Host 'SHUFFLE_VALIDATOR_PACKAGE_READY=yes'
Write-Host "PACKAGE_PATH=$([string]$apps[0].package_path)"
Write-Host "PACKAGE_SHA256=$([string]$apps[0].package_sha256)"
Write-Host "BUNDLE_MANIFEST=$manifestPath"
