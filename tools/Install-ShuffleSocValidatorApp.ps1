#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagePath,
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [ValidateRange(60,420)][int]$UploadTimeoutSeconds = 300,
    [ValidateRange(1,30)][int]$PollIntervalSeconds = 5,
    [string]$ConfirmUpload = '',
    [switch]$ConsoleOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$canonicalInstaller = Join-Path $PSScriptRoot 'Install-ShuffleSocAppBundle.ps1'
. (Join-Path $PSScriptRoot 'ShuffleSocValidatorPackage.ps1')
if (-not (Test-Path -LiteralPath $canonicalInstaller -PathType Leaf)) {
    throw 'The canonical Shuffle SOC App bundle installer is missing.'
}

$resolvedPackage = [IO.Path]::GetFullPath($PackagePath)
if (-not (Test-Path -LiteralPath $resolvedPackage -PathType Leaf)) {
    throw 'The Shuffle Validator package does not exist.'
}
$packageInfo = Get-Item -LiteralPath $resolvedPackage
if ($packageInfo.Length -le 0 -or $packageInfo.Length -gt 5MB) {
    throw 'The Shuffle Validator package is empty or exceeds the fixed 5 MiB limit.'
}

[byte[]]$compatibilitySnapshot = [IO.File]::ReadAllBytes($resolvedPackage)
try {
    $validatorAppRoot = Join-Path $repositoryRoot `
        'observability\shuffle\apps\aws-topology-soc-validator\1.0.0'
    $compatibilityProof = Assert-SocShuffleValidatorPackageSnapshot `
        -PackageBytes $compatibilitySnapshot -AppRoot $validatorAppRoot
    $packageHash = [string]$compatibilityProof.PackageSha256
} finally {
    [Array]::Clear($compatibilitySnapshot, 0, $compatibilitySnapshot.Length)
}

Write-Host 'Shuffle private Validator App upload compatibility preview'
Write-Host 'App: AWS Topology SOC Validator 1.0.0'
Write-Host "Package SHA-256: $packageHash"
Write-Host 'Upload transaction: canonical async SOC App bundle installer only.'
if ($ConfirmUpload -cne 'UPLOAD SHUFFLE VALIDATOR') {
    throw "Preview only. Re-run with -ConfirmUpload 'UPLOAD SHUFFLE VALIDATOR'."
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = [IO.Path]::GetFullPath((Join-Path $tempBase (
    'shuffle-validator-compat-' + [guid]::NewGuid().ToString('N')
)))
if (-not $tempRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The compatibility manifest path escaped the system temporary directory.'
}
$tempManifest = Join-Path $tempRoot 'shuffle-soc-validator-compat-manifest.json'
try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $manifest = [ordered]@{
        schema_version=1
        artifact_kind='shuffle-soc-private-app-bundle'
        current_contract='v2/100104'
        legacy_dispatcher_included=$false
        legacy_dispatcher_excluded_from_current_v2=$true
        created_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        apps=@([ordered]@{
            name='AWS Topology SOC Validator'
            slug='aws-topology-soc-validator'
            version='1.0.0'
            contract_role='current-v2-validator'
            current_v2=$true
            package_path=$resolvedPackage
            package_sha256=$packageHash
            entries=@('Dockerfile','api.yaml','requirements.txt','src/app.py')
        })
        secret_persisted=$false
    }
    [IO.File]::WriteAllText(
        $tempManifest,
        (($manifest | ConvertTo-Json -Depth 16) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $canonicalArguments = @{
        ManifestPath=$tempManifest
        ConfigurationRoot=$ConfigurationRoot
        SecretRoot=$SecretRoot
        EvidenceRoot=$EvidenceRoot
        UploadTimeoutSeconds=$UploadTimeoutSeconds
        PollIntervalSeconds=$PollIntervalSeconds
        ConfirmUpload='UPLOAD SHUFFLE SOC APPS'
    }
    if ($ConsoleOnly.IsPresent) {
        $canonicalArguments.ConsoleOnly = $true
    }
    & $canonicalInstaller @canonicalArguments
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $cleanupTarget = [IO.Path]::GetFullPath($tempRoot)
        if ($cleanupTarget -cne $tempRoot -or
            -not $cleanupTarget.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The compatibility manifest cleanup target is unsafe.'
        }
        Remove-Item -LiteralPath $cleanupTarget -Recurse -Force
    }
}
