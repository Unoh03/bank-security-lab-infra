#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$ConfirmBuild = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$appRoot = Join-Path $repositoryRoot `
    'observability\shuffle\apps\aws-topology-soc-validator\1.0.0'
$requiredFiles = @(
    'api.yaml','Dockerfile','requirements.txt','src\app.py','src\validator.py'
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $appRoot $relativePath) -PathType Leaf)) {
        throw "The Shuffle Validator package source is incomplete: $relativePath"
    }
}

if (-not $OutputDirectory) {
    if (-not $env:USERPROFILE) {
        throw 'USERPROFILE is unavailable; specify -OutputDirectory explicitly.'
    }
    $OutputDirectory = Join-Path $env:USERPROFILE `
        'Documents\aws-topology-evidence\shuffle-packages'
}
$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
$stamp = [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$packagePath = Join-Path $resolvedOutput `
    "aws-topology-soc-validator-1.0.0-$stamp.zip"

Write-Host 'Shuffle SOC Validator package preview'
Write-Host 'App: AWS Topology SOC Validator 1.0.0'
Write-Host "Source: $appRoot"
Write-Host "Output: $packagePath"
Write-Host 'The package contains fixed validation code only; no credential or Workflow ID is included.'
if ($ConfirmBuild -cne 'BUILD SHUFFLE VALIDATOR') {
    throw "Preview only. Re-run with -ConfirmBuild 'BUILD SHUFFLE VALIDATOR'."
}

& python -B -m unittest tests.test_soc_shuffle_validator_app
if ($LASTEXITCODE -ne 0) {
    throw 'The Shuffle SOC Validator unit tests failed; no package was built.'
}

$staging = Join-Path ([IO.Path]::GetTempPath()) `
    ('shuffle-soc-validator-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path (Join-Path $staging 'src') -Force | Out-Null
    foreach ($relativePath in $requiredFiles) {
        $destination = Join-Path $staging $relativePath
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $appRoot $relativePath) `
            -Destination $destination
    }
    New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
    Compress-Archive -LiteralPath @(
        (Join-Path $staging 'api.yaml'),
        (Join-Path $staging 'Dockerfile'),
        (Join-Path $staging 'requirements.txt'),
        (Join-Path $staging 'src')
    ) -DestinationPath $packagePath -CompressionLevel Optimal
} finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

$hash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host 'SHUFFLE_VALIDATOR_PACKAGE_READY=yes'
Write-Host "PACKAGE_PATH=$packagePath"
Write-Host "PACKAGE_SHA256=$hash"

