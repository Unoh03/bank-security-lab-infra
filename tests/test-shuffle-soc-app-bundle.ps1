#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildPath = Join-Path $root 'tools\Build-ShuffleSocAppBundle.ps1'
$uploadPath = Join-Path $root 'tools\Install-ShuffleSocAppBundle.ps1'
$buildText = Get-Content -LiteralPath $buildPath -Raw
$uploadText = Get-Content -LiteralPath $uploadPath -Raw

if ($buildText -notmatch "ConfirmBuild\s+-cne\s+'BUILD SHUFFLE SOC APPS'" -or
    $buildText -notmatch 'tests\.test_soc_shuffle_validator_app' -or
    $buildText -notmatch 'tests\.test_soc_shuffle_github_dispatcher_app' -or
    $buildText -notmatch 'Compress-Archive') {
    throw 'The Shuffle SOC App bundle builder lacks its confirmation, tests, or ZIP step.'
}
if ($uploadText -notmatch "ConfirmUpload\s+-cne\s+'UPLOAD SHUFFLE SOC APPS'" -or
    $uploadText -notmatch '/api/v1/apps/upload' -or
    $uploadText -notmatch "Unprotect-SocSecret\s+-Name\s+'shuffle_api_key'" -or
    $uploadText -match 'Write-Host[^\r\n]*\$apiKey') {
    throw 'The Shuffle SOC App bundle uploader violates its approval or secret contract.'
}
foreach ($path in @($buildPath,$uploadPath)) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,[ref]$tokens,[ref]$errors
    )
    if (@($errors).Count -ne 0) {
        throw "Parser errors in $path`: $(@($errors.Message) -join '; ')"
    }
}

Write-Host 'Shuffle SOC private App bundle static tests passed.'
