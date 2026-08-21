#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildPath = Join-Path $root 'tools\Build-ShuffleSocValidatorApp.ps1'
$uploadPath = Join-Path $root 'tools\Install-ShuffleSocValidatorApp.ps1'
$packageHelperPath = Join-Path $root 'tools\ShuffleSocValidatorPackage.ps1'
$canonicalUploadPath = Join-Path $root 'tools\Install-ShuffleSocAppBundle.ps1'
$canonicalTestPath = Join-Path $root 'tests\test-shuffle-soc-app-bundle.ps1'
$buildText = Get-Content -LiteralPath $buildPath -Raw
$uploadText = Get-Content -LiteralPath $uploadPath -Raw
$packageHelperText = Get-Content -LiteralPath $packageHelperPath -Raw
$canonicalUploadText = Get-Content -LiteralPath $canonicalUploadPath -Raw
$canonicalTestText = Get-Content -LiteralPath $canonicalTestPath -Raw

if ($buildText -notmatch "ConfirmBuild\s+-cne\s+'BUILD SHUFFLE VALIDATOR'" -or
    $buildText -notmatch 'Build-ShuffleSocAppBundle\.ps1' -or
    $buildText -notmatch "ConfirmBuild 'BUILD SHUFFLE SOC APPS'" -or
    $buildText -notmatch "'Dockerfile','api.yaml','requirements.txt','src/app.py'" -or
    $buildText -match 'src/validator\.py') {
    throw 'The Shuffle Validator compatibility builder does not delegate to the canonical four-file bundle path.'
}
if ($uploadText -notmatch "ConfirmUpload\s+-cne\s+'UPLOAD SHUFFLE VALIDATOR'" -or
    $uploadText -notmatch 'Install-ShuffleSocAppBundle\.ps1' -or
    $uploadText -notmatch "ConfirmUpload='UPLOAD SHUFFLE SOC APPS'" -or
    $uploadText -notmatch 'ShuffleSocValidatorPackage\.ps1' -or
    $uploadText -notmatch 'Assert-SocShuffleValidatorPackageSnapshot' -or
    $uploadText -notmatch '\[IO\.File\]::ReadAllBytes\(' -or
    $uploadText -notmatch "'Dockerfile','api.yaml','requirements.txt','src/app.py'" -or
    $uploadText -notmatch 'UploadTimeoutSeconds=\$UploadTimeoutSeconds' -or
    $uploadText -notmatch 'PollIntervalSeconds=\$PollIntervalSeconds' -or
    $uploadText -notmatch '\$canonicalArguments\.ConsoleOnly' -or
    $uploadText -notmatch 'finally\s*\{' -or
    $uploadText -notmatch 'Remove-Item\s+-LiteralPath\s+\$cleanupTarget' -or
    $uploadText -match 'src/validator\.py' -or
    $uploadText -match 'HttpClient|/api/v1/apps/upload|Unprotect-SocSecret|Invoke-ShuffleApiRequest|Invoke-SocShuffleAppUploadTransaction|\[bool\][^\r\n]*result\.success') {
    throw 'The Shuffle Validator compatibility uploader does not delegate exclusively to the canonical async transaction.'
}
if ($canonicalUploadText -notmatch 'Invoke-SocShuffleAppUploadTransaction' -or
    $canonicalUploadText -notmatch 'confirmed_async_502' -or
    $canonicalUploadText -notmatch 'Test-SocShuffleUploadExactBoolean' -or
    $canonicalUploadText -notmatch 'Assert-SocShuffleValidatorPackageSnapshot' -or
    $canonicalUploadText -notmatch 'PackageBytes' -or
    $canonicalUploadText -notmatch 'ByteArrayContent' -or
    ([regex]::Matches(
        $canonicalUploadText,
        '\[IO\.File\]::ReadAllBytes\(\$packagePath\)'
    ).Count -ne 1) -or
    $canonicalUploadText -match '\[IO\.File\]::OpenRead\(|Net\.Http\.StreamContent' -or
    $canonicalTestText -notmatch 'HTTP 502 delayed-success fixture' -or
    $canonicalTestText -notmatch 'strict Boolean' -or
    $canonicalTestText -notmatch 'verified upload snapshot') {
    throw 'The delegated canonical installer lacks its async or immutable snapshot contract.'
}
if ($packageHelperText -notmatch '(?m)^function\s+New-SocShuffleValidatorPackagedApp\b' -or
    $packageHelperText -notmatch '(?m)^function\s+New-SocShuffleValidatorExpectedPackage\b' -or
    $packageHelperText -notmatch '(?m)^function\s+Assert-SocShuffleValidatorPackageSnapshot\b' -or
    $packageHelperText -match '\.CopyTo\(|ReadToEnd\(') {
    throw 'The compatibility path does not share the deterministic Validator package helper.'
}
foreach ($path in @($buildPath,$uploadPath,$packageHelperPath,$canonicalUploadPath)) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,[ref]$tokens,[ref]$errors
    )
    if (@($errors).Count -ne 0) {
        throw "Parser errors in $path`: $(@($errors.Message) -join '; ')"
    }
}

Write-Host 'Shuffle SOC Validator package and upload static tests passed.'
