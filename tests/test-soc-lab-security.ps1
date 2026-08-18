#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'automation\SocLab.Security.psm1'
$scannerPath = Join-Path $root 'tools\Test-SocSecretExposure.ps1'
$initializePath = Join-Path $root 'tools\Initialize-SocLabSecrets.ps1'
$externalSecretPath = Join-Path $root 'tools\Set-SocLabExternalSecret.ps1'
Import-Module $modulePath -Force

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-security-' + [guid]::NewGuid().ToString('N'))
$secretRoot = Join-Path $testRoot 'secrets'
$runtimeRoot = Join-Path $testRoot 'runtime'
$scanRoot = Join-Path $testRoot 'scan'
$dummySecret = 'DummyOnly-A9.*' + [guid]::NewGuid().ToString('N')

try {
    foreach ($scriptPath in @($scannerPath, $initializePath, $externalSecretPath)) {
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "PowerShell parser rejected $scriptPath`: $($errors[0].Message)"
        }
    }
    $scannerText = Get-Content -LiteralPath $scannerPath -Raw
    if ($scannerText -notmatch '__pycache__' -or
        $scannerText -notmatch '\\.pytest_cache' -or
        $scannerText -notmatch 'pyc\|pyo') {
        throw 'The Git changed-file secret scan does not exclude generated Python caches.'
    }

    $secretPath = Protect-SocSecret -Name 'dummy_test' -PlainText $dummySecret -SecretRoot $secretRoot
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
        throw 'The DPAPI test did not create a protected record.'
    }
    if ((Get-Content -LiteralPath $secretPath -Raw).Contains($dummySecret)) {
        throw 'The protected record contains the plaintext test secret.'
    }
    if ((Unprotect-SocSecret -Name 'dummy_test' -SecretRoot $secretRoot) -cne $dummySecret) {
        throw 'The DPAPI test did not recover the original value.'
    }

    $acl = Get-Acl -LiteralPath $secretRoot
    if (-not $acl.AreAccessRulesProtected) {
        throw 'The protected secret directory still inherits access rules.'
    }

    $generated = New-SocStrongSecret -Length 32
    if ($generated.Length -ne 32 -or
        $generated -cnotmatch '[A-Z]' -or
        $generated -cnotmatch '[a-z]' -or
        $generated -notmatch '[0-9]' -or
        $generated -notmatch '[.*+?\-]') {
        throw 'The strong-secret generator did not satisfy the Wazuh password contract.'
    }

    $takeId = New-SocTakeId -Now ([datetimeoffset]'2026-08-18T00:00:00Z')
    if ($takeId -notmatch '^capital-one-20260818T000000Z-[0-9a-f]{8}$') {
        throw 'The TAKE_ID generator violated the frozen format.'
    }

    $runtimePath = Write-SocRuntimeSecretFile `
        -SessionId 'test-session' `
        -RelativePath 'nested\runtime.env' `
        -Content $dummySecret `
        -RuntimeRoot $runtimeRoot
    if ((Get-Content -LiteralPath $runtimePath -Raw) -cne $dummySecret) {
        throw 'The runtime secret file was not written exactly.'
    }
    Remove-SocRuntimeSession -SessionId 'test-session' -RuntimeRoot $runtimeRoot
    if (Test-Path -LiteralPath (Join-Path $runtimeRoot 'test-session')) {
        throw 'The runtime secret session was not removed.'
    }

    New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
    $cleanPath = Join-Path $scanRoot 'clean.json'
    [IO.File]::WriteAllText($cleanPath, '{"status":"sanitized"}', [Text.UTF8Encoding]::new($false))
    if (@(Find-SocSecretExposure -Path $cleanPath).Count -ne 0) {
        throw 'The SOC secret scanner rejected a clean fixture.'
    }

    $leakPath = Join-Path $scanRoot 'leak.txt'
    $fakeAwsKey = 'AKIA' + ('A' * 16)
    [IO.File]::WriteAllText($leakPath, $fakeAwsKey, [Text.UTF8Encoding]::new($false))
    $findings = @(Find-SocSecretExposure -Path $leakPath)
    if ($findings.Count -ne 1 -or [string]$findings[0].Rule -cne 'AwsAccessKey') {
        throw 'The SOC secret scanner did not find the synthetic AWS key fixture.'
    }

    & $scannerPath -Path $cleanPath
    if ($LASTEXITCODE -ne 0) {
        throw 'The command-level SOC secret scanner rejected a clean fixture.'
    }

    $previewFailedClosed = $false
    try {
        & $initializePath -SecretRoot (Join-Path $testRoot 'preview-secrets')
    } catch {
        $previewFailedClosed = $_.Exception.Message -match 'Preview only'
    }
    if (-not $previewFailedClosed -or
        (Test-Path -LiteralPath (Join-Path $testRoot 'preview-secrets'))) {
        throw 'SOC secret initialization did not fail closed in preview mode.'
    }
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab security tests passed.'
