#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'automation\SocLab.Configuration.psm1') -Force

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-config-' + [guid]::NewGuid().ToString('N'))
try {
    $configuration = New-SocLabConfiguration `
        -ShuffleOrgId '11111111-1111-4111-8111-111111111111' `
        -ShuffleWorkflowId '22222222-2222-4222-8222-222222222222' `
        -ShuffleWebhookId '33333333-3333-4333-8333-333333333333'
    $path = Write-SocLabConfiguration -Configuration $configuration -Root $testRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'The SOC configuration was not persisted.'
    }
    $read = Read-SocLabConfiguration -Root $testRoot
    if ([string]$read.github_repository -cne 'Unoh03/Uns-DVWA' -or
        [string]$read.containment_workflow -cne 'soc-contain-dvwa.yml' -or
        [string]$read.shuffle_api_base -cne 'https://shuffler.io/') {
        throw 'The SOC configuration fixed target changed after round-trip.'
    }
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($forbidden in @('api_key','webhook_url','github_pat','credential','password')) {
        if ($text -match ('(?i)' + [regex]::Escape($forbidden))) {
            throw "The SOC configuration persisted a forbidden field: $forbidden"
        }
    }

    $regional = New-SocLabConfiguration `
        -ShuffleOrgId '11111111-1111-4111-8111-111111111111' `
        -ShuffleWorkflowId '22222222-2222-4222-8222-222222222222' `
        -ShuffleWebhookId '33333333-3333-4333-8333-333333333333' `
        -ShuffleApiBase 'https://frankfurt.shuffler.io/'
    if ([string]$regional.shuffle_api_base -cne 'https://frankfurt.shuffler.io/') {
        throw 'A valid regional Shuffle Cloud origin was not preserved.'
    }
    foreach ($unsafeBase in @(
        'https://shuffler.io/api/v1/',
        'https://shuffler.io:444/',
        'https://shuffler.io/?redirect=1',
        'https://shuffler.io.evil.example/'
    )) {
        try {
            [void](New-SocLabConfiguration `
                -ShuffleOrgId '11111111-1111-4111-8111-111111111111' `
                -ShuffleWorkflowId '22222222-2222-4222-8222-222222222222' `
                -ShuffleWebhookId '33333333-3333-4333-8333-333333333333' `
                -ShuffleApiBase $unsafeBase)
            throw "An unsafe Shuffle API origin was accepted: $unsafeBase"
        } catch {
            if ($_.Exception.Message -like 'An unsafe Shuffle API origin was accepted:*') {
                throw
            }
        }
    }
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab configuration tests passed.'
