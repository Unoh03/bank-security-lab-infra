#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Invoke-SocLabReset.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern='\[switch\]\$PrepareRetake';Message='Reset lacks the recording-retake mode.'},
    @{Pattern="ConfirmReset\s+-cne\s+'RESET SOC LAB TO LOW'";Message='Retake Reset lacks exact confirmation.'},
    @{Pattern="ConfirmReset\s+-cne\s+'RESET DVWA QUARANTINE'";Message='Quarantine release lacks exact confirmation.'},
    @{Pattern="gh workflow run 'soc-reset-dvwa\.yml'[\s\S]*?-R 'Unoh03/Uns-DVWA'[\s\S]*?--ref 'main'";Message='Reset does not use the fixed GitHub Workflow target.'},
    @{Pattern='prepare_retake=\$prepareValue[\s\S]*?Wait-SocGitHubWorkflowRun[\s\S]*?Get-SocGitHubTransitionArtifact';Message='Reset does not wait for and validate its exact Workflow result.'},
    @{Pattern="expectedMode[\s\S]*?'prepare_retake'[\s\S]*?'release_quarantine'[\s\S]*?expectedLevel[\s\S]*?'low'[\s\S]*?'unchanged'";Message='Reset does not distinguish its two fixed result contracts.'},
    @{Pattern='Wait-SocArgoDeployment[\s\S]*?ExpectedSecurityLevel low';Message='Retake Reset does not verify the exact low Argo deployment.'},
    @{Pattern='Remove-SocQuarantinedPodsForRetake[\s\S]*?soc\.unoh\.click/state=quarantined[\s\S]*?metadata\.uid[\s\S]*?kubectl -n dvwa delete pod';Message='Retake Reset does not UID-verify quarantine Pod removal.'},
    @{Pattern='Assert-FreshDvWaLow[\s\S]*?user_token[\s\S]*?vulnerabilities/exec/[\s\S]*?security';Message='Retake Reset does not verify a fresh low DVWA session.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}

if ($text -match 'active-soc-session|Read-SocTakeRecord|Set-SocTakeStatus|Shuffle|describe-alarm-history|manifest\.json|SHA256SUMS') {
    throw 'Reset still contains a legacy SOC session, Shuffle, alarm-cycle, or Evidence-finalization dependency.'
}
if ($text -match 'daily-down\.ps1|DESTROY DAILY|git\s+push\s+--force|git\s+reset\s+--hard|terraform\s+(apply|destroy)') {
    throw 'Reset contains a forbidden infrastructure or history-rewrite path.'
}

$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('SOC Reset parser errors: ' + (@($errors.Message) -join '; '))
}

Write-Host 'SOC lab current Reset static tests passed.'
