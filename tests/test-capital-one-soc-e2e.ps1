#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Invoke-CapitalOneSocE2E.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmRun\s+-cne\s+'RUN CAPITAL ONE SOC E2E'";Message='E2E lacks exact real-run confirmation.'},
    @{Pattern="response_mode -cne 'contain'[\s\S]*?status -cne 'READY'";Message='E2E does not require one READY containment TAKE.'},
    @{Pattern='requiredRemainingSeconds[\s\S]*?WazuhTimeoutSeconds[\s\S]*?ShuffleTimeoutSeconds[\s\S]*?GitHubTimeoutSeconds[\s\S]*?ArgoTimeoutSeconds[\s\S]*?600[\s\S]*?daily_hard_deadline_at_utc';Message='E2E does not reserve its configured timeout budget and safety margin.'},
    @{Pattern='Invoke-CapitalOneBaseline\.ps1[\s\S]*?-RequireSocReadyTake[\s\S]*?RUN CAPITAL ONE BASELINE';Message='E2E does not bind the real attack to the READY TAKE.'},
    @{Pattern='TemporaryCredentialEnvironmentCleared -ne \$true[\s\S]*?temporary_credential_environment_cleared=\$true';Message='E2E does not require and preserve proof that temporary AWS credential variables were cleared.'},
    @{Pattern='Wait-SocWazuhRule100103[\s\S]*?02-wazuh-alerts\.json';Message='E2E does not require exact Rule 100103 Evidence.'},
    @{Pattern='Wait-ShuffleSocContainmentOutcomes[\s\S]*?03-shuffle-executions\.json[\s\S]*?github_dispatch_count';Message='E2E does not require one Shuffle dispatch and one suppression.'},
    @{Pattern='RESPONSE_DISPATCHED[\s\S]*?dispatchedBodySha256[\s\S]*?dispatchedRunId[\s\S]*?Wait-SocGitHubWorkflowRun[\s\S]*?-ExpectedRunId \$dispatchedRunId[\s\S]*?Get-SocGitHubTransitionArtifact[\s\S]*?-ExpectedAlertBodySha256 \$dispatchedBodySha256[\s\S]*?Get-SocGitHubRemoteMainSha';Message='E2E does not bind the dispatched Shuffle body hash and Run ID to the GitHub Artifact and main SHA.'},
    @{Pattern='Wait-SocArgoDeployment[\s\S]*?-RequireReplacement[\s\S]*?06-argocd-deploy\.json';Message='E2E does not require the exact Argo revision and new Pod.'},
    @{Pattern='Test-CapitalOneContainment\.ps1[\s\S]*?-RequireSocDeployedTake[\s\S]*?REATTACK_BLOCKED';Message='E2E does not bind reattack validation to DEPLOYED.'},
    @{Pattern='PostContainmentObservationSeconds[\s\S]*?Test-CapitalOneContainment\.ps1[\s\S]*?-PostContainmentObservationSeconds';Message='E2E timeout budgeting does not include the negative observation window.'},
    @{Pattern='Get-ChildItem\s+-LiteralPath\s+\$scopePath\s+-File\s+-Recurse[\s\S]*?GetRelativePath[\s\S]*?scope=''entire-take-directory''';Message='E2E manifest does not recursively cover the entire TAKE Evidence tree.'},
    @{Pattern='Find-SocSecretExposure\s+-Path\s+@\(\$takeDirectory\)[\s\S]*?E2E_SUCCEEDED';Message='E2E can succeed before the entire TAKE Evidence secret scan.'},
    @{Pattern='manifest\.json[\s\S]*?SHA256SUMS';Message='E2E lacks a hashed Evidence manifest.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'daily-down\.ps1|DESTROY DAILY|&\s*terraform\s+(apply|destroy)|Invoke-[A-Za-z]+[^\r\n]*terraform[^\r\n]*(apply|destroy)') {
    throw 'The E2E runner contains an implicit Terraform mutation or destroy path.'
}
if ($text -match 'Write-(Host|Output).*?(adminPassword|shuffleApiKey|credential|cookie|payload)') {
    throw 'The E2E runner can print a protected value.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('SOC E2E parser errors: ' + (@($errors.Message) -join '; '))
}
Write-Host 'Capital One closed SOC E2E static tests passed.'
