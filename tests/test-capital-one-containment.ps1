#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Test-CapitalOneContainment.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmRun\s+-cne\s+'TEST CAPITAL ONE CONTAINMENT'";Message='Containment test lacks exact confirmation.'},
    @{Pattern='\[switch\]\$RequireSocDeployedTake[\s\S]*?active-soc-session\.json[\s\S]*?activeSession\.status -cne ''DEPLOYED''[\s\S]*?activeSession\.response_mode -cne ''contain''[\s\S]*?Read-SocTakeRecord[\s\S]*?activeTake\.status -cne ''DEPLOYED''[\s\S]*?activeTake\.response_mode -cne ''contain''';Message='Containment test can run without the active DEPLOYED containment TAKE binding.'},
    @{Pattern='securityLevel -cne ''impossible''';Message='Containment test does not require a fresh impossible session.'},
    @{Pattern='169\.254\.169\.254/latest/meta-data/iam/security-credentials/';Message='Containment test does not retry the same IMDS discovery target.'},
    @{Pattern='user_token=\$execToken';Message='Containment test could confuse CSRF rejection with containment.'},
    @{Pattern='invalid IP[\s\S]*?startMarker[\s\S]*?karpenter-node';Message='Containment test does not prove command output and role data are absent.'},
    @{Pattern='/index\.php[\s\S]*?/vulnerabilities/sqli/[\s\S]*?Headers\s+@\{''X-SOC-TAKE-ID''=\$TakeId\}[\s\S]*?ip=''127\.0\.0\.1''[\s\S]*?numeric_ip_ping';Message='Containment test lacks a TAKE-bound login, page, and numeric-IP Ping control.'},
    @{Pattern='PostContainmentObservationSeconds\s*=\s*120[\s\S]*?Get-SocWazuhRuleAlerts[\s\S]*?additional_detection';Message='Containment test lacks the bounded post-reattack Wazuh negative observation.'},
    @{Pattern='Get-ShuffleSocOutcome[\s\S]*?additionalShuffleOutcome[\s\S]*?additional_shuffle_outcome';Message='Containment test does not prove that Shuffle outcome state remained unchanged.'},
    @{Pattern='Get-SocGitHubWorkflowRun[\s\S]*?additionalGitHubDispatch[\s\S]*?additional_github_dispatch';Message='Containment test does not prove that the GitHub response run remained singular.'},
    @{Pattern='01-attack\.json[\s\S]*?02-wazuh-alerts\.json[\s\S]*?03-shuffle-executions\.json[\s\S]*?04-github-run\.json';Message='Containment negative observation is not bound to the preceding incident Evidence.'},
    @{Pattern='07-reattack\.json[\s\S]*?08-normal-function\.json';Message='Containment test lacks the frozen Evidence files.'},
    @{Pattern='credential_value_observed=\$false[\s\S]*?response_body_persisted=\$false';Message='Containment Evidence does not state its secret and body boundary.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'Write-(Host|Output).*?(payload|response|cookie|credential)') {
    throw 'Containment test can print a sensitive attack value or response.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('Containment test parser errors: ' + (@($errors.Message) -join '; '))
}
Write-Host 'Capital One containment static tests passed.'
