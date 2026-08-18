#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Invoke-SocRule100103ThreeTakeRehearsal.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmRun\s+-cne\s+'RUN RULE 100103 THREE TAKE REHEARSAL'";Message='Three-TAKE rehearsal lacks exact confirmation.'},
    @{Pattern='for \(\$iteration = 1; \$iteration -le 3; \$iteration\+\+\)[\s\S]*?Start-SocLab\.ps1[\s\S]*?-ResponseMode observe_only[\s\S]*?Test-SocRule100103Rehearsal\.ps1[\s\S]*?Stop-SocLab\.ps1';Message='Three-TAKE rehearsal does not isolate Start, test, and Stop across three sessions.'},
    @{Pattern='attack_event_count -ne 2[\s\S]*?rule_100103_alert_count -ne 2[\s\S]*?normal_rule_100103_count -ne 0[\s\S]*?shuffle_observe_only_count -ne 2[\s\S]*?github_containment_run_count -ne 0';Message='Three-TAKE rehearsal lacks the exact per-TAKE cardinality checks.'},
    @{Pattern='unique_take_count=3[\s\S]*?source_event_count=6[\s\S]*?rule_100103_alert_count=6[\s\S]*?normal_rule_100103_count=0[\s\S]*?shuffle_observe_only_count=6';Message='Three-TAKE rehearsal lacks the exact aggregate Evidence.'},
    @{Pattern='Find-SocSecretExposure[\s\S]*?SHA256SUMS[\s\S]*?GATE_B4_SUCCEEDED=yes';Message='Three-TAKE rehearsal can succeed before secret and hash verification.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'daily-(up|down)\.ps1|terraform\s+(apply|destroy)|gh\s+workflow\s+run') {
    throw 'The Gate B4 wrapper contains a forbidden infrastructure or GitHub mutation.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw ('Three-TAKE parser errors: ' + (@($errors.Message) -join '; ')) }
Write-Host 'SOC Rule 100103 three-TAKE orchestration static tests passed.'
