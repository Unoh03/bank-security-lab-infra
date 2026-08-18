#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Test-SocRule100103Rehearsal.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmRun\s+-cne\s+'RUN RULE 100103 REHEARSAL'";Message='Rehearsal lacks exact attack confirmation.'},
    @{Pattern="response_mode -cne 'observe_only'[\s\S]*?status -cne 'READY'";Message='Rehearsal does not require a READY observe-only TAKE.'},
    @{Pattern='Invoke-CapitalOneBaseline\.ps1[\s\S]*?-SkipAlarmWait -RequireSocReadyTake[\s\S]*?Wait-SocWazuhRule100103';Message='Rehearsal does not run one bound Baseline and verify its two alerts.'},
    @{Pattern="Target '127\.0\.0\.1'[\s\S]*?resource -ceq 'other'[\s\S]*?normal_rule_100103_count=0";Message='Rehearsal does not prove an ordinary numeric control reaches Bridge without Rule 100103.'},
    @{Pattern='ValidateRange\(120,300\).*?DetectionTimeoutSeconds[\s\S]*?normal-negative-window[\s\S]*?normalEvent\.event_id[\s\S]*?normalEvent\.raw_message_sha256[\s\S]*?normal_negative_observation_seconds';Message='Rehearsal can declare a normal-control negative before the full Rule 100103 latency window.'},
    @{Pattern='Compare-Object[\s\S]*?source_to_alert_event_id_match=\$true';Message='Rehearsal does not correlate the two source and alert event IDs.'},
    @{Pattern='Wait-ShuffleSocObserveOnlyOutcomes[\s\S]*?Assert-SocNoGitHubWorkflowRun';Message='Rehearsal does not prove observe-only Shuffle outcomes and zero GitHub response.'},
    @{Pattern='credential_value_persisted=\$false[\s\S]*?response_body_persisted=\$false';Message='Rehearsal Evidence lacks its credential and response-body boundary.'},
    @{Pattern='Find-SocSecretExposure[\s\S]*?RULE_100103_REHEARSAL_SUCCEEDED=yes';Message='Rehearsal can succeed before its Evidence secret scan.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'gh\s+workflow\s+run|--method["'']?\s*,?["'']?(POST|PUT|PATCH|DELETE)|terraform\s+(apply|destroy)') {
    throw 'The observe-only rehearsal contains a forbidden GitHub or Terraform mutation.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw ('Rehearsal parser errors: ' + (@($errors.Message) -join '; ')) }
Write-Host 'SOC Rule 100103 per-TAKE rehearsal static tests passed.'
