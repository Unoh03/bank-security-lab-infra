#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Invoke-SocLabReset.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern='\[switch\]\$PrepareRetake[\s\S]*?RESET DVWA QUARANTINE[\s\S]*?prepare_retake=false';Message='Reset lacks the default quarantine-only release path.'},
    @{Pattern="ConfirmReset\s+-cne\s+'RESET SOC LAB TO LOW'";Message='Reset lacks exact outer confirmation.'},
    @{Pattern='resumableStatuses[\s\S]*?E2E_SUCCEEDED[\s\S]*?E2E_FAILED[\s\S]*?RESET_REQUESTED[\s\S]*?RESET_COMMITTED[\s\S]*?RESET_DEPLOYED[\s\S]*?CLOSED[\s\S]*?response_mode -cne ''contain''';Message='Reset does not limit recovery to an exact completed, failed, closed, or resumable containment TAKE.'},
    @{Pattern='reset-exclusive\.lock[\s\S]*?FileShare\]::None[\s\S]*?Another Reset process already owns';Message='Reset does not serialize one exact TAKE with an exclusive lock.'},
    @{Pattern='reset-status-journal\.json[\s\S]*?Repair-SocResetStatusJournal[\s\S]*?from_status[\s\S]*?target_status';Message='Reset does not journal and repair its two-file status transition.'},
    @{Pattern='Assert-SocEvidenceManifestEntries[\s\S]*?manifest\.json[\s\S]*?SHA256SUMS[\s\S]*?Get-FileHash';Message='Reset does not verify prior E2E Evidence hashes before trusting checkpoints.'},
    @{Pattern='03-shuffle-executions\.json[\s\S]*?dispatched_alert_body_sha256[\s\S]*?dispatched_workflow_run_id';Message='Reset is not bound to the exact Shuffle dispatch Alert hash and GitHub Run ID.'},
    @{Pattern='Get-SocGitHubWorkflowRun[\s\S]*?ExpectedRunId \$dispatchRunId[\s\S]*?Get-SocGitHubTransitionArtifact[\s\S]*?ExpectedAlertBodySha256 \$dispatchBodySha256';Message='Failed-E2E recovery does not re-prove the exact GitHub transition.'},
    @{Pattern='storedContainment[\s\S]*?remoteContainment[\s\S]*?Assert-SocTransitionMatches';Message='Reset does not compare stored containment Evidence with the live GitHub Artifact.'},
    @{Pattern='github_remote_main_sha[\s\S]*?Get-SocGitHubRemoteMainSha[\s\S]*?reset dispatch is refused';Message='Reset does not fail closed on GitHub main drift before dispatch.'},
    @{Pattern="gh workflow run[\s\S]*?reset_workflow[\s\S]*?--ref[\s\S]*?confirm=RESET DVWA TO LOW[\s\S]*?prepare_retake=true";Message='Reset does not dispatch only the fixed manual retake Workflow.'},
    @{Pattern='reset-dispatch-intent\.json[\s\S]*?automatic_redispatch_allowed=\$false[\s\S]*?currentStatus -ceq ''RESET_REQUESTED''[\s\S]*?Wait-SocGitHubWorkflowRun';Message='Reset does not checkpoint and resume the existing dispatch without automatic redispatch.'},
    @{Pattern="ConfirmRetryUndispatched[\s\S]*?RETRY UNDISPATCHED RESET[\s\S]*?Get-SocGitHubWorkflowRun";Message='An ambiguous undispatched Reset cannot be retried through an explicit fail-closed recovery path.'},
    @{Pattern='Wait-SocGitHubWorkflowRun[\s\S]*?Get-SocGitHubTransitionArtifact[\s\S]*?Operation reset[\s\S]*?RequireChange';Message='Reset does not validate its unique Run and transition Artifact.'},
    @{Pattern='remoteResetRun[\s\S]*?ExpectedRunId[\s\S]*?remoteResetTransition[\s\S]*?Assert-SocTransitionMatches';Message='Reset resume does not re-read the exact live GitHub Run and Artifact.'},
    @{Pattern='Wait-SocArgoDeployment[\s\S]*?ExpectedSecurityLevel low[\s\S]*?RequireReplacement';Message='Reset does not require the exact low Argo rollout and new Pod.'},
    @{Pattern='temporary_credential_environment_cleared -ne \$true[\s\S]*?Assert-SocNoProcessCredentialEnvironment';Message='Reset does not bind the TAKE to cleared attack credentials and reject a contaminated reset process.'},
    @{Pattern='describe-alarm-history[\s\S]*?new_state -ceq ''ALARM''[\s\S]*?new_state -ceq ''OK''[\s\S]*?StateValue -ceq ''OK''';Message='Reset does not prove this TAKE alarm transitioned to ALARM and naturally recovered to OK.'},
    @{Pattern='describe-alarm-history[\s\S]*?--scan-by'',''TimestampAscending''[\s\S]*?--max-items'',''100''';Message='Reset does not use the supported bounded alarm-history pagination contract.'},
    @{Pattern='Get-SocCapitalOneDetectionContract[\s\S]*?Wait-SocCapitalOneAlarmCycleReady[\s\S]*?reset-retake-ready\.json';Message='Reset does not record the detector-bound retake readiness gate.'},
    @{Pattern='Remove-SocQuarantinedPodsForRetake[\s\S]*?soc\.unoh\.click/state=quarantined[\s\S]*?metadata\.uid[\s\S]*?kubectl -n dvwa delete pod[\s\S]*?reset-quarantine-removed\.json';Message='Retake reset does not remove only UID-verified orphaned quarantine Pods.'},
    @{Pattern='Assert-FreshDvWaLow[\s\S]*?reset-retake-readiness[\s\S]*?Remove-ShuffleSocTake[\s\S]*?09-reset\.json[\s\S]*?Status CLOSED';Message='Reset does not verify low and retake readiness, close the allow key, record Evidence, and close the TAKE.'},
    @{Pattern='reset-allow-removed\.json[\s\S]*?shuffle_allow_removed=\$true[\s\S]*?automatic_redispatch_used=\$false';Message='Reset does not make allow removal and final recovery Evidence resumable.'},
    @{Pattern='Get-ChildItem\s+-LiteralPath\s+\$scopePath\s+-File\s+-Recurse[\s\S]*?scope=''entire-take-directory''[\s\S]*?Find-SocSecretExposure\s+-Path\s+@\(\$takeDirectory\)';Message='Reset does not refresh and scan the entire TAKE Evidence tree.'},
    @{Pattern='manifest\.json[\s\S]*?SHA256SUMS';Message='Reset does not refresh the final Evidence hashes.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'daily-down\.ps1|DESTROY DAILY|git\s+push\s+--force|git\s+reset\s+--hard|cloudwatch\s+set-alarm-state') {
    throw 'Reset contains a forbidden destroy or history-rewrite path.'
}
$tokens=$null;$errors=$null
$ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw ('SOC Reset parser errors: ' + (@($errors.Message) -join '; ')) }

$functionNames = @(
    'ConvertTo-SocResetUtcDateTimeOffset',
    'Get-SocCapitalOneAlarmStateHistory',
    'Wait-SocCapitalOneAlarmCycleReady'
)
$definitions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in $functionNames
},$true))
if ($definitions.Count -ne $functionNames.Count) {
    throw 'The Reset alarm functions could not be isolated for behavioral tests.'
}
foreach ($definition in $definitions) { Invoke-Expression $definition.Extent.Text }

$jsonTimestamp = ('{"timestamp":"2026-08-18T01:02:05.0000000+00:00"}' |
    ConvertFrom-Json).timestamp
$normalizedTimestamp = ConvertTo-SocResetUtcDateTimeOffset -Value $jsonTimestamp `
    -Label 'fixture timestamp'
if ($normalizedTimestamp.ToString('o') -cne '2026-08-18T01:02:05.0000000+00:00') {
    throw 'The Reset timestamp normalizer changed the UTC instant after ConvertFrom-Json.'
}

$historyAlarm = @{newState=@{stateValue='ALARM'}} | ConvertTo-Json -Compress -Depth 5
$historyOk = @{newState=@{stateValue='OK'}} | ConvertTo-Json -Compress -Depth 5
$script:alarmHistoryFixture = @{
    AlarmHistoryItems=@(
        @{Timestamp='2026-08-18T01:02:05Z';HistoryData=$historyAlarm},
        @{Timestamp='2026-08-18T01:03:05Z';HistoryData=$historyOk}
    )
} | ConvertTo-Json -Compress -Depth 8
$region = 'ap-northeast-2'
function Invoke-SocResetNativeCapture { return $script:alarmHistoryFixture }
$history = @(Get-SocCapitalOneAlarmStateHistory -AwsProfile test -AlarmName test-alarm `
    -NotBeforeUtc ([datetimeoffset]'2026-08-18T01:02:00Z'))
if ($history.Count -ne 2 -or $history[0].new_state -cne 'ALARM' -or
    $history[1].new_state -cne 'OK') {
    throw 'The Reset alarm-history parser did not preserve the ALARM-to-OK cycle.'
}

function Get-SocCapitalOneAlarmSnapshot {
    return [pscustomobject]@{
        ActionsEnabled=$true;AlarmActions=@('arn:aws:sns:ap-northeast-2:111111111111:test');
        StateValue='OK';StateUpdatedTimestamp='2026-08-18T01:03:05Z'
    }
}
function Get-SocCapitalOneAlarmStateHistory {
    return @(
        [pscustomobject]@{timestamp_utc=[datetimeoffset]'2026-08-18T01:02:05Z';new_state='ALARM'},
        [pscustomobject]@{timestamp_utc=[datetimeoffset]'2026-08-18T01:03:05Z';new_state='OK'}
    )
}
$AlarmCycleTimeoutSeconds = 60
$cycle = Wait-SocCapitalOneAlarmCycleReady -AwsProfile test -AlarmName test-alarm `
    -AttackStartedAtUtc ([datetimeoffset]'2026-08-18T01:02:00Z')
if (-not [bool]$cycle.take_alarm_cycle_verified -or [string]$cycle.alarm_state -cne 'OK') {
    throw 'The Reset alarm-cycle gate did not accept a bound ALARM-to-OK fixture.'
}
Write-Host 'SOC lab manual Reset static tests passed.'
