#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$adapterPath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneGt02Gt03Live.ps1'
$runnerPath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneGt02Gt03Runtime.ps1'
if (-not (Test-Path -LiteralPath $adapterPath -PathType Leaf)) { throw 'GT02/GT03 live adapter is missing.' }

$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($adapterPath, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw ('GT02/GT03 live adapter parser errors: ' + (@($errors.Message) -join '; ')) }
$text = Get-Content -LiteralPath $adapterPath -Raw -Encoding UTF8

foreach ($required in @(
    'Invoke-CapitalOneGt02Gt03Runtime','live-adapter-fixed','missing_provider',
    'wazuh_indexer_admin_password','logs','start-query','get-query-results',
    'wazuh-push-live.jsonl','normal_operator','other_bucket','other_prefix',
    'other_principal','failure','meta-data/iam','get-caller-identity','s3api',
    'AWS_ACCESS_KEY_ID','heartbeat_at_utc','queue_not_visible',
    'scroll','_doc','stable_polls','RunObservationBudgetSeconds','RunDeadlineUtc',
    'kubectl','networkpolicy','deployment','capital_one_secondary_control_bucket_name',
    'capital_one_secondary_control_region','capital_one_secondary_control_object_key',
    'capital_one_secondary_control_object_sha256','capital_one_negative_control_role_arn',
    'capital_one_other_prefix_control_object_key','capital_one_other_prefix_control_object_sha256',
    'capital-one-validation-read','security_log_group_names','AdvancedEventSelectors',
    'CAPITAL-ONE-SOC-CONTAINMENT-v1','CAPITAL-ONE-SOC-CONTAINMENT-v2',
    'pagination_cap','quiescence_proven','wazuh_query_incomplete',
    'Resolve-GtLiveOtherPrincipalRoleArn','terraform_managed_role',
    'run_observation_budget_exhausted','StolenCredentials','StolenPrincipalArn','assume-role','AssumedRoleUser.Arn','expectedAssumedArn',
    'Assert-GtLiveSessionBudget','session_safety_margin_seconds','--if-match',
    'gt03_shuffle_integration_active','Assert-GtLiveShuffleIntegrationInactive',
    'ConvertTo-GtLiveCanonicalJson','Restore-GtLiveAwsEnvironment'
)) {
    if ($text -notmatch [regex]::Escape($required)) { throw "Live adapter is missing contract marker: $required" }
}

$paramBlock = ([regex]::Match($text, '(?ms)^param\((.*?)\)')).Groups[1].Value
if ($paramBlock -match '(?i)scriptblock|provider|provenance|ExpectedTakeIds') {
    throw 'Live adapter exposes a caller-controlled provider/provenance or TAKE set.'
}
$removedPrincipalParameter='OtherPrincipal'+'Profile'
$removedDrOutput='dr_application_bucket_'+'name'
$removedRepeatParameter='Negative'+'Repeats'
if ($paramBlock -match $removedPrincipalParameter -or $text -match "configure','list-profiles" -or
    $text -match $removedDrOutput -or $text -match $removedRepeatParameter) {
    throw 'Live adapter still discovers an arbitrary principal/bucket or uses the obsolete uniform repeat contract.'
}
if ($text -match '(?i)WriteAllText|Set-Content|Add-Content|Out-File|Write-SocAtomicJson|Write-G4AtomicJson') {
    throw 'Live adapter contains a durable evidence writer.'
}
if ($text -match '(?i)Invoke-RestMethod|Invoke-WebRequest.*hooks|Shuffle.*POST|github.*dispatch|git\s+push|Remove-Item.*-Recurse') {
    throw 'GT02/GT03 live adapter contains an out-of-scope response write.'
}
if ($text -match 'cloudtrail["'']?\s*,?\s*["'']lookup-events') {
    throw 'Live adapter uses the management-event lookup API instead of S3 data-event logs.'
}
if ($text -match 'X-SOC-TAKE-ID|New-SocTakeRecord|Write-SocTakeRecord|Set-SocTakeStatus|Read-SocTakeRecord|active-take') {
    throw 'Live adapter mutates or injects the frozen SocLab active TAKE contract.'
}
if ($text -match 'printf\s+gt-attack') { throw 'Live adapter still sends the dummy gt-attack command.' }
if ($text -match 'Math\]::Min\([^\r\n]*Max\(1') { throw 'CloudTrail polling can collapse to a one-second timeout.' }
if ($text -notmatch "poll\.status\s+-ceq\s+'Complete'") {
    throw 'CloudTrail polling does not require a Complete query result.'
}
if ($text -notmatch "poll\.status\s+-in\s+@\('Failed','Cancelled','Timeout'\)") {
    throw 'CloudTrail terminal failures are not fail-closed.'
}
if ($text -match "sort=@\(@\{'@timestamp'=@\{order='asc'\}\},@\{'_id'=@\{order='asc'\}\}\)") {
    throw 'Wazuh pagination still relies on the unsupported _id sort tiebreaker.'
}
if ($text -notmatch "sort=@\('_doc'\)|scroll=1m") { throw 'Wazuh pagination does not use a bounded scroll context.' }
if ($text -notmatch 'pagination_cap' -or $text -notmatch 'HttpMethod\]::Delete') { throw 'Wazuh scroll pagination cap/clear is not detected.' }
if ($text -notmatch 'Invoke-GtLivePreflight[\s\S]*?Invoke-CapitalOneGt02Gt03Runtime') {
    throw 'Full read-only preflight is not before the runtime engine.'
}
if ($text -notmatch 'Assert-GtLiveNegativeFixtures[\s\S]*?Get-GtLiveBaseline') {
    throw 'Negative fixtures and all query-provider baseline checks are not pre-attack.'
}
if ($text -notmatch 'Assert-GtLiveSessionBudget[^\r\n]*-MaxRunSeconds\s+\$RunObservationBudgetSeconds') {
    throw 'The requested max run budget is not checked against verified session remaining time.'
}
if ($text -notmatch 'quarantine:sha256|capital-one-validation-read:sha256') {
    throw 'Side-effect fingerprints are not distinct canonical hashes.'
}
if ($text -match 'state:\s*\+\s*\$blobSha|k8s:networkpolicy:') {
    throw 'Side-effect snapshot still uses a shared placeholder fingerprint.'
}
if ($text -notmatch 'hit\._id') { throw 'Wazuh adapter does not preserve the Indexer hit _id.' }
if ($text -notmatch '\$ConfirmRun\s+-cne\s+''RUN GT02 GT03 LIVE''') { throw 'Live adapter is not confirmation gated.' }
if ($text -match 'Invoke-CapitalOneGt02Gt03Runtime[^\r\n]*-ExpectedBucket\s+\$ExpectedBucket') {
    throw 'Runtime engine receives an unresolved caller bucket instead of AdapterState.ExpectedBucket.'
}

. $adapterPath -LibraryOnly
$contract = Get-GtLiveContract
if ([bool]$contract.accepts_provider_scriptblocks -or [bool]$contract.accepts_caller_provenance -or [bool]$contract.durable_json) {
    throw 'Live adapter contract is not fail-closed.'
}
if ([string]$contract.provider_provenance -cne 'live-adapter-fixed') { throw 'Live adapter provenance is not fixed.' }
if ((@($contract.expected_rule_ids) -join ',') -cne '100103,100104') { throw 'Live adapter Rule contract drifted.' }
if ((@($contract.negative_cases) -join ',') -cne 'normal_operator,other_bucket,other_prefix,other_principal,failure') {
    throw 'Live adapter negative case contract drifted.'
}
if ([int]$contract.negative_expected_counts.normal_operator -ne 3 -or
    [int]$contract.negative_expected_counts.other_bucket -ne 1 -or
    [int]$contract.negative_expected_counts.other_prefix -ne 1 -or
    [int]$contract.negative_expected_counts.other_principal -ne 1 -or
    [int]$contract.negative_expected_counts.failure -ne 1) {
    throw 'Live adapter Plan-exact negative matrix drifted.'
}
if ([int]$contract.run_observation_budget_seconds -ne 3300 -or
    [int]$contract.session_safety_margin_seconds -ne 300) {
    throw 'Live adapter session budget contract drifted.'
}

# A caller override is bounded by actual verified session time, not merely by
# the parameter ValidateRange.  A 3600-second run needs more than 3900 seconds
# because the 300-second safety margin is mandatory.
$budgetNow=[DateTimeOffset]::Parse('2026-08-21T00:00:00Z')
foreach($boundary in @(
    [pscustomobject]@{name='daily_60m';daily=$budgetNow.AddSeconds(3600);expiry=$null},
    [pscustomobject]@{name='daily_exact_run_plus_margin';daily=$budgetNow.AddSeconds(3900);expiry=$null},
    [pscustomobject]@{name='heartbeat_exact_run_plus_margin';daily=$budgetNow.AddHours(2);expiry=$budgetNow.AddSeconds(3900)}
)){
    $budgetFailed=$false
    try { Assert-GtLiveSessionBudget -Now $budgetNow -DailyDeadline $boundary.daily -SessionExpiry $boundary.expiry -MaxRunSeconds 3600 | Out-Null }
    catch { $budgetFailed=$_.Exception.Message -match 'session_deadline' }
    if(-not $budgetFailed){throw "Session budget boundary $($boundary.name) did not fail closed."}
}
[void](Assert-GtLiveSessionBudget -Now $budgetNow -DailyDeadline $budgetNow.AddSeconds(3901) -SessionExpiry $budgetNow.AddSeconds(3901) -MaxRunSeconds 3600)

# P1: exact process AWS environment restoration on both added and removed vars.
$awsSentinelName = 'AWS_GT02_LIVE_TEST_SENTINEL'
$awsAddedName = 'AWS_GT02_LIVE_TEST_ADDED'
[Environment]::SetEnvironmentVariable($awsSentinelName, 'before', 'Process')
[Environment]::SetEnvironmentVariable($awsAddedName, $null, 'Process')
$snapshot = Get-GtLiveAwsEnvironmentSnapshot
[Environment]::SetEnvironmentVariable($awsSentinelName, 'mutated', 'Process')
[Environment]::SetEnvironmentVariable($awsAddedName, 'must-disappear', 'Process')
Restore-GtLiveAwsEnvironment -Snapshot $snapshot
if ([Environment]::GetEnvironmentVariable($awsSentinelName, 'Process') -cne 'before' -or
    -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($awsAddedName, 'Process'))) {
    throw 'AWS process environment was not restored exactly.'
}
[Environment]::SetEnvironmentVariable($awsSentinelName, $null, 'Process')

$oldState = $script:AdapterState
try {
    $script:AdapterState = [ordered]@{
        RunDeadlineUtc=[DateTimeOffset]::UtcNow.AddMinutes(5)
        PollDeadlineSeconds=600
        ObservedIds=@{bridge=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)}
    }
    Register-GtLiveObservedIds -Channel 'bridge' -Ids @()
    if ($script:AdapterState.ObservedIds.bridge.Count -ne 0) {
        throw 'An empty observed-ID collection was not accepted as a valid zero-result set.'
    }

    $validEmptyScroll = [pscustomobject]@{
        timed_out=$false
        _shards=[pscustomobject]@{total=1;successful=1;skipped=0;failed=0}
        hits=[pscustomobject]@{total=[pscustomobject]@{value=0;relation='eq'};hits=@()}
    }
    $validated = Assert-GtLiveWazuhScrollPage -Response $validEmptyScroll -PageIndex 0
    if ([int]$validated.total -ne 0 -or @($validated.hits).Count -ne 0) {
        throw 'A complete empty Wazuh scroll page was rejected.'
    }
    foreach ($invalid in @(
        [pscustomobject]@{name='timed_out';value=[pscustomobject]@{timed_out=$true;_shards=[pscustomobject]@{failed=0};hits=[pscustomobject]@{total=[pscustomobject]@{value=0;relation='eq'};hits=@()}}},
        [pscustomobject]@{name='shard_failure';value=[pscustomobject]@{timed_out=$false;_shards=[pscustomobject]@{failed=1};hits=[pscustomobject]@{total=[pscustomobject]@{value=0;relation='eq'};hits=@()}}},
        [pscustomobject]@{name='inexact_total';value=[pscustomobject]@{timed_out=$false;_shards=[pscustomobject]@{failed=0};hits=[pscustomobject]@{total=[pscustomobject]@{value=1;relation='gte'};hits=@()}}}
    )) {
        $failed=$false
        try { Assert-GtLiveWazuhScrollPage -Response $invalid.value -PageIndex 0 | Out-Null }
        catch { $failed=$_.Exception.Message -match 'wazuh_query_incomplete' }
        if(-not $failed){throw "Wazuh scroll $($invalid.name) did not fail closed."}
    }

    $script:AdapterState.RunDeadlineUtc=[DateTimeOffset]::UtcNow.AddSeconds(-1)
    $now=[DateTimeOffset]::UtcNow
    foreach($entry in @(
        [pscustomobject]@{name='deadline';call={Get-GtLivePollDeadline -WindowEnd $now | Out-Null}},
        [pscustomobject]@{name='bridge query';call={Get-GtLiveBridgeRecords -WindowStart $now.AddSeconds(-5) -WindowEnd $now | Out-Null}},
        [pscustomobject]@{name='Wazuh query';call={Invoke-GtLiveWazuhSearch -RuleId '100103' -WindowStart $now.AddSeconds(-5) -WindowEnd $now | Out-Null}},
        [pscustomobject]@{name='CloudTrail query';call={Get-GtLiveCloudTrail -WindowStart $now.AddSeconds(-5) -WindowEnd $now | Out-Null}},
        [pscustomobject]@{name='bridge wait';call={Wait-GtLiveBridgeRecords -WindowStart $now.AddSeconds(-5) -WindowEnd $now -ExternalTakeId '' -CorrelationKey 'expired' | Out-Null}},
        [pscustomobject]@{name='Wazuh wait';call={Wait-GtLiveWazuhAlerts -RuleId '100103' -WindowStart $now.AddSeconds(-5) -WindowEnd $now -WaitForEmpty $false | Out-Null}},
        [pscustomobject]@{name='CloudTrail wait';call={Wait-GtLiveCloudTrail -WindowStart $now.AddSeconds(-5) -WindowEnd $now | Out-Null}}
    )){
        $expiredFailed=$false
        try { & $entry.call }
        catch { $expiredFailed=$_.Exception.Message -match 'run_observation_budget_exhausted' }
        if(-not $expiredFailed){throw "An already-expired run deadline performed a do-once $($entry.name)."}
    }
} finally {
    $script:AdapterState = $oldState
}

try { Invoke-GtLiveRun; throw 'Live adapter unexpectedly ran without explicit confirmation.' }
catch { if ($_.Exception.Message -notmatch 'confirmation_required') { throw 'Missing confirmation did not fail closed with confirmation_required.' } }

$runnerText = Get-Content -LiteralPath $runnerPath -Raw -Encoding UTF8
if ($runnerText -notmatch 'generic-injected-provider') { throw 'The generic runner provenance marker is missing.' }
if ($runnerText -notmatch 'Gate status NOT_RUN|gate02.*NOT_RUN|gate03.*NOT_RUN') { throw 'The generic runner must not claim Runtime PASS.' }
foreach($marker in @('run-final-reconciliation','gt03-negative-shared','GtNegativeRepeatCounts','ExpectedSecondaryBucket','ExpectedOtherPrefixObjectKey','ExpectedOtherPrincipalArn','PreconditionFailed','principal_arn','session_issuer_arn')){
    if($runnerText -notmatch [regex]::Escape($marker)){throw "Generic runner is missing final reconciliation marker: $marker"}
}
if($runnerText -match $removedRepeatParameter){throw 'Generic runner still permits a uniform negative repeat count.'}
$failureFixturePattern="'failure'[\s\S]*?StolenCredentials[\s\S]*?--if-match[\s\S]*?" + [regex]::Escape('$expectSuccess=$false')
if($text -notmatch "'other_bucket'[\s\S]*?StolenCredentials[\s\S]*?OtherBucketObjectSha256" -or
    $text -notmatch "'other_prefix'[\s\S]*?StolenCredentials[\s\S]*?OtherPrefixObjectSha256" -or
    $text -notmatch $failureFixturePattern -or
    $text -notmatch "'other_principal'[\s\S]*?sts','assume-role'[\s\S]*?AssumedRoleUser\.Arn[\s\S]*?expectedAssumedArn[\s\S]*?PrimaryObjectSha256"){
    throw 'Live negative fixtures do not use the exact isolated principal/bucket/prefix/failure paths.'
}
if($text -match "--range|non-target/capital-one-demo\.csv"){
    throw 'Live adapter still uses the old range or missing-object negative fixture.'
}
Write-Host 'GT02/GT03 live adapter static + P1 contract tests: PASS'
