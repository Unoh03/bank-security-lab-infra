#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateRange(3, 3)][int]$TakeCount = 3,
    [string[]]$ExpectedTakeIds,
    [string]$ExpectedBucket = '',
    [string]$ExpectedSecondaryBucket = '',
    [string]$ExpectedSecondaryObjectKey = 'validation/capital-one-demo.csv',
    [string]$ExpectedOtherPrefixObjectKey = '',
    [string]$ExpectedOtherPrincipalArn = '',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ExpectedRegion = 'ap-northeast-2',
    [string]$ExpectedRoleName = 'aws-topology-primary-karpenter-node',
    [string]$ExpectedObjectKey = 'validation/capital-one-demo.csv',
    [ValidateRange(0, 60)][int]$ClockSkewSeconds = 5,
    [ValidateRange(30, 900)][int]$DeliveryGraceSeconds = 600,
    [scriptblock]$TakeProvider,
    [scriptblock]$BaselineProvider,
    [scriptblock]$AttackProvider,
    [scriptblock]$BridgeEventProvider,
    [scriptblock]$WazuhAlertProvider,
    [scriptblock]$CloudTrailProvider,
    [scriptblock]$NegativeProvider,
    [scriptblock]$NormalProvider,
    [scriptblock]$SideEffectProvider
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<##
GT02/GT03 runtime boundary

This runner deliberately has no built-in AWS, Docker, Wazuh, DVWA, Shuffle, or
filesystem command.  Every runtime dependency is an explicit ScriptBlock
provider.  A caller may inject the reviewed operation/query functions, while
tests inject deterministic records.  The providers must return sanitized
objects only; this runner never prints or persists a raw record.

Provider contracts (one argument, a context object):

* TakeProvider: one object `{ take_id }` for a new independent READY TAKE.
* BaselineProvider: one object with `captured_at_utc`, `quiescence_proven=true`, and the four ID arrays
  `bridge_event_ids`, `rule100103_alert_ids`, `rule100104_alert_ids`, and
  `cloudtrail_event_ids`.
* AttackProvider: one object `{ started_at_utc, finished_at_utc }` after the
  approved fixed Capital One attack has completed.
* BridgeEventProvider: Bridge envelopes observed after the supplied baseline.
* WazuhAlertProvider: bounded Wazuh hits for the requested `rule_id` and
  phase.  The provider must not pre-filter away unexpected fresh hits and
  must return only after its bounded final-set/quiescence observation.
* CloudTrailProvider: bounded CloudTrail rows for the requested phase, after
  the same final-set/quiescence observation.
* NegativeProvider: one object `{ supported, started_at_utc, finished_at_utc,
  principal_arn }` for each fixed negative operation.  The three Node Role
  controls must report one identical exact assumed-role session ARN;
  `other_principal` reports its exact AssumeRole result ARN and only
  `normal_operator` leaves `principal_arn` empty.  The Plan-defined matrix is immutable:
  `normal_operator` runs three times and each of `other_bucket`,
  `other_prefix`, `other_principal`, and `failure` runs once.  All operations
  are issued before one shared CloudTrail collection; Rule 100104 absence is
  proved by the full-run final reconciliation, not by sequential zero-result
  waits.  `supported=false` is a fail-closed fixture blocker.
* NormalProvider: one object `{ supported, started_at_utc, finished_at_utc,
  baseline }` for one harmless fixed DVWA operation per TAKE.  Its source and
  event are queried through BridgeEventProvider; all three Rule 100103
  zero-alert controls are proved together by the full-run reconciliation.
* SideEffectProvider: one query-only sanitized baseline before the combined
  three-TAKE run and one after snapshot captured after all positive, normal,
  and negative controls reach their final observation state.
  Each snapshot must contain `read_only=true`, UTC capture/window metadata,
  sanitized query source identifiers, and only the four mutation-ID arrays
  `shuffle_execution_ids`, `github_run_ids`, `quarantine_mutation_ids`, and
  `validation_mutation_ids`.  The before/after sets must be identical; any
  reported side-effect count is a before/after change count, not the size of
  an already-existing snapshot.

* ExpectedTakeIds: an explicit caller-approved run set of exactly three
  canonical, unexpired TAKE_ID values shared by GT02 and GT03.  The runner
  compares provider results to this set; it never accepts arbitrary IDs.

This generic injected-provider runner always reports CONTRACT_TEST_PASS with
Gate status NOT_RUN.  A separate live adapter must verify concrete provider
identity and Runtime evidence before any Gate PASS can be issued.

GT03 never puts TAKE_ID in its positive CloudTrail or Wazuh projection.  TAKE
ID is used only to correlate the DVWA/Bridge GT02 source phase.

No evidence JSON is written.  Success returns a secret-safe in-memory summary
and prints only counts/latencies.  Failure uses fixed messages and does not
include provider exception text, raw events, credentials, or URLs.
##>

$script:GtSha256Pattern = '^[a-f0-9]{64}$'
$script:GtTakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:GtEventIdPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
$script:GtAllowedFailureErrorCodes = @('PreconditionFailed')
$script:GtNegativeCases = @(
    'normal_operator',
    'other_bucket',
    'other_prefix',
    'other_principal',
    'failure'
)
$script:GtNegativeRepeatCounts = [ordered]@{
    normal_operator = 3
    other_bucket     = 1
    other_prefix     = 1
    other_principal  = 1
    failure          = 1
}
$script:GtSideEffectSourceIds = @(
    'shuffle-state',
    'github-state',
    'dvwa-quarantine-state',
    'validation-state'
)

function Get-GtProperty {
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Object,
        [Parameter(Mandatory)][string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }
    foreach ($name in $Names) {
        if ($Object -is [Collections.IDictionary] -and $Object.Contains($name)) {
            return $Object[$name]
        }
        $property = @($Object.PSObject.Properties | Where-Object {
            $_.Name -ieq $name
        }) | Select-Object -First 1
        if ($null -ne $property) {
            return $property.Value
        }
    }
    return $null
}

function Get-GtFirstNonEmpty {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Object,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-GtProperty -Object $Object -Names @($name)
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }
    return $null
}

function Test-GtPropertyExists {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) {
        return $false
    }
    if ($Object -is [Collections.IDictionary] -and $Object.Contains($Name)) {
        return $true
    }
    $property = @($Object.PSObject.Properties | Where-Object {
        $_.Name -ieq $Name
    } | Select-Object -First 1)
    return $property.Count -eq 1
}

function ConvertTo-GtSideEffectSnapshot {
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    if ($null -eq $Snapshot) {
        throw 'GT02 automatic response proof failed: side-effect snapshot is missing.'
    }
    $allowedNames = @(
        'read_only',
        'captured_at_utc',
        'window_start_utc',
        'window_end_utc',
        'source_ids',
        'shuffle_execution_ids',
        'github_run_ids',
        'quarantine_mutation_ids',
        'validation_mutation_ids'
    )
    $actualNames = if ($Snapshot -is [Collections.IDictionary]) {
        @($Snapshot.Keys | ForEach-Object { [string]$_ })
    } else {
        @($Snapshot.PSObject.Properties | ForEach-Object { [string]$_.Name })
    }
    foreach ($actualName in $actualNames) {
        if ($actualName -notin $allowedNames) {
            throw 'GT02 automatic response proof failed: side-effect snapshot contains an unexpected field.'
        }
    }
    if (-not (Test-GtPropertyExists -Object $Snapshot -Name 'read_only') -or
        [bool](Get-GtProperty -Object $Snapshot -Names @('read_only')) -ne $true) {
        throw 'GT02 automatic response proof failed: side-effect provider is not marked query-only.'
    }
    $captured = ConvertTo-GtUtc -Value (Get-GtProperty -Object $Snapshot -Names @('captured_at_utc')) -FieldName 'side-effect.captured_at_utc'
    $windowStart = ConvertTo-GtUtc -Value (Get-GtProperty -Object $Snapshot -Names @('window_start_utc')) -FieldName 'side-effect.window_start_utc'
    $windowEnd = ConvertTo-GtUtc -Value (Get-GtProperty -Object $Snapshot -Names @('window_end_utc')) -FieldName 'side-effect.window_end_utc'
    if ($windowEnd -lt $windowStart) {
        throw 'GT02 automatic response proof failed: side-effect query window is inverted.'
    }
    $sourceIds = Get-GtStringArray -Object $Snapshot -Names @('source_ids')
    if ($sourceIds.Count -eq 0) {
        throw 'GT02 automatic response proof failed: side-effect query source identifiers are missing.'
    }
    $sourceSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($sourceId in $sourceIds) {
        if ($sourceId -notmatch '^[A-Za-z0-9._:/-]{1,200}$' -or -not $sourceSeen.Add($sourceId)) {
            throw 'GT02 automatic response proof failed: side-effect query source identifiers are not sanitized and unique.'
        }
    }
    $normalizedSources = @($sourceIds | Sort-Object -Unique)
    $expectedSources = @($script:GtSideEffectSourceIds | Sort-Object)
    if (($normalizedSources -join "`n") -cne ($expectedSources -join "`n")) {
        throw 'GT02 automatic response proof failed: side-effect query source identifiers do not match the fixed source set.'
    }
    $names = @(
        'shuffle_execution_ids',
        'github_run_ids',
        'quarantine_mutation_ids',
        'validation_mutation_ids'
    )
    $normalized = [ordered]@{}
    foreach ($name in $names) {
        if (-not (Test-GtPropertyExists -Object $Snapshot -Name $name)) {
            throw "GT02 automatic response proof failed: side-effect field $name is missing."
        }
        $ids = Get-GtStringArray -Object $Snapshot -Names @($name)
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $ids) {
            if ($id -notmatch '^[A-Za-z0-9._:/-]{1,200}$' -or -not $seen.Add($id)) {
                throw "GT02 automatic response proof failed: side-effect field $name is not a sanitized unique ID array."
            }
        }
        $normalized[$name] = @($ids | Sort-Object -Unique)
    }
    $normalized['read_only'] = $true
    $normalized['captured_at_utc'] = $captured
    $normalized['window_start_utc'] = $windowStart
    $normalized['window_end_utc'] = $windowEnd
    $normalized['source_ids'] = $normalizedSources
    return [pscustomobject]$normalized
}

function Compare-GtSideEffectSnapshots {
    param(
        [Parameter(Mandatory)][object]$Before,
        [Parameter(Mandatory)][object]$After
    )

    $counts = [ordered]@{}
    foreach ($name in @(
        'shuffle_execution_ids',
        'github_run_ids',
        'quarantine_mutation_ids',
        'validation_mutation_ids'
    )) {
        $beforeIds = @((Get-GtProperty -Object $Before -Names @($name)) | ForEach-Object { [string]$_ })
        $afterIds = @((Get-GtProperty -Object $After -Names @($name)) | ForEach-Object { [string]$_ })
        $beforeSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $afterSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $beforeIds) { [void]$beforeSet.Add($id) }
        foreach ($id in $afterIds) { [void]$afterSet.Add($id) }
        $changeCount = 0
        foreach ($id in $beforeSet) { if (-not $afterSet.Contains($id)) { $changeCount++ } }
        foreach ($id in $afterSet) { if (-not $beforeSet.Contains($id)) { $changeCount++ } }
        if ($changeCount -ne 0) {
            throw "GT02 automatic response proof failed: side-effect field $name changed (delta=$changeCount)."
        }
        $counts[$name] = $changeCount
    }
    if (($Before.source_ids -join "`n") -cne ($After.source_ids -join "`n")) {
        throw 'GT02 automatic response proof failed: side-effect query sources changed.'
    }
    if ($After.captured_at_utc -lt $Before.captured_at_utc) {
        throw 'GT02 automatic response proof failed: after snapshot predates its baseline.'
    }
    return [pscustomobject]$counts
}

function Assert-GtSideEffectCoverage {
    param(
        [Parameter(Mandatory)][object]$Before,
        [Parameter(Mandatory)][object]$After,
        [Parameter(Mandatory)][DateTimeOffset]$EarliestMutationStart,
        [Parameter(Mandatory)][DateTimeOffset]$ObservationWindowStart,
        [Parameter(Mandatory)][DateTimeOffset]$LatestObservationEnd
    )

    if ($Before.window_end_utc -gt $EarliestMutationStart -or
        $Before.captured_at_utc -gt $EarliestMutationStart -or
        $Before.captured_at_utc -lt $Before.window_end_utc) {
        throw 'GT02 automatic response proof failed: side-effect baseline is not bounded before the mutation window.'
    }
    if ($After.window_start_utc -gt $ObservationWindowStart -or
        $After.window_end_utc -lt $LatestObservationEnd -or
        $After.captured_at_utc -lt $After.window_end_utc) {
        throw 'GT02 automatic response proof failed: side-effect after query window does not cover the complete observation window.'
    }
}

function ConvertTo-GtUtc {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$FieldName
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "GT02/GT03 contract failed: $FieldName timestamp is missing."
    }
    try {
        return [DateTimeOffset]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal
        ).ToUniversalTime()
    } catch {
        throw "GT02/GT03 contract failed: $FieldName timestamp is invalid."
    }
}

function Get-GtStringArray {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Object,
        [Parameter(Mandatory)][string[]]$Names
    )

    $value = Get-GtProperty -Object $Object -Names $Names
    if ($null -eq $value) {
        return @()
    }
    return @($value | ForEach-Object { [string]$_ } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    })
}

function Assert-GtUniqueIds {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][string]$Label
    )

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in $Records) {
        $id = [string](Get-GtProperty -Object $record -Names @('id', 'event_id', 'wazuh_alert_id'))
        if ([string]::IsNullOrWhiteSpace($id) -or -not $seen.Add($id)) {
            throw "GT02/GT03 $Label contains a missing or duplicate identifier."
        }
    }
}

function Get-GtExpectedTakeIdSet {
    param(
        [Parameter(Mandatory)][AllowNull()][string[]]$ExpectedTakeIds,
        [Parameter(Mandatory)][int]$TakeCount
    )

    if ($null -eq $ExpectedTakeIds -or @($ExpectedTakeIds).Count -ne $TakeCount) {
        throw "GT02/GT03 blocked: the caller must supply exactly $TakeCount run-approved TAKE_ID values."
    }
    $set = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($takeId in $ExpectedTakeIds) {
        if ([string]::IsNullOrWhiteSpace($takeId) -or $takeId -notmatch $script:GtTakeIdPattern -or -not $set.Add([string]$takeId)) {
            throw 'GT02/GT03 blocked: ExpectedTakeIds must be canonical and unique.'
        }
    }
    return $set
}

function Invoke-GtProvider {
    param(
        [Parameter(Mandatory)][AllowNull()][scriptblock]$Provider,
        [Parameter(Mandatory)][string]$ProviderName,
        [Parameter(Mandatory)][object]$Context
    )

    if ($null -eq $Provider) {
        throw "GT02/GT03 blocked: $ProviderName provider is not supplied."
    }
    try {
        return @(& $Provider $Context)
    } catch {
        throw "GT02/GT03 blocked: $ProviderName provider failed."
    }
}

function Get-GtPayload {
    param([Parameter(Mandatory)][AllowNull()][object]$Record)
    $data = Get-GtProperty -Object $Record -Names @('data')
    if ($null -eq $data) {
        $data = $Record
    }
    $payload = Get-GtProperty -Object $data -Names @('payload')
    if ($null -eq $payload) {
        return $data
    }
    return $payload
}

function Get-GtContextFields {
    param([Parameter(Mandatory)][AllowNull()][object]$Record)
    $payload = Get-GtPayload -Record $Record
    $context = Get-GtProperty -Object $payload -Names @('context')
    if ($null -eq $context) {
        return $payload
    }
    return $context
}

function Get-GtAlertData {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $source = Get-GtProperty -Object $Alert -Names @('_source')
    if ($null -eq $source) {
        $source = $Alert
    }
    $data = Get-GtProperty -Object $source -Names @('data')
    if ($null -eq $data) {
        return $source
    }
    return $data
}

function Get-GtAlertRule {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $source = Get-GtProperty -Object $Alert -Names @('_source')
    if ($null -eq $source) {
        $source = $Alert
    }
    $rule = Get-GtProperty -Object $source -Names @('rule')
    if ($null -eq $rule) {
        return (Get-GtProperty -Object (Get-GtAlertData -Alert $Alert) -Names @('rule'))
    }
    return $rule
}

function Get-GtAlertId {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $source = Get-GtProperty -Object $Alert -Names @('_source')
    if ($null -eq $source) {
        $source = $Alert
    }
    $id = Get-GtFirstNonEmpty -Object $Alert -Names @('wazuh_alert_id', 'alert_id', 'id', '_id')
    if ($null -eq $id) {
        $id = Get-GtFirstNonEmpty -Object $source -Names @('wazuh_alert_id', 'alert_id', 'id', '_id')
    }
    return [string]$id
}

function Get-GtFreshRecords {
    param(
        [Parameter(Mandatory)][object[]]$Records,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$BaselineIds,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Projection,
        [Parameter(Mandatory)][DateTimeOffset]$WindowStart,
        [Parameter(Mandatory)][DateTimeOffset]$WindowEnd,
        [Parameter(Mandatory)][int]$ClockSkewSeconds,
        [switch]$RejectDuplicateIds
    )

    $baseline = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $BaselineIds) {
        if (-not $baseline.Add([string]$id)) {
            throw "GT02/GT03 baseline contains duplicate $Label identifiers."
        }
    }
    $fresh = [Collections.Generic.List[object]]::new()
    $staleCount = 0
    $lower = $WindowStart.AddSeconds(-$ClockSkewSeconds)
    foreach ($record in $Records) {
        $projected = & $Projection $record
        $id = [string]$projected.id
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw "GT02/GT03 $Label record has no identifier."
        }
        if ($baseline.Contains($id)) {
            $staleCount++
            continue
        }
        $timestamp = ConvertTo-GtUtc -Value $projected.event_time_utc -FieldName "$Label.event_time_utc"
        if ($timestamp -lt $lower -or $timestamp -gt $WindowEnd) {
            throw "GT02/GT03 $Label record is outside the bounded runtime window."
        }
        $projected.event_time_utc = $timestamp
        $fresh.Add($projected)
    }
    if ($RejectDuplicateIds) {
        Assert-GtUniqueIds -Records @($fresh) -Label "fresh $Label"
    }
    return [pscustomobject]@{
        records      = @($fresh)
        stale_count  = $staleCount
    }
}

function ConvertTo-GtSourceProjection {
    param([Parameter(Mandatory)][AllowNull()][object]$Record)
    $payload = Get-GtPayload -Record $Record
    $context = Get-GtContextFields -Record $Record
    $eventTime = Get-GtFirstNonEmpty -Object $Record -Names @('event_time', 'event_time_utc')
    if ($null -eq $eventTime) {
        $eventTime = Get-GtFirstNonEmpty -Object $payload -Names @('event_time', 'event_time_utc')
    }
    return [pscustomobject][ordered]@{
        id                  = [string](Get-GtFirstNonEmpty -Object $Record -Names @('event_id', 'id'))
        event_time_utc      = $eventTime
        take_id             = [string](Get-GtFirstNonEmpty -Object $payload -Names @('take_id'))
        source              = [string](Get-GtFirstNonEmpty -Object $Record -Names @('source'))
        transport           = [string](Get-GtFirstNonEmpty -Object $Record -Names @('transport'))
        aws_account_id      = [string](Get-GtFirstNonEmpty -Object $Record -Names @('aws_account_id', 'account_id'))
        aws_region          = [string](Get-GtFirstNonEmpty -Object $Record -Names @('aws_region', 'region'))
        normalized          = Get-GtFirstNonEmpty -Object $payload -Names @('normalized')
        event_type          = [string](Get-GtFirstNonEmpty -Object $payload -Names @('event_type'))
        result              = [string](Get-GtFirstNonEmpty -Object $payload -Names @('result'))
        route               = [string](Get-GtFirstNonEmpty -Object $payload -Names @('route'))
        resource            = [string](Get-GtFirstNonEmpty -Object $context -Names @('resource'))
        action              = [string](Get-GtFirstNonEmpty -Object $context -Names @('action'))
        security_level      = [string](Get-GtFirstNonEmpty -Object $context -Names @('security_level'))
        raw_message_sha256  = [string](Get-GtFirstNonEmpty -Object $Record -Names @('raw_message_sha256'))
    }
}

function ConvertTo-GtRule100103Projection {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $data = Get-GtAlertData -Alert $Alert
    $payload = Get-GtPayload -Record $data
    $source = Get-GtProperty -Object $Alert -Names @('_source')
    if ($null -eq $source) { $source = $Alert }
    $alertTime = Get-GtFirstNonEmpty -Object $source -Names @('timestamp', 'alert_time_utc')
    if ($null -eq $alertTime) {
        $alertTime = Get-GtFirstNonEmpty -Object $Alert -Names @('timestamp', 'alert_time_utc')
    }
    $eventTime = Get-GtFirstNonEmpty -Object $data -Names @('event_time', 'event_time_utc')
    if ($null -eq $eventTime) {
        $eventTime = Get-GtFirstNonEmpty -Object $payload -Names @('event_time', 'event_time_utc')
    }
    $eventId = Get-GtFirstNonEmpty -Object $data -Names @('event_id')
    if ($null -eq $eventId) {
        $eventId = Get-GtFirstNonEmpty -Object $payload -Names @('event_id')
    }
    return [pscustomobject][ordered]@{
        id                  = Get-GtAlertId -Alert $Alert
        event_id            = [string]$eventId
        event_time_utc      = $eventTime
        alert_time_utc      = $alertTime
        rule_id             = [string](Get-GtProperty -Object (Get-GtAlertRule -Alert $Alert) -Names @('id'))
        level               = [string](Get-GtProperty -Object (Get-GtAlertRule -Alert $Alert) -Names @('level'))
        aws_account_id      = [string](Get-GtFirstNonEmpty -Object $data -Names @('aws_account_id', 'account_id'))
        aws_region          = [string](Get-GtFirstNonEmpty -Object $data -Names @('aws_region', 'region'))
        take_id             = [string](Get-GtFirstNonEmpty -Object $payload -Names @('take_id'))
        source              = [string](Get-GtFirstNonEmpty -Object $data -Names @('source'))
        event_type          = [string](Get-GtFirstNonEmpty -Object $payload -Names @('event_type'))
        result              = [string](Get-GtFirstNonEmpty -Object $payload -Names @('result'))
        route               = [string](Get-GtFirstNonEmpty -Object $payload -Names @('route'))
        resource            = [string](Get-GtFirstNonEmpty -Object (Get-GtProperty -Object $payload -Names @('context')) -Names @('resource'))
        raw_message_sha256  = [string](Get-GtFirstNonEmpty -Object $data -Names @('raw_message_sha256'))
    }
}

function Get-GtAlertAws {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $data = Get-GtAlertData -Alert $Alert
    $aws = Get-GtProperty -Object $data -Names @('aws')
    if ($null -ne $aws) { return $aws }
    $incident = Get-GtProperty -Object $data -Names @('incident')
    if ($null -ne $incident) { return $incident }
    return $data
}

function ConvertTo-GtRule100104Projection {
    param([Parameter(Mandatory)][AllowNull()][object]$Alert)
    $data = Get-GtAlertData -Alert $Alert
    $aws = Get-GtAlertAws -Alert $Alert
    $request = Get-GtProperty -Object $aws -Names @('requestParameters')
    if ($null -eq $request) { $request = $aws }
    $identity = Get-GtProperty -Object $aws -Names @('userIdentity')
    $sessionContext = Get-GtProperty -Object $identity -Names @('sessionContext')
    $issuer = Get-GtProperty -Object $sessionContext -Names @('sessionIssuer')
    $additional = Get-GtProperty -Object $aws -Names @('additionalEventData')
    if ($null -eq $additional) { $additional = $aws }
    $incident = Get-GtProperty -Object $data -Names @('incident')
    $source = Get-GtProperty -Object $Alert -Names @('_source')
    if ($null -eq $source) { $source = $Alert }
    $alertTime = Get-GtFirstNonEmpty -Object $source -Names @('timestamp', 'alert_time_utc')
    if ($null -eq $alertTime) { $alertTime = Get-GtFirstNonEmpty -Object $Alert -Names @('timestamp', 'alert_time_utc') }
    $eventId = Get-GtFirstNonEmpty -Object $aws -Names @('eventID', 'event_id')
    if ($null -eq $eventId) { $eventId = Get-GtFirstNonEmpty -Object $incident -Names @('cloudtrail_event_id', 'event_id') }
    $eventTime = Get-GtFirstNonEmpty -Object $aws -Names @('eventTime', 'event_time_utc')
    if ($null -eq $eventTime) { $eventTime = Get-GtFirstNonEmpty -Object $incident -Names @('event_time_utc', 'event_time') }
    $roleName = Get-GtFirstNonEmpty -Object $issuer -Names @('userName', 'user_name')
    if ($null -eq $roleName) { $roleName = Get-GtFirstNonEmpty -Object $incident -Names @('principal_role_name', 'role_name') }
    return [pscustomobject][ordered]@{
        id                  = Get-GtAlertId -Alert $Alert
        event_id            = [string]$eventId
        event_time_utc      = $eventTime
        alert_time_utc      = $alertTime
        rule_id             = [string](Get-GtProperty -Object (Get-GtAlertRule -Alert $Alert) -Names @('id'))
        level               = [string](Get-GtProperty -Object (Get-GtAlertRule -Alert $Alert) -Names @('level'))
        event_source        = [string](Get-GtFirstNonEmpty -Object $aws -Names @('eventSource', 'event_source'))
        event_name          = [string](Get-GtFirstNonEmpty -Object $aws -Names @('eventName', 'event_name'))
        account_id          = [string](Get-GtFirstNonEmpty -Object $aws -Names @('recipientAccountId', 'aws_account_id', 'account_id'))
        region              = [string](Get-GtFirstNonEmpty -Object $aws -Names @('awsRegion', 'aws_region', 'region'))
        role_name           = [string]$roleName
        bucket              = [string](Get-GtFirstNonEmpty -Object $request -Names @('bucketName', 'bucket', 'bucket_name'))
        object_key          = [string](Get-GtFirstNonEmpty -Object $request -Names @('key', 'object_key'))
        http_status         = [string](Get-GtFirstNonEmpty -Object $additional -Names @('httpStatusCode', 'http_status', 'status_code'))
        error_code          = [string](Get-GtFirstNonEmpty -Object $aws -Names @('errorCode', 'error_code'))
    }
}

function ConvertTo-GtCloudTrailProjection {
    param([Parameter(Mandatory)][AllowNull()][object]$Event)
    $identity = Get-GtProperty -Object $Event -Names @('userIdentity')
    $sessionContext = Get-GtProperty -Object $identity -Names @('sessionContext')
    $issuer = Get-GtProperty -Object $sessionContext -Names @('sessionIssuer')
    $roleName = Get-GtFirstNonEmpty -Object $Event -Names @('principal_role_name', 'role_name', 'user_identity_session_issuer_user_name')
    if ($null -eq $roleName) { $roleName = Get-GtFirstNonEmpty -Object $issuer -Names @('userName', 'user_name') }
    if ($null -eq $roleName) { $roleName = Get-GtFirstNonEmpty -Object $Event -Names @('user_identity_arn', 'caller_arn', 'userIdentityArn') }
    $principalArn = Get-GtFirstNonEmpty -Object $Event -Names @('principal_arn', 'user_identity_arn', 'caller_arn', 'userIdentityArn')
    if ($null -eq $principalArn) { $principalArn = Get-GtFirstNonEmpty -Object $identity -Names @('arn') }
    $sessionIssuerArn = Get-GtFirstNonEmpty -Object $Event -Names @('session_issuer_arn', 'user_identity_session_issuer_arn')
    if ($null -eq $sessionIssuerArn) { $sessionIssuerArn = Get-GtFirstNonEmpty -Object $issuer -Names @('arn') }
    return [pscustomobject][ordered]@{
        id                  = [string](Get-GtFirstNonEmpty -Object $Event -Names @('event_id', 'eventID', 'id'))
        event_time_utc      = Get-GtFirstNonEmpty -Object $Event -Names @('event_time_utc', 'event_time', 'eventTime')
        event_source        = [string](Get-GtFirstNonEmpty -Object $Event -Names @('event_source', 'eventSource'))
        event_name          = [string](Get-GtFirstNonEmpty -Object $Event -Names @('event_name', 'eventName'))
        account_id          = [string](Get-GtFirstNonEmpty -Object $Event -Names @('account_id', 'recipientAccountId', 'aws_account_id'))
        region              = [string](Get-GtFirstNonEmpty -Object $Event -Names @('region', 'awsRegion', 'aws_region'))
        role_name           = [string]$roleName
        principal_arn       = [string]$principalArn
        session_issuer_arn  = [string]$sessionIssuerArn
        bucket              = [string](Get-GtFirstNonEmpty -Object $Event -Names @('bucket', 'bucketName', 'bucket_name'))
        object_key          = [string](Get-GtFirstNonEmpty -Object $Event -Names @('object_key', 'key'))
        http_status         = [string](Get-GtFirstNonEmpty -Object $Event -Names @('http_status', 'httpStatusCode', 'status_code'))
        error_code          = [string](Get-GtFirstNonEmpty -Object $Event -Names @('error_code', 'errorCode'))
    }
}

function Assert-GtSourceEvent {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion
    )
    if ([string]$Event.take_id -cne $TakeId -or
        [string]$Event.source -cne 'dvwa' -or
        [string]$Event.transport -cne 'push' -or
        [string]$Event.aws_account_id -cne $ExpectedAccountId -or
        [string]$Event.aws_region -cne $ExpectedRegion -or
        [bool]$Event.normalized -ne $true -or
        [string]$Event.event_type -cne 'command.execution' -or
        [string]$Event.result -cne 'succeeded' -or
        [string]$Event.route -cne '/vulnerabilities/exec/' -or
        [string]$Event.resource -cne 'ec2_imds' -or
        [string]$Event.action -cne 'shell_command' -or
        [string]$Event.security_level -cne 'low' -or
        [string]$Event.raw_message_sha256 -notmatch $script:GtSha256Pattern) {
        throw 'GT02 failed: a fresh source event violates the fixed command-event contract.'
    }
}

function Assert-GtNormalSourceEvent {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion
    )
    if ([string]$Event.take_id -cne $TakeId -or
        [string]$Event.source -cne 'dvwa' -or
        [string]$Event.transport -cne 'push' -or
        [string]$Event.aws_account_id -cne $ExpectedAccountId -or
        [string]$Event.aws_region -cne $ExpectedRegion -or
        [bool]$Event.normalized -ne $true -or
        [string]$Event.event_type -cne 'command.execution' -or
        [string]$Event.result -cne 'succeeded' -or
        [string]$Event.route -cne '/vulnerabilities/exec/' -or
        [string]$Event.resource -cne 'other' -or
        [string]$Event.action -cne 'shell_command' -or
        [string]$Event.security_level -cne 'low' -or
        [string]$Event.raw_message_sha256 -notmatch $script:GtSha256Pattern) {
        throw 'GT02 failed: the harmless normal operation source event violates the fixed negative contract.'
    }
}

function Assert-GtRule100103Alert {
    param(
        [Parameter(Mandatory)][object]$Alert,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion
    )
    if ([string]$Alert.rule_id -cne '100103' -or
        [int]$Alert.level -lt 10 -or
        [string]$Alert.aws_account_id -cne $ExpectedAccountId -or
        [string]$Alert.aws_region -cne $ExpectedRegion -or
        [string]$Alert.take_id -cne $TakeId -or
        [string]$Alert.source -cne 'dvwa' -or
        [string]$Alert.event_type -cne 'command.execution' -or
        [string]$Alert.result -cne 'succeeded' -or
        [string]$Alert.route -cne '/vulnerabilities/exec/' -or
        [string]$Alert.resource -cne 'ec2_imds' -or
        [string]$Alert.raw_message_sha256 -notmatch $script:GtSha256Pattern) {
        throw 'GT02 failed: a fresh Rule 100103 alert violates the fixed observe-only contract.'
    }
}

function Assert-GtRule100104Alert {
    param(
        [Parameter(Mandatory)][object]$Alert,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedBucket,
        [Parameter(Mandatory)][string]$ExpectedObjectKey
    )
    if ([string]$Alert.rule_id -cne '100104' -or
        [int]$Alert.level -lt 12 -or
        [string]$Alert.event_id -notmatch $script:GtEventIdPattern -or
        [string]$Alert.event_source -cne 's3.amazonaws.com' -or
        [string]$Alert.event_name -cne 'GetObject' -or
        [string]$Alert.account_id -cne $ExpectedAccountId -or
        [string]$Alert.region -cne $ExpectedRegion -or
        [string]$Alert.role_name -cne $ExpectedRoleName -or
        [string]$Alert.bucket -cne $ExpectedBucket -or
        [string]$Alert.object_key -cne $ExpectedObjectKey -or
        [string]$Alert.http_status -cne '200' -or
        -not [string]::IsNullOrWhiteSpace([string]$Alert.error_code)) {
        throw 'GT03 failed: a fresh Rule 100104 alert violates the high-confidence contract.'
    }
}

function Assert-GtPositiveCloudTrail {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedBucket,
        [Parameter(Mandatory)][string]$ExpectedObjectKey
    )
    if ([string]$Event.id -notmatch $script:GtEventIdPattern -or
        [string]$Event.event_source -cne 's3.amazonaws.com' -or
        [string]$Event.event_name -cne 'GetObject' -or
        [string]$Event.account_id -cne $ExpectedAccountId -or
        [string]$Event.region -cne $ExpectedRegion -or
        [string]$Event.role_name -cne $ExpectedRoleName -or
        [string]$Event.bucket -cne $ExpectedBucket -or
        [string]$Event.object_key -cne $ExpectedObjectKey -or
        [string]$Event.http_status -cne '200' -or
        -not [string]::IsNullOrWhiteSpace([string]$Event.error_code)) {
        throw 'GT03 failed: the positive CloudTrail event violates the fixed high-confidence contract.'
    }
}

function Test-GtAssumedRolePrincipal {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedRoleArn,
        [string]$ExpectedPrincipalArn = ''
    )
    $expectedPrincipalPattern = '^arn:aws:sts::' + [regex]::Escape($ExpectedAccountId) +
        ':assumed-role/' + [regex]::Escape($ExpectedRoleName) + '/[^/]+$'
    return (
        [string]$Event.role_name -ceq $ExpectedRoleName -and
        [string]$Event.session_issuer_arn -ceq $ExpectedRoleArn -and
        [string]$Event.principal_arn -match $expectedPrincipalPattern -and
        ([string]::IsNullOrWhiteSpace($ExpectedPrincipalArn) -or
            [string]$Event.principal_arn -ceq $ExpectedPrincipalArn)
    )
}

function Assert-GtNegativeCloudTrail {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedBucket,
        [Parameter(Mandatory)][string]$ExpectedSecondaryBucket,
        [Parameter(Mandatory)][string]$ExpectedSecondaryObjectKey,
        [Parameter(Mandatory)][string]$ExpectedOtherPrefixObjectKey,
        [Parameter(Mandatory)][string]$ExpectedNodePrincipalArn,
        [Parameter(Mandatory)][string]$ExpectedOtherPrincipalArn,
        [Parameter(Mandatory)][string]$ExpectedOtherPrincipalSessionArn,
        [Parameter(Mandatory)][string]$ExpectedObjectKey
    )
    if ([string]$Event.id -notmatch $script:GtEventIdPattern -or
        [string]$Event.event_source -cne 's3.amazonaws.com' -or
        [string]$Event.event_name -cne 'GetObject' -or
        [string]$Event.account_id -cne $ExpectedAccountId -or
        [string]$Event.region -cne $ExpectedRegion) {
        throw "GT03 failed: negative case $CaseId did not produce a bounded CloudTrail GetObject event."
    }
    $normalPrincipalValues = @(
        'terra-user',
        "arn:aws:iam::$ExpectedAccountId`:user/terra-user"
    )
    $isNormalOperator = [string]$Event.role_name -cin $normalPrincipalValues
    $nodeRoleArn = "arn:aws:iam::$ExpectedAccountId`:role/$ExpectedRoleName"
    $isNodeRole = Test-GtAssumedRolePrincipal -Event $Event -ExpectedAccountId $ExpectedAccountId `
        -ExpectedRoleName $ExpectedRoleName -ExpectedRoleArn $nodeRoleArn `
        -ExpectedPrincipalArn $ExpectedNodePrincipalArn
    $failureStatus = [string]$Event.http_status
    $hasFixedFailureStatus = [string]::IsNullOrWhiteSpace($failureStatus) -or $failureStatus -match '^[45][0-9]{2}$'
    switch ($CaseId) {
        'normal_operator' {
            if ([string]$Event.bucket -cne $ExpectedBucket -or
                [string]$Event.object_key -cne $ExpectedObjectKey -or
                -not $isNormalOperator -or
                [string]$Event.http_status -cne '200' -or
                -not [string]::IsNullOrWhiteSpace([string]$Event.error_code)) {
                throw 'GT03 failed: normal_operator is not the fixed terra-user control.'
            }
        }
        'other_bucket' {
            if ([string]$Event.bucket -cne $ExpectedSecondaryBucket -or
                [string]$Event.object_key -cne $ExpectedSecondaryObjectKey -or
                -not $isNodeRole -or
                [string]$Event.http_status -cne '200' -or
                -not [string]::IsNullOrWhiteSpace([string]$Event.error_code)) {
                throw 'GT03 blocked: other_bucket fixture does not identify a distinct fixed bucket.'
            }
        }
        'other_prefix' {
            if ([string]$Event.bucket -cne $ExpectedBucket -or
                [string]$Event.object_key -cne $ExpectedOtherPrefixObjectKey -or
                -not $isNodeRole -or
                [string]$Event.http_status -cne '200' -or
                -not [string]::IsNullOrWhiteSpace([string]$Event.error_code)) {
                throw 'GT03 blocked: other_prefix fixture does not identify a distinct fixed prefix.'
            }
        }
        'other_principal' {
            $expectedOtherRoleName = ($ExpectedOtherPrincipalArn -split '/')[-1]
            $isOtherRole = Test-GtAssumedRolePrincipal -Event $Event -ExpectedAccountId $ExpectedAccountId `
                -ExpectedRoleName $expectedOtherRoleName -ExpectedRoleArn $ExpectedOtherPrincipalArn `
                -ExpectedPrincipalArn $ExpectedOtherPrincipalSessionArn
            if (-not $isOtherRole -or
                [string]$Event.bucket -cne $ExpectedBucket -or
                [string]$Event.object_key -cne $ExpectedObjectKey -or
                [string]$Event.http_status -cne '200' -or
                -not [string]::IsNullOrWhiteSpace([string]$Event.error_code)) {
                throw 'GT03 failed: other_principal fixture used the protected Node Role.'
            }
        }
        'failure' {
            if ([string]$Event.bucket -cne $ExpectedBucket -or
                [string]$Event.object_key -cne $ExpectedObjectKey -or
                -not $isNodeRole -or
                [string]$Event.error_code -cnotin $script:GtAllowedFailureErrorCodes -or
                -not $hasFixedFailureStatus) {
                throw 'GT03 failed: failure fixture did not produce the fixed precondition error on the protected object.'
            }
        }
        default {
            throw 'GT03 contract failed: unsupported negative case.'
        }
    }
}

function Resolve-GtNegativeCaseId {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedBucket,
        [Parameter(Mandatory)][string]$ExpectedSecondaryBucket,
        [Parameter(Mandatory)][string]$ExpectedSecondaryObjectKey,
        [Parameter(Mandatory)][string]$ExpectedOtherPrefixObjectKey,
        [Parameter(Mandatory)][string]$ExpectedNodePrincipalArn,
        [Parameter(Mandatory)][string]$ExpectedOtherPrincipalArn,
        [Parameter(Mandatory)][string]$ExpectedOtherPrincipalSessionArn,
        [Parameter(Mandatory)][string]$ExpectedObjectKey
    )
    $matches = [Collections.Generic.List[string]]::new()
    foreach ($caseId in $script:GtNegativeCases) {
        try {
            Assert-GtNegativeCloudTrail -Event $Event -CaseId $caseId `
                -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion `
                -ExpectedRoleName $ExpectedRoleName -ExpectedBucket $ExpectedBucket `
                -ExpectedSecondaryBucket $ExpectedSecondaryBucket -ExpectedSecondaryObjectKey $ExpectedSecondaryObjectKey `
                -ExpectedOtherPrefixObjectKey $ExpectedOtherPrefixObjectKey `
                -ExpectedNodePrincipalArn $ExpectedNodePrincipalArn `
                -ExpectedOtherPrincipalArn $ExpectedOtherPrincipalArn `
                -ExpectedOtherPrincipalSessionArn $ExpectedOtherPrincipalSessionArn `
                -ExpectedObjectKey $ExpectedObjectKey
            $matches.Add($caseId)
        } catch { }
    }
    if ($matches.Count -ne 1) {
        throw 'GT03 failed: a shared negative CloudTrail event does not map to exactly one Plan case.'
    }
    return $matches[0]
}

function Assert-GtExactStringSet {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Actual,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $Actual) {
        if ([string]::IsNullOrWhiteSpace($id) -or -not $actualSet.Add($id)) {
            throw "GT02/GT03 final reconciliation has a missing or duplicate $Label identifier."
        }
    }
    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $Expected) {
        if ([string]::IsNullOrWhiteSpace($id) -or -not $expectedSet.Add($id)) {
            throw "GT02/GT03 expected $Label identifier set is invalid."
        }
    }
    if (-not $actualSet.SetEquals($expectedSet)) {
        throw "GT02/GT03 final reconciliation $Label set differs from the complete run set."
    }
}

function Get-GtBaseline {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][DateTimeOffset]$AttackStart
    )
    if (-not (Test-GtPropertyExists -Object $Value -Name 'quiescence_proven') -or
        [bool](Get-GtProperty -Object $Value -Names @('quiescence_proven')) -ne $true) {
        throw 'GT02/GT03 baseline does not prove a final quiescent observation set.'
    }
    $captured = ConvertTo-GtUtc -Value (Get-GtProperty -Object $Value -Names @('captured_at_utc', 'captured_at')) -FieldName 'baseline.captured_at_utc'
    if ($captured -gt $AttackStart) {
        throw 'GT02/GT03 baseline was captured after the attack began.'
    }
    $baseline = [ordered]@{}
    foreach ($name in @('bridge_event_ids', 'rule100103_alert_ids', 'rule100104_alert_ids', 'cloudtrail_event_ids')) {
        $ids = Get-GtStringArray -Object $Value -Names @($name)
        $set = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $ids) {
            if (-not $set.Add($id)) {
                throw "GT02/GT03 baseline contains duplicate identifiers in $name."
            }
        }
        $baseline[$name] = $ids
    }
    $baseline['captured_at_utc'] = $captured
    $baseline['quiescence_proven'] = $true
    return [pscustomobject]$baseline
}

function Invoke-GtTake {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][object]$Take,
        [Parameter(Mandatory)][scriptblock]$BaselineProvider,
        [Parameter(Mandatory)][scriptblock]$AttackProvider,
        [Parameter(Mandatory)][scriptblock]$BridgeEventProvider,
        [Parameter(Mandatory)][scriptblock]$WazuhAlertProvider,
        [Parameter(Mandatory)][scriptblock]$CloudTrailProvider,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][string]$ExpectedRoleName,
        [Parameter(Mandatory)][string]$ExpectedBucket,
        [Parameter(Mandatory)][string]$ExpectedObjectKey,
        [Parameter(Mandatory)][int]$ClockSkewSeconds,
        [Parameter(Mandatory)][int]$DeliveryGraceSeconds
    )
    $takeId = [string](Get-GtFirstNonEmpty -Object $Take -Names @('take_id', 'id'))
    if ($takeId -notmatch $script:GtTakeIdPattern) {
        throw 'GT02/GT03 blocked: TakeProvider returned a non-canonical TAKE_ID.'
    }
    $takeContext = [pscustomobject][ordered]@{
        gate      = 'GT02-GT03'
        phase     = 'take'
        take_id   = $takeId
        take_index = $Index
    }
    $baselineValues = @(Invoke-GtProvider -Provider $BaselineProvider -ProviderName 'Baseline' -Context $takeContext)
    if ($baselineValues.Count -ne 1) {
        throw 'GT02/GT03 baseline provider must return exactly one baseline.'
    }
    $attackValues = @(Invoke-GtProvider -Provider $AttackProvider -ProviderName 'Attack' -Context $takeContext)
    if ($attackValues.Count -ne 1) {
        throw 'GT02 attack provider must return exactly one completed attack window.'
    }
    $attackStart = ConvertTo-GtUtc -Value (Get-GtProperty -Object $attackValues[0] -Names @('started_at_utc', 'started_at')) -FieldName 'attack.started_at_utc'
    $attackEnd = ConvertTo-GtUtc -Value (Get-GtProperty -Object $attackValues[0] -Names @('finished_at_utc', 'finished_at')) -FieldName 'attack.finished_at_utc'
    if ($attackEnd -lt $attackStart) {
        throw 'GT02 attack window has an end before its start.'
    }
    $baseline = Get-GtBaseline -Value $baselineValues[0] -AttackStart $attackStart
    $windowEnd = $attackEnd.AddSeconds($DeliveryGraceSeconds)
    $context = [pscustomobject][ordered]@{
        gate              = 'GT02-GT03'
        phase             = 'gt02'
        take_id           = $takeId
        take_index        = $Index
        started_at_utc    = $attackStart
        finished_at_utc   = $attackEnd
        window_start_utc  = $attackStart.AddSeconds(-$ClockSkewSeconds)
        window_end_utc    = $windowEnd
        baseline          = $baseline
        rule_id           = '100103'
        expected_count    = -1
        require_full_window = $false
    }

    $bridge = @(Invoke-GtProvider -Provider $BridgeEventProvider -ProviderName 'Bridge event' -Context $context)
    $freshBridge = Get-GtFreshRecords -Records $bridge -BaselineIds $baseline.bridge_event_ids -Label 'Bridge event' -Projection ${function:ConvertTo-GtSourceProjection} -WindowStart $attackStart -WindowEnd $windowEnd -ClockSkewSeconds $ClockSkewSeconds
    $sourceRecords = @($freshBridge.records)
    if ($sourceRecords.Count -eq 0) {
        throw 'GT02 failed: no fresh command.execution source event was observed.'
    }
    foreach ($source in $sourceRecords) {
        Assert-GtSourceEvent -Event $source -TakeId $takeId -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion
    }
    $context.rule_id = '100103'
    $context.phase = 'gt02'
    $context.expected_count = $sourceRecords.Count
    $rule103Raw = @(Invoke-GtProvider -Provider $WazuhAlertProvider -ProviderName 'Rule 100103 alert' -Context $context)
    $fresh103 = Get-GtFreshRecords -Records $rule103Raw -BaselineIds $baseline.rule100103_alert_ids -Label 'Rule 100103 alert' -Projection ${function:ConvertTo-GtRule100103Projection} -WindowStart $attackStart -WindowEnd $windowEnd -ClockSkewSeconds $ClockSkewSeconds
    $alerts103 = @($fresh103.records)
    if ($alerts103.Count -ne $sourceRecords.Count) {
        throw 'GT02 failed: fresh source event and Rule 100103 alert cardinalities differ.'
    }
    foreach ($alert in $alerts103) {
        Assert-GtRule100103Alert -Alert $alert -TakeId $takeId -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion
    }
    $sourceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($source in $sourceRecords) { [void]$sourceIds.Add([string]$source.id) }
    $alertIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $wazuhAlertIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $gt02Evidence = [Collections.Generic.List[object]]::new()
    foreach ($alert in $alerts103) {
        $eventId = [string]$alert.event_id
        if (-not $sourceIds.Contains($eventId) -or -not $alertIds.Add($eventId)) {
            throw 'GT02 failed: source event IDs and Rule 100103 alert IDs are not a one-to-one set.'
        }
        $wazuhAlertId = [string]$alert.id
        if ($wazuhAlertId -notmatch '^[A-Za-z0-9._:/-]{1,200}$' -or -not $wazuhAlertIds.Add($wazuhAlertId)) {
            throw 'GT02 failed: Rule 100103 Wazuh alert identifiers are missing or duplicated.'
        }
        $matchingSource = @($sourceRecords | Where-Object { [string]$_.id -ceq $eventId })
        if ($matchingSource.Count -ne 1 -or [string]$matchingSource[0].raw_message_sha256 -cne [string]$alert.raw_message_sha256) {
            throw 'GT02 failed: a Rule 100103 alert does not match its source event integrity hash.'
        }
        $sourceUtc = ConvertTo-GtUtc -Value $matchingSource[0].event_time_utc -FieldName 'GT02.source_event_utc'
        $wazuhEventUtc = ConvertTo-GtUtc -Value $alert.event_time_utc -FieldName 'GT02.wazuh_event_utc'
        $wazuhAlertUtc = ConvertTo-GtUtc -Value $alert.alert_time_utc -FieldName 'GT02.wazuh_alert_utc'
        $gt02Evidence.Add([pscustomobject][ordered]@{
            source_event_id = $eventId
            source_event_utc = $sourceUtc.ToString('o')
            wazuh_alert_id = $wazuhAlertId
            wazuh_event_id = $eventId
            wazuh_event_utc = $wazuhEventUtc.ToString('o')
            wazuh_alert_utc = $wazuhAlertUtc.ToString('o')
        })
    }
    if ($alertIds.Count -ne $sourceIds.Count) {
        throw 'GT02 failed: a source event was missing from the Rule 100103 alert set.'
    }

    $context.rule_id = '100104'
    $context.phase = 'gt03-positive'
    $context.expected_count = 1
    $cloudTrailRaw = @(Invoke-GtProvider -Provider $CloudTrailProvider -ProviderName 'positive CloudTrail' -Context $context)
    $freshCloudTrail = Get-GtFreshRecords -Records $cloudTrailRaw -BaselineIds $baseline.cloudtrail_event_ids -Label 'positive CloudTrail event' -Projection ${function:ConvertTo-GtCloudTrailProjection} -WindowStart $attackStart -WindowEnd $windowEnd -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $positiveCloudTrail = @($freshCloudTrail.records)
    if ($positiveCloudTrail.Count -ne 1) {
        throw 'GT03 failed: each attack TAKE must produce exactly one fresh positive CloudTrail event.'
    }
    Assert-GtPositiveCloudTrail -Event $positiveCloudTrail[0] -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion -ExpectedRoleName $ExpectedRoleName -ExpectedBucket $ExpectedBucket -ExpectedObjectKey $ExpectedObjectKey

    $rule104Raw = @(Invoke-GtProvider -Provider $WazuhAlertProvider -ProviderName 'Rule 100104 alert' -Context $context)
    $fresh104 = Get-GtFreshRecords -Records $rule104Raw -BaselineIds $baseline.rule100104_alert_ids -Label 'Rule 100104 alert' -Projection ${function:ConvertTo-GtRule100104Projection} -WindowStart $attackStart -WindowEnd $windowEnd -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $alerts104 = @($fresh104.records)
    if ($alerts104.Count -ne 1) {
        throw 'GT03 failed: each attack TAKE must produce exactly one fresh Rule 100104 alert.'
    }
    Assert-GtRule100104Alert -Alert $alerts104[0] -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion -ExpectedRoleName $ExpectedRoleName -ExpectedBucket $ExpectedBucket -ExpectedObjectKey $ExpectedObjectKey
    if ([string]$positiveCloudTrail[0].id -cne [string]$alerts104[0].event_id) {
        throw 'GT03 failed: CloudTrail eventID and Rule 100104 alert eventID differ.'
    }
    $alertTime = ConvertTo-GtUtc -Value $alerts104[0].alert_time_utc -FieldName 'Rule100104.alert_time_utc'
    $positiveEventTime = ConvertTo-GtUtc -Value $positiveCloudTrail[0].event_time_utc -FieldName 'positive CloudTrail.event_time_utc'
    $latency = ($alertTime - $positiveEventTime).TotalSeconds
    if ($latency -lt (-1 * $ClockSkewSeconds) -or $latency -gt $DeliveryGraceSeconds) {
        throw 'GT03 failed: positive CloudTrail-to-Wazuh latency is outside the bounded window.'
    }

    return [pscustomobject][ordered]@{
        take_id                     = $takeId
        attack_started_at_utc       = $attackStart
        attack_finished_at_utc      = $attackEnd
        observation_completed_at_utc = [DateTimeOffset]::UtcNow
        window_start_utc            = $attackStart.AddSeconds(-$ClockSkewSeconds)
        window_end_utc              = $windowEnd
        take_index                 = $Index
        source_event_count         = $sourceRecords.Count
        rule100103_alert_count     = $alerts103.Count
        positive_cloudtrail_count  = $positiveCloudTrail.Count
        positive_cloudtrail_event_id = [string]$positiveCloudTrail[0].id
        gt02_source_event_ids       = @($sourceRecords | ForEach-Object { [string]$_.id })
        gt02_wazuh_alert_ids        = @($alerts103 | ForEach-Object { [string]$_.id })
        gt03_wazuh_alert_id         = [string]$alerts104[0].id
        rule100104_alert_count     = $alerts104.Count
        latency_seconds            = [math]::Round($latency, 3)
        stale_bridge_excluded      = $freshBridge.stale_count
        stale_rule100103_excluded  = $fresh103.stale_count
        stale_cloudtrail_excluded  = $freshCloudTrail.stale_count
        stale_rule100104_excluded  = $fresh104.stale_count
        evidence                    = [pscustomobject][ordered]@{
            take_id = $takeId
            gt02 = @($gt02Evidence)
            gt03 = [pscustomobject][ordered]@{
                cloudtrail_event_id = [string]$positiveCloudTrail[0].id
                wazuh_alert_id = [string]$alerts104[0].id
                event_utc = $positiveEventTime.ToString('o')
                alert_utc = $alertTime.ToString('o')
                latency_seconds = [math]::Round($latency, 3)
                clock_skew_seconds = $ClockSkewSeconds
                window_start_utc = $attackStart.AddSeconds(-$ClockSkewSeconds).ToString('o')
                window_end_utc = $windowEnd.ToString('o')
            }
            counts = [pscustomobject][ordered]@{
                gt02_source_events = $sourceRecords.Count
                gt02_rule100103_alerts = $alerts103.Count
                gt03_cloudtrail_events = $positiveCloudTrail.Count
                gt03_rule100104_alerts = $alerts104.Count
            }
        }
    }
}

function Invoke-GtNormalOperation {
    param(
        [Parameter(Mandatory)][object]$Take,
        [Parameter(Mandatory)][scriptblock]$NormalProvider,
        [Parameter(Mandatory)][scriptblock]$BridgeEventProvider,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedRegion,
        [Parameter(Mandatory)][int]$ClockSkewSeconds,
        [Parameter(Mandatory)][int]$DeliveryGraceSeconds
    )
    $normalContext = [pscustomobject][ordered]@{
        gate       = 'GT02-GT03'
        phase      = 'gt02-normal-operation'
        take_id    = [string]$Take.take_id
        take_index = [int]$Take.take_index
    }
    $operationValues = @(Invoke-GtProvider -Provider $NormalProvider -ProviderName 'normal operation' -Context $normalContext)
    if ($operationValues.Count -ne 1) {
        throw 'GT02 blocked: normal operation provider must return exactly one operation result.'
    }
    $operation = $operationValues[0]
    if ((Get-GtProperty -Object $operation -Names @('supported')) -ne $true) {
        throw 'GT02 blocked: the harmless fixed normal operation fixture is unavailable.'
    }
    $normalStart = ConvertTo-GtUtc -Value (Get-GtProperty -Object $operation -Names @('started_at_utc', 'started_at')) -FieldName 'normal.started_at_utc'
    $normalEnd = ConvertTo-GtUtc -Value (Get-GtProperty -Object $operation -Names @('finished_at_utc', 'finished_at')) -FieldName 'normal.finished_at_utc'
    if ($normalEnd -lt $normalStart) {
        throw 'GT02 normal operation window has an end before its start.'
    }
    $normalBaselineValue = Get-GtProperty -Object $operation -Names @('baseline')
    if ($null -eq $normalBaselineValue) {
        throw 'GT02 blocked: normal operation did not return its pre-operation baseline.'
    }
    $normalBaseline = Get-GtBaseline -Value $normalBaselineValue -AttackStart $normalStart
    $windowEnd = $normalEnd.AddSeconds($DeliveryGraceSeconds)
    $context = [pscustomobject][ordered]@{
        gate             = 'GT02-GT03'
        phase            = 'gt02-normal'
        take_id          = [string]$Take.take_id
        take_index       = [int]$Take.take_index
        started_at_utc   = $normalStart
        finished_at_utc  = $normalEnd
        window_start_utc = $normalStart.AddSeconds(-$ClockSkewSeconds)
        window_end_utc   = $windowEnd
        baseline         = $normalBaseline
        rule_id          = '100103'
        expected_count   = 1
        require_full_window = $false
    }
    $bridgeRaw = @(Invoke-GtProvider -Provider $BridgeEventProvider -ProviderName 'normal Bridge event' -Context $context)
    $freshBridge = Get-GtFreshRecords -Records $bridgeRaw -BaselineIds $normalBaseline.bridge_event_ids -Label 'normal Bridge event' -Projection ${function:ConvertTo-GtSourceProjection} -WindowStart $normalStart -WindowEnd $windowEnd -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $normalEvents = @($freshBridge.records)
    if ($normalEvents.Count -ne 1) {
        throw 'GT02 failed: the harmless normal operation did not produce exactly one fresh source event.'
    }
    Assert-GtNormalSourceEvent -Event $normalEvents[0] -TakeId ([string]$Take.take_id) -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion
    # Do not perform one 600-second zero-result wait per normal operation.
    # Rule 100103 absence for all three controls is proved once by the full-run
    # reconciliation after the last positive and negative operation.
    return [pscustomobject][ordered]@{
        operation_started_at_utc = $normalStart
        operation_finished_at_utc = $normalEnd
        observation_completed_at_utc = [DateTimeOffset]::UtcNow
        source_event_count     = $normalEvents.Count
        source_event_ids       = @($normalEvents | ForEach-Object { [string]$_.id })
        rule100103_alert_count = 0
        stale_bridge_excluded  = $freshBridge.stale_count
        stale_alert_excluded   = 0
        window_start_utc       = $normalStart.AddSeconds(-$ClockSkewSeconds)
        window_end_utc         = $windowEnd
    }
}

function Invoke-CapitalOneGt02Gt03Runtime {
    [CmdletBinding()]
    param(
        [ValidateRange(3, 3)][int]$TakeCount = 3,
        [string[]]$ExpectedTakeIds,
        [string]$ExpectedBucket,
        [string]$ExpectedSecondaryBucket,
        [string]$ExpectedSecondaryObjectKey = 'validation/capital-one-demo.csv',
        [string]$ExpectedOtherPrefixObjectKey,
        [string]$ExpectedOtherPrincipalArn,
        [string]$ExpectedAccountId = '433048100798',
        [string]$ExpectedRegion = 'ap-northeast-2',
        [string]$ExpectedRoleName = 'aws-topology-primary-karpenter-node',
        [string]$ExpectedObjectKey = 'validation/capital-one-demo.csv',
        [ValidateRange(0, 60)][int]$ClockSkewSeconds = 5,
        [ValidateRange(30, 900)][int]$DeliveryGraceSeconds = 600,
        [scriptblock]$TakeProvider,
        [scriptblock]$BaselineProvider,
        [scriptblock]$AttackProvider,
        [scriptblock]$BridgeEventProvider,
        [scriptblock]$WazuhAlertProvider,
        [scriptblock]$CloudTrailProvider,
        [scriptblock]$NegativeProvider,
        [scriptblock]$NormalProvider,
        [scriptblock]$SideEffectProvider
    )

    if ($ExpectedBucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
        throw 'GT03 blocked: ExpectedBucket must be the fixed lab bucket supplied by the caller.'
    }
    if ($ExpectedSecondaryBucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or
        $ExpectedSecondaryBucket -ceq $ExpectedBucket -or
        [string]::IsNullOrWhiteSpace($ExpectedSecondaryObjectKey) -or
        $ExpectedOtherPrefixObjectKey -notmatch '^[^/]+/.+' -or
        $ExpectedOtherPrefixObjectKey -ceq $ExpectedObjectKey -or
        ($ExpectedOtherPrefixObjectKey -split '/', 2)[0] -ceq ($ExpectedObjectKey -split '/', 2)[0] -or
        $ExpectedOtherPrincipalArn -notmatch ('^arn:aws:iam::' + [regex]::Escape($ExpectedAccountId) + ':role/[A-Za-z0-9+=,.@_/-]{1,200}$')) {
        throw 'GT03 blocked: fixed secondary bucket/object, other-prefix object, or other-principal fixture is unresolved.'
    }
    $expectedTakeIdSet = Get-GtExpectedTakeIdSet -ExpectedTakeIds $ExpectedTakeIds -TakeCount $TakeCount
    foreach ($name in @('ExpectedAccountId', 'ExpectedRegion', 'ExpectedRoleName', 'ExpectedObjectKey')) {
        if ([string]::IsNullOrWhiteSpace([string](Get-Variable -Name $name -ValueOnly))) {
            throw "GT02/GT03 blocked: $name is empty."
        }
    }
    if ($ExpectedObjectKey -notmatch '^[^/]+/.+') {
        throw 'GT03 blocked: ExpectedObjectKey must contain the fixed protected prefix.'
    }
    $providerMap = [ordered]@{
        TakeProvider          = $TakeProvider
        BaselineProvider      = $BaselineProvider
        AttackProvider        = $AttackProvider
        BridgeEventProvider   = $BridgeEventProvider
        WazuhAlertProvider    = $WazuhAlertProvider
        CloudTrailProvider    = $CloudTrailProvider
        NegativeProvider      = $NegativeProvider
        NormalProvider        = $NormalProvider
        SideEffectProvider    = $SideEffectProvider
    }
    foreach ($entry in $providerMap.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            throw "GT02/GT03 blocked: $($entry.Key) provider is not supplied."
        }
    }

    $takeResults = [Collections.Generic.List[object]]::new()
    $normalResults = [Collections.Generic.List[object]]::new()
    $sideEffectResults = [Collections.Generic.List[object]]::new()
    $observedTakeIdSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $attackEventIdSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $gt02SourceEventIdSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $gt02WazuhAlertIdSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $gt03WazuhAlertIdSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $runBaselineValues = @(Invoke-GtProvider -Provider $BaselineProvider -ProviderName 'full-run baseline' -Context ([pscustomobject]@{
        gate = 'GT02-GT03'; phase = 'run-baseline'; take_index = 0; take_count = $TakeCount
    }))
    if ($runBaselineValues.Count -ne 1) {
        throw 'GT02/GT03 full-run baseline provider must return exactly one baseline.'
    }
    $sideBeforeValues = @(Invoke-GtProvider -Provider $SideEffectProvider -ProviderName 'side-effect baseline' -Context ([pscustomobject]@{
        gate = 'GT02-GT03'; phase = 'side-effect-baseline'; take_index = 1; take_count = $TakeCount
    }))
    if ($sideBeforeValues.Count -ne 1) {
        throw 'GT02 automatic response proof failed: side-effect baseline provider must return exactly one snapshot.'
    }
    $sideBefore = ConvertTo-GtSideEffectSnapshot -Snapshot $sideBeforeValues[0]
    for ($index = 1; $index -le $TakeCount; $index++) {
        $takeValues = @(Invoke-GtProvider -Provider $TakeProvider -ProviderName 'TAKE' -Context ([pscustomobject]@{
            gate = 'GT02-GT03'; phase = 'take-allocation'; take_index = $index
        }))
        if ($takeValues.Count -ne 1) {
            throw 'GT02/GT03 TAKE provider must return exactly one independent TAKE.'
        }
        $takeResult = Invoke-GtTake -Index $index -Take $takeValues[0] -BaselineProvider $BaselineProvider -AttackProvider $AttackProvider -BridgeEventProvider $BridgeEventProvider -WazuhAlertProvider $WazuhAlertProvider -CloudTrailProvider $CloudTrailProvider -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion -ExpectedRoleName $ExpectedRoleName -ExpectedBucket $ExpectedBucket -ExpectedObjectKey $ExpectedObjectKey -ClockSkewSeconds $ClockSkewSeconds -DeliveryGraceSeconds $DeliveryGraceSeconds
        if (-not $observedTakeIdSet.Add([string]$takeResult.take_id) -or -not $expectedTakeIdSet.Contains([string]$takeResult.take_id)) {
            throw 'GT02/GT03 failed: provider TAKE_ID is not a unique member of the run-approved set.'
        }
        if (-not $attackEventIdSet.Add([string]$takeResult.positive_cloudtrail_event_id)) {
            throw 'GT03 failed: positive CloudTrail attack eventID was reused across attack TAKEs.'
        }
        foreach ($sourceEventId in @($takeResult.gt02_source_event_ids)) {
            if (-not $gt02SourceEventIdSet.Add([string]$sourceEventId)) {
                throw 'GT02 failed: source event_id was reused across attack TAKEs.'
            }
        }
        foreach ($wazuhAlertId in @($takeResult.gt02_wazuh_alert_ids)) {
            if (-not $gt02WazuhAlertIdSet.Add([string]$wazuhAlertId)) {
                throw 'GT02 failed: Rule 100103 Wazuh alert ID was reused across attack TAKEs.'
            }
        }
        if (-not $gt03WazuhAlertIdSet.Add([string]$takeResult.gt03_wazuh_alert_id)) {
            throw 'GT03 failed: Rule 100104 Wazuh alert ID was reused across attack TAKEs.'
        }
        $normalResult = Invoke-GtNormalOperation -Take ([pscustomobject]@{
            take_id = $takeResult.take_id
            take_index = $index
        }) -NormalProvider $NormalProvider -BridgeEventProvider $BridgeEventProvider -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion -ClockSkewSeconds $ClockSkewSeconds -DeliveryGraceSeconds $DeliveryGraceSeconds
        $normalResults.Add($normalResult)
        $takeResults.Add($takeResult)
    }
    if ($observedTakeIdSet.Count -ne $expectedTakeIdSet.Count) {
        throw 'GT02/GT03 failed: observed TAKE_ID set does not equal the run-approved set.'
    }
    $negativeResults = [Collections.Generic.List[object]]::new()
    $negativeOperations = [Collections.Generic.List[object]]::new()
    $negativeBaselineValues = @(Invoke-GtProvider -Provider $BaselineProvider -ProviderName 'shared negative baseline' -Context ([pscustomobject]@{
        gate = 'GT03'; phase = 'gt03-negative-shared-baseline'; take_index = 0
    }))
    if ($negativeBaselineValues.Count -ne 1) {
        throw 'GT03 shared negative baseline provider must return exactly one baseline.'
    }
    foreach ($caseId in $script:GtNegativeCases) {
        $repeatCount = [int]$script:GtNegativeRepeatCounts[$caseId]
        for ($repeat = 1; $repeat -le $repeatCount; $repeat++) {
            $negativeContext = [pscustomobject][ordered]@{
                gate       = 'GT03'
                phase      = 'gt03-negative-operation'
                case_id    = $caseId
                repeat     = $repeat
                expected_account_id = $ExpectedAccountId
                expected_region     = $ExpectedRegion
                expected_role_name  = $ExpectedRoleName
                expected_bucket     = $ExpectedBucket
                expected_secondary_bucket = $ExpectedSecondaryBucket
                expected_secondary_object_key = $ExpectedSecondaryObjectKey
                expected_other_prefix_object_key = $ExpectedOtherPrefixObjectKey
                expected_other_principal_arn = $ExpectedOtherPrincipalArn
                expected_object_key = $ExpectedObjectKey
                take_index          = 0
            }
            $operationValues = @(Invoke-GtProvider -Provider $NegativeProvider -ProviderName "negative $caseId" -Context $negativeContext)
            if ($operationValues.Count -ne 1) {
                throw "GT03 blocked: negative case $caseId provider did not return exactly one operation result."
            }
            $supported = Get-GtProperty -Object $operationValues[0] -Names @('supported')
            if ($null -eq $supported -or [bool]$supported -ne $true) {
                throw "GT03 blocked: negative case $caseId lacks an independently runnable fixed fixture."
            }
            $operationStart = ConvertTo-GtUtc -Value (Get-GtProperty -Object $operationValues[0] -Names @('started_at_utc', 'event_time_utc')) -FieldName "negative.$caseId.started_at_utc"
            $operationEndValue = Get-GtProperty -Object $operationValues[0] -Names @('finished_at_utc', 'event_time_utc')
            $operationEnd = ConvertTo-GtUtc -Value $operationEndValue -FieldName "negative.$caseId.finished_at_utc"
            if ($operationEnd -lt $operationStart) {
                throw "GT03 blocked: negative case $caseId operation window is invalid."
            }
            $operationPrincipalArn = [string](Get-GtProperty -Object $operationValues[0] -Names @('principal_arn'))
            $isNodeSessionControl = $caseId -in @('other_bucket','other_prefix','failure')
            $expectedNodePrincipalPattern = '^arn:aws:sts::' + [regex]::Escape($ExpectedAccountId) +
                ':assumed-role/' + [regex]::Escape($ExpectedRoleName) + '/[^/]+$'
            $expectedOtherRoleName = ($ExpectedOtherPrincipalArn -split '/')[-1]
            $expectedOtherPrincipalPattern = '^arn:aws:sts::' + [regex]::Escape($ExpectedAccountId) +
                ':assumed-role/' + [regex]::Escape($expectedOtherRoleName) + '/[^/]+$'
            $isOtherPrincipalControl = $caseId -ceq 'other_principal'
            if (($isNodeSessionControl -and $operationPrincipalArn -notmatch $expectedNodePrincipalPattern) -or
                ($isOtherPrincipalControl -and $operationPrincipalArn -notmatch $expectedOtherPrincipalPattern) -or
                ($caseId -ceq 'normal_operator' -and -not [string]::IsNullOrWhiteSpace($operationPrincipalArn))) {
                throw "GT03 blocked: negative case $caseId operation principal correlation is invalid."
            }
            $negativeOperations.Add([pscustomobject][ordered]@{
                case_id = $caseId
                repeat = $repeat
                started_at_utc = $operationStart
                finished_at_utc = $operationEnd
                principal_arn = $operationPrincipalArn
            })
        }
    }
    $negativeExpectedTotal = [int](($script:GtNegativeRepeatCounts.Values | Measure-Object -Sum).Sum)
    if ($negativeOperations.Count -ne $negativeExpectedTotal) {
        throw 'GT03 contract failed: the Plan negative operation count drifted.'
    }
    $expectedNodePrincipalArns = @(
        $negativeOperations |
            Where-Object { $_.case_id -in @('other_bucket','other_prefix','failure') } |
            ForEach-Object { [string]$_.principal_arn } |
            Sort-Object -Unique
    )
    if ($expectedNodePrincipalArns.Count -ne 1) {
        throw 'GT03 blocked: Node Role controls do not share one exact assumed-role session.'
    }
    $expectedNodePrincipalArn = [string]$expectedNodePrincipalArns[0]
    $expectedOtherPrincipalSessionArns = @(
        $negativeOperations |
            Where-Object { $_.case_id -ceq 'other_principal' } |
            ForEach-Object { [string]$_.principal_arn } |
            Sort-Object -Unique
    )
    if ($expectedOtherPrincipalSessionArns.Count -ne 1) {
        throw 'GT03 blocked: other_principal does not expose one exact assumed-role session.'
    }
    $expectedOtherPrincipalSessionArn = [string]$expectedOtherPrincipalSessionArns[0]
    $negativeStart = @($negativeOperations.started_at_utc | Sort-Object)[0]
    $negativeFinish = @($negativeOperations.finished_at_utc | Sort-Object)[-1]
    $negativeBaseline = Get-GtBaseline -Value $negativeBaselineValues[0] -AttackStart $negativeStart
    $negativeWindowEnd = $negativeFinish.AddSeconds($DeliveryGraceSeconds)
    $negativeSharedContext = [pscustomobject][ordered]@{
        gate              = 'GT03'
        phase             = 'gt03-negative-shared'
        take_index        = 0
        started_at_utc    = $negativeStart
        finished_at_utc   = $negativeFinish
        window_start_utc  = $negativeStart.AddSeconds(-$ClockSkewSeconds)
        window_end_utc    = $negativeWindowEnd
        baseline          = $negativeBaseline
        rule_id           = '100104'
        expected_count    = $negativeExpectedTotal
        require_full_window = $false
        controls          = @($negativeOperations)
    }
    $negativeCloudTrailRaw = @(Invoke-GtProvider -Provider $CloudTrailProvider -ProviderName 'shared negative CloudTrail' -Context $negativeSharedContext)
    $negativeCloudTrail = Get-GtFreshRecords -Records $negativeCloudTrailRaw -BaselineIds $negativeBaseline.cloudtrail_event_ids -Label 'shared negative CloudTrail event' -Projection ${function:ConvertTo-GtCloudTrailProjection} -WindowStart $negativeStart -WindowEnd $negativeWindowEnd -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $negativeEvents = @($negativeCloudTrail.records)
    if ($negativeEvents.Count -ne $negativeExpectedTotal) {
        throw 'GT03 failed: shared negative CloudTrail cardinality differs from the Plan matrix.'
    }
    $eventsByCase = @{}
    foreach ($caseId in $script:GtNegativeCases) {
        $eventsByCase[$caseId] = [Collections.Generic.List[object]]::new()
    }
    foreach ($event in $negativeEvents) {
        $resolvedCase = Resolve-GtNegativeCaseId -Event $event -ExpectedAccountId $ExpectedAccountId -ExpectedRegion $ExpectedRegion -ExpectedRoleName $ExpectedRoleName -ExpectedBucket $ExpectedBucket -ExpectedSecondaryBucket $ExpectedSecondaryBucket -ExpectedSecondaryObjectKey $ExpectedSecondaryObjectKey -ExpectedOtherPrefixObjectKey $ExpectedOtherPrefixObjectKey -ExpectedNodePrincipalArn $expectedNodePrincipalArn -ExpectedOtherPrincipalArn $ExpectedOtherPrincipalArn -ExpectedOtherPrincipalSessionArn $expectedOtherPrincipalSessionArn -ExpectedObjectKey $ExpectedObjectKey
        $eventsByCase[$resolvedCase].Add($event)
    }
    foreach ($caseId in $script:GtNegativeCases) {
        $caseOperations = @($negativeOperations | Where-Object { $_.case_id -ceq $caseId } | Sort-Object started_at_utc, repeat)
        $caseEvents = @($eventsByCase[$caseId] | Sort-Object event_time_utc, id)
        if ($caseEvents.Count -ne [int]$script:GtNegativeRepeatCounts[$caseId]) {
            throw "GT03 failed: negative case $caseId count differs from the Plan matrix."
        }
        for ($index = 0; $index -lt $caseEvents.Count; $index++) {
            $eventUtc = ConvertTo-GtUtc -Value $caseEvents[$index].event_time_utc -FieldName "negative.$caseId.event_time_utc"
            if ($eventUtc -lt $caseOperations[$index].started_at_utc.AddSeconds(-$ClockSkewSeconds) -or
                $eventUtc -gt $caseOperations[$index].finished_at_utc.AddSeconds($DeliveryGraceSeconds)) {
                throw "GT03 failed: negative case $caseId event is outside its operation correlation window."
            }
            $negativeResults.Add([pscustomobject][ordered]@{
                case_id                    = $caseId
                repeat                     = [int]$caseOperations[$index].repeat
                cloudtrail_event_id        = [string]$caseEvents[$index].id
                cloudtrail_event_time_utc  = $eventUtc.ToString('o')
                cloudtrail_event_count     = 1
                rule100104_alert_count     = 0
                stale_cloudtrail_excluded  = $negativeCloudTrail.stale_count
                stale_rule100104_excluded  = 0
                observation_completed_at_utc = $null
            })
        }
    }

    $mutationStarts = @(
        $takeResults | ForEach-Object { $_.attack_started_at_utc }
        $normalResults | ForEach-Object { $_.operation_started_at_utc }
        $negativeOperations | ForEach-Object { $_.started_at_utc }
    )
    $mutationFinishes = @(
        $takeResults | ForEach-Object { $_.attack_finished_at_utc }
        $normalResults | ForEach-Object { $_.operation_finished_at_utc }
        $negativeOperations | ForEach-Object { $_.finished_at_utc }
    )
    $earliestMutationStart = @($mutationStarts | Sort-Object)[0]
    $latestMutationFinish = @($mutationFinishes | Sort-Object)[-1]
    $observationWindowStart = $earliestMutationStart.AddSeconds(-$ClockSkewSeconds)
    $runDeliveryDeadline = $latestMutationFinish.AddSeconds($DeliveryGraceSeconds)
    $runBaseline = Get-GtBaseline -Value $runBaselineValues[0] -AttackStart $earliestMutationStart

    $expectedAttackSourceIds = @($takeResults | ForEach-Object { $_.gt02_source_event_ids })
    $expectedNormalSourceIds = @($normalResults | ForEach-Object { $_.source_event_ids })
    $expectedRule103AlertIds = @($takeResults | ForEach-Object { $_.gt02_wazuh_alert_ids })
    $expectedPositiveCloudTrailIds = @($takeResults | ForEach-Object { $_.positive_cloudtrail_event_id })
    $expectedNegativeCloudTrailIds = @($negativeResults | ForEach-Object { $_.cloudtrail_event_id })
    $expectedRule104AlertIds = @($takeResults | ForEach-Object { $_.gt03_wazuh_alert_id })

    # One authoritative full-run set covers every operation from START_UTC to
    # the last delivery deadline.  It detects late arrivals that a narrow next
    # baseline could otherwise absorb, and proves all zero-alert controls in a
    # single bounded final quiescence window.
    $reconciliationContext = [pscustomobject][ordered]@{
        gate                = 'GT02-GT03'
        phase               = 'run-final-reconciliation'
        take_id             = ''
        take_index          = 0
        started_at_utc      = $earliestMutationStart
        finished_at_utc     = $latestMutationFinish
        window_start_utc    = $observationWindowStart
        window_end_utc      = $runDeliveryDeadline
        baseline            = $runBaseline
        rule_id             = '100104'
        expected_count      = $expectedRule104AlertIds.Count
        require_full_window = $true
    }

    # Rule 100104 is queried first so the live adapter performs the single
    # full-window wait before the remaining complete-set queries.
    $final104Raw = @(Invoke-GtProvider -Provider $WazuhAlertProvider -ProviderName 'final Rule 100104 reconciliation' -Context $reconciliationContext)
    $final104 = Get-GtFreshRecords -Records $final104Raw -BaselineIds $runBaseline.rule100104_alert_ids -Label 'final Rule 100104 alert' -Projection ${function:ConvertTo-GtRule100104Projection} -WindowStart $earliestMutationStart -WindowEnd $runDeliveryDeadline -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $final104Records = @($final104.records)
    Assert-GtExactStringSet -Actual @($final104Records | ForEach-Object { [string]$_.id }) -Expected $expectedRule104AlertIds -Label 'Rule 100104 alert'
    Assert-GtExactStringSet -Actual @($final104Records | ForEach-Object { [string]$_.event_id }) -Expected $expectedPositiveCloudTrailIds -Label 'Rule 100104 eventID'

    $reconciliationContext.rule_id = '100103'
    $reconciliationContext.expected_count = $expectedRule103AlertIds.Count
    $final103Raw = @(Invoke-GtProvider -Provider $WazuhAlertProvider -ProviderName 'final Rule 100103 reconciliation' -Context $reconciliationContext)
    $final103 = Get-GtFreshRecords -Records $final103Raw -BaselineIds $runBaseline.rule100103_alert_ids -Label 'final Rule 100103 alert' -Projection ${function:ConvertTo-GtRule100103Projection} -WindowStart $earliestMutationStart -WindowEnd $runDeliveryDeadline -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    $final103Records = @($final103.records)
    Assert-GtExactStringSet -Actual @($final103Records | ForEach-Object { [string]$_.id }) -Expected $expectedRule103AlertIds -Label 'Rule 100103 alert'
    Assert-GtExactStringSet -Actual @($final103Records | ForEach-Object { [string]$_.event_id }) -Expected $expectedAttackSourceIds -Label 'Rule 100103 eventID'

    $reconciliationContext.rule_id = ''
    $reconciliationContext.expected_count = $expectedAttackSourceIds.Count + $expectedNormalSourceIds.Count
    $finalBridgeRaw = @(Invoke-GtProvider -Provider $BridgeEventProvider -ProviderName 'final Bridge reconciliation' -Context $reconciliationContext)
    $finalBridge = Get-GtFreshRecords -Records $finalBridgeRaw -BaselineIds $runBaseline.bridge_event_ids -Label 'final Bridge event' -Projection ${function:ConvertTo-GtSourceProjection} -WindowStart $earliestMutationStart -WindowEnd $runDeliveryDeadline -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    Assert-GtExactStringSet -Actual @($finalBridge.records | ForEach-Object { [string]$_.id }) -Expected @($expectedAttackSourceIds + $expectedNormalSourceIds) -Label 'Bridge event'

    $reconciliationContext.expected_count = $expectedPositiveCloudTrailIds.Count + $expectedNegativeCloudTrailIds.Count
    $finalCloudTrailRaw = @(Invoke-GtProvider -Provider $CloudTrailProvider -ProviderName 'final CloudTrail reconciliation' -Context $reconciliationContext)
    $finalCloudTrail = Get-GtFreshRecords -Records $finalCloudTrailRaw -BaselineIds $runBaseline.cloudtrail_event_ids -Label 'final CloudTrail event' -Projection ${function:ConvertTo-GtCloudTrailProjection} -WindowStart $earliestMutationStart -WindowEnd $runDeliveryDeadline -ClockSkewSeconds $ClockSkewSeconds -RejectDuplicateIds
    Assert-GtExactStringSet -Actual @($finalCloudTrail.records | ForEach-Object { [string]$_.id }) -Expected @($expectedPositiveCloudTrailIds + $expectedNegativeCloudTrailIds) -Label 'CloudTrail eventID'

    $latestObservationEnd = [DateTimeOffset]::UtcNow
    foreach($normalResult in $normalResults){
        $normalResult.observation_completed_at_utc=$latestObservationEnd
    }
    foreach($negativeResult in $negativeResults){
        $negativeResult.observation_completed_at_utc=$latestObservationEnd
    }
    $runReconciliation = [pscustomobject][ordered]@{
        window_start_utc        = $observationWindowStart.ToString('o')
        delivery_deadline_utc   = $runDeliveryDeadline.ToString('o')
        completed_at_utc        = $latestObservationEnd.ToString('o')
        bridge_event_count      = @($finalBridge.records).Count
        rule100103_alert_count  = $final103Records.Count
        cloudtrail_event_count  = @($finalCloudTrail.records).Count
        rule100104_alert_count  = $final104Records.Count
        shared_negative_count   = $negativeExpectedTotal
        late_or_unexpected_count = 0
    }

    # Capture the after snapshot only after the complete run reconciliation.
    $sideAfterValues = @(Invoke-GtProvider -Provider $SideEffectProvider -ProviderName 'side-effect after' -Context ([pscustomobject]@{
        gate = 'GT02-GT03'; phase = 'side-effect-after'; take_index = $TakeCount; take_count = $TakeCount
        window_start_utc = $observationWindowStart; window_end_utc = $latestObservationEnd
    }))
    if ($sideAfterValues.Count -ne 1) {
        throw 'GT02 automatic response proof failed: side-effect after provider must return exactly one snapshot.'
    }
    $sideAfter = ConvertTo-GtSideEffectSnapshot -Snapshot $sideAfterValues[0]
    Assert-GtSideEffectCoverage -Before $sideBefore -After $sideAfter -EarliestMutationStart $earliestMutationStart -ObservationWindowStart $observationWindowStart -LatestObservationEnd $latestObservationEnd
    $sideCounts = Compare-GtSideEffectSnapshots -Before $sideBefore -After $sideAfter
    $sideEffectResults.Add([pscustomobject][ordered]@{
        scope = 'all_takes'
        observation_window_start_utc = $observationWindowStart.ToString('o')
        observation_window_end_utc = $latestObservationEnd.ToString('o')
        baseline_captured_at_utc = $sideBefore.captured_at_utc.ToString('o')
        baseline_window_start_utc = $sideBefore.window_start_utc.ToString('o')
        baseline_window_end_utc = $sideBefore.window_end_utc.ToString('o')
        after_captured_at_utc = $sideAfter.captured_at_utc.ToString('o')
        after_window_start_utc = $sideAfter.window_start_utc.ToString('o')
        after_window_end_utc = $sideAfter.window_end_utc.ToString('o')
        source_ids = @($sideAfter.source_ids)
        shuffle_execution_count = $sideCounts.shuffle_execution_ids
        github_run_count = $sideCounts.github_run_ids
        quarantine_mutation_count = $sideCounts.quarantine_mutation_ids
        validation_mutation_count = $sideCounts.validation_mutation_ids
    })

    $summary = [pscustomobject][ordered]@{
        status                    = 'CONTRACT_TEST_PASS'
        execution_mode            = 'contract_test'
        provider_provenance       = 'generic-injected-provider'
        gate02                    = 'NOT_RUN'
        gate03                    = 'NOT_RUN'
        take_count               = $takeResults.Count
        negative_case_count      = $script:GtNegativeCases.Count
        negative_operation_count = $negativeExpectedTotal
        negative_expected_counts = [pscustomobject]$script:GtNegativeRepeatCounts
        source_event_counts      = @($takeResults | ForEach-Object { $_.source_event_count })
        rule100103_alert_counts  = @($takeResults | ForEach-Object { $_.rule100103_alert_count })
        normal_source_event_counts = @($normalResults | ForEach-Object { $_.source_event_count })
        normal_rule100103_alert_counts = @($normalResults | ForEach-Object { $_.rule100103_alert_count })
        positive_alert_count     = @($takeResults | Where-Object { $_.rule100104_alert_count -eq 1 }).Count
        negative_alert_count     = @($negativeResults | Where-Object { $_.rule100104_alert_count -ne 0 }).Count
        automatic_response_side_effects = @($sideEffectResults)
        latencies_seconds        = @($takeResults | ForEach-Object { $_.latency_seconds })
        take_evidence             = @($takeResults | ForEach-Object { $_.evidence })
        run_reconciliation        = $runReconciliation
        stale_excluded_count     = [int]((@($takeResults | ForEach-Object {
            $_.stale_bridge_excluded + $_.stale_rule100103_excluded +
            $_.stale_cloudtrail_excluded + $_.stale_rule100104_excluded
        }) | Measure-Object -Sum).Sum +
            (@($normalResults | ForEach-Object { $_.stale_bridge_excluded }) | Measure-Object -Sum).Sum +
            $negativeCloudTrail.stale_count)
        negative_results          = @($negativeResults)
        automatic_response_side_effect_count = [int](@($sideEffectResults | ForEach-Object {
            $_.shuffle_execution_count + $_.github_run_count +
            $_.quarantine_mutation_count + $_.validation_mutation_count
        }) | Measure-Object -Sum).Sum
    }
    if ([int]$summary.automatic_response_side_effect_count -ne 0) {
        throw 'GT02 automatic response proof failed: a side-effect count was non-zero.'
    }
    Write-Host ("GT02/GT03 CONTRACT_TEST_PASS: takes={0}; positive_rule100104={1}/{0}; normal_rule100103=0/{0}; negative_rule100104={2}; automatic_response_side_effects={3}" -f $summary.take_count, $summary.positive_alert_count, $summary.negative_alert_count, $summary.automatic_response_side_effect_count)
    return $summary
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CapitalOneGt02Gt03Runtime @PSBoundParameters
}
