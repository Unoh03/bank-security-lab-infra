#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runnerPath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneGt02Gt03Runtime.ps1'
if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
    throw 'GT02/GT03 runtime runner is missing.'
}

$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $runnerPath,
    [ref]$tokens,
    [ref]$errors
)
if (@($errors).Count -ne 0) {
    throw ('GT02/GT03 runner parser errors: ' + (@($errors.Message) -join '; '))
}

$runnerText = Get-Content -LiteralPath $runnerPath -Raw -Encoding UTF8
$executableText = [regex]::Replace($runnerText, '(?ms)<#.*?#>', '')
$executableText = [regex]::Replace($executableText, '(?m)^\s*#.*$', '')
foreach ($forbidden in @(
    'Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-NativeCapture',
    'Start-Process', 'ConvertTo-Json',
    'WriteAllText', 'Set-Content', 'Add-Content', 'Out-File',
    'Invoke-CapitalOneBaseline', 'Test-SocRule100103Rehearsal',
    'Invoke-SocRule100103DynamicObserveOnly'
)) {
    if ($executableText -match [regex]::Escape($forbidden)) {
        throw "GT02/GT03 runner contains a forbidden direct/runtime or durable-write dependency: $forbidden"
    }
}
foreach ($required in @(
    'TakeProvider', 'BaselineProvider', 'AttackProvider',
    'BridgeEventProvider', 'WazuhAlertProvider', 'CloudTrailProvider',
    'NegativeProvider', 'NormalProvider', 'SideEffectProvider',
    'normal_operator', 'other_bucket', 'other_prefix',
    'other_principal', 'failure', 'stale_count', 'latency_seconds'
)) {
    if ($runnerText -notmatch [regex]::Escape($required)) {
        throw "GT02/GT03 runner is missing the required contract marker: $required"
    }
}
if ($executableText -match '(?i)full_log|secret|credential|webhook') {
    throw 'GT02/GT03 runner must not handle raw secrets or webhook material.'
}

. $runnerPath

$script:gtMockExpectedBucket = 'capital-one-primary-bucket'
$script:gtMockExpectedSecondaryBucket = 'capital-one-secondary-control-bucket'
$script:gtMockExpectedOtherPrefixObjectKey = 'other-prefix/capital-one-demo.csv'
$script:gtMockExpectedOtherPrincipalArn = 'arn:aws:iam::433048100798:role/aws-topology-capital-one-negative-control'
$script:gtMockTakeCalls = 0
$script:gtMockAttackCalls = 0
$script:gtMockFail = $false
$script:gtMockDuplicateSource = $false
$script:gtMockDuplicateAlert = $false
$script:gtMockDuplicatePositiveEventId = $false
$script:gtMockCrossTakeSourceEventId = $false
$script:gtMockCrossTakeRule103AlertId = $false
$script:gtMockCrossTakeRule104AlertId = $false
$script:gtMockUnsupportedCase = ''
$script:gtMockNormalAlert = $false
$script:gtMockLateFinalRule104Alert = $false
$script:gtMockOmitFailureFromFinal = $false
$script:gtMockOtherPrefixWrongPrincipal = $false
$script:gtMockOtherPrefixWrongSession = $false
$script:gtMockFailureWrongError = $false
$script:gtMockOperationPrincipalDrift = $false
$script:gtMockOtherPrincipalWrongSession = $false
$script:gtMockSideEffectDelta = $false
$script:gtMockSideEffectWrongSource = $false
$script:gtMockSideEffectNarrowWindow = $false
$script:gtMockSideEffectLateBaseline = $false
$script:gtMockSideEffectCalls = 0
$script:gtMockProviderCalls = [Collections.Generic.List[string]]::new()

function Get-GtMockTime {
    param([Parameter(Mandatory)][int]$TakeIndex)
    return [DateTimeOffset]::Parse(
        ('2026-08-20T10:{0:D2}:00Z' -f (($TakeIndex - 1) * 10)),
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-GtMockHash {
    param([Parameter(Mandatory)][int]$Number)
    return ('{0:x64}' -f $Number)
}

function New-GtMockTakeId {
    param([Parameter(Mandatory)][int]$TakeIndex)
    return ('capital-one-20260820T10{0:D4}Z-{1:D8}' -f (($TakeIndex - 1) * 10), $TakeIndex)
}

$takeProvider = {
    param($context)
    $script:gtMockTakeCalls++
    [pscustomobject]@{ take_id = New-GtMockTakeId -TakeIndex ([int]$context.take_index) }
}

$baselineProvider = {
    param($context)
    $baselineIndex = [int]$context.take_index
    $start = if ($baselineIndex -eq 0) { [DateTimeOffset]::Parse('2026-08-20T09:59:00Z') } else { Get-GtMockTime -TakeIndex $baselineIndex }
    [pscustomobject]@{
        captured_at_utc       = $start.AddSeconds(-2).ToString('o')
        quiescence_proven     = $true
        bridge_event_ids      = @("stale-bridge-$($context.take_index)")
        rule100103_alert_ids  = @("stale-100103-$($context.take_index)")
        rule100104_alert_ids  = @("stale-100104-$($context.take_index)")
        cloudtrail_event_ids  = @('00000000-0000-4000-8000-000000000000')
    }
}

$attackProvider = {
    param($context)
    $script:gtMockAttackCalls++
    if ($script:gtMockFail) {
        throw 'mock attack failure'
    }
    $start = Get-GtMockTime -TakeIndex ([int]$context.take_index)
    [pscustomobject]@{
        started_at_utc  = $start.ToString('o')
        finished_at_utc = $start.AddSeconds(4).ToString('o')
    }
}

$normalProvider = {
    param($context)
    $start = (Get-GtMockTime -TakeIndex ([int]$context.take_index)).AddSeconds(20)
    [pscustomobject]@{
        supported = $true
        started_at_utc = $start.ToString('o')
        finished_at_utc = $start.AddSeconds(2).ToString('o')
        baseline = [pscustomobject]@{
            captured_at_utc = $start.AddSeconds(-2).ToString('o')
            quiescence_proven = $true
            bridge_event_ids = @("stale-normal-bridge-$($context.take_index)")
            rule100103_alert_ids = @("stale-normal-100103-$($context.take_index)")
            rule100104_alert_ids = @()
            cloudtrail_event_ids = @()
        }
    }
}

$sideEffectProvider = {
    param($context)
    $script:gtMockSideEffectCalls++
    $index = [int]$context.take_index
    $base = Get-GtMockTime -TakeIndex $index
    $isAfter = [string]$context.phase -eq 'side-effect-after'
    $windowStart = if ($isAfter) { [DateTimeOffset]$context.window_start_utc } else { $base.AddSeconds(-600) }
    $windowEnd = if ($isAfter) { [DateTimeOffset]$context.window_end_utc } else { $base.AddSeconds(-3) }
    if ($script:gtMockSideEffectLateBaseline -and -not $isAfter) {
        $windowEnd = $base.AddSeconds(1)
    }
    if ($script:gtMockSideEffectNarrowWindow -and $isAfter) {
        $windowStart = $windowStart.AddSeconds(1)
        $windowEnd = $windowEnd.AddSeconds(-1)
    }
    $captured = if ($isAfter) {
        $windowEnd.AddSeconds(1)
    } elseif ($script:gtMockSideEffectLateBaseline) {
        $base.AddSeconds(2)
    } else {
        $base.AddSeconds(-2)
    }
    $sourceIds = @('shuffle-state', 'github-state', 'dvwa-quarantine-state', 'validation-state')
    if ($script:gtMockSideEffectWrongSource -and $isAfter) {
        $sourceIds = @('shuffle-state', 'github-state', 'dvwa-quarantine-state', 'wrong-state')
    }
    $snapshot = [ordered]@{
        read_only = $true
        captured_at_utc = $captured.ToString('o')
        window_start_utc = $windowStart.ToString('o')
        window_end_utc = $windowEnd.ToString('o')
        source_ids = $sourceIds
        # A pre-existing execution must not be counted as an automatic side
        # effect when the after snapshot is unchanged.
        shuffle_execution_ids = @('existing-execution')
        github_run_ids = @()
        quarantine_mutation_ids = @()
        validation_mutation_ids = @()
    }
    if ($script:gtMockSideEffectDelta -and [string]$context.phase -eq 'side-effect-after') {
        $snapshot.shuffle_execution_ids = @('existing-execution','execution-new')
    }
    return [pscustomobject]$snapshot
}

$bridgeProvider = {
    param($context)
    $script:gtMockProviderCalls.Add('bridge:'+[string]$context.phase)
    $index = [int]$context.take_index
    $start = [DateTimeOffset]$context.started_at_utc
    if ([string]$context.phase -eq 'run-final-reconciliation') {
        $records = [Collections.Generic.List[object]]::new()
        foreach ($takeIndex in 1..3) {
            $takeStart = Get-GtMockTime -TakeIndex $takeIndex
            $takeId = New-GtMockTakeId -TakeIndex $takeIndex
            foreach ($eventNumber in 1..2) {
                $records.Add([pscustomobject]@{
                    event_id = "cwl:mock:${takeIndex}:${eventNumber}"
                    event_time = $takeStart.AddSeconds($eventNumber).ToString('o')
                    source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
                    raw_message_sha256 = (Get-GtMockHash -Number ($takeIndex * 10 + $eventNumber))
                    payload = [pscustomobject]@{
                        take_id = $takeId; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
                        route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='ec2_imds';action='shell_command';security_level='low'}
                    }
                })
            }
            $normalStart = $takeStart.AddSeconds(20)
            $records.Add([pscustomobject]@{
                event_id = "cwl:normal:$takeIndex"
                event_time = $normalStart.AddSeconds(1).ToString('o')
                source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
                raw_message_sha256 = (Get-GtMockHash -Number (3000 + $takeIndex))
                payload = [pscustomobject]@{
                    take_id = $takeId; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
                    route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='other';action='shell_command';security_level='low'}
                }
            })
        }
        return @($records)
    }
    if ([string]$context.phase -eq 'gt02-normal') {
        return @(
            [pscustomobject]@{
                event_id = "stale-normal-bridge-$index"
                event_time = $start.AddSeconds(-1).ToString('o')
                source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
                raw_message_sha256 = (Get-GtMockHash -Number (300 + $index))
                payload = [pscustomobject]@{
                    take_id = $context.take_id; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
                    route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='other';action='shell_command';security_level='low'}
                }
            }
            [pscustomobject]@{
                event_id = "cwl:normal:$index"
                event_time = $start.AddSeconds(1).ToString('o')
                source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
                raw_message_sha256 = (Get-GtMockHash -Number (3000 + $index))
                payload = [pscustomobject]@{
                    take_id = $context.take_id; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
                    route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='other';action='shell_command';security_level='low'}
                }
            }
        )
    }
    $stale = [pscustomobject]@{
        event_id = "stale-bridge-$index"
        event_time = $start.AddSeconds(-1).ToString('o')
        source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
        raw_message_sha256 = (Get-GtMockHash -Number (100 + $index))
        payload = [pscustomobject]@{
            take_id = $context.take_id; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
            route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='ec2_imds';action='shell_command';security_level='low'}
        }
    }
    $events = [Collections.Generic.List[object]]::new()
    $events.Add($stale)
    $eventIndex = if ($script:gtMockCrossTakeSourceEventId -and $index -eq 2) { 1 } else { $index }
    for ($eventNumber = 1; $eventNumber -le 2; $eventNumber++) {
        $events.Add([pscustomobject]@{
            event_id = "cwl:mock:${eventIndex}:${eventNumber}"
            event_time = $start.AddSeconds($eventNumber).ToString('o')
            source = 'dvwa'; transport = 'push'; aws_account_id = '433048100798'; aws_region = 'ap-northeast-2'
            raw_message_sha256 = (Get-GtMockHash -Number ($eventIndex * 10 + $eventNumber))
            payload = [pscustomobject]@{
                take_id = $context.take_id; normalized = $true; event_type = 'command.execution'; result = 'succeeded'
                route = '/vulnerabilities/exec/'; context = [pscustomobject]@{resource='ec2_imds';action='shell_command';security_level='low'}
            }
        })
    }
    if ($script:gtMockDuplicateSource -and $index -eq 1) {
        $events.Add($events[1])
    }
    return @($events)
}

function New-GtMockRule103Alert {
    param(
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$EventId,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$EventTime,
        [Parameter(Mandatory)][string]$AlertTime,
        [Parameter(Mandatory)][string]$Hash,
        [string]$Resource = 'ec2_imds'
    )
    return [pscustomobject]@{
        _id = $AlertId
        _source = [pscustomobject]@{
            timestamp = $AlertTime
            rule = [pscustomobject]@{id='100103';level=10}
            data = [pscustomobject]@{
                source = 'dvwa'; aws_account_id='433048100798'; aws_region='ap-northeast-2'
                event_id = $EventId; event_time_utc = $EventTime; raw_message_sha256 = $Hash
                payload = [pscustomobject]@{
                    take_id = $TakeId; event_type='command.execution'; result='succeeded'; route='/vulnerabilities/exec/'
                    context = [pscustomobject]@{resource=$Resource}
                }
            }
        }
    }
}

function New-GtMockRule104Alert {
    param(
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$EventId,
        [Parameter(Mandatory)][string]$EventTime,
        [Parameter(Mandatory)][string]$AlertTime
    )
    return [pscustomobject]@{
        _id = $AlertId
        _source = [pscustomobject]@{
            timestamp = $AlertTime
            rule = [pscustomobject]@{id='100104';level=12}
            data = [pscustomobject]@{
                aws = [pscustomobject]@{
                    source='cloudtrail'; eventSource='s3.amazonaws.com'; eventName='GetObject'
                    eventID=$EventId; eventTime=$EventTime; recipientAccountId='433048100798'; awsRegion='ap-northeast-2'
                    requestParameters=[pscustomobject]@{bucketName=$script:gtMockExpectedBucket;key='validation/capital-one-demo.csv'}
                    userIdentity=[pscustomobject]@{
                        type='AssumedRole'; sessionContext=[pscustomobject]@{
                            sessionIssuer=[pscustomobject]@{userName='aws-topology-primary-karpenter-node'}
                        }
                    }
                    additionalEventData=[pscustomobject]@{httpStatusCode=200}; errorCode=''
                }
            }
        }
    }
}

function New-GtMockNegativeCloudTrailEvent {
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][int]$Repeat,
        [Parameter(Mandatory)][DateTimeOffset]$EventTime
    )
    $bucket = $script:gtMockExpectedBucket
    $key = 'validation/capital-one-demo.csv'
    $role = 'terra-user'
    $principalArn = 'arn:aws:iam::433048100798:user/terra-user'
    $sessionIssuerArn = ''
    $http = '200'; $error = ''
    switch ($CaseId) {
        'normal_operator' { }
        'other_bucket' {
            $bucket = $script:gtMockExpectedSecondaryBucket
            $role = 'aws-topology-primary-karpenter-node'
            $principalArn = 'arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/mock-session'
            $sessionIssuerArn = 'arn:aws:iam::433048100798:role/aws-topology-primary-karpenter-node'
        }
        'other_prefix' {
            $key = $script:gtMockExpectedOtherPrefixObjectKey
            $role = 'aws-topology-primary-karpenter-node'
            $principalArn = 'arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/mock-session'
            $sessionIssuerArn = 'arn:aws:iam::433048100798:role/aws-topology-primary-karpenter-node'
            if($script:gtMockOtherPrefixWrongPrincipal){
                $role='terra-user';$principalArn='arn:aws:iam::433048100798:user/terra-user';$sessionIssuerArn=''
            }elseif($script:gtMockOtherPrefixWrongSession){
                $principalArn='arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/unrelated-session'
            }
        }
        'other_principal' {
            $role = 'aws-topology-capital-one-negative-control'
            $sessionName=if($script:gtMockOtherPrincipalWrongSession){'unrelated-session'}else{'mock-other-session'}
            $principalArn = "arn:aws:sts::433048100798:assumed-role/aws-topology-capital-one-negative-control/$sessionName"
            $sessionIssuerArn = $script:gtMockExpectedOtherPrincipalArn
        }
        'failure' {
            $role = 'aws-topology-primary-karpenter-node'
            $principalArn = 'arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/mock-session'
            $sessionIssuerArn = 'arn:aws:iam::433048100798:role/aws-topology-primary-karpenter-node'
            $http = '412'; $error = if($script:gtMockFailureWrongError){'AccessDenied'}else{'PreconditionFailed'}
        }
        default { throw 'unknown negative fixture' }
    }
    $number = 100 + $Repeat + [array]::IndexOf($script:GtNegativeCases, $CaseId) * 10
    return [pscustomobject]@{
        event_id=('{0:D8}-0000-4000-8000-{0:D12}' -f $number)
        event_time_utc=$EventTime.ToString('o'); event_source='s3.amazonaws.com'; event_name='GetObject'
        account_id='433048100798'; region='ap-northeast-2'; role_name=$role; principal_arn=$principalArn; session_issuer_arn=$sessionIssuerArn; bucket=$bucket; object_key=$key
        http_status=$http; error_code=$error
    }
}

$wazuhProvider = {
    param($context)
    $script:gtMockProviderCalls.Add('wazuh:'+[string]$context.phase)
    $index = [int]$context.take_index
    $start = [DateTimeOffset]$context.started_at_utc
    if ([string]$context.phase -eq 'run-final-reconciliation') {
        $records = [Collections.Generic.List[object]]::new()
        if ([string]$context.rule_id -eq '100103') {
            foreach ($takeIndex in 1..3) {
                $takeStart = Get-GtMockTime -TakeIndex $takeIndex
                $takeId = New-GtMockTakeId -TakeIndex $takeIndex
                foreach ($eventNumber in 1..2) {
                    $records.Add((New-GtMockRule103Alert -AlertId "alert-100103-$takeIndex-$eventNumber" -EventId "cwl:mock:${takeIndex}:${eventNumber}" -TakeId $takeId -EventTime $takeStart.AddSeconds($eventNumber).ToString('o') -AlertTime $takeStart.AddSeconds($eventNumber + 1).ToString('o') -Hash (Get-GtMockHash -Number ($takeIndex * 10 + $eventNumber))))
                }
                if ($script:gtMockNormalAlert) {
                    $normalStart = $takeStart.AddSeconds(20)
                    $records.Add((New-GtMockRule103Alert -AlertId "alert-normal-100103-$takeIndex" -EventId "cwl:normal:$takeIndex" -TakeId $takeId -EventTime $normalStart.AddSeconds(1).ToString('o') -AlertTime $normalStart.AddSeconds(2).ToString('o') -Hash (Get-GtMockHash -Number (3000 + $takeIndex)) -Resource 'other'))
                }
            }
            return @($records)
        }
        if ([string]$context.rule_id -eq '100104') {
            foreach ($takeIndex in 1..3) {
                $takeStart = Get-GtMockTime -TakeIndex $takeIndex
                $eventId = ('{0:D8}-0000-4000-8000-{0:D12}' -f $takeIndex)
                $records.Add((New-GtMockRule104Alert -AlertId "alert-100104-$takeIndex" -EventId $eventId -EventTime $takeStart.AddSeconds(3).ToString('o') -AlertTime $takeStart.AddSeconds(4).ToString('o')))
            }
            if ($script:gtMockLateFinalRule104Alert) {
                $lateTime = [DateTimeOffset]::Parse('2026-08-20T12:05:02Z')
                $records.Add((New-GtMockRule104Alert -AlertId 'late-unexpected-100104' -EventId '90000000-0000-4000-8000-000000000900' -EventTime $lateTime.ToString('o') -AlertTime $lateTime.AddSeconds(1).ToString('o')))
            }
            return @($records)
        }
    }
    if ([string]$context.phase -eq 'gt02-normal' -and [string]$context.rule_id -eq '100103') {
        $records = [Collections.Generic.List[object]]::new()
        $records.Add((New-GtMockRule103Alert -AlertId "stale-normal-100103-$index" -EventId "stale-normal-bridge-$index" -TakeId $context.take_id -EventTime $start.AddSeconds(-1).ToString('o') -AlertTime $start.AddSeconds(-1).ToString('o') -Hash (Get-GtMockHash -Number (300 + $index)) -Resource 'other'))
        if ($script:gtMockNormalAlert) {
            $records.Add((New-GtMockRule103Alert -AlertId "alert-normal-100103-$index" -EventId "cwl:normal:$index" -TakeId $context.take_id -EventTime $start.AddSeconds(1).ToString('o') -AlertTime $start.AddSeconds(2).ToString('o') -Hash (Get-GtMockHash -Number (3000 + $index)) -Resource 'other'))
        }
        return @($records)
    }
    if ([string]$context.phase -eq 'gt02' -and [string]$context.rule_id -eq '100103') {
        $records = [Collections.Generic.List[object]]::new()
        $records.Add((New-GtMockRule103Alert -AlertId "stale-100103-$index" -EventId "stale-bridge-$index" -TakeId $context.take_id -EventTime $start.AddSeconds(-1).ToString('o') -AlertTime $start.AddSeconds(-1).ToString('o') -Hash (Get-GtMockHash -Number (100 + $index))))
        $eventIndex = if ($script:gtMockCrossTakeSourceEventId -and $index -eq 2) { 1 } else { $index }
        $alertIndex = if ($script:gtMockCrossTakeRule103AlertId -and $index -eq 2) { 1 } else { $index }
        for ($eventNumber = 1; $eventNumber -le 2; $eventNumber++) {
            $records.Add((New-GtMockRule103Alert -AlertId "alert-100103-$alertIndex-$eventNumber" -EventId "cwl:mock:${eventIndex}:${eventNumber}" -TakeId $context.take_id -EventTime $start.AddSeconds($eventNumber).ToString('o') -AlertTime $start.AddSeconds($eventNumber + 1).ToString('o') -Hash (Get-GtMockHash -Number ($eventIndex * 10 + $eventNumber))))
        }
        if ($script:gtMockDuplicateAlert -and $index -eq 1) {
            $records.Add($records[1])
        }
        return @($records)
    }
    if ([string]$context.phase -eq 'gt03-positive' -and [string]$context.rule_id -eq '100104') {
        $eventIdIndex = if ($script:gtMockDuplicatePositiveEventId -and $index -eq 2) { 1 } else { $index }
        $eventId = ('{0:D8}-0000-4000-8000-{0:D12}' -f $eventIdIndex)
        $alertIndex = if ($script:gtMockCrossTakeRule104AlertId -and $index -eq 2) { 1 } else { $index }
        return @(
            (New-GtMockRule104Alert -AlertId "stale-100104-$index" -EventId '00000000-0000-4000-8000-000000000000' -EventTime $start.AddSeconds(-1).ToString('o') -AlertTime $start.AddSeconds(-1).ToString('o')),
            (New-GtMockRule104Alert -AlertId "alert-100104-$alertIndex" -EventId $eventId -EventTime $start.AddSeconds(3).ToString('o') -AlertTime $start.AddSeconds(4).ToString('o'))
        )
    }
    if ([string]$context.phase -eq 'gt03-negative' -and [string]$context.rule_id -eq '100104') {
        $negativeIndex = ([array]::IndexOf($script:GtNegativeCases, [string]$context.case_id) * 10) + [int]$context.repeat
        $negativeTime = [DateTimeOffset]$context.event_time_utc
        return @(
            (New-GtMockRule104Alert -AlertId "stale-negative-100104-$negativeIndex" -EventId "00000000-0000-4000-8000-000000000000" -EventTime $negativeTime.AddSeconds(-1).ToString('o') -AlertTime $negativeTime.AddSeconds(-1).ToString('o'))
        )
    }
    throw 'mock Wazuh phase was not recognized'
}

$cloudTrailProvider = {
    param($context)
    $script:gtMockProviderCalls.Add('cloudtrail:'+[string]$context.phase)
    if ([string]$context.phase -eq 'gt03-positive') {
        $index = [int]$context.take_index
        $start = [DateTimeOffset]$context.started_at_utc
        $eventIdIndex = if ($script:gtMockDuplicatePositiveEventId -and $index -eq 2) { 1 } else { $index }
        $eventId = ('{0:D8}-0000-4000-8000-{0:D12}' -f $eventIdIndex)
        return @(
            [pscustomobject]@{
                event_id='00000000-0000-4000-8000-000000000000'; event_time_utc=$start.AddSeconds(-1).ToString('o'); event_source='s3.amazonaws.com'; event_name='GetObject'
                account_id='433048100798'; region='ap-northeast-2'; role_name='aws-topology-primary-karpenter-node'
                bucket=$script:gtMockExpectedBucket; object_key='validation/capital-one-demo.csv'; http_status='200'; error_code=''
            }
            [pscustomobject]@{
                event_id=$eventId; event_time_utc=$start.AddSeconds(3).ToString('o'); event_source='s3.amazonaws.com'; event_name='GetObject'
                account_id='433048100798'; region='ap-northeast-2'; role_name='aws-topology-primary-karpenter-node'
                bucket=$script:gtMockExpectedBucket; object_key='validation/capital-one-demo.csv'; http_status='200'; error_code=''
            }
        )
    }
    if ([string]$context.phase -eq 'gt03-negative-shared') {
        $records = [Collections.Generic.List[object]]::new()
        $records.Add([pscustomobject]@{
            event_id='00000000-0000-4000-8000-000000000000';event_time_utc=([DateTimeOffset]$context.started_at_utc).AddSeconds(-1).ToString('o')
            event_source='s3.amazonaws.com';event_name='GetObject';account_id='433048100798';region='ap-northeast-2'
            role_name='terra-user';bucket=$script:gtMockExpectedBucket;object_key='validation/capital-one-demo.csv';http_status='200';error_code=''
        })
        foreach ($control in @($context.controls)) {
            $records.Add((New-GtMockNegativeCloudTrailEvent -CaseId ([string]$control.case_id) -Repeat ([int]$control.repeat) -EventTime ([DateTimeOffset]$control.started_at_utc)))
        }
        return @($records)
    }
    if ([string]$context.phase -eq 'run-final-reconciliation') {
        $records = [Collections.Generic.List[object]]::new()
        foreach ($takeIndex in 1..3) {
            $takeStart=Get-GtMockTime -TakeIndex $takeIndex
            $records.Add([pscustomobject]@{
                event_id=('{0:D8}-0000-4000-8000-{0:D12}' -f $takeIndex);event_time_utc=$takeStart.AddSeconds(3).ToString('o')
                event_source='s3.amazonaws.com';event_name='GetObject';account_id='433048100798';region='ap-northeast-2'
                role_name='aws-topology-primary-karpenter-node';bucket=$script:gtMockExpectedBucket;object_key='validation/capital-one-demo.csv';http_status='200';error_code=''
            })
        }
        foreach ($caseId in $script:GtNegativeCases) {
            if($script:gtMockOmitFailureFromFinal -and $caseId -ceq 'failure'){continue}
            foreach ($repeat in 1..([int]$script:GtNegativeRepeatCounts[$caseId])) {
                $time=[DateTimeOffset]::Parse('2026-08-20T12:00:00Z').AddMinutes(([array]::IndexOf($script:GtNegativeCases,$caseId)*10)+$repeat)
                $records.Add((New-GtMockNegativeCloudTrailEvent -CaseId $caseId -Repeat $repeat -EventTime $time))
            }
        }
        return @($records)
    }
    throw 'mock CloudTrail phase was not recognized'
}

$negativeProvider = {
    param($context)
    if ($script:gtMockUnsupportedCase -ceq [string]$context.case_id) {
        return [pscustomobject]@{supported=$false; event_time_utc='2026-08-20T10:00:00Z'}
    }
    $base = [DateTimeOffset]::Parse('2026-08-20T12:00:00Z').AddMinutes(
        ([array]::IndexOf($script:GtNegativeCases, [string]$context.case_id) * 10) + [int]$context.repeat
    )
    $principalArn=''
    if([string]$context.case_id -in @('other_bucket','other_prefix','failure')){
        $principalArn='arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/mock-session'
    }elseif([string]$context.case_id -ceq 'other_principal'){
        $principalArn='arn:aws:sts::433048100798:assumed-role/aws-topology-capital-one-negative-control/mock-other-session'
    }
    if($script:gtMockOperationPrincipalDrift -and [string]$context.case_id -ceq 'failure'){
        $principalArn='arn:aws:sts::433048100798:assumed-role/aws-topology-primary-karpenter-node/drift-session'
    }
    return [pscustomobject]@{
        supported=$true
        started_at_utc=$base.ToString('o')
        finished_at_utc=$base.AddSeconds(1).ToString('o')
        principal_arn=$principalArn
    }
}

$expectedTakeIds = @(1..3 | ForEach-Object { New-GtMockTakeId -TakeIndex $_ })
$common = @{
    TakeCount = 3
    ExpectedTakeIds = $expectedTakeIds
    ExpectedBucket = $script:gtMockExpectedBucket
    ExpectedSecondaryBucket = $script:gtMockExpectedSecondaryBucket
    ExpectedSecondaryObjectKey = 'validation/capital-one-demo.csv'
    ExpectedOtherPrefixObjectKey = $script:gtMockExpectedOtherPrefixObjectKey
    ExpectedOtherPrincipalArn = $script:gtMockExpectedOtherPrincipalArn
    TakeProvider = $takeProvider
    BaselineProvider = $baselineProvider
    AttackProvider = $attackProvider
    BridgeEventProvider = $bridgeProvider
    WazuhAlertProvider = $wazuhProvider
    CloudTrailProvider = $cloudTrailProvider
    NegativeProvider = $negativeProvider
    NormalProvider = $normalProvider
    SideEffectProvider = $sideEffectProvider
}

$contractInformation = @()
$result = Invoke-CapitalOneGt02Gt03Runtime @common -InformationVariable contractInformation
if ([string]$result.status -cne 'CONTRACT_TEST_PASS' -or
    [string]$result.execution_mode -cne 'contract_test' -or
    [string]$result.provider_provenance -cne 'generic-injected-provider' -or
    [string]$result.gate02 -cne 'NOT_RUN' -or
    [string]$result.gate03 -cne 'NOT_RUN' -or
    [int]$result.take_count -ne 3 -or
    [int]$result.positive_alert_count -ne 3 -or
    [int]$result.negative_alert_count -ne 0 -or
    [int]$result.automatic_response_side_effect_count -ne 0 -or
    @($result.latencies_seconds).Count -ne 3 -or
    @($result.negative_results).Count -ne 7 -or
    @($result.normal_source_event_counts).Count -ne 3 -or
    @($result.normal_rule100103_alert_counts).Count -ne 3 -or
    @($result.automatic_response_side_effects).Count -ne 1) {
    throw 'GT02/GT03 mock success contract did not pass.'
}
if ([int]$result.negative_operation_count -ne 7 -or
    [int]$result.negative_expected_counts.normal_operator -ne 3 -or
    [int]$result.negative_expected_counts.other_bucket -ne 1 -or
    [int]$result.negative_expected_counts.other_prefix -ne 1 -or
    [int]$result.negative_expected_counts.other_principal -ne 1 -or
    [int]$result.negative_expected_counts.failure -ne 1 -or
    @($result.negative_results | Where-Object case_id -eq 'normal_operator').Count -ne 3 -or
    @($result.negative_results | Where-Object case_id -ne 'normal_operator').Count -ne 4) {
    throw 'GT03 Plan-exact negative matrix counts drifted.'
}
if ([int]$result.run_reconciliation.bridge_event_count -ne 9 -or
    [int]$result.run_reconciliation.rule100103_alert_count -ne 6 -or
    [int]$result.run_reconciliation.cloudtrail_event_count -ne 10 -or
    [int]$result.run_reconciliation.rule100104_alert_count -ne 3 -or
    [int]$result.run_reconciliation.shared_negative_count -ne 7 -or
    [int]$result.run_reconciliation.late_or_unexpected_count -ne 0) {
    throw 'GT02/GT03 full-run shared final reconciliation contract did not pass.'
}
if (@($script:gtMockProviderCalls | Where-Object { $_ -ceq 'cloudtrail:gt03-negative-shared' }).Count -ne 1 -or
    @($script:gtMockProviderCalls | Where-Object { $_ -ceq 'wazuh:gt03-negative' }).Count -ne 0 -or
    @($script:gtMockProviderCalls | Where-Object { $_ -ceq 'wazuh:gt02-normal' }).Count -ne 0 -or
    @($script:gtMockProviderCalls | Where-Object { $_ -ceq 'wazuh:run-final-reconciliation' }).Count -ne 2 -or
    @($script:gtMockProviderCalls | Where-Object { $_ -ceq 'bridge:run-final-reconciliation' }).Count -ne 1 -or
    @($script:gtMockProviderCalls | Where-Object { $_ -ceq 'cloudtrail:run-final-reconciliation' }).Count -ne 1) {
    throw 'GT02/GT03 providers reverted to sequential zero-result waits instead of one shared final window.'
}
$contractOutput = @($contractInformation | ForEach-Object { [string]$_ }) -join "`n"
if ($contractOutput -notmatch 'GT02/GT03 CONTRACT_TEST_PASS' -or $contractOutput -match 'Runtime PASS') {
    throw 'GT02/GT03 contract tests were mislabeled as Runtime PASS.'
}
if (@($result.take_evidence).Count -ne 3) {
    throw 'GT02/GT03 secret-safe per-TAKE evidence tuple count is invalid.'
}
foreach ($takeEvidence in @($result.take_evidence)) {
    if ([string]$takeEvidence.take_id -notin $expectedTakeIds -or
        @($takeEvidence.gt02).Count -ne 2 -or
        [int]$takeEvidence.counts.gt02_source_events -ne 2 -or
        [int]$takeEvidence.counts.gt02_rule100103_alerts -ne 2 -or
        [int]$takeEvidence.counts.gt03_cloudtrail_events -ne 1 -or
        [int]$takeEvidence.counts.gt03_rule100104_alerts -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$takeEvidence.gt03.cloudtrail_event_id) -or
        [string]::IsNullOrWhiteSpace([string]$takeEvidence.gt03.wazuh_alert_id) -or
        [double]$takeEvidence.gt03.latency_seconds -ne 1 -or
        [int]$takeEvidence.gt03.clock_skew_seconds -ne 5) {
        throw 'GT02/GT03 per-TAKE evidence tuple is incomplete.'
    }
    foreach ($pair in @($takeEvidence.gt02)) {
        if ([string]::IsNullOrWhiteSpace([string]$pair.source_event_id) -or
            [string]::IsNullOrWhiteSpace([string]$pair.wazuh_alert_id) -or
            [string]$pair.source_event_id -cne [string]$pair.wazuh_event_id -or
            [string]::IsNullOrWhiteSpace([string]$pair.source_event_utc) -or
            [string]::IsNullOrWhiteSpace([string]$pair.wazuh_alert_utc)) {
            throw 'GT02 evidence pair is incomplete.'
        }
    }
}
$evidenceNames = @($result.take_evidence | ForEach-Object {
    $_.PSObject.Properties.Name
    $_.gt03.PSObject.Properties.Name
    $_.gt02 | ForEach-Object { $_.PSObject.Properties.Name }
}) -join "`n"
if ($evidenceNames -match '(?i)raw|payload|secret|credential|webhook') {
    throw 'GT02/GT03 per-TAKE evidence tuple exposes a forbidden field.'
}
if (@($result.source_event_counts | Where-Object { $_ -ne 2 }).Count -ne 0 -or
    @($result.rule100103_alert_counts | Where-Object { $_ -ne 2 }).Count -ne 0) {
    throw 'GT02 mock dynamic cardinality contract did not pass.'
}
if (@($result.latencies_seconds | Where-Object { $_ -ne 1 }).Count -ne 0) {
    throw 'GT03 mock latency contract did not pass.'
}
if (@($result.normal_source_event_counts | Where-Object { $_ -ne 1 }).Count -ne 0 -or
    @($result.normal_rule100103_alert_counts | Where-Object { $_ -ne 0 }).Count -ne 0) {
    throw 'GT02 normal operation 1/TAKE and 0/3 alert contract did not pass.'
}
if (@($result.automatic_response_side_effects | Where-Object {
        $_.shuffle_execution_count -ne 0 -or $_.github_run_count -ne 0 -or
        $_.quarantine_mutation_count -ne 0 -or $_.validation_mutation_count -ne 0
    }).Count -ne 0 -or $script:gtMockSideEffectCalls -ne 2) {
    throw 'GT02 automatic response side-effect zero contract did not pass.'
}
$sideEffectEvidence = @($result.automatic_response_side_effects)[0]
if ([string]$sideEffectEvidence.scope -cne 'all_takes' -or
    @($sideEffectEvidence.source_ids).Count -ne 4 -or
    [string]::IsNullOrWhiteSpace([string]$sideEffectEvidence.baseline_captured_at_utc) -or
    [string]::IsNullOrWhiteSpace([string]$sideEffectEvidence.after_captured_at_utc) -or
    [string]::IsNullOrWhiteSpace([string]$sideEffectEvidence.observation_window_start_utc) -or
    [string]::IsNullOrWhiteSpace([string]$sideEffectEvidence.observation_window_end_utc)) {
    throw 'GT02 whole-run side-effect evidence metadata is incomplete.'
}
if ([int]$result.stale_excluded_count -ne 16) {
    throw 'GT02/GT03 stale baseline exclusion was not observed for every TAKE.'
}

$script:gtMockDuplicateSource = $true
$duplicateSourceFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $duplicateSourceFailed = $_.Exception.Message -match 'fresh source event and Rule 100103 alert cardinalities differ'
}
if (-not $duplicateSourceFailed) {
    throw 'GT02 duplicate source regression did not reach the cardinality contract.'
}
$script:gtMockDuplicateSource = $false

$script:gtMockDuplicateAlert = $true
$duplicateAlertFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $duplicateAlertFailed = $_.Exception.Message -match 'fresh source event and Rule 100103 alert cardinalities differ'
}
if (-not $duplicateAlertFailed) {
    throw 'GT02 duplicate alert regression did not reach the cardinality contract.'
}
$script:gtMockDuplicateAlert = $false

$script:gtMockDuplicatePositiveEventId = $true
$duplicatePositiveEventFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $duplicatePositiveEventFailed = $_.Exception.Message -match 'positive CloudTrail attack eventID was reused across attack TAKEs'
}
if (-not $duplicatePositiveEventFailed) {
    throw 'GT03 duplicate positive CloudTrail eventID regression did not fail closed.'
}
$script:gtMockDuplicatePositiveEventId = $false

$script:gtMockCrossTakeSourceEventId = $true
$crossTakeSourceFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $crossTakeSourceFailed = $_.Exception.Message -match 'source event_id was reused across attack TAKEs'
}
if (-not $crossTakeSourceFailed) {
    throw 'GT02 cross-TAKE source event_id reuse did not fail closed.'
}
$script:gtMockCrossTakeSourceEventId = $false

$script:gtMockCrossTakeRule103AlertId = $true
$crossTakeRule103AlertFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $crossTakeRule103AlertFailed = $_.Exception.Message -match 'Rule 100103 Wazuh alert ID was reused across attack TAKEs'
}
if (-not $crossTakeRule103AlertFailed) {
    throw 'GT02 cross-TAKE Rule 100103 Wazuh alert ID reuse did not fail closed.'
}
$script:gtMockCrossTakeRule103AlertId = $false

$script:gtMockCrossTakeRule104AlertId = $true
$crossTakeRule104AlertFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $crossTakeRule104AlertFailed = $_.Exception.Message -match 'Rule 100104 Wazuh alert ID was reused across attack TAKEs'
}
if (-not $crossTakeRule104AlertFailed) {
    throw 'GT03 cross-TAKE Rule 100104 Wazuh alert ID reuse did not fail closed.'
}
$script:gtMockCrossTakeRule104AlertId = $false

$script:gtMockTakeCalls = 0
$script:gtMockAttackCalls = 0
$script:gtMockFail = $true
$failedFast = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $failedFast = $_.Exception.Message -match 'GT02/GT03 blocked: Attack provider failed'
}
if (-not $failedFast -or $script:gtMockTakeCalls -ne 1 -or $script:gtMockAttackCalls -ne 1) {
    throw 'GT02/GT03 did not fail fast at the first failed TAKE.'
}

$script:gtMockFail = $false
$script:gtMockNormalAlert = $true
$normalAlertFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $normalAlertFailed = $_.Exception.Message -match 'final reconciliation Rule 100103 alert set differs'
}
if (-not $normalAlertFailed) {
    throw 'GT02 shared final absence proof did not fail when a normal operation produced Rule 100103.'
}

$script:gtMockNormalAlert = $false
$script:gtMockLateFinalRule104Alert = $true
$lateFinalAlertFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $lateFinalAlertFailed = $_.Exception.Message -match 'final reconciliation Rule 100104 alert set differs'
}
if (-not $lateFinalAlertFailed) {
    throw 'GT03 full-run reconciliation did not detect a late unexpected Rule 100104 alert.'
}
$script:gtMockLateFinalRule104Alert = $false
$script:gtMockOmitFailureFromFinal = $true
$missingFinalCaseFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $missingFinalCaseFailed = $_.Exception.Message -match 'final reconciliation CloudTrail eventID set differs'
}
if (-not $missingFinalCaseFailed) {
    throw 'GT03 full-run reconciliation did not detect a missing final failure control event.'
}
$script:gtMockOmitFailureFromFinal = $false

$script:gtMockOtherPrefixWrongPrincipal = $true
$otherPrefixSubstitutionFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $otherPrefixSubstitutionFailed = $_.Exception.Message -match 'does not map to exactly one Plan case'
}
if (-not $otherPrefixSubstitutionFailed) {
    throw 'GT03 accepted an unrelated terra-user event as the same-role other_prefix control.'
}
$script:gtMockOtherPrefixWrongPrincipal = $false

$script:gtMockOtherPrefixWrongSession = $true
$otherPrefixSessionSubstitutionFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $otherPrefixSessionSubstitutionFailed = $_.Exception.Message -match 'does not map to exactly one Plan case'
}
if (-not $otherPrefixSessionSubstitutionFailed) {
    throw 'GT03 accepted an unrelated Node Role session as the exact other_prefix control.'
}
$script:gtMockOtherPrefixWrongSession = $false

$script:gtMockOtherPrincipalWrongSession = $true
$otherPrincipalSessionSubstitutionFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $otherPrincipalSessionSubstitutionFailed = $_.Exception.Message -match 'does not map to exactly one Plan case'
}
if (-not $otherPrincipalSessionSubstitutionFailed) {
    throw 'GT03 accepted an unrelated same-role session as the exact other_principal control.'
}
$script:gtMockOtherPrincipalWrongSession = $false

$script:gtMockFailureWrongError = $true
$failureSubstitutionFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $failureSubstitutionFailed = $_.Exception.Message -match 'does not map to exactly one Plan case'
}
if (-not $failureSubstitutionFailed) {
    throw 'GT03 accepted an unrelated AccessDenied event as the fixed precondition-failure control.'
}
$script:gtMockFailureWrongError = $false

$script:gtMockOperationPrincipalDrift = $true
$operationPrincipalDriftFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $operationPrincipalDriftFailed = $_.Exception.Message -match 'do not share one exact assumed-role session'
}
if (-not $operationPrincipalDriftFailed) {
    throw 'GT03 accepted Node Role controls issued by different assumed-role sessions.'
}
$script:gtMockOperationPrincipalDrift = $false

$script:gtMockSideEffectDelta = $true
$sideEffectFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $sideEffectFailed = $_.Exception.Message -match 'side-effect field shuffle_execution_ids changed'
}
if (-not $sideEffectFailed) {
    throw 'GT02 did not fail when an automatic-response side-effect snapshot changed.'
}

$script:gtMockSideEffectDelta = $false
$script:gtMockSideEffectWrongSource = $true
$wrongSideEffectSourceFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $wrongSideEffectSourceFailed = $_.Exception.Message -match 'source identifiers do not match the fixed source set'
}
if (-not $wrongSideEffectSourceFailed) {
    throw 'GT02 wrong side-effect source set did not fail closed.'
}
$script:gtMockSideEffectWrongSource = $false

$script:gtMockSideEffectNarrowWindow = $true
$narrowSideEffectWindowFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $narrowSideEffectWindowFailed = $_.Exception.Message -match 'after query window does not cover the complete observation window'
}
if (-not $narrowSideEffectWindowFailed) {
    throw 'GT02 narrow side-effect query window did not fail closed.'
}
$script:gtMockSideEffectNarrowWindow = $false

$script:gtMockSideEffectLateBaseline = $true
$lateSideEffectBaselineFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $lateSideEffectBaselineFailed = $_.Exception.Message -match 'baseline is not bounded before the mutation window'
}
if (-not $lateSideEffectBaselineFailed) {
    throw 'GT02 late side-effect baseline did not fail closed.'
}
$script:gtMockSideEffectLateBaseline = $false

$spoofedRuntime = $common.Clone()
$spoofedRuntime.ExecutionMode = 'runtime'
$spoofedRuntime.ProviderProvenance = 'runtime:fake'
$runtimeSpoofFailed = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @spoofedRuntime | Out-Null
} catch {
    $runtimeSpoofFailed = $_.Exception.Message -match 'parameter.*cannot be found|cannot find a parameter'
}
if (-not $runtimeSpoofFailed) {
    throw 'GT02/GT03 generic runner accepted a spoofed runtime mode.'
}

$script:gtMockUnsupportedCase = 'other_prefix'
$blockedFixture = $false
try {
    Invoke-CapitalOneGt02Gt03Runtime @common | Out-Null
} catch {
    $blockedFixture = $_.Exception.Message -match 'negative case other_prefix lacks an independently runnable fixed fixture'
}
if (-not $blockedFixture) {
    throw 'GT03 did not fail closed when a negative fixture was unavailable.'
}

Write-Host 'Capital One GT02/GT03 runtime mock tests passed.'
