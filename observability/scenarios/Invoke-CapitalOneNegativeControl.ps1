#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AwsProfile = 'terra-user',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [switch]$ResumeAfterRead,
    [ValidateRange(60, 300)]
    [int]$PostEventAlarmObserveSeconds = 120,
    [ValidateRange(5, 30)]
    [int]$AlarmPollDelaySeconds = 15,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$foundationRoot = Join-Path $terraformRoot 'foundation'
$automationConfigPath = Join-Path $terraformRoot 'automation\project.psd1'
$evidenceModulePath = Join-Path $terraformRoot 'automation\Evidence.Collection.psm1'
$region = 'ap-northeast-2'
$expectedAccountId = '433048100798'
$expectedOperatorArn = "arn:aws:iam::$expectedAccountId`:user/terra-user"
$objectKey = 'validation/capital-one-demo.csv'
$trainingMarker = 'FAKE_TRAINING_DATA'
$minimumSessionRemainingMinutes = 20
if ($AwsProfile -cne 'terra-user') {
    throw 'The negative control permits only the fixed terra-user operator profile.'
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path (
        [Environment]::GetFolderPath('MyDocuments')
    ) 'aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'capital-one-negative-' +
        [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId must use safe path characters.'
}

. (Join-Path $terraformRoot 'daily-common.ps1')
. (Join-Path $terraformRoot 'daily-session-common.ps1')
Import-Module $evidenceModulePath -Force

function Write-CapitalOneJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 10),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Get-AlarmSnapshot {
    param([Parameter(Mandatory)][string]$AlarmName)

    $result = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        'cloudwatch', 'describe-alarms',
        '--profile', $AwsProfile,
        '--region', $region,
        '--alarm-names', $AlarmName,
        '--output', 'json',
        '--no-cli-pager'
    ) -FailureMessage 'The Capital One alarm could not be read.' | ConvertFrom-Json
    $alarms = @($result.MetricAlarms)
    if ($alarms.Count -ne 1) {
        throw 'The Capital One detector must resolve to exactly one alarm.'
    }
    return $alarms[0]
}

function Get-CapitalOneField {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ''
    }
    return [string]$property.Value
}

$credentialEnvironmentNames = @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN'
)
foreach ($name in $credentialEnvironmentNames) {
    if ([Environment]::GetEnvironmentVariable($name, 'Process')) {
        throw "Clear the process-level $name before the negative control."
    }
}

Assert-CommandAvailable -Name 'terraform' | Out-Null
Assert-CommandAvailable -Name 'aws' | Out-Null
if (-not (Test-Path -LiteralPath $automationConfigPath -PathType Leaf)) {
    throw 'The fixed automation configuration is unavailable.'
}
$automationConfig = Import-PowerShellDataFile -LiteralPath $automationConfigPath
$negativeQueries = @($automationConfig.Evidence.Queries | Where-Object {
    [string]$_.Name -ceq 'capital-one-negative-control'
})
if ($negativeQueries.Count -ne 1) {
    throw 'The automation configuration must contain one negative-control query.'
}
$negativeQuery = $negativeQueries[0]
$cloudTrailRetryBudgetSeconds = [int]$negativeQuery.OverallTimeoutSeconds

$identity = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--region', $region,
    '--output', 'json',
    '--no-cli-pager'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $expectedAccountId -or
    [string]$identity.Arn -cne $expectedOperatorArn) {
    throw 'The fixed normal operator identity is required for the negative control.'
}

$sessionPath = Get-DailySessionActiveStatePath
$dailySession = Read-DailySessionState -Path $sessionPath
if ([string]$dailySession.Status -cne 'Active' -or
    [string]$dailySession.SecurityScenarioProfile -cne 'capital-one-lab' -or
    [string]$dailySession.AccountId -cne $expectedAccountId -or
    [string]$dailySession.PrimaryRegion -cne $region -or
    [IO.Path]::GetFullPath([string]$dailySession.TerraformRoot) -cne
        [IO.Path]::GetFullPath($terraformRoot)) {
    throw 'The Active Daily Session does not match the fixed Capital One lab runtime.'
}
$remaining = [datetimeoffset]$dailySession.HardDeadlineAtUtc -
    [datetimeoffset]::UtcNow
if ($remaining.TotalMinutes -lt $minimumSessionRemainingMinutes) {
    throw 'The Daily Session has too little time left for the negative control.'
}

$runtimeProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'runtime_profile'
) -FailureMessage 'The active Runtime profile is unavailable.').Trim()
$securityProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'security_scenario_profile'
) -FailureMessage 'The active security scenario profile is unavailable.').Trim()
if ($runtimeProfile -cne 'minimal' -or $securityProfile -cne 'capital-one-lab') {
    throw 'The negative control requires the prepared minimal + capital-one-lab Runtime.'
}

$bucket = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'primary_application_bucket_name'
) -FailureMessage 'The Primary application bucket is unavailable.').Trim()
if ($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
    throw 'Terraform returned an unsafe Primary application bucket name.'
}

$dataEventsEnabled = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$foundationRoot", 'output', '-raw', 'project_s3_data_events_enabled'
) -FailureMessage 'The Foundation S3 Data Event state is unavailable.').Trim()
$detection = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$foundationRoot", 'output', '-json', 'capital_one_s3_detection'
) -FailureMessage 'The Foundation Capital One detector is unavailable.' |
    ConvertFrom-Json
if ($dataEventsEnabled.ToLowerInvariant() -cne 'true' -or
    -not [bool]$detection.enabled -or
    -not [string]$detection.alarm_name -or
    -not [string]$detection.expected_role_name) {
    throw 'The approved S3 Data Event and Capital One detector must both be active.'
}
$expectedRoleName = [string]$detection.expected_role_name
if ($expectedRoleName -notmatch '^[A-Za-z0-9+=,.@_-]{1,64}$' -or
    [string]$identity.Arn -match (
        ':assumed-role/' + [regex]::Escape($expectedRoleName) + '/'
    )) {
    throw 'The caller must be different from the detector Node Role.'
}

$head = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
    's3api', 'head-object',
    '--profile', $AwsProfile,
    '--region', $region,
    '--bucket', $bucket,
    '--key', $objectKey,
    '--output', 'json',
    '--no-cli-pager'
) -FailureMessage 'Run Prepare-CapitalOneDemoData.ps1 before the negative control.' |
    ConvertFrom-Json
$expectedContentSha256 = [string]$head.Metadata.sha256
$expectedRecordCount = [int]$head.Metadata.'record-count'
if ([string]$head.Metadata.'training-marker' -cne $trainingMarker -or
    $expectedContentSha256 -notmatch '^[a-f0-9]{64}$' -or
    $expectedRecordCount -lt 1 -or $expectedRecordCount -gt 20) {
    throw 'The fixed validation object is missing safe fake-data metadata.'
}

$recordPath = Join-Path $EvidenceRoot (
    "$ExperimentId\source\client\capital-one-negative-control.json"
)
$resumeRecord = $null
$resumeStartedAt = $null
$resumeReadFinishedAt = $null
if ($ResumeAfterRead) {
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw 'Resume requires an existing sanitized negative-control record.'
    }
    $resumeRecord = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([string]$resumeRecord.ScenarioId -cne 'CAPITAL-ONE-NEGATIVE' -or
        [string]$resumeRecord.ExperimentId -cne $ExperimentId -or
        -not [bool]$resumeRecord.GetObjectSucceeded -or
        -not [bool]$resumeRecord.MarkerValidated -or
        [bool]$resumeRecord.CloudTrailObserved -or
        [string]$resumeRecord.FailureStage -cne 'normal-cloudtrail-event' -or
        [string]$resumeRecord.ObjectKey -cne $objectKey -or
        [string]$resumeRecord.ContentSha256 -cne $expectedContentSha256 -or
        [int]$resumeRecord.RecordCount -ne $expectedRecordCount) {
        throw 'The existing record is not an eligible post-read resume checkpoint.'
    }
    $resumeStartedAt = [datetimeoffset]::Parse(
        [string]$resumeRecord.StartedAtUtc
    )
    $resumeReadFinishedAt = [datetimeoffset]::Parse(
        [string]$resumeRecord.ReadFinishedAtUtc
    )
    if ($resumeReadFinishedAt -lt $resumeStartedAt -or
        $resumeReadFinishedAt -gt $resumeStartedAt.AddMinutes(5)) {
        throw 'The existing read window is outside the bounded resume contract.'
    }
} elseif (Test-Path -LiteralPath $recordPath) {
    throw 'The ExperimentId already has a record. Use ResumeAfterRead or a new ID.'
}

$alarmBefore = Get-AlarmSnapshot -AlarmName ([string]$detection.alarm_name)
$alarmBeforeUpdatedAt = [datetimeoffset]$alarmBefore.StateUpdatedTimestamp
if ([string]$alarmBefore.StateValue -cne 'OK' -or
    -not [bool]$alarmBefore.ActionsEnabled -or
    @($alarmBefore.AlarmActions).Count -lt 1) {
    throw 'The Capital One alarm must be OK with an enabled action before the negative control.'
}
if ($ResumeAfterRead -and $alarmBeforeUpdatedAt -ge $resumeStartedAt) {
    throw 'The alarm state timestamp changed after the existing control started.'
}

Write-Host 'Capital One negative-control preview'
Write-Host 'Caller: fixed normal terra-user operator (ARN hidden)'
Write-Host "Runtime: $runtimeProfile + $securityProfile"
Write-Host "Fixed object key: $objectKey"
Write-Host "Expected fake rows / SHA-256: $expectedRecordCount / $expectedContentSha256"
Write-Host "Excluded detector role: $expectedRoleName"
Write-Host "Alarm before control: $($alarmBefore.StateValue)"
Write-Host "Experiment: $ExperimentId"
Write-Host "Mode: $(if ($ResumeAfterRead) { 'resume after fixed read' } else { 'new fixed read' })"
Write-Host (
    'Expected bounded wait: CloudTrail delivery/query about ' +
    "$([math]::Ceiling($cloudTrailRetryBudgetSeconds / 60)) minutes maximum, " +
    "then Alarm observation $PostEventAlarmObserveSeconds seconds."
)
Write-Host 'Account ID, bucket, caller ARN, and object contents are not printed.'

$requiredConfirmation = if ($ResumeAfterRead) {
    'RESUME CAPITAL ONE NEGATIVE CONTROL'
} else {
    'RUN CAPITAL ONE NEGATIVE CONTROL'
}
if ($ConfirmRun -cne $requiredConfirmation) {
    throw (
        "Preview only. Re-run with -ConfirmRun '$requiredConfirmation' " +
        'after the static tests pass.'
    )
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'aws-topology-capital-one-negative-' + [guid]::NewGuid().ToString('N')
)
$downloadPath = Join-Path $tempRoot 'capital-one-demo.csv'
$invocationStartedAt = [datetimeoffset]::UtcNow
$startedAt = if ($ResumeAfterRead) {
    $resumeStartedAt
} else {
    [datetimeoffset]::UtcNow
}
$readFinishedAt = if ($ResumeAfterRead) {
    $resumeReadFinishedAt
} else {
    $null
}
$finishedAt = $null
$failureStage = ''
$failureType = ''
$getObjectSucceeded = [bool]$ResumeAfterRead
$markerValidated = [bool]$ResumeAfterRead
$cloudTrailObserved = $false
$normalCallerConfirmed = $false
$alarmStayedOk = $false
$alarmTimestampUnchanged = $false
$s3ReadSeconds = if (
    $ResumeAfterRead -and
    $null -ne $resumeRecord.PSObject.Properties['StageDurationsSeconds'] -and
    $null -ne $resumeRecord.StageDurationsSeconds.PSObject.Properties[
        'S3ReadAndValidation'
    ]
) {
    [double]$resumeRecord.StageDurationsSeconds.S3ReadAndValidation
} elseif ($ResumeAfterRead) {
    [math]::Round(($resumeReadFinishedAt - $resumeStartedAt).TotalSeconds, 3)
} else {
    0
}
$cloudTrailStageStartedAt = $null
$cloudTrailWaitSeconds = 0
$cloudTrailDeliveryAttempts = 0
$alarmStageStartedAt = $null
$alarmObservationSeconds = 0
$contentSha256 = if ($ResumeAfterRead) {
    [string]$resumeRecord.ContentSha256
} else {
    ''
}
$recordCount = if ($ResumeAfterRead) {
    [int]$resumeRecord.RecordCount
} else {
    0
}

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null

    if (-not $ResumeAfterRead) {
        $s3ReadStartedAt = [datetimeoffset]::UtcNow
        $failureStage = 'normal-operator-s3-read'
        [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            's3api', 'get-object',
            '--profile', $AwsProfile,
            '--region', $region,
            '--bucket', $bucket,
            '--key', $objectKey,
            $downloadPath,
            '--output', 'json',
            '--no-cli-pager'
        ) -FailureMessage 'The fixed normal operator could not read the fake object.')
        $getObjectSucceeded = $true
        $readFinishedAt = [datetimeoffset]::UtcNow

        $failureStage = 'fake-data-validation'
        $contentSha256 = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.
            ToLowerInvariant()
        $downloadedLines = @(Get-Content -LiteralPath $downloadPath)
        if ($downloadedLines.Count -lt 2 -or
            $downloadedLines[0] -cne
                'training_marker,record_id,customer_name,email,account_last4') {
            throw 'The downloaded object is not the fixed fake-data CSV.'
        }
        $dataLines = @($downloadedLines | Select-Object -Skip 1)
        if (@($dataLines | Where-Object { $_ -notlike "$trainingMarker,*" }).Count -ne 0) {
            throw 'A downloaded row is missing the explicit fake training marker.'
        }
        $recordCount = $dataLines.Count
        $downloadedLines = $null
        $dataLines = $null
        if ($contentSha256 -cne $expectedContentSha256 -or
            $recordCount -ne $expectedRecordCount) {
            throw 'The downloaded fake object hash or row count does not match preparation.'
        }
        $markerValidated = $true
        $s3ReadSeconds = [math]::Round(
            ([datetimeoffset]::UtcNow - $s3ReadStartedAt).TotalSeconds,
            3
        )
        Write-Host (
            "Normal fixed S3 read: succeeded; marker=$trainingMarker " +
            "rows=$recordCount sha256=$contentSha256"
        )
    } else {
        Write-Host 'Resume checkpoint: reusing the existing fixed GetObject window.'
    }

    $failureStage = 'normal-cloudtrail-event'
    $queryStart = $startedAt.AddSeconds(-2)
    $queryEnd = $readFinishedAt.AddSeconds(2)
    $queryContext = @{
        TerraformRoot = $terraformRoot
        AwsProfile = $AwsProfile
        PrimaryRegion = $region
        DrRegion = [string]$dailySession.DrRegion
        Tokens = @{
            ProjectName = [string]$automationConfig.Project.Name
            AccountId = $expectedAccountId
            PrimaryRegion = $region
            DrRegion = [string]$dailySession.DrRegion
        }
    }
    $cloudTrailStageStartedAt = [datetimeoffset]::UtcNow
    $progressReporter = {
        param($ProgressState)

        if ([string]$ProgressState.Phase -ceq 'DeliveryAttempt') {
            Write-Host (
                "CloudTrail delivery/query: attempt $($ProgressState.Attempt)/" +
                "$($ProgressState.MaxAttempts), elapsed " +
                "$($ProgressState.ElapsedSeconds)s, remaining budget " +
                "$($ProgressState.RemainingSeconds)s"
            )
        } elseif ([string]$ProgressState.Phase -ceq 'DeliveryResult') {
            Write-Host (
                "CloudTrail delivery/query result: rows=$($ProgressState.RowCount), " +
                "serviceRows=$($ProgressState.ServiceRowCount)"
            )
        } elseif (
            [string]$ProgressState.Phase -ceq 'QueryPoll' -and
            [string]$ProgressState.Status -cne 'Complete' -and
            ([int]$ProgressState.PollAttempt % 6) -eq 0
        ) {
            Write-Host (
                "CloudWatch query: $($ProgressState.Status), poll " +
                "$($ProgressState.PollAttempt)/$($ProgressState.MaxPollAttempts), " +
                "elapsed $($ProgressState.ElapsedSeconds)s, remaining budget " +
                "$($ProgressState.RemainingSeconds)s"
            )
        }
    }.GetNewClosure()
    $queryResult = Invoke-EvidenceCloudWatchInsightsQuery `
        -Query $negativeQuery `
        -Config $automationConfig `
        -Context $queryContext `
        -BundleRoot $tempRoot `
        -StartTimeUtc $queryStart.UtcDateTime `
        -EndTimeUtc $queryEnd.UtcDateTime `
        -ProgressReporter $progressReporter
    $cloudTrailWaitSeconds = [math]::Round(
        ([datetimeoffset]::UtcNow - $cloudTrailStageStartedAt).TotalSeconds,
        3
    )
    if ([string]$queryResult.Status -cne 'Succeeded' -or
        [int]$queryResult.Items -ne 1) {
        throw 'The fixed CloudTrail query did not return exactly one normal GetObject.'
    }
    $queryDocument = Get-Content -LiteralPath $queryResult.Destination -Raw |
        ConvertFrom-Json
    $cloudTrailDeliveryAttempts = [int]$queryDocument.DeliveryAttempts
    $rows = @($queryDocument.Rows)
    if ($rows.Count -ne 1) {
        throw 'The fixed CloudTrail result document does not contain exactly one row.'
    }
    $eventTime = [datetimeoffset]::Parse(
        (Get-CapitalOneField -Row $rows[0] -Name 'event_time'),
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal
    )
    if ((Get-CapitalOneField -Row $rows[0] -Name 'event_name') -cne 'GetObject' -or
        (Get-CapitalOneField -Row $rows[0] -Name 'object_key') -cne $objectKey -or
        -not [string]::IsNullOrWhiteSpace(
            (Get-CapitalOneField -Row $rows[0] -Name 'error_code')
        ) -or
        (Get-CapitalOneField -Row $rows[0] -Name 'caller_arn') -match (
            ':assumed-role/' + [regex]::Escape($expectedRoleName) + '/'
        ) -or
        $eventTime -lt $queryStart -or $eventTime -gt $queryEnd) {
        throw 'The fixed CloudTrail row does not match the negative-control contract.'
    }
    $cloudTrailObserved = $true
    $normalCallerConfirmed = $true
    Write-Host 'CloudTrail negative-control event: exactly one normal GetObject observed.'

    $failureStage = 'alarm-non-transition'
    $alarmStageStartedAt = [datetimeoffset]::UtcNow
    $observeDeadline = [datetimeoffset]::UtcNow.AddSeconds(
        $PostEventAlarmObserveSeconds
    )
    do {
        $alarmElapsedSeconds = [math]::Round(
            ([datetimeoffset]::UtcNow - $alarmStageStartedAt).TotalSeconds
        )
        Write-Host (
            "Alarm non-transition observation: ${alarmElapsedSeconds}/" +
            "$PostEventAlarmObserveSeconds seconds"
        )
        $alarmNow = Get-AlarmSnapshot -AlarmName ([string]$detection.alarm_name)
        $alarmNowUpdatedAt = [datetimeoffset]$alarmNow.StateUpdatedTimestamp
        if ([string]$alarmNow.StateValue -cne 'OK' -or
            $alarmNowUpdatedAt -ge $startedAt) {
            throw 'The Capital One alarm state history changed during the negative control.'
        }
        $alarmRemainingSeconds = [math]::Ceiling(
            ($observeDeadline - [datetimeoffset]::UtcNow).TotalSeconds
        )
        if ($alarmRemainingSeconds -gt 0) {
            Start-Sleep -Seconds ([math]::Min(
                $AlarmPollDelaySeconds,
                $alarmRemainingSeconds
            ))
        }
    } while ([datetimeoffset]::UtcNow -lt $observeDeadline)
    $alarmObservationSeconds = [math]::Round(
        ([datetimeoffset]::UtcNow - $alarmStageStartedAt).TotalSeconds,
        3
    )
    $alarmAfter = Get-AlarmSnapshot -AlarmName ([string]$detection.alarm_name)
    $alarmAfterUpdatedAt = [datetimeoffset]$alarmAfter.StateUpdatedTimestamp
    $alarmStayedOk = [string]$alarmAfter.StateValue -ceq 'OK'
    $alarmTimestampUnchanged = (
        $alarmAfterUpdatedAt -eq $alarmBeforeUpdatedAt -and
        $alarmAfterUpdatedAt -lt $startedAt
    )
    if (-not $alarmStayedOk -or -not $alarmTimestampUnchanged) {
        throw 'The Capital One alarm state history changed during the negative control.'
    }
    Write-Host 'Capital One alarm: remained OK with an unchanged state timestamp.'
} catch {
    $failureType = $_.Exception.GetType().FullName
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    $finishedAt = [datetimeoffset]::UtcNow
    if ($null -ne $cloudTrailStageStartedAt -and $cloudTrailWaitSeconds -eq 0) {
        $cloudTrailWaitSeconds = [math]::Round(
            ($finishedAt - $cloudTrailStageStartedAt).TotalSeconds,
            3
        )
    }
    if ($null -ne $alarmStageStartedAt -and $alarmObservationSeconds -eq 0) {
        $alarmObservationSeconds = [math]::Round(
            ($finishedAt - $alarmStageStartedAt).TotalSeconds,
            3
        )
    }
}

$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'CAPITAL-ONE-NEGATIVE'
    ExperimentId = $ExperimentId
    StartedAtUtc = $startedAt.ToString('o')
    InvocationStartedAtUtc = $invocationStartedAt.ToString('o')
    ReadFinishedAtUtc = if ($null -ne $readFinishedAt) {
        $readFinishedAt.ToString('o')
    } else {
        ''
    }
    FinishedAtUtc = $finishedAt.ToString('o')
    InvocationDurationSeconds = [math]::Round(
        ($finishedAt - $invocationStartedAt).TotalSeconds,
        3
    )
    ControlWindowElapsedSeconds = [math]::Round(
        ($finishedAt - $startedAt).TotalSeconds,
        3
    )
    StageDurationsSeconds = [ordered]@{
        S3ReadAndValidation = $s3ReadSeconds
        CloudTrailDeliveryAndQuery = $cloudTrailWaitSeconds
        AlarmNonTransitionObservation = $alarmObservationSeconds
    }
    CloudTrailDeliveryAttempts = $cloudTrailDeliveryAttempts
    AwsAccountMatched = $true
    Region = $region
    RuntimeProfile = $runtimeProfile
    SecurityScenarioProfile = $securityProfile
    CallerType = 'fixed normal IAM operator'
    ResumeAfterRead = [bool]$ResumeAfterRead
    CallerArnPersisted = $false
    ExcludedDetectorRole = $expectedRoleName
    ObjectKey = $objectKey
    GetObjectSucceeded = $getObjectSucceeded
    TrainingMarker = $trainingMarker
    MarkerValidated = $markerValidated
    RecordCount = $recordCount
    ContentSha256 = $contentSha256
    CloudTrailObserved = $cloudTrailObserved
    NormalCallerConfirmed = $normalCallerConfirmed
    AlarmStartedOk = $true
    AlarmStayedOk = $alarmStayedOk
    AlarmStateTimestampUnchanged = $alarmTimestampUnchanged
    BucketPersisted = $false
    FailureStage = if ($failureType) { $failureStage } else { '' }
    FailureType = $failureType
}
Write-CapitalOneJson -Path $recordPath -Value $record

Write-Host "Sanitized negative-control record: $recordPath"
if ($null -ne $readFinishedAt) {
    Write-Host 'Collect the matching CloudTrail evidence with:'
    Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'CAPITAL-ONE-NEGATIVE' -EvidenceStartUtc '$($startedAt.ToString('o'))' -EvidenceEndUtc '$($readFinishedAt.ToString('o'))' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 10"
}
if ($failureType) {
    throw "CAPITAL-ONE negative control failed at '$failureStage'. See the sanitized record."
}
Write-Host 'CAPITAL-ONE negative control completed without triggering the detector.'
