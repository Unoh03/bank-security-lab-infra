#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('before', 'count', 'block')]
    [string]$Phase = 'before',
    [ValidateRange(10, 60)]
    [int]$AttemptCount = 20,
    [ValidateRange(0, 10)]
    [int]$IntervalSeconds = 1,
    [ValidateRange(60, 300)]
    [int]$RulePropagationWaitSeconds = 90,
    [string]$TerraformRoot = '',
    [string]$FoundationRoot = '',
    [switch]$ValidateLoginFailureAlarm,
    [ValidateRange(60, 900)]
    [int]$AlarmWaitSeconds = 480,
    [ValidateRange(5, 60)]
    [int]$AlarmPollSeconds = 15,
    [string]$AwsProfile = 'terra-user',
    [string]$ExpectedAccountId = '433048100798',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
if (-not $FoundationRoot) {
    $FoundationRoot = Join-Path $TerraformRoot 'foundation'
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'web01-' + $Phase + '-' +
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}

function Invoke-ScenarioNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "$FailureMessage`n$(($output | Out-String).Trim())"
    }
    return ($output | Out-String).Trim()
}

function Write-ScenarioJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 12),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-LoginFailureAlarmSnapshot {
    param(
        [Parameter(Mandatory)][string]$AlarmName,
        [Parameter(Mandatory)][string]$Region
    )

    $response = Invoke-ScenarioNative -FilePath 'aws' -ArgumentList @(
        'cloudwatch', 'describe-alarms',
        '--profile', $AwsProfile,
        '--region', $Region,
        '--alarm-names', $AlarmName,
        '--output', 'json'
    ) -FailureMessage 'The WEB-01 login failure alarm could not be read.' | ConvertFrom-Json
    $alarms = @($response.MetricAlarms)
    if ($alarms.Count -ne 1) {
        throw "Expected exactly one WEB-01 alarm named '$AlarmName'; found $($alarms.Count)."
    }
    return $alarms[0]
}

$identity = Invoke-ScenarioNative -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--output', 'json'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $ExpectedAccountId) {
    throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
}

$alarmContext = $null
if ($ValidateLoginFailureAlarm) {
    $alarmName = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
        "-chdir=$FoundationRoot", 'output', '-raw', 'dvwa_login_failure_alarm_name'
    ) -FailureMessage 'The Foundation WEB-01 alarm output is unavailable.'
    $alarmRegion = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
        "-chdir=$FoundationRoot", 'output', '-raw', 'aws_region'
    ) -FailureMessage 'The Foundation alarm region output is unavailable.'
    $alertTopicArn = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
        "-chdir=$FoundationRoot", 'output', '-raw', 'security_alert_topic_arn'
    ) -FailureMessage 'The Foundation security alert topic output is unavailable.'

    $initialAlarm = Get-LoginFailureAlarmSnapshot `
        -AlarmName $alarmName `
        -Region $alarmRegion
    if ([string]$initialAlarm.StateValue -ceq 'ALARM') {
        throw (
            "The WEB-01 alarm is already ALARM before traffic. Wait for it to return to OK " +
            'so this run can prove a new state transition.'
        )
    }

    $subscriptionResponse = Invoke-ScenarioNative -FilePath 'aws' -ArgumentList @(
        'sns', 'list-subscriptions-by-topic',
        '--profile', $AwsProfile,
        '--region', $alarmRegion,
        '--topic-arn', $alertTopicArn,
        '--output', 'json'
    ) -FailureMessage 'The security alert topic subscriptions could not be read.' | ConvertFrom-Json
    $confirmedSubscriptions = @(
        @($subscriptionResponse.Subscriptions) | Where-Object {
            $_.SubscriptionArn -and
            [string]$_.SubscriptionArn -cne 'PendingConfirmation'
        }
    )
    $confirmedProtocols = @(
        $confirmedSubscriptions |
            ForEach-Object { [string]$_.Protocol } |
            Sort-Object -Unique
    )

    $alarmContext = [ordered]@{
        Name = $alarmName
        Region = $alarmRegion
        TopicArn = $alertTopicArn
        InitialState = [string]$initialAlarm.StateValue
        InitialStateUpdatedAtUtc = ([datetime]$initialAlarm.StateUpdatedTimestamp).
            ToUniversalTime().ToString('o')
        ConfirmedSubscriptionCount = $confirmedSubscriptions.Count
        ConfirmedSubscriptionProtocols = $confirmedProtocols
    }
}

$applicationUrl = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'application_url'
) -FailureMessage 'The Daily Runtime application_url output is unavailable.'
$cloudFrontDomain = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'cloudfront_domain_name'
) -FailureMessage 'The Daily Runtime CloudFront output is unavailable.'
$effectiveWafMode = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'waf_login_rate_rule_mode'
) -FailureMessage 'The WEB-01 WAF mode output is unavailable.'

$expectedMode = if ($Phase -eq 'before') { 'disabled' } else { $Phase }
if ($effectiveWafMode.Trim().ToLowerInvariant() -cne $expectedMode) {
    throw "WEB-01 phase/mode mismatch: phase=$Phase expected=$expectedMode actual=$effectiveWafMode"
}
$plannedRateObservationSeconds = [math]::Max(
    0,
    ($AttemptCount - 1) * $IntervalSeconds
)
if ($Phase -ne 'before' -and $plannedRateObservationSeconds -lt 50) {
    throw (
        'AWS WAF rate mitigation is approximate, can lag, and is not guaranteed within this floor. ' +
        "The $Phase phase must keep sending the approved bounded requests for " +
        "at least 50 seconds; current planned observation is $plannedRateObservationSeconds seconds."
    )
}
$baseUri = [uri]$applicationUrl
if ($baseUri.Scheme -cne 'https' -or -not $baseUri.Host) {
    throw "Refusing an invalid project application URL: $applicationUrl"
}
$loginUri = [uri]::new($baseUri, '/login.php')

Write-Host "WEB-01 target: $loginUri"
Write-Host "AWS account: $($identity.Account)"
Write-Host "CloudFront distribution: $cloudFrontDomain"
Write-Host "Phase/WAF mode: $Phase/$expectedMode"
Write-Host "Bounded requests: $AttemptCount failed login POSTs, interval=${IntervalSeconds}s"
if ($ValidateLoginFailureAlarm) {
    Write-Host "Alarm validation: $($alarmContext.Name), bounded wait=${AlarmWaitSeconds}s"
    Write-Host "Confirmed SNS subscriptions: $($alarmContext.ConfirmedSubscriptionCount)"
}
if ($Phase -ne 'before') {
    Write-Host "WAF propagation wait: ${RulePropagationWaitSeconds}s"
    Write-Host "Planned rate observation: ${plannedRateObservationSeconds}s (approximate control)"
}
if ($ConfirmRun -cne 'RUN WEB-01') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN WEB-01' after explicit approval."
}
if ($Phase -ne 'before') {
    Write-Host 'Waiting for the updated CloudFront Web ACL to propagate before generating traffic...'
    Start-Sleep -Seconds $RulePropagationWaitSeconds
}

$startedAt = (Get-Date).ToUniversalTime()
$results = New-Object System.Collections.Generic.List[object]
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = 'aws-topology-observability-web01/1.0'
$syntheticUser = 'observability-web01'
$syntheticPassword = 'intentionally-invalid-web01'

for ($attempt = 1; $attempt -le $AttemptCount; $attempt++) {
    $attemptStarted = Get-Date
    $page = Invoke-WebRequest `
        -Uri $loginUri `
        -Method Get `
        -WebSession $session `
        -UseBasicParsing `
        -ErrorAction Stop
    $match = [regex]::Match(
        [string]$page.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw "CSRF token was not found before attempt $attempt."
    }

    $statusCode = 0
    try {
        $response = Invoke-WebRequest `
            -Uri $loginUri `
            -Method Post `
            -WebSession $session `
            -UseBasicParsing `
            -Body @{
                username   = $syntheticUser
                password   = $syntheticPassword
                Login      = 'Login'
                user_token = $match.Groups[1].Value
            } `
            -ErrorAction Stop
        $statusCode = [int]$response.StatusCode
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        } else {
            throw
        }
    }

    $results.Add([pscustomobject]@{
        Attempt = $attempt
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        HttpStatus = $statusCode
        DurationMs = [int]((Get-Date) - $attemptStarted).TotalMilliseconds
    })
    if ($attempt -lt $AttemptCount -and $IntervalSeconds -gt 0) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}

$finishedAt = (Get-Date).ToUniversalTime()
$alarmValidation = $null
if ($ValidateLoginFailureAlarm) {
    $alarmDeadline = (Get-Date).AddSeconds($AlarmWaitSeconds)
    $lastAlarm = $null
    $alarmTriggered = $false
    do {
        $lastAlarm = Get-LoginFailureAlarmSnapshot `
            -AlarmName $alarmContext.Name `
            -Region $alarmContext.Region
        $stateUpdatedAt = ([datetime]$lastAlarm.StateUpdatedTimestamp).ToUniversalTime()
        if (
            [string]$lastAlarm.StateValue -ceq 'ALARM' -and
            $stateUpdatedAt -ge $startedAt.AddSeconds(-5)
        ) {
            $alarmTriggered = $true
            break
        }
        if ((Get-Date) -ge $alarmDeadline) {
            break
        }
        Start-Sleep -Seconds $AlarmPollSeconds
    } while ($true)

    $alarmValidation = [ordered]@{
        Requested = $true
        TriggeredByThisRun = $alarmTriggered
        WaitLimitSeconds = $AlarmWaitSeconds
        PollSeconds = $AlarmPollSeconds
        Name = $alarmContext.Name
        Region = $alarmContext.Region
        TopicArn = $alarmContext.TopicArn
        InitialState = $alarmContext.InitialState
        InitialStateUpdatedAtUtc = $alarmContext.InitialStateUpdatedAtUtc
        FinalState = [string]$lastAlarm.StateValue
        FinalStateUpdatedAtUtc = ([datetime]$lastAlarm.StateUpdatedTimestamp).
            ToUniversalTime().ToString('o')
        ConfirmedSubscriptionCount = $alarmContext.ConfirmedSubscriptionCount
        ConfirmedSubscriptionProtocols = $alarmContext.ConfirmedSubscriptionProtocols
    }
}
$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'WEB-01'
    ExperimentId = $ExperimentId
    Phase = $Phase
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $finishedAt.ToString('o')
    Target = $loginUri.AbsoluteUri
    CloudFrontDomain = $cloudFrontDomain
    AwsAccountId = [string]$identity.Account
    WafMode = $expectedMode
    AttemptCount = $AttemptCount
    IntervalSeconds = $IntervalSeconds
    RulePropagationWaitSeconds = if ($Phase -eq 'before') { 0 } else { $RulePropagationWaitSeconds }
    PlannedRateObservationSeconds = $plannedRateObservationSeconds
    SyntheticUser = $syntheticUser
    Results = $results.ToArray()
    AlarmValidation = $alarmValidation
}
$recordPath = Join-Path $EvidenceRoot "$ExperimentId\source\client\web-01.json"
Write-ScenarioJson -Path $recordPath -Value $record

Write-Host "WEB-01 client record: $recordPath"
Write-Host 'Collect the matching AWS evidence with:'
Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'WEB-01' -EvidenceStartUtc '$($startedAt.ToString('o'))' -EvidenceEndUtc '$($finishedAt.ToString('o'))' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 5"
if ($ValidateLoginFailureAlarm -and -not $alarmValidation.TriggeredByThisRun) {
    throw (
        "The WEB-01 request evidence was saved, but alarm '$($alarmContext.Name)' did not " +
        "enter a new ALARM state within $AlarmWaitSeconds seconds."
    )
}
