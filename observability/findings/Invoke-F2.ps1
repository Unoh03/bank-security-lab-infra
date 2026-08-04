#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$FoundationRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$ExpectedAccountId = '433048100798',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [ValidateRange(10, 120)]
    [int]$MaxPollAttempts = 60,
    [ValidateRange(1, 15)]
    [int]$PollDelaySeconds = 5,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sampleFindingType = 'Backdoor:EC2/DenialOfService.Tcp'
if (-not $FoundationRoot) {
    $FoundationRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\foundation')).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'f2-sample-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}

function Invoke-F2Native {
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

function Write-F2Json {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 40),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-F2OptionalProperty {
    param(
        $InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    foreach ($property in @($InputObject.PSObject.Properties)) {
        if ([string]$property.Name -ieq $Name -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    return $Default
}

function Get-FoundationOutputRaw {
    param([Parameter(Mandatory)][string]$Name)

    return Invoke-F2Native -FilePath 'terraform' -ArgumentList @(
        "-chdir=$FoundationRoot", 'output', '-raw', $Name
    ) -FailureMessage "Foundation output '$Name' is unavailable."
}

$identity = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--output', 'json'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $ExpectedAccountId) {
    throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
}

$region = Get-FoundationOutputRaw -Name 'aws_region'
$detectorId = Get-FoundationOutputRaw -Name 'guardduty_detector_id'
$eventRuleName = Get-FoundationOutputRaw -Name 'guardduty_finding_event_rule_name'
$findingLogGroup = Get-FoundationOutputRaw -Name 'guardduty_finding_log_group_name'
$alertTopicArn = Get-FoundationOutputRaw -Name 'security_alert_topic_arn'
$logGroupArns = Invoke-F2Native -FilePath 'terraform' -ArgumentList @(
    "-chdir=$FoundationRoot", 'output', '-json', 'security_log_group_arns'
) -FailureMessage 'Foundation security log group ARN outputs are unavailable.' | ConvertFrom-Json
$findingLogGroupArn = [string]$logGroupArns.guardduty_findings
if (-not $findingLogGroupArn) {
    throw 'The GuardDuty EventBridge log group ARN output is empty.'
}

$featureStatus = Invoke-F2Native -FilePath 'terraform' -ArgumentList @(
    "-chdir=$FoundationRoot", 'output', '-json', 'guardduty_optional_features'
) -FailureMessage 'Foundation GuardDuty optional feature outputs are unavailable.' | ConvertFrom-Json
$expectedDisabledFeatures = @(
    'S3_DATA_EVENTS',
    'EKS_AUDIT_LOGS',
    'EBS_MALWARE_PROTECTION',
    'RDS_LOGIN_EVENTS',
    'LAMBDA_NETWORK_LOGS',
    'RUNTIME_MONITORING',
    'AI_PROTECTION'
)
foreach ($featureName in $expectedDisabledFeatures) {
    $property = $featureStatus.PSObject.Properties[$featureName]
    if ($null -eq $property -or [string]$property.Value -cne 'DISABLED') {
        throw "GuardDuty optional feature '$featureName' is not explicitly DISABLED."
    }
}

$targetsResponse = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
    'events', 'list-targets-by-rule',
    '--profile', $AwsProfile,
    '--region', $region,
    '--rule', $eventRuleName,
    '--output', 'json'
) -FailureMessage 'GuardDuty EventBridge targets could not be read.' | ConvertFrom-Json
$targets = @($targetsResponse.Targets)
if ($targets.Count -ne 2) {
    throw "Expected exactly two GuardDuty EventBridge targets; found $($targets.Count)."
}
$logTarget = @($targets | Where-Object {
    [string]$_.Id -ceq 'guardduty-finding-log' -and
    [string]$_.Arn -ceq $findingLogGroupArn
})
$alertTarget = @($targets | Where-Object {
    [string]$_.Id -ceq 'guardduty-finding-alert' -and
    [string]$_.Arn -ceq $alertTopicArn -and
    -not [string]::IsNullOrWhiteSpace(
        [string](Get-F2OptionalProperty -InputObject $_ -Name 'RoleArn' -Default '')
    )
})
if ($logTarget.Count -ne 1 -or $alertTarget.Count -ne 1) {
    throw 'GuardDuty EventBridge targets do not match the Foundation log and alert boundaries.'
}
if (-not [string]::IsNullOrWhiteSpace(
    [string](Get-F2OptionalProperty -InputObject $logTarget[0] -Name 'RoleArn' -Default '')
)) {
    throw 'The CloudWatch Logs target must not use RoleArn; it requires a resource policy.'
}

$detector = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
    'guardduty', 'get-detector',
    '--profile', $AwsProfile,
    '--region', $region,
    '--detector-id', $detectorId,
    '--output', 'json'
) -FailureMessage 'The GuardDuty detector could not be read.' | ConvertFrom-Json
if ([string]$detector.Status -cne 'ENABLED') {
    throw "GuardDuty detector is not enabled: $($detector.Status)"
}

Write-Host 'F2 preview:'
Write-Host "  AWS account/region: $($identity.Account) / $region"
Write-Host "  Detector: $detectorId"
Write-Host "  Sample type: $sampleFindingType"
Write-Host "  EventBridge targets: persistent CloudWatch Logs + existing SNS"
Write-Host "  Optional protection plans: $($expectedDisabledFeatures.Count) explicitly disabled"
Write-Host "  Bounded wait: $($MaxPollAttempts * $PollDelaySeconds) seconds per delivery stage"
Write-Host '  Boundary: validates Finding delivery and investigation wiring; does not simulate a real attack.'
if ($ConfirmRun -cne 'RUN F2 SAMPLE FINDING') {
    Write-Warning "Preview only. Re-run with -ConfirmRun 'RUN F2 SAMPLE FINDING' after explicit approval."
    return
}

$startedAt = [datetimeoffset]::UtcNow
$startedAtEpochMs = $startedAt.ToUnixTimeMilliseconds()
Invoke-F2Native -FilePath 'aws' -ArgumentList @(
    'guardduty', 'create-sample-findings',
    '--profile', $AwsProfile,
    '--region', $region,
    '--detector-id', $detectorId,
    '--finding-types', $sampleFindingType,
    '--no-cli-pager'
) -FailureMessage 'The approved GuardDuty sample Finding could not be created.' | Out-Null

$criteriaPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-f2-criteria-' + [guid]::NewGuid().ToString('N') + '.json'
)
try {
    Write-F2Json -Path $criteriaPath -Value ([ordered]@{
        Criterion = [ordered]@{
            type = @{ Eq = @($sampleFindingType) }
            updatedAt = @{ Gte = $startedAtEpochMs }
        }
    })
    $criteriaUri = 'file://' + $criteriaPath.Replace('\', '/')

    $finding = $null
    for ($attempt = 1; $attempt -le $MaxPollAttempts; $attempt++) {
        $listResponse = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
            'guardduty', 'list-findings',
            '--profile', $AwsProfile,
            '--region', $region,
            '--detector-id', $detectorId,
            '--finding-criteria', $criteriaUri,
            '--sort-criteria', 'AttributeName=updatedAt,OrderBy=DESC',
            '--max-results', '50',
            '--output', 'json'
        ) -FailureMessage 'GuardDuty sample Finding lookup failed.' | ConvertFrom-Json
        $findingIds = @($listResponse.FindingIds)
        if ($findingIds.Count -gt 0) {
            $arguments = New-Object System.Collections.Generic.List[string]
            foreach ($value in @(
                'guardduty', 'get-findings',
                '--profile', $AwsProfile,
                '--region', $region,
                '--detector-id', $detectorId,
                '--finding-ids'
            )) {
                [void]$arguments.Add($value)
            }
            foreach ($id in $findingIds) {
                [void]$arguments.Add([string]$id)
            }
            [void]$arguments.Add('--output')
            [void]$arguments.Add('json')
            $getResponse = Invoke-F2Native -FilePath 'aws' `
                -ArgumentList @($arguments | ForEach-Object { $_ }) `
                -FailureMessage 'GuardDuty sample Finding details could not be read.' |
                ConvertFrom-Json
            $finding = @(
                @($getResponse.Findings) | Where-Object {
                    [string]$_.Type -ceq $sampleFindingType -and
                    ([string]$_.Title).StartsWith(
                        '[SAMPLE]',
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                } | Sort-Object UpdatedAt -Descending | Select-Object -First 1
            )
            if ($finding.Count -eq 1) {
                $finding = $finding[0]
                break
            }
        }
        if ($attempt -lt $MaxPollAttempts) {
            Start-Sleep -Seconds $PollDelaySeconds
        }
    }
    if ($null -eq $finding) {
        throw 'The GuardDuty sample Finding did not appear within the bounded wait.'
    }

    $findingId = [string]$finding.Id
    $eventResponse = $null
    for ($attempt = 1; $attempt -le $MaxPollAttempts; $attempt++) {
        $eventResponse = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
            'logs', 'filter-log-events',
            '--profile', $AwsProfile,
            '--region', $region,
            '--log-group-name', $findingLogGroup,
            '--start-time', ([string]$startedAtEpochMs),
            '--filter-pattern', $findingId,
            '--limit', '50',
            '--output', 'json'
        ) -FailureMessage 'GuardDuty EventBridge delivery lookup failed.' | ConvertFrom-Json
        if (@($eventResponse.events).Count -gt 0) {
            break
        }
        if ($attempt -lt $MaxPollAttempts) {
            Start-Sleep -Seconds $PollDelaySeconds
        }
    }
    if ($null -eq $eventResponse -or @($eventResponse.events).Count -eq 0) {
        throw 'The GuardDuty Finding did not reach the persistent EventBridge Log Group within the bounded wait.'
    }

    $eventPath = Join-Path $EvidenceRoot "$ExperimentId\source\aws\guardduty-eventbridge-delivery.json"
    Write-F2Json -Path $eventPath -Value ([ordered]@{
        finding_id = $findingId
        log_group = $findingLogGroup
        received_event_count = @($eventResponse.events).Count
        events = @($eventResponse.events)
    })

    $investigationScript = Join-Path $PSScriptRoot 'Invoke-FindingInvestigation.ps1'
    $investigationResult = & $investigationScript `
        -FindingId $findingId `
        -DetectorId $detectorId `
        -Region $region `
        -RuntimeProfile 'foundation-only' `
        -ScenarioId 'F2' `
        -FoundationRoot $FoundationRoot `
        -AwsProfile $AwsProfile `
        -ExpectedAccountId $ExpectedAccountId `
        -EvidenceRoot $EvidenceRoot `
        -ExperimentId $ExperimentId

    $subscriptions = Invoke-F2Native -FilePath 'aws' -ArgumentList @(
        'sns', 'list-subscriptions-by-topic',
        '--profile', $AwsProfile,
        '--region', $region,
        '--topic-arn', $alertTopicArn,
        '--output', 'json'
    ) -FailureMessage 'Security alert subscriptions could not be read.' | ConvertFrom-Json
    $confirmedSubscriptions = @(
        @($subscriptions.Subscriptions) | Where-Object {
            $_.SubscriptionArn -and
            [string]$_.SubscriptionArn -cne 'PendingConfirmation'
        }
    )
    $protocols = @(
        $confirmedSubscriptions |
            ForEach-Object { [string]$_.Protocol } |
            Sort-Object -Unique
    )

    $verificationPath = Join-Path $EvidenceRoot "$ExperimentId\results\f2-delivery-verification.json"
    Write-F2Json -Path $verificationPath -Value ([ordered]@{
        scenario_id = 'F2'
        experiment_id = $ExperimentId
        finding_id = $findingId
        sample = $true
        sample_type = $sampleFindingType
        account_id = [string]$identity.Account
        region = $region
        detector_enabled = $true
        optional_features_disabled = $expectedDisabledFeatures
        eventbridge_log_delivery = $true
        eventbridge_log_event_count = @($eventResponse.events).Count
        sns_target_configured = $true
        confirmed_subscription_count = $confirmedSubscriptions.Count
        confirmed_subscription_protocols = $protocols
        started_at_utc = $startedAt.ToString('o')
        completed_at_utc = [datetimeoffset]::UtcNow.ToString('o')
        caveat = 'AWS sample findings validate the pipeline; they are not evidence of a real attack.'
    })

    Write-Host "F2 delivery verified: Finding=$findingId"
    Write-Host "EventBridge log evidence: $eventPath"
    Write-Host "Delivery verification: $verificationPath"
    Write-Host "Confirmed SNS subscriptions: $($confirmedSubscriptions.Count)"
    Write-Host 'Next Evidence Bundle command:'
    Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'F2' -EvidenceStartUtc '$($investigationResult.WindowStartUtc)' -EvidenceEndUtc '$($investigationResult.WindowEndUtc)' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 5"
} finally {
    if (Test-Path -LiteralPath $criteriaPath) {
        Remove-Item -LiteralPath $criteriaPath -Force -ErrorAction SilentlyContinue
    }
}
