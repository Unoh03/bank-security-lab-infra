#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$detectionPath = Join-Path $root 'foundation\detection.tf'
$outputsPath = Join-Path $root 'foundation\outputs.tf'
$projectPath = Join-Path $root 'automation\project.psd1'
$queryPath = Join-Path $root 'observability\queries\cloudwatch\12_guardduty_findings.cwli'
$runnerPath = Join-Path $root 'observability\findings\Invoke-F2.ps1'
$investigationPath = Join-Path $root 'observability\findings\Invoke-FindingInvestigation.ps1'
$readmePath = Join-Path $root 'observability\findings\README.md'

function Assert-Contains {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

foreach ($path in @(
    $detectionPath,
    $outputsPath,
    $projectPath,
    $queryPath,
    $runnerPath,
    $investigationPath,
    $readmePath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required F2 file is missing: $path"
    }
}

foreach ($scriptPath in @($runnerPath, $investigationPath)) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null
    if ($errors.Count -gt 0) {
        throw "PowerShell parser errors in '$scriptPath': $($errors.Message -join '; ')"
    }
}

$detection = [System.IO.File]::ReadAllText($detectionPath)
$outputs = [System.IO.File]::ReadAllText($outputsPath)
$project = [System.IO.File]::ReadAllText($projectPath)
$query = [System.IO.File]::ReadAllText($queryPath)
$runner = [System.IO.File]::ReadAllText($runnerPath)
$investigation = [System.IO.File]::ReadAllText($investigationPath)

Assert-Contains $detection 'resource\s+"aws_guardduty_detector"\s+"primary"' `
    'The persistent Primary GuardDuty detector is missing.'
Assert-Contains $detection 'finding_publishing_frequency\s*=\s*"FIFTEEN_MINUTES"' `
    'GuardDuty Finding publishing frequency is not explicit.'
foreach ($feature in @(
    'S3_DATA_EVENTS',
    'EKS_AUDIT_LOGS',
    'EBS_MALWARE_PROTECTION',
    'RDS_LOGIN_EVENTS',
    'LAMBDA_NETWORK_LOGS',
    'RUNTIME_MONITORING',
    'AI_PROTECTION'
)) {
    Assert-Contains $detection ([regex]::Escape('"' + $feature + '"')) `
        "GuardDuty optional feature '$feature' is not explicitly controlled."
}
if ($detection -match '"EKS_RUNTIME_MONITORING"') {
    throw 'Deprecated EKS_RUNTIME_MONITORING must not be enabled or managed for F2.'
}
foreach ($configuration in @(
    'EC2_AGENT_MANAGEMENT',
    'ECS_FARGATE_AGENT_MANAGEMENT',
    'EKS_ADDON_MANAGEMENT'
)) {
    Assert-Contains $detection ([regex]::Escape('"' + $configuration + '"')) `
        "Runtime Monitoring additional configuration '$configuration' is not explicitly controlled."
}
Assert-Contains $detection 'status\s*=\s*"DISABLED"' `
    'GuardDuty optional protection plans are not explicitly disabled.'
Assert-Contains $detection '"detail-type"\s*=\s*\["GuardDuty Finding"\]' `
    'The EventBridge rule is not bound to GuardDuty Finding events.'
Assert-Contains $detection 'account\s*=\s*\[data\.aws_caller_identity\.current\.account_id\]' `
    'The EventBridge Finding rule is not scoped to the current account.'
Assert-Contains $detection 'resource\s+"aws_cloudwatch_event_target"\s+"guardduty_log"[\s\S]*?depends_on\s*=\s*\[aws_cloudwatch_log_resource_policy\.guardduty_eventbridge\]' `
    'The EventBridge Logs target lacks its resource-policy dependency.'
Assert-Contains $detection 'resource\s+"aws_cloudwatch_event_target"\s+"guardduty_alert"[\s\S]*?role_arn\s*=\s*aws_iam_role\.guardduty_eventbridge\.arn' `
    'The EventBridge SNS target lacks its narrowly scoped execution role.'
Assert-Contains $detection 'maximum_retry_attempts\s*=\s*3' `
    'F2 delivery retry attempts are not bounded.'
Assert-Contains $detection 'maximum_event_age_in_seconds\s*=\s*3600' `
    'F2 delivery event age is not bounded.'
Assert-Contains $outputs 'output\s+"guardduty_detector_id"' `
    'The GuardDuty detector ID output is missing.'
Assert-Contains $outputs 'guardduty_findings\s*=\s*aws_cloudwatch_log_group\.guardduty_findings' `
    'The persistent Finding Log Group is absent from the Foundation output map.'

Assert-Contains $project "ScenarioIds\s*=\s*@\('F2'\)" `
    'The Evidence Collector has no F2 Scenario mapping.'
Assert-Contains $project "QueryFile\s*=\s*'cloudwatch\\12_guardduty_findings\.cwli'" `
    'The Evidence Collector does not reference the F2 Query.'
foreach ($metadata in @('Purpose:', 'Normal:', 'Attack/abuse:', 'False positive:', 'Runtime verification:')) {
    if (-not $query.Contains($metadata)) {
        throw "The F2 Query is missing metadata: $metadata"
    }
}
foreach ($safeField in @('finding_id', 'finding_type', 'severity', 'resource_type')) {
    if (-not $query.Contains($safeField)) {
        throw "The F2 Query is missing investigation field: $safeField"
    }
}
$queryBodyIndex = $query.IndexOf('fields ', [System.StringComparison]::OrdinalIgnoreCase)
if ($queryBodyIndex -lt 0) {
    throw 'The F2 Query has no executable fields clause.'
}
$queryBody = $query.Substring($queryBodyIndex)
if ($queryBody -match '(?i)description|accessKeyId|authorization|cookie|password') {
    throw 'The F2 Query returns a forbidden or unnecessarily sensitive field.'
}

$gateIndex = $runner.IndexOf("if (`$ConfirmRun -cne 'RUN F2 SAMPLE FINDING')")
$mutationIndex = $runner.IndexOf("'guardduty', 'create-sample-findings'")
if ($gateIndex -lt 0 -or $mutationIndex -lt 0 -or $gateIndex -gt $mutationIndex) {
    throw 'The exact F2 approval gate does not precede the AWS sample Finding mutation.'
}
Assert-Contains $runner 'MaxPollAttempts' 'F2 Finding polling is not bounded.'
Assert-Contains $runner 'PollDelaySeconds' 'F2 Finding polling delay is not bounded.'
Assert-Contains $runner 'Preview only' 'F2 lacks a non-mutating Preview boundary.'
Assert-Contains $investigation 'input_contract\s*=\s*''FindingId only;' `
    'The investigation contract does not derive context from FindingId.'
if ($investigation -match '(?m)^\s*\[string\]\$(SourceIp|FindingType)\s*=') {
    throw 'The investigator must not require a pre-known source IP or attack type.'
}

$script:f2MutationCalled = $false
function global:terraform {
    $signature = $args -join ' '
    $global:LASTEXITCODE = 0
    switch -Regex ($signature) {
        'output -raw aws_region$' { return 'ap-northeast-2' }
        'output -raw guardduty_detector_id$' { return 'detector-test-id' }
        'output -raw guardduty_finding_event_rule_name$' { return 'aws-topology-guardduty-findings' }
        'output -raw guardduty_finding_log_group_name$' { return '/aws/events/aws-topology-guardduty-findings' }
        'output -raw security_alert_topic_arn$' { return 'arn:aws:sns:ap-northeast-2:433048100798:aws-topology-security-alerts' }
        'output -json security_log_group_arns$' {
            return '{"guardduty_findings":"arn:aws:logs:ap-northeast-2:433048100798:log-group:/aws/events/aws-topology-guardduty-findings"}'
        }
        'output -json guardduty_optional_features$' {
            return '{"S3_DATA_EVENTS":"DISABLED","EKS_AUDIT_LOGS":"DISABLED","EBS_MALWARE_PROTECTION":"DISABLED","RDS_LOGIN_EVENTS":"DISABLED","LAMBDA_NETWORK_LOGS":"DISABLED","RUNTIME_MONITORING":"DISABLED","AI_PROTECTION":"DISABLED"}'
        }
        default { throw "Unexpected mocked terraform command: $signature" }
    }
}
function global:aws {
    $signature = $args -join ' '
    $global:LASTEXITCODE = 0
    switch -Regex ($signature) {
        '^sts get-caller-identity ' {
            return '{"Account":"433048100798","Arn":"arn:aws:iam::433048100798:user/test","UserId":"test"}'
        }
        '^events list-targets-by-rule ' {
            return '{"Targets":[{"Id":"guardduty-finding-log","Arn":"arn:aws:logs:ap-northeast-2:433048100798:log-group:/aws/events/aws-topology-guardduty-findings"},{"Id":"guardduty-finding-alert","Arn":"arn:aws:sns:ap-northeast-2:433048100798:aws-topology-security-alerts","RoleArn":"arn:aws:iam::433048100798:role/aws-topology-guardduty-eventbridge"}]}'
        }
        '^guardduty get-detector ' { return '{"Status":"ENABLED"}' }
        '^guardduty create-sample-findings ' {
            $script:f2MutationCalled = $true
            throw 'Preview invoked the sample Finding mutation.'
        }
        default { throw "Unexpected mocked aws command: $signature" }
    }
}
try {
    & $runnerPath -FoundationRoot (Join-Path $root 'foundation') | Out-Null
    if ($script:f2MutationCalled) {
        throw 'F2 Preview crossed the AWS mutation gate.'
    }
} finally {
    Remove-Item -LiteralPath Function:\global:terraform -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\global:aws -ErrorAction SilentlyContinue
}

$fixtureId = '0123456789abcdef0123456789abcdef'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-f2-test-' + [guid]::NewGuid().ToString('N')
)
try {
    New-Item -ItemType Directory -Force -Path $fixtureRoot | Out-Null
    $fixturePath = Join-Path $fixtureRoot 'finding.json'
    $fixture = [ordered]@{
        Findings = @([ordered]@{
            AccountId = '433048100798'
            Id = $fixtureId
            Region = 'ap-northeast-2'
            Type = 'Backdoor:EC2/DenialOfService.Tcp'
            Severity = 8
            Title = '[SAMPLE] Test Finding'
            CreatedAt = '2026-08-04T00:00:00Z'
            UpdatedAt = '2026-08-04T00:02:00Z'
            Resource = [ordered]@{
                ResourceType = 'Instance'
                InstanceDetails = @{
                    InstanceId = 'i-0123456789abcdef0'
                }
                AccessKeyDetails = @{
                    AccessKeyId = 'AKIAREDACTME'
                    PrincipalId = 'test-principal'
                }
            }
            Service = [ordered]@{
                EventFirstSeen = '2026-08-04T00:00:30Z'
                EventLastSeen = '2026-08-04T00:01:30Z'
                Action = [ordered]@{
                    ActionType = 'NETWORK_CONNECTION'
                    NetworkConnectionAction = [ordered]@{
                        RemoteIpDetails = @{ IpAddressV4 = '203.0.113.10' }
                    }
                }
            }
        })
    }
    [System.IO.File]::WriteAllText(
        $fixturePath,
        ($fixture | ConvertTo-Json -Depth 20),
        (New-Object System.Text.UTF8Encoding($false))
    )

    $result = & $investigationPath `
        -FindingId $fixtureId `
        -InputFindingPath $fixturePath `
        -EvidenceRoot $fixtureRoot `
        -ExperimentId 'offline-f2-test' `
        -ExpectedAccountId '433048100798'
    $result = @($result | Where-Object { $_.PSObject.Properties['FindingId'] })
    if ($result.Count -ne 1 -or -not $result[0].Sample) {
        throw 'The offline Finding investigation did not recognize the sample Finding.'
    }

    $normalizedPath = Join-Path $fixtureRoot 'offline-f2-test\source\aws\guardduty-finding.normalized.json'
    $planPath = Join-Path $fixtureRoot 'offline-f2-test\queries\f2-investigation-plan.json'
    $normalizedText = [System.IO.File]::ReadAllText($normalizedPath)
    $normalized = $normalizedText | ConvertFrom-Json
    $plan = [System.IO.File]::ReadAllText($planPath) | ConvertFrom-Json
    if ([string]$normalized.entities.source_ips -notmatch '203\.0\.113\.10' -or
        [string]$normalized.entities.compute_ids -notmatch 'i-0123456789abcdef0') {
        throw 'The investigator failed to derive entities from the Finding.'
    }
    if ($normalizedText -match 'AKIAREDACTME|AccessKeyId') {
        throw 'The normalized Finding retained an Access Key identifier.'
    }
    if (@($plan.query_plan.Queries | Where-Object { $_.Name -eq 'vpc-reject' }).Count -ne 1) {
        throw 'The EC2 network sample did not derive the VPC REJECT investigation query.'
    }
    if ([datetimeoffset]$normalized.window_start_utc -ge [datetimeoffset]'2026-08-04T00:00:00Z' -or
        [datetimeoffset]$normalized.window_end_utc -le [datetimeoffset]'2026-08-04T00:02:00Z') {
        throw 'The investigator did not add a bounded correlation margin to the Finding window.'
    }
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host 'Finding F2 static and offline contract tests passed.'
