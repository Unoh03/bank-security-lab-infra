#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$QueueUrl = '',
    [string]$DlqUrl = '',
    [string]$ReaderRoleArn = '',
    [string]$BootstrapProfile = 'terra-user',
    [ValidateRange(900, 3600)]
    [int]$SessionDurationSeconds = 3600,
    [string]$Region = 'ap-northeast-2',
    [string]$FoundationRoot = '',
    [string]$SpoolDirectory = '',
    [string]$HeartbeatPath = '',
    [string]$StopSignalPath = '',
    [ValidateRange(0, 3600)]
    [int]$MaxReadyQueueAgeSeconds = 120,
    [switch]$Once,
    [string]$ConfirmConsume = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $FoundationRoot) {
    $FoundationRoot = Join-Path $repositoryRoot 'foundation'
}
if (-not $SpoolDirectory) {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    $SpoolDirectory = Join-Path $documents 'aws-topology-evidence\wazuh-push-shadow\dvwa'
}
$liveFilePath = Join-Path $SpoolDirectory 'wazuh-push-live.jsonl'
$lockFilePath = Join-Path $SpoolDirectory 'wazuh-push-bridge.lock'
if (-not $HeartbeatPath) {
    $HeartbeatPath = Join-Path $SpoolDirectory 'wazuh-push-bridge-heartbeat.json'
}
if (-not $StopSignalPath) {
    $StopSignalPath = Join-Path $SpoolDirectory 'wazuh-push-bridge.stop'
}
$script:liveStream = $null
$script:bridgeLockStream = $null
$script:sessionExpiration = [datetimeoffset]::MinValue
$script:lastEventHash = ''
$script:queueVisible = -1
$script:queueNotVisible = -1
$script:queueOldestAgeSeconds = -1
$script:dlqVisible = -1
$script:lastQueueMetricsAt = [datetimeoffset]::MinValue
$script:startedAt = [datetimeoffset]::UtcNow
$script:bridgeFailed = $false
$heartbeatIntervalSeconds = 10
$queueMetricsIntervalSeconds = 30
$sessionRefreshBeforeSeconds = 300
$expectedAccountId = '433048100798'
$expectedRegion = 'ap-northeast-2'

function Get-StableSha256 {
    param([Parameter(Mandatory)][string]$Value)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Invoke-AwsJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = @(& aws @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI request failed for $($Arguments[0]) $($Arguments[1])."
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{}
    }
    return $text | ConvertFrom-Json
}

function Resolve-QueueUrl {
    if ($QueueUrl) {
        return $QueueUrl
    }

    $output = @(& terraform "-chdir=$FoundationRoot" output -raw wazuh_push_primary_queue_url 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'The Push queue URL is unavailable. Apply the reviewed DVWA Push Foundation plan or pass -QueueUrl explicitly.'
    }
    return (($output | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Resolve-DlqUrl {
    if ($DlqUrl) {
        return $DlqUrl
    }

    $output = @(& terraform "-chdir=$FoundationRoot" output -raw wazuh_push_primary_dlq_url 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'The Push DLQ URL is unavailable. Apply the reviewed Reader Foundation policy and output first.'
    }
    return (($output | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Resolve-ReaderRoleArn {
    if ($ReaderRoleArn) {
        return $ReaderRoleArn
    }

    $output = @(& terraform "-chdir=$FoundationRoot" output -raw wazuh_log_reader_role_arn 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'The Wazuh Reader Role ARN is unavailable. Apply the reviewed Reader Foundation plan or pass -ReaderRoleArn explicitly.'
    }
    return (($output | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Enter-ReaderRoleSession {
    param([Parameter(Mandatory)][string]$RoleArn)

    if ($RoleArn -notmatch '^arn:[^:]+:iam::[0-9]{12}:role/.+$') {
        throw 'The resolved Wazuh Reader Role ARN has an unexpected format.'
    }

    $sessionName = 'wazuh-push-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $credentialNames = @(
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_SECURITY_TOKEN'
    )
    $currentCredentials = @{}
    foreach ($name in $credentialNames) {
        $currentCredentials[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    try {
        $session = Invoke-AwsJson -Arguments @(
            'sts', 'assume-role',
            '--role-arn', $RoleArn,
            '--role-session-name', $sessionName,
            '--duration-seconds', [string]$SessionDurationSeconds,
            '--profile', $BootstrapProfile,
            '--region', $Region,
            '--output', 'json',
            '--no-cli-pager'
        )
    } catch {
        foreach ($name in $credentialNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $currentCredentials[$name],
                'Process'
            )
        }
        throw
    }

    if (-not $session.Credentials -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.AccessKeyId) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SecretAccessKey) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SessionToken)) {
        foreach ($name in $credentialNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $currentCredentials[$name],
                'Process'
            )
        }
        throw 'STS AssumeRole returned no complete temporary credential set.'
    }

    $env:AWS_ACCESS_KEY_ID = [string]$session.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = [string]$session.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_SECURITY_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_REGION = $Region
    $env:AWS_DEFAULT_REGION = $Region
    $env:AWS_EC2_METADATA_DISABLED = 'true'

    $script:sessionExpiration = [datetimeoffset]$session.Credentials.Expiration
    return $script:sessionExpiration
}

function Write-BridgeHeartbeat {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('STARTING','READY','RUNNING','DEGRADED','STOPPED')]
        [string]$State
    )

    $record = [ordered]@{
        schema_version                  = 1
        pid                             = $PID
        state                           = $State
        started_at_utc                  = $script:startedAt.ToString('o')
        heartbeat_at_utc                = [datetimeoffset]::UtcNow.ToString('o')
        session_expires_at_utc           = if ($script:sessionExpiration -eq [datetimeoffset]::MinValue) { '' } else { $script:sessionExpiration.ToUniversalTime().ToString('o') }
        last_event_hash                 = $script:lastEventHash
        queue_visible                   = $script:queueVisible
        queue_not_visible               = $script:queueNotVisible
        queue_oldest_age_seconds        = $script:queueOldestAgeSeconds
        dlq_visible                     = $script:dlqVisible
        heartbeat_interval_seconds      = $heartbeatIntervalSeconds
        queue_metrics_interval_seconds  = $queueMetricsIntervalSeconds
    }
    $json = ($record | ConvertTo-Json -Depth 5 -Compress) + "`n"
    $temporaryPath = "$HeartbeatPath.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$HeartbeatPath.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $HeartbeatPath -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $HeartbeatPath, $backupPath)
            Remove-Item -LiteralPath $backupPath -Force
        } else {
            [IO.File]::Move($temporaryPath, $HeartbeatPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-QueueMetrics {
    param([Parameter(Mandatory)][string]$Url)

    $result = Invoke-AwsJson -Arguments @(
        'sqs', 'get-queue-attributes',
        '--queue-url', $Url,
        '--attribute-names',
        'ApproximateNumberOfMessages',
        'ApproximateNumberOfMessagesNotVisible',
        'ApproximateAgeOfOldestMessage',
        '--region', $Region,
        '--output', 'json',
        '--no-cli-pager'
    )
    $attributes = $result.Attributes
    $visibleProperty = if ($null -eq $attributes) {
        $null
    } else {
        $attributes.PSObject.Properties['ApproximateNumberOfMessages']
    }
    $oldestProperty = if ($null -eq $attributes) {
        $null
    } else {
        $attributes.PSObject.Properties['ApproximateAgeOfOldestMessage']
    }
    $notVisibleProperty = if ($null -eq $attributes) {
        $null
    } else {
        $attributes.PSObject.Properties['ApproximateNumberOfMessagesNotVisible']
    }
    return [pscustomobject]@{
        Visible = if ($null -eq $visibleProperty) { 0 } else { [int]$visibleProperty.Value }
        NotVisible = if ($null -eq $notVisibleProperty) { 0 } else { [int]$notVisibleProperty.Value }
        OldestAgeSeconds = if ($null -eq $oldestProperty) { 0 } else { [int]$oldestProperty.Value }
    }
}

function Update-QueueMetrics {
    param(
        [Parameter(Mandatory)][string]$PrimaryUrl,
        [Parameter(Mandatory)][string]$DeadLetterUrl,
        [switch]$Force
    )

    $now = [datetimeoffset]::UtcNow
    if (-not $Force.IsPresent -and
        $now -lt $script:lastQueueMetricsAt.AddSeconds($queueMetricsIntervalSeconds)) {
        return
    }
    $primary = Get-QueueMetrics -Url $PrimaryUrl
    $deadLetter = Get-QueueMetrics -Url $DeadLetterUrl
    $script:queueVisible = $primary.Visible
    $script:queueNotVisible = $primary.NotVisible
    $script:queueOldestAgeSeconds = $primary.OldestAgeSeconds
    $script:dlqVisible = $deadLetter.Visible
    $script:lastQueueMetricsAt = $now
}

function Ensure-ReaderRoleSession {
    param([Parameter(Mandatory)][string]$RoleArn)

    if ([datetimeoffset]::UtcNow -ge
        $script:sessionExpiration.AddSeconds(-$sessionRefreshBeforeSeconds)) {
        [void](Enter-ReaderRoleSession -RoleArn $RoleArn)
    }
}

function Get-BridgeEnvelopeIdentityHash {
    param([Parameter(Mandatory)][object]$Envelope)

    $copy = ($Envelope | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json
    if ($null -ne $copy.PSObject.Properties['bridge_received_at']) {
        $copy.PSObject.Properties.Remove('bridge_received_at')
    }
    return Get-StableSha256 -Value ($copy | ConvertTo-Json -Depth 100 -Compress)
}

function Test-LiveFileContainsEventId {
    param([Parameter(Mandatory)][string]$EventId)

    if (-not (Test-Path -LiteralPath $liveFilePath -PathType Leaf)) {
        return $false
    }
    $stream = [IO.File]::Open(
        $liveFilePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite
    )
    $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true)
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.Length -gt 1048576) {
                throw 'A Wazuh Push live JSONL line exceeded 1 MiB.'
            }
            try {
                $candidate = $line | ConvertFrom-Json
            } catch {
                throw 'The Wazuh Push live JSONL contains invalid JSON.'
            }
            if ([string]$candidate.event_id -ceq $EventId) {
                return $true
            }
        }
        return $false
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Write-LiveEventBytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    if ($null -eq $script:liveStream) {
        throw 'The Wazuh Push live JSONL stream is not open.'
    }
    $script:liveStream.Write($Bytes,0,$Bytes.Length)
    $script:liveStream.Flush($true)
}

function Write-ShadowEvent {
    param([Parameter(Mandatory)][object]$Envelope)

    if ([int]$Envelope.schema_version -ne 1) {
        throw 'Unsupported Wazuh Push schema_version.'
    }
    if ([string]$Envelope.source -cne 'dvwa') {
        throw 'The Primary shadow bridge accepts only source=dvwa.'
    }
    $eventId = [string]$Envelope.event_id
    if ([string]::IsNullOrWhiteSpace($eventId)) {
        throw 'The Wazuh Push envelope has no event_id.'
    }

    $eventHash = Get-StableSha256 -Value $eventId
    $eventPath = Join-Path $SpoolDirectory "$eventHash.json"
    if (Test-Path -LiteralPath $eventPath -PathType Leaf) {
        try {
            $existingText = Get-Content -LiteralPath $eventPath -Raw
            $existing = $existingText | ConvertFrom-Json
        } catch {
            throw "Existing Wazuh Push ledger entry is not valid JSON: $eventPath"
        }
        if ([string]$existing.event_id -cne $eventId -or
            (Get-BridgeEnvelopeIdentityHash -Envelope $existing) -cne
                (Get-BridgeEnvelopeIdentityHash -Envelope $Envelope)) {
            throw "Existing Wazuh Push ledger entry does not match the redelivered event: $eventPath"
        }
        if (-not (Test-LiveFileContainsEventId -EventId $eventId)) {
            $recoveryBytes = [Text.UTF8Encoding]::new($false).GetBytes(
                $existingText.TrimEnd("`r","`n") + "`n"
            )
            Write-LiveEventBytes -Bytes $recoveryBytes
        }
        return [pscustomobject]@{
            Created      = $false
            EventHash    = $eventHash
            Path         = $eventPath
            LiveFilePath = $liveFilePath
        }
    }

    $Envelope.bridge_received_at = [DateTimeOffset]::UtcNow.ToString('o')
    $body = $Envelope | ConvertTo-Json -Depth 100 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("$body`n")
    $temporaryEventPath = "$eventPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $stream = [IO.File]::Open(
        $temporaryEventPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    try {
        [IO.File]::Move($temporaryEventPath, $eventPath)
    } finally {
        if (Test-Path -LiteralPath $temporaryEventPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryEventPath -Force
        }
    }
    Write-LiveEventBytes -Bytes $bytes

    return [pscustomobject]@{
        Created      = $true
        EventHash    = $eventHash
        Path         = $eventPath
        LiveFilePath = $liveFilePath
    }
}

Write-Host 'Wazuh DVWA Push shadow bridge preview'
Write-Host "Region: $Region"
Write-Host "Bootstrap profile: $BootstrapProfile"
Write-Host "Shadow spool: $SpoolDirectory"
Write-Host "Wazuh live JSONL: $liveFilePath"
Write-Host 'Input contract: every event already stored in the approved DVWA CloudWatch log group'
Write-Host 'Bridge output: durable Host spool; Wazuh localfile consumption is configured separately.'

if ($ConfirmConsume -cne 'CONSUME WAZUH PUSH') {
    Write-Host "No queue message was received or deleted. Rerun with -ConfirmConsume 'CONSUME WAZUH PUSH'."
    return
}

foreach ($command in @('aws', 'terraform')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

$resolvedQueueUrl = Resolve-QueueUrl
if ($Region -cne $expectedRegion -or
    $resolvedQueueUrl -notmatch "^https://sqs\.$([regex]::Escape($expectedRegion))\.amazonaws\.com/$expectedAccountId/[A-Za-z0-9_-]+$") {
    throw 'The resolved SQS queue URL has an unexpected format.'
}
$resolvedDlqUrl = Resolve-DlqUrl
if ($resolvedDlqUrl -notmatch "^https://sqs\.$([regex]::Escape($expectedRegion))\.amazonaws\.com/$expectedAccountId/[A-Za-z0-9_-]+$" -or
    $resolvedDlqUrl -ceq $resolvedQueueUrl) {
    throw 'The resolved SQS DLQ URL has an unexpected format.'
}
$resolvedReaderRoleArn = Resolve-ReaderRoleArn
if ($resolvedReaderRoleArn -notmatch "^arn:aws:iam::$expectedAccountId:role/[A-Za-z0-9+=,.@_-]+$") {
    throw 'The resolved Wazuh Reader Role is outside the fixed lab account.'
}

New-Item -ItemType Directory -Path $SpoolDirectory -Force | Out-Null

$temporaryEnvironmentNames = @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN',
    'AWS_REGION',
    'AWS_DEFAULT_REGION',
    'AWS_EC2_METADATA_DISABLED'
)
$previousEnvironment = @{}
foreach ($name in $temporaryEnvironmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    try {
        $script:bridgeLockStream = [IO.File]::Open(
            $lockFilePath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch {
        throw 'Another Wazuh Push bridge already holds the local spool lock.'
    }
    if (Test-Path -LiteralPath $StopSignalPath -PathType Leaf) {
        Remove-Item -LiteralPath $StopSignalPath -Force
    }
    Write-BridgeHeartbeat -State STARTING

    $script:liveStream = [IO.File]::Open(
        $liveFilePath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read
    )
    [void]$script:liveStream.Seek(0, [IO.SeekOrigin]::End)

    [void](Enter-ReaderRoleSession -RoleArn $resolvedReaderRoleArn)
    $identity = Invoke-AwsJson -Arguments @(
        'sts', 'get-caller-identity',
        '--region', $Region,
        '--output', 'json',
        '--no-cli-pager'
    )
    $expectedRoleName = ($resolvedReaderRoleArn -split '/')[-1]
    if ([string]$identity.Account -cne $expectedAccountId -or
        [string]$identity.Arn -notmatch "^arn:aws:sts::$expectedAccountId:assumed-role/$([Regex]::Escape($expectedRoleName))/[^/]+$") {
        throw 'The temporary AWS identity does not match the expected Wazuh Reader Role.'
    }
    Update-QueueMetrics `
        -PrimaryUrl $resolvedQueueUrl `
        -DeadLetterUrl $resolvedDlqUrl `
        -Force
    if ($script:dlqVisible -ne 0) {
        throw 'The Primary Push DLQ is not empty; the bridge cannot enter READY.'
    }
    if ($script:queueNotVisible -ne 0) {
        throw 'The Primary Push queue already has an in-flight message; the bridge cannot enter READY.'
    }
    if ($script:queueVisible -gt 0 -and
        $script:queueOldestAgeSeconds -gt $MaxReadyQueueAgeSeconds) {
        throw 'The Primary Push queue contains stale messages; the bridge cannot enter READY.'
    }
    Write-BridgeHeartbeat -State READY
    Write-Host "Temporary Reader Role session active until: $($script:sessionExpiration.ToUniversalTime().ToString('o'))"
    Write-Host 'WAZUH_PUSH_BRIDGE_READY=yes'

    do {
        if (Test-Path -LiteralPath $StopSignalPath -PathType Leaf) {
            break
        }
        Ensure-ReaderRoleSession -RoleArn $resolvedReaderRoleArn
        Update-QueueMetrics `
            -PrimaryUrl $resolvedQueueUrl `
            -DeadLetterUrl $resolvedDlqUrl
        if ($script:dlqVisible -ne 0) {
            throw 'The Primary Push DLQ became non-empty; consumption stopped.'
        }
        Write-BridgeHeartbeat -State RUNNING

        $response = Invoke-AwsJson -Arguments @(
            'sqs', 'receive-message',
            '--queue-url', $resolvedQueueUrl,
            '--max-number-of-messages', '10',
            '--wait-time-seconds', [string]$heartbeatIntervalSeconds,
            '--visibility-timeout', '90',
            '--attribute-names', 'All',
            '--message-attribute-names', 'All',
            '--region', $Region,
            '--output', 'json',
            '--no-cli-pager'
        )

        $messages = @()
        $responsePropertyNames = @(
            $response.PSObject.Properties | ForEach-Object { $_.Name }
        )
        if ($responsePropertyNames -contains 'Messages' -and $null -ne $response.Messages) {
            $messages = @($response.Messages)
        }

        foreach ($message in $messages) {
            $envelope = [string]$message.Body | ConvertFrom-Json
            $stored = Write-ShadowEvent -Envelope $envelope

            Invoke-AwsJson -Arguments @(
                'sqs', 'delete-message',
                '--queue-url', $resolvedQueueUrl,
                '--receipt-handle', [string]$message.ReceiptHandle,
                '--region', $Region,
                '--output', 'json',
                '--no-cli-pager'
            ) | Out-Null

            $verb = if ($stored.Created) { 'stored' } else { 'deduplicated' }
            $script:lastEventHash = $stored.EventHash
            Write-Host ("DVWA event {0}: {1}..." -f $verb, $stored.EventHash.Substring(0, 12))
        }
        Write-BridgeHeartbeat -State RUNNING
    } while (-not $Once.IsPresent)
} catch {
    $script:bridgeFailed = $true
    try {
        Write-BridgeHeartbeat -State DEGRADED
    } catch {
        # Preserve the original failure if the diagnostic heartbeat cannot be written.
    }
    throw
} finally {
    if ($null -ne $script:liveStream) {
        $script:liveStream.Dispose()
        $script:liveStream = $null
    }
    if ($null -ne $script:bridgeLockStream) {
        $script:bridgeLockStream.Dispose()
        $script:bridgeLockStream = $null
    }
    if (Test-Path -LiteralPath $lockFilePath -PathType Leaf) {
        Remove-Item -LiteralPath $lockFilePath -Force -ErrorAction SilentlyContinue
    }
    if (-not $script:bridgeFailed) {
        try {
            Write-BridgeHeartbeat -State STOPPED
        } catch {
            # Cleanup must still restore the caller's environment.
        }
    }
    foreach ($name in $temporaryEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
