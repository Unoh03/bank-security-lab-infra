#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$QueueUrl = '',
    [string]$ReaderRoleArn = '',
    [string]$BootstrapProfile = 'terra-user',
    [ValidateRange(900, 3600)]
    [int]$SessionDurationSeconds = 3600,
    [string]$Region = 'ap-northeast-2',
    [string]$FoundationRoot = '',
    [string]$SpoolDirectory = '',
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
$script:liveStream = $null
$script:bridgeLockStream = $null

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
        $message = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "AWS CLI request failed: $message"
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

    if (-not $session.Credentials -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.AccessKeyId) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SecretAccessKey) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SessionToken)) {
        throw 'STS AssumeRole returned no complete temporary credential set.'
    }

    $env:AWS_ACCESS_KEY_ID = [string]$session.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = [string]$session.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_SECURITY_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_REGION = $Region
    $env:AWS_DEFAULT_REGION = $Region
    $env:AWS_EC2_METADATA_DISABLED = 'true'

    return [string]$session.Credentials.Expiration
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

    $Envelope.bridge_received_at = [DateTimeOffset]::UtcNow.ToString('o')
    $body = $Envelope | ConvertTo-Json -Depth 100 -Compress
    $eventHash = Get-StableSha256 -Value $eventId
    $eventPath = Join-Path $SpoolDirectory "$eventHash.json"
    if (Test-Path -LiteralPath $eventPath -PathType Leaf) {
        try {
            $existing = Get-Content -LiteralPath $eventPath -Raw | ConvertFrom-Json
        } catch {
            throw "Existing Wazuh Push ledger entry is not valid JSON: $eventPath"
        }
        if ([string]$existing.event_id -cne $eventId) {
            throw "Existing Wazuh Push ledger entry does not match its event ID: $eventPath"
        }
        return [pscustomobject]@{
            Created      = $false
            EventHash    = $eventHash
            Path         = $eventPath
            LiveFilePath = $liveFilePath
        }
    }

    if ($null -eq $script:liveStream) {
        throw 'The Wazuh Push live JSONL stream is not open.'
    }

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("$body`n")
    $script:liveStream.Write($bytes, 0, $bytes.Length)
    $script:liveStream.Flush($true)

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
if ($resolvedQueueUrl -notmatch '^https://sqs\.[^/]+\.amazonaws\.com/[0-9]{12}/[^/]+$') {
    throw 'The resolved SQS queue URL has an unexpected format.'
}
$resolvedReaderRoleArn = Resolve-ReaderRoleArn

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

    $script:liveStream = [IO.File]::Open(
        $liveFilePath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read
    )
    [void]$script:liveStream.Seek(0, [IO.SeekOrigin]::End)

    $sessionExpiration = Enter-ReaderRoleSession -RoleArn $resolvedReaderRoleArn
    $identity = Invoke-AwsJson -Arguments @(
        'sts', 'get-caller-identity',
        '--region', $Region,
        '--output', 'json',
        '--no-cli-pager'
    )
    $expectedRoleName = ($resolvedReaderRoleArn -split '/')[-1]
    if ([string]$identity.Arn -notmatch ":assumed-role/$([Regex]::Escape($expectedRoleName))/") {
        throw 'The temporary AWS identity does not match the expected Wazuh Reader Role.'
    }
    Write-Host "Temporary Reader Role session active until: $sessionExpiration"

    do {
        $response = Invoke-AwsJson -Arguments @(
            'sqs', 'receive-message',
            '--queue-url', $resolvedQueueUrl,
            '--max-number-of-messages', '10',
            '--wait-time-seconds', '20',
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

        if ($messages.Count -eq 0) {
            Write-Host 'No queued DVWA event arrived during this long-poll window.'
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
            Write-Host ("DVWA event {0}: {1}..." -f $verb, $stored.EventHash.Substring(0, 12))
        }
    } while (-not $Once.IsPresent)
} finally {
    if ($null -ne $script:liveStream) {
        $script:liveStream.Dispose()
        $script:liveStream = $null
    }
    if ($null -ne $script:bridgeLockStream) {
        $script:bridgeLockStream.Dispose()
        $script:bridgeLockStream = $null
    }
    foreach ($name in $temporaryEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
