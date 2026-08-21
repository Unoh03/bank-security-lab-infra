#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$QueueUrl = '',
    [string]$ReaderRoleArn = '',
    [string]$BootstrapProfile = 'terra-user',
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
    $SpoolDirectory = Join-Path (
        [Environment]::GetFolderPath('MyDocuments')
    ) 'aws-topology-evidence\wazuh-push-shadow\dvwa'
}

$expectedAccountId = '433048100798'
$expectedRegion = 'ap-northeast-2'
$liveFilePath = Join-Path $SpoolDirectory 'wazuh-push-live.jsonl'
$lockFilePath = Join-Path $SpoolDirectory 'wazuh-push-bridge.lock'
$script:readerSessionExpiresAt = [datetimeoffset]::MinValue

function Invoke-AwsJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = @(& aws @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "AWS CLI request failed: $($Arguments[0]) $($Arguments[1]) (exit $exitCode)."
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{}
    }
    try {
        return $text | ConvertFrom-Json
    } catch {
        throw "AWS CLI returned invalid JSON: $($Arguments[0]) $($Arguments[1])."
    }
}

function Invoke-BootstrapAwsJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $credentialNames = @(
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_SECURITY_TOKEN'
    )
    $saved = @{}
    foreach ($name in $credentialNames) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    try {
        return Invoke-AwsJson -Arguments (
            $Arguments + @('--profile', $BootstrapProfile)
        )
    } finally {
        foreach ($name in $credentialNames) {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
    }
}

function Get-FoundationOutput {
    param([Parameter(Mandatory)][string]$Name)

    $output = @(& terraform "-chdir=$FoundationRoot" output -raw $Name 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Terraform output is unavailable: $Name."
    }
    return (($output | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Set-ReaderSession {
    param([Parameter(Mandatory)][string]$RoleArn)

    $session = Invoke-BootstrapAwsJson -Arguments @(
        'sts', 'assume-role',
        '--role-arn', $RoleArn,
        '--role-session-name', ('wazuh-push-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')),
        '--duration-seconds', '3600',
        '--region', $Region,
        '--output', 'json',
        '--no-cli-pager'
    )
    if (-not $session.Credentials -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.AccessKeyId) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SecretAccessKey) -or
        [string]::IsNullOrWhiteSpace([string]$session.Credentials.SessionToken)) {
        throw 'STS AssumeRole returned incomplete credentials.'
    }

    $env:AWS_ACCESS_KEY_ID = [string]$session.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = [string]$session.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_SECURITY_TOKEN = [string]$session.Credentials.SessionToken
    $env:AWS_REGION = $Region
    $env:AWS_DEFAULT_REGION = $Region
    $env:AWS_EC2_METADATA_DISABLED = 'true'
    $script:readerSessionExpiresAt = [datetimeoffset]$session.Credentials.Expiration
}

function Assert-ReaderIdentity {
    param([Parameter(Mandatory)][string]$RoleArn)

    $identity = Invoke-AwsJson -Arguments @(
        'sts', 'get-caller-identity',
        '--region', $Region,
        '--output', 'json',
        '--no-cli-pager'
    )
    $roleName = ($RoleArn -split '/')[-1]
    if ([string]$identity.Account -cne $expectedAccountId -or
        [string]$identity.Arn -notmatch "^arn:aws:sts::${expectedAccountId}:assumed-role/$([regex]::Escape($roleName))/[^/]+$") {
        throw 'The active AWS identity is not the fixed Wazuh Reader Role.'
    }
}

function Get-ExistingEventIds {
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if (-not (Test-Path -LiteralPath $liveFilePath -PathType Leaf)) {
        return $ids
    }
    foreach ($line in [IO.File]::ReadLines($liveFilePath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $record = $line | ConvertFrom-Json
            $eventId = [string]$record.event_id
            if ($eventId) { [void]$ids.Add($eventId) }
        } catch {
            Write-Warning 'Skipped one malformed existing JSONL line while loading dedupe IDs.'
        }
    }
    return ,$ids
}

function ConvertTo-ValidatedEvent {
    param([Parameter(Mandatory)][string]$Body)

    try {
        $event = $Body | ConvertFrom-Json
    } catch {
        throw 'SQS message body is not JSON.'
    }
    if ([int]$event.schema_version -ne 1 -or [string]$event.source -cne 'dvwa') {
        throw 'SQS message is not a supported DVWA Push event.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$event.event_id)) {
        throw 'DVWA Push event has no event_id.'
    }
    return $event
}

function Write-LiveEvent {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][IO.FileStream]$Stream
    )

    $Event | Add-Member -NotePropertyName bridge_received_at `
        -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
    $line = ($Event | ConvertTo-Json -Depth 100 -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($line)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush($true)
}

function Remove-ConsumedMessages {
    param(
        [Parameter(Mandatory)][string]$ResolvedQueueUrl,
        [Parameter(Mandatory)][Collections.Generic.List[object]]$Entries
    )

    if ($Entries.Count -eq 0) { return }
    $temporaryPath = Join-Path $SpoolDirectory (
        'delete-message-batch-{0}.json' -f [guid]::NewGuid().ToString('N')
    )
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (ConvertTo-Json -InputObject $Entries -Depth 5 -Compress),
            [Text.UTF8Encoding]::new($false)
        )
        $result = Invoke-AwsJson -Arguments @(
            'sqs', 'delete-message-batch',
            '--queue-url', $ResolvedQueueUrl,
            '--entries', ('file://' + $temporaryPath.Replace('\', '/')),
            '--region', $Region,
            '--output', 'json',
            '--no-cli-pager'
        )
        if ($result.PSObject.Properties['Failed'] -and @($result.Failed).Count -gt 0) {
            throw 'SQS failed to delete one or more consumed messages.'
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host 'Wazuh Push Bridge'
Write-Host "Output: $liveFilePath"
if ($ConfirmConsume -cne 'CONSUME WAZUH PUSH') {
    Write-Host "Preview only. Re-run with -ConfirmConsume 'CONSUME WAZUH PUSH'."
    return
}

foreach ($command in @('aws', 'terraform')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

$resolvedQueueUrl = if ($QueueUrl) { $QueueUrl } else {
    Get-FoundationOutput -Name 'wazuh_push_primary_queue_url'
}
$resolvedReaderRoleArn = if ($ReaderRoleArn) { $ReaderRoleArn } else {
    Get-FoundationOutput -Name 'wazuh_log_reader_role_arn'
}
if ($Region -cne $expectedRegion -or
    $resolvedQueueUrl -notmatch "^https://sqs\.$expectedRegion\.amazonaws\.com/${expectedAccountId}/[A-Za-z0-9_-]+$") {
    throw 'The Queue is outside the fixed lab account or region.'
}
if ($resolvedReaderRoleArn -notmatch "^arn:aws:iam::${expectedAccountId}:role/[A-Za-z0-9+=,.@_-]+$") {
    throw 'The Reader Role is outside the fixed lab account.'
}

New-Item -ItemType Directory -Path $SpoolDirectory -Force | Out-Null
$environmentNames = @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN',
    'AWS_REGION',
    'AWS_DEFAULT_REGION',
    'AWS_EC2_METADATA_DISABLED'
)
$savedEnvironment = @{}
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$lockStream = $null
$liveStream = $null
try {
    try {
        $lockStream = [IO.File]::Open(
            $lockFilePath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch {
        throw 'Another Wazuh Push Bridge is already running.'
    }

    $eventIds = Get-ExistingEventIds
    $liveStream = [IO.File]::Open(
        $liveFilePath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::Write,
        [IO.FileShare]::ReadWrite
    )
    [void]$liveStream.Seek(0, [IO.SeekOrigin]::End)

    Set-ReaderSession -RoleArn $resolvedReaderRoleArn
    Assert-ReaderIdentity -RoleArn $resolvedReaderRoleArn
    Write-Host 'WAZUH_PUSH_BRIDGE_READY=yes'

    do {
        if ([datetimeoffset]::UtcNow -ge $script:readerSessionExpiresAt.AddMinutes(-5)) {
            Set-ReaderSession -RoleArn $resolvedReaderRoleArn
            Assert-ReaderIdentity -RoleArn $resolvedReaderRoleArn
        }

        $response = Invoke-AwsJson -Arguments @(
            'sqs', 'receive-message',
            '--queue-url', $resolvedQueueUrl,
            '--max-number-of-messages', '10',
            '--wait-time-seconds', '20',
            '--visibility-timeout', '120',
            '--region', $Region,
            '--output', 'json',
            '--no-cli-pager'
        )
        $messages = if ($response.PSObject.Properties['Messages']) {
            @($response.Messages)
        } else {
            @()
        }

        $deleteEntries = [Collections.Generic.List[object]]::new()
        $storedCount = 0
        $index = 0
        foreach ($message in $messages) {
            try {
                $event = ConvertTo-ValidatedEvent -Body ([string]$message.Body)
                $eventId = [string]$event.event_id
                if ($eventIds.Add($eventId)) {
                    Write-LiveEvent -Event $event -Stream $liveStream
                    $storedCount++
                }
                $deleteEntries.Add([ordered]@{
                    Id = ('message-{0:d2}' -f $index)
                    ReceiptHandle = [string]$message.ReceiptHandle
                })
                $index++
            } catch {
                Write-Warning "Message left in SQS: $($_.Exception.Message)"
            }
        }

        if ($deleteEntries.Count -gt 0) {
            Remove-ConsumedMessages -ResolvedQueueUrl $resolvedQueueUrl -Entries $deleteEntries
        }
        if ($messages.Count -gt 0) {
            Write-Host "Consumed=$($deleteEntries.Count) Stored=$storedCount"
        }
    } while (-not $Once.IsPresent)
} finally {
    if ($liveStream) { $liveStream.Dispose() }
    if ($lockStream) { $lockStream.Dispose() }
    Remove-Item -LiteralPath $lockFilePath -Force -ErrorAction SilentlyContinue
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
