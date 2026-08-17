#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TakeId = '',
    [string]$AwsProfile = 'terra-user',
    [string]$FoundationRoot = '',
    [string]$EvidenceRoot = '',
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $FoundationRoot) {
    $FoundationRoot = Join-Path $repositoryRoot 'foundation'
}
if (-not $EvidenceRoot) {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    $EvidenceRoot = Join-Path $documents 'aws-topology-evidence\wazuh-push-validation'
}
if (-not $TakeId) {
    $TakeId = 'wazuh-push-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
}
if ($TakeId -notmatch '^wazuh-push-[0-9]{8}T[0-9]{9}Z$') {
    throw 'TakeId must use the fixed wazuh-push-yyyyMMddTHHmmssfffZ format.'
}

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $output = @(& $FilePath @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $detail = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "$FailureMessage $detail"
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{}
    }
    return $text | ConvertFrom-Json
}

foreach ($command in @('aws', 'terraform')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

$sources = @(& terraform "-chdir=$FoundationRoot" output -json wazuh_log_sources 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'The Wazuh log source output is unavailable.'
}
$sources = (($sources | ForEach-Object { [string]$_ }) -join '') | ConvertFrom-Json

$transport = @(& terraform "-chdir=$FoundationRoot" output -json wazuh_push_transport 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'The Wazuh Push transport output is unavailable.'
}
$transport = (($transport | ForEach-Object { [string]$_ }) -join '') | ConvertFrom-Json

$logGroupName = [string]$sources.cloudwatch.dvwa.log_group_name
$region = [string]$sources.cloudwatch.dvwa.region
$expectedAccountId = [string]$sources.cloudtrail.account_id
if (-not [bool]$sources.enabled -or
    -not [bool]$transport.enabled -or
    [string]$transport.source -cne 'dvwa' -or
    [string]$transport.source_log_group -cne $logGroupName -or
    [string]$transport.source_region -cne $region) {
    throw 'The active Foundation state does not match the fixed DVWA Push validation contract.'
}

$identity = Invoke-NativeJson -FilePath 'aws' -Arguments @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--region', $region,
    '--output', 'json',
    '--no-cli-pager'
) -FailureMessage 'The AWS identity could not be verified.'
if ([string]$identity.Account -cne $expectedAccountId) {
    throw 'The AWS account does not match the active Foundation state.'
}

Write-Host 'Wazuh DVWA Push validation preview'
Write-Host "Take: $TakeId"
Write-Host 'Event: wazuh.push.validation / GET /health / SAFE_VALIDATION_EVENT'
Write-Host 'No attack, credential, cookie, command, or application response is generated.'
if ($ConfirmRun -cne 'SEND WAZUH PUSH VALIDATION') {
    throw "Preview only. Re-run with -ConfirmRun 'SEND WAZUH PUSH VALIDATION'."
}

$eventTime = [DateTimeOffset]::UtcNow
$streamName = "wazuh-push-validation/$TakeId"
$message = [ordered]@{
    event_type      = 'wazuh.push.validation'
    take_id         = $TakeId
    request_method  = 'GET'
    request_path    = '/health'
    result          = 'success'
    training_marker = 'SAFE_VALIDATION_EVENT'
} | ConvertTo-Json -Compress
$logEvents = ConvertTo-Json -InputObject @(
    [ordered]@{
        timestamp = $eventTime.ToUnixTimeMilliseconds()
        message   = $message
    }
) -Compress

$tempPath = Join-Path ([IO.Path]::GetTempPath()) ("$TakeId-log-events.json")
try {
    [IO.File]::WriteAllText($tempPath, $logEvents, [Text.UTF8Encoding]::new($false))
    $logEventsUri = 'file://' + ($tempPath -replace '\\', '/')

    [void](Invoke-NativeJson -FilePath 'aws' -Arguments @(
        'logs', 'create-log-stream',
        '--log-group-name', $logGroupName,
        '--log-stream-name', $streamName,
        '--profile', $AwsProfile,
        '--region', $region,
        '--output', 'json',
        '--no-cli-pager'
    ) -FailureMessage 'The validation log stream could not be created.')

    [void](Invoke-NativeJson -FilePath 'aws' -Arguments @(
        'logs', 'put-log-events',
        '--log-group-name', $logGroupName,
        '--log-stream-name', $streamName,
        '--log-events', $logEventsUri,
        '--profile', $AwsProfile,
        '--region', $region,
        '--output', 'json',
        '--no-cli-pager'
    ) -FailureMessage 'The safe validation event could not be sent.')
} finally {
    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
}

$sentAt = [DateTimeOffset]::UtcNow
New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
$recordPath = Join-Path $EvidenceRoot "$TakeId-source.json"
$record = [ordered]@{
    schema_version  = 1
    take_id         = $TakeId
    event_type      = 'wazuh.push.validation'
    event_time      = $eventTime.ToString('o')
    sent_at         = $sentAt.ToString('o')
    source          = 'dvwa'
    source_region   = $region
    request_method  = 'GET'
    request_path    = '/health'
    result          = 'success'
    training_marker = 'SAFE_VALIDATION_EVENT'
    synthetic       = $true
    contains_attack = $false
    contains_secret = $false
} | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText($recordPath, "$record`n", [Text.UTF8Encoding]::new($false))

Write-Host "WAZUH_PUSH_TAKE_ID=$TakeId"
Write-Host "WAZUH_PUSH_EVENT_TIME_UTC=$($eventTime.ToString('o'))"
Write-Host "WAZUH_PUSH_SENT_AT_UTC=$($sentAt.ToString('o'))"
Write-Host "Sanitized source record: $recordPath"
