#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AwsProfile = 'terra-user',
    [string]$EvidenceRoot = '',
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$region = 'ap-northeast-2'
$expectedAccountId = '433048100798'
$objectKey = 'validation/capital-one-demo.csv'
$trainingMarker = 'FAKE_TRAINING_DATA'
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path (
        [Environment]::GetFolderPath('MyDocuments')
    ) 'aws-topology-evidence'
}

. (Join-Path $terraformRoot 'daily-common.ps1')

function Write-CapitalOneJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 8),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-StringSha256 {
    param([Parameter(Mandatory)][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

foreach ($name in @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN'
)) {
    if ([Environment]::GetEnvironmentVariable($name, 'Process')) {
        throw "Clear the process-level $name before preparing the demo object."
    }
}

Assert-CommandAvailable -Name 'terraform' | Out-Null
Assert-CommandAvailable -Name 'aws' | Out-Null

$identity = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--region', $region,
    '--output', 'json',
    '--no-cli-pager'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $expectedAccountId) {
    throw 'AWS account mismatch. The fixed Capital One lab account is required.'
}

$securityProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'security_scenario_profile'
) -FailureMessage 'The active security scenario profile is unavailable.').Trim()
if ($securityProfile -cne 'capital-one-lab') {
    throw "The demo object may be prepared only for capital-one-lab; active=$securityProfile."
}

$dataEventsEnabled = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$(Join-Path $terraformRoot 'foundation')",
    'output', '-raw', 'project_s3_data_events_enabled'
) -FailureMessage 'The Foundation S3 Data Event state is unavailable.').Trim()
if ($dataEventsEnabled.ToLowerInvariant() -cne 'true') {
    throw 'Capital One preparation requires approved Foundation S3 Data Events.'
}

$bucket = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'primary_application_bucket_name'
) -FailureMessage 'The Primary application bucket is unavailable.').Trim()
if ($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
    throw 'Terraform returned an unsafe Primary application bucket name.'
}

$fakeCsv = @'
training_marker,record_id,customer_name,email,account_last4
FAKE_TRAINING_DATA,CAP-001,Demo Customer 01,demo01@example.invalid,0001
FAKE_TRAINING_DATA,CAP-002,Demo Customer 02,demo02@example.invalid,0002
FAKE_TRAINING_DATA,CAP-003,Demo Customer 03,demo03@example.invalid,0003
FAKE_TRAINING_DATA,CAP-004,Demo Customer 04,demo04@example.invalid,0004
FAKE_TRAINING_DATA,CAP-005,Demo Customer 05,demo05@example.invalid,0005
'@
$fakeCsv = $fakeCsv.Trim() + "`n"
$recordCount = 5
$contentSha256 = Get-StringSha256 -Value $fakeCsv

Write-Host 'Capital One demo-data preview'
Write-Host 'AWS account matched: yes'
Write-Host "Security profile: $securityProfile"
Write-Host "Fixed object key: $objectKey"
Write-Host "Training marker / rows: $trainingMarker / $recordCount"
Write-Host "Content SHA-256: $contentSha256"
Write-Host 'Bucket name is intentionally not printed or persisted.'

if ($ConfirmRun -cne 'PREPARE CAPITAL ONE DATA') {
    throw (
        "Preview only. Re-run with -ConfirmRun 'PREPARE CAPITAL ONE DATA' " +
        'after confirming the fixed fake-data contract.'
    )
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'aws-topology-capital-one-prep-' + [guid]::NewGuid().ToString('N')
)
$tempCsv = Join-Path $tempRoot 'capital-one-demo.csv'
$startedAt = [datetimeoffset]::UtcNow
try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    [IO.File]::WriteAllText(
        $tempCsv,
        $fakeCsv,
        (New-Object Text.UTF8Encoding($false))
    )

    [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        's3api', 'put-object',
        '--profile', $AwsProfile,
        '--region', $region,
        '--bucket', $bucket,
        '--key', $objectKey,
        '--body', $tempCsv,
        '--content-type', 'text/csv',
        '--metadata', (
            "training-marker=$trainingMarker," +
            "sha256=$contentSha256,record-count=$recordCount"
        ),
        '--output', 'json',
        '--no-cli-pager'
    ) -FailureMessage 'The fixed fake-data upload failed.')

    $head = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        's3api', 'head-object',
        '--profile', $AwsProfile,
        '--region', $region,
        '--bucket', $bucket,
        '--key', $objectKey,
        '--output', 'json',
        '--no-cli-pager'
    ) -FailureMessage 'The uploaded fake-data object could not be verified.' |
        ConvertFrom-Json

    if ([string]$head.Metadata.'training-marker' -cne $trainingMarker -or
        [string]$head.Metadata.sha256 -cne $contentSha256 -or
        [int]$head.Metadata.'record-count' -ne $recordCount) {
        throw 'The uploaded object metadata does not match the fixed fake-data contract.'
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$finishedAt = [datetimeoffset]::UtcNow

$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'CAPITAL-ONE-PREP'
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $finishedAt.ToString('o')
    AwsAccountMatched = $true
    Region = $region
    SecurityScenarioProfile = $securityProfile
    ObjectKey = $objectKey
    TrainingMarker = $trainingMarker
    RecordCount = $recordCount
    ContentSha256 = $contentSha256
    BucketPersisted = $false
    CredentialsPersisted = $false
}
$recordPath = Join-Path $EvidenceRoot 'preparation\capital-one-demo-data.json'
Write-CapitalOneJson -Path $recordPath -Value $record

Write-Host "Prepared fake object: $objectKey"
Write-Host "Sanitized preparation record: $recordPath"
