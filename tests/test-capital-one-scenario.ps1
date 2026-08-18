#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$preparePath = Join-Path $root 'observability\scenarios\Prepare-CapitalOneDemoData.ps1'
$runnerPath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneBaseline.ps1'
$negativePath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneNegativeControl.ps1'
$negativeQueryPath = Join-Path $root 'observability\queries\cloudwatch\14_capital_one_negative_control.cwli'
$configPath = Join-Path $root 'automation\project.psd1'
$evidenceModulePath = Join-Path $root 'automation\Evidence.Collection.psm1'
$dailyAutomationPath = Join-Path $root 'automation\Daily.Automation.psm1'

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

foreach ($path in @($preparePath, $runnerPath, $negativePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Capital One scenario file is missing: $path"
    }
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -gt 0) {
        throw "PowerShell parser rejected $path`: $($errors[0].Message)"
    }
}

$invalidTakeRejected = $false
try {
    & $runnerPath `
        -ExperimentId 'capital-one-20260818T010203Z-deadbeef' `
        -TakeId 'capital-one-20260818T010203Z-DEADBEEF' 6>$null
} catch {
    $invalidTakeRejected = $_.Exception.Message -match 'fixed capital-one-yyyyMMddTHHmmssZ-xxxxxxxx format'
}
if (-not $invalidTakeRejected) {
    throw 'The baseline did not fail closed on a non-canonical SOC TAKE_ID.'
}

$prepare = Get-Content -LiteralPath $preparePath -Raw
$runner = Get-Content -LiteralPath $runnerPath -Raw
$negative = Get-Content -LiteralPath $negativePath -Raw
$negativeQuery = Get-Content -LiteralPath $negativeQueryPath -Raw
$config = Get-Content -LiteralPath $configPath -Raw
$evidenceModule = Get-Content -LiteralPath $evidenceModulePath -Raw
$dailyAutomation = Get-Content -LiteralPath $dailyAutomationPath -Raw

Assert-Contains $prepare "ConfirmRun -cne 'PREPARE CAPITAL ONE DATA'" `
    'Preparation lacks its exact fake-data confirmation.'
Assert-Contains $prepare "validation/capital-one-demo\.csv" `
    'Preparation does not use the fixed validation object key.'
Assert-Contains $prepare 'FAKE_TRAINING_DATA' `
    'Preparation does not visibly mark every record as fake training data.'
Assert-Contains $prepare "'s3api', 'put-object'" `
    'Preparation does not upload through the bounded S3 API call.'
Assert-Contains $prepare 'BucketPersisted\s*=\s*\$false' `
    'Preparation evidence does not state that the bucket is omitted.'

Assert-Contains $runner "ConfirmRun -cne 'RUN CAPITAL ONE BASELINE'" `
    'The baseline lacks its exact attack confirmation.'
Assert-Contains $runner 'Import-Module \$socSecurityModulePath -Force' `
    'The baseline does not use the shared SOC TAKE_ID implementation.'
Assert-Contains $runner "TakeId -cnotmatch '\^capital-one-\[0-9\]\{8\}T\[0-9\]\{6\}Z-\[a-f0-9\]\{8\}\$'" `
    'The baseline does not enforce the frozen SOC TAKE_ID format.'
Assert-Contains $runner '''X-SOC-TAKE-ID''\s*=\s*\$TakeId' `
    'The baseline does not prepare the SOC TAKE_ID request header.'
if ([regex]::Matches($runner, 'Invoke-DvwaForm[^\r\n]+-Headers \$attackHeaders').Count -ne 2) {
    throw 'The baseline must send the SOC TAKE_ID on exactly two attack POST requests.'
}
Assert-Contains $runner 'TakeIdHeaderPostCount\s*=\s*\$takeIdHeaderPostCount' `
    'The sanitized baseline record does not retain the successful TAKE_ID POST count.'
Assert-Contains $runner 'TakeIdHeaderSent\s*=\s*\(\$takeIdHeaderPostCount -eq 2\)' `
    'The sanitized baseline record does not derive TAKE_ID delivery from both attack POSTs.'
Assert-Contains $runner 'Read-DailySessionState' `
    'The baseline does not require an Active Daily Session.'
Assert-Contains $runner "securityProfile -cne 'capital-one-lab'" `
    'The baseline is not restricted to capital-one-lab.'
Assert-Contains $runner "runtimeProfile -cne 'minimal'" `
    'The baseline is not restricted to the prepared minimal Runtime.'
Assert-Contains $runner "primary_metadata_options\.httpTokens -cne 'optional'" `
    'The baseline does not verify the intended Primary IMDS token mode.'
Assert-Contains $runner 'primary_metadata_options\.httpPutResponseHopLimit -ne 2' `
    'The baseline does not verify the intended Primary IMDS hop limit.'
Assert-Contains $runner '169\.254\.169\.254/latest/meta-data/iam/security-credentials/' `
    'The baseline does not use the fixed IMDS role path.'
Assert-Contains $runner "validation/capital-one-demo\.csv" `
    'The baseline does not use the fixed fake-data object key.'
Assert-Contains $runner "'s3api', 'get-object'" `
    'The baseline does not perform the fixed S3 read.'
Assert-Contains $runner 'Get-AlarmSnapshot[\s\S]*?StateValue -cne ''OK''' `
    'The baseline does not require an OK alarm before a new TAKE.'
Assert-Contains $runner 'StateValue -ceq ''ALARM''[\s\S]*?alarmUpdatedAt -ge \$startedAt' `
    'The baseline does not require a new alarm transition from this TAKE.'
Assert-Contains $runner 'Invoke-SensitiveNativeCapture[\s\S]*?throw \$FailureMessage' `
    'Sensitive native failures can expose captured command output.'
Assert-Contains $runner 'finally\s*\{[\s\S]*?Remove-Item "Env:\$name"' `
    'The baseline does not clear temporary AWS credential variables in finally.'
Assert-Contains $runner "CredentialHandling = 'memory-only; values never printed or persisted'" `
    'The sanitized record lacks an explicit credential-handling statement.'
Assert-Contains $runner 'credentialEnvironmentCleared[\s\S]*?TemporaryCredentialEnvironmentCleared' `
    'The baseline does not verify and record process-level temporary credential cleanup.'
Assert-Contains $runner 'BucketPersisted\s*=\s*\$false' `
    'The sanitized record does not omit the bucket name.'
Assert-Contains $runner '\[switch\]\$SkipAlarmWait[\s\S]*?skipped for the separate low-latency SOC path[\s\S]*?AlarmWaitSkipped' `
    'The baseline lacks an explicit low-latency SOC path that preserves the alarm-verification distinction.'
Assert-Contains $runner '\[switch\]\$RequireSocReadyTake[\s\S]*?active-soc-session\.json[\s\S]*?ATTACK_STARTED[\s\S]*?Read-SocTakeRecord[\s\S]*?expires_at_utc' `
    'The baseline can execute without an active unexpired READY TAKE binding.'

if ($runner -match '(?m)^\s*\[string\]\$(BaseUrl|Bucket|ObjectKey|Command|Payload)\b') {
    throw 'The baseline accepts an arbitrary target, bucket, object key, command, or payload.'
}
if ($runner -match '(?i)--no-verify-ssl|Invoke-Expression|\biex\b|Start-Transcript') {
    throw 'The baseline contains a TLS bypass, dynamic execution, or transcript capture.'
}
if ($runner -match '(?i)Write-(Host|Output|Verbose|Debug).*?(AccessKey|SecretAccessKey|SessionToken|credentialJson)') {
    throw 'The baseline can print a credential field or raw credential document.'
}
if ($runner -match '(?i)(AccessKeyId|SecretAccessKey|Token)\s*=\s*[''"][A-Za-z0-9/+]{16,}') {
    throw 'The baseline contains a credential-like literal.'
}

Assert-Contains $negative "AwsProfile -cne 'terra-user'" `
    'The negative control does not restrict execution to the fixed normal operator profile.'
Assert-Contains $negative "'RUN CAPITAL ONE NEGATIVE CONTROL'" `
    'The negative control lacks its fixed new-read confirmation text.'
Assert-Contains $negative 'ConfirmRun -cne \$requiredConfirmation' `
    'The negative control does not enforce the selected exact confirmation.'
Assert-Contains $negative 'RESUME CAPITAL ONE NEGATIVE CONTROL' `
    'The negative control lacks a no-repeat post-read resume confirmation.'
Assert-Contains $negative 'FailureStage -cne ''normal-cloudtrail-event''' `
    'Resume is not restricted to the eligible post-read failure stage.'
Assert-Contains $negative 'ExperimentId already has a record' `
    'The negative control does not prevent an accidental duplicate fixed read.'
Assert-Contains $negative 'Import-Module \$evidenceModulePath -Force' `
    'The negative control does not import the shared Evidence query implementation.'
Assert-Contains $negative 'Invoke-EvidenceCloudWatchInsightsQuery' `
    'The negative control does not reuse the shared CWLI implementation.'
Assert-Contains $evidenceModule "'Invoke-EvidenceCloudWatchInsightsQuery'" `
    'The shared CWLI implementation is not exported for bounded scenario reuse.'
Assert-Contains $negative 'CloudTrail delivery/query: attempt' `
    'The negative control does not show bounded CloudTrail delivery progress.'
Assert-Contains $negative 'PollAttempt % 6[\s\S]*?CloudWatch query:' `
    'The negative control does not report a long-running CWLI query about every thirty seconds.'
Assert-Contains $negative 'Read-DailySessionState' `
    'The negative control does not require an Active Daily Session.'
Assert-Contains $negative "securityProfile -cne 'capital-one-lab'" `
    'The negative control is not restricted to capital-one-lab.'
Assert-Contains $negative "runtimeProfile -cne 'minimal'" `
    'The negative control is not restricted to the prepared minimal Runtime.'
Assert-Contains $negative "validation/capital-one-demo\.csv" `
    'The negative control does not use the fixed fake-data object key.'
Assert-Contains $negative "'s3api', 'get-object'" `
    'The negative control does not perform the fixed normal S3 read.'
Assert-Contains $negative 'StateValue -cne ''OK''' `
    'The negative control does not require the alarm to stay OK.'
Assert-Contains $negative 'alarmTimestampUnchanged' `
    'The negative control does not verify an unchanged alarm state timestamp.'
Assert-Contains $negative 'CloudTrailObserved = \$cloudTrailObserved' `
    'The negative control does not persist its CloudTrail visibility verdict.'
Assert-Contains $negative 'StageDurationsSeconds = \[ordered\]@\{' `
    'The negative control does not persist stage timings.'
Assert-Contains $negative 'InvocationDurationSeconds' `
    'The negative control does not persist current invocation duration.'
Assert-Contains $negative 'CallerArnPersisted = \$false' `
    'The negative-control record does not omit the caller ARN.'
Assert-Contains $negative 'BucketPersisted = \$false' `
    'The negative-control record does not omit the bucket name.'
Assert-Contains $negativeQuery 'requestParameters\.key = "validation/capital-one-demo\.csv"' `
    'The negative-control query is not restricted to the fixed object.'
Assert-Contains $negativeQuery 'userIdentity\.arn not like /assumed-role\\/aws-topology-primary-karpenter-node\\//' `
    'The negative-control query does not exclude the detector Node Role.'
Assert-Contains $config "ScenarioIds\s*=\s*@\('CAPITAL-ONE-NEGATIVE'\)" `
    'The Evidence configuration does not register the negative-control scenario.'
Assert-Contains $config "QueryFile\s*=\s*'cloudwatch\\14_capital_one_negative_control\.cwli'" `
    'The Evidence configuration does not register the negative-control query.'
Assert-Contains $config 'MaxDeliveryAttempts\s*=\s*20[\s\S]*?DeliveryRetryDelaySeconds\s*=\s*30[\s\S]*?OverallTimeoutSeconds\s*=\s*600' `
    'The negative-control query does not use the reviewed ten-minute delivery budget.'
Assert-Contains $evidenceModule 'OverallTimeoutSeconds[\s\S]*?exceeded its overall timeout' `
    'The shared CWLI implementation does not enforce the configured overall timeout.'
Assert-Contains $dailyAutomation 'OverallTimeoutSeconds[\s\S]*?between 0 and 3600' `
    'The automation config loader does not reject an invalid query overall timeout.'

if ($negative -match '(?m)^\s*\[string\]\$(BaseUrl|Bucket|ObjectKey|Command|Payload)\b') {
    throw 'The negative control accepts an arbitrary target, bucket, object key, command, or payload.'
}
if ($negative -match '(?i)--no-verify-ssl|Invoke-Expression|\biex\b|Start-Transcript') {
    throw 'The negative control contains a TLS bypass, dynamic execution, or transcript capture.'
}
if ($negative -match "'logs',\s*'start-query'") {
    throw 'The negative control reimplements AWS CWLI execution instead of using the shared module.'
}

Write-Host 'Capital One scenario static tests passed.'
