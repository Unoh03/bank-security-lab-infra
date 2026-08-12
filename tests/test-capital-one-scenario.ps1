#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$preparePath = Join-Path $root 'observability\scenarios\Prepare-CapitalOneDemoData.ps1'
$runnerPath = Join-Path $root 'observability\scenarios\Invoke-CapitalOneBaseline.ps1'

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

foreach ($path in @($preparePath, $runnerPath)) {
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

$prepare = Get-Content -LiteralPath $preparePath -Raw
$runner = Get-Content -LiteralPath $runnerPath -Raw

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
Assert-Contains $runner 'BucketPersisted\s*=\s*\$false' `
    'The sanitized record does not omit the bucket name.'

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

Write-Host 'Capital One scenario static tests passed.'
