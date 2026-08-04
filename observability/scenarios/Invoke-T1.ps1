#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TerraformRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$Region = 'ap-northeast-2',
    [string]$DrRegion = 'ap-northeast-1',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ProjectName = 'aws-topology',
    [string]$PrimaryBastionKeyPairName = 'seoul-public-ec2-key',
    [string]$DrBastionKeyPairName = 'tokyo-public-ec2-key',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [ValidateRange(10, 120)]
    [int]$RequestTimeoutSeconds = 30,
    [ValidateRange(30, 180)]
    [int]$MinimumSessionRemainingMinutes = 60,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 't1-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}

. (Join-Path $TerraformRoot 'daily-common.ps1')
Add-Type -AssemblyName System.Net.Http

function Write-T1Json {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 12),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-T1RuntimeFeatures {
    $json = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'output', '-json', 'runtime_features'
    ) -FailureMessage 'The active Daily Runtime feature selection is unavailable.'
    return $json | ConvertFrom-Json
}

function Assert-T1CloudFrontOnlyPlan {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [switch]$AllowNoOp
    )

    Assert-DailyPlanPreservesFoundation -Summary $Summary
    $counts = $Summary.Counts
    $changed = @($Summary.Changed)
    if (
        $counts.Create -eq 0 -and
        $counts.Update -eq 0 -and
        $counts.Delete -eq 0 -and
        $counts.Replace -eq 0
    ) {
        if ($AllowNoOp) {
            return
        }
        throw 'T1 expected one CloudFront update, but the plan contains no change.'
    }
    if (
        $counts.Create -ne 0 -or
        $counts.Update -ne 1 -or
        $counts.Delete -ne 0 -or
        $counts.Replace -ne 0 -or
        $changed.Count -ne 1 -or
        [string]$changed[0] -cne "update`taws_cloudfront_distribution.this"
    ) {
        throw (
            'T1 refuses a plan that changes anything except ' +
            "aws_cloudfront_distribution.this:`n$($changed -join "`n")"
        )
    }
}

function New-T1TerraformPlan {
    param(
        [Parameter(Mandatory)][bool]$EnableHttpsRedirect,
        [Parameter(Mandatory)][string]$PlanPath,
        [Parameter(Mandatory)][object]$RuntimeFeatures,
        [Parameter(Mandatory)][string]$RuntimeProfile,
        [switch]$AllowNoOp
    )

    Assert-DailySessionTerraformIdle -TerraformRoot $TerraformRoot
    $enableValkey = ([bool]$RuntimeFeatures.valkey).ToString().ToLowerInvariant()
    $enableEfs = ([bool]$RuntimeFeatures.efs).ToString().ToLowerInvariant()
    $redirect = $EnableHttpsRedirect.ToString().ToLowerInvariant()
    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'plan',
        '-input=false',
        "-var=aws_profile=$AwsProfile",
        "-var=project_name=$ProjectName",
        "-var=primary_region=$Region",
        "-var=dr_region=$DrRegion",
        "-var=runtime_profile=$RuntimeProfile",
        "-var=enable_valkey=$enableValkey",
        "-var=enable_efs=$enableEfs",
        "-var=enable_https_redirect=$redirect",
        "-var=primary_bastion_key_pair_name=$PrimaryBastionKeyPairName",
        "-var=dr_bastion_key_pair_name=$DrBastionKeyPairName",
        "-out=$PlanPath"
    ) -FailureMessage 'T1 Terraform plan failed.' | Out-Host
    $summary = Get-TerraformPlanSummary -Root $TerraformRoot -PlanPath $PlanPath
    Assert-T1CloudFrontOnlyPlan -Summary $summary -AllowNoOp:$AllowNoOp
    return $summary
}

function Invoke-T1PlanApply {
    param([Parameter(Mandatory)][string]$PlanPath)

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'apply', '-input=false', $PlanPath
    ) -FailureMessage 'T1 Terraform apply failed.' | Out-Host
}

function Invoke-T1Probe {
    param(
        [Parameter(Mandatory)][ValidateSet('http', 'https')][string]$Scheme,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$Phase
    )

    $safePhase = $Phase.ToLowerInvariant() -replace '[^a-z0-9-]', '-'
    $builder = [System.UriBuilder]::new($Scheme, $HostName)
    $builder.Path = "/t1-observability/$ExperimentId/$safePhase.txt"
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds($RequestTimeoutSeconds)
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::Get,
        $builder.Uri
    )
    [void]$request.Headers.TryAddWithoutValidation('Cache-Control', 'no-cache')
    $userAgentSent = $request.Headers.UserAgent.Count -gt 0
    $started = Get-Date
    try {
        $response = $client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        try {
            $edgeRequestId = ''
            if ($response.Headers.Contains('X-Amz-Cf-Id')) {
                $edgeRequestId = [string](@(
                    $response.Headers.GetValues('X-Amz-Cf-Id')
                )[0])
            }
            if (-not $edgeRequestId) {
                throw "CloudFront response ID is missing for $($builder.Uri.AbsoluteUri)."
            }
            return [pscustomobject]@{
                Phase = $Phase
                TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
                Scheme = $Scheme
                Path = $builder.Uri.AbsolutePath
                HttpStatus = [int]$response.StatusCode
                Location = if ($response.Headers.Location) {
                    [string]$response.Headers.Location
                } else {
                    ''
                }
                EdgeRequestId = $edgeRequestId
                UserAgentSent = $userAgentSent
                DurationMs = [int]((Get-Date) - $started).TotalMilliseconds
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Assert-T1RedirectProbe {
    param(
        [Parameter(Mandatory)][object]$Probe,
        [Parameter(Mandatory)][string]$ExpectedHost
    )

    if ([int]$Probe.HttpStatus -notin @(301, 307, 308)) {
        throw "Expected HTTP-to-HTTPS redirect; status=$($Probe.HttpStatus)."
    }
    [uri]$location = $null
    if (-not [uri]::TryCreate([string]$Probe.Location, [UriKind]::Absolute, [ref]$location) -or
        $location.Scheme -cne 'https' -or
        $location.Host -ine $ExpectedHost) {
        throw "Redirect did not preserve the expected host over HTTPS: $($Probe.Location)"
    }
}

function Assert-T1AllowedHttpProbe {
    param([Parameter(Mandatory)][object]$Probe)

    if ([int]$Probe.HttpStatus -in @(301, 307, 308)) {
        throw "HTTP was still redirected during the approved allow-all phase; status=$($Probe.HttpStatus)."
    }
}

Assert-CommandAvailable -Name 'terraform' | Out-Null
Assert-CommandAvailable -Name 'aws' | Out-Null

$identity = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity', '--profile', $AwsProfile, '--output', 'json'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $ExpectedAccountId) {
    throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
}

$sessionPath = Get-DailySessionActiveStatePath
$session = Read-DailySessionState -Path $sessionPath
if ([string]$session.Status -cne 'Active') {
    throw "T1 requires an Active Daily Session; status=$($session.Status)."
}
if ([string]$session.AccountId -cne $ExpectedAccountId -or
    [string]$session.PrimaryRegion -cne $Region -or
    [string]$session.DrRegion -cne $DrRegion -or
    [System.IO.Path]::GetFullPath([string]$session.TerraformRoot) -cne
        [System.IO.Path]::GetFullPath($TerraformRoot)) {
    throw 'The active Daily Session does not match the requested T1 account, regions, or Terraform root.'
}
$remaining = ([datetimeoffset]$session.HardDeadlineAtUtc) - [datetimeoffset]::UtcNow
if ($remaining.TotalMinutes -lt $MinimumSessionRemainingMinutes) {
    throw (
        'T1 requires enough time for allow and restore CloudFront deployments; ' +
        "remaining=$([math]::Floor($remaining.TotalMinutes)) minutes."
    )
}
if ([string]$session.WatchdogMode -cne 'On') {
    Write-Warning 'The active Daily Session has WatchdogMode=Off; automatic teardown is not available.'
}

$runtimeProfile = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'runtime_profile'
) -FailureMessage 'The active Runtime profile is unavailable.').Trim()
$runtimeFeatures = Get-T1RuntimeFeatures
if (-not [bool]$runtimeFeatures.https_redirect) {
    throw 'T1 must start from the safe HTTPS redirect state.'
}
$applicationUrl = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'application_url'
) -FailureMessage 'The active application URL is unavailable.').Trim()
$cloudFrontDomain = (Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'cloudfront_domain_name'
) -FailureMessage 'The active CloudFront domain is unavailable.').Trim()
$baseUri = [uri]$applicationUrl
if ($baseUri.Scheme -cne 'https' -or -not $baseUri.Host) {
    throw "T1 refuses an invalid project application URL: $applicationUrl"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-t1-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$allowPlanPath = Join-Path $tempRoot 'allow-http.tfplan'
$restorePlanPath = Join-Path $tempRoot 'restore-https.tfplan'
$allowSummary = $null
$restoreSummary = $null
$allowSummary = New-T1TerraformPlan `
    -EnableHttpsRedirect $false `
    -PlanPath $allowPlanPath `
    -RuntimeFeatures $runtimeFeatures `
    -RuntimeProfile $runtimeProfile
Write-TerraformPlanSummary -Summary $allowSummary -Label 'T1 allow HTTP'

Write-Host "T1 target: $($baseUri.Host)"
Write-Host "AWS account: $($identity.Account)"
Write-Host "CloudFront distribution: $cloudFrontDomain"
Write-Host 'Temporary change: update aws_cloudfront_distribution.this only'
Write-Host 'Safety action: restore HTTPS redirect in finally before reporting success or failure'
if ($ConfirmRun -cne 'RUN T1 HTTP') {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    throw "Preview only. Re-run with -ConfirmRun 'RUN T1 HTTP' after explicit approval."
}

$startedAt = (Get-Date).ToUniversalTime()
$probes = New-Object System.Collections.Generic.List[object]
$failure = $null
$failureStage = ''
$restoreFailure = $null
$httpsRestored = $false
$stage = 'baseline-probe'
try {
    $baselineHttp = Invoke-T1Probe -Scheme http -HostName $baseUri.Host -Phase 'baseline-redirect'
    $probes.Add($baselineHttp)
    Assert-T1RedirectProbe -Probe $baselineHttp -ExpectedHost $baseUri.Host
    $probes.Add((Invoke-T1Probe -Scheme https -HostName $baseUri.Host -Phase 'baseline-https'))

    $stage = 'allow-http-apply'
    Invoke-T1PlanApply -PlanPath $allowPlanPath
    $appliedFeatures = Get-T1RuntimeFeatures
    if ([bool]$appliedFeatures.https_redirect) {
        throw 'Terraform apply completed without disabling the redirect for T1.'
    }

    $stage = 'allow-http-probe'
    $allowedHttp = Invoke-T1Probe -Scheme http -HostName $baseUri.Host -Phase 'allow-http'
    $probes.Add($allowedHttp)
    Assert-T1AllowedHttpProbe -Probe $allowedHttp
    $probes.Add((Invoke-T1Probe -Scheme https -HostName $baseUri.Host -Phase 'allow-https'))
} catch {
    $failure = $_
    $failureStage = $stage
} finally {
    try {
        $stage = 'restore-https-plan'
        $currentFeatures = Get-T1RuntimeFeatures
        $restoreSummary = New-T1TerraformPlan `
            -EnableHttpsRedirect $true `
            -PlanPath $restorePlanPath `
            -RuntimeFeatures $currentFeatures `
            -RuntimeProfile $runtimeProfile `
            -AllowNoOp
        Write-TerraformPlanSummary -Summary $restoreSummary -Label 'T1 restore HTTPS'
        if ($restoreSummary.Counts.Update -eq 1) {
            $stage = 'restore-https-apply'
            Invoke-T1PlanApply -PlanPath $restorePlanPath
        }
        $restoredFeatures = Get-T1RuntimeFeatures
        if (-not [bool]$restoredFeatures.https_redirect) {
            throw 'HTTPS redirect remains disabled after the restoration attempt.'
        }
        $stage = 'restore-https-probe'
        $restoredHttp = Invoke-T1Probe -Scheme http -HostName $baseUri.Host -Phase 'restored-redirect'
        $probes.Add($restoredHttp)
        Assert-T1RedirectProbe -Probe $restoredHttp -ExpectedHost $baseUri.Host
        $probes.Add((Invoke-T1Probe -Scheme https -HostName $baseUri.Host -Phase 'restored-https'))
        $httpsRestored = $true
    } catch {
        $restoreFailure = $_
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$finishedAt = (Get-Date).ToUniversalTime()
$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'T1'
    ExperimentId = $ExperimentId
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $finishedAt.ToString('o')
    AwsAccountId = [string]$identity.Account
    RuntimeProfile = $runtimeProfile
    TargetHost = $baseUri.Host
    CloudFrontDomain = $cloudFrontDomain
    HttpsRedirectStartedEnabled = $true
    HttpsRedirectRestored = $httpsRestored
    FailureStage = $failureStage
    FailureType = if ($failure) { $failure.Exception.GetType().FullName } else { '' }
    RestoreFailureType = if ($restoreFailure) {
        $restoreFailure.Exception.GetType().FullName
    } else {
        ''
    }
    AllowPlanChanges = if ($allowSummary) { @($allowSummary.Changed) } else { @() }
    RestorePlanChanges = if ($restoreSummary) { @($restoreSummary.Changed) } else { @() }
    Probes = $probes.ToArray()
}
$recordPath = Join-Path $EvidenceRoot "$ExperimentId\source\client\t1-http-https.json"
Write-T1Json -Path $recordPath -Value $record
Write-Host "T1 client record: $recordPath"
Write-Host 'Collect matching CloudWatch and raw S3 evidence with:'
Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'T1' -EvidenceStartUtc '$($startedAt.ToString('o'))' -EvidenceEndUtc '$($finishedAt.ToString('o'))' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 10"
Write-Host 'After CloudFront S3 delivery, run the bounded Athena trace with:'
Write-Host ".\observability\Invoke-AthenaQueryPack.ps1 -QueryName cloudfront-trace -StartUtc '$($startedAt.ToString('o'))' -EndUtc '$($finishedAt.ToString('o'))' -CreateSchema -ExperimentId '$ExperimentId' -ConfirmRun 'RUN ATHENA QUERY PACK'"

if ($restoreFailure) {
    throw (
        "CRITICAL: T1 failed to verify HTTPS restoration at '$stage'. " +
        "Cause: $($restoreFailure.Exception.Message)"
    )
}
if ($failure) {
    throw (
        "T1 failed at '$failureStage', but HTTPS restoration was verified. " +
        "Cause: $($failure.Exception.Message)"
    )
}
Write-Host 'T1 completed: temporary HTTP access observed and HTTPS redirect restored.'
