#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateRange(60,1200)][int]$GitHubTimeoutSeconds = 600,
    [ValidateRange(60,1800)][int]$ArgoTimeoutSeconds = 1200,
    [ValidateRange(10,60)][int]$RequestTimeoutSeconds = 30,
    [switch]$PrepareRetake,
    [string]$ConfirmReset = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Deployment.psm1') -Force

function Invoke-SocResetNativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $output = @()
    $exitCode = -1
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @ArgumentList 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        $output = $null
        throw $FailureMessage
    }
    return (($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim()
}

function New-SocResetTakeId {
    return 'capital-one-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Invoke-SocFixedResetWorkflow {
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][datetimeoffset]$RequestedAt,
        [Parameter(Mandatory)][bool]$PrepareForRetake
    )

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The gh command is unavailable.'
    }
    $workflowConfirmation = if ($PrepareForRetake) {
        'RESET DVWA TO LOW'
    } else {
        'RESET DVWA QUARANTINE'
    }
    $prepareValue = if ($PrepareForRetake) { 'true' } else { 'false' }
    $output = @(& gh workflow run 'soc-reset-dvwa.yml' `
        -R 'Unoh03/Uns-DVWA' --ref 'main' `
        -f "take_id=$TakeId" -f "confirm=$workflowConfirmation" `
        -f "prepare_retake=$prepareValue" 2>&1)
    $exitCode = $LASTEXITCODE
    $output = $null
    if ($exitCode -ne 0) {
        throw 'The fixed DVWA Reset Workflow dispatch was rejected.'
    }

    $run = Wait-SocGitHubWorkflowRun -TakeId $TakeId -Operation reset `
        -NotBeforeUtc $RequestedAt -TimeoutSeconds $GitHubTimeoutSeconds
    $transition = Get-SocGitHubTransitionArtifact -RunId ([int64]$run.run_id) `
        -TakeId $TakeId -Operation reset
    $expectedMode = if ($PrepareForRetake) { 'prepare_retake' } else { 'release_quarantine' }
    $expectedLevel = if ($PrepareForRetake) { 'low' } else { 'unchanged' }
    if ([string]$transition.reset_mode -cne $expectedMode -or
        [string]$transition.target_level -cne $expectedLevel) {
        throw 'The DVWA Reset Artifact violated the requested reset contract.'
    }

    return [pscustomobject][ordered]@{
        run = $run
        transition = $transition
    }
}

function Remove-SocQuarantinedPodsForRetake {
    $raw = Invoke-SocResetNativeCapture -FilePath 'ssh' -ArgumentList @(
        'bas',
        "kubectl -n dvwa get pods -l 'soc.unoh.click/state=quarantined' -o json"
    ) -FailureMessage 'Quarantined DVWA Pods could not be listed for the retake reset.'
    try {
        $document = $raw | ConvertFrom-Json -Depth 30
    } catch {
        throw 'The quarantined DVWA Pod list is not valid JSON.'
    }

    $removed = @()
    foreach ($pod in @($document.items)) {
        $name = [string]$pod.metadata.name
        $uid = [string]$pod.metadata.uid
        $state = [string]$pod.metadata.labels.'soc.unoh.click/state'
        $instance = [string]$pod.metadata.labels.'app.kubernetes.io/instance'
        if ($name -cnotmatch '^dvwa-[a-z0-9]{8,16}-[a-z0-9]{5}$' -or
            $uid -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or
            $state -cne 'quarantined' -or $instance -cne 'dvwa-quarantined' -or
            @($pod.metadata.ownerReferences).Count -ne 0) {
            throw 'A candidate retake Pod does not match the exact orphaned quarantine contract.'
        }
        $command = "test `"`$(kubectl -n dvwa get pod '$name' -o jsonpath='{.metadata.uid}')`" = '$uid' && kubectl -n dvwa delete pod '$name' --wait=true --timeout=60s"
        [void](Invoke-SocResetNativeCapture -FilePath 'ssh' -ArgumentList @('bas',$command) `
            -FailureMessage "The UID-verified quarantined DVWA Pod could not be removed: $name")
        $removed += [pscustomobject][ordered]@{name=$name;uid=$uid}
    }
    return @($removed)
}

function Assert-FreshDvWaLow {
    param([Parameter(Mandatory)][uri]$BaseUri)

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = 'aws-topology-soc-reset/1.0'
    $login = Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/login.php')) -Method Get `
        -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $token = [regex]::Match(
        [string]$login.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $token.Success) { throw 'The reset login CSRF token was not found.' }
    [void](Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/login.php')) -Method Post `
        -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
        -Body @{username='admin';password='password';Login='Login';user_token=$token.Groups[1].Value})
    $exec = Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/vulnerabilities/exec/')) -Method Get `
        -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $security = @($session.Cookies.GetCookies($BaseUri) | Where-Object {
        $_.Name -ceq 'security'
    }) | Select-Object -Last 1
    if (-not $security -or [string]$security.Value -cne 'low' -or
        [string]$exec.Content -notmatch 'name\s*=\s*["'']ip["'']') {
        throw 'A fresh DVWA session did not return to the low Command Injection page.'
    }
}

if ($PrepareRetake.IsPresent) {
    Write-Host 'SOC recording retake reset preview'
    Write-Host 'Action: reset DVWA GitOps state to low, verify Argo, and remove UID-verified quarantine Pods.'
    Write-Host 'This command does not use a previous SOC session or alter Terraform infrastructure.'
    if ($ConfirmReset -cne 'RESET SOC LAB TO LOW') {
        throw "Preview only. Re-run with -ConfirmReset 'RESET SOC LAB TO LOW'."
    }
    foreach ($command in @('terraform','ssh')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "The $command command is unavailable."
        }
    }

    $takeId = New-SocResetTakeId
    $result = Invoke-SocFixedResetWorkflow -TakeId $takeId `
        -RequestedAt ([datetimeoffset]::UtcNow) -PrepareForRetake $true
    $transition = $result.transition
    $deployed = Wait-SocArgoDeployment -ExpectedRevision ([string]$transition.commit_sha) `
        -ExpectedSecurityLevel low -TimeoutSeconds $ArgoTimeoutSeconds
    $removedQuarantinePods = @(Remove-SocQuarantinedPodsForRetake)
    $applicationUrlText = @(& terraform "-chdir=$terraformRoot" output -raw application_url 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'The active application URL could not be read after reset.'
    }
    $applicationUrl = [uri](($applicationUrlText | ForEach-Object { [string]$_ }) -join '').Trim()
    Assert-FreshDvWaLow -BaseUri $applicationUrl

    Write-Host 'SOC recording retake reset completed.'
    Write-Host "TAKE_ID=$takeId"
    Write-Host "GITHUB_RUN_ID=$([int64]$result.run.run_id)"
    Write-Host "COMMIT_SHA=$([string]$transition.commit_sha)"
    Write-Host "CHANGED=$([bool]$transition.changed)"
    Write-Host "ARGO_REVISION=$([string]$deployed.revision)"
    Write-Host "REMOVED_QUARANTINE_PODS=$($removedQuarantinePods.Count)"
    return
}

Write-Host 'SOC quarantine release preview'
Write-Host 'Action: clear only the stale DVWA GitOps quarantine request.'
Write-Host 'Preserved runtime Pods and the current DVWA security level are unchanged.'
Write-Host 'Use -PrepareRetake for the complete recording reset.'
if ($ConfirmReset -cne 'RESET DVWA QUARANTINE') {
    throw "Preview only. Re-run with -ConfirmReset 'RESET DVWA QUARANTINE'."
}

$takeId = New-SocResetTakeId
$result = Invoke-SocFixedResetWorkflow -TakeId $takeId `
    -RequestedAt ([datetimeoffset]::UtcNow) -PrepareForRetake $false
Write-Host 'DVWA GitOps quarantine release completed.'
Write-Host "TAKE_ID=$takeId"
Write-Host "GITHUB_RUN_ID=$([int64]$result.run.run_id)"
Write-Host "COMMIT_SHA=$([string]$result.transition.commit_sha)"
Write-Host "CHANGED=$([bool]$result.transition.changed)"
