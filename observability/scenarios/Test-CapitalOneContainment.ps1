#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TakeId,
    [Parameter(Mandatory)][string]$ExpectedRevision,
    [string]$EvidenceRoot = '',
    [string]$SecretRoot = '',
    [string]$ConfigurationRoot = '',
    [ValidateRange(10,60)][int]$RequestTimeoutSeconds = 30,
    [ValidateRange(120,300)][int]$PostContainmentObservationSeconds = 120,
    [switch]$RequireSocDeployedTake,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Security.psm1') -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.WazuhEvidence.psm1') -Force
Import-Module (Join-Path $terraformRoot 'automation\SocLab.Deployment.psm1') -Force
if ($TakeId -cnotmatch '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$') {
    throw 'TakeId violates the frozen SOC format.'
}
if ($ExpectedRevision -cnotmatch '^[0-9a-f]{40}$') {
    throw 'ExpectedRevision must be one full Git commit SHA.'
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'aws-topology-evidence'
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
if ($RequireSocDeployedTake.IsPresent) {
    $socRuntimeRoot = Get-SocRuntimeRoot
    $activeSessionPath = Join-Path $socRuntimeRoot 'active-soc-session.json'
    if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
        throw 'The active SOC session is unavailable.'
    }
    $activeSession = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    if ([int]$activeSession.schema_version -ne 1 -or
        [string]$activeSession.take_id -cne $TakeId -or
        [string]$activeSession.status -cne 'DEPLOYED' -or
        [string]$activeSession.response_mode -cne 'contain' -or
        -not (Test-Path -LiteralPath ([string]$activeSession.session_path) -PathType Container)) {
        throw 'The containment test is not bound to the active SOC session.'
    }
    $activeTake = Read-SocTakeRecord -RuntimeRoot ([string]$activeSession.session_path)
    if ([string]$activeTake.take_id -cne $TakeId -or
        [string]$activeTake.status -cne 'DEPLOYED' -or
        [string]$activeTake.response_mode -cne 'contain') {
        throw 'The containment test requires the active TAKE to be DEPLOYED.'
    }
}

function Invoke-RequiredTerraformRaw {
    param([string]$Name)

    $output = @(& terraform "-chdir=$terraformRoot" output -raw $Name 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Required Terraform output is unavailable: $Name"
    }
    return (($output | ForEach-Object { [string]$_ }) -join '').Trim()
}

foreach ($command in @('terraform')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}
$runtimeProfile = Invoke-RequiredTerraformRaw -Name runtime_profile
$securityProfile = Invoke-RequiredTerraformRaw -Name security_scenario_profile
$applicationUrl = [uri](Invoke-RequiredTerraformRaw -Name application_url)
if ($runtimeProfile -cne 'minimal' -or $securityProfile -cne 'capital-one-lab' -or
    $applicationUrl.Scheme -cne 'https' -or -not $applicationUrl.Host) {
    throw 'The active Runtime does not match the fixed containment validation target.'
}

Write-Host 'Capital One containment validation preview'
Write-Host "TAKE: $TakeId"
Write-Host "Expected deployed revision: $ExpectedRevision"
Write-Host 'Test: same IMDS role-discovery injection is rejected at DVWA impossible.'
Write-Host 'Control: login, home, SQL Injection page, and numeric-IP Ping remain available.'
Write-Host "Negative observation: no new Rule 100103, Shuffle outcome, or GitHub run for $PostContainmentObservationSeconds seconds."
if ($ConfirmRun -cne 'TEST CAPITAL ONE CONTAINMENT') {
    throw "Preview only. Re-run with -ConfirmRun 'TEST CAPITAL ONE CONTAINMENT'."
}

function Get-SocOutcomeSignature {
    param([Parameter(Mandatory)][object]$Record)

    return (@(
        [string]$Record.schema_version,
        [string]$Record.take_id,
        [string]$Record.raw_message_sha256,
        [string]$Record.body_sha256,
        [string]$Record.account_alias,
        [string]$Record.scenario_id,
        [string]$Record.rule_id,
        [string]$Record.result,
        [string]$Record.github_dispatch_count,
        [string]$Record.workflow_run_id,
        [string]$Record.completed_at_utc
    ) -join '|')
}

$directory = Join-Path $EvidenceRoot "$TakeId\soc"
$attackEvidencePath = Join-Path $directory '01-attack.json'
$wazuhEvidencePath = Join-Path $directory '02-wazuh-alerts.json'
$shuffleEvidencePath = Join-Path $directory '03-shuffle-executions.json'
$githubEvidencePath = Join-Path $directory '04-github-run.json'
foreach ($path in @($attackEvidencePath,$wazuhEvidencePath,$shuffleEvidencePath,$githubEvidencePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Containment validation requires the exact preceding SOC Evidence set.'
    }
}
$attackEvidence = Get-Content -LiteralPath $attackEvidencePath -Raw | ConvertFrom-Json
$wazuhEvidence = Get-Content -LiteralPath $wazuhEvidencePath -Raw | ConvertFrom-Json
$shuffleEvidence = Get-Content -LiteralPath $shuffleEvidencePath -Raw | ConvertFrom-Json
$githubEvidence = Get-Content -LiteralPath $githubEvidencePath -Raw | ConvertFrom-Json
$rawMessageHashes = @($wazuhEvidence.alerts | ForEach-Object { [string]$_.raw_message_sha256 })
$expectedRunId = [int64]$shuffleEvidence.dispatched_workflow_run_id
if ([string]$attackEvidence.take_id -cne $TakeId -or
    [string]$wazuhEvidence.take_id -cne $TakeId -or
    [int]$wazuhEvidence.observed_count -ne 2 -or
    $rawMessageHashes.Count -ne 2 -or
    @($rawMessageHashes | Where-Object { $_ -cnotmatch '^[a-f0-9]{64}$' }).Count -ne 0 -or
    @($rawMessageHashes | Select-Object -Unique).Count -ne 2 -or
    [string]$shuffleEvidence.take_id -cne $TakeId -or
    [int]$shuffleEvidence.alert_outcome_count -ne 2 -or
    [int]$shuffleEvidence.github_dispatch_count -ne 1 -or
    $expectedRunId -le 0 -or
    [string]$githubEvidence.take_id -cne $TakeId -or
    [int64]$githubEvidence.expected_workflow_run_id -ne $expectedRunId -or
    [int64]$githubEvidence.run.run_id -ne $expectedRunId -or
    [int]$githubEvidence.matching_run_count -ne 1) {
    throw 'The preceding SOC Evidence cannot bind the negative observation to one exact incident.'
}

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
$adminPassword = $null
$shuffleApiKey = $null
$wazuhCountBefore = 0
$wazuhCountAfter = 0
$shuffleCountBefore = 0
$shuffleCountAfter = 0
$githubRunCountAfter = 0
$additionalDetection = $null
$additionalShuffleOutcome = $null
$additionalGitHubDispatch = $null
$normalPing = $false
$sameAttackRetried = $false
$negativeObservationStartedAt = [datetimeoffset]::MinValue
$negativeObservationElapsedSeconds = 0.0
$negativeObservationCompleted = $false

$startedAt = [datetimeoffset]::UtcNow
$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$session.UserAgent = 'aws-topology-capital-one-containment/1.0'
$attackBlocked = $false
$normalLogin = $false
$normalHome = $false
$normalFeature = $false
$securityLevel = ''
$failureStage = ''
$failureType = ''
try {
    $failureStage = 'negative-observation-preflight'
    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' `
        -SecretRoot $resolvedSecretRoot
    $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' `
        -SecretRoot $resolvedSecretRoot
    $beforeHits = @(Get-SocWazuhRuleAlerts -TakeId $TakeId -RuleId 100103 `
        -AdminPassword $adminPassword)
    $beforeRecords = @(ConvertTo-SocRule100103Evidence -Hit $beforeHits -TakeId $TakeId)
    $wazuhCountBefore = $beforeRecords.Count
    $beforeHashes = @($beforeRecords.raw_message_sha256 | Sort-Object)
    if (($beforeHashes -join ',') -cne (($rawMessageHashes | Sort-Object) -join ',')) {
        throw 'Current Wazuh Rule 100103 alerts do not match the frozen detection Evidence.'
    }
    $beforeOutcomes = [Collections.Generic.List[object]]::new()
    foreach ($hash in $rawMessageHashes) {
        $outcome = Get-ShuffleSocOutcome -TakeId $TakeId -RawMessageSha256 $hash `
            -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        if ($null -eq $outcome) { throw 'A frozen Shuffle outcome is unavailable.' }
        $beforeOutcomes.Add($outcome)
    }
    $shuffleCountBefore = $beforeOutcomes.Count
    $beforeOutcomeSignatures = @($beforeOutcomes | ForEach-Object {
        Get-SocOutcomeSignature -Record $_
    } | Sort-Object)
    $githubBefore = Get-SocGitHubWorkflowRun -TakeId $TakeId -Operation contain `
        -NotBeforeUtc ([datetimeoffset]::Parse([string]$attackEvidence.started_at_utc)) `
        -ExpectedRunId $expectedRunId
    if ($null -eq $githubBefore -or [int64]$githubBefore.id -ne $expectedRunId -or
        [string]$githubBefore.status -cne 'completed' -or
        [string]$githubBefore.conclusion -cne 'success') {
        throw 'The exact completed containment GitHub run is unavailable before reattack.'
    }

    $failureStage = 'login-page'
    $login = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/login.php')) `
        -Method Get -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $loginToken = [regex]::Match(
        [string]$login.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $loginToken.Success) { throw 'The login CSRF token was not found.' }
    $failureStage = 'login'
    $loginResult = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/login.php')) `
        -Method Post -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
        -Body @{username='admin';password='password';Login='Login';user_token=$loginToken.Groups[1].Value}
    $normalLogin = $loginResult.StatusCode -eq 200

    $failureStage = 'impossible-page'
    $execPage = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/vulnerabilities/exec/')) `
        -Method Get -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $securityCookie = @(
        $session.Cookies.GetCookies($applicationUrl) |
            Where-Object { $_.Name -ceq 'security' }
    ) | Select-Object -Last 1
    $securityLevel = if ($securityCookie) { [string]$securityCookie.Value } else { '' }
    if ($securityLevel -cne 'impossible') {
        throw 'The new DVWA session did not receive the impossible security level.'
    }
    $execToken = [regex]::Match(
        [string]$execPage.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $execToken.Success) { throw 'The impossible Command Injection CSRF token was not found.' }

    $failureStage = 'same-attack-retry'
    $startMarker = '__SOC_REATTACK_BEGIN__'
    $endMarker = '__SOC_REATTACK_END__'
    $payload = (
        "127.0.0.1; printf '\n$startMarker\n'; " +
        'curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/; ' +
        "printf '\n$endMarker\n'"
    )
    $sameAttackRetried = $true
    $retry = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/vulnerabilities/exec/')) `
        -Method Post -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
        -Headers @{'X-SOC-TAKE-ID'=$TakeId} `
        -Body @{ip=$payload;Submit='Submit';user_token=$execToken.Groups[1].Value}
    $retryText = [Net.WebUtility]::HtmlDecode([string]$retry.Content)
    $attackBlocked = (
        $retry.StatusCode -eq 200 -and
        $retryText -match 'ERROR:\s*You have entered an invalid IP' -and
        $retryText -notmatch [regex]::Escape($startMarker) -and
        $retryText -notmatch [regex]::Escape($endMarker) -and
        $retryText -notmatch 'aws-topology-primary-karpenter-node'
    )
    if (-not $attackBlocked) {
        throw 'The same IMDS role-discovery injection was not demonstrably blocked.'
    }
    $payload = $null
    $retryText = $null

    $failureStage = 'normal-controls'
    $home = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/index.php')) `
        -Method Get -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $feature = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/vulnerabilities/sqli/')) `
        -Method Get -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $freshExecPage = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/vulnerabilities/exec/')) `
        -Method Get -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $freshExecToken = [regex]::Match(
        [string]$freshExecPage.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $freshExecToken.Success) { throw 'The normal Ping CSRF token was not found.' }
    $ping = Invoke-WebRequest -Uri ([uri]::new($applicationUrl,'/vulnerabilities/exec/')) `
        -Method Post -WebSession $session -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
        -Headers @{'X-SOC-TAKE-ID'=$TakeId} `
        -Body @{ip='127.0.0.1';Submit='Submit';user_token=$freshExecToken.Groups[1].Value}
    $pingText = [Net.WebUtility]::HtmlDecode([string]$ping.Content)
    $normalHome = $home.StatusCode -eq 200 -and [string]$home.Content -match 'Damn Vulnerable Web Application'
    $normalFeature = $feature.StatusCode -eq 200 -and [string]$feature.Content -match 'SQL Injection'
    $normalPing = $ping.StatusCode -eq 200 -and
        $pingText -notmatch 'ERROR:\s*You have entered an invalid IP' -and
        $pingText -match '127\.0\.0\.1'
    $pingText = $null
    if (-not $normalLogin -or -not $normalHome -or -not $normalFeature -or -not $normalPing) {
        throw 'A fixed normal DVWA control failed after containment.'
    }

    $failureStage = 'negative-observation-window'
    $negativeObservationStartedAt = [datetimeoffset]::UtcNow
    $observationDeadline = $negativeObservationStartedAt.AddSeconds($PostContainmentObservationSeconds)
    do {
        $afterHits = @(Get-SocWazuhRuleAlerts -TakeId $TakeId -RuleId 100103 `
            -AdminPassword $adminPassword)
        if ($afterHits.Count -gt 2) {
            $additionalDetection = $true
            throw 'Reattack or normal Ping produced an additional Rule 100103 alert.'
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $observationDeadline)
    $afterRecords = @(ConvertTo-SocRule100103Evidence -Hit $afterHits -TakeId $TakeId)
    $wazuhCountAfter = $afterRecords.Count
    $afterHashes = @($afterRecords.raw_message_sha256 | Sort-Object)
    if (($afterHashes -join ',') -cne ($beforeHashes -join ',')) {
        $additionalDetection = $true
        throw 'The Rule 100103 alert identity changed during the negative observation.'
    }
    $additionalDetection = $false

    $additionalShuffleOutcome = $true
    $afterOutcomes = [Collections.Generic.List[object]]::new()
    foreach ($hash in $rawMessageHashes) {
        $outcome = Get-ShuffleSocOutcome -TakeId $TakeId -RawMessageSha256 $hash `
            -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        if ($null -eq $outcome) { throw 'A frozen Shuffle outcome disappeared after reattack.' }
        $afterOutcomes.Add($outcome)
    }
    $shuffleCountAfter = $afterOutcomes.Count
    $afterOutcomeSignatures = @($afterOutcomes | ForEach-Object {
        Get-SocOutcomeSignature -Record $_
    } | Sort-Object)
    if (($afterOutcomeSignatures -join "`n") -cne ($beforeOutcomeSignatures -join "`n")) {
        throw 'A frozen Shuffle outcome changed during the negative observation.'
    }
    $additionalShuffleOutcome = $false

    $additionalGitHubDispatch = $true
    $githubAfter = Get-SocGitHubWorkflowRun -TakeId $TakeId -Operation contain `
        -NotBeforeUtc ([datetimeoffset]::Parse([string]$attackEvidence.started_at_utc)) `
        -ExpectedRunId $expectedRunId
    $githubRunCountAfter = if ($null -eq $githubAfter) { 0 } else { 1 }
    if ($null -eq $githubAfter -or [int64]$githubAfter.id -ne $expectedRunId -or
        [string]$githubAfter.status -cne 'completed' -or
        [string]$githubAfter.conclusion -cne 'success') {
        throw 'The exact single GitHub containment run changed or disappeared after reattack.'
    }
    $additionalGitHubDispatch = $false
    $negativeObservationElapsedSeconds = [math]::Round(
        ([datetimeoffset]::UtcNow - $negativeObservationStartedAt).TotalSeconds,3
    )
    $negativeObservationCompleted = $true
} catch {
    $failureType = $_.Exception.GetType().FullName
} finally {
    $finishedAt = [datetimeoffset]::UtcNow
    if ($negativeObservationStartedAt -ne [datetimeoffset]::MinValue -and
        -not $negativeObservationCompleted) {
        $negativeObservationElapsedSeconds = [math]::Round(
            ($finishedAt - $negativeObservationStartedAt).TotalSeconds,3
        )
    }
    $adminPassword = $null
    $shuffleApiKey = $null
}

New-Item -ItemType Directory -Path $directory -Force | Out-Null
$reattackPath = Join-Path $directory '07-reattack.json'
$normalPath = Join-Path $directory '08-normal-function.json'
[IO.File]::WriteAllText($reattackPath, (([ordered]@{
    schema_version=1;take_id=$TakeId;expected_revision=$ExpectedRevision;
    started_at_utc=$startedAt.ToString('o');finished_at_utc=$finishedAt.ToString('o');
    dvwa_security_level=$securityLevel;same_attack_retried=$sameAttackRetried;
    attack_blocked=$attackBlocked;credential_value_observed=$false;
    negative_observation_requested_seconds=$PostContainmentObservationSeconds;
    negative_observation_elapsed_seconds=$negativeObservationElapsedSeconds;
    negative_observation_completed=$negativeObservationCompleted;
    rule_100103_count_before=$wazuhCountBefore;rule_100103_count_after=$wazuhCountAfter;
    shuffle_outcome_count_before=$shuffleCountBefore;shuffle_outcome_count_after=$shuffleCountAfter;
    github_matching_run_count_after=$githubRunCountAfter;
    additional_detection=$additionalDetection;additional_shuffle_outcome=$additionalShuffleOutcome;
    additional_github_dispatch=$additionalGitHubDispatch;
    response_body_persisted=$false;failure_stage=if($failureType){$failureStage}else{''};
    failure_type=$failureType
} | ConvertTo-Json -Depth 8) + "`n"),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($normalPath, (([ordered]@{
    schema_version=1;take_id=$TakeId;checked_at_utc=$finishedAt.ToString('o');
    authenticated_login=$normalLogin;home_available=$normalHome;
    sqli_page_available=$normalFeature;numeric_ip_ping=$normalPing;
    normal_function_maintained=($normalLogin -and $normalHome -and $normalFeature -and $normalPing)
} | ConvertTo-Json -Depth 8) + "`n"),[Text.UTF8Encoding]::new($false))

if ($failureType) {
    throw "Containment validation failed at '$failureStage'. See sanitized Evidence."
}
Write-Host 'CAPITAL_ONE_REATTACK_BLOCKED=yes'
Write-Host 'DVWA_NORMAL_FUNCTION=yes'
Write-Host "REATTACK_EVIDENCE=$reattackPath"
Write-Host "NORMAL_EVIDENCE=$normalPath"
