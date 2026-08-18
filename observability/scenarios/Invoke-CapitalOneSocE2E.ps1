#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [ValidateRange(60,300)][int]$WazuhTimeoutSeconds = 120,
    [ValidateRange(60,300)][int]$ShuffleTimeoutSeconds = 180,
    [ValidateRange(60,1200)][int]$GitHubTimeoutSeconds = 600,
    [ValidateRange(60,1800)][int]$ArgoTimeoutSeconds = 1200,
    [ValidateRange(120,300)][int]$PostContainmentObservationSeconds = 120,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.WazuhEvidence.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Deployment.psm1') -Force

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'

Write-Host 'Capital One closed SOC E2E preview'
Write-Host 'Mutating path: controlled DVWA attack -> Shuffle containment -> GitHub main -> Argo deployment.'
Write-Host 'The command refuses a non-READY contain TAKE and never performs Terraform Apply or Destroy.'
if ($ConfirmRun -cne 'RUN CAPITAL ONE SOC E2E') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN CAPITAL ONE SOC E2E'."
}

function Write-SocE2EAtomicJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Value)

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,(($Value | ConvertTo-Json -Depth 30) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath,$Path,$backupPath)
            Remove-Item -LiteralPath $backupPath -Force
        } else {
            [IO.File]::Move($temporaryPath,$Path)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

function Set-SocE2EStatus {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][object]$Session
    )

    [void](Set-SocTakeStatus -RuntimeRoot $SessionPath -Status $Status)
    $Session.status = $Status
    $Session | Add-Member -NotePropertyName status_updated_at_utc `
        -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
    Write-SocE2EAtomicJson -Path $activeSessionPath -Value $Session
}

function Write-SocE2EManifest {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$ScopeRoot,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$Outcome,
        [string]$FailureStage = ''
    )

    $scopePath = [IO.Path]::GetFullPath($ScopeRoot).TrimEnd('\')
    $manifestPath = [IO.Path]::GetFullPath((Join-Path $Directory 'manifest.json'))
    $sumsPath = [IO.Path]::GetFullPath((Join-Path $Directory 'SHA256SUMS'))
    $files = @(Get-ChildItem -LiteralPath $scopePath -File -Recurse | Where-Object {
        $_.FullName -cne $manifestPath -and $_.FullName -cne $sumsPath
    } | Sort-Object FullName)
    $entries = @($files | ForEach-Object {
        [ordered]@{
            path=[IO.Path]::GetRelativePath($scopePath,$_.FullName).Replace('\','/')
            bytes=$_.Length
            sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
    Write-SocE2EAtomicJson -Path $manifestPath -Value ([ordered]@{
        schema_version=1;take_id=$TakeId;generated_at_utc=[datetimeoffset]::UtcNow.ToString('o');
        scope='entire-take-directory';
        outcome=$Outcome;failure_stage=$FailureStage;files=$entries
    })
    $hashFiles = @(Get-ChildItem -LiteralPath $scopePath -File -Recurse | Where-Object {
        $_.FullName -cne $sumsPath
    } | Sort-Object FullName)
    $lines = @($hashFiles | ForEach-Object {
        '{0}  {1}' -f (
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        ),([IO.Path]::GetRelativePath($scopePath,$_.FullName).Replace('\','/'))
    })
    [IO.File]::WriteAllLines($sumsPath,$lines,[Text.UTF8Encoding]::new($false))
}

if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
    throw 'Start-SocLab must create one active READY session before E2E.'
}
$session = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
foreach ($field in @(
    'schema_version','session_id','session_path','status','take_id','response_mode',
    'ready_evidence_path','daily_hard_deadline_at_utc'
)) {
    if ($null -eq $session.PSObject.Properties[$field] -or
        [string]::IsNullOrWhiteSpace([string]$session.$field)) {
        throw "The active SOC session field is missing: $field"
    }
}
$sessionPath = [IO.Path]::GetFullPath([string]$session.session_path)
$expectedPrefix = [IO.Path]::GetFullPath($resolvedRuntimeRoot).TrimEnd('\') + '\'
if ([int]$session.schema_version -ne 1 -or
    -not $sessionPath.StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase) -or
    [string]$session.status -cne 'READY' -or
    [string]$session.response_mode -cne 'contain') {
    throw 'The active SOC session is not one fixed READY containment session.'
}
$take = Read-SocTakeRecord -RuntimeRoot $sessionPath
$takeId = [string]$take.take_id
$requiredRemainingSeconds = $WazuhTimeoutSeconds + $ShuffleTimeoutSeconds +
    $GitHubTimeoutSeconds + $ArgoTimeoutSeconds + $PostContainmentObservationSeconds + 600
$requiredDeadline = [datetimeoffset]::UtcNow.AddSeconds($requiredRemainingSeconds)
if ($takeId -cne [string]$session.take_id -or [string]$take.status -cne 'READY' -or
    [string]$take.response_mode -cne 'contain' -or
    [datetimeoffset]$take.expires_at_utc -le $requiredDeadline -or
    [datetimeoffset]$session.daily_hard_deadline_at_utc -le $requiredDeadline) {
    throw 'The active containment TAKE or Daily Runtime cannot cover the configured E2E timeout budget plus ten minutes.'
}
$readyEvidencePath = [IO.Path]::GetFullPath([string]$session.ready_evidence_path)
if (-not (Test-Path -LiteralPath $readyEvidencePath -PathType Leaf)) {
    throw 'The READY Evidence is unavailable.'
}
$ready = Get-Content -LiteralPath $readyEvidencePath -Raw | ConvertFrom-Json
if ([string]$ready.take_id -cne $takeId -or [string]$ready.response_mode -cne 'contain' -or
    [bool]$ready.attack_executed -ne $false -or [bool]$ready.github_write_executed -ne $false -or
    [string]$ready.github_remote_main_sha -notmatch '^[0-9a-f]{40}$') {
    throw 'The READY Evidence does not match an untouched containment TAKE.'
}
$evidenceDirectory = Split-Path -Parent $readyEvidencePath
$takeDirectory = Split-Path -Parent $evidenceDirectory
$evidenceRoot = Split-Path -Parent $takeDirectory
if ((Split-Path -Leaf $takeDirectory) -cne $takeId -or
    (Split-Path -Leaf $evidenceDirectory) -cne 'soc') {
    throw 'The READY Evidence escaped the fixed TAKE Evidence layout.'
}

$configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
$adminPassword = $null
$shuffleApiKey = $null
$failureStage = 'preflight'
$attackStartedAt = [datetimeoffset]::MinValue
try {
    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $resolvedSecretRoot
    $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot

    $beforeDocument = Get-SocArgoRuntimeDocument
    $beforeArgo = Assert-SocArgoRuntimeDocument -Document $beforeDocument `
        -ExpectedRevision ([string]$ready.github_remote_main_sha) -ExpectedSecurityLevel low
    $beforePodUid = @($beforeArgo.pod_uids)

    $failureStage = 'attack'
    $attackStartedAt = [datetimeoffset]::UtcNow
    Set-SocE2EStatus -SessionPath $sessionPath -Status ATTACK_STARTED -Session $session
    & (Join-Path $terraformRoot 'observability\scenarios\Invoke-CapitalOneBaseline.ps1') `
        -AwsProfile ([string]$configuration.aws_profile) `
        -EvidenceRoot $evidenceRoot -ExperimentId $takeId -TakeId $takeId `
        -SkipAlarmWait -RequireSocReadyTake `
        -ConfirmRun 'RUN CAPITAL ONE BASELINE'
    $baselinePath = Join-Path $evidenceRoot "$takeId\source\client\capital-one-baseline.json"
    $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
    if ([string]$baseline.TakeId -cne $takeId -or [string]$baseline.FailureType -or
        [bool]$baseline.RoleMatched -ne $true -or [bool]$baseline.CallerRoleMatched -ne $true -or
        [bool]$baseline.GetObjectSucceeded -ne $true -or [bool]$baseline.MarkerValidated -ne $true -or
        [bool]$baseline.TakeIdHeaderSent -ne $true -or [int]$baseline.TakeIdHeaderPostCount -ne 2 -or
        [bool]$baseline.AlarmWaitSkipped -ne $true -or
        [bool]$baseline.TemporaryCredentialEnvironmentCleared -ne $true) {
        throw 'The controlled attack result violated the fixed baseline contract.'
    }
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '01-attack.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;started_at_utc=[string]$baseline.StartedAtUtc;
        finished_at_utc=[string]$baseline.FinishedAtUtc;command_injection_requests=2;
        take_header_requests=2;imds_role_matched=$true;temporary_credential_acquired=$true;
        temporary_credential_environment_cleared=$true;
        fixed_fake_s3_read=$true;training_marker_validated=$true;
        credential_value_persisted=$false;response_body_persisted=$false
    })

    $failureStage = 'wazuh-detection'
    $wazuhRecords = @(Wait-SocWazuhRule100103 -TakeId $takeId `
        -AdminPassword $adminPassword -TimeoutSeconds $WazuhTimeoutSeconds)
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '02-wazuh-alerts.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;expected_rule_id='100103';expected_count=2;
        observed_count=$wazuhRecords.Count;unique_event_count=@($wazuhRecords.event_id | Select-Object -Unique).Count;
        maximum_latency_seconds=($wazuhRecords | Measure-Object -Property latency_seconds -Maximum).Maximum;
        alerts=$wazuhRecords
    })
    Set-SocE2EStatus -SessionPath $sessionPath -Status DETECTED -Session $session

    $failureStage = 'shuffle-response'
    $shuffleOutcomes = @(Wait-ShuffleSocContainmentOutcomes -TakeId $takeId `
        -RawMessageSha256 @($wazuhRecords.raw_message_sha256) `
        -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
        -BaseUri ([uri][string]$configuration.shuffle_api_base) `
        -TimeoutSeconds $ShuffleTimeoutSeconds)
    $dispatchedOutcome = @($shuffleOutcomes | Where-Object {
        [string]$_.result -ceq 'RESPONSE_DISPATCHED'
    })
    if ($dispatchedOutcome.Count -ne 1 -or
        [string]$dispatchedOutcome[0].raw_message_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$dispatchedOutcome[0].body_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [int64]$dispatchedOutcome[0].workflow_run_id -le 0) {
        throw 'Shuffle did not bind one dispatched sanitized Alert to one GitHub Run ID.'
    }
    $dispatchedRawSha256 = [string]$dispatchedOutcome[0].raw_message_sha256
    $dispatchedBodySha256 = [string]$dispatchedOutcome[0].body_sha256
    $dispatchedRunId = [int64]$dispatchedOutcome[0].workflow_run_id
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '03-shuffle-executions.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;source='shuffle-datastore-outcomes';
        alert_outcome_count=$shuffleOutcomes.Count;
        github_dispatch_count=($shuffleOutcomes | Measure-Object -Property github_dispatch_count -Sum).Sum;
        dispatched_raw_message_sha256=$dispatchedRawSha256;
        dispatched_alert_body_sha256=$dispatchedBodySha256;
        dispatched_workflow_run_id=$dispatchedRunId;
        results=@($shuffleOutcomes | ForEach-Object {
            [ordered]@{raw_message_sha256=[string]$_.raw_message_sha256;result=[string]$_.result;
                body_sha256=[string]$_.body_sha256;
                github_dispatch_count=[int]$_.github_dispatch_count;
                workflow_run_id=[int64]$_.workflow_run_id;
                completed_at_utc=[string]$_.completed_at_utc}
        })
    })
    Set-SocE2EStatus -SessionPath $sessionPath -Status RESPONSE_DISPATCHED -Session $session

    $failureStage = 'github-workflow'
    $githubRun = Wait-SocGitHubWorkflowRun -TakeId $takeId -Operation contain `
        -NotBeforeUtc $attackStartedAt -ExpectedRunId $dispatchedRunId `
        -TimeoutSeconds $GitHubTimeoutSeconds
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '04-github-run.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;expected_alert_body_sha256=$dispatchedBodySha256;
        expected_workflow_run_id=$dispatchedRunId;
        run=$githubRun;matching_run_count=1
    })
    $transition = Get-SocGitHubTransitionArtifact -RunId ([int64]$githubRun.run_id) `
        -TakeId $takeId -Operation contain `
        -ExpectedAlertBodySha256 $dispatchedBodySha256 -RequireChange
    if ([string]$transition.before_sha -cne [string]$ready.github_remote_main_sha -or
        (Get-SocGitHubRemoteMainSha) -cne [string]$transition.commit_sha) {
        throw 'The containment Artifact does not form the exact READY-to-main Git transition.'
    }
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '05-git-transition.json') -Value $transition
    Set-SocE2EStatus -SessionPath $sessionPath -Status COMMITTED -Session $session

    $failureStage = 'argocd-deploy'
    $argoStartedAt = [datetimeoffset]::UtcNow
    $deployed = Wait-SocArgoDeployment -ExpectedRevision ([string]$transition.commit_sha) `
        -ExpectedSecurityLevel impossible -PreviousPodUid $beforePodUid -RequireReplacement `
        -TimeoutSeconds $ArgoTimeoutSeconds
    $argoFinishedAt = [datetimeoffset]::UtcNow
    Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory '06-argocd-deploy.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;expected_revision=[string]$transition.commit_sha;
        observed_revision=[string]$deployed.revision;sync=[string]$deployed.sync;
        health=[string]$deployed.health;security_level=[string]$deployed.security_level;
        previous_pod_uids=$beforePodUid;new_pod_uids=@($deployed.pod_uids);
        started_at_utc=$argoStartedAt.ToString('o');finished_at_utc=$argoFinishedAt.ToString('o')
    })
    Set-SocE2EStatus -SessionPath $sessionPath -Status DEPLOYED -Session $session

    $failureStage = 'reattack-and-controls'
    & (Join-Path $terraformRoot 'observability\scenarios\Test-CapitalOneContainment.ps1') `
        -TakeId $takeId -ExpectedRevision ([string]$transition.commit_sha) `
        -EvidenceRoot $evidenceRoot -SecretRoot $resolvedSecretRoot `
        -ConfigurationRoot $ConfigurationRoot `
        -PostContainmentObservationSeconds $PostContainmentObservationSeconds `
        -RequireSocDeployedTake `
        -ConfirmRun 'TEST CAPITAL ONE CONTAINMENT'
    Set-SocE2EStatus -SessionPath $sessionPath -Status REATTACK_BLOCKED -Session $session

    $failureStage = 'evidence-integrity'
    Write-SocE2EManifest -Directory $evidenceDirectory -ScopeRoot $takeDirectory `
        -TakeId $takeId -Outcome E2E_SUCCEEDED
    $exposures = @(Find-SocSecretExposure -Path @($takeDirectory))
    if ($exposures.Count -ne 0) {
        throw 'The final E2E Evidence failed the local secret exposure scan.'
    }
    Set-SocE2EStatus -SessionPath $sessionPath -Status E2E_SUCCEEDED -Session $session

    Write-Host 'SOC_E2E_SUCCEEDED=yes'
    Write-Host "TAKE_ID=$takeId"
    Write-Host "CONTAINMENT_COMMIT=$([string]$transition.commit_sha)"
    Write-Host "ARGO_REVISION=$([string]$deployed.revision)"
    Write-Host "EVIDENCE_DIRECTORY=$evidenceDirectory"
} catch {
    $failureType = $_.Exception.GetType().FullName
    try {
        $current = Read-SocTakeRecord -RuntimeRoot $sessionPath
        if ([string]$current.status -cne 'E2E_FAILED') {
            Set-SocE2EStatus -SessionPath $sessionPath -Status E2E_FAILED -Session $session
        }
    } catch {}
    try {
        Write-SocE2EAtomicJson -Path (Join-Path $evidenceDirectory 'failure.json') -Value ([ordered]@{
            schema_version=1;take_id=$takeId;failed_at_utc=[datetimeoffset]::UtcNow.ToString('o');
            failure_stage=$failureStage;failure_type=$failureType;
            error_message_persisted=$false;credential_value_persisted=$false
        })
        Write-SocE2EManifest -Directory $evidenceDirectory -ScopeRoot $takeDirectory `
            -TakeId $takeId `
            -Outcome E2E_FAILED -FailureStage $failureStage
    } catch {}
    throw "Capital One SOC E2E failed at '$failureStage'. See sanitized Evidence."
} finally {
    $adminPassword = $null
    $shuffleApiKey = $null
}
