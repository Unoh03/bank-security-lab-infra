#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [ValidateRange(60,1200)][int]$GitHubTimeoutSeconds = 600,
    [ValidateRange(60,1800)][int]$ArgoTimeoutSeconds = 1200,
    [ValidateRange(10,60)][int]$RequestTimeoutSeconds = 30,
    [ValidateRange(60,1200)][int]$AlarmCycleTimeoutSeconds = 900,
    [string]$ConfirmRetryUndispatched = '',
    [switch]$PrepareRetake,
    [string]$ConfirmReset = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$region = 'ap-northeast-2'
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Deployment.psm1') -Force

if (-not $PrepareRetake.IsPresent) {
    Write-Host 'SOC quarantine release preview'
    Write-Host 'Action: clear only the stale DVWA GitOps quarantine request.'
    Write-Host 'Preserved runtime Pods and the current DVWA security level are unchanged.'
    Write-Host 'Use -PrepareRetake for the complete recording reset.'
    if ($ConfirmReset -cne 'RESET DVWA QUARANTINE') {
        throw "Preview only. Re-run with -ConfirmReset 'RESET DVWA QUARANTINE'."
    }
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The gh command is unavailable.'
    }

    $releaseTakeId = 'capital-one-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
    $releaseRequestedAt = [datetimeoffset]::UtcNow
    $releaseOutput = @(& gh workflow run 'soc-reset-dvwa.yml' `
        -R 'Unoh03/Uns-DVWA' --ref 'main' `
        -f "take_id=$releaseTakeId" -f 'confirm=RESET DVWA QUARANTINE' `
        -f 'prepare_retake=false' 2>&1)
    $releaseExitCode = $LASTEXITCODE
    $releaseOutput = $null
    if ($releaseExitCode -ne 0) {
        throw 'The fixed quarantine release Workflow dispatch was rejected.'
    }
    $releaseRun = Wait-SocGitHubWorkflowRun -TakeId $releaseTakeId -Operation reset `
        -NotBeforeUtc $releaseRequestedAt -TimeoutSeconds $GitHubTimeoutSeconds
    $releaseResult = Get-SocGitHubTransitionArtifact -RunId ([int64]$releaseRun.run_id) `
        -TakeId $releaseTakeId -Operation reset
    if ([string]$releaseResult.reset_mode -cne 'release_quarantine' -or
        [string]$releaseResult.target_level -cne 'unchanged') {
        throw 'The quarantine release Artifact violated the fixed release-only contract.'
    }
    Write-Host 'DVWA GitOps quarantine release completed.'
    Write-Host "TAKE_ID=$releaseTakeId"
    Write-Host "GITHUB_RUN_ID=$([int64]$releaseRun.run_id)"
    Write-Host "COMMIT_SHA=$([string]$releaseResult.commit_sha)"
    Write-Host "CHANGED=$([bool]$releaseResult.changed)"
    return
}

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'

Write-Host 'SOC lab manual reset preview'
Write-Host 'Action: one fixed GitHub Reset Workflow -> exact Argo revision -> fresh DVWA low session.'
Write-Host 'Runtime action: delete only UID-verified orphaned DVWA quarantine Pods.'
Write-Host "Retake gate: this TAKE alarm ALARM -> natural OK within $AlarmCycleTimeoutSeconds seconds."
Write-Host 'This command does not run Terraform Apply, Destroy, or force-push.'
if ($ConfirmReset -cne 'RESET SOC LAB TO LOW') {
    throw "Preview only. Re-run with -ConfirmReset 'RESET SOC LAB TO LOW'."
}

$credentialEnvironmentNames = @(
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_SECURITY_TOKEN'
)

function Write-SocResetAtomicJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Value)
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
        } else { [IO.File]::Move($temporaryPath,$Path) }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

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

function Assert-SocNoProcessCredentialEnvironment {
    $present = @($credentialEnvironmentNames | Where-Object {
        [Environment]::GetEnvironmentVariable($_, 'Process')
    })
    if ($present.Count -ne 0) {
        throw 'Process-level AWS credential environment variables remain set; retake readiness is refused.'
    }
    return $true
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

function ConvertTo-SocResetUtcDateTimeOffset {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).ToUniversalTime()
    }
    if ($Value -is [datetime]) {
        if ([datetime]$Value -eq [datetime]::MinValue -or
            ([datetime]$Value).Kind -eq [DateTimeKind]::Unspecified) {
            throw "$Label must include an explicit UTC offset."
        }
        return ([datetimeoffset]([datetime]$Value)).ToUniversalTime()
    }

    $text = [string]$Value
    if ($text -notmatch '(?:Z|[+\-][0-9]{2}:[0-9]{2})$') {
        throw "$Label must include an explicit UTC offset."
    }
    $parsed = [datetimeoffset]::MinValue
    $valid = [datetimeoffset]::TryParse(
        $text,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    )
    if (-not $valid) { throw "$Label is not a valid timestamp." }
    return $parsed.ToUniversalTime()
}

function Get-SocCapitalOneDetectionContract {
    $raw = Invoke-SocResetNativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$(Join-Path $terraformRoot 'foundation')",
        'output','-json','capital_one_s3_detection'
    ) -FailureMessage 'The Foundation Capital One detector contract could not be read.'
    try {
        $detection = $raw | ConvertFrom-Json
    } catch {
        throw 'The Foundation Capital One detector contract is not valid JSON.'
    }
    if (-not [bool]$detection.enabled -or
        [string]$detection.alarm_name -notmatch '^[A-Za-z0-9_.\-]{1,255}$') {
        throw 'The Foundation Capital One detector must be enabled with one valid alarm name.'
    }
    return $detection
}

function Get-SocCapitalOneAlarmSnapshot {
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$AlarmName
    )

    $raw = Invoke-SocResetNativeCapture -FilePath 'aws' -ArgumentList @(
        'cloudwatch','describe-alarms',
        '--profile',$AwsProfile,
        '--region',$region,
        '--alarm-names',$AlarmName,
        '--output','json',
        '--no-cli-pager'
    ) -FailureMessage 'The Capital One alarm could not be read during reset.'
    try {
        $document = $raw | ConvertFrom-Json
    } catch {
        throw 'The Capital One alarm response is not valid JSON.'
    }
    $alarms = @($document.MetricAlarms)
    if ($alarms.Count -ne 1) {
        throw 'Reset requires exactly one Capital One alarm.'
    }
    return $alarms[0]
}

function Get-SocCapitalOneAlarmStateHistory {
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$AlarmName,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc
    )

    $raw = Invoke-SocResetNativeCapture -FilePath 'aws' -ArgumentList @(
        'cloudwatch','describe-alarm-history',
        '--profile',$AwsProfile,
        '--region',$region,
        '--alarm-name',$AlarmName,
        '--history-item-type','StateUpdate',
        '--start-date',$NotBeforeUtc.ToUniversalTime().ToString('o'),
        '--scan-by','TimestampAscending',
        '--max-items','100',
        '--output','json',
        '--no-cli-pager'
    ) -FailureMessage 'The Capital One alarm state history could not be read during reset.'
    try {
        $document = $raw | ConvertFrom-Json
    } catch {
        throw 'The Capital One alarm history response is not valid JSON.'
    }

    $records = @()
    foreach ($item in @($document.AlarmHistoryItems)) {
        $timestamp = ConvertTo-SocResetUtcDateTimeOffset -Value $item.Timestamp `
            -Label 'Alarm history timestamp'
        if ($timestamp -lt $NotBeforeUtc.ToUniversalTime()) { continue }
        try {
            $historyData = [string]$item.HistoryData | ConvertFrom-Json
        } catch {
            throw 'A Capital One alarm state-history item is not valid JSON.'
        }
        $newState = [string]$historyData.newState.stateValue
        if ($newState -notin @('OK','ALARM','INSUFFICIENT_DATA')) {
            throw 'A Capital One alarm history item has an unexpected target state.'
        }
        $records += [pscustomobject][ordered]@{
            timestamp_utc = $timestamp
            new_state = $newState
        }
    }
    return @($records | Sort-Object timestamp_utc)
}

function Wait-SocCapitalOneAlarmCycleReady {
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$AlarmName,
        [Parameter(Mandatory)][datetimeoffset]$AttackStartedAtUtc
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($AlarmCycleTimeoutSeconds)
    do {
        $snapshot = Get-SocCapitalOneAlarmSnapshot -AwsProfile $AwsProfile -AlarmName $AlarmName
        if (-not [bool]$snapshot.ActionsEnabled -or @($snapshot.AlarmActions).Count -lt 1) {
            throw 'The Capital One alarm action is disabled or missing during reset.'
        }
        $history = @(Get-SocCapitalOneAlarmStateHistory -AwsProfile $AwsProfile `
            -AlarmName $AlarmName -NotBeforeUtc $AttackStartedAtUtc)
        $alarmTransition = $history | Where-Object { $_.new_state -ceq 'ALARM' } |
            Select-Object -Last 1
        $okTransition = if ($null -ne $alarmTransition) {
            $history | Where-Object {
                $_.new_state -ceq 'OK' -and
                $_.timestamp_utc -gt $alarmTransition.timestamp_utc
            } | Select-Object -Last 1
        } else { $null }
        $snapshotUpdatedAt = ConvertTo-SocResetUtcDateTimeOffset `
            -Value $snapshot.StateUpdatedTimestamp -Label 'Alarm state timestamp'
        if ($null -ne $alarmTransition -and $null -ne $okTransition -and
            [string]$snapshot.StateValue -ceq 'OK' -and
            $snapshotUpdatedAt -ge $okTransition.timestamp_utc) {
            return [pscustomobject][ordered]@{
                alarm_name = $AlarmName
                alarm_state = 'OK'
                actions_enabled = $true
                alarm_action_count = @($snapshot.AlarmActions).Count
                take_alarm_at_utc = $alarmTransition.timestamp_utc.ToString('o')
                recovered_ok_at_utc = $okTransition.timestamp_utc.ToString('o')
                current_state_updated_at_utc = $snapshotUpdatedAt.ToString('o')
                take_alarm_cycle_verified = $true
            }
        }
        Start-Sleep -Seconds 10
    } while ([datetimeoffset]::UtcNow -lt $deadline)

    throw 'The Capital One alarm did not complete this TAKE ALARM-to-OK cycle in time.'
}

function Set-SocResetStatus {
    param([string]$SessionPath,[string]$Status,[object]$Session)

    $take = Read-SocTakeRecord -RuntimeRoot $SessionPath
    $active = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    if ([string]$take.take_id -cne [string]$Session.take_id -or
        [string]$active.take_id -cne [string]$Session.take_id -or
        [string]$take.status -cne [string]$active.status) {
        throw 'The Reset status records diverged before the requested transition.'
    }
    if ([string]$take.status -ceq $Status) {
        $Session.status = $Status
        return
    }

    $journalPath = Join-Path $SessionPath 'reset-status-journal.json'
    if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
        throw 'A previous Reset status journal must be recovered before another transition.'
    }
    Write-SocResetAtomicJson -Path $journalPath -Value ([ordered]@{
        schema_version=1;take_id=[string]$take.take_id;
        from_status=[string]$take.status;target_status=$Status;
        created_at_utc=[datetimeoffset]::UtcNow.ToString('o')
    })

    [void](Set-SocTakeStatus -RuntimeRoot $SessionPath -Status $Status)
    $Session.status = $Status
    $Session | Add-Member -NotePropertyName status_updated_at_utc `
        -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
    Write-SocResetAtomicJson -Path $activeSessionPath -Value $Session
    Remove-Item -LiteralPath $journalPath -Force
}

function Repair-SocResetStatusJournal {
    param([Parameter(Mandatory)][string]$SessionPath,[Parameter(Mandatory)][object]$Session)

    $journalPath = Join-Path $SessionPath 'reset-status-journal.json'
    if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
        return $Session
    }
    $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    $journalCreatedAt = ConvertTo-SocResetUtcDateTimeOffset `
        -Value $journal.created_at_utc -Label 'Reset status journal timestamp'
    $allowed = @{
        E2E_SUCCEEDED='RESET_REQUESTED';E2E_FAILED='RESET_REQUESTED';
        RESET_REQUESTED='RESET_COMMITTED';RESET_COMMITTED='RESET_DEPLOYED';
        RESET_DEPLOYED='CLOSED'
    }
    $from = [string]$journal.from_status
    $target = [string]$journal.target_status
    if ([int]$journal.schema_version -ne 1 -or
        [string]$journal.take_id -cne [string]$Session.take_id -or
        -not $allowed.ContainsKey($from) -or [string]$allowed[$from] -cne $target -or
        $journalCreatedAt -gt [datetimeoffset]::UtcNow.AddMinutes(5)) {
        throw 'The interrupted Reset status journal is invalid.'
    }

    $take = Read-SocTakeRecord -RuntimeRoot $SessionPath
    $active = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    if ([string]$take.take_id -cne [string]$journal.take_id -or
        [string]$active.take_id -cne [string]$journal.take_id -or
        [string]$take.status -notin @($from,$target) -or
        [string]$active.status -notin @($from,$target)) {
        throw 'The interrupted Reset status journal does not match the active TAKE.'
    }
    if ([string]$take.status -ceq $from) {
        [void](Set-SocTakeStatus -RuntimeRoot $SessionPath -Status $target)
    }
    if ([string]$active.status -ceq $from) {
        $active.status = $target
        $active | Add-Member -NotePropertyName status_updated_at_utc `
            -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
        Write-SocResetAtomicJson -Path $activeSessionPath -Value $active
    }
    Remove-Item -LiteralPath $journalPath -Force
    return (Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json)
}

function Assert-SocEvidenceManifestEntries {
    param([Parameter(Mandatory)][string]$TakeDirectory,[Parameter(Mandatory)][string]$EvidenceDirectory)

    $manifestPath = Join-Path $EvidenceDirectory 'manifest.json'
    $sumsPath = Join-Path $EvidenceDirectory 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        throw 'The prior E2E manifest or SHA256SUMS is unavailable.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $sumByPath = @{}
    foreach ($line in @(Get-Content -LiteralPath $sumsPath)) {
        if ($line -notmatch '^([a-f0-9]{64})  (.+)$') {
            throw 'The prior E2E SHA256SUMS contains an invalid line.'
        }
        $sumByPath[[string]$Matches[2]] = [string]$Matches[1]
    }
    $manifestRelative = [IO.Path]::GetRelativePath($TakeDirectory,$manifestPath).Replace('\','/')
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $sumByPath.ContainsKey($manifestRelative) -or
        [string]$sumByPath[$manifestRelative] -cne $manifestHash -or
        [string]$manifest.scope -cne 'entire-take-directory') {
        throw 'The prior E2E manifest is not bound to SHA256SUMS.'
    }
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        if ($relative -match '(^|/)\.\.(/|$)' -or [IO.Path]::IsPathRooted($relative)) {
            throw 'The prior E2E manifest contains an unsafe path.'
        }
        $path = [IO.Path]::GetFullPath((Join-Path $TakeDirectory $relative))
        $prefix = [IO.Path]::GetFullPath($TakeDirectory).TrimEnd('\') + '\'
        if (-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'A prior E2E manifest file is missing or outside the TAKE.'
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne [string]$entry.sha256 -or
            -not $sumByPath.ContainsKey($relative) -or
            [string]$sumByPath[$relative] -cne $hash) {
            throw 'A prior E2E Evidence hash no longer matches its manifest.'
        }
    }
}

function Assert-SocTransitionMatches {
    param(
        [Parameter(Mandatory)][object]$Stored,
        [Parameter(Mandatory)][object]$Remote,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation
    )

    $fields = @('schema_version','operation','take_id','before_sha','commit_sha',
        'diff_sha256','target_path','target_level','changed')
    if ($Operation -ceq 'contain') { $fields += 'alert_body_sha256' }
    foreach ($field in $fields) {
        if ([string]$Stored.$field -cne [string]$Remote.$field) {
            throw "The stored $Operation transition differs from the current GitHub Artifact."
        }
    }
}

function Read-SocResetIntentEvidence {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$ContainmentCommitSha
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'The resumable Reset session lacks its dispatch intent Evidence.'
    }
    $intent = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $requestedAt = ConvertTo-SocResetUtcDateTimeOffset -Value $intent.requested_at_utc `
        -Label 'Reset dispatch intent timestamp'
    $beforePodUid = @($intent.before_pod_uids | ForEach-Object { [string]$_ })
    $preResetRuntime = [string]$intent.pre_reset_runtime
    $intentFields = @($intent.PSObject.Properties.Name | Sort-Object)
    $expectedIntentFields = @(
        'automatic_redispatch_allowed','before_pod_uids','containment_commit_sha',
        'dispatch_command_succeeded','pre_reset_runtime','requested_at_utc',
        'schema_version','take_id'
    ) | Sort-Object
    if (($intentFields -join ',') -cne ($expectedIntentFields -join ',') -or
        [int]$intent.schema_version -ne 1 -or [string]$intent.take_id -cne $TakeId -or
        [string]$intent.containment_commit_sha -cne $ContainmentCommitSha -or
        $requestedAt.Offset -ne [timespan]::Zero -or
        $preResetRuntime -notin @('containment-deployed','containment-not-confirmed') -or
        @($beforePodUid | Where-Object { $_ -notmatch '^[0-9a-f-]{36}$' }).Count -ne 0 -or
        $intent.dispatch_command_succeeded -isnot [bool] -or
        [bool]$intent.automatic_redispatch_allowed -ne $false) {
        throw 'The resumable Reset dispatch intent is invalid.'
    }
    return [pscustomobject][ordered]@{
        document=$intent;requested_at=$requestedAt;before_pod_uids=$beforePodUid;
        pre_reset_runtime=$preResetRuntime;
        dispatch_command_succeeded=[bool]$intent.dispatch_command_succeeded
    }
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

function Update-SocResetManifest {
    param([string]$Directory,[string]$ScopeRoot,[string]$TakeId)
    $scopePath = [IO.Path]::GetFullPath($ScopeRoot).TrimEnd('\')
    $manifestPath = [IO.Path]::GetFullPath((Join-Path $Directory 'manifest.json'))
    $sumsPath = [IO.Path]::GetFullPath((Join-Path $Directory 'SHA256SUMS'))
    $files = @(Get-ChildItem -LiteralPath $scopePath -File -Recurse | Where-Object {
        $_.FullName -cne $manifestPath -and $_.FullName -cne $sumsPath
    } | Sort-Object FullName)
    Write-SocResetAtomicJson -Path $manifestPath -Value ([ordered]@{
        schema_version=1;take_id=$TakeId;generated_at_utc=[datetimeoffset]::UtcNow.ToString('o');
        scope='entire-take-directory';
        outcome='CLOSED';failure_stage='';files=@($files | ForEach-Object {
            [ordered]@{path=[IO.Path]::GetRelativePath($scopePath,$_.FullName).Replace('\','/');bytes=$_.Length;
                sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        })
    })
    $hashFiles = @(Get-ChildItem -LiteralPath $scopePath -File -Recurse | Where-Object {
        $_.FullName -cne $sumsPath
    } | Sort-Object FullName)
    [IO.File]::WriteAllLines($sumsPath,@($hashFiles | ForEach-Object {
        '{0}  {1}' -f (
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        ),([IO.Path]::GetRelativePath($scopePath,$_.FullName).Replace('\','/'))
    }),[Text.UTF8Encoding]::new($false))
}

if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
    throw 'No active completed SOC session exists.'
}
[void](Assert-SocNoProcessCredentialEnvironment)
$session = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
$sessionPath = [IO.Path]::GetFullPath([string]$session.session_path)
$expectedPrefix = [IO.Path]::GetFullPath($resolvedRuntimeRoot).TrimEnd('\') + '\'
if ([int]$session.schema_version -ne 1 -or
    -not $sessionPath.StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase) -or
    [string]$session.response_mode -cne 'contain') {
    throw 'Manual reset requires one exact containment session inside the SOC Runtime root.'
}
$resetLockPath = Join-Path $sessionPath 'reset-exclusive.lock'
$resetLock = $null
try {
    try {
        $resetLock = [IO.File]::Open(
            $resetLockPath,[IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,[IO.FileShare]::None
        )
    } catch {
        throw 'Another Reset process already owns this exact TAKE.'
    }
    $session = Repair-SocResetStatusJournal -SessionPath $sessionPath -Session $session
$resumableStatuses = @(
    'E2E_SUCCEEDED','E2E_FAILED','RESET_REQUESTED','RESET_COMMITTED','RESET_DEPLOYED','CLOSED'
)
if ([string]$session.status -notin $resumableStatuses -or
    [string]$session.response_mode -cne 'contain') {
    throw 'Manual reset requires one exact completed, failed, or resumable containment session.'
}
$take = Read-SocTakeRecord -RuntimeRoot $sessionPath
$takeId = [string]$take.take_id
if ([string]$take.status -cne [string]$session.status -or
    [string]$take.status -notin $resumableStatuses -or
    $takeId -cne [string]$session.take_id) {
    throw 'The active TAKE is not the exact completed, failed, or resumable containment TAKE.'
}
$evidenceDirectory = Split-Path -Parent ([IO.Path]::GetFullPath([string]$session.ready_evidence_path))
$takeDirectory = Split-Path -Parent $evidenceDirectory
$readyPath = [IO.Path]::GetFullPath([string]$session.ready_evidence_path)
$expectedTakeDirectory = [IO.Path]::GetFullPath((Join-Path (
    Split-Path -Parent $takeDirectory
) $takeId))
if ((Split-Path -Leaf $evidenceDirectory) -cne 'soc' -or
    [IO.Path]::GetFullPath($takeDirectory) -ine $expectedTakeDirectory -or
    -not $readyPath.StartsWith(
        ([IO.Path]::GetFullPath($evidenceDirectory).TrimEnd('\') + '\'),
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw 'The reset Evidence path escaped the fixed TAKE/soc layout.'
}
Assert-SocEvidenceManifestEntries -TakeDirectory $takeDirectory -EvidenceDirectory $evidenceDirectory
$ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
if ([string]$ready.take_id -cne $takeId -or
    [string]$ready.github_remote_main_sha -cnotmatch '^[a-f0-9]{40}$') {
    throw 'The reset READY Evidence is invalid.'
}
$shufflePath = Join-Path $evidenceDirectory '03-shuffle-executions.json'
if (-not (Test-Path -LiteralPath $shufflePath -PathType Leaf)) {
    throw 'The exact Shuffle dispatch Evidence is unavailable for reset binding.'
}
$shuffle = Get-Content -LiteralPath $shufflePath -Raw | ConvertFrom-Json
$dispatchBodySha256 = [string]$shuffle.dispatched_alert_body_sha256
$dispatchRunId = [int64]$shuffle.dispatched_workflow_run_id
if ([string]$shuffle.take_id -cne $takeId -or
    [int]$shuffle.github_dispatch_count -ne 1 -or
    $dispatchBodySha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $dispatchRunId -le 0) {
    throw 'The Shuffle dispatch Evidence cannot bind reset to one exact containment run.'
}
$transitionPath = Join-Path $evidenceDirectory '05-git-transition.json'
$recoveredTransition = $false
$attackPath = Join-Path $evidenceDirectory '01-attack.json'
if (-not (Test-Path -LiteralPath $attackPath -PathType Leaf)) {
    throw 'The E2E session lacks the attack time needed for exact Run verification.'
}
$attack = Get-Content -LiteralPath $attackPath -Raw | ConvertFrom-Json
$notBefore = ConvertTo-SocResetUtcDateTimeOffset -Value $attack.started_at_utc `
    -Label 'Attack start timestamp'
if ([int]$attack.schema_version -ne 1 -or [string]$attack.take_id -cne $takeId -or
    $notBefore.Offset -ne [timespan]::Zero -or
    [bool]$attack.temporary_credential_acquired -ne $true -or
    [bool]$attack.temporary_credential_environment_cleared -ne $true -or
    [bool]$attack.credential_value_persisted -ne $false) {
    throw 'The attack Evidence does not prove safe temporary credential cleanup for this TAKE.'
}
$containmentRun = Get-SocGitHubWorkflowRun -TakeId $takeId -Operation contain `
    -NotBeforeUtc $notBefore -ExpectedRunId $dispatchRunId
if ($null -eq $containmentRun -or [string]$containmentRun.status -cne 'completed' -or
    [string]$containmentRun.conclusion -cne 'success') {
    throw 'The exact containment Workflow Run is absent, incomplete, or unsuccessful.'
}
$remoteContainment = Get-SocGitHubTransitionArtifact -RunId $dispatchRunId `
    -TakeId $takeId -Operation contain `
    -ExpectedAlertBodySha256 $dispatchBodySha256 -RequireChange
if (Test-Path -LiteralPath $transitionPath -PathType Leaf) {
    $storedContainment = Get-Content -LiteralPath $transitionPath -Raw | ConvertFrom-Json
    Assert-SocTransitionMatches -Stored $storedContainment -Remote $remoteContainment `
        -Operation contain
    $containment = $remoteContainment
} else {
    if ([string]$session.status -cne 'E2E_FAILED') {
        throw 'The successful E2E session lacks its containment Git transition Evidence.'
    }
    $containment = $remoteContainment
    Write-SocResetAtomicJson -Path $transitionPath -Value $containment
    Write-SocResetAtomicJson -Path (Join-Path $evidenceDirectory 'reset-recovered-containment.json') `
        -Value ([ordered]@{
            schema_version=1;take_id=$takeId;workflow_run_id=$dispatchRunId;
            workflow_conclusion=[string]$containmentRun.conclusion;
            alert_body_sha256=$dispatchBodySha256;
            commit_sha=[string]$containment.commit_sha;
            recovered_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        })
    $recoveredTransition = $true
}
[void](Assert-SocGitHubTransitionResult -Result $containment -TakeId $takeId `
    -Operation contain -ExpectedAlertBodySha256 $dispatchBodySha256 -RequireChange)
if ([string]$containment.before_sha -cne [string]$ready.github_remote_main_sha) {
    throw 'The containment transition does not start at the exact READY Git revision.'
}
$configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
$shuffleApiKey = $null
$failureStage = 'reset-preflight'
$entryStatus = [string]$session.status
$currentStatus = $entryStatus
$resetIntentPath = Join-Path $evidenceDirectory 'reset-dispatch-intent.json'
$resetTransitionPath = Join-Path $evidenceDirectory 'reset-transition.json'
$resetDeployPath = Join-Path $evidenceDirectory 'reset-deploy.json'
$resetRetakeReadyPath = Join-Path $evidenceDirectory 'reset-retake-ready.json'
$resetAllowRemovedPath = Join-Path $evidenceDirectory 'reset-allow-removed.json'
$resetQuarantineRemovedPath = Join-Path $evidenceDirectory 'reset-quarantine-removed.json'
$requestedAt = [datetimeoffset]::MinValue
$run = $null
$transition = $null
$deployed = $null
$beforePodUid = @()
$preResetRuntime = 'unconfirmed'
$intentDispatchSucceeded = $false
$dispatchNeeded = $false
try {
    if ($currentStatus -in @('E2E_SUCCEEDED','E2E_FAILED')) {
        if ((Get-SocGitHubRemoteMainSha) -cne [string]$containment.commit_sha) {
            throw 'GitHub main is not the exact verified containment transition; reset dispatch is refused.'
        }
        if (Test-Path -LiteralPath $resetIntentPath -PathType Leaf) {
            $intentState = Read-SocResetIntentEvidence -Path $resetIntentPath `
                -TakeId $takeId -ContainmentCommitSha ([string]$containment.commit_sha)
            if ([bool]$intentState.dispatch_command_succeeded) {
                throw 'A completed dispatch intent cannot coexist with a pre-reset TAKE status.'
            }
            $requestedAt = [datetimeoffset]$intentState.requested_at
            $beforePodUid = @($intentState.before_pod_uids)
            $preResetRuntime = [string]$intentState.pre_reset_runtime
        } else {
            try {
                $current = Get-SocArgoRuntimeDocument
                $before = Assert-SocArgoRuntimeDocument -Document $current `
                    -ExpectedRevision ([string]$containment.commit_sha) -ExpectedSecurityLevel impossible
                $beforePodUid = @($before.pod_uids)
                $preResetRuntime = 'containment-deployed'
            } catch {
                # A failed E2E may have pushed the bounded commit before Argo became Healthy.
                # Git identity above is sufficient to authorize the fixed reset; final low
                # deployment and a fresh DVWA session are still mandatory below.
                $beforePodUid = @()
                $preResetRuntime = 'containment-not-confirmed'
            }
            $requestedAt = [datetimeoffset]::UtcNow
            Write-SocResetAtomicJson -Path $resetIntentPath -Value ([ordered]@{
                schema_version=1;take_id=$takeId;requested_at_utc=$requestedAt.ToString('o');
                containment_commit_sha=[string]$containment.commit_sha;
                pre_reset_runtime=$preResetRuntime;before_pod_uids=$beforePodUid;
                dispatch_command_succeeded=$false;automatic_redispatch_allowed=$false
            })
        }
        Set-SocResetStatus -SessionPath $sessionPath -Status RESET_REQUESTED -Session $session
        $currentStatus = 'RESET_REQUESTED'
        $dispatchNeeded = $true
    } else {
        $intentState = Read-SocResetIntentEvidence -Path $resetIntentPath `
            -TakeId $takeId -ContainmentCommitSha ([string]$containment.commit_sha)
        $requestedAt = [datetimeoffset]$intentState.requested_at
        $beforePodUid = @($intentState.before_pod_uids)
        $preResetRuntime = [string]$intentState.pre_reset_runtime
        $intentDispatchSucceeded = [bool]$intentState.dispatch_command_succeeded
    }

    if ($dispatchNeeded) {
        $failureStage = 'reset-dispatch'
        $output = @(& gh workflow run ([string]$configuration.reset_workflow) `
            -R ([string]$configuration.github_repository) --ref ([string]$configuration.github_ref) `
            -f "take_id=$takeId" -f 'confirm=RESET DVWA TO LOW' `
            -f 'prepare_retake=true' 2>&1)
        $exitCode = $LASTEXITCODE
        $output = $null
        if ($exitCode -ne 0) { throw 'The fixed manual Reset Workflow dispatch was rejected.' }
        Write-SocResetAtomicJson -Path $resetIntentPath -Value ([ordered]@{
            schema_version=1;take_id=$takeId;requested_at_utc=$requestedAt.ToString('o');
            containment_commit_sha=[string]$containment.commit_sha;
            pre_reset_runtime=$preResetRuntime;before_pod_uids=$beforePodUid;
            dispatch_command_succeeded=$true;automatic_redispatch_allowed=$false
        })
        $intentDispatchSucceeded = $true
    }

    if ($currentStatus -ceq 'RESET_REQUESTED') {
        $failureStage = 'reset-workflow'
        if (-not $intentDispatchSucceeded) {
            $existingRun = Get-SocGitHubWorkflowRun -TakeId $takeId -Operation reset `
                -NotBeforeUtc $requestedAt
            if ($null -eq $existingRun) {
                if ($ConfirmRetryUndispatched -cne 'RETRY UNDISPATCHED RESET') {
                    throw "No Reset Run is visible for the interrupted dispatch. Re-run only after verifying GitHub with -ConfirmRetryUndispatched 'RETRY UNDISPATCHED RESET'."
                }
                $output = @(& gh workflow run ([string]$configuration.reset_workflow) `
                    -R ([string]$configuration.github_repository) --ref ([string]$configuration.github_ref) `
                    -f "take_id=$takeId" -f 'confirm=RESET DVWA TO LOW' `
                    -f 'prepare_retake=true' 2>&1)
                $exitCode = $LASTEXITCODE
                $output = $null
                if ($exitCode -ne 0) { throw 'The explicit Reset Workflow retry was rejected.' }
                Write-SocResetAtomicJson -Path $resetIntentPath -Value ([ordered]@{
                    schema_version=1;take_id=$takeId;requested_at_utc=$requestedAt.ToString('o');
                    containment_commit_sha=[string]$containment.commit_sha;
                    pre_reset_runtime=$preResetRuntime;before_pod_uids=$beforePodUid;
                    dispatch_command_succeeded=$true;automatic_redispatch_allowed=$false
                })
            }
        }
        $run = Wait-SocGitHubWorkflowRun -TakeId $takeId -Operation reset `
            -NotBeforeUtc $requestedAt -TimeoutSeconds $GitHubTimeoutSeconds
        $transition = Get-SocGitHubTransitionArtifact -RunId ([int64]$run.run_id) `
            -TakeId $takeId -Operation reset -RequireChange
        if ([string]$transition.before_sha -cne [string]$containment.commit_sha -or
            (Get-SocGitHubRemoteMainSha) -cne [string]$transition.commit_sha) {
            throw 'The Reset Artifact does not form the exact containment-to-low transition.'
        }
        Write-SocResetAtomicJson -Path $resetTransitionPath -Value ([ordered]@{
            schema_version=1;take_id=$takeId;requested_at_utc=$requestedAt.ToString('o');
            github_run=$run;transition=$transition
        })
        Set-SocResetStatus -SessionPath $sessionPath -Status RESET_COMMITTED -Session $session
        $currentStatus = 'RESET_COMMITTED'
    } else {
        if (-not (Test-Path -LiteralPath $resetTransitionPath -PathType Leaf)) {
            throw 'A committed or deployed Reset lacks its transition Evidence.'
        }
        $transitionEvidence = Get-Content -LiteralPath $resetTransitionPath -Raw | ConvertFrom-Json
        if ([int]$transitionEvidence.schema_version -ne 1 -or
            [string]$transitionEvidence.take_id -cne $takeId -or
            (ConvertTo-SocResetUtcDateTimeOffset `
                -Value $transitionEvidence.requested_at_utc `
                -Label 'Reset transition request timestamp') -ne $requestedAt) {
            throw 'The resumable Reset transition Evidence is invalid.'
        }
        $run = $transitionEvidence.github_run
        $transition = $transitionEvidence.transition
    }
    $remoteResetRun = Get-SocGitHubWorkflowRun -TakeId $takeId -Operation reset `
        -NotBeforeUtc $requestedAt -ExpectedRunId ([int64]$run.run_id)
    if ($null -eq $remoteResetRun -or [string]$remoteResetRun.status -cne 'completed' -or
        [string]$remoteResetRun.conclusion -cne 'success') {
        throw 'The exact Reset Workflow Run is no longer verifiably successful.'
    }
    $remoteResetTransition = Get-SocGitHubTransitionArtifact -RunId ([int64]$run.run_id) `
        -TakeId $takeId -Operation reset -RequireChange
    Assert-SocTransitionMatches -Stored $transition -Remote $remoteResetTransition `
        -Operation reset
    $transition = $remoteResetTransition
    [void](Assert-SocGitHubTransitionResult -Result $transition -TakeId $takeId `
        -Operation reset -RequireChange)
    if ([int64]$run.run_id -le 0 -or [string]$run.operation -cne 'reset' -or
        [string]$run.workflow_file -cne 'soc-reset-dvwa.yml' -or
        [string]$run.status -cne 'completed' -or
        [string]$run.conclusion -cne 'success' -or
        [string]$run.html_url -notmatch '^https://github\.com/Unoh03/Uns-DVWA/actions/runs/[0-9]+$' -or
        [string]$transition.before_sha -cne [string]$containment.commit_sha -or
        (Get-SocGitHubRemoteMainSha) -cne [string]$transition.commit_sha) {
        throw 'The resumable Reset Run, transition, or current GitHub main is invalid.'
    }

    if ($currentStatus -ceq 'RESET_COMMITTED') {
        $failureStage = 'reset-deploy'
        $deployed = Wait-SocArgoDeployment -ExpectedRevision ([string]$transition.commit_sha) `
            -ExpectedSecurityLevel low -PreviousPodUid $beforePodUid `
            -RequireReplacement:($preResetRuntime -ceq 'containment-deployed') `
            -TimeoutSeconds $ArgoTimeoutSeconds
        Write-SocResetAtomicJson -Path $resetDeployPath -Value ([ordered]@{
            schema_version=1;take_id=$takeId;deployment=$deployed;
            pre_reset_runtime=$preResetRuntime;
            pod_replacement_required=($preResetRuntime -ceq 'containment-deployed');
            verified_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        })
        Set-SocResetStatus -SessionPath $sessionPath -Status RESET_DEPLOYED -Session $session
        $currentStatus = 'RESET_DEPLOYED'
    } else {
        if (-not (Test-Path -LiteralPath $resetDeployPath -PathType Leaf)) {
            throw 'A deployed Reset lacks its Argo deployment Evidence.'
        }
        $deployEvidence = Get-Content -LiteralPath $resetDeployPath -Raw | ConvertFrom-Json
        $deployed = $deployEvidence.deployment
        if ([int]$deployEvidence.schema_version -ne 1 -or
            [string]$deployEvidence.take_id -cne $takeId -or
            [string]$deployed.revision -cne [string]$transition.commit_sha -or
            [string]$deployed.sync -cne 'Synced' -or [string]$deployed.health -cne 'Healthy' -or
            [string]$deployed.security_level -cne 'low' -or @($deployed.pod_uids).Count -lt 1 -or
            @($deployed.pod_uids | Where-Object { [string]$_ -notmatch '^[0-9a-f-]{36}$' }).Count -ne 0 -or
            [string]$deployEvidence.pre_reset_runtime -cne $preResetRuntime) {
            throw 'The resumable Reset deployment Evidence is invalid.'
        }
        [void](Wait-SocArgoDeployment -ExpectedRevision ([string]$transition.commit_sha) `
            -ExpectedSecurityLevel low -TimeoutSeconds $ArgoTimeoutSeconds)
    }

    $failureStage = 'reset-quarantine-cleanup'
    $removedQuarantinePods = @(Remove-SocQuarantinedPodsForRetake)
    Write-SocResetAtomicJson -Path $resetQuarantineRemovedPath -Value ([ordered]@{
        schema_version=1;take_id=$takeId;removed_pods=$removedQuarantinePods;
        removed_count=$removedQuarantinePods.Count;
        verified_at_utc=[datetimeoffset]::UtcNow.ToString('o')
    })

    $failureStage = 'reset-low-validation'
    $applicationUrlText = @(& terraform "-chdir=$terraformRoot" output -raw application_url 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'The active application URL could not be read after reset.' }
    $applicationUrl = [uri](($applicationUrlText | ForEach-Object { [string]$_ }) -join '').Trim()
    Assert-FreshDvWaLow -BaseUri $applicationUrl

    $failureStage = 'reset-retake-readiness'
    $detection = Get-SocCapitalOneDetectionContract
    $alarmCycle = Wait-SocCapitalOneAlarmCycleReady `
        -AwsProfile ([string]$configuration.aws_profile) `
        -AlarmName ([string]$detection.alarm_name) `
        -AttackStartedAtUtc $notBefore
    [void](Assert-SocNoProcessCredentialEnvironment)
    Write-SocResetAtomicJson -Path $resetRetakeReadyPath -Value ([ordered]@{
        schema_version=1;take_id=$takeId;attack_started_at_utc=$notBefore.ToString('o');
        alarm_name=[string]$alarmCycle.alarm_name;alarm_state=[string]$alarmCycle.alarm_state;
        alarm_actions_enabled=[bool]$alarmCycle.actions_enabled;
        alarm_action_count=[int]$alarmCycle.alarm_action_count;
        take_alarm_at_utc=[string]$alarmCycle.take_alarm_at_utc;
        recovered_ok_at_utc=[string]$alarmCycle.recovered_ok_at_utc;
        take_alarm_cycle_verified=[bool]$alarmCycle.take_alarm_cycle_verified;
        attack_process_credential_environment_cleared=$true;
        reset_process_credential_environment_clear=$true;
        alarm_state_forced=$false;next_take_issued_by_reset=$false;
        next_take_requires_new_soc_start=$true;
        verified_at_utc=[datetimeoffset]::UtcNow.ToString('o')
    })

    $failureStage = 'reset-take-close'
    if (Test-Path -LiteralPath $resetAllowRemovedPath -PathType Leaf) {
        $allowEvidence = Get-Content -LiteralPath $resetAllowRemovedPath -Raw | ConvertFrom-Json
        if ([int]$allowEvidence.schema_version -ne 1 -or
            [string]$allowEvidence.take_id -cne $takeId -or
            [bool]$allowEvidence.shuffle_allow_removed -ne $true) {
            throw 'The resumable Shuffle allow-removal Evidence is invalid.'
        }
    } else {
        $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
        [void](Remove-ShuffleSocTake -TakeId $takeId `
            -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
            -BaseUri ([uri][string]$configuration.shuffle_api_base))
        Write-SocResetAtomicJson -Path $resetAllowRemovedPath -Value ([ordered]@{
            schema_version=1;take_id=$takeId;shuffle_allow_removed=$true;
            removed_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        })
    }
    $session | Add-Member -NotePropertyName shuffle_allow_removed -NotePropertyValue $true -Force
    Write-SocResetAtomicJson -Path (Join-Path $evidenceDirectory '09-reset.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;requested_at_utc=$requestedAt.ToString('o');
        github_run_id=[int64]$run.run_id;before_sha=[string]$transition.before_sha;
        reset_commit_sha=[string]$transition.commit_sha;changed=[bool]$transition.changed;
        argo_revision=[string]$deployed.revision;argo_sync=[string]$deployed.sync;
        argo_health=[string]$deployed.health;security_level='low';new_pod_uids=@($deployed.pod_uids);
        pre_reset_runtime=$preResetRuntime;containment_transition_recovered=$recoveredTransition;
        pod_replacement_required=($preResetRuntime -ceq 'containment-deployed');
        fresh_low_session=$true;take_alarm_cycle_verified=$true;alarm_state='OK';
        temporary_credential_environment_clear=$true;alarm_state_forced=$false;
        next_take_issued_by_reset=$false;next_take_requires_new_soc_start=$true;
        shuffle_allow_removed=$true;force_push_used=$false;
        resumed_from_status=$entryStatus;automatic_redispatch_used=$false
    })
    $exposures = @(Find-SocSecretExposure -Path @($takeDirectory))
    if ($exposures.Count -ne 0) { throw 'The Reset Evidence failed the secret exposure scan.' }
    Update-SocResetManifest -Directory $evidenceDirectory -ScopeRoot $takeDirectory -TakeId $takeId
    Set-SocResetStatus -SessionPath $sessionPath -Status CLOSED -Session $session

    Write-Host 'SOC_RESET_SUCCEEDED=yes'
    Write-Host "TAKE_ID=$takeId"
    Write-Host "RESET_COMMIT=$([string]$transition.commit_sha)"
    Write-Host "ARGO_REVISION=$([string]$deployed.revision)"
    Write-Host 'RETAKE_PREREQUISITES=verified'
    Write-Host 'NEXT_TAKE_ISSUED=no'
    Write-Host "RESET_EVIDENCE=$(Join-Path $evidenceDirectory '09-reset.json')"
} catch {
    $failureType = $_.Exception.GetType().FullName
    try {
        Write-SocResetAtomicJson -Path (Join-Path $evidenceDirectory 'reset-failure.json') -Value ([ordered]@{
            schema_version=1;take_id=$takeId;failed_at_utc=[datetimeoffset]::UtcNow.ToString('o');
            failure_stage=$failureStage;failure_type=$failureType;error_message_persisted=$false;
            credential_value_persisted=$false;resume_status=$currentStatus;
            automatic_redispatch_used=$false
        })
    } catch {}
    throw "SOC lab Reset failed at '$failureStage'. See sanitized Evidence."
} finally {
    $shuffleApiKey = $null
}
} finally {
    if ($null -ne $resetLock) {
        $resetLock.Dispose()
    }
}
