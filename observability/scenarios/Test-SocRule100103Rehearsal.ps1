#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [ValidateRange(120,300)][int]$DetectionTimeoutSeconds = 120,
    [ValidateRange(30,300)][int]$ShuffleTimeoutSeconds = 180,
    [ValidateRange(30,300)][int]$NoGithubObservationSeconds = 60,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.WazuhEvidence.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Deployment.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'

Write-Host 'Rule 100103 one-TAKE observe-only rehearsal preview'
Write-Host 'Actual requests: one fixed Capital One baseline (two Command Injection requests) and one ordinary numeric Ping.'
Write-Host 'Expected per TAKE: source Events 2+1, Rule 100103 Alerts 2+0, two OBSERVE_ONLY outcomes, zero GitHub runs.'
if ($ConfirmRun -cne 'RUN RULE 100103 REHEARSAL') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN RULE 100103 REHEARSAL'."
}

function Invoke-RehearsalNativeCapture {
    param([string]$FilePath,[string[]]$Arguments,[string]$FailureMessage)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) { throw $FailureMessage }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Write-RehearsalAtomicJson {
    param([string]$Path,[object]$Value)
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Value | ConvertTo-Json -Depth 100) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath,$Path,$backupPath,$true)
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        } else {
            [IO.File]::Move($temporaryPath,$Path)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

function New-RehearsalDvWaSession {
    param([Parameter(Mandatory)][uri]$BaseUri)

    if ($BaseUri.Scheme -cne 'https' -or -not $BaseUri.Host) {
        throw 'Terraform returned an unsafe DVWA URL.'
    }
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $login = Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/login.php')) `
        -Method Get -WebSession $session -TimeoutSec 30 -ErrorAction Stop
    $token = [regex]::Match(
        [string]$login.Content,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $login = $null
    if (-not $token.Success) { throw 'The DVWA login token is unavailable.' }
    $response = Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/login.php')) `
        -Method Post -WebSession $session -TimeoutSec 30 -ErrorAction Stop -Body @{
            username='admin';password='password';Login='Login';user_token=$token.Groups[1].Value
        }
    $response = $null
    $page = Invoke-WebRequest -Uri ([uri]::new($BaseUri,'/vulnerabilities/exec/')) `
        -Method Get -WebSession $session -TimeoutSec 30 -ErrorAction Stop
    $cookie = @($session.Cookies.GetCookies($BaseUri) | Where-Object { $_.Name -ceq 'security' }) |
        Select-Object -Last 1
    if (-not $cookie -or [string]$cookie.Value -cne 'low' -or
        [string]$page.Content -notmatch 'name\s*=\s*["'']ip["'']') {
        throw 'DVWA is not in the required low Command Injection state.'
    }
    $page = $null
    return $session
}

function Invoke-RehearsalCommand {
    param(
        [Parameter(Mandatory)][uri]$ExecUri,
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$Target
    )

    $response = Invoke-WebRequest -Uri $ExecUri -Method Post -WebSession $Session `
        -Headers @{'X-SOC-TAKE-ID'=$TakeId} -TimeoutSec 30 -ErrorAction Stop `
        -Body @{ip=$Target;Submit='Submit'}
    try {
        if ([int]$response.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace([string]$response.Content)) {
            throw 'The DVWA rehearsal request did not return the expected page.'
        }
    } finally {
        $response = $null
    }
}

function Get-RehearsalBridgeEvents {
    param([string]$Path,[string]$TakeId)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $file = Get-Item -LiteralPath $Path
    if ($file.Length -gt 128MB) { throw 'The Wazuh live JSONL exceeded the bounded rehearsal read size.' }
    $events = [Collections.Generic.List[object]]::new()
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true)
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.Length -gt 1048576) { throw 'A Wazuh live JSONL line exceeded 1 MiB.' }
            try { $item = $line | ConvertFrom-Json -Depth 100 }
            catch { throw 'The Wazuh live JSONL contains invalid JSON.' }
            $payload = $item.payload
            if ([string]$payload.take_id -cne $TakeId -or
                [string]$payload.event_type -cne 'command.execution') { continue }
            if (-not $ids.Add([string]$item.event_id)) { throw 'The Bridge contains a duplicate rehearsal event ID.' }
            if ([int]$item.schema_version -ne 1 -or [string]$item.source -cne 'dvwa' -or
                [string]$item.transport -cne 'push' -or [string]$item.aws_account_id -cne '433048100798' -or
                [string]$item.aws_region -cne 'ap-northeast-2' -or [bool]$payload.normalized -ne $true -or
                [string]$payload.result -cne 'succeeded' -or [string]$payload.route -cne '/vulnerabilities/exec/' -or
                [string]$payload.context.action -cne 'shell_command' -or
                [string]$payload.context.security_level -cne 'low' -or
                [string]$item.raw_message_sha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw 'A Bridge rehearsal event violated the fixed source contract.'
            }
            $events.Add([pscustomobject][ordered]@{
                event_id=[string]$item.event_id
                event_time_utc=([datetimeoffset]$item.event_time).ToUniversalTime().ToString('o')
                bridge_received_at_utc=([datetimeoffset]$item.bridge_received_at).ToUniversalTime().ToString('o')
                raw_message_sha256=[string]$item.raw_message_sha256
                resource=[string]$payload.context.resource
            })
        }
    } finally {
        $reader.Dispose();$stream.Dispose()
    }
    return @($events)
}

$evidenceDirectory = $null
$failureStage = 'preflight'
$adminPassword = $null
$shuffleApiKey = $null
try {
    if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
        throw 'Start-SocLab must create one active observe-only session first.'
    }
    $state = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    $sessionScope = if ($state.PSObject.Properties['scope']) {
        [string]$state.scope
    } else {
        'full'
    }
    $sessionPath = [IO.Path]::GetFullPath([string]$state.session_path)
    $expectedPrefix = [IO.Path]::GetFullPath($resolvedRuntimeRoot).TrimEnd('\') + '\'
    if ([int]$state.schema_version -ne 1 -or
        -not $sessionPath.StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        [string]$state.status -cne 'READY' -or [string]$state.response_mode -cne 'observe_only' -or
        $sessionScope -cne 'full') {
        throw 'The active SOC session is not one fixed Full READY observe-only session.'
    }
    $take = Read-SocTakeRecord -RuntimeRoot $sessionPath
    $takeId = [string]$take.take_id
    if ([string]$take.status -cne 'READY' -or [string]$take.response_mode -cne 'observe_only' -or
        [datetimeoffset]$take.expires_at_utc -le [datetimeoffset]::UtcNow.AddMinutes(10)) {
        throw 'The active observe-only TAKE is unavailable or too close to expiry.'
    }
    $readyEvidencePath = [IO.Path]::GetFullPath([string]$state.ready_evidence_path)
    $evidenceDirectory = Split-Path -Parent $readyEvidencePath
    $takeDirectory = Split-Path -Parent $evidenceDirectory
    $evidenceRoot = Split-Path -Parent $takeDirectory
    if ((Split-Path -Leaf $evidenceDirectory) -cne 'soc' -or
        (Split-Path -Leaf $takeDirectory) -cne $takeId) {
        throw 'The rehearsal Evidence directory escaped the fixed TAKE layout.'
    }
    $heartbeat = Get-Content -LiteralPath ([string]$state.heartbeat_path) -Raw | ConvertFrom-Json
    if ([int]$heartbeat.pid -ne [int]$state.bridge_pid -or
        [string]$heartbeat.state -notin @('READY','RUNNING') -or
        ([datetimeoffset]::UtcNow - [datetimeoffset]$heartbeat.heartbeat_at_utc).TotalSeconds -gt 30 -or
        [int]$heartbeat.dlq_visible -ne 0) {
        throw 'The Bridge is not healthy for the rehearsal.'
    }
    [void](Get-Process -Id ([int]$state.bridge_pid) -ErrorAction Stop)
    $lockPath = [IO.Path]::GetFullPath([string]$state.bridge_lock_path)
    if ((Split-Path -Leaf $lockPath) -cne 'wazuh-push-bridge.lock') {
        throw 'The Bridge lock path is invalid.'
    }
    $livePath = Join-Path (Split-Path -Parent $lockPath) 'wazuh-push-live.jsonl'

    $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $resolvedSecretRoot
    $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
    if (@(Get-SocWazuhRuleAlerts -TakeId $takeId -RuleId 100103 -AdminPassword $adminPassword).Count -ne 0) {
        throw 'The observe-only TAKE already has Rule 100103 alerts and cannot prove a fresh per-TAKE run.'
    }

    $applicationUrl = Invoke-RehearsalNativeCapture -FilePath 'terraform' -Arguments @(
        "-chdir=$terraformRoot",'output','-raw','application_url'
    ) -FailureMessage 'The active DVWA URL is unavailable.'
    $baseUri = [uri]$applicationUrl
    $execUri = [uri]::new($baseUri,'/vulnerabilities/exec/')
    $webSession = New-RehearsalDvWaSession -BaseUri $baseUri

    $failureStage = 'capital-one-baseline'
    $startedAt = [datetimeoffset]::UtcNow
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
        [bool]$baseline.AlarmWaitSkipped -ne $true) {
        throw 'The controlled observe-only baseline violated the fixed attack contract.'
    }

    $failureStage = 'two-detections'
    $wazuhRecords = @(Wait-SocWazuhRule100103 -TakeId $takeId `
        -AdminPassword $adminPassword -TimeoutSeconds $DetectionTimeoutSeconds)

    $failureStage = 'normal-control'
    $normalControlStartedAt = [datetimeoffset]::UtcNow
    Invoke-RehearsalCommand -ExecUri $execUri -Session $webSession -TakeId $takeId -Target '127.0.0.1'
    $bridgeDeadline = [datetimeoffset]::UtcNow.AddSeconds($DetectionTimeoutSeconds)
    do {
        $bridgeEvents = @(Get-RehearsalBridgeEvents -Path $livePath -TakeId $takeId)
        if ($bridgeEvents.Count -eq 3) { break }
        if ($bridgeEvents.Count -gt 3) { throw 'The rehearsal produced more than three command execution source events.' }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $bridgeDeadline)
    if ($bridgeEvents.Count -ne 3 -or
        @($bridgeEvents | Where-Object { $_.resource -ceq 'ec2_imds' }).Count -ne 2 -or
        @($bridgeEvents | Where-Object { $_.resource -ceq 'other' }).Count -ne 1) {
        throw 'The Bridge did not retain exactly two baseline IMDS Events and one ordinary control.'
    }
    $normalEvent = @($bridgeEvents | Where-Object { $_.resource -ceq 'other' })[0]
    $sourceEventIds = @($bridgeEvents | Where-Object { $_.resource -ceq 'ec2_imds' } |
        ForEach-Object { [string]$_.event_id } | Sort-Object)
    $alertEventIds = @($wazuhRecords | ForEach-Object { [string]$_.event_id } | Sort-Object)
    if (@(Compare-Object -ReferenceObject $sourceEventIds -DifferenceObject $alertEventIds).Count -ne 0) {
        throw 'The two Rule 100103 Alerts do not map exactly to the two IMDS source Events.'
    }

    $failureStage = 'normal-negative-window'
    $normalNegativeDeadline = ([datetimeoffset]$normalEvent.event_time_utc).AddSeconds(
        $DetectionTimeoutSeconds
    )
    do {
        $normalGuardHits = @(Get-SocWazuhRuleAlerts -TakeId $takeId -RuleId 100103 `
            -AdminPassword $adminPassword)
        if ($normalGuardHits.Count -gt 2 -or @($normalGuardHits | Where-Object {
            [string]$_._source.data.event_id -ceq [string]$normalEvent.event_id -or
            [string]$_._source.data.raw_message_sha256 -ceq [string]$normalEvent.raw_message_sha256
        }).Count -ne 0) {
            throw 'The ordinary numeric Ping produced a delayed Rule 100103 alert.'
        }
        if ([datetimeoffset]::UtcNow -ge $normalNegativeDeadline) { break }
        Start-Sleep -Seconds 2
    } while ($true)
    if ($normalGuardHits.Count -ne 2) {
        throw 'The Rule 100103 count changed during the full normal-control negative window.'
    }
    $normalNegativeObservedSeconds = [math]::Round(
        ([datetimeoffset]::UtcNow - $normalControlStartedAt).TotalSeconds,3
    )

    $failureStage = 'shuffle-observe-only'
    $finalHits = @(Get-SocWazuhRuleAlerts -TakeId $takeId -RuleId 100103 -AdminPassword $adminPassword)
    $wazuhRecords = @(ConvertTo-SocRule100103Evidence -Hit $finalHits -TakeId $takeId -ExpectedCount 2)
    $shuffleOutcomes = @(Wait-ShuffleSocObserveOnlyOutcomes -TakeId $takeId `
        -RawMessageSha256 @($wazuhRecords.raw_message_sha256) `
        -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
        -BaseUri ([uri][string]$configuration.shuffle_api_base) -TimeoutSeconds $ShuffleTimeoutSeconds)
    $normalOutcome = Get-ShuffleSocOutcome -TakeId $takeId `
        -RawMessageSha256 ([string]$normalEvent.raw_message_sha256) `
        -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $shuffleApiKey `
        -BaseUri ([uri][string]$configuration.shuffle_api_base)
    if ($null -ne $normalOutcome) { throw 'The ordinary numeric Ping unexpectedly reached a Rule 100103 Shuffle outcome.' }

    $failureStage = 'no-github-response'
    $github = Assert-SocNoGitHubWorkflowRun -TakeId $takeId -NotBeforeUtc $startedAt `
        -ObservationSeconds $NoGithubObservationSeconds
    $finalHits = @(Get-SocWazuhRuleAlerts -TakeId $takeId -RuleId 100103 -AdminPassword $adminPassword)
    $wazuhRecords = @(ConvertTo-SocRule100103Evidence -Hit $finalHits -TakeId $takeId -ExpectedCount 2)

    $failureStage = 'evidence'
    Write-RehearsalAtomicJson -Path (Join-Path $evidenceDirectory '01-attack.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;started_at_utc=[string]$baseline.StartedAtUtc;
        finished_at_utc=[string]$baseline.FinishedAtUtc;command_injection_requests=2;
        take_header_requests=2;imds_role_matched=$true;temporary_credential_acquired=$true;
        fixed_fake_s3_read=$true;training_marker_validated=$true;
        credential_value_persisted=$false;response_body_persisted=$false
    })
    $recordPath = Join-Path $evidenceDirectory '02-wazuh-alerts.json'
    Write-RehearsalAtomicJson -Path $recordPath -Value ([ordered]@{
        schema_version=1
        take_id=$takeId
        response_mode='observe_only'
        started_at_utc=$startedAt.ToString('o')
        completed_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        request_count=3
        attack_event_count=2
        normal_control_count=1
        rule_100103_alert_count=2
        missed_detection_count=0
        duplicate_detection_count=0
        normal_rule_100103_count=0
        normal_negative_observation_seconds=$normalNegativeObservedSeconds
        source_to_alert_event_id_match=$true
        shuffle_observe_only_count=2
        github_containment_run_count=[int]$github.matching_run_count
        alerts=$wazuhRecords
        normal_control=[ordered]@{
            bridge_event_id=[string]$normalEvent.event_id
            raw_message_sha256=[string]$normalEvent.raw_message_sha256
            resource='other'
            reached_bridge=$true
            reached_rule_100103=$false
            reached_shuffle_outcome=$false
        }
        response_body_persisted=$false
        credential_value_persisted=$false
        github_write_executed=$false
    })
    $findings = @(Find-SocSecretExposure -Path $recordPath)
    if ($findings.Count -ne 0) { throw 'The rehearsal Evidence failed the secret exposure scan.' }

    Write-Host 'RULE_100103_REHEARSAL_SUCCEEDED=yes'
    Write-Host "TAKE_ID=$takeId"
    Write-Host 'SOURCE_EVENTS=2'
    Write-Host 'DETECTIONS=2'
    Write-Host 'NORMAL_FALSE_POSITIVES=0'
    Write-Host 'GITHUB_RUNS=0'
    Write-Host "REHEARSAL_EVIDENCE=$recordPath"
} catch {
    if ($evidenceDirectory -and (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) {
        Write-RehearsalAtomicJson -Path (Join-Path $evidenceDirectory 'rule100103-rehearsal-failure.json') -Value ([ordered]@{
            schema_version=1
            failed_at_utc=[datetimeoffset]::UtcNow.ToString('o')
            failure_stage=$failureStage
            failure_type=$_.Exception.GetType().FullName
            message_persisted=$false
        })
    }
    throw
} finally {
    $adminPassword=$null;$shuffleApiKey=$null
}
