#requires -Version 7.4
[CmdletBinding()]
param(
    [switch]$StopWazuh,
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [string]$ConfirmStop = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$moduleRoot = Join-Path $repositoryRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'

Write-Host 'SOC lab controlled stop preview'
Write-Host 'Actions: stop the exact Bridge PID and remove its Shuffle TAKE allow key.'
Write-Host "Stop Wazuh and remove Runtime plaintext: $($StopWazuh.IsPresent)"
Write-Host 'Terraform Daily Runtime is never destroyed by this command.'
if ($ConfirmStop -cne 'STOP SOC LAB') {
    throw "Preview only. Re-run with -ConfirmStop 'STOP SOC LAB'."
}

function Write-SocStopAtomicJson {
    param([string]$Path,[object]$Value)

    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Value | ConvertTo-Json -Depth 20) + "`n"),
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

function Assert-SocChildPath {
    param([string]$Path,[string]$Parent,[string]$Label)

    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolvedPath.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped the active SOC Runtime session."
    }
    return $resolvedPath
}

function Invoke-SocStopCompose {
    param([string[]]$File,[string[]]$Arguments)

    $native = [Collections.Generic.List[string]]::new()
    $native.Add('compose')
    foreach ($path in $File) {
        $native.Add('-f')
        $native.Add($path)
    }
    foreach ($argument in $Arguments) { $native.Add($argument) }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& docker @native 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $output = $null
    if ($exitCode -ne 0) {
        throw 'Docker Compose could not stop the exact SOC Wazuh stack.'
    }
}

if (-not (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
    throw 'No active SOC session exists.'
}
$state = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
foreach ($field in @(
    'schema_version','session_id','session_path','compose_files','bridge_pid',
    'heartbeat_path','stop_signal_path','bridge_lock_path','take_id','response_mode',
    'ready_evidence_path','status'
)) {
    if ($null -eq $state.PSObject.Properties[$field] -or
        [string]::IsNullOrWhiteSpace([string]$state.$field)) {
        throw "The active SOC session field is missing: $field"
    }
}
if ([int]$state.schema_version -ne 1 -or
    [string]$state.session_id -notmatch '^soc-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' -or
    [string]$state.take_id -notmatch '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' -or
    [string]$state.response_mode -notin @('observe_only','contain')) {
    throw 'The active SOC session identity is invalid.'
}
$socScope = if ($state.PSObject.Properties['scope']) {
    if ([string]$state.scope -notin @('detection_only','full')) {
        throw 'The active SOC session scope is invalid.'
    }
    [string]$state.scope
} else {
    # Compatibility for a pre-scope full session created by the prior contract.
    'full'
}
$shuffleAllowWasRegistered = if ($state.PSObject.Properties['shuffle_allow_registered']) {
    if ($state.shuffle_allow_registered -isnot [bool]) {
        throw 'The active SOC session Shuffle allow flag is invalid.'
    }
    [bool]$state.shuffle_allow_registered
} else {
    # Compatibility for a pre-scope full session created by the prior contract.
    $true
}
if (($socScope -ceq 'detection_only' -and
        ([string]$state.response_mode -cne 'observe_only' -or $shuffleAllowWasRegistered)) -or
    ($socScope -ceq 'full' -and -not $shuffleAllowWasRegistered)) {
    throw 'The active SOC session scope and Shuffle allow contract do not match.'
}
$expectedSessionPath = [IO.Path]::GetFullPath((Join-Path $resolvedRuntimeRoot ([string]$state.session_id)))
if ([IO.Path]::GetFullPath([string]$state.session_path) -ine $expectedSessionPath) {
    throw 'The active SOC session path is not the expected private Runtime directory.'
}
$resetLockPath = Join-Path $expectedSessionPath 'reset-exclusive.lock'
$resetLock = $null
try {
    try {
        $resetLock = [IO.File]::Open(
            $resetLockPath,[IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,[IO.FileShare]::None
        )
    } catch {
        throw 'An E2E or Reset recovery process still owns this exact TAKE.'
    }
    $state = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
    $activeTake = Read-SocTakeRecord -RuntimeRoot $expectedSessionPath
    $stopResumePair = (
        [string]$activeTake.status -in @('READY','CLOSED') -and
        [string]$state.status -in @('BRIDGE_STOPPED','STOPPED')
    )
    if ([string]$activeTake.take_id -cne [string]$state.take_id -or
        [string]$activeTake.response_mode -cne [string]$state.response_mode -or
        ([string]$activeTake.status -cne [string]$state.status -and -not $stopResumePair)) {
        throw 'The active SOC session and TAKE identities or statuses do not match.'
    }
    if (Test-Path -LiteralPath (Join-Path $expectedSessionPath 'reset-status-journal.json') -PathType Leaf) {
        throw 'An interrupted Reset status journal must be recovered before Stop-SocLab.'
    }
    if ([string]$state.response_mode -ceq 'contain' -and
        [string]$activeTake.status -notin @('READY','CLOSED')) {
        throw (
            "Containment TAKE status '$([string]$activeTake.status)' may require E2E or Reset recovery. " +
            'Stop-SocLab refuses to delete its recovery state.'
        )
    }
$heartbeatPath = Assert-SocChildPath -Path ([string]$state.heartbeat_path) `
    -Parent $expectedSessionPath -Label 'Heartbeat path'
$stopSignalPath = Assert-SocChildPath -Path ([string]$state.stop_signal_path) `
    -Parent $expectedSessionPath -Label 'Stop signal path'
$expectedBridgeLockPath = [IO.Path]::GetFullPath((Join-Path (
    Join-Path ([Environment]::GetFolderPath('MyDocuments')) `
        'aws-topology-evidence\wazuh-push-shadow\dvwa'
) 'wazuh-push-bridge.lock'))
$bridgeLockPath = [IO.Path]::GetFullPath([string]$state.bridge_lock_path)
if ($bridgeLockPath -ine $expectedBridgeLockPath) {
    throw 'The active Bridge lock path is outside the fixed Evidence spool.'
}
$composeFiles = @($state.compose_files | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
if ($composeFiles.Count -ne 4 -or
    @($composeFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -ne 0) {
    throw 'The active SOC Compose file set is missing or unexpected.'
}

$bridgePid = [int]$state.bridge_pid
$bridge = Get-Process -Id $bridgePid -ErrorAction SilentlyContinue
if ($bridge) {
    if ($bridge.ProcessName -cne 'pwsh' -or
        -not (Test-Path -LiteralPath $heartbeatPath -PathType Leaf)) {
        throw 'The active Bridge PID cannot be safely identified.'
    }
    $heartbeat = Get-Content -LiteralPath $heartbeatPath -Raw | ConvertFrom-Json
    $heartbeatStarted = [datetimeoffset]::Parse([string]$heartbeat.started_at_utc)
    $processStarted = [datetimeoffset]$bridge.StartTime.ToUniversalTime()
    if ([int]$heartbeat.pid -ne $bridgePid -or
        [math]::Abs(($heartbeatStarted - $processStarted).TotalSeconds) -gt 30) {
        throw 'The Bridge heartbeat does not identify the current pwsh process.'
    }
    [IO.File]::WriteAllText($stopSignalPath,"stop`n",[Text.UTF8Encoding]::new($false))
    $deadline = [datetimeoffset]::UtcNow.AddSeconds(25)
    do {
        Start-Sleep -Milliseconds 500
        $bridge.Refresh()
    } while (-not $bridge.HasExited -and [datetimeoffset]::UtcNow -lt $deadline)
    if (-not $bridge.HasExited) {
        $bridge.Kill($true)
        if (-not $bridge.WaitForExit(5000)) {
            throw 'The exact Bridge process did not stop.'
        }
    }
    $bridge.Dispose()
}
$stopDeadline = [datetimeoffset]::UtcNow.AddSeconds(5)
do {
    $finalHeartbeat = if (Test-Path -LiteralPath $heartbeatPath -PathType Leaf) {
        try { Get-Content -LiteralPath $heartbeatPath -Raw | ConvertFrom-Json } catch { $null }
    } else { $null }
    if ($null -ne $finalHeartbeat -and
        [string]$finalHeartbeat.state -ceq 'STOPPED' -and
        -not (Test-Path -LiteralPath $bridgeLockPath -PathType Leaf)) {
        break
    }
    Start-Sleep -Milliseconds 250
} while ([datetimeoffset]::UtcNow -lt $stopDeadline)
if ($null -eq $finalHeartbeat -or [string]$finalHeartbeat.state -cne 'STOPPED' -or
    (Test-Path -LiteralPath $bridgeLockPath -PathType Leaf)) {
    throw 'The Bridge process exited without a verified STOPPED heartbeat and released lock.'
}

$state.status = 'BRIDGE_STOPPED'
$state | Add-Member -NotePropertyName bridge_stopped_at_utc `
    -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
Write-SocStopAtomicJson -Path $activeSessionPath -Value $state

$allowAlreadyRemoved = (
    $null -ne $state.PSObject.Properties['shuffle_allow_removed'] -and
    [bool]$state.shuffle_allow_removed
)
if (-not $shuffleAllowWasRegistered -and -not $allowAlreadyRemoved) {
    $state | Add-Member -NotePropertyName shuffle_allow_removed -NotePropertyValue $true -Force
    Write-SocStopAtomicJson -Path $activeSessionPath -Value $state
    $allowAlreadyRemoved = $true
}
if ($shuffleAllowWasRegistered -and -not $allowAlreadyRemoved) {
    $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
    $shuffleApiKey = $null
    try {
        $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
        [void](Remove-ShuffleSocTake `
            -TakeId ([string]$state.take_id) `
            -OrgId ([string]$configuration.shuffle_org_id) `
            -ApiKey $shuffleApiKey `
            -BaseUri ([uri][string]$configuration.shuffle_api_base))
    } finally {
        $shuffleApiKey = $null
    }
    $state | Add-Member -NotePropertyName shuffle_allow_removed -NotePropertyValue $true -Force
    Write-SocStopAtomicJson -Path $activeSessionPath -Value $state
}

if ($StopWazuh.IsPresent) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker is unavailable; Runtime Secrets cannot be removed while Wazuh may still mount them.'
    }
    Invoke-SocStopCompose -File $composeFiles -Arguments @('down')
}

$state.status = if ($StopWazuh.IsPresent) { 'STOPPED' } else { 'BRIDGE_STOPPED' }
$state | Add-Member -NotePropertyName stopped_at_utc `
    -NotePropertyValue ([datetimeoffset]::UtcNow.ToString('o')) -Force
$evidenceDirectory = Split-Path -Parent ([string]$state.ready_evidence_path)
$stopEvidencePath = Join-Path $evidenceDirectory '01-stopped.json'
Write-SocStopAtomicJson -Path $stopEvidencePath -Value ([ordered]@{
    schema_version         = 1
    checked_at_utc         = [string]$state.stopped_at_utc
    session_id             = [string]$state.session_id
    take_id                = [string]$state.take_id
    scope                  = $socScope
    bridge_stopped         = $true
    shuffle_allow_removed  = $true
    wazuh_stopped          = $StopWazuh.IsPresent
    runtime_secrets_removed = $StopWazuh.IsPresent
    terraform_destroyed    = $false
})

if ($StopWazuh.IsPresent) {
    $resetLock.Dispose()
    $resetLock = $null
    Remove-SocRuntimeSession -SessionId ([string]$state.session_id) -RuntimeRoot $resolvedRuntimeRoot
    Remove-Item -LiteralPath $activeSessionPath -Force
    Write-Host 'SOC_LAB_STOPPED=yes'
    Write-Host 'WAZUH_STOPPED=yes'
    Write-Host 'RUNTIME_SECRETS_REMOVED=yes'
} else {
    Write-SocStopAtomicJson -Path $activeSessionPath -Value $state
    Write-Host 'SOC_BRIDGE_STOPPED=yes'
    Write-Host 'WAZUH_STOPPED=no'
    Write-Host 'RUNTIME_SECRETS_RETAINED=yes'
    Write-Host "Re-run with -StopWazuh -ConfirmStop 'STOP SOC LAB' before deleting local Runtime material."
}
Write-Host "STOP_EVIDENCE=$stopEvidencePath"
} finally {
    if ($null -ne $resetLock) {
        $resetLock.Dispose()
    }
}
