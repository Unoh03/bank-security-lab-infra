#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DailySessionStateRoot {
    [CmdletBinding()]
    param([string]$StateRoot = '')

    if ($StateRoot) {
        return [System.IO.Path]::GetFullPath($StateRoot)
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is unavailable; the Daily Session state root cannot be resolved.'
    }
    return Join-Path $env:LOCALAPPDATA 'aws-topology\daily-session'
}

function Get-DailySessionActiveStatePath {
    [CmdletBinding()]
    param([string]$StateRoot = '')

    return Join-Path (Get-DailySessionStateRoot -StateRoot $StateRoot) 'active-session.json'
}

function Write-DailySessionJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Value
    )

    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 8),
            (New-Object System.Text.UTF8Encoding($false))
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Read-DailySessionState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Daily Session state is unavailable: $Path"
    }
    $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($field in @(
        'SchemaVersion',
        'SessionId',
        'Status',
        'AccountId',
        'PrimaryRegion',
        'DrRegion',
        'TerraformRoot',
        'StartedAtUtc',
        'SoftDeadlineAtUtc',
        'HardDeadlineAtUtc',
        'RetryUntilUtc',
        'ExperimentId'
    )) {
        if ($null -eq $state.PSObject.Properties[$field] -or
            -not [string]$state.$field) {
            throw "Daily Session state field is missing: $field"
        }
    }
    if ([int]$state.SchemaVersion -ne 1) {
        throw "Unsupported Daily Session state schema: $($state.SchemaVersion)"
    }
    if ($null -eq $state.PSObject.Properties['WatchdogMode']) {
        $state | Add-Member -NotePropertyName WatchdogMode -NotePropertyValue 'On'
    }
    if ([string]$state.WatchdogMode -notin @('On', 'Off')) {
        throw "Unsupported Daily Session WatchdogMode: $($state.WatchdogMode)"
    }
    if ([string]$state.SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{7,63}$') {
        throw 'Daily Session ID is unsafe.'
    }
    foreach ($field in @(
        'StartedAtUtc',
        'SoftDeadlineAtUtc',
        'HardDeadlineAtUtc',
        'RetryUntilUtc'
    )) {
        [void][datetimeoffset]::Parse(
            [string]$state.$field,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    $state.TerraformRoot = [System.IO.Path]::GetFullPath(
        [string]$state.TerraformRoot
    )
    return $state
}

function Get-DailySessionTaskName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SessionSafety,
        [Parameter(Mandatory)][string]$SessionId
    )

    $prefix = [string]$SessionSafety.TaskNamePrefix
    if ($prefix -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$') {
        throw 'SessionSafety.TaskNamePrefix is unsafe.'
    }
    if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{7,63}$') {
        throw 'Daily Session ID is unsafe.'
    }
    return "$prefix-$SessionId"
}

function Get-DailySessionLogPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [string]$StateRoot = ''
    )

    $root = Get-DailySessionStateRoot -StateRoot $StateRoot
    return Join-Path (Join-Path $root 'logs') "$SessionId.log"
}

function Write-DailySessionLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][string]$Event,
        [string]$Detail = '',
        [string]$StateRoot = ''
    )

    if ($Event -notmatch '^[A-Za-z0-9._-]{2,64}$') {
        throw 'Daily Session log event is unsafe.'
    }
    $safeDetail = ($Detail -replace '[\r\n]+', ' ').Trim()
    if ($safeDetail.Length -gt 240) {
        $safeDetail = $safeDetail.Substring(0, 240)
    }
    $path = Get-DailySessionLogPath -SessionId $SessionId -StateRoot $StateRoot
    $directory = Split-Path -Parent $path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $line = "{0}`t{1}`t{2}" -f (
        (Get-Date).ToUniversalTime().ToString('o'),
        $Event,
        $safeDetail
    )
    Add-Content -LiteralPath $path -Value $line -Encoding UTF8
}

function Get-DailySessionDiagnosticLogPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [string]$AttemptId = '',
        [string]$StateRoot = ''
    )

    if ($SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{7,63}$') {
        throw 'Daily Session ID is unsafe for a diagnostic log.'
    }
    if (-not $AttemptId) {
        $AttemptId = [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    }
    if ($AttemptId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$') {
        throw 'Daily Session diagnostic attempt ID is unsafe.'
    }
    $root = Get-DailySessionStateRoot -StateRoot $StateRoot
    return Join-Path (Join-Path $root 'logs') "$SessionId.daily-down.$AttemptId.log"
}

function Protect-DailySessionDiagnosticText {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if (-not $Text) {
        return ''
    }
    $safe = [regex]::Replace(
        $Text,
        '(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----',
        '[REDACTED PRIVATE KEY]'
    )
    $safe = [regex]::Replace(
        $safe,
        '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
        '[REDACTED AWS ACCESS KEY]'
    )
    $safe = [regex]::Replace(
        $safe,
        '\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b',
        '[REDACTED GITHUB TOKEN]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+',
        'Bearer [REDACTED]'
    )
    $safe = [regex]::Replace(
        $safe,
        '(?im)"?\b(password|passwd|secret|token|authorization|cookie|credential|private[_ -]?key|access[_ -]?key)\b"?\s*[:=]\s*(?:"[^"]*"|\S+)',
        '$1=[REDACTED]'
    )
    return $safe
}

function Get-DailySessionDiagnosticSlice {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [ValidateRange(4096, 2097152)][int]$MaxCharacters = 1048576
    )

    if (-not $Text -or $Text.Length -le $MaxCharacters) {
        return [string]$Text
    }
    return "[TRUNCATED TO LAST $MaxCharacters CHARACTERS]`r`n" +
        $Text.Substring($Text.Length - $MaxCharacters)
}

function Write-DailySessionProcessDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][int]$ExitCode,
        [string]$AttemptId = '',
        [string]$StandardOutputPath = '',
        [string]$StandardErrorPath = '',
        [string]$Context = '',
        [string]$StateRoot = ''
    )

    $stdout = if ($StandardOutputPath -and
        (Test-Path -LiteralPath $StandardOutputPath -PathType Leaf)) {
        Get-Content -LiteralPath $StandardOutputPath -Raw
    } else {
        ''
    }
    $stderr = if ($StandardErrorPath -and
        (Test-Path -LiteralPath $StandardErrorPath -PathType Leaf)) {
        Get-Content -LiteralPath $StandardErrorPath -Raw
    } else {
        ''
    }
    $stdout = Get-DailySessionDiagnosticSlice `
        -Text (Protect-DailySessionDiagnosticText -Text $stdout)
    $stderr = Get-DailySessionDiagnosticSlice `
        -Text (Protect-DailySessionDiagnosticText -Text $stderr)
    $safeContext = Get-DailySessionDiagnosticSlice `
        -Text (Protect-DailySessionDiagnosticText -Text $Context) `
        -MaxCharacters 131072
    $path = Get-DailySessionDiagnosticLogPath `
        -SessionId $SessionId `
        -AttemptId $AttemptId `
        -StateRoot $StateRoot
    $directory = Split-Path -Parent $path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $content = @(
        "timestamp_utc=$((Get-Date).ToUniversalTime().ToString('o'))"
        "exit_code=$ExitCode"
        '[context]'
        $safeContext
        '[stdout]'
        $stdout
        '[stderr]'
        $stderr
    ) -join "`r`n"
    [System.IO.File]::WriteAllText(
        $path,
        $content,
        (New-Object System.Text.UTF8Encoding($false))
    )
    return $path
}

function Set-DailySessionStateStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Status,
        [string]$LastResult = ''
    )

    if ($Status -notmatch '^[A-Za-z][A-Za-z0-9]{2,39}$') {
        throw 'Daily Session status is unsafe.'
    }
    $state = Read-DailySessionState -Path $Path
    $state.Status = $Status
    $state.LastAttemptAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.LastResult = ($LastResult -replace '[\r\n]+', ' ').Trim()
    Write-DailySessionJson -Path $Path -Value $state
    return $state
}

function Test-TerraformCommandLineTargetsRoot {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$CommandLine,
        [Parameter(Mandatory)][string]$TerraformRoot
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $root = [System.IO.Path]::GetFullPath($TerraformRoot).TrimEnd('\', '/')
    foreach ($candidate in @($root, $root.Replace('\', '/'))) {
        $pattern = [regex]::Escape($candidate) + '(?:[\\/]|(?=["''\s]|$))'
        if ([regex]::IsMatch(
            $CommandLine,
            $pattern,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )) {
            return $true
        }
    }

    return $false
}

function Get-TerraformCommandLineChdir {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $match = [regex]::Match(
        $CommandLine,
        '(?i)(?:^|\s)(?:"-chdir=(?<wrapped>[^"]+)"|-chdir="(?<quoted>[^"]+)"|-chdir=(?<bare>[^\s"]+))'
    )
    if (-not $match.Success) {
        return ''
    }

    $value = foreach ($groupName in @('wrapped', 'quoted', 'bare')) {
        if ($match.Groups[$groupName].Success) {
            $match.Groups[$groupName].Value
            break
        }
    }
    if (-not $value -or -not [System.IO.Path]::IsPathRooted($value)) {
        return ''
    }

    try {
        return [System.IO.Path]::GetFullPath($value)
    } catch {
        return ''
    }
}

function Get-DailySessionTerraformProcessInventory {
    [CmdletBinding()]
    param()

    try {
        return @(Get-CimInstance `
            -ClassName Win32_Process `
            -Filter "Name = 'terraform.exe'" `
            -ErrorAction Stop)
    } catch {
        return @(Get-Process -Name terraform -ErrorAction SilentlyContinue)
    }
}

function Get-DailySessionTerraformActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TerraformRoot,
        [AllowNull()][object[]]$ProcessInventory
    )

    $root = [System.IO.Path]::GetFullPath($TerraformRoot)
    $processes = if ($PSBoundParameters.ContainsKey('ProcessInventory')) {
        @($ProcessInventory)
    } else {
        @(Get-DailySessionTerraformProcessInventory)
    }
    $relatedProcessIds = New-Object System.Collections.Generic.List[int]
    $unscopedProcessIds = New-Object System.Collections.Generic.List[int]
    $unrelatedProcessIds = New-Object System.Collections.Generic.List[int]
    foreach ($process in $processes) {
        $idProperty = $process.PSObject.Properties['ProcessId']
        if ($null -eq $idProperty) {
            $idProperty = $process.PSObject.Properties['Id']
        }
        if ($null -eq $idProperty) {
            continue
        }
        $processId = [int]$idProperty.Value
        $commandLineProperty = $process.PSObject.Properties['CommandLine']
        $commandLine = if ($null -eq $commandLineProperty) {
            ''
        } else {
            [string]$commandLineProperty.Value
        }
        if (Test-TerraformCommandLineTargetsRoot `
            -CommandLine $commandLine `
            -TerraformRoot $root) {
            $relatedProcessIds.Add($processId)
        } else {
            $processRoot = Get-TerraformCommandLineChdir -CommandLine $commandLine
            if ($processRoot) {
                $unrelatedProcessIds.Add($processId)
            } else {
                # Windows does not expose a reliable process working directory here.
                # Fail closed unless an explicit absolute -chdir proves another root.
                $unscopedProcessIds.Add($processId)
            }
        }
    }
    $lockPaths = New-Object System.Collections.Generic.List[string]
    $lockPath = Join-Path $root '.terraform.tfstate.lock.info'
    if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
        $lockPaths.Add($lockPath)
    }
    $blockingProcessIds = @(
        @($relatedProcessIds | ForEach-Object { $_ }) +
        @($unscopedProcessIds | ForEach-Object { $_ })
    )
    return [pscustomobject]@{
        ProcessIds         = $blockingProcessIds
        RootProcessIds     = @($relatedProcessIds | ForEach-Object { $_ })
        UnscopedProcessIds = @($unscopedProcessIds | ForEach-Object { $_ })
        UnrelatedProcessIds = @($unrelatedProcessIds | ForEach-Object { $_ })
        LockPaths          = @($lockPaths | ForEach-Object { $_ })
        IsBusy             = ($blockingProcessIds.Count -gt 0 -or $lockPaths.Count -gt 0)
    }
}

function Assert-DailySessionTerraformIdle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TerraformRoot,
        [ValidateRange(0, 5000)][int]$StabilizationDelayMilliseconds = 250
    )

    $activity = Get-DailySessionTerraformActivity -TerraformRoot $TerraformRoot
    if ($StabilizationDelayMilliseconds -gt 0) {
        Start-Sleep -Milliseconds $StabilizationDelayMilliseconds
        $activity = Get-DailySessionTerraformActivity -TerraformRoot $TerraformRoot
    }
    if ($activity.IsBusy) {
        throw "Another Terraform operation or state lock exists. process_count=$(@($activity.ProcessIds).Count), unscoped_process_count=$(@($activity.UnscopedProcessIds).Count), lock_count=$(@($activity.LockPaths).Count)"
    }
    return $activity
}

function Get-DailySessionWatchdogDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$State,
        [Parameter(Mandatory)][datetimeoffset]$NowUtc,
        [Parameter(Mandatory)][object]$TerraformActivity
    )

    $hardDeadline = [datetimeoffset]::Parse(
        [string]$State.HardDeadlineAtUtc,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )
    $retryUntil = [datetimeoffset]::Parse(
        [string]$State.RetryUntilUtc,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )

    if ($NowUtc -lt $hardDeadline) {
        return 'BeforeDeadline'
    }
    if ($NowUtc -ge $retryUntil) {
        return 'RetryWindowExpired'
    }
    if ([bool]$TerraformActivity.IsBusy) {
        return 'TerraformBusy'
    }
    return 'RunDailyDown'
}

function Get-DailySessionPowerShellExecutable {
    [CmdletBinding()]
    param()

    try {
        $currentProcessPath = (Get-Process -Id $PID -ErrorAction Stop).Path
        $currentExecutable = [System.IO.Path]::GetFileName($currentProcessPath)
        if ($currentExecutable -in @('powershell.exe', 'pwsh.exe') -and
            (Test-Path -LiteralPath $currentProcessPath -PathType Leaf)) {
            return $currentProcessPath
        }
    } catch {
        # Fall through to a stable system executable.
    }
    $windowsPowerShell = Join-Path $env:SystemRoot (
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    )
    if (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf) {
        return $windowsPowerShell
    }
    $command = Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Neither Windows PowerShell nor pwsh is available for the Watchdog.'
    }
    return [string]$command.Source
}

function ConvertTo-DailySessionQuotedArgument {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    if ($Value -match '["\r\n]') {
        throw 'Scheduled Task arguments must be single-line values without quotes.'
    }
    return '"' + $Value + '"'
}

function New-DailySessionWatchdogArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WatchdogScriptPath,
        [Parameter(Mandatory)][string]$SessionStatePath,
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$AutomationConfigPath,
        [Parameter(Mandatory)][string]$PrimaryBastionKeyPairName,
        [Parameter(Mandatory)][string]$DrBastionKeyPairName
    )

    $arguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-DailySessionQuotedArgument $WatchdogScriptPath),
        '-SessionStatePath', (ConvertTo-DailySessionQuotedArgument $SessionStatePath),
        '-AwsProfile', (ConvertTo-DailySessionQuotedArgument $AwsProfile),
        '-ProjectName', (ConvertTo-DailySessionQuotedArgument $ProjectName),
        '-AutomationConfigPath', (ConvertTo-DailySessionQuotedArgument $AutomationConfigPath),
        '-PrimaryBastionKeyPairName', (ConvertTo-DailySessionQuotedArgument $PrimaryBastionKeyPairName),
        '-DrBastionKeyPairName', (ConvertTo-DailySessionQuotedArgument $DrBastionKeyPairName)
    )
    return $arguments -join ' '
}

function Register-DailySessionScheduledTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$State,
        [Parameter(Mandatory)][hashtable]$SessionSafety,
        [Parameter(Mandatory)][string]$SessionStatePath,
        [Parameter(Mandatory)][string]$WatchdogScriptPath,
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$AutomationConfigPath,
        [Parameter(Mandatory)][string]$PrimaryBastionKeyPairName,
        [Parameter(Mandatory)][string]$DrBastionKeyPairName
    )

    foreach ($commandName in @(
        'New-ScheduledTaskAction',
        'New-ScheduledTaskTrigger',
        'New-ScheduledTaskSettingsSet',
        'Register-ScheduledTask'
    )) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "ScheduledTasks command is unavailable: $commandName"
        }
    }
    foreach ($path in @($WatchdogScriptPath, $SessionStatePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Watchdog file is unavailable: $path"
        }
    }

    $taskName = Get-DailySessionTaskName `
        -SessionSafety $SessionSafety `
        -SessionId ([string]$State.SessionId)
    $hardDeadline = [datetimeoffset]::Parse([string]$State.HardDeadlineAtUtc)
    $triggerAt = $hardDeadline.LocalDateTime
    if ($triggerAt -le (Get-Date)) {
        $triggerAt = (Get-Date).AddMinutes(1)
    }
    $retryInterval = New-TimeSpan `
        -Minutes ([int]$SessionSafety.RetryIntervalMinutes)
    $retryDuration = New-TimeSpan `
        -Hours ([int]$SessionSafety.RetryGraceHours)
    $powerShell = Get-DailySessionPowerShellExecutable
    $actionArguments = New-DailySessionWatchdogArguments `
        -WatchdogScriptPath $WatchdogScriptPath `
        -SessionStatePath $SessionStatePath `
        -AwsProfile $AwsProfile `
        -ProjectName $ProjectName `
        -AutomationConfigPath $AutomationConfigPath `
        -PrimaryBastionKeyPairName $PrimaryBastionKeyPairName `
        -DrBastionKeyPairName $DrBastionKeyPairName
    $action = New-ScheduledTaskAction `
        -Execute $powerShell `
        -Argument $actionArguments `
        -WorkingDirectory ([string]$State.TerraformRoot)
    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At $triggerAt `
        -RepetitionInterval $retryInterval `
        -RepetitionDuration $retryDuration
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -WakeToRun `
        -RunOnlyIfNetworkAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([timespan]::Zero)

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Description 'Bounded Daily AWS Runtime shutdown guard.' `
        -Force | Out-Null
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        throw "Daily Session Watchdog registration could not be verified: $taskName"
    }
    return $taskName
}

function Unregister-DailySessionScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TaskName)

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        throw "Daily Session Watchdog still exists after unregister: $TaskName"
    }
}

function Start-DailySessionGuard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SessionSafety,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [Parameter(Mandatory)][string]$TerraformRoot,
        [Parameter(Mandatory)][string]$AccountId,
        [Parameter(Mandatory)][string]$PrimaryRegion,
        [Parameter(Mandatory)][string]$DrRegion,
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$AutomationConfigPath,
        [Parameter(Mandatory)][string]$PrimaryBastionKeyPairName,
        [Parameter(Mandatory)][string]$DrBastionKeyPairName,
        [Parameter(Mandatory)][string]$WatchdogScriptPath,
        [ValidateSet('On', 'Off')][string]$WatchdogMode = 'On',
        [string]$ExperimentId = '',
        [string]$StateRoot = ''
    )

    if (-not [bool]$SessionSafety.Enabled) {
        throw 'Daily Session safety is disabled; Daily Apply is not allowed.'
    }
    $root = Get-DailySessionStateRoot -StateRoot $StateRoot
    $statePath = Get-DailySessionActiveStatePath -StateRoot $root
    $terraformFullPath = [System.IO.Path]::GetFullPath($TerraformRoot)
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $existing = Read-DailySessionState -Path $statePath
        if ([string]$existing.AccountId -cne $AccountId -or
            [string]$existing.PrimaryRegion -cne $PrimaryRegion -or
            [string]$existing.DrRegion -cne $DrRegion -or
            [string]$existing.TerraformRoot -ine $terraformFullPath) {
            throw 'Another Daily Session state exists for a different AWS or Terraform scope.'
        }
        $softDeadline = [datetimeoffset]::Parse(
            [string]$existing.SoftDeadlineAtUtc
        )
        if ([datetimeoffset]::UtcNow -ge $softDeadline) {
            throw 'The existing Daily Session reached its Soft Deadline. New Apply was not started; collect evidence and run Daily Down.'
        }
        $retryUntil = [datetimeoffset]::Parse([string]$existing.RetryUntilUtc)
        if ([datetimeoffset]::UtcNow -gt $retryUntil) {
            throw 'The existing Daily Session exceeded its retry window. Inspect and clear it only after Runtime reconciliation.'
        }
        if ([string]$existing.WatchdogMode -cne $WatchdogMode) {
            throw "The existing Daily Session uses WatchdogMode '$($existing.WatchdogMode)'. Run Daily Down before changing it to '$WatchdogMode'."
        }
        $taskName = Get-DailySessionTaskName `
            -SessionSafety $SessionSafety `
            -SessionId ([string]$existing.SessionId)
        if ($WatchdogMode -ceq 'On' -and
            -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            [void](Register-DailySessionScheduledTask `
                -State $existing `
                -SessionSafety $SessionSafety `
                -SessionStatePath $statePath `
                -WatchdogScriptPath $WatchdogScriptPath `
                -AwsProfile $AwsProfile `
                -ProjectName $ProjectName `
                -AutomationConfigPath $AutomationConfigPath `
                -PrimaryBastionKeyPairName $PrimaryBastionKeyPairName `
                -DrBastionKeyPairName $DrBastionKeyPairName)
        } elseif ($WatchdogMode -ceq 'Off' -and
            (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            throw 'WatchdogMode is Off, but a Scheduled Task still exists. Run Daily Down before reusing this session.'
        }
        Write-DailySessionLog `
            -SessionId ([string]$existing.SessionId) `
            -Event 'GuardReused' `
            -Detail 'Existing deadline retained.' `
            -StateRoot $root
        return $existing
    }

    $startedUtc = ([datetimeoffset]$StartedAt).ToUniversalTime()
    $softDeadline = $startedUtc.AddHours([int]$SessionSafety.SoftDeadlineHours)
    $hardDeadline = $startedUtc.AddHours([int]$SessionSafety.MaxRuntimeHours)
    $retryUntil = $hardDeadline.AddHours([int]$SessionSafety.RetryGraceHours)
    if ($softDeadline -le [datetimeoffset]::UtcNow) {
        throw 'Daily Up preflight exceeded the Session Soft Deadline; Apply was not started.'
    }
    if ($hardDeadline -le [datetimeoffset]::UtcNow) {
        throw 'Daily Up preflight exceeded the Session hard deadline; Apply was not started.'
    }
    $sessionId = $startedUtc.ToString('yyyyMMddTHHmmssZ') + '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
    if (-not $ExperimentId) {
        $ExperimentId = "daily-session-$sessionId"
    }
    if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,100}$') {
        throw 'ExperimentId is unsafe.'
    }
    $state = [ordered]@{
        SchemaVersion     = 1
        SessionId        = $sessionId
        Status           = 'Active'
        AccountId        = $AccountId
        PrimaryRegion    = $PrimaryRegion
        DrRegion         = $DrRegion
        TerraformRoot    = $terraformFullPath
        StartedAtUtc     = $startedUtc.ToString('o')
        SoftDeadlineAtUtc = $softDeadline.ToString('o')
        HardDeadlineAtUtc = $hardDeadline.ToString('o')
        RetryUntilUtc    = $retryUntil.ToString('o')
        ExperimentId     = $ExperimentId
        WatchdogMode     = $WatchdogMode
        LastAttemptAtUtc = ''
        LastResult       = if ($WatchdogMode -ceq 'On') { 'GuardRegistrationPending' } else { 'GuardDisabled' }
    }
    Write-DailySessionJson -Path $statePath -Value $state
    if ($WatchdogMode -ceq 'Off') {
        Write-DailySessionLog `
            -SessionId $sessionId `
            -Event 'GuardDisabled' `
            -Detail "hard=$($hardDeadline.ToString('o')); no Scheduled Task will run" `
            -StateRoot $root
        Write-Warning 'WatchdogMode=Off: deadlines are recorded, but no automatic Daily Down Scheduled Task will run.'
        return Read-DailySessionState -Path $statePath
    }
    try {
        [void](Register-DailySessionScheduledTask `
            -State ([pscustomobject]$state) `
            -SessionSafety $SessionSafety `
            -SessionStatePath $statePath `
            -WatchdogScriptPath $WatchdogScriptPath `
            -AwsProfile $AwsProfile `
            -ProjectName $ProjectName `
            -AutomationConfigPath $AutomationConfigPath `
            -PrimaryBastionKeyPairName $PrimaryBastionKeyPairName `
            -DrBastionKeyPairName $DrBastionKeyPairName)
        $state.LastResult = 'GuardRegistered'
        Write-DailySessionJson -Path $statePath -Value $state
        Write-DailySessionLog `
            -SessionId $sessionId `
            -Event 'GuardRegistered' `
            -Detail "hard=$($hardDeadline.ToString('o')); retry_until=$($retryUntil.ToString('o'))" `
            -StateRoot $root
    } catch {
        Write-DailySessionLog `
            -SessionId $sessionId `
            -Event 'GuardRegistrationFailed' `
            -Detail 'Daily Apply was not started.' `
            -StateRoot $root
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        throw
    }
    return Read-DailySessionState -Path $statePath
}

function Complete-DailySessionGuard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SessionSafety,
        [string]$TerraformRoot = '',
        [string]$StateRoot = ''
    )

    $root = Get-DailySessionStateRoot -StateRoot $StateRoot
    $statePath = Get-DailySessionActiveStatePath -StateRoot $root
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return [pscustomobject]@{ Removed = $false; Reason = 'NoActiveSession' }
    }
    $state = Read-DailySessionState -Path $statePath
    if ($TerraformRoot -and
        [string]$state.TerraformRoot -ine [System.IO.Path]::GetFullPath($TerraformRoot)) {
        throw 'Daily Session Terraform root does not match the completed Daily Down.'
    }
    $taskName = Get-DailySessionTaskName `
        -SessionSafety $SessionSafety `
        -SessionId ([string]$state.SessionId)
    Unregister-DailySessionScheduledTask -TaskName $taskName
    Write-DailySessionLog `
        -SessionId ([string]$state.SessionId) `
        -Event 'SessionCompleted' `
        -Detail 'Daily Runtime removal was verified.' `
        -StateRoot $root
    Remove-Item -LiteralPath $statePath -Force
    return [pscustomobject]@{
        Removed  = $true
        SessionId = [string]$state.SessionId
        TaskName = $taskName
    }
}

function Enter-DailySessionDownMutex {
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 0)

    $mutex = New-Object System.Threading.Mutex(
        $false,
        'Local\aws-topology-daily-down'
    )
    try {
        $acquired = $mutex.WaitOne([timespan]::FromSeconds($TimeoutSeconds))
    } catch [System.Threading.AbandonedMutexException] {
        $acquired = $true
    }
    if (-not $acquired) {
        $mutex.Dispose()
        throw 'Another Daily Down operation is already running.'
    }
    return $mutex
}

function Exit-DailySessionDownMutex {
    [CmdletBinding()]
    param([System.Threading.Mutex]$Mutex)

    if ($Mutex) {
        try {
            $Mutex.ReleaseMutex()
        } finally {
            $Mutex.Dispose()
        }
    }
}
