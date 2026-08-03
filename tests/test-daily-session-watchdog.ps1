#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$commonPath = Join-Path $root 'daily-session-common.ps1'
$watchdogPath = Join-Path $root 'daily-session-watchdog.ps1'
$dailyUpPath = Join-Path $root 'daily-up.ps1'
$dailyDownPath = Join-Path $root 'daily-down.ps1'
$modulePath = Join-Path $root 'automation\Daily.Automation.psm1'
$configPath = Join-Path $root 'automation\project.psd1'

. $commonPath
Import-Module $modulePath -Force
$config = Import-DailyAutomationConfig -Path $configPath
$safety = $config.SessionSafety

$dailyUpSource = Get-Content -LiteralPath $dailyUpPath -Raw
if ($dailyUpSource -notmatch '(?s)ConfirmApply\s+-cne\s+''APPLY DAILY''.*?Start-DailySessionGuard.*?''apply''') {
    throw 'daily-up does not register the guard after confirmation and before Terraform Apply.'
}
$dailyDownSource = Get-Content -LiteralPath $dailyDownPath -Raw
if ($dailyDownSource -notmatch 'Enter-DailySessionDownMutex' -or
    $dailyDownSource -notmatch 'Assert-DailySessionTerraformIdle' -or
    @([regex]::Matches($dailyDownSource, 'Complete-DailySessionGuard')).Count -lt 2) {
    throw 'daily-down does not retain mutex, Terraform-idle, and successful guard cleanup contracts.'
}

if (-not [bool]$safety.Enabled -or
    [int]$safety.SoftDeadlineHours -ne 5 -or
    [int]$safety.MaxRuntimeHours -ne 6 -or
    [int]$safety.RetryGraceHours -ne 2 -or
    [int]$safety.RetryIntervalMinutes -ne 15) {
    throw 'Daily Session safety defaults do not match the reviewed 5h/6h/2h/15m contract.'
}

$referenceNow = [datetimeoffset]'2026-08-02T00:00:00Z'
$decisionState = [pscustomobject]@{
    HardDeadlineAtUtc = $referenceNow.AddHours(6).ToString('o')
    RetryUntilUtc = $referenceNow.AddHours(8).ToString('o')
}
$idle = [pscustomobject]@{ IsBusy = $false }
$busy = [pscustomobject]@{ IsBusy = $true }
$decisionCases = @(
    @($referenceNow.AddHours(5), $idle, 'BeforeDeadline'),
    @($referenceNow.AddHours(6), $busy, 'TerraformBusy'),
    @($referenceNow.AddHours(6), $idle, 'RunDailyDown'),
    @($referenceNow.AddHours(8), $idle, 'RetryWindowExpired')
)
foreach ($case in $decisionCases) {
    $actual = Get-DailySessionWatchdogDecision `
        -State $decisionState `
        -NowUtc ([datetimeoffset]$case[0]) `
        -TerraformActivity $case[1]
    if ($actual -cne [string]$case[2]) {
        throw "Unexpected Watchdog decision: expected=$($case[2]), actual=$actual"
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'daily-session-watchdog-test-' + [guid]::NewGuid().ToString('N')
)
$terraformTestRoot = Join-Path $testRoot 'terraform-root'
$stateRoot = Join-Path $testRoot 'session-state'
$taskPrefix = 'aws-topology-session-test-' +
    [guid]::NewGuid().ToString('N').Substring(0, 8)
$testSafety = @{
    Enabled = $true
    SoftDeadlineHours = 5
    MaxRuntimeHours = 6
    RetryGraceHours = 2
    RetryIntervalMinutes = 15
    TaskNamePrefix = $taskPrefix
}
$taskName = ''
$offTaskName = ''

New-Item -ItemType Directory -Path $terraformTestRoot -Force | Out-Null
try {
    $lockPath = Join-Path $terraformTestRoot '.terraform.tfstate.lock.info'
    [System.IO.File]::WriteAllText(
        $lockPath,
        '{}',
        (New-Object System.Text.UTF8Encoding($false))
    )
    $activity = Get-DailySessionTerraformActivity -TerraformRoot $terraformTestRoot
    if (-not $activity.IsBusy -or @($activity.LockPaths).Count -ne 1) {
        throw 'Terraform state-lock detection did not fail closed.'
    }
    Remove-Item -LiteralPath $lockPath -Force

    $softDeadlineRejected = $false
    try {
        [void](Start-DailySessionGuard `
            -SessionSafety $testSafety `
            -StartedAt (Get-Date).AddHours(-5).AddMinutes(-1) `
            -TerraformRoot $terraformTestRoot `
            -AccountId '000000000000' `
            -PrimaryRegion 'ap-northeast-2' `
            -DrRegion 'ap-northeast-1' `
            -AwsProfile 'watchdog-test-profile' `
            -ProjectName 'aws-topology' `
            -AutomationConfigPath $configPath `
            -PrimaryBastionKeyPairName 'watchdog-primary-test' `
            -DrBastionKeyPairName 'watchdog-dr-test' `
            -WatchdogScriptPath $watchdogPath `
            -ExperimentId 'watchdog-soft-deadline-test' `
            -StateRoot $stateRoot)
    } catch {
        if ($_.Exception.Message -like '*Soft Deadline*') {
            $softDeadlineRejected = $true
        } else {
            throw
        }
    }
    if (-not $softDeadlineRejected) {
        throw 'Daily Apply was not rejected after the Soft Deadline.'
    }

    $session = Start-DailySessionGuard `
        -SessionSafety $testSafety `
        -StartedAt (Get-Date) `
        -TerraformRoot $root `
        -AccountId '000000000000' `
        -PrimaryRegion 'ap-northeast-2' `
        -DrRegion 'ap-northeast-1' `
        -AwsProfile 'watchdog-test-profile' `
        -ProjectName 'aws-topology' `
        -AutomationConfigPath $configPath `
        -PrimaryBastionKeyPairName 'watchdog-primary-test' `
        -DrBastionKeyPairName 'watchdog-dr-test' `
        -WatchdogScriptPath $watchdogPath `
        -ExperimentId 'watchdog-static-test' `
        -StateRoot $stateRoot
    $taskName = Get-DailySessionTaskName `
        -SessionSafety $testSafety `
        -SessionId ([string]$session.SessionId)
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if (-not $task.Settings.WakeToRun -or
        -not $task.Settings.StartWhenAvailable -or
        [string]$task.Settings.MultipleInstances -cne 'IgnoreNew') {
        throw 'Registered Watchdog task does not retain the reviewed wake/start/concurrency settings.'
    }
    $actionArguments = [string]$task.Actions[0].Arguments
    foreach ($expected in @(
        'daily-session-watchdog.ps1',
        'watchdog-test-profile',
        'watchdog-static-test'
    )) {
        if ($actionArguments -notlike "*$expected*") {
            if ($expected -ceq 'watchdog-static-test') {
                # Experiment ID lives only in the state file, not Task arguments.
                continue
            }
            throw "Watchdog task action is missing a required non-secret routing value: $expected"
        }
    }

    $probeOutput = Join-Path $testRoot 'watchdog-probe.out'
    $probeError = Join-Path $testRoot 'watchdog-probe.err'
    $earlyProbe = Start-Process `
        -FilePath ([string]$task.Actions[0].Execute) `
        -ArgumentList $actionArguments `
        -RedirectStandardOutput $probeOutput `
        -RedirectStandardError $probeError `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ([int]$earlyProbe.ExitCode -ne 0) {
        $probeDetail = @(
            Get-Content -LiteralPath $probeOutput -ErrorAction SilentlyContinue
            Get-Content -LiteralPath $probeError -ErrorAction SilentlyContinue
        ) -join ' '
        throw "Watchdog entrypoint failed its no-op pre-deadline probe: $($earlyProbe.ExitCode); $probeDetail"
    }

    $statePath = Get-DailySessionActiveStatePath -StateRoot $stateRoot
    $stateJson = Get-Content -LiteralPath $statePath -Raw
    if ($stateJson -match '(?i)password|credential|private.?key|access.?key|secret|token|awsprofile') {
        throw 'Daily Session state contains a forbidden secret-bearing field or value.'
    }
    $stored = Read-DailySessionState -Path $statePath
    $expectedHard = ([datetimeoffset]$stored.StartedAtUtc).AddHours(6)
    if ([datetimeoffset]$stored.HardDeadlineAtUtc -ne $expectedHard) {
        throw 'Daily Session hard deadline was not calculated from the command start time.'
    }
    $expectedRetryUntil = $expectedHard.AddHours(2)
    if ([datetimeoffset]$stored.RetryUntilUtc -ne $expectedRetryUntil) {
        throw 'Daily Session retry window is not bounded to two hours.'
    }

    $completion = Complete-DailySessionGuard `
        -SessionSafety $testSafety `
        -TerraformRoot $root `
        -StateRoot $stateRoot
    if (-not $completion.Removed) {
        throw 'Daily Session completion did not remove the active guard.'
    }
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        throw 'Daily Session active state remains after successful completion.'
    }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'Daily Session Scheduled Task remains after successful completion.'
    }
    $logPath = Get-DailySessionLogPath `
        -SessionId ([string]$session.SessionId) `
        -StateRoot $stateRoot
    if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
        throw 'Sanitized Daily Session lifecycle log was not retained.'
    }
    $logContent = Get-Content -LiteralPath $logPath -Raw
    if ($logContent -notmatch 'BeforeDeadline' -or
        $logContent -notmatch 'SessionCompleted') {
        throw 'Watchdog lifecycle log does not include the pre-deadline no-op and completion events.'
    }

    $offStateRoot = Join-Path $testRoot 'session-state-watchdog-off'
    $offSession = Start-DailySessionGuard `
        -SessionSafety $testSafety `
        -StartedAt (Get-Date) `
        -TerraformRoot $root `
        -AccountId '000000000000' `
        -PrimaryRegion 'ap-northeast-2' `
        -DrRegion 'ap-northeast-1' `
        -AwsProfile 'watchdog-test-profile' `
        -ProjectName 'aws-topology' `
        -AutomationConfigPath $configPath `
        -PrimaryBastionKeyPairName 'watchdog-primary-test' `
        -DrBastionKeyPairName 'watchdog-dr-test' `
        -WatchdogScriptPath $watchdogPath `
        -WatchdogMode Off `
        -ExperimentId 'watchdog-disabled-test' `
        -StateRoot $offStateRoot
    $offTaskName = Get-DailySessionTaskName `
        -SessionSafety $testSafety `
        -SessionId ([string]$offSession.SessionId)
    if (Get-ScheduledTask -TaskName $offTaskName -ErrorAction SilentlyContinue) {
        throw 'WatchdogMode Off unexpectedly registered a Scheduled Task.'
    }
    if ([string]$offSession.WatchdogMode -cne 'Off' -or
        [string]$offSession.LastResult -cne 'GuardDisabled') {
        throw 'WatchdogMode Off was not retained in the bounded Daily Session state.'
    }
    $offLogPath = Get-DailySessionLogPath `
        -SessionId ([string]$offSession.SessionId) `
        -StateRoot $offStateRoot
    if ((Get-Content -LiteralPath $offLogPath -Raw) -notmatch 'GuardDisabled') {
        throw 'WatchdogMode Off did not write the expected sanitized lifecycle event.'
    }
    $offCompletion = Complete-DailySessionGuard `
        -SessionSafety $testSafety `
        -TerraformRoot $root `
        -StateRoot $offStateRoot
    if (-not $offCompletion.Removed) {
        throw 'WatchdogMode Off session was not cleaned up by Daily Down completion.'
    }
} finally {
    if ($taskName) {
        Unregister-ScheduledTask `
            -TaskName $taskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if ($offTaskName) {
        Unregister-ScheduledTask `
            -TaskName $offTaskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Daily Session Watchdog self-test passed.'
