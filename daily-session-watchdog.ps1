#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SessionStatePath,
    [Parameter(Mandatory)][string]$AwsProfile,
    [Parameter(Mandatory)][string]$ProjectName,
    [Parameter(Mandatory)][string]$AutomationConfigPath,
    [Parameter(Mandatory)][string]$PrimaryBastionKeyPairName,
    [Parameter(Mandatory)][string]$DrBastionKeyPairName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'daily-session-common.ps1')

function Invoke-WatchdogDailyDown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$State,
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$ConfiguredProjectName,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$PrimaryKeyPair,
        [Parameter(Mandatory)][string]$DrKeyPair
    )

    $dailyDownPath = Join-Path ([string]$State.TerraformRoot) 'daily-down.ps1'
    if (-not (Test-Path -LiteralPath $dailyDownPath -PathType Leaf)) {
        throw 'daily-down.ps1 is unavailable for the Watchdog.'
    }
    $parts = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-DailySessionQuotedArgument $dailyDownPath),
        '-ConfirmDestroy', (ConvertTo-DailySessionQuotedArgument 'DESTROY DAILY'),
        '-TerraformRoot', (ConvertTo-DailySessionQuotedArgument ([string]$State.TerraformRoot)),
        '-AwsProfile', (ConvertTo-DailySessionQuotedArgument $Profile),
        '-Region', (ConvertTo-DailySessionQuotedArgument ([string]$State.PrimaryRegion)),
        '-DrRegion', (ConvertTo-DailySessionQuotedArgument ([string]$State.DrRegion)),
        '-ExpectedAccountId', (ConvertTo-DailySessionQuotedArgument ([string]$State.AccountId)),
        '-ProjectName', (ConvertTo-DailySessionQuotedArgument $ConfiguredProjectName),
        '-PrimaryBastionKeyPairName', (ConvertTo-DailySessionQuotedArgument $PrimaryKeyPair),
        '-DrBastionKeyPairName', (ConvertTo-DailySessionQuotedArgument $DrKeyPair),
        '-AutomationConfigPath', (ConvertTo-DailySessionQuotedArgument $ConfigPath),
        '-ExperimentId', (ConvertTo-DailySessionQuotedArgument ([string]$State.ExperimentId)),
        '-EvidenceStartUtc', (ConvertTo-DailySessionQuotedArgument ([string]$State.StartedAtUtc))
    )
    $process = Start-Process `
        -FilePath (Get-DailySessionPowerShellExecutable) `
        -ArgumentList ($parts -join ' ') `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    return [int]$process.ExitCode
}

$state = $null
$stateRoot = Split-Path -Parent $SessionStatePath
try {
    $state = Read-DailySessionState -Path $SessionStatePath
    $modulePath = Join-Path ([string]$state.TerraformRoot) (
        'automation\Daily.Automation.psm1'
    )
    Import-Module $modulePath -Force
    $config = Import-DailyAutomationConfig -Path $AutomationConfigPath
    $activity = Get-DailySessionTerraformActivity `
        -TerraformRoot ([string]$state.TerraformRoot)
    $decision = Get-DailySessionWatchdogDecision `
        -State $state `
        -NowUtc ([datetimeoffset]::UtcNow) `
        -TerraformActivity $activity

    switch ($decision) {
        'BeforeDeadline' {
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'BeforeDeadline' `
                -Detail 'No action was taken.' `
                -StateRoot $stateRoot
            exit 0
        }
        'RetryWindowExpired' {
            [void](Set-DailySessionStateStatus `
                -Path $SessionStatePath `
                -Status 'RetryWindowExpired' `
                -LastResult 'Automatic retries stopped.')
            $taskName = Get-DailySessionTaskName `
                -SessionSafety $config.SessionSafety `
                -SessionId ([string]$state.SessionId)
            Unregister-DailySessionScheduledTask -TaskName $taskName
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'RetryWindowExpired' `
                -Detail 'Daily Runtime may still exist; manual reconciliation is required.' `
                -StateRoot $stateRoot
            exit 4
        }
        'TerraformBusy' {
            [void](Set-DailySessionStateStatus `
                -Path $SessionStatePath `
                -Status 'WaitingForTerraform' `
                -LastResult 'Process or state lock still exists.')
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'TerraformBusy' `
                -Detail "process_count=$(@($activity.ProcessIds).Count); lock_count=$(@($activity.LockPaths).Count)" `
                -StateRoot $stateRoot
            exit 3
        }
        'RunDailyDown' {
            [void](Set-DailySessionStateStatus `
                -Path $SessionStatePath `
                -Status 'DownStarting' `
                -LastResult 'Starting bounded Daily Down.')
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'DownStarting' `
                -Detail 'Fresh plan, evidence, destroy, residue, and Foundation checks follow.' `
                -StateRoot $stateRoot
            $exitCode = Invoke-WatchdogDailyDown `
                -State $state `
                -Profile $AwsProfile `
                -ConfiguredProjectName $ProjectName `
                -ConfigPath $AutomationConfigPath `
                -PrimaryKeyPair $PrimaryBastionKeyPairName `
                -DrKeyPair $DrBastionKeyPairName
            if ($exitCode -ne 0) {
                [void](Set-DailySessionStateStatus `
                    -Path $SessionStatePath `
                    -Status 'DownFailed' `
                    -LastResult "daily-down exit code $exitCode")
                Write-DailySessionLog `
                    -SessionId ([string]$state.SessionId) `
                    -Event 'DownFailed' `
                    -Detail "exit_code=$exitCode; a bounded retry remains scheduled." `
                    -StateRoot $stateRoot
                exit 1
            }
            if (Test-Path -LiteralPath $SessionStatePath -PathType Leaf) {
                [void](Complete-DailySessionGuard `
                    -SessionSafety $config.SessionSafety `
                    -TerraformRoot ([string]$state.TerraformRoot) `
                    -StateRoot $stateRoot)
            }
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'DownSucceeded' `
                -Detail 'Daily Runtime removal and Foundation retention were verified.' `
                -StateRoot $stateRoot
            exit 0
        }
        default {
            throw "Unsupported Watchdog decision: $decision"
        }
    }
} catch {
    if ($state) {
        try {
            Write-DailySessionLog `
                -SessionId ([string]$state.SessionId) `
                -Event 'WatchdogError' `
                -Detail "error_type=$($_.Exception.GetType().Name); no secret-bearing error text was copied." `
                -StateRoot $stateRoot
        } catch {
            # The state or log destination itself may be unavailable.
        }
    }
    throw
}
