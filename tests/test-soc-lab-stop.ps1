#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'tools\Stop-SocLab.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmStop\s+-cne\s+'STOP SOC LAB'"; Message='Stop lacks exact confirmation.'},
    @{Pattern='ProcessName[\s\S]*?pwsh[\s\S]*?started_at_utc[\s\S]*?heartbeat\.pid'; Message='Stop does not bind the PID to the Bridge heartbeat.'},
    @{Pattern='stopSignalPath[\s\S]*?WaitForExit'; Message='Stop does not attempt controlled Bridge shutdown.'},
    @{Pattern="finalHeartbeat\.state -cne 'STOPPED'[\s\S]*?bridgeLockPath[\s\S]*?released lock"; Message='Stop does not verify the final STOPPED heartbeat and released Bridge lock.'},
    @{Pattern='reset-exclusive\.lock[\s\S]*?FileShare\]::None[\s\S]*?recovery process still owns'; Message='Stop does not share the exact TAKE Reset lock.'},
    @{Pattern='activeTake\.status -cne \[string\]\$state\.status[\s\S]*?reset-status-journal\.json[\s\S]*?recovered before Stop-SocLab'; Message='Stop can delete mismatched Reset status records or a pending status journal.'},
    @{Pattern='Read-SocTakeRecord[\s\S]*?response_mode -ceq ''contain''[\s\S]*?status -notin @\(''READY'',''CLOSED''\)[\s\S]*?refuses to delete its recovery state'; Message='Stop can delete an in-progress containment or Reset recovery state.'},
    @{Pattern='state\.status = ''BRIDGE_STOPPED''[\s\S]*?Write-SocStopAtomicJson -Path \$activeSessionPath[\s\S]*?Remove-ShuffleSocTake'; Message='Stop does not persist its recoverable state before external Shuffle cleanup.'},
    @{Pattern='Remove-ShuffleSocTake'; Message='Stop leaves the TAKE allow key active in Shuffle.'},
    @{Pattern="StopWazuh[\s\S]*?Arguments @\('down'\)[\s\S]*?Remove-SocRuntimeSession"; Message='Stop does not unmount Wazuh before deleting Runtime Secrets.'},
    @{Pattern='terraform_destroyed\s*=\s*\$false'; Message='Stop Evidence omits its no-Destroy boundary.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match "Invoke-SocNativeCapture\s+-FilePath\s+'terraform'|daily-down\.ps1|DESTROY DAILY") {
    throw 'Stop-SocLab contains a forbidden Daily Terraform destroy path.'
}
$tokens=$null; $errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('Stop-SocLab parser errors: ' + (@($errors.Message) -join '; '))
}
Write-Host 'SOC lab controlled-stop static tests passed.'
