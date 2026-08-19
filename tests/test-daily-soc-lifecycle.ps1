#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$up = Get-Content -LiteralPath (Join-Path $root 'daily-up.ps1') -Raw
$down = Get-Content -LiteralPath (Join-Path $root 'daily-down.ps1') -Raw
$start = Get-Content -LiteralPath (Join-Path $root 'tools\Start-SocLab.ps1') -Raw
$stop = Get-Content -LiteralPath (Join-Path $root 'tools\Stop-SocLab.ps1') -Raw

if ($up -notmatch '\[switch\]\$SkipSocLab') {
    throw 'daily-up lacks the explicit SOC opt-out switch.'
}
if ($up -notmatch "SecurityScenarioProfile\s+-ceq\s+'capital-one-lab'[\s\S]*?SkipSocLab\.IsPresent[\s\S]*?Start-SocLab\.ps1[\s\S]*?Scope[\s\S]*?detection_only") {
    throw 'daily-up does not auto-start Detection-only SOC only for capital-one-lab.'
}
if ($up -notmatch "AWS Runtime and Watchdog remain active[\s\S]*?SOC_LAB_READY=no") {
    throw 'daily-up does not report partial success when SOC startup fails.'
}
if ($up.IndexOf('Start-SocLab.ps1',[StringComparison]::Ordinal) -gt $up.IndexOf('Daily up completed.',[StringComparison]::Ordinal)) {
    throw 'daily-up prints its success banner before starting SOC.'
}

if ($down -notmatch 'function Get-DailySocActiveSessionPath[\s\S]*?active-soc-session\.json' -or
    $down -notmatch 'function Stop-ActiveDailySocLab[\s\S]*?Get-DailySocActiveSessionPath[\s\S]*?Stop-SocLab\.ps1[\s\S]*?-StopWazuh') {
    throw 'daily-down lacks the bounded active SOC stop helper.'
}
if ($down -notmatch 'Local SOC lab stop failed; continuing Daily teardown so AWS cleanup is not blocked') {
    throw 'daily-down local SOC stop is not explicitly non-blocking.'
}
$preDestroyEvidenceIndex = $down.IndexOf("-Phase 'pre-destroy'",[StringComparison]::Ordinal)
$normalSocStopIndex = $down.LastIndexOf('$socStopStatus = Stop-ActiveDailySocLab',[StringComparison]::Ordinal)
$karpenterIndex = $down.IndexOf('Invoke-KarpenterPreDestroyCleanup',[StringComparison]::Ordinal)
if ($preDestroyEvidenceIndex -lt 0 -or $normalSocStopIndex -le $preDestroyEvidenceIndex -or
    $karpenterIndex -le $normalSocStopIndex) {
    throw 'daily-down stops SOC after Karpenter cleanup instead of before AWS destroy.'
}
if ($down -notmatch "if \(\`$EvidenceOnly\)[\s\S]*?exit 0") {
    throw 'daily-down EvidenceOnly path is missing.'
}
if ($down -notmatch "dailyState\.Count -eq 0[\s\S]*?ConfirmDestroy -ceq 'DESTROY DAILY'[\s\S]*?Stop-ActiveDailySocLab") {
    throw 'daily-down cannot recover a stale local SOC session after AWS state is already empty.'
}
if ($down -notmatch 'Daily AWS teardown completed, but the local SOC lab still failed to stop[\s\S]*?Complete-DailySessionGuard') {
    throw 'daily-down clears its Watchdog guard instead of surfacing retryable local SOC residue.'
}

if ($start -notmatch 'ValidateSet\(''detection_only'',''full''\)[\s\S]*?\$Scope\s*=\s*''detection_only''') {
    throw 'Start-SocLab lacks the detection_only/full scope contract.'
}
if ($start -notmatch 'Get-SocQueueUrl[\s\S]*?dlq_arn') {
    throw 'Start-SocLab lacks the DLQ transport ARN fallback.'
}
if ($start -notmatch 'New-WazuhDetectionOverrideText') {
    throw 'Start-SocLab does not use the detection-only Compose override.'
}
if ($stop -notmatch 'shuffle_allow_registered[\s\S]*?pre-scope full session') {
    throw 'Stop-SocLab lacks backward-compatible scope/allow handling.'
}

foreach ($path in @(
    (Join-Path $root 'daily-up.ps1'),
    (Join-Path $root 'daily-down.ps1'),
    (Join-Path $root 'tools\Start-SocLab.ps1'),
    (Join-Path $root 'tools\Stop-SocLab.ps1')
)) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors) | Out-Null
    if (@($errors).Count -ne 0) {
        throw "Parser errors in ${path}: $(@($errors.Message) -join '; ')"
    }
}

Write-Host 'Daily SOC lifecycle static tests passed.'
