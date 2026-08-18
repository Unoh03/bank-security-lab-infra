#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [string]$EvidenceRoot = '',
    [ValidateRange(30,300)][int]$DetectionTimeoutSeconds = 120,
    [ValidateRange(30,300)][int]$ShuffleTimeoutSeconds = 180,
    [ValidateRange(30,300)][int]$NoGithubObservationSeconds = 60,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force

$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'aws-topology-evidence'
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
$runId = 'gate-b4-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$summaryDirectory = Join-Path $EvidenceRoot $runId

Write-Host 'Gate B4 Rule 100103 three-TAKE rehearsal preview'
Write-Host 'Sequence: three independent observe-only SOC sessions.'
Write-Host 'Per TAKE: Start-SocLab -> fixed Capital One baseline -> numeric Ping -> Event 2+1 / Alert 2+0 -> Shuffle OBSERVE_ONLY -> GitHub 0 -> Stop-SocLab.'
Write-Host 'Runtime writes: safe CloudWatch probe, Shuffle allow/outcome keys, three bounded lab attacks and reads. No infrastructure mutation or intended GitHub write.'
Write-Host 'Prerequisite: Prepare-CapitalOneDemoData must already have created the fixed fake object in the current Daily Runtime.'
if ($ConfirmRun -cne 'RUN RULE 100103 THREE TAKE REHEARSAL') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN RULE 100103 THREE TAKE REHEARSAL'."
}

function Write-ThreeTakeAtomicJson {
    param([string]$Path,[object]$Value)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
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

if (Test-Path -LiteralPath $activeSessionPath -PathType Leaf) {
    throw 'An active SOC session already exists. Stop it before the three-TAKE rehearsal.'
}

New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null
$results = [Collections.Generic.List[object]]::new()
$failureIteration = 0
try {
    for ($iteration = 1; $iteration -le 3; $iteration++) {
        $failureIteration = $iteration
        $started = $false
        try {
            $remainingRequired = 45 + ((3 - $iteration) * 15)
            & (Join-Path $terraformRoot 'tools\Start-SocLab.ps1') `
                -ResponseMode observe_only `
                -MinimumDailyRemainingMinutes $remainingRequired `
                -SecretRoot $SecretRoot -RuntimeRoot $RuntimeRoot `
                -ConfigurationRoot $ConfigurationRoot -EvidenceRoot $EvidenceRoot `
                -ConfirmStart 'START SOC LAB'
            $started = $true
            $state = Get-Content -LiteralPath $activeSessionPath -Raw | ConvertFrom-Json
            $takeId = [string]$state.take_id
            if ($takeId -notmatch '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' -or
                [string]$state.status -cne 'READY' -or [string]$state.response_mode -cne 'observe_only') {
                throw 'Start-SocLab did not return the fixed observe-only READY state.'
            }

            & (Join-Path $terraformRoot 'observability\scenarios\Test-SocRule100103Rehearsal.ps1') `
                -SecretRoot $SecretRoot -RuntimeRoot $RuntimeRoot `
                -ConfigurationRoot $ConfigurationRoot `
                -DetectionTimeoutSeconds $DetectionTimeoutSeconds `
                -ShuffleTimeoutSeconds $ShuffleTimeoutSeconds `
                -NoGithubObservationSeconds $NoGithubObservationSeconds `
                -ConfirmRun 'RUN RULE 100103 REHEARSAL'

            $takeEvidence = Join-Path $EvidenceRoot "$takeId\soc\02-wazuh-alerts.json"
            $record = Get-Content -LiteralPath $takeEvidence -Raw | ConvertFrom-Json
            if ([string]$record.take_id -cne $takeId -or
                [int]$record.attack_event_count -ne 2 -or [int]$record.rule_100103_alert_count -ne 2 -or
                [int]$record.normal_rule_100103_count -ne 0 -or
                [int]$record.shuffle_observe_only_count -ne 2 -or
                [int]$record.github_containment_run_count -ne 0 -or
                [bool]$record.source_to_alert_event_id_match -ne $true) {
                throw 'The per-TAKE rehearsal Evidence violated the Gate B4 contract.'
            }
            $results.Add([pscustomobject][ordered]@{
                iteration=$iteration
                take_id=$takeId
                evidence_path=$takeEvidence
                evidence_sha256=(Get-FileHash -LiteralPath $takeEvidence -Algorithm SHA256).Hash.ToLowerInvariant()
                source_event_count=2
                rule_100103_alert_count=2
                normal_rule_100103_count=0
                shuffle_observe_only_count=2
                github_containment_run_count=0
                maximum_latency_seconds=($record.alerts | Measure-Object -Property latency_seconds -Maximum).Maximum
            })
        } finally {
            if ($started -and (Test-Path -LiteralPath $activeSessionPath -PathType Leaf)) {
                & (Join-Path $terraformRoot 'tools\Stop-SocLab.ps1') `
                    -StopWazuh -SecretRoot $SecretRoot -RuntimeRoot $RuntimeRoot `
                    -ConfigurationRoot $ConfigurationRoot `
                    -ConfirmStop 'STOP SOC LAB'
            }
        }
    }

    if ($results.Count -ne 3 -or @($results.take_id | Select-Object -Unique).Count -ne 3 -or
        ($results | Measure-Object -Property source_event_count -Sum).Sum -ne 6 -or
        ($results | Measure-Object -Property rule_100103_alert_count -Sum).Sum -ne 6 -or
        ($results | Measure-Object -Property normal_rule_100103_count -Sum).Sum -ne 0 -or
        ($results | Measure-Object -Property github_containment_run_count -Sum).Sum -ne 0) {
        throw 'The three-TAKE aggregate did not satisfy Gate B4.'
    }
    $summaryPath = Join-Path $summaryDirectory 'gate-b4-summary.json'
    Write-ThreeTakeAtomicJson -Path $summaryPath -Value ([ordered]@{
        schema_version=1
        run_id=$runId
        completed_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        take_count=3
        unique_take_count=3
        source_event_count=6
        rule_100103_alert_count=6
        normal_control_count=3
        normal_rule_100103_count=0
        missed_detection_count=0
        duplicate_event_id_count=0
        shuffle_observe_only_count=6
        github_containment_run_count=0
        takes=@($results)
    })
    $findings = @(Find-SocSecretExposure -Path @($summaryDirectory,@($results.evidence_path)))
    if ($findings.Count -ne 0) { throw 'The Gate B4 Evidence failed the secret exposure scan.' }
    [IO.File]::WriteAllText(
        (Join-Path $summaryDirectory 'SHA256SUMS'),
        ('{0}  gate-b4-summary.json' -f ((Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash.ToLowerInvariant())) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'GATE_B4_SUCCEEDED=yes'
    Write-Host 'TAKES=3'
    Write-Host 'SOURCE_EVENTS=6'
    Write-Host 'RULE_100103_ALERTS=6'
    Write-Host 'NORMAL_FALSE_POSITIVES=0'
    Write-Host 'GITHUB_RUNS=0'
    Write-Host "GATE_B4_EVIDENCE=$summaryPath"
} catch {
    Write-ThreeTakeAtomicJson -Path (Join-Path $summaryDirectory 'failure.json') -Value ([ordered]@{
        schema_version=1
        run_id=$runId
        failed_at_utc=[datetimeoffset]::UtcNow.ToString('o')
        failed_iteration=$failureIteration
        completed_take_count=$results.Count
        failure_type=$_.Exception.GetType().FullName
        message_persisted=$false
    })
    throw
}
