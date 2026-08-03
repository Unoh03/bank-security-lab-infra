#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'Review-SecurityWindow.ps1'
$modulePath = Join-Path $root 'automation\Security.Review.psm1'
$configPath = Join-Path $root 'automation\project.psd1'

foreach ($path in @($scriptPath, $modulePath, $configPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Security review artifact is missing: $path"
    }
    if ([System.IO.Path]::GetExtension($path) -in @('.ps1', '.psm1')) {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $path,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "PowerShell parser rejected $path`: $($errors[0].Message)"
        }
    }
}

$config = Import-PowerShellDataFile -LiteralPath $configPath
if (-not $config.Evidence.Review -or
    [string]$config.Evidence.Review.ScenarioId -cne 'SOC-REVIEW') {
    throw 'SOC-REVIEW configuration is missing.'
}
$queryNames = @($config.Evidence.Queries | ForEach-Object { [string]$_.Name })
foreach ($required in @(
    'review-application-events',
    'review-waf-requests',
    'review-kubernetes-sensitive-actions',
    'review-cloudtrail-security-changes'
)) {
    if ($required -notin $queryNames) {
        throw "Security review query is not configured: $required"
    }
}
foreach ($query in @($config.Evidence.Queries | Where-Object {
    'SOC-REVIEW' -in @($_.ScenarioIds)
})) {
    $queryPath = Join-Path (Join-Path $root $config.Evidence.QueryPackRoot) ([string]$query.QueryFile)
    if (-not (Test-Path -LiteralPath $queryPath -PathType Leaf)) {
        throw "Security review query file is missing: $queryPath"
    }
}

$preview = & $scriptPath `
    -StartKst '2026-08-03 14:00' `
    -EndKst '2026-08-03 14:20' `
    -SourceIp '203.0.113.10' `
    -Label 'fixture-preview' 6>&1 | Out-String
if ($preview -notmatch 'Preview only' -or
    $preview -notmatch '2026-08-03T05:00:00') {
    throw 'Security review Preview did not parse KST or stop before AWS queries.'
}

function Write-TestJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 30),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function New-AthenaFixture {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][object[][]]$Rows
    )
    $allRows = New-Object System.Collections.Generic.List[object]
    $allRows.Add([ordered]@{
        Data = @($Headers | ForEach-Object { [ordered]@{ VarCharValue = $_ } })
    })
    foreach ($row in $Rows) {
        $allRows.Add([ordered]@{
            Data = @($row | ForEach-Object { [ordered]@{ VarCharValue = [string]$_ } })
        })
    }
    return [ordered]@{
        ResultSet = [ordered]@{ Rows = $allRows.ToArray() }
    }
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-security-review-test-' + [guid]::NewGuid().ToString('N')
)
try {
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    Write-TestJson -Path (Join-Path $tempRoot 'manifest.json') -Value ([ordered]@{
        SchemaVersion = 2
        ExperimentId = 'review-test'
        Files = @()
    })

    $traceId = 'Root=1-65b00000-0123456789abcdef01234567'
    $appRows = @()
    for ($index = 0; $index -lt 5; $index++) {
        $appRows += [ordered]@{
            event_time = "2026-08-03T05:00:0$($index + 1).000Z"
            event_name = 'auth.login.failed'
            result = 'denied'
            user_id = 'user-test'
            source_ip = '203.0.113.10'
            route = '/login.php'
            request_id = if ($index -eq 0) { $traceId } else { "app-$index" }
            detail = if ($index -eq 0) { 'password=supersecret' } else { '' }
        }
    }
    Write-TestJson `
        -Path (Join-Path $tempRoot 'results\cloudwatch\review-application-events.json') `
        -Value ([ordered]@{ Rows = $appRows })
    Write-TestJson `
        -Path (Join-Path $tempRoot 'results\cloudwatch\review-waf-requests.json') `
        -Value ([ordered]@{ Rows = @([ordered]@{
            event_time = '2026-08-03T05:00:01.500Z'
            source_ip = '203.0.113.10'
            method = 'POST'
            route = '/login.php'
            result = 'COUNT'
            event_name = 'bank-login-rate'
        }) })
    foreach ($queryName in @(
        'review-kubernetes-sensitive-actions',
        'review-cloudtrail-security-changes'
    )) {
        Write-TestJson `
            -Path (Join-Path $tempRoot "results\cloudwatch\$queryName.json") `
            -Value ([ordered]@{ Rows = @() })
    }

    Write-TestJson `
        -Path (Join-Path $tempRoot 'results\athena\cloudfront-trace-results.json') `
        -Value (New-AthenaFixture `
            -Headers @('date', 'time', 'source_ip', 'method', 'path', 'status', 'edge_request_id', 'time_taken') `
            -Rows @(, @('2026-08-03', '05:00:01.100', '203.0.113.10', 'POST', '/login.php', '200', 'edge-test', '0.010')))
    Write-TestJson `
        -Path (Join-Path $tempRoot 'results\athena\alb-window-results.json') `
        -Value (New-AthenaFixture `
            -Headers @('event_time', 'source_ip', 'method', 'route', 'elb_status_code', 'target_status_code', 'trace_id') `
            -Rows @(, @('2026-08-03T05:00:01.300Z', '203.0.113.10', 'POST', '/login.php', '200', '200', $traceId)))

    Import-Module $modulePath -Force
    $result = Export-SecurityReview `
        -ReviewConfig $config.Evidence.Review `
        -BundleRoot $tempRoot `
        -StartTimeUtc ([datetime]'2026-08-03T05:00:00Z') `
        -EndTimeUtc ([datetime]'2026-08-03T05:01:00Z') `
        -SourceIp '203.0.113.10' `
        -Label 'fixture-test'

    foreach ($path in @(
        $result.SummaryPath,
        $result.TimelinePath,
        $result.TriagePath,
        (Join-Path $tempRoot 'SHA256SUMS.txt'),
        (Join-Path $tempRoot 'manifest.json.sha256')
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Security review output is missing: $path"
        }
    }
    $combined = @(
        Get-Content -Raw -LiteralPath $result.SummaryPath
        Get-Content -Raw -LiteralPath $result.TimelinePath
        Get-Content -Raw -LiteralPath $result.TriagePath
    ) -join "`n"
    if ($combined -match 'supersecret') {
        throw 'Security review output leaked a sensitive fixture value.'
    }
    if ($combined -notmatch '\[REDACTED\]') {
        throw 'Security review output did not preserve the redaction marker.'
    }
    if ($combined -notmatch 'exact') {
        throw 'Exact Application-to-ALB request correlation was not produced.'
    }
    $triage = Get-Content -Raw -LiteralPath $result.TriagePath | ConvertFrom-Json
    if ([string]$triage.Verdict -cne 'NeedsAnalystReview') {
        throw 'Automatic review overclaimed a final analyst verdict.'
    }
    if ([string]$triage.SuggestedSeverity -cne 'medium') {
        throw 'Repeated login fixture did not produce the expected suggested severity.'
    }
    if ([int]$triage.EventCount -lt 8) {
        throw "Timeline lost fixture events: $($triage.EventCount)"
    }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $tempRoot 'manifest.json') |
        ConvertFrom-Json
    if (-not $manifest.Review -or [string]$manifest.Review.IncidentId -ne [string]$result.IncidentId) {
        throw 'Evidence manifest was not updated with the review result.'
    }
    $sums = Get-Content -Raw -LiteralPath (Join-Path $tempRoot 'SHA256SUMS.txt')
    foreach ($expected in @('review/summary.md', 'review/timeline.csv', 'review/triage.json')) {
        if (-not $sums.Contains($expected)) {
            throw "Evidence hash index is missing: $expected"
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Security review static and fixture tests passed.'
