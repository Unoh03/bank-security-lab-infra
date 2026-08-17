#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ComposeRoot = 'D:\Wazuh\wazuh-docker\single-node',
    [switch]$StartStack,
    [string]$BackupPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedServices = @(
    'wazuh.dashboard',
    'wazuh.indexer',
    'wazuh.manager'
)
$expectedDashboardTitles = @(
    'AWS 보안관제 현황',
    'AWS 보안 사건 상세'
)
$expectedVisualizationTitles = @(
    '[AWS-SOC] 01 중요 경보',
    '[AWS-SOC] 02 WAF 검사 요청',
    '[AWS-SOC] 03 WAF 차단 요청',
    '[AWS-SOC] 04 ALB 오류 응답',
    '[AWS-SOC] 10 웹 요청 추이',
    '[AWS-SOC] 11 ALB 응답 상태',
    '[AWS-SOC] 12 AWS API 활동 추이',
    '[AWS-SOC] 13 주요 AWS Service',
    '[AWS-SOC] 31 Workload 의심 행위',
    '[AWS-SOC] 32 보호 데이터 접근',
    '[AWS-SOC] 33 대응 연결 상태',
    '[AWS-SOC] 40 사건 단계별 Evidence',
    '[AWS-SOC] 41 관련 Event 수집 흐름',
    '[AWS-SOC] 51 분석과 다음 조치'
)
$expectedSearchTitles = @(
    '[AWS-SOC] 20 최근 중요 경보',
    '[AWS-SOC] 50 탐지 근거'
)
$expectedSearchColumns = @(
    'timestamp',
    'rule.level',
    'rule.description',
    'data.aws.eventSource',
    'data.aws.eventName',
    'data.aws.requestParameters.key'
)
$adminCertificateArguments = @(
    '--cert', '/usr/share/wazuh-indexer/config/certs/admin.pem',
    '--key', '/usr/share/wazuh-indexer/config/certs/admin-key.pem',
    '--cacert', '/usr/share/wazuh-indexer/config/certs/root-ca.pem'
)

function Invoke-DockerCapture {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [string]$FailureMessage = 'Docker command failed.'
    )

    $output = @(& docker @ArgumentList 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage`n$($output -join "`n")"
    }
    return $output
}

function Invoke-IndexerGet {
    param([Parameter(Mandatory)][string]$Path)

    $arguments = @(
        'compose', 'exec', '-T', 'wazuh.indexer',
        'curl', '-sS'
    ) + $adminCertificateArguments + @(
        "https://wazuh.indexer:9200/$Path"
    )
    $raw = (Invoke-DockerCapture -ArgumentList $arguments `
        -FailureMessage "Wazuh Indexer GET failed: $Path") -join "`n"
    return $raw | ConvertFrom-Json -DateKind String
}

function Invoke-IndexerPost {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 30 -Compress
    $arguments = @(
        'compose', 'exec', '-T', 'wazuh.indexer',
        'curl', '-sS'
    ) + $adminCertificateArguments + @(
        '-H', 'Content-Type: application/json',
        '-X', 'POST',
        "https://wazuh.indexer:9200/$Path",
        '-d', '@-'
    )
    $raw = @($json | & docker @arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh Indexer POST failed: $Path`n$($raw -join "`n")"
    }
    return ($raw -join "`n") | ConvertFrom-Json -DateKind String
}

function Assert-Condition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Get-SavedObject {
    param(
        [Parameter(Mandatory)][object[]]$Documents,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Title
    )

    $document = @($Documents | Where-Object {
        $_._source.type -eq $Type -and $_._source.$Type.title -eq $Title
    }) | Select-Object -First 1
    Assert-Condition -Condition ($null -ne $document) `
        -Message "Saved Object is missing: $Title"
    return $document
}

function Get-EventCount {
    param(
        [Parameter(Mandatory)][string]$Index,
        [Parameter(Mandatory)][hashtable]$Query
    )

    $boundedQuery = @{
        bool = @{
            filter = @(
                @{ range = @{ timestamp = @{ gte = 'now-7d'; lte = 'now' } } },
                $Query
            )
        }
    }
    $result = Invoke-IndexerPost `
        -Path "$Index/_count?ignore_unavailable=true" `
        -Body @{ query = $boundedQuery }
    return [int64]$result.count
}

if (-not (Test-Path -LiteralPath $ComposeRoot -PathType Container)) {
    throw "Wazuh Compose root does not exist: $ComposeRoot"
}

Push-Location $ComposeRoot
try {
    [void](Invoke-DockerCapture -ArgumentList @('compose', 'config', '--quiet') `
        -FailureMessage 'Wazuh Compose configuration is invalid.')

    if ($StartStack) {
        [void](Invoke-DockerCapture -ArgumentList @('compose', 'up', '-d') `
            -FailureMessage 'Wazuh Stack could not be started.')
    }

    $runningServices = @(Invoke-DockerCapture -ArgumentList @(
        'compose', 'ps', '--services', '--status', 'running'
    ))
    $missingServices = @($expectedServices | Where-Object {
        $_ -notin $runningServices
    })
    Assert-Condition -Condition ($missingServices.Count -eq 0) `
        -Message (
            'Wazuh services are not all running: ' +
            ($missingServices -join ', ') +
            '. Re-run with -StartStack.'
        )
    Write-Host "[PASS] Wazuh services: $($expectedServices -join ', ')"

    $indexerReady = $false
    $lastIndexerError = ''
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $health = Invoke-IndexerGet `
                -Path '_cluster/health?wait_for_status=yellow&timeout=1s'
            if ($health.status -in @('yellow', 'green')) {
                $indexerReady = $true
                break
            }
            $lastIndexerError = "status=$($health.status)"
        } catch {
            $lastIndexerError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }
    Assert-Condition -Condition $indexerReady `
        -Message "Wazuh Indexer was not ready within 60 seconds. $lastIndexerError"
    Write-Host "[PASS] Wazuh Indexer API ready: $($health.status)"

    $savedObjectResult = Invoke-IndexerGet `
        -Path '.kibana_1/_search?size=1000&seq_no_primary_term=true'
    $documents = @($savedObjectResult.hits.hits)

    foreach ($title in $expectedDashboardTitles) {
        [void](Get-SavedObject -Documents $documents -Type 'dashboard' -Title $title)
    }
    foreach ($title in $expectedVisualizationTitles) {
        [void](Get-SavedObject -Documents $documents -Type 'visualization' -Title $title)
    }
    foreach ($title in $expectedSearchTitles) {
        [void](Get-SavedObject -Documents $documents -Type 'search' -Title $title)
    }
    Write-Host '[PASS] AWS-SOC Saved Objects: dashboards=2, visualizations=14, searches=2'

    foreach ($title in $expectedDashboardTitles) {
        $dashboardDocument = Get-SavedObject `
            -Documents $documents `
            -Type 'dashboard' `
            -Title $title
        $dashboard = $dashboardDocument._source.dashboard
        $panels = @($dashboard.panelsJSON | ConvertFrom-Json)
        Assert-Condition -Condition ([bool]$dashboard.timeRestore) `
            -Message "Dashboard does not restore its time range: $title"
        Assert-Condition -Condition (
            $dashboard.timeFrom -eq 'now-15m' -and $dashboard.timeTo -eq 'now'
        ) -Message "Dashboard live-demo time range changed: $title"
        Write-Host "[PASS] $title : panels=$($panels.Count), saved time=Last 15 minutes"
    }

    foreach ($title in $expectedSearchTitles) {
        $searchDocument = Get-SavedObject `
            -Documents $documents `
            -Type 'search' `
            -Title $title
        $search = $searchDocument._source.search
        $actualColumns = @($search.columns)
        Assert-Condition -Condition (
            ($actualColumns -join "`n") -ceq ($expectedSearchColumns -join "`n")
        ) -Message "Saved Search columns changed: $title"
        $sortJson = ConvertTo-Json -InputObject $search.sort -Depth 10 -Compress
        Assert-Condition -Condition ($sortJson -ceq '[["timestamp","desc"]]') `
            -Message "Saved Search sort changed: $title ($sortJson)"
        $searchSource = $search.kibanaSavedObjectMeta.searchSourceJSON |
            ConvertFrom-Json -DateKind String
        Assert-Condition -Condition (@($searchSource.filter).Count -eq 0) `
            -Message "Saved Search has unexpected Exists filters: $title"
    }
    Write-Host '[PASS] Saved Search columns, newest-first sort, and zero Exists filters'

    $albDocument = Get-SavedObject `
        -Documents $documents `
        -Type 'visualization' `
        -Title '[AWS-SOC] 11 ALB 응답 상태'
    $albVisualization = $albDocument._source.visualization.visState |
        ConvertFrom-Json -DateKind String
    $albTerms = @($albVisualization.aggs | Where-Object {
        $_.type -eq 'terms'
    }) | Select-Object -First 1
    Assert-Condition -Condition (
        $albTerms.params.orderBy -eq '_key' -and $albTerms.params.order -eq 'asc'
    ) -Message 'ALB response status ordering is not key ascending.'
    Write-Host '[PASS] ALB response status ordering: code ascending'

    $counts = [ordered]@{
        'Edge 요청' = Get-EventCount -Index 'wazuh-archives-*' -Query @{
            term = @{ 'data.cs-uri-stem' = '/vulnerabilities/exec/' }
        }
        'WAF 검사' = Get-EventCount -Index 'wazuh-archives-*' -Query @{
            term = @{ 'data.httpRequest.uri' = '/vulnerabilities/exec/' }
        }
        'ALB 전달' = Get-EventCount -Index 'wazuh-archives-*' -Query @{
            wildcard = @{ 'data.aws.request' = @{ value = '*vulnerabilities/exec/*' } }
        }
        'Workload 실행' = Get-EventCount -Index 'wazuh-archives-*' -Query @{
            bool = @{ filter = @(
                @{ term = @{ 'data.app_event.event_type' = 'command.execution' } },
                @{ term = @{ 'data.app_event.context.resource' = 'ec2_imds' } }
            ) }
        }
        'AWS 데이터 접근' = Get-EventCount -Index 'wazuh-archives-*' -Query @{
            bool = @{ filter = @(
                @{ term = @{ 'data.aws.source' = 'cloudtrail' } },
                @{ term = @{ 'data.aws.eventName' = 'GetObject' } },
                @{ term = @{ 'data.aws.requestParameters.key' = 'validation/capital-one-demo.csv' } }
            ) }
        }
        'Rule 100100' = Get-EventCount -Index 'wazuh-alerts-*' -Query @{
            term = @{ 'rule.id' = '100100' }
        }
    }
    foreach ($entry in $counts.GetEnumerator()) {
        Assert-Condition -Condition ($entry.Value -gt 0) `
            -Message "Mini-drill evidence is missing: $($entry.Key)"
        Write-Host "[PASS] $($entry.Key): $($entry.Value) retained event(s)"
    }

    if ($BackupPath) {
        $selectedDocuments = @($documents | Where-Object {
            $type = [string]$_. _source.type
            if ($type -notin @('dashboard', 'visualization', 'search')) {
                return $false
            }
            $title = [string]$_. _source.$type.title
            return (
                ($type -eq 'dashboard' -and $title -in $expectedDashboardTitles) -or
                ($type -eq 'visualization' -and $title -in $expectedVisualizationTitles) -or
                ($type -eq 'search' -and $title -in $expectedSearchTitles)
            )
        })
        $referenceIds = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($document in $selectedDocuments) {
            foreach ($reference in @($document._source.references)) {
                [void]$referenceIds.Add("$($reference.type):$($reference.id)")
            }
        }
        $dependencyDocuments = @($documents | Where-Object {
            $referenceIds.Contains([string]$_. _id)
        })
        $backupDocuments = @($selectedDocuments + $dependencyDocuments |
            Sort-Object -Property _id -Unique)
        $lines = foreach ($document in $backupDocuments) {
            [ordered]@{
                format       = 'wazuh-kibana-raw-backup-v1'
                index        = '.kibana_1'
                id           = [string]$document._id
                seq_no       = $document._seq_no
                primary_term = $document._primary_term
                source       = $document._source
            } | ConvertTo-Json -Depth 100 -Compress
        }
        $backupText = ($lines -join "`n") + "`n"
        foreach ($pattern in @(
            'AKIA[0-9A-Z]{16}',
            'ASIA[0-9A-Z]{16}',
            'aws_secret_access_key',
            'aws_session_token'
        )) {
            Assert-Condition -Condition ($backupText -notmatch $pattern) `
                -Message "Credential-like material matched backup guard: $pattern"
        }
        $backupDirectory = Split-Path -Parent $BackupPath
        if ($backupDirectory) {
            [void](New-Item -ItemType Directory -Force -Path $backupDirectory)
        }
        Set-Content -LiteralPath $BackupPath -Value $backupText -Encoding utf8NoBOM -NoNewline
        $hash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$BackupPath.sha256" `
            -Value "$hash  $(Split-Path -Leaf $BackupPath)`n" `
            -Encoding ascii `
            -NoNewline
        Write-Host "[PASS] Raw recovery backup: $BackupPath"
        Write-Host "[PASS] Backup SHA-256: $hash"
    }

    Write-Host ''
    Write-Host 'WAZUH_MINI_DRILL_READY=yes'
    Write-Host 'Tomorrow: open each dashboard and change its saved Last 15 minutes to Last 7 days.'
    Write-Host 'Boundary: the retained five-source records were collected across multiple lab runs.'
} finally {
    Pop-Location
}
