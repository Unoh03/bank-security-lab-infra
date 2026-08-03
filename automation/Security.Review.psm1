Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-SecurityReviewUtf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-SecurityReviewValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string[]]$Names,
        [AllowNull()]$Default = ''
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    return $Default
}

function Protect-SecurityReviewScalar {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return ''
    }
    $text = ([string]$Value).Replace("`0", '').Replace("`r", ' ').Replace("`n", ' ')
    $text = [regex]::Replace(
        $text,
        '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+',
        'Bearer [REDACTED]'
    )
    $text = [regex]::Replace(
        $text,
        '(?i)\b(password|passwd|secret|token|cookie|authorization|session[_-]?id|access[_-]?key)(\s*[=:]\s*)([^,\s;"''}]+)',
        '$1$2[REDACTED]'
    )
    $text = [regex]::Replace(
        $text,
        '(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s?"]+)\?[^\s"]+',
        '$1 $2?[REDACTED_QUERY]'
    )
    $text = [regex]::Replace($text, '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED_AWS_KEY_ID]')
    if ($text.Length -gt 600) {
        return $text.Substring(0, 600) + '...[TRUNCATED]'
    }
    return $text
}

function ConvertTo-SecurityReviewTime {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or -not [string]$Value) {
        return $null
    }
    $parsed = [datetimeoffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetimeoffset]::TryParse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed
    )) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function ConvertTo-SecurityReviewRoute {
    param([AllowNull()]$Value)

    $route = Protect-SecurityReviewScalar -Value $Value
    if (-not $route) {
        return ''
    }
    $uri = $null
    if ([uri]::TryCreate($route, [UriKind]::Absolute, [ref]$uri)) {
        return [string]$uri.AbsolutePath
    }
    return ($route -split '\?', 2)[0]
}

function New-SecurityReviewEvent {
    param(
        [Parameter(Mandatory)][string]$Source,
        [AllowNull()]$Timestamp,
        [string]$Event = '',
        [string]$Result = '',
        [string]$SourceIp = '',
        [string]$User = '',
        [string]$Route = '',
        [string]$RequestId = '',
        [string]$TraceId = '',
        [string]$Detail = ''
    )

    $time = ConvertTo-SecurityReviewTime -Value $Timestamp
    $correlationId = if ($TraceId) { $TraceId } else { $RequestId }
    return [pscustomobject][ordered]@{
        TimestampUtc = $time
        TimestampKst = if ($time) { $time.ToOffset([timespan]::FromHours(9)) } else { $null }
        Source = Protect-SecurityReviewScalar -Value $Source
        Event = Protect-SecurityReviewScalar -Value $Event
        Result = Protect-SecurityReviewScalar -Value $Result
        SourceIp = Protect-SecurityReviewScalar -Value $SourceIp
        User = Protect-SecurityReviewScalar -Value $User
        Route = ConvertTo-SecurityReviewRoute -Value $Route
        RequestId = Protect-SecurityReviewScalar -Value $RequestId
        TraceId = Protect-SecurityReviewScalar -Value $TraceId
        CorrelationId = Protect-SecurityReviewScalar -Value $correlationId
        Confidence = 'uncorrelated'
        Detail = Protect-SecurityReviewScalar -Value $Detail
    }
}

function Read-SecurityReviewCloudWatchRows {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    $document = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    return @(Get-SecurityReviewValue -InputObject $document -Names @('Rows') -Default @())
}

function ConvertFrom-SecurityReviewCloudWatch {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][ValidateSet('Application', 'WAF', 'Kubernetes', 'CloudTrail')]
        [string]$Normalizer
    )

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($row in @(Read-SecurityReviewCloudWatchRows -Path $Path)) {
        $time = Get-SecurityReviewValue $row @('event_time', '@timestamp')
        switch ($Normalizer) {
            'Application' {
                $requestId = [string](Get-SecurityReviewValue $row @('request_id'))
                $traceId = if ($requestId -match '^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$') {
                    $requestId
                } else {
                    ''
                }
                $events.Add((New-SecurityReviewEvent `
                    -Source $Source `
                    -Timestamp $time `
                    -Event ([string](Get-SecurityReviewValue $row @('event_name'))) `
                    -Result ([string](Get-SecurityReviewValue $row @('result'))) `
                    -SourceIp ([string](Get-SecurityReviewValue $row @('source_ip'))) `
                    -User ([string](Get-SecurityReviewValue $row @('user_id'))) `
                    -Route ([string](Get-SecurityReviewValue $row @('route'))) `
                    -RequestId $requestId `
                    -TraceId $traceId `
                    -Detail ([string](Get-SecurityReviewValue $row @('detail')))))
            }
            'WAF' {
                $rule = [string](Get-SecurityReviewValue $row @('event_name'))
                if (-not $rule) { $rule = 'waf.request' }
                $method = [string](Get-SecurityReviewValue $row @('method'))
                $events.Add((New-SecurityReviewEvent `
                    -Source $Source `
                    -Timestamp $time `
                    -Event "$method $rule".Trim() `
                    -Result ([string](Get-SecurityReviewValue $row @('result'))) `
                    -SourceIp ([string](Get-SecurityReviewValue $row @('source_ip'))) `
                    -Route ([string](Get-SecurityReviewValue $row @('route')))))
            }
            'Kubernetes' {
                $verb = [string](Get-SecurityReviewValue $row @('verb'))
                $resource = [string](Get-SecurityReviewValue $row @('objectRef.resource'))
                $subresource = [string](Get-SecurityReviewValue $row @('objectRef.subresource'))
                $namespace = [string](Get-SecurityReviewValue $row @('objectRef.namespace'))
                $name = [string](Get-SecurityReviewValue $row @('objectRef.name'))
                $resourcePath = @($namespace, $resource, $subresource, $name) |
                    Where-Object { $_ }
                $events.Add((New-SecurityReviewEvent `
                    -Source $Source `
                    -Timestamp $time `
                    -Event ((@($verb, $resource, $subresource) | Where-Object { $_ }) -join ' ') `
                    -Result ([string](Get-SecurityReviewValue $row @('responseStatus.code'))) `
                    -SourceIp ([string](Get-SecurityReviewValue $row @('sourceIPs.0'))) `
                    -User ([string](Get-SecurityReviewValue $row @('user.username'))) `
                    -Route ($resourcePath -join '/')))
            }
            'CloudTrail' {
                $events.Add((New-SecurityReviewEvent `
                    -Source $Source `
                    -Timestamp $time `
                    -Event ([string](Get-SecurityReviewValue $row @('event_name', 'eventName'))) `
                    -Result ([string](Get-SecurityReviewValue $row @('result', 'errorCode') -Default 'Success')) `
                    -SourceIp ([string](Get-SecurityReviewValue $row @('source_ip', 'sourceIPAddress'))) `
                    -User ([string](Get-SecurityReviewValue $row @('user_id', 'userIdentity.arn'))) `
                    -RequestId ([string](Get-SecurityReviewValue $row @('request_id', 'requestID'))) `
                    -Detail ([string](Get-SecurityReviewValue $row @('detail', 'eventSource')))))
            }
        }
    }
    return $events.ToArray()
}

function Read-SecurityReviewAthenaRows {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    $document = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $resultSet = Get-SecurityReviewValue $document @('ResultSet') $null
    $rows = @(Get-SecurityReviewValue $resultSet @('Rows') @())
    if ($rows.Count -lt 2) {
        return @()
    }
    $headers = @($rows[0].Data | ForEach-Object {
        [string](Get-SecurityReviewValue $_ @('VarCharValue'))
    })
    $result = New-Object System.Collections.Generic.List[object]
    for ($rowIndex = 1; $rowIndex -lt $rows.Count; $rowIndex++) {
        $record = [ordered]@{}
        $cells = @($rows[$rowIndex].Data)
        for ($columnIndex = 0; $columnIndex -lt $headers.Count; $columnIndex++) {
            $value = if ($columnIndex -lt $cells.Count) {
                [string](Get-SecurityReviewValue $cells[$columnIndex] @('VarCharValue'))
            } else {
                ''
            }
            $record[$headers[$columnIndex]] = $value
        }
        $result.Add([pscustomobject]$record)
    }
    return $result.ToArray()
}

function ConvertFrom-SecurityReviewAthena {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('CloudFront', 'ALB')][string]$Normalizer
    )

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($row in @(Read-SecurityReviewAthenaRows -Path $Path)) {
        if ($Normalizer -ceq 'CloudFront') {
            $eventTime = "$(Get-SecurityReviewValue $row @('date'))T$(Get-SecurityReviewValue $row @('time'))Z"
            $method = [string](Get-SecurityReviewValue $row @('method'))
            $route = [string](Get-SecurityReviewValue $row @('path'))
            $events.Add((New-SecurityReviewEvent `
                -Source 'CloudFront' `
                -Timestamp $eventTime `
                -Event "$method $route".Trim() `
                -Result ([string](Get-SecurityReviewValue $row @('status'))) `
                -SourceIp ([string](Get-SecurityReviewValue $row @('source_ip'))) `
                -Route $route `
                -RequestId ([string](Get-SecurityReviewValue $row @('edge_request_id')))))
        } else {
            $method = [string](Get-SecurityReviewValue $row @('method'))
            $route = [string](Get-SecurityReviewValue $row @('route'))
            $elbStatus = [string](Get-SecurityReviewValue $row @('elb_status_code'))
            $targetStatus = [string](Get-SecurityReviewValue $row @('target_status_code'))
            $traceId = [string](Get-SecurityReviewValue $row @('trace_id'))
            $events.Add((New-SecurityReviewEvent `
                -Source 'ALB' `
                -Timestamp (Get-SecurityReviewValue $row @('event_time')) `
                -Event "$method $route".Trim() `
                -Result "elb=$elbStatus target=$targetStatus" `
                -SourceIp ([string](Get-SecurityReviewValue $row @('source_ip'))) `
                -Route $route `
                -RequestId $traceId `
                -TraceId $traceId))
        }
    }
    return $events.ToArray()
}

function Select-SecurityReviewEvents {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [string]$SourceIp = ''
    )

    if (-not $SourceIp) {
        return @($Events)
    }
    $matching = @($Events | Where-Object { [string]$_.SourceIp -ceq $SourceIp })
    $identifiers = @($matching | ForEach-Object { [string]$_.CorrelationId } |
        Where-Object { $_ } | Sort-Object -Unique)
    return @($Events | Where-Object {
        [string]$_.SourceIp -ceq $SourceIp -or
        ([string]$_.CorrelationId -and [string]$_.CorrelationId -in $identifiers)
    })
}

function Set-SecurityReviewCorrelation {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events)

    $idGroups = @($Events | Where-Object { [string]$_.CorrelationId } |
        Group-Object CorrelationId)
    foreach ($group in $idGroups) {
        $sources = @($group.Group.Source | Sort-Object -Unique)
        if ($sources.Count -gt 1) {
            foreach ($event in $group.Group) {
                $event.Confidence = 'exact'
            }
        }
    }

    $routeGroups = @($Events | Where-Object {
        $_.Confidence -cne 'exact' -and $_.TimestampUtc -and $_.SourceIp -and $_.Route
    } | Group-Object { "$($_.SourceIp)|$($_.Route)" })
    foreach ($group in $routeGroups) {
        $items = @($group.Group | Sort-Object TimestampUtc)
        if (@($items.Source | Sort-Object -Unique).Count -lt 2) {
            continue
        }
        for ($index = 0; $index -lt $items.Count; $index++) {
            for ($otherIndex = $index + 1; $otherIndex -lt $items.Count; $otherIndex++) {
                if ($items[$index].Source -ceq $items[$otherIndex].Source) {
                    continue
                }
                $seconds = [math]::Abs((
                    $items[$otherIndex].TimestampUtc - $items[$index].TimestampUtc
                ).TotalSeconds)
                if ($seconds -le 2) {
                    if ($items[$index].Confidence -cne 'exact') {
                        $items[$index].Confidence = 'strong_inference'
                    }
                    if ($items[$otherIndex].Confidence -cne 'exact') {
                        $items[$otherIndex].Confidence = 'strong_inference'
                    }
                }
            }
        }
    }
    foreach ($event in $Events) {
        if ($event.Confidence -ceq 'uncorrelated' -and $event.SourceIp) {
            $event.Confidence = 'time_window_association'
        }
    }
}

function Get-SecurityReviewCandidateReasons {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events)

    $reasons = New-Object System.Collections.Generic.List[string]
    $severity = 'informational'
    $loginFailures = @($Events | Where-Object {
        $_.Event -ceq 'auth.login.failed'
    }).Count
    if ($loginFailures -ge 5) {
        $reasons.Add("반복 로그인 실패 ${loginFailures}건: 계정 공격 또는 사용자 오류 확인 필요")
        $severity = 'medium'
    }
    $wafBlocks = @($Events | Where-Object {
        $_.Source -ceq 'WAF' -and $_.Result -ceq 'BLOCK'
    }).Count
    if ($wafBlocks -gt 0) {
        $reasons.Add("WAF BLOCK ${wafBlocks}건: 차단 Rule과 원 요청 확인 필요")
        $severity = 'medium'
    }
    $execEvents = @($Events | Where-Object {
        $_.Source -ceq 'Kubernetes' -and $_.Event -match '(?i)pods?\s+exec|exec'
    }).Count
    if ($execEvents -gt 0) {
        $reasons.Add("Kubernetes Pod exec ${execEvents}건: 승인된 운영 활동인지 확인 필요")
        $severity = 'medium'
    }
    $secretEvents = @($Events | Where-Object {
        $_.Source -ceq 'Kubernetes' -and $_.Event -match '(?i)secrets?'
    }).Count
    if ($secretEvents -gt 0) {
        $reasons.Add("Kubernetes Secret 접근 ${secretEvents}건: Actor와 권한 필요성 확인 필요")
        $severity = 'medium'
    }
    $controlChanges = @($Events | Where-Object {
        $_.Source -ceq 'CloudTrail' -and $_.Event -match '(?i)CreateAccessKey|UpdateAssumeRolePolicy|AuthorizeSecurityGroupIngress|AttachRolePolicy|PutRolePolicy'
    }).Count
    if ($controlChanges -gt 0) {
        $reasons.Add("AWS 보안 설정 변경 ${controlChanges}건: Terraform Baseline 또는 비인가 변경인지 확인 필요")
        $severity = 'medium'
    }
    if ($reasons.Count -eq 0) {
        $reasons.Add('자동 승격 조건 없음: 정상 활동 여부를 시간창과 담당자 맥락으로 확인')
    }
    return [pscustomobject]@{
        SuggestedSeverity = $severity
        Reasons = $reasons.ToArray()
    }
}

function ConvertTo-SecurityReviewMarkdownCell {
    param([AllowNull()]$Value)

    return (Protect-SecurityReviewScalar -Value $Value).Replace('|', '\|')
}

function Update-SecurityReviewBundleIndex {
    param(
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][hashtable]$ReviewMetadata,
        [ValidateSet('SHA256', 'SHA384', 'SHA512')][string]$Algorithm = 'SHA256'
    )

    $manifestPath = Join-Path $BundleRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Evidence manifest is unavailable: $manifestPath"
    }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $excluded = @('manifest.json', 'manifest.json.sha256', 'manifest.json.sha384', 'manifest.json.sha512', 'SHA256SUMS.txt', 'SHA384SUMS.txt', 'SHA512SUMS.txt')
    $files = @(Get-ChildItem -LiteralPath $BundleRoot -Recurse -File | Where-Object {
        $_.Name -notin $excluded
    } | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            Path = $_.FullName.Substring($BundleRoot.Length).TrimStart('\', '/') -replace '\\', '/'
            Length = [long]$_.Length
            Algorithm = $Algorithm
            Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm $Algorithm).Hash
        }
    })
    $manifest.Files = $files
    $manifest | Add-Member -Force -NotePropertyName Review -NotePropertyValue $ReviewMetadata
    Write-SecurityReviewUtf8NoBom -Path $manifestPath -Content (
        $manifest | ConvertTo-Json -Depth 100
    )
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm $Algorithm).Hash.ToLowerInvariant()
    $manifestHashPath = "$manifestPath.$($Algorithm.ToLowerInvariant())"
    Write-SecurityReviewUtf8NoBom `
        -Path $manifestHashPath `
        -Content "$manifestHash  manifest.json`n"

    $sumName = "$($Algorithm.ToUpperInvariant())SUMS.txt"
    $sumLines = @(Get-ChildItem -LiteralPath $BundleRoot -Recurse -File | Where-Object {
        $_.Name -ne $sumName
    } | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($BundleRoot.Length).TrimStart('\', '/') -replace '\\', '/'
        "$((Get-FileHash -LiteralPath $_.FullName -Algorithm $Algorithm).Hash)  $relative"
    })
    Write-SecurityReviewUtf8NoBom `
        -Path (Join-Path $BundleRoot $sumName) `
        -Content (($sumLines -join "`n") + "`n")
}

function Export-SecurityReview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$ReviewConfig,
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][datetime]$StartTimeUtc,
        [Parameter(Mandatory)][datetime]$EndTimeUtc,
        [string]$SourceIp = '',
        [string]$Label = 'security-window',
        [ValidateSet('SHA256', 'SHA384', 'SHA512')][string]$HashAlgorithm = 'SHA256'
    )

    $events = New-Object System.Collections.Generic.List[object]
    $missingSources = New-Object System.Collections.Generic.List[string]
    foreach ($source in @($ReviewConfig.CloudWatchSources)) {
        $path = Join-Path $BundleRoot (
            "results\cloudwatch\$([string]$source.QueryName).json"
        )
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $missingSources.Add([string]$source.Name)
            continue
        }
        foreach ($event in @(ConvertFrom-SecurityReviewCloudWatch `
            -Path $path `
            -Source ([string]$source.Name) `
            -Normalizer ([string]$source.Normalizer))) {
            $events.Add($event)
        }
    }

    $cloudFrontPath = Join-Path $BundleRoot 'results\athena\cloudfront-trace-results.json'
    if (Test-Path -LiteralPath $cloudFrontPath -PathType Leaf) {
        foreach ($event in @(ConvertFrom-SecurityReviewAthena -Path $cloudFrontPath -Normalizer CloudFront)) {
            $events.Add($event)
        }
    } else {
        $missingSources.Add('CloudFront')
    }
    $albPath = Join-Path $BundleRoot 'results\athena\alb-window-results.json'
    if (Test-Path -LiteralPath $albPath -PathType Leaf) {
        foreach ($event in @(ConvertFrom-SecurityReviewAthena -Path $albPath -Normalizer ALB)) {
            $events.Add($event)
        }
    } else {
        $missingSources.Add('ALB')
    }

    $selectedEvents = @(Select-SecurityReviewEvents -Events $events.ToArray() -SourceIp $SourceIp)
    Set-SecurityReviewCorrelation -Events $selectedEvents
    $selectedEvents = @($selectedEvents | Sort-Object @{ Expression = {
        if ($_.TimestampUtc) { $_.TimestampUtc } else { [datetimeoffset]::MaxValue }
    } }, Source, Event)

    $candidate = Get-SecurityReviewCandidateReasons -Events $selectedEvents
    $safeLabel = [regex]::Replace($Label.ToLowerInvariant(), '[^a-z0-9._-]', '-')
    $safeLabel = $safeLabel.Trim('-')
    if (-not $safeLabel) { $safeLabel = 'security-window' }
    $incidentId = 'SOC-' + $StartTimeUtc.ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + $safeLabel
    $sourceCounts = @($selectedEvents | Group-Object Source | Sort-Object Name | ForEach-Object {
        [ordered]@{ Source = $_.Name; Events = $_.Count }
    })
    $confidenceCounts = @($selectedEvents | Group-Object Confidence | Sort-Object Name | ForEach-Object {
        [ordered]@{ Confidence = $_.Name; Events = $_.Count }
    })

    $reviewRoot = Join-Path $BundleRoot 'review'
    New-Item -ItemType Directory -Force -Path $reviewRoot | Out-Null
    $timelinePath = Join-Path $reviewRoot 'timeline.csv'
    $csvRows = @($selectedEvents | ForEach-Object {
        [pscustomobject][ordered]@{
            TimestampKst = if ($_.TimestampKst) { $_.TimestampKst.ToString('yyyy-MM-dd HH:mm:ss.fff zzz') } else { '' }
            TimestampUtc = if ($_.TimestampUtc) { $_.TimestampUtc.ToString('o') } else { '' }
            Source = $_.Source
            Event = $_.Event
            Result = $_.Result
            SourceIp = $_.SourceIp
            User = $_.User
            Route = $_.Route
            RequestId = $_.RequestId
            TraceId = $_.TraceId
            Confidence = $_.Confidence
            Detail = $_.Detail
        }
    })
    $csvText = if ($csvRows.Count -gt 0) {
        (@($csvRows | ConvertTo-Csv -NoTypeInformation) -join "`n") + "`n"
    } else {
        'TimestampKst,TimestampUtc,Source,Event,Result,SourceIp,User,Route,RequestId,TraceId,Confidence,Detail' + "`n"
    }
    Write-SecurityReviewUtf8NoBom -Path $timelinePath -Content $csvText

    $triage = [ordered]@{
        SchemaVersion = 1
        IncidentId = $incidentId
        Title = "Security review: $safeLabel"
        Status = 'Open'
        Verdict = 'NeedsAnalystReview'
        SuggestedSeverity = $candidate.SuggestedSeverity
        Window = [ordered]@{
            StartTimeUtc = $StartTimeUtc.ToUniversalTime().ToString('o')
            EndTimeUtc = $EndTimeUtc.ToUniversalTime().ToString('o')
            StartTimeKst = ([datetimeoffset]$StartTimeUtc).ToOffset([timespan]::FromHours(9)).ToString('o')
            EndTimeKst = ([datetimeoffset]$EndTimeUtc).ToOffset([timespan]::FromHours(9)).ToString('o')
        }
        Filter = [ordered]@{ SourceIp = $SourceIp }
        EventCount = $selectedEvents.Count
        SourceCounts = $sourceCounts
        ConfidenceCounts = $confidenceCounts
        CandidateReasons = $candidate.Reasons
        MissingSources = @($missingSources | Sort-Object -Unique)
        AnalystDecision = [ordered]@{
            ExpectedActivity = $null
            FinalVerdict = ''
            Escalation = ''
            Containment = ''
            Notes = ''
        }
    }
    $triagePath = Join-Path $reviewRoot 'triage.json'
    Write-SecurityReviewUtf8NoBom -Path $triagePath -Content (
        $triage | ConvertTo-Json -Depth 30
    )

    $summaryLines = New-Object System.Collections.Generic.List[string]
    $summaryLines.Add("# Security Window Review — $incidentId")
    $summaryLines.Add('')
    $summaryLines.Add('> 자동 분류는 조사 시작점이며 정탐·오탐 판정이 아니다. 원본 Evidence와 운영자 맥락을 함께 확인한다.')
    $summaryLines.Add('')
    $summaryLines.Add('## Triage')
    $summaryLines.Add('')
    $summaryLines.Add('- Status: `Open`')
    $summaryLines.Add('- Verdict: `NeedsAnalystReview`')
    $summaryLines.Add(('- Suggested severity: `{0}`' -f $candidate.SuggestedSeverity))
    $startKstText = ([datetimeoffset]$StartTimeUtc).ToOffset([timespan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss')
    $endKstText = ([datetimeoffset]$EndTimeUtc).ToOffset([timespan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss')
    $summaryLines.Add(('- KST window: `{0}` ~ `{1}`' -f $startKstText, $endKstText))
    $sourceIpText = if ($SourceIp) { $SourceIp } else { 'none' }
    $summaryLines.Add(('- Source IP filter: `{0}`' -f $sourceIpText))
    $summaryLines.Add(('- Timeline events: `{0}`' -f $selectedEvents.Count))
    $summaryLines.Add('')
    $summaryLines.Add('## 자동 검토 후보')
    $summaryLines.Add('')
    foreach ($reason in @($candidate.Reasons)) {
        $summaryLines.Add("- $(ConvertTo-SecurityReviewMarkdownCell $reason)")
    }
    $summaryLines.Add('')
    $summaryLines.Add('## Source coverage')
    $summaryLines.Add('')
    $summaryLines.Add('| Source | Events |')
    $summaryLines.Add('|---|---:|')
    foreach ($count in $sourceCounts) {
        $summaryLines.Add("| $(ConvertTo-SecurityReviewMarkdownCell $count.Source) | $($count.Events) |")
    }
    foreach ($missing in @($missingSources | Sort-Object -Unique)) {
        $summaryLines.Add("| $(ConvertTo-SecurityReviewMarkdownCell $missing) | missing |")
    }
    $summaryLines.Add('')
    $summaryLines.Add('## Timeline preview')
    $summaryLines.Add('')
    $summaryLines.Add('| KST | Source | Event | Result | Source IP | Route | Confidence |')
    $summaryLines.Add('|---|---|---|---|---|---|---|')
    foreach ($event in @($selectedEvents | Select-Object -First 50)) {
        $kst = if ($event.TimestampKst) { $event.TimestampKst.ToString('HH:mm:ss.fff') } else { '-' }
        $summaryLines.Add("| $kst | $(ConvertTo-SecurityReviewMarkdownCell $event.Source) | $(ConvertTo-SecurityReviewMarkdownCell $event.Event) | $(ConvertTo-SecurityReviewMarkdownCell $event.Result) | $(ConvertTo-SecurityReviewMarkdownCell $event.SourceIp) | $(ConvertTo-SecurityReviewMarkdownCell $event.Route) | $($event.Confidence) |")
    }
    $summaryLines.Add('')
    $summaryLines.Add('## Analyst decision')
    $summaryLines.Add('')
    $summaryLines.Add('- [ ] 이 활동은 예정되거나 승인된 활동인가?')
    $summaryLines.Add('- [ ] 정탐·오탐·정상·판단 보류 중 무엇인가?')
    $summaryLines.Add('- [ ] 영향 자산과 사용자 범위가 확인됐는가?')
    $summaryLines.Add('- [ ] 상위 분석가 또는 운영팀 이관이 필요한가?')
    $summaryLines.Add('- [ ] 조치 후 동일 조건 재검증 결과가 남았는가?')
    $summaryLines.Add('')
    $summaryLines.Add('## Correlation confidence')
    $summaryLines.Add('')
    $summaryLines.Add('- `exact`: 동일 `request_id` 또는 `trace_id`가 둘 이상의 Source에서 확인됨')
    $summaryLines.Add('- `strong_inference`: 동일 Source IP·Route가 2초 안에 둘 이상의 Source에서 확인됨')
    $summaryLines.Add('- `time_window_association`: 같은 시간창 또는 Source IP만 일치함')
    $summaryLines.Add('- `uncorrelated`: 다른 Source와 연결할 식별자가 없음')
    $summaryPath = Join-Path $reviewRoot 'summary.md'
    Write-SecurityReviewUtf8NoBom -Path $summaryPath -Content (
        ($summaryLines -join "`n") + "`n"
    )

    $reviewMetadata = @{
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        IncidentId = $incidentId
        Verdict = 'NeedsAnalystReview'
        SuggestedSeverity = $candidate.SuggestedSeverity
        EventCount = $selectedEvents.Count
        MissingSources = @($missingSources | Sort-Object -Unique)
        Summary = 'review/summary.md'
        Timeline = 'review/timeline.csv'
        Triage = 'review/triage.json'
    }
    Update-SecurityReviewBundleIndex `
        -BundleRoot $BundleRoot `
        -ReviewMetadata $reviewMetadata `
        -Algorithm $HashAlgorithm

    return [pscustomobject]@{
        IncidentId = $incidentId
        EventCount = $selectedEvents.Count
        SummaryPath = $summaryPath
        TimelinePath = $timelinePath
        TriagePath = $triagePath
        MissingSources = @($missingSources | Sort-Object -Unique)
    }
}

Export-ModuleMember -Function @(
    'Export-SecurityReview',
    'Update-SecurityReviewBundleIndex'
)
