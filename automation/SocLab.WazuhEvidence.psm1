#requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:ExpectedAccountId = '433048100798'
$script:ExpectedRegion = 'ap-northeast-2'

function Invoke-SocWazuhIndexerSearch {
    param(
        [Parameter(Mandatory)][object]$Query,
        [Parameter(Mandatory)][string]$AdminPassword
    )

    if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
        throw 'The Wazuh indexer password is unavailable.'
    }
    $uri = [uri]'https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search'
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.ServerCertificateCustomValidationCallback = { $true }
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds(20)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,$uri)
    $authBytes = [Text.Encoding]::UTF8.GetBytes("admin:$AdminPassword")
    try {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Basic',[Convert]::ToBase64String($authBytes)
        )
        $request.Content = [Net.Http.StringContent]::new(
            ($Query | ConvertTo-Json -Depth 30 -Compress),
            [Text.Encoding]::UTF8,
            'application/json'
        )
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -ne 200) {
                throw 'The fixed Wazuh indexer search was rejected.'
            }
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($text.Length -gt 8388608) {
                throw 'The fixed Wazuh indexer response exceeded 8 MiB.'
            }
            try {
                return $text | ConvertFrom-Json -Depth 100
            } finally {
                $text = $null
            }
        } finally {
            $response.Dispose()
        }
    } catch {
        throw 'The fixed Wazuh indexer search failed.'
    } finally {
        [Array]::Clear($authBytes,0,$authBytes.Length)
        if ($request.Content) { $request.Content.Dispose() }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-SocWazuhRuleAlerts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('100102','100103')][string]$RuleId,
        [Parameter(Mandatory)][string]$AdminPassword,
        [ValidateRange(1,20)][int]$Size = 10
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern -and
        $TakeId -cnotmatch '^wazuh-push-[0-9]{8}T[0-9]{9}Z$') {
        throw 'The Wazuh query TAKE ID is invalid.'
    }
    $result = Invoke-SocWazuhIndexerSearch -AdminPassword $AdminPassword -Query ([ordered]@{
        size=$Size
        query=[ordered]@{bool=[ordered]@{filter=@(
            @{term=@{'rule.id'=$RuleId}},
            @{term=@{'data.payload.take_id'=$TakeId}}
        )}}
        sort=@(@{'@timestamp'=@{order='asc'}})
    })
    return @($result.hits.hits)
}

function ConvertTo-SocRule100103Evidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Hit,
        [Parameter(Mandatory)][string]$TakeId,
        [ValidateRange(1,10)][int]$ExpectedCount = 2
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern) {
        throw 'The Rule 100103 Evidence TAKE ID is invalid.'
    }
    if ($Hit.Count -ne $ExpectedCount) {
        throw "Rule 100103 requires exactly $ExpectedCount alerts for this check; observed $($Hit.Count)."
    }
    $records = [Collections.Generic.List[object]]::new()
    $eventIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $Hit) {
        $source = $item._source
        $data = $source.data
        $payload = $data.payload
        $context = $payload.context
        if ([string]$source.rule.id -cne '100103' -or
            [int]$source.rule.level -ne 10 -or
            [string]$data.source -cne 'dvwa' -or
            [string]$data.transport -cne 'push' -or
            [string]$data.aws_account_id -cne $script:ExpectedAccountId -or
            [string]$data.aws_region -cne $script:ExpectedRegion -or
            [bool]$payload.normalized -ne $true -or
            [string]$payload.take_id -cne $TakeId -or
            [string]$payload.event_type -cne 'command.execution' -or
            [string]$payload.result -cne 'succeeded' -or
            [string]$payload.route -cne '/vulnerabilities/exec/' -or
            [string]$context.action -cne 'shell_command' -or
            [string]$context.resource -cne 'ec2_imds' -or
            [string]$context.security_level -cne 'low') {
            throw 'A Rule 100103 alert violated the fixed source and detection contract.'
        }
        $eventId = [string]$data.event_id
        $alertId = [string]$source.id
        $rawHash = [string]$data.raw_message_sha256
        if ($eventId -notmatch '^cwl:433048100798:[\x21-\x7e]{20,480}$' -or
            $alertId -notmatch '^[0-9]+\.[0-9]+$' -or
            $rawHash -notmatch '^[a-f0-9]{64}$' -or
            -not $eventIds.Add($eventId)) {
            throw 'A Rule 100103 alert ID, event ID, hash, or uniqueness check failed.'
        }
        $eventTime = [datetimeoffset]::Parse([string]$data.event_time)
        $alertTime = [datetimeoffset]::Parse([string]$source.timestamp)
        $latency = [math]::Round(($alertTime - $eventTime).TotalSeconds,3)
        if ($latency -lt -5 -or $latency -gt 120) {
            throw 'A Rule 100103 source-to-alert latency exceeded the fixed low-latency window.'
        }
        $records.Add([pscustomobject][ordered]@{
            event_id            = $eventId
            wazuh_alert_id       = $alertId
            event_time_utc       = $eventTime.ToUniversalTime().ToString('o')
            alert_time_utc       = $alertTime.ToUniversalTime().ToString('o')
            latency_seconds      = $latency
            raw_message_sha256   = $rawHash
            event_type           = 'command.execution'
            result               = 'succeeded'
            route                = '/vulnerabilities/exec/'
            resource             = 'ec2_imds'
        })
    }
    return @($records)
}

function Wait-SocWazuhRule100103 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$AdminPassword,
        [ValidateRange(30,300)][int]$TimeoutSeconds = 120
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $hits = @(Get-SocWazuhRuleAlerts -TakeId $TakeId -RuleId 100103 -AdminPassword $AdminPassword)
        if ($hits.Count -eq 2) {
            return ConvertTo-SocRule100103Evidence -Hit $hits -TakeId $TakeId
        }
        if ($hits.Count -gt 2) {
            throw 'Rule 100103 produced more than two alerts for one TAKE.'
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw "Rule 100103 did not produce exactly two alerts in time; observed $($hits.Count)."
}

Export-ModuleMember -Function @(
    'Get-SocWazuhRuleAlerts',
    'ConvertTo-SocRule100103Evidence',
    'Wait-SocWazuhRule100103'
)
