[CmdletBinding()]
param(
    [string]$Profile = 'terra-user',
    [string]$Region = 'us-east-1',
    [string]$LogGroupIdentifier = 'arn:aws:logs:us-east-1:433048100798:log-group:aws-waf-logs-aws-topology-edge',
    [ValidateRange(1024,65535)][int]$Port = 8787,
    [ValidateRange(20,500)][int]$MaxEvents = 200,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'PowerShell 7 이상이 필요합니다.'
}

$aws = Get-Command aws -ErrorAction Stop
$utf8 = [Text.UTF8Encoding]::new($false)

$queue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$history = [Collections.Generic.List[object]]::new()
$stderr = [Collections.Generic.List[string]]::new()

$sequence = 0L
$startedAt = [DateTimeOffset]::Now
$exitReported = $false

function Mask-Ip([string]$ip) {
    if ($ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3]).xxx"
    }

    if ($ip -like '*:*') {
        $parts = @($ip -split ':' | Where-Object { $_ })

        if ($parts.Count -ge 3) {
            return (($parts[0..2] -join ':') + ':…')
        }

        return 'IPv6:…'
    }

    return 'masked'
}

function Decode-Arg([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) {
        return ''
    }

    try {
        return [Uri]::UnescapeDataString($value.Replace('+', ' '))
    }
    catch {
        return $value
    }
}

function Convert-WafEvent(
    $log,
    [DateTimeOffset]$received
) {
    if ($null -eq $log.timestamp) {
        return $null
    }

    $rule = ''
    $groupName = ''
    $innerAction = ''
    $signals = [Collections.Generic.List[string]]::new()

    foreach ($group in @($log.ruleGroupList)) {
        if ($null -eq $group) {
            continue
        }

        if ($group.ruleGroupId) {
            $groupName = [string]$group.ruleGroupId
        }

        if (
            $null -ne $group.terminatingRule -and
            $group.terminatingRule.ruleId
        ) {
            $rule = [string]$group.terminatingRule.ruleId
            $innerAction = [string]$group.terminatingRule.action
            break
        }
    }

    $outer = @($log.nonTerminatingMatchingRules)

    foreach ($match in $outer) {
        if ($null -eq $match) {
            continue
        }

        if (-not $rule -and $match.ruleId) {
            $rule = [string]$match.ruleId
        }

        foreach ($detail in @($match.ruleMatchDetails)) {
            if ($null -ne $detail -and $detail.conditionType) {
                $signals.Add([string]$detail.conditionType)
            }
        }
    }

    if (-not $rule) {
        $rule = [string]$log.terminatingRuleId
    }

    if ($groupName -like '*#*') {
        $groupName = ($groupName -split '#')[-1]
    }

    $labels = @(
        $log.labels |
        ForEach-Object { $_.name }
    )

    $classificationText = (
        @($rule, $groupName) +
        $labels +
        $signals
    ) -join ' '

    $type = if ($classificationText -match '(?i)XSS|CrossSiteScripting') {
        'XSS'
    }
    elseif ($classificationText -match '(?i)SQLI|SQL_INJECTION|SQLInjection') {
        'SQLi'
    }
    else {
        'OTHER'
    }

    $finalAction = ([string]$log.action).ToUpperInvariant()

    $counted = @(
        $outer |
        Where-Object {
            ([string]$_.action).ToUpperInvariant() -eq 'COUNT'
        }
    ).Count -gt 0

    $evaluation = if ($counted) {
        'COUNT'
    }
    elseif ($finalAction -eq 'BLOCK') {
        'BLOCK'
    }
    elseif ($innerAction) {
        $innerAction.ToUpperInvariant()
    }
    else {
        $finalAction
    }

    $eventTime = [DateTimeOffset]::FromUnixTimeMilliseconds(
        [int64]$log.timestamp
    ).ToLocalTime()

    $delay = [Math]::Max(
        0,
        ($received - $eventTime).TotalSeconds
    )

    $http = $log.httpRequest
    $script:sequence++

    return [ordered]@{
        sequence       = $script:sequence
        timestamp      = $eventTime.ToString('HH:mm:ss.fff')
        receivedAt     = $received.ToLocalTime().ToString('HH:mm:ss.fff')
        delaySeconds   = [Math]::Round($delay, 3)

        type           = $type
        rule           = $rule
        ruleGroup      = $groupName

        evaluation     = $evaluation
        finalAction    = $finalAction

        country        = [string]$http.country
        clientIpMasked = Mask-Ip ([string]$http.clientIp)

        method         = [string]$http.httpMethod
        host           = [string]$http.host
        uri            = [string]$http.uri
        query          = Decode-Arg ([string]$http.args)
    }
}

$html = @'
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Live Monitor</title>

<style>
:root {
    color-scheme: dark;
    --bg: #0a1020;
    --panel: #121b2f;
    --border: #2b3a5b;
    --text: #edf3ff;
    --muted: #94a6c8;
    --blue: #6da8ff;
    --green: #54d39b;
    --yellow: #f5c66a;
    --red: #ff7373;
    --purple: #c49bff;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        radial-gradient(circle at top, #172442 0, var(--bg) 48%);
    color: var(--text);
    font-family: "Segoe UI", sans-serif;
}

main {
    max-width: 1120px;
    margin: auto;
    padding: 28px 18px 60px;
}

header,
.top,
.toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}

header {
    justify-content: space-between;
    margin-bottom: 18px;
}

h1 {
    margin: 0;
    font-size: 32px;
}

.sub,
.muted {
    color: var(--muted);
}

.status {
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--panel);
}

.dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--yellow);
    margin-right: 7px;
}

.dot.ok {
    background: var(--green);
}

.dot.bad {
    background: var(--red);
}

.stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin-bottom: 16px;
}

.stat,
.card {
    background: rgba(18, 27, 47, 0.94);
    border: 1px solid var(--border);
    border-radius: 14px;
}

.stat {
    padding: 14px;
}

.stat b {
    display: block;
    font-size: 26px;
    margin-top: 5px;
}

.toolbar {
    margin-bottom: 14px;
}

select,
button {
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 8px 11px;
}

button {
    cursor: pointer;
}

button:hover {
    border-color: var(--blue);
}

.session {
    margin-left: auto;
    color: var(--muted);
}

#feed {
    display: grid;
    gap: 11px;
}

.card {
    padding: 15px;
    border-left: 4px solid var(--blue);
}

.card.xss {
    border-left-color: var(--purple);
}

.card.sqli {
    border-left-color: var(--yellow);
}

.card.block {
    box-shadow:
        inset 0 0 0 1px rgba(255, 115, 115, 0.3);
}

.badge {
    display: inline-block;
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
}

.badge.xss {
    color: var(--purple);
}

.badge.sqli {
    color: var(--yellow);
}

.badge.block {
    color: var(--red);
}

.delay {
    margin-left: auto;
    color: var(--muted);
}

.request {
    font-weight: 700;
    margin-top: 10px;
    overflow-wrap: anywhere;
}

code {
    display: block;
    margin-top: 9px;
    padding: 9px 11px;
    border: 1px solid #263451;
    border-radius: 9px;
    background: #080d19;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}

.meta {
    display: flex;
    gap: 8px 15px;
    flex-wrap: wrap;
    margin-top: 10px;
    color: var(--muted);
    font-size: 13px;
}

.empty,
.error {
    padding: 28px;
    border: 1px dashed var(--border);
    border-radius: 14px;
    text-align: center;
    color: var(--muted);
}

.error {
    display: none;
    text-align: left;
    border-style: solid;
    border-color: var(--red);
    color: #ffdada;
    background: #4a1721;
}

@media (max-width: 800px) {
    .stats {
        grid-template-columns: repeat(2, 1fr);
    }

    .session {
        margin-left: 0;
    }

    h1 {
        font-size: 26px;
    }
}
</style>
</head>

<body>
<main>
<header>
    <div>
        <h1>WAF Live Monitor</h1>
        <div class="sub">
            CloudWatch Live Tail · localhost only · 원본 로그 미저장
        </div>
    </div>

    <div class="status">
        <span id="dot" class="dot"></span>
        <span id="status">연결 중</span>
    </div>
</header>

<section class="stats">
    <div class="stat">
        <span class="muted">전체</span>
        <b id="total">0</b>
    </div>

    <div class="stat">
        <span class="muted">XSS</span>
        <b id="xss">0</b>
    </div>

    <div class="stat">
        <span class="muted">SQLi</span>
        <b id="sqli">0</b>
    </div>

    <div class="stat">
        <span class="muted">최종 BLOCK</span>
        <b id="block">0</b>
    </div>

    <div class="stat">
        <span class="muted">최근 지연</span>
        <b id="delay">-</b>
    </div>
</section>

<div id="error" class="error"></div>

<section class="toolbar">
    <label>
        유형
        <select id="filter">
            <option>ALL</option>
            <option>XSS</option>
            <option>SQLi</option>
            <option>OTHER</option>
            <option>BLOCK</option>
        </select>
    </label>

    <button id="pause">일시정지</button>
    <button id="clear">화면 지우기</button>

    <span class="session">
        세션 <span id="timer">00:00:00</span>
    </span>
</section>

<section id="feed"></section>
</main>

<script>
let paused = false;
const hiddenSequences = new Set();
let filter = 'ALL';
let start = Date.now();
let latest = [];

const $ = id => document.getElementById(id);

function setStatus(text, level) {
    $('status').textContent = text;
    $('dot').className = 'dot ' + (level || '');
}

function formatTime(ms) {
    const seconds = Math.floor(ms / 1000);
    const hours = String(
        Math.floor(seconds / 3600)
    ).padStart(2, '0');

    const minutes = String(
        Math.floor((seconds % 3600) / 60)
    ).padStart(2, '0');

    const remain = String(
        seconds % 60
    ).padStart(2, '0');

    return `${hours}:${minutes}:${remain}`;
}

function node(tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== undefined) {
        element.textContent = text;
    }

    return element;
}

function render() {
    if (paused) {
        return;
    }

    const all = latest.filter(
        event => !hiddenSequences.has(event.sequence)
    );

    $('total').textContent = all.length;

    $('xss').textContent = all.filter(
        event => event.type === 'XSS'
    ).length;

    $('sqli').textContent = all.filter(
        event => event.type === 'SQLi'
    ).length;

    $('block').textContent = all.filter(
        event => event.finalAction === 'BLOCK'
    ).length;

    $('delay').textContent = all[0]
        ? all[0].delaySeconds.toFixed(1) + 's'
        : '-';

    let visible = all;

    if (filter === 'BLOCK') {
        visible = all.filter(
            event => event.finalAction === 'BLOCK'
        );
    }
    else if (filter !== 'ALL') {
        visible = all.filter(
            event => event.type === filter
        );
    }

    $('feed').replaceChildren();

    if (!visible.length) {
        $('feed').append(
            node(
                'div',
                'empty',
                '새 WAF 탐지 이벤트를 기다리는 중입니다.'
            )
        );

        return;
    }

    for (const event of visible) {
        let className = 'card ';

        if (event.type === 'XSS') {
            className += 'xss';
        }
        else if (event.type === 'SQLi') {
            className += 'sqli';
        }

        if (event.finalAction === 'BLOCK') {
            className += ' block';
        }

        const card = node('article', className);
        const top = node('div', 'top');

        const typeClass =
            event.type === 'XSS'
                ? 'xss'
                : event.type === 'SQLi'
                    ? 'sqli'
                    : '';

        top.append(
            node(
                'span',
                `badge ${typeClass}`,
                event.type
            ),
            node(
                'span',
                `badge ${
                    event.finalAction === 'BLOCK'
                        ? 'block'
                        : ''
                }`,
                `${event.evaluation} → ${event.finalAction}`
            ),
            node(
                'span',
                'muted',
                event.timestamp
            ),
            node(
                'span',
                'delay',
                `지연 ${event.delaySeconds.toFixed(3)}s`
            )
        );

        card.append(
            top,
            node(
                'div',
                'request',
                `${event.method || '-'}  ${
                    event.host || ''
                }${event.uri || ''}`
            )
        );

        if (event.query) {
            card.append(
                node('code', '', event.query)
            );
        }

        const meta = node('div', 'meta');

        meta.append(
            node(
                'span',
                '',
                `Rule: ${event.rule || '-'}`
            ),
            node(
                'span',
                '',
                `Group: ${event.ruleGroup || '-'}`
            ),
            node(
                'span',
                '',
                `Country: ${event.country || '-'}`
            ),
            node(
                'span',
                '',
                `IP: ${event.clientIpMasked || '-'}`
            ),
            node(
                'span',
                '',
                `Received: ${event.receivedAt}`
            )
        );

        card.append(meta);
        $('feed').append(card);
    }
}

async function poll() {
    try {
        const response = await fetch(
            '/events',
            { cache: 'no-store' }
        );

        const data = await response.json();
        latest = data.events || [];

        if (data.running) {
            setStatus('Live Tail 연결됨', 'ok');
            $('error').style.display = 'none';
        }
        else {
            setStatus('Live Tail 종료됨', 'bad');

            if (data.error) {
                $('error').textContent = data.error;
                $('error').style.display = 'block';
            }
        }

        render();
    }
    catch {
        setStatus('Viewer 연결 실패', 'bad');
    }
}

$('filter').onchange = event => {
    filter = event.target.value;
    render();
};

$('pause').onclick = () => {
    paused = !paused;
    $('pause').textContent =
        paused ? '재개' : '일시정지';

    if (!paused) {
        render();
    }
};

$('clear').onclick = () => {
    let targets = latest.filter(
        event => !hiddenSequences.has(event.sequence)
    );

    if (filter === 'BLOCK') {
        targets = targets.filter(
            event => event.finalAction === 'BLOCK'
        );
    }
    else if (filter !== 'ALL') {
        targets = targets.filter(
            event => event.type === filter
        );
    }

    for (const event of targets) {
        hiddenSequences.add(event.sequence);
    }

    render();
};

setInterval(() => {
    $('timer').textContent =
        formatTime(Date.now() - start);
}, 1000);

setInterval(poll, 700);
poll();
</script>
</body>
</html>
'@

function Send-Response(
    [Net.Sockets.TcpClient]$client,
    [string]$type,
    [byte[]]$body,
    [int]$code = 200,
    [string]$text = 'OK'
) {
    $stream = $client.GetStream()

    $header = (
        "HTTP/1.1 $code $text`r`n" +
        "Content-Type: $type`r`n" +
        "Content-Length: $($body.Length)`r`n" +
        "Cache-Control: no-store`r`n" +
        "X-Content-Type-Options: nosniff`r`n" +
        "Connection: close`r`n`r`n"
    )

    try {
        $headerBytes = $utf8.GetBytes($header)

        $stream.Write(
            $headerBytes,
            0,
            $headerBytes.Length
        )

        $stream.Write(
            $body,
            0,
            $body.Length
        )

        $stream.Flush()
    }
    finally {
        $stream.Dispose()
        $client.Dispose()
    }
}

function Handle-Request(
    [Net.Sockets.TcpClient]$client
) {
    $stream = $client.GetStream()

    $reader = [IO.StreamReader]::new(
        $stream,
        [Text.Encoding]::ASCII,
        $false,
        1024,
        $true
    )

    try {
        $request = $reader.ReadLine()

        while ($reader.ReadLine()) {
        }

        $path = if ($request) {
            ($request.Split(' ')[1]).Split('?')[0]
        }
        else {
            '/'
        }

        if ($path -eq '/events') {
            $payload = [ordered]@{
                running = -not $process.HasExited
                startedAt = $startedAt.ToString('o')

                error = if ($stderr.Count) {
                    $stderr -join "`n"
                }
                else {
                    ''
                }

                events = @(
                    $history |
                    Sort-Object sequence -Descending
                )
            } |
            ConvertTo-Json -Depth 10 -Compress

            Send-Response `
                $client `
                'application/json; charset=utf-8' `
                ($utf8.GetBytes($payload))
        }
        elseif ($path -eq '/') {
            Send-Response `
                $client `
                'text/html; charset=utf-8' `
                ($utf8.GetBytes($html))
        }
        else {
            Send-Response `
                $client `
                'text/plain; charset=utf-8' `
                ($utf8.GetBytes('Not Found')) `
                404 `
                'Not Found'
        }
    }
    catch {
        try {
            $client.Dispose()
        }
        catch {
        }
    }
    finally {
        $reader.Dispose()
    }
}

$process = [Diagnostics.Process]::new()
$process.StartInfo = [Diagnostics.ProcessStartInfo]::new()

$process.StartInfo.FileName = $aws.Source
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true

$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true

$process.StartInfo.StandardOutputEncoding = $utf8
$process.StartInfo.StandardErrorEncoding = $utf8

foreach ($argument in @(
    'logs',
    'start-live-tail',
    '--profile',
    $Profile,
    '--region',
    $Region,
    '--log-group-identifiers',
    $LogGroupIdentifier,
    '--mode',
    'print-only',
    '--no-cli-pager'
)) {
    $process.StartInfo.ArgumentList.Add($argument)
}

$stdoutId = (
    "WafViewer.stdout.$PID." +
    [guid]::NewGuid().ToString('N')
)

$stderrId = (
    "WafViewer.stderr.$PID." +
    [guid]::NewGuid().ToString('N')
)

$listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Loopback,
    $Port
)

try {
    $listener.Start()

    if (-not $process.Start()) {
        throw 'AWS CLI 프로세스 시작 실패'
    }

    Register-ObjectEvent `
        -InputObject $process `
        -EventName OutputDataReceived `
        -SourceIdentifier $stdoutId `
        -MessageData $queue `
        -Action {
            if ($null -ne $EventArgs.Data) {
                $Event.MessageData.Enqueue(
                    [pscustomobject]@{
                        Kind = 'out'
                        Data = $EventArgs.Data
                        At = [DateTimeOffset]::Now
                    }
                )
            }
        } |
    Out-Null

    Register-ObjectEvent `
        -InputObject $process `
        -EventName ErrorDataReceived `
        -SourceIdentifier $stderrId `
        -MessageData $queue `
        -Action {
            if ($null -ne $EventArgs.Data) {
                $Event.MessageData.Enqueue(
                    [pscustomobject]@{
                        Kind = 'err'
                        Data = $EventArgs.Data
                        At = [DateTimeOffset]::Now
                    }
                )
            }
        } |
    Out-Null

    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()

    $url = "http://127.0.0.1:$Port/"

    Write-Host ''
    Write-Host "WAF Live Viewer: $url" -ForegroundColor Cyan
    Write-Host '종료: Ctrl+C'
    Write-Host '원본 로그는 디스크에 저장하지 않음'
    Write-Host ''

    if (-not $NoBrowser) {
        Start-Process $url
    }

    while ($true) {
        if ($listener.Pending()) {
            Handle-Request (
                $listener.AcceptTcpClient()
            )
        }

        $item = $null

        while ($queue.TryDequeue([ref]$item)) {
            if ($item.Kind -eq 'err') {
                if ($item.Data) {
                    $stderr.Add(
                        [string]$item.Data
                    )

                    Write-Warning $item.Data
                }

                continue
            }

            if (-not $item.Data) {
                continue
            }

            try {
                $log = $item.Data |
                    ConvertFrom-Json -Depth 64

                $event = Convert-WafEvent `
                    $log `
                    $item.At

                if ($null -eq $event) {
                    continue
                }

                $history.Add($event)

                while ($history.Count -gt $MaxEvents) {
                    $history.RemoveAt(0)
                }

                Write-Host (
                    '[{0}] {1,-5} {2}→{3} {4} {5}{6} ({7:N3}s)' -f
                    $event.timestamp,
                    $event.type,
                    $event.evaluation,
                    $event.finalAction,
                    $event.method,
                    $event.host,
                    $event.uri,
                    $event.delaySeconds
                )
            }
            catch {
                Write-Warning (
                    "로그 파싱 실패: " +
                    $_.Exception.Message
                )
            }
        }

        if (
            $process.HasExited -and
            -not $exitReported
        ) {
            $exitReported = $true

            Write-Warning (
                "AWS Live Tail 종료됨. " +
                "ExitCode=$($process.ExitCode)"
            )
        }

        Start-Sleep -Milliseconds 40
    }
}
finally {
    Write-Host ''
    Write-Host 'Viewer 종료 중...' -ForegroundColor Yellow

    try {
        $listener.Stop()
    }
    catch {
    }

    try {
        if (-not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit(3000)
        }
    }
    catch {
    }

    foreach ($id in @(
        $stdoutId,
        $stderrId
    )) {
        Unregister-Event `
            -SourceIdentifier $id `
            -ErrorAction SilentlyContinue

        Get-Job `
            -Name $id `
            -ErrorAction SilentlyContinue |
        Remove-Job `
            -Force `
            -ErrorAction SilentlyContinue
    }

    $process.Dispose()

    Write-Host '종료 완료.' -ForegroundColor Green
}
