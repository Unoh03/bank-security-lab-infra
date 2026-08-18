#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('observe_only','contain')]
    [string]$ResponseMode = 'observe_only',
    [ValidateRange(30, 120)]
    [int]$TakeLifetimeMinutes = 120,
    [ValidateRange(60, 600)]
    [int]$ReadyTimeoutSeconds = 300,
    [ValidateRange(45, 120)]
    [int]$MinimumDailyRemainingMinutes = 60,
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$ConfigurationRoot = '',
    [string]$EvidenceRoot = '',
    [string]$ConfirmStart = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$foundationRoot = Join-Path $repositoryRoot 'foundation'
$expectedAccountId = '433048100798'
$expectedRegion = 'ap-northeast-2'
$sshHost = 'bas'
$moduleRoot = Join-Path $repositoryRoot 'automation'

Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Wazuh.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
. (Join-Path $repositoryRoot 'daily-session-common.ps1')

$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path (
        [Environment]::GetFolderPath('MyDocuments')
    ) 'aws-topology-evidence'
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)

Write-Host 'SOC lab one-command READY preview'
Write-Host "Response mode: $ResponseMode"
Write-Host 'Read-only preflight: Daily, DVWA, Shuffle, GitHub, Argo CD, Foundation.'
Write-Host 'Runtime actions: local Wazuh/Bridge start, harmless Rule 100102 probe, TAKE allow registration.'
Write-Host "Required Daily runtime remaining: at least $MinimumDailyRemainingMinutes minutes."
Write-Host 'Excluded: Terraform Apply/Destroy, real attack, GitHub write, Reset.'
if ($ConfirmStart -cne 'START SOC LAB') {
    throw "Preview only. Re-run with -ConfirmStart 'START SOC LAB'."
}

function Invoke-SocNativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        $output = $null
        throw $FailureMessage
    }
    return (($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim()
}

function Get-SocTerraformRaw {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Name
    )

    return (Invoke-SocNativeCapture -FilePath 'terraform' -Arguments @(
        "-chdir=$Root", 'output', '-raw', $Name
    ) -FailureMessage "Required Terraform output is unavailable: $Name").Trim()
}

function Get-SocTerraformJson {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Name
    )

    $text = Invoke-SocNativeCapture -FilePath 'terraform' -Arguments @(
        "-chdir=$Root", 'output', '-json', $Name
    ) -FailureMessage "Required Terraform output is unavailable: $Name"
    return $text | ConvertFrom-Json -Depth 100
}

function Invoke-SocComposeCapture {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $nativeArguments = [Collections.Generic.List[string]]::new()
    foreach ($path in $File) {
        $nativeArguments.Add('-f')
        $nativeArguments.Add($path)
    }
    foreach ($argument in $Arguments) {
        $nativeArguments.Add($argument)
    }
    return Invoke-SocNativeCapture `
        -FilePath 'docker' `
        -Arguments (@('compose') + @($nativeArguments)) `
        -FailureMessage $FailureMessage
}

function Assert-SocEffectiveCompose {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][string]$ExpectedAdmin,
        [Parameter(Mandatory)][string]$ExpectedKibana,
        [Parameter(Mandatory)][string]$ExpectedApi
    )

    $text = Invoke-SocComposeCapture `
        -File $File `
        -Arguments @('config','--format','json') `
        -FailureMessage 'Docker Compose rejected the generated SOC runtime configuration.'
    try {
        $config = $text | ConvertFrom-Json -Depth 100
    } finally {
        $text = $null
    }
    foreach ($serviceName in @('wazuh.manager','wazuh.indexer','wazuh.dashboard')) {
        $service = $config.services.PSObject.Properties[$serviceName].Value
        foreach ($port in @($service.ports)) {
            if ([string]$port.host_ip -cne '127.0.0.1') {
                throw "The effective SOC Compose exposes a non-loopback port: $serviceName"
            }
        }
    }
    if ([string]$config.services.'wazuh.manager'.environment.INDEXER_PASSWORD -cne $ExpectedAdmin -or
        [string]$config.services.'wazuh.manager'.environment.API_PASSWORD -cne $ExpectedApi -or
        [string]$config.services.'wazuh.dashboard'.environment.INDEXER_PASSWORD -cne $ExpectedAdmin -or
        [string]$config.services.'wazuh.dashboard'.environment.DASHBOARD_PASSWORD -cne $ExpectedKibana -or
        [string]$config.services.'wazuh.dashboard'.environment.API_PASSWORD -cne $ExpectedApi) {
        throw 'The effective SOC Compose lost a protected Wazuh credential override.'
    }
    $managerMounts = @($config.services.'wazuh.manager'.volumes)
    $mountByTarget = @{}
    foreach ($mount in $managerMounts) {
        $mountByTarget[[string]$mount.target] = $mount
    }
    foreach ($target in @(
        '/wazuh-config-mount/etc/ossec.conf',
        '/soc-bootstrap/custom-shuffle-soc',
        '/var/ossec/soc-secrets/shuffle_webhook_url',
        '/var/ossec/soc-secrets/shuffle_webhook_header_key'
    )) {
        if (-not $mountByTarget.ContainsKey($target) -or
            [bool]$mountByTarget[$target].read_only -ne $true) {
            throw "The effective SOC Compose lost a read-only SOC mount: $target"
        }
    }
}

function Wait-SocComposeServices {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [ValidateRange(30, 600)][int]$TimeoutSeconds = 300
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $services = @('wazuh.manager','wazuh.indexer','wazuh.dashboard')
    do {
        $allReady = $true
        foreach ($service in $services) {
            $containerId = Invoke-SocComposeCapture `
                -File $File `
                -Arguments @('ps','-q',$service) `
                -FailureMessage "The Wazuh container ID is unavailable: $service"
            if (-not $containerId -or $containerId -notmatch '^[a-f0-9]{12,64}$') {
                $allReady = $false
                break
            }
            $state = Invoke-SocNativeCapture -FilePath 'docker' -Arguments @(
                'inspect','--format',
                '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}',
                $containerId
            ) -FailureMessage "The Wazuh container state is unavailable: $service"
            $parts = $state -split '\|',2
            if ($parts[0] -cne 'running' -or
                ($parts.Count -gt 1 -and $parts[1] -and $parts[1] -cne 'healthy')) {
                $allReady = $false
                break
            }
        }
        if ($allReady) {
            return
        }
        Start-Sleep -Seconds 3
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw 'The Wazuh services did not become running and healthy in time.'
}

function Invoke-SocLoopbackRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [AllowNull()][object]$Body = $null
    )

    if ($Uri.Scheme -cne 'https' -or $Uri.Host -cne '127.0.0.1' -or
        $Uri.Port -notin @(9200,55000)) {
        throw 'A Wazuh local request escaped the fixed loopback endpoints.'
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.ServerCertificateCustomValidationCallback = { $true }
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds(20)
    $httpMethod = if ($Method -ceq 'GET') {
        [Net.Http.HttpMethod]::Get
    } else {
        [Net.Http.HttpMethod]::Post
    }
    $request = [Net.Http.HttpRequestMessage]::new($httpMethod, $Uri)
    $authBytes = [Text.Encoding]::UTF8.GetBytes("${UserName}:$Password")
    try {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Basic', [Convert]::ToBase64String($authBytes)
        )
        if ($null -ne $Body) {
            $request.Content = [Net.Http.StringContent]::new(
                ($Body | ConvertTo-Json -Depth 30 -Compress),
                [Text.Encoding]::UTF8,
                'application/json'
            )
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($text.Length -gt 8388608) {
                throw 'A Wazuh local response exceeded the fixed 8 MiB limit.'
            }
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Text       = $text
            }
        } finally {
            $response.Dispose()
        }
    } catch {
        throw 'A fixed Wazuh loopback request failed.'
    } finally {
        [Array]::Clear($authBytes, 0, $authBytes.Length)
        if ($request.Content) { $request.Content.Dispose() }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Test-SocLoopbackBasicAuth {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [ValidateSet('GET','POST')][string]$Method = 'GET'
    )

    $response = Invoke-SocLoopbackRequest `
        -Method $Method `
        -Uri $Uri `
        -UserName $UserName `
        -Password $Password
    try {
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            return $true
        }
        if ($response.StatusCode -in @(401,403)) {
            return $false
        }
        throw "Unexpected Wazuh authentication status: $($response.StatusCode)"
    } finally {
        $response.Text = $null
    }
}

function Get-SocWazuhProbeAlerts {
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$AdminPassword
    )

    $query = [ordered]@{
        size  = 3
        query = [ordered]@{
            bool = [ordered]@{
                filter = @(
                    @{ term = @{ 'rule.id' = '100102' } },
                    @{ term = @{ 'data.payload.take_id' = $TakeId } }
                )
            }
        }
        sort = @(@{ '@timestamp' = @{ order = 'asc' } })
    }
    $response = Invoke-SocLoopbackRequest `
        -Method POST `
        -Uri 'https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search' `
        -UserName admin `
        -Password $AdminPassword `
        -Body $query
    try {
        if ($response.StatusCode -ne 200) {
            throw 'The Wazuh safe-probe query was rejected.'
        }
        $result = $response.Text | ConvertFrom-Json -Depth 100
        return @($result.hits.hits)
    } finally {
        $response.Text = $null
    }
}

function Assert-SocDvWaLow {
    param([Parameter(Mandatory)][uri]$BaseUri)

    if ($BaseUri.Scheme -cne 'https' -or -not $BaseUri.Host) {
        throw 'Terraform returned an unsafe DVWA application URL.'
    }
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = 'aws-topology-soc-ready/1.0'
    try {
        $login = Invoke-WebRequest `
            -Uri ([uri]::new($BaseUri,'/login.php')) `
            -Method Get `
            -WebSession $session `
            -TimeoutSec 30 `
            -ErrorAction Stop
        $match = [regex]::Match(
            [string]$login.Content,
            'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)["'']',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if (-not $match.Success) {
            throw 'The DVWA login CSRF token is unavailable.'
        }
        [void](Invoke-WebRequest `
            -Uri ([uri]::new($BaseUri,'/login.php')) `
            -Method Post `
            -WebSession $session `
            -TimeoutSec 30 `
            -Body @{
                username='admin'; password='password'; Login='Login';
                user_token=$match.Groups[1].Value
            } `
            -ErrorAction Stop)
        $page = Invoke-WebRequest `
            -Uri ([uri]::new($BaseUri,'/vulnerabilities/exec/')) `
            -Method Get `
            -WebSession $session `
            -TimeoutSec 30 `
            -ErrorAction Stop
        $securityCookie = @(
            $session.Cookies.GetCookies($BaseUri) |
                Where-Object { $_.Name -ceq 'security' }
        ) | Select-Object -Last 1
        if (-not $securityCookie -or $securityCookie.Value -cne 'low' -or
            [string]$page.Content -notmatch 'name\s*=\s*["'']ip["'']') {
            throw 'DVWA is not at the low Command Injection baseline.'
        }
    } catch {
        throw 'DVWA low-mode login and Command Injection preflight failed.'
    }
}

function Get-SocGithubState {
    param([Parameter(Mandatory)][object]$Configuration)

    foreach ($workflowName in @(
        [string]$Configuration.containment_workflow,
        [string]$Configuration.reset_workflow
    )) {
        $workflow = Invoke-SocNativeCapture -FilePath 'gh' -Arguments @(
            'api','--method','GET',
            "repos/$($Configuration.github_repository)/actions/workflows/$workflowName"
        ) -FailureMessage "The required GitHub Workflow is not available on main: $workflowName" |
            ConvertFrom-Json -Depth 30
        if ([string]$workflow.state -cne 'active' -or
            [string]$workflow.path -cne ".github/workflows/$workflowName") {
            throw "The required GitHub Workflow is not active at its fixed path: $workflowName"
        }
    }
    $commit = Invoke-SocNativeCapture -FilePath 'gh' -Arguments @(
        'api','--method','GET',
        "repos/$($Configuration.github_repository)/commits/$($Configuration.github_ref)"
    ) -FailureMessage 'The remote GitHub main commit is unavailable.' | ConvertFrom-Json -Depth 50
    $sha = [string]$commit.sha
    if ($sha -notmatch '^[0-9a-f]{40}$') {
        throw 'GitHub returned an invalid remote main commit SHA.'
    }
    $content = Invoke-SocNativeCapture -FilePath 'gh' -Arguments @(
        'api','--method','GET',
        "repos/$($Configuration.github_repository)/contents/deploy/dvwa/values.yaml?ref=$($Configuration.github_ref)"
    ) -FailureMessage 'The remote DVWA values.yaml is unavailable.' | ConvertFrom-Json -Depth 30
    $bytes = $null
    try {
        $bytes = [Convert]::FromBase64String(([string]$content.content -replace '\s',''))
        $valuesText = [Text.Encoding]::UTF8.GetString($bytes)
    } finally {
        if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
    }
    if (@([regex]::Matches($valuesText,'(?m)^defaultSecurityLevel:\s*low\s*$')).Count -ne 1 -or
        $valuesText -match '(?m)^defaultSecurityLevel:\s*impossible\s*$') {
        throw 'Remote main is not at the unique low DVWA baseline.'
    }
    return [pscustomobject]@{ Sha=$sha; SecurityLevel='low' }
}

function Get-SocArgoState {
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$ExpectedRevision
    )

    $application = Invoke-SocNativeCapture -FilePath 'ssh' -Arguments @(
        '-o','BatchMode=yes',
        '-o','LogLevel=ERROR',
        '-o','StrictHostKeyChecking=accept-new',
        '-o','ConnectTimeout=20',
        $sshHost,
        "kubectl -n argocd get application $($Configuration.argo_application) -o json"
    ) -FailureMessage 'The Argo CD application state is unavailable through the fixed Bastion host.' |
        ConvertFrom-Json -Depth 100
    $sync = [string]$application.status.sync.status
    $health = [string]$application.status.health.status
    $revision = [string]$application.status.sync.revision
    $errorConditions = @($application.status.conditions | Where-Object {
        [string]$_.type -match 'Error$'
    })
    if ($sync -cne 'Synced' -or $health -cne 'Healthy' -or
        $revision -cne $ExpectedRevision -or $errorConditions.Count -ne 0) {
        throw 'Argo CD is not Synced and Healthy at the exact remote main revision.'
    }
    return [pscustomobject]@{ Sync=$sync; Health=$health; Revision=$revision }
}

function Read-SocHardeningEvidence {
    $root = Join-Path $EvidenceRoot 'soc-lab-hardening'
    $file = Get-ChildItem -LiteralPath $root -File -Filter 'wazuh-hardening-*.json' `
        -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $file) {
        throw 'Wazuh credential hardening Runtime Evidence is absent.'
    }
    $record = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ([int]$record.schema_version -ne 1 -or
        [bool]$record.local_only_ports -ne $true -or
        [bool]$record.named_volumes_removed -ne $false -or
        [bool]$record.secrets_printed -ne $false -or
        [string]$record.new_admin_authentication -cne 'accepted' -or
        [string]$record.default_admin_authentication -cne 'rejected' -or
        [string]$record.new_kibanaserver_authentication -cne 'accepted' -or
        [string]$record.default_kibana_authentication -cne 'rejected' -or
        [string]$record.new_wazuh_wui_authentication -cne 'accepted' -or
        [string]$record.default_wazuh_wui_authentication -cne 'rejected') {
        throw 'The latest Wazuh hardening Evidence does not prove complete credential rotation.'
    }
    return $file.FullName
}

function Wait-SocBridgeReady {
    param(
        [Parameter(Mandatory)][string]$HeartbeatPath,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [ValidateRange(30, 600)][int]$TimeoutSeconds
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'The Wazuh Push Bridge exited before READY.'
        }
        if (Test-Path -LiteralPath $HeartbeatPath -PathType Leaf) {
            try {
                $heartbeat = Get-Content -LiteralPath $HeartbeatPath -Raw | ConvertFrom-Json
                $heartbeatAt = [datetimeoffset]::Parse([string]$heartbeat.heartbeat_at_utc)
                $expiresAt = [datetimeoffset]::Parse([string]$heartbeat.session_expires_at_utc)
                if ([int]$heartbeat.pid -eq $Process.Id -and
                    [string]$heartbeat.state -in @('READY','RUNNING') -and
                    ([datetimeoffset]::UtcNow - $heartbeatAt).TotalSeconds -le 30 -and
                    ($expiresAt - [datetimeoffset]::UtcNow).TotalMinutes -ge 10 -and
                    [int]$heartbeat.dlq_visible -eq 0 -and
                    [int]$heartbeat.queue_not_visible -eq 0 -and
                    (-not ([int]$heartbeat.queue_visible -gt 0) -or
                        [int]$heartbeat.queue_oldest_age_seconds -le 120)) {
                    return $heartbeat
                }
            } catch {
                # The writer atomically replaces the heartbeat; retry a bounded parse race.
            }
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw 'The Wazuh Push Bridge did not satisfy the READY heartbeat contract in time.'
}

function Write-SocAtomicJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Value | ConvertTo-Json -Depth 20) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath,$Path,$backupPath)
            Remove-Item -LiteralPath $backupPath -Force
        } else {
            [IO.File]::Move($temporaryPath,$Path)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

$runtimeSessionId = 'soc-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
    [guid]::NewGuid().ToString('N').Substring(0,8)
$sessionPath = Join-Path $resolvedRuntimeRoot $runtimeSessionId
$activeSessionPath = Join-Path $resolvedRuntimeRoot 'active-soc-session.json'
$bridgeProcess = $null
$composeFiles = @()
$composeStarted = $false
$stage = 'preflight'
$succeeded = $false
$adminPassword = $null
$kibanaPassword = $null
$apiPassword = $null
$shuffleApiKey = $null
$shuffleWebhookUrl = $null
$shuffleHeaderKey = $null
$takeRecord = $null
$shuffleAllowRegistered = $false
$configuration = $null

try {
    if (Test-Path -LiteralPath $activeSessionPath -PathType Leaf) {
        throw 'An active or unclean SOC session exists. Run Stop-SocLab before starting another session.'
    }
    foreach ($name in @('terraform','aws','docker','gh','ssh','pwsh')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw "Required command is unavailable: $name"
        }
    }
    foreach ($name in @(
        'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN'
    )) {
        if ([Environment]::GetEnvironmentVariable($name,'Process')) {
            throw "Clear the process-level $name before starting the SOC lab."
        }
    }

    $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
    $wazuhRoot = [IO.Path]::GetFullPath([string]$configuration.wazuh_root)
    $baseComposePath = Join-Path $wazuhRoot 'docker-compose.yml'
    $internalUsersSourcePath = Join-Path $wazuhRoot 'config\wazuh_indexer\internal_users.yml'
    $dashboardSourcePath = Join-Path $wazuhRoot 'config\wazuh_dashboard\wazuh.yml'
    $managerSourcePath = Join-Path $wazuhRoot 'config\wazuh_cluster\wazuh_manager.conf'
    $portOverridePath = Join-Path $repositoryRoot 'observability\wazuh\docker-compose.soc.override.yml'
    $integrationScriptPath = Join-Path $repositoryRoot 'observability\wazuh\integrations\custom-shuffle-soc'
    $integrationXmlPath = Join-Path $repositoryRoot 'observability\wazuh\templates\shuffle-integration.xml'
    foreach ($path in @(
        $baseComposePath,$internalUsersSourcePath,$dashboardSourcePath,
        $managerSourcePath,$portOverridePath,$integrationScriptPath,$integrationXmlPath
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required SOC startup input is unavailable: $path"
        }
    }
    foreach ($secretName in @(
        'wazuh_indexer_admin_password','wazuh_indexer_kibanaserver_password',
        'wazuh_api_wui_password','shuffle_webhook_header_key',
        'shuffle_api_key','shuffle_webhook_url'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedSecretRoot "$secretName.dpapi.json") -PathType Leaf)) {
            throw "Protected SOC secret is unavailable: $secretName"
        }
    }
    $hardeningEvidencePath = Read-SocHardeningEvidence

    $identity = Invoke-SocNativeCapture -FilePath 'aws' -Arguments @(
        'sts','get-caller-identity','--profile',[string]$configuration.aws_profile,
        '--region',$expectedRegion,'--output','json','--no-cli-pager'
    ) -FailureMessage 'The fixed AWS identity could not be verified.' | ConvertFrom-Json
    if ([string]$identity.Account -cne $expectedAccountId) {
        throw 'The AWS account does not match the fixed SOC lab account.'
    }
    $dailySession = Read-DailySessionState -Path (Get-DailySessionActiveStatePath)
    if ([string]$dailySession.Status -cne 'Active' -or
        [string]$dailySession.SecurityScenarioProfile -cne 'capital-one-lab' -or
        [string]$dailySession.AccountId -cne $expectedAccountId -or
        [string]$dailySession.PrimaryRegion -cne $expectedRegion -or
        [IO.Path]::GetFullPath([string]$dailySession.TerraformRoot) -cne $repositoryRoot) {
        throw 'The Active Daily Session does not match the fixed SOC lab runtime.'
    }
    if (([datetimeoffset]$dailySession.HardDeadlineAtUtc - [datetimeoffset]::UtcNow).TotalMinutes -lt $MinimumDailyRemainingMinutes) {
        throw "The Active Daily Session has less than $MinimumDailyRemainingMinutes minutes remaining."
    }
    if ((Get-SocTerraformRaw -Root $repositoryRoot -Name runtime_profile) -cne 'minimal' -or
        (Get-SocTerraformRaw -Root $repositoryRoot -Name security_scenario_profile) -cne 'capital-one-lab') {
        throw 'The Terraform Runtime is not minimal + capital-one-lab.'
    }
    $applicationUrl = [uri](Get-SocTerraformRaw -Root $repositoryRoot -Name application_url)
    $transport = Get-SocTerraformJson -Root $foundationRoot -Name wazuh_push_transport
    $sources = Get-SocTerraformJson -Root $foundationRoot -Name wazuh_log_sources
    if (-not [bool]$transport.enabled -or [string]$transport.mode -cne 'shadow' -or
        [string]$transport.source -cne 'dvwa' -or -not [bool]$sources.enabled) {
        throw 'The Foundation Wazuh Reader and DVWA Push transport are not both active.'
    }
    $queueUrl = Get-SocTerraformRaw -Root $foundationRoot -Name wazuh_push_primary_queue_url
    $dlqUrl = Get-SocTerraformRaw -Root $foundationRoot -Name wazuh_push_primary_dlq_url
    $readerRoleArn = Get-SocTerraformRaw -Root $foundationRoot -Name wazuh_log_reader_role_arn
    if ($queueUrl -notmatch '^https://sqs\.ap-northeast-2\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]+$' -or
        $dlqUrl -notmatch '^https://sqs\.ap-northeast-2\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]+$' -or
        $readerRoleArn -notmatch "^arn:aws:iam::$expectedAccountId:role/[A-Za-z0-9+=,.@_-]+$") {
        throw 'A Foundation Queue, DLQ, or Reader Role output is unsafe.'
    }
    Assert-SocDvWaLow -BaseUri $applicationUrl

    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $resolvedSecretRoot
    $kibanaPassword = Unprotect-SocSecret -Name 'wazuh_indexer_kibanaserver_password' -SecretRoot $resolvedSecretRoot
    $apiPassword = Unprotect-SocSecret -Name 'wazuh_api_wui_password' -SecretRoot $resolvedSecretRoot
    $shuffleHeaderKey = Unprotect-SocSecret -Name 'shuffle_webhook_header_key' -SecretRoot $resolvedSecretRoot
    $shuffleApiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
    $shuffleWebhookUrl = Unprotect-SocSecret -Name 'shuffle_webhook_url' -SecretRoot $resolvedSecretRoot
    if ($shuffleHeaderKey -notmatch '^[A-Za-z0-9.*+?-]{24,128}$') {
        throw 'The protected Shuffle Webhook header key is invalid.'
    }
    $webhookUri = [uri]$shuffleWebhookUrl
    $webhookId = [regex]::Escape([string]$configuration.shuffle_webhook_id)
    if ($webhookUri.Scheme -cne 'https' -or
        ($webhookUri.Host -cne 'shuffler.io' -and -not $webhookUri.Host.EndsWith('.shuffler.io')) -or
        $webhookUri.UserInfo -or $webhookUri.Query -or $webhookUri.Fragment -or
        $webhookUri.AbsolutePath -notmatch "^/api/v1/(?:hooks/$webhookId|webhooks/webhook_$webhookId)$") {
        throw 'The protected Shuffle Webhook URL does not match the configured trigger.'
    }
    $shuffleWorkflow = Get-ShuffleSocWorkflow `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -WebhookId ([string]$configuration.shuffle_webhook_id) `
        -ApiKey $shuffleApiKey `
        -OrgId ([string]$configuration.shuffle_org_id) `
        -BaseUri ([uri][string]$configuration.shuffle_api_base)
    $shuffleWorkflowStage = 'core'
    $gateB5Evidence = $null
    $shuffleCloudProvenance = $null
    if ($ResponseMode -ceq 'contain') {
        [void](Assert-ShuffleSocProductionWorkflow `
            -Workflow $shuffleWorkflow `
            -WorkflowId ([string]$configuration.shuffle_workflow_id) `
            -WebhookId ([string]$configuration.shuffle_webhook_id))
        $appUploadEvidence = Get-ShuffleSocAppUploadEvidence `
            -EvidenceRoot $EvidenceRoot `
            -ExpectedOrgId ([string]$configuration.shuffle_org_id)
        $shuffleCloudProvenance = Get-ShuffleSocCloudProvenance `
            -Workflow $shuffleWorkflow `
            -UploadEvidence $appUploadEvidence `
            -ApiKey $shuffleApiKey `
            -OrgId ([string]$configuration.shuffle_org_id) `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        if (-not [bool]$shuffleCloudProvenance.authentication_active -or
            [bool]$shuffleCloudProvenance.secret_value_inspected -ne $false) {
            throw 'The current Shuffle Cloud App or Authentication provenance is not verified.'
        }
        $gateB5Evidence = Assert-ShuffleSocGateB5Evidence `
            -EvidenceRoot $EvidenceRoot `
            -WorkflowId ([string]$configuration.shuffle_workflow_id)
        $productionCoreHash = Get-ShuffleSocCoreContractSha256 `
            -Workflow $shuffleWorkflow `
            -WebhookId ([string]$configuration.shuffle_webhook_id)
        if ($productionCoreHash -cne [string]$gateB5Evidence.WorkflowCoreSha256) {
            throw 'The Production Workflow core changed after Gate B5 outside the approved dispatch slot.'
        }
        $shuffleWorkflowStage = 'production'
    }
    $githubState = Get-SocGithubState -Configuration $configuration
    $argoState = Get-SocArgoState -Configuration $configuration -ExpectedRevision $githubState.Sha

    $stage = 'wazuh-runtime'
    $adminHash = Get-WazuhPasswordHash -Password $adminPassword
    $kibanaHash = Get-WazuhPasswordHash -Password $kibanaPassword
    $internalUsersText = Get-Content -LiteralPath $internalUsersSourcePath -Raw
    $internalUsersText = Set-WazuhInternalUserHashText `
        -Text $internalUsersText -UserName admin -Hash $adminHash
    $internalUsersText = Set-WazuhInternalUserHashText `
        -Text $internalUsersText -UserName kibanaserver -Hash $kibanaHash
    $dashboardText = Set-WazuhDashboardApiPasswordText `
        -Text (Get-Content -LiteralPath $dashboardSourcePath -Raw) `
        -Password $apiPassword
    $managerText = Add-WazuhManagerSocIntegrationText `
        -ManagerConfigText (Get-Content -LiteralPath $managerSourcePath -Raw) `
        -IntegrationXml (Get-Content -LiteralPath $integrationXmlPath -Raw)

    $internalUsersPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\internal_users.yml' -Content $internalUsersText -RuntimeRoot $resolvedRuntimeRoot
    $dashboardPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\wazuh.yml' -Content $dashboardText -RuntimeRoot $resolvedRuntimeRoot
    $managerPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\ossec.conf' -Content $managerText -RuntimeRoot $resolvedRuntimeRoot
    $webhookPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'secrets\shuffle_webhook_url' -Content "$shuffleWebhookUrl`n" -RuntimeRoot $resolvedRuntimeRoot
    $headerPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'secrets\shuffle_webhook_header_key' -Content "$shuffleHeaderKey`n" -RuntimeRoot $resolvedRuntimeRoot
    $secretOverride = New-WazuhSecretOverrideText -Phase Final `
        -InternalUsersPath $internalUsersPath -AdminPassword $adminPassword `
        -KibanaserverPassword $kibanaPassword -ApiPassword $apiPassword `
        -DashboardConfigPath $dashboardPath
    $secretOverridePath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'compose\docker-compose.secrets.yml' -Content $secretOverride -RuntimeRoot $resolvedRuntimeRoot
    $socOverride = New-WazuhSocIntegrationOverrideText `
        -ManagerConfigPath $managerPath -IntegrationScriptPath $integrationScriptPath `
        -WebhookUrlPath $webhookPath -WebhookHeaderKeyPath $headerPath
    $socOverridePath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'compose\docker-compose.soc.yml' -Content $socOverride -RuntimeRoot $resolvedRuntimeRoot
    $composeFiles = @($baseComposePath,$portOverridePath,$secretOverridePath,$socOverridePath)
    Assert-SocEffectiveCompose -File $composeFiles -ExpectedAdmin $adminPassword `
        -ExpectedKibana $kibanaPassword -ExpectedApi $apiPassword
    [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @('up','-d') `
        -FailureMessage 'The Wazuh SOC Compose stack could not start.')
    $composeStarted = $true
    Wait-SocComposeServices -File $composeFiles -TimeoutSeconds $ReadyTimeoutSeconds
    [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @(
        'exec','-T','--user','root','wazuh.manager','install',
        '-o','root','-g','wazuh','-m','0750',
        '/soc-bootstrap/custom-shuffle-soc',
        '/var/ossec/integrations/custom-shuffle-soc'
    ) -FailureMessage 'The Wazuh Shuffle integration could not be installed into the retained integration volume.')
    [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @('restart','wazuh.manager') `
        -FailureMessage 'The Wazuh Manager could not restart with the SOC integration.')
    Wait-SocComposeServices -File $composeFiles -TimeoutSeconds $ReadyTimeoutSeconds
    $wazuhChecks = @(
        ,@('exec','-T','wazuh.manager','/var/ossec/bin/wazuh-analysisd','-t')
        ,@('exec','-T','wazuh.manager','/var/ossec/bin/wazuh-modulesd','-t')
        ,@('exec','-T','wazuh.manager','test','-x','/var/ossec/integrations/custom-shuffle-soc')
    )
    foreach ($command in $wazuhChecks) {
        [void](Invoke-SocComposeCapture -File $composeFiles -Arguments $command `
            -FailureMessage 'The Wazuh Manager configuration, module, Rule, or integration test failed.')
    }
    if (-not (Test-SocLoopbackBasicAuth -Uri 'https://127.0.0.1:9200/' -UserName admin -Password $adminPassword) -or
        -not (Test-SocLoopbackBasicAuth -Uri 'https://127.0.0.1:9200/_plugins/_security/authinfo' -UserName kibanaserver -Password $kibanaPassword) -or
        -not (Test-SocLoopbackBasicAuth -Uri 'https://127.0.0.1:55000/security/user/authenticate?raw=true' -Method POST -UserName wazuh-wui -Password $apiPassword)) {
        throw 'A rotated Wazuh credential was rejected during READY.'
    }
    if (Test-SocLoopbackBasicAuth -Uri 'https://127.0.0.1:9200/' -UserName admin -Password ('Secret'+'Password')) {
        throw 'The Wazuh indexer accepted the official default admin credential.'
    }

    $stage = 'bridge'
    $heartbeatPath = Join-Path $sessionPath 'bridge-heartbeat.json'
    $stopSignalPath = Join-Path $sessionPath 'bridge.stop'
    $bridgeSpoolDirectory = Join-Path $EvidenceRoot 'wazuh-push-shadow\dvwa'
    $bridgeLockPath = Join-Path $bridgeSpoolDirectory 'wazuh-push-bridge.lock'
    $bridgeStdoutPath = Join-Path $sessionPath 'bridge.stdout.log'
    $bridgeStderrPath = Join-Path $sessionPath 'bridge.stderr.log'
    $bridgePath = Join-Path $repositoryRoot 'tools\Start-WazuhPushShadowBridge.ps1'
    $bridgeArguments = @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',$bridgePath,
        '-QueueUrl',$queueUrl,'-DlqUrl',$dlqUrl,'-ReaderRoleArn',$readerRoleArn,
        '-BootstrapProfile',[string]$configuration.aws_profile,
        '-Region',$expectedRegion,'-SpoolDirectory',$bridgeSpoolDirectory,
        '-HeartbeatPath',$heartbeatPath,
        '-StopSignalPath',$stopSignalPath,'-MaxReadyQueueAgeSeconds','120',
        '-ConfirmConsume','CONSUME WAZUH PUSH'
    )
    $bridgeProcess = Start-Process -FilePath (Get-Command pwsh).Source `
        -ArgumentList $bridgeArguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $bridgeStdoutPath -RedirectStandardError $bridgeStderrPath
    $bridgeHeartbeat = Wait-SocBridgeReady -HeartbeatPath $heartbeatPath `
        -Process $bridgeProcess -TimeoutSeconds $ReadyTimeoutSeconds

    $stage = 'safe-probe'
    $probeTakeId = 'wazuh-push-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $probeStartedAt = [datetimeoffset]::UtcNow
    & (Join-Path $repositoryRoot 'observability\wazuh\Invoke-WazuhPushValidation.ps1') `
        -TakeId $probeTakeId `
        -AwsProfile ([string]$configuration.aws_profile) `
        -ConfirmRun 'SEND WAZUH PUSH VALIDATION' | Out-Null
    $probeDeadline = [datetimeoffset]::UtcNow.AddSeconds(120)
    $probeHits = @()
    do {
        $probeHits = @(Get-SocWazuhProbeAlerts -TakeId $probeTakeId -AdminPassword $adminPassword)
        if ($probeHits.Count -eq 1) { break }
        if ($probeHits.Count -gt 1) {
            throw 'The harmless Rule 100102 probe produced duplicate Wazuh alerts.'
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $probeDeadline)
    if ($probeHits.Count -ne 1) {
        throw 'The harmless Rule 100102 probe was not detected in time.'
    }
    $probeDetectedAt = [datetimeoffset]::Parse([string]$probeHits[0]._source.timestamp)
    $probeLatencySeconds = [math]::Round(($probeDetectedAt - $probeStartedAt).TotalSeconds,3)
    if ($probeLatencySeconds -lt -5 -or $probeLatencySeconds -gt 120) {
        throw 'The harmless Rule 100102 probe latency was outside the bounded READY window.'
    }

    $stage = 'take-registration'
    $takeId = New-SocTakeId
    $takeRecord = New-SocTakeRecord -TakeId $takeId `
        -ResponseMode $ResponseMode -LifetimeMinutes $TakeLifetimeMinutes
    [void](Write-SocTakeRecord -Record $takeRecord -RuntimeRoot $sessionPath)
    $shuffleAllow = Register-ShuffleSocTake `
        -TakeRecord $takeRecord `
        -OrgId ([string]$configuration.shuffle_org_id) `
        -ApiKey $shuffleApiKey `
        -BaseUri ([uri][string]$configuration.shuffle_api_base)
    $shuffleAllowRegistered = $true
    $takeRecord = Set-SocTakeStatus -RuntimeRoot $sessionPath -Status READY

    $stage = 'ready-evidence'
    $readyAt = [datetimeoffset]::UtcNow
    $readyEvidenceDirectory = Join-Path $EvidenceRoot "$takeId\soc"
    New-Item -ItemType Directory -Path $readyEvidenceDirectory -Force | Out-Null
    $readyEvidencePath = Join-Path $readyEvidenceDirectory '00-ready.json'
    $readyEvidence = [ordered]@{
        schema_version             = 1
        checked_at_utc             = $readyAt.ToString('o')
        session_id                 = $runtimeSessionId
        take_id                    = $takeId
        response_mode              = $ResponseMode
        daily_session_id           = [string]$dailySession.SessionId
        daily_hard_deadline_at_utc = ([datetimeoffset]$dailySession.HardDeadlineAtUtc).ToString('o')
        minimum_daily_remaining_minutes = $MinimumDailyRemainingMinutes
        runtime_profile            = 'minimal'
        security_scenario_profile  = 'capital-one-lab'
        dvwa_security_level        = 'low'
        wazuh_services_running     = $true
        wazuh_local_only_ports     = $true
        wazuh_rotated_auth         = $true
        bridge_pid                 = $bridgeProcess.Id
        bridge_state               = [string]$bridgeHeartbeat.state
        bridge_dlq_visible         = [int]$bridgeHeartbeat.dlq_visible
        bridge_queue_not_visible   = [int]$bridgeHeartbeat.queue_not_visible
        bridge_oldest_age_seconds  = [int]$bridgeHeartbeat.queue_oldest_age_seconds
        safe_probe_rule_id         = '100102'
        safe_probe_alert_count     = 1
        safe_probe_latency_seconds = $probeLatencySeconds
        shuffle_workflow_valid     = $true
        shuffle_workflow_stage     = $shuffleWorkflowStage
        shuffle_cloud_provenance   = if ($shuffleCloudProvenance) {
            [ordered]@{
                validator_app_id=[string]$shuffleCloudProvenance.validator_app_id
                dispatcher_app_id=[string]$shuffleCloudProvenance.dispatcher_app_id
                dispatcher_authentication_id_sha256=[string]$shuffleCloudProvenance.dispatcher_authentication_id_sha256
                authentication_active=[bool]$shuffleCloudProvenance.authentication_active
                authentication_field_keys=@($shuffleCloudProvenance.authentication_field_keys)
                secret_value_inspected=[bool]$shuffleCloudProvenance.secret_value_inspected
            }
        } else { $null }
        shuffle_gate_b5_evidence   = if ($gateB5Evidence) {
            [ordered]@{
                take_id=[string]$gateB5Evidence.TakeId
                manifest_sha256=[string]$gateB5Evidence.ManifestSha256
                workflow_core_sha256=[string]$gateB5Evidence.WorkflowCoreSha256
                completed_at_utc=[string]$gateB5Evidence.CompletedAtUtc
            }
        } else { $null }
        shuffle_allow_registered   = [bool]$shuffleAllow.registered
        shuffle_allow_verified     = [bool]$shuffleAllow.verified
        github_remote_main_sha     = [string]$githubState.Sha
        github_workflows_active    = $true
        argo_sync                  = [string]$argoState.Sync
        argo_health                = [string]$argoState.Health
        argo_revision              = [string]$argoState.Revision
        hardening_evidence_present = $true
        secrets_printed            = $false
        terraform_changed          = $false
        attack_executed            = $false
        github_write_executed      = $false
    }
    Write-SocAtomicJson -Path $readyEvidencePath -Value $readyEvidence

    Set-SocPrivateDirectoryAcl -Path $resolvedRuntimeRoot
    $activeSession = [ordered]@{
        schema_version       = 1
        session_id           = $runtimeSessionId
        status               = 'READY'
        started_at_utc       = $probeStartedAt.ToString('o')
        ready_at_utc         = $readyAt.ToString('o')
        session_path         = $sessionPath
        compose_files        = $composeFiles
        bridge_pid           = $bridgeProcess.Id
        heartbeat_path       = $heartbeatPath
        stop_signal_path     = $stopSignalPath
        bridge_lock_path     = $bridgeLockPath
        take_id              = $takeId
        response_mode        = $ResponseMode
        ready_evidence_path  = $readyEvidencePath
        hardening_evidence_path = $hardeningEvidencePath
        daily_hard_deadline_at_utc = ([datetimeoffset]$dailySession.HardDeadlineAtUtc).ToString('o')
    }
    Write-SocAtomicJson -Path $activeSessionPath -Value $activeSession

    $succeeded = $true
    Write-Host 'SOC_LAB_READY=yes'
    Write-Host "ACTIVE_TAKE_ID=$takeId"
    Write-Host "RESPONSE_MODE=$ResponseMode"
    Write-Host "READY_EVIDENCE=$readyEvidencePath"
} catch {
    $message = $_.Exception.Message
    if ($shuffleAllowRegistered -and $takeRecord -and $shuffleApiKey -and $configuration) {
        try {
            [void](Remove-ShuffleSocTake `
                -TakeId ([string]$takeRecord.take_id) `
                -OrgId ([string]$configuration.shuffle_org_id) `
                -ApiKey $shuffleApiKey `
                -BaseUri ([uri][string]$configuration.shuffle_api_base))
        } catch {}
    }
    if ($bridgeProcess) {
        try {
            if (-not $bridgeProcess.HasExited) {
                [IO.File]::WriteAllText($stopSignalPath,"stop`n",[Text.UTF8Encoding]::new($false))
                if (-not $bridgeProcess.WaitForExit(15000)) {
                    $bridgeProcess.Kill($true)
                    [void]$bridgeProcess.WaitForExit(5000)
                }
            }
        } catch {}
    }
    if ($composeStarted -and $composeFiles.Count -gt 0) {
        try {
            [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @('down') `
                -FailureMessage 'SOC failure cleanup could not stop Wazuh.')
        } catch {}
    }
    try { Remove-SocRuntimeSession -SessionId $runtimeSessionId -RuntimeRoot $resolvedRuntimeRoot } catch {}
    Remove-Item -LiteralPath $activeSessionPath -Force -ErrorAction SilentlyContinue
    throw "SOC startup failed at $stage. $message"
} finally {
    $adminPassword = $null
    $kibanaPassword = $null
    $apiPassword = $null
    $shuffleApiKey = $null
    $shuffleWebhookUrl = $null
    $shuffleHeaderKey = $null
    if ($bridgeProcess) { $bridgeProcess.Dispose() }
    if (-not $succeeded) {
        Write-Warning 'No Terraform Apply, attack, or GitHub write was performed by Start-SocLab.'
    }
}
