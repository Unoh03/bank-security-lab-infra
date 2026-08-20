#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('detection_only','full')]
    [string]$Scope = 'detection_only',
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
$Scope = $Scope.ToLowerInvariant()
$ResponseMode = $ResponseMode.ToLowerInvariant()

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$foundationRoot = Join-Path $repositoryRoot 'foundation'
$expectedAccountId = '433048100798'
$expectedRegion = 'ap-northeast-2'
$sshHost = 'bas'
$moduleRoot = Join-Path $repositoryRoot 'automation'

Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Wazuh.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
if ($Scope -ceq 'full') {
    Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
}
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
Write-Host "Scope: $Scope"
Write-Host "Response mode: $ResponseMode"
if ($Scope -ceq 'full') {
    if ($ResponseMode -ceq 'observe_only') {
        Write-Host 'Read-only preflight: Daily, DVWA, Shuffle, Foundation.'
        Write-Host 'Runtime actions: local Wazuh/Bridge start, harmless Rule 100102 probe, local TAKE/session only.'
        Write-Host 'Skipped in OBSERVE_ONLY: GitHub, Argo CD, Shuffle Datastore TAKE registration.'
    } else {
        Write-Host 'Read-only preflight: Daily, DVWA, Shuffle, GitHub, Argo CD, Foundation.'
        Write-Host 'Runtime actions: local Wazuh/Bridge start, harmless Rule 100102 probe, TAKE allow registration.'
    }
} else {
    Write-Host 'Read-only preflight: Daily, DVWA, Foundation.'
    Write-Host 'Runtime actions: local Wazuh/Bridge start and harmless Rule 100102 probe.'
}
Write-Host "Required Daily runtime remaining: at least $MinimumDailyRemainingMinutes minutes."
Write-Host 'Excluded: Terraform Apply/Destroy, real attack, GitHub write, Reset.'
if ($ConfirmStart -cne 'START SOC LAB') {
    throw "Preview only. Re-run with -ConfirmStart 'START SOC LAB'."
}
if ($ResponseMode -ceq 'contain' -and $Scope -cne 'full') {
    throw 'Contain response mode requires -Scope full.'
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

function Get-SocQueueUrl {
    param(
        [Parameter(Mandatory)][string]$OutputName,
        [Parameter(Mandatory)][string]$TransportProperty,
        [Parameter(Mandatory)][object]$Transport
    )

    try {
        $value = Get-SocTerraformRaw -Root $foundationRoot -Name $OutputName
        if ($value) { return $value }
    } catch {
        # The output may be absent in an older Foundation state. Derive it
        # from the already-verified transport ARN without changing AWS state.
    }
    $arn = [string]$Transport.$TransportProperty
    if ($arn -notmatch '^arn:aws:sqs:([a-z0-9-]+):([0-9]{12}):([A-Za-z0-9_-]+)$') {
        throw "The Foundation transport does not expose a safe $TransportProperty ARN."
    }
    if ($Matches[1] -cne $expectedRegion -or $Matches[2] -cne $expectedAccountId) {
        throw "The Foundation $TransportProperty ARN is outside the fixed SOC account or region."
    }
    return "https://sqs.$($Matches[1]).amazonaws.com/$($Matches[2])/$($Matches[3])"
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
        [Parameter(Mandatory)][string]$ExpectedApi,
        [ValidateSet('detection_only','full')]
        [string]$Scope = 'full'
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
    $expectedTargets = @('/wazuh-config-mount/etc/ossec.conf','/var/ossec/wazuh-push/dvwa')
    if ($Scope -ceq 'full') {
        $expectedTargets += @(
            '/soc-bootstrap/custom-shuffle-soc',
            '/var/ossec/soc-secrets/shuffle_webhook_url',
            '/var/ossec/soc-secrets/shuffle_webhook_header_key'
        )
    }
    foreach ($target in $expectedTargets) {
        if (-not $mountByTarget.ContainsKey($target) -or
            [bool]$mountByTarget[$target].read_only -ne $true) {
            throw "The effective SOC Compose lost a read-only SOC mount: $target"
        }
    }
    if ($Scope -ceq 'detection_only') {
        foreach ($target in @(
            '/soc-bootstrap/custom-shuffle-soc',
            '/var/ossec/soc-secrets/shuffle_webhook_url',
            '/var/ossec/soc-secrets/shuffle_webhook_header_key'
        )) {
            if ($mountByTarget.ContainsKey($target)) {
                throw "The Detection-only Compose unexpectedly contains a Full SOC mount: $target"
            }
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

function Get-SocWazuhPreflightRuntimeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComposePath,
        [scriptblock]$ComposeAdapter = $null,
        [scriptblock]$InspectAdapter = $null
    )

    $services = @('wazuh.manager','wazuh.indexer','wazuh.dashboard')
    $records = [Collections.Generic.List[object]]::new()
    foreach ($service in $services) {
        $idsText = if ($null -ne $ComposeAdapter) {
            & $ComposeAdapter -File @($ComposePath) -Arguments @('ps','-a','-q',$service)
        } else {
            Invoke-SocComposeCapture -File @($ComposePath) `
                -Arguments @('ps','-a','-q',$service) `
                -FailureMessage "The existing Wazuh container state is unavailable: $service"
        }
        $ids = @([string]$idsText -split "`r?`n" | ForEach-Object {
            $_.Trim()
        } | Where-Object { $_ })
        if ($ids.Count -gt 1) {
            throw "The existing Wazuh runtime contains duplicate containers for $service."
        }
        if ($ids.Count -eq 0) {
            $records.Add([pscustomobject]@{ Service=$service; State='absent'; ContainerId=$null })
            continue
        }
        if ([string]$ids[0] -notmatch '^[a-f0-9]{12,64}$') {
            throw "The existing Wazuh runtime returned an unsafe container ID for $service."
        }
        $stateText = if ($null -ne $InspectAdapter) {
            & $InspectAdapter -ContainerId ([string]$ids[0])
        } else {
            Invoke-SocNativeCapture -FilePath 'docker' -Arguments @(
                'inspect','--format','{{.State.Status}}',[string]$ids[0]
            ) -FailureMessage "The existing Wazuh container state is unavailable: $service"
        }
        $state = ([string]$stateText).Trim().ToLowerInvariant()
        if ($state -notin @('running','created','exited','dead','paused')) {
            throw "The existing Wazuh runtime has an unsupported $service state: $state"
        }
        $records.Add([pscustomobject]@{
            Service=$service; State=$state; ContainerId=[string]$ids[0]
        })
    }

    $running = @($records | Where-Object { $_.State -ceq 'running' })
    if ($running.Count -eq $services.Count) {
        return [pscustomobject]@{ Mode='running'; Records=@($records) }
    }
    $absent = @($records | Where-Object { $_.State -ceq 'absent' })
    $stopped = @($records | Where-Object {
        $_.State -in @('created','exited','dead')
    })
    if ($running.Count -eq 0 -and
        ($absent.Count -eq $services.Count -or $stopped.Count -eq $services.Count)) {
        return [pscustomobject]@{ Mode='deferred_stopped_runtime'; Records=@($records) }
    }
    throw 'The existing Wazuh runtime is partial or mixed; refusing to infer a safe preflight state.'
}

function Set-SocIndexerInternalUsers {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][string]$InternalUsersText,
        [ValidateRange(30, 300)][int]$TimeoutSeconds = 180
    )

    $desiredNames = @([regex]::Matches(
        $InternalUsersText,
        '(?m)^([A-Za-z0-9_.-]+):\s*$'
    ) | ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -cne '_meta' } | Sort-Object -Unique)
    if ($desiredNames.Count -eq 0) {
        throw 'The generated Wazuh internal-users file contains no users.'
    }

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $currentText = Invoke-SocComposeCapture -File $File -Arguments @(
                'exec','-T','wazuh.indexer','curl',
                '--silent','--show-error','--fail-with-body',
                '--cacert','/usr/share/wazuh-indexer/config/certs/root-ca.pem',
                '--cert','/usr/share/wazuh-indexer/config/certs/admin.pem',
                '--key','/usr/share/wazuh-indexer/config/certs/admin-key.pem',
                'https://wazuh.indexer:9200/_plugins/_security/api/internalusers'
            ) -FailureMessage 'The current Wazuh internal-user names are unavailable.'
            $currentDocument = $currentText | ConvertFrom-Json -AsHashtable
            $currentNames = @($currentDocument.Keys | Sort-Object)
            $currentText = $null
            if (($currentNames -join "`n") -cne ($desiredNames -join "`n")) {
                throw 'The runtime internal-users file would add or remove a Wazuh user.'
            }
            break
        } catch {
            if ($_.Exception.Message -match 'would add or remove') { throw }
            if ([datetimeoffset]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Seconds 5
        }
    } while ($true)

    $securityOutput = Invoke-SocComposeCapture -File $File -Arguments @(
        'exec','-T','-e','OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk',
        'wazuh.indexer','bash',
        '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh',
        '-f','/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml',
        '-t','internalusers','-nhnv',
        '-cacert','/usr/share/wazuh-indexer/config/certs/root-ca.pem',
        '-cert','/usr/share/wazuh-indexer/config/certs/admin.pem',
        '-key','/usr/share/wazuh-indexer/config/certs/admin-key.pem',
        '-p','9200','-icl'
    ) -FailureMessage 'The bounded Wazuh internal-users update failed.'
    try {
        if ($securityOutput -notmatch "Configuration for 'internalusers' created or updated") {
            throw 'The Wazuh internal-users update returned an unexpected result.'
        }
    } finally {
        $securityOutput = $null
    }
}

function Wait-SocManagerInternalReady {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [ValidateRange(30, 300)][int]$TimeoutSeconds = 180
    )

    $required = @(
        'wazuh-modulesd is running',
        'wazuh-logcollector is running',
        'wazuh-analysisd is running',
        'wazuh-integratord is running',
        'wazuh-apid is running'
    )
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $status = Invoke-SocComposeCapture -File $File -Arguments @(
                'exec','-T','wazuh.manager','sh','-c',
                '/var/ossec/bin/wazuh-control status || true'
            ) -FailureMessage 'The Wazuh internal daemon status is unavailable.'
            $missing = @($required | Where-Object {
                $status -notmatch [regex]::Escape($_)
            })
            if ($missing.Count -eq 0) { return }
        } catch {
            # The manager can reject exec briefly while its internal init runs.
        }
        Start-Sleep -Seconds 5
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw 'The required Wazuh manager daemons did not become ready in time.'
}

function Assert-SocFilebeatOutput {
    param([Parameter(Mandatory)][string[]]$File)

    $output = Invoke-SocComposeCapture -File $File -Arguments @(
        'exec','-T','wazuh.manager',
        '/usr/share/filebeat/bin/filebeat','test','output',
        '-c','/etc/filebeat/filebeat.yml'
    ) -FailureMessage 'Wazuh Filebeat could not authenticate to the indexer.'
    try {
        if ($output -notmatch '(?im)^\s*talk to server\.\.\.\s*OK\s*$') {
            throw 'Wazuh Filebeat did not prove a successful indexer connection.'
        }
    } finally {
        $output = $null
    }
}

function Invoke-SocLoopbackRequest {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [AllowNull()][object]$Body = $null,
        [switch]$AllowObserveOnlyPassword
    )

    if ($Uri.Scheme -cne 'https' -or $Uri.Host -cne '127.0.0.1' -or
        $Uri.Port -notin @(9200,55000)) {
        throw 'A Wazuh local request escaped the fixed loopback endpoints.'
    }
    $knownDefaultCredential = (
        ($UserName -ceq 'admin' -and $Password -ceq ('Secret' + 'Password')) -or
        ($UserName -ceq 'kibanaserver' -and $Password -ceq ('kibana' + 'server')) -or
        ($UserName -ceq 'wazuh-wui' -and $Password -ceq ('MyS3cr37P450r.' + '*-'))
    )
    if ($UserName -notin @('admin','kibanaserver','wazuh-wui') -or
        ($Password -notmatch $(if ($AllowObserveOnlyPassword) {
                '^[A-Za-z0-9.*+?\-]{8,64}$'
            } else {
                '^[A-Za-z0-9.*+?\-]{24,64}$'
            }) -and
         -not $knownDefaultCredential)) {
        throw 'A Wazuh local request credential violates the generated-secret contract.'
    }

    $containerHost = if ($Uri.Port -eq 9200) { 'wazuh.indexer' } else { 'localhost' }
    $certificatePath = if ($Uri.Port -eq 9200) {
        '/etc/ssl/root-ca.pem'
    } else {
        '/var/ossec/api/configuration/ssl/server.crt'
    }
    $targetUri = "https://${containerHost}:$($Uri.Port)$($Uri.PathAndQuery)"
    $arguments = [Collections.Generic.List[string]]::new()
    $arguments.Add('compose')
    foreach ($path in $File) {
        $arguments.Add('-f')
        $arguments.Add($path)
    }
    foreach ($argument in @(
        'exec','-T','wazuh.manager','curl',
        '--silent','--show-error','--no-progress-meter',
        '--cacert',$certificatePath,
        '--connect-timeout','5','--max-time','20',
        '--output','-','--write-out',"`n%{http_code}",
        '--config','-'
    )) {
        $arguments.Add($argument)
    }
    if ($Method -ceq 'POST') {
        $arguments.Add('--request')
        $arguments.Add('POST')
    }
    if ($null -ne $Body) {
        $arguments.Add('--header')
        $arguments.Add('Content-Type: application/json')
        $arguments.Add('--data-binary')
        $arguments.Add(($Body | ConvertTo-Json -Depth 30 -Compress))
    }
    $arguments.Add($targetUri)

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'docker'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = $null
    $stderr = $null
    try {
        if (-not $process.Start()) {
            throw 'The bounded Wazuh container request could not start.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine("user = `"${UserName}:$Password`"")
        $process.StandardInput.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $stdout.Length -gt 8388624) {
            throw 'The bounded Wazuh container request failed.'
        }
        $separatorIndex = $stdout.LastIndexOf("`n")
        if ($separatorIndex -lt 0) {
            throw 'The bounded Wazuh container response has no status line.'
        }
        $statusText = $stdout.Substring($separatorIndex + 1).Trim()
        if ($statusText -notmatch '^[0-9]{3}$') {
            throw 'The bounded Wazuh container response has an invalid status line.'
        }
        return [pscustomobject]@{
            StatusCode = [int]$statusText
            Text       = $stdout.Substring(0,$separatorIndex)
        }
    } catch {
        throw 'A fixed Wazuh loopback request failed.'
    } finally {
        $stdout = $null
        $stderr = $null
        $process.Dispose()
    }
}

function Test-SocLoopbackBasicAuth {
    param(
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [ValidateSet('GET','POST')][string]$Method = 'GET',
        [switch]$AllowObserveOnlyPassword
    )

    $response = Invoke-SocLoopbackRequest `
        -File $File `
        -Method $Method `
        -Uri $Uri `
        -UserName $UserName `
        -Password $Password `
        -AllowObserveOnlyPassword:$AllowObserveOnlyPassword
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
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$AdminPassword,
        [switch]$AllowObserveOnlyPassword
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
        -File $File `
        -Method POST `
        -Uri 'https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search' `
        -UserName admin `
        -Password $AdminPassword `
        -Body $query `
        -AllowObserveOnlyPassword:$AllowObserveOnlyPassword
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

function Get-SocJsonRequiredProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "The Wazuh hardening Evidence is missing required property: $Name"
    }
    return $property.Value
}

function Get-SocJsonStringProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonRequiredProperty -Object $Object -Name $Name
    if ($value -isnot [string]) {
        throw "The Wazuh hardening Evidence property is not a JSON string: $Name"
    }
    return [string]$value
}

function Get-SocJsonTimestampText {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonRequiredProperty -Object $Object -Name $Name
    if ($value -is [string]) { return [string]$value }
    # ConvertFrom-Json on PowerShell 7.4 may materialize ISO JSON strings as
    # DateTime. The file-level reader still checks that the source token was a
    # quoted JSON string before accepting this compatibility representation.
    if ($value -is [datetimeoffset]) { return $value.ToString('o') }
    if ($value -is [datetime]) { return ([datetimeoffset]$value.ToUniversalTime()).ToString('o') }
    throw "The Wazuh hardening Evidence property is not a JSON timestamp: $Name"
}

function Get-SocJsonBooleanProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonRequiredProperty -Object $Object -Name $Name
    if ($value -isnot [bool]) {
        throw "The Wazuh hardening Evidence property is not a JSON Boolean: $Name"
    }
    return [bool]$value
}

function Get-SocJsonIntegerProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonRequiredProperty -Object $Object -Name $Name
    if ($value -is [bool] -or $value -isnot [ValueType] -or
        [string]$value.GetType().Name -notmatch '^(Byte|SByte|Int16|UInt16|Int32|UInt32|Int64|UInt64)$') {
        throw "The Wazuh hardening Evidence property is not a JSON integer: $Name"
    }
    return [int64]$value
}

function Get-SocJsonObjectProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonRequiredProperty -Object $Object -Name $Name
    if ($null -eq $value -or $value -is [string] -or $value -is [bool] -or
        $value -is [ValueType] -or $value -is [Array]) {
        throw "The Wazuh hardening Evidence property is not a JSON object: $Name"
    }
    return $value
}

function Assert-SocSha256Property {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-SocJsonStringProperty -Object $Object -Name $Name
    if ($value -cnotmatch '^[0-9a-f]{64}$') {
        throw "The Wazuh hardening Evidence property is not a lowercase SHA-256: $Name"
    }
}

function Assert-SocHardeningMutationSummary {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$ProducerMode
    )

    if ($ProducerMode -cnotin @('verify_existing','mutating_hardening')) {
        throw 'The Wazuh hardening mutation summary producer is not canonical.'
    }

    $summary = Get-SocJsonObjectProperty -Object $Record -Name 'mutation_summary'
    $requiredNames = @(
        'docker_mutations','credential_rotation_observed','wazuh_mutations',
        'compose_mutations','aws_mutations','shuffle_mutations','bridge_mutations'
    )
    $actualNames = @($summary.PSObject.Properties.Name | Sort-Object)
    if ((@($actualNames) -join '|') -cne (@($requiredNames | Sort-Object) -join '|')) {
        throw 'The Wazuh hardening mutation_summary property set is not frozen.'
    }
    foreach ($name in @(
        'docker_mutations','wazuh_mutations','compose_mutations',
        'aws_mutations','shuffle_mutations','bridge_mutations'
    )) {
        if ((Get-SocJsonIntegerProperty -Object $summary -Name $name) -lt 0) {
            throw "The Wazuh hardening mutation count is negative: $name"
        }
    }
    $rotationObserved = Get-SocJsonBooleanProperty -Object $summary -Name 'credential_rotation_observed'
    if ($ProducerMode -ceq 'verify_existing') {
        if ($rotationObserved -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'docker_mutations') -ne 0 -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'wazuh_mutations') -ne 0 -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'compose_mutations') -ne 0 -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'aws_mutations') -ne 0 -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'shuffle_mutations') -ne 0 -or
            (Get-SocJsonIntegerProperty -Object $summary -Name 'bridge_mutations') -ne 0) {
            throw 'verify_existing Evidence claims a mutation or credential rotation.'
        }
    } elseif (-not $rotationObserved) {
        throw 'Mutating Wazuh Evidence does not explicitly attest credential rotation.'
    }
}

function Assert-SocHardeningDpapiBinding {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$SecretRoot
    )

    $hashObject = Get-SocJsonObjectProperty -Object $Record -Name 'dpapi_record_sha256'
    $names = @(
        'wazuh_indexer_admin_password',
        'wazuh_indexer_kibanaserver_password',
        'wazuh_api_wui_password'
    )
    $actualNames = @($hashObject.PSObject.Properties.Name | Sort-Object)
    if ((@($actualNames) -join '|') -cne (@($names | Sort-Object) -join '|')) {
        throw 'The Wazuh hardening DPAPI hash property set is not frozen.'
    }
    foreach ($name in $names) {
        $expectedPath = Join-Path $SecretRoot "$name.dpapi.json"
        if (-not (Test-Path -LiteralPath $expectedPath -PathType Leaf)) {
            throw "The canonical DPAPI credential record is unavailable: $name"
        }
        $expectedHash = (Get-FileHash -LiteralPath $expectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $actualHash = Get-SocJsonStringProperty -Object $hashObject -Name $name
        if ($actualHash -cne $expectedHash -or $actualHash -cnotmatch '^[0-9a-f]{64}$') {
            throw "The Wazuh hardening DPAPI hash does not bind to the current record: $name"
        }
    }
}

function Assert-SocHardeningEvidenceRecord {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc
    )

    if ($Record -is [Array]) {
        throw 'The Wazuh hardening Evidence root must be one JSON object.'
    }
    if ((Get-SocJsonIntegerProperty -Object $Record -Name 'schema_version') -ne 1) {
        throw 'The Wazuh hardening Evidence schema_version is unsupported.'
    }
    $producerMode = Get-SocJsonStringProperty -Object $Record -Name 'producer_mode'
    if ($producerMode -cnotin @('verify_existing','mutating_hardening')) {
        throw 'The Wazuh hardening Evidence producer_mode is not approved.'
    }
    $checkedAtText = Get-SocJsonTimestampText -Object $Record -Name 'checked_at'
    try {
        $checkedAt = [datetimeoffset]::Parse(
            $checkedAtText,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    } catch {
        throw 'The Wazuh hardening Evidence checked_at is not a parseable timestamp.'
    }
    if ($checkedAt.Offset -ne [timespan]::Zero -or
        $checkedAt -gt [datetimeoffset]::UtcNow.AddMinutes(5) -or
        ([datetimeoffset]::UtcNow - $checkedAt).TotalMinutes -gt 30 -or
        $checkedAt -lt $NotBeforeUtc.ToUniversalTime()) {
        throw 'The Wazuh hardening Evidence checked_at is not a fresh UTC timestamp.'
    }
    $wazuhVersion = Get-SocJsonStringProperty -Object $Record -Name 'wazuh_version'
    $wazuhMajorVersion = Get-SocJsonIntegerProperty -Object $Record -Name 'wazuh_major_version'
    if ($wazuhVersion -cne '4.14.7' -or
        $wazuhVersion -notmatch '^4\.\d+\.\d+$' -or
        $wazuhMajorVersion -ne 4) {
        throw 'The Wazuh hardening Evidence version is unsupported.'
    }
    foreach ($name in @('local_only_ports','named_volumes_removed','named_volumes_identical_before_after','secrets_printed','wazuh_authentication_verified','wazuh_credential_rotation_observed')) {
        [void](Get-SocJsonBooleanProperty -Object $Record -Name $name)
    }
    if (-not (Get-SocJsonBooleanProperty -Object $Record -Name 'local_only_ports') -or
        (Get-SocJsonBooleanProperty -Object $Record -Name 'named_volumes_removed') -or
        -not (Get-SocJsonBooleanProperty -Object $Record -Name 'named_volumes_identical_before_after') -or
        (Get-SocJsonBooleanProperty -Object $Record -Name 'secrets_printed') -or
        -not (Get-SocJsonBooleanProperty -Object $Record -Name 'wazuh_authentication_verified')) {
        throw 'The Wazuh hardening Evidence does not prove the required safe runtime state.'
    }
    $rotationObserved = Get-SocJsonBooleanProperty -Object $Record -Name 'wazuh_credential_rotation_observed'
    $runtimeSessionId = Get-SocJsonStringProperty -Object $Record -Name 'runtime_session_id'
    $activeStateProvenance = Get-SocJsonStringProperty -Object $Record -Name 'active_state_provenance'
    if ($producerMode -ceq 'verify_existing' -and $rotationObserved) {
        throw 'verify_existing Evidence cannot claim credential rotation.'
    }
    if ($producerMode -ceq 'mutating_hardening' -and -not $rotationObserved) {
        throw 'Mutating Evidence must explicitly claim observed credential rotation.'
    }
    if ($producerMode -ceq 'verify_existing') {
        if ($runtimeSessionId -cnotmatch '^wazuh-hardening-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$' -or
            $activeStateProvenance -cne 'not_written_verify_only') {
            throw 'verify_existing Evidence has non-canonical runtime session semantics.'
        }
        if (-not (Get-SocJsonBooleanProperty -Object $Record -Name 'named_volumes_identical_before_after')) {
            throw 'verify_existing Evidence does not attest identical named volumes.'
        }
        if ((Get-SocJsonRequiredProperty -Object $Record -Name 'active_state_path') -ne $null) {
            throw 'verify_existing Evidence must not point to a mutable runtime secret state file.'
        }
        if ((Get-SocJsonStringProperty -Object $Record -Name 'credential_provenance') -cne
            'canonical DPAPI CurrentUser records; values decrypted in memory only') {
            throw 'verify_existing Evidence has unexpected credential provenance.'
        }
    } else {
        if ($runtimeSessionId -cnotmatch '^wazuh-hardening-[0-9]{8}T[0-9]{6}Z(?:-[0-9a-f]{8})?$' -or
            $activeStateProvenance -cne 'protected_runtime_state_written') {
            throw 'Mutating Evidence has non-canonical runtime session semantics.'
        }
        $activeState = Get-SocJsonRequiredProperty -Object $Record -Name 'active_state_path'
        if ($activeState -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$activeState)) {
            throw 'Mutating Evidence must identify its protected active state file.'
        }
    }
    foreach ($name in @(
        'new_admin_authentication','default_admin_authentication',
        'new_kibanaserver_authentication','default_kibana_authentication',
        'new_wazuh_wui_authentication','default_wazuh_wui_authentication'
    )) {
        $value = Get-SocJsonStringProperty -Object $Record -Name $name
        if (($name -like 'new_*' -and $value -cne 'accepted') -or
            ($name -like 'default_*' -and $value -cne 'rejected')) {
            throw "The Wazuh hardening authentication result is not frozen: $name"
        }
    }
    foreach ($name in @(
        'runtime_container_set_sha256','published_ports_sha256',
        'named_volumes_before_sha256','named_volumes_after_sha256',
        'authentication_results_sha256'
    )) {
        Assert-SocSha256Property -Object $Record -Name $name
    }
    if ((Get-SocJsonStringProperty -Object $Record -Name 'named_volumes_before_sha256') -cne
        (Get-SocJsonStringProperty -Object $Record -Name 'named_volumes_after_sha256')) {
        throw 'The named-volume before/after hashes are not equal.'
    }
    $volumeFingerprint = Get-SocJsonObjectProperty -Object $Record -Name 'named_volume_fingerprint'
    if ((Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'algorithm') -cne 'sha256' -or
        (Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'equality') -cne
            'exact named-volume set and identity metadata before/after' -or
        (Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'source') -cne
            'docker inspect Mounts + docker volume inspect (read-only)') {
        throw 'The named-volume fingerprint semantics are not frozen.'
    }
    $fingerprintFields = @('Service','Source','Target','ReadOnly','IdentityName','Driver','Scope','CreatedAt','MountpointSha256','Mode','Propagation','OptionsSha256','LabelsSha256')
    $actualFingerprintFields = @((Get-SocJsonRequiredProperty -Object $volumeFingerprint -Name 'fields') | ForEach-Object { [string]$_ })
    if ((@($actualFingerprintFields) -join '|') -cne (@($fingerprintFields) -join '|')) {
        throw 'The named-volume fingerprint field set is not frozen.'
    }
    Assert-SocSha256Property -Object $volumeFingerprint -Name 'before_sha256'
    Assert-SocSha256Property -Object $volumeFingerprint -Name 'after_sha256'
    if ((Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'before_sha256') -cne
            (Get-SocJsonStringProperty -Object $Record -Name 'named_volumes_before_sha256') -or
        (Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'after_sha256') -cne
            (Get-SocJsonStringProperty -Object $Record -Name 'named_volumes_after_sha256') -or
        (Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'before_sha256') -cne
            (Get-SocJsonStringProperty -Object $volumeFingerprint -Name 'after_sha256')) {
        throw 'The named-volume fingerprint hashes do not bind to the Evidence fields.'
    }
    $compose = Get-SocJsonObjectProperty -Object $Record -Name 'compose_provenance'
    if ((Get-SocJsonStringProperty -Object $compose -Name 'source') -cne 'docker inspect compose labels (read-only)' -or
        (Get-SocJsonStringProperty -Object $compose -Name 'project') -cne 'single-node') {
        throw 'The Wazuh hardening Compose provenance is not frozen.'
    }
    foreach ($name in @('working_dir_sha256','config_files_sha256')) {
        Assert-SocSha256Property -Object $compose -Name $name
    }
    if ((Get-SocJsonIntegerProperty -Object $compose -Name 'config_file_count') -lt 1) {
        throw 'The Wazuh hardening Compose provenance has no config files.'
    }
    Assert-SocHardeningMutationSummary -Record $Record -ProducerMode $producerMode
    Assert-SocHardeningDpapiBinding -Record $Record -SecretRoot $SecretRoot
    return $producerMode
}

function Read-SocHardeningEvidence {
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$ExpectedRuntimeSessionId,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc
    )

    $root = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) 'soc-lab-hardening'
    $path = [IO.Path]::GetFullPath($EvidencePath)
    if ((Split-Path -Parent $path) -ine $root -or
        [IO.Path]::GetFileName($path) -cnotmatch '^wazuh-hardening-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.json$' -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'The fresh Wazuh hardening Evidence path is outside the exact approved directory or shape.'
    }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The fresh Wazuh hardening Evidence does not match its exact returned SHA-256.'
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    try {
        $actualSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
        if ($actualSha256 -cne $ExpectedSha256) {
            throw 'The fresh Wazuh hardening Evidence does not match its exact returned SHA-256.'
        }
        try {
            $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            if ($raw -notmatch '(?m)"checked_at"\s*:\s*"([^"]+)"') {
                throw 'checked_at is not a quoted JSON string'
            }
            $checkedAtText = [string]$Matches[1]
            $record = $raw | ConvertFrom-Json -Depth 30
            if ($record -is [Array]) { throw 'array root' }
            [void](Get-SocJsonTimestampText -Object $record -Name 'checked_at')
            $checkedAt = [datetimeoffset]::Parse(
                $checkedAtText,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            if ($checkedAt.Offset -ne [timespan]::Zero) { throw 'non-UTC timestamp' }
        } catch {
            throw 'The exact Wazuh hardening Evidence is malformed or lacks a UTC checked_at.'
        }
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    $producerMode = Assert-SocHardeningEvidenceRecord `
        -Record $record `
        -SecretRoot ([IO.Path]::GetFullPath($SecretRoot)) `
        -NotBeforeUtc $NotBeforeUtc
    $runtimeSessionId = Get-SocJsonStringProperty -Object $record -Name 'runtime_session_id'
    if ($producerMode -cne 'verify_existing' -or
        $runtimeSessionId -cne $ExpectedRuntimeSessionId -or
        [IO.Path]::GetFileName($path) -cne "$runtimeSessionId.json") {
        throw 'The exact Wazuh hardening Evidence does not bind to the fresh verify_existing result.'
    }
    return [pscustomobject]@{
        Path = $path
        Sha256 = $ExpectedSha256
        Record = $record
        ProducerMode = $producerMode
        CheckedAt = $checkedAt
    }
}

function Invoke-SocFreshHardeningEvidence {
    param(
        [Parameter(Mandatory)][string]$WazuhRoot,
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc
    )

    $runnerPath = Join-Path $repositoryRoot 'tools\Test-SocWazuhHardeningRuntime.ps1'
    if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
        throw 'The verify-only Wazuh hardening runner is unavailable.'
    }
    $invocationStartedAtUtc = [datetimeoffset]::UtcNow
    $resultText = Invoke-SocNativeCapture `
        -FilePath (Get-Command pwsh -ErrorAction Stop).Source `
        -Arguments @(
            '-NoProfile','-File',$runnerPath,
            '-WazuhRoot',$WazuhRoot,
            '-SecretRoot',$SecretRoot,
            '-EvidenceRoot',$EvidenceRoot
        ) `
        -FailureMessage 'The fresh verify-only Wazuh hardening runtime check failed.'
    try {
        $result = $resultText | ConvertFrom-Json -Depth 8
    } catch {
        throw 'The fresh verify-only Wazuh hardening runner returned invalid JSON.'
    }
    if ($result -is [Array] -or
        (Get-SocJsonIntegerProperty -Object $result -Name 'schema_version') -ne 1 -or
        (Get-SocJsonStringProperty -Object $result -Name 'producer_mode') -cne 'verify_existing') {
        throw 'The fresh verify-only Wazuh hardening runner returned an invalid result contract.'
    }
    $runtimeSessionId = Get-SocJsonStringProperty -Object $result -Name 'runtime_session_id'
    $evidencePath = Get-SocJsonStringProperty -Object $result -Name 'evidence_path'
    $evidenceSha256 = Get-SocJsonStringProperty -Object $result -Name 'evidence_sha256'
    if ($runtimeSessionId -cnotmatch '^wazuh-hardening-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$' -or
        $evidenceSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The fresh verify-only Wazuh hardening runner returned unsafe identifiers.'
    }
    $minimumCheckedAtUtc = $NotBeforeUtc.ToUniversalTime()
    if ($invocationStartedAtUtc -gt $minimumCheckedAtUtc) {
        $minimumCheckedAtUtc = $invocationStartedAtUtc
    }
    return Read-SocHardeningEvidence `
        -EvidenceRoot $EvidenceRoot `
        -SecretRoot $SecretRoot `
        -EvidencePath $evidencePath `
        -ExpectedSha256 $evidenceSha256 `
        -ExpectedRuntimeSessionId $runtimeSessionId `
        -NotBeforeUtc $minimumCheckedAtUtc
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

function Get-SocBridgeFailureCategory {
    param(
        [Parameter(Mandatory)][string]$HeartbeatPath,
        [Parameter(Mandatory)][string]$StandardOutputPath,
        [Parameter(Mandatory)][string]$StandardErrorPath
    )

    # Persist only a bounded enum and numeric heartbeat counters. Never copy
    # Bridge stdout/stderr, queue URLs, ARNs, or AWS error text to Evidence.
    $heartbeat = $null
    if (Test-Path -LiteralPath $HeartbeatPath -PathType Leaf) {
        try { $heartbeat = Get-Content -LiteralPath $HeartbeatPath -Raw | ConvertFrom-Json } catch { $heartbeat = $null }
    }
    $metrics = [ordered]@{
        observed = ($null -ne $heartbeat)
        queue_visible = -1
        queue_not_visible = -1
        queue_oldest_age_seconds = -1
        dlq_visible = -1
    }
    if ($null -ne $heartbeat) {
        foreach ($name in @('queue_visible','queue_not_visible','queue_oldest_age_seconds','dlq_visible')) {
            try { $metrics[$name] = [int]$heartbeat.$name } catch { $metrics[$name] = -1 }
        }
        if ($metrics.dlq_visible -gt 0) { return [pscustomobject]@{ category = 'dlq_nonempty'; metrics = $metrics } }
        if ($metrics.queue_not_visible -gt 0) { return [pscustomobject]@{ category = 'inflight_nonzero'; metrics = $metrics } }
        if ($metrics.queue_visible -gt 0 -and $metrics.queue_oldest_age_seconds -gt 120) {
            return [pscustomobject]@{ category = 'stale_primary_backlog'; metrics = $metrics }
        }
    }

    $diagnosticText = ''
    foreach ($path in @($StandardOutputPath,$StandardErrorPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try { $diagnosticText += "`n" + ((Get-Content -LiteralPath $path -Tail 40 -ErrorAction Stop) -join "`n") } catch {}
        }
    }
    if ($diagnosticText -match 'DLQ is not empty|DLQ became non-empty|Primary Push DLQ') {
        return [pscustomobject]@{ category = 'dlq_nonempty'; metrics = $metrics }
    }
    if ($diagnosticText -match 'in-flight message|queue_not_visible') {
        return [pscustomobject]@{ category = 'inflight_nonzero'; metrics = $metrics }
    }
    if ($diagnosticText -match 'stale messages|queue contains stale|oldest age') {
        return [pscustomobject]@{ category = 'stale_primary_backlog'; metrics = $metrics }
    }
    if ($diagnosticText -match 'already holds the local spool lock|spool lock') {
        return [pscustomobject]@{ category = 'lock_held'; metrics = $metrics }
    }
    if ($diagnosticText -match 'AWS CLI request failed|AssumeRole|STS|temporary AWS identity') {
        return [pscustomobject]@{ category = 'aws_request_failed'; metrics = $metrics }
    }
    return [pscustomobject]@{ category = 'unknown'; metrics = $metrics }
}

function Write-SocBridgeFailureEvidence {
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$RuntimeSessionId,
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][object]$Failure
    )

    $directory = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) 'soc-lab-failures'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $timestamp = [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $path = Join-Path $directory "soc-failure-$timestamp-$RuntimeSessionId.json"
    $value = [ordered]@{
        schema_version = 1
        checked_at_utc = [datetimeoffset]::UtcNow.ToString('o')
        session_id = $RuntimeSessionId
        stage = $Stage
        category = [string]$Failure.category
        heartbeat = [ordered]@{
            observed = [bool]$Failure.metrics.observed
            queue_visible = [int]$Failure.metrics.queue_visible
            queue_not_visible = [int]$Failure.metrics.queue_not_visible
            queue_oldest_age_seconds = [int]$Failure.metrics.queue_oldest_age_seconds
            dlq_visible = [int]$Failure.metrics.dlq_visible
        }
    }
    Write-SocAtomicJson -Path $path -Value $value
    return $path
}

function ConvertTo-SocProcessArgument {
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
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
$allowObserveOnlyPassword = $false
$takeRecord = $null
$shuffleAllowRegistered = $false
$configuration = $null
$shuffleWorkflowStage = 'not_checked'
$preflightHardeningMode = 'not_checked'
$gateB5Evidence = $null
$shuffleCloudProvenance = $null
$githubState = $null
$argoState = $null

try {
    if (Test-Path -LiteralPath $activeSessionPath -PathType Leaf) {
        throw 'An active or unclean SOC session exists. Run Stop-SocLab before starting another session.'
    }
    $requiredCommands = @('terraform','aws','docker','pwsh')
    if ($Scope -ceq 'full' -and $ResponseMode -ceq 'contain') { $requiredCommands += @('gh','ssh') }
    foreach ($name in $requiredCommands) {
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

    $configuration = if ($Scope -ceq 'full') {
        Read-SocLabConfiguration -Root $ConfigurationRoot
    } else {
        # Detection-only deliberately has no Shuffle, GitHub, or Argo
        # configuration dependency. These two values are fixed lab inputs.
        [pscustomobject]@{
            wazuh_root = 'D:\Wazuh\wazuh-docker\single-node'
            aws_profile = 'terra-user'
        }
    }
    $wazuhRoot = [IO.Path]::GetFullPath([string]$configuration.wazuh_root)
    $baseComposePath = Join-Path $wazuhRoot 'docker-compose.yml'
    $internalUsersSourcePath = Join-Path $wazuhRoot 'config\wazuh_indexer\internal_users.yml'
    $dashboardSourcePath = Join-Path $wazuhRoot 'config\wazuh_dashboard\wazuh.yml'
    $managerSourcePath = Join-Path $wazuhRoot 'config\wazuh_cluster\wazuh_manager.conf'
    $portOverridePath = Join-Path $repositoryRoot 'observability\wazuh\docker-compose.soc.override.yml'
    $integrationScriptPath = Join-Path $repositoryRoot 'observability\wazuh\integrations\custom-shuffle-soc'
    $integrationXmlPath = Join-Path $repositoryRoot 'observability\wazuh\templates\shuffle-integration.xml'
    $bridgeSpoolDirectory = Join-Path $EvidenceRoot 'wazuh-push-shadow\dvwa'
    $bridgeLiveFilePath = Join-Path $bridgeSpoolDirectory 'wazuh-push-live.jsonl'
    $bridgeLockPath = Join-Path $bridgeSpoolDirectory 'wazuh-push-bridge.lock'
    $startupPaths = @(
        $baseComposePath,$internalUsersSourcePath,$dashboardSourcePath,
        $managerSourcePath,$portOverridePath
    )
    if ($Scope -ceq 'full') { $startupPaths += @($integrationScriptPath,$integrationXmlPath) }
    foreach ($path in $startupPaths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required SOC startup input is unavailable: $path"
        }
    }
    $requiredSecrets = @(
        'wazuh_indexer_admin_password','wazuh_indexer_kibanaserver_password',
        'wazuh_api_wui_password'
    )
    if ($Scope -ceq 'full') {
        $requiredSecrets += @('shuffle_webhook_header_key','shuffle_api_key','shuffle_webhook_url')
    }
    foreach ($secretName in $requiredSecrets) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedSecretRoot "$secretName.dpapi.json") -PathType Leaf)) {
            throw "Protected SOC secret is unavailable: $secretName"
        }
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
    $preflightRuntimeState = Get-SocWazuhPreflightRuntimeState `
        -ComposePath $baseComposePath
    if ([string]$preflightRuntimeState.Mode -ceq 'running') {
        $hardeningEvidence = Invoke-SocFreshHardeningEvidence `
            -WazuhRoot $wazuhRoot `
            -EvidenceRoot $EvidenceRoot `
            -SecretRoot $resolvedSecretRoot `
            -NotBeforeUtc ([datetimeoffset]$dailySession.StartedAtUtc)
        $preflightHardeningMode = 'verified_existing'
    } else {
        $hardeningEvidence = $null
        $preflightHardeningMode = 'deferred_stopped_runtime'
    }
    $hardeningEvidencePath = if ($hardeningEvidence) { [string]$hardeningEvidence.Path } else { $null }

    $identity = Invoke-SocNativeCapture -FilePath 'aws' -Arguments @(
        'sts','get-caller-identity','--profile',[string]$configuration.aws_profile,
        '--region',$expectedRegion,'--output','json','--no-cli-pager'
    ) -FailureMessage 'The fixed AWS identity could not be verified.' | ConvertFrom-Json
    if ([string]$identity.Account -cne $expectedAccountId) {
        throw 'The AWS account does not match the fixed SOC lab account.'
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
    $queueUrl = Get-SocQueueUrl -OutputName 'wazuh_push_primary_queue_url' -TransportProperty 'queue_arn' -Transport $transport
    $dlqUrl = Get-SocQueueUrl -OutputName 'wazuh_push_primary_dlq_url' -TransportProperty 'dlq_arn' -Transport $transport
    $readerRoleArn = Get-SocTerraformRaw -Root $foundationRoot -Name wazuh_log_reader_role_arn
    if ($queueUrl -notmatch "^https://sqs\.ap-northeast-2\.amazonaws\.com/${expectedAccountId}/[A-Za-z0-9_-]+$" -or
        $dlqUrl -notmatch "^https://sqs\.ap-northeast-2\.amazonaws\.com/${expectedAccountId}/[A-Za-z0-9_-]+$" -or
        $readerRoleArn -notmatch "^arn:aws:iam::${expectedAccountId}:role/[A-Za-z0-9+=,.@_-]+$") {
        throw 'A Foundation Queue, DLQ, or Reader Role output is unsafe.'
    }
    Assert-SocDvWaLow -BaseUri $applicationUrl

    $adminPassword = Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $resolvedSecretRoot
    $kibanaPassword = Unprotect-SocSecret -Name 'wazuh_indexer_kibanaserver_password' -SecretRoot $resolvedSecretRoot
    $apiPassword = Unprotect-SocSecret -Name 'wazuh_api_wui_password' -SecretRoot $resolvedSecretRoot
    if ($Scope -ceq 'full') {
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
            $webhookUri.AbsolutePath -notmatch "^/api/v1/(?:hooks/(?:webhook_)?$webhookId|webhooks/webhook_$webhookId)$") {
            throw 'The protected Shuffle Webhook URL does not match the configured trigger.'
        }
        if ($ResponseMode -ceq 'observe_only') {
            $shuffleWorkflow = Get-ShuffleSocObserveOnlyWorkflow `
                -WorkflowId ([string]$configuration.shuffle_workflow_id) `
                -WebhookId ([string]$configuration.shuffle_webhook_id) `
                -ExpectedHeaderValue $shuffleHeaderKey `
                -ApiKey $shuffleApiKey `
                -OrgId ([string]$configuration.shuffle_org_id) `
                -BaseUri ([uri][string]$configuration.shuffle_api_base)
            $shuffleWorkflowStage = 'observe_only'
        } else {
            $shuffleWorkflow = Get-ShuffleSocWorkflow `
                -WorkflowId ([string]$configuration.shuffle_workflow_id) `
                -WebhookId ([string]$configuration.shuffle_webhook_id) `
                -ApiKey $shuffleApiKey `
                -OrgId ([string]$configuration.shuffle_org_id) `
                -BaseUri ([uri][string]$configuration.shuffle_api_base)
            $shuffleWorkflowStage = 'core'
        }
    }
    $allowObserveOnlyPassword = ($ResponseMode -ceq 'observe_only')
    if ($Scope -ceq 'full' -and $ResponseMode -ceq 'contain') {
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
    if ($Scope -ceq 'full' -and $ResponseMode -ceq 'contain') {
        $githubState = Get-SocGithubState -Configuration $configuration
        $argoState = Get-SocArgoState -Configuration $configuration -ExpectedRevision $githubState.Sha
    }

    $stage = 'wazuh-runtime'
    New-Item -ItemType Directory -Path $bridgeSpoolDirectory -Force | Out-Null
    if (-not (Test-Path -LiteralPath $bridgeLiveFilePath -PathType Leaf)) {
        $liveStream = [IO.File]::Open(
            $bridgeLiveFilePath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read
        )
        $liveStream.Dispose()
    }
    $adminHash = Get-WazuhPasswordHash -Password $adminPassword `
        -AllowObserveOnlyPassword:$allowObserveOnlyPassword
    $kibanaHash = Get-WazuhPasswordHash -Password $kibanaPassword `
        -AllowObserveOnlyPassword:$allowObserveOnlyPassword
    $internalUsersText = Get-Content -LiteralPath $internalUsersSourcePath -Raw
    $internalUsersText = Set-WazuhInternalUserHashText `
        -Text $internalUsersText -UserName admin -Hash $adminHash
    $internalUsersText = Set-WazuhInternalUserHashText `
        -Text $internalUsersText -UserName kibanaserver -Hash $kibanaHash
    $dashboardText = Set-WazuhDashboardApiPasswordText `
        -Text (Get-Content -LiteralPath $dashboardSourcePath -Raw) `
        -Password $apiPassword `
        -AllowObserveOnlyPassword:$allowObserveOnlyPassword
    $managerText = if ($Scope -ceq 'full') {
        Add-WazuhManagerSocIntegrationText `
            -ManagerConfigText (Get-Content -LiteralPath $managerSourcePath -Raw) `
            -IntegrationXml (Get-Content -LiteralPath $integrationXmlPath -Raw)
    } else {
        Get-Content -LiteralPath $managerSourcePath -Raw
    }

    $internalUsersPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\internal_users.yml' -Content $internalUsersText -RuntimeRoot $resolvedRuntimeRoot
    $dashboardPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\wazuh.yml' -Content $dashboardText -RuntimeRoot $resolvedRuntimeRoot
    $managerPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'wazuh\ossec.conf' -Content $managerText -RuntimeRoot $resolvedRuntimeRoot
    $webhookPath = $null
    $headerPath = $null
    if ($Scope -ceq 'full') {
        $webhookPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
            -RelativePath 'secrets\shuffle_webhook_url' -Content "$shuffleWebhookUrl`n" -RuntimeRoot $resolvedRuntimeRoot
        $headerPath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
            -RelativePath 'secrets\shuffle_webhook_header_key' -Content "$shuffleHeaderKey`n" -RuntimeRoot $resolvedRuntimeRoot
    }
    $secretOverride = New-WazuhSecretOverrideText -Phase Final `
        -InternalUsersPath $internalUsersPath -AdminPassword $adminPassword `
        -KibanaserverPassword $kibanaPassword -ApiPassword $apiPassword `
        -DashboardConfigPath $dashboardPath `
        -AllowObserveOnlyPassword:$allowObserveOnlyPassword
    $secretOverridePath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'compose\docker-compose.secrets.yml' -Content $secretOverride -RuntimeRoot $resolvedRuntimeRoot
    $socOverride = if ($Scope -ceq 'full') {
        New-WazuhSocIntegrationOverrideText `
            -ManagerConfigPath $managerPath -IntegrationScriptPath $integrationScriptPath `
            -WebhookUrlPath $webhookPath -WebhookHeaderKeyPath $headerPath `
            -LiveSpoolPath $bridgeSpoolDirectory
    } else {
        New-WazuhDetectionOverrideText `
            -ManagerConfigPath $managerPath -LiveSpoolPath $bridgeSpoolDirectory
    }
    $socOverridePath = Write-SocRuntimeSecretFile -SessionId $runtimeSessionId `
        -RelativePath 'compose\docker-compose.soc.yml' -Content $socOverride -RuntimeRoot $resolvedRuntimeRoot
    $composeFiles = @($baseComposePath,$portOverridePath,$secretOverridePath,$socOverridePath)
    Assert-SocEffectiveCompose -File $composeFiles -ExpectedAdmin $adminPassword `
        -ExpectedKibana $kibanaPassword -ExpectedApi $apiPassword -Scope $Scope
    [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @('up','-d') `
        -FailureMessage 'The Wazuh SOC Compose stack could not start.')
    $composeStarted = $true
    Wait-SocComposeServices -File $composeFiles -TimeoutSeconds $ReadyTimeoutSeconds
    Set-SocIndexerInternalUsers -File $composeFiles `
        -InternalUsersText $internalUsersText -TimeoutSeconds $ReadyTimeoutSeconds
    if ($Scope -ceq 'full') {
        [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @(
            'exec','-T','--user','root','wazuh.manager','install',
            '-o','root','-g','wazuh','-m','0750',
            '/soc-bootstrap/custom-shuffle-soc',
            '/var/ossec/integrations/custom-shuffle-soc'
        ) -FailureMessage 'The Wazuh Shuffle integration could not be installed into the retained integration volume.')
    }
    [void](Invoke-SocComposeCapture -File $composeFiles -Arguments @(
        'exec','-T','wazuh.manager','/var/ossec/bin/wazuh-control','restart'
    ) -FailureMessage 'The Wazuh Manager daemons could not restart with the SOC integration.')
    Wait-SocManagerInternalReady -File $composeFiles -TimeoutSeconds $ReadyTimeoutSeconds
    Assert-SocFilebeatOutput -File $composeFiles
    $wazuhChecks = @(
        ,@('exec','-T','wazuh.manager','/var/ossec/bin/wazuh-analysisd','-t')
        ,@('exec','-T','wazuh.manager','/var/ossec/bin/wazuh-modulesd','-t')
    )
    if ($Scope -ceq 'full') {
        $wazuhChecks += ,@('exec','-T','wazuh.manager','test','-x','/var/ossec/integrations/custom-shuffle-soc')
    }
    foreach ($command in $wazuhChecks) {
        [void](Invoke-SocComposeCapture -File $composeFiles -Arguments $command `
            -FailureMessage 'The Wazuh Manager configuration, module, Rule, or integration test failed.')
    }
    if (-not (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:9200/' -UserName admin -Password $adminPassword `
            -AllowObserveOnlyPassword:$allowObserveOnlyPassword) -or
        -not (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:9200/_plugins/_security/authinfo' -UserName kibanaserver -Password $kibanaPassword `
            -AllowObserveOnlyPassword:$allowObserveOnlyPassword) -or
        -not (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:55000/security/user/authenticate?raw=true' -Method POST -UserName wazuh-wui -Password $apiPassword `
            -AllowObserveOnlyPassword:$allowObserveOnlyPassword)) {
        throw 'A Wazuh credential was rejected during the READY authentication verification.'
    }
    if (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:9200/' -UserName admin -Password ('Secret'+'Password')) {
        throw 'The Wazuh indexer accepted the official default admin credential.'
    }
    if (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:9200/_plugins/_security/authinfo' -UserName kibanaserver -Password ('kibana'+'server')) {
        throw 'The Wazuh indexer accepted the official default kibanaserver credential.'
    }
    if (Test-SocLoopbackBasicAuth -File $composeFiles -Uri 'https://127.0.0.1:55000/security/user/authenticate?raw=true' -Method POST -UserName wazuh-wui -Password ('MyS3cr37P450r.'+'*-')) {
        throw 'The Wazuh API accepted the official default wazuh-wui credential.'
    }
    # Re-bind READY to the runtime that exists after Compose and the bounded
    # internal-user update. The preflight Evidence cannot stand in for this
    # later container, port, volume-identity, and six-probe observation.
    $hardeningEvidence = Invoke-SocFreshHardeningEvidence `
        -WazuhRoot $wazuhRoot `
        -EvidenceRoot $EvidenceRoot `
        -SecretRoot $resolvedSecretRoot `
        -NotBeforeUtc ([datetimeoffset]$dailySession.StartedAtUtc)
    $hardeningEvidencePath = [string]$hardeningEvidence.Path

    $stage = 'bridge'
    $heartbeatPath = Join-Path $sessionPath 'bridge-heartbeat.json'
    $stopSignalPath = Join-Path $sessionPath 'bridge.stop'
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
    $bridgeArgumentLine = ($bridgeArguments | ForEach-Object {
        ConvertTo-SocProcessArgument -Value ([string]$_)
    }) -join ' '
    $bridgeProcess = Start-Process -FilePath (Get-Command pwsh).Source `
        -ArgumentList $bridgeArgumentLine -WindowStyle Hidden -PassThru `
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
        $probeHits = @(Get-SocWazuhProbeAlerts -File $composeFiles `
            -TakeId $probeTakeId -AdminPassword $adminPassword `
            -AllowObserveOnlyPassword:$allowObserveOnlyPassword)
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
    if ($Scope -ceq 'full' -and $ResponseMode -ceq 'contain') {
        $shuffleAllow = Register-ShuffleSocTake `
            -TakeRecord $takeRecord `
            -OrgId ([string]$configuration.shuffle_org_id) `
            -ApiKey $shuffleApiKey `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        $shuffleAllowRegistered = $true
    } else {
        $shuffleAllow = [pscustomobject]@{ registered = $false; verified = $false }
    }
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
        scope                      = $Scope
        response_mode              = $ResponseMode
        daily_session_id           = [string]$dailySession.SessionId
        daily_hard_deadline_at_utc = ([datetimeoffset]$dailySession.HardDeadlineAtUtc).ToString('o')
        minimum_daily_remaining_minutes = $MinimumDailyRemainingMinutes
        runtime_profile            = 'minimal'
        security_scenario_profile  = 'capital-one-lab'
        dvwa_security_level        = 'low'
        wazuh_services_running     = $true
        wazuh_local_only_ports     = $true
        wazuh_authentication_verified = $true
        wazuh_credential_rotation_observed = [bool]$hardeningEvidence.Record.wazuh_credential_rotation_observed
        wazuh_preflight_hardening     = $preflightHardeningMode
        bridge_pid                 = $bridgeProcess.Id
        bridge_state               = [string]$bridgeHeartbeat.state
        bridge_dlq_visible         = [int]$bridgeHeartbeat.dlq_visible
        bridge_queue_not_visible   = [int]$bridgeHeartbeat.queue_not_visible
        bridge_oldest_age_seconds  = [int]$bridgeHeartbeat.queue_oldest_age_seconds
        safe_probe_rule_id         = '100102'
        safe_probe_alert_count     = 1
        safe_probe_latency_seconds = $probeLatencySeconds
        shuffle_workflow_valid     = if ($Scope -ceq 'full') { $true } else { $false }
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
        github_remote_main_sha     = if ($githubState) { [string]$githubState.Sha } else { $null }
        github_workflows_active    = if ($githubState) { $true } else { $false }
        argo_sync                  = if ($argoState) { [string]$argoState.Sync } else { $null }
        argo_health                = if ($argoState) { [string]$argoState.Health } else { $null }
        argo_revision              = if ($argoState) { [string]$argoState.Revision } else { $null }
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
        scope                = $Scope
        shuffle_allow_registered = [bool]$shuffleAllowRegistered
        response_mode        = $ResponseMode
        ready_evidence_path  = $readyEvidencePath
        hardening_evidence_path = $hardeningEvidencePath
        daily_hard_deadline_at_utc = ([datetimeoffset]$dailySession.HardDeadlineAtUtc).ToString('o')
    }
    Write-SocAtomicJson -Path $activeSessionPath -Value $activeSession

    $succeeded = $true
    Write-Host 'SOC_LAB_READY=yes'
    Write-Host "SOC_SCOPE=$Scope"
    Write-Host "ACTIVE_TAKE_ID=$takeId"
    Write-Host "RESPONSE_MODE=$ResponseMode"
    Write-Host "READY_EVIDENCE=$readyEvidencePath"
} catch {
    $message = $_.Exception.Message
    $bridgeFailureCategory = $null
    $bridgeFailureEvidencePath = $null
    if ($stage -ceq 'bridge' -and $bridgeProcess) {
        try {
            $bridgeFailure = Get-SocBridgeFailureCategory `
                -HeartbeatPath $heartbeatPath `
                -StandardOutputPath $bridgeStdoutPath `
                -StandardErrorPath $bridgeStderrPath
            $bridgeFailureCategory = [string]$bridgeFailure.category
            $bridgeFailureEvidencePath = Write-SocBridgeFailureEvidence `
                -EvidenceRoot $EvidenceRoot `
                -RuntimeSessionId $runtimeSessionId `
                -Stage $stage `
                -Failure $bridgeFailure
        } catch {
            $bridgeFailureCategory = 'unknown'
        }
    }
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
    $categorySuffix = if ($bridgeFailureCategory) { " [$bridgeFailureCategory]" } else { '' }
    $evidenceSuffix = if ($bridgeFailureEvidencePath) { " Evidence: $bridgeFailureEvidencePath" } else { '' }
    throw "SOC startup failed at $stage$categorySuffix. $message.$evidenceSuffix"
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
