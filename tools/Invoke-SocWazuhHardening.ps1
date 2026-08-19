#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$WazuhRoot = 'D:\Wazuh\wazuh-docker\single-node',
    [string]$SecretRoot = '',
    [string]$RuntimeRoot = '',
    [string]$EvidenceRoot = '',
    [string]$ConfirmApply = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$securityModulePath = Join-Path $repositoryRoot 'automation\SocLab.Security.psm1'
$wazuhModulePath = Join-Path $repositoryRoot 'automation\SocLab.Wazuh.psm1'
$portOverridePath = Join-Path $repositoryRoot 'observability\wazuh\docker-compose.soc.override.yml'
Import-Module $securityModulePath -Force
Import-Module $wazuhModulePath -Force

$WazuhRoot = [IO.Path]::GetFullPath($WazuhRoot)
$baseComposePath = Join-Path $WazuhRoot 'docker-compose.yml'
$internalUsersSourcePath = Join-Path $WazuhRoot 'config\wazuh_indexer\internal_users.yml'
$dashboardSourcePath = Join-Path $WazuhRoot 'config\wazuh_dashboard\wazuh.yml'
$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$resolvedRuntimeRoot = Get-SocRuntimeRoot -Root $RuntimeRoot
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'aws-topology-evidence\soc-lab-hardening'
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)

$requiredFiles = @(
    $baseComposePath,
    $internalUsersSourcePath,
    $dashboardSourcePath,
    $portOverridePath
)
foreach ($path in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Wazuh hardening input is unavailable: $path"
    }
}
foreach ($command in @('docker','git')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

Write-Host 'Wazuh SOC hardening preview'
Write-Host "Wazuh root: $WazuhRoot"
Write-Host "Protected secret root: $resolvedSecretRoot"
Write-Host "Private runtime root: $resolvedRuntimeRoot"
Write-Host 'Actions: DPAPI decrypt in memory; two-phase admin then kibanaserver/API rotation; Local-only ports; existing named volumes retained.'
Write-Host 'The script retains named volumes and never prints a password, hash, token, or effective Compose JSON.'
if ($ConfirmApply -cne 'ROTATE WAZUH CREDENTIALS') {
    throw "Preview only. Re-run with -ConfirmApply 'ROTATE WAZUH CREDENTIALS'."
}

$secretNames = [ordered]@{
    Admin  = 'wazuh_indexer_admin_password'
    Kibana = 'wazuh_indexer_kibanaserver_password'
    Api    = 'wazuh_api_wui_password'
}
foreach ($name in $secretNames.Values) {
    $path = Join-Path $resolvedSecretRoot "$name.dpapi.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Protected Wazuh secret is unavailable. Run Initialize-SocLabSecrets.ps1 first: $name"
    }
}

function Invoke-ProcessWithSecretInput {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$InputText
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $secretEnvironmentName = 'WAZUH_HASH_INPUT'
    $startInfo.Environment[$secretEnvironmentName] = $InputText

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'The bounded secret-input process could not start.'
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut   = $stdout
            StdErr   = $stderr
        }
    } finally {
        [void]$startInfo.Environment.Remove($secretEnvironmentName)
        $process.Dispose()
    }
}

function Get-WazuhPasswordHash {
    param([Parameter(Mandatory)][string]$Password)

    $result = Invoke-ProcessWithSecretInput -FilePath 'docker' -Arguments @(
        'run','--rm','-e','WAZUH_HASH_INPUT','wazuh/wazuh-indexer:4.14.7',
        'bash','/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh',
        '-env','WAZUH_HASH_INPUT'
    ) -InputText $Password
    if ($result.ExitCode -ne 0) {
        throw 'Wazuh password hash generation failed. Output was suppressed because it handled secret input.'
    }
    $matches = [regex]::Matches(
        ([string]$result.StdOut + [string]$result.StdErr),
        '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'
    )
    if ($matches.Count -ne 1) {
        throw 'Wazuh password hash generation did not return exactly one bcrypt hash.'
    }
    return [string]$matches[0].Value
}

function Invoke-ComposeSafe {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$SuppressOutput
    )

    $dockerArguments = [Collections.Generic.List[string]]::new()
    foreach ($file in $Files) {
        $dockerArguments.Add('-f')
        $dockerArguments.Add($file)
    }
    foreach ($argument in $Arguments) {
        $dockerArguments.Add($argument)
    }
    $output = @(& docker compose @dockerArguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed during the bounded Wazuh hardening step: $($Arguments[0])"
    }
    if (-not $SuppressOutput.IsPresent) {
        $output | ForEach-Object { Write-Host ([string]$_) }
    }
    return @($output)
}

function Assert-EffectiveCompose {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$ExpectedAdmin,
        [string]$ExpectedKibana = '',
        [string]$ExpectedApi = ''
    )

    $output = Invoke-ComposeSafe -Files $Files -Arguments @('config','--format','json') -SuppressOutput
    $config = (($output | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json
    foreach ($serviceName in @('wazuh.manager','wazuh.indexer','wazuh.dashboard')) {
        foreach ($port in @($config.services.$serviceName.ports)) {
            if ([string]$port.host_ip -cne '127.0.0.1') {
                throw "The effective Wazuh Compose exposes a non-local port: $serviceName"
            }
        }
    }
    if ([string]$config.services.'wazuh.manager'.environment.INDEXER_PASSWORD -cne $ExpectedAdmin -or
        [string]$config.services.'wazuh.dashboard'.environment.INDEXER_PASSWORD -cne $ExpectedAdmin) {
        throw 'The effective Wazuh Compose does not use the protected admin password.'
    }
    if ($ExpectedKibana -and
        [string]$config.services.'wazuh.dashboard'.environment.DASHBOARD_PASSWORD -cne $ExpectedKibana) {
        throw 'The effective Wazuh Compose does not use the protected kibanaserver password.'
    }
    if ($ExpectedApi -and
        ([string]$config.services.'wazuh.manager'.environment.API_PASSWORD -cne $ExpectedApi -or
         [string]$config.services.'wazuh.dashboard'.environment.API_PASSWORD -cne $ExpectedApi)) {
        throw 'The effective Wazuh Compose does not use the protected API password.'
    }
}

function Wait-WazuhServiceRunning {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string[]]$Service,
        [ValidateRange(10, 600)][int]$TimeoutSeconds = 300
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $running = @(Invoke-ComposeSafe -Files $Files -Arguments @('ps','--status','running','--services') -SuppressOutput)
        $runningNames = @($running | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        $missing = @($Service | Where-Object { $_ -notin $runningNames })
        if ($missing.Count -eq 0) {
            return
        }
        Start-Sleep -Seconds 5
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw "Wazuh service did not reach running state: $($missing -join ', ')"
}

function Invoke-WazuhSecurityAdmin {
    param([Parameter(Mandatory)][string[]]$Files)

    $arguments = @(
        'exec','-T','wazuh.indexer','bash',
        '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh',
        '-cd','/usr/share/wazuh-indexer/config/opensearch-security/',
        '-nhnv',
        '-cacert','/usr/share/wazuh-indexer/config/certs/root-ca.pem',
        '-cert','/usr/share/wazuh-indexer/config/certs/admin.pem',
        '-key','/usr/share/wazuh-indexer/config/certs/admin-key.pem',
        '-p','9200','-icl'
    )
    $deadline = [datetimeoffset]::UtcNow.AddMinutes(5)
    do {
        try {
            [void](Invoke-ComposeSafe -Files $Files -Arguments $arguments -SuppressOutput)
            return
        } catch {
            if ([datetimeoffset]::UtcNow -ge $deadline) {
                throw
            }
            Start-Sleep -Seconds 10
        }
    } while ($true)
}

function Test-LoopbackBasicAuth {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [ValidateSet('Get','Post')][string]$Method = 'Get'
    )

    $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $credential = [Management.Automation.PSCredential]::new($UserName, $secure)
    try {
        $response = Invoke-RestMethod `
            -Uri $Uri `
            -Method $Method `
            -Authentication Basic `
            -Credential $credential `
            -SkipCertificateCheck `
            -TimeoutSec 15
        $response = $null
        return $true
    } catch {
        $statusCode = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(401,403)) {
            return $false
        }
        throw 'A loopback Wazuh authentication probe failed for a non-authentication reason.'
    }
}

function Assert-LoopbackPorts {
    $containerNames = @(
        'single-node-wazuh.manager-1',
        'single-node-wazuh.indexer-1',
        'single-node-wazuh.dashboard-1'
    )
    foreach ($container in $containerNames) {
        $output = @(& docker inspect $container --format '{{json .HostConfig.PortBindings}}' 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "The Wazuh PortBindings could not be inspected: $container"
        }
        $bindings = (($output | ForEach-Object { [string]$_ }) -join '') | ConvertFrom-Json -AsHashtable
        foreach ($entry in $bindings.GetEnumerator()) {
            foreach ($binding in @($entry.Value)) {
                if ([string]$binding.HostIp -cne '127.0.0.1') {
                    throw "A Wazuh runtime port is not local-only: $container/$($entry.Key)"
                }
            }
        }
    }
}

$adminPassword = $null
$kibanaPassword = $null
$apiPassword = $null
$runtimeSessionId = 'wazuh-hardening-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$sessionPath = Join-Path $resolvedRuntimeRoot $runtimeSessionId
$succeeded = $false
try {
    $adminPassword = Unprotect-SocSecret -Name $secretNames.Admin -SecretRoot $resolvedSecretRoot
    $kibanaPassword = Unprotect-SocSecret -Name $secretNames.Kibana -SecretRoot $resolvedSecretRoot
    $apiPassword = Unprotect-SocSecret -Name $secretNames.Api -SecretRoot $resolvedSecretRoot

    $adminHash = Get-WazuhPasswordHash -Password $adminPassword
    $kibanaHash = Get-WazuhPasswordHash -Password $kibanaPassword
    $internalUsersSource = Get-Content -LiteralPath $internalUsersSourcePath -Raw
    $dashboardSource = Get-Content -LiteralPath $dashboardSourcePath -Raw

    $adminUsers = Set-WazuhInternalUserHashText `
        -Text $internalUsersSource `
        -UserName admin `
        -Hash $adminHash
    $finalUsers = Set-WazuhInternalUserHashText `
        -Text $adminUsers `
        -UserName kibanaserver `
        -Hash $kibanaHash
    $finalDashboard = Set-WazuhDashboardApiPasswordText `
        -Text $dashboardSource `
        -Password $apiPassword

    $adminUsersPath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'admin\internal_users.yml' `
        -Content $adminUsers `
        -RuntimeRoot $resolvedRuntimeRoot
    $finalUsersPath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'final\internal_users.yml' `
        -Content $finalUsers `
        -RuntimeRoot $resolvedRuntimeRoot
    $finalDashboardPath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'final\wazuh.yml' `
        -Content $finalDashboard `
        -RuntimeRoot $resolvedRuntimeRoot

    $adminOverride = New-WazuhSecretOverrideText `
        -Phase Admin `
        -InternalUsersPath $adminUsersPath `
        -AdminPassword $adminPassword
    $adminOverridePath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'admin\docker-compose.secrets.yml' `
        -Content $adminOverride `
        -RuntimeRoot $resolvedRuntimeRoot
    $finalOverride = New-WazuhSecretOverrideText `
        -Phase Final `
        -InternalUsersPath $finalUsersPath `
        -AdminPassword $adminPassword `
        -KibanaserverPassword $kibanaPassword `
        -ApiPassword $apiPassword `
        -DashboardConfigPath $finalDashboardPath
    $finalOverridePath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'final\docker-compose.secrets.yml' `
        -Content $finalOverride `
        -RuntimeRoot $resolvedRuntimeRoot

    $adminFiles = @($baseComposePath,$portOverridePath,$adminOverridePath)
    $finalFiles = @($baseComposePath,$portOverridePath,$finalOverridePath)
    Assert-EffectiveCompose -Files $adminFiles -ExpectedAdmin $adminPassword
    Assert-EffectiveCompose `
        -Files $finalFiles `
        -ExpectedAdmin $adminPassword `
        -ExpectedKibana $kibanaPassword `
        -ExpectedApi $apiPassword

    Write-Host 'Phase 1/2: rotating the Wazuh indexer admin credential.'
    [void](Invoke-ComposeSafe -Files $adminFiles -Arguments @('down'))
    [void](Invoke-ComposeSafe -Files $adminFiles -Arguments @('up','-d'))
    Wait-WazuhServiceRunning -Files $adminFiles -Service @('wazuh.indexer')
    Invoke-WazuhSecurityAdmin -Files $adminFiles
    [void](Invoke-ComposeSafe -Files $adminFiles -Arguments @('restart','wazuh.manager','wazuh.dashboard'))

    if (-not (Test-LoopbackBasicAuth -Uri 'https://127.0.0.1:9200/' -UserName 'admin' -Password $adminPassword)) {
        throw 'The new Wazuh indexer admin credential was rejected after phase 1.'
    }
    $oldAdmin = 'Secret' + 'Password'
    if (Test-LoopbackBasicAuth -Uri 'https://127.0.0.1:9200/' -UserName 'admin' -Password $oldAdmin) {
        throw 'The Wazuh indexer still accepts the official default admin credential.'
    }

    Write-Host 'Phase 2/2: rotating kibanaserver and wazuh-wui credentials.'
    [void](Invoke-ComposeSafe -Files $adminFiles -Arguments @('down'))
    [void](Invoke-ComposeSafe -Files $finalFiles -Arguments @('up','-d'))
    Wait-WazuhServiceRunning -Files $finalFiles -Service @('wazuh.indexer')
    Invoke-WazuhSecurityAdmin -Files $finalFiles
    [void](Invoke-ComposeSafe -Files $finalFiles -Arguments @('restart','wazuh.manager','wazuh.dashboard'))
    Wait-WazuhServiceRunning `
        -Files $finalFiles `
        -Service @('wazuh.manager','wazuh.indexer','wazuh.dashboard') `
        -TimeoutSeconds 300

    Assert-LoopbackPorts
    if (-not (Test-LoopbackBasicAuth -Uri 'https://127.0.0.1:9200/' -UserName 'admin' -Password $adminPassword)) {
        throw 'The final Wazuh indexer admin authentication probe failed.'
    }
    if (-not (Test-LoopbackBasicAuth -Uri 'https://127.0.0.1:9200/_plugins/_security/authinfo' -UserName 'kibanaserver' -Password $kibanaPassword)) {
        throw 'The final Wazuh kibanaserver authentication probe failed.'
    }
    $oldKibana = 'kibana' + 'server'
    if (Test-LoopbackBasicAuth -Uri 'https://127.0.0.1:9200/_plugins/_security/authinfo' -UserName 'kibanaserver' -Password $oldKibana) {
        throw 'The Wazuh indexer still accepts the official default kibanaserver credential.'
    }
    if (-not (Test-LoopbackBasicAuth `
        -Uri 'https://127.0.0.1:55000/security/user/authenticate?raw=true' `
        -Method Post `
        -UserName 'wazuh-wui' `
        -Password $apiPassword)) {
        throw 'The final Wazuh API wazuh-wui authentication probe failed.'
    }
    $oldApi = 'MyS3cr37P450r.' + '*-'
    if (Test-LoopbackBasicAuth `
        -Uri 'https://127.0.0.1:55000/security/user/authenticate?raw=true' `
        -Method Post `
        -UserName 'wazuh-wui' `
        -Password $oldApi) {
        throw 'The Wazuh API still accepts the official default wazuh-wui credential.'
    }

    $activeStatePath = Write-SocRuntimeSecretFile `
        -SessionId $runtimeSessionId `
        -RelativePath 'active-wazuh-runtime.json' `
        -Content (([ordered]@{
            schema_version         = 1
            session_id             = $runtimeSessionId
            created_at             = [datetimeoffset]::UtcNow.ToString('o')
            base_compose_path      = $baseComposePath
            port_override_path     = $portOverridePath
            secret_override_path   = $finalOverridePath
            local_only_ports       = $true
            admin_rotated          = $true
            kibanaserver_rotated   = $true
            wazuh_wui_rotated      = $true
        } | ConvertTo-Json -Depth 5) + "`n") `
        -RuntimeRoot $resolvedRuntimeRoot

    New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
    $evidencePath = Join-Path $EvidenceRoot "$runtimeSessionId.json"
    $evidence = [ordered]@{
        schema_version                   = 1
        checked_at                       = [datetimeoffset]::UtcNow.ToString('o')
        runtime_session_id               = $runtimeSessionId
        wazuh_version                    = '4.14.7'
        local_only_ports                 = $true
        new_admin_authentication         = 'accepted'
        default_admin_authentication     = 'rejected'
        new_kibanaserver_authentication  = 'accepted'
        default_kibana_authentication    = 'rejected'
        new_wazuh_wui_authentication     = 'accepted'
        default_wazuh_wui_authentication = 'rejected'
        named_volumes_removed            = $false
        secrets_printed                  = $false
        active_state_path                = $activeStatePath
    } | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($evidencePath, "$evidence`n", [Text.UTF8Encoding]::new($false))

    $succeeded = $true
    Write-Host 'WAZUH_LOCAL_HARDENING=yes'
    Write-Host "WAZUH_RUNTIME_SESSION=$runtimeSessionId"
    Write-Host "WAZUH_HARDENING_EVIDENCE=$evidencePath"
    Write-Host 'Log out or clear the previous Wazuh Dashboard cookie before signing in again.'
} finally {
    $adminPassword = $null
    $kibanaPassword = $null
    $apiPassword = $null
    if (-not $succeeded) {
        Write-Warning "Wazuh hardening did not complete. Private recovery files were retained at: $sessionPath"
    }
}
