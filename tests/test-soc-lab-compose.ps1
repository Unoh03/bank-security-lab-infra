#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$WazuhRoot = 'D:\Wazuh\wazuh-docker\single-node'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$wazuhModulePath = Join-Path $repositoryRoot 'automation\SocLab.Wazuh.psm1'
$portOverridePath = Join-Path $repositoryRoot 'observability\wazuh\docker-compose.soc.override.yml'
$integrationScriptPath = Join-Path $repositoryRoot 'observability\wazuh\integrations\custom-shuffle-soc'
$baseComposePath = Join-Path ([IO.Path]::GetFullPath($WazuhRoot)) 'docker-compose.yml'
Import-Module $wazuhModulePath -Force

foreach ($path in @($baseComposePath,$portOverridePath,$integrationScriptPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Compose fixture is unavailable: $path"
    }
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required for the effective Compose contract test.'
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-compose-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $admin = 'AdminOnly-A9.*' + ('a' * 18)
    $kibana = 'KibanaOnly-B8+?' + ('b' * 17)
    $api = 'ApiOnly-C7.-' + ('c' * 20)
    $paths = [ordered]@{
        InternalUsers = Join-Path $testRoot 'internal_users.yml'
        Dashboard     = Join-Path $testRoot 'wazuh.yml'
        Manager       = Join-Path $testRoot 'ossec.conf'
        Webhook       = Join-Path $testRoot 'shuffle_webhook_url'
        HeaderKey     = Join-Path $testRoot 'shuffle_webhook_header_key'
        LiveSpool     = Join-Path $testRoot 'wazuh-push-dvwa'
        SecretCompose = Join-Path $testRoot 'docker-compose.secrets.yml'
        SocCompose    = Join-Path $testRoot 'docker-compose.soc-runtime.yml'
    }
    foreach ($path in @($paths.Values | Where-Object { $_ -cne $paths.LiveSpool })) {
        [IO.File]::WriteAllText($path, 'test-fixture', [Text.UTF8Encoding]::new($false))
    }
    New-Item -ItemType Directory -Path $paths.LiveSpool | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $paths.LiveSpool 'wazuh-push-live.jsonl'),
        '',
        [Text.UTF8Encoding]::new($false)
    )
    $secretOverride = New-WazuhSecretOverrideText `
        -Phase Final `
        -InternalUsersPath $paths.InternalUsers `
        -AdminPassword $admin `
        -KibanaserverPassword $kibana `
        -ApiPassword $api `
        -DashboardConfigPath $paths.Dashboard
    [IO.File]::WriteAllText($paths.SecretCompose, $secretOverride, [Text.UTF8Encoding]::new($false))

    $socOverride = New-WazuhSocIntegrationOverrideText `
        -ManagerConfigPath $paths.Manager `
        -IntegrationScriptPath $integrationScriptPath `
        -WebhookUrlPath $paths.Webhook `
        -WebhookHeaderKeyPath $paths.HeaderKey `
        -LiveSpoolPath $paths.LiveSpool
    [IO.File]::WriteAllText($paths.SocCompose, $socOverride, [Text.UTF8Encoding]::new($false))

    $composeFiles = @(
        $baseComposePath,
        $portOverridePath,
        $paths.SecretCompose,
        $paths.SocCompose
    )
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($file in $composeFiles) {
        $arguments.Add('-f')
        $arguments.Add($file)
    }
    $arguments.Add('config')
    $arguments.Add('--format')
    $arguments.Add('json')
    $output = @(& docker compose @arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose rejected the combined SOC runtime configuration.'
    }
    $config = (($output | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json

    foreach ($serviceName in @('wazuh.manager','wazuh.indexer','wazuh.dashboard')) {
        foreach ($port in @($config.services.$serviceName.ports)) {
            if ([string]$port.host_ip -cne '127.0.0.1') {
                throw "The effective SOC Compose exposes a non-loopback port: $serviceName"
            }
        }
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
        '/var/ossec/soc-secrets/shuffle_webhook_header_key',
        '/var/ossec/wazuh-push/dvwa',
        '/var/ossec/logs',
        '/var/ossec/etc'
    )) {
        if (-not $mountByTarget.ContainsKey($target)) {
            throw "The effective SOC Compose lost a required mount: $target"
        }
    }
    $actualManagerSource = [IO.Path]::GetFullPath(
        [string]$mountByTarget['/wazuh-config-mount/etc/ossec.conf'].source
    )
    $expectedManagerSource = [IO.Path]::GetFullPath($paths.Manager)
    if ($actualManagerSource -ine $expectedManagerSource) {
        throw 'The runtime Manager configuration did not replace the base ossec.conf bind.'
    }
    foreach ($target in @(
        '/wazuh-config-mount/etc/ossec.conf',
        '/soc-bootstrap/custom-shuffle-soc',
        '/var/ossec/soc-secrets/shuffle_webhook_url',
        '/var/ossec/soc-secrets/shuffle_webhook_header_key',
        '/var/ossec/wazuh-push/dvwa'
    )) {
        if ([bool]$mountByTarget[$target].read_only -ne $true) {
            throw "The effective SOC Compose has a writable SOC bind: $target"
        }
    }
    if ([string]$config.services.'wazuh.manager'.environment.INDEXER_PASSWORD -cne $admin -or
        [string]$config.services.'wazuh.manager'.environment.API_PASSWORD -cne $api -or
        [string]$config.services.'wazuh.dashboard'.environment.DASHBOARD_PASSWORD -cne $kibana) {
        throw 'The effective SOC Compose lost the protected Wazuh credential override.'
    }

    $detectionOverride = New-WazuhDetectionOverrideText `
        -ManagerConfigPath $paths.Manager `
        -LiveSpoolPath $paths.LiveSpool
    [IO.File]::WriteAllText($paths.SocCompose, $detectionOverride, [Text.UTF8Encoding]::new($false))
    $output = @(& docker compose @arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose rejected the Detection-only runtime configuration.'
    }
    $detectionConfig = (($output | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json
    $detectionMounts = @{}
    foreach ($mount in @($detectionConfig.services.'wazuh.manager'.volumes)) {
        $detectionMounts[[string]$mount.target] = $mount
    }
    foreach ($target in @('/wazuh-config-mount/etc/ossec.conf','/var/ossec/wazuh-push/dvwa')) {
        if (-not $detectionMounts.ContainsKey($target) -or
            [bool]$detectionMounts[$target].read_only -ne $true) {
            throw "The effective Detection-only Compose lost a read-only mount: $target"
        }
    }
    foreach ($target in @(
        '/soc-bootstrap/custom-shuffle-soc',
        '/var/ossec/soc-secrets/shuffle_webhook_url',
        '/var/ossec/soc-secrets/shuffle_webhook_header_key'
    )) {
        if ($detectionMounts.ContainsKey($target)) {
            throw "The effective Detection-only Compose contains a Full SOC mount: $target"
        }
    }
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab effective Compose contract tests passed.'
