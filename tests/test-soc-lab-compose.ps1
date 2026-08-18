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
        SecretCompose = Join-Path $testRoot 'docker-compose.secrets.yml'
        SocCompose    = Join-Path $testRoot 'docker-compose.soc-runtime.yml'
    }
    foreach ($path in $paths.Values) {
        [IO.File]::WriteAllText($path, 'test-fixture', [Text.UTF8Encoding]::new($false))
    }
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
        -WebhookHeaderKeyPath $paths.HeaderKey
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
        '/var/ossec/soc-secrets/shuffle_webhook_header_key'
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
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab effective Compose contract tests passed.'
