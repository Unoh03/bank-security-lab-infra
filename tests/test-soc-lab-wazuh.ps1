#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'automation\SocLab.Wazuh.psm1'
$hardeningPath = Join-Path $root 'tools\Invoke-SocWazuhHardening.ps1'
Import-Module $modulePath -Force

$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $hardeningPath,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -gt 0) {
    throw "PowerShell parser rejected the Wazuh hardening script: $($errors[0].Message)"
}

$hashA = '$2y$12$' + ('A' * 53)
$hashB = '$2y$12$' + ('B' * 53)
$passwordA = 'AdminOnly-A9.*' + ('a' * 18)
$passwordB = 'KibanaOnly-B8+?' + ('b' * 17)
$passwordC = 'ApiOnly-C7.-' + ('c' * 20)

$internalUsers = @"
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "OLD_ADMIN"
  reserved: true

kibanaserver:
  hash: "OLD_KIBANA"
  reserved: true
"@

$adminUpdated = Set-WazuhInternalUserHashText -Text $internalUsers -UserName admin -Hash $hashA
if ($adminUpdated -notmatch [regex]::Escape($hashA) -or
    $adminUpdated -notmatch 'kibanaserver:\s+hash: "OLD_KIBANA"') {
    throw 'The admin phase did not change only the admin hash.'
}
$finalUsers = Set-WazuhInternalUserHashText -Text $adminUpdated -UserName kibanaserver -Hash $hashB
if ($finalUsers -notmatch [regex]::Escape($hashA) -or
    $finalUsers -notmatch [regex]::Escape($hashB) -or
    $finalUsers -match 'OLD_(ADMIN|KIBANA)') {
    throw 'The final phase did not contain exactly the two new hashes.'
}

$dashboard = @"
hosts:
  - default:
      url: "https://wazuh.manager"
      port: 55000
      username: wazuh-wui
      password: "OLD_API"
      run_as: true
"@
$dashboardUpdated = Set-WazuhDashboardApiPasswordText -Text $dashboard -Password $passwordC
if ($dashboardUpdated -notmatch [regex]::Escape($passwordC) -or $dashboardUpdated -match 'OLD_API') {
    throw 'The dashboard API password transformation failed.'
}

$adminOverride = New-WazuhSecretOverrideText `
    -Phase Admin `
    -InternalUsersPath 'C:\runtime\admin-users.yml' `
    -AdminPassword $passwordA
if ($adminOverride -notmatch 'INDEXER_PASSWORD' -or
    $adminOverride -match 'DASHBOARD_PASSWORD|API_PASSWORD') {
    throw 'The admin-phase Compose override widened its credential scope.'
}

$finalOverride = New-WazuhSecretOverrideText `
    -Phase Final `
    -InternalUsersPath 'C:\runtime\final-users.yml' `
    -AdminPassword $passwordA `
    -KibanaserverPassword $passwordB `
    -ApiPassword $passwordC `
    -DashboardConfigPath 'C:\runtime\wazuh.yml'
foreach ($required in @(
    'INDEXER_PASSWORD',
    'DASHBOARD_PASSWORD',
    'API_PASSWORD',
    '/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml',
    '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml'
)) {
    if ($finalOverride -notmatch [regex]::Escape($required)) {
        throw "The final Compose override is missing: $required"
    }
}

foreach ($defaultPattern in @(
    [regex]::Escape(('Secret' + 'Password')),
    [regex]::Escape(('MyS3cr37P450r.' + '*-')),
    ('DASHBOARD_' + 'PASSWORD:\s*"kibanaserver"')
)) {
    if ($finalOverride -match $defaultPattern) {
        throw 'The final Compose override contains a Wazuh default credential.'
    }
}

$managerConfig = @"
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>

<ossec_config>
  <localfile>
    <location>/var/ossec/wazuh-push/dvwa/wazuh-push-live.jsonl</location>
    <log_format>json</log_format>
  </localfile>
</ossec_config>
"@
$integrationFragment = @"
<ossec_config>
  <integration>
    <name>custom-shuffle-soc</name>
    <level>10</level>
    <rule_id>100103</rule_id>
    <alert_format>json</alert_format>
    <timeout>10</timeout>
    <retries>1</retries>
  </integration>
</ossec_config>
"@
$managerWithIntegration = Add-WazuhManagerSocIntegrationText `
    -ManagerConfigText $managerConfig `
    -IntegrationXml $integrationFragment
if ([regex]::Matches($managerWithIntegration, 'custom-shuffle-soc').Count -ne 1 -or
    $managerWithIntegration -notmatch '<rule_id>100103</rule_id>') {
    throw 'The Wazuh Manager integration fragment was not added exactly once.'
}
$managerIdempotent = Add-WazuhManagerSocIntegrationText `
    -ManagerConfigText $managerWithIntegration `
    -IntegrationXml $integrationFragment
if ($managerIdempotent -cne $managerWithIntegration) {
    throw 'The Wazuh Manager integration transform is not idempotent.'
}

$badIntegration = $integrationFragment -replace '<rule_id>100103</rule_id>', '<rule_id>100100</rule_id>'
$badIntegrationRejected = $false
try {
    [void](Add-WazuhManagerSocIntegrationText `
        -ManagerConfigText $managerConfig `
        -IntegrationXml $badIntegration)
} catch {
    $badIntegrationRejected = $_.Exception.Message -match 'not frozen'
}
if (-not $badIntegrationRejected) {
    throw 'The Wazuh Manager integration transform accepted a non-frozen rule ID.'
}

$integrationOverride = New-WazuhSocIntegrationOverrideText `
    -ManagerConfigPath 'C:\runtime\ossec.conf' `
    -IntegrationScriptPath 'C:\repo\custom-shuffle-soc' `
    -WebhookUrlPath 'C:\runtime\shuffle_webhook_url' `
    -WebhookHeaderKeyPath 'C:\runtime\shuffle_webhook_header_key'
foreach ($required in @(
    '/wazuh-config-mount/etc/ossec.conf',
    '/soc-bootstrap/custom-shuffle-soc',
    '/var/ossec/soc-secrets/shuffle_webhook_url',
    '/var/ossec/soc-secrets/shuffle_webhook_header_key',
    'read_only: true'
)) {
    if ($integrationOverride -notmatch [regex]::Escape($required)) {
        throw "The Wazuh SOC integration override is missing: $required"
    }
}
foreach ($forbidden in @('shuffle_api_key','github_pat','Authorization:')) {
    if ($integrationOverride -match [regex]::Escape($forbidden)) {
        throw "The Wazuh SOC integration override contains a forbidden secret surface: $forbidden"
    }
}

Write-Host 'SOC lab Wazuh transformation tests passed.'
