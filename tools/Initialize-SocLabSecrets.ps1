#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$SecretRoot = '',
    [string]$ConfirmInitialize = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $repositoryRoot 'automation\SocLab.Security.psm1'
Import-Module $modulePath -Force

$resolvedRoot = Get-SocSecretRoot -Root $SecretRoot
$secretNames = @(
    'wazuh_indexer_admin_password',
    'wazuh_indexer_kibanaserver_password',
    'wazuh_api_wui_password',
    'shuffle_webhook_header_key'
)

Write-Host 'SOC lab secret initialization preview'
Write-Host "Protected root: $resolvedRoot"
Write-Host ('Generated names: ' + ($secretNames -join ', '))
Write-Host 'Values are generated locally, protected with Windows DPAPI CurrentUser, and never printed.'
Write-Host 'Existing protected values are never overwritten by this command.'

if ($ConfirmInitialize -cne 'INITIALIZE SOC LAB SECRETS') {
    throw "Preview only. Re-run with -ConfirmInitialize 'INITIALIZE SOC LAB SECRETS'."
}

foreach ($name in $secretNames) {
    $path = Join-Path $resolvedRoot "$name.dpapi.json"
    if (Test-Path -LiteralPath $path) {
        throw "Protected SOC secret already exists; initialization made no change: $name"
    }
}

$created = [Collections.Generic.List[string]]::new()
try {
    foreach ($name in $secretNames) {
        $value = New-SocStrongSecret -Length 32
        try {
            $path = Protect-SocSecret -Name $name -PlainText $value -SecretRoot $resolvedRoot
            $created.Add($path)
        } finally {
            $value = $null
        }
    }
} catch {
    foreach ($path in $created) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    throw
}

foreach ($name in $secretNames) {
    $roundTrip = Unprotect-SocSecret -Name $name -SecretRoot $resolvedRoot
    if ([string]::IsNullOrWhiteSpace($roundTrip)) {
        throw "Protected SOC secret failed its local decryptability check: $name"
    }
    $roundTrip = $null
}

Write-Host "SOC_SECRET_INITIALIZED=yes"
Write-Host "SOC_SECRET_COUNT=$($secretNames.Count)"
Write-Host 'No plaintext value was printed or persisted outside the DPAPI records.'
