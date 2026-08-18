#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('shuffle_api_key','shuffle_webhook_url')]
    [string]$Name,
    [string]$SecretRoot = '',
    [string]$ConfirmStore = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $repositoryRoot 'automation\SocLab.Security.psm1'
Import-Module $modulePath -Force

Write-Host 'SOC external secret registration preview'
Write-Host "Secret name: $Name"
Write-Host 'The value is requested interactively, encrypted with DPAPI CurrentUser, and never printed.'
if ($ConfirmStore -cne 'STORE SOC EXTERNAL SECRET') {
    throw "Preview only. Re-run with -ConfirmStore 'STORE SOC EXTERNAL SECRET'."
}

$secure = Read-Host -Prompt "Enter $Name" -AsSecureString
$pointer = [IntPtr]::Zero
$plainText = $null
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plainText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($plainText)) {
        throw 'An empty external SOC secret cannot be stored.'
    }
    [void](Protect-SocSecret -Name $Name -PlainText $plainText -SecretRoot $SecretRoot)
} finally {
    $plainText = $null
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

Write-Host "SOC_EXTERNAL_SECRET_STORED=$Name"
Write-Host 'No plaintext value was printed.'
