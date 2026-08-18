#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ShuffleOrgId,
    [Parameter(Mandatory)][string]$ShuffleWorkflowId,
    [Parameter(Mandatory)][string]$ShuffleWebhookId,
    [uri]$ShuffleApiBase = 'https://shuffler.io/',
    [string]$ConfigurationRoot = '',
    [string]$ConfirmWrite = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force

$configuration = New-SocLabConfiguration `
    -ShuffleOrgId $ShuffleOrgId `
    -ShuffleWorkflowId $ShuffleWorkflowId `
    -ShuffleWebhookId $ShuffleWebhookId `
    -ShuffleApiBase $ShuffleApiBase
$root = Get-SocConfigurationRoot -Root $ConfigurationRoot

Write-Host 'SOC lab non-secret configuration preview'
Write-Host "Configuration root: $root"
Write-Host "Shuffle API origin: $($configuration.shuffle_api_base)"
Write-Host 'Fixed target: Unoh03/Uns-DVWA, main, containment/reset Workflows, Argo application dvwa.'
Write-Host 'No API key, Webhook URL, GitHub token, password, or AWS credential is stored here.'
if ($ConfirmWrite -cne 'WRITE SOC LAB CONFIG') {
    throw "Preview only. Re-run with -ConfirmWrite 'WRITE SOC LAB CONFIG'."
}

Set-SocPrivateDirectoryAcl -Path $root
$path = Write-SocLabConfiguration -Configuration $configuration -Root $root
Write-Host 'SOC_LAB_CONFIGURED=yes'
Write-Host "SOC_LAB_CONFIG_PATH=$path"
