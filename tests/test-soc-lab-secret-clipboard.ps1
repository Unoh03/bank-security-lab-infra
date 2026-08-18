#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'tools\Copy-SocLabWebhookHeader.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern="ConfirmCopy\s+-cne\s+'COPY SOC HEADER TO CLIPBOARD'";Message='Clipboard helper lacks exact user confirmation.'},
    @{Pattern="Unprotect-SocSecret\s+-Name\s+'shuffle_webhook_header_key'";Message='Clipboard helper can read an unexpected Secret.'},
    @{Pattern='ExcludeClipboardContentFromMonitorProcessing';Message='Clipboard helper does not opt out of History and Cloud Clipboard processing.'},
    @{Pattern='ClearIfMatches\(\$secret\)';Message='Clipboard helper does not conditionally clear its exact value.'},
    @{Pattern='No plaintext value is printed or persisted';Message='Clipboard helper lacks its no-output contract.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match 'Write-(?:Host|Output)[^\r\n]*\$secret|Set-Clipboard') {
    throw 'Clipboard helper may print the Secret or use history-prone Set-Clipboard.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('SOC Webhook clipboard parser errors: ' + (@($errors.Message) -join '; '))
}
Write-Host 'SOC Webhook protected clipboard static tests passed.'
