#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'observability\scenarios\Test-ShuffleSocGateB5.ps1'
$text = Get-Content -LiteralPath $scriptPath -Raw

$requirements = @(
    @{Pattern="ConfirmRun -cne 'RUN SHUFFLE GATE B5'";Message='Gate B5 lacks an exact external-write confirmation.'},
    @{Pattern='Assert-ShuffleSocGateB5Workflow';Message='Gate B5 does not prove the dispatch Stub before sending.'},
    @{Pattern='Send-GateB5ExecuteBatch[\s\S]*?-PayloadJson \(\[string\]\$valid\.Json\) -Count 10';Message='Gate B5 does not execute one exact Payload ten times concurrently.'},
    @{Pattern='Send-GateB5WebhookBatch[\s\S]*?-ExpectedSuccess \$false[\s\S]*?Send-GateB5WebhookBatch[\s\S]*?-ExpectedSuccess \$true';Message='Gate B5 does not test rejected and accepted Webhook Headers separately.'},
    @{Pattern='new_claim_count=\$freshCount[\s\S]*?duplicate_claim_count=\$duplicateCount[\s\S]*?stub_execution_count=\$stubCount';Message='Gate B5 does not persist atomic-claim evidence.'},
    @{Pattern="wrong-take[\s\S]*?write_rejected_take[\s\S]*?'wrong-account'='write_rejected_allowlist'[\s\S]*?'wrong-scenario'='write_rejected_allowlist'[\s\S]*?'wrong-rule'='write_rejected_allowlist'[\s\S]*?'wrong-body-hash'='write_rejected_schema'";Message='Gate B5 negative cases are not bound to their intended branches.'},
    @{Pattern='productionWriterCount -ne 0';Message='Gate B5 can falsely record a production response.'},
    @{Pattern='real_github_dispatch_count=0';Message='Gate B5 does not record zero real GitHub dispatches.'},
    @{Pattern='Remove-ShuffleSocTake[\s\S]*?Remove-ShuffleSocCacheKey';Message='Gate B5 lacks bounded allow and Dedupe cleanup.'},
    @{Pattern='Test-SocSecretExposure\.ps1';Message='Gate B5 Evidence is not secret-scanned.'}
)
foreach ($requirement in $requirements) {
    if ($text -notmatch $requirement.Pattern) { throw $requirement.Message }
}
foreach ($forbidden in @('Write-(Host|Output).*?\$(apiKey|webhookUrl|headerKey|Authorization)','Out-File.*?\$(apiKey|webhookUrl|headerKey)')) {
    if ($text -match $forbidden) { throw 'Gate B5 may print or persist a secret-bearing variable.' }
}

$preview = @()
$previewFailed = $false
try { $preview = @(& $scriptPath 2>&1) }
catch {
    $previewFailed = $true
    $preview += $_.Exception.Message
}
if (-not $previewFailed -or ($preview -join "`n") -notmatch 'Preview only') {
    throw 'Gate B5 preview did not fail closed before external writes.'
}

Write-Host 'Shuffle Gate B5 harness contract tests passed.'
