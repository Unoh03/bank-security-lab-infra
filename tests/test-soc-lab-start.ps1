#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'tools\Start-SocLab.ps1'
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw 'Start-SocLab.ps1 is missing.'
}
$text = Get-Content -LiteralPath $path -Raw

function Assert-Match {
    param([string]$Pattern,[string]$Message)
    if ($text -notmatch $Pattern) { throw $Message }
}
function Assert-NotMatch {
    param([string]$Pattern,[string]$Message)
    if ($text -match $Pattern) { throw $Message }
}

Assert-Match "ConfirmStart\s+-cne\s+'START SOC LAB'" 'Start lacks its exact mutation confirmation.'
Assert-Match 'Read-DailySessionState[\s\S]*?capital-one-lab' 'Start does not verify the Active Daily security profile.'
Assert-Match 'MinimumDailyRemainingMinutes\s*=\s*60[\s\S]*?HardDeadlineAtUtc[\s\S]*?MinimumDailyRemainingMinutes' 'Start does not reserve the default 60-minute Daily runtime window.'
Assert-Match 'daily_hard_deadline_at_utc' 'Start does not bind READY to the Daily hard deadline.'
Assert-Match 'runtime_profile[\s\S]*?minimal' 'Start does not verify the minimal Runtime.'
Assert-Match 'Assert-SocDvWaLow' 'Start does not verify the DVWA low baseline.'
Assert-Match 'Get-ShuffleSocWorkflow' 'Start does not read back the frozen Shuffle Workflow.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Assert-ShuffleSocProductionWorkflow[\s\S]*?shuffleWorkflowStage\s*=\s*'production'" 'Contain READY does not require the strict Production Workflow export contract.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Get-ShuffleSocAppUploadEvidence[\s\S]*?Get-ShuffleSocCloudProvenance[\s\S]*?authentication_active[\s\S]*?secret_value_inspected" 'Contain READY does not bind the Workflow to the uploaded private Apps and encrypted Dispatcher Authentication.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Assert-ShuffleSocGateB5Evidence" 'Contain READY does not require prior Gate B5 Runtime atomicity Evidence.'
Assert-Match 'Get-ShuffleSocCoreContractSha256[\s\S]*?WorkflowCoreSha256[\s\S]*?Production Workflow core changed' 'Contain READY does not bind Production to the Gate B5 core fingerprint.'
Assert-Match 'shuffle_workflow_stage' 'READY Evidence does not preserve the validated Shuffle stage.'
Assert-Match 'shuffle_cloud_provenance[\s\S]*?validator_app_id[\s\S]*?dispatcher_app_id[\s\S]*?dispatcher_authentication_id_sha256[\s\S]*?secret_value_inspected' 'READY Evidence does not preserve sanitized Cloud App and Authentication provenance.'
Assert-Match 'shuffle_gate_b5_evidence[\s\S]*?manifest_sha256[\s\S]*?workflow_core_sha256' 'READY Evidence does not bind the prior Gate B5 manifest and core fingerprint.'
Assert-Match 'Get-SocGithubState' 'Start does not verify both remote GitHub Workflows and main.'
Assert-Match 'Get-SocArgoState' 'Start does not verify exact Argo health and revision.'
Assert-Match 'Assert-SocEffectiveCompose' 'Start does not inspect its effective local-only Compose configuration.'
Assert-Match "install[\s\S]*?custom-shuffle-soc[\s\S]*?restart','wazuh.manager" 'Start does not install and activate the custom Wazuh integration.'
Assert-Match 'Wait-SocBridgeReady[\s\S]*?dlq_visible[\s\S]*?queue_oldest_age_seconds' 'Start does not enforce the Bridge heartbeat readiness contract.'
Assert-Match "Invoke-WazuhPushValidation\.ps1[\s\S]*?SEND WAZUH PUSH VALIDATION" 'Start does not execute the harmless Rule 100102 probe.'
Assert-Match "rule\.id'\s*=\s*'100102'[\s\S]*?data\.payload\.take_id" 'Start does not query one exact safe-probe alert.'
Assert-Match 'Register-ShuffleSocTake[\s\S]*?Set-SocTakeStatus[\s\S]*?READY' 'Start does not register and verify the TAKE before READY.'
Assert-Match 'SOC_LAB_READY=yes[\s\S]*?ACTIVE_TAKE_ID=[\s\S]*?RESPONSE_MODE=[\s\S]*?READY_EVIDENCE=' 'Start lacks the frozen four-line READY output.'
Assert-Match "Invoke-SocComposeCapture[\s\S]*?Arguments @\('down'\)" 'Start does not stop Wazuh on partial failure before deleting Runtime Secrets.'
Assert-NotMatch "Invoke-SocNativeCapture\s+-FilePath\s+'terraform'[\s\S]{0,240}'(apply|destroy)'|Invoke-SocNativeCapture\s+-FilePath\s+'gh'[\s\S]{0,300}'--method','(POST|PUT|PATCH|DELETE)'" 'Start contains a forbidden Terraform or GitHub mutation.'
Assert-NotMatch 'Invoke-CapitalOneBaseline|RUN CAPITAL ONE BASELINE' 'Start must not execute a real attack.'

$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('Start-SocLab parser errors: ' + (@($errors.Message) -join '; '))
}

Write-Host 'SOC lab one-command READY static tests passed.'
