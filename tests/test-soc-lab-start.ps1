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
Assert-Match "ValidateSet\('detection_only','full'\)[\s\S]*?Scope\s*=\s*'detection_only'" 'Start does not default to the bounded Detection-only scope.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Scope\s+-cne\s+'full'" 'Start allows containment without the Full SOC scope.'
Assert-Match "if \(\`$Scope -ceq 'full'\) \{[\s\S]*?SocLab\.Shuffle\.psm1[\s\S]*?SocLab\.Configuration\.psm1" 'Detection-only still imports the Full Shuffle/configuration modules.'
Assert-Match "configuration = if \(\`$Scope -ceq 'full'\)[\s\S]*?Read-SocLabConfiguration[\s\S]*?else \{[\s\S]*?wazuh_root[\s\S]*?aws_profile = 'terra-user'" 'Detection-only does not use only its two fixed local inputs.'
Assert-Match "requiredSecrets = @[\s\S]*?wazuh_api_wui_password[\s\S]*?if \(\`$Scope -ceq 'full'\)[\s\S]*?shuffle_webhook_header_key" 'Detection-only still requires protected Shuffle secrets.'
Assert-Match 'Get-SocQueueUrl[\s\S]*?TransportProperty[\s\S]*?queue_arn[\s\S]*?dlq_arn' 'Start does not retain the safe Queue/DLQ ARN fallback.'
Assert-Match 'Detection-only Compose unexpectedly contains a Full SOC mount' 'Detection-only does not reject leaked Full SOC mounts.'
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
Assert-Match 'Read-SocHardeningEvidence' 'Start does not read the hardening Evidence.'
Assert-Match 'Read-DailySessionState[\s\S]*?Invoke-SocFreshHardeningEvidence[\s\S]*?-NotBeforeUtc \(\[datetimeoffset\]\$dailySession\.StartedAtUtc\)' 'Start does not bind fresh hardening Evidence to the Active Daily Session start.'
Assert-Match 'invocationStartedAtUtc[\s\S]*?minimumCheckedAtUtc[\s\S]*?Read-SocHardeningEvidence' 'Start allows a pre-existing hardening Evidence file to satisfy a fresh preflight.'
Assert-Match '-EvidencePath \$evidencePath[\s\S]*?-ExpectedSha256 \$evidenceSha256[\s\S]*?-ExpectedRuntimeSessionId \$runtimeSessionId' 'Start does not consume the exact path, hash, and runtime ID returned by the fresh runner.'
Assert-Match 'TotalMinutes -gt 30' 'Start does not enforce the 30-minute hardening Evidence age limit.'
Assert-Match 'Assert-SocHardeningDpapiBinding' 'Start does not bind hardening Evidence to current DPAPI records.'
Assert-Match 'Get-SocJsonBooleanProperty' 'Start does not require actual JSON Boolean hardening fields.'
Assert-Match 'producer_mode' 'Start does not read the hardening producer mode.'
Assert-Match 'verify_existing' 'Start does not recognize verify-only hardening Evidence.'
Assert-Match 'mutating_hardening' 'Start does not recognize explicit mutating hardening Evidence.'
Assert-Match 'wazuh_authentication_verified' 'READY Evidence does not record authentication verification.'
Assert-Match 'wazuh_credential_rotation_observed' 'READY Evidence does not record credential rotation semantics.'
Assert-NotMatch 'wazuh_rotated_auth' 'READY Evidence retains the misleading rotated-auth field.'
Assert-Match 'named_volumes_before_sha256[\s\S]*?-cne[\s\S]*?named_volumes_after_sha256' 'Start does not require exact before/after named-volume hash equality.'
Assert-Match "'CreatedAt','MountpointSha256'" 'Start does not bind named volumes to creation time and mountpoint identity.'
Assert-Match "install[\s\S]*?custom-shuffle-soc[\s\S]*?'/var/ossec/bin/wazuh-control','restart'" 'Start does not install and activate the custom Wazuh integration through the manager daemon controller.'
Assert-NotMatch "Arguments\s+@\(\s*'restart','wazuh\.manager'" 'Start must not restart the Manager container after applying protected credentials.'
Assert-Match 'currentNames[\s\S]*?desiredNames[\s\S]*?would add or remove a Wazuh user' 'Start does not fail closed when the protected internal-user name set drifts.'
Assert-Match "securityadmin\.sh'[\s\S]*?'-f','/usr/share/wazuh-indexer/config/opensearch-security/internal_users\.yml'[\s\S]*?'-t','internalusers'" 'Start does not restrict the OpenSearch security update to internal users.'
Assert-Match 'wazuh-integratord is running[\s\S]*?wazuh-control status' 'Start does not verify the required Wazuh manager daemons.'
Assert-Match "filebeat','test','output'[\s\S]*?talk to server" 'Start does not verify Filebeat authentication to the indexer.'
Assert-Match 'bridgeLiveFilePath[\s\S]*?FileMode\]::CreateNew[\s\S]*?LiveSpoolPath' 'Start does not create and bind the live bridge spool before Compose startup.'
Assert-Match '--config[\s\S]*?RedirectStandardInput\s*=\s*\$true[\s\S]*?StandardInput\.WriteLine' 'Start does not pass loopback credentials through curl configuration on standard input.'
Assert-Match "Port -eq 9200[\s\S]*?'wazuh\.indexer'[\s\S]*?'localhost'[\s\S]*?/var/ossec/api/configuration/ssl/server\.crt" 'Start does not verify the Wazuh API against its localhost-only server certificate.'
Assert-Match "official default admin credential[\s\S]*?official default kibanaserver credential[\s\S]*?official default wazuh-wui credential" 'Post-start READY checks do not reject all three official Wazuh defaults.'
Assert-Match 'official default wazuh-wui credential[\s\S]*?Invoke-SocFreshHardeningEvidence[\s\S]*?\$hardeningEvidencePath' 'READY is not rebound to a fresh post-start container, port, volume, and six-probe observation.'
Assert-Match 'Wait-SocBridgeReady[\s\S]*?dlq_visible[\s\S]*?queue_oldest_age_seconds' 'Start does not enforce the Bridge heartbeat readiness contract.'
Assert-Match "Invoke-WazuhPushValidation\.ps1[\s\S]*?SEND WAZUH PUSH VALIDATION" 'Start does not execute the harmless Rule 100102 probe.'
Assert-Match "rule\.id'\s*=\s*'100102'[\s\S]*?data\.payload\.take_id" 'Start does not query one exact safe-probe alert.'
Assert-Match 'ConvertTo-SocProcessArgument[\s\S]*?bridgeArgumentLine[\s\S]*?-ArgumentList \$bridgeArgumentLine' 'Start does not preserve multiword confirmations and spaced paths when spawning the Bridge.'
Assert-Match 'hooks/\(\?:webhook_\)\?\$webhookId\|webhooks/webhook_\$webhookId' 'Start does not accept the bounded Shuffle Cloud hooks/webhook_UUID endpoint shape.'
Assert-Match 'Register-ShuffleSocTake[\s\S]*?Set-SocTakeStatus[\s\S]*?READY' 'Start does not register and verify the TAKE before READY.'
Assert-Match 'SOC_LAB_READY=yes[\s\S]*?ACTIVE_TAKE_ID=[\s\S]*?RESPONSE_MODE=[\s\S]*?READY_EVIDENCE=' 'Start lacks the frozen four-line READY output.'
Assert-Match "Invoke-SocComposeCapture[\s\S]*?Arguments @\('down'\)" 'Start does not stop Wazuh on partial failure before deleting Runtime Secrets.'
Assert-NotMatch "Invoke-SocNativeCapture\s+-FilePath\s+'terraform'[\s\S]{0,240}'(apply|destroy)'|Invoke-SocNativeCapture\s+-FilePath\s+'gh'[\s\S]{0,300}'--method','(POST|PUT|PATCH|DELETE)'" 'Start contains a forbidden Terraform or GitHub mutation.'
Assert-NotMatch 'Invoke-CapitalOneBaseline|RUN CAPITAL ONE BASELINE' 'Start must not execute a real attack.'

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('Start-SocLab parser errors: ' + (@($errors.Message) -join '; '))
}
$quoteFunction = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'ConvertTo-SocProcessArgument'
}, $true)
if ($null -eq $quoteFunction) {
    throw 'The Bridge process-argument quoting helper could not be loaded for its runtime contract test.'
}
Invoke-Expression $quoteFunction.Extent.Text
if ((ConvertTo-SocProcessArgument -Value 'plain') -cne 'plain' -or
    (ConvertTo-SocProcessArgument -Value 'CONSUME WAZUH PUSH') -cne '"CONSUME WAZUH PUSH"' -or
    (ConvertTo-SocProcessArgument -Value 'C:\Path With Space\') -cne '"C:\Path With Space\\"' -or
    (ConvertTo-SocProcessArgument -Value 'quote"inside') -cne '"quote\"inside"') {
    throw 'The Bridge process-argument quoting helper failed a Windows command-line round-trip fixture.'
}

$queueFunction = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-SocQueueUrl'
}, $true)
if ($null -eq $queueFunction) {
    throw 'The Queue URL fallback helper could not be loaded for its runtime contract test.'
}
Invoke-Expression $queueFunction.Extent.Text
$script:foundationRoot = 'C:\fixture-foundation'
$script:expectedRegion = 'ap-northeast-2'
$script:expectedAccountId = '433048100798'
function Get-SocTerraformRaw { throw 'fixture output absent' }
$transportFixture = [pscustomobject]@{
    queue_arn = 'arn:aws:sqs:ap-northeast-2:433048100798:primary-test'
    dlq_arn = 'arn:aws:sqs:ap-northeast-2:433048100798:primary-test-dlq'
}
if ((Get-SocQueueUrl -OutputName 'missing' -TransportProperty 'dlq_arn' `
        -Transport $transportFixture) -cne
    'https://sqs.ap-northeast-2.amazonaws.com/433048100798/primary-test-dlq') {
    throw 'The Queue URL fallback did not derive the fixed SQS URL from the DLQ ARN.'
}
$foreignArnRejected = $false
try {
    [void](Get-SocQueueUrl -OutputName 'missing' -TransportProperty 'dlq_arn' `
        -Transport ([pscustomobject]@{
            dlq_arn = 'arn:aws:sqs:ap-northeast-2:000000000000:foreign-dlq'
        }))
} catch {
    $foreignArnRejected = $_.Exception.Message -match 'outside the fixed SOC account or region'
}
if (-not $foreignArnRejected) {
    throw 'The Queue URL fallback accepted a foreign account ARN.'
}

Write-Host 'SOC lab one-command READY static tests passed.'
