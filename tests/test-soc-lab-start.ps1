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

$containDiagnostic = 'The legacy Rule 100103 Active TAKE cannot authorize v2/100104 containment'
Assert-Match 'legacy v1 control for the Rule 100103 early-warning[\s\S]*?Current high-confidence S3 Alerts use Rule 100104/schema v2' `
    'Start does not document the legacy Rule 100103 versus current v2/100104 boundary.'
Assert-Match "ResponseMode\s*-ceq\s*'observe_only'" `
    'Start no longer exposes the allowed Rule 100103 OBSERVE_ONLY mode.'
$containOutput = @(& (Get-Command pwsh -ErrorAction Stop).Source -NoProfile -File $path `
    -Scope full -ResponseMode contain 2>&1)
$containExitCode = $LASTEXITCODE
$containText = ($containOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
if ($containExitCode -eq 0 -or $containText -notmatch [regex]::Escape($containDiagnostic)) {
    throw 'Start did not reject legacy Rule 100103 containment at the CLI boundary.'
}

Assert-Match "ConfirmStart\s+-cne\s+'START SOC LAB'" 'Start lacks its exact mutation confirmation.'
Assert-Match '\$Scope\s*=\s*\$Scope\.ToLowerInvariant\(\)[\s\S]*?\$ResponseMode\s*=\s*\$ResponseMode\.ToLowerInvariant\(\)' 'Start does not normalize case-insensitive ValidateSet values before case-sensitive routing.'
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
Assert-Match 'Get-ShuffleSocObserveOnlyWorkflow' 'OBSERVE_ONLY does not read back its dedicated Shuffle Workflow contract.'
Assert-Match "ResponseMode\s+-ceq\s+'observe_only'[\s\S]*?Get-ShuffleSocObserveOnlyWorkflow[\s\S]*?shuffleWorkflowStage\s*=\s*'observe_only'" 'OBSERVE_ONLY does not use the observe-only Workflow assertion and evidence stage.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Assert-ShuffleSocProductionWorkflow[\s\S]*?shuffleWorkflowStage\s*=\s*'production'" 'Contain READY does not require the strict Production Workflow export contract.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Get-ShuffleSocAppUploadEvidence[\s\S]*?Get-ShuffleSocCloudProvenance[\s\S]*?authentication_active[\s\S]*?secret_value_inspected" 'Contain READY does not bind the Workflow to the uploaded private Apps and encrypted Dispatcher Authentication.'
Assert-Match "ResponseMode\s+-ceq\s+'contain'[\s\S]*?Assert-ShuffleSocGateB5Evidence" 'Contain READY does not require prior Gate B5 Runtime atomicity Evidence.'
Assert-Match 'Get-ShuffleSocCoreContractSha256[\s\S]*?WorkflowCoreSha256[\s\S]*?Production Workflow core changed' 'Contain READY does not bind Production to the Gate B5 core fingerprint.'
Assert-Match 'shuffle_workflow_stage' 'READY Evidence does not preserve the validated Shuffle stage.'
Assert-Match 'shuffle_cloud_provenance[\s\S]*?validator_app_id[\s\S]*?dispatcher_app_id[\s\S]*?dispatcher_authentication_id_sha256[\s\S]*?secret_value_inspected' 'READY Evidence does not preserve sanitized Cloud App and Authentication provenance.'
Assert-Match 'shuffle_gate_b5_evidence[\s\S]*?manifest_sha256[\s\S]*?workflow_core_sha256' 'READY Evidence does not bind the prior Gate B5 manifest and core fingerprint.'
Assert-Match 'Get-SocGithubState' 'Start does not verify both remote GitHub Workflows and main.'
Assert-Match 'Get-SocArgoState' 'Start does not verify exact Argo health and revision.'
Assert-Match "if \(\`$Scope -ceq 'full' -and \`$ResponseMode -ceq 'contain'\) \{[\s\S]*?\`$githubState = Get-SocGithubState[\s\S]*?\`$argoState = Get-SocArgoState" 'OBSERVE_ONLY still requires GitHub or Argo reads.'
Assert-Match 'Assert-SocEffectiveCompose' 'Start does not inspect its effective local-only Compose configuration.'
Assert-Match 'Read-SocHardeningEvidence' 'Start does not read the hardening Evidence.'
Assert-Match 'Read-DailySessionState[\s\S]*?Invoke-SocFreshHardeningEvidence[\s\S]*?-NotBeforeUtc \(\[datetimeoffset\]\$dailySession\.StartedAtUtc\)' 'Start does not bind fresh hardening Evidence to the Active Daily Session start.'
Assert-Match 'Get-SocWazuhPreflightRuntimeState[\s\S]*?deferred_stopped_runtime[\s\S]*?partial or mixed' 'Start does not classify stopped versus partial Wazuh preflight state fail-closed.'
Assert-Match 'preflightRuntimeState\.Mode[\s\S]*?verified_existing[\s\S]*?deferred_stopped_runtime' 'Start does not defer fresh preflight only for an entirely stopped/absent runtime.'
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
Assert-Match '\$knownDefaultCredential\s*=\s*\([\s\S]*?admin[\s\S]*?Secret.*?Password[\s\S]*?kibanaserver[\s\S]*?kibana.*?server[\s\S]*?wazuh-wui[\s\S]*?MyS3cr37P450r' 'Loopback negative probes do not whitelist all three exact official default credentials.'
Assert-Match '-notmatch[\s\S]*?-and[\s\S]*?-not \$knownDefaultCredential' 'Loopback requests no longer reject arbitrary credentials outside the generated-secret contract.'
Assert-Match 'official default wazuh-wui credential[\s\S]*?Invoke-SocFreshHardeningEvidence[\s\S]*?\$hardeningEvidencePath' 'READY is not rebound to a fresh post-start container, port, volume, and six-probe observation.'
Assert-Match 'Wait-SocBridgeReady[\s\S]*?dlq_visible[\s\S]*?queue_oldest_age_seconds' 'Start does not enforce the Bridge heartbeat readiness contract.'
Assert-Match 'function Get-SocBridgeFailureCategory[\s\S]*?dlq_nonempty[\s\S]*?inflight_nonzero[\s\S]*?stale_primary_backlog[\s\S]*?lock_held[\s\S]*?aws_request_failed[\s\S]*?unknown' 'Start does not map bounded Bridge failure categories.'
Assert-Match 'function Write-SocBridgeFailureEvidence[\s\S]*?soc-lab-failures[\s\S]*?Write-SocAtomicJson' 'Start does not preserve sanitized Bridge failure Evidence before runtime cleanup.'
Assert-Match 'Get-SocBridgeFailureCategory[\s\S]*?Write-SocBridgeFailureEvidence[\s\S]*?Remove-SocRuntimeSession' 'Bridge failure Evidence is not written before runtime cleanup.'
Assert-Match "Invoke-WazuhPushValidation\.ps1[\s\S]*?SEND WAZUH PUSH VALIDATION" 'Start does not execute the harmless Rule 100102 probe.'
Assert-Match "rule\.id'\s*=\s*'100102'[\s\S]*?data\.payload\.take_id" 'Start does not query one exact safe-probe alert.'
Assert-Match 'ConvertTo-SocProcessArgument[\s\S]*?bridgeArgumentLine[\s\S]*?-ArgumentList \$bridgeArgumentLine' 'Start does not preserve multiword confirmations and spaced paths when spawning the Bridge.'
Assert-Match 'hooks/\(\?:webhook_\)\?\$webhookId\|webhooks/webhook_\$webhookId' 'Start does not accept the bounded Shuffle Cloud hooks/webhook_UUID endpoint shape.'
Assert-Match 'Register-ShuffleSocTake[\s\S]*?Set-SocTakeStatus[\s\S]*?READY' 'Start does not register and verify the TAKE before READY.'
Assert-Match "if \(\`$Scope -ceq 'full' -and \`$ResponseMode -ceq 'contain'\) \{[\s\S]*?Register-ShuffleSocTake" 'OBSERVE_ONLY still registers a Shuffle Datastore TAKE.'
Assert-Match "requiredCommands[\s\S]*?Scope -ceq 'full' -and \`$ResponseMode -ceq 'contain'[\s\S]*?gh','ssh" 'OBSERVE_ONLY still requires gh or ssh.'
Assert-Match 'Skipped in OBSERVE_ONLY: GitHub, Argo CD, Shuffle Datastore TAKE registration' 'The preview does not disclose OBSERVE_ONLY exclusions.'
Assert-Match 'Assert-SocLegacyObserveOnlyTake' 'OBSERVE_ONLY does not bind the Active TAKE to the legacy Rule 100103 contract.'
Assert-Match 'Current v2/100104 sanitized Alerts do not contain TAKE_ID' 'OBSERVE_ONLY does not disclose that TAKE_ID is outside the v2 Alert payload.'
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
$bridgeCategoryFunction = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-SocBridgeFailureCategory'
}, $true)
if ($null -eq $bridgeCategoryFunction) {
    throw 'The Bridge failure category helper could not be loaded for its mock contract test.'
}
Invoke-Expression $bridgeCategoryFunction.Extent.Text
$bridgeFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-bridge-category-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $bridgeFixtureRoot -Force | Out-Null
    $bridgeHeartbeatPath = Join-Path $bridgeFixtureRoot 'heartbeat.json'
    $bridgeStdoutPath = Join-Path $bridgeFixtureRoot 'stdout.log'
    $bridgeStderrPath = Join-Path $bridgeFixtureRoot 'stderr.log'
    $getBridgeCategory = {
        param([hashtable]$Heartbeat,[string]$Diagnostic)
        $Heartbeat | ConvertTo-Json | Set-Content -LiteralPath $bridgeHeartbeatPath
        Set-Content -LiteralPath $bridgeStdoutPath -Value ''
        Set-Content -LiteralPath $bridgeStderrPath -Value $Diagnostic
        return Get-SocBridgeFailureCategory -HeartbeatPath $bridgeHeartbeatPath `
            -StandardOutputPath $bridgeStdoutPath -StandardErrorPath $bridgeStderrPath
    }
    $bridgeCategoryResults = @(
        (& $getBridgeCategory @{queue_visible=2;queue_not_visible=0;queue_oldest_age_seconds=121;dlq_visible=0} '')
        (& $getBridgeCategory @{queue_visible=0;queue_not_visible=0;queue_oldest_age_seconds=0;dlq_visible=1} '')
        (& $getBridgeCategory @{queue_visible=0;queue_not_visible=1;queue_oldest_age_seconds=0;dlq_visible=0} '')
        (& $getBridgeCategory @{queue_visible=0;queue_not_visible=0;queue_oldest_age_seconds=0;dlq_visible=0} 'spool lock')
        (& $getBridgeCategory @{queue_visible=0;queue_not_visible=0;queue_oldest_age_seconds=0;dlq_visible=0} 'AWS CLI request failed')
        (& $getBridgeCategory @{queue_visible=0;queue_not_visible=0;queue_oldest_age_seconds=0;dlq_visible=0} 'other')
    )
    if ((@($bridgeCategoryResults | ForEach-Object { [string]$_.category }) -join ',') -cne
        'stale_primary_backlog,dlq_nonempty,inflight_nonzero,lock_held,aws_request_failed,unknown') {
        throw 'The Bridge failure category helper returned an unexpected bounded category.'
    }
} finally {
    if (Test-Path -LiteralPath $bridgeFixtureRoot) {
        Remove-Item -LiteralPath $bridgeFixtureRoot -Recurse -Force
    }
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

$preflightFunction = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-SocWazuhPreflightRuntimeState'
}, $true)
if ($null -eq $preflightFunction) {
    throw 'The Wazuh preflight runtime classifier could not be loaded for its mock contract test.'
}
Invoke-Expression $preflightFunction.Extent.Text
$script:preflightIds = @{}
$script:preflightStates = @{}
$preflightComposeAdapter = {
    param([string[]]$File,[string[]]$Arguments)
    [string]$script:preflightIds[[string]$Arguments[-1]]
}
$preflightInspectAdapter = {
    param([string]$ContainerId)
    [string]$script:preflightStates[$ContainerId]
}
$script:preflightIds = @{
    'wazuh.manager' = ('a' * 64)
    'wazuh.indexer' = ('b' * 64)
    'wazuh.dashboard' = ('c' * 64)
}
$script:preflightStates = @{
    (('a' * 64)) = 'running'
    (('b' * 64)) = 'running'
    (('c' * 64)) = 'running'
}
$runningState = Get-SocWazuhPreflightRuntimeState -ComposePath 'C:\fixture\docker-compose.yml' `
    -ComposeAdapter $preflightComposeAdapter -InspectAdapter $preflightInspectAdapter
if ([string]$runningState.Mode -cne 'running') {
    throw 'The Wazuh preflight classifier did not accept exactly one running container per service.'
}
$script:preflightStates[('a' * 64)] = 'exited'
$script:preflightStates[('b' * 64)] = 'exited'
$script:preflightStates[('c' * 64)] = 'exited'
$stoppedState = Get-SocWazuhPreflightRuntimeState -ComposePath 'C:\fixture\docker-compose.yml' `
    -ComposeAdapter $preflightComposeAdapter -InspectAdapter $preflightInspectAdapter
if ([string]$stoppedState.Mode -cne 'deferred_stopped_runtime') {
    throw 'The Wazuh preflight classifier did not defer an entirely stopped runtime.'
}
$script:preflightIds['wazuh.manager'] = ''
$mixedStoppedRejected = $false
try {
    [void](Get-SocWazuhPreflightRuntimeState -ComposePath 'C:\fixture\docker-compose.yml' `
        -ComposeAdapter $preflightComposeAdapter -InspectAdapter $preflightInspectAdapter)
} catch {
    $mixedStoppedRejected = $_.Exception.Message -match 'partial or mixed'
}
if (-not $mixedStoppedRejected) {
    throw 'The Wazuh preflight classifier accepted a mixed absent/stopped runtime.'
}
$script:preflightIds['wazuh.manager'] = ('a' * 64)
$script:preflightStates[('a' * 64)] = 'running'
$partialRejected = $false
try {
    [void](Get-SocWazuhPreflightRuntimeState -ComposePath 'C:\fixture\docker-compose.yml' `
        -ComposeAdapter $preflightComposeAdapter -InspectAdapter $preflightInspectAdapter)
} catch {
    $partialRejected = $_.Exception.Message -match 'partial or mixed'
}
if (-not $partialRejected) {
    throw 'The Wazuh preflight classifier accepted a partial runtime.'
}
$script:preflightStates[('a' * 64)] = 'running'
$script:preflightIds['wazuh.manager'] = (('a' * 64) + "`n" + ('d' * 64))
$duplicateRejected = $false
try {
    [void](Get-SocWazuhPreflightRuntimeState -ComposePath 'C:\fixture\docker-compose.yml' `
        -ComposeAdapter $preflightComposeAdapter -InspectAdapter $preflightInspectAdapter)
} catch {
    $duplicateRejected = $_.Exception.Message -match 'duplicate containers'
}
if (-not $duplicateRejected) {
    throw 'The Wazuh preflight classifier accepted duplicate containers.'
}

Write-Host 'SOC lab one-command READY static tests passed.'
