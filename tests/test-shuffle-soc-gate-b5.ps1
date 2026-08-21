#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'observability\scenarios\Test-ShuffleSocGateB5.ps1'
$text = Get-Content -LiteralPath $scriptPath -Raw
$shuffleModuleText = Get-Content -LiteralPath (Join-Path $root 'automation\SocLab.Shuffle.psm1') -Raw
Import-Module (Join-Path $root 'automation\SocLab.Shuffle.psm1') -Force

# Exercise the v2 helper against a fully local fixture.  This never reaches
# Shuffle; it proves the raw-workflow assertion and fingerprint are callable
# without the legacy v1 getter/core contract.
$v2WorkflowId = '11111111-1111-4111-8111-111111111111'
$v2WebhookId = '22222222-2222-4222-8222-222222222222'
$v2ActionIds = @(
    '33333333-3333-4333-8333-333333333331',
    '33333333-3333-4333-8333-333333333332',
    '33333333-3333-4333-8333-333333333333',
    '33333333-3333-4333-8333-333333333334',
    '33333333-3333-4333-8333-333333333335',
    '33333333-3333-4333-8333-333333333336',
    '33333333-3333-4333-8333-333333333337',
    '33333333-3333-4333-8333-333333333338',
    '33333333-3333-4333-8333-333333333339'
)
$v2ActionLabels = @(
    'validate_payload','claim_event_dedupe','classify_dedupe_claim','write_duplicate_suppressed',
    'write_observe_only','write_rejected_schema','write_rejected_allowlist',
    'write_safety_gate_blocked','repeat_back_to_me'
)
$v2Actions = for ($index = 0; $index -lt $v2ActionLabels.Count; $index++) {
    $label = $v2ActionLabels[$index]
    if ($label -ceq 'validate_payload') {
        [pscustomobject]@{
            id=$v2ActionIds[$index];label=$label;app_id=('a' * 32);is_valid=$true
            app_name='AWS Topology SOC Validator';app_version='1.0.0'
            name='validate_sanitized_alert'
            parameters=@([pscustomobject]@{name='input_data';value='$exec'})
        }
    } elseif ($label -ceq 'claim_event_dedupe') {
        [pscustomobject]@{
            id=$v2ActionIds[$index];label=$label;app_name='Shuffle Tools';is_valid=$true
            app_version='1.2.0';name='set_datastore_value'
            parameters=@(
                [pscustomobject]@{name='category';value='soc-v2'},
                [pscustomobject]@{name='key';value='$validate_payload.dedupe_key'},
                [pscustomobject]@{name='value';value='$validate_payload.body_sha256'}
            )
        }
    } elseif ($label -ceq 'classify_dedupe_claim') {
        [pscustomobject]@{
            id=$v2ActionIds[$index];label=$label;app_name='AWS Topology SOC Validator';is_valid=$true
            app_version='1.0.0';name='classify_dedupe_claim'
            parameters=@(
                [pscustomobject]@{name='claim_result';value='$claim_event_dedupe'},
                [pscustomobject]@{name='expected_key';value='$validate_payload.dedupe_key'}
            )
        }
    } elseif ($label -ceq 'repeat_back_to_me') {
        [pscustomobject]@{
            id=$v2ActionIds[$index];label=$label;app_name='Shuffle Tools';is_valid=$true
            app_version='1.2.0';name='repeat_back_to_me'
            parameters=@([pscustomobject]@{name='call';value='GATE_B5_REPEAT_STUB'})
        }
    } else {
        [pscustomobject]@{
            id=$v2ActionIds[$index];label=$label;app_name='Shuffle Tools';is_valid=$true
            app_version='1.2.0';name='repeat_back_to_me'
            parameters=@([pscustomobject]@{name='call';value=$label})
        }
    }
}
function New-V2Condition {
    param([Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$Destination)
    [pscustomobject]@{
        source=[pscustomobject]@{id=[guid]::NewGuid().ToString();name='source';variant='STATIC_VALUE';value=$Source}
        condition=[pscustomobject]@{id=[guid]::NewGuid().ToString();name='condition';value='equals'}
        destination=[pscustomobject]@{id=[guid]::NewGuid().ToString();name='destination';variant='STATIC_VALUE';value=$Destination}
    }
}
$v2Branches = @(
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444441';source_id=$v2WebhookId;destination_id=$v2ActionIds[0];conditions=@()},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444442';source_id=$v2ActionIds[0];destination_id=$v2ActionIds[1];conditions=@((New-V2Condition -Source '$validate_payload.valid' -Destination 'true'))},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444443';source_id=$v2ActionIds[0];destination_id=$v2ActionIds[5];conditions=@((New-V2Condition -Source '$validate_payload.rejection' -Destination 'REJECTED_SCHEMA'))},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444445';source_id=$v2ActionIds[0];destination_id=$v2ActionIds[6];conditions=@((New-V2Condition -Source '$validate_payload.rejection' -Destination 'REJECTED_ALLOWLIST'))},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444446';source_id=$v2ActionIds[1];destination_id=$v2ActionIds[2];conditions=@()},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444447';source_id=$v2ActionIds[2];destination_id=$v2ActionIds[7];conditions=@((New-V2Condition -Source '$classify_dedupe_claim.valid' -Destination 'false'))},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444448';source_id=$v2ActionIds[2];destination_id=$v2ActionIds[8];conditions=@((New-V2Condition -Source '$classify_dedupe_claim.valid' -Destination 'true'),(New-V2Condition -Source '$classify_dedupe_claim.existed' -Destination 'false'))},
    [pscustomobject]@{id='44444444-4444-4444-8444-444444444449';source_id=$v2ActionIds[2];destination_id=$v2ActionIds[3];conditions=@((New-V2Condition -Source '$classify_dedupe_claim.valid' -Destination 'true'),(New-V2Condition -Source '$classify_dedupe_claim.existed' -Destination 'true'))}
)
$v2Workflow = [pscustomobject]@{
    id=$v2WorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';sharing='private';is_valid=$true
    triggers=@([pscustomobject]@{id=$v2WebhookId;trigger_type='webhook';status='running';auth='X-SOC-Webhook-Key: synthetic-test-only'})
    actions=@($v2Actions);branches=$v2Branches
}
[void](Assert-ShuffleSocV2Workflow -Workflow $v2Workflow -WorkflowId $v2WorkflowId -WebhookId $v2WebhookId)
$v2CoreHash = Get-ShuffleSocV2CoreContractSha256 -Workflow $v2Workflow -WebhookId $v2WebhookId
if ($v2CoreHash -notmatch '^[a-f0-9]{64}$') { throw 'The v2 core fingerprint is malformed.' }
$v2Unsafe = $v2Workflow | ConvertTo-Json -Depth 30 | ConvertFrom-Json
@($v2Unsafe.actions | Where-Object { [string]$_.label -ceq 'claim_event_dedupe' })[0].name = 'execute_http_request'
$v2UnsafeRejected = $false
try {
    [void](Assert-ShuffleSocV2Workflow -Workflow $v2Unsafe -WorkflowId $v2WorkflowId -WebhookId $v2WebhookId)
} catch { $v2UnsafeRejected = $_.Exception.Message -match 'safe Action mapping' }
if (-not $v2UnsafeRejected) {
    throw 'The v2 assertion accepted an arbitrary non-validator Action shape.'
}
$v2Changed = $v2Workflow | ConvertTo-Json -Depth 30 | ConvertFrom-Json
@($v2Changed.actions | Where-Object { [string]$_.label -ceq 'validate_payload' })[0].app_id = ('b' * 32)
if ((Get-ShuffleSocV2CoreContractSha256 -Workflow $v2Changed -WebhookId $v2WebhookId) -ceq $v2CoreHash) {
    throw 'The v2 core fingerprint ignored the exact Action contract.'
}

$requirements = @(
    @{Pattern="ConfirmRun -cne 'RUN SHUFFLE GATE B5'";Message='Gate B5 lacks an exact external-write confirmation.'},
    @{Pattern='Assert-GateB5WorkflowContract';Message='Gate B5 does not prove the exact side-effect-free Workflow contract before sending.'},
    @{Pattern="'repeat_back_to_me'";Message='Gate B5 does not bind the repeat_back_to_me Stub.'},
    @{Pattern='GATE_B5_REPEAT_STUB';Message='Gate B5 Stub marker is not fixed.'},
    @{Pattern='cloudtrail_event_id';Message='Gate B5 does not use the CloudTrail eventID identity.'},
    @{Pattern='CAPITAL-ONE:\$\{account\}:\$\(\$eventId\.ToLowerInvariant\(\)\)';Message='Gate B5 does not construct the exact lowercase eventID Dedupe key.'},
    @{Pattern='Get-ShuffleSocWorkflowV2';Message='Gate B5 still uses the legacy v1 Workflow getter.'},
    @{Pattern='Get-ShuffleSocV2CoreContractSha256';Message='Gate B5 still uses the legacy v1 core fingerprint.'},
    @{Pattern='\[AllowEmptyString\(\)\]\[string\]\$HeaderKey';Message='Missing Webhook Header binding is not explicitly allowed to be empty.'},
    @{Pattern='SupportsShouldProcess';Message='Missing Webhook Header binding lacks a runtime-free invocation path.'},
    @{Pattern='GT05-06 containment';Message='Gate B5 Evidence is not inside the GT05-06 containment bundle.'},
    @{Pattern='gate-b5\\\$runId';Message='Gate B5 Evidence does not use the gate-b5 section.'},
    @{Pattern='bundle_section_path';Message='Gate B5 artifact/manifest does not declare its bundle section.'},
    @{Pattern='failure_stage=\$failureStage[\s\S]*?failure_category=\$failureCategory[\s\S]*?exception_type=\$safeExceptionType';Message='Gate B5 failure Evidence is not reduced to fixed stage/category/exception enums.'},
    @{Pattern='Send-GateB5ExecuteBatch[\s\S]*?-PayloadJson \(\[string\]\$valid\.Json\) -Count 10';Message='Gate B5 does not execute one exact Payload ten times concurrently.'},
    @{Pattern='-IncludeHeader -ExpectedSuccess \$false[\s\S]*?Assert-GateB5NoNewExecution[\s\S]*?HeaderKey .+ -PayloadJson[\s\S]*?-ExpectedSuccess \$false';Message='Gate B5 does not test wrong and missing Webhook Headers without an Execution.'},
    @{Pattern='Always perform a final bounded query[\s\S]*?Get-GateB5ExecutionIds';Message='Rejected-header observation may return early without a final bounded query.'},
    @{Pattern='new_claim_count=\$freshCount[\s\S]*?duplicate_claim_count=\$duplicateCount[\s\S]*?stub_execution_count=\$stubCount[\s\S]*?external_action_count=\$externalActionCount';Message='Gate B5 does not persist atomicity and zero-external-action evidence.'},
    @{Pattern="'wrong-account'='write_rejected_allowlist'[\s\S]*?'wrong-scenario'='write_rejected_allowlist'[\s\S]*?'wrong-rule'='write_rejected_allowlist'[\s\S]*?'wrong-body-hash'='write_rejected_schema'";Message='Gate B5 negative cases are not bound to their intended branches.'},
    @{Pattern="'wrong-role'='write_rejected_allowlist'[\s\S]*?'wrong-bucket'='write_rejected_allowlist'[\s\S]*?'wrong-key'='write_rejected_allowlist'";Message='Gate B5 does not test the full fixed allowlist.'},
    @{Pattern="'claim_event_dedupe'[\s\S]*?'repeat_back_to_me'[\s\S]*?Get-GateB5ExternalActionCount";Message='Gate B5 does not reject claims/stub/external actions for negative cases.'},
    @{Pattern='externalActionCount -ne 0';Message='Gate B5 can falsely record an external Action.'},
    @{Pattern='real_github_dispatch_count=0';Message='Gate B5 does not record zero real GitHub dispatches.'},
    @{Pattern='Remove-ShuffleSocV2CacheKey';Message='Gate B5 lacks bounded v2 event Dedupe cleanup.'},
    @{Pattern='real_containment_count=0';Message='Gate B5 does not record zero Containment actions.'},
    @{Pattern='-match \x27\(\?i\)\(github\|http\|argo\|kubernetes\|kubectl\)';Message='Gate B5 does not reject external dispatch-capable Actions.'},
    @{Pattern='Test-SocSecretExposure\.ps1';Message='Gate B5 Evidence is not secret-scanned.'}
)
foreach ($requirement in $requirements) {
    if ($text -notmatch $requirement.Pattern) { throw $requirement.Message }
}
foreach ($requirement in @(
    @{Pattern='set_datastore_value';Message='Gate B5 does not bind the exact Shuffle Datastore claim Action.'},
    @{Pattern='\$validate_payload\.dedupe_key';Message='Gate B5 Datastore claim key is not bound to the Validator output.'},
    @{Pattern='\$validate_payload\.body_sha256';Message='Gate B5 Datastore claim value is not bound to the Validator output.'},
    @{Pattern='classify_dedupe_claim';Message='Gate B5 Dedupe Branch does not use the scalar Dedupe Classifier.'},
    @{Pattern='\$classify_dedupe_claim\.valid';Message='Gate B5 Dedupe safety branch does not use the scalar valid result.'},
    @{Pattern='\$classify_dedupe_claim\.existed';Message='Gate B5 Dedupe branches do not use the scalar existed result.'}
)) {
    if ($shuffleModuleText -notmatch $requirement.Pattern) { throw $requirement.Message }
}
foreach ($forbidden in @('Write-(Host|Output).*?\$(apiKey|webhookUrl|headerKey|Authorization)','Out-File.*?\$(apiKey|webhookUrl|headerKey)')) {
    if ($text -match $forbidden) { throw 'Gate B5 may print or persist a secret-bearing variable.' }
}
if ($text -match "-Case wrong-take" -or
    $text -match '\.incident\.take_id' -or
    $text -match 'soc:v1' -or
    $text -match '\$takeId') {
    throw 'Gate B5 retains a legacy TAKE payload or soc:v1 dependency.'
}
if ($text -match 'shuffle-gate-b5') {
    throw 'Gate B5 still writes a forbidden separate top-level shuffle-gate-b5 bundle.'
}
if ($text -match 'error_message|error_type') {
    throw 'Gate B5 failure Evidence still persists a raw exception field.'
}

$tokens = $null
$parseErrors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$parseErrors
)
$webhookFunctionAst = $scriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Send-GateB5WebhookBatch'
}, $true)
if ($null -eq $webhookFunctionAst) {
    throw 'The Gate B5 Webhook batch function could not be isolated for the binding probe.'
}
. ([scriptblock]::Create($webhookFunctionAst.Extent.Text))
$bindingProbe = @(Send-GateB5WebhookBatch `
    -WebhookUri ([uri]'https://example.invalid/gate-b5') -HeaderKey '' `
    -PayloadJson '{}' -Count 1 -ExpectedSuccess:$false -WhatIf)
if ($bindingProbe.Count -ne 1 -or
    [bool]$bindingProbe[0].WhatIf -ne $true -or
    [bool]$bindingProbe[0].HeaderKeyBound -ne $true) {
    throw 'The missing Webhook Header did not bind through the runtime-free probe.'
}

$invalidV2Keys = @(
    'CAPITAL-ONE:433048100798:AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
    'soc:v2:433048100798:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'capital-one:433048100798:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
)
foreach ($invalidV2Key in $invalidV2Keys) {
    $v2KeyRejected = $false
    try {
        [void](Remove-ShuffleSocV2CacheKey `
            -Key $invalidV2Key `
            -OrgId '33333333-3333-4333-8333-333333333333' -ApiKey 'synthetic-only')
    } catch { $v2KeyRejected = $_.Exception.Message -match 'outside the fixed namespace' }
    if (-not $v2KeyRejected) {
        throw "The v2 cache cleanup accepted an invalid key or would have reached the network: $invalidV2Key"
    }
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
