#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'automation\SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $root 'automation\SocLab.Shuffle.psm1') -Force

$workflowId = '11111111-1111-4111-8111-111111111111'
$webhookId = '22222222-2222-4222-8222-222222222222'
$orgId = '33333333-3333-4333-8333-333333333333'
$validatorAppId = 'a' * 32
$dispatcherAppId = 'b' * 32
$dispatcherAuthId = 'c' * 32
$workflow = [pscustomobject]@{
    id       = $workflowId
    name     = 'CAPITAL-ONE-SOC-CONTAINMENT-v1'
    sharing  = 'private'
    is_valid = $true
    triggers = @([pscustomobject]@{
        id           = $webhookId
        trigger_type = 'webhook'
        status       = 'running'
        auth         = 'X-SOC-Webhook-Key: synthetic-test-only'
    })
    actions = @(
        'validate_payload','get_take_allow','claim_take_dispatch',
        'dispatch_github_containment','write_response_dispatched',
        'write_duplicate_suppressed','write_observe_only',
        'write_rejected_schema','write_rejected_allowlist','write_rejected_take',
        'write_response_failed'
    ) | ForEach-Object {
        if ($_ -ceq 'validate_payload') {
            [pscustomobject]@{
                id=[guid]::NewGuid().ToString()
                label=$_
                app_id=$validatorAppId
                app_name='AWS Topology SOC Validator'
                app_version='1.0.0'
                name='validate_sanitized_alert'
                parameters=@([pscustomobject]@{
                    name='input_data';value='$exec'
                })
            }
        } elseif ($_ -ceq 'dispatch_github_containment') {
            [pscustomobject]@{
                id='44444444-4444-4444-8444-444444444444'
                label=$_
                app_name='Shuffle Tools'
                app_version='1.2.0'
                name='repeat_back_to_me'
                parameters=@([pscustomobject]@{
                    name='call';value='GATE_B5_GITHUB_STUB'
                })
            }
        } else {
            [pscustomobject]@{
                id=[guid]::NewGuid().ToString()
                label=$_
                app_name='Shuffle Tools'
                app_version='1.2.0'
                name='repeat_back_to_me'
                parameters=@([pscustomobject]@{name='call';value=$_})
            }
        }
    }
}
$claimId = [string]@($workflow.actions | Where-Object {
    [string]$_.label -ceq 'claim_take_dispatch'
})[0].id
$dispatchId = [string]@($workflow.actions | Where-Object {
    [string]$_.label -ceq 'dispatch_github_containment'
})[0].id
$workflow | Add-Member -NotePropertyName branches -NotePropertyValue @(
    [pscustomobject]@{
        id='55555555-5555-4555-8555-555555555555'
        source_id=$claimId
        destination_id=$dispatchId
        conditions=@([pscustomobject]@{source='$claim_take_dispatch.existed';operator='equals';value=$false})
    }
) -Force
[void](Assert-ShuffleSocWorkflow `
    -Workflow $workflow `
    -WorkflowId $workflowId `
    -WebhookId $webhookId)
[void](Assert-ShuffleSocGateB5Workflow `
    -Workflow $workflow `
    -WorkflowId $workflowId `
    -WebhookId $webhookId)
$gateWithoutClaimBranch = $workflow | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$gateWithoutClaimBranch.branches = @()
$gateWithoutClaimBranchRejected = $false
try {
    [void](Assert-ShuffleSocGateB5Workflow -Workflow $gateWithoutClaimBranch `
        -WorkflowId $workflowId -WebhookId $webhookId)
} catch { $gateWithoutClaimBranchRejected = $_.Exception.Message -match 'fresh-claim input' }
if (-not $gateWithoutClaimBranchRejected) {
    throw 'Gate B5 accepted a disconnected dispatch Stub.'
}

$inactive = $workflow.PSObject.Copy()
$inactive.triggers = @([pscustomobject]@{
    id = $webhookId; trigger_type = 'webhook'; status = 'stopped'
})
$inactiveRejected = $false
try {
    [void](Assert-ShuffleSocWorkflow `
        -Workflow $inactive `
        -WorkflowId $workflowId `
        -WebhookId $webhookId)
} catch {
    $inactiveRejected = $_.Exception.Message -match 'not active'
}
if (-not $inactiveRejected) {
    throw 'The Shuffle contract accepted an inactive Webhook.'
}

$productionDispatch = $workflow | ConvertTo-Json -Depth 20 | ConvertFrom-Json
@($productionDispatch.actions | Where-Object {
    [string]$_.label -ceq 'dispatch_github_containment'
})[0].app_name = 'GitHub'
$productionRejected = $false
try {
    [void](Assert-ShuffleSocGateB5Workflow `
        -Workflow $productionDispatch `
        -WorkflowId $workflowId `
        -WebhookId $webhookId)
} catch { $productionRejected = $_.Exception.Message -match 'dispatch Stub' }
if (-not $productionRejected) {
    throw 'Gate B5 accepted a real GitHub dispatch Action.'
}

$production = $workflow | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$dispatchAction = @($production.actions | Where-Object {
    [string]$_.label -ceq 'dispatch_github_containment'
})[0]
$dispatchAction.app_name = 'AWS Topology SOC GitHub Dispatcher'
$dispatchAction.app_version = '1.0.0'
$dispatchAction.name = 'dispatch_containment'
$dispatchAction | Add-Member -NotePropertyName app_id `
    -NotePropertyValue $dispatcherAppId -Force
$dispatchAction | Add-Member -NotePropertyName authentication_id `
    -NotePropertyValue $dispatcherAuthId -Force
$dispatchAction.parameters = @(
    [pscustomobject]@{
        name='github_token';value='';configuration=$true
    },
    [pscustomobject]@{
        name='take_id';value='$validate_payload.take_id'
    },
    [pscustomobject]@{
        name='scenario_id';value='$validate_payload.scenario_id'
    },
    [pscustomobject]@{
        name='rule_id';value='$validate_payload.rule_id'
    },
    [pscustomobject]@{
        name='alert_body_sha256';value='$validate_payload.body_sha256'
    }
)
$dispatchedWriterId = [string]@($production.actions | Where-Object {
    [string]$_.label -ceq 'write_response_dispatched'
})[0].id
$failedWriterId = [string]@($production.actions | Where-Object {
    [string]$_.label -ceq 'write_response_failed'
})[0].id
$production.branches += @(
    [pscustomobject]@{
        id='66666666-6666-4666-8666-666666666666'
        source_id=$dispatchId
        destination_id=$dispatchedWriterId
        conditions=@([pscustomobject]@{source='$dispatch_github_containment.success';operator='equals';value=$true})
    },
    [pscustomobject]@{
        id='77777777-7777-4777-8777-777777777777'
        source_id=$dispatchId
        destination_id=$failedWriterId
        conditions=@([pscustomobject]@{source='$dispatch_github_containment.success';operator='equals';value=$false})
    }
)
[void](Assert-ShuffleSocProductionWorkflow -Workflow $production `
    -WorkflowId $workflowId -WebhookId $webhookId)
$uploadEvidence = [pscustomobject]@{
    schema_version=1;artifact_kind='shuffle-soc-private-app-bundle-upload';
    organization_id=$orgId;secret_persisted=$false
    apps=@(
        [pscustomobject]@{app_name='AWS Topology SOC Validator';app_version='1.0.0';app_id=$validatorAppId;package_sha256=('d' * 64)},
        [pscustomobject]@{app_name='AWS Topology SOC GitHub Dispatcher';app_version='1.0.0';app_id=$dispatcherAppId;package_sha256=('e' * 64)}
    )
}
$cloudApps = @(
    [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0'},
    [pscustomobject]@{id=$dispatcherAppId;name='AWS Topology SOC GitHub Dispatcher';app_version='1.0.0'}
)
$cloudAuth = [pscustomobject]@{
    success=$true
    data=@([pscustomobject]@{
        id=$dispatcherAuthId;active=$true;encrypted=$true;org_id=$orgId
        app=[pscustomobject]@{id=$dispatcherAppId;name='AWS Topology SOC GitHub Dispatcher';app_version='1.0.0'}
        fields=@([pscustomobject]@{key='github_token';value='must-not-be-inspected'})
    })
}
$provenance = Assert-ShuffleSocCloudProvenance -Workflow $production `
    -UploadEvidence $uploadEvidence -AppsResponse $cloudApps `
    -AuthenticationResponse $cloudAuth -ExpectedOrgId $orgId
if (-not $provenance.authentication_active -or $provenance.secret_value_inspected) {
    throw 'The current private App and Authentication provenance was not verified safely.'
}
$wrongAuthApp = $cloudAuth | ConvertTo-Json -Depth 20 | ConvertFrom-Json
$wrongAuthApp.data[0].app.id = 'f' * 32
$wrongAuthRejected = $false
try {
    [void](Assert-ShuffleSocCloudProvenance -Workflow $production `
        -UploadEvidence $uploadEvidence -AppsResponse $cloudApps `
        -AuthenticationResponse $wrongAuthApp -ExpectedOrgId $orgId)
} catch { $wrongAuthRejected = $_.Exception.Message -match 'does not belong' }
if (-not $wrongAuthRejected) {
    throw 'A Dispatcher Authentication belonging to another App was accepted.'
}
$productionWithoutFailureBranch = $production | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$failureWriterIdForRemoval = [string]@($productionWithoutFailureBranch.actions | Where-Object {
    [string]$_.label -ceq 'write_response_failed'
})[0].id
$productionWithoutFailureBranch.branches = @(
    $productionWithoutFailureBranch.branches | Where-Object {
        [string]$_.destination_id -cne $failureWriterIdForRemoval
    }
)
$missingFailureBranchRejected = $false
try {
    [void](Assert-ShuffleSocProductionWorkflow -Workflow $productionWithoutFailureBranch `
        -WorkflowId $workflowId -WebhookId $webhookId)
} catch { $missingFailureBranchRejected = $_.Exception.Message -match 'success and one failure' }
if (-not $missingFailureBranchRejected) {
    throw 'Production accepted a dispatch Action without its failure Branch.'
}
$gateCoreHash = Get-ShuffleSocCoreContractSha256 -Workflow $workflow -WebhookId $webhookId
$productionCoreHash = Get-ShuffleSocCoreContractSha256 -Workflow $production -WebhookId $webhookId
if ($gateCoreHash -cne $productionCoreHash) {
    throw 'Replacing only the fixed dispatch slot changed the Shuffle core fingerprint.'
}
$changedCore = $production | ConvertTo-Json -Depth 30 | ConvertFrom-Json
@($changedCore.actions | Where-Object {
    [string]$_.label -ceq 'write_observe_only'
})[0].parameters[0].value = 'changed-after-gate'
if ((Get-ShuffleSocCoreContractSha256 -Workflow $changedCore -WebhookId $webhookId) -ceq $gateCoreHash) {
    throw 'A non-dispatch Action change did not change the Shuffle core fingerprint.'
}
$changedIncomingBranch = $production | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$dispatchIdForChange = [string]@($changedIncomingBranch.actions | Where-Object {
    [string]$_.label -ceq 'dispatch_github_containment'
})[0].id
@($changedIncomingBranch.branches | Where-Object {
    [string]$_.destination_id -ceq $dispatchIdForChange
})[0].conditions[0].value = $true
if ((Get-ShuffleSocCoreContractSha256 -Workflow $changedIncomingBranch `
    -WebhookId $webhookId) -ceq $gateCoreHash) {
    throw 'A fresh-claim input Branch change did not change the Shuffle core fingerprint.'
}

$productionWithoutAuthPlaceholder = $production | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$productionWithoutAuthPlaceholder.actions = @(
    $productionWithoutAuthPlaceholder.actions | ForEach-Object {
        if ([string]$_.label -ceq 'dispatch_github_containment') {
            $_.parameters = @($_.parameters | Where-Object {
                [string]$_.name -cne 'github_token'
            })
        }
        $_
    }
)
[void](Assert-ShuffleSocProductionWorkflow -Workflow $productionWithoutAuthPlaceholder `
    -WorkflowId $workflowId -WebhookId $webhookId)

$literalPat = $production | ConvertTo-Json -Depth 30 | ConvertFrom-Json
@($literalPat.actions | Where-Object {
    [string]$_.label -ceq 'dispatch_github_containment'
})[0].parameters += [pscustomobject]@{
    name='password';value=('github_' + 'pat_' + ('a' * 50));configuration=$false
}
$literalPatRejected = $false
try {
    [void](Assert-ShuffleSocProductionWorkflow -Workflow $literalPat `
        -WorkflowId $workflowId -WebhookId $webhookId)
} catch { $literalPatRejected = $_.Exception.Message -match 'literal GitHub credential' }
if (-not $literalPatRejected) {
    throw 'Production Workflow accepted a literal GitHub credential.'
}

$gateEvidenceRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('soc-gate-b5-test-' + [guid]::NewGuid().ToString('N'))
try {
    $gateTake = 'capital-one-20260818T020000Z-deadbeef'
    $gateRun = Join-Path $gateEvidenceRoot "shuffle-gate-b5\$gateTake"
    New-Item -ItemType Directory -Path $gateRun -Force | Out-Null
    $workflowEvidence = [ordered]@{
        schema_version=1;workflow_id=$workflowId;
        workflow_name='CAPITAL-ONE-SOC-CONTAINMENT-v1';
        workflow_export_sha256=('a' * 64);
        workflow_core_sha256=(Get-ShuffleSocCoreContractSha256 `
            -Workflow $workflow -WebhookId $webhookId);
        gate_b5_stub_verified=$true;
        real_dispatch_action_count=0
    }
    $negativeEvidence = @(
        'wrong-account','wrong-scenario','wrong-rule','wrong-take','wrong-body-hash'
    ) | ForEach-Object {
        [ordered]@{case=$_;claim_count=0;stub_count=0;github_dispatch_count=0}
    }
    $runtimeEvidence = [ordered]@{
        schema_version=1;concurrent_request_count=10;unique_execution_count=10;
        new_claim_count=1;duplicate_claim_count=9;stub_execution_count=1;
        duplicate_writer_count=9;production_writer_count=0;
        real_github_dispatch_count=0;webhook_invalid_header_rejected=$true;
        webhook_valid_header_accepted=$true;negative_results=$negativeEvidence;
        completed_at_utc='2026-08-18T02:03:04Z'
    }
    $cleanupEvidence = [ordered]@{
        schema_version=1;cleanup=@(
            [ordered]@{key_type='allow';removed=$true},
            [ordered]@{key_type='dedupe';removed=$true}
        )
    }
    $gateFiles = [ordered]@{
        '00-workflow-export-summary.json'=$workflowEvidence
        '01-concurrency-and-rejections.json'=$runtimeEvidence
        '02-cleanup.json'=$cleanupEvidence
    }
    foreach ($entry in $gateFiles.GetEnumerator()) {
        [IO.File]::WriteAllText(
            (Join-Path $gateRun $entry.Key),
            (($entry.Value | ConvertTo-Json -Depth 20) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
    }
    $manifest = [ordered]@{
        schema_version=1;take_id=$gateTake;files=@($gateFiles.Keys | ForEach-Object {
            [ordered]@{
                file=$_
                sha256=(Get-FileHash -LiteralPath (Join-Path $gateRun $_) `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
    }
    [IO.File]::WriteAllText(
        (Join-Path $gateRun 'manifest.json'),
        (($manifest | ConvertTo-Json -Depth 20) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $gateProof = Assert-ShuffleSocGateB5Evidence `
        -EvidenceRoot $gateEvidenceRoot -WorkflowId $workflowId
    if ([string]$gateProof.TakeId -cne $gateTake -or
        [string]$gateProof.ManifestSha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'The Gate B5 Evidence validator did not return the verified proof binding.'
    }
    Add-Content -LiteralPath (Join-Path $gateRun '01-concurrency-and-rejections.json') `
        -Value 'tampered'
    $tamperRejected = $false
    try {
        [void](Assert-ShuffleSocGateB5Evidence `
            -EvidenceRoot $gateEvidenceRoot -WorkflowId $workflowId)
    } catch { $tamperRejected = $true }
    if (-not $tamperRejected) {
        throw 'The Gate B5 Evidence validator accepted a tampered Runtime file.'
    }
} finally {
    if (Test-Path -LiteralPath $gateEvidenceRoot) {
        Remove-Item -LiteralPath $gateEvidenceRoot -Recurse -Force
    }
}

$take = New-SocTakeRecord `
    -TakeId 'capital-one-20260818T000000Z-deadbeef' `
    -ResponseMode contain `
    -IssuedAtUtc ([datetimeoffset]::UtcNow) `
    -LifetimeMinutes 60
$allow = New-ShuffleSocAllowRecord -TakeRecord $take -OrgId $orgId
if ($allow.Key -cne 'soc:v1:allow:primary-lab:CAPITAL-ONE:capital-one-20260818T000000Z-deadbeef' -or
    $allow.Category -cne 'soc-v1' -or
    [bool]$allow.SetBody.ignore_security_rules -ne $false) {
    throw 'The Shuffle TAKE allowlist key or category violated the frozen contract.'
}
$roundTrip = $allow.ValueJson | ConvertFrom-Json
foreach ($pair in @{
    take_id='capital-one-20260818T000000Z-deadbeef'
    account_alias='primary-lab'
    scenario_id='CAPITAL-ONE'
    expected_rule_id='100103'
    response_mode='contain'
}.GetEnumerator()) {
    if ([string]$roundTrip.($pair.Key) -cne [string]$pair.Value) {
        throw "The Shuffle allowlist value changed: $($pair.Key)"
    }
}
foreach ($forbidden in @('token','credential','cookie','password','webhook','aws_account_id')) {
    if ($allow.ValueJson -match ('(?i)' + [regex]::Escape($forbidden))) {
        throw "The Shuffle allowlist value contains a forbidden field: $forbidden"
    }
}

$shuffleModuleText = Get-Content -LiteralPath (
    Join-Path $root 'automation\SocLab.Shuffle.psm1'
) -Raw
if ($shuffleModuleText -notmatch 'function\s+Remove-ShuffleSocTake[\s\S]*?delete_cache[\s\S]*?category\s*=\s*\$script:ShuffleCategory') {
    throw 'The Shuffle module lacks a category-bound TAKE allowlist removal path.'
}

$outcomeTakeId = 'capital-one-20260818T010000Z-deadbeef'
$hash1 = 'a' * 64
$hash2 = 'b' * 64
$record1 = [pscustomobject]@{
    schema_version=1;take_id=$outcomeTakeId;raw_message_sha256=$hash1;
    body_sha256=('c' * 64);
    account_alias='primary-lab';scenario_id='CAPITAL-ONE';rule_id='100103';
    result='RESPONSE_DISPATCHED';github_dispatch_count=1;workflow_run_id=123456789;
    completed_at_utc='2026-08-18T01:02:03Z'
}
[void](Assert-ShuffleSocOutcomeRecord -Record $record1 -TakeId $outcomeTakeId -RawMessageSha256 $hash1)
$record2 = $record1.PSObject.Copy()
$record2.raw_message_sha256 = $hash2
$record2.result = 'DUPLICATE_SUPPRESSED'
$record2.github_dispatch_count = 0
$record2.workflow_run_id = 0
[void](Assert-ShuffleSocOutcomeRecord -Record $record2 -TakeId $outcomeTakeId -RawMessageSha256 $hash2)
$badDispatchRejected = $false
$record2.github_dispatch_count = 1
try {
    [void](Assert-ShuffleSocOutcomeRecord -Record $record2 -TakeId $outcomeTakeId -RawMessageSha256 $hash2)
} catch { $badDispatchRejected = $_.Exception.Message -match 'non-dispatched' }
if (-not $badDispatchRejected) {
    throw 'A duplicate Shuffle outcome was allowed to claim a GitHub dispatch.'
}
$record2.github_dispatch_count = 0
foreach ($rejectedResult in @('REJECTED_SCHEMA','REJECTED_ALLOWLIST','RESPONSE_FAILED')) {
    $record2.result = $rejectedResult
    [void](Assert-ShuffleSocOutcomeRecord -Record $record2 `
        -TakeId $outcomeTakeId -RawMessageSha256 $hash2)
}

$claimId = @($workflow.actions | Where-Object {
    [string]$_.label -ceq 'claim_take_dispatch'
})[0].id
$syntheticExecution = [pscustomobject]@{
    execution_id='55555555-5555-4555-8555-555555555555'
    status='FINISHED'
    started_at=1
    completed_at=2
    results=@([pscustomobject]@{
        action_id=$claimId
        status='SUCCESS'
        result='{"success":true,"keys_existed":[{"key":"synthetic","existed":false}]}'
    })
}
$summary = Get-ShuffleSocExecutionSummary -Execution $syntheticExecution -Workflow $workflow
if ($summary.Actions.Count -ne 1 -or
    [string]$summary.Actions[0].Label -cne 'claim_take_dispatch') {
    throw 'Shuffle Action results were not mapped back to the Workflow label.'
}
$flags = @(Get-ShuffleSocKeysExistedFlags -Value $summary.Actions[0].Value)
if ($flags.Count -ne 1 -or $flags[0] -ne $false) {
    throw 'Shuffle claim keys_existed evidence was not parsed exactly.'
}
$claims = @(Get-ShuffleSocKeysExistedClaims -Value $summary.Actions[0].Value)
if ($claims.Count -ne 1 -or [string]$claims[0].Key -cne 'synthetic') {
    throw 'Shuffle claim evidence did not preserve the exact Datastore key.'
}

foreach ($label in @(
    'validate_payload','get_take_allow','claim_take_dispatch',
    'dispatch_github_containment','write_response_dispatched',
    'write_duplicate_suppressed','write_observe_only',
    'write_rejected_schema','write_rejected_allowlist','write_rejected_take',
    'write_response_failed'
)) {
    if ($shuffleModuleText -notmatch [regex]::Escape("'$label'")) {
        throw "The Shuffle Workflow structural contract is missing action label: $label"
    }
}
if ($shuffleModuleText -notmatch 'Assert-ShuffleSocProductionWorkflow') {
    throw 'The Shuffle module lacks the Production export validator.'
}

$unsafeUriRejected = $false
try {
    [void](Invoke-ShuffleApiRequest `
        -Method GET `
        -RelativePath '/api/v1/workflows/11111111-1111-4111-8111-111111111111' `
        -ApiKey 'synthetic-test-key' `
        -BaseUri 'https://example.com/')
} catch {
    $unsafeUriRejected = $_.Exception.Message -match 'host allowlist'
}
if (-not $unsafeUriRejected) {
    throw 'The Shuffle API client accepted an unapproved origin.'
}

Write-Host 'SOC lab Shuffle contract tests passed.'
