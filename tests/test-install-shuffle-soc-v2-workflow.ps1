#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installerPath = Join-Path $root 'tools\Install-ShuffleSocV2Workflow.ps1'
$installerText = Get-Content -LiteralPath $installerPath -Raw
$shuffleModulePath = Join-Path $root 'automation\SocLab.Shuffle.psm1'
$shuffleModuleText = Get-Content -LiteralPath $shuffleModulePath -Raw

function Assert-TestCondition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function Add-TestProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Value
    )
    Add-Member -InputObject $Object -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Assert-TestWorkflowListRequestOptions {
    param([AllowNull()][object]$RequestOptions)

    $headers = Get-SocShuffleV2Property -Object $RequestOptions -Name 'request_headers'
    $includeMetadata = Get-SocShuffleV2Property `
        -Object $RequestOptions -Name 'include_response_metadata'
    $headerNames = @(Get-SocShuffleV2PropertyNames -Object $headers)
    Assert-TestCondition -Condition ($null -ne $headers -and $headerNames.Count -eq 1 -and
        [string]$headerNames[0] -ceq 'truncate' -and
        (Get-SocShuffleV2Property -Object $headers -Name 'truncate') -is [string] -and
        [string](Get-SocShuffleV2Property -Object $headers -Name 'truncate') -ceq 'false' -and
        (Test-SocShuffleV2ExactBoolean -Value $includeMetadata -Expected $true)) `
        -Message 'Workflow discovery did not request truncate=false with response metadata.'
}

function New-TestWorkflowListEnvelope {
    param(
        [AllowEmptyCollection()][object[]]$Workflows = @(),
        [AllowNull()][object]$Truncated = $null
    )

    $headers = [ordered]@{}
    if ($null -ne $Truncated) {
        $headers['X-SHUFFLE_TRUNCATED'] = @($Truncated)
    }
    $workflowItems = @($Workflows | Where-Object {$null -ne $_})
    return [pscustomobject][ordered]@{
        body=[object[]]$workflowItems
        response_headers=[pscustomobject]$headers
    }
}

foreach ($forbidden in @(
    '#0','WriteAllText','Out-File','Export-Clixml','/api/v1/workflows/$WorkflowId/start',
    'Invoke-WebRequest -Uri'
)) {
    Assert-TestCondition -Condition ($installerText -notmatch [regex]::Escape($forbidden)) `
        -Message "The v2 installer contains forbidden legacy/evidence/API text: $forbidden"
}
Assert-TestCondition -Condition ($installerText -match "-RelativePath '/api/v1/hooks'") `
    -Message 'The installer does not use the official hook start endpoint.'
Assert-TestCondition -Condition ($installerText -match 'classify_dedupe_claim' -and
    $installerText -match '\$classify_dedupe_claim\.valid' -and
    $installerText -match '\$classify_dedupe_claim\.existed') `
    -Message 'The scalar classifier contract is absent.'
Assert-TestCondition -Condition ($installerText -match 'Assert-ShuffleSocV2Workflow') `
    -Message 'The installer does not reuse the shared v2 assertion.'
Assert-TestCondition -Condition ($installerText -notmatch '(?im)Write-Host.*(?:HeaderValue|apiKey|headerValue)') `
    -Message 'The installer may print a credential or raw Header value.'
Assert-TestCondition -Condition ($shuffleModuleText -match "TryAddWithoutValidation\('truncate', 'false'\)" -and
    $shuffleModuleText -match "TryGetValues\('X-SHUFFLE_TRUNCATED'") `
    -Message 'The shared Shuffle API helper does not transmit truncate=false or capture the truncation header.'
Assert-TestCondition -Condition ($installerText -match
    [regex]::Escape("-RelativePath '/api/v1/workflows?top=600&truncate=false'")) `
    -Message 'Workflow discovery does not use the bounded non-truncated list endpoint.'

. $installerPath -NoRun
Import-Module (Join-Path $root 'automation\SocLab.Shuffle.psm1') -Force

$validatorAppId = '0123456789abcdef0123456789abcdef'
$shuffleToolsAppId = '3e2bdf9d5069fe3f4746c29d68785a6a'
$headerValue = 'synthetic-header-only'
$organizationId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
$oldWorkflowId = '11111111-1111-4111-8111-111111111111'
$newWorkflowId = '22222222-2222-4222-8222-222222222222'
$newWebhookId = '33333333-3333-4333-8333-333333333333'
$exactWorkflowId = '44444444-4444-4444-8444-444444444444'
$exactWebhookId = '55555555-5555-4555-8555-555555555555'
$driftWorkflowId = '66666666-6666-4666-8666-666666666666'
$saveFailureWorkflowId = '77777777-7777-4777-8777-777777777777'
$saveFailureWebhookId = '88888888-8888-4888-8888-888888888888'
$duplicateWorkflowId = '99999999-9999-4999-8999-999999999999'

foreach ($orgCase in @(
    [pscustomobject]@{label='missing';item=[pscustomobject]@{
        id=$newWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2'}},
    [pscustomobject]@{label='wrong';item=[pscustomobject]@{
        id=$newWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id='other-org'}},
    [pscustomobject]@{label='ambiguous';item=[pscustomobject]@{
        id=$newWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId;organization_id='other-org'}}
)) {
    $orgError = ''
    $orgList = [object[]]@($orgCase.item)
    try {
        [void](Resolve-SocShuffleV2WorkflowCandidates -Response $orgList `
            -OrganizationId $organizationId)
    } catch { $orgError = $_.Exception.Message }
    Assert-TestCondition -Condition ($orgError -ceq
        'A Workflow discovery summary does not prove the configured Organization.') `
        -Message "The $([string]$orgCase.label) Workflow Organization case was accepted."
}

function New-OfficialBasicWorkflow {
    param(
        [Parameter(Mandatory)][string]$WorkflowId,
        [switch]$InjectedStarter,
        [switch]$OmitServerDerived,
        [ValidateSet('cloud','Cloud')][string]$StarterEnvironment = 'Cloud'
    )

    $workflow = [ordered]@{
        actions=@()
        branches=@()
        triggers=@()
        schedules=$null
        id=$WorkflowId
        is_valid=$true
        name='CAPITAL-ONE-SOC-CONTAINMENT-v2'
        description='AWS Topology SOC Gate B5 v2 (managed by Install-ShuffleSocV2Workflow.ps1)'
        start=''
        owner='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        sharing='private'
        execution_org=[pscustomobject]@{name='Synthetic Org';org=$organizationId;users=$null;id=$organizationId}
        org_id=$organizationId
        workflow_variables=$null
        environment='cloud'
        previously_saved=$false
        created=1787241600
        edited=1787241600
        status='test'
        workflow_type='workflow'
    }
    if ($OmitServerDerived) {
        $workflow.Remove('name')
        $workflow.Remove('is_valid')
    }
    if ($InjectedStarter) {
        $starterId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        $workflow.actions = @([pscustomobject][ordered]@{
            id=$starterId;label='Change Me';app_name='Shuffle Tools';app_version='1.2.0';
            app_id=$shuffleToolsAppId;name='repeat_back_to_me';environment=$StarterEnvironment;is_valid=$true;
            parameters=@([pscustomobject][ordered]@{name='call';value='Hello world'})
        })
        $workflow.start = $starterId
        $workflow.previously_saved = $false
    }
    return [pscustomobject]$workflow
}

function Add-RealisticShuffleMetadata {
    param([Parameter(Mandatory)][object]$Workflow)

    $copy = Copy-SocShuffleV2Object -Value $Workflow
    foreach ($action in @($copy.actions)) {
        Add-TestProperty $action description ''
        Add-TestProperty $action errors @()
        Add-TestProperty $action is_valid $true
        Add-TestProperty $action environment 'cloud'
        Add-TestProperty $action position ([pscustomobject]@{x=100;y=200})
        Add-TestProperty $action authentication_id ''
        Add-TestProperty $action execution_delay 0
        Add-TestProperty $action parent_controlled $false
        foreach ($parameter in @($action.parameters)) {
            Add-TestProperty $parameter description ''
            Add-TestProperty $parameter id ([guid]::NewGuid().ToString())
            Add-TestProperty $parameter variant 'STATIC_VALUE'
            Add-TestProperty $parameter configuration $false
            Add-TestProperty $parameter required $true
        }
    }
    foreach ($trigger in @($copy.triggers)) {
        Add-TestProperty $trigger description 'Webhook trigger'
        Add-TestProperty $trigger errors @()
        Add-TestProperty $trigger is_valid $true
        Add-TestProperty $trigger position ([pscustomobject]@{x=0;y=0})
        Add-TestProperty $trigger execution_delay 0
        Add-TestProperty $trigger parent_controlled $false
        foreach ($parameter in @($trigger.parameters)) {
            Add-TestProperty $parameter description ''
            Add-TestProperty $parameter id ([guid]::NewGuid().ToString())
            Add-TestProperty $parameter variant 'STATIC_VALUE'
            Add-TestProperty $parameter configuration $false
            Add-TestProperty $parameter required $true
        }
    }
    foreach ($branch in @($copy.branches)) {
        Add-TestProperty $branch label ''
        Add-TestProperty $branch has_errors $false
        Add-TestProperty $branch decorator $null
        Add-TestProperty $branch parent_controlled $false
        Add-TestProperty $branch source_parent ''
        foreach ($condition in @($branch.conditions)) {
            foreach ($part in @($condition.source,$condition.condition,$condition.destination)) {
                Add-TestProperty $part description ''
                Add-TestProperty $part required $true
                Add-TestProperty $part configuration $false
            }
        }
    }
    return $copy
}

function Set-TestWorkflowRunning {
    param([Parameter(Mandatory)][object]$Workflow)
    $Workflow.triggers[0].status = 'running'
}

function New-ExactWorkflow {
    param(
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId,
        [ValidateSet('stopped','running')][string]$Status = 'running'
    )

    $base = New-OfficialBasicWorkflow -WorkflowId $WorkflowId
    $definition = New-SocShuffleV2WorkflowDefinition -WebhookId $WebhookId `
        -ValidatorAppId $validatorAppId -ShuffleToolsAppId $shuffleToolsAppId `
        -HeaderValue $headerValue
    $workflow = Merge-SocShuffleV2WorkflowDefinition -ServerNativeBase $base `
        -Definition $definition -WorkflowId $WorkflowId
    $workflow = Add-RealisticShuffleMetadata -Workflow $workflow
    $workflow.triggers[0].status = $Status
    return $workflow
}

# The two server shapes observed for POST /api/v1/workflows are both safe
# resumable bases: the documented empty object and the current backend's one
# canonical Shuffle Tools starter.  Name/is_valid are intentionally omitted in
# the first fixture to prove they are server-derived, not required markers.
$emptyBase = New-OfficialBasicWorkflow -WorkflowId $exactWorkflowId -OmitServerDerived
$emptyPartial = Assert-SocShuffleV2BasicPartial -Workflow $emptyBase `
    -WorkflowId $exactWorkflowId -ShuffleToolsAppId $shuffleToolsAppId `
    -HeaderValue $headerValue
Assert-TestCondition -Condition ([string]::IsNullOrEmpty([string]$emptyPartial)) `
    -Message 'The documented empty basic Workflow shape was not resumable.'
$injectedBase = New-OfficialBasicWorkflow -WorkflowId $exactWorkflowId -InjectedStarter
$injectedPartial = Assert-SocShuffleV2BasicPartial -Workflow $injectedBase `
    -WorkflowId $exactWorkflowId -ShuffleToolsAppId $shuffleToolsAppId `
    -HeaderValue $headerValue
Assert-TestCondition -Condition ([string]::IsNullOrEmpty([string]$injectedPartial) -and
    $injectedBase.previously_saved -is [bool] -and -not [bool]$injectedBase.previously_saved -and
    [string]$injectedBase.actions[0].app_id -ceq $shuffleToolsAppId -and
    [string]$injectedBase.actions[0].parameters[0].value -ceq 'Hello world' -and
    [string]$injectedBase.actions[0].environment -ceq 'Cloud' -and
    [bool]$injectedBase.actions[0].is_valid -and
    [string]$injectedBase.start -ceq [string]$injectedBase.actions[0].id) `
    -Message 'The current injected Shuffle Tools starter shape was not resumable.'
$lowercaseInjectedBase = New-OfficialBasicWorkflow -WorkflowId $exactWorkflowId `
    -InjectedStarter -StarterEnvironment 'cloud'
$lowercaseInjectedPartial = Assert-SocShuffleV2BasicPartial -Workflow $lowercaseInjectedBase `
    -WorkflowId $exactWorkflowId -ShuffleToolsAppId $shuffleToolsAppId `
    -HeaderValue $headerValue
Assert-TestCondition -Condition ([string]::IsNullOrEmpty([string]$lowercaseInjectedPartial) -and
    [string]$lowercaseInjectedBase.actions[0].environment -ceq 'cloud') `
    -Message 'The source-shaped lowercase Shuffle Tools starter was not resumable.'
$unsafeStarterCases = @(
    [pscustomobject]@{label='starter label';mutate={param($workflow) $workflow.actions[0].label = 'Unapproved Starter'}},
    [pscustomobject]@{label='starter call';mutate={param($workflow) $workflow.actions[0].parameters[0].value = '$exec'}},
    [pscustomobject]@{label='previously_saved';mutate={param($workflow) $workflow.previously_saved = $true}},
    [pscustomobject]@{label='starter environment array';mutate={param($workflow) $workflow.actions[0].environment = @('Cloud')}},
    [pscustomobject]@{label='starter environment non-string';mutate={param($workflow) $workflow.actions[0].environment = 123}},
    [pscustomobject]@{label='starter environment uppercase';mutate={param($workflow) $workflow.actions[0].environment = 'CLOUD'}},
    [pscustomobject]@{label='starter environment other';mutate={param($workflow) $workflow.actions[0].environment = 'onprem'}},
    [pscustomobject]@{label='starter is_valid';mutate={param($workflow) $workflow.actions[0].is_valid = $false}}
)
foreach ($unsafeStarterCase in $unsafeStarterCases) {
    $unsafeStarter = Copy-SocShuffleV2Object -Value $injectedBase
    & $unsafeStarterCase.mutate $unsafeStarter
    $unsafeStarterError = ''
    try {
        [void](Assert-SocShuffleV2BasicPartial -Workflow $unsafeStarter `
            -WorkflowId $exactWorkflowId -ShuffleToolsAppId $shuffleToolsAppId `
            -HeaderValue $headerValue)
    } catch { $unsafeStarterError = $_.Exception.Message }
    Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($unsafeStarterError)) `
        -Message "An unsafe basic Workflow $([string]$unsafeStarterCase.label) was accepted."

    if ([string]$unsafeStarterCase.label -like 'starter environment*') {
        $unsafeStarterCalls = [Collections.Generic.List[object]]::new()
        $unsafeStarterApi = {
            param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
            [void]$unsafeStarterCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath})
            if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
                return [pscustomobject]@{apps=@(
                    [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
                    [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
                )}
            }
            if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
                Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
                return New-TestWorkflowListEnvelope -Workflows @([pscustomobject]@{
                    id=$exactWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId
                }) -Truncated 'false'
            }
            if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$exactWorkflowId") {
                return (Copy-SocShuffleV2Object -Value $unsafeStarter)
            }
            throw "Unexpected unsafe starter mock API call: $Method $RelativePath"
        }.GetNewClosure()
        $unsafeInstallError = ''
        try {
            [void](Invoke-SocShuffleV2Install -ApiCall $unsafeStarterApi `
                -HeaderValue $headerValue -OrganizationId $organizationId)
        } catch { $unsafeInstallError = $_.Exception.Message }
        Assert-TestCondition -Condition ($unsafeInstallError -match '\[workflow-drift\]' -and
            @($unsafeStarterCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
            -Message "The unsafe basic Workflow $([string]$unsafeStarterCase.label) wrote state."
    }
}

# Scenario 1: official basic create -> authoritative GET base -> full PUT ->
# semantic readback -> POST /api/v1/hooks -> running Workflow readback.
$createCalls = [Collections.Generic.List[object]]::new()
$createState = @{workflow=$null}
$createApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$createCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @([pscustomobject]@{
            id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id=$organizationId
        }) -Truncated 'false'
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$oldWorkflowId") {
        return [pscustomobject]@{id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';sharing='private';org_id=$organizationId}
    }
    if ($Method -ceq 'POST' -and $RelativePath -ceq '/api/v1/workflows') {
        Assert-TestCondition -Condition ((@(Get-SocShuffleV2PropertyNames $Body | Sort-Object) -join ',') -ceq 'description,name') `
            -Message 'POST /workflows did not use the official basic create body.'
        Assert-TestCondition -Condition ([string]$Body.name -ceq 'CAPITAL-ONE-SOC-CONTAINMENT-v2' -and
            [string]$Body.description -ceq $script:SocShuffleV2WorkflowDescription) `
            -Message 'The basic create marker is not exact.'
        $createState.workflow = New-OfficialBasicWorkflow -WorkflowId $newWorkflowId -InjectedStarter
        return (Copy-SocShuffleV2Object -Value $createState.workflow)
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$newWorkflowId") {
        return (Copy-SocShuffleV2Object -Value $createState.workflow)
    }
    if ($Method -ceq 'PUT' -and $RelativePath -ceq "/api/v1/workflows/$newWorkflowId") {
        Assert-TestCondition -Condition ([string]$Body.owner -ceq 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' -and
            [string]$Body.execution_org.id -ceq $organizationId -and $null -eq $Body.schedules) `
            -Message 'The full PUT did not preserve the server-native create base.'
        $createState.workflow = Add-RealisticShuffleMetadata -Workflow $Body
        return [pscustomobject]@{success=$true}
    }
    if ($Method -ceq 'POST' -and $RelativePath -ceq '/api/v1/hooks') {
        Assert-TestCondition -Condition ((@(Get-SocShuffleV2PropertyNames $Body | Sort-Object) -join ',') -ceq
            'auth,environment,id,name,start,type,workflow') `
            -Message 'POST /hooks body is not the documented seven-field shape.'
        $validateId = [string](@($createState.workflow.actions | Where-Object label -ceq 'validate_payload')[0].id)
        Assert-TestCondition -Condition ([string]$Body.name -ceq 'Webhook 1' -and
            [string]$Body.type -ceq 'webhook' -and [string]$Body.id -ceq $newWebhookId -and
            [string]$Body.workflow -ceq $newWorkflowId -and [string]$Body.start -ceq $validateId -and
            [string]$Body.environment -ceq 'cloud' -and
            [string]$Body.auth -ceq "X-SOC-Webhook-Key: $headerValue") `
            -Message 'POST /hooks did not bind the exact Workflow, start Action, or protected Header.'
        Set-TestWorkflowRunning -Workflow $createState.workflow
        return [pscustomobject]@{success=$true}
    }
    throw "Unexpected create mock API call: $Method $RelativePath"
}.GetNewClosure()

$createResult = Invoke-SocShuffleV2Install -ApiCall $createApi -HeaderValue $headerValue `
    -OrganizationId $organizationId -ExistingWorkflowId $oldWorkflowId -NewWebhookId $newWebhookId
Assert-TestCondition -Condition (-not [bool]$createResult.reused -and [bool]$createResult.started) `
    -Message 'The official create path result flags are wrong.'
Assert-TestCondition -Condition ([string]$createResult.workflow_id -ceq $newWorkflowId -and
    [string]$createResult.webhook_id -ceq $newWebhookId) `
    -Message 'The created v2 Workflow/Webhook IDs are wrong.'
Assert-TestCondition -Condition ($createCalls.Method -notcontains 'DELETE') `
    -Message 'The installer attempted a destructive API call.'
Assert-TestCondition -Condition ((@($createCalls | Where-Object {
    $_.Method -in @('PUT','POST') -and $_.Path -ceq "/api/v1/workflows/$oldWorkflowId"
}).Count) -eq 0) -Message 'Legacy v1 was mutated.'
Assert-TestCondition -Condition ((@($createCalls | Where-Object {
    $_.Method -ceq 'POST' -and $_.Path -ceq '/api/v1/hooks'
}).Count) -eq 1) -Message 'The official hook endpoint was not called exactly once.'
[void](Assert-SocShuffleV2Workflow -Workflow $createState.workflow -WorkflowId $newWorkflowId `
    -WebhookId $newWebhookId -ValidatorAppId $validatorAppId -ShuffleToolsAppId $shuffleToolsAppId `
    -HeaderValue $headerValue -ExpectedWebhookState Running)
$createdTrigger = @($createState.workflow.triggers)[0]
Assert-TestCondition -Condition ((@($createdTrigger.parameters | ForEach-Object {[string]$_.name}) -join ',') -ceq
    'url,tmp,auth_headers,custom_response_body,await_response' -and
    [string]$createdTrigger.trigger_type -ceq 'WEBHOOK' -and
    [string]$createdTrigger.parameters[0].value -ceq '' -and
    [string]$createdTrigger.parameters[1].value -ceq '' -and
    [string]$createdTrigger.parameters[2].value -ceq "X-SOC-Webhook-Key: $headerValue" -and
    [string]$createdTrigger.parameters[3].value -ceq '' -and
    $createdTrigger.parameters[4].value -is [string] -and
    [string]$createdTrigger.parameters[4].value -ceq 'v1') `
    -Message 'The saved Webhook trigger did not retain the canonical uppercase/full parameter shape without assumed hook enrichment.'
$toolsActions = @($createState.workflow.actions | Where-Object {[string]$_.app_name -ceq 'Shuffle Tools'})
Assert-TestCondition -Condition ($toolsActions.Count -eq 7 -and
    @($toolsActions | Where-Object {[string]$_.app_id -cne $shuffleToolsAppId}).Count -eq 0) `
    -Message 'Not every Shuffle Tools Action was enriched with the active app_id.'
[void](Assert-SocShuffleV2Workflow -Workflow $createState.workflow -WorkflowId $newWorkflowId `
        -WebhookId $newWebhookId -ValidatorAppId $validatorAppId -ShuffleToolsAppId $shuffleToolsAppId `
        -HeaderValue $headerValue `
    -ExpectedWebhookState Running)

$createdWorkflow = $createState.workflow
$actionById = @{}
foreach ($action in @($createdWorkflow.actions)) { $actionById[[string]$action.id] = [string]$action.label }
$actionById[$newWebhookId] = '__WEBHOOK_TRIGGER__'
Assert-TestCondition -Condition (@($createdWorkflow.branches).Count -eq 8) `
    -Message 'The v2 Workflow does not contain the exact eight-edge graph.'
$claimEdges = @($createdWorkflow.branches | Where-Object {
    $actionById[[string]$_.source_id] -ceq 'validate_payload' -and
    $actionById[[string]$_.destination_id] -ceq 'claim_event_dedupe'
})
Assert-TestCondition -Condition ($claimEdges.Count -eq 1 -and @($claimEdges[0].conditions).Count -eq 1 -and
    [string]$claimEdges[0].conditions[0].source.value -ceq '$validate_payload.valid' -and
    $claimEdges[0].conditions[0].destination.value -is [string] -and
    [string]$claimEdges[0].conditions[0].destination.value -ceq 'true') `
    -Message 'Invalid Validator input can reach the Datastore claim.'
$rejectionValues = @($createdWorkflow.branches | Where-Object {
    $actionById[[string]$_.source_id] -ceq 'validate_payload' -and
    $actionById[[string]$_.destination_id] -in @('write_rejected_schema','write_rejected_allowlist')
} | ForEach-Object {[string]$_.conditions[0].destination.value} | Sort-Object)
Assert-TestCondition -Condition (($rejectionValues -join ',') -ceq 'REJECTED_ALLOWLIST,REJECTED_SCHEMA') `
    -Message 'The two fixed rejection strings are not exact.'
Assert-TestCondition -Condition (@($createdWorkflow.branches.conditions.destination | Where-Object {
    $null -ne $_ -and $_.value -isnot [string]
}).Count -eq 0) -Message 'A Branch destination uses a non-string value.'

# Scenario 2: realistic server metadata is tolerated by the semantic projection;
# an exact running v2 is reused with GET-only calls.
$exactWorkflow = New-ExactWorkflow -WorkflowId $exactWorkflowId -WebhookId $exactWebhookId -Status running
$invalidExactValidityCases = @(
    [pscustomobject]@{label='missing Workflow is_valid';mutate={param($workflow) $workflow.PSObject.Properties.Remove('is_valid')}},
    [pscustomobject]@{label='null Workflow is_valid';mutate={param($workflow) $workflow.is_valid = $null}},
    [pscustomobject]@{label='string Workflow is_valid';mutate={param($workflow) $workflow.is_valid = 'false'}},
    [pscustomobject]@{label='missing Action is_valid';mutate={param($workflow) $workflow.actions[0].PSObject.Properties.Remove('is_valid')}},
    [pscustomobject]@{label='null Action is_valid';mutate={param($workflow) $workflow.actions[0].is_valid = $null}},
    [pscustomobject]@{label='string Action is_valid';mutate={param($workflow) $workflow.actions[0].is_valid = 'false'}}
)
foreach ($invalidValidityCase in $invalidExactValidityCases) {
    $invalidValidityWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
    & $invalidValidityCase.mutate $invalidValidityWorkflow
    $invalidValidityError = ''
    try {
        [void](Assert-SocShuffleV2Workflow -Workflow $invalidValidityWorkflow `
            -WorkflowId $exactWorkflowId -WebhookId $exactWebhookId `
            -ValidatorAppId $validatorAppId -ShuffleToolsAppId $shuffleToolsAppId `
            -HeaderValue $headerValue -ExpectedWebhookState Running)
    } catch { $invalidValidityError = $_.Exception.Message }
    Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($invalidValidityError)) `
        -Message "Exact readback accepted $([string]$invalidValidityCase.label)."
}

$missingValidityProjectionWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
$missingValidityProjectionWorkflow.PSObject.Properties.Remove('is_valid')
$missingValidityProjectionWorkflow.actions[0].PSObject.Properties.Remove('is_valid')
$semanticMissingValidity = Get-SocShuffleV2SemanticProjection `
    -Workflow $missingValidityProjectionWorkflow
$sharedMissingValidity = Get-SocShuffleV2SharedProjection `
    -Workflow $missingValidityProjectionWorkflow
Assert-TestCondition -Condition ($null -eq $semanticMissingValidity.is_valid -and
    @($semanticMissingValidity.actions | Where-Object {$null -eq $_.is_valid}).Count -eq 1 -and
    $null -eq $sharedMissingValidity.is_valid -and
    @($sharedMissingValidity.actions | Where-Object {$null -eq $_.is_valid}).Count -eq 1) `
    -Message 'A final projection synthesized a missing Workflow or Action is_valid value.'

$appAvailabilityCases = @(
    [pscustomobject]@{label='missing activated';field='activated';kind='missing'},
    [pscustomobject]@{label='null activated';field='activated';kind='null'},
    [pscustomobject]@{label='string activated';field='activated';kind='string'},
    [pscustomobject]@{label='false activated';field='activated';kind='false'},
    [pscustomobject]@{label='missing is_valid';field='is_valid';kind='missing'},
    [pscustomobject]@{label='null is_valid';field='is_valid';kind='null'},
    [pscustomobject]@{label='string is_valid';field='is_valid';kind='string'},
    [pscustomobject]@{label='false is_valid';field='is_valid';kind='false'},
    [pscustomobject]@{label='missing invalid';field='invalid';kind='missing'},
    [pscustomobject]@{label='null invalid';field='invalid';kind='null'},
    [pscustomobject]@{label='string invalid';field='invalid';kind='string'},
    [pscustomobject]@{label='invalid true';field='invalid';kind='false'}
)
foreach ($availabilityCase in $appAvailabilityCases) {
    $candidateApps = [pscustomobject]@{apps=@(
        [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
        [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
    )}
    foreach ($app in @($candidateApps.apps)) {
        if ([string]$availabilityCase.kind -ceq 'missing') {
            $app.PSObject.Properties.Remove([string]$availabilityCase.field)
        } elseif ([string]$availabilityCase.kind -ceq 'null') {
            $app.([string]$availabilityCase.field) = $null
        } elseif ([string]$availabilityCase.kind -ceq 'string') {
            $app.([string]$availabilityCase.field) = if ([string]$availabilityCase.field -ceq 'invalid') { 'false' } else { 'true' }
        } else {
            $app.([string]$availabilityCase.field) = if ([string]$availabilityCase.field -ceq 'invalid') { $true } else { $false }
        }
    }
    $validatorAvailabilityError = ''
    $toolsAvailabilityError = ''
    try { [void](Resolve-SocShuffleV2ValidatorApp -Response $candidateApps -OrganizationId $organizationId) } `
        catch { $validatorAvailabilityError = $_.Exception.Message }
    try { [void](Resolve-SocShuffleV2ShuffleToolsApp -Response $candidateApps) } `
        catch { $toolsAvailabilityError = $_.Exception.Message }
    Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($validatorAvailabilityError) -and
        -not [string]::IsNullOrWhiteSpace($toolsAvailabilityError)) `
        -Message "The App availability case $([string]$availabilityCase.label) was accepted."
}

$legacyAvailabilityApps = [pscustomobject]@{apps=@(
    [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;active=$true},
    [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';is_active=$true}
)}
$legacyValidatorError = ''
$legacyToolsError = ''
try { [void](Resolve-SocShuffleV2ValidatorApp -Response $legacyAvailabilityApps -OrganizationId $organizationId) } `
    catch { $legacyValidatorError = $_.Exception.Message }
try { [void](Resolve-SocShuffleV2ShuffleToolsApp -Response $legacyAvailabilityApps) } `
    catch { $legacyToolsError = $_.Exception.Message }
Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($legacyValidatorError) -and
    -not [string]::IsNullOrWhiteSpace($legacyToolsError)) `
    -Message 'Legacy active/is_active fields were accepted instead of the Cloud App contract.'

foreach ($referenceOrgCase in @('missing','wrong','ambiguous','array','nonstring')) {
    $referenceValidator = [pscustomobject]@{
        id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0'
        activated=$true;is_valid=$true;invalid=$false
    }
    if ($referenceOrgCase -ceq 'wrong') {
        Add-TestProperty $referenceValidator reference_org 'other-org'
    } elseif ($referenceOrgCase -ceq 'ambiguous') {
        Add-TestProperty $referenceValidator reference_org @($organizationId,'other-org')
    } elseif ($referenceOrgCase -ceq 'array') {
        Add-TestProperty $referenceValidator reference_org @($organizationId)
    } elseif ($referenceOrgCase -ceq 'nonstring') {
        Add-TestProperty $referenceValidator reference_org 123
    }
    $referenceCalls = [Collections.Generic.List[object]]::new()
    $referenceApi = {
        param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
        [void]$referenceCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath})
        if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
            return [pscustomobject]@{apps=@(
                $referenceValidator,
                [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
            )}
        }
        throw "Unexpected Validator org mock API call: $Method $RelativePath"
    }.GetNewClosure()
    $referenceError = ''
    try {
        [void](Invoke-SocShuffleV2Install -ApiCall $referenceApi -HeaderValue $headerValue `
            -OrganizationId $organizationId)
    } catch { $referenceError = $_.Exception.Message }
    Assert-TestCondition -Condition ($referenceError -match '\[validator-app\]' -and
        @($referenceCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
        -Message "The Validator reference_org case $referenceOrgCase was accepted or wrote state."
}

$reuseCalls = [Collections.Generic.List[object]]::new()
$reuseApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$reuseCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
    [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @([pscustomobject]@{
            id=$exactWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId
        }) -Truncated 'false'
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$oldWorkflowId") {
        return [pscustomobject]@{id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';sharing='private';org_id=$organizationId}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$exactWorkflowId") {
        return (Copy-SocShuffleV2Object -Value $exactWorkflow)
    }
    throw "Unexpected reuse mock API call: $Method $RelativePath"
}.GetNewClosure()
$reuseResult = Invoke-SocShuffleV2Install -ApiCall $reuseApi -HeaderValue $headerValue `
    -OrganizationId $organizationId -ExistingWorkflowId $oldWorkflowId
Assert-TestCondition -Condition ([bool]$reuseResult.reused -and -not [bool]$reuseResult.started) `
    -Message 'The exact running v2 Workflow was not reused.'
Assert-TestCondition -Condition ($reuseCalls.Count -eq 4 -and
    @($reuseCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'Exact v2 reuse performed an unexpected write.'
Assert-TestCondition -Condition ((@($reuseCalls | Where-Object {
    $_.Method -ceq 'GET' -and $_.Path -ceq "/api/v1/workflows/$oldWorkflowId"
}).Count) -eq 1) -Message 'Exact v2 reuse did not verify the legacy rollback anchor exactly once.'

$relativeUrlWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
$relativeUrlWorkflow.triggers[0].parameters[0].value = "/api/v1/hooks/webhook_$exactWebhookId"
$relativeUrlWorkflow.triggers[0].parameters[1].value = 'tmp'
[void](Assert-SocShuffleV2Workflow -Workflow $relativeUrlWorkflow -WorkflowId $exactWorkflowId `
    -WebhookId $exactWebhookId -ValidatorAppId $validatorAppId `
    -ShuffleToolsAppId $shuffleToolsAppId -HeaderValue $headerValue `
    -ExpectedWebhookState Running)

$absoluteUrlWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
$absoluteUrlWorkflow.triggers[0].parameters[0].value = "https://shuffler.io/api/v1/hooks/webhook_$exactWebhookId"
$absoluteUrlWorkflow.triggers[0].parameters[1].value = 'tmp'
[void](Assert-SocShuffleV2Workflow -Workflow $absoluteUrlWorkflow -WorkflowId $exactWorkflowId `
    -WebhookId $exactWebhookId -ValidatorAppId $validatorAppId `
    -ShuffleToolsAppId $shuffleToolsAppId -HeaderValue $headerValue `
    -ExpectedWebhookState Running)

$unsafeWebhookParameterCases = @(
    [pscustomobject]@{index=0;value='$exec';label='dynamic URL'},
    [pscustomobject]@{index=0;value="https://evil.example/api/v1/hooks/webhook_$exactWebhookId";label='foreign origin'},
    [pscustomobject]@{index=0;value="https://shuffler.io/api/v1/hooks/not_$exactWebhookId";label='wrong path'},
    [pscustomobject]@{index=0;value="https://shuffler.io/api/v1/hooks/webhook_$exactWebhookId`r`nX-Test: bad";label='CRLF URL'},
    [pscustomobject]@{index=1;value='$exec';label='dynamic tmp'},
    [pscustomobject]@{index=3;value='{`"status`":`"$exec`"}';label='custom response body'},
    [pscustomobject]@{index=4;value='false';label='obsolete await_response sentinel'},
    [pscustomobject]@{index=4;value=$false;label='Boolean await_response'}
)
foreach ($unsafeCase in $unsafeWebhookParameterCases) {
    $unsafeWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
    $unsafeWorkflow.triggers[0].parameters[[int]$unsafeCase.index].value = [string]$unsafeCase.value
    $unsafeError = ''
    try {
        [void](Assert-SocShuffleV2Workflow -Workflow $unsafeWorkflow -WorkflowId $exactWorkflowId `
            -WebhookId $exactWebhookId -ValidatorAppId $validatorAppId `
            -ShuffleToolsAppId $shuffleToolsAppId -HeaderValue $headerValue `
            -ExpectedWebhookState Running)
    } catch { $unsafeError = $_.Exception.Message }
    Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($unsafeError)) `
        -Message "The unsafe Webhook $([string]$unsafeCase.label) value was accepted."
}

# Scenario 3: undocumented executable metadata and call drift fail closed.
$driftWorkflow = Copy-SocShuffleV2Object -Value $exactWorkflow
$driftWorkflow.id = $driftWorkflowId
Add-TestProperty $driftWorkflow.actions[0] unknown_side_effect 'unsafe'
$driftCalls = [Collections.Generic.List[object]]::new()
$driftApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$driftCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @([pscustomobject]@{
            id=$driftWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId
        }) -Truncated 'false'
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$driftWorkflowId") {
        return (Copy-SocShuffleV2Object -Value $driftWorkflow)
    }
    throw "Unexpected drift mock API call: $Method $RelativePath"
}.GetNewClosure()
$driftError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $driftApi -HeaderValue $headerValue `
        -OrganizationId $organizationId)
} catch { $driftError = $_.Exception.Message }
Assert-TestCondition -Condition ($driftError -match '\[workflow-drift\]') `
    -Message 'Unknown v2 executable metadata was not rejected.'
Assert-TestCondition -Condition ($driftError -notmatch 'unknown_side_effect|unsafe|synthetic-header-only') `
    -Message 'The drift failure exposed raw drift or Header material.'
Assert-TestCondition -Condition (@($driftCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'Drift handling attempted a write.'

$callDrift = Copy-SocShuffleV2Object -Value $exactWorkflow
$callDrift.id = $driftWorkflowId
@($callDrift.actions | Where-Object label -ceq 'repeat_back_to_me')[0].parameters[0].value = 'UNAPPROVED_CALL'
$callDriftError = ''
try {
    [void](Assert-SocShuffleV2Workflow -Workflow $callDrift -WorkflowId $driftWorkflowId `
        -WebhookId $exactWebhookId -ValidatorAppId $validatorAppId -ShuffleToolsAppId $shuffleToolsAppId `
        -HeaderValue $headerValue)
} catch { $callDriftError = $_.Exception.Message }
Assert-TestCondition -Condition (-not [string]::IsNullOrWhiteSpace($callDriftError)) `
    -Message 'A changed repeat call marker was accepted.'

# Scenario 4: first full PUT fails. Rerun discovers the one installer-marked
# basic Workflow, resumes the same ID, and never POSTs another Workflow.
$saveCalls = [Collections.Generic.List[object]]::new()
$saveState = @{workflow=$null;fail_save=$true;create_count=0}
$saveApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$saveCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        $items = @([pscustomobject]@{
            id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id=$organizationId
        })
        if ($null -ne $saveState.workflow) {
            $items += [pscustomobject]@{
                id=$saveFailureWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId
            }
        }
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows $items -Truncated 'false'
    }
    if ($Method -ceq 'POST' -and $RelativePath -ceq '/api/v1/workflows') {
        $saveState.create_count++
        Assert-TestCondition -Condition ((@(Get-SocShuffleV2PropertyNames $Body | Sort-Object) -join ',') -ceq 'description,name') `
            -Message 'Resume fixture received a non-basic Workflow create body.'
        $saveState.workflow = New-OfficialBasicWorkflow -WorkflowId $saveFailureWorkflowId
        return (Copy-SocShuffleV2Object -Value $saveState.workflow)
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$saveFailureWorkflowId") {
        return (Copy-SocShuffleV2Object -Value $saveState.workflow)
    }
    if ($Method -ceq 'PUT' -and $RelativePath -ceq "/api/v1/workflows/$saveFailureWorkflowId") {
        if ([bool]$saveState.fail_save) {
            $saveState.fail_save = $false
            $saveException = [InvalidOperationException]::new(
                'Shuffle API request failed: HTTP 422'
            )
            $saveException.Data['ResponseJson'] = @{
                success=$false
                reason='Action environment is required'
                debug='raw_uri=https://shuffle.invalid header=synthetic-header-only credential=secret'
            } | ConvertTo-Json -Compress
            throw $saveException
        }
        $saveState.workflow = Add-RealisticShuffleMetadata -Workflow $Body
        return [pscustomobject]@{success=$true}
    }
    if ($Method -ceq 'POST' -and $RelativePath -ceq '/api/v1/hooks') {
        Assert-TestCondition -Condition ([string]$Body.workflow -ceq $saveFailureWorkflowId -and
            [string]$Body.id -ceq $saveFailureWebhookId -and
            [string]$Body.auth -ceq "X-SOC-Webhook-Key: $headerValue") `
            -Message 'Resumed hook start body is unsafe.'
        Set-TestWorkflowRunning -Workflow $saveState.workflow
        return [pscustomobject]@{success=$true}
    }
    throw "Unexpected save/resume mock API call: $Method $RelativePath"
}.GetNewClosure()
$saveError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $saveApi -HeaderValue $headerValue `
        -OrganizationId $organizationId -NewWebhookId $saveFailureWebhookId)
} catch { $saveError = $_.Exception.Message }
Assert-TestCondition -Condition ($saveError -match '\[workflow-save\]' -and
    $saveError -match [regex]::Escape($saveFailureWorkflowId) -and
    $saveError -match 'http_status=422' -and
    $saveError -match 'diagnostic=json_required_field') `
    -Message 'The first PUT failure did not preserve the fixed safe category and Workflow ID.'
Assert-TestCondition -Condition ($saveError -notmatch 'raw_uri|shuffle\.invalid|synthetic-header-only|credential=secret') `
    -Message 'The first PUT failure exposed raw URI or credential material.'
Assert-TestCondition -Condition ($saveCalls.Method -notcontains 'DELETE') `
    -Message 'The failed create attempted destructive cleanup.'

$statusOnlyError = ''
try {
    [void](Invoke-SocShuffleV2ApiStage -ApiCall {
            throw 'Shuffle API request failed: HTTP 502'
        } -Method PUT -RelativePath "/api/v1/workflows/$saveFailureWorkflowId" `
        -Body ([pscustomobject]@{}) -Category 'workflow-save' `
        -WorkflowId $saveFailureWorkflowId -WebhookId $saveFailureWebhookId)
} catch { $statusOnlyError = $_.Exception.Message }
Assert-TestCondition -Condition ($statusOnlyError -match 'http_status=502' -and
    $statusOnlyError -match 'diagnostic=status_only' -and
    $statusOnlyError -notmatch 'Shuffle API request failed') `
    -Message 'The status-only Workflow save diagnostic was not bounded or secret-safe.'

$unclassifiedError = ''
try {
    [void](Invoke-SocShuffleV2ApiStage -ApiCall {
            $exception = [InvalidOperationException]::new('opaque upstream failure')
            $exception.Data['StatusCode'] = 400
            $exception.Data['ResponseJson'] = '{"reason":"tenant token raw-value-should-not-leak"}'
            throw $exception
        } -Method PUT -RelativePath "/api/v1/workflows/$saveFailureWorkflowId" `
        -Body ([pscustomobject]@{}) -Category 'workflow-save' `
        -WorkflowId $saveFailureWorkflowId -WebhookId $saveFailureWebhookId)
} catch { $unclassifiedError = $_.Exception.Message }
Assert-TestCondition -Condition ($unclassifiedError -match 'http_status=400' -and
    $unclassifiedError -match 'diagnostic=json_known_field_unclassified' -and
    $unclassifiedError -notmatch 'token|raw-value|opaque upstream') `
    -Message 'An unclassified JSON Workflow save error leaked raw diagnostic text.'

$resumeResult = Invoke-SocShuffleV2Install -ApiCall $saveApi -HeaderValue $headerValue `
    -OrganizationId $organizationId -NewWebhookId $saveFailureWebhookId
Assert-TestCondition -Condition ([bool]$resumeResult.reused -and [bool]$resumeResult.resumed -and
    [bool]$resumeResult.started -and [string]$resumeResult.workflow_id -ceq $saveFailureWorkflowId) `
    -Message 'The single basic v2 partial was not resumed safely.'
Assert-TestCondition -Condition ([int]$saveState.create_count -eq 1 -and
    (@($saveCalls | Where-Object { $_.Method -ceq 'POST' -and $_.Path -ceq '/api/v1/workflows' }).Count) -eq 1) `
    -Message 'Rerun POSTed a duplicate v2 Workflow.'

# Scenario 5: more than one fixed-name v2 in the org is a hard stop.
$duplicateCalls = [Collections.Generic.List[object]]::new()
$duplicateApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$duplicateCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @(
            [pscustomobject]@{id=$exactWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId},
            [pscustomobject]@{id=$duplicateWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v2';org_id=$organizationId}
        ) -Truncated 'false'
    }
    throw "Unexpected duplicate mock API call: $Method $RelativePath"
}.GetNewClosure()
$duplicateError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $duplicateApi -HeaderValue $headerValue `
        -OrganizationId $organizationId)
} catch { $duplicateError = $_.Exception.Message }
Assert-TestCondition -Condition ($duplicateError -match '\[workflow-duplicate\]') `
    -Message 'Multiple v2 Workflows were not rejected.'
Assert-TestCondition -Condition (@($duplicateCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'Duplicate discovery attempted a write.'

# Scenario 6: a truncated org Workflow list is a hard stop before any POST.
$truncatedCalls = [Collections.Generic.List[object]]::new()
$truncatedApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$truncatedCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @() -Truncated 'true'
    }
    throw "Unexpected truncated mock API call: $Method $RelativePath"
}.GetNewClosure()
$truncatedError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $truncatedApi -HeaderValue $headerValue `
        -OrganizationId $organizationId)
} catch { $truncatedError = $_.Exception.Message }
Assert-TestCondition -Condition ($truncatedError -match '\[workflow-discovery\]' -and
    @($truncatedCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'A truncated Workflow list did not stop before POST.'
$truncatedListCall = @($truncatedCalls | Where-Object {
    $_.Method -ceq 'GET' -and $_.Path -ceq '/api/v1/workflows?top=600&truncate=false'
})
Assert-TestCondition -Condition ($truncatedListCall.Count -eq 1) `
    -Message 'The truncated Workflow list request was not made exactly once.'
Assert-TestWorkflowListRequestOptions -RequestOptions $truncatedListCall[0].Options

# Scenario 7: a scalar Workflow object cannot prove a complete org list.
$scalarCalls = [Collections.Generic.List[object]]::new()
$scalarApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$scalarCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return [pscustomobject][ordered]@{
            body=[pscustomobject]@{
                id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id=$organizationId
            }
            response_headers=[pscustomobject]@{'X-SHUFFLE_TRUNCATED'=@('false')}
        }
    }
    throw "Unexpected scalar mock API call: $Method $RelativePath"
}.GetNewClosure()
$scalarError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $scalarApi -HeaderValue $headerValue `
        -OrganizationId $organizationId)
} catch { $scalarError = $_.Exception.Message }
Assert-TestCondition -Condition ($scalarError -match '\[workflow-discovery\]' -and
    @($scalarCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'A scalar Workflow object was accepted as a complete Workflow list.'

# Scenario 8: top=600 cannot prove that the organization list is complete.
$boundedWorkflows = @(
    1..600 | ForEach-Object {
        [pscustomobject]@{
            id=('{0:x8}-0000-4000-8000-000000000000' -f $_)
            name='CAPITAL-ONE-SOC-CONTAINMENT-v1'
            org_id=$organizationId
        }
    }
)
$boundedCalls = [Collections.Generic.List[object]]::new()
$boundedApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$boundedCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows $boundedWorkflows -Truncated 'false'
    }
    throw "Unexpected bounded mock API call: $Method $RelativePath"
}.GetNewClosure()
$boundedError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $boundedApi -HeaderValue $headerValue `
        -OrganizationId $organizationId)
} catch { $boundedError = $_.Exception.Message }
Assert-TestCondition -Condition ($boundedError -match '\[workflow-discovery\]' -and
    @($boundedCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'A Workflow list at the top=600 completeness bound was accepted.'

# Scenario 9: zero-v2 lists still require exact Organization scope proof.
$listScopeCases = @(
    [pscustomobject]@{label='empty';items=[object[]]@()},
    [pscustomobject]@{label='missing';items=[object[]]@([pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1'})},
    [pscustomobject]@{label='wrong';items=[object[]]@([pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id='other-org'})},
    [pscustomobject]@{label='ambiguous';items=[object[]]@([pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1'
        org_id=$organizationId;organization_id='other-org'})},
    [pscustomobject]@{label='array';items=[object[]]@([pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id=@($organizationId)})},
    [pscustomobject]@{label='nonstring';items=[object[]]@([pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';org_id=123})}
)
foreach ($listScopeCase in $listScopeCases) {
    $listScopeCalls = [Collections.Generic.List[object]]::new()
    $listScopeItems = [object[]]$listScopeCase.items
    $listScopeApi = {
        param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
        [void]$listScopeCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath})
        if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
            return [pscustomobject]@{apps=@(
                [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
                [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
            )}
        }
        if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
            Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
            return New-TestWorkflowListEnvelope -Workflows $listScopeItems -Truncated 'false'
        }
        throw "Unexpected list scope mock API call: $Method $RelativePath"
    }.GetNewClosure()
    $listScopeError = ''
    try {
        [void](Invoke-SocShuffleV2Install -ApiCall $listScopeApi -HeaderValue $headerValue `
            -OrganizationId $organizationId)
    } catch { $listScopeError = $_.Exception.Message }
    Assert-TestCondition -Condition ($listScopeError -match '\[workflow-discovery\]' -and
        @($listScopeCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
        -Message "The zero-v2 list scope case $([string]$listScopeCase.label) was accepted or wrote state."
}

# Scenario 10: the configured v1 rollback anchor must prove the same Organization.
foreach ($anchorOrgCase in @('missing','wrong','ambiguous','array','nonstring')) {
    $anchorObject = [pscustomobject]@{
        id=$oldWorkflowId;name='CAPITAL-ONE-SOC-CONTAINMENT-v1';sharing='private'
    }
    if ($anchorOrgCase -ceq 'wrong') {
        Add-TestProperty $anchorObject org_id 'other-org'
    } elseif ($anchorOrgCase -ceq 'ambiguous') {
        Add-TestProperty $anchorObject org_id $organizationId
        Add-TestProperty $anchorObject organization_id 'other-org'
    } elseif ($anchorOrgCase -ceq 'array') {
        Add-TestProperty $anchorObject org_id @($organizationId)
    } elseif ($anchorOrgCase -ceq 'nonstring') {
        Add-TestProperty $anchorObject org_id 123
    }
    $anchorCalls = [Collections.Generic.List[object]]::new()
    $anchorApi = {
        param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
        [void]$anchorCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath})
        if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
            return [pscustomobject]@{apps=@(
                [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
                [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
            )}
        }
        if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$oldWorkflowId") {
            return $anchorObject
        }
        throw "Unexpected anchor org mock API call: $Method $RelativePath"
    }.GetNewClosure()
    $anchorError = ''
    try {
        [void](Invoke-SocShuffleV2Install -ApiCall $anchorApi -HeaderValue $headerValue `
            -OrganizationId $organizationId -ExistingWorkflowId $oldWorkflowId)
    } catch { $anchorError = $_.Exception.Message }
    Assert-TestCondition -Condition ($anchorError -match '\[workflow-drift\]' -and
        @($anchorCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
        -Message "The v1 anchor Organization case $anchorOrgCase was accepted or wrote state."
}

# Scenario 11: configured legacy is GET-only and unknown identity fails closed.
$unknownCalls = [Collections.Generic.List[object]]::new()
$unknownApi = {
    param([string]$Method,[string]$RelativePath,[AllowNull()][object]$Body,[AllowNull()][object]$RequestOptions)
    [void]$unknownCalls.Add([pscustomobject]@{Method=$Method;Path=$RelativePath;Body=$Body;Options=$RequestOptions})
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/apps') {
        return [pscustomobject]@{apps=@(
            [pscustomobject]@{id=$validatorAppId;name='AWS Topology SOC Validator';app_version='1.0.0';reference_org=$organizationId;activated=$true;is_valid=$true;invalid=$false},
            [pscustomobject]@{id=$shuffleToolsAppId;name='Shuffle Tools';app_version='1.2.0';activated=$true;is_valid=$true;invalid=$false}
        )}
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq '/api/v1/workflows?top=600&truncate=false') {
        Assert-TestWorkflowListRequestOptions -RequestOptions $RequestOptions
        return New-TestWorkflowListEnvelope -Workflows @() -Truncated 'false'
    }
    if ($Method -ceq 'GET' -and $RelativePath -ceq "/api/v1/workflows/$oldWorkflowId") {
        return [pscustomobject]@{id=$oldWorkflowId;name='UNKNOWN-WORKFLOW';sharing='private';org_id=$organizationId}
    }
    throw "Unexpected unknown mock API call: $Method $RelativePath"
}.GetNewClosure()
$unknownError = ''
try {
    [void](Invoke-SocShuffleV2Install -ApiCall $unknownApi -HeaderValue $headerValue `
        -OrganizationId $organizationId -ExistingWorkflowId $oldWorkflowId)
} catch { $unknownError = $_.Exception.Message }
Assert-TestCondition -Condition ($unknownError -match '\[workflow-drift\]') `
    -Message 'An unknown configured Workflow was treated as legacy v1.'
Assert-TestCondition -Condition (@($unknownCalls | Where-Object Method -in @('PUT','POST','DELETE')).Count -eq 0) `
    -Message 'Unknown configured Workflow drift attempted a write.'

'test-install-shuffle-soc-v2-workflow: PASS'
