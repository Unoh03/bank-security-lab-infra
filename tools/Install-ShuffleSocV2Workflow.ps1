#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$ExistingWorkflowId = '',
    [string]$ConfirmInstall = '',
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SocShuffleV2WorkflowName = 'CAPITAL-ONE-SOC-CONTAINMENT-v2'
$script:SocShuffleV2WorkflowDescription = 'AWS Topology SOC Gate B5 v2 (managed by Install-ShuffleSocV2Workflow.ps1)'
$script:SocShuffleLegacyWorkflowName = 'CAPITAL-ONE-SOC-CONTAINMENT-v1'
$script:SocShuffleV2ValidatorName = 'AWS Topology SOC Validator'
$script:SocShuffleV2ValidatorVersion = '1.0.0'
$script:SocShuffleV2ShuffleToolsVersion = '1.2.0'
$script:SocShuffleV2HeaderName = 'X-SOC-Webhook-Key'
$script:SocShuffleV2WebhookName = 'Webhook 1'
$script:SocShuffleV2FailureCategories = @(
    'configuration', 'secret', 'validator-app', 'workflow-readback',
    'workflow-discovery', 'workflow-duplicate', 'workflow-drift',
    'workflow-create', 'workflow-save', 'webhook-start', 'webhook-readback'
)
$script:SocShuffleV2ActionLabels = @(
    'validate_payload',
    'claim_event_dedupe',
    'classify_dedupe_claim',
    'write_duplicate_suppressed',
    'write_observe_only',
    'write_rejected_schema',
    'write_rejected_allowlist',
    'write_safety_gate_blocked',
    'repeat_back_to_me'
)
$script:SocShuffleV2WorkflowProperties = @(
    'workflow_as_code','actions','branches','visual_branches','triggers','comments',
    'configuration','created','edited','last_runtime','due_date','errors','tags','id',
    'is_valid','name','description','start','owner','sharing','image','org',
    'execution_org','org_id','organization_id','workflow_variables','execution_variables',
    'execution_environment','environment','first_save','categories','example_argument','public',
    'default_return_value','contact_info','published_id','revision_id','subflows',
    'usecase_ids','input_questions','form_control','blogpost','video','status',
    'workflow_type','generated','hidden','background_processing','updated_by',
    'validated','validation','parentorg_workflow','childorg_workflow_ids',
    'suborg_distribution','backup_config','auth_groups','ai_config','schedules','previously_saved'
)
$script:SocShuffleV2ActionProperties = @(
    'app_name','app_version','description','app_id','errors','id','is_valid',
    'isStartNode','sharing','private_id','label','small_image','public','generated',
    'large_image','environment','name','parameters','previous_parameters',
    'execution_variable','position','priority','authentication_id','example',
    'auth_not_required','category','reference_url','sub_action','run_magic_output',
    'run_magic_input','execution_delay','category_label','suggestion','parent_controlled',
    'source_workflow','source_execution'
)
$script:SocShuffleV2TriggerProperties = @(
    'app_name','description','long_description','status','app_version','errors','id',
    'is_valid','isStartNode','label','small_image','large_image','environment',
    'trigger_type','type','name','tags','parameters','position','priority',
    'source_workflow','execution_delay','app_association','parent_controlled',
    'replacement_for_trigger'
)
$script:SocShuffleV2BranchProperties = @(
    'destination_id','id','source_id','label','has_errors','conditions','decorator',
    'parent_controlled','source_parent'
)
$script:SocShuffleV2ParameterProperties = @(
    'description','id','name','example','value','multiline','multiselect','options',
    'action_field','variant','required','configuration','tags','schema',
    'skip_multicheck','custom_value','value_replace','unique_toggled','error','hidden'
)
$script:SocShuffleV2UuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

function New-SocShuffleV2Failure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'configuration', 'secret', 'validator-app', 'workflow-readback',
            'workflow-discovery', 'workflow-duplicate', 'workflow-drift',
            'workflow-create', 'workflow-save', 'webhook-start',
            'webhook-readback'
        )][string]$Category,
        [string]$WorkflowId = '',
        [string]$WebhookId = '',
        [ValidateRange(0,599)][int]$HttpStatus = 0,
        [ValidateSet(
            'unavailable','status_only','json_required_field','json_invalid_workflow',
            'json_authorization','json_not_found','json_conflict',
            'json_no_known_field','json_nonscalar_field','json_known_field_unclassified'
        )][string]$Diagnostic = 'unavailable'
    )

    $suffix = [Collections.Generic.List[string]]::new()
    if ($WorkflowId -match $script:SocShuffleV2UuidPattern) {
        $suffix.Add("workflow_id=$WorkflowId")
    }
    if ($WebhookId -match $script:SocShuffleV2UuidPattern) {
        $suffix.Add("webhook_id=$WebhookId")
    }
    if ($HttpStatus -ge 100) {
        $suffix.Add("http_status=$HttpStatus")
    }
    if ($Diagnostic -cne 'unavailable') {
        $suffix.Add("diagnostic=$Diagnostic")
    }
    $detail = if ($suffix.Count -eq 0) { '' } else { " ($($suffix -join ';'))" }
    return "Shuffle v2 installer failed [$Category]$detail. Raw URI, Header, credential, and exception details were withheld."
}

function Get-SocShuffleV2SafeSaveDiagnostic {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$ErrorRecord)

    $exception = $ErrorRecord.Exception
    $status = 0
    $statusCandidates = [Collections.Generic.List[object]]::new()
    $statusProperty = $exception.PSObject.Properties['StatusCode']
    if ($null -ne $statusProperty) { [void]$statusCandidates.Add($statusProperty.Value) }
    if ($null -ne $exception.Data -and $exception.Data.Contains('StatusCode')) {
        [void]$statusCandidates.Add($exception.Data['StatusCode'])
    }
    foreach ($candidate in $statusCandidates) {
        if ($candidate -is [Net.HttpStatusCode]) {
            $status = [int]$candidate
        } elseif ($candidate -is [byte] -or $candidate -is [int16] -or
            $candidate -is [int32] -or $candidate -is [int64]) {
            $status = [int]$candidate
        } elseif ($candidate -is [string] -and $candidate -match '^[1-5][0-9]{2}$') {
            $status = [int]$candidate
        }
        if ($status -ge 100 -and $status -le 599) { break }
        $status = 0
    }
    if ($status -eq 0 -and $exception.Message -match
        '^Shuffle API request failed: HTTP (?<status>[1-5][0-9]{2})$') {
        $status = [int]$Matches.status
    }

    $jsonText = ''
    if ($null -ne $exception.Data -and $exception.Data.Contains('ResponseJson') -and
        $exception.Data['ResponseJson'] -is [string]) {
        $jsonText = [string]$exception.Data['ResponseJson']
    } elseif ($null -ne $ErrorRecord.ErrorDetails -and
        $ErrorRecord.ErrorDetails.Message -is [string]) {
        $jsonText = [string]$ErrorRecord.ErrorDetails.Message
    } elseif ($exception.Message -match '^\s*\{') {
        $jsonText = [string]$exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($jsonText) -or $jsonText.Length -gt 4096) {
        return [pscustomobject][ordered]@{
            http_status=$status
            diagnostic=$(if ($status -ge 100) {'status_only'} else {'unavailable'})
        }
    }

    try {
        $document = ConvertFrom-Json -InputObject $jsonText -Depth 20 -NoEnumerate
    } catch {
        $document = $null
    } finally {
        $jsonText = $null
    }
    if ($null -eq $document -or $document -is [array] -or
        $document -is [Collections.IList] -or $document -is [string] -or
        $document -is [ValueType]) {
        return [pscustomobject][ordered]@{
            http_status=$status
            diagnostic=$(if ($status -ge 100) {'status_only'} else {'unavailable'})
        }
    }

    $knownFieldPresent = $false
    $nonscalarFieldPresent = $false
    $reasonParts = [Collections.Generic.List[string]]::new()
    $propertyNames = @(Get-SocShuffleV2PropertyNames -Object $document)
    foreach ($name in @('reason','message','error','detail')) {
        if ($name -notin $propertyNames) { continue }
        $knownFieldPresent = $true
        $value = Get-SocShuffleV2Property -Object $document -Name $name
        if ($value -isnot [string] -or $value.Length -gt 1024) {
            $nonscalarFieldPresent = $true
            continue
        }
        [void]$reasonParts.Add([string]$value)
    }
    $diagnostic = if ($nonscalarFieldPresent) {
        'json_nonscalar_field'
    } elseif (-not $knownFieldPresent) {
        'json_no_known_field'
    } elseif ($reasonParts.Count -eq 0) {
        'json_known_field_unclassified'
    } else {
        $reason = $reasonParts -join ' '
        if ($reason -match '(?i)(?:\b(?:required|missing)\b.{0,80}\b(?:field|property|parameter|environment|workflow|action|trigger|branch)\b|\b(?:field|property|parameter|environment|workflow|action|trigger|branch)\b.{0,80}\b(?:required|missing)\b)') {
            'json_required_field'
        } elseif ($reason -match '(?i)(?:\b(?:invalid|malformed)\b.{0,80}\b(?:workflow|action|trigger|branch|condition|parameter)\b|\b(?:workflow|action|trigger|branch|condition|parameter)\b.{0,80}\b(?:invalid|malformed)\b)') {
            'json_invalid_workflow'
        } elseif ($reason -match '(?i)\b(?:unauthorized|forbidden|permission denied)\b') {
            'json_authorization'
        } elseif ($reason -match '(?i)\b(?:not found|does not exist)\b') {
            'json_not_found'
        } elseif ($reason -match '(?i)\b(?:conflict|already exists)\b') {
            'json_conflict'
        } else {
            'json_known_field_unclassified'
        }
    }
    return [pscustomobject][ordered]@{http_status=$status;diagnostic=$diagnostic}
}

function Get-SocShuffleV2Property {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            $value = $Object[$Name]
            if ($value -is [array] -or $value -is [Collections.IList]) {
                Write-Output -NoEnumerate $value
                return
            }
            return $value
        }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $value = $property.Value
    if ($value -is [array] -or $value -is [Collections.IList]) {
        Write-Output -NoEnumerate $value
        return
    }
    return $value
}

function Get-SocShuffleV2PropertyNames {
    param([AllowNull()][object]$Object)

    if ($null -eq $Object) { return @() }
    if ($Object -is [Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object { [string]$_ })
    }
    return @($Object.PSObject.Properties.Name | ForEach-Object { [string]$_ })
}

function Get-SocShuffleV2ExactOrganizationId {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$PropertyNames
    )

    $objectProperties = @(Get-SocShuffleV2PropertyNames -Object $Object)
    $values = [Collections.Generic.List[string]]::new()
    foreach ($propertyName in $PropertyNames) {
        if ($propertyName -notin $objectProperties) { continue }
        $value = Get-SocShuffleV2Property -Object $Object -Name $propertyName
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or
            $value -match '[\r\n]' -or $value -notmatch $script:SocShuffleV2UuidPattern) {
            return ''
        }
        $values.Add([string]$value)
    }
    if ($values.Count -eq 0) { return '' }
    foreach ($value in $values) {
        if ([string]$value -cne [string]$values[0]) { return '' }
    }
    return [string]$values[0]
}

function Assert-SocShuffleV2AllowedProperties {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string]$Label
    )

    $unknown = @(Get-SocShuffleV2PropertyNames -Object $Object | Where-Object { $_ -notin $Allowed })
    if ($unknown.Count -ne 0) {
        throw "$Label contains an unapproved property."
    }
}

function Copy-SocShuffleV2Object {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
}

function Get-SocShuffleV2List {
    param(
        [AllowNull()][object]$Response,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $nested = Get-SocShuffleV2Property -Object $Response -Name $PropertyName
    if ($null -ne $nested) { return @($nested) }
    if ($Response -is [array] -or $Response -is [Collections.IList]) {
        return @($Response)
    }
    if ($null -eq $Response) { return @() }
    return @($Response)
}

function Get-SocShuffleV2WorkflowObject {
    param([AllowNull()][object]$Response)

    $nested = Get-SocShuffleV2Property -Object $Response -Name 'workflow'
    if ($null -ne $nested) { return $nested }
    $nested = Get-SocShuffleV2Property -Object $Response -Name 'data'
    if ($null -ne $nested -and $null -ne (Get-SocShuffleV2Property -Object $nested -Name 'id')) {
        return $nested
    }
    if ($null -ne (Get-SocShuffleV2Property -Object $Response -Name 'id')) {
        return $Response
    }
    return $null
}

function Get-SocShuffleV2WorkflowId {
    param([AllowNull()][object]$Response)

    $workflow = Get-SocShuffleV2WorkflowObject -Response $Response
    foreach ($candidate in @(
        (Get-SocShuffleV2Property -Object $workflow -Name 'id'),
        (Get-SocShuffleV2Property -Object $Response -Name 'workflow_id'),
        (Get-SocShuffleV2Property -Object $Response -Name 'id')
    )) {
        if ([string]$candidate -match $script:SocShuffleV2UuidPattern) {
            return [string]$candidate
        }
    }
    return ''
}

function Get-SocShuffleV2GeneratedId {
    param([Parameter(Mandatory)][scriptblock]$IdFactory)

    $id = [string](& $IdFactory)
    if ($id -notmatch $script:SocShuffleV2UuidPattern) {
        throw 'Generated Shuffle identity is not a canonical UUID.'
    }
    return $id
}

function New-SocShuffleV2Parameter {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    return [ordered]@{name=$Name;value=$Value}
}

function New-SocShuffleV2Action {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string]$AppVersion,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$Parameters,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$AppId
    )

    $action = [ordered]@{
        id=$Id
        label=$Label
        app_name=$AppName
        app_version=$AppVersion
        name=$Name
        is_valid=$true
        parameters=@($Parameters)
    }
    $action.app_id = $AppId
    return $action
}

function New-SocShuffleV2Condition {
    param(
        [Parameter(Mandatory)][string]$SourceExpression,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DestinationValue,
        [Parameter(Mandatory)][scriptblock]$IdFactory
    )

    return [ordered]@{
        source=[ordered]@{
            id=Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
            name='source'
            variant='STATIC_VALUE'
            value=$SourceExpression
        }
        condition=[ordered]@{
            id=Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
            name='condition'
            value='equals'
        }
        destination=[ordered]@{
            id=Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
            name='destination'
            variant='STATIC_VALUE'
            value=$DestinationValue
        }
    }
}

function New-SocShuffleV2Branch {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$SourceId,
        [Parameter(Mandatory)][string]$DestinationId,
        [object[]]$Conditions = @()
    )

    return [ordered]@{
        id=$Id
        source_id=$SourceId
        destination_id=$DestinationId
        conditions=@($Conditions)
    }
}

function New-SocShuffleV2WorkflowDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookId,
        [Parameter(Mandatory)][string]$ValidatorAppId,
        [Parameter(Mandatory)][string]$ShuffleToolsAppId,
        [Parameter(Mandatory)][string]$HeaderValue,
        [scriptblock]$IdFactory = { [guid]::NewGuid().ToString() }
    )

    if ($WebhookId -notmatch $script:SocShuffleV2UuidPattern -or
        $ValidatorAppId -notmatch '^[a-f0-9]{32}$') {
        throw 'The v2 Webhook or Validator App identity is invalid.'
    }
    if ([string]::IsNullOrWhiteSpace($HeaderValue) -or
        $HeaderValue -match '[\s\r\n:]') {
        throw 'The v2 Webhook Header value is empty or unsafe.'
    }

    $actionIds = [ordered]@{}
    foreach ($label in $script:SocShuffleV2ActionLabels) {
        $actionIds[$label] = Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
    }
    $branchIds = [ordered]@{}
    foreach ($name in @(
        'webhook-validator', 'validator-claim', 'validator-rejected-schema',
        'validator-rejected-allowlist', 'claim-classify',
        'classify-safety-gate', 'classify-repeat', 'classify-duplicate'
    )) {
        $branchIds[$name] = Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
    }

    $actions = @(
        (New-SocShuffleV2Action -Id $actionIds.validate_payload `
            -Label 'validate_payload' -AppName $script:SocShuffleV2ValidatorName `
            -AppVersion $script:SocShuffleV2ValidatorVersion -Name 'validate_sanitized_alert' `
            -AppId $ValidatorAppId -Parameters @(
                (New-SocShuffleV2Parameter -Name 'input_data' -Value '$exec')
            )),
        (New-SocShuffleV2Action -Id $actionIds.claim_event_dedupe `
            -Label 'claim_event_dedupe' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'set_datastore_value' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'category' -Value 'soc-v2'),
                (New-SocShuffleV2Parameter -Name 'key' -Value '$validate_payload.dedupe_key'),
                (New-SocShuffleV2Parameter -Name 'value' -Value '$validate_payload.body_sha256')
            )),
        (New-SocShuffleV2Action -Id $actionIds.classify_dedupe_claim `
            -Label 'classify_dedupe_claim' -AppName $script:SocShuffleV2ValidatorName `
            -AppVersion $script:SocShuffleV2ValidatorVersion -Name 'classify_dedupe_claim' `
            -AppId $ValidatorAppId -Parameters @(
                (New-SocShuffleV2Parameter -Name 'claim_result' -Value '$claim_event_dedupe'),
                (New-SocShuffleV2Parameter -Name 'expected_key' -Value '$validate_payload.dedupe_key')
            )),
        (New-SocShuffleV2Action -Id $actionIds.write_duplicate_suppressed `
            -Label 'write_duplicate_suppressed' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'write_duplicate_suppressed')
            )),
        (New-SocShuffleV2Action -Id $actionIds.write_observe_only `
            -Label 'write_observe_only' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'write_observe_only')
            )),
        (New-SocShuffleV2Action -Id $actionIds.write_rejected_schema `
            -Label 'write_rejected_schema' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'write_rejected_schema')
            )),
        (New-SocShuffleV2Action -Id $actionIds.write_rejected_allowlist `
            -Label 'write_rejected_allowlist' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'write_rejected_allowlist')
            )),
        (New-SocShuffleV2Action -Id $actionIds.write_safety_gate_blocked `
            -Label 'write_safety_gate_blocked' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'write_safety_gate_blocked')
            )),
        (New-SocShuffleV2Action -Id $actionIds.repeat_back_to_me `
            -Label 'repeat_back_to_me' -AppName 'Shuffle Tools' `
            -AppVersion $script:SocShuffleV2ShuffleToolsVersion -Name 'repeat_back_to_me' `
            -AppId $ShuffleToolsAppId `
            -Parameters @(
                (New-SocShuffleV2Parameter -Name 'call' -Value 'GATE_B5_REPEAT_STUB')
            ))
    )

    $branches = @(
        (New-SocShuffleV2Branch -Id $branchIds.'webhook-validator' `
            -SourceId $WebhookId -DestinationId $actionIds.validate_payload),
        (New-SocShuffleV2Branch -Id $branchIds.'validator-claim' `
            -SourceId $actionIds.validate_payload -DestinationId $actionIds.claim_event_dedupe `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$validate_payload.valid' `
                    -DestinationValue 'true' -IdFactory $IdFactory)
            )),
        (New-SocShuffleV2Branch -Id $branchIds.'validator-rejected-schema' `
            -SourceId $actionIds.validate_payload -DestinationId $actionIds.write_rejected_schema `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$validate_payload.rejection' `
                    -DestinationValue 'REJECTED_SCHEMA' -IdFactory $IdFactory)
            )),
        (New-SocShuffleV2Branch -Id $branchIds.'validator-rejected-allowlist' `
            -SourceId $actionIds.validate_payload -DestinationId $actionIds.write_rejected_allowlist `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$validate_payload.rejection' `
                    -DestinationValue 'REJECTED_ALLOWLIST' -IdFactory $IdFactory)
            )),
        (New-SocShuffleV2Branch -Id $branchIds.'claim-classify' `
            -SourceId $actionIds.claim_event_dedupe -DestinationId $actionIds.classify_dedupe_claim),
        (New-SocShuffleV2Branch -Id $branchIds.'classify-safety-gate' `
            -SourceId $actionIds.classify_dedupe_claim `
            -DestinationId $actionIds.write_safety_gate_blocked `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$classify_dedupe_claim.valid' `
                    -DestinationValue 'false' -IdFactory $IdFactory)
            )),
        (New-SocShuffleV2Branch -Id $branchIds.'classify-repeat' `
            -SourceId $actionIds.classify_dedupe_claim `
            -DestinationId $actionIds.repeat_back_to_me `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$classify_dedupe_claim.valid' `
                    -DestinationValue 'true' -IdFactory $IdFactory),
                (New-SocShuffleV2Condition -SourceExpression '$classify_dedupe_claim.existed' `
                    -DestinationValue 'false' -IdFactory $IdFactory)
            )),
        (New-SocShuffleV2Branch -Id $branchIds.'classify-duplicate' `
            -SourceId $actionIds.classify_dedupe_claim `
            -DestinationId $actionIds.write_duplicate_suppressed `
            -Conditions @(
                (New-SocShuffleV2Condition -SourceExpression '$classify_dedupe_claim.valid' `
                    -DestinationValue 'true' -IdFactory $IdFactory),
                (New-SocShuffleV2Condition -SourceExpression '$classify_dedupe_claim.existed' `
                    -DestinationValue 'true' -IdFactory $IdFactory)
            ))
    )

    return [ordered]@{
        name=$script:SocShuffleV2WorkflowName
        description=$script:SocShuffleV2WorkflowDescription
        sharing='private'
        is_valid=$true
        start=$actionIds.validate_payload
        workflow_variables=@()
        triggers=@(
            [ordered]@{
                id=$WebhookId
                app_name='Webhook'
                app_version='1.0.0'
                label=$script:SocShuffleV2WebhookName
                name='Webhook'
                environment='cloud'
                trigger_type='WEBHOOK'
                status='stopped'
                parameters=@(
                    (New-SocShuffleV2Parameter -Name 'url' -Value ''),
                    (New-SocShuffleV2Parameter -Name 'tmp' -Value ''),
                    (New-SocShuffleV2Parameter -Name 'auth_headers' `
                        -Value "$($script:SocShuffleV2HeaderName): $HeaderValue"),
                    (New-SocShuffleV2Parameter -Name 'custom_response_body' -Value ''),
                    # shuffle-shared bd5bfb0f Webhook constructor/runtime uses
                    # the version sentinel as a string, not a Boolean value.
                    (New-SocShuffleV2Parameter -Name 'await_response' -Value 'v1')
                )
            }
        )
        actions=$actions
        branches=$branches
    }
}

function Get-SocShuffleV2ActionSpec {
    param(
        [Parameter(Mandatory)][string]$ValidatorAppId,
        [Parameter(Mandatory)][string]$ShuffleToolsAppId
    )

    return [ordered]@{
        validate_payload=[ordered]@{
            app_name=$script:SocShuffleV2ValidatorName
            app_version=$script:SocShuffleV2ValidatorVersion
            name='validate_sanitized_alert'
            app_id=$ValidatorAppId
            parameters=@([ordered]@{name='input_data';value='$exec'})
        }
        claim_event_dedupe=[ordered]@{
            app_name='Shuffle Tools'
            app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='set_datastore_value'
            app_id=$ShuffleToolsAppId
            parameters=@(
                [ordered]@{name='category';value='soc-v2'},
                [ordered]@{name='key';value='$validate_payload.dedupe_key'},
                [ordered]@{name='value';value='$validate_payload.body_sha256'}
            )
        }
        classify_dedupe_claim=[ordered]@{
            app_name=$script:SocShuffleV2ValidatorName
            app_version=$script:SocShuffleV2ValidatorVersion
            name='classify_dedupe_claim'
            app_id=$ValidatorAppId
            parameters=@(
                [ordered]@{name='claim_result';value='$claim_event_dedupe'},
                [ordered]@{name='expected_key';value='$validate_payload.dedupe_key'}
            )
        }
        write_duplicate_suppressed=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='write_duplicate_suppressed'})
        }
        write_observe_only=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='write_observe_only'})
        }
        write_rejected_schema=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='write_rejected_schema'})
        }
        write_rejected_allowlist=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='write_rejected_allowlist'})
        }
        write_safety_gate_blocked=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='write_safety_gate_blocked'})
        }
        repeat_back_to_me=[ordered]@{
            app_name='Shuffle Tools';app_version=$script:SocShuffleV2ShuffleToolsVersion
            name='repeat_back_to_me';app_id=$ShuffleToolsAppId;parameters=@([ordered]@{name='call';value='GATE_B5_REPEAT_STUB'})
        }
    }
}

function Test-SocShuffleV2FalseLike {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return -not [bool]$Value }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or $Value -is [single] -or
        $Value -is [double] -or $Value -is [decimal]) {
        return [decimal]$Value -eq 0
    }
    if ($Value -is [string]) {
        return [string]::IsNullOrWhiteSpace($Value) -or $Value.ToLowerInvariant() -in @('false','0')
    }
    if ($Value -is [Collections.ICollection]) { return $Value.Count -eq 0 }
    return $false
}

function Test-SocShuffleV2ExactBoolean {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][bool]$Expected
    )

    return $Value -is [bool] -and $Value -eq $Expected
}

function Test-SocShuffleV2BasicStarterEnvironment {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return $false }
    return $Value -ceq 'cloud' -or $Value -ceq 'Cloud'
}

function Assert-SocShuffleV2ParameterMetadata {
    param(
        [Parameter(Mandatory)][object]$Parameter,
        [Parameter(Mandatory)][string]$Label
    )

    Assert-SocShuffleV2AllowedProperties -Object $Parameter `
        -Allowed $script:SocShuffleV2ParameterProperties -Label $Label
    $variant = [string](Get-SocShuffleV2Property -Object $Parameter -Name 'variant')
    if ($variant -and $variant -cne 'STATIC_VALUE') {
        throw "$Label contains a non-static value variant."
    }
    foreach ($name in @('configuration','custom_value','value_replace','action_field')) {
        if (-not (Test-SocShuffleV2FalseLike `
                -Value (Get-SocShuffleV2Property -Object $Parameter -Name $name))) {
            throw "$Label contains an executable parameter override."
        }
    }
}

function Get-SocShuffleV2TriggerType {
    param([Parameter(Mandatory)][object]$Trigger)

    $values = @(@('trigger_type','type') | ForEach-Object {
        $value = Get-SocShuffleV2Property -Object $Trigger -Name $_
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            [string]$value
        }
    } | Sort-Object -Unique)
    if ($values.Count -ne 1) { throw 'The v2 Webhook trigger type representation is ambiguous.' }
    return $values[0].ToUpperInvariant()
}

function Get-SocShuffleV2StatusClass {
    param([AllowNull()][object]$Value)

    $status = [string]$Value
    if ($status.ToLowerInvariant() -in @('running','active')) { return 'running' }
    if ($status.ToLowerInvariant() -in @('stopped','inactive')) { return 'stopped' }
    return 'unknown'
}

function Test-SocShuffleV2CanonicalWebhookUrl {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$WebhookId
    )

    if ($Value -isnot [string] -or $WebhookId -notmatch $script:SocShuffleV2UuidPattern) {
        return $false
    }
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    if ($Value -match '[\r\n]') { return $false }
    $expectedPath = "/api/v1/hooks/webhook_$WebhookId"
    if ($Value -ceq $expectedPath) { return $true }

    $parsed = $null
    if (-not [uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsed)) { return $false }
    $approvedHosts = @(
        'shuffler.io','uk.shuffler.io','frankfurt.shuffler.io',
        'california.shuffler.io','ca.shuffler.io','au.shuffler.io'
    )
    return $parsed.Scheme -ceq 'https' -and
        [string]::IsNullOrEmpty($parsed.UserInfo) -and $parsed.IsDefaultPort -and
        [string]::IsNullOrEmpty($parsed.Query) -and [string]::IsNullOrEmpty($parsed.Fragment) -and
        $parsed.Host.ToLowerInvariant() -cin $approvedHosts -and
        $parsed.AbsolutePath -ceq $expectedPath
}

function Get-SocShuffleV2SemanticProjection {
    param([Parameter(Mandatory)][object]$Workflow)

    $trigger = @((Get-SocShuffleV2Property -Object $Workflow -Name 'triggers'))[0]
    $actions = @((Get-SocShuffleV2Property -Object $Workflow -Name 'actions') | ForEach-Object {
        [ordered]@{
            id=[string](Get-SocShuffleV2Property -Object $_ -Name 'id')
            label=[string](Get-SocShuffleV2Property -Object $_ -Name 'label')
            app_id=[string](Get-SocShuffleV2Property -Object $_ -Name 'app_id')
            app_name=[string](Get-SocShuffleV2Property -Object $_ -Name 'app_name')
            app_version=[string](Get-SocShuffleV2Property -Object $_ -Name 'app_version')
            name=[string](Get-SocShuffleV2Property -Object $_ -Name 'name')
            is_valid=Get-SocShuffleV2Property -Object $_ -Name 'is_valid'
            parameters=@((Get-SocShuffleV2Property -Object $_ -Name 'parameters') | ForEach-Object {
                [ordered]@{name=[string]$_.name;value=[string]$_.value}
            } | Sort-Object name)
        }
    } | Sort-Object label)
    $branches = @((Get-SocShuffleV2Property -Object $Workflow -Name 'branches') | ForEach-Object {
        [ordered]@{
            id=[string]$_.id
            source_id=[string]$_.source_id
            destination_id=[string]$_.destination_id
            conditions=@($_.conditions | ForEach-Object {
                [ordered]@{
                    source=[ordered]@{id=[string]$_.source.id;name=[string]$_.source.name;variant=[string]$_.source.variant;value=[string]$_.source.value}
                    condition=[ordered]@{id=[string]$_.condition.id;name=[string]$_.condition.name;value=[string]$_.condition.value}
                    destination=[ordered]@{id=[string]$_.destination.id;name=[string]$_.destination.name;variant=[string]$_.destination.variant;value=[string]$_.destination.value}
                }
            })
        }
    } | Sort-Object id)
    $workflowName = [string](Get-SocShuffleV2Property -Object $Workflow -Name 'name')
    if ([string]::IsNullOrWhiteSpace($workflowName)) { $workflowName = $script:SocShuffleV2WorkflowName }
    $isValidProperty = Get-SocShuffleV2Property -Object $Workflow -Name 'is_valid'
    return [ordered]@{
        id=[string](Get-SocShuffleV2Property -Object $Workflow -Name 'id')
        name=$workflowName
        description=[string](Get-SocShuffleV2Property -Object $Workflow -Name 'description')
        sharing=[string](Get-SocShuffleV2Property -Object $Workflow -Name 'sharing')
        is_valid=$isValidProperty
        start=[string](Get-SocShuffleV2Property -Object $Workflow -Name 'start')
        workflow_variables=@((Get-SocShuffleV2Property -Object $Workflow -Name 'workflow_variables'))
        trigger=[ordered]@{
            id=[string](Get-SocShuffleV2Property -Object $trigger -Name 'id')
            trigger_type=Get-SocShuffleV2TriggerType -Trigger $trigger
            status=Get-SocShuffleV2StatusClass `
                -Value (Get-SocShuffleV2Property -Object $trigger -Name 'status')
            parameters=@((Get-SocShuffleV2Property -Object $trigger -Name 'parameters') | ForEach-Object {
                $parameterName = [string]$_.name
                # url/tmp may be server-native Webhook fields. Their values are
                # validated against a closed safe set before this projection.
                $parameterValue = if ($parameterName -in @('url','tmp')) {
                    '<server-native>'
                } else { [string]$_.value }
                [ordered]@{name=$parameterName;value=$parameterValue}
            })
        }
        actions=$actions
        branches=$branches
    }
}

function Get-SocShuffleV2ComparableJson {
    param([Parameter(Mandatory)][object]$Value)

    return (Get-SocShuffleV2SemanticProjection -Workflow $Value |
        ConvertTo-Json -Depth 100 -Compress)
}

function Get-SocShuffleV2SharedProjection {
    param([Parameter(Mandatory)][object]$Workflow)

    $trigger = @($Workflow.triggers)[0]
    $workflowName = [string](Get-SocShuffleV2Property -Object $Workflow -Name 'name')
    if ([string]::IsNullOrWhiteSpace($workflowName)) {
        $workflowName = $script:SocShuffleV2WorkflowName
    }
    $isValidProperty = Get-SocShuffleV2Property -Object $Workflow -Name 'is_valid'
    return [pscustomobject][ordered]@{
        id=[string]$Workflow.id
        name=$workflowName
        sharing=[string]$Workflow.sharing
        is_valid=$isValidProperty
        workflow_variables=@()
        triggers=@([pscustomobject][ordered]@{
            id=[string]$trigger.id
            trigger_type=Get-SocShuffleV2TriggerType -Trigger $trigger
            status=[string]$trigger.status
            parameters=@($trigger.parameters | ForEach-Object {
                [pscustomobject][ordered]@{name=[string]$_.name;value=[string]$_.value}
            })
        })
        actions=@($Workflow.actions | ForEach-Object {
            $item = [ordered]@{
                id=[string]$_.id;label=[string]$_.label;app_name=[string]$_.app_name
                app_version=[string]$_.app_version;name=[string]$_.name
                is_valid=Get-SocShuffleV2Property -Object $_ -Name 'is_valid'
                parameters=@($_.parameters | ForEach-Object {
                    [pscustomobject][ordered]@{name=[string]$_.name;value=[string]$_.value}
                })
            }
            $appId = [string](Get-SocShuffleV2Property -Object $_ -Name 'app_id')
            if (-not [string]::IsNullOrWhiteSpace($appId)) { $item.app_id = $appId }
            [pscustomobject]$item
        })
        branches=@($Workflow.branches | ForEach-Object {
            [pscustomobject][ordered]@{
                id=[string]$_.id;source_id=[string]$_.source_id;destination_id=[string]$_.destination_id
                conditions=@($_.conditions | ForEach-Object {
                    [pscustomobject][ordered]@{
                        source=[pscustomobject][ordered]@{id=[string]$_.source.id;name=[string]$_.source.name;variant=[string]$_.source.variant;value=[string]$_.source.value}
                        condition=[pscustomobject][ordered]@{id=[string]$_.condition.id;name=[string]$_.condition.name;value=[string]$_.condition.value}
                        destination=[pscustomobject][ordered]@{id=[string]$_.destination.id;name=[string]$_.destination.name;variant=[string]$_.destination.variant;value=[string]$_.destination.value}
                    }
                })
            }
        })
    }
}

function Assert-SocShuffleV2Workflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId,
        [Parameter(Mandatory)][string]$ValidatorAppId,
        [Parameter(Mandatory)][string]$ShuffleToolsAppId,
        [Parameter(Mandatory)][string]$HeaderValue,
        [ValidateSet('Any','Stopped','Running')][string]$ExpectedWebhookState = 'Any',
        [switch]$RequireRunning
    )

    if ($RequireRunning) { $ExpectedWebhookState = 'Running' }
    Assert-SocShuffleV2AllowedProperties -Object $Workflow `
        -Allowed $script:SocShuffleV2WorkflowProperties -Label 'The v2 Workflow'
    $workflowName = Get-SocShuffleV2Property -Object $Workflow -Name 'name'
    $isValidProperty = Get-SocShuffleV2Property -Object $Workflow -Name 'is_valid'
    if ($WorkflowId -notmatch $script:SocShuffleV2UuidPattern -or
        [string](Get-SocShuffleV2Property -Object $Workflow -Name 'id') -cne $WorkflowId -or
        ($null -ne $workflowName -and -not [string]::IsNullOrWhiteSpace([string]$workflowName) -and
            [string]$workflowName -cne $script:SocShuffleV2WorkflowName) -or
        [string](Get-SocShuffleV2Property -Object $Workflow -Name 'description') -cne $script:SocShuffleV2WorkflowDescription -or
        [string](Get-SocShuffleV2Property -Object $Workflow -Name 'sharing') -cne 'private' -or
        -not (Test-SocShuffleV2ExactBoolean -Value $isValidProperty -Expected $true)) {
        throw 'The v2 Workflow identity, marker, sharing, or validity is unsafe.'
    }
    $variables = Get-SocShuffleV2Property -Object $Workflow -Name 'workflow_variables'
    if ($null -ne $variables -and @($variables).Count -ne 0) {
        throw 'The v2 Workflow contains an unapproved Workflow variable.'
    }
    $triggers = @((Get-SocShuffleV2Property -Object $Workflow -Name 'triggers'))
    if ($triggers.Count -ne 1 -or [string]$triggers[0].id -cne $WebhookId) {
        throw 'The v2 Workflow must contain exactly one Webhook trigger.'
    }
    $trigger = $triggers[0]
    Assert-SocShuffleV2AllowedProperties -Object $trigger `
        -Allowed $script:SocShuffleV2TriggerProperties -Label 'The v2 Webhook trigger'
    if ((Get-SocShuffleV2TriggerType -Trigger $trigger) -cne 'WEBHOOK') {
        throw 'The v2 trigger is not a Webhook.'
    }
    foreach ($typeProperty in @('trigger_type','type')) {
        $typeValue = Get-SocShuffleV2Property -Object $trigger -Name $typeProperty
        if ($null -ne $typeValue -and [string]$typeValue -cne 'WEBHOOK') {
            throw 'The v2 Webhook trigger type is not canonical uppercase WEBHOOK.'
        }
    }
    foreach ($name in @('execution_delay','source_workflow','replacement_for_trigger','parent_controlled')) {
        if (-not (Test-SocShuffleV2FalseLike `
                -Value (Get-SocShuffleV2Property -Object $trigger -Name $name))) {
            throw 'The v2 Webhook trigger contains an executable override.'
        }
    }
    $triggerState = Get-SocShuffleV2StatusClass `
        -Value (Get-SocShuffleV2Property -Object $trigger -Name 'status')
    if ($triggerState -ceq 'unknown' -or
        ($ExpectedWebhookState -cne 'Any' -and $triggerState -cne $ExpectedWebhookState.ToLowerInvariant())) {
        throw 'The v2 Webhook trigger state is not the expected state.'
    }
    $triggerParameters = @((Get-SocShuffleV2Property -Object $trigger -Name 'parameters'))
    $expectedTriggerParameterNames = @('url','tmp','auth_headers','custom_response_body','await_response')
    if ($triggerParameters.Count -ne $expectedTriggerParameterNames.Count -or
        ((@($triggerParameters | ForEach-Object {[string]$_.name}) -join ',') -cne
            ($expectedTriggerParameterNames -join ','))) {
        throw 'The v2 Webhook parameter set is not the canonical ordered shape.'
    }
    for ($parameterIndex = 0; $parameterIndex -lt $triggerParameters.Count; $parameterIndex++) {
        Assert-SocShuffleV2ParameterMetadata -Parameter $triggerParameters[$parameterIndex] `
            -Label "The v2 Webhook parameter $($expectedTriggerParameterNames[$parameterIndex])"
    }
    if (-not (Test-SocShuffleV2CanonicalWebhookUrl -Value $triggerParameters[0].value `
            -WebhookId $WebhookId) -or
        $triggerParameters[1].value -isnot [string] -or
        [string]$triggerParameters[1].value -notin @('','tmp') -or
        $triggerParameters[2].value -isnot [string] -or
        [string]$triggerParameters[2].value -cne "$($script:SocShuffleV2HeaderName): $HeaderValue" -or
        $triggerParameters[3].value -isnot [string] -or
        [string]$triggerParameters[3].value -cne '' -or
        $triggerParameters[4].value -isnot [string] -or
        [string]$triggerParameters[4].value -cne 'v1') {
        throw 'The v2 Webhook server-native parameter values or auth binding are unsafe.'
    }

    $actions = @((Get-SocShuffleV2Property -Object $Workflow -Name 'actions'))
    $labels = @($actions | ForEach-Object {[string]$_.label})
    if ($labels.Count -ne $script:SocShuffleV2ActionLabels.Count -or
        @($labels | Sort-Object -Unique).Count -ne $labels.Count -or
        (($labels | Sort-Object) -join ',') -cne (($script:SocShuffleV2ActionLabels | Sort-Object) -join ',')) {
        throw 'The v2 Workflow Action labels are not the exact fixed set.'
    }
    $specs = Get-SocShuffleV2ActionSpec -ValidatorAppId $ValidatorAppId `
        -ShuffleToolsAppId $ShuffleToolsAppId
    foreach ($action in $actions) {
        Assert-SocShuffleV2AllowedProperties -Object $action `
            -Allowed $script:SocShuffleV2ActionProperties -Label 'The v2 Action'
        if ([string]$action.id -notmatch $script:SocShuffleV2UuidPattern -or
            [string]$action.name -match '(?i)^(execute_python|execute_bash|execute_http_request)$' -or
            -not (Test-SocShuffleV2ExactBoolean `
                -Value (Get-SocShuffleV2Property -Object $action -Name 'is_valid') `
                -Expected $true)) {
            throw 'The v2 Workflow contains an unsafe Action identity or operation.'
        }
        foreach ($name in @(
            'authentication_id','execution_delay','sub_action','run_magic_output','run_magic_input',
            'source_workflow','source_execution','parent_controlled'
        )) {
            if (-not (Test-SocShuffleV2FalseLike `
                    -Value (Get-SocShuffleV2Property -Object $action -Name $name))) {
                throw 'The v2 Workflow contains an Action Authentication or execution override.'
            }
        }
        $spec = $specs[[string]$action.label]
        if ([string]$action.app_name -cne [string]$spec.app_name -or
            [string]$action.app_version -cne [string]$spec.app_version -or
            [string]$action.name -cne [string]$spec.name) {
            throw "The v2 Action contract is unsafe for label $([string]$action.label)."
        }
        $expectedAppId = [string](Get-SocShuffleV2Property -Object $spec -Name 'app_id')
        if ([string]::IsNullOrWhiteSpace($expectedAppId) -or
            [string]$action.app_id -cne $expectedAppId) {
            throw 'The v2 Action App binding is not exact.'
        }
        $actualParameters = @($action.parameters)
        $expectedParameters = @($spec.parameters)
        if ($actualParameters.Count -ne $expectedParameters.Count) {
            throw "The v2 Action parameter count is unsafe for label $([string]$action.label)."
        }
        foreach ($actualParameter in $actualParameters) {
            Assert-SocShuffleV2ParameterMetadata -Parameter $actualParameter `
                -Label "The v2 Action parameter for $([string]$action.label)"
        }
        foreach ($expected in $expectedParameters) {
            $actual = @($actualParameters | Where-Object {[string]$_.name -ceq [string]$expected.name})
            if ($actual.Count -ne 1 -or [string]$actual[0].value -cne [string]$expected.value) {
                throw "The v2 Action parameter mapping is unsafe for label $([string]$action.label)."
            }
        }
    }

    $idToLabel = @{$WebhookId='__WEBHOOK_TRIGGER__'}
    foreach ($action in $actions) {
        $actionId = [string]$action.id
        if ($idToLabel.ContainsKey($actionId)) { throw 'The v2 Workflow contains a duplicate Action identity.' }
        $idToLabel[$actionId] = [string]$action.label
    }
    $validateActionId = [string](@($actions | Where-Object label -ceq 'validate_payload')[0].id)
    if ([string](Get-SocShuffleV2Property -Object $Workflow -Name 'start') -cne $validateActionId) {
        throw 'The v2 Workflow start node is not validate_payload.'
    }
    $expectedGraph = @(
        [pscustomobject]@{source='__WEBHOOK_TRIGGER__';destination='validate_payload';conditions=@()},
        [pscustomobject]@{source='validate_payload';destination='claim_event_dedupe';conditions=@([pscustomobject]@{source='$validate_payload.valid';destination='true'})},
        [pscustomobject]@{source='validate_payload';destination='write_rejected_schema';conditions=@([pscustomobject]@{source='$validate_payload.rejection';destination='REJECTED_SCHEMA'})},
        [pscustomobject]@{source='validate_payload';destination='write_rejected_allowlist';conditions=@([pscustomobject]@{source='$validate_payload.rejection';destination='REJECTED_ALLOWLIST'})},
        [pscustomobject]@{source='claim_event_dedupe';destination='classify_dedupe_claim';conditions=@()},
        [pscustomobject]@{source='classify_dedupe_claim';destination='write_safety_gate_blocked';conditions=@([pscustomobject]@{source='$classify_dedupe_claim.valid';destination='false'})},
        [pscustomobject]@{source='classify_dedupe_claim';destination='repeat_back_to_me';conditions=@(
            [pscustomobject]@{source='$classify_dedupe_claim.valid';destination='true'},
            [pscustomobject]@{source='$classify_dedupe_claim.existed';destination='false'})},
        [pscustomobject]@{source='classify_dedupe_claim';destination='write_duplicate_suppressed';conditions=@(
            [pscustomobject]@{source='$classify_dedupe_claim.valid';destination='true'},
            [pscustomobject]@{source='$classify_dedupe_claim.existed';destination='true'})}
    )
    $branches = @((Get-SocShuffleV2Property -Object $Workflow -Name 'branches'))
    if ($branches.Count -ne $expectedGraph.Count) {
        throw 'The v2 Workflow Branch count is not the fixed eight-edge graph.'
    }
    $branchIds = [Collections.Generic.HashSet[string]]::new()
    $branchEdges = [Collections.Generic.HashSet[string]]::new()
    foreach ($branch in $branches) {
        Assert-SocShuffleV2AllowedProperties -Object $branch `
            -Allowed $script:SocShuffleV2BranchProperties -Label 'The v2 Branch'
        foreach ($name in @('has_errors','decorator','parent_controlled','source_parent')) {
            if (-not (Test-SocShuffleV2FalseLike `
                    -Value (Get-SocShuffleV2Property -Object $branch -Name $name))) {
                throw 'The v2 Branch contains an executable or parent override.'
            }
        }
        $branchId = [string]$branch.id
        $sourceId = [string]$branch.source_id
        $destinationId = [string]$branch.destination_id
        if ($branchId -notmatch $script:SocShuffleV2UuidPattern -or
            -not $branchIds.Add($branchId) -or
            -not $idToLabel.ContainsKey($sourceId) -or
            -not $idToLabel.ContainsKey($destinationId)) {
            throw 'The v2 Workflow contains a duplicate, dangling, or malformed Branch.'
        }
        if (-not $branchEdges.Add(('{0}|{1}' -f $idToLabel[$sourceId],$idToLabel[$destinationId]))) {
            throw 'The v2 Workflow contains a duplicate Branch edge.'
        }
    }
    foreach ($expectedEdge in $expectedGraph) {
        $matches = @($branches | Where-Object {
            $idToLabel[[string]$_.source_id] -ceq [string]$expectedEdge.source -and
            $idToLabel[[string]$_.destination_id] -ceq [string]$expectedEdge.destination
        })
        if ($matches.Count -ne 1) { throw 'The v2 Workflow is missing or duplicating a fixed Branch edge.' }
        $conditions = @($matches[0].conditions)
        $expectedConditions = @($expectedEdge.conditions)
        if ($conditions.Count -ne $expectedConditions.Count) {
            throw 'The v2 Workflow Branch condition count is not exact.'
        }
        for ($conditionIndex = 0; $conditionIndex -lt $expectedConditions.Count; $conditionIndex++) {
            $condition = $conditions[$conditionIndex]
            $expectedCondition = $expectedConditions[$conditionIndex]
            Assert-SocShuffleV2AllowedProperties -Object $condition `
                -Allowed @('source','condition','destination') -Label 'The v2 Branch condition'
            $source = Get-SocShuffleV2Property -Object $condition -Name 'source'
            $operator = Get-SocShuffleV2Property -Object $condition -Name 'condition'
            $destination = Get-SocShuffleV2Property -Object $condition -Name 'destination'
            foreach ($part in @($source,$operator,$destination)) {
                Assert-SocShuffleV2ParameterMetadata -Parameter $part -Label 'The v2 Branch condition parameter'
            }
            if ([string]$source.id -notmatch $script:SocShuffleV2UuidPattern -or
                [string]$source.name -cne 'source' -or [string]$source.variant -cne 'STATIC_VALUE' -or
                [string]$source.value -cne [string]$expectedCondition.source -or
                [string]$operator.id -notmatch $script:SocShuffleV2UuidPattern -or
                [string]$operator.name -cne 'condition' -or [string]$operator.value -cne 'equals' -or
                [string]$destination.id -notmatch $script:SocShuffleV2UuidPattern -or
                [string]$destination.name -cne 'destination' -or [string]$destination.variant -cne 'STATIC_VALUE' -or
                $destination.value -isnot [string] -or
                [string]$destination.value -cne [string]$expectedCondition.destination) {
                throw 'The v2 Branch condition fields or string destination are not exact.'
            }
        }
    }
    if ($ExpectedWebhookState -ceq 'Running') {
        $sharedAssertion = Get-Command -Name 'Assert-ShuffleSocV2Workflow' `
            -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $sharedAssertion) {
            $sharedProjection = Get-SocShuffleV2SharedProjection -Workflow $Workflow
            [void](& $sharedAssertion -Workflow $sharedProjection -WorkflowId $WorkflowId `
                -WebhookId $WebhookId -ExpectedHeaderValue $HeaderValue)
        }
    }
    return $Workflow
}

function Test-SocShuffleV2AppAvailability {
    param(
        [Parameter(Mandatory)][object]$App,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Quiet
    )

    try {
        foreach ($requirement in @(
            [pscustomobject]@{name='activated';expected=$true},
            [pscustomobject]@{name='is_valid';expected=$true},
            [pscustomobject]@{name='invalid';expected=$false}
        )) {
            $name = [string]$requirement.name
            $propertyNames = @(Get-SocShuffleV2PropertyNames -Object $App)
            $value = Get-SocShuffleV2Property -Object $App -Name $name
            if ($name -notin $propertyNames -or
                -not (Test-SocShuffleV2ExactBoolean -Value $value `
                    -Expected ([bool]$requirement.expected))) {
                throw "$Label does not expose the exact $name boolean contract."
            }
        }
        return $true
    } catch {
        if ($Quiet) { return $false }
        throw $_
    }
}

function Invoke-SocShuffleV2ApiStage {
    param(
        [Parameter(Mandatory)][scriptblock]$ApiCall,
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT')][string]$Method,
        [Parameter(Mandatory)][string]$RelativePath,
        [AllowNull()][object]$Body,
        [AllowNull()][object]$RequestOptions = $null,
        [Parameter(Mandatory)][ValidateSet(
            'validator-app','workflow-discovery','workflow-readback','workflow-create',
            'workflow-save','webhook-start','webhook-readback'
        )][string]$Category,
        [string]$WorkflowId = '',
        [string]$WebhookId = ''
    )

    try {
        return & $ApiCall $Method $RelativePath $Body $RequestOptions
    } catch {
        if ($Category -ceq 'workflow-save') {
            $diagnostic = Get-SocShuffleV2SafeSaveDiagnostic -ErrorRecord $_
            throw (New-SocShuffleV2Failure -Category $Category -WorkflowId $WorkflowId `
                -WebhookId $WebhookId -HttpStatus ([int]$diagnostic.http_status) `
                -Diagnostic ([string]$diagnostic.diagnostic))
        }
        throw (New-SocShuffleV2Failure -Category $Category -WorkflowId $WorkflowId -WebhookId $WebhookId)
    }
}

function Resolve-SocShuffleV2ValidatorApp {
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OrganizationId,
        [string]$ExpectedAppId = ''
    )

    $apps = @(Get-SocShuffleV2List -Response $Response -PropertyName 'apps' | Where-Object {
        [string](Get-SocShuffleV2Property -Object $_ -Name 'name') -ceq $script:SocShuffleV2ValidatorName -and
        ([string](Get-SocShuffleV2Property -Object $_ -Name 'app_version') -ceq $script:SocShuffleV2ValidatorVersion -or
         [string](Get-SocShuffleV2Property -Object $_ -Name 'version') -ceq $script:SocShuffleV2ValidatorVersion)
    })
    if ($ExpectedAppId) { $apps = @($apps | Where-Object {[string]$_.id -ceq $ExpectedAppId}) }
    if ($apps.Count -ne 1 -or [string]$apps[0].id -notmatch '^[a-f0-9]{32}$') {
        throw 'The current v2 Validator App is absent or ambiguous.'
    }
    if ((Get-SocShuffleV2ExactOrganizationId -Object $apps[0] `
            -PropertyNames @('reference_org')) -cne $OrganizationId) {
        throw 'The current v2 Validator App does not prove the configured Organization.'
    }
    [void](Test-SocShuffleV2AppAvailability -App $apps[0] -Label 'v2 Validator App')
    return $apps[0]
}

function Resolve-SocShuffleV2ShuffleToolsApp {
    param(
        [Parameter(Mandatory)][object]$Response,
        [string]$ExpectedAppId = ''
    )

    $apps = @(Get-SocShuffleV2List -Response $Response -PropertyName 'apps' | Where-Object {
        [string](Get-SocShuffleV2Property -Object $_ -Name 'name') -ceq 'Shuffle Tools' -and
        ([string](Get-SocShuffleV2Property -Object $_ -Name 'app_version') -ceq $script:SocShuffleV2ShuffleToolsVersion -or
         [string](Get-SocShuffleV2Property -Object $_ -Name 'version') -ceq $script:SocShuffleV2ShuffleToolsVersion)
    })
    if ($ExpectedAppId) { $apps = @($apps | Where-Object {[string]$_.id -ceq $ExpectedAppId}) }
    $apps = @($apps | Where-Object {
        Test-SocShuffleV2AppAvailability -App $_ -Label 'Shuffle Tools App' -Quiet
    })
    if ($apps.Count -ne 1 -or [string](Get-SocShuffleV2Property -Object $apps[0] -Name 'id') -notmatch '^[a-f0-9]{32}$') {
        throw 'The active Shuffle Tools 1.2.0 App is absent or ambiguous.'
    }
    return $apps[0]
}

function Resolve-SocShuffleV2WorkflowListEnvelope {
    param([Parameter(Mandatory)][object]$Response)

    $body = Get-SocShuffleV2Property -Object $Response -Name 'body'
    $headers = Get-SocShuffleV2Property -Object $Response -Name 'response_headers'
    if ($null -eq $body -or $null -eq $headers) {
        throw 'The Workflow list response metadata envelope is absent.'
    }
    $truncated = Get-SocShuffleV2Property -Object $headers -Name 'X-SHUFFLE_TRUNCATED'
    if ($null -ne $truncated) {
        $values = @($truncated)
        if ($values.Count -ne 1 -or $values[0] -isnot [string] -or
            [string]$values[0] -notin @('true','false')) {
            throw 'The Workflow list truncation response header is ambiguous.'
        }
        if ([string]$values[0] -ceq 'true') {
            throw 'The Workflow list response is truncated.'
        }
    }
    if ($body -is [array] -or $body -is [Collections.IList]) {
        Write-Output -NoEnumerate $body
        return
    }
    return $body
}

function Resolve-SocShuffleV2WorkflowCandidates {
    param(
        [AllowNull()][object]$Response,
        [string]$OrganizationId = ''
    )

    if ($Response -isnot [array] -and $Response -isnot [Collections.IList]) {
        throw 'The Workflow discovery response shape is unknown.'
    }
    $items = @($Response)
    if ($items.Count -eq 0) {
        throw 'The Workflow discovery response cannot prove the Organization scope.'
    }
    if ($items.Count -ge 600) {
        throw 'The Workflow discovery response reached the completeness bound.'
    }

    $workflowMatches = [Collections.Generic.List[object]]::new()
    foreach ($item in @($items)) {
        if ($null -eq $item) { throw 'The Workflow discovery list contains a null item.' }
        $itemId = [string](Get-SocShuffleV2Property -Object $item -Name 'id')
        $itemName = [string](Get-SocShuffleV2Property -Object $item -Name 'name')
        if ($itemId -notmatch $script:SocShuffleV2UuidPattern -or
            [string]::IsNullOrWhiteSpace($itemName)) {
            throw 'The Workflow discovery list contains a malformed summary.'
        }
        if ((Get-SocShuffleV2ExactOrganizationId -Object $item `
                -PropertyNames @('org_id','organization_id')) -cne $OrganizationId) {
            throw 'A Workflow discovery summary does not prove the configured Organization.'
        }
        if ($itemName -cne $script:SocShuffleV2WorkflowName) {
            continue
        }
        [void]$workflowMatches.Add($item)
    }
    return @($workflowMatches)
}

function Set-SocShuffleV2Property {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Value
    )

    if ($Object -is [Collections.IDictionary]) {
        $Object[$Name] = $Value
        return
    }
    Add-Member -InputObject $Object -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Assert-SocShuffleV2BasicPartial {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$ShuffleToolsAppId,
        [Parameter(Mandatory)][string]$HeaderValue
    )

    Assert-SocShuffleV2AllowedProperties -Object $Workflow `
        -Allowed $script:SocShuffleV2WorkflowProperties -Label 'The basic v2 Workflow'
    $workflowName = Get-SocShuffleV2Property -Object $Workflow -Name 'name'
    $isValidProperty = Get-SocShuffleV2Property -Object $Workflow -Name 'is_valid'
    if ($WorkflowId -notmatch $script:SocShuffleV2UuidPattern -or
        [string](Get-SocShuffleV2Property -Object $Workflow -Name 'id') -cne $WorkflowId -or
        ($null -ne $workflowName -and -not [string]::IsNullOrWhiteSpace([string]$workflowName) -and
            [string]$workflowName -cne $script:SocShuffleV2WorkflowName) -or
        ($null -ne (Get-SocShuffleV2Property -Object $Workflow -Name 'description') -and
            [string](Get-SocShuffleV2Property -Object $Workflow -Name 'description') -cne $script:SocShuffleV2WorkflowDescription) -or
        [string](Get-SocShuffleV2Property -Object $Workflow -Name 'sharing') -cne 'private' -or
        ($null -ne $isValidProperty -and
            -not (Test-SocShuffleV2ExactBoolean -Value $isValidProperty -Expected $true))) {
        throw 'The resumable basic v2 Workflow identity or installer marker is unsafe.'
    }
    $actions = @((Get-SocShuffleV2Property -Object $Workflow -Name 'actions') | Where-Object {$null -ne $_})
    $branches = @((Get-SocShuffleV2Property -Object $Workflow -Name 'branches') | Where-Object {$null -ne $_})
    $variables = @((Get-SocShuffleV2Property -Object $Workflow -Name 'workflow_variables') | Where-Object {$null -ne $_})
    if ($actions.Count -gt 1 -or $branches.Count -ne 0 -or $variables.Count -ne 0) {
        throw 'The resumable v2 Workflow is not a basic create object.'
    }
    $triggers = @((Get-SocShuffleV2Property -Object $Workflow -Name 'triggers'))
    if ($triggers.Count -ne 0) { throw 'The basic v2 Workflow contains an unexpected trigger set.' }
    $start = [string](Get-SocShuffleV2Property -Object $Workflow -Name 'start')

    if ($actions.Count -eq 0) {
        if (-not [string]::IsNullOrWhiteSpace($start)) {
            throw 'The empty basic v2 Workflow has an unexpected start node.'
        }
        return ''
    }

    # Some current backends enrich a fresh POST with the single canonical
    # Shuffle Tools starter.  Only this harmless shape is resumable; any other
    # executable or branch drift fails closed before a PUT.
    $starter = $actions[0]
    Assert-SocShuffleV2AllowedProperties -Object $starter `
        -Allowed $script:SocShuffleV2ActionProperties -Label 'The basic Shuffle Tools starter'
    $previouslySaved = Get-SocShuffleV2Property -Object $Workflow -Name 'previously_saved'
    $starterEnvironment = Get-SocShuffleV2Property -Object $starter -Name 'environment'
    $starterIsValid = Get-SocShuffleV2Property -Object $starter -Name 'is_valid'
    if ([string]$starter.id -notmatch $script:SocShuffleV2UuidPattern -or
        [string]$starter.app_name -cne 'Shuffle Tools' -or
        [string]$starter.app_version -cne $script:SocShuffleV2ShuffleToolsVersion -or
        [string]$starter.label -cne 'Change Me' -or
        [string]$starter.name -cne 'repeat_back_to_me' -or
        [string]$starter.app_id -cne $ShuffleToolsAppId -or
        [string]$start -cne [string]$starter.id -or
        -not (Test-SocShuffleV2ExactBoolean -Value $previouslySaved -Expected $false) -or
        -not (Test-SocShuffleV2ExactBoolean -Value $isValidProperty -Expected $true) -or
        -not (Test-SocShuffleV2BasicStarterEnvironment -Value $starterEnvironment) -or
        -not (Test-SocShuffleV2ExactBoolean -Value $starterIsValid -Expected $true)) {
        throw 'The basic v2 Workflow contains an unknown Shuffle Tools starter.'
    }
    foreach ($name in @(
        'authentication_id','execution_delay','sub_action','run_magic_output','run_magic_input',
        'source_workflow','source_execution','parent_controlled'
    )) {
        if (-not (Test-SocShuffleV2FalseLike `
                -Value (Get-SocShuffleV2Property -Object $starter -Name $name))) {
            throw 'The basic v2 Shuffle Tools starter contains an executable override.'
        }
    }
    $starterParameters = @((Get-SocShuffleV2Property -Object $starter -Name 'parameters'))
    if ($starterParameters.Count -ne 1 -or [string]$starterParameters[0].name -cne 'call' -or
        $starterParameters[0].value -isnot [string] -or
        [string]$starterParameters[0].value -cne 'Hello world') {
        throw 'The basic v2 Workflow starter parameters are not canonical.'
    }
    Assert-SocShuffleV2ParameterMetadata -Parameter $starterParameters[0] `
        -Label 'The basic Shuffle Tools starter parameter'
    return ''
}

function Merge-SocShuffleV2WorkflowDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$ServerNativeBase,
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][string]$WorkflowId
    )

    Assert-SocShuffleV2AllowedProperties -Object $ServerNativeBase `
        -Allowed $script:SocShuffleV2WorkflowProperties -Label 'The server-native v2 Workflow base'
    if ([string](Get-SocShuffleV2Property -Object $ServerNativeBase -Name 'id') -cne $WorkflowId) {
        throw 'The server-native v2 Workflow base has the wrong identity.'
    }
    $merged = Copy-SocShuffleV2Object -Value $ServerNativeBase
    foreach ($name in @(
        'name','description','sharing','is_valid','start','workflow_variables',
        'triggers','actions','branches'
    )) {
        Set-SocShuffleV2Property -Object $merged -Name $name `
            -Value (Copy-SocShuffleV2Object -Value (Get-SocShuffleV2Property -Object $Definition -Name $name))
    }
    return $merged
}

function New-SocShuffleV2HookBody {
    param(
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId,
        [Parameter(Mandatory)][string]$StartActionId,
        [Parameter(Mandatory)][string]$HeaderValue
    )

    return [ordered]@{
        name=$script:SocShuffleV2WebhookName
        type='webhook'
        id=$WebhookId
        workflow=$WorkflowId
        start=$StartActionId
        environment='cloud'
        auth="$($script:SocShuffleV2HeaderName): $HeaderValue"
    }
}

function Complete-SocShuffleV2Workflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ApiCall,
        [Parameter(Mandatory)][object]$FullObject,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId,
        [Parameter(Mandatory)][string]$ValidatorAppId,
        [Parameter(Mandatory)][string]$ShuffleToolsAppId,
        [Parameter(Mandatory)][string]$HeaderValue
    )

    try {
        [void](Assert-SocShuffleV2Workflow -Workflow $FullObject -WorkflowId $WorkflowId `
            -WebhookId $WebhookId -ValidatorAppId $ValidatorAppId -HeaderValue $HeaderValue `
            -ShuffleToolsAppId $ShuffleToolsAppId `
            -ExpectedWebhookState Stopped)
    } catch {
        throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
            -WorkflowId $WorkflowId -WebhookId $WebhookId)
    }
    [void](Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method PUT `
        -RelativePath "/api/v1/workflows/$WorkflowId" -Body $FullObject `
        -Category 'workflow-save' -WorkflowId $WorkflowId -WebhookId $WebhookId)
    $savedResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
        -RelativePath "/api/v1/workflows/$WorkflowId" -Body $null `
        -Category 'workflow-readback' -WorkflowId $WorkflowId -WebhookId $WebhookId
    $savedObject = Get-SocShuffleV2WorkflowObject -Response $savedResponse
    try {
        [void](Assert-SocShuffleV2Workflow -Workflow $savedObject -WorkflowId $WorkflowId `
            -WebhookId $WebhookId -ValidatorAppId $ValidatorAppId -HeaderValue $HeaderValue `
            -ShuffleToolsAppId $ShuffleToolsAppId `
            -ExpectedWebhookState Stopped)
        if ((Get-SocShuffleV2ComparableJson -Value $FullObject) -cne
            (Get-SocShuffleV2ComparableJson -Value $savedObject)) {
            throw 'The saved v2 semantic contract differs from the approved definition.'
        }
    } catch {
        throw (New-SocShuffleV2Failure -Category 'workflow-readback' `
            -WorkflowId $WorkflowId -WebhookId $WebhookId)
    }

    $startActionId = [string](Get-SocShuffleV2Property -Object $savedObject -Name 'start')
    $hookBody = New-SocShuffleV2HookBody -WorkflowId $WorkflowId -WebhookId $WebhookId `
        -StartActionId $startActionId -HeaderValue $HeaderValue
    $hookResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method POST `
        -RelativePath '/api/v1/hooks' -Body $hookBody -Category 'webhook-start' `
        -WorkflowId $WorkflowId -WebhookId $WebhookId
    if (-not (Test-SocShuffleV2ExactBoolean `
            -Value (Get-SocShuffleV2Property -Object $hookResponse -Name 'success') `
            -Expected $true)) {
        throw (New-SocShuffleV2Failure -Category 'webhook-start' `
            -WorkflowId $WorkflowId -WebhookId $WebhookId)
    }
    $startedResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
        -RelativePath "/api/v1/workflows/$WorkflowId" -Body $null `
        -Category 'webhook-readback' -WorkflowId $WorkflowId -WebhookId $WebhookId
    $startedObject = Get-SocShuffleV2WorkflowObject -Response $startedResponse
    try {
        [void](Assert-SocShuffleV2Workflow -Workflow $startedObject -WorkflowId $WorkflowId `
            -WebhookId $WebhookId -ValidatorAppId $ValidatorAppId `
            -ShuffleToolsAppId $ShuffleToolsAppId -HeaderValue $HeaderValue `
            -ExpectedWebhookState Running)
    } catch {
        throw (New-SocShuffleV2Failure -Category 'webhook-readback' `
            -WorkflowId $WorkflowId -WebhookId $WebhookId)
    }
    return $startedObject
}

function Invoke-SocShuffleV2Install {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ApiCall,
        [Parameter(Mandatory)][string]$HeaderValue,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OrganizationId,
        [string]$ExistingWorkflowId = '',
        [string]$ValidatorAppId = '',
        [string]$NewWebhookId = '',
        [scriptblock]$IdFactory = { [guid]::NewGuid().ToString() }
    )

    if ([string]::IsNullOrWhiteSpace($HeaderValue) -or $HeaderValue -match '[\s\r\n:]') {
        throw (New-SocShuffleV2Failure -Category 'secret')
    }
    if ([string]::IsNullOrWhiteSpace($OrganizationId) -or
        $OrganizationId -notmatch $script:SocShuffleV2UuidPattern -or
        ($ExistingWorkflowId -and $ExistingWorkflowId -notmatch $script:SocShuffleV2UuidPattern) -or
        ($NewWebhookId -and $NewWebhookId -notmatch $script:SocShuffleV2UuidPattern)) {
        throw (New-SocShuffleV2Failure -Category 'configuration')
    }
    $appsResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
        -RelativePath '/api/v1/apps' -Body $null -Category 'validator-app'
    try {
        $validator = Resolve-SocShuffleV2ValidatorApp -Response $appsResponse `
            -OrganizationId $OrganizationId `
            -ExpectedAppId $ValidatorAppId
        $shuffleTools = Resolve-SocShuffleV2ShuffleToolsApp -Response $appsResponse
    } catch {
        throw (New-SocShuffleV2Failure -Category 'validator-app')
    }
    $resolvedValidatorAppId = [string]$validator.id
    $resolvedShuffleToolsAppId = [string]$shuffleTools.id

    if ($ExistingWorkflowId) {
        $legacyResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
            -RelativePath "/api/v1/workflows/$ExistingWorkflowId" -Body $null `
            -Category 'workflow-readback' -WorkflowId $ExistingWorkflowId
        $legacyObject = Get-SocShuffleV2WorkflowObject -Response $legacyResponse
        if ($null -eq $legacyObject -or
            [string](Get-SocShuffleV2Property -Object $legacyObject -Name 'id') -cne $ExistingWorkflowId -or
            [string](Get-SocShuffleV2Property -Object $legacyObject -Name 'name') -cne $script:SocShuffleLegacyWorkflowName -or
            (Get-SocShuffleV2ExactOrganizationId -Object $legacyObject `
                -PropertyNames @('org_id','organization_id')) -cne $OrganizationId) {
            throw (New-SocShuffleV2Failure -Category 'workflow-drift' -WorkflowId $ExistingWorkflowId)
        }
        # Verify the configured rollback anchor on every run.  It remains GET-only.
    }

    $workflowListRequestOptions = [pscustomobject][ordered]@{
        request_headers=[ordered]@{truncate='false'}
        include_response_metadata=$true
    }
    $workflowListEnvelope = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
        -RelativePath '/api/v1/workflows?top=600&truncate=false' -Body $null `
        -RequestOptions $workflowListRequestOptions -Category 'workflow-discovery'
    try {
        $workflowListResponse = Resolve-SocShuffleV2WorkflowListEnvelope `
            -Response $workflowListEnvelope
        $v2Candidates = @(Resolve-SocShuffleV2WorkflowCandidates `
            -Response $workflowListResponse -OrganizationId $OrganizationId)
    } catch {
        throw (New-SocShuffleV2Failure -Category 'workflow-discovery')
    }
    if ($v2Candidates.Count -gt 1) {
        throw (New-SocShuffleV2Failure -Category 'workflow-duplicate')
    }

    if ($v2Candidates.Count -eq 1) {
        $workflowId = [string](Get-SocShuffleV2Property -Object $v2Candidates[0] -Name 'id')
        $existingResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
            -RelativePath "/api/v1/workflows/$workflowId" -Body $null `
            -Category 'workflow-readback' -WorkflowId $workflowId
        $existingObject = Get-SocShuffleV2WorkflowObject -Response $existingResponse
        $webhookId = ''
        $isExact = $false
        try {
            $triggers = @((Get-SocShuffleV2Property -Object $existingObject -Name 'triggers'))
            if ($triggers.Count -ne 1) { throw 'Not a configured v2 Workflow.' }
            $webhookId = [string](Get-SocShuffleV2Property -Object $triggers[0] -Name 'id')
            [void](Assert-SocShuffleV2Workflow -Workflow $existingObject `
                -WorkflowId $workflowId -WebhookId $webhookId `
                -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
                -HeaderValue $HeaderValue)
            $isExact = $true
        } catch {
            $isExact = $false
        }

        if ($isExact) {
            if ($NewWebhookId -and $NewWebhookId -cne $webhookId) {
                throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
                    -WorkflowId $workflowId -WebhookId $webhookId)
            }
            $statusClass = Get-SocShuffleV2StatusClass `
                -Value (Get-SocShuffleV2Property -Object $existingObject.triggers[0] -Name 'status')
            if ($statusClass -ceq 'running') {
                try {
                    [void](Assert-SocShuffleV2Workflow -Workflow $existingObject `
                        -WorkflowId $workflowId -WebhookId $webhookId `
                        -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
                        -HeaderValue $HeaderValue `
                        -ExpectedWebhookState Running)
                } catch {
                    throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
                        -WorkflowId $workflowId -WebhookId $webhookId)
                }
                return [pscustomobject][ordered]@{
                    workflow_id=$workflowId;webhook_id=$webhookId
                    validator_app_id=$resolvedValidatorAppId;shuffle_tools_app_id=$resolvedShuffleToolsAppId
                    reused=$true;resumed=$false;started=$false
                }
            }
            if ($statusClass -cne 'stopped') {
                throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
                    -WorkflowId $workflowId -WebhookId $webhookId)
            }
            $fullObject = Copy-SocShuffleV2Object -Value $existingObject
        } else {
            try {
                $partialWebhookId = [string](Assert-SocShuffleV2BasicPartial `
                    -Workflow $existingObject -WorkflowId $workflowId `
                    -ShuffleToolsAppId $resolvedShuffleToolsAppId -HeaderValue $HeaderValue)
            } catch {
                throw (New-SocShuffleV2Failure -Category 'workflow-drift' -WorkflowId $workflowId)
            }
            if ($partialWebhookId -and $NewWebhookId -and $partialWebhookId -cne $NewWebhookId) {
                throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
                    -WorkflowId $workflowId -WebhookId $partialWebhookId)
            }
            try {
                $webhookId = if ($partialWebhookId) {
                    $partialWebhookId
                } elseif ($NewWebhookId) {
                    $NewWebhookId
                } else {
                    Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
                }
                $definition = New-SocShuffleV2WorkflowDefinition -WebhookId $webhookId `
                    -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
                    -HeaderValue $HeaderValue `
                    -IdFactory $IdFactory
                $fullObject = Merge-SocShuffleV2WorkflowDefinition `
                    -ServerNativeBase $existingObject -Definition $definition -WorkflowId $workflowId
            } catch {
                throw (New-SocShuffleV2Failure -Category 'workflow-drift' `
                    -WorkflowId $workflowId -WebhookId $webhookId)
            }
        }

        [void](Complete-SocShuffleV2Workflow -ApiCall $ApiCall -FullObject $fullObject `
            -WorkflowId $workflowId -WebhookId $webhookId `
            -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
            -HeaderValue $HeaderValue)
        return [pscustomobject][ordered]@{
            workflow_id=$workflowId;webhook_id=$webhookId
            validator_app_id=$resolvedValidatorAppId;shuffle_tools_app_id=$resolvedShuffleToolsAppId
            reused=$true;resumed=$true;started=$true
        }
    }

    $createBody = [ordered]@{
        name=$script:SocShuffleV2WorkflowName
        description=$script:SocShuffleV2WorkflowDescription
    }
    $createResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method POST `
        -RelativePath '/api/v1/workflows' -Body $createBody -Category 'workflow-create'
    $workflowId = Get-SocShuffleV2WorkflowId -Response $createResponse
    if ($workflowId -notmatch $script:SocShuffleV2UuidPattern) {
        throw (New-SocShuffleV2Failure -Category 'workflow-create')
    }
    $baseResponse = Invoke-SocShuffleV2ApiStage -ApiCall $ApiCall -Method GET `
        -RelativePath "/api/v1/workflows/$workflowId" -Body $null `
        -Category 'workflow-readback' -WorkflowId $workflowId
    $baseObject = Get-SocShuffleV2WorkflowObject -Response $baseResponse
    try {
        $baseWebhookId = [string](Assert-SocShuffleV2BasicPartial -Workflow $baseObject `
            -WorkflowId $workflowId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
            -HeaderValue $HeaderValue)
    } catch {
        throw (New-SocShuffleV2Failure -Category 'workflow-create' -WorkflowId $workflowId)
    }
    if ($baseWebhookId) {
        throw (New-SocShuffleV2Failure -Category 'workflow-create' `
            -WorkflowId $workflowId -WebhookId $baseWebhookId)
    }
    $webhookId = ''
    try {
        $webhookId = if ($NewWebhookId) {
            $NewWebhookId
        } else {
            Get-SocShuffleV2GeneratedId -IdFactory $IdFactory
        }
        $definition = New-SocShuffleV2WorkflowDefinition -WebhookId $webhookId `
            -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
            -HeaderValue $HeaderValue -IdFactory $IdFactory
        $fullObject = Merge-SocShuffleV2WorkflowDefinition -ServerNativeBase $baseObject `
            -Definition $definition -WorkflowId $workflowId
    } catch {
        throw (New-SocShuffleV2Failure -Category 'workflow-create' `
            -WorkflowId $workflowId -WebhookId $webhookId)
    }
    [void](Complete-SocShuffleV2Workflow -ApiCall $ApiCall -FullObject $fullObject `
        -WorkflowId $workflowId -WebhookId $webhookId `
        -ValidatorAppId $resolvedValidatorAppId -ShuffleToolsAppId $resolvedShuffleToolsAppId `
        -HeaderValue $HeaderValue)
    return [pscustomobject][ordered]@{
        workflow_id=$workflowId;webhook_id=$webhookId
        validator_app_id=$resolvedValidatorAppId;shuffle_tools_app_id=$resolvedShuffleToolsAppId
        reused=$false;resumed=$false;started=$true
    }
}

if (-not $NoRun) {
    Write-Host 'Shuffle SOC v2 Workflow installer preview'
    Write-Host 'Target: private CAPITAL-ONE-SOC-CONTAINMENT-v2; no v1 Workflow update or deletion.'
    Write-Host 'Runtime writes: none until explicit -ConfirmInstall.'
    if ($ConfirmInstall -cne 'INSTALL SHUFFLE SOC V2') {
        throw "Preview only. Re-run with -ConfirmInstall 'INSTALL SHUFFLE SOC V2'."
    }

    $apiKey = $null
    $headerValue = $null
    try {
        $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
        Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
        Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force
        Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Shuffle.psm1') -Force
        $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
        $apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $SecretRoot
        $headerValue = Unprotect-SocSecret -Name 'shuffle_webhook_header_key' -SecretRoot $SecretRoot
        $baseUri = [uri][string]$configuration.shuffle_api_base
        $orgId = [string]$configuration.shuffle_org_id
        $apiCall = {
            param(
                [string]$Method,
                [string]$RelativePath,
                [AllowNull()][object]$Body,
                [AllowNull()][object]$RequestOptions
            )
            $invokeParameters = @{
                Method=$Method;RelativePath=$RelativePath;ApiKey=$apiKey
                OrgId=$orgId;BaseUri=$baseUri;Body=$Body
            }
            if ($null -ne $RequestOptions) {
                $requestHeaders = Get-SocShuffleV2Property `
                    -Object $RequestOptions -Name 'request_headers'
                $includeMetadata = Get-SocShuffleV2Property `
                    -Object $RequestOptions -Name 'include_response_metadata'
                if ($null -ne $requestHeaders) { $invokeParameters.RequestHeaders = $requestHeaders }
                if (Test-SocShuffleV2ExactBoolean -Value $includeMetadata -Expected $true) {
                    $invokeParameters.IncludeResponseMetadata = $true
                }
            }
            Invoke-ShuffleApiRequest @invokeParameters
        }.GetNewClosure()
        $result = Invoke-SocShuffleV2Install -ApiCall $apiCall -HeaderValue $headerValue `
            -OrganizationId $orgId `
            -ExistingWorkflowId $(if ($ExistingWorkflowId) {$ExistingWorkflowId} else {[string]$configuration.shuffle_workflow_id})
        Write-Host 'SHUFFLE_SOC_V2_READY=yes'
        Write-Host "WORKFLOW_ID=$($result.workflow_id)"
        Write-Host "WEBHOOK_ID=$($result.webhook_id)"
        Write-Host "VALIDATOR_APP_ID=$($result.validator_app_id)"
        Write-Host "SHUFFLE_TOOLS_APP_ID=$($result.shuffle_tools_app_id)"
        Write-Host "REUSED=$($result.reused.ToString().ToLowerInvariant())"
        Write-Host "RESUMED=$($result.resumed.ToString().ToLowerInvariant())"
        Write-Host "STARTED=$($result.started.ToString().ToLowerInvariant())"
    } catch {
        if ([string]$_.Exception.Message -match '^Shuffle v2 installer failed \[') { throw }
        throw (New-SocShuffleV2Failure -Category 'configuration')
    } finally {
        $apiKey = $null
        $headerValue = $null
    }
}
