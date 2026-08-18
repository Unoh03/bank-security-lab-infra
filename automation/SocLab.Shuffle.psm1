#requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$script:TakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:ShuffleWorkflowName = 'CAPITAL-ONE-SOC-CONTAINMENT-v1'
$script:ShuffleCategory = 'soc-v1'
$script:ValidatorAppName = 'AWS Topology SOC Validator'
$script:ValidatorAppVersion = '1.0.0'
$script:DispatcherAppName = 'AWS Topology SOC GitHub Dispatcher'
$script:DispatcherAppVersion = '1.0.0'
$script:ProductionActionLabels = @()
$script:RequiredActionLabels = @(
    'validate_payload',
    'get_take_allow',
    'claim_take_dispatch',
    'dispatch_github_containment',
    'write_response_dispatched',
    'write_duplicate_suppressed',
    'write_observe_only',
    'write_rejected_schema',
    'write_rejected_allowlist',
    'write_rejected_take',
    'write_response_failed'
)

function Assert-ShuffleUuid {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -cnotmatch $script:UuidPattern) {
        throw "$Label is not a canonical UUID."
    }
}

function Resolve-ShuffleApiUri {
    param(
        [Parameter(Mandatory)][uri]$BaseUri,
        [Parameter(Mandatory)][string]$RelativePath
    )

    if ($BaseUri.Scheme -cne 'https' -or
        ($BaseUri.Host -cne 'shuffler.io' -and -not $BaseUri.Host.EndsWith('.shuffler.io')) -or
        -not $BaseUri.IsDefaultPort -or $BaseUri.AbsolutePath -cne '/' -or
        $BaseUri.UserInfo -or $BaseUri.Query -or $BaseUri.Fragment) {
        throw 'The Shuffle API base URI violates the fixed HTTPS host allowlist.'
    }
    if ($RelativePath -notmatch '^/api/v[12]/[A-Za-z0-9_?=&./{}:-]+$' -or
        $RelativePath.Contains('..')) {
        throw 'The Shuffle API relative path is unsafe.'
    }
    $resolved = [uri]::new($BaseUri, $RelativePath)
    if ($resolved.Scheme -cne 'https' -or $resolved.Host -cne $BaseUri.Host) {
        throw 'The Shuffle API request escaped the approved origin.'
    }
    return $resolved
}

function Invoke-ShuffleApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$ApiKey,
        [string]$OrgId = '',
        [AllowNull()][object]$Body = $null,
        [uri]$BaseUri = 'https://shuffler.io/',
        [ValidateRange(5,60)][int]$TimeoutSeconds = 20
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey) -or $ApiKey -match '[\r\n]') {
        throw 'The Shuffle API key is empty or unsafe.'
    }
    if ($OrgId) {
        Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    }
    $uri = Resolve-ShuffleApiUri -BaseUri $BaseUri -RelativePath $RelativePath
    $httpMethod = switch ($Method) {
        'GET'    { [Net.Http.HttpMethod]::Get }
        'POST'   { [Net.Http.HttpMethod]::Post }
        'PUT'    { [Net.Http.HttpMethod]::Put }
        'DELETE' { [Net.Http.HttpMethod]::Delete }
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds($TimeoutSeconds)
    $request = [Net.Http.HttpRequestMessage]::new($httpMethod, $uri)
    try {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $ApiKey)
        if ($OrgId) {
            [void]$request.Headers.TryAddWithoutValidation('Org-Id', $OrgId)
        }
        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Depth 30 -Compress
            $request.Content = [Net.Http.StringContent]::new(
                $json,
                [Text.Encoding]::UTF8,
                'application/json'
            )
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$response.StatusCode
            if ($statusCode -ge 300 -and $statusCode -lt 400) {
                throw "Shuffle API redirect was refused: HTTP $statusCode"
            }
            if ($statusCode -lt 200 -or $statusCode -ge 300) {
                throw "Shuffle API request failed: HTTP $statusCode"
            }
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($text.Length -gt 8388608) {
                throw 'Shuffle API response exceeded the fixed 8 MiB limit.'
            }
            if ([string]::IsNullOrWhiteSpace($text)) {
                return [pscustomobject]@{}
            }
            try {
                return $text | ConvertFrom-Json -Depth 100
            } catch {
                throw 'Shuffle API returned a non-JSON response.'
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        if ($request.Content) {
            $request.Content.Dispose()
        }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Assert-ShuffleSocWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId
    )

    Assert-ShuffleUuid -Value $WorkflowId -Label 'Shuffle Workflow ID'
    Assert-ShuffleUuid -Value $WebhookId -Label 'Shuffle Webhook ID'
    if ([string]$Workflow.id -cne $WorkflowId -or
        [string]$Workflow.name -cne $script:ShuffleWorkflowName -or
        [string]$Workflow.sharing -cne 'private' -or
        [bool]$Workflow.is_valid -ne $true) {
        throw 'The Shuffle Workflow identity or validity does not match the frozen contract.'
    }
    $allTriggers = @($Workflow.triggers)
    if ($allTriggers.Count -ne 1) {
        throw 'The frozen Shuffle Workflow must contain exactly one trigger.'
    }
    $trigger = @($allTriggers | Where-Object {
        [string]$_.id -ceq $WebhookId
    }) | Select-Object -First 1
    if ($null -eq $trigger) {
        throw 'The frozen Shuffle Webhook trigger is absent from the Workflow.'
    }
    $type = if ($null -ne $trigger.PSObject.Properties['trigger_type']) {
        [string]$trigger.trigger_type
    } elseif ($null -ne $trigger.PSObject.Properties['type']) {
        [string]$trigger.type
    } else {
        ''
    }
    if ($type.ToLowerInvariant() -cne 'webhook') {
        throw 'The frozen Shuffle trigger is not a webhook.'
    }
    $status = if ($null -ne $trigger.PSObject.Properties['status']) {
        [string]$trigger.status
    } else {
        ''
    }
    if ($status -and $status.ToLowerInvariant() -notin @('running','active')) {
        throw 'The frozen Shuffle Webhook trigger is not active.'
    }
    $authentication = ''
    foreach ($propertyName in @('auth','authentication')) {
        if ($null -ne $trigger.PSObject.Properties[$propertyName]) {
            $authentication = [string]$trigger.$propertyName
            if ($authentication) { break }
        }
    }
    if (-not $authentication -and $null -ne $trigger.PSObject.Properties['parameters']) {
        $authentication = @($trigger.parameters | Where-Object {
            [string]$_.name -match '(?i)^(auth|auth_headers|authentication)$'
        } | ForEach-Object { [string]$_.value }) -join "`n"
    }
    if ($authentication -notmatch '(?im)^X-SOC-Webhook-Key\s*:\s*\S+') {
        throw 'The frozen Shuffle Webhook does not prove required Header authentication.'
    }
    $actionLabels = @($Workflow.actions | ForEach-Object { [string]$_.label })
    foreach ($label in $script:RequiredActionLabels) {
        if (@($actionLabels | Where-Object { $_ -ceq $label }).Count -ne 1) {
            throw "The frozen Shuffle Workflow action label is absent or duplicated: $label"
        }
    }
    if ($actionLabels.Count -ne $script:RequiredActionLabels.Count -or
        (@($actionLabels | Sort-Object) -join ',') -cne
        (@($script:RequiredActionLabels | Sort-Object) -join ',')) {
        throw 'The frozen Shuffle Workflow contains an unapproved extra Action.'
    }
    if ($null -ne $Workflow.PSObject.Properties['workflow_variables'] -and
        @($Workflow.workflow_variables).Count -ne 0) {
        throw 'The frozen Shuffle Workflow contains an unapproved Workflow variable.'
    }
    $unexpectedAuthentication = @($Workflow.actions | Where-Object {
        [string]$_.label -cne 'dispatch_github_containment' -and
        $null -ne $_.PSObject.Properties['authentication_id'] -and
        -not [string]::IsNullOrWhiteSpace([string]$_.authentication_id)
    })
    if ($unexpectedAuthentication.Count -ne 0) {
        throw 'A non-dispatch Shuffle Action contains an unapproved Authentication reference.'
    }
    $validator = @($Workflow.actions | Where-Object {
        [string]$_.label -ceq 'validate_payload'
    })
    if ($validator.Count -ne 1 -or
        [string]$validator[0].app_name -cne $script:ValidatorAppName -or
        [string]$validator[0].app_version -cne $script:ValidatorAppVersion -or
        [string]$validator[0].name -cne 'validate_sanitized_alert') {
        throw 'The Workflow does not use the fixed private SOC Validator App.'
    }
    $validatorInput = @($validator[0].parameters | Where-Object {
        [string]$_.name -ceq 'input_data'
    })
    if ($validatorInput.Count -ne 1 -or [string]$validatorInput[0].value -cne '$exec') {
        throw 'The SOC Validator must receive the complete Execution Argument exactly once.'
    }
    $dynamicCode = @($Workflow.actions | Where-Object {
        [string]$_.name -match '(?i)^(execute_python|execute_bash)$'
    })
    if ($dynamicCode.Count -ne 0) {
        throw 'The SOC Workflow contains a forbidden dynamic code execution Action.'
    }
    return $Workflow
}

function Get-ShuffleActionParameterMap {
    param([Parameter(Mandatory)][object]$Action)

    $map = @{}
    foreach ($parameter in @($Action.parameters)) {
        $name = [string]$parameter.name
        if ([string]::IsNullOrWhiteSpace($name) -or $map.ContainsKey($name)) {
            throw "The Shuffle Action contains an empty or duplicate parameter: $([string]$Action.label)"
        }
        $map[$name] = [string]$parameter.value
    }
    return $map
}

function Get-ShuffleSocDispatchGraph {
    param([Parameter(Mandatory)][object]$Workflow)

    $byLabel = @{}
    foreach ($action in @($Workflow.actions)) {
        $label = [string]$action.label
        if ([string]::IsNullOrWhiteSpace($label) -or $byLabel.ContainsKey($label)) {
            throw 'The Shuffle dispatch graph contains a missing or duplicate Action label.'
        }
        $byLabel[$label] = $action
    }
    foreach ($label in @(
        'claim_take_dispatch','dispatch_github_containment',
        'write_response_dispatched','write_response_failed'
    )) {
        if (-not $byLabel.ContainsKey($label) -or
            [string]::IsNullOrWhiteSpace([string]$byLabel[$label].id)) {
            throw "The Shuffle dispatch graph lacks an Action identity: $label"
        }
    }
    $dispatchId = [string]$byLabel['dispatch_github_containment'].id
    $branches = if ($null -ne $Workflow.PSObject.Properties['branches']) {
        @($Workflow.branches)
    } else { @() }
    $incoming = @($branches | Where-Object {
        [string]$_.destination_id -ceq $dispatchId
    })
    $outgoing = @($branches | Where-Object {
        [string]$_.source_id -ceq $dispatchId
    })
    return [pscustomobject]@{
        ByLabel=$byLabel
        Incoming=$incoming
        Outgoing=$outgoing
    }
}

function ConvertTo-ShuffleSocList {
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][ValidateSet('apps','authentication')][string]$Kind
    )

    if ($Response -is [array] -or $Response -is [Collections.IList]) {
        return @($Response)
    }
    if ($null -ne $Response.PSObject.Properties['success'] -and
        [bool]$Response.success -ne $true) {
        throw "Shuffle returned an unsuccessful $Kind list."
    }
    foreach ($propertyName in @('data','apps')) {
        if ($null -ne $Response.PSObject.Properties[$propertyName]) {
            return @($Response.$propertyName)
        }
    }
    throw "Shuffle returned an unsupported $Kind list shape."
}

function Assert-ShuffleSocAppUploadEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Evidence,
        [string]$ExpectedOrgId = ''
    )

    if ($ExpectedOrgId) {
        Assert-ShuffleUuid -Value $ExpectedOrgId -Label 'Shuffle Organization ID'
    }
    if ([int]$Evidence.schema_version -ne 1 -or
        [string]$Evidence.artifact_kind -cne 'shuffle-soc-private-app-bundle-upload' -or
        [bool]$Evidence.secret_persisted -ne $false -or
        ($ExpectedOrgId -and [string]$Evidence.organization_id -cne $ExpectedOrgId)) {
        throw 'The Shuffle App upload Evidence is invalid.'
    }
    $expectedNames = @($script:ValidatorAppName,$script:DispatcherAppName) | Sort-Object
    $apps = @($Evidence.apps)
    if ($apps.Count -ne 2 -or
        (@($apps.app_name | Sort-Object) -join ',') -cne ($expectedNames -join ',') -or
        @($apps | Where-Object {
            [string]$_.app_version -cne '1.0.0' -or
            [string]$_.app_id -cnotmatch '^[a-f0-9]{32}$' -or
            [string]$_.package_sha256 -cnotmatch '^[a-f0-9]{64}$'
        }).Count -ne 0) {
        throw 'The Shuffle App upload Evidence does not contain the exact two private Apps.'
    }
    return $Evidence
}

function Get-ShuffleSocAppUploadEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [string]$ExpectedOrgId = ''
    )

    $path = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) `
        'shuffle-app\soc-private-app-bundle-upload.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'The Shuffle SOC private App upload Evidence is unavailable.'
    }
    $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
    return Assert-ShuffleSocAppUploadEvidence -Evidence $evidence `
        -ExpectedOrgId $ExpectedOrgId
}

function Assert-ShuffleSocCloudProvenance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][object]$UploadEvidence,
        [Parameter(Mandatory)][object]$AppsResponse,
        [Parameter(Mandatory)][object]$AuthenticationResponse,
        [Parameter(Mandatory)][string]$ExpectedOrgId
    )

    Assert-ShuffleUuid -Value $ExpectedOrgId -Label 'Shuffle Organization ID'

    [void](Assert-ShuffleSocAppUploadEvidence -Evidence $UploadEvidence `
        -ExpectedOrgId $ExpectedOrgId)
    $expected = @{}
    foreach ($entry in @($UploadEvidence.apps)) {
        $name = [string]$entry.app_name
        if ($name -notin @($script:ValidatorAppName,$script:DispatcherAppName) -or
            $expected.ContainsKey($name) -or
            [string]$entry.app_version -cne '1.0.0' -or
            [string]$entry.app_id -cnotmatch '^[a-f0-9]{32}$' -or
            [string]$entry.package_sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The Shuffle App upload Evidence contains an invalid or duplicate App.'
        }
        $expected[$name] = $entry
    }
    if ($expected.Count -ne 2) {
        throw 'The Shuffle App upload Evidence does not contain the exact two private Apps.'
    }

    $cloudApps = @(ConvertTo-ShuffleSocList -Response $AppsResponse -Kind apps)
    foreach ($name in @($script:ValidatorAppName,$script:DispatcherAppName)) {
        $actionLabel = if ($name -ceq $script:ValidatorAppName) {
            'validate_payload'
        } else { 'dispatch_github_containment' }
        $action = @($Workflow.actions | Where-Object {
            [string]$_.label -ceq $actionLabel
        })
        $expectedId = [string]$expected[$name].app_id
        if ($action.Count -ne 1 -or
            [string]$action[0].app_id -cne $expectedId) {
            throw "The Workflow Action is not bound to the uploaded private App: $name"
        }
        $cloud = @($cloudApps | Where-Object {
            $null -ne $_.PSObject.Properties['id'] -and
            [string]$_.id -ceq $expectedId
        })
        if ($cloud.Count -ne 1) {
            throw "The uploaded private App is not uniquely available in the current Shuffle organization: $name"
        }
        $cloudVersion = if ($null -ne $cloud[0].PSObject.Properties['app_version']) {
            [string]$cloud[0].app_version
        } elseif ($null -ne $cloud[0].PSObject.Properties['version']) {
            [string]$cloud[0].version
        } else { '' }
        if ([string]$cloud[0].name -cne $name -or $cloudVersion -cne '1.0.0') {
            throw "The current Shuffle App identity differs from the uploaded App: $name"
        }
    }

    $dispatcher = @($Workflow.actions | Where-Object {
        [string]$_.label -ceq 'dispatch_github_containment'
    })[0]
    $authenticationId = [string]$dispatcher.authentication_id
    if ($authenticationId -cnotmatch '^[a-f0-9]{32}$') {
        throw 'The Dispatcher Authentication reference is not a canonical Shuffle App Authentication ID.'
    }
    $authentications = @(ConvertTo-ShuffleSocList `
        -Response $AuthenticationResponse -Kind authentication)
    $authentication = @($authentications | Where-Object {
        $null -ne $_.PSObject.Properties['id'] -and
        [string]$_.id -ceq $authenticationId
    })
    if ($authentication.Count -ne 1 -or
        $null -eq $authentication[0].PSObject.Properties['active'] -or
        [bool]$authentication[0].active -ne $true -or
        $null -eq $authentication[0].PSObject.Properties['encrypted'] -or
        [bool]$authentication[0].encrypted -ne $true -or
        [string]$authentication[0].org_id -cne $ExpectedOrgId -or
        $null -eq $authentication[0].PSObject.Properties['app'] -or
        $null -eq $authentication[0].PSObject.Properties['fields']) {
        throw 'The Dispatcher Authentication reference is absent, inactive, or incomplete.'
    }
    $authApp = $authentication[0].app
    $authVersion = if ($null -ne $authApp.PSObject.Properties['app_version']) {
        [string]$authApp.app_version
    } elseif ($null -ne $authApp.PSObject.Properties['version']) {
        [string]$authApp.version
    } else { '' }
    if ([string]$authApp.id -cne [string]$expected[$script:DispatcherAppName].app_id -or
        [string]$authApp.name -cne $script:DispatcherAppName -or
        $authVersion -cne $script:DispatcherAppVersion) {
        throw 'The selected Authentication does not belong to the uploaded Dispatcher App.'
    }
    $fieldKeys = @($authentication[0].fields | ForEach-Object {
        if ($null -eq $_.PSObject.Properties['key']) { '' } else { [string]$_.key }
    } | Sort-Object)
    if (($fieldKeys -join ',') -cne 'github_token') {
        throw 'The Dispatcher Authentication field contract is not exactly github_token.'
    }
    $authIdBytes = [Text.Encoding]::UTF8.GetBytes($authenticationId)
    try {
        $authIdSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($authIdBytes)
        ).ToLowerInvariant()
    } finally {
        [Array]::Clear($authIdBytes,0,$authIdBytes.Length)
    }
    return [pscustomobject][ordered]@{
        validator_app_id=[string]$expected[$script:ValidatorAppName].app_id
        dispatcher_app_id=[string]$expected[$script:DispatcherAppName].app_id
        dispatcher_authentication_id_sha256=$authIdSha256
        authentication_active=$true
        authentication_field_keys=@('github_token')
        secret_value_inspected=$false
    }
}

function Get-ShuffleSocCloudProvenance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][object]$UploadEvidence,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$OrgId,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    $apps = Invoke-ShuffleApiRequest -Method GET -RelativePath '/api/v1/apps' `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri
    $authentications = Invoke-ShuffleApiRequest -Method GET `
        -RelativePath '/api/v1/apps/authentication' `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri
    return Assert-ShuffleSocCloudProvenance -Workflow $Workflow `
        -UploadEvidence $UploadEvidence -AppsResponse $apps `
        -AuthenticationResponse $authentications -ExpectedOrgId $OrgId
}

function ConvertTo-ShuffleSocCanonicalValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [Collections.IDictionary]) {
        $dictionary = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $dictionary[$key] = ConvertTo-ShuffleSocCanonicalValue -Value $Value[$key]
        }
        return $dictionary
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((ConvertTo-ShuffleSocCanonicalValue -Value $item))
        }
        return ,@($items)
    }
    $properties = @($Value.PSObject.Properties | Where-Object {
        $_.MemberType -in @('NoteProperty','Property','AliasProperty')
    } | Sort-Object Name)
    if ($properties.Count -eq 0) {
        return [string]$Value
    }
    $object = [ordered]@{}
    foreach ($property in $properties) {
        $object[$property.Name] = ConvertTo-ShuffleSocCanonicalValue -Value $property.Value
    }
    return $object
}

function Get-ShuffleSocCoreContractSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WebhookId
    )

    Assert-ShuffleUuid -Value $WebhookId -Label 'Shuffle Webhook ID'
    $idToLabel = @{$WebhookId='__WEBHOOK_TRIGGER__'}
    $normalizedActions = [Collections.Generic.List[object]]::new()
    foreach ($action in @($Workflow.actions)) {
        $id = [string]$action.id
        $label = [string]$action.label
        if ([string]::IsNullOrWhiteSpace($id) -or
            [string]::IsNullOrWhiteSpace($label) -or
            $idToLabel.ContainsKey($id)) {
            throw 'The Shuffle core fingerprint found a missing or duplicate Action identity.'
        }
        $idToLabel[$id] = $label
        if ($label -ceq 'dispatch_github_containment') {
            $normalizedActions.Add([ordered]@{label=$label;slot='fixed-dispatch-replacement'})
            continue
        }
        $parameterNames = @($action.parameters | ForEach-Object { [string]$_.name })
        if (@($parameterNames | Sort-Object -Unique).Count -ne $parameterNames.Count) {
            throw "The Shuffle core fingerprint found duplicate parameters: $label"
        }
        $parameters = @($action.parameters | ForEach-Object {
            [ordered]@{
                name=[string]$_.name
                value=ConvertTo-ShuffleSocCanonicalValue -Value $_.value
                variant=if ($null -ne $_.PSObject.Properties['variant']) {[string]$_.variant} else {''}
                configuration=if ($null -ne $_.PSObject.Properties['configuration']) {[bool]$_.configuration} else {$false}
            }
        } | Sort-Object name)
        $normalizedActions.Add([ordered]@{
            label=$label
            app_id=if ($null -ne $action.PSObject.Properties['app_id']) {[string]$action.app_id} else {''}
            app_name=[string]$action.app_name
            app_version=[string]$action.app_version
            name=[string]$action.name
            parameters=$parameters
        })
    }
    $normalizedBranches = [Collections.Generic.List[object]]::new()
    $branches = if ($null -ne $Workflow.PSObject.Properties['branches']) {
        @($Workflow.branches)
    } else { @() }
    foreach ($branch in $branches) {
        $sourceId = [string]$branch.source_id
        $destinationId = [string]$branch.destination_id
        if (-not $idToLabel.ContainsKey($sourceId) -or
            -not $idToLabel.ContainsKey($destinationId)) {
            throw 'The Shuffle core fingerprint found a dangling Branch.'
        }
        $sourceLabel = [string]$idToLabel[$sourceId]
        $destinationLabel = [string]$idToLabel[$destinationId]
        if ($sourceLabel -ceq 'dispatch_github_containment') {
            continue
        }
        $conditions = if ($null -ne $branch.PSObject.Properties['conditions']) {
            ConvertTo-ShuffleSocCanonicalValue -Value $branch.conditions
        } else { @() }
        $normalizedBranches.Add([ordered]@{
            source=$sourceLabel
            destination=$destinationLabel
            conditions=$conditions
        })
    }
    $sortedBranches = @($normalizedBranches | Sort-Object {
        $_ | ConvertTo-Json -Depth 50 -Compress
    })
    $core = [ordered]@{
        schema_version=1
        workflow_name=[string]$Workflow.name
        sharing=[string]$Workflow.sharing
        webhook_id=$WebhookId
        required_header_name='X-SOC-Webhook-Key'
        actions=@($normalizedActions | Sort-Object label)
        branches=$sortedBranches
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(
        ($core | ConvertTo-Json -Depth 100 -Compress)
    )
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
    } finally {
        [Array]::Clear($bytes,0,$bytes.Length)
    }
}

function Assert-ShuffleSocProductionWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId
    )

    [void](Assert-ShuffleSocWorkflow -Workflow $Workflow `
        -WorkflowId $WorkflowId -WebhookId $WebhookId)
    foreach ($label in $script:ProductionActionLabels) {
        if (@($Workflow.actions | Where-Object { [string]$_.label -ceq $label }).Count -ne 1) {
            throw "The Production Workflow Action label is absent or duplicated: $label"
        }
    }

    $dispatch = @($Workflow.actions | Where-Object {
        [string]$_.label -ceq 'dispatch_github_containment'
    })[0]
    if ([string]$dispatch.app_name -cne $script:DispatcherAppName -or
        [string]$dispatch.app_version -cne $script:DispatcherAppVersion -or
        [string]$dispatch.name -cne 'dispatch_containment') {
        throw 'Production dispatch must use the fixed private SOC GitHub Dispatcher App.'
    }

    $external = @($Workflow.actions | Where-Object {
        [string]$_.app_name -match '(?i)^(github|http)$' -or
        [string]$_.app_name -ceq $script:DispatcherAppName
    })
    $externalLabels = (@($external.label | Sort-Object) -join ',')
    if ($external.Count -ne 1 -or $externalLabels -cne 'dispatch_github_containment') {
        throw 'Production contains an extra GitHub, HTTP, or SOC Dispatcher Action.'
    }
    $dispatchAuth = if ($null -ne $dispatch.PSObject.Properties['authentication_id']) {
        [string]$dispatch.authentication_id
    } else { '' }
    if ([string]::IsNullOrWhiteSpace($dispatchAuth) -or
        $dispatchAuth -match '(?i)(?:github_pat_|gh[pousr]_[A-Za-z0-9]{20,})') {
        throw 'Production GitHub dispatch lacks a safe Shuffle Authentication reference.'
    }

    $configurationParameters = @($dispatch.parameters | Where-Object {
        $null -ne $_.PSObject.Properties['configuration'] -and
        [bool]$_.configuration -eq $true
    })
    if ($configurationParameters.Count -gt 1 -or
        ($configurationParameters.Count -eq 1 -and
         [string]$configurationParameters[0].name -cne 'github_token')) {
        throw 'Production dispatch contains an unexpected encrypted configuration parameter.'
    }
    $literalConfiguration = if ($configurationParameters.Count -eq 1 -and
        $null -ne $configurationParameters[0].PSObject.Properties['value']) {
        [string]$configurationParameters[0].value
    } else { '' }
    if ($literalConfiguration -match '(?i)(?:github_pat_|gh[pousr]_[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9_-]{20,})') {
        throw 'Production Workflow export contains a literal GitHub credential.'
    }
    $allParameterText = @($Workflow.actions | ForEach-Object {
        @($_.parameters | ForEach-Object { [string]$_.value }) -join "`n"
    }) -join "`n"
    if ($allParameterText -match '(?i)(?:github_pat_|gh[pousr]_[A-Za-z0-9]{20,}|Authorization\s*:\s*Bearer\s+[A-Za-z0-9_-]{20,})') {
        throw 'Production Workflow export contains a literal GitHub credential.'
    }

    $regularParameters = @($dispatch.parameters | Where-Object {
        $null -eq $_.PSObject.Properties['configuration'] -or
        [bool]$_.configuration -ne $true
    })
    $regularAction = [pscustomobject]@{
        label='dispatch_github_containment';parameters=$regularParameters
    }
    $dispatchParameters = Get-ShuffleActionParameterMap -Action $regularAction
    if ((@($dispatchParameters.Keys | Sort-Object) -join ',') -cne
        'alert_body_sha256,rule_id,scenario_id,take_id' -or
        $dispatchParameters.take_id -cne '$validate_payload.take_id' -or
        $dispatchParameters.scenario_id -cne '$validate_payload.scenario_id' -or
        $dispatchParameters.rule_id -cne '$validate_payload.rule_id' -or
        $dispatchParameters.alert_body_sha256 -cne '$validate_payload.body_sha256') {
        throw 'Production dispatch inputs are not the exact four-field Validator output mapping.'
    }

    $graph = Get-ShuffleSocDispatchGraph -Workflow $Workflow
    if ($graph.Incoming.Count -ne 1 -or
        [string]$graph.Incoming[0].source_id -cne
            [string]$graph.ByLabel['claim_take_dispatch'].id -or
        $null -eq $graph.Incoming[0].conditions) {
        throw 'Production dispatch lacks the single conditioned fresh-claim input Branch.'
    }
    if ($graph.Outgoing.Count -ne 2) {
        throw 'Production dispatch must have exactly one success and one failure output Branch.'
    }
    $expectedDestinations = @(
        [string]$graph.ByLabel['write_response_dispatched'].id,
        [string]$graph.ByLabel['write_response_failed'].id
    ) | Sort-Object
    $actualDestinations = @($graph.Outgoing.destination_id | ForEach-Object {
        [string]$_
    } | Sort-Object)
    if (($actualDestinations -join ',') -cne ($expectedDestinations -join ',') -or
        @($graph.Outgoing | Where-Object { $null -eq $_.conditions }).Count -ne 0) {
        throw 'Production dispatch output Branches do not target the conditioned success and failure writers.'
    }
    $conditionShapes = @($graph.Outgoing | ForEach-Object {
        (ConvertTo-ShuffleSocCanonicalValue -Value $_.conditions) |
            ConvertTo-Json -Depth 50 -Compress
    } | Sort-Object -Unique)
    if ($conditionShapes.Count -ne 2) {
        throw 'Production dispatch success and failure Branch conditions are not distinct.'
    }

    return $Workflow
}

function Assert-ShuffleSocGateB5Evidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$WorkflowId
    )

    Assert-ShuffleUuid -Value $WorkflowId -Label 'Shuffle Workflow ID'
    $gateRoot = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) 'shuffle-gate-b5'
    if (-not (Test-Path -LiteralPath $gateRoot -PathType Container)) {
        throw 'No Shuffle Gate B5 Runtime Evidence directory exists.'
    }
    $runs = @(Get-ChildItem -LiteralPath $gateRoot -Directory | Where-Object {
        $_.Name -cmatch $script:TakeIdPattern
    } | Sort-Object LastWriteTimeUtc -Descending)
    if ($runs.Count -eq 0) {
        throw 'No canonical Shuffle Gate B5 Runtime Evidence run exists.'
    }
    $run = $runs[0]
    if (Test-Path -LiteralPath (Join-Path $run.FullName '99-failure.json') -PathType Leaf) {
        throw 'The latest Shuffle Gate B5 Runtime Evidence is a failed run.'
    }
    $required = @(
        '00-workflow-export-summary.json',
        '01-concurrency-and-rejections.json',
        '02-cleanup.json',
        'manifest.json'
    )
    foreach ($name in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $run.FullName $name) -PathType Leaf)) {
            throw "The latest Shuffle Gate B5 Evidence is incomplete: $name"
        }
    }
    try {
        $workflow = Get-Content -LiteralPath (
            Join-Path $run.FullName '00-workflow-export-summary.json'
        ) -Raw | ConvertFrom-Json -Depth 40
        $runtime = Get-Content -LiteralPath (
            Join-Path $run.FullName '01-concurrency-and-rejections.json'
        ) -Raw | ConvertFrom-Json -Depth 40
        $cleanup = Get-Content -LiteralPath (
            Join-Path $run.FullName '02-cleanup.json'
        ) -Raw | ConvertFrom-Json -Depth 40
        $manifest = Get-Content -LiteralPath (
            Join-Path $run.FullName 'manifest.json'
        ) -Raw | ConvertFrom-Json -Depth 40
    } catch {
        throw 'The latest Shuffle Gate B5 Evidence is not valid JSON.'
    }
    if ([string]$workflow.workflow_id -cne $WorkflowId -or
        [string]$workflow.workflow_name -cne $script:ShuffleWorkflowName -or
        [bool]$workflow.gate_b5_stub_verified -ne $true -or
        [string]$workflow.workflow_core_sha256 -notmatch '^[a-f0-9]{64}$' -or
        [int]$workflow.real_dispatch_action_count -ne 0) {
        throw 'The Gate B5 Evidence belongs to another or unsafe Workflow.'
    }
    if ([int]$runtime.concurrent_request_count -ne 10 -or
        [int]$runtime.unique_execution_count -ne 10 -or
        [int]$runtime.new_claim_count -ne 1 -or
        [int]$runtime.duplicate_claim_count -ne 9 -or
        [int]$runtime.stub_execution_count -ne 1 -or
        [int]$runtime.duplicate_writer_count -ne 9 -or
        [int]$runtime.production_writer_count -ne 0 -or
        [int]$runtime.real_github_dispatch_count -ne 0 -or
        [bool]$runtime.webhook_invalid_header_rejected -ne $true -or
        [bool]$runtime.webhook_valid_header_accepted -ne $true) {
        throw 'The Gate B5 Runtime counters do not prove the frozen atomicity contract.'
    }
    $negative = @($runtime.negative_results)
    $expectedCases = @(
        'wrong-account','wrong-scenario','wrong-rule','wrong-take','wrong-body-hash'
    )
    if ($negative.Count -ne 5 -or
        (@($negative.case | Sort-Object -Unique) -join ',') -cne
            (($expectedCases | Sort-Object) -join ',') -or
        @($negative | Where-Object {
            [int]$_.claim_count -ne 0 -or [int]$_.stub_count -ne 0 -or
            [int]$_.github_dispatch_count -ne 0
        }).Count -ne 0) {
        throw 'The Gate B5 negative cases are missing or reached a response branch.'
    }
    $cleanupItems = @($cleanup.cleanup)
    if ($cleanupItems.Count -lt 2 -or
        @($cleanupItems | Where-Object { [bool]$_.removed -ne $true }).Count -ne 0) {
        throw 'The Gate B5 temporary Datastore keys were not fully cleaned up.'
    }
    $manifestEntries = @($manifest.files)
    foreach ($name in $required | Where-Object { $_ -ne 'manifest.json' }) {
        $entry = @($manifestEntries | Where-Object { [string]$_.file -ceq $name })
        if ($entry.Count -ne 1 -or [string]$entry[0].sha256 -notmatch '^[a-f0-9]{64}$') {
            throw "The Gate B5 manifest entry is missing or malformed: $name"
        }
        $actual = (Get-FileHash -LiteralPath (Join-Path $run.FullName $name) `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne [string]$entry[0].sha256) {
            throw "The Gate B5 Evidence hash changed: $name"
        }
    }
    return [pscustomobject]@{
        EvidenceDirectory   = $run.FullName
        TakeId              = $run.Name
        WorkflowExportSha256 = [string]$workflow.workflow_export_sha256
        WorkflowCoreSha256   = [string]$workflow.workflow_core_sha256
        CompletedAtUtc      = [string]$runtime.completed_at_utc
        ManifestSha256      = (Get-FileHash -LiteralPath (
            Join-Path $run.FullName 'manifest.json'
        ) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Assert-ShuffleSocGateB5Workflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId
    )

    [void](Assert-ShuffleSocWorkflow -Workflow $Workflow `
        -WorkflowId $WorkflowId -WebhookId $WebhookId)
    $dispatch = @($Workflow.actions | Where-Object {
        [string]$_.label -ceq 'dispatch_github_containment'
    })
    if ($dispatch.Count -ne 1 -or
        [string]$dispatch[0].app_name -cne 'Shuffle Tools' -or
        [string]$dispatch[0].app_version -cne '1.2.0' -or
        [string]$dispatch[0].name -cne 'repeat_back_to_me') {
        throw 'Gate B5 requires the fixed Shuffle Tools dispatch Stub.'
    }
    $parameterText = @($dispatch[0].parameters | ForEach-Object {
        [string]$_.value
    }) -join "`n"
    if ($parameterText -cnotmatch '(?m)^GATE_B5_GITHUB_STUB$') {
        throw 'The Gate B5 dispatch Stub marker is absent or dynamic.'
    }
    $externalDispatch = @($Workflow.actions | Where-Object {
        [string]$_.app_name -match '(?i)(github|http)' -or
        [string]$_.name -match '(?i)(workflow.?dispatch|api.?request)'
    })
    if ($externalDispatch.Count -ne 0) {
        throw 'Gate B5 contains a real external dispatch-capable Action.'
    }
    $graph = Get-ShuffleSocDispatchGraph -Workflow $Workflow
    if ($graph.Incoming.Count -ne 1 -or
        [string]$graph.Incoming[0].source_id -cne
            [string]$graph.ByLabel['claim_take_dispatch'].id -or
        $null -eq $graph.Incoming[0].conditions -or
        $graph.Outgoing.Count -ne 0) {
        throw 'Gate B5 Stub must have one conditioned fresh-claim input and no output Branch.'
    }
    return $Workflow
}

function Get-ShuffleSocWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$OrgId,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    Assert-ShuffleUuid -Value $WorkflowId -Label 'Shuffle Workflow ID'
    $workflow = Invoke-ShuffleApiRequest `
        -Method GET `
        -RelativePath "/api/v1/workflows/$WorkflowId" `
        -ApiKey $ApiKey `
        -OrgId $OrgId `
        -BaseUri $BaseUri
    return Assert-ShuffleSocWorkflow `
        -Workflow $workflow `
        -WorkflowId $WorkflowId `
        -WebhookId $WebhookId
}

function Get-ShuffleSocWorkflowExecutions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$OrgId,
        [uri]$BaseUri = 'https://shuffler.io/',
        [ValidateRange(10,100)][int]$Top = 50
    )

    Assert-ShuffleUuid -Value $WorkflowId -Label 'Shuffle Workflow ID'
    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    $response = Invoke-ShuffleApiRequest -Method GET `
        -RelativePath "/api/v1/workflows/$WorkflowId/executions?top=$Top" `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri
    if ($null -ne $response.PSObject.Properties['executions']) {
        if ($null -ne $response.PSObject.Properties['success'] -and
            [bool]$response.success -ne $true) {
            throw 'Shuffle did not return the Workflow execution list.'
        }
        return @($response.executions)
    }
    if ($response -is [array] -or $response -is [Collections.IList]) {
        return @($response)
    }
    throw 'Shuffle returned an unsupported Workflow execution-list shape.'
}

function Get-ShuffleSocExecutionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutionId,
        [Parameter(Mandatory)][string]$ExecutionAuthorization,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$OrgId,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    Assert-ShuffleUuid -Value $ExecutionId -Label 'Shuffle Execution ID'
    Assert-ShuffleUuid -Value $ExecutionAuthorization -Label 'Shuffle Execution authorization'
    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    $response = Invoke-ShuffleApiRequest -Method POST `
        -RelativePath '/api/v1/streams/results' `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri `
        -Body ([ordered]@{
            execution_id = $ExecutionId
            authorization = $ExecutionAuthorization
        })
    if ([string]$response.execution_id -cne $ExecutionId) {
        throw 'Shuffle returned results for a different Execution ID.'
    }
    return $response
}

function ConvertFrom-ShuffleResultValue {
    param([AllowNull()][object]$Value)

    $current = $Value
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        if ($current -isnot [string]) { break }
        $text = ([string]$current).Trim()
        if ($text.Length -gt 1048576 -or
            (-not $text.StartsWith('{') -and -not $text.StartsWith('['))) {
            break
        }
        try {
            $current = $text | ConvertFrom-Json -Depth 100
        } catch {
            break
        }
    }
    return $current
}

function Get-ShuffleSocExecutionSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Execution,
        [Parameter(Mandatory)][object]$Workflow
    )

    $executionId = [string]$Execution.execution_id
    Assert-ShuffleUuid -Value $executionId -Label 'Shuffle Execution ID'
    $labelsById = @{}
    foreach ($action in @($Workflow.actions)) {
        if ([string]$action.id -and [string]$action.label) {
            $labelsById[[string]$action.id] = [string]$action.label
        }
    }
    $actions = [Collections.Generic.List[object]]::new()
    foreach ($result in @($Execution.results)) {
        $actionId = ''
        $label = ''
        if ($null -ne $result.PSObject.Properties['action']) {
            if ($result.action -is [string]) {
                $actionId = [string]$result.action
            } elseif ($null -ne $result.action) {
                if ($null -ne $result.action.PSObject.Properties['id']) {
                    $actionId = [string]$result.action.id
                }
                if ($null -ne $result.action.PSObject.Properties['label']) {
                    $label = [string]$result.action.label
                }
            }
        }
        if (-not $actionId -and $null -ne $result.PSObject.Properties['action_id']) {
            $actionId = [string]$result.action_id
        }
        if (-not $label -and $actionId -and $labelsById.ContainsKey($actionId)) {
            $label = [string]$labelsById[$actionId]
        }
        if (-not $label -and $null -ne $result.PSObject.Properties['label']) {
            $label = [string]$result.label
        }
        if (-not $label) {
            throw "Shuffle Execution $executionId contains an unmapped Action result."
        }
        $value = if ($null -ne $result.PSObject.Properties['result']) {
            ConvertFrom-ShuffleResultValue -Value $result.result
        } else { $null }
        $status = if ($null -ne $result.PSObject.Properties['status']) {
            [string]$result.status
        } else { '' }
        $actions.Add([pscustomobject]@{
            Label    = $label
            ActionId = $actionId
            Status   = $status
            Value    = $value
        })
    }
    return [pscustomobject]@{
        ExecutionId = $executionId
        Status      = [string]$Execution.status
        StartedAt   = $Execution.started_at
        CompletedAt = $Execution.completed_at
        Actions     = @($actions)
    }
}

function Get-ShuffleSocKeysExistedClaims {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)

    $claims = [Collections.Generic.List[object]]::new()
    function Visit-ShuffleValue {
        param([AllowNull()][object]$Node,[int]$Depth)
        if ($null -eq $Node -or $Depth -gt 12) { return }
        $Node = ConvertFrom-ShuffleResultValue -Value $Node
        if ($Node -is [string] -or $Node -is [ValueType]) { return }
        if ($null -ne $Node.PSObject.Properties['keys_existed']) {
            foreach ($entry in @($Node.keys_existed)) {
                if ($null -eq $entry.PSObject.Properties['existed']) {
                    throw 'Shuffle keys_existed entry lacks the existed flag.'
                }
                if ($null -eq $entry.PSObject.Properties['key'] -or
                    [string]::IsNullOrWhiteSpace([string]$entry.key)) {
                    throw 'Shuffle keys_existed entry lacks the exact key.'
                }
                $claims.Add([pscustomobject]@{
                    Key=[string]$entry.key
                    Existed=[bool]$entry.existed
                })
            }
        }
        if ($Node -is [Collections.IDictionary]) {
            foreach ($item in $Node.Values) {
                Visit-ShuffleValue -Node $item -Depth ($Depth + 1)
            }
            return
        }
        if ($Node -is [Collections.IEnumerable]) {
            foreach ($item in $Node) {
                Visit-ShuffleValue -Node $item -Depth ($Depth + 1)
            }
            return
        }
        foreach ($property in $Node.PSObject.Properties) {
            if ($property.Name -cne 'keys_existed') {
                Visit-ShuffleValue -Node $property.Value -Depth ($Depth + 1)
            }
        }
    }
    Visit-ShuffleValue -Node $Value -Depth 0
    return @($claims)
}

function Get-ShuffleSocKeysExistedFlags {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)

    return @(Get-ShuffleSocKeysExistedClaims -Value $Value | ForEach-Object {
        [bool]$_.Existed
    })
}

function Remove-ShuffleSocCacheKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    if ($Key.Length -gt 1024 -or $Key -match '[\r\n]' -or
        $Key -notmatch '^soc:v1:(allow|response|event|outcome):[A-Za-z0-9:._/-]+$') {
        throw 'The Shuffle cache cleanup key is outside the SOC namespace.'
    }
    $response = Invoke-ShuffleApiRequest -Method POST `
        -RelativePath "/api/v1/orgs/$OrgId/delete_cache" `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri `
        -Body ([ordered]@{org_id=$OrgId;key=$Key;category=$script:ShuffleCategory})
    if ([bool]$response.success -ne $true) {
        throw 'Shuffle did not delete the bounded SOC cache key.'
    }
    return [pscustomobject]@{removed=$true;key=$Key;category=$script:ShuffleCategory}
}

function New-ShuffleSocAllowRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$TakeRecord,
        [Parameter(Mandatory)][string]$OrgId
    )

    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    if ([string]$TakeRecord.take_id -cnotmatch $script:TakeIdPattern -or
        [string]$TakeRecord.scenario_id -cne 'CAPITAL-ONE' -or
        [string]$TakeRecord.account_alias -cne 'primary-lab' -or
        [string]$TakeRecord.expected_rule_id -cne '100103' -or
        [string]$TakeRecord.response_mode -notin @('observe_only','contain') -or
        [string]$TakeRecord.status -cne 'ISSUED') {
        throw 'The Active TAKE cannot be registered in Shuffle.'
    }
    $expires = [datetimeoffset]::Parse([string]$TakeRecord.expires_at_utc)
    if ($expires -le [datetimeoffset]::UtcNow) {
        throw 'The Active TAKE expired before Shuffle registration.'
    }
    $key = "soc:v1:allow:primary-lab:CAPITAL-ONE:$($TakeRecord.take_id)"
    $value = [ordered]@{
        schema_version   = 1
        take_id          = [string]$TakeRecord.take_id
        account_alias    = 'primary-lab'
        scenario_id      = 'CAPITAL-ONE'
        expected_rule_id = '100103'
        response_mode    = [string]$TakeRecord.response_mode
        expires_at_utc   = $expires.ToUniversalTime().ToString('o')
    }
    $valueJson = $value | ConvertTo-Json -Depth 8 -Compress
    return [pscustomobject]@{
        Key      = $key
        Category = $script:ShuffleCategory
        Value    = $value
        ValueJson = $valueJson
        SetBody  = [ordered]@{
            key                   = $key
            value                 = $valueJson
            category              = $script:ShuffleCategory
            ignore_security_rules = $false
        }
        GetBody  = [ordered]@{
            org_id   = $OrgId
            key      = $key
            category = $script:ShuffleCategory
        }
    }
}

function Register-ShuffleSocTake {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$TakeRecord,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    $allow = New-ShuffleSocAllowRecord -TakeRecord $TakeRecord -OrgId $OrgId
    $set = Invoke-ShuffleApiRequest `
        -Method POST `
        -RelativePath "/api/v1/orgs/$OrgId/set_cache" `
        -ApiKey $ApiKey `
        -OrgId $OrgId `
        -Body $allow.SetBody `
        -BaseUri $BaseUri
    $keys = @($set.keys_existed)
    if ([bool]$set.success -ne $true -or
        $keys.Count -ne 1 -or
        [string]$keys[0].key -cne $allow.Key -or
        [bool]$keys[0].existed -ne $false) {
        throw 'Shuffle did not create one fresh TAKE allowlist key.'
    }
    $get = Invoke-ShuffleApiRequest `
        -Method POST `
        -RelativePath "/api/v1/orgs/$OrgId/get_cache" `
        -ApiKey $ApiKey `
        -OrgId $OrgId `
        -Body $allow.GetBody `
        -BaseUri $BaseUri
    if ([bool]$get.success -ne $true -or
        [string]$get.key -cne $allow.Key -or
        [string]$get.category -cne $allow.Category -or
        [string]$get.value -cne $allow.ValueJson) {
        throw 'Shuffle TAKE allowlist read-back did not match the exact registered value.'
    }
    return [pscustomobject]@{
        registered = $true
        verified   = $true
        key        = $allow.Key
        category   = $allow.Category
    }
}

function Remove-ShuffleSocTake {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    if ($TakeId -cnotmatch $script:TakeIdPattern) {
        throw 'The TAKE ID cannot be removed from the Shuffle allowlist.'
    }
    $key = "soc:v1:allow:primary-lab:CAPITAL-ONE:$TakeId"
    $result = Invoke-ShuffleApiRequest `
        -Method POST `
        -RelativePath "/api/v1/orgs/$OrgId/delete_cache" `
        -ApiKey $ApiKey `
        -OrgId $OrgId `
        -Body ([ordered]@{
            org_id   = $OrgId
            key      = $key
            category = $script:ShuffleCategory
        }) `
        -BaseUri $BaseUri
    if ([bool]$result.success -ne $true) {
        throw 'Shuffle did not remove the TAKE allowlist key.'
    }
    return [pscustomobject]@{
        removed  = $true
        key      = $key
        category = $script:ShuffleCategory
    }
}

function Get-ShuffleSocOutcomeKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$RawMessageSha256
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern -or
        $RawMessageSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The Shuffle outcome identity is invalid.'
    }
    return "soc:v1:outcome:${TakeId}:$RawMessageSha256"
}

function Assert-ShuffleSocOutcomeRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$RawMessageSha256
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern -or
        $RawMessageSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The expected Shuffle outcome identity is invalid.'
    }
    $requiredFields = @(
        'schema_version','take_id','raw_message_sha256','body_sha256',
        'account_alias','scenario_id','rule_id','result',
        'github_dispatch_count','workflow_run_id','completed_at_utc'
    )
    $actualFields = @($Record.PSObject.Properties.Name | Sort-Object)
    if (($actualFields -join ',') -cne (($requiredFields | Sort-Object) -join ',')) {
        throw 'The Shuffle outcome contains missing or extra fields.'
    }
    $result = [string]$Record.result
    if ([int]$Record.schema_version -ne 1 -or
        [string]$Record.take_id -cne $TakeId -or
        [string]$Record.raw_message_sha256 -cne $RawMessageSha256 -or
        [string]$Record.body_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Record.account_alias -cne 'primary-lab' -or
        [string]$Record.scenario_id -cne 'CAPITAL-ONE' -or
        [string]$Record.rule_id -cne '100103' -or
        $result -notin @(
            'REJECTED_SCHEMA','REJECTED_ALLOWLIST',
            'RESPONSE_DISPATCHED','DUPLICATE_SUPPRESSED','OBSERVE_ONLY',
            'REJECTED_TAKE','RESPONSE_FAILED'
        ) -or
        [int]$Record.github_dispatch_count -notin @(0,1)) {
        throw 'The Shuffle outcome violated the fixed result contract.'
    }
    $completed = [datetimeoffset]::Parse([string]$Record.completed_at_utc)
    if ($completed.Offset -ne [timespan]::Zero) {
        throw 'The Shuffle outcome timestamp is not UTC.'
    }
    if ($result -ceq 'RESPONSE_DISPATCHED' -and
        ([int]$Record.github_dispatch_count -ne 1 -or
         $Record.workflow_run_id -isnot [ValueType] -or
         [int64]$Record.workflow_run_id -le 0)) {
        throw 'A dispatched Shuffle outcome does not bind one positive GitHub Workflow Run ID.'
    }
    if ($result -cne 'RESPONSE_DISPATCHED' -and
        ([int]$Record.github_dispatch_count -ne 0 -or
         [int64]$Record.workflow_run_id -ne 0)) {
        throw 'A non-dispatched Shuffle outcome records a GitHub dispatch or Run ID.'
    }
    return $Record
}

function Get-ShuffleSocOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$RawMessageSha256,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/'
    )

    Assert-ShuffleUuid -Value $OrgId -Label 'Shuffle Organization ID'
    $key = Get-ShuffleSocOutcomeKey -TakeId $TakeId -RawMessageSha256 $RawMessageSha256
    $response = Invoke-ShuffleApiRequest -Method POST `
        -RelativePath "/api/v1/orgs/$OrgId/get_cache" `
        -ApiKey $ApiKey -OrgId $OrgId -BaseUri $BaseUri `
        -Body ([ordered]@{org_id=$OrgId;key=$key;category=$script:ShuffleCategory})
    if ([bool]$response.success -ne $true) {
        return $null
    }
    if ([string]$response.key -cne $key -or [string]$response.category -cne $script:ShuffleCategory) {
        throw 'Shuffle returned an outcome from the wrong key or category.'
    }
    try {
        $record = [string]$response.value | ConvertFrom-Json
    } catch {
        throw 'The Shuffle outcome value is not valid JSON.'
    }
    return Assert-ShuffleSocOutcomeRecord -Record $record -TakeId $TakeId `
        -RawMessageSha256 $RawMessageSha256
}

function Wait-ShuffleSocContainmentOutcomes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string[]]$RawMessageSha256,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/',
        [ValidateRange(30,300)][int]$TimeoutSeconds = 180
    )

    if ($RawMessageSha256.Count -ne 2 -or
        @($RawMessageSha256 | Select-Object -Unique).Count -ne 2) {
        throw 'Containment requires exactly two unique Wazuh message hashes.'
    }
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $records = [Collections.Generic.List[object]]::new()
        foreach ($hash in $RawMessageSha256) {
            $outcome = Get-ShuffleSocOutcome -TakeId $TakeId `
                -RawMessageSha256 $hash -OrgId $OrgId -ApiKey $ApiKey -BaseUri $BaseUri
            if ($null -ne $outcome) { $records.Add($outcome) }
        }
        if ($records.Count -eq 2) {
            $results = @($records | ForEach-Object { [string]$_.result })
            if (@($results | Where-Object { $_ -ceq 'RESPONSE_DISPATCHED' }).Count -ne 1 -or
                @($results | Where-Object { $_ -ceq 'DUPLICATE_SUPPRESSED' }).Count -ne 1 -or
                ($records | Measure-Object -Property github_dispatch_count -Sum).Sum -ne 1) {
                throw 'Shuffle did not produce one dispatch and one duplicate suppression.'
            }
            return @($records)
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw "Shuffle did not publish exactly two fixed outcomes in time; observed $($records.Count)."
}

function Wait-ShuffleSocObserveOnlyOutcomes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string[]]$RawMessageSha256,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [uri]$BaseUri = 'https://shuffler.io/',
        [ValidateRange(30,300)][int]$TimeoutSeconds = 180
    )

    if ($RawMessageSha256.Count -lt 1 -or $RawMessageSha256.Count -gt 10 -or
        @($RawMessageSha256 | Select-Object -Unique).Count -ne $RawMessageSha256.Count) {
        throw 'Observe-only rehearsal requires one to ten unique Wazuh message hashes.'
    }
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $records = [Collections.Generic.List[object]]::new()
        foreach ($hash in $RawMessageSha256) {
            $outcome = Get-ShuffleSocOutcome -TakeId $TakeId `
                -RawMessageSha256 $hash -OrgId $OrgId -ApiKey $ApiKey -BaseUri $BaseUri
            if ($null -ne $outcome) { $records.Add($outcome) }
        }
        if ($records.Count -eq $RawMessageSha256.Count) {
            if (@($records | Where-Object { [string]$_.result -cne 'OBSERVE_ONLY' }).Count -ne 0 -or
                ($records | Measure-Object -Property github_dispatch_count -Sum).Sum -ne 0) {
                throw 'Shuffle observe-only rehearsal produced a response or a non-observe outcome.'
            }
            return @($records)
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw "Shuffle did not publish all observe-only outcomes in time; expected $($RawMessageSha256.Count), observed $($records.Count)."
}

Export-ModuleMember -Function @(
    'Invoke-ShuffleApiRequest',
    'Assert-ShuffleSocWorkflow',
    'Assert-ShuffleSocGateB5Workflow',
    'Assert-ShuffleSocProductionWorkflow',
    'Assert-ShuffleSocGateB5Evidence',
    'Get-ShuffleSocWorkflow',
    'Get-ShuffleSocWorkflowExecutions',
    'Get-ShuffleSocExecutionResult',
    'Get-ShuffleSocExecutionSummary',
    'Get-ShuffleSocCoreContractSha256',
    'Assert-ShuffleSocAppUploadEvidence',
    'Get-ShuffleSocAppUploadEvidence',
    'Assert-ShuffleSocCloudProvenance',
    'Get-ShuffleSocCloudProvenance',
    'Get-ShuffleSocKeysExistedClaims',
    'Get-ShuffleSocKeysExistedFlags',
    'New-ShuffleSocAllowRecord',
    'Register-ShuffleSocTake',
    'Remove-ShuffleSocTake',
    'Remove-ShuffleSocCacheKey',
    'Get-ShuffleSocOutcomeKey',
    'Assert-ShuffleSocOutcomeRecord',
    'Get-ShuffleSocOutcome',
    'Wait-ShuffleSocContainmentOutcomes',
    'Wait-ShuffleSocObserveOnlyOutcomes'
)
