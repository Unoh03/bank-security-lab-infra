#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$ConfirmRun = '',
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [ValidateRange(60,300)][int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$moduleRoot = Join-Path $repositoryRoot 'automation'
Import-Module (Join-Path $moduleRoot 'SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Runtime.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Security.psm1') -Force
Import-Module (Join-Path $moduleRoot 'SocLab.Shuffle.psm1') -Force

Write-Host 'Shuffle Gate B5 preview'
Write-Host 'External writes: one ten-execution API stress, wrong/missing/valid Webhook Header smokes, bounded event-dedupe cleanup.'
Write-Host 'Safety: repeat_back_to_me is the fixed Gate B5 Stub; Containment, GitHub, Argo, and other external Actions are forbidden.'
Write-Host 'Evidence: sanitized counts, IDs, labels, hashes, and latency only; API keys, Webhook URL/Header, execution authorization, and Payload body are not persisted.'
if ($ConfirmRun -cne 'RUN SHUFFLE GATE B5') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN SHUFFLE GATE B5'."
}

function Write-GateB5AtomicJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Value)
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Value | ConvertTo-Json -Depth 40) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-GateB5Payload {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Nonce,
        [Parameter(Mandatory)][string]$Case
    )
    $scriptPath = Join-Path $repositoryRoot 'observability\shuffle\soc_gate_b5_payload.py'
    $output = @(& python -B $scriptPath --control-id $ControlId --nonce $Nonce --case $Case 2>&1)
    if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
        throw "The Gate B5 Payload generator failed for case $Case."
    }
    $json = [string]$output[0]
    if ($json.Length -gt 65536) {
        throw 'A Gate B5 Payload exceeded the fixed size limit.'
    }
    try { $value = $json | ConvertFrom-Json -Depth 100 }
    catch { throw "The Gate B5 Payload generator returned invalid JSON for case $Case." }
    foreach ($forbidden in @('full_log','source_ip','user_id','request_id','command','cookie','token','credential')) {
        if ($json -match ('(?i)"' + [regex]::Escape($forbidden) + '"')) {
            throw "The Gate B5 Payload contains a forbidden field: $forbidden"
        }
    }
    return [pscustomobject]@{Json=$json;Value=$value}
}

function Get-GateB5DedupeKey {
    param([Parameter(Mandatory)][object]$Payload)
    $account = [string]$Payload.aws_account_id
    $eventId = [string]$Payload.incident.cloudtrail_event_id
    if ($account -notmatch '^[0-9]{12}$' -or
        $eventId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') {
        throw 'The Gate B5 Dedupe identity is malformed.'
    }
    return "CAPITAL-ONE:${account}:$($eventId.ToLowerInvariant())"
}

function Assert-GateB5WorkflowContract {
    param(
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][string]$WebhookId
    )
    $allowedLabels = @(
        'validate_payload','claim_event_dedupe','classify_dedupe_claim','write_duplicate_suppressed',
        'write_observe_only','write_rejected_schema','write_rejected_allowlist',
        'write_safety_gate_blocked','repeat_back_to_me'
    )
    $forbiddenLabels = @(
        'get_take_allow','claim_take_dispatch','dispatch_github_containment',
        'write_rejected_take','write_response_dispatched','write_response_failed',
        'quarantine_fixed_dvwa','restrict_validation_prefix'
    )
    $actions = @($Workflow.actions)
    if ([string]$Workflow.triggers[0].id -cne $WebhookId) {
        throw 'Gate B5 configured Webhook identity does not match the read-back Workflow.'
    }
    $labels = @($actions | ForEach-Object { [string]$_.label })
    if ($labels.Count -ne @($labels | Sort-Object -Unique).Count -or
        ($labels | Where-Object { $_ -notin $allowedLabels }).Count -ne 0 -or
        ($forbiddenLabels | Where-Object { $_ -in $labels }).Count -ne 0 -or
        ($labels | Sort-Object) -join ',' -cne ($allowedLabels | Sort-Object) -join ',') {
        throw 'Gate B5 Workflow Action labels are not the exact side-effect-free allowlist.'
    }
    $stub = @($actions | Where-Object { [string]$_.label -ceq 'repeat_back_to_me' })
    if ($stub.Count -ne 1 -or [string]$stub[0].app_name -cne 'Shuffle Tools' -or
        [string]$stub[0].name -cne 'repeat_back_to_me') {
        throw 'Gate B5 requires exactly one Shuffle Tools/repeat_back_to_me Stub.'
    }
    $marker = @($stub[0].parameters | Where-Object {
        [string]$_.value -ceq 'GATE_B5_REPEAT_STUB'
    })
    if ($marker.Count -ne 1) {
        throw 'The Gate B5 repeat_back_to_me Stub marker is absent or dynamic.'
    }
    $external = @($actions | Where-Object {
        [string]$_.app_name -match '(?i)(github|http|argo|kubernetes|kubectl)' -or
        [string]$_.name -match '(?i)(workflow.?dispatch|api.?request|contain|quarantine|restrict|kubectl)'
    })
    if ($external.Count -ne 0) {
        throw 'Gate B5 contains a real Containment, GitHub, Argo, or HTTP Action.'
    }
    $branches = @($Workflow.branches)
    $branchIds = @($branches | ForEach-Object { [string]$_.id })
    if ($branchIds.Count -ne @($branchIds | Sort-Object -Unique).Count) {
        throw 'Gate B5 Branch IDs are duplicated.'
    }
    $branchTuples = @($branches | ForEach-Object {
        $condition = if ($null -ne $_.PSObject.Properties['conditions']) {
            $_.conditions | ConvertTo-Json -Depth 20 -Compress
        } else { '' }
        '{0}|{1}|{2}' -f [string]$_.source_id,[string]$_.destination_id,$condition
    })
    if ($branchTuples.Count -ne @($branchTuples | Sort-Object -Unique).Count) {
        throw 'Gate B5 Branch source/destination/condition tuples are duplicated.'
    }
    $validatorId = [string]@($actions | Where-Object {
        [string]$_.label -ceq 'validate_payload'
    })[0].id
    $actionIds = @($actions | ForEach-Object { [string]$_.id })
    $allowedSourceIds = @($WebhookId) + $actionIds
    if (($branches | Where-Object {
        [string]$_.source_id -notin $allowedSourceIds -or [string]$_.destination_id -notin $actionIds
    }).Count -ne 0) {
        throw 'Gate B5 Branch references an unknown Webhook or Action identity.'
    }
    $webhookToValidator = @($branches | Where-Object {
        [string]$_.source_id -ceq $WebhookId -and
        [string]$_.destination_id -ceq $validatorId
    })
    if ($webhookToValidator.Count -ne 1) {
        throw 'Gate B5 requires exactly one Webhook-to-validator Branch.'
    }
    $firstBranch = $webhookToValidator[0]
    $conditions = if ($null -ne $firstBranch.PSObject.Properties['conditions']) {
        @($firstBranch.conditions)
    } else { @() }
    $singularCondition = if ($null -ne $firstBranch.PSObject.Properties['condition']) {
        $firstBranch.condition
    } else { $null }
    if ($conditions.Count -ne 0 -or
        ($null -ne $singularCondition -and @($singularCondition.PSObject.Properties).Count -ne 0)) {
        throw 'Gate B5 Webhook-to-validator Branch must be unconditional.'
    }
    return $Workflow
}

function Get-ExecutionReferenceFromResponse {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text.Length -gt 1048576) {
        return $null
    }
    try { $value = $Text | ConvertFrom-Json -Depth 100 }
    catch { return $null }
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue($value)
    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        if ($null -eq $node) { continue }
        if ($null -ne $node.PSObject.Properties['execution_id']) {
            $executionId = [string]$node.execution_id
            $authorization = if ($null -ne $node.PSObject.Properties['authorization']) {
                [string]$node.authorization
            } else { '' }
            if ($executionId -match '^[0-9a-f-]{36}$') {
                return [pscustomobject]@{
                    ExecutionId=$executionId
                    Authorization=$authorization
                }
            }
        }
        if ($node -is [Collections.IDictionary]) {
            foreach ($item in $node.Values) { if ($null -ne $item) { $queue.Enqueue($item) } }
        } elseif ($node -is [Collections.IEnumerable] -and $node -isnot [string]) {
            foreach ($item in $node) { if ($null -ne $item) { $queue.Enqueue($item) } }
        } else {
            foreach ($property in $node.PSObject.Properties) {
                if ($null -ne $property.Value -and $property.Value -isnot [string]) {
                    $queue.Enqueue($property.Value)
                }
            }
        }
    }
    return $null
}

function Send-GateB5WebhookBatch {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][uri]$WebhookUri,
        [Parameter(Mandatory)][AllowEmptyString()][string]$HeaderKey,
        [Parameter(Mandatory)][string]$PayloadJson,
        [Parameter(Mandatory)][ValidateRange(1,10)][int]$Count,
        [switch]$IncludeHeader,
        [bool]$ExpectedSuccess = $true
    )
    if (-not $PSCmdlet.ShouldProcess($WebhookUri.AbsoluteUri, 'POST Gate B5 Webhook batch')) {
        return [pscustomobject]@{
            WhatIf=$true
            HeaderKeyBound=$true
            HeaderIncluded=[bool]$IncludeHeader
            Count=$Count
        }
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds(30)
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($PayloadJson)
    $requests = [Collections.Generic.List[Net.Http.HttpRequestMessage]]::new()
    $tasks = [Collections.Generic.List[System.Threading.Tasks.Task[Net.Http.HttpResponseMessage]]]::new()
    try {
        for ($index = 0; $index -lt $Count; $index++) {
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $WebhookUri)
            $content = [Net.Http.ByteArrayContent]::new($payloadBytes)
            $content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
            $request.Content = $content
            if ($IncludeHeader) {
                [void]$request.Headers.TryAddWithoutValidation('X-SOC-Webhook-Key', $HeaderKey)
            }
            $requests.Add($request)
            $tasks.Add($client.SendAsync($request))
        }
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks.ToArray())
        $responses = [Collections.Generic.List[object]]::new()
        foreach ($task in $tasks) {
            $response = $task.GetAwaiter().GetResult()
            try {
                $statusCode = [int]$response.StatusCode
                $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $succeeded = $statusCode -ge 200 -and $statusCode -lt 300
                if ($succeeded -ne $ExpectedSuccess) {
                    throw "Shuffle Webhook Header smoke returned an unexpected HTTP class: $statusCode."
                }
                $responses.Add([pscustomobject]@{
                    StatusCode=$statusCode
                    Reference=(Get-ExecutionReferenceFromResponse -Text $text)
                })
            } finally {
                $response.Dispose()
            }
        }
        return @($responses)
    } finally {
        foreach ($request in $requests) { $request.Dispose() }
        [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
        $client.Dispose()
        $handler.Dispose()
    }
}

function Send-GateB5ExecuteBatch {
    param(
        [Parameter(Mandatory)][uri]$ApiBaseUri,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$OrgId,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$PayloadJson,
        [Parameter(Mandatory)][ValidateRange(1,10)][int]$Count
    )
    if ($ApiBaseUri.Scheme -cne 'https' -or
        ($ApiBaseUri.Host -cne 'shuffler.io' -and -not $ApiBaseUri.Host.EndsWith('.shuffler.io')) -or
        $ApiBaseUri.UserInfo -or $ApiBaseUri.Query -or $ApiBaseUri.Fragment -or
        $WorkflowId -notmatch '^[0-9a-f-]{36}$' -or $OrgId -notmatch '^[0-9a-f-]{36}$') {
        throw 'The Gate B5 Execute API target violates the Shuffle allowlist.'
    }
    $uri = [uri]::new($ApiBaseUri, "/api/v1/workflows/$WorkflowId/execute")
    $outerJson = [ordered]@{execution_argument=$PayloadJson;start=''} |
        ConvertTo-Json -Depth 8 -Compress
    $outerBytes = [Text.Encoding]::UTF8.GetBytes($outerJson)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds(30)
    $requests = [Collections.Generic.List[Net.Http.HttpRequestMessage]]::new()
    $tasks = [Collections.Generic.List[System.Threading.Tasks.Task[Net.Http.HttpResponseMessage]]]::new()
    try {
        for ($index = 0; $index -lt $Count; $index++) {
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $uri)
            $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $ApiKey)
            [void]$request.Headers.TryAddWithoutValidation('Org-Id', $OrgId)
            $content = [Net.Http.ByteArrayContent]::new($outerBytes)
            $content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
            $request.Content = $content
            $requests.Add($request)
            $tasks.Add($client.SendAsync($request))
        }
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks.ToArray())
        $references = [Collections.Generic.List[object]]::new()
        foreach ($task in $tasks) {
            $response = $task.GetAwaiter().GetResult()
            try {
                $statusCode = [int]$response.StatusCode
                $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ($statusCode -lt 200 -or $statusCode -ge 300) {
                    throw "Shuffle Execute API failed during Gate B5: HTTP $statusCode."
                }
                $reference = Get-ExecutionReferenceFromResponse -Text $text
                if ($null -eq $reference -or
                    [string]$reference.ExecutionId -notmatch '^[0-9a-f-]{36}$' -or
                    [string]$reference.Authorization -notmatch '^[0-9a-f-]{36}$') {
                    throw 'Shuffle Execute API did not return the documented Execution ID and authorization.'
                }
                $references.Add($reference)
            } finally {
                $response.Dispose()
            }
        }
        return @($references)
    } finally {
        foreach ($request in $requests) { $request.Dispose() }
        [Array]::Clear($outerBytes, 0, $outerBytes.Length)
        $client.Dispose()
        $handler.Dispose()
    }
}

function Wait-GateB5ExecutionIds {
    param(
        [Parameter(Mandatory)][object[]]$WebhookResponses,
        [Parameter(Mandatory)][string[]]$BeforeIds,
        [Parameter(Mandatory)][string]$PayloadJson,
        [Parameter(Mandatory)][int]$ExpectedCount,
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][datetimeoffset]$Deadline
    )
    $references = @($WebhookResponses.Reference | Where-Object { $null -ne $_ })
    $responseIds = @($references.ExecutionId | Sort-Object -Unique)
    if ($responseIds.Count -eq $ExpectedCount) { return $references }

    $beforeSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $BeforeIds) { [void]$beforeSet.Add($id) }
    do {
        $executions = @(Get-ShuffleSocWorkflowExecutions `
            -WorkflowId ([string]$Configuration.shuffle_workflow_id) `
            -ApiKey $ApiKey -OrgId ([string]$Configuration.shuffle_org_id) `
            -BaseUri ([uri][string]$Configuration.shuffle_api_base) -Top 100)
        $matches = @($executions | Where-Object {
            $id = [string]$_.execution_id
            if (-not $id -or $beforeSet.Contains($id)) { return $false }
            if ($null -eq $_.PSObject.Properties['execution_argument']) { return $true }
            $argument = [string]$_.execution_argument
            return $argument -ceq $PayloadJson
        })
        if ($matches.Count -eq $ExpectedCount) {
            return @($matches | ForEach-Object {
                [pscustomobject]@{
                    ExecutionId=[string]$_.execution_id
                    Authorization=if ($null -ne $_.PSObject.Properties['authorization']) {
                        [string]$_.authorization
                    } else { '' }
                }
            })
        }
        if ($matches.Count -gt $ExpectedCount) {
            throw 'Shuffle produced more matching Gate B5 Executions than requests.'
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $Deadline)
    throw "Shuffle did not expose $ExpectedCount matching Gate B5 Execution IDs in time."
}

function Wait-GateB5Execution {
    param(
        [Parameter(Mandatory)][object]$Reference,
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][object]$Workflow,
        [Parameter(Mandatory)][datetimeoffset]$Deadline
    )
    do {
        $execution = $null
        if ([string]$Reference.Authorization -match '^[0-9a-f-]{36}$') {
            $execution = Get-ShuffleSocExecutionResult `
                -ExecutionId ([string]$Reference.ExecutionId) `
                -ExecutionAuthorization ([string]$Reference.Authorization) `
                -ApiKey $ApiKey -OrgId ([string]$Configuration.shuffle_org_id) `
                -BaseUri ([uri][string]$Configuration.shuffle_api_base)
        } else {
            $execution = @(Get-ShuffleSocWorkflowExecutions `
                -WorkflowId ([string]$Configuration.shuffle_workflow_id) `
                -ApiKey $ApiKey -OrgId ([string]$Configuration.shuffle_org_id) `
                -BaseUri ([uri][string]$Configuration.shuffle_api_base) -Top 100 | Where-Object {
                    [string]$_.execution_id -ceq [string]$Reference.ExecutionId
                }) | Select-Object -First 1
        }
        if ($null -ne $execution) {
            $status = [string]$execution.status
            if ($status -in @('ABORTED','FAILED','FAILURE')) {
                throw "Shuffle Gate B5 Execution failed: $($Reference.ExecutionId) status=$status"
            }
            if ($status -in @('FINISHED','SUCCESS','COMPLETED')) {
                return Get-ShuffleSocExecutionSummary -Execution $execution -Workflow $Workflow
            }
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $Deadline)
    throw "Shuffle Gate B5 Execution did not finish in time: $($Reference.ExecutionId)"
}

function Get-ActionCount {
    param([Parameter(Mandatory)][object[]]$Summaries,[Parameter(Mandatory)][string]$Label)
    return @($Summaries | ForEach-Object { @($_.Actions) } | Where-Object {
        [string]$_.Label -ceq $Label -and [string]$_.Status -notin @('SKIPPED','ABORTED')
    }).Count
}

function Get-GateB5DedupeClassifierResult {
    param([Parameter(Mandatory)][object]$Action)
    $value = $Action.Value
    if ($value -is [string]) {
        $text = ([string]$value).Trim()
        if ($text.Length -gt 65536 -or
            (-not $text.StartsWith('{') -or -not $text.EndsWith('}'))) {
            throw 'The Dedupe Classifier returned an invalid scalar result.'
        }
        try { $value = $text | ConvertFrom-Json -Depth 10 }
        catch { throw 'The Dedupe Classifier returned invalid JSON.' }
    }
    if ($null -eq $value -or
        (@($value.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'existed,reason_code,valid' -or
        $value.valid -isnot [bool] -or $value.existed -isnot [bool] -or
        [string]$value.reason_code -cne '') {
        throw 'The Dedupe Classifier returned a malformed or non-success result.'
    }
    return $value
}

function Get-GateB5ExecutionIds {
    param([Parameter(Mandatory)][object]$Configuration,[Parameter(Mandatory)][string]$ApiKey)
    return @(
        Get-ShuffleSocWorkflowExecutions `
            -WorkflowId ([string]$Configuration.shuffle_workflow_id) `
            -ApiKey $ApiKey -OrgId ([string]$Configuration.shuffle_org_id) `
            -BaseUri ([uri][string]$Configuration.shuffle_api_base) -Top 100 |
            ForEach-Object { [string]$_.execution_id } |
            Where-Object { $_ -match '^[0-9a-f-]{36}$' }
    )
}

function Assert-GateB5NoNewExecution {
    param(
        [Parameter(Mandatory)][string[]]$BeforeIds,
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][datetimeoffset]$Deadline
    )
    $before = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $BeforeIds) { [void]$before.Add($id) }
    $observedNew = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    do {
        foreach ($id in @(Get-GateB5ExecutionIds -Configuration $Configuration -ApiKey $ApiKey |
            Where-Object { -not $before.Contains($_) })) {
            [void]$observedNew.Add([string]$id)
        }
        Start-Sleep -Seconds 2
    } while ([datetimeoffset]::UtcNow -lt $Deadline)
    # Always perform a final bounded query after the observation window.  A
    # transiently empty list is not proof that the rejected request made no
    # Execution.
    foreach ($id in @(Get-GateB5ExecutionIds -Configuration $Configuration -ApiKey $ApiKey |
        Where-Object { -not $before.Contains($_) })) {
        [void]$observedNew.Add([string]$id)
    }
    if ($observedNew.Count -ne 0) {
        throw 'A rejected Gate B5 Webhook Header created a Shuffle Execution.'
    }
}

function Get-GateB5ExternalActionCount {
    param([Parameter(Mandatory)][object[]]$Summaries)
    return @($Summaries | ForEach-Object { @($_.Actions) } | Where-Object {
        $appName = if ($null -ne $_.PSObject.Properties['AppName']) {
            [string]$_.AppName
        } else { '' }
        $name = if ($null -ne $_.PSObject.Properties['Name']) {
            [string]$_.Name
        } else { '' }
        [string]$_.Label -in @(
            'get_take_allow','claim_take_dispatch','dispatch_github_containment',
            'quarantine_fixed_dvwa','restrict_validation_prefix','write_response_dispatched'
        ) -or
        $appName -match '(?i)(github|http|argo|kubernetes|kubectl)' -or
        $name -match '(?i)(workflow.?dispatch|api.?request|contain|quarantine|restrict|kubectl)'
    }).Count
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

$configuration = $null
$apiKey = $null
$webhookUrl = $null
$headerKey = $null
$runId = $null
$evidenceDirectory = $null
$dedupeKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$cleanup = [Collections.Generic.List[object]]::new()
$failure = $null
$failureStage = 'preflight'
$failureCategory = 'contract'
try {
    $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
    $apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $SecretRoot
    $webhookUrl = Unprotect-SocSecret -Name 'shuffle_webhook_url' -SecretRoot $SecretRoot
    $headerKey = Unprotect-SocSecret -Name 'shuffle_webhook_header_key' -SecretRoot $SecretRoot
    if ($headerKey -notmatch '^[A-Za-z0-9.*+?-]{24,128}$') {
        throw 'The protected Shuffle Webhook Header value is invalid.'
    }
    $webhookUri = [uri]$webhookUrl
    if ($webhookUri.Scheme -cne 'https' -or
        ($webhookUri.Host -cne 'shuffler.io' -and -not $webhookUri.Host.EndsWith('.shuffler.io')) -or
        $webhookUri.Query -or $webhookUri.Fragment -or
        $webhookUri.AbsolutePath -notmatch [regex]::Escape([string]$configuration.shuffle_webhook_id)) {
        throw 'The protected Shuffle Webhook URL violates the configured HTTPS allowlist.'
    }

    $failureStage = 'workflow_readback'
    $failureCategory = 'contract'
    $workflow = Get-ShuffleSocWorkflowV2 `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -WebhookId ([string]$configuration.shuffle_webhook_id) `
        -ApiKey $apiKey -OrgId ([string]$configuration.shuffle_org_id) `
        -BaseUri ([uri][string]$configuration.shuffle_api_base)
    [void](Assert-GateB5WorkflowContract -Workflow $workflow `
        -WebhookId ([string]$configuration.shuffle_webhook_id))

    $runId = [guid]::NewGuid().ToString()
    $failureStage = 'evidence_setup'
    $failureCategory = 'evidence'

    if (-not $EvidenceRoot) {
        if (-not $env:USERPROFILE) { throw 'USERPROFILE is unavailable for Gate B5 Evidence.' }
        $EvidenceRoot = Join-Path $env:USERPROFILE 'Documents\aws-topology-evidence'
    }
    $resolvedEvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
    $resolvedLeaf = Split-Path -Leaf $resolvedEvidenceRoot
    $resolvedParent = Split-Path -Parent $resolvedEvidenceRoot
    $containmentBundleRoot = if ($resolvedLeaf -ieq 'GT05-06 containment') {
        $resolvedEvidenceRoot
    } elseif ($resolvedLeaf -ieq 'gate-b5' -and
        (Split-Path -Leaf $resolvedParent) -ieq 'GT05-06 containment') {
        $resolvedParent
    } else {
        Join-Path $resolvedEvidenceRoot 'GT05-06 containment'
    }
    $evidenceDirectory = Join-Path $containmentBundleRoot "gate-b5\$runId"
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

    $workflowBytes = [Text.Encoding]::UTF8.GetBytes(($workflow | ConvertTo-Json -Depth 100 -Compress))
    try { $workflowHash = Get-Sha256Hex -Bytes $workflowBytes }
    finally { [Array]::Clear($workflowBytes, 0, $workflowBytes.Length) }
    $actionSummary = @($workflow.actions | ForEach-Object {
        [ordered]@{label=[string]$_.label;app_name=[string]$_.app_name;name=[string]$_.name}
    })
    $workflowCoreHash = Get-ShuffleSocV2CoreContractSha256 -Workflow $workflow `
        -WebhookId ([string]$configuration.shuffle_webhook_id)
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '00-workflow-export-summary.json') -Value ([ordered]@{
        schema_version=2;bundle_name='GT05-06 containment';bundle_section='gate-b5';
        bundle_section_path="gate-b5/$runId";
        workflow_id=[string]$workflow.id;workflow_name=[string]$workflow.name;
        sharing=[string]$workflow.sharing;workflow_export_sha256=$workflowHash;
        workflow_core_sha256=$workflowCoreHash;
        webhook_id=[string]$configuration.shuffle_webhook_id;webhook_authentication_configured=$true;
        action_count=$actionSummary.Count;actions=$actionSummary;branch_count=@($workflow.branches).Count;
        gate_b5_stub_verified=$true;stub_label='repeat_back_to_me';
        external_action_count=0;real_github_dispatch_count=0
    })

    $negativeResults = [Collections.Generic.List[object]]::new()
    $failureStage = 'webhook_ingress'
    $failureCategory = 'authentication'
    $invalidHeaderPayload = Get-GateB5Payload -ControlId $runId `
        -Nonce 'ingress-invalid-header' -Case valid
    $invalidHeaderBefore = @(Get-GateB5ExecutionIds -Configuration $configuration -ApiKey $apiKey)
    $wrongHeaderKey = New-SocStrongSecret -Length 32
    $invalidHeaderResponses = @(Send-GateB5WebhookBatch -WebhookUri $webhookUri `
        -HeaderKey $wrongHeaderKey -PayloadJson ([string]$invalidHeaderPayload.Json) `
        -Count 1 -IncludeHeader -ExpectedSuccess $false)
    $wrongHeaderKey = $null
    $invalidHeaderStatus = [int]$invalidHeaderResponses[0].StatusCode
    Assert-GateB5NoNewExecution -BeforeIds $invalidHeaderBefore `
        -Configuration $configuration -ApiKey $apiKey `
        -Deadline ([datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds))

    $missingHeaderBefore = @(Get-GateB5ExecutionIds -Configuration $configuration -ApiKey $apiKey)
    $missingHeaderResponses = @(Send-GateB5WebhookBatch -WebhookUri $webhookUri `
        -HeaderKey '' -PayloadJson ([string]$invalidHeaderPayload.Json) `
        -Count 1 -ExpectedSuccess $false)
    $missingHeaderStatus = [int]$missingHeaderResponses[0].StatusCode
    Assert-GateB5NoNewExecution -BeforeIds $missingHeaderBefore `
        -Configuration $configuration -ApiKey $apiKey `
        -Deadline ([datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds))

    $webhookBefore = @(Get-ShuffleSocWorkflowExecutions `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -ApiKey $apiKey -OrgId ([string]$configuration.shuffle_org_id) `
        -BaseUri ([uri][string]$configuration.shuffle_api_base) -Top 100)
    $webhookPayload = Get-GateB5Payload -ControlId $runId `
        -Nonce 'ingress-valid-header' -Case valid
    $webhookStarted = [datetimeoffset]::UtcNow
    $webhookResponses = @(Send-GateB5WebhookBatch -WebhookUri $webhookUri `
        -HeaderKey $headerKey -PayloadJson ([string]$webhookPayload.Json) `
        -Count 1 -IncludeHeader -ExpectedSuccess $true)
    $webhookDeadline = $webhookStarted.AddSeconds($TimeoutSeconds)
    $webhookReference = @(Wait-GateB5ExecutionIds `
        -WebhookResponses $webhookResponses -BeforeIds @($webhookBefore.execution_id) `
        -PayloadJson ([string]$webhookPayload.Json) -ExpectedCount 1 `
        -Configuration $configuration -ApiKey $apiKey -Deadline $webhookDeadline)[0]
    $webhookSummary = Wait-GateB5Execution -Reference $webhookReference `
        -Configuration $configuration -ApiKey $apiKey -Workflow $workflow `
        -Deadline $webhookDeadline
    if ((Get-ActionCount -Summaries @($webhookSummary) -Label 'repeat_back_to_me') -ne 1 -or
        (Get-GateB5ExternalActionCount -Summaries @($webhookSummary)) -ne 0) {
        throw 'The valid Webhook Header smoke did not reach exactly one repeat_back_to_me Stub.'
    }
    [void]$dedupeKeys.Add((Get-GateB5DedupeKey -Payload $webhookPayload.Value))
    $negativeResults.Add([ordered]@{
        case='webhook-valid-header';transport='webhook';execution_id=[string]$webhookSummary.ExecutionId;
        result_label='repeat_back_to_me';claim_count=1;stub_count=1;external_action_count=0
    })

    $failureStage = 'atomicity_stress'
    $failureCategory = 'dedupe'
    $valid = Get-GateB5Payload -ControlId $runId -Nonce 'same-exact-body' -Case valid
    $validBytes = [Text.Encoding]::UTF8.GetBytes([string]$valid.Json)
    try { $payloadHash = Get-Sha256Hex -Bytes $validBytes }
    finally { [Array]::Clear($validBytes, 0, $validBytes.Length) }
    $batchStarted = [datetimeoffset]::UtcNow
    $references = @(Send-GateB5ExecuteBatch `
        -ApiBaseUri ([uri][string]$configuration.shuffle_api_base) `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
        -PayloadJson ([string]$valid.Json) -Count 10)
    $deadline = $batchStarted.AddSeconds($TimeoutSeconds)
    if (@($references.ExecutionId | Sort-Object -Unique).Count -ne 10) {
        throw 'The concurrent Gate B5 batch did not produce ten unique Execution IDs.'
    }
    $summaries = @($references | ForEach-Object {
        Wait-GateB5Execution -Reference $_ -Configuration $configuration `
            -ApiKey $apiKey -Workflow $workflow -Deadline $deadline
    })
    $expectedDedupeKey = Get-GateB5DedupeKey -Payload $valid.Value
    $claims = @($summaries | ForEach-Object {
        $claim = @($_.Actions | Where-Object { [string]$_.Label -ceq 'claim_event_dedupe' })
        if ($claim.Count -ne 1) { throw 'A concurrent Execution did not run exactly one Dedupe Claim.' }
        $observed = @(Get-ShuffleSocKeysExistedClaims -Value $claim[0].Value)
        if ($observed.Count -ne 1) { throw 'A Dedupe Claim did not expose exactly one existed flag.' }
        if ([string]$observed[0].Key -cne $expectedDedupeKey) {
            throw 'A Dedupe Claim keys_existed result belongs to the wrong key.'
        }
        $classifier = @($_.Actions | Where-Object {
            [string]$_.Label -ceq 'classify_dedupe_claim' -and
            [string]$_.Status -notin @('SKIPPED','ABORTED')
        })
        if ($classifier.Count -ne 1) {
            throw 'A concurrent Execution did not run exactly one Dedupe Classifier.'
        }
        $classifierResult = Get-GateB5DedupeClassifierResult -Action $classifier[0]
        if ([bool]$classifierResult.valid -ne $true -or
            [bool]$classifierResult.existed -ne [bool]$observed[0].Existed) {
            throw 'The Dedupe Classifier did not reduce the exact Datastore claim.'
        }
        [pscustomobject]@{
            Key=[string]$observed[0].Key
            Existed=[bool]$observed[0].Existed
            ClassifierValid=[bool]$classifierResult.valid
            ClassifierExisted=[bool]$classifierResult.existed
        }
    })
    $freshCount = @($claims | Where-Object { [bool]$_.Existed -eq $false }).Count
    $duplicateCount = @($claims | Where-Object { [bool]$_.Existed -eq $true }).Count
    $classifierValidCount = @($claims | Where-Object { [bool]$_.ClassifierValid -eq $true }).Count
    $classifierFreshCount = @($claims | Where-Object { [bool]$_.ClassifierExisted -eq $false }).Count
    $classifierDuplicateCount = @($claims | Where-Object { [bool]$_.ClassifierExisted -eq $true }).Count
    $stubCount = Get-ActionCount -Summaries $summaries -Label 'repeat_back_to_me'
    $duplicateWriterCount = Get-ActionCount -Summaries $summaries -Label 'write_duplicate_suppressed'
    $externalActionCount = Get-GateB5ExternalActionCount -Summaries $summaries
    [void]$dedupeKeys.Add($expectedDedupeKey)
    if ($freshCount -ne 1 -or $duplicateCount -ne 9 -or
        $classifierValidCount -ne 10 -or $classifierFreshCount -ne 1 -or
        $classifierDuplicateCount -ne 9 -or $stubCount -ne 1 -or
        $duplicateWriterCount -ne 9 -or $externalActionCount -ne 0) {
        throw 'Gate B5 atomicity failed: expected claim fresh=1 duplicate=9, classifier valid=10 fresh=1 duplicate=9, stub=1 duplicate-writer=9 external=0.'
    }

    $failureStage = 'negative_controls'
    $failureCategory = 'validation'
    $negativeExpected = [ordered]@{
        'wrong-account'='write_rejected_allowlist'
        'wrong-scenario'='write_rejected_allowlist'
        'wrong-rule'='write_rejected_allowlist'
        'wrong-role'='write_rejected_allowlist'
        'wrong-bucket'='write_rejected_allowlist'
        'wrong-key'='write_rejected_allowlist'
        'wrong-event-source'='write_rejected_allowlist'
        'wrong-event-name'='write_rejected_allowlist'
        'wrong-result'='write_rejected_allowlist'
        'wrong-body-hash'='write_rejected_schema'
    }
    foreach ($case in $negativeExpected.Keys) {
        $payload = Get-GateB5Payload -ControlId $runId -Nonce "negative-$case" -Case $case
        $caseStarted = [datetimeoffset]::UtcNow
        $caseReference = @(Send-GateB5ExecuteBatch `
            -ApiBaseUri ([uri][string]$configuration.shuffle_api_base) `
            -WorkflowId ([string]$configuration.shuffle_workflow_id) `
            -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
            -PayloadJson ([string]$payload.Json) -Count 1)[0]
        $caseDeadline = $caseStarted.AddSeconds($TimeoutSeconds)
        $caseSummary = Wait-GateB5Execution -Reference $caseReference `
            -Configuration $configuration -ApiKey $apiKey -Workflow $workflow -Deadline $caseDeadline
        $expectedLabel = [string]$negativeExpected[$case]
        if ((Get-ActionCount -Summaries @($caseSummary) -Label $expectedLabel) -ne 1 -or
            (Get-ActionCount -Summaries @($caseSummary) -Label 'claim_event_dedupe') -ne 0 -or
            (Get-ActionCount -Summaries @($caseSummary) -Label 'repeat_back_to_me') -ne 0 -or
            (Get-GateB5ExternalActionCount -Summaries @($caseSummary)) -ne 0) {
            throw "Gate B5 negative case reached the wrong branch: $case"
        }
        $negativeResults.Add([ordered]@{
            case=$case;transport='execute-api';execution_id=[string]$caseSummary.ExecutionId;
            result_label=$expectedLabel;claim_count=0;stub_count=0;external_action_count=0
        })
    }

    $completed = [datetimeoffset]::UtcNow
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '01-concurrency-and-rejections.json') -Value ([ordered]@{
        schema_version=2;run_id=$runId;payload_sha256=$payloadHash;
        stress_transport='authenticated-execute-api';concurrent_request_count=10;
        unique_execution_count=10;webhook_invalid_header_rejected=$true;
        webhook_invalid_header_status=$invalidHeaderStatus;webhook_missing_header_rejected=$true;
        webhook_missing_header_status=$missingHeaderStatus;webhook_valid_header_accepted=$true;
        execution_ids=@($summaries.ExecutionId | Sort-Object);
        cloudtrail_event_id=[string]$valid.Value.incident.cloudtrail_event_id;
        new_claim_count=$freshCount;duplicate_claim_count=$duplicateCount;
        classifier_valid_count=$classifierValidCount;
        classifier_fresh_count=$classifierFreshCount;
        classifier_duplicate_count=$classifierDuplicateCount;
        stub_execution_count=$stubCount;duplicate_writer_count=$duplicateWriterCount;
        external_action_count=$externalActionCount;real_github_dispatch_count=0;real_containment_count=0;
        negative_results=@($negativeResults);
        started_at_utc=$batchStarted.ToString('o');completed_at_utc=$completed.ToString('o');
        elapsed_ms=[math]::Round(($completed-$batchStarted).TotalMilliseconds)
    })
} catch {
    $safeExceptionType = switch ([string]$_.Exception.GetType().Name) {
        'HttpRequestException' { 'HttpRequestException'; break }
        'TaskCanceledException' { 'TaskCanceledException'; break }
        'TimeoutException' { 'TimeoutException'; break }
        'ArgumentException' { 'ArgumentException'; break }
        'InvalidOperationException' { 'InvalidOperationException'; break }
        'RuntimeException' { 'RuntimeException'; break }
        default { 'Other'; break }
    }
    if ($evidenceDirectory) {
        try {
            Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '99-failure.json') -Value ([ordered]@{
                schema_version=2;run_id=$runId;status='FAILED';
                failed_at_utc=[datetimeoffset]::UtcNow.ToString('o');
                failure_stage=$failureStage;failure_category=$failureCategory;
                exception_type=$safeExceptionType
            })
        } catch { }
    }
    $failure = [InvalidOperationException]::new(
        "Gate B5 failed at $failureStage [$failureCategory]. See sanitized failure evidence."
    )
} finally {
    if ($configuration -and $apiKey) {
        foreach ($dedupeKey in @($dedupeKeys)) {
            try {
                [void](Remove-ShuffleSocV2CacheKey `
                    -Key $dedupeKey `
                    -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
                    -BaseUri ([uri][string]$configuration.shuffle_api_base))
                $cleanup.Add([ordered]@{key_type='event_dedupe';removed=$true})
            } catch {
                $cleanup.Add([ordered]@{key_type='event_dedupe';removed=$false})
            }
        }
    }
    $apiKey = $null
    $webhookUrl = $null
    $headerKey = $null
}

if ($evidenceDirectory) {
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '02-cleanup.json') -Value ([ordered]@{
        schema_version=2;run_id=$runId;cleanup=@($cleanup)
    })
    $evidenceFiles = @(Get-ChildItem -LiteralPath $evidenceDirectory -File | Where-Object {
        $_.Name -ne 'manifest.json'
    } | Sort-Object Name)
    $manifestEntries = @($evidenceFiles | ForEach-Object {
        [ordered]@{file=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory 'manifest.json') -Value ([ordered]@{
        schema_version=2;bundle_name='GT05-06 containment';bundle_section='gate-b5';
        bundle_section_path="gate-b5/$runId";run_id=$runId;files=$manifestEntries
    })
    & (Join-Path $repositoryRoot 'tools\Test-SocSecretExposure.ps1') -EvidenceRoot $evidenceDirectory
    if ($LASTEXITCODE -ne 0) { throw 'The Gate B5 Evidence secret scan failed.' }
}

if ($failure) { throw $failure }
if (@($cleanup | Where-Object { -not [bool]$_.removed }).Count -ne 0) {
    throw 'Gate B5 passed, but one or more temporary Shuffle cache keys require manual cleanup.'
}
Write-Host "Shuffle Gate B5 passed: fresh=1 duplicate=9 repeat_back_to_me=1 external=0."
Write-Host "Sanitized Evidence: $evidenceDirectory"
