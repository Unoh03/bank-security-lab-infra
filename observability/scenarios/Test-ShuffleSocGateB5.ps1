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
Write-Host 'External writes: one temporary TAKE allow key, one ten-execution API stress, two Webhook Header smokes, four API negative cases, bounded SOC cache cleanup.'
Write-Host 'Safety: dispatch_github_containment must be the fixed Shuffle Tools Stub; any GitHub/HTTP dispatch-capable Action aborts the test.'
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
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][string]$Nonce,
        [Parameter(Mandatory)][string]$Case
    )
    $scriptPath = Join-Path $repositoryRoot 'observability\shuffle\soc_gate_b5_payload.py'
    $output = @(& python -B $scriptPath --take-id $TakeId --nonce $Nonce --case $Case 2>&1)
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
    param(
        [Parameter(Mandatory)][uri]$WebhookUri,
        [Parameter(Mandatory)][string]$HeaderKey,
        [Parameter(Mandatory)][string]$PayloadJson,
        [Parameter(Mandatory)][ValidateRange(1,10)][int]$Count,
        [bool]$ExpectedSuccess = $true
    )
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
            [void]$request.Headers.TryAddWithoutValidation('X-SOC-Webhook-Key', $HeaderKey)
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
            return ($argument -ceq $PayloadJson -or
                ($argument -match [regex]::Escape([string](($PayloadJson | ConvertFrom-Json).incident.take_id)) -and
                 $argument -match [regex]::Escape([string](($PayloadJson | ConvertFrom-Json).integrity.raw_message_sha256))))
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
$allowRegistered = $false
$takeId = $null
$evidenceDirectory = $null
$cleanup = [Collections.Generic.List[object]]::new()
$failure = $null
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

    $workflow = Get-ShuffleSocWorkflow `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -WebhookId ([string]$configuration.shuffle_webhook_id) `
        -ApiKey $apiKey -OrgId ([string]$configuration.shuffle_org_id) `
        -BaseUri ([uri][string]$configuration.shuffle_api_base)
    [void](Assert-ShuffleSocGateB5Workflow -Workflow $workflow `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -WebhookId ([string]$configuration.shuffle_webhook_id))

    $takeId = New-SocTakeId
    $take = New-SocTakeRecord -TakeId $takeId -ResponseMode contain -LifetimeMinutes 30
    [void](Register-ShuffleSocTake -TakeRecord $take `
        -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
        -BaseUri ([uri][string]$configuration.shuffle_api_base))
    $allowRegistered = $true

    if (-not $EvidenceRoot) {
        if (-not $env:USERPROFILE) { throw 'USERPROFILE is unavailable for Gate B5 Evidence.' }
        $EvidenceRoot = Join-Path $env:USERPROFILE 'Documents\aws-topology-evidence'
    }
    $evidenceDirectory = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) "shuffle-gate-b5\$takeId"
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

    $workflowBytes = [Text.Encoding]::UTF8.GetBytes(($workflow | ConvertTo-Json -Depth 100 -Compress))
    try { $workflowHash = Get-Sha256Hex -Bytes $workflowBytes }
    finally { [Array]::Clear($workflowBytes, 0, $workflowBytes.Length) }
    $actionSummary = @($workflow.actions | ForEach-Object {
        [ordered]@{label=[string]$_.label;app_name=[string]$_.app_name;name=[string]$_.name}
    })
    $workflowCoreHash = Get-ShuffleSocCoreContractSha256 -Workflow $workflow `
        -WebhookId ([string]$configuration.shuffle_webhook_id)
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '00-workflow-export-summary.json') -Value ([ordered]@{
        schema_version=1;workflow_id=[string]$workflow.id;workflow_name=[string]$workflow.name;
        sharing=[string]$workflow.sharing;workflow_export_sha256=$workflowHash;
        workflow_core_sha256=$workflowCoreHash;
        webhook_id=[string]$configuration.shuffle_webhook_id;webhook_authentication_configured=$true;
        action_count=$actionSummary.Count;actions=$actionSummary;branch_count=@($workflow.branches).Count;
        gate_b5_stub_verified=$true;real_dispatch_action_count=0
    })

    $negativeResults = [Collections.Generic.List[object]]::new()
    $invalidHeaderPayload = Get-GateB5Payload -TakeId $takeId `
        -Nonce 'ingress-invalid-header' -Case wrong-take
    $wrongHeaderKey = New-SocStrongSecret -Length 32
    $invalidHeaderResponses = @(Send-GateB5WebhookBatch -WebhookUri $webhookUri `
        -HeaderKey $wrongHeaderKey -PayloadJson ([string]$invalidHeaderPayload.Json) `
        -Count 1 -ExpectedSuccess $false)
    $wrongHeaderKey = $null
    $invalidHeaderStatus = [int]$invalidHeaderResponses[0].StatusCode

    $webhookBefore = @(Get-ShuffleSocWorkflowExecutions `
        -WorkflowId ([string]$configuration.shuffle_workflow_id) `
        -ApiKey $apiKey -OrgId ([string]$configuration.shuffle_org_id) `
        -BaseUri ([uri][string]$configuration.shuffle_api_base) -Top 100)
    $webhookPayload = Get-GateB5Payload -TakeId $takeId `
        -Nonce 'ingress-valid-header' -Case wrong-take
    $webhookStarted = [datetimeoffset]::UtcNow
    $webhookResponses = @(Send-GateB5WebhookBatch -WebhookUri $webhookUri `
        -HeaderKey $headerKey -PayloadJson ([string]$webhookPayload.Json) `
        -Count 1 -ExpectedSuccess $true)
    $webhookDeadline = $webhookStarted.AddSeconds($TimeoutSeconds)
    $webhookReference = @(Wait-GateB5ExecutionIds `
        -WebhookResponses $webhookResponses -BeforeIds @($webhookBefore.execution_id) `
        -PayloadJson ([string]$webhookPayload.Json) -ExpectedCount 1 `
        -Configuration $configuration -ApiKey $apiKey -Deadline $webhookDeadline)[0]
    $webhookSummary = Wait-GateB5Execution -Reference $webhookReference `
        -Configuration $configuration -ApiKey $apiKey -Workflow $workflow `
        -Deadline $webhookDeadline
    if ((Get-ActionCount -Summaries @($webhookSummary) -Label 'write_rejected_take') -ne 1 -or
        (Get-ActionCount -Summaries @($webhookSummary) -Label 'claim_take_dispatch') -ne 0 -or
        (Get-ActionCount -Summaries @($webhookSummary) -Label 'dispatch_github_containment') -ne 0) {
        throw 'The valid Webhook Header smoke did not reach the bounded rejected-TAKE branch.'
    }
    $negativeResults.Add([ordered]@{
        case='wrong-take';transport='webhook';execution_id=[string]$webhookSummary.ExecutionId;
        result_label='write_rejected_take';claim_count=0;stub_count=0;github_dispatch_count=0
    })

    $valid = Get-GateB5Payload -TakeId $takeId -Nonce 'same-exact-body' -Case valid
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
    $expectedDedupeKey = "soc:v1:response:primary-lab:CAPITAL-ONE:$takeId"
    $claims = @($summaries | ForEach-Object {
        $claim = @($_.Actions | Where-Object { [string]$_.Label -ceq 'claim_take_dispatch' })
        if ($claim.Count -ne 1) { throw 'A concurrent Execution did not run exactly one Dedupe Claim.' }
        $observed = @(Get-ShuffleSocKeysExistedClaims -Value $claim[0].Value)
        if ($observed.Count -ne 1) { throw 'A Dedupe Claim did not expose exactly one existed flag.' }
        if ([string]$observed[0].Key -cne $expectedDedupeKey) {
            throw 'A Dedupe Claim keys_existed result belongs to the wrong key.'
        }
        $observed[0]
    })
    $freshCount = @($claims | Where-Object { [bool]$_.Existed -eq $false }).Count
    $duplicateCount = @($claims | Where-Object { [bool]$_.Existed -eq $true }).Count
    $stubCount = Get-ActionCount -Summaries $summaries -Label 'dispatch_github_containment'
    $duplicateWriterCount = Get-ActionCount -Summaries $summaries -Label 'write_duplicate_suppressed'
    $productionWriterCount = Get-ActionCount -Summaries $summaries -Label 'write_response_dispatched'
    if ($freshCount -ne 1 -or $duplicateCount -ne 9 -or $stubCount -ne 1 -or
        $duplicateWriterCount -ne 9 -or $productionWriterCount -ne 0) {
        throw 'Gate B5 atomicity failed: expected fresh=1 duplicate=9 stub=1 duplicate-writer=9 production-writer=0.'
    }

    $negativeExpected = [ordered]@{
        'wrong-account'='write_rejected_allowlist'
        'wrong-scenario'='write_rejected_allowlist'
        'wrong-rule'='write_rejected_allowlist'
        'wrong-body-hash'='write_rejected_schema'
    }
    foreach ($case in $negativeExpected.Keys) {
        $payload = Get-GateB5Payload -TakeId $takeId -Nonce "negative-$case" -Case $case
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
            (Get-ActionCount -Summaries @($caseSummary) -Label 'claim_take_dispatch') -ne 0 -or
            (Get-ActionCount -Summaries @($caseSummary) -Label 'dispatch_github_containment') -ne 0) {
            throw "Gate B5 negative case reached the wrong branch: $case"
        }
        $negativeResults.Add([ordered]@{
            case=$case;transport='execute-api';execution_id=[string]$caseSummary.ExecutionId;
            result_label=$expectedLabel;claim_count=0;stub_count=0;github_dispatch_count=0
        })
    }

    $completed = [datetimeoffset]::UtcNow
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '01-concurrency-and-rejections.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;payload_sha256=$payloadHash;
        stress_transport='authenticated-execute-api';concurrent_request_count=10;
        unique_execution_count=10;webhook_invalid_header_rejected=$true;
        webhook_invalid_header_status=$invalidHeaderStatus;webhook_valid_header_accepted=$true;
        execution_ids=@($summaries.ExecutionId | Sort-Object);
        new_claim_count=$freshCount;duplicate_claim_count=$duplicateCount;
        stub_execution_count=$stubCount;duplicate_writer_count=$duplicateWriterCount;
        production_writer_count=$productionWriterCount;real_github_dispatch_count=0;
        negative_results=@($negativeResults);
        started_at_utc=$batchStarted.ToString('o');completed_at_utc=$completed.ToString('o');
        elapsed_ms=[math]::Round(($completed-$batchStarted).TotalMilliseconds)
    })
} catch {
    $failure = $_
    if ($evidenceDirectory) {
        Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '99-failure.json') -Value ([ordered]@{
            schema_version=1;take_id=$takeId;status='FAILED';
            failed_at_utc=[datetimeoffset]::UtcNow.ToString('o');
            error_type=$_.Exception.GetType().Name;
            error_message=[string]$_.Exception.Message
        })
    }
} finally {
    if ($allowRegistered -and $configuration -and $apiKey -and $takeId) {
        try {
            [void](Remove-ShuffleSocTake -TakeId $takeId `
                -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
                -BaseUri ([uri][string]$configuration.shuffle_api_base))
            $cleanup.Add([ordered]@{key_type='allow';removed=$true})
        } catch { $cleanup.Add([ordered]@{key_type='allow';removed=$false}) }
        try {
            [void](Remove-ShuffleSocCacheKey `
                -Key "soc:v1:response:primary-lab:CAPITAL-ONE:$takeId" `
                -OrgId ([string]$configuration.shuffle_org_id) -ApiKey $apiKey `
                -BaseUri ([uri][string]$configuration.shuffle_api_base))
            $cleanup.Add([ordered]@{key_type='dedupe';removed=$true})
        } catch { $cleanup.Add([ordered]@{key_type='dedupe';removed=$false}) }
    }
    $apiKey = $null
    $webhookUrl = $null
    $headerKey = $null
}

if ($evidenceDirectory) {
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory '02-cleanup.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;cleanup=@($cleanup)
    })
    $evidenceFiles = @(Get-ChildItem -LiteralPath $evidenceDirectory -File | Where-Object {
        $_.Name -ne 'manifest.json'
    } | Sort-Object Name)
    $manifestEntries = @($evidenceFiles | ForEach-Object {
        [ordered]@{file=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    Write-GateB5AtomicJson -Path (Join-Path $evidenceDirectory 'manifest.json') -Value ([ordered]@{
        schema_version=1;take_id=$takeId;files=$manifestEntries
    })
    & (Join-Path $repositoryRoot 'tools\Test-SocSecretExposure.ps1') -EvidenceRoot $evidenceDirectory
    if ($LASTEXITCODE -ne 0) { throw 'The Gate B5 Evidence secret scan failed.' }
}

if ($failure) { throw $failure }
if (@($cleanup | Where-Object { -not [bool]$_.removed }).Count -ne 0) {
    throw 'Gate B5 passed, but one or more temporary Shuffle cache keys require manual cleanup.'
}
Write-Host "Shuffle Gate B5 passed: TAKE=$takeId fresh=1 duplicate=9 stub=1 GitHub=0."
Write-Host "Sanitized Evidence: $evidenceDirectory"
