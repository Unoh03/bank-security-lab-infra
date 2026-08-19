#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Read-RequiredFile {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Wazuh Push artifact is missing: $RelativePath"
    }
    return Get-Content -LiteralPath $path -Raw
}

function Assert-Match {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

function Assert-NotMatch {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Text -match $Pattern) {
        throw $Message
    }
}

$main = Read-RequiredFile 'foundation\main.tf'
$variables = Read-RequiredFile 'foundation\variables.tf'
$push = Read-RequiredFile 'foundation\wazuh-push.tf'
$reader = Read-RequiredFile 'foundation\wazuh.tf'
$outputs = Read-RequiredFile 'foundation\outputs.tf'
$setup = Read-RequiredFile 'setup-foundation.ps1'
$forwarder = Read-RequiredFile 'foundation\lambda\wazuh_push_forwarder.py'
$bridge = Read-RequiredFile 'tools\Start-WazuhPushShadowBridge.ps1'
$validation = Read-RequiredFile 'observability\wazuh\Invoke-WazuhPushValidation.ps1'

Assert-Match $main 'archive\s*=\s*\{[\s\S]*?source\s*=\s*"hashicorp/archive"' `
    'Foundation does not declare the Archive provider used for the Lambda package.'
Assert-Match $variables 'variable\s+"enable_wazuh_push_transport"[\s\S]*?default\s*=\s*false' `
    'The Wazuh Push transport must be disabled by default.'
Assert-Match $push 'check\s+"wazuh_push_requires_reader"[\s\S]*?!var\.enable_wazuh_push_transport\s*\|\|\s*var\.enable_wazuh_log_reader' `
    'Push must fail closed when no explicit local Reader Role exists.'

foreach ($queueName in @('wazuh_push_primary', 'wazuh_push_primary_dlq')) {
    Assert-Match $push "resource\s+`"aws_sqs_queue`"\s+`"$queueName`"[\s\S]*?count\s*=\s*var\.enable_wazuh_push_transport" `
        "The default-off queue is missing: $queueName"
}
Assert-Match $push 'message_retention_seconds\s*=\s*local\.wazuh_push_queue_retention_seconds' `
    'The Primary queue retention is not explicit.'
Assert-Match $push 'receive_wait_time_seconds\s*=\s*20' `
    'The Primary queue does not use 20-second long polling.'
Assert-Match $push 'sqs_managed_sse_enabled\s*=\s*true' `
    'The Push queues are not encrypted with SQS-managed encryption.'
Assert-Match $push 'redrive_policy[\s\S]*?wazuh_push_primary_dlq[\s\S]*?maxReceiveCount' `
    'The Primary queue has no bounded DLQ redrive contract.'
Assert-Match $push 'DenyInsecureTransport[\s\S]*?aws:SecureTransport[\s\S]*?false' `
    'The Primary queue lacks a deny-on-plain-transport policy.'

Assert-NotMatch $push 'reserved_concurrent_executions' `
    'The account concurrency quota is 10 and cannot reserve function concurrency while retaining the AWS-required unreserved minimum.'
Assert-Match $push 'resource\s+"aws_lambda_function"\s+"wazuh_push_primary"[\s\S]*?memory_size\s*=\s*128[\s\S]*?timeout\s*=\s*30' `
    'The Push forwarder lacks its small memory and timeout execution boundaries.'
Assert-Match $push 'EXPECTED_LOG_GROUP\s*=\s*aws_cloudwatch_log_group\.dvwa_primary\.name' `
    'The Forwarder is not pinned to the approved DVWA log group.'
Assert-Match $push 'actions\s*=\s*\["sqs:SendMessage"\][\s\S]*?aws_sqs_queue\.wazuh_push_primary' `
    'The Forwarder cannot send only to the approved Primary queue.'
Assert-NotMatch $push 'aws_lambda_function_url|FunctionUrl|apigateway|0\.0\.0\.0/0' `
    'The Push path must not expose a public Lambda or API endpoint.'

Assert-Match $push 'resource\s+"aws_cloudwatch_log_subscription_filter"\s+"wazuh_push_dvwa"[\s\S]*?log_group_name\s*=\s*aws_cloudwatch_log_group\.dvwa_primary\.name' `
    'The first Push subscription is not bound to the DVWA log group.'
Assert-Match $push 'filter_pattern\s*=\s*""' `
    'The DVWA transport must forward every event already stored in the approved log group.'
Assert-Match $push 'resource\s+"aws_lambda_permission"\s+"wazuh_push_dvwa"[\s\S]*?principal\s*=\s*"logs\.amazonaws\.com"[\s\S]*?source_account' `
    'CloudWatch Logs invocation is not restricted to the active account.'
Assert-NotMatch $push 'command\.execution|GetObject|ec2_imds' `
    'Detection conditions must remain in Wazuh Rules, not in the Push transport.'

Assert-Match $reader 'ConsumePrimaryWazuhPushQueue[\s\S]*?sqs:DeleteMessage[\s\S]*?sqs:ReceiveMessage' `
    'The explicit Reader Role cannot consume and acknowledge the Primary shadow queue.'
Assert-Match $reader 'InspectPrimaryWazuhPushDlq[\s\S]*?actions\s*=\s*\[[\s\S]*?sqs:GetQueueAttributes[\s\S]*?sqs:GetQueueUrl[\s\S]*?resources\s*=\s*\[aws_sqs_queue\.wazuh_push_primary_dlq\[0\]\.arn\]' `
    'The Reader Role cannot inspect the Primary Push DLQ without consuming it.'
Assert-NotMatch $reader 'InspectPrimaryWazuhPushDlq[\s\S]{0,300}sqs:(ReceiveMessage|DeleteMessage)' `
    'The Reader Role can consume or delete a Primary Push DLQ message.'
Assert-NotMatch $reader 'sqs:SendMessage' `
    'The local Reader Role must not be able to inject Push events.'

Assert-Match $outputs 'output\s+"wazuh_push_primary_queue_url"' `
    'The local Shadow Bridge cannot discover the Primary queue URL.'
Assert-Match $outputs 'output\s+"wazuh_push_primary_dlq_url"[\s\S]*?wazuh_push_primary_dlq\[0\]\.id' `
    'The local Shadow Bridge cannot discover the read-only Primary DLQ URL.'
Assert-Match $outputs 'output\s+"wazuh_push_transport"[\s\S]*?mode\s*=\s*"shadow"[\s\S]*?forwards_all_events\s*=\s*true' `
    'The non-sensitive Push state does not declare Shadow mode and full-source forwarding.'
Assert-Match $outputs 'payload_mode\s*=\s*"safe_allowlist"[\s\S]*?raw_message_stored\s*=\s*false' `
    'The Push output does not declare the safe allowlist and no-raw-message payload boundary.'

Assert-Match $setup '\[switch\]\$EnableWazuhPushTransport' `
    'Foundation setup does not expose the Push opt-in.'
Assert-Match $setup '-var=enable_wazuh_push_transport=\$enableWazuhPushTransportValue' `
    'Foundation setup does not pass the reviewed Push state to Terraform.'
Assert-Match $setup 'Wazuh Push transport requires -EnableWazuhLogReader' `
    'Foundation setup must reject Push without an explicit Reader Role.'
Assert-Match $setup 'ConfirmWazuhPushTransport\s+-cne\s+''ENABLE WAZUH PUSH''[\s\S]*?''apply''' `
    'The separate Push confirmation must occur before Foundation Apply.'

Assert-Match $forwarder 'for\s+log_event\s+in\s+log_events' `
    'The Lambda does not forward every CloudWatch Logs data event.'
Assert-Match $forwarder 'payload\.get\("logGroup"\)[\s\S]*?expected_log_group' `
    'The Lambda does not fail closed on an unexpected log group.'
Assert-Match $forwarder 'SAFE_PAYLOAD_FIELDS[\s\S]*?SAFE_CONTEXT_FIELDS[\s\S]*?normalized' `
    'The Lambda does not normalize DVWA events through explicit safe-field allowlists.'
Assert-NotMatch $forwarder 'return\s+\{\s*"message"\s*:\s*message\s*\}' `
    'The Lambda can persist an unstructured raw log message.'
Assert-NotMatch $forwarder 'print\(|logger\.(info|debug).*payload|command\.execution|GetObject' `
    'The Lambda logs payload data or embeds detection conditions.'

Assert-Match $bridge 'ConfirmConsume\s+-cne\s+''CONSUME WAZUH PUSH''' `
    'The Shadow Bridge can consume messages without explicit confirmation.'
Assert-Match $bridge 'FileMode\]::CreateNew' `
    'The Shadow Bridge does not use atomic event-id deduplication.'
Assert-Match $bridge "wazuh-push-live\.jsonl[\s\S]*?FileMode\]::OpenOrCreate[\s\S]*?Seek\(0, \[IO\.SeekOrigin\]::End\)" `
    'The Bridge does not maintain one stable append-only JSONL input for Wazuh.'
Assert-Match $bridge 'FileMode\]::CreateNew[\s\S]*?File\]::Move\(\$temporaryEventPath, \$eventPath\)[\s\S]*?Write-LiveEventBytes -Bytes \$bytes' `
    'The Bridge must durably commit the ledger before appending the live Wazuh record.'
Assert-Match $bridge 'temporaryEventPath[\s\S]*?Flush\(\$true\)[\s\S]*?File\]::Move\(\$temporaryEventPath, \$eventPath\)' `
    'The Bridge ledger must be flushed to a temporary file and atomically renamed.'
Assert-Match $bridge 'Existing Wazuh Push ledger entry is not valid JSON[\s\S]*?Get-BridgeEnvelopeIdentityHash[\s\S]*?Test-LiveFileContainsEventId[\s\S]*?Write-LiveEventBytes' `
    'The Bridge cannot validate and recover an existing ledger before queue deletion.'
Assert-Match $bridge 'wazuh-push-bridge\.lock[\s\S]*?FileShare\]::None' `
    'The Bridge does not prevent concurrent writers to its live JSONL and ledger.'
Assert-Match $bridge 'wazuh_push_primary_dlq_url' `
    'The Bridge cannot discover the Terraform-managed Primary DLQ URL.'
Assert-Match $bridge 'wazuh_log_reader_role_arn' `
    'The Bridge cannot discover the Terraform-managed Reader Role.'
Assert-Match $bridge 'arn:aws:iam::\$\{expectedAccountId\}:role/' `
    'The Bridge IAM Role regex can lose the account ID to PowerShell scoped-variable interpolation.'
Assert-Match $bridge 'arn:aws:sts::\$\{expectedAccountId\}:assumed-role/' `
    'The Bridge STS Role regex can lose the account ID to PowerShell scoped-variable interpolation.'
Assert-Match $bridge "'sts', 'assume-role'" `
    'The Bridge does not obtain a temporary Reader Role session.'
Assert-Match $bridge 'Remove-Item "Env:\$name"[\s\S]*?''sts'', ''assume-role''[\s\S]*?sessionExpiration' `
    'The Bridge cannot renew STS from the fixed Bootstrap profile without reusing its expiring session.'
Assert-Match $bridge 'sessionExpiration\.AddSeconds\(-\$sessionRefreshBeforeSeconds\)[\s\S]*?Enter-ReaderRoleSession' `
    'The Bridge does not renew the Reader session before expiration.'
Assert-Match $bridge 'AWS_ACCESS_KEY_ID[\s\S]*?finally[\s\S]*?SetEnvironmentVariable' `
    'The Bridge does not restore process-level temporary credentials.'
Assert-NotMatch $bridge '(WriteAllText|Set-Content|Add-Content)[\s\S]{0,200}(AccessKeyId|SecretAccessKey|SessionToken)' `
    'The Bridge persists an AWS credential value.'
Assert-Match $bridge 'Bridge output: durable Host spool; Wazuh localfile consumption is configured separately' `
    'The Bridge does not state the Host-spool and Wazuh-localfile responsibility boundary.'
Assert-Match $bridge 'wazuh-push-bridge-heartbeat\.json[\s\S]*?heartbeat_at_utc[\s\S]*?session_expires_at_utc[\s\S]*?queue_visible[\s\S]*?queue_not_visible[\s\S]*?dlq_visible' `
    'The Bridge heartbeat omits a required readiness field.'
Assert-Match $bridge 'File\]::Replace\(\$temporaryPath, \$HeartbeatPath, \$backupPath\)' `
    'The Bridge heartbeat does not atomically replace its previous record.'
Assert-Match $bridge "'sqs', 'get-queue-attributes'[\s\S]*?ApproximateNumberOfMessages[\s\S]*?ApproximateNumberOfMessagesNotVisible" `
    'The Bridge does not inspect bounded Primary and DLQ queue attributes.'
Assert-NotMatch $bridge "'sqs', 'get-queue-attributes'[\s\S]{0,300}'ApproximateAgeOfOldestMessage'" `
    'The Bridge requests a CloudWatch metric as an invalid SQS queue attribute.'
Assert-Match $bridge "'cloudwatch', 'get-metric-statistics'[\s\S]*?AWS/SQS[\s\S]*?ApproximateAgeOfOldestMessage" `
    'The Bridge does not query the oldest-message age from the AWS/SQS CloudWatch metric.'
Assert-Match $bridge 'dlqVisible -ne 0[\s\S]*?cannot enter READY' `
    'The Bridge can enter READY while the DLQ is non-empty.'
Assert-Match $bridge 'Get-QueueMetrics -Url \$DeadLetterUrl -UseBootstrapProfile' `
    'The Bridge cannot inspect DLQ readiness while the live Reader policy trails its source contract.'
Assert-Match $bridge 'queueNotVisible -ne 0[\s\S]*?in-flight message[\s\S]*?cannot enter READY' `
    'The Bridge can enter READY while a Primary queue message is already in flight.'
Assert-Match $bridge 'queueNotVisible -ne 0[\s\S]*?-not \$AllowStaleBacklogDrain\.IsPresent' `
    'The Bridge does not isolate its parallel in-flight exception to explicit catch-up mode.'
Assert-Match $bridge 'MaxReadyQueueAgeSeconds\s*=\s*120' `
    'The Bridge does not declare a bounded stale-queue readiness threshold.'
Assert-Match $bridge 'queueVisible -gt 0[\s\S]*?queueOldestAgeSeconds -gt \$MaxReadyQueueAgeSeconds[\s\S]*?stale messages[\s\S]*?cannot enter READY' `
    'The Bridge can enter READY while stale Primary queue messages remain.'
Assert-Match $bridge "PSObject\.Properties\['ApproximateNumberOfMessages'\][\s\S]*?PSObject\.Properties\['ApproximateNumberOfMessagesNotVisible'\]" `
    'The Bridge does not tolerate an AWS response with an omitted SQS count attribute.'
Assert-Match $bridge 'AllowStaleBacklogDrain[\s\S]*?explicit non-live SpoolDirectory[\s\S]*?DRAIN STALE WAZUH PUSH BACKLOG' `
    'Stale backlog drain is not isolated behind an explicit spool and confirmation.'
Assert-Match $bridge 'StopSignalPath[\s\S]*?wazuh-push-bridge\.stop[\s\S]*?Write-BridgeHeartbeat -State STOPPED' `
    'The Bridge lacks a controlled stop signal and final state.'
Assert-NotMatch $bridge 'AWS CLI request failed: \$message' `
    'The Bridge can print unbounded AWS CLI failure output.'
$writeIndex = $bridge.IndexOf('Write-ShadowEvent -Envelope')
$deleteIndex = $bridge.IndexOf("'sqs', 'delete-message-batch'")
if ($writeIndex -lt 0 -or $deleteIndex -lt 0 -or $writeIndex -ge $deleteIndex) {
    throw 'The Shadow Bridge must durably write or deduplicate an event before deleting its SQS message.'
}
Assert-Match $bridge "'sqs', 'receive-message',[\s\S]*?'--max-number-of-messages', '10'" `
    'The Bridge does not receive a bounded SQS batch.'
Assert-Match $bridge "Write-ShadowEvent[\s\S]*?'sqs', 'delete-message-batch'" `
    'The Bridge does not durably preserve the full received batch before deleting it from SQS.'
Assert-Match $bridge "deleteResponse[\s\S]*?Properties\['Failed'\][\s\S]*?throw" `
    'The Bridge does not fail closed when SQS rejects a ledger-preserved batch deletion.'
Assert-NotMatch $bridge "'sqs', 'delete-message'," `
    'The Bridge still deletes one SQS message per AWS CLI process instead of using the bounded batch contract.'

Assert-Match $validation "ConfirmRun\s+-cne\s+'SEND WAZUH PUSH VALIDATION'" `
    'The safe Push validation can mutate CloudWatch Logs without exact confirmation.'
Assert-Match $validation 'wazuh\.push\.validation[\s\S]*?SAFE_VALIDATION_EVENT' `
    'The validation script does not emit the fixed harmless event contract.'
Assert-Match $validation 'contains_attack\s*=\s*\$false[\s\S]*?contains_secret\s*=\s*\$false' `
    'The validation Evidence does not declare its non-attack and non-secret boundary.'
Assert-NotMatch $validation 'command\.execution|169\.254\.169\.254|validation/capital-one-demo\.csv' `
    'The transport validation script contains attack or protected-object behavior.'

Write-Host 'Wazuh Push contract static tests passed.'
