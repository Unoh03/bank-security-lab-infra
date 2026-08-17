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
Assert-NotMatch $reader 'sqs:SendMessage' `
    'The local Reader Role must not be able to inject Push events.'

Assert-Match $outputs 'output\s+"wazuh_push_primary_queue_url"' `
    'The local Shadow Bridge cannot discover the Primary queue URL.'
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
Assert-Match $bridge 'liveStream\.Write[\s\S]*?liveStream\.Flush\(\$true\)[\s\S]*?FileMode\]::CreateNew' `
    'The Bridge must flush the live Wazuh record before recording the event ledger.'
Assert-Match $bridge 'temporaryEventPath[\s\S]*?Flush\(\$true\)[\s\S]*?File\]::Move\(\$temporaryEventPath, \$eventPath\)' `
    'The Bridge ledger must be flushed to a temporary file and atomically renamed.'
Assert-Match $bridge 'Existing Wazuh Push ledger entry is not valid JSON[\s\S]*?existing\.event_id' `
    'The Bridge does not validate an existing ledger record before deduplication.'
Assert-Match $bridge 'wazuh-push-bridge\.lock[\s\S]*?FileShare\]::None' `
    'The Bridge does not prevent concurrent writers to its live JSONL and ledger.'
Assert-Match $bridge 'wazuh_log_reader_role_arn' `
    'The Bridge cannot discover the Terraform-managed Reader Role.'
Assert-Match $bridge "'sts', 'assume-role'" `
    'The Bridge does not obtain a temporary Reader Role session.'
Assert-Match $bridge 'AWS_ACCESS_KEY_ID[\s\S]*?finally[\s\S]*?SetEnvironmentVariable' `
    'The Bridge does not restore process-level temporary credentials.'
Assert-NotMatch $bridge '(WriteAllText|Set-Content|Add-Content)[\s\S]{0,200}(AccessKeyId|SecretAccessKey|SessionToken)' `
    'The Bridge persists an AWS credential value.'
Assert-Match $bridge 'Bridge output: durable Host spool; Wazuh localfile consumption is configured separately' `
    'The Bridge does not state the Host-spool and Wazuh-localfile responsibility boundary.'
$writeIndex = $bridge.IndexOf('Write-ShadowEvent -Envelope')
$deleteIndex = $bridge.IndexOf("'sqs', 'delete-message'")
if ($writeIndex -lt 0 -or $deleteIndex -lt 0 -or $writeIndex -ge $deleteIndex) {
    throw 'The Shadow Bridge must durably write or deduplicate an event before deleting its SQS message.'
}

Assert-Match $validation "ConfirmRun\s+-cne\s+'SEND WAZUH PUSH VALIDATION'" `
    'The safe Push validation can mutate CloudWatch Logs without exact confirmation.'
Assert-Match $validation 'wazuh\.push\.validation[\s\S]*?SAFE_VALIDATION_EVENT' `
    'The validation script does not emit the fixed harmless event contract.'
Assert-Match $validation 'contains_attack\s*=\s*\$false[\s\S]*?contains_secret\s*=\s*\$false' `
    'The validation Evidence does not declare its non-attack and non-secret boundary.'
Assert-NotMatch $validation 'command\.execution|169\.254\.169\.254|validation/capital-one-demo\.csv' `
    'The transport validation script contains attack or protected-object behavior.'

Write-Host 'Wazuh Push contract static tests passed.'
