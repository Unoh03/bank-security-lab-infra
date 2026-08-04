#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'automation\Daily.Automation.psm1'
$evidenceModulePath = Join-Path $root 'automation\Evidence.Collection.psm1'
$configPath = Join-Path $root 'automation\project.psd1'
$terraformDataPath = Join-Path $root 'data.tf'
$terraformVariablesPath = Join-Path $root 'variables.tf'
$clusterAddonsTemplatePath = Join-Path $root 'templates\install-cluster-addons.sh.tpl'
$clusterAddonsSsmPath = Join-Path $root 'cluster-addons-ssm.tf'
$observabilityPath = Join-Path $root 'observability.tf'
$foundationObservabilityPath = Join-Path $root 'foundation\observability.tf'
$foundationVariablesPath = Join-Path $root 'foundation\variables.tf'
$dailyCommonPath = Join-Path $root 'daily-common.ps1'
$dailyDownPath = Join-Path $root 'daily-down.ps1'
$queryPackRoot = Join-Path $root 'observability\queries'

Import-Module $modulePath -Force
Import-Module $evidenceModulePath -Force
. $dailyCommonPath
$config = Import-DailyAutomationConfig -Path $configPath
$application = Get-DailyApplication -Config $config -Name 'dvwa'

$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$escapedModulePath = $modulePath.Replace("'", "''")
$escapedConfigPath = $configPath.Replace("'", "''")
$noProfileProbe = @"
Import-Module '$escapedModulePath' -Force
`$probeConfig = Import-DailyAutomationConfig -Path '$escapedConfigPath'
if ([int]`$probeConfig.SchemaVersion -ne 1) { throw 'Unexpected automation schema.' }
"@
$encodedProbe = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($noProfileProbe)
)
& $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -EncodedCommand $encodedProbe
if ($LASTEXITCODE -ne 0) {
    throw 'Daily automation config import failed in a fresh NoProfile Windows PowerShell process.'
}

$evidenceModule = Get-Module | Where-Object {
    $_.Path -and (Resolve-Path -LiteralPath $_.Path).Path -ceq (
        Resolve-Path -LiteralPath $evidenceModulePath
    ).Path
} | Select-Object -First 1
if (-not $evidenceModule) {
    throw 'Evidence Collection module was not imported.'
}

$previousPythonUtf8 = $env:PYTHONUTF8
$previousAwsCliFileEncoding = $env:AWS_CLI_FILE_ENCODING
try {
    $env:PYTHONUTF8 = 'restore-python-test'
    $env:AWS_CLI_FILE_ENCODING = 'restore-aws-test'
    $encodingProbe = & $evidenceModule {
        $python = Invoke-EvidenceNative `
            -FilePath $env:ComSpec `
            -ArgumentList @('/d', '/c', 'echo %PYTHONUTF8%')
        $awsFile = Invoke-EvidenceNative `
            -FilePath $env:ComSpec `
            -ArgumentList @('/d', '/c', 'echo %AWS_CLI_FILE_ENCODING%')
        [pscustomobject]@{ Python = $python; AwsFile = $awsFile }
    }
    if ([string]$encodingProbe.Python -cne '1' -or
        [string]$encodingProbe.AwsFile -cne 'UTF-8') {
        throw 'Evidence native process did not receive UTF-8 environment settings.'
    }
    if ($env:PYTHONUTF8 -cne 'restore-python-test' -or
        $env:AWS_CLI_FILE_ENCODING -cne 'restore-aws-test') {
        throw 'Evidence native process did not restore the caller environment.'
    }
} finally {
    if ($null -eq $previousPythonUtf8) {
        Remove-Item Env:\PYTHONUTF8 -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONUTF8 = $previousPythonUtf8
    }
    if ($null -eq $previousAwsCliFileEncoding) {
        Remove-Item Env:\AWS_CLI_FILE_ENCODING -ErrorAction SilentlyContinue
    } else {
        $env:AWS_CLI_FILE_ENCODING = $previousAwsCliFileEncoding
    }
}

$terraformData = Get-Content -LiteralPath $terraformDataPath -Raw
$terraformVariables = Get-Content -LiteralPath $terraformVariablesPath -Raw
if ($terraformVariables -notmatch '(?s)variable\s+"web_health_check_path"\s*\{.*?default\s*=\s*"/login\.php"') {
    throw 'ALB health checks must use the unauthenticated login endpoint to avoid authorization audit noise.'
}
$dbPasswordResource = [regex]::Match(
    $terraformData,
    '(?s)resource\s+"random_password"\s+"db_master"\s*\{(?<body>.*?)\r?\n\}'
)
if (-not $dbPasswordResource.Success) {
    throw 'Terraform DB master password resource was not found.'
}
$overrideSpecial = [regex]::Match(
    $dbPasswordResource.Groups['body'].Value,
    'override_special\s*=\s*"(?<characters>[^"]*)"'
)
if (-not $overrideSpecial.Success) {
    throw 'Terraform DB master password special-character allowlist was not found.'
}
if ($overrideSpecial.Groups['characters'].Value -match '[/@" ]') {
    throw 'Terraform DB master password allowlist contains a character rejected by RDS.'
}

$clusterAddonsTemplate = Get-Content -LiteralPath $clusterAddonsTemplatePath -Raw
if ($clusterAddonsTemplate -match '(?m)^\s{2}extraFilters:\s*\|$' -or
    $clusterAddonsTemplate -notmatch '(?m)^additionalFilters:\s*\|$' -or
    $clusterAddonsTemplate -notmatch '(?m)^\s{6}Regex\s+\$kubernetes\[''namespace_name''\]\s+\^\$\{web_namespace\}\$$') {
    throw 'Fluent Bit values do not retain the DVWA namespace filter supported by the pinned AWS chart.'
}

$foundationVariables = Get-Content -LiteralPath $foundationVariablesPath -Raw
if ($foundationVariables -notmatch '(?s)variable\s+"security_log_retention_days"\s*\{.*?default\s*=\s*30') {
    throw 'Persistent security-log retention is not pinned to 30 days.'
}

$dailyCommon = Get-Content -LiteralPath $dailyCommonPath -Raw
if ($dailyCommon -notmatch '(?s)''vpc-flow-log''\s*\{.*?describe-flow-logs.*?FlowLogs\)\.Count\s+-gt\s+0') {
    throw 'Daily residue verification does not confirm VPC Flow Log existence through the EC2 API.'
}
$sshConfigTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'daily-ssh-config-test-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $sshConfigTestRoot | Out-Null
try {
    $sshConfigPath = Join-Path $sshConfigTestRoot 'config'
    [System.IO.File]::WriteAllText(
        $sshConfigPath,
        "Host other`r`n    HostName 192.0.2.10`r`n`r`nHost bas`r`n    HostName 192.0.2.20`r`n    User old-user`r`n",
        (New-Object System.Text.UTF8Encoding($false))
    )
    Set-SshConfigHost `
        -ConfigPath $sshConfigPath `
        -HostAlias 'bas' `
        -HostName '198.51.100.25' `
        -User 'ec2-user' `
        -IdentityFile 'C:\Users\test\.ssh\key.pem'
    $firstSshConfig = [System.IO.File]::ReadAllText($sshConfigPath)
    if ($firstSshConfig -notmatch '(?m)^Host other\r?$' -or
        $firstSshConfig -notmatch '(?m)^\s+HostName 192\.0\.2\.10\r?$' -or
        $firstSshConfig -notmatch '(?ms)^Host bas\r?\n\s+HostName 198\.51\.100\.25\r?\n\s+User ec2-user\r?\n\s+IdentityFile C:/Users/test/\.ssh/key\.pem\r?$' -or
        ([regex]::Matches($firstSshConfig, '(?m)^Host bas\r?$')).Count -ne 1) {
        throw 'Daily Up SSH alias refresh did not update only the exact bas block.'
    }
    Set-SshConfigHost `
        -ConfigPath $sshConfigPath `
        -HostAlias 'bas' `
        -HostName '198.51.100.25' `
        -User 'ec2-user' `
        -IdentityFile 'C:\Users\test\.ssh\key.pem'
    if ([System.IO.File]::ReadAllText($sshConfigPath) -cne $firstSshConfig) {
        throw 'Daily Up SSH alias refresh is not idempotent.'
    }

    $missingConfigPath = Join-Path $sshConfigTestRoot 'missing-config'
    Set-SshConfigHost `
        -ConfigPath $missingConfigPath `
        -HostAlias 'bas' `
        -HostName '203.0.113.40' `
        -User 'ec2-user' `
        -IdentityFile 'C:\Users\test\.ssh\key.pem'
    if ([System.IO.File]::ReadAllText($missingConfigPath) -notmatch '(?m)^Host bas\r?$') {
        throw 'Daily Up SSH alias refresh did not create a missing config.'
    }
} finally {
    Remove-Item -LiteralPath $sshConfigTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$dailyDown = Get-Content -LiteralPath $dailyDownPath -Raw
if ($dailyDown -notmatch '\[switch\]\$RunEvidenceQueries' -or
    $dailyDown -notmatch "RunQueries\s*=\s*\[bool\]\(\`$RunEvidenceQueries\s+-and\s+\`$Phase\s+-cne\s+'post-destroy'\)") {
    throw 'daily-down does not expose and forward the optional Evidence query switch.'
}
if ($dailyDown -notmatch '\[int\]\$EvidenceDeliveryGraceMinutes\s*=\s*0' -or
    $dailyDown -notmatch 'S3DeliveryGraceMinutes\s*=\s*\$EvidenceDeliveryGraceMinutes') {
    throw 'daily-down does not separate the event window from S3 delivery grace.'
}
if ($dailyDown -notmatch '\[int\]\$EvidenceEventTailSeconds\s*=\s*0' -or
    $dailyDown -notmatch 'EventTailSeconds\s*=\s*\$EvidenceEventTailSeconds') {
    throw 'daily-down does not expose a bounded server-event tail.'
}

if ($dailyDown -notmatch "status\.sync\.revision" -or
    $dailyDown -notmatch '\$evidenceContext\.ArgoRevision\s*=') {
    throw 'daily-down does not capture the live Argo CD sync revision for evidence.'
}

$clusterAddonsSsm = Get-Content -LiteralPath $clusterAddonsSsmPath -Raw
$observability = Get-Content -LiteralPath $observabilityPath -Raw
$foundationObservability = Get-Content -LiteralPath $foundationObservabilityPath -Raw
if ($foundationObservability -match 'output_format\s*=\s*"json"' -and
    $observability -match '(?m)^\s*field_delimiter\s*=') {
    throw 'CloudFront JSON delivery must not configure field_delimiter.'
}
if ($foundationVariables -notmatch '(?s)variable\s+"enable_project_s3_data_events"\s*\{.*?default\s*=\s*false' -or
    $foundationObservability -notmatch 'dynamic\s+"event_selector"' -or
    $foundationObservability -notmatch 'var\.enable_project_s3_data_events\s*\?\s*\[\]\s*:\s*\[1\]' -or
    $foundationObservability -notmatch 'name\s*=\s*"Management events"' -or
    $foundationObservability -notmatch 'name\s*=\s*"Project S3 canary object events"' -or
    $foundationObservability -notmatch 'equals\s*=\s*\["GetObject", "PutObject", "DeleteObject"\]' -or
    $foundationObservability -notmatch 's3:::.*-primary-' -or
    $foundationObservability -notmatch 's3:::.*-dr-') {
    throw 'CloudTrail S3 data events are not an explicit default-off experiment option.'
}
if ($clusterAddonsSsm -match 'enable_fluent_bit\s*=\s*"false"' -or
    $clusterAddonsSsm -notmatch 'fluent_bit_log_group\s*=\s*local\.security_log_group_names\.dvwa_dr' -or
    $observability -notmatch 'resource\s+"aws_eks_pod_identity_association"\s+"dr_dvwa_log_forwarder"' -or
    $observability -notmatch 'security_log_group_arns\.dvwa_dr') {
    throw 'DR DVWA log forwarding is not fully wired through Fluent Bit and EKS Pod Identity.'
}

$drDvwaCollector = @($config.Evidence.Collectors | Where-Object {
    [string]$_.Name -ceq 'dvwa-application-dr'
})
if ($drDvwaCollector.Count -ne 1 -or
    [string]$drDvwaCollector[0].Region -cne 'Dr') {
    throw 'DR DVWA evidence collector is missing or uses the wrong region.'
}

$scenarioQueries = @{
    'cloudwatch\06_waf_login_rate_limit.cwli' = @(
        'Purpose:',
        'Runtime verification:',
        'action = "BLOCK"',
        'httpRequest.uri = "/login.php"'
    )
    'cloudwatch\07_pod_identity_and_s3_activity.cwli' = @(
        'Purpose:',
        'Runtime verification:',
        'AssumeRoleForPodIdentity',
        'web/experiment-'
    )
    'athena\04_alb_trace_id_correlation.sql' = @(
        'Purpose:',
        'Runtime verification:',
        '${trace_id}',
        'target_status_code'
    )
    'cloudwatch\10_t1_waf_requests.cwli' = @(
        'Purpose:',
        'Runtime verification:',
        '/t1-observability/'
    )
    'cloudwatch\11_t1_application_requests.cwli' = @(
        'Purpose:',
        'Runtime verification:',
        '/t1-observability/'
    )
    'athena\03_cloudfront_request_trace.sql' = @(
        'Purpose:',
        'Runtime verification:',
        '"cs-protocol" AS protocol'
    )
}
foreach ($relativePath in $scenarioQueries.Keys) {
    $queryPath = Join-Path $queryPackRoot $relativePath
    if (-not (Test-Path -LiteralPath $queryPath -PathType Leaf)) {
        throw "Required scenario query is missing: $relativePath"
    }
    $queryText = Get-Content -LiteralPath $queryPath -Raw
    foreach ($requiredText in $scenarioQueries[$relativePath]) {
        if (-not $queryText.Contains($requiredText)) {
            throw "Scenario query '$relativePath' is missing contract text: $requiredText"
        }
    }
}

$queryMetadataContracts = @(
    @{ Name = 'Purpose'; Pattern = '(?im)^\s*(?:--|#)\s*Purpose:' }
    @{ Name = 'Normal'; Pattern = '(?im)^\s*(?:--|#)\s*(?:Normal|Normal/Attack):' }
    @{ Name = 'Attack'; Pattern = '(?im)^\s*(?:--|#)\s*(?:Attack(?:/abuse)?|Normal/Attack):' }
    @{ Name = 'False positive'; Pattern = '(?im)^\s*(?:--|#)\s*False positive:' }
    @{ Name = 'Runtime verification'; Pattern = '(?im)^\s*(?:--|#)\s*Runtime verification:' }
)
foreach ($queryFile in @(Get-ChildItem -LiteralPath $queryPackRoot -File -Recurse | Where-Object {
    $_.Extension -in @('.cwli', '.sql')
})) {
    # Windows PowerShell 5.1 treats BOM-less UTF-8 as the active ANSI code page
    # unless an encoding is specified. Query metadata contains Korean text, so
    # use the .NET UTF-8 reader consistently across powershell.exe and pwsh.
    $queryText = [System.IO.File]::ReadAllText($queryFile.FullName)
    foreach ($contract in $queryMetadataContracts) {
        if ($queryText -notmatch ([string]$contract.Pattern)) {
            throw "Query '$($queryFile.FullName)' is missing metadata: $($contract.Name)"
        }
    }
}

$athenaSchemaPath = Join-Path $queryPackRoot 'athena\00_create_security_log_tables.sql'
$athenaSchema = [System.IO.File]::ReadAllText($athenaSchemaPath)
foreach ($requiredPlaceholder in @(
    '${database}',
    '${security_log_bucket}',
    '${account_id}',
    '${primary_region}',
    '${cloudfront_table}',
    '${alb_table}',
    '${vpc_flow_table}'
)) {
    if (-not $athenaSchema.Contains($requiredPlaceholder)) {
        throw "Athena schema is missing placeholder: $requiredPlaceholder"
    }
}

foreach ($albQueryName in @(
    '01_alb_4xx_5xx_by_source.sql',
    '04_alb_trace_id_correlation.sql'
)) {
    $albQuery = [System.IO.File]::ReadAllText(
        (Join-Path $queryPackRoot "athena\$albQueryName")
    )
    if ($albQuery -match 'split_part\s*\(\s*client_port') {
        throw "Athena ALB query treats numeric client_port as a source IP: $albQueryName"
    }
    if ($albQuery -notmatch '(?i)\bclient_ip\b') {
        throw "Athena ALB query does not use the schema client_ip field: $albQueryName"
    }
}

$athenaRendererPath = Join-Path $root 'observability\render-athena-schema.ps1'
$renderedAthenaPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-athena-schema-{0}.sql' -f [guid]::NewGuid().ToString('N')
)
try {
    & $athenaRendererPath `
        -SecurityLogBucket 'example-security-log-bucket' `
        -AccountId '123456789012' `
        -PrimaryRegion 'ap-northeast-2' `
        -OutputPath $renderedAthenaPath | Out-Null

    $renderedAthena = [System.IO.File]::ReadAllText($renderedAthenaPath)
    if ($renderedAthena -match '\$\{[^}]+\}') {
        throw 'Rendered Athena schema retained an unresolved placeholder.'
    }
    foreach ($expectedText in @(
        's3://example-security-log-bucket/AWSLogs/123456789012/CloudFront/',
        's3://example-security-log-bucket/alb/primary/AWSLogs/123456789012/elasticloadbalancing/ap-northeast-2/',
        's3://example-security-log-bucket/vpc-flow/AWSLogs/123456789012/vpcflowlogs/ap-northeast-2/',
        'client_ip string'
    )) {
        if (-not $renderedAthena.Contains($expectedText)) {
            throw "Rendered Athena schema is missing expected text: $expectedText"
        }
    }
}
finally {
    Remove-Item -LiteralPath $renderedAthenaPath -Force -ErrorAction SilentlyContinue
}

if ([string]$application.Namespace -cne 'dvwa') {
    throw 'Application lookup returned an unexpected namespace.'
}

$resolved = Resolve-DailyTemplate `
    -Value '{ProjectName}/{AccountId}/{PrimaryRegion}/{UserHome}' `
    -Tokens @{
        ProjectName   = 'project'
        AccountId     = '123456789012'
        PrimaryRegion = 'ap-northeast-2'
        UserHome      = 'C:\Users\test'
    }
if ($resolved -cne 'project/123456789012/ap-northeast-2/C:\Users\test') {
    throw "Template resolution failed: $resolved"
}

$duplicateRejected = $false
$copy = @{
    SchemaVersion = 1
    Project = @{ Name = 'test' }
    Applications = @($config.Applications[0], $config.Applications[0])
    Evidence = $config.Evidence
}
$temp = Join-Path ([System.IO.Path]::GetTempPath()) (
    'daily-automation-test-' + [guid]::NewGuid().ToString('N') + '.psd1'
)
try {
    $content = @"
@{
    SchemaVersion = 1
    Project = @{ Name = 'test' }
    SessionSafety = @{ Enabled = `$true; SoftDeadlineHours = 5; MaxRuntimeHours = 6; RetryGraceHours = 2; RetryIntervalMinutes = 15; TaskNamePrefix = 'daily-test' }
    Applications = @(
        @{ Name = 'same'; SourceRootDefault = 'x'; GitHubRepositoryDefault = 'a/b'; WorkflowFile = 'w'; ValuesRelativePath = 'v'; ArgoBootstrapRelativePath = 'a'; ArgoApplication = 'a'; Namespace = 'n'; WorkloadKind = 'deployment'; WorkloadName = 'w'; PodSelector = 'p=v'; UrlTerraformOutput = 'u'; Database = @{ Enabled = `$true; Type = 'MariaDbDvwa'; TerraformOutput = 'db'; BootstrapScript = 'db.sh'; KubernetesSecretName = 'db' } }
        @{ Name = 'same'; SourceRootDefault = 'x'; GitHubRepositoryDefault = 'a/b'; WorkflowFile = 'w'; ValuesRelativePath = 'v'; ArgoBootstrapRelativePath = 'a'; ArgoApplication = 'a'; Namespace = 'n'; WorkloadKind = 'deployment'; WorkloadName = 'w'; PodSelector = 'p=v'; UrlTerraformOutput = 'u'; Database = @{ Enabled = `$true; Type = 'MariaDbDvwa'; TerraformOutput = 'db'; BootstrapScript = 'db.sh'; KubernetesSecretName = 'db' } }
    )
    Evidence = @{ RootDefault = 'x'; HashAlgorithm = 'SHA256'; Collectors = @() }
}
"@
    [System.IO.File]::WriteAllText(
        $temp,
        $content,
        (New-Object System.Text.UTF8Encoding($false))
    )
    try {
        [void](Import-DailyAutomationConfig -Path $temp)
    } catch {
        if ($_.Exception.Message -like 'Duplicate application name:*') {
            $duplicateRejected = $true
        } else {
            throw
        }
    }
} finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}
if (-not $duplicateRejected) {
    throw 'Duplicate application validation did not fail closed.'
}

$evidenceRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'daily-evidence-test-' + [guid]::NewGuid().ToString('N')
)
try {
    $emptyEvidenceConfig = @{
        Evidence = @{
            RootDefault  = $evidenceRoot
            HashAlgorithm = 'SHA256'
            Collectors   = @()
        }
    }
    $evidence = Invoke-DailyEvidenceCollection `
        -Config $emptyEvidenceConfig `
        -Context @{
            AccountId     = '123456789012'
            ProjectName   = 'test'
            PrimaryRegion = 'ap-northeast-2'
            DrRegion      = 'ap-northeast-1'
        } `
        -EvidenceRoot $evidenceRoot
    if (-not (Test-Path -LiteralPath $evidence.ManifestPath -PathType Leaf)) {
        throw 'Evidence collection did not create a run manifest.'
    }
    if (-not (Test-Path -LiteralPath "$($evidence.ManifestPath).sha256" -PathType Leaf)) {
        throw 'Evidence collection did not create a manifest hash.'
    }
} finally {
    Remove-Item -LiteralPath $evidenceRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$redactedJson = Protect-SecurityEvidenceText -Text (
    '{"password":"raw-password","nested":{"cookie":"raw-cookie"},' +
    '"message":"Bearer raw-token\r\nforged-line","event_type":"auth.login.failed"}'
)
if ($redactedJson -match 'raw-password|raw-cookie|raw-token') {
    throw 'Evidence JSON redaction retained a forbidden secret.'
}
$redactedObject = $redactedJson | ConvertFrom-Json
if ([string]$redactedObject.message -match '[\r\n]') {
    throw 'Evidence JSON redaction retained a log-injection newline.'
}
$deepValue = [ordered]@{
    leaf = 'preserved'
    password = 'raw-deep-secret'
}
for ($depth = 1; $depth -le 40; $depth++) {
    $deepValue = [ordered]@{ "level$depth" = $deepValue }
}
$deepWarnings = @()
$deepRedacted = Protect-SecurityEvidenceText `
    -Text ($deepValue | ConvertTo-Json -Depth 100) `
    -WarningVariable +deepWarnings
if ($deepWarnings.Count -ne 0) {
    throw 'Evidence JSON redaction emitted a depth-truncation warning.'
}
$deepObject = $deepRedacted | ConvertFrom-Json
for ($depth = 40; $depth -ge 1; $depth--) {
    $deepObject = $deepObject."level$depth"
}
if ([string]$deepObject.leaf -cne 'preserved') {
    throw 'Evidence JSON redaction truncated a deeply nested leaf value.'
}
if ([string]$deepObject.password -cne '[REDACTED]') {
    throw 'Evidence JSON redaction retained a deeply nested secret.'
}
$redactedRequestLine = Protect-SecurityEvidenceText -Text (
    'GET /login.php?username=alice&password=raw-query-secret HTTP/1.1'
)
if ($redactedRequestLine -match 'alice|raw-query-secret' -or
    $redactedRequestLine -notmatch '\?\[REDACTED_QUERY\]') {
    throw 'Evidence text redaction retained an HTTP query string.'
}

$retryAttempts = 0
$retryResult = Invoke-EvidenceBoundedRetry `
    -MaxAttempts 3 `
    -DelaySeconds 0 `
    -Operation {
        $script:retryAttempts++
        if ($script:retryAttempts -lt 3) {
            throw 'transient'
        }
        return 'recovered'
    }
if ($retryResult -cne 'recovered' -or $retryAttempts -ne 3) {
    throw 'Bounded retry did not stop after a successful third attempt.'
}

$collectorEvidenceRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'security-evidence-test-' + [guid]::NewGuid().ToString('N')
)
$windowStart = [datetime]'2026-07-31T00:00:00Z'
$windowEnd = [datetime]'2026-07-31T01:00:00Z'
$queryState = @{ Polls = 0; EndTime = 0 }
$fakeInvoker = {
    param($FilePath, $ArgumentList, $AllowFailure)

    $signature = @($ArgumentList[0], $ArgumentList[1]) -join ' '
    switch ($signature) {
        's3api list-objects-v2' {
            return (@{
                Contents = @(
                    @{
                        Key = 'AWSLogs/123456789012/CloudTrail/in-window.json'
                        LastModified = '2026-07-31T00:30:00Z'
                        Size = 42
                    },
                    @{
                        Key = 'AWSLogs/123456789012/CloudTrail/in-window-empty.log'
                        LastModified = '2026-07-31T00:31:00Z'
                        Size = 0
                    },
                    @{
                        Key = 'AWSLogs/123456789012/CloudTrail/delivery-grace.json'
                        LastModified = '2026-07-31T01:04:00Z'
                        Size = 42
                    },
                    @{
                        Key = 'AWSLogs/123456789012/CloudTrail/outside.json'
                        LastModified = '2026-07-30T22:00:00Z'
                        Size = 42
                    }
                )
            } | ConvertTo-Json -Depth 6)
        }
        's3api get-object' {
            $destination = [string]$ArgumentList[-1]
            $keyIndex = [array]::IndexOf($ArgumentList, '--key')
            $objectKey = if ($keyIndex -ge 0) {
                [string]$ArgumentList[$keyIndex + 1]
            } else {
                ''
            }
            $objectText = if ($objectKey.EndsWith('in-window-empty.log')) {
                ''
            } else {
                '{"event_type":"cloudtrail.test","password":"raw-s3-secret"}'
            }
            [System.IO.File]::WriteAllText(
                $destination,
                $objectText,
                (New-Object System.Text.UTF8Encoding($false))
            )
            return '{}'
        }
        'logs filter-log-events' {
            return (@{
                events = @(
                    @{
                        timestamp = 1785457800000
                        message = '{"event_type":"auth.login.failed","password":"raw-cw-secret"}'
                    }
                )
                searchedLogStreams = @()
            } | ConvertTo-Json -Depth 8)
        }
        'logs start-query' {
            $endIndex = [array]::IndexOf($ArgumentList, '--end-time')
            $queryState.EndTime = [long]$ArgumentList[$endIndex + 1]
            return (@{ queryId = 'query-123' } | ConvertTo-Json)
        }
        'logs get-query-results' {
            $queryState.Polls++
            if ($queryState.Polls -eq 1) {
                return (@{ status = 'Running'; results = @() } | ConvertTo-Json)
            }
            return (@{
                status = 'Complete'
                statistics = @{ recordsMatched = 1; recordsScanned = 1 }
                results = @(
                    @(
                        @{ field = '@timestamp'; value = '2026-07-31T01:03:00Z' },
                        @{ field = 'eventTime'; value = '2026-07-31T00:30:00Z' },
                        @{ field = 'event_type'; value = 'auth.login.failed' },
                        @{ field = 'password'; value = 'raw-query-secret' }
                    ),
                    @(
                        @{ field = '@timestamp'; value = '2026-07-31T01:04:00Z' },
                        @{ field = 'eventTime'; value = '2026-07-31T01:02:00Z' },
                        @{ field = 'event_type'; value = 'late-next-phase' }
                    )
                )
            } | ConvertTo-Json -Depth 10)
        }
        default {
            throw "Unexpected fake command: $FilePath $($ArgumentList -join ' ')"
        }
    }
}.GetNewClosure()
$collectorConfig = @{
    Evidence = @{
        RootDefault = $collectorEvidenceRoot
        HashAlgorithm = 'SHA256'
        DefaultWindowMinutes = 60
        QueryPackRoot = 'observability\queries'
        Queries = @(
            @{
                Name = 'test-query'
                Type = 'CloudWatchLogsInsights'
                ScenarioIds = @('TEST-01')
                QueryFile = 'cloudwatch\01_repeated_login_failures.cwli'
                LogGroup = '/aws/eks/{ProjectName}-primary/dvwa'
                Region = 'Primary'
                Required = $true
                DeliveryGraceMinutes = 5
                EventTimeField = 'eventTime'
                MaxPollAttempts = 3
                PollDelaySeconds = 0
            }
        )
        Collectors = @(
            @{
                Name = 'test-s3'
                Type = 'S3Prefix'
                SourceRoot = 'Foundation'
                Bucket = 'test-bucket'
                Prefix = 'AWSLogs/{AccountId}/CloudTrail/'
                Region = 'Primary'
                Destination = 'cloudtrail'
                FailurePolicy = 'Warn'
                Required = $true
                MaxAttempts = 3
                RetryDelaySeconds = 0
            },
            @{
                Name = 'test-cloudwatch'
                Type = 'CloudWatchLogs'
                SourceRoot = 'Foundation'
                LogGroup = '/aws/eks/{ProjectName}-primary/dvwa'
                Region = 'Primary'
                Destination = 'dvwa'
                FailurePolicy = 'Warn'
                Required = $true
                MaxAttempts = 3
                RetryDelaySeconds = 0
            }
        )
    }
}
$collectorContext = @{
    TerraformRoot = $root
    FoundationRoot = Join-Path $root 'foundation'
    AwsProfile = 'test'
    AccountId = '123456789012'
    ProjectName = 'test'
    PrimaryRegion = 'ap-northeast-2'
    DrRegion = 'ap-northeast-1'
    GitCommit = '0123456789abcdef'
    ImageSha = 'sha-0123456789abcdef'
    ArgoRevision = '0123456789abcdef'
}
try {
    $bundle = Invoke-SecurityEvidenceCollection `
        -Config $collectorConfig `
        -Context $collectorContext `
        -EvidenceRoot $collectorEvidenceRoot `
        -ExperimentId 'test-evidence' `
        -ScenarioId 'TEST-01' `
        -StartTimeUtc $windowStart `
        -EndTimeUtc $windowEnd `
        -EventTailSeconds 2 `
        -S3DeliveryGraceMinutes 5 `
        -RequireEvidence `
        -RunQueries `
        -Invoker $fakeInvoker
    if (-not (Test-Path -LiteralPath $bundle.ManifestPath -PathType Leaf)) {
        throw 'Security evidence manifest was not created.'
    }
    $sumPath = Join-Path $bundle.BundleRoot 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf) -or
        (Get-Content -LiteralPath $sumPath -Raw) -notmatch 'manifest\.json') {
        throw 'Security evidence SHA256SUMS does not cover the manifest.'
    }
    $s3Index = Get-Content `
        -LiteralPath (Join-Path $bundle.BundleRoot 'source\cloudtrail\objects.json') `
        -Raw |
        ConvertFrom-Json
    if (@($s3Index.Objects).Count -ne 3) {
        throw 'S3 collector did not preserve empty objects or include the bounded delivery-grace window.'
    }
    $sanitizedText = Get-ChildItem `
        -LiteralPath (Join-Path $bundle.BundleRoot 'sanitized') `
        -File `
        -Recurse |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
    if (($sanitizedText -join "`n") -match 'raw-s3-secret|raw-cw-secret') {
        throw 'Collector output retained a forbidden secret.'
    }
    $queryResultPath = Join-Path $bundle.BundleRoot 'results\cloudwatch\test-query.json'
    if (-not (Test-Path -LiteralPath $queryResultPath -PathType Leaf)) {
        throw 'CloudWatch Logs Insights query result was not written to the Evidence Bundle.'
    }
    $queryResultText = Get-Content -LiteralPath $queryResultPath -Raw
    if ($queryResultText -match 'raw-query-secret') {
        throw 'CloudWatch Logs Insights query output retained a forbidden secret.'
    }
    $queryResult = $queryResultText | ConvertFrom-Json
    $eventTimeUtc = [datetimeoffset]::Parse(
        [string]$queryResult.Rows.eventTime,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal
    ).UtcDateTime
    if (@($queryResult.Rows).Count -ne 1 -or
        $eventTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss') -cne '2026-07-31T00:30:00' -or
        [int]$queryResult.ServiceRowCount -ne 2 -or
        $queryState.EndTime -ne ([DateTimeOffset]::new($windowEnd.ToUniversalTime())).AddSeconds(2).AddMinutes(5).ToUnixTimeSeconds()) {
        throw "CloudWatch query delivery grace did not filter results back to the exact event window: rows=$(@($queryResult.Rows).Count), eventTime=$($queryResult.Rows.eventTime), serviceRows=$($queryResult.ServiceRowCount), scanEnd=$($queryState.EndTime)"
    }
    $manifest = Get-Content -LiteralPath $bundle.ManifestPath -Raw | ConvertFrom-Json
    if (-not [bool]$manifest.QueryExecutionRequested -or
        @($manifest.Results | Where-Object {
            [string]$_.Name -ceq 'test-query' -and
            [string]$_.Status -ceq 'Succeeded'
        }).Count -ne 1 -or
        $queryState.Polls -ne 2) {
        throw 'CloudWatch Logs Insights query execution was not recorded or bounded as expected.'
    }
    if ([int]$manifest.Window.EventTailSeconds -ne 2 -or
        [int]$manifest.Window.S3DeliveryGraceMinutes -ne 5 -or
        ([datetime]$manifest.Window.EndTimeUtc).ToUniversalTime() -ne $windowEnd.ToUniversalTime() -or
        ([datetime]$manifest.Window.EventEndTimeUtc).ToUniversalTime() -ne $windowEnd.AddSeconds(2).ToUniversalTime() -or
        ([datetime]$manifest.Window.S3EndTimeUtc).ToUniversalTime() -ne $windowEnd.AddSeconds(2).AddMinutes(5).ToUniversalTime()) {
        throw 'Evidence manifest did not distinguish event and S3 delivery windows.'
    }

    $emptyQueryConfig = @{
        Evidence = @{
            RootDefault = $collectorEvidenceRoot
            HashAlgorithm = 'SHA256'
            QueryPackRoot = 'observability\queries'
            Collectors = @()
            Queries = @(
                @{
                    Name = 'empty-query'
                    Type = 'CloudWatchLogsInsights'
                    ScenarioIds = @('EMPTY-01')
                    QueryFile = 'cloudwatch\01_repeated_login_failures.cwli'
                    LogGroup = '/aws/eks/{ProjectName}-primary/dvwa'
                    Region = 'Primary'
                    Required = $true
                    MaxPollAttempts = 1
                    PollDelaySeconds = 0
                }
            )
        }
    }
    $emptyQueryInvoker = {
        param($FilePath, $ArgumentList, $AllowFailure)
        $signature = @($ArgumentList[0], $ArgumentList[1]) -join ' '
        switch ($signature) {
            'logs start-query' { return '{"queryId":"empty-query-id"}' }
            'logs get-query-results' { return '{"status":"Complete","results":[]}' }
            default { throw "Unexpected empty-query command: $signature" }
        }
    }
    $emptyQueryBundle = Invoke-SecurityEvidenceCollection `
        -Config $emptyQueryConfig `
        -Context $collectorContext `
        -EvidenceRoot $collectorEvidenceRoot `
        -ExperimentId 'empty-query-result' `
        -ScenarioId 'EMPTY-01' `
        -StartTimeUtc $windowStart `
        -EndTimeUtc $windowEnd `
        -RequireEvidence `
        -RunQueries `
        -Invoker $emptyQueryInvoker
    $emptyResult = @($emptyQueryBundle.Results | Where-Object {
        [string]$_.Name -ceq 'empty-query'
    })
    if ($emptyResult.Count -ne 1 -or
        [string]$emptyResult[0].Status -cne 'Succeeded' -or
        [int]$emptyResult[0].Items -ne 0) {
        throw 'A zero-row CloudWatch Logs Insights query was not preserved as successful evidence.'
    }

    $failingConfig = @{
        Evidence = @{
            RootDefault = $collectorEvidenceRoot
            HashAlgorithm = 'SHA256'
            DefaultWindowMinutes = 60
            Collectors = @(
                @{
                    Name = 'required-failure'
                    Type = 'CloudWatchLogs'
                    SourceRoot = 'Foundation'
                    LogGroup = '/missing'
                    Region = 'Primary'
                    Destination = 'missing'
                    FailurePolicy = 'Warn'
                    Required = $true
                    MaxAttempts = 1
                    RetryDelaySeconds = 0
                }
            )
        }
    }
    $alwaysFailInvoker = {
        param($FilePath, $ArgumentList, $AllowFailure)
        throw 'simulated collector failure'
    }
    $partial = Invoke-SecurityEvidenceCollection `
        -Config $failingConfig `
        -Context $collectorContext `
        -EvidenceRoot $collectorEvidenceRoot `
        -ExperimentId 'partial-failure' `
        -StartTimeUtc $windowStart `
        -EndTimeUtc $windowEnd `
        -Invoker $alwaysFailInvoker
    if ([string]$partial.Results[0].Status -cne 'Failed') {
        throw 'Normal evidence mode did not preserve a partial failure.'
    }

    $strictRejected = $false
    try {
        [void](Invoke-SecurityEvidenceCollection `
            -Config $failingConfig `
            -Context $collectorContext `
            -EvidenceRoot $collectorEvidenceRoot `
            -ExperimentId 'strict-failure' `
            -StartTimeUtc $windowStart `
            -EndTimeUtc $windowEnd `
            -RequireEvidence `
            -Invoker $alwaysFailInvoker)
    } catch {
        if ($_.Exception.Message -like 'Required evidence is incomplete*') {
            $strictRejected = $true
        } else {
            throw
        }
    }
    if (-not $strictRejected) {
        throw 'Strict evidence mode did not fail closed.'
    }
} finally {
    Remove-Item -LiteralPath $collectorEvidenceRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Daily automation self-test passed.'
