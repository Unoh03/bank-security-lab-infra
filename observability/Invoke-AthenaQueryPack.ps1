#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('alb-errors', 'vpc-reject', 'cloudfront-trace', 'alb-trace')]
    [string]$QueryName = 'alb-errors',

    [string]$StartUtc = '',
    [string]$EndUtc = '',
    [string]$SourceIp = '',

    [ValidatePattern('^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$')]
    [string]$TraceId = '',

    [switch]$CreateSchema,

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$Database = 'aws_topology_security',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$CloudFrontTable = 'cloudfront_access',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$AlbTable = 'alb_primary_access',

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$VpcFlowTable = 'vpc_reject',

    [ValidateSet('primary')]
    [string]$WorkGroup = 'primary',

    [ValidateRange(10, 120)]
    [int]$MaxPollAttempts = 60,

    [ValidateRange(1, 10)]
    [int]$PollDelaySeconds = 2,

    [ValidateRange(1, 1000)]
    [int]$MaxResultRows = 1000,

    [string]$FoundationRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$ExpectedAccountId = '433048100798',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $FoundationRoot) {
    $FoundationRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\foundation')).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'athena-' + $QueryName + '-' +
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}

function Invoke-AthenaNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "$FailureMessage`n$(($output | Out-String).Trim())"
    }
    return ($output | Out-String).Trim()
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        $Text,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    Write-Utf8File -Path $Path -Text ($Value | ConvertTo-Json -Depth 30)
}

function Get-OptionalProperty {
    param(
        $InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $Default
    }
    return $property.Value
}

function Convert-ToUtcBound {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse(
        $Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed
    )) {
        throw "$Name must be an ISO-8601 timestamp with an explicit or assumed UTC offset."
    }
    return $parsed.ToUniversalTime()
}

function New-ClientRequestToken {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Sql
    )

    $material = "$ExperimentId`n$Label`n$Sql"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material))
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
    return "aws-topology-$hex"
}

$identity = Invoke-AthenaNative -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--output', 'json'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $ExpectedAccountId) {
    throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
}

$securityLogBucket = Invoke-AthenaNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$FoundationRoot", 'output', '-raw', 'security_log_bucket_name'
) -FailureMessage 'The Foundation security log bucket output is unavailable.'
$primaryRegion = Invoke-AthenaNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$FoundationRoot", 'output', '-raw', 'aws_region'
) -FailureMessage 'The Foundation region output is unavailable.'

$queryMetadata = @{
    'alb-errors' = @{
        File = '01_alb_4xx_5xx_by_source.sql'
        RequiresTime = $true
        RequiresTraceId = $false
    }
    'vpc-reject' = @{
        File = '02_vpc_reject_by_source.sql'
        RequiresTime = $true
        RequiresTraceId = $false
    }
    'cloudfront-trace' = @{
        File = '03_cloudfront_request_trace.sql'
        RequiresTime = $true
        RequiresTraceId = $false
    }
    'alb-trace' = @{
        File = '04_alb_trace_id_correlation.sql'
        RequiresTime = $false
        RequiresTraceId = $true
    }
}
$selected = $queryMetadata[$QueryName]

$start = $null
$end = $null
if ($selected.RequiresTime) {
    if (-not $StartUtc -or -not $EndUtc) {
        throw "$QueryName requires both StartUtc and EndUtc."
    }
    $start = Convert-ToUtcBound -Value $StartUtc -Name 'StartUtc'
    $end = Convert-ToUtcBound -Value $EndUtc -Name 'EndUtc'
    if ($end -le $start) {
        throw 'EndUtc must be later than StartUtc.'
    }
    if (($end - $start).TotalHours -gt 6) {
        throw 'Athena evidence queries are limited to a six-hour window.'
    }
}
if ($selected.RequiresTraceId -and -not $TraceId) {
    throw "$QueryName requires TraceId."
}

$normalizedSourceIp = ''
if ($SourceIp) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($SourceIp, [ref]$parsedIp)) {
        throw 'SourceIp must be a valid IPv4 or IPv6 address.'
    }
    $normalizedSourceIp = $parsedIp.ToString()
}

$queryPackRoot = Join-Path $PSScriptRoot 'queries\athena'
$queryPath = Join-Path $queryPackRoot $selected.File
if (-not (Test-Path -LiteralPath $queryPath -PathType Leaf)) {
    throw "Approved Athena query is unavailable: $queryPath"
}
$querySql = [System.IO.File]::ReadAllText($queryPath)
$replacements = [ordered]@{
    '${database}'            = $Database
    '${cloudfront_table}'    = $CloudFrontTable
    '${alb_table}'           = $AlbTable
    '${vpc_flow_table}'      = $VpcFlowTable
    '${start_utc}'           = if ($start) { $start.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { '' }
    '${end_utc}'             = if ($end) { $end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { '' }
    '${start_epoch_seconds}' = if ($start) { [string]$start.ToUnixTimeSeconds() } else { '' }
    '${end_epoch_seconds}'   = if ($end) { [string]$end.ToUnixTimeSeconds() } else { '' }
    '${source_ip}'           = $normalizedSourceIp
    '${trace_id}'            = $TraceId
}
foreach ($entry in $replacements.GetEnumerator()) {
    $querySql = $querySql.Replace([string]$entry.Key, [string]$entry.Value)
}
$unresolved = @(
    [regex]::Matches($querySql, '\$\{[^}]+\}') |
        ForEach-Object { $_.Value } |
        Sort-Object -Unique
)
if ($unresolved.Count -gt 0) {
    throw "Athena query retained unresolved placeholders: $($unresolved -join ', ')."
}

$localRoot = Join-Path $EvidenceRoot $ExperimentId
$localQueryDir = Join-Path $localRoot 'queries\athena'
$localResultDir = Join-Path $localRoot 'results\athena'
$queryOutputLocation = "s3://$securityLogBucket/athena-results/$ExperimentId/"
$resultConfiguration = @{
    OutputLocation = $queryOutputLocation
    ExpectedBucketOwner = [string]$identity.Account
    EncryptionConfiguration = @{
        EncryptionOption = 'SSE_S3'
    }
} | ConvertTo-Json -Compress

$workGroupResponse = Invoke-AthenaNative -FilePath 'aws' -ArgumentList @(
    'athena', 'get-work-group',
    '--profile', $AwsProfile,
    '--region', $primaryRegion,
    '--work-group', $WorkGroup,
    '--output', 'json'
) -FailureMessage 'The Athena primary workgroup configuration could not be read.' | ConvertFrom-Json
$workGroupConfiguration = Get-OptionalProperty `
    -InputObject $workGroupResponse.WorkGroup `
    -Name 'Configuration' `
    -Default ([pscustomobject]@{})
$workGroupEnforcesConfiguration = [bool](Get-OptionalProperty `
    -InputObject $workGroupConfiguration `
    -Name 'EnforceWorkGroupConfiguration' `
    -Default $false)
$workGroupResultConfiguration = Get-OptionalProperty `
    -InputObject $workGroupConfiguration `
    -Name 'ResultConfiguration' `
    -Default ([pscustomobject]@{})
$workGroupOutputLocation = [string](Get-OptionalProperty `
    -InputObject $workGroupResultConfiguration `
    -Name 'OutputLocation' `
    -Default '')
if (
    $workGroupEnforcesConfiguration -and
    $workGroupOutputLocation -and
    -not $workGroupOutputLocation.StartsWith(
        "s3://$securityLogBucket/",
        [System.StringComparison]::Ordinal
    )
) {
    throw (
        "The Athena primary workgroup overrides results to an unapproved bucket: " +
        $workGroupOutputLocation
    )
}

Write-Host "Athena query: $QueryName"
Write-Host "AWS account/region: $($identity.Account)/$primaryRegion"
Write-Host "Foundation log bucket: $securityLogBucket"
Write-Host "Create schema: $([bool]$CreateSchema)"
if ($start) {
    Write-Host "Bounded UTC window: $($start.ToString('o')) .. $($end.ToString('o'))"
}
Write-Host "AWS result prefix: $queryOutputLocation"
if ($workGroupEnforcesConfiguration -and $workGroupOutputLocation) {
    Write-Host "Workgroup enforced result prefix: $workGroupOutputLocation"
}
Write-Host "Local Evidence: $localRoot"
if ($ConfirmRun -cne 'RUN ATHENA QUERY PACK') {
    throw (
        "Preview only. Athena DDL changes the Glue catalog and SELECT queries incur " +
        "scan charges. Re-run with -ConfirmRun 'RUN ATHENA QUERY PACK' after approval."
    )
}

function Invoke-AthenaStatement {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Sql,
        [Parameter(Mandatory)][bool]$CaptureRows
    )

    $safeLabel = $Label -replace '[^A-Za-z0-9._-]', '-'
    $sqlPath = Join-Path $localQueryDir "$safeLabel.sql"
    Write-Utf8File -Path $sqlPath -Text $Sql

    $arguments = @(
        'athena', 'start-query-execution',
        '--profile', $AwsProfile,
        '--region', $primaryRegion,
        '--work-group', $WorkGroup,
        '--query-string', $Sql,
        '--client-request-token', (New-ClientRequestToken -Label $Label -Sql $Sql),
        '--result-configuration', $resultConfiguration,
        '--output', 'json'
    )
    if ($Sql -match '(?is)^\s*(?:--[^\r\n]*[\r\n]+)*\s*SELECT\b') {
        $arguments += @(
            '--query-execution-context',
            "Database=$Database,Catalog=AwsDataCatalog"
        )
    }

    $started = (Get-Date).ToUniversalTime()
    $startResponse = Invoke-AthenaNative -FilePath 'aws' -ArgumentList $arguments `
        -FailureMessage "Athena statement '$Label' could not be started." | ConvertFrom-Json
    $queryExecutionId = [string]$startResponse.QueryExecutionId
    if (-not $queryExecutionId) {
        throw "Athena statement '$Label' returned no QueryExecutionId."
    }

    $execution = $null
    for ($attempt = 1; $attempt -le $MaxPollAttempts; $attempt++) {
        $executionResponse = Invoke-AthenaNative -FilePath 'aws' -ArgumentList @(
            'athena', 'get-query-execution',
            '--profile', $AwsProfile,
            '--region', $primaryRegion,
            '--query-execution-id', $queryExecutionId,
            '--output', 'json'
        ) -FailureMessage "Athena statement '$Label' status could not be read." | ConvertFrom-Json
        $execution = $executionResponse.QueryExecution
        $state = [string]$execution.Status.State
        if ($state -in @('SUCCEEDED', 'FAILED', 'CANCELLED')) {
            break
        }
        if ($attempt -lt $MaxPollAttempts) {
            Start-Sleep -Seconds $PollDelaySeconds
        }
    }

    $finished = (Get-Date).ToUniversalTime()
    $stateReason = [string](Get-OptionalProperty `
        -InputObject $execution.Status `
        -Name 'StateChangeReason' `
        -Default '')
    $statistics = Get-OptionalProperty `
        -InputObject $execution `
        -Name 'Statistics' `
        -Default ([pscustomobject]@{})
    $actualResultConfiguration = Get-OptionalProperty `
        -InputObject $execution `
        -Name 'ResultConfiguration' `
        -Default ([pscustomobject]@{})
    $executionRecord = [ordered]@{
        SchemaVersion = 1
        ExperimentId = $ExperimentId
        QueryName = $QueryName
        Label = $Label
        QueryExecutionId = $queryExecutionId
        AwsAccountId = [string]$identity.Account
        Region = $primaryRegion
    WorkGroup = $WorkGroup
    WorkGroupEnforcesConfiguration = $workGroupEnforcesConfiguration
    WorkGroupOutputLocation = $workGroupOutputLocation
    Database = $Database
        StartedAtUtc = $started.ToString('o')
        FinishedAtUtc = $finished.ToString('o')
        State = [string]$execution.Status.State
        StateChangeReason = $stateReason
        DataScannedInBytes = [long](Get-OptionalProperty `
            -InputObject $statistics `
            -Name 'DataScannedInBytes' `
            -Default 0)
        EngineExecutionTimeInMillis = [long](Get-OptionalProperty `
            -InputObject $statistics `
            -Name 'EngineExecutionTimeInMillis' `
            -Default 0)
        OutputLocation = [string](Get-OptionalProperty `
            -InputObject $actualResultConfiguration `
            -Name 'OutputLocation' `
            -Default $queryOutputLocation)
        LocalSqlPath = $sqlPath
    }
    $executionPath = Join-Path $localResultDir "$safeLabel-execution.json"
    Write-JsonFile -Path $executionPath -Value $executionRecord

    if ([string]$execution.Status.State -notin @('SUCCEEDED')) {
        throw (
            "Athena statement '$Label' ended in $($execution.Status.State): " +
            $stateReason
        )
    }

    if ($CaptureRows) {
        $rows = Invoke-AthenaNative -FilePath 'aws' -ArgumentList @(
            'athena', 'get-query-results',
            '--profile', $AwsProfile,
            '--region', $primaryRegion,
            '--query-execution-id', $queryExecutionId,
            '--max-items', [string]$MaxResultRows,
            '--output', 'json'
        ) -FailureMessage "Athena statement '$Label' results could not be read." | ConvertFrom-Json
        $rowsPath = Join-Path $localResultDir "$safeLabel-results.json"
        Write-JsonFile -Path $rowsPath -Value $rows
    }

    return [pscustomobject]$executionRecord
}

$executions = New-Object System.Collections.Generic.List[object]
$renderedSchemaPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    'aws-topology-athena-schema-{0}.sql' -f [guid]::NewGuid().ToString('N')
)
try {
    if ($CreateSchema) {
        & (Join-Path $PSScriptRoot 'render-athena-schema.ps1') `
            -SecurityLogBucket $securityLogBucket `
            -AccountId ([string]$identity.Account) `
            -PrimaryRegion $primaryRegion `
            -Database $Database `
            -CloudFrontTable $CloudFrontTable `
            -AlbTable $AlbTable `
            -VpcFlowTable $VpcFlowTable `
            -OutputPath $renderedSchemaPath | Out-Null
        $renderedSchema = [System.IO.File]::ReadAllText($renderedSchemaPath)
        $schemaStatements = @(
            [regex]::Split($renderedSchema, ';\s*(?:\r?\n|$)') |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
        )
        if ($schemaStatements.Count -ne 4) {
            throw "Expected four bounded Athena DDL statements; found $($schemaStatements.Count)."
        }
        for ($index = 0; $index -lt $schemaStatements.Count; $index++) {
            $executions.Add((Invoke-AthenaStatement `
                -Label ('schema-{0:d2}' -f ($index + 1)) `
                -Sql ($schemaStatements[$index] + ';') `
                -CaptureRows $false))
        }
    }

    $executions.Add((Invoke-AthenaStatement `
        -Label $QueryName `
        -Sql $querySql `
        -CaptureRows $true))
}
finally {
    Remove-Item -LiteralPath $renderedSchemaPath -Force -ErrorAction SilentlyContinue
}

$summaryPath = Join-Path $localResultDir 'athena-run-summary.json'
Write-JsonFile -Path $summaryPath -Value ([ordered]@{
    SchemaVersion = 1
    ExperimentId = $ExperimentId
    QueryName = $QueryName
    CreateSchema = [bool]$CreateSchema
    AwsAccountId = [string]$identity.Account
    Region = $primaryRegion
    Database = $Database
    ResultPrefix = $queryOutputLocation
    Executions = $executions.ToArray()
})

Write-Host "Athena Query Pack completed: $summaryPath"
Write-Host 'Run the Evidence Collector for the same ExperimentId to add the bundle manifest and SHA256SUMS.txt.'
