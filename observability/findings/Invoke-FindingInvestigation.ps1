#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{32}$')]
    [string]$FindingId,

    [string]$DetectorId = '',
    [string]$Region = '',
    [string]$RuntimeProfile = 'unknown',
    [string]$ScenarioId = 'F2',
    [string]$FoundationRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$ExpectedAccountId = '433048100798',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [string]$InputFindingPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $FoundationRoot) {
    $FoundationRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\foundation')).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'f2-investigation-' +
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}
if ($ScenarioId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,40}$') {
    throw 'ScenarioId contains unsafe characters.'
}

function Invoke-FindingNative {
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

    Write-Utf8File -Path $Path -Text ($Value | ConvertTo-Json -Depth 40)
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
    foreach ($property in @($InputObject.PSObject.Properties)) {
        if ([string]$property.Name -ieq $Name -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    return $Default
}

function Get-NestedOptionalProperty {
    param(
        $InputObject,
        [Parameter(Mandatory)][string[]]$Path,
        $Default = $null
    )

    $current = $InputObject
    foreach ($name in $Path) {
        $current = Get-OptionalProperty -InputObject $current -Name $name
        if ($null -eq $current) {
            return $Default
        }
    }
    return $current
}

function Convert-ToUtcTimestamp {
    param($Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed
    )) {
        return $null
    }
    return $parsed.ToUniversalTime()
}

function Add-UniqueFindingEntity {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Entities,
        [Parameter(Mandatory)][string]$Category,
        $Value
    )

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or $text.Length -gt 512) {
        return
    }
    $text = $text.Trim()
    if (-not $Entities.Contains($Category)) {
        return
    }
    if (-not $Entities[$Category].Contains($text)) {
        [void]$Entities[$Category].Add($text)
    }
}

function Visit-FindingValue {
    param(
        $Value,
        [string]$PropertyName,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Entities
    )

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        switch -Regex ($PropertyName) {
            '^(ipAddressV4|ipAddressV6|clientIp|sourceIp)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category source_ips -Value $Value
            }
            '^(instanceId|containerInstanceId)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category compute_ids -Value $Value
            }
            '^(clusterName|kubernetesClusterName)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category cluster_names -Value $Value
            }
            '^(bucketName|functionName|resourceName|resourceArn|arn)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category resource_names -Value $Value
            }
            '^(principalId|userName|roleName|sessionName)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category identities -Value $Value
            }
            '^(domain|domainName|hostname)$' {
                Add-UniqueFindingEntity -Entities $Entities -Category domains -Value $Value
            }
        }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            Visit-FindingValue -Value $Value[$key] -PropertyName ([string]$key) -Entities $Entities
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            Visit-FindingValue -Value $item -PropertyName $PropertyName -Entities $Entities
        }
        return
    }
    foreach ($property in @($Value.PSObject.Properties)) {
        # AccessKeyId is intentionally excluded from the normalized entity set.
        if ([string]$property.Name -ieq 'AccessKeyId') {
            continue
        }
        Visit-FindingValue `
            -Value $property.Value `
            -PropertyName ([string]$property.Name) `
            -Entities $Entities
    }
}

function Get-FindingQueryPlan {
    param(
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter(Mandatory)][string]$ActionType,
        [Parameter(Mandatory)][string[]]$SourceIps
    )

    $material = "$FindingType $ResourceType $ActionType"
    $queries = New-Object System.Collections.Generic.List[object]
    [void]$queries.Add([ordered]@{
        Name = 'guardduty-finding'
        Engine = 'CloudWatchLogsInsights'
        QueryFile = 'cloudwatch\12_guardduty_findings.cwli'
        Required = $true
        Reason = 'Confirm EventBridge delivery of the Finding that started the investigation.'
    })
    [void]$queries.Add([ordered]@{
        Name = 'cloudtrail-security-changes'
        Engine = 'CloudWatchLogsInsights'
        QueryFile = 'cloudwatch\04_cloudtrail_security_changes.cwli'
        Required = $false
        Reason = 'Check nearby AWS control-plane activity without assuming the attacker or action.'
    })
    if ($material -match '(?i)EKS|Kubernetes|Container') {
        [void]$queries.Add([ordered]@{
            Name = 'kubernetes-sensitive-actions'
            Engine = 'CloudWatchLogsInsights'
            QueryFile = 'cloudwatch\03_kubectl_exec_and_secret_access.cwli'
            Required = $false
            Reason = 'Correlate Kubernetes API, exec, and Secret access activity.'
        })
    }
    if ($material -match '(?i)IAM|AccessKey|S3|Credential') {
        [void]$queries.Add([ordered]@{
            Name = 'pod-identity-and-s3-activity'
            Engine = 'CloudWatchLogsInsights'
            QueryFile = 'cloudwatch\07_pod_identity_and_s3_activity.cwli'
            Required = $false
            Reason = 'Correlate identity and S3 data-plane activity near the Finding window.'
        })
    }
    if ($material -match '(?i)EC2|Network|Port|DenialOfService|Recon') {
        [void]$queries.Add([ordered]@{
            Name = 'vpc-reject'
            Engine = 'Athena'
            QueryName = 'vpc-reject'
            Required = $false
            Reason = 'Check rejected network traffic for the Finding entity and time window.'
        })
    }
    if ($material -match '(?i)Web|HTTP|ALB|CloudFront') {
        [void]$queries.Add([ordered]@{
            Name = 'waf-requests'
            Engine = 'CloudWatchLogsInsights'
            QueryFile = 'cloudwatch\09_review_waf_requests.cwli'
            Required = $false
            Reason = 'Check whether the request reached or was handled by the edge control.'
        })
        [void]$queries.Add([ordered]@{
            Name = 'alb-window'
            Engine = 'Athena'
            QueryName = 'alb-window'
            Required = $false
            Reason = 'Correlate ALB requests in the derived Finding window.'
        })
    }

    return [ordered]@{
        DerivedFromFinding = $true
        SourceIps = @($SourceIps)
        Queries = @($queries | ForEach-Object { $_ })
    }
}

$rawJson = ''
if ($InputFindingPath) {
    $resolvedInput = (Resolve-Path -LiteralPath $InputFindingPath).Path
    $rawJson = [System.IO.File]::ReadAllText($resolvedInput)
} else {
    $identity = Invoke-FindingNative -FilePath 'aws' -ArgumentList @(
        'sts', 'get-caller-identity',
        '--profile', $AwsProfile,
        '--output', 'json'
    ) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
    if ([string]$identity.Account -cne $ExpectedAccountId) {
        throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
    }
    if (-not $DetectorId) {
        $DetectorId = Invoke-FindingNative -FilePath 'terraform' -ArgumentList @(
            "-chdir=$FoundationRoot", 'output', '-raw', 'guardduty_detector_id'
        ) -FailureMessage 'The Foundation GuardDuty detector output is unavailable.'
    }
    if (-not $Region) {
        $Region = Invoke-FindingNative -FilePath 'terraform' -ArgumentList @(
            "-chdir=$FoundationRoot", 'output', '-raw', 'aws_region'
        ) -FailureMessage 'The Foundation region output is unavailable.'
    }
    $rawJson = Invoke-FindingNative -FilePath 'aws' -ArgumentList @(
        'guardduty', 'get-findings',
        '--profile', $AwsProfile,
        '--region', $Region,
        '--detector-id', $DetectorId,
        '--finding-ids', $FindingId,
        '--output', 'json'
    ) -FailureMessage "GuardDuty Finding '$FindingId' could not be read."
}

$parsed = $rawJson | ConvertFrom-Json
$candidateFindings = @(Get-OptionalProperty -InputObject $parsed -Name 'Findings' -Default @())
if ($candidateFindings.Count -eq 0) {
    $candidateFindings = @($parsed)
}
$finding = @(
    $candidateFindings | Where-Object {
        [string](Get-OptionalProperty -InputObject $_ -Name 'Id' -Default '') -ceq $FindingId
    }
)
if ($finding.Count -ne 1) {
    throw "Expected exactly one GuardDuty Finding '$FindingId'; found $($finding.Count)."
}
$finding = $finding[0]

$findingAccount = [string](Get-OptionalProperty -InputObject $finding -Name 'AccountId' -Default '')
if ($findingAccount -and $findingAccount -cne $ExpectedAccountId) {
    throw "Finding account mismatch: expected=$ExpectedAccountId actual=$findingAccount"
}
$findingRegion = [string](Get-OptionalProperty -InputObject $finding -Name 'Region' -Default $Region)
$findingType = [string](Get-OptionalProperty -InputObject $finding -Name 'Type' -Default 'unknown')
$title = [string](Get-OptionalProperty -InputObject $finding -Name 'Title' -Default '')
$severity = Get-OptionalProperty -InputObject $finding -Name 'Severity' -Default 0
$resourceType = [string](Get-NestedOptionalProperty `
    -InputObject $finding -Path @('Resource', 'ResourceType') -Default 'unknown')
$actionType = [string](Get-NestedOptionalProperty `
    -InputObject $finding -Path @('Service', 'Action', 'ActionType') -Default 'unknown')

$timeCandidates = New-Object System.Collections.Generic.List[datetimeoffset]
foreach ($value in @(
    (Get-NestedOptionalProperty -InputObject $finding -Path @('Service', 'EventFirstSeen')),
    (Get-NestedOptionalProperty -InputObject $finding -Path @('Service', 'EventLastSeen')),
    (Get-OptionalProperty -InputObject $finding -Name 'CreatedAt'),
    (Get-OptionalProperty -InputObject $finding -Name 'UpdatedAt')
)) {
    $parsedTime = Convert-ToUtcTimestamp -Value $value
    if ($null -ne $parsedTime) {
        [void]$timeCandidates.Add($parsedTime)
    }
}
if ($timeCandidates.Count -eq 0) {
    [void]$timeCandidates.Add([datetimeoffset]::UtcNow)
}
$firstSeen = ($timeCandidates | Sort-Object | Select-Object -First 1)
$lastSeen = ($timeCandidates | Sort-Object | Select-Object -Last 1)
$windowStart = $firstSeen.AddMinutes(-5)
$windowEnd = $lastSeen.AddMinutes(5)

$entities = [ordered]@{
    source_ips = New-Object System.Collections.Generic.List[string]
    compute_ids = New-Object System.Collections.Generic.List[string]
    cluster_names = New-Object System.Collections.Generic.List[string]
    resource_names = New-Object System.Collections.Generic.List[string]
    identities = New-Object System.Collections.Generic.List[string]
    domains = New-Object System.Collections.Generic.List[string]
}
Visit-FindingValue -Value $finding -PropertyName 'Finding' -Entities $entities
$safeEntities = [ordered]@{}
foreach ($category in $entities.Keys) {
    $safeEntities[$category] = @($entities[$category] | Sort-Object -Unique)
}

$isSample = $title.StartsWith('[SAMPLE]', [System.StringComparison]::OrdinalIgnoreCase)
$bundleRoot = Join-Path $EvidenceRoot $ExperimentId
$rawPath = Join-Path $bundleRoot 'source\aws\guardduty-finding.raw.json'
$normalizedPath = Join-Path $bundleRoot 'source\aws\guardduty-finding.normalized.json'
$planPath = Join-Path $bundleRoot 'queries\f2-investigation-plan.json'
Write-Utf8File -Path $rawPath -Text $rawJson

$normalized = [ordered]@{
    finding_id = $FindingId
    timestamp = $lastSeen.ToString('o')
    window_start_utc = $windowStart.ToString('o')
    window_end_utc = $windowEnd.ToString('o')
    runtime_profile = $RuntimeProfile
    account_id = if ($findingAccount) { $findingAccount } else { $ExpectedAccountId }
    region = $findingRegion
    source = 'GuardDuty'
    severity = $severity
    finding_type = $findingType
    title = $title
    sample = $isSample
    resource_type = $resourceType
    action_type = $actionType
    entities = $safeEntities
    evidence_pointer = 'source/aws/guardduty-finding.raw.json'
    scenario_id = $ScenarioId
}
Write-JsonFile -Path $normalizedPath -Value $normalized

$queryPlan = Get-FindingQueryPlan `
    -FindingType $findingType `
    -ResourceType $resourceType `
    -ActionType $actionType `
    -SourceIps @($safeEntities.source_ips | ForEach-Object { [string]$_ })
$investigation = [ordered]@{
    finding_id = $FindingId
    sample = $isSample
    window_start_utc = $windowStart.ToString('o')
    window_end_utc = $windowEnd.ToString('o')
    input_contract = 'FindingId only; source IP, attack type, and time window are derived.'
    caveat = if ($isSample) {
        'AWS sample findings validate delivery and investigation wiring; they do not prove matching workload activity.'
    } else {
        'A finding is an investigation lead, not standalone proof of compromise.'
    }
    query_plan = $queryPlan
}
Write-JsonFile -Path $planPath -Value $investigation

Write-Host "Finding normalized: $normalizedPath"
Write-Host "Investigation plan: $planPath"
Write-Output ([pscustomobject]@{
    FindingId = $FindingId
    Sample = $isSample
    WindowStartUtc = $windowStart.ToString('o')
    WindowEndUtc = $windowEnd.ToString('o')
    NormalizedPath = $normalizedPath
    QueryPlanPath = $planPath
})
