#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StartKst,
    [Parameter(Mandatory)][string]$EndKst,
    [string]$SourceIp = '',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{2,60}$')]
    [string]$Label = 'security-window',
    [string]$TerraformRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$Region = 'ap-northeast-2',
    [string]$DrRegion = 'ap-northeast-1',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ProjectName = 'aws-topology',
    [string]$AutomationConfigPath = '',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [switch]$SkipAthena,
    [switch]$CreateAthenaSchema,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = $PSScriptRoot
}
if (-not $AutomationConfigPath) {
    $AutomationConfigPath = Join-Path $TerraformRoot 'automation\project.psd1'
}

. (Join-Path $TerraformRoot 'daily-common.ps1')
$dailyModule = Join-Path $TerraformRoot 'automation\Daily.Automation.psm1'
$evidenceModule = Join-Path $TerraformRoot 'automation\Evidence.Collection.psm1'
$reviewModule = Join-Path $TerraformRoot 'automation\Security.Review.psm1'
Import-Module $dailyModule -Force
Import-Module $evidenceModule -Force
Import-Module $reviewModule -Force

$config = Import-DailyAutomationConfig -Path $AutomationConfigPath
if (-not $config.Evidence.ContainsKey('Review') -or -not $config.Evidence.Review) {
    throw 'Evidence.Review configuration is required.'
}
$reviewConfig = $config.Evidence.Review
foreach ($field in @('ScenarioId', 'MaxWindowHours', 'CloudWatchSources', 'AthenaQueries')) {
    if (-not $reviewConfig.ContainsKey($field)) {
        throw "Evidence.Review field is required: $field"
    }
}

function ConvertFrom-KstInput {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    [string[]]$formats = @(
        'yyyy-MM-dd HH:mm',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-ddTHH:mm',
        'yyyy-MM-ddTHH:mm:ss'
    )
    $local = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
        $Value,
        $formats,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$local
    )) {
        throw "$Name must use KST yyyy-MM-dd HH:mm[:ss]."
    }
    return [datetimeoffset]::new(
        [datetime]::SpecifyKind($local, [DateTimeKind]::Unspecified),
        [timespan]::FromHours(9)
    )
}

function Write-SecurityReviewLocalText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $Path,
        $Text,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

$start = ConvertFrom-KstInput -Value $StartKst -Name 'StartKst'
$end = ConvertFrom-KstInput -Value $EndKst -Name 'EndKst'
if ($end -le $start) {
    throw 'EndKst must be later than StartKst.'
}
$windowHours = ($end - $start).TotalHours
if ($windowHours -gt [double]$reviewConfig.MaxWindowHours) {
    throw "Security review window exceeds $($reviewConfig.MaxWindowHours) hours."
}
if ($SourceIp) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($SourceIp, [ref]$parsedIp)) {
        throw 'SourceIp must be a valid IPv4 or IPv6 address.'
    }
    $SourceIp = $parsedIp.ToString()
}
if (-not $ExperimentId) {
    $ExperimentId = 'review-' + $start.ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + $Label.ToLowerInvariant()
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}

Write-Host 'Security review preview'
Write-Host "  KST: $($start.ToString('yyyy-MM-dd HH:mm:ss zzz')) -> $($end.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
Write-Host "  UTC: $($start.ToUniversalTime().ToString('o')) -> $($end.ToUniversalTime().ToString('o'))"
Write-Host "  Source IP: $(if ($SourceIp) { $SourceIp } else { 'all' })"
Write-Host "  CloudWatch queries: $(@($reviewConfig.CloudWatchSources).Count)"
Write-Host "  Athena queries: $(if ($SkipAthena) { 0 } else { @($reviewConfig.AthenaQueries).Count })"
Write-Host "  Create Athena schema: $([bool]$CreateAthenaSchema)"
Write-Host '  Terraform/AWS resource mutation: none, except optional Athena/Glue schema creation'

if ($ConfirmRun -cne 'RUN SECURITY REVIEW') {
    Write-Host "Preview only. Add -ConfirmRun 'RUN SECURITY REVIEW' to collect and analyze this window."
    return
}

foreach ($command in @('terraform', 'aws')) {
    Assert-CommandAvailable -Name $command
}
$identity = Get-AwsIdentity -Profile $AwsProfile -Region $Region
Assert-AwsIdentity -Identity $identity -ExpectedAccountId $ExpectedAccountId
Write-Host "AWS read-only review: account=$($identity.Account), primary=$Region, dr=$DrRegion"

$context = @{
    TerraformRoot  = $TerraformRoot
    FoundationRoot = Join-Path $TerraformRoot 'foundation'
    AwsProfile     = $AwsProfile
    AccountId      = [string]$identity.Account
    ProjectName    = $ProjectName
    PrimaryRegion  = $Region
    DrRegion       = $DrRegion
}
$application = Get-DailyApplication -Config $config -Name 'dvwa'
$sourceRoot = [string]$application.SourceRootDefault
if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
    try {
        $gitCommit = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
            '-C', $sourceRoot, 'rev-parse', 'HEAD'
        ) -FailureMessage 'DVWA Git commit could not be read.'
        $context.GitCommit = $gitCommit.Trim()
    } catch {
        Write-Warning 'DVWA Git commit was not added to the Evidence manifest.'
    }
    $valuesPath = Join-Path $sourceRoot ([string]$application.ValuesRelativePath)
    if (Test-Path -LiteralPath $valuesPath -PathType Leaf) {
        try {
            $declaredImage = Get-DeclaredImage -ValuesPath $valuesPath
            $context.ImageSha = [string]$declaredImage.Tag
        } catch {
            Write-Warning 'Declared DVWA Image was not added to the Evidence manifest.'
        }
    }
}

$collection = Invoke-DailyEvidenceCollection `
    -Config $config `
    -Context $context `
    -EvidenceRoot $EvidenceRoot `
    -ExperimentId $ExperimentId `
    -ScenarioId ([string]$reviewConfig.ScenarioId) `
    -StartTimeUtc $start.UtcDateTime `
    -EndTimeUtc $end.UtcDateTime `
    -EventTailSeconds 2 `
    -S3DeliveryGraceMinutes 5 `
    -RunQueries `
    -Phase 'security-review'

$bundleRoot = [string]$collection.BundleRoot
if (-not $SkipAthena) {
    $athenaRunner = Join-Path $TerraformRoot 'observability\Invoke-AthenaQueryPack.ps1'
    $athenaQueries = @($reviewConfig.AthenaQueries)
    for ($index = 0; $index -lt $athenaQueries.Count; $index++) {
        $queryName = [string]$athenaQueries[$index]
        try {
            $arguments = @{
                QueryName = $queryName
                StartUtc = $start.ToUniversalTime().ToString('o')
                EndUtc = $end.ToUniversalTime().ToString('o')
                SourceIp = $SourceIp
                AwsProfile = $AwsProfile
                ExpectedAccountId = $ExpectedAccountId
                EvidenceRoot = if ($EvidenceRoot) { $EvidenceRoot } else { [string]$collection.Root }
                ExperimentId = $ExperimentId
                ConfirmRun = 'RUN ATHENA QUERY PACK'
            }
            if ($CreateAthenaSchema -and $index -eq 0) {
                $arguments.CreateSchema = $true
            }
            & $athenaRunner @arguments
        } catch {
            $safeError = Protect-SecurityEvidenceText -Text $_.Exception.Message
            $errorPath = Join-Path $bundleRoot "results\athena\$queryName-wrapper-error.txt"
            Write-SecurityReviewLocalText -Path $errorPath -Text ($safeError + "`n")
            Write-Warning "Athena query failed and was retained as partial evidence: $queryName"
        }
    }
}

$review = Export-SecurityReview `
    -ReviewConfig $reviewConfig `
    -BundleRoot $bundleRoot `
    -StartTimeUtc $start.UtcDateTime `
    -EndTimeUtc $end.UtcDateTime `
    -SourceIp $SourceIp `
    -Label $Label `
    -HashAlgorithm ([string]$config.Evidence.HashAlgorithm)

Write-Host "Security review completed: $($review.IncidentId)"
Write-Host "  Events: $($review.EventCount)"
Write-Host "  Summary: $($review.SummaryPath)"
Write-Host "  Timeline: $($review.TimelinePath)"
Write-Host "  Triage: $($review.TriagePath)"
if ($review.MissingSources.Count -gt 0) {
    Write-Warning "Missing or unexecuted sources: $($review.MissingSources -join ', ')"
}
