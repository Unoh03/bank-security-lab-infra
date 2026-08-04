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
        throw "Required lifecycle artifact is missing: $RelativePath"
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

$variables = Read-RequiredFile 'variables.tf'
$main = Read-RequiredFile 'main.tf'
$data = Read-RequiredFile 'data.tf'
$edge = Read-RequiredFile 'edge.tf'
$storage = Read-RequiredFile 'storage-access.tf'
$eks = Read-RequiredFile 'eks.tf'
$outputs = Read-RequiredFile 'outputs.tf'
$foundationEdge = Read-RequiredFile 'foundation\edge.tf'
$foundationOutputs = Read-RequiredFile 'foundation\outputs.tf'
$dailyUp = Read-RequiredFile 'daily-up.ps1'
$dailyCommon = Read-RequiredFile 'daily-common.ps1'
$sessionCommon = Read-RequiredFile 'daily-session-common.ps1'
$setupFoundation = Read-RequiredFile 'setup-foundation.ps1'

Assert-Match $variables 'variable\s+"runtime_profile"[\s\S]*?minimal[\s\S]*?dr-test[\s\S]*?full' `
    'runtime_profile must accept minimal, dr-test, and full.'
Assert-Match $variables 'variable\s+"enable_valkey"[\s\S]*?default\s*=\s*false' `
    'Valkey must be opt-in.'
Assert-Match $variables 'variable\s+"enable_efs"[\s\S]*?default\s*=\s*false' `
    'EFS must be opt-in.'

Assert-Match $main 'runtime_profiles\s*=\s*\{' `
    'Runtime profile settings must be defined once in locals.'
Assert-Match $main 'module\s+"dr_vpc"\s*\{[\s\S]*?count\s*=\s*local\.enable_dr_runtime\s*\?\s*1\s*:\s*0' `
    'DR VPC must be absent outside a DR-enabled profile.'
Assert-Match $data 'resource\s+"aws_db_instance"\s+"primary"[\s\S]*?multi_az\s*=\s*local\.primary_rds_multi_az' `
    'Primary RDS Multi-AZ must be profile-controlled.'
Assert-Match $data 'resource\s+"aws_db_instance"\s+"dr_replica"[\s\S]*?count\s*=\s*local\.enable_dr_runtime\s*\?\s*1\s*:\s*0' `
    'DR RDS replica must be absent in minimal.'
Assert-Match $data 'resource\s+"aws_elasticache_replication_group"\s+"primary"[\s\S]*?count\s*=\s*var\.enable_valkey\s*\?\s*1\s*:\s*0' `
    'Primary Valkey must be opt-in.'
Assert-Match $storage 'resource\s+"aws_efs_file_system"\s+"primary"[\s\S]*?count\s*=\s*var\.enable_efs\s*\?\s*1\s*:\s*0' `
    'Primary EFS must be opt-in.'
Assert-Match $eks 'enable_efs' `
    'The EFS CSI add-on must follow the EFS opt-in.'
Assert-Match $outputs 'output\s+"runtime_profile"' `
    'The applied runtime profile must be stored as a Terraform output.'
Assert-Match $outputs 'output\s+"runtime_features"[\s\S]*?valkey[\s\S]*?efs[\s\S]*?https_redirect' `
    'The applied optional feature selection must be stored as a Terraform output.'

Assert-NotMatch $edge '(resource|data)\s+"aws_route53_zone"' `
    'The Daily root must not own or independently discover the Hosted Zone.'
Assert-NotMatch $edge 'resource\s+"aws_acm_certificate"' `
    'The Daily root must not own the CloudFront ACM certificate.'
Assert-Match $foundationEdge 'data\s+"aws_route53_zone"\s+"existing"' `
    'Foundation must discover the existing public Hosted Zone.'
Assert-Match $foundationEdge 'resource\s+"aws_acm_certificate"\s+"cloudfront"' `
    'Foundation must own the CloudFront ACM certificate.'
Assert-Match $foundationOutputs 'output\s+"cloudfront_acm_certificate_arn"' `
    'Foundation must export the CloudFront certificate ARN.'
Assert-Match $foundationOutputs 'output\s+"foundation_contract_version"[\s\S]*?value\s*=\s*2' `
    'Foundation must expose the fail-closed v2 output contract.'
Assert-Match $dailyCommon 'Foundation contract v2 output is missing' `
    'Daily preflight must fail closed when Foundation v2 outputs are absent.'
Assert-Match $setupFoundation '\$DomainName[\s\S]*?-var=domain_name=\$DomainName' `
    'Foundation setup must expose and pass the persistent domain input.'
Assert-Match $setupFoundation '\[Parameter\(Mandatory\)\][\s\S]*?\[AllowEmptyString\(\)\][\s\S]*?\[string\]\$DomainName' `
    'Foundation setup must require an explicit domain decision to prevent accidental certificate removal.'

Assert-Match $variables 'variable\s+"enable_https_redirect"[\s\S]*?default\s*=\s*true' `
    'HTTPS redirect must remain the safe default.'
Assert-Match $edge 'viewer_protocol_policy\s*=\s*var\.enable_https_redirect\s*\?\s*"redirect-to-https"\s*:\s*"allow-all"' `
    'CloudFront viewer protocol policy must implement the T1 toggle.'

Assert-Match $dailyUp '\[ValidateSet\(''minimal'',\s*''dr-test'',\s*''full''\)\][\s\S]*?\$RuntimeProfile' `
    'daily-up must expose the reviewed runtime profiles.'
Assert-Match $dailyUp '\[ValidateSet\(''On'',\s*''Off''\)\][\s\S]*?\$WatchdogMode' `
    'daily-up must expose the Watchdog On/Off toggle.'
Assert-Match $dailyUp '-var=runtime_profile=\$RuntimeProfile' `
    'daily-up must pass the selected profile to Terraform.'
Assert-Match $dailyUp '-var=enable_valkey=\$enableValkeyValue[\s\S]*?-var=enable_efs=\$enableEfsValue[\s\S]*?-var=enable_https_redirect=\$enableHttpsRedirectValue' `
    'daily-up must pass every reviewed optional feature toggle to Terraform.'
Assert-Match $dailyUp 'Start-DailySessionGuard[\s\S]*?-WatchdogMode\s+\$WatchdogMode' `
    'daily-up must pass WatchdogMode to the session guard.'
Assert-Match $sessionCommon 'WatchdogMode[\s\S]*?GuardDisabled[\s\S]*?Register-DailySessionScheduledTask' `
    'The session guard must preserve deadlines while skipping task registration in Off mode.'

Write-Host 'Runtime profile, lifecycle, HTTPS, and Watchdog static contracts passed.'
