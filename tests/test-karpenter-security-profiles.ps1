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
        throw "Required security profile artifact is missing: $RelativePath"
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
$scenario = Read-RequiredFile 'security-scenario.tf'
$eks = Read-RequiredFile 'eks.tf'
$ssm = Read-RequiredFile 'cluster-addons-ssm.tf'
$ssmTemplate = Read-RequiredFile 'templates\install-cluster-addons.sh.tpl'
$chartValues = Read-RequiredFile 'charts\karpenter-node-config\values.yaml'
$chartTemplate = Read-RequiredFile 'charts\karpenter-node-config\templates\nodeclass.yaml'
$outputs = Read-RequiredFile 'outputs.tf'
$dailyUp = Read-RequiredFile 'daily-up.ps1'
$sessionCommon = Read-RequiredFile 'daily-session-common.ps1'

Assert-Match $variables 'variable\s+"security_scenario_profile"[\s\S]*?default\s*=\s*"hardened"[\s\S]*?contains\(\["hardened",\s*"capital-one-lab"\]' `
    'The security scenario variable must default to hardened and reject unknown profiles.'
Assert-Match $scenario 'hardened_karpenter_metadata_options[\s\S]*?httpPutResponseHopLimit\s*=\s*1[\s\S]*?httpTokens\s*=\s*"required"' `
    'The explicit hardened Karpenter metadata contract is missing.'
Assert-Match $scenario 'primary_karpenter_metadata_options[\s\S]*?capital_one_lab_enabled\s*\?\s*2\s*:\s*1[\s\S]*?capital_one_lab_enabled\s*\?\s*"optional"\s*:\s*"required"' `
    'The Primary Karpenter metadata contract does not switch only the intended lab values.'

Assert-Match $scenario 'resource\s+"aws_iam_role_policy"\s+"primary_karpenter_capital_one_lab"[\s\S]*?count\s*=\s*local\.capital_one_lab_enabled\s*\?\s*1\s*:\s*0' `
    'The lab IAM policy must be absent from the hardened profile.'
Assert-Match $scenario 'role\s*=\s*module\.primary_karpenter\.node_iam_role_name' `
    'The lab IAM policy must attach only to the Primary Karpenter Node Role.'
Assert-Match $scenario 'Action\s*=\s*\["s3:ListBucket"\][\s\S]*?"s3:prefix"\s*=\s*\["validation",\s*"validation/\*"\]' `
    'ListBucket must be limited to the validation prefix.'
Assert-Match $scenario 'Action\s*=\s*\["s3:GetObject"\][\s\S]*?aws_s3_bucket\.primary\.arn}/validation/\*' `
    'GetObject must be limited to Primary validation objects.'
Assert-NotMatch $scenario 's3:(PutObject|DeleteObject)|aws_s3_bucket\.dr|module\.dr_karpenter' `
    'The lab policy must not grant writes or reference DR resources.'

Assert-Match $eks 'primary_karpenter_node_config[\s\S]*?metadataOptions\s*=\s*local\.primary_karpenter_metadata_options' `
    'The local Helm Primary path must receive the selected security metadata.'
Assert-Match $eks 'dr_karpenter_node_config[\s\S]*?metadataOptions\s*=\s*local\.hardened_karpenter_metadata_options' `
    'The local Helm DR path must remain hardened.'
Assert-Match $ssm 'primary_cluster_addons_script[\s\S]*?metadata_http_tokens\s*=\s*local\.primary_karpenter_metadata_options\.httpTokens' `
    'The default SSM Primary path must receive the selected security metadata.'
Assert-Match $ssm 'dr_cluster_addons_script[\s\S]*?metadata_http_tokens\s*=\s*local\.hardened_karpenter_metadata_options\.httpTokens' `
    'The default SSM DR path must remain hardened.'

foreach ($field in @(
    'httpEndpoint',
    'httpProtocolIPv6',
    'httpPutResponseHopLimit',
    'httpTokens'
)) {
    Assert-Match $ssmTemplate ("(?m)^\s+{0}:" -f [regex]::Escape($field)) `
        "The SSM NodeClass template is missing metadataOptions.$field."
    Assert-Match $chartValues ("(?m)^\s+{0}:" -f [regex]::Escape($field)) `
        "The Helm values file is missing metadataOptions.$field."
    Assert-Match $chartTemplate ("(?m)^\s+{0}:" -f [regex]::Escape($field)) `
        "The Helm NodeClass template is missing metadataOptions.$field."
}
Assert-Match $chartValues 'httpPutResponseHopLimit:\s*1[\s\S]*?httpTokens:\s*required' `
    'The standalone Helm chart defaults must remain hardened.'

Assert-Match $outputs 'output\s+"security_scenario_profile"' `
    'The applied security scenario must be recorded as a Terraform output.'
Assert-Match $outputs 'output\s+"security_scenario_features"[\s\S]*?primary_metadata_options[\s\S]*?dr_metadata_options' `
    'Expected Primary and DR metadata controls must be visible without exposing credentials.'
Assert-Match $dailyUp '\[ValidateSet\(''hardened'',\s*''capital-one-lab''\)\][\s\S]*?\$SecurityScenarioProfile' `
    'daily-up must expose only the reviewed security scenarios.'
Assert-Match $dailyUp '-var=security_scenario_profile=\$SecurityScenarioProfile' `
    'daily-up must pass the selected security scenario to Terraform.'
Assert-Match $dailyUp 'ConfirmSecurityScenario\s+-cne\s+''ENABLE CAPITAL ONE LAB''[\s\S]*?Start-DailySessionGuard' `
    'The lab confirmation must be checked after Plan and before the session guard and Apply.'
Assert-Match $dailyUp 'Start-DailySessionGuard[\s\S]*?-SecurityScenarioProfile\s+\$SecurityScenarioProfile' `
    'daily-up must persist the selected security scenario in the Daily Session.'
Assert-Match $sessionCommon 'existing\.SecurityScenarioProfile[\s\S]*?Run Daily Down before changing it' `
    'An active Daily Session must reject security scenario changes.'

$helm = Get-Command 'helm' -ErrorAction SilentlyContinue
if ($helm) {
    $chartPath = Join-Path $root 'charts\karpenter-node-config'
    $rendered = & $helm.Source template security-profile-test $chartPath `
        --set 'clusterName=test-cluster' `
        --set 'projectName=test-project' `
        --set 'nodeRole=test-role' `
        --set 'metadataOptions.httpEndpoint=enabled' `
        --set 'metadataOptions.httpProtocolIPv6=disabled' `
        --set 'metadataOptions.httpPutResponseHopLimit=2' `
        --set 'metadataOptions.httpTokens=optional' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Helm could not render the lab NodeClass: $rendered"
    }
    Assert-Match $rendered 'httpPutResponseHopLimit:\s*2[\s\S]*?httpTokens:\s*"?optional"?' `
        'The Helm-rendered lab NodeClass does not contain Hop 2 and optional tokens.'
} else {
    Write-Warning 'helm is unavailable; mandatory static wiring checks passed, but live Helm rendering was skipped.'
}

Write-Host 'Karpenter security profile contracts passed.'
