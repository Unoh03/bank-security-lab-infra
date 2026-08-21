#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$storagePath = Join-Path $root 'storage-observability.tf'
$scenarioPath = Join-Path $root 'security-scenario.tf'
$outputsPath = Join-Path $root 'outputs.tf'
$foundationPath = Join-Path $root 'foundation\observability.tf'
$foundationOutputsPath = Join-Path $root 'foundation\outputs.tf'

foreach ($path in @($storagePath, $scenarioPath, $outputsPath, $foundationPath, $foundationOutputsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Capital One secondary-control file is missing: $path"
    }
}

$storage = Get-Content -LiteralPath $storagePath -Raw
$scenario = Get-Content -LiteralPath $scenarioPath -Raw
$outputs = Get-Content -LiteralPath $outputsPath -Raw
$foundation = Get-Content -LiteralPath $foundationPath -Raw
$foundationOutputs = Get-Content -LiteralPath $foundationOutputsPath -Raw

function Assert-Contains {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Text -notmatch $Pattern) { throw $Message }
}

Assert-Contains $storage 'resource\s+"aws_s3_bucket"\s+"capital_one_secondary_control"' `
    'The secondary Capital One control bucket is missing.'
Assert-Contains $storage 'capital_one_secondary_control_enabled\s*=\s*local\.capital_one_lab_enabled\s*&&\s*var\.runtime_profile\s*==\s*"minimal"' `
    'The secondary control fixture is not restricted to minimal + capital-one-lab.'
if ([regex]::Matches($storage, 'count\s*=\s*local\.capital_one_secondary_control_enabled\s*\?\s*1\s*:\s*0').Count -ne 5) {
    throw 'Every secondary and other-prefix control component must use the single minimal + capital-one-lab condition.'
}
Assert-Contains $storage 'bucket_prefix\s*=\s*"\$\{local\.name\}-cap1-secondary-"' `
    'The secondary control bucket does not use the fixed project prefix.'
$secondaryPrefixMatch = [regex]::Match(
    $storage,
    'bucket_prefix\s*=\s*"\$\{local\.name\}-(?<Suffix>[^"]+)"'
)
if (-not $secondaryPrefixMatch.Success) {
    throw 'The secondary control bucket prefix could not be parsed.'
}
$resolvedSecondaryPrefix = 'aws-topology-' + $secondaryPrefixMatch.Groups['Suffix'].Value
if ($resolvedSecondaryPrefix.Length -gt 37) {
    throw "The secondary control bucket prefix exceeds the AWS provider limit: $($resolvedSecondaryPrefix.Length) > 37."
}
Assert-Contains $storage 'resource\s+"aws_s3_bucket"\s+"capital_one_secondary_control"[\s\S]*?force_destroy\s*=\s*false' `
    'The secondary control bucket must fail closed on unexpected objects during teardown.'
Assert-Contains $storage 'resource\s+"aws_s3_bucket_server_side_encryption_configuration"\s+"capital_one_secondary_control"[\s\S]*?sse_algorithm\s*=\s*"AES256"' `
    'The secondary control bucket must use SSE-S3.'
Assert-Contains $storage 'resource\s+"aws_s3_bucket_public_access_block"\s+"capital_one_secondary_control"[\s\S]*?block_public_acls\s*=\s*true[\s\S]*?block_public_policy\s*=\s*true[\s\S]*?ignore_public_acls\s*=\s*true[\s\S]*?restrict_public_buckets\s*=\s*true' `
    'The secondary control bucket is not private-by-default.'
Assert-Contains $storage 'capital_one_secondary_control_object_key\s*=\s*"validation/capital-one-demo\.csv"' `
    'The secondary control object key is not the approved deterministic key.'
Assert-Contains $storage 'resource\s+"aws_s3_object"\s+"capital_one_secondary_control"[\s\S]*?key\s*=\s*local\.capital_one_secondary_control_object_key[\s\S]*?FAKE_TRAINING_DATA[\s\S]*?record-count\s*=\s*"5"' `
    'The secondary control object is not the fixed harmless fake-data fixture.'
Assert-Contains $storage 'capital_one_other_prefix_control_object_key\s*=\s*"other-prefix/capital-one-demo\.csv"' `
    'The other-prefix control object key is not fixed outside validation/.'
Assert-Contains $storage 'resource\s+"aws_s3_object"\s+"capital_one_other_prefix_control"[\s\S]*?count\s*=\s*local\.capital_one_secondary_control_enabled[\s\S]*?bucket\s*=\s*aws_s3_bucket\.primary\.id[\s\S]*?key\s*=\s*local\.capital_one_other_prefix_control_object_key[\s\S]*?content\s*=\s*local\.capital_one_secondary_control_csv[\s\S]*?record-count\s*=\s*"5"' `
    'The other-prefix fixture is not the fixed harmless object in the Primary bucket.'
Assert-Contains $storage 'resource\s+"aws_s3_bucket"\s+"primary"[\s\S]*?force_destroy\s*=\s*true' `
    'The versioned Primary bucket cannot clean up the managed other-prefix fixture during Daily Down.'

$csvMatch = [regex]::Match(
    $storage,
    'capital_one_secondary_control_csv\s*=\s*format\("%s\\n",\s*trimspace\(<<-CSV\r?\n(?<body>[\s\S]*?)\r?\n\s*CSV\r?\n\s*\)\)',
    [Text.RegularExpressions.RegexOptions]::Singleline
)
if (-not $csvMatch.Success) { throw 'The deterministic fake-data CSV body could not be located.' }
$actualCsv = ((@($csvMatch.Groups['body'].Value -split '\r?\n') |
    ForEach-Object { $_.TrimStart() }) -join "`n").Trim() + "`n"
$expectedCsv = @'
training_marker,record_id,customer_name,email,account_last4
FAKE_TRAINING_DATA,CAP-001,Demo Customer 01,demo01@example.invalid,0001
FAKE_TRAINING_DATA,CAP-002,Demo Customer 02,demo02@example.invalid,0002
FAKE_TRAINING_DATA,CAP-003,Demo Customer 03,demo03@example.invalid,0003
FAKE_TRAINING_DATA,CAP-004,Demo Customer 04,demo04@example.invalid,0004
FAKE_TRAINING_DATA,CAP-005,Demo Customer 05,demo05@example.invalid,0005
'@
$expectedCsv = $expectedCsv.Trim() + "`n"
if ($actualCsv -cne $expectedCsv) { throw 'A control object no longer uses the exact approved fake-data CSV.' }
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $actualHash = ([BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actualCsv))
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}
if ($actualHash -cne '625dad237e31a1ba4c6de1b0bf0153c2f62e56f5b6a18d97242d4c41665a4d9e') {
    throw 'The deterministic control-object SHA-256 changed.'
}
if ($storage -match 'aws_s3_bucket_versioning"\s+"capital_one_secondary_control|aws_s3_bucket_lifecycle_configuration"\s+"capital_one_secondary_control') {
    throw 'The disposable secondary control fixture must not leave versions that block Daily Down.'
}

$scenarioMatch = [regex]::Match(
    $scenario,
    'resource\s+"aws_iam_role_policy"\s+"primary_karpenter_capital_one_lab"[\s\S]*?policy\s*=\s*jsonencode\(\{([\s\S]*?)\n\s*\}\)\n\}',
    [Text.RegularExpressions.RegexOptions]::Singleline
)
if (-not $scenarioMatch.Success) { throw 'The Capital One Node Role policy could not be located.' }
$policy = $scenarioMatch.Groups[1].Value
Assert-Contains $policy 'ReadSecondaryControlObject' `
    'The compromised Node Role lacks the secondary control statement.'
Assert-Contains $policy 'local\.capital_one_secondary_control_enabled\s*\?\s*\[' `
    'The secondary control IAM statement is not conditional on minimal + capital-one-lab.'
Assert-Contains $policy 'Action\s*=\s*\["s3:GetObject"\][\s\S]*?aws_s3_bucket\.capital_one_secondary_control\[0\]\.arn[\s\S]*?capital_one_secondary_control_object_key' `
    'The secondary control grant is not exact-object GetObject only.'
Assert-Contains $policy 'ReadOtherPrefixControlObject[\s\S]*?Action\s*=\s*\["s3:GetObject"\][\s\S]*?aws_s3_bucket\.primary\.arn[\s\S]*?capital_one_other_prefix_control_object_key' `
    'The compromised Node Role lacks exact-object GetObject for the other-prefix control.'
if ($policy -match 'ReadSecondaryControlObject[\s\S]*?Action\s*=\s*\[[^\]]*(?:ListBucket|PutObject|DeleteObject)') {
    throw 'The secondary control statement grants broader than GetObject access.'
}
if ($policy -match 'ReadOtherPrefixControlObject[\s\S]*?Action\s*=\s*\[[^\]]*(?:ListBucket|PutObject|DeleteObject)') {
    throw 'The other-prefix control statement grants broader than exact GetObject access.'
}

foreach ($name in @(
    'capital_one_secondary_control_bucket_name',
    'capital_one_secondary_control_region',
    'capital_one_secondary_control_object_key'
)) {
    Assert-Contains $outputs ('output\s+"' + [regex]::Escape($name) + '"') `
        "Terraform output is missing: $name"
}
Assert-Contains $outputs 'capital_one_secondary_control_region[\s\S]*?value\s*=\s*local\.capital_one_secondary_control_enabled\s*\?\s*var\.primary_region\s*:\s*null' `
    'The secondary control region output is not tied to the primary provider region.'
foreach ($name in @(
    'capital_one_secondary_control_bucket_name',
    'capital_one_secondary_control_region',
    'capital_one_secondary_control_object_key',
    'capital_one_secondary_control_object_sha256',
    'capital_one_other_prefix_control_object_key',
    'capital_one_other_prefix_control_object_sha256'
)) {
    Assert-Contains $outputs ('output\s+"' + [regex]::Escape($name) + '"[\s\S]*?value\s*=\s*local\.capital_one_secondary_control_enabled\s*\?') `
        "Terraform output is not null outside minimal + capital-one-lab: $name"
}
Assert-Contains $outputs 'capital_one_other_prefix_control_object_key[\s\S]*?value\s*=\s*local\.capital_one_secondary_control_enabled\s*\?\s*local\.capital_one_other_prefix_control_object_key\s*:\s*null' `
    'The other-prefix key output is not fixed and null outside the target profile.'
Assert-Contains $outputs 'capital_one_other_prefix_control_object_sha256[\s\S]*?value\s*=\s*local\.capital_one_secondary_control_enabled\s*\?\s*sha256\(local\.capital_one_secondary_control_csv\)\s*:\s*null' `
    'The other-prefix hash output is not tied to the deterministic fake-data body.'

Assert-Contains $foundationOutputs 'output\s+"wazuh_reader_trusted_principal_arn"[\s\S]*?value\s*=\s*local\.wazuh_reader_trusted_principal_arn' `
    'Foundation does not export the already configured explicit trusted principal.'
Assert-Contains $scenario 'capital_one_negative_control_trusted_principal_arn\s*=\s*try\([\s\S]*?terraform_remote_state\.foundation\.outputs\.wazuh_reader_trusted_principal_arn' `
    'The negative-control role does not reuse the Foundation trusted principal.'
Assert-Contains $scenario 'data\s+"aws_iam_policy_document"\s+"capital_one_negative_control_assume"[\s\S]*?count\s*=\s*local\.capital_one_secondary_control_enabled[\s\S]*?actions\s*=\s*\["sts:AssumeRole"\][\s\S]*?identifiers\s*=\s*\[local\.capital_one_negative_control_assume_principal_arn\]' `
    'The negative-control trust is not restricted to the explicit same-account principal.'
Assert-Contains $scenario 'resource\s+"aws_iam_role"\s+"capital_one_negative_control"[\s\S]*?precondition[\s\S]*?capital_one_negative_control_trusted_principal_arn\s*!=\s*""[\s\S]*?data\.aws_caller_identity\.current\.account_id[\s\S]*?\(user\|role\)' `
    'The negative-control role does not fail closed on an empty or cross-account principal.'

$negativePolicyMatch = [regex]::Match(
    $scenario,
    'data\s+"aws_iam_policy_document"\s+"capital_one_negative_control"\s*\{([\s\S]*?)\n\}',
    [Text.RegularExpressions.RegexOptions]::Singleline
)
if (-not $negativePolicyMatch.Success) { throw 'The negative-control permissions policy is missing.' }
$negativePolicy = $negativePolicyMatch.Groups[1].Value
Assert-Contains $negativePolicy 'actions\s*=\s*\["s3:GetObject"\]' `
    'The other-principal role does not have exact GetObject permission.'
Assert-Contains $negativePolicy 'aws_s3_bucket\.primary\.arn[\s\S]*?capital_one_secondary_control_object_key' `
    'The other-principal role is not restricted to the exact Primary validation object.'
if ($negativePolicy -match 'ListBucket|PutObject|DeleteObject|aws_s3_bucket\.capital_one_secondary_control') {
    throw 'The other-principal role has broader access or access to the secondary bucket.'
}
Assert-Contains $outputs 'output\s+"capital_one_negative_control_role_arn"[\s\S]*?value\s*=\s*local\.capital_one_secondary_control_enabled\s*\?\s*aws_iam_role\.capital_one_negative_control\[0\]\.arn\s*:\s*null' `
    'The negative-control role output is not null outside minimal + capital-one-lab.'

Assert-Contains $foundation 'cap1-secondary-' `
    'CloudTrail S3 data-event selector does not capture the secondary control bucket prefix.'
Assert-Contains $foundation 's3:::\$\{local\.name\}-primary-[\s\S]*?cap1-secondary-' `
    'CloudTrail selector no longer retains the primary prefix alongside the secondary control prefix.'
if ($storage -match 'aws_s3_bucket_versioning"\s+"capital_one_other_prefix_control|aws_s3_bucket_lifecycle_configuration"\s+"capital_one_other_prefix_control') {
    throw 'The managed other-prefix object must not add a separate versioning or lifecycle resource.'
}

Write-Host 'Capital One secondary-control static tests passed.'
