#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfirmSetup = '',
    [string]$ConfirmCapitalOneDetection = '',
    [string]$TerraformRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$Region = 'ap-northeast-2',
    [string]$DrRegion = 'ap-northeast-1',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ProjectName = 'aws-topology',
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$DomainName,
    [switch]$EnableProjectS3DataEvents,
    [switch]$EnableCapitalOneDetection,
    [switch]$EnableWazuhLogReader,
    [string]$WazuhReaderTrustedPrincipalArn = '',
    [string]$GitHubRepository = 'Unoh03/Uns-DVWA',
    [string]$ArgoDeployKeyPath = "$HOME\.ssh\argocd-uns-dvwa",
    [switch]$RotateDeployKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = $PSScriptRoot
}

. (Join-Path $PSScriptRoot 'daily-common.ps1')

$foundationRoot = Join-Path $TerraformRoot 'foundation'
$planPath = Join-Path $foundationRoot 'foundation.tfplan'
$foundationVars = Join-Path $foundationRoot 'terraform.tfvars'
$enableProjectS3DataEventsValue = if ($EnableProjectS3DataEvents.IsPresent) { 'true' } else { 'false' }
$enableCapitalOneDetectionValue = if ($EnableCapitalOneDetection.IsPresent) { 'true' } else { 'false' }
$enableWazuhLogReaderValue = if ($EnableWazuhLogReader.IsPresent) { 'true' } else { 'false' }

if ($EnableCapitalOneDetection.IsPresent -and
    -not $EnableProjectS3DataEvents.IsPresent) {
    throw 'Capital One detection requires -EnableProjectS3DataEvents because its input is a CloudTrail S3 object data event.'
}
if ($EnableProjectS3DataEvents.IsPresent) {
    Write-Warning 'Project S3 Data Events are enabled and can add CloudTrail data-event charges.'
}
if ($EnableCapitalOneDetection.IsPresent) {
    Write-Warning 'Capital One detection is enabled: a CloudWatch custom metric and alarm will be created for the approved experiment.'
}
if ($EnableWazuhLogReader.IsPresent) {
    if (-not $WazuhReaderTrustedPrincipalArn) {
        throw 'Wazuh log reader requires -WazuhReaderTrustedPrincipalArn with an explicit same-account IAM user or role ARN.'
    }

    $wazuhPrincipalMatch = [regex]::Match(
        $WazuhReaderTrustedPrincipalArn,
        '^arn:[^:]+:iam::(?<AccountId>[0-9]{12}):(user|role)/.+$'
    )
    if (-not $wazuhPrincipalMatch.Success -or
        $wazuhPrincipalMatch.Groups['AccountId'].Value -cne $ExpectedAccountId) {
        throw 'WazuhReaderTrustedPrincipalArn must be an IAM user or role ARN in ExpectedAccountId.'
    }

    Write-Warning 'The optional read-only Wazuh Reader Role is enabled for the explicitly named bootstrap principal.'
} elseif ($WazuhReaderTrustedPrincipalArn) {
    throw 'WazuhReaderTrustedPrincipalArn was provided without -EnableWazuhLogReader.'
}

function Get-GitHubRepositoryMetadata {
    $json = Invoke-NativeCapture -FilePath 'gh' -ArgumentList @(
        'api', "repos/$GitHubRepository"
    ) -FailureMessage 'Private GitHub repository metadata could not be read.'
    return $json | ConvertFrom-Json
}

function Assert-ImmutableOidcSubject {
    param([Parameter(Mandatory)][object]$Repository)

    $parts = $GitHubRepository -split '/', 2
    if ($parts.Count -ne 2) {
        throw 'GitHubRepository must use OWNER/REPOSITORY format.'
    }
    if (-not $Repository.private) {
        throw 'Uns-DVWA must remain a private GitHub repository.'
    }

    $expectedPrefix = "repo:$($Repository.owner.login)@$($Repository.owner.id)/$($Repository.name)@$($Repository.id)"
    $oidcJson = Invoke-NativeCapture -FilePath 'gh' -ArgumentList @(
        'api',
        '-H', 'X-GitHub-Api-Version: 2026-03-10',
        "repos/$GitHubRepository/actions/oidc/customization/sub"
    ) -FailureMessage 'GitHub OIDC subject configuration could not be read.'
    $oidc = $oidcJson | ConvertFrom-Json
    if (-not $oidc.use_default -or
        [string]$oidc.sub_claim_prefix -cne $expectedPrefix) {
        throw "GitHub does not currently issue the expected immutable default OIDC subject prefix.`nExpected: $expectedPrefix`nActual: $($oidc.sub_claim_prefix)"
    }

    $expected = "${expectedPrefix}:ref:refs/heads/main"
    $text = Get-Content -LiteralPath $foundationVars -Raw
    $match = [regex]::Match($text, '"(repo:[^"]+:ref:refs/heads/main)"')
    if (-not $match.Success) {
        throw 'Foundation terraform.tfvars does not contain one exact main-branch OIDC subject.'
    }
    if ($match.Groups[1].Value -cne $expected) {
        throw "GitHub immutable OIDC subject mismatch.`nExpected: $expected`nConfigured: $($match.Groups[1].Value)"
    }

    Write-Host "GitHub immutable OIDC subject verified for repository ID $($Repository.id)."
}

function Protect-PrivateKey {
    param([Parameter(Mandatory)][string]$Path)
    & icacls.exe $Path /inheritance:r /grant:r "$($env:USERNAME):(R,W)" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Deploy-key ACL could not be restricted: $Path"
    }
}

function Ensure-ReadOnlyDeployKey {
    $publicPath = "$ArgoDeployKeyPath.pub"
    $sshDirectory = Split-Path -Parent $ArgoDeployKeyPath
    if (-not (Test-Path -LiteralPath $sshDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $sshDirectory | Out-Null
    }

    if ((Test-Path -LiteralPath $ArgoDeployKeyPath) -xor
        (Test-Path -LiteralPath $publicPath)) {
        throw 'Only one half of the Argo CD deploy-key pair exists. Repair it manually before setup.'
    }

    if (-not (Test-Path -LiteralPath $ArgoDeployKeyPath)) {
        Invoke-NativePassthrough -FilePath 'ssh-keygen' -ArgumentList @(
            '-t', 'ed25519',
            '-C', 'argocd-readonly@Uns-DVWA',
            '-f', $ArgoDeployKeyPath,
            '-N', '""'
        ) -FailureMessage 'The Argo CD deploy-key pair could not be generated.'
    }
    Protect-PrivateKey -Path $ArgoDeployKeyPath

    $publicKey = (Get-Content -LiteralPath $publicPath -Raw).Trim()
    if ($publicKey -notmatch '^ssh-ed25519\s+') {
        throw 'The Argo CD deploy public key is not ED25519.'
    }

    $keysJson = Invoke-NativeCapture -FilePath 'gh' -ArgumentList @(
        'api', "repos/$GitHubRepository/keys"
    ) -FailureMessage 'GitHub deploy keys could not be listed.'
    $parsedKeys = $keysJson | ConvertFrom-Json
    $keys = if ($null -eq $parsedKeys) {
        @()
    } else {
        @($parsedKeys)
    }
    $existing = $keys | Where-Object { $_.title -ceq 'Argo CD read-only' } |
        Select-Object -First 1

    if ($existing) {
        if (-not $existing.read_only) {
            throw 'The existing Argo CD deploy key is writable. Replace it only after explicit review.'
        }
        if ([string]$existing.key -cne $publicKey) {
            if (-not $RotateDeployKey) {
                throw 'GitHub contains a different Argo CD read-only deploy key. On a new authorized laptop, rerun with -RotateDeployKey to replace it.'
            }
            Write-Warning 'Rotating the GitHub Argo CD read-only deploy key. Existing Argo CD runtimes using the previous private key will lose repository access.'
            Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
                'api', '--method', 'DELETE',
                "repos/$GitHubRepository/keys/$($existing.id)"
            ) -FailureMessage 'The previous Argo CD deploy key could not be removed.'
        } else {
            Write-Host 'GitHub read-only Argo CD deploy key already matches.'
            return
        }
    }

    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'api', '--method', 'POST',
        "repos/$GitHubRepository/keys",
        '-f', 'title=Argo CD read-only',
        '-f', "key=$publicKey",
        '-F', 'read_only=true'
    ) -FailureMessage 'The read-only Argo CD deploy key could not be registered.'
}

function Set-AndVerifyRepositoryVariable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'variable', 'set', $Name,
        '--repo', $GitHubRepository,
        '--body', $Value
    ) -FailureMessage "GitHub repository variable could not be set: $Name"

    $actual = Invoke-NativeCapture -FilePath 'gh' -ArgumentList @(
        'variable', 'get', $Name,
        '--repo', $GitHubRepository
    ) -FailureMessage "GitHub repository variable could not be read back: $Name"
    if ($actual -cne $Value) {
        throw "GitHub repository variable readback mismatch: $Name"
    }
}

try {
    Start-AwakeMode
    foreach ($command in @('terraform', 'aws', 'gh', 'ssh-keygen')) {
        Assert-CommandAvailable -Name $command
    }
    if (-not (Test-Path -LiteralPath $foundationVars -PathType Leaf)) {
        throw "Foundation variable file is missing: $foundationVars"
    }

    $identity = Get-AwsIdentity -Profile $AwsProfile -Region $Region
    Assert-AwsIdentity -Identity $identity -ExpectedAccountId $ExpectedAccountId
    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'auth', 'status'
    ) -FailureMessage 'GitHub CLI is not authenticated.'

    $repository = Get-GitHubRepositoryMetadata
    Assert-ImmutableOidcSubject -Repository $repository

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$foundationRoot", 'init', '-input=false', '-upgrade=false'
    ) -FailureMessage 'Foundation Terraform initialization failed.'

    $foundationPlanArguments = @(
        "-chdir=$foundationRoot", 'plan',
        '-input=false',
        "-var=aws_profile=$AwsProfile",
        "-var=primary_region=$Region",
        "-var=dr_region=$DrRegion",
        "-var=project_name=$ProjectName",
        "-var=domain_name=$DomainName",
        "-var=expected_account_id=$ExpectedAccountId",
        "-var=enable_project_s3_data_events=$enableProjectS3DataEventsValue",
        "-var=enable_capital_one_s3_detection=$enableCapitalOneDetectionValue",
        "-var=enable_wazuh_log_reader=$enableWazuhLogReaderValue"
    )
    if ($EnableWazuhLogReader.IsPresent) {
        $foundationPlanArguments += "-var=wazuh_reader_trusted_principal_arn=$WazuhReaderTrustedPrincipalArn"
    }
    $foundationPlanArguments += "-out=$planPath"

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList $foundationPlanArguments `
        -FailureMessage 'Foundation Terraform plan failed.'

    $summary = Get-TerraformPlanSummary -Root $foundationRoot -PlanPath $planPath
    Write-TerraformPlanSummary -Summary $summary -Label 'Foundation'

    if ($ConfirmSetup -cne 'SETUP FOUNDATION') {
        Write-Host "No AWS or GitHub change was made. Review the plan, then rerun with -ConfirmSetup 'SETUP FOUNDATION'."
        exit 2
    }
    if ($EnableCapitalOneDetection.IsPresent -and
        $ConfirmCapitalOneDetection -cne 'ENABLE CAPITAL ONE DETECTION') {
        Write-Host "No AWS or GitHub change was made. Capital One detection also requires -ConfirmCapitalOneDetection 'ENABLE CAPITAL ONE DETECTION'."
        exit 3
    }

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$foundationRoot", 'apply',
        '-input=false',
        $planPath
    ) -FailureMessage 'Foundation Terraform apply failed.'
    Remove-Item -LiteralPath $planPath -Force -ErrorAction SilentlyContinue

    $foundation = Get-FoundationContext `
        -FoundationRoot $foundationRoot `
        -Profile $AwsProfile `
        -Region $Region `
        -DrRegion $DrRegion `
        -ExpectedAccountId $ExpectedAccountId

    Ensure-ReadOnlyDeployKey
    Set-AndVerifyRepositoryVariable -Name 'AWS_REGION' -Value $Region
    Set-AndVerifyRepositoryVariable `
        -Name 'ECR_REPOSITORY' `
        -Value $foundation.RepositoryName
    Set-AndVerifyRepositoryVariable `
        -Name 'AWS_ROLE_ARN' `
        -Value $foundation.RoleArn

    Write-Host ''
    Write-Host 'Foundation setup completed.'
    Write-Host "ECR: $($foundation.RepositoryUrl)"
    Write-Host "GitHub Actions Role: $($foundation.RoleArn)"
    if ($foundation.SecurityLogBucket) {
        Write-Host "Security log archive: $($foundation.SecurityLogBucket)"
        Write-Host "Security log retention: $($foundation.SecurityRetentionDays) days"
    }
    Write-Host 'Argo CD deploy key: registered read-only'
    Write-Host 'GitHub variables: AWS_REGION, ECR_REPOSITORY, AWS_ROLE_ARN'
} finally {
    Stop-AwakeMode
}
