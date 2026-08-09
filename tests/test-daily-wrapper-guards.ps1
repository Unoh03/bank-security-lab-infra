#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'daily-common.ps1')
. (Join-Path $root 'daily-session-common.ps1')

foreach ($message in @(
    'An error occurred (AccessDeniedException) when calling DescribeAssociation',
    'An error occurred (ExpiredToken) when calling DescribeAssociation',
    'An error occurred (InvalidClientTokenId) when calling DescribeAssociation',
    'Unable to locate credentials. You can configure credentials by running aws configure.',
    'The config profile (terra-user) could not be found',
    'The SSO session associated with this profile has expired'
)) {
    if (-not (Test-AwsCliNonRetryableIdentityFailure -Message $message)) {
        throw "A non-retryable AWS identity failure was not classified as fatal: $message"
    }
}

foreach ($message in @(
    'ThrottlingException: Rate exceeded',
    'RequestTimeout: Request timed out',
    'AssociationDoesNotExist: the association is not visible yet',
    'InternalServerError: please retry'
)) {
    if (Test-AwsCliNonRetryableIdentityFailure -Message $message) {
        throw "A retryable AWS failure was classified as fatal: $message"
    }
}

$dailyUpSource = Get-Content -LiteralPath (Join-Path $root 'daily-up.ps1') -Raw
if ($dailyUpSource -notmatch 'Test-AwsCliNonRetryableIdentityFailure\s+-Message\s+\$errorMessage') {
    throw 'Wait-SsmAssociationSuccess does not use the non-retryable AWS identity failure classifier.'
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'daily-wrapper-guards-' + [guid]::NewGuid().ToString('N')
)
$otherRoot = "$testRoot-other"
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
New-Item -ItemType Directory -Path $otherRoot -Force | Out-Null

try {
    $currentRootProcess = [pscustomobject]@{
        ProcessId  = 101
        CommandLine = "terraform.exe -chdir=`"$testRoot`" plan"
    }
    $otherRootProcess = [pscustomobject]@{
        ProcessId  = 202
        CommandLine = "terraform.exe -chdir=`"$otherRoot`" plan"
    }
    $unknownProcess = [pscustomobject]@{
        ProcessId  = 303
        CommandLine = 'terraform.exe plan'
    }

    $activity = Get-DailySessionTerraformActivity `
        -TerraformRoot $testRoot `
        -ProcessInventory @($currentRootProcess, $otherRootProcess, $unknownProcess)
    if (-not $activity.IsBusy -or
        @($activity.RootProcessIds).Count -ne 1 -or
        [int]$activity.RootProcessIds[0] -ne 101) {
        throw 'The Terraform guard did not identify the current-root process exactly.'
    }
    if (@($activity.UnscopedProcessIds).Count -ne 1 -or
        @($activity.UnrelatedProcessIds).Count -ne 1) {
        throw 'The Terraform guard did not distinguish unrelated and unscoped processes.'
    }

    $unrelatedOnly = Get-DailySessionTerraformActivity `
        -TerraformRoot $testRoot `
        -ProcessInventory @($otherRootProcess)
    if ($unrelatedOnly.IsBusy) {
        throw 'A Terraform process explicitly scoped to another root blocked this root.'
    }

    $unknownOnly = Get-DailySessionTerraformActivity `
        -TerraformRoot $testRoot `
        -ProcessInventory @($unknownProcess)
    if (-not $unknownOnly.IsBusy -or @($unknownOnly.UnscopedProcessIds).Count -ne 1) {
        throw 'A Terraform process with an unverifiable root did not fail closed.'
    }

    $planPathProcess = [pscustomobject]@{
        ProcessId  = 404
        CommandLine = "terraform.exe apply `"$testRoot\daily-up.tfplan`""
    }
    $planActivity = Get-DailySessionTerraformActivity `
        -TerraformRoot $testRoot `
        -ProcessInventory @($planPathProcess)
    if (-not $planActivity.IsBusy) {
        throw 'A Terraform process referencing a plan in the current root was not detected.'
    }

    $lockPath = Join-Path $testRoot '.terraform.tfstate.lock.info'
    [System.IO.File]::WriteAllText(
        $lockPath,
        '{}',
        (New-Object System.Text.UTF8Encoding($false))
    )
    $lockActivity = Get-DailySessionTerraformActivity `
        -TerraformRoot $testRoot `
        -ProcessInventory @()
    if (-not $lockActivity.IsBusy -or @($lockActivity.LockPaths).Count -ne 1) {
        throw 'The current-root Terraform state lock did not fail closed.'
    }
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $otherRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Daily wrapper guard tests passed.'
