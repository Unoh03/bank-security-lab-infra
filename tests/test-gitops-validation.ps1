#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'automation\GitOps.Validation.psm1'
$dailyUpPath = Join-Path $root 'daily-up.ps1'

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-False {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Condition) {
        throw $Message
    }
}

function Assert-Contains {
    param(
        [Parameter(Mandatory)][object[]]$Values,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Expected -notin @($Values)) {
        throw $Message
    }
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

function Invoke-TestGit {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $output = & git -C $RepositoryRoot @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed:`n$(($output | Out-String).Trim())"
    }
    return ($output | Out-String).Trim()
}

function Write-TestFile {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Content
    )

    $path = Join-Path $RepositoryRoot $RelativePath
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $path,
        $Content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Commit-TestRepository {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Message
    )

    [void](Invoke-TestGit -RepositoryRoot $RepositoryRoot -Arguments @('add', '--all'))
    [void](Invoke-TestGit -RepositoryRoot $RepositoryRoot -Arguments @('commit', '-m', $Message))
    return Invoke-TestGit -RepositoryRoot $RepositoryRoot -Arguments @('rev-parse', 'HEAD')
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is required for GitOps validation tests.'
}
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "GitOps validation module is missing: $modulePath"
}
if (-not (Test-Path -LiteralPath $dailyUpPath -PathType Leaf)) {
    throw "daily-up.ps1 is missing: $dailyUpPath"
}

Import-Module $modulePath -Force

Assert-True `
    -Condition (Test-GitOpsIgnoredPath -Path 'deploy/dvwa/values.yaml') `
    -Message 'The generated DVWA values change must remain CI-ignored.'
Assert-True `
    -Condition (Test-GitOpsIgnoredPath -Path 'deploy/README.md') `
    -Message 'The deploy README must remain CI-ignored.'
Assert-True `
    -Condition (Test-GitOpsIgnoredPath -Path 'gitops/argocd/dvwa.yaml') `
    -Message 'The gitops tree must remain CI-ignored.'
Assert-False `
    -Condition (Test-GitOpsIgnoredPath -Path 'README.md') `
    -Message 'Root README changes are build-relevant under the current workflow contract.'
Assert-False `
    -Condition (Test-GitOpsIgnoredPath -Path 'dvwa/index.php') `
    -Message 'Application source must never be treated as CI-ignored.'

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'gitops-validation-test-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    [void](Invoke-TestGit -RepositoryRoot $tempRoot -Arguments @('init'))
    [void](Invoke-TestGit -RepositoryRoot $tempRoot -Arguments @('config', 'user.name', 'GitOps Validation Test'))
    [void](Invoke-TestGit -RepositoryRoot $tempRoot -Arguments @('config', 'user.email', 'gitops-validation@example.invalid'))

    Write-TestFile -RepositoryRoot $tempRoot -RelativePath 'dvwa/index.php' -Content "<?php echo 'v1';`n"
    $sourceCommit = Commit-TestRepository -RepositoryRoot $tempRoot -Message 'application source'
    $imageTag = "sha-$sourceCommit"

    Write-TestFile `
        -RepositoryRoot $tempRoot `
        -RelativePath 'deploy/dvwa/values.yaml' `
        -Content "image:`n  tag: `"$imageTag`"`n"
    [void](Commit-TestRepository -RepositoryRoot $tempRoot -Message 'generated values')

    Write-TestFile `
        -RepositoryRoot $tempRoot `
        -RelativePath 'gitops/argocd/dvwa.yaml' `
        -Content "kind: Application`n"
    [void](Commit-TestRepository -RepositoryRoot $tempRoot -Message 'gitops metadata')

    Write-TestFile `
        -RepositoryRoot $tempRoot `
        -RelativePath 'deploy/README.md' `
        -Content "deployment notes`n"
    [void](Commit-TestRepository -RepositoryRoot $tempRoot -Message 'ignored deploy docs')

    $fresh = Get-ApplicationImageFreshness `
        -RepositoryRoot $tempRoot `
        -ImageTag $imageTag `
        -Revision 'HEAD'
    Assert-True `
        -Condition ([bool]$fresh.IsFresh) `
        -Message 'Only workflow-ignored changes after an image commit must remain fresh.'
    Assert-True `
        -Condition ($fresh.BuildRelevantPaths.Count -eq 0) `
        -Message 'Ignored GitOps changes must not be reported as build-relevant.'

    Write-TestFile `
        -RepositoryRoot $tempRoot `
        -RelativePath 'README.md' `
        -Content "root documentation change`n"
    [void](Commit-TestRepository -RepositoryRoot $tempRoot -Message 'build-relevant root docs')

    $stale = Get-ApplicationImageFreshness `
        -RepositoryRoot $tempRoot `
        -ImageTag $imageTag `
        -Revision 'HEAD'
    Assert-False `
        -Condition ([bool]$stale.IsFresh) `
        -Message 'A build-relevant change after the image commit must make the image stale.'
    Assert-Contains `
        -Values @($stale.BuildRelevantPaths) `
        -Expected 'README.md' `
        -Message 'The stale-image result must identify the build-relevant path.'

    $invalid = Get-ApplicationImageFreshness `
        -RepositoryRoot $tempRoot `
        -ImageTag 'latest' `
        -Revision 'HEAD'
    Assert-False `
        -Condition ([bool]$invalid.IsFresh) `
        -Message 'Mutable or malformed image tags must fail freshness validation.'
    Assert-True `
        -Condition ([string]$invalid.Reason -ceq 'ImageTagInvalid') `
        -Message 'Malformed tags must return the ImageTagInvalid reason.'
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module GitOps.Validation -Force -ErrorAction SilentlyContinue
}

$dailyUp = Get-Content -LiteralPath $dailyUpPath -Raw
Assert-Match `
    -Text $dailyUp `
    -Pattern 'Get-ApplicationImageFreshness[\s\S]*?BuildRelevantPaths' `
    -Message 'daily-up must gate ECR image reuse on build-relevant Git history.'
Assert-Match `
    -Text $dailyUp `
    -Pattern 'argocd\.argoproj\.io/refresh=hard' `
    -Message 'daily-up must force an Argo CD hard refresh after repository credential injection.'
Assert-Match `
    -Text $dailyUp `
    -Pattern 'sync_revision[\s\S]*?expected_revision' `
    -Message 'daily-up must compare the reconciled Argo revision with the expected GitOps commit.'
Assert-Match `
    -Text $dailyUp `
    -Pattern 'error_conditions[\s\S]*?Error\\\|' `
    -Message 'daily-up must reject current Argo CD error conditions.'

Write-Host 'GitOps image freshness and Argo revision static contracts passed.'
