Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GitCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter()][string[]]$Arguments = @(),
        [Parameter()][string]$FailureMessage = 'git command failed'
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & git -C $RepositoryRoot @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        $detail = ($output | Out-String).Trim()
        throw "$FailureMessage`n$detail"
    }

    return ($output | Out-String).Trim()
}

function Test-GitCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter()][string[]]$Arguments = @()
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & git -C $RepositoryRoot @Arguments 1>$null 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }

    return $exitCode -eq 0
}

function Test-GitOpsIgnoredPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $normalized = $Path.Replace('\', '/')
    while ($normalized.StartsWith('./', [System.StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -ceq 'deploy/dvwa/values.yaml' -or
        $normalized -ceq 'deploy/README.md') {
        return $true
    }

    return $normalized.StartsWith(
        'gitops/',
        [System.StringComparison]::Ordinal
    )
}

function Get-ApplicationImageFreshness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$ImageTag,
        [string]$Revision = 'origin/main'
    )

    if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
        throw "Application repository is unavailable: $RepositoryRoot"
    }

    if ($ImageTag -notmatch '^sha-([0-9a-f]{40})$') {
        return [pscustomobject]@{
            IsFresh            = $false
            Reason             = 'ImageTagInvalid'
            ImageTag           = $ImageTag
            SourceCommit       = ''
            Revision           = $Revision
            ChangedPaths       = @()
            BuildRelevantPaths = @()
        }
    }
    $sourceCommit = [string]$Matches[1]

    if (-not (Test-GitCommand `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('cat-file', '-e', "$sourceCommit^{commit}"))) {
        return [pscustomobject]@{
            IsFresh            = $false
            Reason             = 'ImageSourceCommitMissing'
            ImageTag           = $ImageTag
            SourceCommit       = $sourceCommit
            Revision           = $Revision
            ChangedPaths       = @()
            BuildRelevantPaths = @()
        }
    }

    if (-not (Test-GitCommand `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('rev-parse', '--verify', "$Revision^{commit}"))) {
        return [pscustomobject]@{
            IsFresh            = $false
            Reason             = 'TargetRevisionMissing'
            ImageTag           = $ImageTag
            SourceCommit       = $sourceCommit
            Revision           = $Revision
            ChangedPaths       = @()
            BuildRelevantPaths = @()
        }
    }

    if (-not (Test-GitCommand `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @(
                'merge-base', '--is-ancestor',
                $sourceCommit,
                $Revision
            ))) {
        return [pscustomobject]@{
            IsFresh            = $false
            Reason             = 'ImageSourceCommitNotAncestor'
            ImageTag           = $ImageTag
            SourceCommit       = $sourceCommit
            Revision           = $Revision
            ChangedPaths       = @()
            BuildRelevantPaths = @()
        }
    }

    $changedText = Invoke-GitCapture `
        -RepositoryRoot $RepositoryRoot `
        -Arguments @(
            'diff',
            '--name-only',
            '--diff-filter=ACDMRTUXB',
            "$sourceCommit..$Revision",
            '--',
            '.'
        ) `
        -FailureMessage 'Application changes since the image source commit could not be read.'

    $changedPaths = if ($changedText) {
        @(
            [regex]::Split($changedText.Trim(), '\r?\n') |
                Where-Object { $_ }
        )
    } else {
        @()
    }
    $buildRelevantPaths = @(
        $changedPaths |
            Where-Object { -not (Test-GitOpsIgnoredPath -Path $_) }
    )

    return [pscustomobject]@{
        IsFresh            = $buildRelevantPaths.Count -eq 0
        Reason             = if ($buildRelevantPaths.Count -eq 0) {
            'Current'
        } else {
            'BuildRelevantChangesAfterImage'
        }
        ImageTag           = $ImageTag
        SourceCommit       = $sourceCommit
        Revision           = $Revision
        ChangedPaths       = $changedPaths
        BuildRelevantPaths = $buildRelevantPaths
    }
}

Export-ModuleMember -Function @(
    'Get-ApplicationImageFreshness',
    'Test-GitOpsIgnoredPath'
)
