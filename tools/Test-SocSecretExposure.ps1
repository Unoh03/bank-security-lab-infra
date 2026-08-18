#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$GitRoot = '',
    [string]$EvidenceRoot = '',
    [string[]]$Path = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $repositoryRoot 'automation\SocLab.Security.psm1'
Import-Module $modulePath -Force

$targets = [Collections.Generic.List[string]]::new()
foreach ($candidate in $Path) {
    if ($candidate) {
        $targets.Add([IO.Path]::GetFullPath($candidate))
    }
}

if ($GitRoot) {
    $resolvedGitRoot = [IO.Path]::GetFullPath($GitRoot)
    $relativeFiles = @()
    foreach ($arguments in @(
        @('-C', $resolvedGitRoot, 'diff', '--name-only', '--diff-filter=ACMR'),
        @('-C', $resolvedGitRoot, 'diff', '--cached', '--name-only', '--diff-filter=ACMR'),
        @('-C', $resolvedGitRoot, 'ls-files', '--others', '--exclude-standard')
    )) {
        $output = @(& git @arguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw 'Git changed-file discovery failed during the SOC secret scan.'
        }
        $relativeFiles += @($output | ForEach-Object { [string]$_ })
    }
    foreach ($relativePath in @($relativeFiles | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($relativePath -match '(^|/)(?:__pycache__|\.pytest_cache)(?:/|$)' -or
            $relativePath -match '\.(?:pyc|pyo)$') {
            continue
        }
        $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedGitRoot $relativePath))
        if ($candidate.StartsWith($resolvedGitRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $targets.Add($candidate)
        }
    }
}

if ($EvidenceRoot) {
    $targets.Add([IO.Path]::GetFullPath($EvidenceRoot))
}
if ($targets.Count -eq 0) {
    throw 'Provide -GitRoot, -EvidenceRoot, or -Path for the SOC secret scan.'
}

$findings = @(Find-SocSecretExposure -Path @($targets | Sort-Object -Unique))
if ($findings.Count -gt 0) {
    foreach ($finding in $findings) {
        Write-Host ("SECRET_FINDING rule={0} path={1}" -f $finding.Rule,$finding.Path)
    }
    throw "SOC secret scan failed with $($findings.Count) redacted finding(s)."
}

Write-Host "SOC secret scan passed: $($targets.Count) target(s), 0 findings."
