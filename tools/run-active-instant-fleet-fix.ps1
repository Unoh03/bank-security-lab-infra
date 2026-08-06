Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourcePath = Join-Path $PSScriptRoot 'apply-active-instant-fleet-fix.ps1'
$generatedPath = Join-Path $PSScriptRoot '.generated-active-instant-fleet-fix.ps1'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$source = [System.IO.File]::ReadAllText($sourcePath).Replace("`r`n", "`n")
$functionPattern = '(?s)function Replace-Exact \{.*?\n\}\n\n\$dailyCommonPath'
$replacement = @'
function Replace-Exact {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Old,
        [Parameter(Mandatory)][string]$New,
        [Parameter(Mandatory)][string]$Label
    )

    $tokens = @([regex]::Split($Old.Trim(), '\s+') | Where-Object { $_ })
    $pattern = ($tokens | ForEach-Object { [regex]::Escape($_) }) -join '\s+'
    $matches = [regex]::Matches($Content, $pattern)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one source block for ${Label}; found $($matches.Count)."
    }
    return [regex]::Replace(
        $Content,
        $pattern,
        [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $New },
        1
    )
}

$dailyCommonPath
'@

$updated = [regex]::Replace($source, $functionPattern, $replacement, 1)
if ($updated -ceq $source) {
    throw 'The temporary patch runner could not replace Replace-Exact.'
}

try {
    [System.IO.File]::WriteAllText($generatedPath, $updated, $utf8NoBom)
    & $generatedPath
} finally {
    Remove-Item -LiteralPath $generatedPath -Force -ErrorAction SilentlyContinue
}
