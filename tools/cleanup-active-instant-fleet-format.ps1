Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Update-ExactText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Replacements
    )

    $content = [System.IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    foreach ($old in $Replacements.Keys) {
        $count = ([regex]::Matches($content, [regex]::Escape([string]$old))).Count
        if ($count -ne 1) {
            throw "Expected exactly one formatting target in ${Path}; found $count for: $old"
        }
        $content = $content.Replace([string]$old, [string]$Replacements[$old])
    }
    [System.IO.File]::WriteAllText($Path, $content, $utf8NoBom)
}

Update-ExactText `
    -Path (Join-Path $root 'daily-common.ps1') `
    -Replacements @{
        '                                        $fleetState = [string]$fleet.FleetState' = '                    $fleetState = [string]$fleet.FleetState'
        '                                        if ($instanceIds.Count -eq 0) {' = '                    if ($instanceIds.Count -eq 0) {'
    }

Update-ExactText `
    -Path (Join-Path $root 'tests\test-fleet-residue.ps1') `
    -Replacements @{
        '                $state = switch ($global:FleetResidueMockScenario) {' = '        $state = switch ($global:FleetResidueMockScenario) {'
        '                $instanceIds = switch ($global:FleetResidueMockScenario) {' = '        $instanceIds = switch ($global:FleetResidueMockScenario) {'
        "                                        FleetId = 'fleet-11111111-2222-3333-4444-555555555555'" = "                    FleetId = 'fleet-11111111-2222-3333-4444-555555555555'"
        "                                'active-instant-not-found' {" = "                'active-instant-not-found' {"
        "                                'running' { `$state = 'running' }" = "                'running' { `$state = 'running' }"
        "        `$global:FleetResidueMockScenario = 'active'" = "    `$global:FleetResidueMockScenario = 'active'"
        '        $unsupportedCalls = @(' = '    $unsupportedCalls = @('
        "        -Message 'An empty active instant Fleet with no fulfilled capacity must be inactive.'`n`n`n    `$global:FleetResidueMockScenario = 'running'" = "        -Message 'An empty active instant Fleet with no fulfilled capacity must be inactive.'`n`n    `$global:FleetResidueMockScenario = 'running'"
    }

Write-Host 'Active instant Fleet formatting cleaned.'
