#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'automation\SocLab.Runtime.psm1') -Force

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-runtime-' + [guid]::NewGuid().ToString('N'))
try {
    $record = New-SocTakeRecord `
        -TakeId 'capital-one-20260818T000000Z-deadbeef' `
        -ResponseMode observe_only `
        -IssuedAtUtc ([datetimeoffset]'2026-08-18T00:00:00Z') `
        -LifetimeMinutes 60
    $path = Write-SocTakeRecord -Record $record -RuntimeRoot $testRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'The Active TAKE record was not persisted.'
    }
    $ready = Set-SocTakeStatus -RuntimeRoot $testRoot -Status READY
    if ([string]$ready.status -cne 'READY') {
        throw 'The Active TAKE did not enter READY.'
    }
    $readyAgain = Set-SocTakeStatus -RuntimeRoot $testRoot -Status READY
    if ([string]$readyAgain.status -cne 'READY') {
        throw 'An idempotent Active TAKE status write failed.'
    }

    $beforeFailure = [IO.File]::ReadAllText($path)
    $held = [IO.File]::Open(
        $path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    try {
        $writeFailed = $false
        try {
            [void](Write-SocTakeRecord -Record $record -RuntimeRoot $testRoot)
        } catch {
            $writeFailed = $true
        }
        if (-not $writeFailed) {
            throw 'A locked Active TAKE destination unexpectedly accepted an overwrite.'
        }
    } finally {
        $held.Dispose()
    }
    if ([IO.File]::ReadAllText($path) -cne $beforeFailure) {
        throw 'A failed Active TAKE write modified the original record.'
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.(tmp|bak)$' }).Count -ne 0) {
        throw 'A failed Active TAKE write left a temporary or backup artifact.'
    }

    $invalidTransitionRejected = $false
    try {
        [void](Set-SocTakeStatus -RuntimeRoot $testRoot -Status DEPLOYED)
    } catch {
        $invalidTransitionRejected = $_.Exception.Message -match 'not allowed'
    }
    if (-not $invalidTransitionRejected) {
        throw 'The Active TAKE accepted a skipped state transition.'
    }
    $badRecord = $record.PSObject.Copy()
    $badRecord | Add-Member -NotePropertyName token -NotePropertyValue 'synthetic' -Force
    $forbiddenRejected = $false
    try {
        [void](Assert-SocTakeRecord -Record $badRecord)
    } catch {
        $forbiddenRejected = $_.Exception.Message -match 'forbidden field'
    }
    if (-not $forbiddenRejected) {
        throw 'The Active TAKE accepted a forbidden secret-like field.'
    }

    $legacyGuardAccepted = $false
    try {
        [void](Assert-SocLegacyObserveOnlyTake -Record $record)
        $legacyGuardAccepted = $true
    } catch { }
    if (-not $legacyGuardAccepted) {
        throw 'The legacy Rule 100103 OBSERVE_ONLY boundary rejected a valid observe-only TAKE.'
    }
    $containRecord = New-SocTakeRecord `
        -TakeId 'capital-one-20260818T000001Z-deadbeef' `
        -ResponseMode contain `
        -IssuedAtUtc ([datetimeoffset]'2026-08-18T00:00:00Z') `
        -LifetimeMinutes 60
    $legacyContainRejected = $false
    try {
        [void](Assert-SocLegacyObserveOnlyTake -Record $containRecord)
    } catch {
        $legacyContainRejected = $_.Exception.Message -match 'legacy Rule 100103 OBSERVE_ONLY'
    }
    if (-not $legacyContainRejected) {
        throw 'The legacy Rule 100103 boundary accepted a containment TAKE.'
    }
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab runtime state tests passed.'
