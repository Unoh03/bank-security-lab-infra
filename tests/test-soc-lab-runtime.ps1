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
} finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'SOC lab runtime state tests passed.'
