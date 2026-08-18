#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:TakeStatuses = @(
    'ISSUED',
    'READY',
    'ATTACK_STARTED',
    'DETECTED',
    'RESPONSE_DISPATCHED',
    'COMMITTED',
    'DEPLOYED',
    'REATTACK_BLOCKED',
    'E2E_SUCCEEDED',
    'E2E_FAILED',
    'RESET_REQUESTED',
    'RESET_COMMITTED',
    'RESET_DEPLOYED',
    'CLOSED'
)
$script:TakeTransitions = @{
    ISSUED              = @('READY','E2E_FAILED')
    READY               = @('ATTACK_STARTED','E2E_FAILED')
    ATTACK_STARTED      = @('DETECTED','E2E_FAILED')
    DETECTED            = @('RESPONSE_DISPATCHED','E2E_FAILED')
    RESPONSE_DISPATCHED = @('COMMITTED','E2E_FAILED')
    COMMITTED           = @('DEPLOYED','E2E_FAILED')
    DEPLOYED            = @('REATTACK_BLOCKED','E2E_FAILED')
    REATTACK_BLOCKED    = @('E2E_SUCCEEDED','E2E_FAILED')
    E2E_SUCCEEDED       = @('RESET_REQUESTED')
    E2E_FAILED          = @('RESET_REQUESTED')
    RESET_REQUESTED     = @('RESET_COMMITTED','E2E_FAILED')
    RESET_COMMITTED     = @('RESET_DEPLOYED','E2E_FAILED')
    RESET_DEPLOYED      = @('CLOSED','E2E_FAILED')
    CLOSED              = @()
}

function Get-SocActiveTakePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeRoot)

    return Join-Path ([IO.Path]::GetFullPath($RuntimeRoot)) 'active-take.json'
}

function Assert-SocTakeRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Record)

    $required = @(
        'schema_version','take_id','scenario_id','response_mode',
        'issued_at_utc','expires_at_utc','status','account_alias',
        'expected_rule_id'
    )
    foreach ($field in $required) {
        if ($null -eq $Record.PSObject.Properties[$field] -or
            [string]::IsNullOrWhiteSpace([string]$Record.$field)) {
            throw "Active TAKE field is missing: $field"
        }
    }
    if ([int]$Record.schema_version -ne 1) {
        throw 'The Active TAKE schema version is unsupported.'
    }
    if ([string]$Record.take_id -cnotmatch $script:TakeIdPattern) {
        throw 'The Active TAKE ID violates the frozen format.'
    }
    if ([string]$Record.scenario_id -cne 'CAPITAL-ONE' -or
        [string]$Record.account_alias -cne 'primary-lab' -or
        [string]$Record.expected_rule_id -cne '100103') {
        throw 'The Active TAKE fixed allowlist fields do not match the frozen contract.'
    }
    if ([string]$Record.response_mode -notin @('observe_only','contain')) {
        throw 'The Active TAKE response mode is unsupported.'
    }
    if ([string]$Record.status -notin $script:TakeStatuses) {
        throw 'The Active TAKE status is unsupported.'
    }
    $issued = [datetimeoffset]::Parse(
        [string]$Record.issued_at_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    $expires = [datetimeoffset]::Parse(
        [string]$Record.expires_at_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    if ($expires -le $issued -or $expires -gt $issued.AddHours(2)) {
        throw 'The Active TAKE expiry must be after issuance and no more than two hours later.'
    }
    foreach ($forbidden in @(
        'account_id','aws_account_id','token','credential','cookie',
        'password','secret','webhook','bucket'
    )) {
        if ($null -ne $Record.PSObject.Properties[$forbidden]) {
            throw "The Active TAKE contains a forbidden field: $forbidden"
        }
    }
    return $Record
}

function New-SocTakeRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('observe_only','contain')][string]$ResponseMode,
        [datetimeoffset]$IssuedAtUtc = [datetimeoffset]::UtcNow,
        [ValidateRange(5,120)][int]$LifetimeMinutes = 120
    )

    $record = [pscustomobject][ordered]@{
        schema_version   = 1
        take_id          = $TakeId
        scenario_id      = 'CAPITAL-ONE'
        response_mode    = $ResponseMode
        issued_at_utc    = $IssuedAtUtc.ToUniversalTime().ToString('o')
        expires_at_utc   = $IssuedAtUtc.ToUniversalTime().AddMinutes($LifetimeMinutes).ToString('o')
        status           = 'ISSUED'
        account_alias    = 'primary-lab'
        expected_rule_id = '100103'
    }
    return Assert-SocTakeRecord -Record $record
}

function Write-SocTakeRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    [void](Assert-SocTakeRecord -Record $Record)
    $root = [IO.Path]::GetFullPath($RuntimeRoot)
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $path = Get-SocActiveTakePath -RuntimeRoot $root
    $temporaryPath = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$path.$([guid]::NewGuid().ToString('N')).bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Record | ConvertTo-Json -Depth 8) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $path, $backupPath)
            Remove-Item -LiteralPath $backupPath -Force
        } else {
            [IO.File]::Move($temporaryPath, $path)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
    return $path
}

function Read-SocTakeRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeRoot)

    $path = Get-SocActiveTakePath -RuntimeRoot $RuntimeRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The Active TAKE is unavailable: $path"
    }
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    return Assert-SocTakeRecord -Record $record
}

function Set-SocTakeStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$Status
    )

    if ($Status -notin $script:TakeStatuses) {
        throw 'The requested Active TAKE status is unsupported.'
    }
    $record = Read-SocTakeRecord -RuntimeRoot $RuntimeRoot
    $current = [string]$record.status
    if ($Status -ceq $current) {
        return $record
    }
    if ($Status -notin @($script:TakeTransitions[$current])) {
        throw "The Active TAKE transition is not allowed: $current -> $Status"
    }
    $record.status = $Status
    [void](Write-SocTakeRecord -Record $record -RuntimeRoot $RuntimeRoot)
    return $record
}

Export-ModuleMember -Function @(
    'Get-SocActiveTakePath',
    'Assert-SocTakeRecord',
    'New-SocTakeRecord',
    'Write-SocTakeRecord',
    'Read-SocTakeRecord',
    'Set-SocTakeStatus'
)
