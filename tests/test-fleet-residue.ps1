#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dailyCommonPath = Join-Path $root 'daily-common.ps1'

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

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )

    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "$Message`nUnexpected error: $($_.Exception.Message)"
        }
        return
    }
    throw $Message
}

if (-not (Test-Path -LiteralPath $dailyCommonPath -PathType Leaf)) {
    throw "daily-common.ps1 is missing: $dailyCommonPath"
}

. $dailyCommonPath

$global:FleetResidueMockScenario = ''
$global:FleetResidueMockCalls = New-Object System.Collections.Generic.List[string]

function global:aws {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $global:FleetResidueMockCalls.Add(($arguments -join ' '))

    if ($arguments.Count -ge 2 -and
        $arguments[0] -ceq 'ec2' -and
        $arguments[1] -ceq 'describe-fleets') {
        $state = switch ($global:FleetResidueMockScenario) {
            'deleted' { 'deleted' }
            'active' { 'active' }
            'deleted-running-not-found' { 'deleted_running' }
            default { 'deleted_terminating' }
        }
        $instanceIds = switch ($global:FleetResidueMockScenario) {
            'no-instance-ids' { @() }
            'blank-instance-ids' { @('', '   ', $null) }
            'mixed-notfound-running' {
                @(
                    'i-0123456789abcdef0',
                    'i-0fedcba9876543210'
                )
            }
            default { @('i-0123456789abcdef0') }
        }
        $global:LASTEXITCODE = 0
        return (@{
            Fleets = @(
                @{
                    FleetId = 'fleet-11111111-2222-3333-4444-555555555555'
                    FleetState = $state
                    Instances = @(
                        @{ InstanceIds = $instanceIds }
                    )
                }
            )
        } | ConvertTo-Json -Depth 8 -Compress)
    }

    if ($arguments.Count -ge 2 -and
        $arguments[0] -ceq 'ec2' -and
        $arguments[1] -ceq 'describe-instances') {
        $instanceIdIndex = [array]::IndexOf($arguments, '--instance-ids')
        $instanceId = if ($instanceIdIndex -ge 0 -and
            $instanceIdIndex + 1 -lt $arguments.Count) {
            $arguments[$instanceIdIndex + 1]
        } else {
            ''
        }
        if ($global:FleetResidueMockScenario -ceq 'mixed-notfound-running') {
            if ($instanceId -ceq 'i-0123456789abcdef0') {
                $global:LASTEXITCODE = 255
                return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
            }
            $state = 'running'
        } else {
            switch ($global:FleetResidueMockScenario) {
                'not-found' {
                    $global:LASTEXITCODE = 255
                    return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
                }
                'deleted-running-not-found' {
                    $global:LASTEXITCODE = 255
                    return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
                }
                'access-denied' {
                    $global:LASTEXITCODE = 254
                    return 'An error occurred (AccessDeniedException) when calling the DescribeInstances operation'
                }
                'running' { $state = 'running' }
                default { $state = 'terminated' }
            }
        }
        $global:LASTEXITCODE = 0
        return (@{
            Reservations = @(
                @{
                    Instances = @(
                        @{
                            InstanceId = 'i-0123456789abcdef0'
                            State = @{ Name = $state }
                        }
                    )
                }
            )
        } | ConvertTo-Json -Depth 8 -Compress)
    }

    $global:LASTEXITCODE = 2
    return "Unexpected mocked AWS command: $($arguments -join ' ')"
}

$arn = 'arn:aws:ec2:ap-northeast-2:433048100798:fleet/fleet-11111111-2222-3333-4444-555555555555'

try {
    $global:FleetResidueMockScenario = 'deleted'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'A deleted Fleet must be inactive.'

    $global:FleetResidueMockScenario = 'active'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active Fleet must remain active.'

    $global:FleetResidueMockScenario = 'running'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'deleted_terminating with a running instance must remain active.'

    $global:FleetResidueMockScenario = 'mixed-notfound-running'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'A stale NotFound ID must not hide another running Fleet instance.'

    $global:FleetResidueMockScenario = 'terminated'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'deleted_terminating with only terminated instances must be inactive.'

    $global:FleetResidueMockScenario = 'not-found'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'deleted_terminating with only NotFound instances must be inactive.'

    $global:FleetResidueMockScenario = 'deleted-running-not-found'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'deleted_running with only NotFound instances must be inactive.'

    $global:FleetResidueMockScenario = 'no-instance-ids'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'A deleting Fleet with no referenced instances must be inactive.'

    $global:FleetResidueMockScenario = 'blank-instance-ids'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'Blank or whitespace Fleet instance IDs must be ignored.'

    $global:FleetResidueMockScenario = 'access-denied'
    Assert-Throws `
        -Operation {
            [void](Test-TaggedProjectRuntimeResourceActive `
                -Arn $arn -Profile 'test' -Region 'ap-northeast-2')
        } `
        -Pattern 'failed closed' `
        -Message 'Instance inventory errors other than NotFound must fail closed.'
} finally {
    Remove-Item Function:\aws -Force -ErrorAction SilentlyContinue
    Remove-Variable FleetResidueMockScenario -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable FleetResidueMockCalls -Scope Global -ErrorAction SilentlyContinue
}

Write-Host 'EC2 Fleet residue-state contracts passed.'

exit 0
