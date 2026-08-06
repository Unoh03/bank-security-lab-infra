Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Read-NormalizedText {
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
}

function Write-NormalizedText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Replace-Exact {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Old,
        [Parameter(Mandatory)][string]$New,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not $Content.Contains($Old)) {
        throw "Expected source block was not found: $Label"
    }
    return $Content.Replace($Old, $New)
}

$dailyCommonPath = Join-Path $root 'daily-common.ps1'
$dailyCommon = Read-NormalizedText -Path $dailyCommonPath

$oldFleetGate = @'
                    $fleetState = [string]$fleet.FleetState
                    if ($fleetState -ceq 'deleted') {
                        return $false
                    }
                    if ($fleetState -notin @(
                        'deleted_terminating',
                        'deleted_running'
                    )) {
                        return $true
                    }

                    # Fleet state propagation may lag behind EC2 termination.
                    # Verify each referenced instance independently so one stale
                    # InvalidInstanceID.NotFound does not hide another live ID.
'@
$newFleetGate = @'
                    $fleetState = [string]$fleet.FleetState
                    if ($fleetState -ceq 'deleted') {
                        return $false
                    }

                    $fleetType = [string]$fleet.Type
                    $inspectReferencedInstances = (
                        $fleetType -ceq 'instant' -or
                        $fleetState -in @(
                            'deleted_terminating',
                            'deleted_running'
                        )
                    )
                    if (-not $inspectReferencedInstances) {
                        return $true
                    }

                    # DescribeFleetInstances does not support instant Fleets.
                    # DescribeFleets already returns Instances[].InstanceIds, so
                    # verify each referenced EC2 instance directly. This also
                    # handles Fleet-state propagation lag after EC2 termination.
'@
$dailyCommon = Replace-Exact `
    -Content $dailyCommon `
    -Old $oldFleetGate `
    -New $newFleetGate `
    -Label 'Fleet state gate'

$oldEmptyIds = @'
                    if ($instanceIds.Count -eq 0) {
                        return $false
                    }
'@
$newEmptyIds = @'
                    if ($instanceIds.Count -eq 0) {
                        if ($fleetType -ceq 'instant') {
                            $fulfilledCapacity = 0.0
                            if ($fleet.PSObject.Properties.Name -contains 'FulfilledCapacity') {
                                $fulfilledCapacity = [double]$fleet.FulfilledCapacity
                            }
                            # An active instant Fleet that reports fulfilled
                            # capacity but omits its instance IDs is unresolved.
                            # Keep failing closed instead of hiding a live EC2.
                            return $fulfilledCapacity -gt 0
                        }
                        return $false
                    }
'@
$dailyCommon = Replace-Exact `
    -Content $dailyCommon `
    -Old $oldEmptyIds `
    -New $newEmptyIds `
    -Label 'Fleet empty instance-ID handling'

Write-NormalizedText -Path $dailyCommonPath -Content $dailyCommon

$testPath = Join-Path $root 'tests\test-fleet-residue.ps1'
$testSource = Read-NormalizedText -Path $testPath

$oldStateSetup = @'
        $state = switch ($global:FleetResidueMockScenario) {
            'deleted' { 'deleted' }
            'active' { 'active' }
            'deleted-running-not-found' { 'deleted_running' }
            default { 'deleted_terminating' }
        }
'@
$newStateSetup = @'
        $state = switch ($global:FleetResidueMockScenario) {
            'deleted' { 'deleted' }
            'active' { 'active' }
            'active-instant-terminated' { 'active' }
            'active-instant-not-found' { 'active' }
            'active-instant-running' { 'active' }
            'active-instant-no-instance-ids-fulfilled' { 'active' }
            'active-instant-no-instance-ids-empty' { 'active' }
            'deleted-running-not-found' { 'deleted_running' }
            default { 'deleted_terminating' }
        }
        $fleetType = if ($global:FleetResidueMockScenario -like 'active-instant-*') {
            'instant'
        } else {
            'maintain'
        }
        $fulfilledCapacity = if (
            $global:FleetResidueMockScenario -ceq 'active-instant-no-instance-ids-empty'
        ) {
            0
        } else {
            1
        }
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldStateSetup `
    -New $newStateSetup `
    -Label 'Fleet mock state setup'

$oldInstanceIds = @'
        $instanceIds = switch ($global:FleetResidueMockScenario) {
            'no-instance-ids' { @() }
            'blank-instance-ids' { @('', '   ', $null) }
            'mixed-notfound-running' {
'@
$newInstanceIds = @'
        $instanceIds = switch ($global:FleetResidueMockScenario) {
            'no-instance-ids' { @() }
            'blank-instance-ids' { @('', '   ', $null) }
            'active-instant-no-instance-ids-fulfilled' { @() }
            'active-instant-no-instance-ids-empty' { @() }
            'mixed-notfound-running' {
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldInstanceIds `
    -New $newInstanceIds `
    -Label 'Fleet mock instance IDs'

$oldFleetPayload = @'
                    FleetId = 'fleet-11111111-2222-3333-4444-555555555555'
                    FleetState = $state
                    Instances = @(
'@
$newFleetPayload = @'
                    FleetId = 'fleet-11111111-2222-3333-4444-555555555555'
                    FleetState = $state
                    Type = $fleetType
                    FulfilledCapacity = $fulfilledCapacity
                    Instances = @(
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldFleetPayload `
    -New $newFleetPayload `
    -Label 'Fleet mock payload'

$oldNotFoundCase = @'
                'not-found' {
                    $global:LASTEXITCODE = 255
                    return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
                }
'@
$newNotFoundCase = @'
                'active-instant-not-found' {
                    $global:LASTEXITCODE = 255
                    return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
                }
                'not-found' {
                    $global:LASTEXITCODE = 255
                    return "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID does not exist"
                }
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldNotFoundCase `
    -New $newNotFoundCase `
    -Label 'Active instant NotFound mock'

$oldRunningCase = @'
                'running' { $state = 'running' }
                default { $state = 'terminated' }
'@
$newRunningCase = @'
                'running' { $state = 'running' }
                'active-instant-running' { $state = 'running' }
                default { $state = 'terminated' }
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldRunningCase `
    -New $newRunningCase `
    -Label 'Active instant running mock'

$oldActiveAssertion = @'
    $global:FleetResidueMockScenario = 'active'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active Fleet must remain active.'

'@
$newActiveAssertion = @'
    $global:FleetResidueMockScenario = 'active'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active non-instant Fleet must remain active.'

    $global:FleetResidueMockScenario = 'active-instant-terminated'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active instant Fleet with only terminated instances must be inactive.'

    $global:FleetResidueMockScenario = 'active-instant-not-found'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active instant Fleet with only NotFound instances must be inactive.'

    $global:FleetResidueMockScenario = 'active-instant-running'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active instant Fleet with a running instance must remain active.'

    $global:FleetResidueMockScenario = 'active-instant-no-instance-ids-fulfilled'
    Assert-True `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An active instant Fleet with fulfilled capacity but no instance IDs must fail closed.'

    $global:FleetResidueMockScenario = 'active-instant-no-instance-ids-empty'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'An empty active instant Fleet with no fulfilled capacity must be inactive.'

'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldActiveAssertion `
    -New $newActiveAssertion `
    -Label 'Active instant Fleet assertions'

$oldAccessDeniedStart = @'
    $global:FleetResidueMockScenario = 'access-denied'
'@
$newAccessDeniedStart = @'
    $unsupportedCalls = @(
        $global:FleetResidueMockCalls | Where-Object {
            $_ -match '(^| )ec2 describe-fleet-instances( |$)'
        }
    )
    Assert-False `
        -Condition ($unsupportedCalls.Count -gt 0) `
        -Message 'Instant Fleet validation must not call unsupported DescribeFleetInstances.'

    $global:FleetResidueMockScenario = 'access-denied'
'@
$testSource = Replace-Exact `
    -Content $testSource `
    -Old $oldAccessDeniedStart `
    -New $newAccessDeniedStart `
    -Label 'Unsupported DescribeFleetInstances assertion'

Write-NormalizedText -Path $testPath -Content $testSource

Write-Host 'Active instant Fleet residue fix applied.'
