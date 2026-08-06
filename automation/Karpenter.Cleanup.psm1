Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-KarpenterSafeIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') {
        throw "$Label contains unsupported characters."
    }
}

function Invoke-KarpenterNative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @(),
        [Parameter()][string]$FailureMessage = "$FilePath failed"
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "$FailureMessage`n$text"
    }
    return $text
}

function Get-KarpenterTagValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Tags,
        [Parameter(Mandatory)][string]$Key
    )

    $tag = @($Tags | Where-Object { [string]$_.Key -ceq $Key }) |
        Select-Object -First 1
    if (-not $tag) {
        return ''
    }
    return [string]$tag.Value
}

function Test-KarpenterInstanceScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Instance,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$ClusterName
    )

    $tags = @($Instance.Tags)
    $discovery = Get-KarpenterTagValue -Tags $tags -Key 'karpenter.sh/discovery'
    $nodeClaim = Get-KarpenterTagValue -Tags $tags -Key 'karpenter.sh/nodeclaim'
    $nodePool = Get-KarpenterTagValue -Tags $tags -Key 'karpenter.sh/nodepool'
    $project = Get-KarpenterTagValue -Tags $tags -Key 'Project'
    $managedBy = Get-KarpenterTagValue -Tags $tags -Key 'ManagedBy'

    $clusterTagPrefix = 'kubernetes.io/cluster/'
    $ownedClusters = @(
        $tags |
            ForEach-Object {
                $key = [string]$_.Key
                if ($key.StartsWith(
                        $clusterTagPrefix,
                        [System.StringComparison]::Ordinal
                    ) -and [string]$_.Value -ceq 'owned') {
                    $key.Substring($clusterTagPrefix.Length)
                }
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    $discoveryMatches = $discovery -ceq $ClusterName
    $ownershipMatches = $ownedClusters -ccontains $ClusterName
    $otherOwnedClusters = @(
        $ownedClusters | Where-Object { $_ -cne $ClusterName }
    )
    $discoveryPointsElsewhere = (
        [bool]$discovery -and
        -not $discoveryMatches
    )
    $hasTargetIdentity = $discoveryMatches -or $ownershipMatches
    $hasOtherIdentity = (
        $discoveryPointsElsewhere -or
        $otherOwnedClusters.Count -gt 0
    )
    $identityConflict = $hasTargetIdentity -and $hasOtherIdentity
    $projectManaged = (
        $project -ceq $ProjectName -and
        $managedBy -ceq 'Karpenter'
    )
    $hasNodeIdentity = [bool]$nodeClaim -and [bool]$nodePool

    # Project/ManagedBy are the broad inventory boundary. A candidate with no
    # cluster identity remains in scope as ambiguous so cleanup fails closed
    # instead of incorrectly reporting NothingToRemove.
    $ambiguous = (
        -not $hasTargetIdentity -and
        -not $hasOtherIdentity -and
        $projectManaged
    )
    $isKarpenter = $hasTargetIdentity -or $ambiguous
    $strictOwned = (
        $isKarpenter -and
        $ownershipMatches -and
        -not $identityConflict -and
        $projectManaged -and
        $hasNodeIdentity -and
        (-not $discovery -or $discoveryMatches)
    )

    $reason = if ($identityConflict) {
        'conflicting Karpenter cluster identity tags'
    } elseif (-not $isKarpenter) {
        'Karpenter cluster identity tags point to another cluster'
    } elseif ($ambiguous) {
        'Project and ManagedBy match but Karpenter cluster identity tags are missing'
    } elseif (-not $ownershipMatches) {
        'target cluster ownership tag is missing'
    } elseif (-not $hasNodeIdentity) {
        'Karpenter NodeClaim or NodePool tag is missing'
    } elseif (-not $projectManaged) {
        'Project or ManagedBy tag does not match the strict orphan-cleanup contract'
    } elseif (-not $discovery) {
        'strict project, cluster ownership, and Karpenter tags match; discovery tag is absent'
    } else {
        'strict project, cluster, and Karpenter tags match'
    }

    return [pscustomobject]@{
        InstanceId      = [string]$Instance.InstanceId
        State           = [string]$Instance.State.Name
        Discovery       = $discovery
        OwnedClusters   = $ownedClusters
        NodeClaim       = $nodeClaim
        NodePool        = $nodePool
        HasNodeIdentity = $hasNodeIdentity
        Ambiguous       = $ambiguous
        IdentityConflict = $identityConflict
        IsKarpenter     = $isKarpenter
        StrictOwned     = $strictOwned
        Reason          = $reason
    }
}

function Get-KarpenterClusterInstances {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$ClusterName
    )

    Assert-KarpenterSafeIdentifier -Value $ProjectName -Label 'ProjectName'
    Assert-KarpenterSafeIdentifier -Value $ClusterName -Label 'ClusterName'
    $json = Invoke-KarpenterNative -FilePath 'aws' -ArgumentList @(
        'ec2', 'describe-instances',
        '--profile', $AwsProfile,
        '--region', $Region,
        '--filters',
        'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down',
        "Name=tag:Project,Values=$ProjectName",
        'Name=tag:ManagedBy,Values=Karpenter',
        '--output', 'json'
    ) -FailureMessage "Karpenter instance inventory failed for $ClusterName."
    $response = $json | ConvertFrom-Json
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($reservation in @($response.Reservations)) {
        foreach ($instance in @($reservation.Instances)) {
            $scope = Test-KarpenterInstanceScope `
                -Instance $instance `
                -ProjectName $ProjectName `
                -ClusterName $ClusterName
            if ($scope.IsKarpenter) {
                $result.Add($scope)
            }
        }
    }
    return $result.ToArray()
}

function Test-KarpenterClusterExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$ClusterName
    )

    try {
        [void](Invoke-KarpenterNative -FilePath 'aws' -ArgumentList @(
            'eks', 'describe-cluster',
            '--profile', $AwsProfile,
            '--region', $Region,
            '--name', $ClusterName,
            '--output', 'json'
        ) -FailureMessage "EKS cluster inventory failed for $ClusterName.")
        return $true
    } catch {
        if ($_.Exception.Message -match '(?i)ResourceNotFoundException|not found|does not exist') {
            return $false
        }
        throw
    }
}

function Get-KarpenterNodePoolDeleteCommands {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Region)

    Assert-KarpenterSafeIdentifier -Value $Region -Label 'Region'
    return @(
        'export HOME=/root',
        'export KUBECONFIG=/root/.kube/config',
        "export AWS_REGION=$Region",
        "export AWS_DEFAULT_REGION=$Region",
        'kubectl delete nodepools.karpenter.sh --all --ignore-not-found=true --wait=false',
        'kubectl delete nodeclaims.karpenter.sh --all --ignore-not-found=true --wait=false'
    )
}

function Invoke-KarpenterSsmNodePoolDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][string]$BastionInstanceId,
        [ValidateRange(1, 120)][int]$MaxAttempts = 24,
        [ValidateRange(1, 60)][int]$DelaySeconds = 5
    )

    if ($BastionInstanceId -notmatch '^i-[0-9a-f]{8,17}$') {
        throw "Invalid Bastion instance ID for $ClusterName."
    }
    $parameterPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'karpenter-cleanup-' + [guid]::NewGuid().ToString('N') + '.json'
    )
    try {
        $parameters = @{
            commands = @(Get-KarpenterNodePoolDeleteCommands -Region $Region)
        } | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText(
            $parameterPath,
            $parameters,
            (New-Object System.Text.UTF8Encoding($false))
        )
        $parameterUri = 'file://' + $parameterPath.Replace('\', '/')
        $commandId = Invoke-KarpenterNative -FilePath 'aws' -ArgumentList @(
            'ssm', 'send-command',
            '--profile', $AwsProfile,
            '--region', $Region,
            '--instance-ids', $BastionInstanceId,
            '--document-name', 'AWS-RunShellScript',
            '--parameters', $parameterUri,
            '--query', 'Command.CommandId',
            '--output', 'text'
        ) -FailureMessage "Karpenter cleanup command could not start for $ClusterName."
        if ($commandId -notmatch '^[0-9a-f-]{36}$') {
            throw "SSM returned an invalid cleanup command ID for $ClusterName."
        }

        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try {
                $invocationJson = Invoke-KarpenterNative -FilePath 'aws' -ArgumentList @(
                    'ssm', 'get-command-invocation',
                    '--profile', $AwsProfile,
                    '--region', $Region,
                    '--command-id', $commandId,
                    '--instance-id', $BastionInstanceId,
                    '--output', 'json'
                ) -FailureMessage "Karpenter cleanup status could not be read for $ClusterName."
            } catch {
                if ($_.Exception.Message -match '(?i)InvocationDoesNotExist') {
                    Start-Sleep -Seconds $DelaySeconds
                    continue
                }
                throw
            }
            $invocation = $invocationJson | ConvertFrom-Json
            $status = [string]$invocation.Status
            if ($status -ceq 'Success') {
                Write-Host "Karpenter NodePool deletion requested: cluster=$ClusterName"
                return
            }
            if ($status -in @('Cancelled', 'Cancelling', 'Failed', 'TimedOut')) {
                $detail = ([string]$invocation.StandardErrorContent -replace '[\r\n]+', ' ').Trim()
                if ($detail.Length -gt 400) {
                    $detail = $detail.Substring(0, 400)
                }
                throw "Karpenter cleanup command failed for ${ClusterName}: status=$status; $detail"
            }
            Start-Sleep -Seconds $DelaySeconds
        }
        throw "Karpenter cleanup command timed out for $ClusterName."
    } finally {
        Remove-Item -LiteralPath $parameterPath -Force -ErrorAction SilentlyContinue
    }
}

function Wait-KarpenterInstancesGone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$ClusterName,
        [ValidateRange(30, 3600)][int]$TimeoutSeconds = 900,
        [ValidateRange(1, 60)][int]$PollSeconds = 15
    )

    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $instances = @(Get-KarpenterClusterInstances `
            -AwsProfile $AwsProfile `
            -Region $Region `
            -ProjectName $ProjectName `
            -ClusterName $ClusterName)
        if ($instances.Count -eq 0) {
            Write-Host "Karpenter instances removed: cluster=$ClusterName"
            return
        }
        if ([datetimeoffset]::UtcNow -ge $deadline) {
            $ids = @($instances | ForEach-Object { $_.InstanceId }) -join ', '
            throw "Karpenter instances did not terminate before the bounded timeout: cluster=$ClusterName; instances=$ids"
        }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Invoke-KarpenterPreDestroyCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AwsProfile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$BastionInstanceId = '',
        [switch]$AllowStrictOrphanTermination,
        [ValidateRange(30, 3600)][int]$TimeoutSeconds = 900,
        [ValidateRange(1, 60)][int]$PollSeconds = 15
    )

    $clusterExists = Test-KarpenterClusterExists `
        -AwsProfile $AwsProfile `
        -Region $Region `
        -ClusterName $ClusterName
    if ($clusterExists) {
        if (-not $BastionInstanceId) {
            throw "EKS cluster exists but its Bastion instance is unavailable: $ClusterName"
        }
        Invoke-KarpenterSsmNodePoolDelete `
            -AwsProfile $AwsProfile `
            -Region $Region `
            -ClusterName $ClusterName `
            -BastionInstanceId $BastionInstanceId
        Wait-KarpenterInstancesGone `
            -AwsProfile $AwsProfile `
            -Region $Region `
            -ProjectName $ProjectName `
            -ClusterName $ClusterName `
            -TimeoutSeconds $TimeoutSeconds `
            -PollSeconds $PollSeconds
        return [pscustomobject]@{
            Cluster = $ClusterName
            Mode    = 'GracefulNodePoolDeletion'
        }
    }

    $orphans = @(Get-KarpenterClusterInstances `
        -AwsProfile $AwsProfile `
        -Region $Region `
        -ProjectName $ProjectName `
        -ClusterName $ClusterName)
    if ($orphans.Count -eq 0) {
        return [pscustomobject]@{
            Cluster = $ClusterName
            Mode    = 'NothingToRemove'
        }
    }
    $unsafe = @($orphans | Where-Object { -not $_.StrictOwned })
    if ($unsafe.Count -gt 0) {
        $details = @($unsafe | ForEach-Object { "$($_.InstanceId): $($_.Reason)" }) -join '; '
        throw "Karpenter orphan cleanup refused because strict ownership is unproven: $details"
    }
    if (-not $AllowStrictOrphanTermination) {
        throw "Strictly-scoped Karpenter orphan instances exist, but DESTROY DAILY was not confirmed."
    }
    $instanceIds = @($orphans | ForEach-Object { [string]$_.InstanceId })
    foreach ($instanceId in $instanceIds) {
        if ($instanceId -notmatch '^i-[0-9a-f]{8,17}$') {
            throw "Karpenter inventory returned an unsafe instance ID: $instanceId"
        }
    }
    [void](Invoke-KarpenterNative -FilePath 'aws' -ArgumentList (
        @(
            'ec2', 'terminate-instances',
            '--profile', $AwsProfile,
            '--region', $Region,
            '--instance-ids'
        ) + $instanceIds + @('--output', 'json')
    ) -FailureMessage "Strict Karpenter orphan termination failed for $ClusterName.")
    Write-Host "Strict Karpenter orphan termination requested: cluster=$ClusterName; count=$($instanceIds.Count)"
    Wait-KarpenterInstancesGone `
        -AwsProfile $AwsProfile `
        -Region $Region `
        -ProjectName $ProjectName `
        -ClusterName $ClusterName `
        -TimeoutSeconds $TimeoutSeconds `
        -PollSeconds $PollSeconds
    return [pscustomobject]@{
        Cluster = $ClusterName
        Mode    = 'StrictOrphanTermination'
    }
}

Export-ModuleMember -Function @(
    'Get-KarpenterNodePoolDeleteCommands',
    'Test-KarpenterInstanceScope',
    'Get-KarpenterClusterInstances',
    'Invoke-KarpenterPreDestroyCleanup'
)
