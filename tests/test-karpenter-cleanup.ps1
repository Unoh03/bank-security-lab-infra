#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'automation\Karpenter.Cleanup.psm1'
Import-Module $modulePath -Force

function New-TestTag {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )
    return [pscustomobject]@{ Key = $Key; Value = $Value }
}

function New-TestKarpenterInstance {
    param(
        [AllowNull()][string]$Discovery = 'aws-topology-primary',
        [AllowNull()][string]$ClusterOwnership = 'owned',
        [AllowNull()][string]$OtherClusterOwnership = $null,
        [string]$Project = 'aws-topology',
        [string]$ManagedBy = 'Karpenter',
        [AllowNull()][string]$NodeClaim = 'default-test',
        [AllowNull()][string]$NodePool = 'default'
    )

    $tags = New-Object System.Collections.Generic.List[object]
    if (-not [string]::IsNullOrWhiteSpace($Discovery)) {
        $tags.Add((New-TestTag -Key 'karpenter.sh/discovery' -Value $Discovery))
    }
    if (-not [string]::IsNullOrWhiteSpace($ClusterOwnership)) {
        $tags.Add((New-TestTag `
            -Key 'kubernetes.io/cluster/aws-topology-primary' `
            -Value $ClusterOwnership))
    }
    if (-not [string]::IsNullOrWhiteSpace($OtherClusterOwnership)) {
        $tags.Add((New-TestTag `
            -Key 'kubernetes.io/cluster/another-cluster' `
            -Value $OtherClusterOwnership))
    }
    if (-not [string]::IsNullOrWhiteSpace($NodeClaim)) {
        $tags.Add((New-TestTag -Key 'karpenter.sh/nodeclaim' -Value $NodeClaim))
    }
    if (-not [string]::IsNullOrWhiteSpace($NodePool)) {
        $tags.Add((New-TestTag -Key 'karpenter.sh/nodepool' -Value $NodePool))
    }
    $tags.Add((New-TestTag -Key 'Project' -Value $Project))
    $tags.Add((New-TestTag -Key 'ManagedBy' -Value $ManagedBy))

    return [pscustomobject]@{
        InstanceId = 'i-0123456789abcdef0'
        State = [pscustomobject]@{ Name = 'running' }
        Tags = $tags.ToArray()
    }
}

$strictScope = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance) `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $strictScope.IsKarpenter -or -not $strictScope.StrictOwned) {
    throw 'Exact project, cluster, and Karpenter tags were not accepted.'
}

$legacyMissingDiscovery = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -Discovery $null) `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $legacyMissingDiscovery.IsKarpenter -or
    -not $legacyMissingDiscovery.StrictOwned) {
    throw 'A legacy Karpenter instance with exact cluster ownership but no discovery tag was not safely tracked.'
}

$wrongProject = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -Project 'another-project') `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $wrongProject.IsKarpenter -or $wrongProject.StrictOwned) {
    throw 'A Karpenter instance with the wrong Project tag was not rejected for orphan termination.'
}

$otherCluster = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance `
        -Discovery 'another-cluster' `
        -ClusterOwnership $null `
        -OtherClusterOwnership 'owned') `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if ($otherCluster.IsKarpenter -or $otherCluster.StrictOwned) {
    throw 'An instance belonging only to another cluster entered target-cluster cleanup scope.'
}

$conflictingIdentity = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -Discovery 'another-cluster') `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $conflictingIdentity.IsKarpenter -or
    $conflictingIdentity.StrictOwned -or
    -not $conflictingIdentity.IdentityConflict) {
    throw 'Conflicting discovery and ownership tags were not retained as an unsafe cleanup candidate.'
}

$ambiguousIdentity = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance `
        -Discovery $null `
        -ClusterOwnership $null) `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $ambiguousIdentity.IsKarpenter -or
    $ambiguousIdentity.StrictOwned -or
    -not $ambiguousIdentity.Ambiguous) {
    throw 'A project-scoped Karpenter instance with no cluster identity was not retained for fail-closed handling.'
}

$missingNodeIdentity = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -NodeClaim $null) `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $missingNodeIdentity.IsKarpenter -or $missingNodeIdentity.StrictOwned) {
    throw 'A target-cluster instance missing NodeClaim identity was accepted for strict orphan termination.'
}

$global:KarpenterInventoryCalls = New-Object System.Collections.Generic.List[string]
function global:aws {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $global:KarpenterInventoryCalls.Add(($arguments -join ' '))
    $global:LASTEXITCODE = 0
    return (@{
        Reservations = @(
            @{
                Instances = @(
                    @{
                        InstanceId = 'i-0123456789abcdef0'
                        State = @{ Name = 'running' }
                        Tags = @(
                            @{ Key = 'kubernetes.io/cluster/aws-topology-primary'; Value = 'owned' }
                            @{ Key = 'karpenter.sh/nodeclaim'; Value = 'default-test' }
                            @{ Key = 'karpenter.sh/nodepool'; Value = 'default' }
                            @{ Key = 'Project'; Value = 'aws-topology' }
                            @{ Key = 'ManagedBy'; Value = 'Karpenter' }
                        )
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 8 -Compress)
}
try {
    $inventory = @(Get-KarpenterClusterInstances `
        -AwsProfile 'test' `
        -Region 'ap-northeast-2' `
        -ProjectName 'aws-topology' `
        -ClusterName 'aws-topology-primary')
    if ($inventory.Count -ne 1 -or -not $inventory[0].StrictOwned) {
        throw 'Broad Karpenter inventory did not retain a legacy instance with a missing discovery tag.'
    }
    $inventoryCall = @($global:KarpenterInventoryCalls) | Select-Object -First 1
    foreach ($requiredFilter in @(
        'Name=tag:Project,Values=aws-topology',
        'Name=tag:ManagedBy,Values=Karpenter'
    )) {
        if ($inventoryCall -notmatch [regex]::Escape($requiredFilter)) {
            throw "Karpenter inventory is missing its broad ownership filter: $requiredFilter"
        }
    }
    if ($inventoryCall -match 'Name=tag:karpenter\.sh/discovery' -or
        $inventoryCall -match 'Name=tag:kubernetes\.io/cluster/') {
        throw 'Karpenter inventory still filters out partially tagged instances before scope validation.'
    }
} finally {
    Remove-Item Function:\aws -Force -ErrorAction SilentlyContinue
    Remove-Variable KarpenterInventoryCalls -Scope Global -ErrorAction SilentlyContinue
}

$commands = @(Get-KarpenterNodePoolDeleteCommands -Region 'ap-northeast-2')
foreach ($expected in @(
    'export KUBECONFIG=/root/.kube/config',
    'kubectl delete nodepools.karpenter.sh --all --ignore-not-found=true --wait=false',
    'kubectl delete nodeclaims.karpenter.sh --all --ignore-not-found=true --wait=false'
)) {
    if ($commands -notcontains $expected) {
        throw "Karpenter graceful cleanup command is missing: $expected"
    }
}

$dailyDownPath = Join-Path $root 'daily-down.ps1'
$dailyDownSource = Get-Content -LiteralPath $dailyDownPath -Raw
$confirmationIndex = $dailyDownSource.IndexOf("if (`$ConfirmDestroy -cne 'DESTROY DAILY')")
$cleanupIndex = $dailyDownSource.IndexOf('Invoke-KarpenterPreDestroyCleanup')
$destroyApplyIndex = $dailyDownSource.IndexOf(
    "Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(",
    $cleanupIndex
)
if ($confirmationIndex -lt 0 -or $cleanupIndex -lt 0 -or $destroyApplyIndex -lt 0 -or
    $cleanupIndex -le $confirmationIndex -or $cleanupIndex -ge $destroyApplyIndex) {
    throw 'Karpenter cleanup is not ordered after exact confirmation and before Terraform destroy apply.'
}

$moduleSource = Get-Content -LiteralPath $modulePath -Raw
if ($moduleSource -notmatch 'pending,running,stopping,stopped,shutting-down') {
    throw 'Karpenter wait can stop before an EC2 instance finishes shutting down.'
}

$nodeClassSource = Get-Content -LiteralPath (
    Join-Path $root 'charts\karpenter-node-config\templates\nodeclass.yaml'
) -Raw
$ssmTemplateSource = Get-Content -LiteralPath (
    Join-Path $root 'templates\install-cluster-addons.sh.tpl'
) -Raw
foreach ($source in @($nodeClassSource, $ssmTemplateSource)) {
    # Selector의 discovery Tag와 사용자 정의 소유권 Tag는 필요하다.
    foreach ($requiredText in @(
        'karpenter.sh/discovery:',
        'Project:',
        'ManagedBy:'
    )) {
        if ($source -notmatch [regex]::Escape($requiredText)) {
            throw "Karpenter node template is missing required content: $requiredText"
        }
    }

    # EC2NodeClass spec.tags에는 Karpenter restricted domain을 직접 넣으면 안 된다.
    # 정확히 네 칸 들여쓴 줄만 검사하므로, 여덟 칸 들여쓴 Selector Tag는 허용된다.
    foreach ($restrictedSpecTag in @(
        '(?m)^ {4}karpenter\.sh/discovery:',
        '(?m)^ {4}\S.*kubernetes\.io/cluster/'
    )) {
        if ($source -match $restrictedSpecTag) {
            throw "EC2NodeClass spec.tags contains a restricted Karpenter tag: $restrictedSpecTag"
        }
    }
}
}

Write-Host 'Karpenter cleanup self-test passed.'
