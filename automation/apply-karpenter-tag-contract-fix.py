from pathlib import Path
import subprocess

EXPECTED_BLOBS = {
    Path("templates/install-cluster-addons.sh.tpl"): "2b4c2d6abaec18cffd07095622b12e6991b09e61",
    Path("automation/Karpenter.Cleanup.psm1"): "861a9f35b53f2681cb11a1ad2e0f39c5bdc2c56f",
    Path("tests/test-karpenter-cleanup.ps1"): "92abd461c45a44a9a7fe0cc8c03c7bc5dc20a718",
    Path("charts/karpenter-node-config/templates/nodeclass.yaml"): "1bfe1a4d055da678b35d39f42b836446e1368849",
}


def assert_blob(path: Path, expected: str) -> None:
    actual = subprocess.check_output(
        ["git", "hash-object", str(path)], text=True
    ).strip()
    if actual != expected:
        raise SystemExit(f"{path} changed unexpectedly: {actual} != {expected}")


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one patch target in {path}, received {count}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def replace_between(path: Path, start: str, end: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"start marker not found in {path}: {start}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"end marker not found in {path}: {end}")
    updated = text[:start_index] + replacement + text[end_index:]
    path.write_text(updated, encoding="utf-8", newline="\n")


for file_path, blob_sha in EXPECTED_BLOBS.items():
    assert_blob(file_path, blob_sha)

ssm_template = Path("templates/install-cluster-addons.sh.tpl")
replace_once(
    ssm_template,
    '''  tags:
    Project: "${project_name}"
    ManagedBy: "Karpenter"
''',
    '''  tags:
    karpenter.sh/discovery: "${cluster_name}"
    "kubernetes.io/cluster/${cluster_name}": "owned"
    Project: "${project_name}"
    ManagedBy: "Karpenter"
''',
)

cleanup_module = Path("automation/Karpenter.Cleanup.psm1")
new_scope_function = r'''function Test-KarpenterInstanceScope {
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

'''
replace_between(
    cleanup_module,
    "function Test-KarpenterInstanceScope {",
    "function Get-KarpenterClusterInstances {",
    new_scope_function,
)
replace_once(
    cleanup_module,
    '''        'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down',
        "Name=tag:karpenter.sh/discovery,Values=$ClusterName",
        "Name=tag:kubernetes.io/cluster/$ClusterName,Values=owned",
        '--output', 'json'
''',
    '''        'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down',
        "Name=tag:Project,Values=$ProjectName",
        'Name=tag:ManagedBy,Values=Karpenter',
        '--output', 'json'
''',
)

cleanup_test = Path("tests/test-karpenter-cleanup.ps1")
new_test_instance_function = r'''function New-TestKarpenterInstance {
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
    if ($null -ne $Discovery) {
        $tags.Add((New-TestTag -Key 'karpenter.sh/discovery' -Value $Discovery))
    }
    if ($null -ne $ClusterOwnership) {
        $tags.Add((New-TestTag `
            -Key 'kubernetes.io/cluster/aws-topology-primary' `
            -Value $ClusterOwnership))
    }
    if ($null -ne $OtherClusterOwnership) {
        $tags.Add((New-TestTag `
            -Key 'kubernetes.io/cluster/another-cluster' `
            -Value $OtherClusterOwnership))
    }
    if ($null -ne $NodeClaim) {
        $tags.Add((New-TestTag -Key 'karpenter.sh/nodeclaim' -Value $NodeClaim))
    }
    if ($null -ne $NodePool) {
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

'''
replace_between(
    cleanup_test,
    "function New-TestKarpenterInstance {",
    "$strictScope =",
    new_test_instance_function,
)

new_scope_tests = r'''$strictScope = Test-KarpenterInstanceScope `
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

'''
replace_between(
    cleanup_test,
    "$strictScope =",
    "$commands =",
    new_scope_tests,
)
replace_once(
    cleanup_test,
    "@('kubernetes.io/cluster/', 'Project:', 'ManagedBy:')",
    "@('karpenter.sh/discovery:', 'kubernetes.io/cluster/', 'Project:', 'ManagedBy:')",
)

print("Karpenter tag contract patch applied.")
