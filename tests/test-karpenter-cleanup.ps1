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
        [string]$Discovery = 'aws-topology-primary',
        [string]$ClusterOwnership = 'owned',
        [string]$Project = 'aws-topology',
        [string]$ManagedBy = 'Karpenter'
    )
    return [pscustomobject]@{
        InstanceId = 'i-0123456789abcdef0'
        State = [pscustomobject]@{ Name = 'running' }
        Tags = @(
            New-TestTag -Key 'karpenter.sh/discovery' -Value $Discovery
            New-TestTag -Key 'kubernetes.io/cluster/aws-topology-primary' -Value $ClusterOwnership
            New-TestTag -Key 'karpenter.sh/nodeclaim' -Value 'default-test'
            New-TestTag -Key 'karpenter.sh/nodepool' -Value 'default'
            New-TestTag -Key 'Project' -Value $Project
            New-TestTag -Key 'ManagedBy' -Value $ManagedBy
        )
    }
}

$strictScope = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance) `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $strictScope.IsKarpenter -or -not $strictScope.StrictOwned) {
    throw 'Exact project, cluster, and Karpenter tags were not accepted.'
}

$wrongProject = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -Project 'another-project') `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if (-not $wrongProject.IsKarpenter -or $wrongProject.StrictOwned) {
    throw 'A Karpenter instance with the wrong Project tag was not rejected for orphan termination.'
}

$wrongCluster = Test-KarpenterInstanceScope `
    -Instance (New-TestKarpenterInstance -Discovery 'another-cluster') `
    -ProjectName 'aws-topology' `
    -ClusterName 'aws-topology-primary'
if ($wrongCluster.IsKarpenter -or $wrongCluster.StrictOwned) {
    throw 'An instance with the wrong cluster discovery tag entered Karpenter cleanup scope.'
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
    foreach ($requiredTag in @('kubernetes.io/cluster/', 'Project:', 'ManagedBy:')) {
        if ($source -notmatch [regex]::Escape($requiredTag)) {
            throw "Karpenter node template is missing a strict cleanup tag: $requiredTag"
        }
    }
}

Write-Host 'Karpenter cleanup self-test passed.'
