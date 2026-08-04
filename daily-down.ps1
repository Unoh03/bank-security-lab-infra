#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfirmDestroy = '',
    [string]$TerraformRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$Region = 'ap-northeast-2',
    [string]$DrRegion = 'ap-northeast-1',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ProjectName = 'aws-topology',
    [string]$PrimaryBastionKeyPairName = 'seoul-public-ec2-key',
    [string]$DrBastionKeyPairName = 'tokyo-public-ec2-key',
    [string]$SshHost = 'bas',
    [string]$AutomationConfigPath = '',
    [string]$EvidenceRoot = '',
    [switch]$EvidenceOnly,
    [string]$ExperimentId = '',
    [string]$ScenarioId = 'daily-lifecycle',
    [datetime]$EvidenceStartUtc,
    [datetime]$EvidenceEndUtc,
    [ValidateRange(0, 30)]
    [int]$EvidenceEventTailSeconds = 0,
    [ValidateRange(0, 30)]
    [int]$EvidenceDeliveryGraceMinutes = 0,
    [switch]$RequireEvidence,
    [string[]]$RequiredEvidenceCollector = @(),
    [switch]$RunEvidenceQueries,
    [ValidateRange(30, 3600)]
    [int]$KarpenterCleanupTimeoutSeconds = 900,
    [ValidateRange(1, 60)]
    [int]$KarpenterCleanupPollSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = $PSScriptRoot
}

. (Join-Path $PSScriptRoot 'daily-common.ps1')
. (Join-Path $PSScriptRoot 'daily-session-common.ps1')

if (-not $AutomationConfigPath) {
    $AutomationConfigPath = Join-Path $PSScriptRoot 'automation\project.psd1'
}
$automationModule = Join-Path $PSScriptRoot 'automation\Daily.Automation.psm1'
Import-Module $automationModule -Force
$karpenterCleanupModule = Join-Path $PSScriptRoot 'automation\Karpenter.Cleanup.psm1'
Import-Module $karpenterCleanupModule -Force
$automationConfig = Import-DailyAutomationConfig -Path $AutomationConfigPath

$startedAt = Get-Date
$foundationRoot = Join-Path $TerraformRoot 'foundation'
$planPath = Join-Path $TerraformRoot 'daily-down.tfplan'
$evidence = $null
$sessionMutex = $null
$hasEvidenceStart = $PSBoundParameters.ContainsKey('EvidenceStartUtc')
$hasEvidenceEnd = $PSBoundParameters.ContainsKey('EvidenceEndUtc')

if (-not $ExperimentId) {
    $ExperimentId = 'daily-' +
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Get-ResourceRegion {
    param(
        [Parameter(Mandatory)][object]$Values,
        [Parameter(Mandatory)][string]$DefaultRegion
    )

    if ($Values.PSObject.Properties.Name -contains 'region' -and $Values.region) {
        return [string]$Values.region
    }
    foreach ($property in @('arn', 'cluster_arn')) {
        if ($Values.PSObject.Properties.Name -contains $property -and $Values.$property) {
            $parts = ([string]$Values.$property) -split ':'
            if ($parts.Count -gt 3 -and $parts[3]) {
                return $parts[3]
            }
        }
    }
    return $DefaultRegion
}

function Add-TrackedResources {
    param(
        [Parameter(Mandatory)][object]$Module,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Destination
    )

    $resources = if ($Module.PSObject.Properties.Name -contains 'resources') {
        @($Module.resources)
    } else {
        @()
    }
    foreach ($resource in $resources) {
        if ($resource.mode -ne 'managed') {
            continue
        }
        $type = [string]$resource.type
        if ($type -notin @(
            'aws_eks_cluster',
            'aws_instance',
            'aws_nat_gateway',
            'aws_eip',
            'aws_lb',
            'aws_lb_target_group',
            'aws_db_instance',
            'aws_cloudfront_distribution',
            'aws_efs_file_system',
            'aws_elasticache_replication_group',
            'aws_s3_bucket'
        )) {
            continue
        }

        $values = $resource.values
        $id = if ($type -in @('aws_lb', 'aws_lb_target_group')) {
            [string]$values.arn
        } elseif ($type -eq 'aws_eip' -and
                  $values.PSObject.Properties.Name -contains 'allocation_id') {
            [string]$values.allocation_id
        } elseif ($type -eq 'aws_eks_cluster' -and
                  $values.PSObject.Properties.Name -contains 'name') {
            [string]$values.name
        } else {
            [string]$values.id
        }
        if (-not $id) {
            continue
        }

        $Destination.Add([pscustomobject]@{
            Address = [string]$resource.address
            Type    = $type
            Id      = $id
            Region  = Get-ResourceRegion -Values $values -DefaultRegion $Region
        })
    }

    $children = if ($Module.PSObject.Properties.Name -contains 'child_modules') {
        @($Module.child_modules)
    } else {
        @()
    }
    foreach ($child in $children) {
        Add-TrackedResources -Module $child -Destination $Destination
    }
}

function Get-TrackedRuntimeResources {
    $json = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'show', '-json'
    ) -FailureMessage 'Current Terraform state could not be inspected before destroy.'
    $state = $json | ConvertFrom-Json
    $result = New-Object System.Collections.Generic.List[object]
    if ($state.values -and $state.values.root_module) {
        Add-TrackedResources -Module $state.values.root_module -Destination $result
    }
    return $result.ToArray()
}

function Test-TrackedResourceStillExists {
    param([Parameter(Mandatory)][object]$Resource)

    $common = @('--profile', $AwsProfile, '--region', $Resource.Region, '--output', 'json')
    switch ($Resource.Type) {
        'aws_eks_cluster' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('eks', 'describe-cluster', '--name', $Resource.Id) + $common
            )
        }
        'aws_instance' {
            $json = Get-OptionalAwsJson -ArgumentList (
                @('ec2', 'describe-instances', '--instance-ids', $Resource.Id) + $common
            )
            if (-not $json) { return $false }
            $instance = $json.Reservations.Instances |
                Select-Object -First 1
            return $instance -and $instance.State.Name -ne 'terminated'
        }
        'aws_nat_gateway' {
            $json = Get-OptionalAwsJson -ArgumentList (
                @('ec2', 'describe-nat-gateways', '--nat-gateway-ids', $Resource.Id) + $common
            )
            if (-not $json) { return $false }
            $gateway = $json.NatGateways |
                Select-Object -First 1
            return $gateway -and $gateway.State -ne 'deleted'
        }
        'aws_eip' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('ec2', 'describe-addresses', '--allocation-ids', $Resource.Id) + $common
            )
        }
        'aws_lb' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('elbv2', 'describe-load-balancers', '--load-balancer-arns', $Resource.Id) + $common
            )
        }
        'aws_lb_target_group' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('elbv2', 'describe-target-groups', '--target-group-arns', $Resource.Id) + $common
            )
        }
        'aws_db_instance' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('rds', 'describe-db-instances', '--db-instance-identifier', $Resource.Id) + $common
            )
        }
        'aws_cloudfront_distribution' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList @(
                'cloudfront', 'get-distribution',
                '--id', $Resource.Id,
                '--profile', $AwsProfile,
                '--output', 'json'
            )
        }
        'aws_efs_file_system' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @('efs', 'describe-file-systems', '--file-system-id', $Resource.Id) + $common
            )
        }
        'aws_elasticache_replication_group' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList (
                @(
                    'elasticache', 'describe-replication-groups',
                    '--replication-group-id', $Resource.Id
                ) + $common
            )
        }
        'aws_s3_bucket' {
            return Test-NativeCommand -FilePath 'aws' -ArgumentList @(
                's3api', 'head-bucket',
                '--bucket', $Resource.Id,
                '--profile', $AwsProfile
            )
        }
        default {
            return $false
        }
    }
}

try {
    $sessionMutex = Enter-DailySessionDownMutex
    [void](Assert-DailySessionTerraformIdle -TerraformRoot $TerraformRoot)
    Start-AwakeMode
    foreach ($command in @('terraform', 'aws')) {
        Assert-CommandAvailable -Name $command
    }

    $identity = Get-AwsIdentity -Profile $AwsProfile -Region $Region
    Assert-AwsIdentity -Identity $identity -ExpectedAccountId $ExpectedAccountId
    Write-Host "AWS preflight: account=$($identity.Account), region=$Region"

    $foundation = Get-FoundationContext `
        -FoundationRoot $foundationRoot `
        -Profile $AwsProfile `
        -Region $Region `
        -DrRegion $DrRegion `
        -ExpectedAccountId $ExpectedAccountId
    $dailyState = @(Get-TerraformStateAddresses -Root $TerraformRoot)

    $evidenceContext = @{
        TerraformRoot  = $TerraformRoot
        FoundationRoot = $foundationRoot
        AwsProfile     = $AwsProfile
        AccountId      = [string]$identity.Account
        ProjectName    = $ProjectName
        PrimaryRegion  = $Region
        DrRegion       = $DrRegion
    }
    $application = Get-DailyApplication -Config $automationConfig -Name 'dvwa'
    $sourceRoot = [string]$application.SourceRootDefault
    if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
        $gitCommit = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
            '-C', $sourceRoot, 'rev-parse', 'HEAD'
        ) -FailureMessage 'DVWA Git commit could not be read for the evidence manifest.'
        $evidenceContext.GitCommit = $gitCommit.Trim()

        $valuesPath = Join-Path $sourceRoot ([string]$application.ValuesRelativePath)
        if (Test-Path -LiteralPath $valuesPath -PathType Leaf) {
            $declaredImage = Get-DeclaredImage -ValuesPath $valuesPath
            $evidenceContext.ImageSha = [string]$declaredImage.Tag
        }
    }
    if ($dailyState.Count -gt 0) {
        try {
            [void](Assert-CommandAvailable -Name 'ssh')
            $argoRevision = Invoke-NativeCapture -FilePath 'ssh' -ArgumentList @(
                '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'ConnectTimeout=15',
                $SshHost,
                "kubectl -n argocd get application $([string]$application.ArgoApplication) -o jsonpath='{.status.sync.revision}'"
            ) -FailureMessage 'Argo CD sync revision could not be read through the Bastion.'
            if ($argoRevision) {
                $evidenceContext.ArgoRevision = $argoRevision.Trim()
            }
        } catch {
            Write-Warning "Argo revision was not added to evidence context: $($_.Exception.Message)"
        }
    }

    function Invoke-ConfiguredEvidenceCollection {
        param(
            [Parameter(Mandatory)][string]$Phase,
            [switch]$UsePhaseSuffix
        )

        $phaseExperimentId = if ($UsePhaseSuffix) {
            "$ExperimentId-$Phase"
        } else {
            $ExperimentId
        }
        $arguments = @{
            Config = $automationConfig
            Context = $evidenceContext
            EvidenceRoot = $EvidenceRoot
            ExperimentId = $phaseExperimentId
            ScenarioId = $ScenarioId
            RequireEvidence = $RequireEvidence
            RequiredCollectorNames = $RequiredEvidenceCollector
            # Runtime Log Groups may be removed by Terraform. Execute mapped
            # Insights queries before teardown (or EvidenceOnly), not after it.
            RunQueries = [bool]($RunEvidenceQueries -and $Phase -cne 'post-destroy')
            EventTailSeconds = $EvidenceEventTailSeconds
            S3DeliveryGraceMinutes = $EvidenceDeliveryGraceMinutes
            Phase = $Phase
        }
        if ($hasEvidenceStart) {
            $arguments.StartTimeUtc = $EvidenceStartUtc
        }
        if ($hasEvidenceEnd) {
            $arguments.EndTimeUtc = $EvidenceEndUtc
        }
        return Invoke-DailyEvidenceCollection @arguments
    }

    if ($EvidenceOnly) {
        $evidence = Invoke-ConfiguredEvidenceCollection -Phase 'manual'
        Write-Host "Evidence collection completed without Terraform changes: $($evidence.ManifestPath)"
        exit 0
    }

    if ($dailyState.Count -eq 0) {
        $untrackedRuntime = @(Get-TaggedProjectRuntimeResources `
            -Profile $AwsProfile `
            -ProjectName $ProjectName `
            -Regions @($Region, $DrRegion, 'us-east-1'))
        if ($untrackedRuntime.Count -gt 0) {
            $details = Format-TaggedProjectRuntimeResources -Resources $untrackedRuntime
            throw "Daily state is empty, but tagged project runtime remains in AWS. Nothing was deleted automatically:`n$($details -join "`n")"
        }
        Write-Host 'Daily Terraform state is already empty.'
        Write-Host 'Tagged daily AWS runtime: none'
        Write-Host "Foundation retained: ECR=$($foundation.RepositoryName)"
        if ($foundation.SecurityLogBucket) {
            Write-Host "Foundation retained: security logs=$($foundation.SecurityLogBucket)"
        }
        [void](Complete-DailySessionGuard `
            -SessionSafety $automationConfig.SessionSafety `
            -TerraformRoot $TerraformRoot)
        exit 0
    }

    Write-Warning 'Capture any required runtime or security evidence before confirming destroy.'
    $trackedResources = Get-TrackedRuntimeResources

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'init', '-input=false', '-upgrade=false'
    ) -FailureMessage 'Daily Terraform initialization failed.'

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'plan',
        '-destroy',
        '-input=false',
        "-var=aws_profile=$AwsProfile",
        "-var=project_name=$ProjectName",
        "-var=primary_region=$Region",
        "-var=dr_region=$DrRegion",
        "-var=primary_bastion_key_pair_name=$PrimaryBastionKeyPairName",
        "-var=dr_bastion_key_pair_name=$DrBastionKeyPairName",
        "-out=$planPath"
    ) -FailureMessage 'Daily Terraform destroy plan failed.'

    $planSummary = Get-TerraformPlanSummary -Root $TerraformRoot -PlanPath $planPath
    Write-TerraformPlanSummary -Summary $planSummary -Label 'Daily down'
    Assert-DailyPlanPreservesFoundation -Summary $planSummary

    $removesLegacyTrail = @($planSummary.Changed | Where-Object {
        $_ -match '^delete\s+aws_cloudtrail\.this$'
    }).Count -gt 0
    if ($removesLegacyTrail -and -not $foundation.SecurityTrailName) {
        throw 'Daily destroy would remove the legacy CloudTrail before the persistent security trail exists. Apply the reviewed Foundation plan first.'
    }

    if ($ConfirmDestroy -cne 'DESTROY DAILY') {
        Write-Host "No AWS change was made. Review the plan, then rerun with -ConfirmDestroy 'DESTROY DAILY'."
        exit 2
    }

    $evidence = Invoke-ConfiguredEvidenceCollection `
        -Phase 'pre-destroy' `
        -UsePhaseSuffix
    foreach ($result in @($evidence.Results)) {
        Write-Host "Evidence: $($result.Name) [$($result.Status)] $($result.Detail)"
    }
    Write-Host "Evidence manifest: $($evidence.ManifestPath)"

    $primaryBastion = @($trackedResources | Where-Object {
        $_.Address -ceq 'aws_instance.primary_bastion'
    }) | Select-Object -First 1
    $drBastion = @($trackedResources | Where-Object {
        $_.Address -ceq 'aws_instance.dr_bastion[0]'
    }) | Select-Object -First 1
    $karpenterTargets = @(
        [pscustomobject]@{
            Region            = $Region
            ClusterName       = "$ProjectName-primary"
            BastionInstanceId = if ($primaryBastion) { [string]$primaryBastion.Id } else { '' }
        },
        [pscustomobject]@{
            Region            = $DrRegion
            ClusterName       = "$ProjectName-dr"
            BastionInstanceId = if ($drBastion) { [string]$drBastion.Id } else { '' }
        }
    )
    foreach ($target in $karpenterTargets) {
        $cleanup = Invoke-KarpenterPreDestroyCleanup `
            -AwsProfile $AwsProfile `
            -Region ([string]$target.Region) `
            -ProjectName $ProjectName `
            -ClusterName ([string]$target.ClusterName) `
            -BastionInstanceId ([string]$target.BastionInstanceId) `
            -AllowStrictOrphanTermination `
            -TimeoutSeconds $KarpenterCleanupTimeoutSeconds `
            -PollSeconds $KarpenterCleanupPollSeconds
        Write-Host "Karpenter pre-destroy cleanup: cluster=$($cleanup.Cluster); mode=$($cleanup.Mode)"
    }

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'apply',
        '-input=false',
        $planPath
    ) -FailureMessage 'Daily Terraform destroy failed.'
    Remove-Item -LiteralPath $planPath -Force -ErrorAction SilentlyContinue

    $remainingState = @(Get-TerraformStateAddresses -Root $TerraformRoot)
    if ($remainingState.Count -gt 0) {
        throw "Daily Terraform state is not empty after destroy: $($remainingState.Count) addresses remain."
    }

    # The destroy itself generates audit events. Sync the persistent archive
    # again after the long teardown; the removed legacy Daily bucket now skips.
    $postDestroyEvidence = Invoke-ConfiguredEvidenceCollection `
        -Phase 'post-destroy' `
        -UsePhaseSuffix
    $evidence = $postDestroyEvidence
    foreach ($result in @($postDestroyEvidence.Results)) {
        Write-Host "Post-destroy evidence: $($result.Name) [$($result.Status)] $($result.Detail)"
    }
    Write-Host "Post-destroy evidence manifest: $($postDestroyEvidence.ManifestPath)"

    $residue = New-Object System.Collections.Generic.List[object]
    foreach ($resource in $trackedResources) {
        if (Test-TrackedResourceStillExists -Resource $resource) {
            $residue.Add($resource)
        }
    }
    if ($residue.Count -gt 0) {
        $details = $residue |
            ForEach-Object { "$($_.Type)`t$($_.Id)`t$($_.Region)" }
        throw "Daily AWS residue remains and may incur cost:`n$($details -join "`n")"
    }

    $taggedResidue = @(Get-TaggedProjectRuntimeResources `
        -Profile $AwsProfile `
        -ProjectName $ProjectName `
        -Regions @($Region, $DrRegion, 'us-east-1'))
    if ($taggedResidue.Count -gt 0) {
        $details = Format-TaggedProjectRuntimeResources -Resources $taggedResidue
        throw "Tagged project runtime remains after destroy and may incur cost:`n$($details -join "`n")"
    }

    $retained = Get-FoundationContext `
        -FoundationRoot $foundationRoot `
        -Profile $AwsProfile `
        -Region $Region `
        -DrRegion $DrRegion `
        -ExpectedAccountId $ExpectedAccountId

    [void](Complete-DailySessionGuard `
        -SessionSafety $automationConfig.SessionSafety `
        -TerraformRoot $TerraformRoot)

    $elapsed = (Get-Date) - $startedAt
    Write-Host ''
    Write-Host 'Daily down completed.'
    Write-Host 'Daily Terraform state: empty'
    Write-Host 'Tracked daily AWS residue: none'
    Write-Host 'Tagged daily AWS runtime: none'
    Write-Host "Foundation ECR retained: $($retained.RepositoryName)"
    Write-Host "Foundation GitHub Actions Role retained: $($retained.RoleArn)"
    if ($retained.SecurityLogBucket) {
        Write-Host "Foundation security logs retained: $($retained.SecurityLogBucket)"
        Write-Host "Foundation security-log retention: $($retained.SecurityRetentionDays) days"
    }
    if ($evidence) {
        Write-Host "Local evidence archive: $($evidence.Root)"
    }
    Write-Host "Elapsed: $([math]::Round($elapsed.TotalMinutes, 1)) minutes"
} finally {
    Stop-AwakeMode
    Exit-DailySessionDownMutex -Mutex $sessionMutex
}
