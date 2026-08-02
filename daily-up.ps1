#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfirmApply = '',
    [string]$TerraformRoot = '',
    [string]$DvWaRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$Region = 'ap-northeast-2',
    [string]$DrRegion = 'ap-northeast-1',
    [string]$ExpectedAccountId = '433048100798',
    [string]$ProjectName = 'aws-topology',
    [string]$GitHubRepository = '',
    [string]$ApplicationName = 'dvwa',
    [string]$AutomationConfigPath = '',
    [string]$PrimaryBastionKeyPairName = 'seoul-public-ec2-key',
    [string]$DrBastionKeyPairName = 'tokyo-public-ec2-key',
    [string]$SshKeyPath = "$HOME\.ssh\seoul-public-ec2-key.pem",
    [string]$SshConfigPath = "$HOME\.ssh\config",
    [string]$ArgoDeployKeyPath = "$HOME\.ssh\argocd-uns-dvwa",
    [string]$ExperimentId = ''
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
$automationConfig = Import-DailyAutomationConfig -Path $AutomationConfigPath
$application = Get-DailyApplication `
    -Config $automationConfig `
    -Name $ApplicationName
if (-not $DvWaRoot) {
    $DvWaRoot = [string]$application.SourceRootDefault
}
if (-not $GitHubRepository) {
    $GitHubRepository = [string]$application.GitHubRepositoryDefault
}

$startedAt = Get-Date
$foundationRoot = Join-Path $TerraformRoot 'foundation'
$planPath = Join-Path $TerraformRoot 'daily-up.tfplan'
$valuesPath = Join-Path $DvWaRoot ([string]$application.ValuesRelativePath)
$runtimeBootstrap = Join-Path $TerraformRoot ([string]$application.Database.BootstrapScript)
$argoBootstrap = Join-Path $DvWaRoot ([string]$application.ArgoBootstrapRelativePath)
$runtimeBootstrapFileName = Split-Path -Leaf $runtimeBootstrap
$argoBootstrapFileName = Split-Path -Leaf $argoBootstrap
$workflowFile = [string]$application.WorkflowFile
$argoApplication = [string]$application.ArgoApplication
$applicationNamespace = [string]$application.Namespace
$workloadKind = [string]$application.WorkloadKind
$workloadName = [string]$application.WorkloadName
$podSelector = [string]$application.PodSelector
$urlTerraformOutput = [string]$application.UrlTerraformOutput
$databaseOutput = [string]$application.Database.TerraformOutput
$databaseSecretName = [string]$application.Database.KubernetesSecretName
$watchdogScript = Join-Path $PSScriptRoot 'daily-session-watchdog.ps1'
$tempRoot = $null

function Assert-FileAvailable {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is unavailable: $Path"
    }
}

function Sync-ApplicationRepository {
    $dirty = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
        '-C', $DvWaRoot, 'status', '--porcelain'
    )
    if ($dirty) {
        throw "$DvWaRoot has uncommitted changes. Commit or discard them before daily-up."
    }

    Invoke-NativePassthrough -FilePath 'git' -ArgumentList @(
        '-C', $DvWaRoot, 'fetch', '--no-tags', 'origin', 'main'
    ) -FailureMessage 'DVWA origin/main could not be fetched.'

    $head = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
        '-C', $DvWaRoot, 'rev-parse', 'HEAD'
    )
    $remote = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
        '-C', $DvWaRoot, 'rev-parse', 'origin/main'
    )
    if ($head -eq $remote) {
        return
    }

    $base = Invoke-NativeCapture -FilePath 'git' -ArgumentList @(
        '-C', $DvWaRoot, 'merge-base', 'HEAD', 'origin/main'
    )
    if ($head -eq $base) {
        Invoke-NativePassthrough -FilePath 'git' -ArgumentList @(
            '-C', $DvWaRoot, 'merge', '--ff-only', 'origin/main'
        ) -FailureMessage 'DVWA could not be fast-forwarded to origin/main.'
        return
    }

    if ($remote -eq $base) {
        throw "$DvWaRoot contains commits that are not on origin/main. Push them before daily-up."
    }

    throw "$DvWaRoot and origin/main have diverged. Resolve the Git history before daily-up."
}

function Test-EcrImage {
    param(
        [Parameter(Mandatory)][string]$RepositoryName,
        [Parameter(Mandatory)][string]$Tag
    )

    return Test-NativeCommand -FilePath 'aws' -ArgumentList @(
        'ecr', 'describe-images',
        '--profile', $AwsProfile,
        '--region', $Region,
        '--repository-name', $RepositoryName,
        '--image-ids', "imageTag=$Tag",
        '--output', 'json'
    )
}

function Invoke-ApplicationCiWhenNeeded {
    param([Parameter(Mandatory)][object]$Foundation)

    $image = Get-DeclaredImage -ValuesPath $valuesPath
    $validTag = $image.Tag -match '^sha-[0-9a-f]{40}$'
    $correctRepository = $image.Repository -ceq $Foundation.RepositoryUrl
    $exists = $validTag -and $correctRepository -and
        (Test-EcrImage -RepositoryName $Foundation.RepositoryName -Tag $image.Tag)

    if ($exists) {
        Write-Host "ECR image already exists: $($image.Tag)"
        return $image
    }

    Assert-CommandAvailable -Name 'gh'
    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'auth', 'status'
    ) -FailureMessage 'GitHub CLI is not authenticated.'

    $triggeredAt = (Get-Date).ToUniversalTime().AddMinutes(-1)
    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'workflow', 'run', $workflowFile,
        '--repo', $GitHubRepository,
        '--ref', 'main'
    ) -FailureMessage 'The DVWA CI workflow could not be started.'

    $run = $null
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        Start-Sleep -Seconds 2
        $runsJson = Invoke-NativeCapture -FilePath 'gh' -ArgumentList @(
            'run', 'list',
            '--repo', $GitHubRepository,
            '--workflow', $workflowFile,
            '--branch', 'main',
            '--event', 'workflow_dispatch',
            '--limit', '5',
            '--json', 'databaseId,createdAt,status,conclusion'
        ) -FailureMessage 'GitHub Actions runs could not be listed.'
        $run = @($runsJson | ConvertFrom-Json) |
            Where-Object { [datetime]$_.createdAt -ge $triggeredAt } |
            Sort-Object { [datetime]$_.createdAt } -Descending |
            Select-Object -First 1
        if ($run) {
            break
        }
    }
    if (-not $run) {
        throw 'The triggered GitHub Actions run could not be identified.'
    }

    Invoke-NativePassthrough -FilePath 'gh' -ArgumentList @(
        'run', 'watch', [string]$run.databaseId,
        '--repo', $GitHubRepository,
        '--exit-status'
    ) -FailureMessage 'DVWA CI failed.'

    Sync-ApplicationRepository
    $image = Get-DeclaredImage -ValuesPath $valuesPath
    if ($image.Repository -cne $Foundation.RepositoryUrl -or
        $image.Tag -notmatch '^sha-[0-9a-f]{40}$' -or
        -not (Test-EcrImage -RepositoryName $Foundation.RepositoryName -Tag $image.Tag)) {
        throw 'CI completed, but the declared immutable image is not present in Foundation ECR.'
    }

    return $image
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Protect-LocalSecretFile {
    param([Parameter(Mandatory)][string]$Path)
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $Path /inheritance:r /grant:r "${currentIdentity}:(R,W)" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Local secret file ACL could not be restricted: $Path"
    }
}

function ConvertTo-MariaDbOptionValue {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match "[`r`n]") {
        throw 'A database option contains a newline and cannot be serialized safely.'
    }
    return '"' + ($Value.Replace('\', '\\').Replace('"', '\"')) + '"'
}

function Invoke-Ssh {
    param(
        [Parameter(Mandatory)][string[]]$CommonArguments,
        [Parameter(Mandatory)][string]$Remote,
        [Parameter(Mandatory)][string]$Command
    )
    Invoke-NativePassthrough -FilePath 'ssh' -ArgumentList (
        $CommonArguments + @($Remote, $Command)
    ) -FailureMessage "Remote command failed: $Command"
}

function Wait-SsmAssociationSuccess {
    param(
        [Parameter(Mandatory)][string]$AssociationId,
        [int]$MaxAttempts = 120,
        [int]$DelaySeconds = 10
    )

    $lastStatus = 'unknown'
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $associationJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
                'ssm', 'describe-association',
                '--profile', $AwsProfile,
                '--region', $Region,
                '--association-id', $AssociationId,
                '--output', 'json'
            ) -FailureMessage 'The EKS add-on SSM association could not be read.'
            $association = $associationJson | ConvertFrom-Json
            $lastStatus = [string]$association.AssociationDescription.Overview.Status
            if ($lastStatus -eq 'Success') {
                Write-Host "EKS add-on association succeeded after $attempt check(s)."
                return
            }
            if ($lastStatus -eq 'Failed') {
                throw "EKS add-on association failed: $AssociationId"
            }
        } catch {
            if ($attempt -eq $MaxAttempts -or
                $_.Exception.Message -like 'EKS add-on association failed:*') {
                throw
            }
            $lastStatus = $_.Exception.Message
        }

        if ($attempt % 6 -eq 0) {
            Write-Host "Waiting for EKS add-on association: status=$lastStatus, attempt=$attempt/$MaxAttempts"
        }
        Start-Sleep -Seconds $DelaySeconds
    }

    throw "EKS add-on association did not reach Success: status=$lastStatus"
}

try {
    Start-AwakeMode

    foreach ($command in @('terraform', 'aws', 'git', 'ssh', 'scp')) {
        Assert-CommandAvailable -Name $command
    }
    foreach ($file in @(
        $valuesPath,
        $runtimeBootstrap,
        $argoBootstrap,
        $watchdogScript,
        $SshKeyPath,
        $ArgoDeployKeyPath
    )) {
        Assert-FileAvailable -Path $file
    }

    [void](Assert-DailySessionTerraformIdle -TerraformRoot $TerraformRoot)

    $identity = Get-AwsIdentity -Profile $AwsProfile -Region $Region
    Assert-AwsIdentity -Identity $identity -ExpectedAccountId $ExpectedAccountId
    Write-Host "AWS preflight: account=$($identity.Account), region=$Region"

    $foundation = Get-FoundationContext `
        -FoundationRoot $foundationRoot `
        -Profile $AwsProfile `
        -Region $Region `
        -DrRegion $DrRegion `
        -ExpectedAccountId $ExpectedAccountId

    Sync-ApplicationRepository

    $dailyState = @(Get-TerraformStateAddresses -Root $TerraformRoot)
    if ($dailyState.Count -eq 0) {
        $untrackedRuntime = @(Get-TaggedProjectRuntimeResources `
            -Profile $AwsProfile `
            -ProjectName $ProjectName `
            -Regions @($Region, $DrRegion, 'us-east-1'))
        if ($untrackedRuntime.Count -gt 0) {
            $details = Format-TaggedProjectRuntimeResources -Resources $untrackedRuntime
            throw "Daily state is empty, but tagged project runtime still exists in AWS. Reconcile ownership before apply:`n$($details -join "`n")"
        }
    }

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'init', '-input=false', '-upgrade=false'
    ) -FailureMessage 'Daily Terraform initialization failed.'

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'plan',
        '-input=false',
        "-var=aws_profile=$AwsProfile",
        "-var=project_name=$ProjectName",
        "-var=primary_region=$Region",
        "-var=dr_region=$DrRegion",
        "-var=primary_bastion_key_pair_name=$PrimaryBastionKeyPairName",
        "-var=dr_bastion_key_pair_name=$DrBastionKeyPairName",
        "-out=$planPath"
    ) -FailureMessage 'Daily Terraform plan failed.'

    $planSummary = Get-TerraformPlanSummary -Root $TerraformRoot -PlanPath $planPath
    Write-TerraformPlanSummary -Summary $planSummary -Label 'Daily up'
    Assert-DailyPlanPreservesFoundation -Summary $planSummary

    if ($ConfirmApply -cne 'APPLY DAILY') {
        Write-Host "No AWS change was made. Review the plan, then rerun with -ConfirmApply 'APPLY DAILY'."
        exit 2
    }

    $session = Start-DailySessionGuard `
        -SessionSafety $automationConfig.SessionSafety `
        -StartedAt $startedAt `
        -TerraformRoot $TerraformRoot `
        -AccountId ([string]$identity.Account) `
        -PrimaryRegion $Region `
        -DrRegion $DrRegion `
        -AwsProfile $AwsProfile `
        -ProjectName $ProjectName `
        -AutomationConfigPath $AutomationConfigPath `
        -PrimaryBastionKeyPairName $PrimaryBastionKeyPairName `
        -DrBastionKeyPairName $DrBastionKeyPairName `
        -WatchdogScriptPath $watchdogScript `
        -ExperimentId $ExperimentId
    Write-Host "Daily Session: $($session.SessionId)"
    Write-Host "Soft deadline: $(([datetimeoffset]$session.SoftDeadlineAtUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz'))"
    Write-Host "Hard deadline: $(([datetimeoffset]$session.HardDeadlineAtUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz'))"

    Invoke-NativePassthrough -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'apply',
        '-input=false',
        $planPath
    ) -FailureMessage 'Daily Terraform apply failed.'
    Remove-Item -LiteralPath $planPath -Force -ErrorAction SilentlyContinue

    $associationId = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'output', '-raw',
        'primary_cluster_addons_association_id'
    )
    Wait-SsmAssociationSuccess -AssociationId $associationId

    $image = Invoke-ApplicationCiWhenNeeded -Foundation $foundation

    $bastionIp = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'output', '-raw', 'seoul_bastion_public_ip'
    )
    if ($bastionIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        throw 'Terraform did not return a valid Bastion IPv4 address.'
    }
    Set-SshConfigHost `
        -ConfigPath $SshConfigPath `
        -HostAlias 'bas' `
        -HostName $bastionIp `
        -User 'ec2-user' `
        -IdentityFile $SshKeyPath
    Write-Host "SSH alias refreshed: bas -> $bastionIp"

    if (-not [bool]$application.Database.Enabled -or
        [string]$application.Database.Type -cne 'MariaDbDvwa') {
        throw "Unsupported database bootstrap contract for application '$ApplicationName'."
    }
    $dbJson = & terraform "-chdir=$TerraformRoot" output -json $databaseOutput 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $dbJson) {
        throw 'Sensitive database bootstrap output could not be read.'
    }
    $db = ($dbJson | Out-String) | ConvertFrom-Json

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'dvwa-daily-' + [guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $adminCnf = Join-Path $tempRoot 'dvwa-admin.cnf'
    $appEnv = Join-Path $tempRoot 'dvwa.env'
    $knownHosts = Join-Path $tempRoot 'known_hosts'

    $adminContent = @(
        '[client]'
        "host=$(ConvertTo-MariaDbOptionValue ([string]$db.host))"
        "port=$([int]$db.port)"
        "user=$(ConvertTo-MariaDbOptionValue ([string]$db.admin_username))"
        "password=$(ConvertTo-MariaDbOptionValue ([string]$db.admin_password))"
        'ssl-ca=/tmp/aws-rds-global-bundle.pem'
        'ssl-verify-server-cert'
    ) -join "`n"
    $appContent = @(
        "DB_SERVER=$([string]$db.host)"
        "DB_PORT=$([int]$db.port)"
        "DB_DATABASE=$([string]$db.app_database)"
        "DB_USER=$([string]$db.app_username)"
        "DB_PASSWORD=$([string]$db.app_password)"
        'DB_SSL=true'
        'DB_SSL_CA=/etc/ssl/certs/aws-rds-global-bundle.pem'
    ) -join "`n"

    Write-Utf8NoBom -Path $adminCnf -Content ($adminContent + "`n")
    Write-Utf8NoBom -Path $appEnv -Content ($appContent + "`n")
    Protect-LocalSecretFile -Path $adminCnf
    Protect-LocalSecretFile -Path $appEnv

    $knownHostsSsh = $knownHosts.Replace('\', '/')
    $commonSsh = @(
        '-i', $SshKeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$knownHostsSsh",
        '-o', 'ConnectTimeout=30'
    )
    $remote = "ec2-user@$bastionIp"

    Invoke-NativePassthrough -FilePath 'scp' -ArgumentList (
        $commonSsh + @(
            $runtimeBootstrap,
            $adminCnf,
            $appEnv,
            "${remote}:/tmp/"
        )
    ) -FailureMessage 'DVWA database bootstrap files could not be copied to the Bastion.'

    Invoke-Ssh -CommonArguments $commonSsh -Remote $remote -Command (
        "chmod 0700 /tmp/$runtimeBootstrapFileName; " +
        "/tmp/$runtimeBootstrapFileName /tmp/dvwa-admin.cnf /tmp/dvwa.env $applicationNamespace $databaseSecretName; " +
        "rm -f /tmp/$runtimeBootstrapFileName"
    )

    Invoke-NativePassthrough -FilePath 'scp' -ArgumentList (
        $commonSsh + @(
            $argoBootstrap,
            $ArgoDeployKeyPath,
            "${remote}:/tmp/"
        )
    ) -FailureMessage 'Argo CD bootstrap files could not be copied to the Bastion.'

    Invoke-Ssh -CommonArguments $commonSsh -Remote $remote -Command (
        "set -e; trap 'rm -f /tmp/$argoBootstrapFileName /tmp/argocd-uns-dvwa' EXIT; " +
        "chmod 0700 /tmp/$argoBootstrapFileName; chmod 0600 /tmp/argocd-uns-dvwa; " +
        "/tmp/$argoBootstrapFileName /tmp/argocd-uns-dvwa"
    )

$waitCommand = @'
set -e
for attempt in $(seq 1 120); do
  sync_status="$(kubectl -n argocd get application __ARGO_APPLICATION__ -o jsonpath={.status.sync.status} 2>/dev/null || true)"
  health_status="$(kubectl -n argocd get application __ARGO_APPLICATION__ -o jsonpath={.status.health.status} 2>/dev/null || true)"
  if [ "x$sync_status" = xSynced ] && [ "x$health_status" = xHealthy ]; then
    break
  fi
  if [ "$attempt" -eq 120 ]; then
    echo "Argo CD did not reach Synced Healthy within 20 minutes: $sync_status $health_status" >&2
    exit 1
  fi
  sleep 10
done
kubectl -n __NAMESPACE__ rollout status __WORKLOAD_KIND__/__WORKLOAD_NAME__ --timeout=10m
kubectl -n __NAMESPACE__ get pod,service
'@
    $waitCommand = $waitCommand.
        Replace('__ARGO_APPLICATION__', $argoApplication).
        Replace('__NAMESPACE__', $applicationNamespace).
        Replace('__WORKLOAD_KIND__', $workloadKind).
        Replace('__WORKLOAD_NAME__', $workloadName)
    Invoke-Ssh -CommonArguments $commonSsh -Remote $remote -Command $waitCommand

    $actualImage = Invoke-NativeCapture -FilePath 'ssh' -ArgumentList (
        $commonSsh + @(
            $remote,
            "kubectl -n $applicationNamespace get pod -l $podSelector -o jsonpath='{.items[0].spec.containers[0].image}'"
        )
    ) -FailureMessage 'The running DVWA image could not be read.'
    $expectedImage = "$($image.Repository):$($image.Tag)"
    if ($actualImage -cne $expectedImage) {
        throw "Running image mismatch. Expected $expectedImage, received $actualImage."
    }

    $applicationUrl = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'output', '-raw', $urlTerraformOutput
    )
    $httpReady = $false
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $applicationUrl -UseBasicParsing -TimeoutSec 15
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
                $httpReady = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 10
        }
    }
    if (-not $httpReady) {
        throw "Application '$ApplicationName' did not return a successful HTTP response: $applicationUrl"
    }

    $elapsed = (Get-Date) - $startedAt
    Write-Host ''
    Write-Host 'Daily up completed.'
    Write-Host "Account: $($identity.Account)"
    Write-Host "Region: $Region"
    Write-Host "Image: $expectedImage"
    Write-Host 'Argo CD: Synced / Healthy'
    Write-Host "Application '$ApplicationName': Ready"
    Write-Host "URL: $applicationUrl"
    Write-Host "Elapsed: $([math]::Round($elapsed.TotalMinutes, 1)) minutes"
} finally {
    if ($tempRoot -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Stop-AwakeMode
}
