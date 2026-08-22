#requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TakeIdPattern = '^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$'
$script:ShaPattern = '^[0-9a-f]{40}$'
$script:Repository = 'Unoh03/Uns-DVWA'
$script:Branch = 'main'
$script:ArgoApplication = 'dvwa'
$script:ApplicationNamespace = 'dvwa'
$script:DeploymentName = 'dvwa'
$script:SshHost = 'bas'

function Invoke-SocDeploymentNativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw $FailureMessage
    }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Assert-SocGitHubRunCollection {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Run = @(),
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc,
        [ValidateRange(0,9223372036854775807)][int64]$ExpectedRunId = 0
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern) {
        throw 'The GitHub run TAKE ID is invalid.'
    }
    $workflowFile = if ($Operation -ceq 'contain') {
        'soc-contain-dvwa.yml'
    } else {
        'soc-reset-dvwa.yml'
    }
    $title = if ($Operation -ceq 'contain') {
        "SOC contain $TakeId"
    } else {
        "SOC reset $TakeId"
    }
    $matches = @($Run | Where-Object {
        # ConvertFrom-Json materializes GitHub's ISO timestamp as a UTC DateTime.
        # Casting that object preserves the UTC instant; stringifying it first
        # drops the Kind marker and makes Parse reinterpret it as local time.
        $created = [datetimeoffset]$_.created_at
        [string]$_.display_title -ceq $title -and
        [string]$_.event -ceq 'workflow_dispatch' -and
        [string]$_.head_branch -ceq $script:Branch -and
        [string]$_.path -ceq ".github/workflows/$workflowFile" -and
        $created -ge $NotBeforeUtc.AddMinutes(-1)
    })
    if ($matches.Count -gt 1) {
        throw 'More than one matching GitHub Workflow run exists for one TAKE.'
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    $match = $matches[0]
    $runId = [int64]$match.id
    if ($runId -le 0 -or [string]$match.html_url -notmatch '^https://github\.com/Unoh03/Uns-DVWA/actions/runs/[0-9]+$') {
        throw 'The matching GitHub Workflow run identity is invalid.'
    }
    if ($ExpectedRunId -gt 0 -and $runId -ne $ExpectedRunId) {
        throw 'The matching GitHub Workflow run is not the exact Run ID returned by Shuffle.'
    }
    return $match
}

function Wait-SocGitHubWorkflowRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc,
        [ValidateRange(0,9223372036854775807)][int64]$ExpectedRunId = 0,
        [ValidateRange(60,1200)][int]$TimeoutSeconds = 600
    )

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The gh command is unavailable.'
    }
    $workflowFile = if ($Operation -ceq 'contain') {
        'soc-contain-dvwa.yml'
    } else {
        'soc-reset-dvwa.yml'
    }
    $relativePath = "repos/$($script:Repository)/actions/workflows/$workflowFile/runs?branch=main&event=workflow_dispatch&per_page=20"
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $document = Invoke-SocDeploymentNativeCapture -FilePath 'gh' -Arguments @(
            'api',$relativePath
        ) -FailureMessage 'The fixed GitHub Workflow run list could not be read.' | ConvertFrom-Json
        $run = Assert-SocGitHubRunCollection -Run @($document.workflow_runs) `
            -TakeId $TakeId -Operation $Operation -NotBeforeUtc $NotBeforeUtc `
            -ExpectedRunId $ExpectedRunId
        if ($null -ne $run) {
            if ([string]$run.status -ceq 'completed') {
                if ([string]$run.conclusion -cne 'success') {
                    throw "The fixed GitHub Workflow completed unsuccessfully: $([string]$run.conclusion)"
                }
                return [pscustomobject][ordered]@{
                    run_id         = [int64]$run.id
                    operation      = $Operation
                    workflow_file  = $workflowFile
                    status         = 'completed'
                    conclusion     = 'success'
                    created_at_utc = ([datetimeoffset]$run.created_at).ToUniversalTime().ToString('o')
                    updated_at_utc = ([datetimeoffset]$run.updated_at).ToUniversalTime().ToString('o')
                    html_url       = [string]$run.html_url
                }
            }
            if ([string]$run.status -notin @('queued','in_progress','waiting','requested','pending')) {
                throw "The fixed GitHub Workflow entered an unsupported state: $([string]$run.status)"
            }
        }
        Start-Sleep -Seconds 5
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw 'The fixed GitHub Workflow did not complete within the bounded wait.'
}

function Get-SocGitHubWorkflowRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc,
        [ValidateRange(0,9223372036854775807)][int64]$ExpectedRunId = 0
    )

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The gh command is unavailable.'
    }
    $workflowFile = if ($Operation -ceq 'contain') {
        'soc-contain-dvwa.yml'
    } else {
        'soc-reset-dvwa.yml'
    }
    $relativePath = "repos/$($script:Repository)/actions/workflows/$workflowFile/runs?branch=main&event=workflow_dispatch&per_page=20"
    $document = Invoke-SocDeploymentNativeCapture -FilePath 'gh' -Arguments @(
        'api',$relativePath
    ) -FailureMessage 'The fixed GitHub Workflow run list could not be read.' | ConvertFrom-Json
    return Assert-SocGitHubRunCollection -Run @($document.workflow_runs) `
        -TakeId $TakeId -Operation $Operation -NotBeforeUtc $NotBeforeUtc `
        -ExpectedRunId $ExpectedRunId
}

function Assert-SocNoGitHubWorkflowRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc,
        [ValidateRange(10,120)][int]$ObservationSeconds = 30
    )

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The gh command is unavailable.'
    }
    $relativePath = "repos/$($script:Repository)/actions/workflows/soc-contain-dvwa.yml/runs?branch=main&event=workflow_dispatch&per_page=20"
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($ObservationSeconds)
    do {
        $document = Invoke-SocDeploymentNativeCapture -FilePath 'gh' -Arguments @(
            'api',$relativePath
        ) -FailureMessage 'The fixed GitHub containment run list could not be read.' | ConvertFrom-Json
        $run = Assert-SocGitHubRunCollection -Run @($document.workflow_runs) `
            -TakeId $TakeId -Operation contain -NotBeforeUtc $NotBeforeUtc
        if ($null -ne $run) {
            throw 'Observe-only rehearsal unexpectedly created a GitHub containment run.'
        }
        Start-Sleep -Seconds 5
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    return [pscustomobject][ordered]@{
        take_id=$TakeId
        operation='contain'
        matching_run_count=0
        observed_until_utc=[datetimeoffset]::UtcNow.ToString('o')
    }
}

function Assert-SocGitHubTransitionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation,
        [string]$ExpectedAlertBodySha256 = '',
        [switch]$RequireChange
    )

    if ($TakeId -cnotmatch $script:TakeIdPattern) {
        throw 'The transition TAKE ID is invalid.'
    }
    $resetMode = ''
    if ($Operation -ceq 'reset' -and $null -ne $Result.PSObject.Properties['reset_mode']) {
        $resetMode = [string]$Result.reset_mode
    }
    if ($Operation -ceq 'reset' -and $resetMode -notin @('', 'prepare_retake', 'release_quarantine')) {
        throw 'The GitHub reset Artifact has an unsupported reset mode.'
    }
    $targetLevel = if ($Operation -ceq 'contain') {
        'impossible'
    } elseif ($resetMode -ceq 'release_quarantine') {
        'unchanged'
    } else {
        'low'
    }
    if ($Operation -ceq 'contain' -and
        ($ExpectedAlertBodySha256 -cnotmatch '^[a-f0-9]{64}$' -or
         [string]$Result.alert_body_sha256 -cne $ExpectedAlertBodySha256)) {
        throw 'The containment Artifact is not bound to the dispatched sanitized Alert.'
    }
    if ([int]$Result.schema_version -ne 1 -or
        [string]$Result.operation -cne $Operation -or
        [string]$Result.take_id -cne $TakeId -or
        [string]$Result.before_sha -cnotmatch $script:ShaPattern -or
        [string]$Result.commit_sha -cnotmatch $script:ShaPattern -or
        [string]$Result.diff_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Result.target_path -cne 'deploy/dvwa/values.yaml' -or
        [string]$Result.target_level -cne $targetLevel) {
        throw 'The GitHub transition Artifact violated the fixed contract.'
    }
    if ($RequireChange.IsPresent -and [bool]$Result.changed -ne $true) {
        throw 'The E2E transition did not create the required bounded change.'
    }
    if ([bool]$Result.changed -and [string]$Result.before_sha -ceq [string]$Result.commit_sha) {
        throw 'The changed transition Artifact reused the before SHA.'
    }
    if (-not [bool]$Result.changed -and [string]$Result.before_sha -cne [string]$Result.commit_sha) {
        throw 'The idempotent transition Artifact unexpectedly changed the SHA.'
    }
    return $Result
}

function Get-SocGitHubTransitionArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int64]$RunId,
        [Parameter(Mandatory)][string]$TakeId,
        [Parameter(Mandatory)][ValidateSet('contain','reset')][string]$Operation,
        [string]$ExpectedAlertBodySha256 = '',
        [switch]$RequireChange
    )

    if ($RunId -le 0 -or $TakeId -cnotmatch $script:TakeIdPattern) {
        throw 'The GitHub Artifact request identity is invalid.'
    }
    $prefix = if ($Operation -ceq 'contain') { 'soc-containment' } else { 'soc-reset' }
    $resultFile = if ($Operation -ceq 'contain') {
        'soc-containment-result.json'
    } else {
        'soc-reset-result.json'
    }
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-github-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        [void](Invoke-SocDeploymentNativeCapture -FilePath 'gh' -Arguments @(
            'run','download',[string]$RunId,'-R',$script:Repository,
            '-n',"$prefix-$TakeId",'-D',$temporaryRoot
        ) -FailureMessage 'The fixed GitHub Workflow Artifact could not be downloaded.')
        $path = Join-Path $temporaryRoot $resultFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'The fixed GitHub Workflow result file is absent from the Artifact.'
        }
        $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        return Assert-SocGitHubTransitionResult -Result $result -TakeId $TakeId `
            -Operation $Operation -ExpectedAlertBodySha256 $ExpectedAlertBodySha256 `
            -RequireChange:$RequireChange.IsPresent
    } finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-SocGitHubRemoteMainSha {
    [CmdletBinding()]
    param()

    $reference = Invoke-SocDeploymentNativeCapture -FilePath 'gh' -Arguments @(
        'api',"repos/$($script:Repository)/git/ref/heads/$($script:Branch)"
    ) -FailureMessage 'The fixed GitHub main reference could not be read.' | ConvertFrom-Json
    $sha = [string]$reference.object.sha
    if ($sha -cnotmatch $script:ShaPattern) {
        throw 'GitHub returned an invalid main SHA.'
    }
    return $sha
}

function Get-SocArgoRuntimeDocument {
    [CmdletBinding()]
    param()

    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        throw 'The ssh command is unavailable.'
    }
    $application = Invoke-SocDeploymentNativeCapture -FilePath 'ssh' -Arguments @(
        $script:SshHost,
        "kubectl -n argocd get application $($script:ArgoApplication) -o json"
    ) -FailureMessage 'The fixed Argo CD Application could not be read.' | ConvertFrom-Json
    $deployment = Invoke-SocDeploymentNativeCapture -FilePath 'ssh' -Arguments @(
        $script:SshHost,
        "kubectl -n $($script:ApplicationNamespace) get deployment $($script:DeploymentName) -o json"
    ) -FailureMessage 'The fixed DVWA Deployment could not be read.' | ConvertFrom-Json
    $pods = Invoke-SocDeploymentNativeCapture -FilePath 'ssh' -Arguments @(
        $script:SshHost,
        "kubectl -n $($script:ApplicationNamespace) get pods -l app.kubernetes.io/name=dvwa,app.kubernetes.io/instance=dvwa -o json"
    ) -FailureMessage 'The fixed DVWA Pods could not be read.' | ConvertFrom-Json
    return [pscustomobject]@{
        Application = $application
        Deployment  = $deployment
        Pods        = $pods
    }
}

function Assert-SocArgoRuntimeDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Document,
        [Parameter(Mandatory)][string]$ExpectedRevision,
        [Parameter(Mandatory)][ValidateSet('low','impossible')][string]$ExpectedSecurityLevel,
        [string[]]$PreviousPodUid = @(),
        [switch]$RequireReplacement
    )

    if ($ExpectedRevision -cnotmatch $script:ShaPattern) {
        throw 'The expected Argo revision is invalid.'
    }
    $application = $Document.Application
    $deployment = $Document.Deployment
    $pods = @($Document.Pods.items)
    $errors = @($application.status.conditions | Where-Object {
        [string]$_.type -match 'Error'
    })
    if ([string]$application.metadata.name -cne $script:ArgoApplication -or
        [string]$application.status.sync.status -cne 'Synced' -or
        [string]$application.status.health.status -cne 'Healthy' -or
        [string]$application.status.sync.revision -cne $ExpectedRevision -or
        $errors.Count -ne 0) {
        throw 'Argo CD has not reconciled the exact healthy Git revision.'
    }
    $envEntry = @($deployment.spec.template.spec.containers | Where-Object {
        [string]$_.name -ceq 'dvwa'
    } | ForEach-Object { @($_.env) } | Where-Object {
        [string]$_.name -ceq 'DEFAULT_SECURITY_LEVEL'
    })
    $replicas = [int]$deployment.spec.replicas
    if ([string]$deployment.metadata.name -cne $script:DeploymentName -or
        $envEntry.Count -ne 1 -or [string]$envEntry[0].value -cne $ExpectedSecurityLevel -or
        $replicas -lt 1 -or [int]$deployment.status.observedGeneration -lt [int]$deployment.metadata.generation -or
        [int]$deployment.status.updatedReplicas -ne $replicas -or
        [int]$deployment.status.readyReplicas -ne $replicas -or
        [int]$deployment.status.availableReplicas -ne $replicas) {
        throw 'The DVWA Deployment has not completed the exact security-level rollout.'
    }
    $readyPods = @($pods | Where-Object {
        ($null -eq $_.metadata.PSObject.Properties['deletionTimestamp'] -or
         [string]::IsNullOrWhiteSpace([string]$_.metadata.deletionTimestamp)) -and
        @($_.status.conditions | Where-Object {
            [string]$_.type -ceq 'Ready' -and [string]$_.status -ceq 'True'
        }).Count -eq 1
    })
    if ($readyPods.Count -ne $replicas) {
        throw 'The exact number of new DVWA Pods is not Ready.'
    }
    $podUids = @($readyPods | ForEach-Object { [string]$_.metadata.uid })
    if (@($podUids | Where-Object { $_ -notmatch '^[0-9a-f-]{36}$' }).Count -ne 0 -or
        @($podUids | Select-Object -Unique).Count -ne $podUids.Count) {
        throw 'A DVWA Pod UID is invalid or duplicated.'
    }
    if ($RequireReplacement.IsPresent -and $PreviousPodUid.Count -gt 0 -and
        @($podUids | Where-Object { $_ -in $PreviousPodUid }).Count -ne 0) {
        throw 'The DVWA rollout retained a Pod from before the Git transition.'
    }
    return [pscustomobject][ordered]@{
        revision       = $ExpectedRevision
        sync           = 'Synced'
        health         = 'Healthy'
        security_level = $ExpectedSecurityLevel
        replicas       = $replicas
        pod_uids       = $podUids
    }
}

function Wait-SocArgoDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExpectedRevision,
        [Parameter(Mandatory)][ValidateSet('low','impossible')][string]$ExpectedSecurityLevel,
        [string[]]$PreviousPodUid = @(),
        [switch]$RequireReplacement,
        [ValidateRange(60,1800)][int]$TimeoutSeconds = 1200
    )

    if ($ExpectedRevision -cnotmatch $script:ShaPattern) {
        throw 'The expected Argo revision is invalid.'
    }
    [void](Invoke-SocDeploymentNativeCapture -FilePath 'ssh' -Arguments @(
        $script:SshHost,
        "kubectl -n argocd annotate application $($script:ArgoApplication) argocd.argoproj.io/refresh=hard --overwrite"
    ) -FailureMessage 'The fixed Argo CD Application could not be hard-refreshed.')
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $document = Get-SocArgoRuntimeDocument
            return Assert-SocArgoRuntimeDocument -Document $document `
                -ExpectedRevision $ExpectedRevision `
                -ExpectedSecurityLevel $ExpectedSecurityLevel `
                -PreviousPodUid $PreviousPodUid `
                -RequireReplacement:$RequireReplacement.IsPresent
        } catch {
            if ([datetimeoffset]::UtcNow -ge $deadline) {
                throw
            }
        }
        Start-Sleep -Seconds 10
    } while ([datetimeoffset]::UtcNow -lt $deadline)
    throw 'Argo CD did not deploy the exact Git revision within the bounded wait.'
}

Export-ModuleMember -Function @(
    'Assert-SocGitHubRunCollection',
    'Assert-SocNoGitHubWorkflowRun',
    'Get-SocGitHubWorkflowRun',
    'Wait-SocGitHubWorkflowRun',
    'Assert-SocGitHubTransitionResult',
    'Get-SocGitHubTransitionArtifact',
    'Get-SocGitHubRemoteMainSha',
    'Get-SocArgoRuntimeDocument',
    'Assert-SocArgoRuntimeDocument',
    'Wait-SocArgoDeployment'
)
