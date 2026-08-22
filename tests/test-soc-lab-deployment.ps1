#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'automation\SocLab.Deployment.psm1'
Import-Module $modulePath -Force
$takeId = 'capital-one-20260818T010000Z-deadbeef'
$created = [datetimeoffset]'2026-08-18T01:01:00Z'
$run = [pscustomobject]@{
    id=123;display_title="SOC contain $takeId";event='workflow_dispatch';head_branch='main';
    path='.github/workflows/soc-contain-dvwa.yml';created_at=$created.ToString('o');
    updated_at=$created.AddMinutes(1).ToString('o');status='completed';conclusion='success';
    html_url='https://github.com/Unoh03/Uns-DVWA/actions/runs/123'
}
if ((Assert-SocGitHubRunCollection -Run @($run) -TakeId $takeId -Operation contain `
    -NotBeforeUtc $created -ExpectedRunId 123).id -ne 123) {
    throw 'The exact GitHub run was not selected.'
}
$apiRun = $run | ConvertTo-Json -Depth 5 | ConvertFrom-Json
if ((Assert-SocGitHubRunCollection -Run @($apiRun) -TakeId $takeId -Operation contain `
    -NotBeforeUtc $created -ExpectedRunId 123).id -ne 123) {
    throw 'A GitHub API UTC DateTime was shifted to local time during run selection.'
}
$wrongRunIdRejected = $false
try {
    [void](Assert-SocGitHubRunCollection -Run @($run) -TakeId $takeId `
        -Operation contain -NotBeforeUtc $created -ExpectedRunId 456)
} catch { $wrongRunIdRejected = $_.Exception.Message -match 'exact Run ID' }
if (-not $wrongRunIdRejected) { throw 'A GitHub run not returned by Shuffle was accepted.' }
$duplicateRejected = $false
try {
    [void](Assert-SocGitHubRunCollection -Run @($run,$run) -TakeId $takeId -Operation contain -NotBeforeUtc $created)
} catch { $duplicateRejected = $_.Exception.Message -match 'More than one' }
if (-not $duplicateRejected) { throw 'Duplicate GitHub runs were accepted.' }

$transition = [pscustomobject]@{
    schema_version=1;operation='contain';take_id=$takeId;
    alert_body_sha256=('b' * 64);
    before_sha=('1' * 40);commit_sha=('2' * 40);changed=$true;
    diff_sha256=('a' * 64);target_path='deploy/dvwa/values.yaml';target_level='impossible'
}
[void](Assert-SocGitHubTransitionResult -Result $transition -TakeId $takeId -Operation contain `
    -ExpectedAlertBodySha256 ('b' * 64) -RequireChange)
$wrongAlertRejected = $false
try {
    [void](Assert-SocGitHubTransitionResult -Result $transition -TakeId $takeId -Operation contain `
        -ExpectedAlertBodySha256 ('c' * 64) -RequireChange)
} catch { $wrongAlertRejected = $_.Exception.Message -match 'dispatched sanitized Alert' }
if (-not $wrongAlertRejected) { throw 'A containment Artifact from another Alert was accepted.' }

$release = [pscustomobject]@{
    schema_version=1;operation='reset';reset_mode='release_quarantine';take_id=$takeId;
    before_sha=('2' * 40);commit_sha=('3' * 40);changed=$true;
    diff_sha256=('d' * 64);target_path='deploy/dvwa/values.yaml';target_level='unchanged'
}
[void](Assert-SocGitHubTransitionResult -Result $release -TakeId $takeId -Operation reset -RequireChange)
$retake = [pscustomobject]@{
    schema_version=1;operation='reset';reset_mode='prepare_retake';take_id=$takeId;
    before_sha=('3' * 40);commit_sha=('4' * 40);changed=$true;
    diff_sha256=('e' * 64);target_path='deploy/dvwa/values.yaml';target_level='low'
}
[void](Assert-SocGitHubTransitionResult -Result $retake -TakeId $takeId -Operation reset -RequireChange)
$legacyReset = $retake.PSObject.Copy()
$legacyReset.PSObject.Properties.Remove('reset_mode')
[void](Assert-SocGitHubTransitionResult -Result $legacyReset -TakeId $takeId -Operation reset -RequireChange)
$release.target_level = 'low'
$wrongResetModeRejected = $false
try {
    [void](Assert-SocGitHubTransitionResult -Result $release -TakeId $takeId -Operation reset)
} catch { $wrongResetModeRejected = $_.Exception.Message -match 'fixed contract' }
if (-not $wrongResetModeRejected) { throw 'A quarantine-only Artifact with a low target was accepted.' }

function New-TestPod([string]$Uid) {
    [pscustomobject]@{
        # Kubernetes omits deletionTimestamp entirely for ordinary live Pods.
        metadata=[pscustomobject]@{uid=$Uid}
        status=[pscustomobject]@{conditions=@([pscustomobject]@{type='Ready';status='True'})}
    }
}
$revision = '3' * 40
$document = [pscustomobject]@{
    Application=[pscustomobject]@{
        metadata=[pscustomobject]@{name='dvwa'}
        status=[pscustomobject]@{
            sync=[pscustomobject]@{status='Synced';revision=$revision}
            health=[pscustomobject]@{status='Healthy'}
            conditions=@()
        }
    }
    Deployment=[pscustomobject]@{
        metadata=[pscustomobject]@{name='dvwa';generation=2}
        spec=[pscustomobject]@{
            replicas=1
            template=[pscustomobject]@{spec=[pscustomobject]@{containers=@(
                [pscustomobject]@{name='dvwa';env=@([pscustomobject]@{name='DEFAULT_SECURITY_LEVEL';value='impossible'})}
            )}}
        }
        status=[pscustomobject]@{observedGeneration=2;updatedReplicas=1;readyReplicas=1;availableReplicas=1}
    }
    Pods=[pscustomobject]@{items=@((New-TestPod '22222222-2222-4222-8222-222222222222'))}
}
$state = Assert-SocArgoRuntimeDocument -Document $document -ExpectedRevision $revision `
    -ExpectedSecurityLevel impossible -PreviousPodUid @('11111111-1111-4111-8111-111111111111') -RequireReplacement
if ($state.security_level -cne 'impossible' -or $state.pod_uids.Count -ne 1) {
    throw 'The exact Argo deployment was not accepted.'
}
$document.Deployment.spec.template.spec.containers[0].env[0].value = 'low'
$wrongLevelRejected = $false
try {
    [void](Assert-SocArgoRuntimeDocument -Document $document -ExpectedRevision $revision -ExpectedSecurityLevel impossible)
} catch { $wrongLevelRejected = $_.Exception.Message -match 'security-level rollout' }
if (-not $wrongLevelRejected) { throw 'The wrong deployed security level was accepted.' }

$parseErrors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile($modulePath,[ref]$null,[ref]$parseErrors)
if($parseErrors.Count){$parseErrors | Format-List *; exit 1}
Write-Host 'SOC lab GitHub and Argo deployment tests passed.'
