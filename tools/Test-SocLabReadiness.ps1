#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [switch]$Online,
    [switch]$RequireReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dvwaRoot = [IO.Path]::GetFullPath('D:\DVWA')
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Shuffle.psm1') -Force

if (-not $EvidenceRoot) {
    if (-not $env:USERPROFILE) { throw 'USERPROFILE is unavailable.' }
    $EvidenceRoot = Join-Path $env:USERPROFILE 'Documents\aws-topology-evidence'
}
$resolvedEvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
$resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
$checks = [Collections.Generic.List[object]]::new()
$remaining = [Collections.Generic.List[string]]::new()

function Add-ReadinessCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ready,
        [Parameter(Mandatory)][string]$Detail
    )
    $checks.Add([pscustomobject]@{Name=$Name;Ready=$Ready;Detail=$Detail})
}

$dvwaCommitPaths = @(
    '.github/workflows/soc-contain-dvwa.yml',
    '.github/workflows/soc-reset-dvwa.yml',
    '.github/scripts/update-dvwa-security-level.py',
    'dvwa/includes/dvwaAudit.inc.php',
    'tests/test_audit_log.php',
    'tests/test_soc_security_level_transition.py',
    'tests/test_soc_workflow_contract.py'
)
$sourcePaths = @(
    (Join-Path $repositoryRoot 'tools\Start-SocLab.ps1'),
    (Join-Path $repositoryRoot 'observability\scenarios\Invoke-CapitalOneSocE2E.ps1'),
    (Join-Path $repositoryRoot 'observability\scenarios\Invoke-SocLabReset.ps1'),
    (Join-Path $repositoryRoot 'observability\shuffle\apps\aws-topology-soc-validator\1.0.0\api.yaml'),
    (Join-Path $repositoryRoot 'observability\shuffle\apps\aws-topology-soc-github-dispatcher\1.0.0\api.yaml')
)
$sourcePaths += @($dvwaCommitPaths | ForEach-Object { Join-Path $dvwaRoot $_ })
$missingSource = @($sourcePaths | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf)
})
Add-ReadinessCheck -Name 'source-contracts' -Ready ($missingSource.Count -eq 0) `
    -Detail $(if ($missingSource.Count -eq 0) {'required files present'} else {"missing=$($missingSource.Count)"})
if ($missingSource.Count -ne 0) {
    $remaining.Add('Agent: restore or complete the missing fixed source files.')
}

$dvwaScopeReady = $false
$dvwaScopeDetail = 'local Git status could not be validated'
try {
    $statusLines = @(& git -c core.quotePath=false -C $dvwaRoot status `
        --porcelain=v1 --untracked-files=all 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
    $unexpectedPaths = [Collections.Generic.List[string]]::new()
    foreach ($line in $statusLines) {
        $text = [string]$line
        if ($text.Length -lt 4) { throw 'git status returned an invalid record' }
        $relativePath = $text.Substring(3)
        $generatedCache = (
            $relativePath -match '(?:^|/)__pycache__/' -or
            $relativePath -match '^\.pytest_cache/'
        )
        if ($relativePath -notin $dvwaCommitPaths -and -not $generatedCache) {
            $unexpectedPaths.Add($relativePath)
        }
    }
    $dvwaScopeReady = $unexpectedPaths.Count -eq 0
    $dvwaScopeDetail = if ($dvwaScopeReady) {
        'clean or limited to the seven reviewed files plus generated caches'
    } else {
        "unexpected_paths=$($unexpectedPaths.Count)"
    }
} catch {
    $dvwaScopeReady = $false
}
Add-ReadinessCheck -Name 'dvwa-local-scope' -Ready $dvwaScopeReady -Detail $dvwaScopeDetail
if (-not $dvwaScopeReady) {
    $remaining.Add('User review: remove or separately preserve unexpected DVWA changes before the bounded commit.')
}

$githubRemoteReady = $false
$githubRemoteDetail = if ($Online) {'remote main validation failed or was not reached'} else {'not checked; use -Online'}
if ($Online -and (Get-Command gh -ErrorAction SilentlyContinue)) {
    try {
        $runtimePaths = @(
            '.github/workflows/soc-contain-dvwa.yml',
            '.github/workflows/soc-reset-dvwa.yml',
            '.github/scripts/update-dvwa-security-level.py',
            'dvwa/includes/dvwaAudit.inc.php',
            'deploy/dvwa/values.yaml'
        )
        foreach ($relativePath in $runtimePaths) {
            $localPath = Join-Path $dvwaRoot $relativePath
            if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) {
                throw 'A required local DVWA runtime file is absent.'
            }
            $remoteText = @(& gh api --method GET `
                "repos/Unoh03/Uns-DVWA/contents/$relativePath`?ref=main" 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw 'A required DVWA runtime file is absent from remote main.'
            }
            $remote = ($remoteText -join "`n") | ConvertFrom-Json -Depth 20
            $localBlob = @(& git -C $dvwaRoot hash-object -- $localPath 2>&1)
            if ($LASTEXITCODE -ne 0 -or
                [string]$remote.sha -cne [string]($localBlob | Select-Object -First 1)) {
                throw 'Local and remote DVWA runtime files differ.'
            }
        }
        foreach ($workflowName in @('soc-contain-dvwa.yml','soc-reset-dvwa.yml')) {
            $workflowText = @(& gh api --method GET `
                "repos/Unoh03/Uns-DVWA/actions/workflows/$workflowName" 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw 'A required DVWA Workflow is absent from remote main.'
            }
            $workflowState = ($workflowText -join "`n") | ConvertFrom-Json -Depth 20
            if ([string]$workflowState.state -cne 'active' -or
                [string]$workflowState.path -cne ".github/workflows/$workflowName") {
                throw 'A required DVWA Workflow is not active at its fixed path.'
            }
        }
        $remoteValues = @(& gh api --method GET `
            'repos/Unoh03/Uns-DVWA/contents/deploy/dvwa/values.yaml?ref=main' 2>&1)
        if ($LASTEXITCODE -ne 0) { throw 'Remote values.yaml is unavailable.' }
        $valuesDocument = ($remoteValues -join "`n") | ConvertFrom-Json -Depth 20
        $valuesBytes = [Convert]::FromBase64String(
            ([string]$valuesDocument.content -replace '\s','')
        )
        try { $valuesText = [Text.Encoding]::UTF8.GetString($valuesBytes) }
        finally { [Array]::Clear($valuesBytes,0,$valuesBytes.Length) }
        if (@([regex]::Matches($valuesText,'(?m)^defaultSecurityLevel:\s*low\s*$')).Count -ne 1 -or
            $valuesText -match '(?m)^defaultSecurityLevel:\s*impossible\s*$') {
            throw 'Remote DVWA is not at the unique low baseline.'
        }
        $githubRemoteReady = $true
        $githubRemoteDetail = 'fixed runtime files match active remote main; baseline=low'
    } catch {
        $githubRemoteDetail = 'required files are absent, changed, inactive, or not at low on remote main'
    }
}
Add-ReadinessCheck -Name 'github-remote-runtime' -Ready $githubRemoteReady `
    -Detail $githubRemoteDetail
if (-not $githubRemoteReady) {
    $remaining.Add('User approval: review, commit, and push the bounded DVWA runtime changes; wait for CI, Argo, and remote low baseline to settle.')
}

$configuration = $null
try {
    $configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
    Add-ReadinessCheck -Name 'shuffle-public-config' -Ready $true -Detail 'valid fixed IDs and targets'
} catch {
    Add-ReadinessCheck -Name 'shuffle-public-config' -Ready $false -Detail 'not configured or invalid'
    $remaining.Add('User: sign in to Shuffle Cloud, create the private Workflow/Webhook, then register only the public IDs.')
}

$requiredSecretNames = @(
    'wazuh_indexer_admin_password',
    'wazuh_indexer_kibanaserver_password',
    'wazuh_api_wui_password',
    'shuffle_webhook_header_key',
    'shuffle_api_key',
    'shuffle_webhook_url'
)
$validSecrets = [Collections.Generic.List[string]]::new()
foreach ($name in $requiredSecretNames) {
    $path = Join-Path $resolvedSecretRoot "$name.dpapi.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    try {
        $value = Unprotect-SocSecret -Name $name -SecretRoot $resolvedSecretRoot
        if (-not [string]::IsNullOrWhiteSpace($value)) { $validSecrets.Add($name) }
    } catch {
        # Report only the name/state. Never print a decrypted value or exception body.
    } finally {
        $value = $null
    }
}
$missingSecrets = @($requiredSecretNames | Where-Object { $_ -notin $validSecrets })
Add-ReadinessCheck -Name 'local-dpapi-secrets' -Ready ($missingSecrets.Count -eq 0) `
    -Detail $(if ($missingSecrets.Count -eq 0) {'all six records decrypt'} else {"missing_or_invalid=$($missingSecrets -join ',')"})
if (@($missingSecrets | Where-Object { $_ -notin @('shuffle_api_key','shuffle_webhook_url') }).Count -ne 0) {
    $remaining.Add('User: run Initialize-SocLabSecrets once; generated values remain local DPAPI records.')
}
if ('shuffle_api_key' -in $missingSecrets -or 'shuffle_webhook_url' -in $missingSecrets) {
    $remaining.Add('User: enter the Shuffle API key and Webhook URL in the two secure prompts.')
}

$uploadReady = $false
$upload = $null
try {
    $expectedOrgId = if ($null -ne $configuration) {
        [string]$configuration.shuffle_org_id
    } else { '' }
    $upload = Get-ShuffleSocAppUploadEvidence -EvidenceRoot $resolvedEvidenceRoot `
        -ExpectedOrgId $expectedOrgId
    $uploadReady = $true
} catch { $uploadReady = $false }
Add-ReadinessCheck -Name 'shuffle-private-app-upload' -Ready $uploadReady `
    -Detail $(if ($uploadReady) {'Validator and Dispatcher upload evidence valid'} else {'bundle upload evidence absent or invalid'})
if (-not $uploadReady) {
    $remaining.Add('User approval: upload the already built, reviewed Private App bundle to the selected Shuffle organization.')
}

$gateB5Ready = $false
$gateB5Detail = 'requires configured Workflow and Runtime Evidence'
if ($null -ne $configuration) {
    try {
        $proof = Assert-ShuffleSocGateB5Evidence -EvidenceRoot $resolvedEvidenceRoot `
            -WorkflowId ([string]$configuration.shuffle_workflow_id)
        $gateB5Ready = $true
        $gateB5Detail = "verified take=$([string]$proof.TakeId)"
    } catch { $gateB5Detail = 'no valid current Gate B5 Evidence' }
}
Add-ReadinessCheck -Name 'shuffle-gate-b5' -Ready $gateB5Ready -Detail $gateB5Detail
if (-not $gateB5Ready) {
    $remaining.Add('User approval: run the safe 10-request Gate B5 Stub test after the Cloud Workflow is assembled.')
}

$productionReady = $false
$productionDetail = if ($Online) {'online validation not reached'} else {'not checked; use -Online after Cloud setup'}
if ($Online -and $null -ne $configuration -and $uploadReady -and
    'shuffle_api_key' -in $validSecrets) {
    try {
        $apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $resolvedSecretRoot
        $workflow = Get-ShuffleSocWorkflow `
            -WorkflowId ([string]$configuration.shuffle_workflow_id) `
            -WebhookId ([string]$configuration.shuffle_webhook_id) `
            -ApiKey $apiKey -OrgId ([string]$configuration.shuffle_org_id) `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        [void](Assert-ShuffleSocProductionWorkflow -Workflow $workflow `
            -WorkflowId ([string]$configuration.shuffle_workflow_id) `
            -WebhookId ([string]$configuration.shuffle_webhook_id))
        $provenance = Get-ShuffleSocCloudProvenance -Workflow $workflow `
            -UploadEvidence $upload -ApiKey $apiKey `
            -OrgId ([string]$configuration.shuffle_org_id) `
            -BaseUri ([uri][string]$configuration.shuffle_api_base)
        if (-not $provenance.authentication_active -or
            [bool]$provenance.secret_value_inspected -ne $false) {
            throw 'The current Cloud App or Authentication provenance is not verified.'
        }
        $gateProof = Assert-ShuffleSocGateB5Evidence -EvidenceRoot $resolvedEvidenceRoot `
            -WorkflowId ([string]$configuration.shuffle_workflow_id)
        $coreHash = Get-ShuffleSocCoreContractSha256 -Workflow $workflow `
            -WebhookId ([string]$configuration.shuffle_webhook_id)
        if ($coreHash -cne [string]$gateProof.WorkflowCoreSha256) {
            throw 'Production Workflow core differs from the verified Gate B5 core.'
        }
        $productionReady = $true
        $productionDetail = 'current Cloud export, uploaded App IDs, and encrypted Dispatcher Authentication satisfy the fixed Production contract'
    } catch {
        $productionDetail = 'current Cloud export is unavailable or violates Production contract'
    } finally {
        $apiKey = $null
    }
}
Add-ReadinessCheck -Name 'shuffle-production-export' -Ready $productionReady `
    -Detail $productionDetail
if (-not $productionReady) {
    $remaining.Add('User: create the repository-scoped fine-grained PAT, register it as Dispatcher App Authentication, and allow read-only App/Auth/Workflow validation.')
}

$staticCheckNames = @('source-contracts','dvwa-local-scope')
$staticReady = @($checks | Where-Object {
    $_.Name -in $staticCheckNames -and -not $_.Ready
}).Count -eq 0
$cloudReady = @($checks | Where-Object {
    $_.Name -notin $staticCheckNames -and -not $_.Ready
}).Count -eq 0 -and $staticReady
Write-Host 'SOC lab readiness (no secret values printed)'
foreach ($check in $checks) {
    $state = if ($check.Ready) {'READY'} else {'PENDING'}
    Write-Host ("[{0}] {1}: {2}" -f $state,$check.Name,$check.Detail)
}
Write-Host "SOC_STATIC_READY=$($staticReady.ToString().ToLowerInvariant())"
Write-Host "SOC_CLOUD_READY=$($cloudReady.ToString().ToLowerInvariant())"
Write-Host "REMAINING_USER_ACTIONS=$($remaining.Count)"
for ($index = 0; $index -lt $remaining.Count; $index++) {
    Write-Host ("{0}. {1}" -f ($index + 1),$remaining[$index])
}

if ($RequireReady -and (-not $staticReady -or -not $cloudReady)) {
    throw 'SOC lab is not ready; complete only the listed user/Cloud boundaries.'
}
