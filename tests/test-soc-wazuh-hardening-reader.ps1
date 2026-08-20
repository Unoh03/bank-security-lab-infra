#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$startPath = Join-Path $root 'tools\Start-SocLab.ps1'
$startText = Get-Content -LiteralPath $startPath -Raw
foreach ($requiredText in @(
    'producer_mode',
    'wazuh_authentication_verified',
    'wazuh_credential_rotation_observed',
    'active_state_provenance',
    'Assert-SocHardeningDpapiBinding',
    'Get-SocJsonBooleanProperty',
    'wazuh_major_version',
    'Get-SocJsonTimestampText',
    'Invoke-SocFreshHardeningEvidence',
    'invocationStartedAtUtc',
    'checked_at is not a fresh UTC timestamp'
)) {
    if ($startText -notmatch [regex]::Escape($requiredText)) {
        throw "Start-SocLab is missing the hardening reader contract: $requiredText"
    }
}
if ($startText -notmatch '(?s)\$hardeningEvidence\s*=\s*Invoke-SocFreshHardeningEvidence.*?Add-WazuhManagerSocIntegrationText') {
    throw 'Start-SocLab does not verify Wazuh version Evidence before applying the integration fragment.'
}
if ($startText -match 'wazuh_rotated_auth|complete credential rotation') {
    throw 'Start-SocLab retains misleading rotated-auth hardening semantics.'
}
if ($startText -match 'Sort-Object\s+LastWriteTimeUtc') {
    throw 'Start-SocLab still selects hardening Evidence by filesystem mtime.'
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($startPath,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('PowerShell parser rejected Start-SocLab: ' + (@($errors.Message) -join '; '))
}
$functionNames = @(
    'Get-SocJsonRequiredProperty','Get-SocJsonStringProperty','Get-SocJsonTimestampText','Get-SocJsonBooleanProperty',
    'Get-SocJsonIntegerProperty','Get-SocJsonObjectProperty','Assert-SocSha256Property',
    'Assert-SocHardeningMutationSummary','Assert-SocHardeningDpapiBinding',
    'Assert-SocHardeningEvidenceRecord','Read-SocHardeningEvidence','Invoke-SocFreshHardeningEvidence'
)
foreach ($functionName in $functionNames) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true)
    if ($null -eq $functionAst) { throw "Could not extract Start reader function: $functionName" }
    Invoke-Expression $functionAst.Extent.Text
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-wazuh-reader-' + [guid]::NewGuid().ToString('N'))
$secretRoot = Join-Path $testRoot 'secrets'
$evidenceRoot = Join-Path $testRoot 'evidence'
$hardeningRoot = Join-Path $evidenceRoot 'soc-lab-hardening'
$dpapiNames = @(
    'wazuh_indexer_admin_password',
    'wazuh_indexer_kibanaserver_password',
    'wazuh_api_wui_password'
)
$script:testSessionCounter = 0
$script:nativeFixture = $null
$script:lastNativeArguments = @()
$script:repositoryRoot = $root

function New-TestRuntimeSessionId {
    $script:testSessionCounter++
    return 'wazuh-hardening-{0}-{1:x8}' -f [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'),$script:testSessionCounter
}

function Get-TestFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-TestEvidenceRecord {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RuntimeSessionId,
        [Parameter(Mandatory)][datetimeoffset]$CheckedAt,
        [string]$ProducerMode = 'verify_existing',
        [string]$ActiveStateProvenance = '',
        [switch]$StringBoolean,
        [switch]$BadDpapiHash,
        [switch]$UnequalVolumeHashes,
        [switch]$UnequalFingerprintHashes,
        [switch]$OmitProducerMode
    )

    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $isMutating = $ProducerMode -ceq 'mutating_hardening'
    if ([string]::IsNullOrEmpty($ActiveStateProvenance)) {
        $ActiveStateProvenance = if ($isMutating) {
            'protected_runtime_state_written'
        } else {
            'not_written_verify_only'
        }
    }
    $mutation = [ordered]@{
        docker_mutations = if ($isMutating) { 2 } else { 0 }
        credential_rotation_observed = [bool]$isMutating
        wazuh_mutations = if ($isMutating) { 1 } else { 0 }
        compose_mutations = if ($isMutating) { 2 } else { 0 }
        aws_mutations = 0
        shuffle_mutations = 0
        bridge_mutations = 0
    }
    $hashes = [ordered]@{}
    foreach ($dpapiName in $dpapiNames) {
        $hashes[$dpapiName] = if ($BadDpapiHash) {
            ('0' * 64) -join ''
        } else {
            Get-TestFileSha256 -Path (Join-Path $secretRoot "$dpapiName.dpapi.json")
        }
    }
    $volumeBefore = ('5' * 64) -join ''
    $volumeAfter = if ($UnequalVolumeHashes) { ('7' * 64) -join '' } else { $volumeBefore }
    $record = [ordered]@{
        schema_version = 1
        producer_mode = $ProducerMode
        checked_at = $CheckedAt.ToUniversalTime().ToString('o')
        runtime_session_id = $RuntimeSessionId
        wazuh_version = '4.14.7'
        wazuh_major_version = 4
        wazuh_authentication_verified = $true
        wazuh_credential_rotation_observed = [bool]$isMutating
        local_only_ports = if ($StringBoolean) { 'true' } else { $true }
        new_admin_authentication = 'accepted'
        default_admin_authentication = 'rejected'
        new_kibanaserver_authentication = 'accepted'
        default_kibana_authentication = 'rejected'
        new_wazuh_wui_authentication = 'accepted'
        default_wazuh_wui_authentication = 'rejected'
        named_volumes_removed = $false
        named_volumes_identical_before_after = $true
        secrets_printed = $false
        active_state_path = if ($isMutating) { 'C:\fixture\active-state.json' } else { $null }
        active_state_provenance = $ActiveStateProvenance
        compose_provenance = [ordered]@{
            project = 'single-node'
            working_dir_sha256 = ('1' * 64) -join ''
            config_files_sha256 = ('2' * 64) -join ''
            config_file_count = 2
            source = 'docker inspect compose labels (read-only)'
        }
        runtime_container_set_sha256 = ('3' * 64) -join ''
        published_ports_sha256 = ('4' * 64) -join ''
        named_volumes_before_sha256 = $volumeBefore
        named_volumes_after_sha256 = $volumeAfter
        named_volume_fingerprint = [ordered]@{
            algorithm = 'sha256'
            equality = 'exact named-volume set and identity metadata before/after'
            source = 'docker inspect Mounts + docker volume inspect (read-only)'
            fields = @('Service','Source','Target','ReadOnly','IdentityName','Driver','Scope','CreatedAt','MountpointSha256','Mode','Propagation','OptionsSha256','LabelsSha256')
            before_sha256 = $volumeBefore
            after_sha256 = if ($UnequalFingerprintHashes) { ('8' * 64) -join '' } else { $volumeAfter }
        }
        authentication_results_sha256 = ('6' * 64) -join ''
        dpapi_record_sha256 = $hashes
        credential_provenance = 'canonical DPAPI CurrentUser records; values decrypted in memory only'
        mutation_summary = $mutation
    }
    if ($OmitProducerMode) { [void]$record.Remove('producer_mode') }
    $path = Join-Path $Root "$RuntimeSessionId.json"
    [IO.File]::WriteAllText(
        $path,
        (($record | ConvertTo-Json -Depth 12) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    return $path
}

function Read-TestEvidence {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RuntimeSessionId,
        [Parameter(Mandatory)][datetimeoffset]$NotBeforeUtc,
        [string]$ExpectedSha256 = ''
    )
    if ([string]::IsNullOrEmpty($ExpectedSha256)) {
        $ExpectedSha256 = Get-TestFileSha256 -Path $Path
    }
    return Read-SocHardeningEvidence `
        -EvidenceRoot $evidenceRoot `
        -SecretRoot $secretRoot `
        -EvidencePath $Path `
        -ExpectedSha256 $ExpectedSha256 `
        -ExpectedRuntimeSessionId $RuntimeSessionId `
        -NotBeforeUtc $NotBeforeUtc
}

function Assert-TestReaderFails {
    param([scriptblock]$Script,[string]$MessagePattern)
    $failed = $false
    $actualMessage = ''
    try { & $Script } catch {
        $actualMessage = $_.Exception.Message
        $failed = $actualMessage -match $MessagePattern
    }
    if (-not $failed) {
        throw "Reader did not fail with the expected contract: $MessagePattern; actual: $actualMessage"
    }
}

function Invoke-SocNativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )
    $script:lastNativeArguments = @($Arguments)
    if ($null -eq $script:nativeFixture) { throw 'The test native fixture is unset.' }
    return & $script:nativeFixture
}

try {
    New-Item -ItemType Directory -Path $secretRoot,$hardeningRoot -Force | Out-Null
    foreach ($dpapiName in $dpapiNames) {
        [IO.File]::WriteAllText(
            (Join-Path $secretRoot "$dpapiName.dpapi.json"),
            "fixture-$dpapiName`n",
            [Text.UTF8Encoding]::new($false)
        )
    }

    $now = [datetimeoffset]::UtcNow
    $notBefore = $now.AddMinutes(-5)
    $arbitraryId = New-TestRuntimeSessionId
    $arbitraryPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $arbitraryId -CheckedAt $now.AddMinutes(-2)
    $selectedId = New-TestRuntimeSessionId
    $selectedPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $selectedId -CheckedAt $now.AddMinutes(-1)
    (Get-Item -LiteralPath $selectedPath).LastWriteTimeUtc = $now.AddHours(-2).UtcDateTime
    (Get-Item -LiteralPath $arbitraryPath).LastWriteTimeUtc = $now.UtcDateTime
    $selected = Read-TestEvidence -Path $selectedPath -RuntimeSessionId $selectedId -NotBeforeUtc $notBefore
    if ($selected.Path -cne [IO.Path]::GetFullPath($selectedPath) -or
        $selected.Sha256 -cne (Get-TestFileSha256 -Path $selectedPath) -or
        $selected.ProducerMode -cne 'verify_existing') {
        throw 'The exact hardening reader did not consume only its returned path and hash.'
    }

    $unsupportedVersionId = New-TestRuntimeSessionId
    $unsupportedVersionPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $unsupportedVersionId -CheckedAt $now
    $unsupportedVersionRecord = Get-Content -LiteralPath $unsupportedVersionPath -Raw | ConvertFrom-Json -Depth 20 -DateKind String
    $unsupportedVersionRecord.wazuh_version = '5.0.0'
    $unsupportedVersionRecord.wazuh_major_version = 5
    [IO.File]::WriteAllText(
        $unsupportedVersionPath,
        (($unsupportedVersionRecord | ConvertTo-Json -Depth 20) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    Assert-TestReaderFails {
        Read-TestEvidence -Path $unsupportedVersionPath -RuntimeSessionId $unsupportedVersionId `
            -NotBeforeUtc $notBefore | Out-Null
    } 'version is unsupported'

    $script:nativeFixture = {
        $freshId = New-TestRuntimeSessionId
        $freshPath = Write-TestEvidenceRecord -Root $hardeningRoot `
            -RuntimeSessionId $freshId -CheckedAt ([datetimeoffset]::UtcNow)
        $script:lastFreshCreatedPath = $freshPath
        return ([ordered]@{
            schema_version = 1
            producer_mode = 'verify_existing'
            runtime_session_id = $freshId
            evidence_path = $freshPath
            evidence_sha256 = Get-TestFileSha256 -Path $freshPath
        } | ConvertTo-Json -Compress)
    }
    $fresh = Invoke-SocFreshHardeningEvidence `
        -WazuhRoot (Join-Path $testRoot 'single-node') `
        -SecretRoot $secretRoot `
        -EvidenceRoot $evidenceRoot `
        -NotBeforeUtc $notBefore
    if ($fresh.Path -cne [IO.Path]::GetFullPath($script:lastFreshCreatedPath) -or
        $fresh.Sha256 -cne (Get-TestFileSha256 -Path $script:lastFreshCreatedPath) -or
        $script:lastNativeArguments -notcontains (Join-Path $root 'tools\Test-SocWazuhHardeningRuntime.ps1')) {
        throw 'Start did not consume the exact path/hash returned by the fresh verify-only runner.'
    }

    $oldExactHash = Get-TestFileSha256 -Path $selectedPath
    $script:nativeFixture = {
        return ([ordered]@{
            schema_version = 1
            producer_mode = 'verify_existing'
            runtime_session_id = $selectedId
            evidence_path = $selectedPath
            evidence_sha256 = $oldExactHash
        } | ConvertTo-Json -Compress)
    }
    Assert-TestReaderFails {
        Invoke-SocFreshHardeningEvidence `
            -WazuhRoot (Join-Path $testRoot 'single-node') `
            -SecretRoot $secretRoot `
            -EvidenceRoot $evidenceRoot `
            -NotBeforeUtc $notBefore | Out-Null
    } 'fresh UTC timestamp'

    Assert-TestReaderFails {
        Read-TestEvidence -Path $selectedPath -RuntimeSessionId $selectedId `
            -NotBeforeUtc $notBefore -ExpectedSha256 (('0' * 64) -join '') | Out-Null
    } 'SHA-256|malformed'

    $stringBooleanId = New-TestRuntimeSessionId
    $stringBooleanPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $stringBooleanId -CheckedAt $now -StringBoolean
    Assert-TestReaderFails {
        Read-TestEvidence -Path $stringBooleanPath -RuntimeSessionId $stringBooleanId -NotBeforeUtc $notBefore | Out-Null
    } 'JSON Boolean'

    $badHashId = New-TestRuntimeSessionId
    $badHashPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $badHashId -CheckedAt $now -BadDpapiHash
    Assert-TestReaderFails {
        Read-TestEvidence -Path $badHashPath -RuntimeSessionId $badHashId -NotBeforeUtc $notBefore | Out-Null
    } 'DPAPI hash'

    $legacyId = New-TestRuntimeSessionId
    $legacyPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $legacyId -CheckedAt $now -OmitProducerMode
    Assert-TestReaderFails {
        Read-TestEvidence -Path $legacyPath -RuntimeSessionId $legacyId -NotBeforeUtc $notBefore | Out-Null
    } 'producer_mode'

    $caseId = New-TestRuntimeSessionId
    $casePath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $caseId -CheckedAt $now -ProducerMode 'Verify_Existing'
    Assert-TestReaderFails {
        Read-TestEvidence -Path $casePath -RuntimeSessionId $caseId -NotBeforeUtc $notBefore | Out-Null
    } 'producer_mode is not approved'

    $provenanceId = New-TestRuntimeSessionId
    $provenancePath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $provenanceId -CheckedAt $now -ActiveStateProvenance 'Not_Written_Verify_Only'
    Assert-TestReaderFails {
        Read-TestEvidence -Path $provenancePath -RuntimeSessionId $provenanceId -NotBeforeUtc $notBefore | Out-Null
    } 'runtime session semantics'

    $unequalId = New-TestRuntimeSessionId
    $unequalPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $unequalId -CheckedAt $now -UnequalVolumeHashes
    Assert-TestReaderFails {
        Read-TestEvidence -Path $unequalPath -RuntimeSessionId $unequalId -NotBeforeUtc $notBefore | Out-Null
    } 'before/after hashes'

    $unequalFingerprintId = New-TestRuntimeSessionId
    $unequalFingerprintPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $unequalFingerprintId -CheckedAt $now -UnequalFingerprintHashes
    Assert-TestReaderFails {
        Read-TestEvidence -Path $unequalFingerprintPath `
            -RuntimeSessionId $unequalFingerprintId -NotBeforeUtc $notBefore | Out-Null
    } 'fingerprint hashes'

    $upperSessionId = (New-TestRuntimeSessionId).ToUpperInvariant()
    $upperSessionPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $upperSessionId -CheckedAt $now
    $upperSessionRecord = Get-Content -LiteralPath $upperSessionPath -Raw | ConvertFrom-Json -Depth 20
    Assert-TestReaderFails {
        Assert-SocHardeningEvidenceRecord `
            -Record $upperSessionRecord -SecretRoot $secretRoot -NotBeforeUtc $notBefore | Out-Null
    } 'runtime session semantics'

    $staleId = New-TestRuntimeSessionId
    $stalePath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $staleId -CheckedAt $now.AddMinutes(-31)
    Assert-TestReaderFails {
        Read-TestEvidence -Path $stalePath -RuntimeSessionId $staleId `
            -NotBeforeUtc $now.AddHours(-1) | Out-Null
    } 'fresh UTC timestamp'

    $preSessionId = New-TestRuntimeSessionId
    $preSessionPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $preSessionId -CheckedAt $now.AddMinutes(-2)
    Assert-TestReaderFails {
        Read-TestEvidence -Path $preSessionPath -RuntimeSessionId $preSessionId `
            -NotBeforeUtc $now.AddMinutes(-1) | Out-Null
    } 'fresh UTC timestamp'

    $mutatingId = New-TestRuntimeSessionId
    $mutatingPath = Write-TestEvidenceRecord -Root $hardeningRoot `
        -RuntimeSessionId $mutatingId -CheckedAt $now -ProducerMode mutating_hardening
    $mutatingRecord = Get-Content -LiteralPath $mutatingPath -Raw | ConvertFrom-Json -Depth 20
    $mutatingMode = Assert-SocHardeningEvidenceRecord `
        -Record $mutatingRecord -SecretRoot $secretRoot -NotBeforeUtc $notBefore
    if ($mutatingMode -cne 'mutating_hardening' -or
        $mutatingRecord.wazuh_credential_rotation_observed -isnot [bool] -or
        $mutatingRecord.wazuh_credential_rotation_observed -ne $true) {
        throw 'Explicit mutating Evidence semantics were not preserved by the strict record validator.'
    }
    Assert-TestReaderFails {
        Read-TestEvidence -Path $mutatingPath -RuntimeSessionId $mutatingId -NotBeforeUtc $notBefore | Out-Null
    } 'fresh verify_existing result'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'Strict Wazuh hardening reader tests passed.'
