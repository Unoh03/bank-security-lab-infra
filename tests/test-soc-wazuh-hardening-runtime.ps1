#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runnerPath = Join-Path $root 'tools\Test-SocWazuhHardeningRuntime.ps1'
$securityPath = Join-Path $root 'automation\SocLab.Security.psm1'
Import-Module $securityPath -Force

if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
    throw 'The verify-only Wazuh hardening runtime runner is missing.'
}
$runnerText = Get-Content -LiteralPath $runnerPath -Raw
foreach ($required in @(
    '-CommandAdapter',
    '-HttpAdapter',
    'producer_mode',
    'verify_existing',
    'Write-SocEvidenceAtomically',
    'docker inspect',
    'local_only_ports',
    'named_volumes_before_sha256',
    'named_volumes_after_sha256',
    'CreatedAt',
    'MountpointSha256',
    'evidence_sha256'
)) {
    if ($runnerText -notmatch [regex]::Escape($required)) {
        throw "The verify-only runtime runner is missing its required contract: $required"
    }
}
if ($runnerText -match "(?s)'(?:down|up|restart|exec|run|rm)'|docker\s+compose") {
    throw 'The verify-only runtime runner contains a Docker mutation or Compose invocation.'
}
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile($runnerPath,[ref]$tokens,[ref]$errors) | Out-Null
if (@($errors).Count -ne 0) {
    throw ('PowerShell parser rejected the verify-only runtime runner: ' + (@($errors.Message) -join '; '))
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soc-wazuh-hardening-' + [guid]::NewGuid().ToString('N'))
$testSecretRoot = Join-Path $testRoot 'secrets'
$testEvidenceRoot = Join-Path $testRoot 'evidence'
$fixtureWazuhRoot = Join-Path $testRoot 'single-node'
$customAdmin = 'FixtureAdmin-A9.*-' + [guid]::NewGuid().ToString('N')
$customKibana = 'FixtureKibana-B8.*-' + [guid]::NewGuid().ToString('N')
$customApi = 'FixtureApi-C7.*-' + [guid]::NewGuid().ToString('N')
$mockIds = @{
    'wazuh.manager' = ('a' * 64) -join ''
    'wazuh.indexer' = ('b' * 64) -join ''
    'wazuh.dashboard' = ('c' * 64) -join ''
}
$mockLabels = @{
    'com.docker.compose.project' = 'single-node'
    'com.docker.compose.project.working_dir' = $fixtureWazuhRoot
    'com.docker.compose.project.config_files' = ((Join-Path $fixtureWazuhRoot 'docker-compose.yml') + ';' +
        (Join-Path $fixtureWazuhRoot 'docker-compose.soc.override.yml'))
}
$mockLabelsByService = @{}
$mockPorts = @{
    'wazuh.manager' = [ordered]@{
        '1514/tcp' = @([ordered]@{ HostIp='127.0.0.1'; HostPort='1514' })
        '1515/tcp' = @([ordered]@{ HostIp='127.0.0.1'; HostPort='1515' })
        '514/udp'  = @([ordered]@{ HostIp='127.0.0.1'; HostPort='514' })
        '55000/tcp' = @([ordered]@{ HostIp='127.0.0.1'; HostPort='55000' })
    }
    'wazuh.indexer' = [ordered]@{
        '9200/tcp' = @([ordered]@{ HostIp='127.0.0.1'; HostPort='9200' })
    }
    'wazuh.dashboard' = [ordered]@{
        '443/tcp' = @([ordered]@{ HostIp='127.0.0.1'; HostPort='443' })
    }
}
$mockMounts = @{
    'wazuh.manager' = @(
        [ordered]@{ Type='volume'; Name='single-node_wazuh_etc'; Source='single-node_wazuh_etc'; Destination='/var/ossec/etc'; RW=$true; Mode='rw'; Propagation='rprivate' }
        [ordered]@{ Type='volume'; Name='single-node_wazuh_queue'; Source='single-node_wazuh_queue'; Destination='/var/ossec/queue'; RW=$true; Mode='rw'; Propagation='rprivate' }
    )
    'wazuh.indexer' = @(
        [ordered]@{ Type='volume'; Name='single-node_wazuh-indexer-data'; Source='single-node_wazuh-indexer-data'; Destination='/var/lib/wazuh-indexer'; RW=$true; Mode='rw'; Propagation='rprivate' }
    )
    'wazuh.dashboard' = @(
        [ordered]@{ Type='volume'; Name='single-node_wazuh-dashboard-config'; Source='single-node_wazuh-dashboard-config'; Destination='/usr/share/wazuh-dashboard/data/wazuh/config'; RW=$true; Mode='rw'; Propagation='rprivate' }
    )
}
$mockVolumeMetadata = @{}
foreach ($mount in @($mockMounts.Values | ForEach-Object { $_ })) {
    foreach ($entry in @($mount)) {
        $mockVolumeMetadata[[string]$entry.Name] = [ordered]@{
            Name = [string]$entry.Name
            Driver = 'local'
            Scope = 'local'
            CreatedAt = '2026-08-18T00:00:00Z'
            Mountpoint = '/var/lib/docker/volumes/' + [string]$entry.Name + '/_data'
            Options = [ordered]@{}
            Labels = [ordered]@{}
        }
    }
}

try {
    New-Item -ItemType Directory -Path $fixtureWazuhRoot -Force | Out-Null
    foreach ($file in @('docker-compose.yml','docker-compose.soc.override.yml')) {
        [IO.File]::WriteAllText((Join-Path $fixtureWazuhRoot $file), "fixture`n", [Text.UTF8Encoding]::new($false))
    }
    foreach ($service in $mockIds.Keys) {
        $serviceLabels = [ordered]@{}
        foreach ($entry in $mockLabels.GetEnumerator()) { $serviceLabels[$entry.Key] = $entry.Value }
        $serviceLabels['com.docker.compose.service'] = $service
        $mockLabelsByService[$service] = $serviceLabels
    }

    $script:mockCalls = [Collections.Generic.List[string]]::new()
    $mockCommandAdapter = {
        param([string]$FilePath,[string[]]$Arguments)
        $script:mockCalls.Add("$FilePath $($Arguments -join ' ')")
        $args = @($Arguments)
        if ($FilePath -cne 'docker') { throw 'fixture only supports docker' }
        if ($args[0] -ceq 'ps') {
            $label = @($args | Where-Object { $_ -like 'label=com.docker.compose.service=*' })[0]
            $service = [string]$label -replace '^label=com\.docker\.compose\.service=', ''
            return [pscustomobject]@{ ExitCode=0; StdOut="$($mockIds[$service])`n"; StdErr='' }
        }
        if ($args[0] -ceq 'inspect') {
            $template = [string]$args[2]
            $id = [string]$args[3]
            $service = @($mockIds.GetEnumerator() | Where-Object { $_.Value -ceq $id } | Select-Object -ExpandProperty Key)[0]
            $value = switch ($template) {
                '{{json .Config.Labels}}' { $mockLabelsByService[$service] | ConvertTo-Json -Compress }
                '{{json .State.Status}}' { '"running"' }
                '{{json .Config.Image}}' { '"wazuh/wazuh-manager:4.14.7"' }
                '{{json .NetworkSettings.Ports}}' { $mockPorts[$service] | ConvertTo-Json -Depth 10 -Compress }
                '{{json .Mounts}}' { $mockMounts[$service] | ConvertTo-Json -Depth 10 -Compress }
                default { throw "unexpected inspect template: $template" }
            }
            if ($service -ceq 'wazuh.indexer') {
                if ($template -ceq '{{json .Config.Image}}') { $value = '"wazuh/wazuh-indexer:4.14.7"' }
            } elseif ($service -ceq 'wazuh.dashboard') {
                if ($template -ceq '{{json .Config.Image}}') { $value = '"wazuh/wazuh-dashboard:4.14.7"' }
            }
            return [pscustomobject]@{ ExitCode=0; StdOut=[string]$value; StdErr='' }
        }
        if ($args[0] -ceq 'volume' -and $args[1] -ceq 'inspect') {
            $volumeName = [string]$args[4]
            return [pscustomobject]@{
                ExitCode=0
                StdOut=($mockVolumeMetadata[$volumeName] | ConvertTo-Json -Depth 10 -Compress)
                StdErr=''
            }
        }
        throw 'unexpected read-only fixture command'
    }
    $script:mockProbeCalls = [Collections.Generic.List[object]]::new()
    $expectedProbePasswords = @{
        new_admin = $customAdmin
        default_admin = ('Secret'+'Password')
        new_kibanaserver = $customKibana
        default_kibanaserver = ('kibana'+'server')
        new_wazuh_wui = $customApi
        default_wazuh_wui = ('MyS3cr37P450r.'+'*-')
    }
    $mockHttpAdapter = {
        param([string]$ProbeName,[string]$UserName,[string]$Password,[int]$Port,[string]$Method)
        $passwordContractMatched = $expectedProbePasswords.ContainsKey($ProbeName) -and
            [string]::Equals(
                [string]$Password,
                [string]$expectedProbePasswords[$ProbeName],
                [StringComparison]::Ordinal
            )
        $status = if (-not $passwordContractMatched) { 500 }
            elseif ($ProbeName -ceq 'default_kibanaserver') { 403 }
            elseif ($ProbeName -like 'default_*') { 401 }
            else { 200 }
        $script:mockProbeCalls.Add([pscustomobject]@{
            ProbeName=$ProbeName
            UserName=$UserName
            Port=$Port
            Method=$Method
            StatusCode=$status
            PasswordContractMatched=[bool]$passwordContractMatched
        })
        if ($ProbeName -like 'default_*') {
            return [pscustomobject]@{ StatusCode=$status }
        }
        if ([string]::IsNullOrEmpty($Password) -or $Port -notin @(9200,55000)) {
            return [pscustomobject]@{ StatusCode=500 }
        }
        return [pscustomobject]@{ StatusCode=200 }
    }

    New-Item -ItemType Directory -Path $testSecretRoot -Force | Out-Null
    foreach ($secret in @(
        @{ Name='wazuh_indexer_admin_password'; Value=$customAdmin },
        @{ Name='wazuh_indexer_kibanaserver_password'; Value=$customKibana },
        @{ Name='wazuh_api_wui_password'; Value=$customApi }
    )) {
        # Keep the fixture independent of host ACL/elevation policy while using
        # the exact DPAPI record shape consumed by Unprotect-SocSecret.
        $plainBytes = [Text.Encoding]::UTF8.GetBytes($secret.Value)
        $cipherBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes,
            [Text.Encoding]::UTF8.GetBytes("aws-topology-soc-v1:$($secret.Name)"),
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        try {
            $record = [ordered]@{
                schema_version = 1
                name = $secret.Name
                protected_at = [DateTimeOffset]::UtcNow.ToString('o')
                scope = 'CurrentUser'
                cipher_base64 = [Convert]::ToBase64String($cipherBytes)
            } | ConvertTo-Json -Depth 4
            [IO.File]::WriteAllText(
                (Join-Path $testSecretRoot "$($secret.Name).dpapi.json"),
                "$record`n",
                [Text.UTF8Encoding]::new($false)
            )
        } finally {
            if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
            if ($cipherBytes) { [Array]::Clear($cipherBytes, 0, $cipherBytes.Length) }
        }
    }

    # Load functions without executing the live runner, then exercise the same
    # production function with injected read-only command and HTTP adapters.
    . $runnerPath -NoRun
    $captured = Invoke-SocWazuhHardeningRuntimeEvidence `
        -WazuhRoot $fixtureWazuhRoot `
        -SecretRoot $testSecretRoot `
        -EvidenceRoot $testEvidenceRoot `
        -CommandAdapter $mockCommandAdapter `
        -HttpAdapter $mockHttpAdapter
    $capturedText = $captured | ConvertTo-Json -Depth 5 -Compress
    foreach ($secretValue in @($customAdmin,$customKibana,$customApi)) {
        if ($capturedText.Contains($secretValue)) { throw 'The runner output exposed a fixture credential.' }
    }
    if ($mockProbeCalls.Count -ne 6) { throw 'The verify-only runner did not issue exactly six authentication probes.' }
    $expectedProbes = @(
        @{ Name='new_admin'; User='admin'; Port=9200; Method='Get'; Status=200 },
        @{ Name='default_admin'; User='admin'; Port=9200; Method='Get'; Status=401 },
        @{ Name='new_kibanaserver'; User='kibanaserver'; Port=9200; Method='Get'; Status=200 },
        @{ Name='default_kibanaserver'; User='kibanaserver'; Port=9200; Method='Get'; Status=403 },
        @{ Name='new_wazuh_wui'; User='wazuh-wui'; Port=55000; Method='Post'; Status=200 },
        @{ Name='default_wazuh_wui'; User='wazuh-wui'; Port=55000; Method='Post'; Status=401 }
    )
    for ($probeIndex = 0; $probeIndex -lt $expectedProbes.Count; $probeIndex++) {
        $expectedProbe = $expectedProbes[$probeIndex]
        $actualProbe = $mockProbeCalls[$probeIndex]
        if ($actualProbe.ProbeName -cne $expectedProbe.Name -or
            $actualProbe.UserName -cne $expectedProbe.User -or
            [int]$actualProbe.Port -ne $expectedProbe.Port -or
            $actualProbe.Method -cne $expectedProbe.Method -or
            [int]$actualProbe.StatusCode -ne $expectedProbe.Status -or
            $actualProbe.PasswordContractMatched -isnot [bool] -or
            $actualProbe.PasswordContractMatched -ne $true) {
            throw "Authentication probe tuple $probeIndex did not match the frozen contract."
        }
    }
    $hardeningEvidenceRoot = Join-Path $testEvidenceRoot 'soc-lab-hardening'
    $evidenceFile = @(Get-ChildItem -LiteralPath $hardeningEvidenceRoot -File -Filter 'wazuh-hardening-*.json')
    if ($evidenceFile.Count -ne 1) { throw 'The mock runtime did not create exactly one hardening Evidence file.' }
    if ([int]$captured.schema_version -ne 1 -or
        [string]$captured.producer_mode -cne 'verify_existing' -or
        [string]$captured.runtime_session_id -cne [IO.Path]::GetFileNameWithoutExtension($evidenceFile[0].Name) -or
        [IO.Path]::GetFullPath([string]$captured.evidence_path) -cne $evidenceFile[0].FullName -or
        [string]$captured.evidence_sha256 -cne (Get-FileHash -LiteralPath $evidenceFile[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'The verify-only runner did not return the exact Evidence path/hash contract.'
    }
    $evidenceText = Get-Content -LiteralPath $evidenceFile[0].FullName -Raw
    $record = $evidenceText | ConvertFrom-Json
    foreach ($booleanContract in @(
        @{ Object=$record; Name='local_only_ports'; Expected=$true },
        @{ Object=$record; Name='named_volumes_removed'; Expected=$false },
        @{ Object=$record; Name='named_volumes_identical_before_after'; Expected=$true },
        @{ Object=$record; Name='secrets_printed'; Expected=$false },
        @{ Object=$record; Name='wazuh_authentication_verified'; Expected=$true },
        @{ Object=$record; Name='wazuh_credential_rotation_observed'; Expected=$false },
        @{ Object=$record.mutation_summary; Name='credential_rotation_observed'; Expected=$false }
    )) {
        $property = $booleanContract.Object.PSObject.Properties[$booleanContract.Name]
        if ($null -eq $property -or
            $property.Value -isnot [bool] -or
            $property.Value -ne $booleanContract.Expected) {
            throw "The Evidence property is not the required JSON Boolean: $($booleanContract.Name)"
        }
    }
    if ([int]$record.schema_version -ne 1 -or
        [string]$record.producer_mode -cne 'verify_existing' -or
        [int]$record.mutation_summary.docker_mutations -ne 0 -or
        [int]$record.mutation_summary.wazuh_mutations -ne 0 -or
        [string]$record.new_admin_authentication -cne 'accepted' -or
        [string]$record.default_admin_authentication -cne 'rejected' -or
        [string]$record.new_kibanaserver_authentication -cne 'accepted' -or
        [string]$record.default_kibana_authentication -cne 'rejected' -or
        [string]$record.new_wazuh_wui_authentication -cne 'accepted' -or
        [string]$record.default_wazuh_wui_authentication -cne 'rejected' -or
        [string]$record.named_volumes_before_sha256 -cne [string]$record.named_volumes_after_sha256 -or
        [string]$record.named_volume_fingerprint.source -cne 'docker inspect Mounts + docker volume inspect (read-only)' -or
        (@($record.named_volume_fingerprint.fields) -join '|') -cne
            'Service|Source|Target|ReadOnly|IdentityName|Driver|Scope|CreatedAt|MountpointSha256|Mode|Propagation|OptionsSha256|LabelsSha256' -or
        [string]$record.named_volume_fingerprint.before_sha256 -cne [string]$record.named_volumes_before_sha256 -or
        [string]$record.named_volume_fingerprint.after_sha256 -cne [string]$record.named_volumes_after_sha256) {
        throw 'The mock hardening Evidence did not satisfy the Start-SocLab contract.'
    }
    foreach ($secretValue in @($customAdmin,$customKibana,$customApi)) {
        if ($evidenceText.Contains($secretValue)) { throw 'The Evidence file exposed a fixture credential.' }
    }
    if ($evidenceText -match '(?i)https?://') { throw 'The Evidence file contains a URI.' }
    if (@(Get-ChildItem -LiteralPath $hardeningEvidenceRoot -File -Filter '*.tmp').Count -ne 0) {
        throw 'The atomic Evidence temporary file was not cleaned up.'
    }
    & (Join-Path $root 'tools\Test-SocSecretExposure.ps1') -Path $evidenceFile[0].FullName | Out-Host

    # Exercise the real ProcessStartInfo path with enough output on both pipes
    # to expose the classic sequential-read deadlock.
    $pwshPath = (Get-Command pwsh -ErrorAction Stop).Source
    $noisyCommand = "[Console]::Out.Write(('O' * 200000)); [Console]::Error.Write(('E' * 200000))"
    $noisyResult = Invoke-SocReadOnlyCommand `
        -FilePath $pwshPath `
        -Arguments @('-NoProfile','-Command',$noisyCommand)
    if ($noisyResult.ExitCode -ne 0 -or
        $noisyResult.StdOut.Length -ne 200000 -or
        $noisyResult.StdErr.Length -ne 200000) {
        throw 'The dual-stream ProcessStartInfo capture fixture failed.'
    }

    $invalidHttpAdapter = {
        param([string]$ProbeName,[string]$UserName,[string]$Password,[int]$Port,[string]$Method)
        if ($ProbeName -ceq 'new_kibanaserver') { return [pscustomobject]@{ StatusCode=500 } }
        if ($ProbeName -like 'default_*') { return [pscustomobject]@{ StatusCode=401 } }
        return [pscustomobject]@{ StatusCode=200 }
    }
    $invalidStatusFailedClosed = $false
    try {
        Invoke-SocWazuhHardeningRuntimeEvidence `
            -WazuhRoot $fixtureWazuhRoot `
            -SecretRoot $testSecretRoot `
            -EvidenceRoot (Join-Path $testRoot 'invalid-status-evidence') `
            -CommandAdapter $mockCommandAdapter `
            -HttpAdapter $invalidHttpAdapter | Out-Null
    } catch {
        $invalidStatusFailedClosed = $_.Exception.Message -match 'authentication probe|HTTP adapter'
    }
    if (-not $invalidStatusFailedClosed -or
        (Test-Path -LiteralPath (Join-Path $testRoot 'invalid-status-evidence'))) {
        throw 'The verify-only runner did not fail closed on an invalid authentication status.'
    }

    # Simulate a volume recreation between the before/after snapshots. Both the
    # creation time and mountpoint identity change without changing the name.
    $script:recreatedVolumeInspectCount = 0
    $recreatedVolumeAdapter = {
        param([string]$FilePath,[string[]]$Arguments)
        $result = & $mockCommandAdapter -FilePath $FilePath -Arguments $Arguments
        $args = @($Arguments)
        if ($args[0] -ceq 'volume' -and $args[1] -ceq 'inspect') {
            $script:recreatedVolumeInspectCount++
            if ($script:recreatedVolumeInspectCount -gt $mockVolumeMetadata.Count) {
                $identity = $result.StdOut | ConvertFrom-Json -Depth 10
                $identity.CreatedAt = '2026-08-19T00:00:00Z'
                $identity.Mountpoint = '/var/lib/docker/volumes/recreated/_data'
                return [pscustomobject]@{
                    ExitCode=0
                    StdOut=($identity | ConvertTo-Json -Depth 10 -Compress)
                    StdErr=''
                }
            }
        }
        return $result
    }
    $recreatedEvidenceRoot = Join-Path $testRoot 'recreated-volume-evidence'
    $recreatedFailedClosed = $false
    try {
        Invoke-SocWazuhHardeningRuntimeEvidence `
            -WazuhRoot $fixtureWazuhRoot `
            -SecretRoot $testSecretRoot `
            -EvidenceRoot $recreatedEvidenceRoot `
            -CommandAdapter $recreatedVolumeAdapter `
            -HttpAdapter $mockHttpAdapter | Out-Null
    } catch {
        $recreatedFailedClosed = $_.Exception.Message -match 'runtime changed'
    }
    if (-not $recreatedFailedClosed -or (Test-Path -LiteralPath $recreatedEvidenceRoot)) {
        throw 'The verify-only runner did not detect a same-name Docker volume recreation.'
    }

    # A non-loopback binding is an inconsistency: no second PASS Evidence may be written.
    $mockPorts['wazuh.manager']['55000/tcp'][0].HostIp = '0.0.0.0'
    $failedClosed = $false
    try {
        Invoke-SocWazuhHardeningRuntimeEvidence `
            -WazuhRoot $fixtureWazuhRoot `
            -SecretRoot $testSecretRoot `
            -EvidenceRoot (Join-Path $testRoot 'rejected-evidence') `
            -CommandAdapter $mockCommandAdapter `
            -HttpAdapter $mockHttpAdapter | Out-Null
    } catch {
        $failedClosed = $_.Exception.Message -match 'loopback|published Wazuh port'
    }
    if (-not $failedClosed -or (Test-Path -LiteralPath (Join-Path $testRoot 'rejected-evidence'))) {
        throw 'The verify-only runner did not fail closed on a non-loopback runtime.'
    }
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'Verify-only Wazuh hardening runtime tests passed.'
