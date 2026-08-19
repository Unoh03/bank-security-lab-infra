#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$WazuhRoot = 'D:\Wazuh\wazuh-docker\single-node',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [scriptblock]$CommandAdapter = $null,
    [scriptblock]$HttpAdapter = $null,
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$securityModulePath = Join-Path $repositoryRoot 'automation\SocLab.Security.psm1'
Import-Module $securityModulePath -Force

function ConvertTo-SocSha256Text {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Text)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $hash.Dispose()
    }
}

function ConvertTo-SocCanonicalLines {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Record)

    return @($Record | ForEach-Object {
            $fields = [ordered]@{}
            foreach ($property in $_.PSObject.Properties | Sort-Object Name) {
                $fields[[string]$property.Name] = [string]$property.Value
            }
            ($fields.GetEnumerator() | ForEach-Object {
                '{0}={1}' -f $_.Key,([string]$_.Value).Replace("`r", '').Replace("`n", '')
            }) -join '|'
        } | Sort-Object) -join "`n"
}

function Invoke-SocReadOnlyCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [scriptblock]$Adapter = $null
    )

    if ($null -ne $Adapter) {
        try {
            $adapted = @(& $Adapter -FilePath $FilePath -Arguments $Arguments)
        } catch {
            throw "The read-only command adapter failed for $FilePath."
        }
        if ($adapted.Count -ne 1 -or $null -eq $adapted[0]) {
            throw "The read-only command adapter returned an invalid result for $FilePath."
        }
        $result = $adapted[0]
        if ($null -eq $result.PSObject.Properties['ExitCode'] -or
            $null -eq $result.PSObject.Properties['StdOut'] -or
            $null -eq $result.PSObject.Properties['StdErr']) {
            throw "The read-only command adapter returned an incomplete result for $FilePath."
        }
        if ([int]$result.ExitCode -ne 0) {
            throw "The read-only command failed for $FilePath (exit code $([int]$result.ExitCode))."
        }
        return [pscustomobject]@{
            ExitCode = [int]$result.ExitCode
            StdOut   = [string]$result.StdOut
            StdErr   = [string]$result.StdErr
        }
    }

    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        throw "The required read-only command is unavailable: $FilePath"
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "The read-only command could not start: $FilePath"
        }
        # Drain both pipes concurrently. Reading one redirected stream to EOF
        # before opening the other can deadlock on a noisy child process.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "The read-only command failed for $FilePath (exit code $($process.ExitCode))."
        }
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            StdOut   = [string]$stdout
            StdErr   = [string]$stderr
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-SocReadOnlyJsonCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [scriptblock]$Adapter = $null
    )

    $result = Invoke-SocReadOnlyCommand -FilePath 'docker' -Arguments $Arguments -Adapter $Adapter
    if ([string]::IsNullOrWhiteSpace($result.StdErr)) {
        # No native diagnostic is forwarded. A successful Docker probe is expected
        # to keep stderr empty; retaining it in memory would add no evidence value.
    }
    if ([string]::IsNullOrWhiteSpace($result.StdOut)) {
        throw 'The read-only Docker probe returned no data.'
    }
    try {
        return ([string]$result.StdOut).Trim() | ConvertFrom-Json -Depth 30
    } catch {
        throw 'The read-only Docker probe returned invalid JSON.'
    }
}

function Get-SocDockerInspectValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ContainerId,
        [Parameter(Mandatory)][string]$Template,
        [scriptblock]$Adapter = $null
    )

    return Invoke-SocReadOnlyJsonCommand -Arguments @(
        'inspect',
        '--format',
        $Template,
        $ContainerId
    ) -Adapter $Adapter
}

function Get-SocDockerVolumeInspectValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VolumeName,
        [scriptblock]$Adapter = $null
    )

    return Invoke-SocReadOnlyJsonCommand -Arguments @(
        'volume','inspect',
        '--format','{{json .}}',
        $VolumeName
    ) -Adapter $Adapter
}

function Get-SocRunningContainerId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('wazuh.manager','wazuh.indexer','wazuh.dashboard')][string]$Service,
        [scriptblock]$Adapter = $null
    )

    $result = Invoke-SocReadOnlyCommand -FilePath 'docker' -Arguments @(
        'ps','-q',
        '--filter',"label=com.docker.compose.service=$Service",
        '--filter','status=running'
    ) -Adapter $Adapter
    $ids = @([string]$result.StdOut -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($ids.Count -ne 1 -or $ids[0] -notmatch '^[0-9a-fA-F]{12,64}$') {
        throw "The active Wazuh runtime did not expose exactly one running $Service container."
    }
    return $ids[0].ToLowerInvariant()
}

function Resolve-SocAbsolutePathLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -match '^(?i:https?|file|tcp|udp)://') {
        throw 'The active Compose label contained an unsafe path or URI.'
    }
    try {
        $resolved = [IO.Path]::GetFullPath($Path)
    } catch {
        throw 'The active Compose label contained an invalid path.'
    }
    if (-not [IO.Path]::IsPathRooted($resolved)) {
        throw 'The active Compose label contained a relative path.'
    }
    return $resolved
}

function Get-SocRuntimeDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WazuhRoot,
        [scriptblock]$Adapter = $null
    )

    $services = @('wazuh.manager','wazuh.indexer','wazuh.dashboard')
    $records = [Collections.Generic.List[object]]::new()
    $volumeMetadata = @{}
    foreach ($service in $services) {
        $containerId = Get-SocRunningContainerId -Service $service -Adapter $Adapter
        $labels = Get-SocDockerInspectValue -ContainerId $containerId `
            -Template '{{json .Config.Labels}}' -Adapter $Adapter
        $state = Get-SocDockerInspectValue -ContainerId $containerId `
            -Template '{{json .State.Status}}' -Adapter $Adapter
        $image = Get-SocDockerInspectValue -ContainerId $containerId `
            -Template '{{json .Config.Image}}' -Adapter $Adapter
        $ports = Get-SocDockerInspectValue -ContainerId $containerId `
            -Template '{{json .NetworkSettings.Ports}}' -Adapter $Adapter
        $mounts = Get-SocDockerInspectValue -ContainerId $containerId `
            -Template '{{json .Mounts}}' -Adapter $Adapter
        foreach ($volumeMount in @($mounts | Where-Object { [string]$_.Type -ceq 'volume' })) {
            $volumeName = [string]$volumeMount.Name
            if ([string]::IsNullOrWhiteSpace($volumeName)) {
                $volumeName = [string]$volumeMount.Source
            }
            if ([string]::IsNullOrWhiteSpace($volumeName)) {
                throw 'The active Wazuh runtime contained a volume mount without an identity name.'
            }
            if (-not $volumeMetadata.ContainsKey($volumeName)) {
                $volumeMetadata[$volumeName] = Get-SocDockerVolumeInspectValue `
                    -VolumeName $volumeName -Adapter $Adapter
            }
        }

        $labelService = [string]$labels.'com.docker.compose.service'
        $project = [string]$labels.'com.docker.compose.project'
        $workingDir = Resolve-SocAbsolutePathLabel -Path ([string]$labels.'com.docker.compose.project.working_dir')
        $configFilesRaw = [string]$labels.'com.docker.compose.project.config_files'
        if ($labelService -cne $service -or [string]::IsNullOrWhiteSpace($project) -or
            [string]::IsNullOrWhiteSpace($configFilesRaw)) {
            throw "The active $service container has incomplete Compose provenance labels."
        }
        $configFiles = @($configFilesRaw -split '[,;]' | ForEach-Object {
                Resolve-SocAbsolutePathLabel -Path $_.Trim()
            })
        if ($configFiles.Count -eq 0 -or @($configFiles | Sort-Object -Unique).Count -ne $configFiles.Count) {
            throw 'The active Compose config-file set is empty or duplicated.'
        }
        if ([string]$state -cne 'running') {
            throw "The active $service container is not running."
        }
        if ([string]$image -notmatch ':4\.14\.7$') {
            throw 'The active Wazuh containers are not all pinned to Wazuh 4.14.7.'
        }
        $records.Add([pscustomobject]@{
            Service          = $service
            ContainerId      = $containerId
            Image            = [string]$image
            Project          = $project
            WorkingDir       = $workingDir
            ConfigFilesRaw   = $configFilesRaw
            ConfigFiles      = @($configFiles)
            Ports            = $ports
            Mounts           = $mounts
            VolumeMetadata   = $volumeMetadata
        })
    }

    $projects = @($records | Select-Object -ExpandProperty Project -Unique)
    $workingDirs = @($records | Select-Object -ExpandProperty WorkingDir -Unique)
    $configFileSets = @($records | ForEach-Object { $_.ConfigFilesRaw } | Select-Object -Unique)
    if ($projects.Count -ne 1 -or $projects[0] -cne 'single-node' -or
        $workingDirs.Count -ne 1 -or
        ([IO.Path]::GetFullPath($workingDirs[0]).TrimEnd('\') -cne $WazuhRoot.TrimEnd('\')) -or
        $configFileSets.Count -ne 1) {
        throw 'The active Wazuh containers do not belong to one expected Compose runtime.'
    }

    return [pscustomobject]@{
        Services       = @($records)
        Project        = $projects[0]
        WorkingDir     = $workingDirs[0]
        ConfigFilesRaw = $configFileSets[0]
        ConfigFiles    = @($records[0].ConfigFiles)
        VolumeMetadata = $volumeMetadata
    }
}

function Get-SocPublishedPorts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Runtime)

    $ports = [Collections.Generic.List[object]]::new()
    foreach ($serviceRecord in $Runtime.Services) {
        foreach ($property in @($serviceRecord.Ports.PSObject.Properties)) {
            if ($null -eq $property.Value) { continue }
            $key = [string]$property.Name
            $parts = $key -split '/', 2
            if ($parts.Count -ne 2 -or $parts[0] -notmatch '^\d+$') {
                throw 'The active Docker runtime returned an invalid port key.'
            }
            foreach ($binding in @($property.Value)) {
                $hostIp = [string]$binding.HostIp
                $hostPort = [string]$binding.HostPort
                if ($hostIp -cne '127.0.0.1' -or $hostPort -notmatch '^\d+$') {
                    throw 'A published Wazuh port is not bound to loopback only.'
                }
                $ports.Add([pscustomobject]@{
                    Service  = [string]$serviceRecord.Service
                    Target   = [int]$parts[0]
                    Protocol = [string]$parts[1]
                    HostIp   = $hostIp
                    Published = [int]$hostPort
                })
            }
        }
    }

    foreach ($required in @(
        [pscustomobject]@{ Service='wazuh.indexer'; Target=9200; Protocol='tcp' },
        [pscustomobject]@{ Service='wazuh.manager'; Target=55000; Protocol='tcp' }
    )) {
        if (@($ports | Where-Object {
                    $_.Service -ceq $required.Service -and
                    [int]$_.Target -eq $required.Target -and
                    $_.Protocol -ceq $required.Protocol
                }).Count -ne 1) {
            throw "The required Wazuh authentication port is not uniquely published: $($required.Service)/$($required.Target)."
        }
    }

    $canonical = ConvertTo-SocCanonicalLines -Record @($ports)
    return [pscustomobject]@{
        Records = @($ports | Sort-Object Service,Target,Protocol,Published)
        Sha256  = ConvertTo-SocSha256Text -Text $canonical
    }
}

function Get-SocNamedVolumes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Runtime)

    $volumes = [Collections.Generic.List[object]]::new()
    foreach ($serviceRecord in $Runtime.Services) {
        foreach ($mount in @($serviceRecord.Mounts)) {
            if ([string]$mount.Type -cne 'volume') { continue }
            $source = [string]$mount.Name
            if ([string]::IsNullOrWhiteSpace($source)) { $source = [string]$mount.Source }
            $target = [string]$mount.Destination
            if ([string]::IsNullOrWhiteSpace($source) -or [string]::IsNullOrWhiteSpace($target)) {
                throw 'The active Wazuh runtime contained an unnamed Docker volume mount.'
            }
            $volumeIdentity = $Runtime.VolumeMetadata[$source]
            if ($null -eq $volumeIdentity -or
                $null -eq $volumeIdentity.PSObject.Properties['Name'] -or
                $null -eq $volumeIdentity.PSObject.Properties['Driver'] -or
                $null -eq $volumeIdentity.PSObject.Properties['CreatedAt'] -or
                $null -eq $volumeIdentity.PSObject.Properties['Mountpoint']) {
                throw 'The active named Docker volume identity metadata is incomplete.'
            }
            $identityName = [string]$volumeIdentity.Name
            $driver = [string]$volumeIdentity.Driver
            $createdAt = [string]$volumeIdentity.CreatedAt
            $mountpoint = [string]$volumeIdentity.Mountpoint
            $scope = if ($null -ne $volumeIdentity.PSObject.Properties['Scope']) {
                [string]$volumeIdentity.Scope
            } else { '' }
            if ($identityName -cne $source -or
                [string]::IsNullOrWhiteSpace($driver) -or
                [string]::IsNullOrWhiteSpace($createdAt) -or
                [string]::IsNullOrWhiteSpace($mountpoint)) {
                throw 'The active named Docker volume identity does not match its mount source.'
            }
            $readOnly = $false
            if ($null -ne $mount.PSObject.Properties['RW']) {
                $readOnly = -not [bool]$mount.RW
            } elseif ($null -ne $mount.PSObject.Properties['ReadOnly']) {
                $readOnly = [bool]$mount.ReadOnly
            }
            $volumes.Add([pscustomobject]@{
                Service       = [string]$serviceRecord.Service
                Source        = $source
                Target        = $target
                ReadOnly      = [bool]$readOnly
                Driver        = $driver
                Scope         = $scope
                IdentityName  = $identityName
                CreatedAt     = $createdAt
                MountpointSha256 = ConvertTo-SocSha256Text -Text $mountpoint
                Mode          = if ($null -ne $mount.PSObject.Properties['Mode']) { [string]$mount.Mode } else { '' }
                Propagation   = if ($null -ne $mount.PSObject.Properties['Propagation']) { [string]$mount.Propagation } else { '' }
                OptionsSha256 = ConvertTo-SocSha256Text -Text ($volumeIdentity.Options | ConvertTo-Json -Depth 10 -Compress)
                LabelsSha256  = ConvertTo-SocSha256Text -Text ($volumeIdentity.Labels | ConvertTo-Json -Depth 10 -Compress)
            })
        }
    }
    if ($volumes.Count -eq 0) {
        throw 'The active Wazuh runtime has no named Docker volumes.'
    }
    $canonical = ConvertTo-SocCanonicalLines -Record @($volumes)
    return [pscustomobject]@{
        Records = @($volumes | Sort-Object Service,Source,Target)
        Sha256  = ConvertTo-SocSha256Text -Text $canonical
    }
}

function Get-SocContainerSetHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Runtime)

    $records = @($Runtime.Services | ForEach-Object {
            [pscustomobject]@{
                Service     = [string]$_.Service
                ContainerId = [string]$_.ContainerId
                Image       = [string]$_.Image
            }
        })
    return ConvertTo-SocSha256Text -Text (ConvertTo-SocCanonicalLines -Record $records)
}

function Get-SocTargetPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PortResult,
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][int]$Target
    )

    $matches = @($PortResult.Records | Where-Object {
            $_.Service -ceq $Service -and [int]$_.Target -eq $Target -and $_.Protocol -ceq 'tcp'
        })
    if ($matches.Count -ne 1) {
        throw "The active Wazuh target port is not unique: $Service/$Target."
    }
    return [int]$matches[0].Published
}

function Get-SocHttpStatusCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Response)

    if ($null -eq $Response -or $null -eq $Response.PSObject.Properties['StatusCode']) {
        throw 'The HTTP authentication adapter returned no status code.'
    }
    try { return [int]$Response.StatusCode } catch { throw 'The HTTP authentication adapter returned an invalid status code.' }
}

function Invoke-SocAuthProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProbeName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][ValidateSet('Get','Post')][string]$Method,
        [Parameter(Mandatory)][ValidateSet('accepted','rejected')][string]$Expected,
        [scriptblock]$Adapter = $null
    )

    $status = 0
    if ($null -ne $Adapter) {
        try {
            $response = @(& $Adapter `
                -ProbeName $ProbeName `
                -UserName $UserName `
                -Password $Password `
                -Port $Port `
                -Method $Method)
        } catch {
            throw "The read-only HTTP adapter failed for $ProbeName."
        }
        if ($response.Count -ne 1) { throw "The read-only HTTP adapter returned an invalid result for $ProbeName." }
        $status = Get-SocHttpStatusCode -Response $response[0]
    } else {
        $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $credential = [Management.Automation.PSCredential]::new($UserName, $secure)
        $path = if ($ProbeName -match 'admin') {
            '/'
        } elseif ($ProbeName -match 'kibanaserver') {
            '/_plugins/_security/authinfo'
        } elseif ($ProbeName -match 'wazuh_wui') {
            '/security/user/authenticate?raw=true'
        } else {
            throw "The read-only Wazuh authentication probe name is unknown: $ProbeName."
        }
        $uri = [uri]::new("https://127.0.0.1:$Port$path")
        try {
            $request = @{
                Uri                = $uri
                Method             = $Method
                Authentication     = 'Basic'
                Credential         = $credential
                SkipCertificateCheck = $true
                MaximumRedirection = 0
                TimeoutSec         = 15
                ErrorAction        = 'Stop'
            }
            Invoke-WebRequest @request | Out-Null
            $status = 200
        } catch {
            $response = $_.Exception.Response
            if ($null -ne $response -and $null -ne $response.StatusCode) {
                try { $status = [int]$response.StatusCode } catch { $status = 0 }
            }
            if ($status -notin @(401,403)) {
                throw "The read-only Wazuh authentication probe failed for $ProbeName."
            }
        } finally {
            $credential = $null
            $secure = $null
        }
    }

    $actual = if ($status -in 200..299) { 'accepted' } elseif ($status -in @(401,403)) { 'rejected' } else { 'unknown' }
    if ($actual -cne $Expected) {
        throw "The Wazuh authentication probe did not produce the expected result for $ProbeName."
    }
    return [pscustomobject]@{
        ProbeName = $ProbeName
        Method    = $Method
        Port      = $Port
        Result    = $actual
        StatusClass = if ($actual -ceq 'accepted') { '2xx' } else { '401_or_403' }
    }
}

function Assert-SocEvidenceHasNoSecrets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string[]]$SecretValue
    )

    foreach ($value in $SecretValue) {
        if ([string]::IsNullOrEmpty($value)) { continue }
        if ($Text.Contains($value, [StringComparison]::Ordinal)) {
            throw 'The proposed Wazuh hardening Evidence contains a credential value.'
        }
    }
    if ($Text -match '(?i)https?://') {
        throw 'The proposed Wazuh hardening Evidence contains a URI.'
    }
}

function Write-SocEvidenceAtomically {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][string]$Serialized
    )

    $root = [IO.Path]::GetFullPath($EvidenceRoot)
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $target = Join-Path $root "$SessionId.json"
    $temporary = Join-Path $root (".$SessionId.{0}.tmp" -f [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temporary, "$Serialized`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $target)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
    return $target
}

function Invoke-SocWazuhHardeningRuntimeEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WazuhRoot,
        [string]$SecretRoot = '',
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [scriptblock]$CommandAdapter = $null,
        [scriptblock]$HttpAdapter = $null
    )

    $resolvedWazuhRoot = [IO.Path]::GetFullPath($WazuhRoot).TrimEnd('\')
    $resolvedSecretRoot = Get-SocSecretRoot -Root $SecretRoot
    $runtimeSessionId = 'wazuh-hardening-' + [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
    $secretNames = @(
        'wazuh_indexer_admin_password',
        'wazuh_indexer_kibanaserver_password',
        'wazuh_api_wui_password'
    )
    $passwords = [ordered]@{}
    $dpapiRecordHashes = [ordered]@{}
    $evidencePath = $null
    $serialized = $null

    try {
        foreach ($name in $secretNames) {
            $recordPath = Join-Path $resolvedSecretRoot "$name.dpapi.json"
            if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
                throw "The canonical DPAPI credential record is unavailable: $name"
            }
            $dpapiRecordHashes[$name] = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $passwords[$name] = Unprotect-SocSecret -Name $name -SecretRoot $resolvedSecretRoot
            if ([string]::IsNullOrEmpty([string]$passwords[$name])) {
                throw "The canonical DPAPI credential record is empty: $name"
            }
        }

        $defaults = [ordered]@{
            admin = 'Secret' + 'Password'
            kibana = 'kibana' + 'server'
            api = 'MyS3cr37P450r.' + '*-'
        }
        if ($passwords.Values | Where-Object { $_ -in $defaults.Values }) {
            throw 'A canonical Wazuh credential equals an official default credential.'
        }

        $runtimeBefore = Get-SocRuntimeDescriptor -WazuhRoot $resolvedWazuhRoot -Adapter $CommandAdapter
        $portsBefore = Get-SocPublishedPorts -Runtime $runtimeBefore
        $volumesBefore = Get-SocNamedVolumes -Runtime $runtimeBefore
        $containerHashBefore = Get-SocContainerSetHash -Runtime $runtimeBefore

        $authResults = [Collections.Generic.List[object]]::new()
        $indexerPort = Get-SocTargetPort -PortResult $portsBefore -Service 'wazuh.indexer' -Target 9200
        $apiPort = Get-SocTargetPort -PortResult $portsBefore -Service 'wazuh.manager' -Target 55000
        foreach ($probe in @(
            [pscustomobject]@{ Name='new_admin'; User='admin'; PasswordKey='wazuh_indexer_admin_password'; Port=$indexerPort; Method='Get'; Expected='accepted' },
            [pscustomobject]@{ Name='default_admin'; User='admin'; PasswordKey='admin_default'; Port=$indexerPort; Method='Get'; Expected='rejected' },
            [pscustomobject]@{ Name='new_kibanaserver'; User='kibanaserver'; PasswordKey='wazuh_indexer_kibanaserver_password'; Port=$indexerPort; Method='Get'; Expected='accepted' },
            [pscustomobject]@{ Name='default_kibanaserver'; User='kibanaserver'; PasswordKey='kibana_default'; Port=$indexerPort; Method='Get'; Expected='rejected' },
            [pscustomobject]@{ Name='new_wazuh_wui'; User='wazuh-wui'; PasswordKey='wazuh_api_wui_password'; Port=$apiPort; Method='Post'; Expected='accepted' },
            [pscustomobject]@{ Name='default_wazuh_wui'; User='wazuh-wui'; PasswordKey='api_default'; Port=$apiPort; Method='Post'; Expected='rejected' }
        )) {
            $password = if ($probe.PasswordKey -eq 'admin_default') { $defaults.admin }
                elseif ($probe.PasswordKey -eq 'kibana_default') { $defaults.kibana }
                elseif ($probe.PasswordKey -eq 'api_default') { $defaults.api }
                else { [string]$passwords[$probe.PasswordKey] }
            $authResults.Add((Invoke-SocAuthProbe `
                    -ProbeName $probe.Name `
                    -UserName $probe.User `
                    -Password $password `
                    -Port ([int]$probe.Port) `
                    -Method $probe.Method `
                    -Expected $probe.Expected `
                    -Adapter $HttpAdapter))
            $password = $null
        }

        $runtimeAfter = Get-SocRuntimeDescriptor -WazuhRoot $resolvedWazuhRoot -Adapter $CommandAdapter
        $portsAfter = Get-SocPublishedPorts -Runtime $runtimeAfter
        $volumesAfter = Get-SocNamedVolumes -Runtime $runtimeAfter
        $containerHashAfter = Get-SocContainerSetHash -Runtime $runtimeAfter
        if ($volumesBefore.Sha256 -cne $volumesAfter.Sha256 -or
            $containerHashBefore -cne $containerHashAfter -or
            $portsBefore.Sha256 -cne $portsAfter.Sha256) {
            throw 'The Wazuh runtime changed during verify-only observation.'
        }

        $authCanonical = ConvertTo-SocCanonicalLines -Record @($authResults)
        $composeProvenance = [ordered]@{
            project                  = [string]$runtimeBefore.Project
            working_dir_sha256       = ConvertTo-SocSha256Text -Text ([string]$runtimeBefore.WorkingDir)
            config_files_sha256      = ConvertTo-SocSha256Text -Text ((@($runtimeBefore.ConfigFiles) -join "`n"))
            config_file_count        = @($runtimeBefore.ConfigFiles).Count
            source                   = 'docker inspect compose labels (read-only)'
        }
        $evidence = [ordered]@{
            schema_version                   = 1
            producer_mode                    = 'verify_existing'
            checked_at                       = [datetimeoffset]::UtcNow.ToString('o')
            runtime_session_id               = $runtimeSessionId
            wazuh_version                    = '4.14.7'
            wazuh_authentication_verified    = $true
            wazuh_credential_rotation_observed = $false
            local_only_ports                 = $true
            new_admin_authentication         = 'accepted'
            default_admin_authentication     = 'rejected'
            new_kibanaserver_authentication  = 'accepted'
            default_kibana_authentication    = 'rejected'
            new_wazuh_wui_authentication     = 'accepted'
            default_wazuh_wui_authentication = 'rejected'
            named_volumes_removed            = $false
            named_volumes_identical_before_after = $true
            secrets_printed                  = $false
            active_state_path                = $null
            active_state_provenance          = 'not_written_verify_only'
            compose_provenance               = $composeProvenance
            runtime_container_set_sha256     = $containerHashBefore
            published_ports_sha256            = $portsBefore.Sha256
            named_volumes_before_sha256       = $volumesBefore.Sha256
            named_volumes_after_sha256        = $volumesAfter.Sha256
            named_volume_fingerprint          = [ordered]@{
                algorithm = 'sha256'
                equality = 'exact named-volume set and identity metadata before/after'
                source = 'docker inspect Mounts + docker volume inspect (read-only)'
                fields = @('Service','Source','Target','ReadOnly','IdentityName','Driver','Scope','CreatedAt','MountpointSha256','Mode','Propagation','OptionsSha256','LabelsSha256')
                before_sha256 = $volumesBefore.Sha256
                after_sha256 = $volumesAfter.Sha256
            }
            authentication_results_sha256    = ConvertTo-SocSha256Text -Text $authCanonical
            dpapi_record_sha256               = $dpapiRecordHashes
            credential_provenance             = 'canonical DPAPI CurrentUser records; values decrypted in memory only'
            mutation_summary                  = [ordered]@{
                docker_mutations = 0
                credential_rotation_observed = $false
                wazuh_mutations = 0
                compose_mutations = 0
                aws_mutations = 0
                shuffle_mutations = 0
                bridge_mutations = 0
            }
        }
        $serialized = $evidence | ConvertTo-Json -Depth 10
        $secretValuesForEvidence = @($passwords.Values) + @($defaults.admin,$defaults.api)
        Assert-SocEvidenceHasNoSecrets -Text $serialized -SecretValue $secretValuesForEvidence
        if ($serialized -match '(?i)"[^"\r\n]+"\s*:\s*"kibanaserver"') {
            throw 'The proposed Wazuh hardening Evidence contains the default kibanaserver password as a JSON value.'
        }
        $evidenceBase = [IO.Path]::GetFullPath($EvidenceRoot)
        $hardeningEvidenceRoot = if ((Split-Path -Leaf $evidenceBase) -ieq 'soc-lab-hardening') {
            $evidenceBase
        } else {
            Join-Path $evidenceBase 'soc-lab-hardening'
        }
        $evidencePath = Write-SocEvidenceAtomically `
            -EvidenceRoot $hardeningEvidenceRoot `
            -SessionId $runtimeSessionId `
            -Serialized $serialized
        $written = Get-Content -LiteralPath $evidencePath -Raw
        Assert-SocEvidenceHasNoSecrets -Text $written -SecretValue $secretValuesForEvidence
        if ($written -match '(?i)"[^"\r\n]+"\s*:\s*"kibanaserver"') {
            throw 'The Wazuh hardening Evidence contains the default kibanaserver password as a JSON value.'
        }
        $evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
        return [pscustomobject]@{
            schema_version = 1
            producer_mode = 'verify_existing'
            runtime_session_id = $runtimeSessionId
            evidence_path = $evidencePath
            evidence_sha256 = $evidenceHash
        }
    } finally {
        foreach ($key in @($passwords.Keys)) { $passwords[$key] = $null }
        $passwords = $null
    }
}

if (-not $NoRun.IsPresent) {
    if (-not $EvidenceRoot) {
        $EvidenceRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'aws-topology-evidence'
    }
    $result = Invoke-SocWazuhHardeningRuntimeEvidence `
        -WazuhRoot $WazuhRoot `
        -SecretRoot $SecretRoot `
        -EvidenceRoot ([IO.Path]::GetFullPath($EvidenceRoot)) `
        -CommandAdapter $CommandAdapter `
        -HttpAdapter $HttpAdapter
    $result | ConvertTo-Json -Depth 5 -Compress
}
