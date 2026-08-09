Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Update-ProcessPath {
    $pathEntries = New-Object System.Collections.Generic.List[string]
    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable(
            'Path',
            [EnvironmentVariableTarget]::$scope
        )
        foreach ($entry in @($value -split ';')) {
            $trimmed = $entry.Trim()
            if ($trimmed -and
                -not ($pathEntries | Where-Object { $_ -ieq $trimmed })) {
                $pathEntries.Add($trimmed)
            }
        }
    }
    $env:Path = $pathEntries -join ';'
}

function Assert-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Update-ProcessPath
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Required command is unavailable after refreshing User and Machine PATH: $Name"
    }
    return $command
}

function Set-SshConfigHost {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$HostAlias,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$IdentityFile
    )

    foreach ($value in @($HostAlias, $HostName, $User, $IdentityFile)) {
        if (-not $value -or $value -match "[`r`n]") {
            throw 'SSH config values must be non-empty single-line strings.'
        }
    }
    if ($HostAlias -match '[\s#*?!]') {
        throw "SSH Host alias must be a single literal name: $HostAlias"
    }

    $directory = Split-Path -Parent $ConfigPath
    if (-not $directory) {
        throw "SSH config path must include a parent directory: $ConfigPath"
    }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $content = if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        [System.IO.File]::ReadAllText($ConfigPath)
    } else {
        ''
    }
    $newLine = if ($content.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = @()
    if ($content.Length -gt 0) {
        $lines = @([regex]::Split($content, '\r?\n'))
    }

    $matchingHeaders = New-Object System.Collections.Generic.List[int]
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $header = [regex]::Match($lines[$index], '(?i)^\s*Host\s+(.+?)\s*$')
        if (-not $header.Success) {
            continue
        }
        $hostSpec = ($header.Groups[1].Value -split '\s+#', 2)[0].Trim()
        $tokens = @($hostSpec -split '\s+' | Where-Object { $_ })
        if ($tokens.Count -eq 1 -and $tokens[0] -ieq $HostAlias) {
            $matchingHeaders.Add($index)
        }
    }
    if ($matchingHeaders.Count -gt 1) {
        throw "SSH config contains duplicate exact Host blocks: $HostAlias"
    }

    $block = @(
        "Host $HostAlias"
        "    HostName $HostName"
        "    User $User"
        "    IdentityFile $($IdentityFile.Replace('\', '/'))"
    )
    $updatedLines = New-Object System.Collections.Generic.List[string]

    if ($matchingHeaders.Count -eq 1) {
        $start = $matchingHeaders[0]
        $end = $lines.Count
        for ($index = $start + 1; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '(?i)^\s*(Host|Match)\s+') {
                $end = $index
                break
            }
        }
        for ($index = 0; $index -lt $start; $index++) {
            $updatedLines.Add($lines[$index])
        }
        foreach ($line in $block) {
            $updatedLines.Add($line)
        }
        for ($index = $end; $index -lt $lines.Count; $index++) {
            $updatedLines.Add($lines[$index])
        }
    } else {
        foreach ($line in $lines) {
            $updatedLines.Add($line)
        }
        if ($updatedLines.Count -gt 0 -and $updatedLines[$updatedLines.Count - 1] -ne '') {
            $updatedLines.Add('')
        }
        foreach ($line in $block) {
            $updatedLines.Add($line)
        }
    }

    $updated = $updatedLines -join $newLine
    if (-not $updated.EndsWith($newLine)) {
        $updated += $newLine
    }
    $tempPath = Join-Path $directory (
        ".$([System.IO.Path]::GetFileName($ConfigPath)).$([guid]::NewGuid().ToString('N')).tmp"
    )
    try {
        [System.IO.File]::WriteAllText(
            $tempPath,
            $updated,
            (New-Object System.Text.UTF8Encoding($false))
        )
        Move-Item -LiteralPath $tempPath -Destination $ConfigPath -Force
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @(),
        [Parameter()][string]$FailureMessage = "$FilePath failed"
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        $detail = ($output | Out-String).Trim()
        throw "$FailureMessage`n$detail"
    }

    return ($output | Out-String).Trim()
}

function Test-AwsCliNonRetryableIdentityFailure {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    foreach ($pattern in @(
        '\bAccessDenied(?:Exception)?\b',
        '\bUnauthorizedOperation\b',
        '\bExpiredToken(?:Exception)?\b',
        '\bInvalidClientTokenId\b',
        '\bUnrecognizedClientException\b',
        '\bInvalidAccessKeyId\b',
        '\bSignatureDoesNotMatch\b',
        '\bAuthFailure\b',
        '\bNoCredentialsError\b',
        '\bProfileNotFound\b',
        'Unable to locate credentials',
        'Partial credentials found',
        'config profile .+ could not be found',
        'SSO session .+ expired',
        'Error when retrieving token from sso'
    )) {
        if ($Message -match "(?i)$pattern") {
            return $true
        }
    }

    return $false
}

function Invoke-NativePassthrough {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @(),
        [Parameter()][string]$FailureMessage = "$FilePath failed"
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $FilePath @ArgumentList
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw $FailureMessage
    }
}

function Test-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @()
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $FilePath @ArgumentList 1>$null 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return $exitCode -eq 0
}

function Get-AwsIdentity {
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$Region
    )

    $json = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        'sts', 'get-caller-identity',
        '--profile', $Profile,
        '--region', $Region,
        '--output', 'json'
    ) -FailureMessage 'AWS credentials are unavailable or expired.'

    return $json | ConvertFrom-Json
}

function Assert-AwsIdentity {
    param(
        [Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$ExpectedAccountId
    )

    if ([string]$Identity.Account -cne $ExpectedAccountId) {
        throw "Wrong AWS account. Expected $ExpectedAccountId, received $($Identity.Account)."
    }
}

function Initialize-CodexPowerApi {
    if ('Codex.NativePower' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Codex {
    [StructLayout(LayoutKind.Sequential)]
    public struct SystemPowerStatus {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    public static class NativePower {
        [DllImport("kernel32.dll")]
        public static extern bool GetSystemPowerStatus(out SystemPowerStatus status);

        [DllImport("kernel32.dll")]
        public static extern uint SetThreadExecutionState(uint executionState);
    }
}
'@
}

function Start-AwakeMode {
    Initialize-CodexPowerApi

    $status = New-Object Codex.SystemPowerStatus
    if (-not [Codex.NativePower]::GetSystemPowerStatus([ref]$status)) {
        throw 'Windows power status could not be read.'
    }

    if ($status.ACLineStatus -eq 0) {
        throw 'External power is offline. Connect the laptop charger before a long Terraform run.'
    }
    if ($status.ACLineStatus -eq 255) {
        Write-Warning 'Windows could not determine whether external power is online.'
    }

    # ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
    $result = [Codex.NativePower]::SetThreadExecutionState([uint32]2147483713)
    if ($result -eq 0) {
        throw 'Windows awake mode could not be enabled for this process.'
    }

    $battery = if ($status.BatteryLifePercent -eq 255) {
        'unknown'
    } else {
        "$($status.BatteryLifePercent)%"
    }
    Write-Host "Power preflight: AC=$($status.ACLineStatus), battery=$battery"

    try {
        $lid = & powercfg.exe /query SCHEME_CURRENT SUB_BUTTONS LIDACTION 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'The lid-close policy could not be queried. It was not changed.'
        } else {
            $hexValues = [regex]::Matches(($lid | Out-String), '0x[0-9a-fA-F]{8}')
            if ($hexValues.Count -ge 2) {
                $acLidAction = $hexValues[$hexValues.Count - 2].Value
                if ($acLidAction -ne '0x00000000') {
                    Write-Warning "The AC lid-close action may suspend the laptop (index $acLidAction)."
                }
            }
        }
    } catch {
        Write-Warning 'The lid-close policy could not be evaluated. It was not changed.'
    }
}

function Stop-AwakeMode {
    Initialize-CodexPowerApi
    # ES_CONTINUOUS clears the requirement created by this process.
    [void][Codex.NativePower]::SetThreadExecutionState([uint32]2147483648)
}

function Get-TerraformStateAddresses {
    param([Parameter(Mandatory)][string]$Root)

    if (-not (Test-Path -LiteralPath (Join-Path $Root 'terraform.tfstate') -PathType Leaf)) {
        return @()
    }

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & terraform "-chdir=$Root" state list 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "Terraform state could not be read: $Root"
    }
    return @($output | Where-Object { $_ -and $_.Trim() -ne '' })
}

function Get-OptionalAwsJson {
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $json = & aws @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        $detail = ($json | Out-String).Trim()
        if ($detail -match '(?i)(NotFound|not found|does not exist|NoSuch)') {
            return $null
        }
        throw "AWS inventory query failed closed:`n$detail"
    }
    if (-not $json) {
        return $null
    }
    return (($json | Out-String) | ConvertFrom-Json)
}

function Test-TaggedProjectRuntimeResourceActive {
    param(
        [Parameter(Mandatory)][string]$Arn,
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$Region
    )

    $parts = $Arn -split ':', 6
    if ($parts.Count -ne 6) {
        return $null
    }
    $service = $parts[2]
    $resource = $parts[5]
    $common = @('--profile', $Profile, '--region', $Region, '--output', 'json')

    switch ($service) {
        'ec2' {
            $typeAndId = $resource -split '/', 2
            if ($typeAndId.Count -ne 2) { return $null }
            $id = $typeAndId[1]
            switch ($typeAndId[0]) {
                'instance' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-instances', '--instance-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    $instance = @(
                        $json.Reservations | ForEach-Object { $_.Instances }
                    ) | Select-Object -First 1
                    return $instance -and $instance.State.Name -ne 'terminated'
                }
                'natgateway' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-nat-gateways', '--nat-gateway-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    $gateway = $json.NatGateways | Select-Object -First 1
                    return $gateway -and $gateway.State -ne 'deleted'
                }
                'elastic-ip' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-addresses', '--allocation-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.Addresses).Count -gt 0
                }
                'volume' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-volumes', '--volume-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.Volumes).Count -gt 0
                }
                'snapshot' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-snapshots', '--snapshot-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.Snapshots).Count -gt 0
                }
                'vpc' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-vpcs', '--vpc-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.Vpcs).Count -gt 0
                }
                'subnet' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-subnets', '--subnet-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.Subnets).Count -gt 0
                }
                'network-interface' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-network-interfaces', '--network-interface-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.NetworkInterfaces).Count -gt 0
                }
                'security-group' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @('ec2', 'describe-security-groups', '--group-ids', $id) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.SecurityGroups).Count -gt 0
                }
                'security-group-rule' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @(
                            'ec2', 'describe-security-group-rules',
                            '--security-group-rule-ids', $id
                        ) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.SecurityGroupRules).Count -gt 0
                }
                'vpc-flow-log' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @(
                            'ec2', 'describe-flow-logs',
                            '--flow-log-ids', $id
                        ) + $common
                    )
                    if (-not $json) { return $false }
                    return @($json.FlowLogs).Count -gt 0
                }
                'fleet' {
                    $json = Get-OptionalAwsJson -ArgumentList (
                        @(
                            'ec2', 'describe-fleets',
                            '--fleet-ids', $id
                        ) + $common
                    )

                    if (-not $json) {
                        return $false
                    }

                    $fleet = @($json.Fleets) | Select-Object -First 1
                    if (-not $fleet) {
                        return $false
                    }

                    $fleetState = [string]$fleet.FleetState
                    if ($fleetState -ceq 'deleted') {
                        return $false
                    }

                    $fleetType = [string]$fleet.Type
                    $inspectReferencedInstances = (
                        $fleetType -ceq 'instant' -or
                        $fleetState -in @(
                            'deleted_terminating',
                            'deleted_running'
                        )
                    )
                    if (-not $inspectReferencedInstances) {
                        return $true
                    }

                    # DescribeFleetInstances does not support instant Fleets.
                    # DescribeFleets already returns Instances[].InstanceIds, so
                    # verify each referenced EC2 instance directly. This also
                    # handles Fleet-state propagation lag after EC2 termination.
                    $instanceIds = @(
                        @(
                            foreach ($fleetInstance in @($fleet.Instances)) {
                                if ($null -eq $fleetInstance) {
                                    continue
                                }
                                if ($fleetInstance.PSObject.Properties.Name -notcontains 'InstanceIds') {
                                    continue
                                }
                                foreach ($rawInstanceId in @($fleetInstance.InstanceIds)) {
                                    $candidate = ([string]$rawInstanceId).Trim()
                                    if ($candidate) {
                                        $candidate
                                    }
                                }
                            }
                        ) | Sort-Object -Unique
                    )
                    if ($instanceIds.Count -eq 0) {
                        if ($fleetType -ceq 'instant') {
                            $fulfilledCapacity = 0.0
                            if ($fleet.PSObject.Properties.Name -contains 'FulfilledCapacity') {
                                $fulfilledCapacity = [double]$fleet.FulfilledCapacity
                            }
                            # An active instant Fleet that reports fulfilled
                            # capacity but omits its instance IDs is unresolved.
                            # Keep failing closed instead of hiding a live EC2.
                            return $fulfilledCapacity -gt 0
                        }
                        return $false
                    }

                    foreach ($instanceId in $instanceIds) {
                        if ($instanceId -notmatch '^i-[0-9a-f]{8,17}$') {
                            throw "AWS inventory query failed closed: EC2 Fleet returned an unsafe instance ID: $instanceId"
                        }
                        $instanceJson = Get-OptionalAwsJson -ArgumentList (
                            @(
                                'ec2', 'describe-instances',
                                '--instance-ids', $instanceId
                            ) + $common
                        )
                        if (-not $instanceJson) {
                            continue
                        }
                        $instance = @(
                            $instanceJson.Reservations |
                                ForEach-Object { $_.Instances }
                        ) | Select-Object -First 1
                        if ($instance -and
                            [string]$instance.State.Name -cne 'terminated') {
                            return $true
                        }
                    }

                    return $false
                }
                default { return $null }
            }
        }
        'eks' {
            if ($resource -like 'cluster/*') {
                $name = ($resource -split '/', 2)[1]
                $json = Get-OptionalAwsJson -ArgumentList (
                    @('eks', 'describe-cluster', '--name', $name) + $common
                )
                return $null -ne $json
            }
            if ($resource -like 'podidentityassociation/*') {
                $segments = $resource -split '/'
                if ($segments.Count -ne 3) { return $null }
                $json = Get-OptionalAwsJson -ArgumentList (
                    @(
                        'eks', 'describe-pod-identity-association',
                        '--cluster-name', $segments[1],
                        '--association-id', $segments[2]
                    ) + $common
                )
                return $null -ne $json
            }
            return $null
        }
        'rds' {
            if ($resource -notlike 'db:*') { return $null }
            $identifier = ($resource -split ':', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList (
                @('rds', 'describe-db-instances', '--db-instance-identifier', $identifier) + $common
            )
            return $null -ne $json
        }
        'elasticloadbalancing' {
            if ($resource -like 'loadbalancer/*') {
                $json = Get-OptionalAwsJson -ArgumentList (
                    @('elbv2', 'describe-load-balancers', '--load-balancer-arns', $Arn) + $common
                )
                return $null -ne $json
            }
            if ($resource -like 'targetgroup/*') {
                $json = Get-OptionalAwsJson -ArgumentList (
                    @('elbv2', 'describe-target-groups', '--target-group-arns', $Arn) + $common
                )
                return $null -ne $json
            }
            return $null
        }
        'elasticfilesystem' {
            if ($resource -notlike 'file-system/*') { return $null }
            $id = ($resource -split '/', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList (
                @('efs', 'describe-file-systems', '--file-system-id', $id) + $common
            )
            return $null -ne $json
        }
        'elasticache' {
            if ($resource -notlike 'replicationgroup:*') { return $null }
            $id = ($resource -split ':', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList (
                @('elasticache', 'describe-replication-groups', '--replication-group-id', $id) + $common
            )
            return $null -ne $json
        }
        'cloudfront' {
            if ($resource -notlike 'distribution/*') { return $null }
            $id = ($resource -split '/', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList @(
                'cloudfront', 'get-distribution', '--id', $id,
                '--profile', $Profile, '--output', 'json'
            )
            return $null -ne $json
        }
        's3' {
            $json = Get-OptionalAwsJson -ArgumentList @(
                's3api', 'get-bucket-location',
                '--bucket', $resource,
                '--profile', $Profile,
                '--output', 'json'
            )
            return $null -ne $json
        }
        'kms' {
            if ($resource -notlike 'key/*') { return $null }
            $id = ($resource -split '/', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList (
                @('kms', 'describe-key', '--key-id', $id) + $common
            )
            if (-not $json) { return $false }
            return $json.KeyMetadata.KeyState -notin @(
                'PendingDeletion',
                'PendingReplicaDeletion'
            )
        }
        'logs' {
            if ($resource -notlike 'log-group:*') { return $null }
            $name = ($resource -replace '^log-group:', '') -replace ':\*$', ''
            $json = Get-OptionalAwsJson -ArgumentList (
                @('logs', 'describe-log-groups', '--log-group-name-prefix', $name) + $common
            )
            if (-not $json) { return $false }
            return @($json.logGroups | Where-Object { $_.logGroupName -ceq $name }).Count -gt 0
        }
        'route53' {
            if ($resource -notlike 'hostedzone/*') { return $null }
            $id = ($resource -split '/', 2)[1]
            $json = Get-OptionalAwsJson -ArgumentList @(
                'route53', 'get-hosted-zone', '--id', $id,
                '--profile', $Profile, '--output', 'json'
            )
            return $null -ne $json
        }
        'cloudtrail' {
            if ($resource -notlike 'trail/*') { return $null }
            $json = Get-OptionalAwsJson -ArgumentList (
                @('cloudtrail', 'get-trail-status', '--name', $Arn) + $common
            )
            return $null -ne $json
        }
        default { return $null }
    }
}

function Get-TaggedProjectRuntimeResources {
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string[]]$Regions
    )

    $resources = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($scanRegion in @($Regions | Where-Object { $_ } | Select-Object -Unique)) {
        $json = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            'resourcegroupstaggingapi', 'get-resources',
            '--profile', $Profile,
            '--region', $scanRegion,
            '--tag-filters', "Key=Project,Values=$ProjectName",
            '--output', 'json'
        ) -FailureMessage "Tagged AWS resources could not be inventoried in $scanRegion."
        $response = $json | ConvertFrom-Json

        foreach ($mapping in @($response.ResourceTagMappingList)) {
            $tags = @{}
            foreach ($tag in @($mapping.Tags)) {
                $tags[[string]$tag.Key] = [string]$tag.Value
            }
            if ($tags.ContainsKey('Lifecycle') -and
                $tags['Lifecycle'] -ceq 'persistent-foundation') {
                continue
            }

            $arn = [string]$mapping.ResourceARN
            if (-not $arn -or $seen.ContainsKey($arn)) {
                continue
            }
            $active = Test-TaggedProjectRuntimeResourceActive `
                -Arn $arn `
                -Profile $Profile `
                -Region $scanRegion
            if ($null -ne $active -and -not $active) {
                continue
            }
            $seen[$arn] = $true
            $resources.Add([pscustomobject]@{
                Arn       = $arn
                Region    = $scanRegion
                Name      = if ($tags.ContainsKey('Name')) { $tags['Name'] } else { '' }
                ManagedBy = if ($tags.ContainsKey('ManagedBy')) { $tags['ManagedBy'] } else { '' }
                Verification = if ($null -eq $active) { 'unverified-type' } else { 'verified-active' }
            })
        }
    }

    return @($resources | Sort-Object Arn)
}

function Format-TaggedProjectRuntimeResources {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Resources
    )

    return @($Resources | ForEach-Object {
        $name = if ($_.Name) { "`t$($_.Name)" } else { '' }
        $verification = if (
            $_.PSObject.Properties.Name -contains 'Verification'
        ) {
            "`t$($_.Verification)"
        } else {
            ''
        }
        "$($_.Region)`t$($_.Arn)$name$verification"
    })
}

function Get-FoundationContext {
    param(
        [Parameter(Mandatory)][string]$FoundationRoot,
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$DrRegion,
        [Parameter(Mandatory)][string]$ExpectedAccountId
    )

    $state = @(Get-TerraformStateAddresses -Root $FoundationRoot)
    if ($state.Count -eq 0) {
        throw 'Persistent Foundation is not applied. Run the approved one-time Foundation setup first.'
    }

    $json = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$FoundationRoot", 'output', '-json'
    ) -FailureMessage 'Foundation outputs could not be read.'
    $outputs = $json | ConvertFrom-Json

    $requiredOutputs = @(
        'foundation_contract_version',
        'domain_name',
        'route53_zone_id',
        'cloudfront_acm_certificate_arn'
    )
    foreach ($requiredOutput in $requiredOutputs) {
        if ($outputs.PSObject.Properties.Name -notcontains $requiredOutput) {
            throw "Foundation contract v2 output is missing: $requiredOutput. Apply the reviewed Foundation plan before Daily Up."
        }
    }
    if ([int]$outputs.foundation_contract_version.value -lt 2) {
        throw 'Foundation contract version is older than v2. Apply the reviewed Foundation plan before Daily Up.'
    }

    if ([string]$outputs.aws_account_id.value -cne $ExpectedAccountId) {
        throw 'Foundation state belongs to a different AWS account.'
    }
    if ([string]$outputs.aws_region.value -cne $Region) {
        throw 'Foundation state belongs to a different AWS region.'
    }

    $domainName = [string]$outputs.domain_name.value
    $route53ZoneId = [string]$outputs.route53_zone_id.value
    $cloudFrontCertificateArn = [string]$outputs.cloudfront_acm_certificate_arn.value
    if ($domainName -and (-not $route53ZoneId -or -not $cloudFrontCertificateArn)) {
        throw 'Foundation domain outputs are incomplete. Route 53 zone ID and CloudFront ACM certificate ARN are both required.'
    }
    if ($domainName) {
        $hostedZoneJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            'route53', 'get-hosted-zone',
            '--profile', $Profile,
            '--id', $route53ZoneId,
            '--output', 'json'
        ) -FailureMessage 'Persistent Route 53 hosted zone is missing.'
        $hostedZone = $hostedZoneJson | ConvertFrom-Json
        if ([string]$hostedZone.HostedZone.Name.TrimEnd('.') -cne $domainName.TrimEnd('.')) {
            throw 'Foundation Route 53 hosted zone does not match the declared domain.'
        }

        $certificateJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            'acm', 'describe-certificate',
            '--profile', $Profile,
            '--region', 'us-east-1',
            '--certificate-arn', $cloudFrontCertificateArn,
            '--output', 'json'
        ) -FailureMessage 'Persistent CloudFront ACM certificate is missing.'
        $certificate = $certificateJson | ConvertFrom-Json
        if ([string]$certificate.Certificate.Status -cne 'ISSUED' -or
            [string]$certificate.Certificate.DomainName -cne $domainName) {
            throw 'Foundation CloudFront ACM certificate is not issued for the declared domain.'
        }
    }

    $repositoryName = [string]$outputs.application_ecr_repository_name.value
    $roleArn = [string]$outputs.github_actions_role_arn.value
    $providerArn = [string]$outputs.github_oidc_provider_arn.value
    $roleName = ($roleArn -split '/')[-1]
    $securityLogBucket = if (
        $outputs.PSObject.Properties.Name -contains 'security_log_bucket_name'
    ) {
        [string]$outputs.security_log_bucket_name.value
    } else {
        ''
    }
    $securityTrailName = if (
        $outputs.PSObject.Properties.Name -contains 'security_cloudtrail_name'
    ) {
        [string]$outputs.security_cloudtrail_name.value
    } else {
        ''
    }
    $securityLogGroup = if (
        $outputs.PSObject.Properties.Name -contains 'security_cloudwatch_log_group_name'
    ) {
        [string]$outputs.security_cloudwatch_log_group_name.value
    } else {
        ''
    }
    $securityLogGroups = @{}
    if ($outputs.PSObject.Properties.Name -contains 'security_log_group_names') {
        foreach ($property in $outputs.security_log_group_names.value.PSObject.Properties) {
            $securityLogGroups[[string]$property.Name] = [string]$property.Value
        }
    } elseif ($securityLogGroup) {
        $securityLogGroups['cloudtrail'] = $securityLogGroup
    }
    $securityRetentionDays = if (
        $outputs.PSObject.Properties.Name -contains 'security_log_retention_days'
    ) {
        [int]$outputs.security_log_retention_days.value
    } else {
        0
    }

    [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        'ecr', 'describe-repositories',
        '--profile', $Profile,
        '--region', $Region,
        '--repository-names', $repositoryName,
        '--output', 'json'
    ) -FailureMessage 'Persistent ECR repository is missing.')

    [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        'iam', 'get-role',
        '--profile', $Profile,
        '--role-name', $roleName,
        '--output', 'json'
    ) -FailureMessage 'Persistent GitHub Actions IAM role is missing.')

    [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
        'iam', 'get-open-id-connect-provider',
        '--profile', $Profile,
        '--open-id-connect-provider-arn', $providerArn,
        '--output', 'json'
    ) -FailureMessage 'Persistent GitHub OIDC provider is missing.')

    if ($securityLogBucket) {
        [void](Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            's3api', 'head-bucket',
            '--profile', $Profile,
            '--bucket', $securityLogBucket
        ) -FailureMessage 'Persistent security log bucket is missing.')
        $lifecycleJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            's3api', 'get-bucket-lifecycle-configuration',
            '--profile', $Profile,
            '--bucket', $securityLogBucket,
            '--output', 'json'
        ) -FailureMessage 'Persistent security-log lifecycle configuration is missing.'
        $lifecycle = $lifecycleJson | ConvertFrom-Json
        $retentionRule = @($lifecycle.Rules | Where-Object {
            [string]$_.ID -ceq 'expire-security-evidence' -and
            [string]$_.Status -ceq 'Enabled'
        }) | Select-Object -First 1
        if (-not $retentionRule -or
            [int]$retentionRule.Expiration.Days -ne $securityRetentionDays -or
            [int]$retentionRule.NoncurrentVersionExpiration.NoncurrentDays -ne $securityRetentionDays) {
            throw 'Persistent security-log lifecycle does not match the declared retention period.'
        }
    }
    if ($securityTrailName) {
        $trailStatusJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            'cloudtrail', 'get-trail-status',
            '--profile', $Profile,
            '--region', $Region,
            '--name', $securityTrailName,
            '--output', 'json'
        ) -FailureMessage 'Persistent security CloudTrail is missing.'
        $trailStatus = $trailStatusJson | ConvertFrom-Json
        if (-not [bool]$trailStatus.IsLogging) {
            throw 'Persistent security CloudTrail exists but is not logging.'
        }
        if ($trailStatus.PSObject.Properties.Name -contains 'LatestDeliveryError' -and
            [string]$trailStatus.LatestDeliveryError) {
            throw "Persistent security CloudTrail delivery failed: $($trailStatus.LatestDeliveryError)"
        }
    }
    foreach ($entry in $securityLogGroups.GetEnumerator()) {
        $logGroupRegion = if ([string]$entry.Key -ceq 'waf') {
            'us-east-1'
        } elseif ([string]$entry.Key -like '*_dr') {
            $DrRegion
        } else {
            $Region
        }
        $logGroupName = [string]$entry.Value
        $logGroupsJson = Invoke-NativeCapture -FilePath 'aws' -ArgumentList @(
            'logs', 'describe-log-groups',
            '--profile', $Profile,
            '--region', $logGroupRegion,
            '--log-group-name-prefix', $logGroupName,
            '--output', 'json'
        ) -FailureMessage 'Persistent security CloudWatch log group could not be read.'
        $logGroups = $logGroupsJson | ConvertFrom-Json
        if (@($logGroups.logGroups | Where-Object {
            [string]$_.logGroupName -ceq $logGroupName
        }).Count -ne 1) {
            throw "Persistent security CloudWatch log group is missing: $logGroupName"
        }
        $matchingLogGroup = @($logGroups.logGroups | Where-Object {
            [string]$_.logGroupName -ceq $logGroupName
        })[0]
        if ([int]$matchingLogGroup.retentionInDays -ne $securityRetentionDays) {
            throw "Persistent security CloudWatch retention does not match the declared retention period: $logGroupName"
        }
    }

    return [pscustomobject]@{
        RepositoryName          = $repositoryName
        RepositoryUrl           = [string]$outputs.application_ecr_repository_url.value
        RoleArn                 = $roleArn
        OidcProviderArn         = $providerArn
        SecurityLogBucket       = $securityLogBucket
        SecurityTrailName       = $securityTrailName
        SecurityLogGroup        = $securityLogGroup
        SecurityLogGroups       = $securityLogGroups
        SecurityRetentionDays   = $securityRetentionDays
        DomainName              = $domainName
        Route53ZoneId           = $route53ZoneId
        CloudFrontCertificateArn = $cloudFrontCertificateArn
    }
}

function Get-TerraformPlanSummary {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$PlanPath
    )

    $json = Invoke-NativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$Root", 'show', '-json', $PlanPath
    ) -FailureMessage 'Saved Terraform plan could not be inspected.'
    $plan = $json | ConvertFrom-Json

    $summary = [ordered]@{
        Create  = 0
        Update  = 0
        Delete  = 0
        Replace = 0
        NoOp    = 0
    }
    $changed = New-Object System.Collections.Generic.List[string]

    foreach ($change in @($plan.resource_changes)) {
        $actions = @($change.change.actions)
        $signature = $actions -join ','
        switch ($signature) {
            'create'        { $summary.Create++ }
            'update'        { $summary.Update++ }
            'delete'        { $summary.Delete++ }
            'delete,create' { $summary.Replace++ }
            'create,delete' { $summary.Replace++ }
            'no-op'         { $summary.NoOp++ }
        }
        if ($signature -ne 'no-op' -and $signature -ne 'read') {
            $changed.Add("$signature`t$($change.address)")
        }
    }

    return [pscustomobject]@{
        Counts  = [pscustomobject]$summary
        Changed = @($changed)
    }
}

function Write-TerraformPlanSummary {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Label
    )

    Write-Host "$Label plan: create=$($Summary.Counts.Create), update=$($Summary.Counts.Update), delete=$($Summary.Counts.Delete), replace=$($Summary.Counts.Replace)"
    $Summary.Changed | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" }
    if ($Summary.Changed.Count -gt 25) {
        Write-Host "  ... $($Summary.Changed.Count - 25) more changes"
    }
}

function Assert-DailyPlanPreservesFoundation {
    param(
        [Parameter(Mandatory)][object]$Summary
    )

    $foundationPatterns = @(
        'github_actions',
        'aws_ecr_repository',
        'github_actions_ecr',
        'github_actions_oidc',
        'module\.primary_eks\.aws_cloudwatch_log_group\.this'
    )
    $forbidden = @($Summary.Changed | Where-Object {
        $change = [string]$_
        @($foundationPatterns | Where-Object {
            $change -match $_
        }).Count -gt 0
    })
    if ($forbidden.Count -gt 0) {
        throw "Foundation resource detected in Daily plan. Complete the reviewed state ownership migration before apply/destroy:`n$($forbidden -join "`n")"
    }
}

function Get-DeclaredImage {
    param([Parameter(Mandatory)][string]$ValuesPath)

    $lines = Get-Content -LiteralPath $ValuesPath
    $repositoryLine = $lines | Where-Object { $_ -match '^\s{2}repository:\s*' } | Select-Object -First 1
    $tagLine = $lines | Where-Object { $_ -match '^\s{2}tag:\s*' } | Select-Object -First 1
    if (-not $repositoryLine -or -not $tagLine) {
        throw "Image repository or tag is missing from $ValuesPath"
    }

    $repository = ($repositoryLine -replace '^\s{2}repository:\s*', '').Trim().Trim('"', "'")
    $tag = ($tagLine -replace '^\s{2}tag:\s*', '').Trim().Trim('"', "'")
    return [pscustomobject]@{ Repository = $repository; Tag = $tag }
}
