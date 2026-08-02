Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Scheduled Tasks start a fresh, non-interactive PowerShell process. Import the
# built-in module explicitly instead of relying on command auto-loading.
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop

$evidenceModulePath = Join-Path $PSScriptRoot 'Evidence.Collection.psm1'
Import-Module $evidenceModulePath -Force

function Write-DailyUtf8NoBom {
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

function Import-DailyAutomationConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Daily automation configuration is unavailable: $Path"
    }

    $config = Microsoft.PowerShell.Utility\Import-PowerShellDataFile `
        -LiteralPath $Path
    if ([int]$config.SchemaVersion -ne 1) {
        throw "Unsupported daily automation schema: $($config.SchemaVersion)"
    }
    if (-not $config.Project -or -not [string]$config.Project.Name) {
        throw 'Daily automation Project.Name is required.'
    }

    if (-not $config.ContainsKey('SessionSafety') -or
        -not $config.SessionSafety) {
        throw 'Daily automation SessionSafety is required.'
    }
    foreach ($field in @(
        'Enabled',
        'SoftDeadlineHours',
        'MaxRuntimeHours',
        'RetryGraceHours',
        'RetryIntervalMinutes',
        'TaskNamePrefix'
    )) {
        if (-not $config.SessionSafety.ContainsKey($field)) {
            throw "SessionSafety field is required: $field"
        }
    }
    if (-not [bool]$config.SessionSafety.Enabled) {
        throw 'SessionSafety.Enabled must remain true for Daily Apply.'
    }
    $softDeadlineHours = [int]$config.SessionSafety.SoftDeadlineHours
    $maxRuntimeHours = [int]$config.SessionSafety.MaxRuntimeHours
    $retryGraceHours = [int]$config.SessionSafety.RetryGraceHours
    $retryIntervalMinutes = [int]$config.SessionSafety.RetryIntervalMinutes
    if ($softDeadlineHours -lt 1 -or
        $maxRuntimeHours -lt 2 -or
        $maxRuntimeHours -gt 24 -or
        $softDeadlineHours -ge $maxRuntimeHours) {
        throw 'SessionSafety deadlines must satisfy 1 <= SoftDeadlineHours < MaxRuntimeHours <= 24.'
    }
    if ($retryGraceHours -lt 1 -or $retryGraceHours -gt 12) {
        throw 'SessionSafety.RetryGraceHours must be between 1 and 12.'
    }
    if ($retryIntervalMinutes -lt 5 -or $retryIntervalMinutes -gt 60) {
        throw 'SessionSafety.RetryIntervalMinutes must be between 5 and 60.'
    }
    if ([string]$config.SessionSafety.TaskNamePrefix -notmatch
        '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$') {
        throw 'SessionSafety.TaskNamePrefix is unsafe.'
    }

    $applicationNames = @{}
    foreach ($application in @($config.Applications)) {
        foreach ($field in @(
            'Name',
            'SourceRootDefault',
            'GitHubRepositoryDefault',
            'WorkflowFile',
            'ValuesRelativePath',
            'ArgoBootstrapRelativePath',
            'ArgoApplication',
            'Namespace',
            'WorkloadKind',
            'WorkloadName',
            'PodSelector',
            'UrlTerraformOutput'
        )) {
            if (-not [string]$application[$field]) {
                throw "Application field is required: $field"
            }
        }
        if ($applicationNames.ContainsKey([string]$application.Name)) {
            throw "Duplicate application name: $($application.Name)"
        }
        foreach ($nameField in @(
            'Name',
            'ArgoApplication',
            'Namespace',
            'WorkloadName'
        )) {
            if ([string]$application[$nameField] -notmatch '^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$') {
                throw "Application $nameField is not a safe Kubernetes-compatible identifier."
            }
        }
        if ([string]$application.GitHubRepositoryDefault -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
            throw 'GitHubRepositoryDefault must use OWNER/REPOSITORY format.'
        }
        if ([string]$application.WorkloadKind -notin @(
            'deployment',
            'statefulset',
            'daemonset'
        )) {
            throw "Unsupported WorkloadKind: $($application.WorkloadKind)"
        }
        if ([string]$application.PodSelector -notmatch '^[A-Za-z0-9./_-]+=[A-Za-z0-9./_-]+$') {
            throw 'PodSelector must be one exact label equality expression.'
        }
        if ([string]$application.UrlTerraformOutput -notmatch '^[A-Za-z0-9_]+$') {
            throw 'UrlTerraformOutput is not a safe Terraform output name.'
        }
        foreach ($relativePathField in @(
            'ValuesRelativePath',
            'ArgoBootstrapRelativePath'
        )) {
            $relativePath = [string]$application[$relativePathField]
            if ([System.IO.Path]::IsPathRooted($relativePath) -or
                $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
                throw "Application $relativePathField must stay inside SourceRootDefault."
            }
        }
        $argoBootstrapFile = Split-Path -Leaf (
            [string]$application.ArgoBootstrapRelativePath
        )
        if ($argoBootstrapFile -notmatch '^[A-Za-z0-9._-]+$') {
            throw 'ArgoBootstrapRelativePath must end in a shell-safe file name.'
        }
        if (-not $application.Database -or
            -not [bool]$application.Database.Enabled -or
            [string]$application.Database.Type -cne 'MariaDbDvwa') {
            throw 'The current application runner requires the MariaDbDvwa database contract.'
        }
        foreach ($databaseField in @(
            'TerraformOutput',
            'BootstrapScript',
            'KubernetesSecretName'
        )) {
            if (-not [string]$application.Database[$databaseField]) {
                throw "Application Database field is required: $databaseField"
            }
        }
        if ([string]$application.Database.TerraformOutput -notmatch '^[A-Za-z0-9_]+$') {
            throw 'Database TerraformOutput is not a safe Terraform output name.'
        }
        if ([System.IO.Path]::IsPathRooted([string]$application.Database.BootstrapScript) -or
            [string]$application.Database.BootstrapScript -match '(^|[\\/])\.\.([\\/]|$)') {
            throw 'Database BootstrapScript must stay inside TerraformRoot.'
        }
        if ((Split-Path -Leaf ([string]$application.Database.BootstrapScript)) -notmatch '^[A-Za-z0-9._-]+$') {
            throw 'Database BootstrapScript must end in a shell-safe file name.'
        }
        $applicationNames[[string]$application.Name] = $true
    }
    if ($applicationNames.Count -eq 0) {
        throw 'At least one application must be configured.'
    }

    if (-not $config.Evidence -or -not [string]$config.Evidence.RootDefault) {
        throw 'Evidence.RootDefault is required.'
    }
    if ([string]$config.Evidence.HashAlgorithm -notin @('SHA256', 'SHA384', 'SHA512')) {
        throw 'Evidence.HashAlgorithm must be SHA256, SHA384, or SHA512.'
    }
    if ($config.Evidence.ContainsKey('DefaultWindowMinutes') -and (
        [int]$config.Evidence.DefaultWindowMinutes -lt 1 -or
        [int]$config.Evidence.DefaultWindowMinutes -gt 10080
    )) {
        throw 'Evidence.DefaultWindowMinutes must be between 1 and 10080.'
    }
    if ($config.Evidence.ContainsKey('QueryPackRoot')) {
        $queryPackRoot = [string]$config.Evidence.QueryPackRoot
        if ([System.IO.Path]::IsPathRooted($queryPackRoot) -or
            $queryPackRoot -match '(^|[\\/])\.\.([\\/]|$)') {
            throw 'Evidence.QueryPackRoot must stay inside TerraformRoot.'
        }
    }

    $collectorNames = @{}
    foreach ($collector in @($config.Evidence.Collectors)) {
        foreach ($field in @('Name', 'Type', 'Region', 'Destination', 'FailurePolicy')) {
            if (-not [string]$collector[$field]) {
                throw "Evidence collector field is required: $field"
            }
        }
        if ([string]$collector.Type -notin @('S3Prefix', 'CloudWatchLogs')) {
            throw "Unsupported evidence collector type: $($collector.Type)"
        }
        if ([string]$collector.FailurePolicy -notin @('Stop', 'Warn')) {
            throw "Unsupported evidence failure policy: $($collector.FailurePolicy)"
        }
        if ([string]$collector.SourceRoot -notin @('Foundation', 'Daily')) {
            throw "Unsupported evidence collector SourceRoot: $($collector.SourceRoot)"
        }
        if ([string]$collector.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
            throw "Evidence collector Name is unsafe: $($collector.Name)"
        }
        $destination = [string]$collector.Destination
        if ([System.IO.Path]::IsPathRooted($destination) -or
            $destination -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "Evidence collector Destination must stay inside EvidenceRoot: $($collector.Name)"
        }
        if ($collector.ContainsKey('TerraformOutput') -and
            [string]$collector.TerraformOutput -notmatch '^[A-Za-z0-9_]+$') {
            throw "Evidence collector TerraformOutput is unsafe: $($collector.Name)"
        }
        if ($collector.ContainsKey('TerraformResourceValue') -and
            [string]$collector.TerraformResourceValue -notmatch '^[A-Za-z0-9_]+$') {
            throw "Evidence collector TerraformResourceValue is unsafe: $($collector.Name)"
        }
        if ([string]$collector.Type -ceq 'S3Prefix' -and
            -not [string]$collector.Prefix) {
            throw "S3Prefix collector Prefix is required: $($collector.Name)"
        }
        if ([string]$collector.Type -ceq 'CloudWatchLogs' -and
            -not [string]$collector.LogGroup) {
            throw "CloudWatchLogs collector LogGroup is required: $($collector.Name)"
        }
        if ($collector.ContainsKey('MaxAttempts') -and (
            [int]$collector.MaxAttempts -lt 1 -or
            [int]$collector.MaxAttempts -gt 5
        )) {
            throw "Evidence collector MaxAttempts must be between 1 and 5: $($collector.Name)"
        }
        if ($collector.ContainsKey('RetryDelaySeconds') -and (
            [int]$collector.RetryDelaySeconds -lt 0 -or
            [int]$collector.RetryDelaySeconds -gt 30
        )) {
            throw "Evidence collector RetryDelaySeconds must be between 0 and 30: $($collector.Name)"
        }
        if ($collectorNames.ContainsKey([string]$collector.Name)) {
            throw "Duplicate evidence collector name: $($collector.Name)"
        }
        $collectorNames[[string]$collector.Name] = $true
    }

    $queryNames = @{}
    $queries = if ($config.Evidence.ContainsKey('Queries')) {
        @($config.Evidence.Queries)
    } else {
        @()
    }
    if ($queries.Count -gt 0 -and
        (-not $config.Evidence.ContainsKey('QueryPackRoot') -or
        -not [string]$config.Evidence.QueryPackRoot)) {
        throw 'Evidence.QueryPackRoot is required when Evidence.Queries are configured.'
    }
    foreach ($query in $queries) {
        foreach ($field in @(
            'Name',
            'Type',
            'QueryFile',
            'LogGroup',
            'Region'
        )) {
            if (-not [string]$query[$field]) {
                throw "Evidence query field is required: $field"
            }
        }
        if ([string]$query.Type -cne 'CloudWatchLogsInsights') {
            throw "Unsupported evidence query type: $($query.Type)"
        }
        if ([string]$query.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
            throw "Evidence query Name is unsafe: $($query.Name)"
        }
        if ($queryNames.ContainsKey([string]$query.Name)) {
            throw "Duplicate evidence query name: $($query.Name)"
        }
        $queryFile = [string]$query.QueryFile
        if ([System.IO.Path]::IsPathRooted($queryFile) -or
            $queryFile -match '(^|[\\/])\.\.([\\/]|$)' -or
            [System.IO.Path]::GetExtension($queryFile) -cne '.cwli') {
            throw "Evidence query file must be a .cwli file inside QueryPackRoot: $($query.Name)"
        }
        $scenarioIds = @($query.ScenarioIds)
        if ($scenarioIds.Count -eq 0 -or @($scenarioIds | Where-Object {
            [string]$_ -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,80}$'
        }).Count -gt 0) {
            throw "Evidence query ScenarioIds are missing or unsafe: $($query.Name)"
        }
        if ($query.ContainsKey('MaxPollAttempts') -and (
            [int]$query.MaxPollAttempts -lt 1 -or
            [int]$query.MaxPollAttempts -gt 120
        )) {
            throw "Evidence query MaxPollAttempts must be between 1 and 120: $($query.Name)"
        }
        if ($query.ContainsKey('PollDelaySeconds') -and (
            [int]$query.PollDelaySeconds -lt 0 -or
            [int]$query.PollDelaySeconds -gt 30
        )) {
            throw "Evidence query PollDelaySeconds must be between 0 and 30: $($query.Name)"
        }
        $queryNames[[string]$query.Name] = $true
    }

    return $config
}

function Get-DailyApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$Name
    )

    $matches = @($Config.Applications | Where-Object {
        [string]$_.Name -ceq $Name
    })
    if ($matches.Count -ne 1) {
        throw "Exactly one configured application is required for '$Name'; found $($matches.Count)."
    }
    return $matches[0]
}

function Resolve-DailyTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $resolved = $Value
    foreach ($key in $Tokens.Keys) {
        $resolved = $resolved.Replace(
            "{$key}",
            [string]$Tokens[$key]
        )
    }
    if ($resolved -match '\{[A-Za-z][A-Za-z0-9]*\}') {
        throw "Unresolved automation token in value: $resolved"
    }
    return $resolved
}

function Invoke-DailyNativeCapture {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @(),
        [switch]$AllowFailure
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
        if ($AllowFailure) {
            return $null
        }
        $detail = ($output | Out-String).Trim()
        throw "$FilePath failed with exit code $exitCode.`n$detail"
    }
    return ($output | Out-String).Trim()
}

function Find-DailyTerraformResource {
    param(
        [Parameter(Mandatory)][object]$Module,
        [Parameter(Mandatory)][string]$Address
    )

    $resources = if (
        $Module.PSObject.Properties.Name -contains 'resources'
    ) {
        @($Module.resources)
    } else {
        @()
    }
    foreach ($resource in $resources) {
        if ([string]$resource.address -ceq $Address) {
            return $resource
        }
    }
    $children = if (
        $Module.PSObject.Properties.Name -contains 'child_modules'
    ) {
        @($Module.child_modules)
    } else {
        @()
    }
    foreach ($child in $children) {
        $match = Find-DailyTerraformResource -Module $child -Address $Address
        if ($match) {
            return $match
        }
    }
    return $null
}

function Get-DailyTerraformResourceValue {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$ValueName
    )

    $json = Invoke-DailyNativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$Root", 'show', '-json'
    ) -AllowFailure
    if (-not $json) {
        return $null
    }

    $state = $json | ConvertFrom-Json
    if ($state.PSObject.Properties.Name -notcontains 'values' -or
        -not $state.values -or
        $state.values.PSObject.Properties.Name -notcontains 'root_module' -or
        -not $state.values.root_module) {
        return $null
    }
    $resource = Find-DailyTerraformResource `
        -Module $state.values.root_module `
        -Address $Address
    if (-not $resource -or
        -not $resource.values -or
        $resource.values.PSObject.Properties.Name -notcontains $ValueName) {
        return $null
    }
    return [string]$resource.values.$ValueName
}

function Get-DailyTerraformOutputValue {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Name
    )

    return Invoke-DailyNativeCapture -FilePath 'terraform' -ArgumentList @(
        "-chdir=$Root", 'output', '-raw', $Name
    ) -AllowFailure
}

function Get-DailyCollectorBucket {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context
    )

    $root = switch ([string]$Collector.SourceRoot) {
        'Foundation' { [string]$Context.FoundationRoot }
        'Daily'      { [string]$Context.TerraformRoot }
        default      { throw "Unsupported collector SourceRoot: $($Collector.SourceRoot)" }
    }

    if ($Collector.ContainsKey('TerraformOutput') -and
        [string]$Collector.TerraformOutput) {
        return Get-DailyTerraformOutputValue `
            -Root $root `
            -Name ([string]$Collector.TerraformOutput)
    }
    if ($Collector.ContainsKey('TerraformResource') -and
        [string]$Collector.TerraformResource) {
        $valueName = if (
            $Collector.ContainsKey('TerraformResourceValue') -and
            [string]$Collector.TerraformResourceValue
        ) {
            [string]$Collector.TerraformResourceValue
        } else {
            'id'
        }
        return Get-DailyTerraformResourceValue `
            -Root $root `
            -Address ([string]$Collector.TerraformResource) `
            -ValueName $valueName
    }
    if ($Collector.ContainsKey('Bucket') -and [string]$Collector.Bucket) {
        return [string]$Collector.Bucket
    }

    throw "Collector '$($Collector.Name)' does not define a bucket source."
}

function Invoke-DailyS3PrefixCollector {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )

    $bucket = Get-DailyCollectorBucket -Collector $Collector -Context $Context
    if (-not $bucket) {
        if ($Collector.ContainsKey('SkipIfMissing') -and
            [bool]$Collector.SkipIfMissing) {
            return [pscustomobject]@{
                Name        = [string]$Collector.Name
                Type        = [string]$Collector.Type
                Status      = 'Skipped'
                Detail      = 'Source bucket is not currently available.'
                Destination = ''
            }
        }
        throw "Collector '$($Collector.Name)' could not resolve its source bucket."
    }

    $tokens = @{
        AccountId    = [string]$Context.AccountId
        ProjectName  = [string]$Context.ProjectName
        PrimaryRegion = [string]$Context.PrimaryRegion
        DrRegion     = [string]$Context.DrRegion
        UserHome     = [string]$HOME
    }
    $prefix = Resolve-DailyTemplate -Value ([string]$Collector.Prefix) -Tokens $tokens
    $relativeDestination = Resolve-DailyTemplate `
        -Value ([string]$Collector.Destination) `
        -Tokens $tokens
    $destination = Join-Path $EvidenceRoot $relativeDestination
    New-Item -ItemType Directory -Force -Path $destination | Out-Null

    $region = switch ([string]$Collector.Region) {
        'Primary' { [string]$Context.PrimaryRegion }
        'Dr'      { [string]$Context.DrRegion }
        default   { [string]$Collector.Region }
    }
    $source = "s3://$bucket/$prefix"
    $before = @(Get-ChildItem -LiteralPath $destination -File -Recurse -ErrorAction SilentlyContinue).Count

    [void](Invoke-DailyNativeCapture -FilePath 'aws' -ArgumentList @(
        's3', 'sync',
        $source,
        $destination,
        '--profile', [string]$Context.AwsProfile,
        '--region', $region,
        '--no-progress',
        '--only-show-errors'
    ))

    $files = @(Get-ChildItem -LiteralPath $destination -File -Recurse -ErrorAction SilentlyContinue)
    return [pscustomobject]@{
        Name        = [string]$Collector.Name
        Type        = [string]$Collector.Type
        Status      = 'Succeeded'
        Detail      = "Files before=$before, after=$($files.Count)"
        Destination = $destination
    }
}

function Update-DailyEvidenceHashIndex {
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$Algorithm
    )

    $stateRoot = Join-Path $EvidenceRoot '_state'
    New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
    $indexPath = Join-Path $stateRoot 'hash-index.json'
    $existing = @{}
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        $parsed = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
        foreach ($entry in @($parsed.Files)) {
            $existing[[string]$entry.Path] = $entry
        }
    }

    $rootPrefix = (Resolve-Path -LiteralPath $EvidenceRoot).Path.TrimEnd('\') + '\'
    $entries = New-Object System.Collections.Generic.List[object]
    $hashed = 0
    $reused = 0
    $files = Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse |
        Where-Object {
            $_.FullName -notlike "$stateRoot\*" -and
            $_.FullName -notlike "$(Join-Path $EvidenceRoot '_runs')\*"
        } |
        Sort-Object FullName

    foreach ($file in $files) {
        $relative = $file.FullName.Substring($rootPrefix.Length)
        $lastWrite = $file.LastWriteTimeUtc.ToString('o')
        $prior = $existing[$relative]
        if ($prior -and
            [long]$prior.Length -eq [long]$file.Length -and
            [string]$prior.LastWriteTimeUtc -ceq $lastWrite -and
            [string]$prior.Algorithm -ceq $Algorithm) {
            $hash = [string]$prior.Hash
            $reused++
        } else {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm $Algorithm).Hash
            $hashed++
        }

        $entries.Add([pscustomobject]@{
            Path             = $relative
            Length           = [long]$file.Length
            LastWriteTimeUtc = $lastWrite
            Algorithm        = $Algorithm
            Hash             = $hash
        })
    }

    $index = [ordered]@{
        SchemaVersion = 1
        UpdatedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Files         = @($entries | ForEach-Object { $_ })
    }
    $tempPath = "$indexPath.tmp"
    Write-DailyUtf8NoBom -Path $tempPath -Content (
        $index | ConvertTo-Json -Depth 8
    )
    Move-Item -LiteralPath $tempPath -Destination $indexPath -Force

    return [pscustomobject]@{
        IndexPath = $indexPath
        FileCount = $entries.Count
        Hashed    = $hashed
        Reused    = $reused
    }
}

function Invoke-LegacyDailyEvidenceCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Context,
        [string]$EvidenceRoot = ''
    )

    $tokens = @{
        AccountId     = [string]$Context.AccountId
        ProjectName   = [string]$Context.ProjectName
        PrimaryRegion = [string]$Context.PrimaryRegion
        DrRegion      = [string]$Context.DrRegion
        UserHome      = [string]$HOME
    }
    if (-not $EvidenceRoot) {
        $EvidenceRoot = Resolve-DailyTemplate `
            -Value ([string]$Config.Evidence.RootDefault) `
            -Tokens $tokens
    }
    New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
    $EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path

    $started = (Get-Date).ToUniversalTime()
    $results = New-Object System.Collections.Generic.List[object]
    $stopFailures = New-Object System.Collections.Generic.List[string]

    foreach ($collector in @($Config.Evidence.Collectors)) {
        try {
            $result = switch ([string]$collector.Type) {
                'S3Prefix' {
                    Invoke-DailyS3PrefixCollector `
                        -Collector $collector `
                        -Context $Context `
                        -EvidenceRoot $EvidenceRoot
                }
                default {
                    throw "Unsupported collector type: $($collector.Type)"
                }
            }
            $results.Add($result)
        } catch {
            $message = $_.Exception.Message
            $results.Add([pscustomobject]@{
                Name        = [string]$collector.Name
                Type        = [string]$collector.Type
                Status      = 'Failed'
                Detail      = $message
                Destination = ''
            })
            if ([string]$collector.FailurePolicy -ceq 'Stop') {
                $stopFailures.Add("$($collector.Name): $message")
            } else {
                Write-Warning "Evidence collector failed but its source remains recoverable: $($collector.Name)"
            }
        }
    }

    $hashIndex = Update-DailyEvidenceHashIndex `
        -EvidenceRoot $EvidenceRoot `
        -Algorithm ([string]$Config.Evidence.HashAlgorithm)

    $runsRoot = Join-Path $EvidenceRoot '_runs'
    New-Item -ItemType Directory -Force -Path $runsRoot | Out-Null
    $runId = $started.ToString('yyyyMMddTHHmmssZ')
    $manifestPath = Join-Path $runsRoot "$runId.json"
    $manifest = [ordered]@{
        SchemaVersion = 1
        RunId         = $runId
        StartedAtUtc  = $started.ToString('o')
        FinishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Project       = [string]$Context.ProjectName
        AccountId     = [string]$Context.AccountId
        PrimaryRegion = [string]$Context.PrimaryRegion
        DrRegion      = [string]$Context.DrRegion
        Results       = @($results | ForEach-Object { $_ })
        HashIndex     = @{
            Algorithm = [string]$Config.Evidence.HashAlgorithm
            FileCount = [int]$hashIndex.FileCount
            Hashed    = [int]$hashIndex.Hashed
            Reused    = [int]$hashIndex.Reused
        }
    }
    Write-DailyUtf8NoBom -Path $manifestPath -Content (
        $manifest | ConvertTo-Json -Depth 10
    )
    $manifestHash = (Get-FileHash `
        -LiteralPath $manifestPath `
        -Algorithm ([string]$Config.Evidence.HashAlgorithm)).Hash
    Write-DailyUtf8NoBom `
        -Path "$manifestPath.$(([string]$Config.Evidence.HashAlgorithm).ToLowerInvariant())" `
        -Content "$manifestHash  $([System.IO.Path]::GetFileName($manifestPath))`n"

    if ($stopFailures.Count -gt 0) {
        throw "Required evidence collection failed. Daily destroy was not started:`n$($stopFailures -join "`n")"
    }

    return [pscustomobject]@{
        Root         = $EvidenceRoot
        ManifestPath = $manifestPath
        Results      = @($results | ForEach-Object { $_ })
        HashIndex    = $hashIndex
    }
}

function Invoke-DailyEvidenceCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Context,
        [string]$EvidenceRoot = '',
        [string]$ExperimentId = '',
        [string]$ScenarioId = 'daily-lifecycle',
        [datetime]$StartTimeUtc,
        [datetime]$EndTimeUtc,
        [ValidateRange(0, 30)]
        [int]$EventTailSeconds = 0,
        [ValidateRange(0, 30)]
        [int]$S3DeliveryGraceMinutes = 0,
        [switch]$RequireEvidence,
        [string[]]$RequiredCollectorNames = @(),
        [switch]$RunQueries,
        [string]$Phase = 'manual',
        [scriptblock]$Invoker
    )

    $arguments = @{
        Config = $Config
        Context = $Context
        EvidenceRoot = $EvidenceRoot
        ExperimentId = $ExperimentId
        ScenarioId = $ScenarioId
        RequireEvidence = $RequireEvidence
        RequiredCollectorNames = $RequiredCollectorNames
        RunQueries = $RunQueries
        EventTailSeconds = $EventTailSeconds
        S3DeliveryGraceMinutes = $S3DeliveryGraceMinutes
        Phase = $Phase
        Invoker = $Invoker
    }
    if ($PSBoundParameters.ContainsKey('StartTimeUtc')) {
        $arguments.StartTimeUtc = $StartTimeUtc
    }
    if ($PSBoundParameters.ContainsKey('EndTimeUtc')) {
        $arguments.EndTimeUtc = $EndTimeUtc
    }

    return Invoke-SecurityEvidenceCollection @arguments
}

Export-ModuleMember -Function @(
    'Import-DailyAutomationConfig',
    'Get-DailyApplication',
    'Resolve-DailyTemplate',
    'Invoke-DailyEvidenceCollection'
)
