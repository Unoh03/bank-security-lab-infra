Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:EvidenceJsonDepth = 100

function Write-EvidenceUtf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Resolve-EvidenceTemplate {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $resolved = $Value
    foreach ($key in $Tokens.Keys) {
        $resolved = $resolved.Replace("{$key}", [string]$Tokens[$key])
    }
    if ($resolved -match '\{[A-Za-z][A-Za-z0-9]*\}') {
        throw "Unresolved evidence token: $resolved"
    }
    return $resolved
}

function Invoke-EvidenceNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [scriptblock]$Invoker,
        [switch]$AllowFailure
    )

    if ($Invoker) {
        return & $Invoker $FilePath $ArgumentList ([bool]$AllowFailure)
    }

    # AWS CLI v2 inherits the Windows console code page. EKS audit messages can
    # contain characters that cp949 cannot encode, so force UTF-8 only for the
    # child process and restore the caller's environment afterwards.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $previousConsoleOutputEncoding = [Console]::OutputEncoding
    $previousOutputEncoding = $OutputEncoding
    $previousPythonUtf8 = $env:PYTHONUTF8
    $previousAwsCliFileEncoding = $env:AWS_CLI_FILE_ENCODING
    try {
        [Console]::OutputEncoding = $utf8
        $OutputEncoding = $utf8
        $env:PYTHONUTF8 = '1'
        $env:AWS_CLI_FILE_ENCODING = 'UTF-8'
        $output = & $FilePath @ArgumentList 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    } finally {
        [Console]::OutputEncoding = $previousConsoleOutputEncoding
        $OutputEncoding = $previousOutputEncoding
        if ($null -eq $previousPythonUtf8) {
            Remove-Item Env:\PYTHONUTF8 -ErrorAction SilentlyContinue
        } else {
            $env:PYTHONUTF8 = $previousPythonUtf8
        }
        if ($null -eq $previousAwsCliFileEncoding) {
            Remove-Item Env:\AWS_CLI_FILE_ENCODING -ErrorAction SilentlyContinue
        } else {
            $env:AWS_CLI_FILE_ENCODING = $previousAwsCliFileEncoding
        }
    }
    if ($exitCode -ne 0) {
        if ($AllowFailure) {
            return $null
        }
        throw "$FilePath failed (exit=$exitCode): $($output.Trim())"
    }
    return $output.Trim()
}

function Invoke-EvidenceBoundedRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [ValidateRange(1, 5)][int]$MaxAttempts = 3,
        [ValidateRange(0, 30)][int]$DelaySeconds = 2
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Operation $attempt
        } catch {
            $lastError = $_
            if ($attempt -lt $MaxAttempts -and $DelaySeconds -gt 0) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    throw $lastError
}

function Test-EvidenceSensitiveKey {
    param([Parameter(Mandatory)][string]$Key)

    return $Key -match '(?i)(password|passwd|secret|token|cookie|authorization|session|access.?key|private.?key|credential|db.?password)'
}

function Protect-EvidenceScalar {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [bool] -or
        $Value -is [byte] -or
        $Value -is [int16] -or
        $Value -is [int32] -or
        $Value -is [int64] -or
        $Value -is [decimal] -or
        $Value -is [double] -or
        $Value -is [single]) {
        return $Value
    }

    $text = ([string]$Value).Replace("`0", '').Replace("`r", ' ').Replace("`n", ' ')
    $text = [regex]::Replace(
        $text,
        '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+',
        'Bearer [REDACTED]'
    )
    $text = [regex]::Replace(
        $text,
        '(?i)\b(password|passwd|secret|token|cookie|authorization|session[_-]?id|access[_-]?key)(\s*[=:]\s*)([^,\s;"''}]+)',
        '$1$2[REDACTED]'
    )
    $text = [regex]::Replace(
        $text,
        '(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s?"]+)\?[^\s"]+',
        '$1 $2?[REDACTED_QUERY]'
    )
    $text = [regex]::Replace($text, '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED_AWS_KEY_ID]')
    return $text
}

function ConvertTo-EvidenceSafeValue {
    param(
        [AllowNull()]$Value,
        [string]$Key = ''
    )

    if ($Key -and (Test-EvidenceSensitiveKey -Key $Key)) {
        return '[REDACTED]'
    }
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $safe = [ordered]@{}
        foreach ($entryKey in $Value.Keys) {
            $safe[[string]$entryKey] = ConvertTo-EvidenceSafeValue `
                -Value $Value[$entryKey] `
                -Key ([string]$entryKey)
        }
        return $safe
    }
    if ($Value -is [pscustomobject]) {
        $safe = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $safe[[string]$property.Name] = ConvertTo-EvidenceSafeValue `
                -Value $property.Value `
                -Key ([string]$property.Name)
        }
        return $safe
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object {
            ConvertTo-EvidenceSafeValue -Value $_
        })
    }
    if ($Value -is [string]) {
        $nestedText = $Value.Trim()
        if ($nestedText.StartsWith('{') -or $nestedText.StartsWith('[')) {
            try {
                $nestedValue = $nestedText | ConvertFrom-Json
                $safeNestedValue = ConvertTo-EvidenceSafeValue -Value $nestedValue
                return $safeNestedValue |
                    ConvertTo-Json -Depth $script:EvidenceJsonDepth -Compress
            } catch {
                # Preserve non-JSON log messages and sanitize them as plain text.
            }
        }
    }
    return Protect-EvidenceScalar -Value $Value
}

function Protect-SecurityEvidenceText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $trimmed = $Text.Trim()
    if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
        try {
            $parsed = $Text | ConvertFrom-Json
            $safe = ConvertTo-EvidenceSafeValue -Value $parsed
            return $safe | ConvertTo-Json -Depth $script:EvidenceJsonDepth
        } catch {
            # Some AWS text logs begin with JSON-like characters. Fall through
            # to the line-preserving text sanitizer instead of losing evidence.
        }
    }

    $safeLines = @($Text -split "\r?\n" | ForEach-Object {
        Protect-EvidenceScalar -Value $_
    })
    return $safeLines -join "`n"
}

function Get-EvidenceStringHash {
    param([Parameter(Mandatory)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-EvidenceRegion {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context
    )

    switch ([string]$Collector.Region) {
        'Primary' { return [string]$Context.PrimaryRegion }
        'Dr'      { return [string]$Context.DrRegion }
        'Global'  { return 'us-east-1' }
        default   { return [string]$Collector.Region }
    }
}

function Get-EvidenceBucket {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context,
        [scriptblock]$Invoker
    )

    if ($Collector.ContainsKey('Bucket') -and [string]$Collector.Bucket) {
        return [string]$Collector.Bucket
    }

    $root = switch ([string]$Collector.SourceRoot) {
        'Foundation' { [string]$Context.FoundationRoot }
        'Daily'      { [string]$Context.TerraformRoot }
        default      { throw "Unsupported collector SourceRoot: $($Collector.SourceRoot)" }
    }
    if ($Collector.ContainsKey('TerraformOutput') -and [string]$Collector.TerraformOutput) {
        return Invoke-EvidenceNative `
            -FilePath 'terraform' `
            -ArgumentList @(
                "-chdir=$root",
                'output',
                '-raw',
                [string]$Collector.TerraformOutput
            ) `
            -Invoker $Invoker `
            -AllowFailure
    }

    throw "S3 collector '$($Collector.Name)' does not define Bucket or TerraformOutput."
}

function Read-EvidenceObjectText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ObjectKey
    )

    if ($ObjectKey.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        $inputStream = [System.IO.File]::OpenRead($Path)
        try {
            $gzip = New-Object System.IO.Compression.GZipStream(
                $inputStream,
                [System.IO.Compression.CompressionMode]::Decompress
            )
            try {
                $reader = New-Object System.IO.StreamReader(
                    $gzip,
                    (New-Object System.Text.UTF8Encoding($false, $false)),
                    $true
                )
                try {
                    return $reader.ReadToEnd()
                } finally {
                    $reader.Dispose()
                }
            } finally {
                $gzip.Dispose()
            }
        } finally {
            $inputStream.Dispose()
        }
    }

    return [System.IO.File]::ReadAllText(
        $Path,
        (New-Object System.Text.UTF8Encoding($false, $false))
    )
}

function Invoke-EvidenceS3PrefixCollector {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][datetime]$StartTimeUtc,
        [Parameter(Mandatory)][datetime]$EndTimeUtc,
        [scriptblock]$Invoker
    )

    $bucket = Get-EvidenceBucket -Collector $Collector -Context $Context -Invoker $Invoker
    if (-not $bucket) {
        if ($Collector.ContainsKey('SkipIfMissing') -and [bool]$Collector.SkipIfMissing) {
            return [pscustomobject]@{
                Name = [string]$Collector.Name
                Type = 'S3Prefix'
                Status = 'Skipped'
                Detail = 'Source bucket is unavailable.'
                Items = 0
                Destination = ''
            }
        }
        throw "Collector '$($Collector.Name)' could not resolve its source bucket."
    }

    $tokens = $Context.Tokens
    $prefix = Resolve-EvidenceTemplate -Value ([string]$Collector.Prefix) -Tokens $tokens
    $relativeDestination = Resolve-EvidenceTemplate `
        -Value ([string]$Collector.Destination) `
        -Tokens $tokens
    $metadataRoot = Join-Path (Join-Path $BundleRoot 'source') $relativeDestination
    $sanitizedRoot = Join-Path (Join-Path $BundleRoot 'sanitized') $relativeDestination
    $tempRoot = Join-Path $BundleRoot '_tmp'
    New-Item -ItemType Directory -Force -Path $metadataRoot, $sanitizedRoot, $tempRoot | Out-Null

    $region = Get-EvidenceRegion -Collector $Collector -Context $Context
    $maxAttempts = if ($Collector.ContainsKey('MaxAttempts')) {
        [int]$Collector.MaxAttempts
    } else {
        3
    }
    $delaySeconds = if ($Collector.ContainsKey('RetryDelaySeconds')) {
        [int]$Collector.RetryDelaySeconds
    } else {
        2
    }

    $listingJson = Invoke-EvidenceBoundedRetry -MaxAttempts $maxAttempts -DelaySeconds $delaySeconds -Operation {
        Invoke-EvidenceNative `
            -FilePath 'aws' `
            -ArgumentList @(
                's3api', 'list-objects-v2',
                '--bucket', $bucket,
                '--prefix', $prefix,
                '--profile', [string]$Context.AwsProfile,
                '--region', $region,
                '--output', 'json'
            ) `
            -Invoker $Invoker
    }
    $listing = if ($listingJson) {
        $listingJson | ConvertFrom-Json
    } else {
        [pscustomobject]@{ Contents = @() }
    }
    $objects = @()
    if ($listing.PSObject.Properties.Name -contains 'Contents' -and $listing.Contents) {
        $objects = @($listing.Contents | Where-Object {
            $lastModified = ([datetime]$_.LastModified).ToUniversalTime()
            $lastModified -ge $StartTimeUtc -and $lastModified -le $EndTimeUtc
        })
    }

    $index = New-Object System.Collections.Generic.List[object]
    foreach ($object in $objects) {
        $key = [string]$object.Key
        if (-not $key) {
            continue
        }
        $keyHash = Get-EvidenceStringHash -Value $key
        $tempPath = Join-Path $tempRoot "$keyHash.download"
        try {
            [void](Invoke-EvidenceBoundedRetry -MaxAttempts $maxAttempts -DelaySeconds $delaySeconds -Operation {
                Invoke-EvidenceNative `
                    -FilePath 'aws' `
                    -ArgumentList @(
                        's3api', 'get-object',
                        '--bucket', $bucket,
                        '--key', $key,
                        '--profile', [string]$Context.AwsProfile,
                        '--region', $region,
                        '--output', 'json',
                        $tempPath
                    ) `
                    -Invoker $Invoker
            })

            $leaf = [System.IO.Path]::GetFileName($key)
            if ($leaf.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
                $leaf = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
            }
            $leaf = [regex]::Replace($leaf, '[^A-Za-z0-9._-]', '_')
            if (-not $leaf) {
                $leaf = 'log.txt'
            }
            $outputPath = Join-Path $sanitizedRoot "$($keyHash.Substring(0, 12))-$leaf"
            $safeText = Protect-SecurityEvidenceText -Text (
                Read-EvidenceObjectText -Path $tempPath -ObjectKey $key
            )
            Write-EvidenceUtf8NoBom -Path $outputPath -Content $safeText

            $index.Add([pscustomobject]@{
                Key = $key
                LastModifiedUtc = ([datetime]$object.LastModified).ToUniversalTime().ToString('o')
                Size = [long]$object.Size
                SanitizedFile = $outputPath.Substring($BundleRoot.Length + 1)
            })
        } finally {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-EvidenceUtf8NoBom `
        -Path (Join-Path $metadataRoot 'objects.json') `
        -Content (([ordered]@{
            Bucket = $bucket
            Prefix = $prefix
            StartTimeUtc = $StartTimeUtc.ToString('o')
            EndTimeUtc = $EndTimeUtc.ToString('o')
            Objects = @($index | ForEach-Object { $_ })
        }) | ConvertTo-Json -Depth 10)

    return [pscustomobject]@{
        Name = [string]$Collector.Name
        Type = 'S3Prefix'
        Status = if ($index.Count -gt 0) { 'Succeeded' } else { 'Empty' }
        Detail = "Objects in time window=$($index.Count)"
        Items = $index.Count
        Destination = $sanitizedRoot
    }
}

function Invoke-EvidenceCloudWatchLogsCollector {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][datetime]$StartTimeUtc,
        [Parameter(Mandatory)][datetime]$EndTimeUtc,
        [scriptblock]$Invoker
    )

    $tokens = $Context.Tokens
    $logGroup = Resolve-EvidenceTemplate -Value ([string]$Collector.LogGroup) -Tokens $tokens
    $relativeDestination = Resolve-EvidenceTemplate `
        -Value ([string]$Collector.Destination) `
        -Tokens $tokens
    $metadataRoot = Join-Path (Join-Path $BundleRoot 'source') $relativeDestination
    $sanitizedRoot = Join-Path (Join-Path $BundleRoot 'sanitized') $relativeDestination
    New-Item -ItemType Directory -Force -Path $metadataRoot, $sanitizedRoot | Out-Null

    $region = Get-EvidenceRegion -Collector $Collector -Context $Context
    $arguments = @(
        'logs', 'filter-log-events',
        '--log-group-name', $logGroup,
        '--start-time', ([DateTimeOffset]$StartTimeUtc).ToUnixTimeMilliseconds().ToString(),
        '--end-time', ([DateTimeOffset]$EndTimeUtc).ToUnixTimeMilliseconds().ToString(),
        '--profile', [string]$Context.AwsProfile,
        '--region', $region,
        '--output', 'json'
    )
    if ($Collector.ContainsKey('FilterPattern') -and [string]$Collector.FilterPattern) {
        $arguments += @('--filter-pattern', [string]$Collector.FilterPattern)
    }
    $maxAttempts = if ($Collector.ContainsKey('MaxAttempts')) {
        [int]$Collector.MaxAttempts
    } else {
        3
    }
    $delaySeconds = if ($Collector.ContainsKey('RetryDelaySeconds')) {
        [int]$Collector.RetryDelaySeconds
    } else {
        2
    }

    $json = Invoke-EvidenceBoundedRetry -MaxAttempts $maxAttempts -DelaySeconds $delaySeconds -Operation {
        Invoke-EvidenceNative -FilePath 'aws' -ArgumentList $arguments -Invoker $Invoker
    }
    $parsed = if ($json) {
        $json | ConvertFrom-Json
    } else {
        [pscustomobject]@{ events = @(); searchedLogStreams = @() }
    }
    $eventCount = if ($parsed.PSObject.Properties.Name -contains 'events') {
        @($parsed.events).Count
    } else {
        0
    }

    Write-EvidenceUtf8NoBom `
        -Path (Join-Path $metadataRoot 'query.json') `
        -Content (([ordered]@{
            LogGroup = $logGroup
            Region = $region
            StartTimeUtc = $StartTimeUtc.ToString('o')
            EndTimeUtc = $EndTimeUtc.ToString('o')
            FilterPattern = if ($Collector.ContainsKey('FilterPattern')) {
                [string]$Collector.FilterPattern
            } else {
                ''
            }
        }) | ConvertTo-Json -Depth 6)
    Write-EvidenceUtf8NoBom `
        -Path (Join-Path $sanitizedRoot 'events.json') `
        -Content (Protect-SecurityEvidenceText -Text $json)

    return [pscustomobject]@{
        Name = [string]$Collector.Name
        Type = 'CloudWatchLogs'
        Status = if ($eventCount -gt 0) { 'Succeeded' } else { 'Empty' }
        Detail = "Events in time window=$eventCount"
        Items = $eventCount
        Destination = $sanitizedRoot
    }
}

function Get-EvidenceCloudWatchQueryText {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Evidence query file is unavailable: $Path"
    }
    $queryText = (@(Get-Content -LiteralPath $Path -Encoding UTF8 | Where-Object {
        $_ -notmatch '^\s*#'
    }) -join "`n").Trim()
    if (-not $queryText) {
        throw "Evidence query is empty after comments are removed: $Path"
    }
    if ($queryText.Length -gt 10000) {
        throw "Evidence query exceeds the CloudWatch Logs Insights 10000-character limit: $Path"
    }
    return $queryText
}

function ConvertFrom-EvidenceCloudWatchQueryRows {
    param([AllowNull()]$Rows)

    return @($Rows | ForEach-Object {
        $row = [ordered]@{}
        foreach ($cell in @($_)) {
            if ($null -eq $cell -or
                $cell.PSObject.Properties.Name -notcontains 'field') {
                continue
            }
            $field = [string]$cell.field
            if (-not $field) {
                continue
            }
            $row[$field] = if ($cell.PSObject.Properties.Name -contains 'value') {
                [string]$cell.value
            } else {
                ''
            }
        }
        [pscustomobject]$row
    })
}

function Invoke-EvidenceCloudWatchInsightsQuery {
    param(
        [Parameter(Mandatory)][hashtable]$Query,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][datetime]$StartTimeUtc,
        [Parameter(Mandatory)][datetime]$EndTimeUtc,
        [scriptblock]$Invoker
    )

    $queryPackRoot = Join-Path (
        [string]$Context.TerraformRoot
    ) ([string]$Config.Evidence.QueryPackRoot)
    $queryPath = Join-Path $queryPackRoot ([string]$Query.QueryFile)
    $queryText = Get-EvidenceCloudWatchQueryText -Path $queryPath
    $logGroup = Resolve-EvidenceTemplate `
        -Value ([string]$Query.LogGroup) `
        -Tokens $Context.Tokens
    $region = Get-EvidenceRegion -Collector $Query -Context $Context

    $scanEndTimeUtc = $EndTimeUtc
    if ($Query.ContainsKey('DeliveryGraceMinutes')) {
        $deliveryGraceMinutes = [int]$Query.DeliveryGraceMinutes
        if ($deliveryGraceMinutes -lt 0 -or $deliveryGraceMinutes -gt 30) {
            throw "Evidence query DeliveryGraceMinutes must be between 0 and 30: $($Query.Name)"
        }
        $scanEndTimeUtc = $EndTimeUtc.AddMinutes($deliveryGraceMinutes)
    }

    $startJson = Invoke-EvidenceBoundedRetry -MaxAttempts 3 -DelaySeconds 2 -Operation {
        Invoke-EvidenceNative `
            -FilePath 'aws' `
            -ArgumentList @(
                'logs', 'start-query',
                '--query-language', 'CWLI',
                '--log-group-name', $logGroup,
                '--start-time', ([DateTimeOffset]$StartTimeUtc).ToUnixTimeSeconds().ToString(),
                '--end-time', ([DateTimeOffset]$scanEndTimeUtc).ToUnixTimeSeconds().ToString(),
                '--query-string', $queryText,
                '--limit', '10000',
                '--profile', [string]$Context.AwsProfile,
                '--region', $region,
                '--output', 'json'
            ) `
            -Invoker $Invoker
    }
    $start = $startJson | ConvertFrom-Json
    $queryId = if ($start.PSObject.Properties.Name -contains 'queryId') {
        [string]$start.queryId
    } else {
        ''
    }
    if (-not $queryId) {
        throw "CloudWatch Logs Insights did not return a queryId: $($Query.Name)"
    }

    $maxPollAttempts = if ($Query.ContainsKey('MaxPollAttempts')) {
        [int]$Query.MaxPollAttempts
    } else {
        30
    }
    $pollDelaySeconds = if ($Query.ContainsKey('PollDelaySeconds')) {
        [int]$Query.PollDelaySeconds
    } else {
        2
    }
    $response = $null
    for ($attempt = 1; $attempt -le $maxPollAttempts; $attempt++) {
        $resultJson = Invoke-EvidenceNative `
            -FilePath 'aws' `
            -ArgumentList @(
                'logs', 'get-query-results',
                '--query-id', $queryId,
                '--profile', [string]$Context.AwsProfile,
                '--region', $region,
                '--output', 'json'
            ) `
            -Invoker $Invoker
        $response = $resultJson | ConvertFrom-Json
        $status = [string]$response.status
        if ($status -ceq 'Complete') {
            break
        }
        if ($status -notin @('Scheduled', 'Running')) {
            throw "CloudWatch Logs Insights query '$($Query.Name)' ended with status '$status'."
        }
        if ($attempt -lt $maxPollAttempts -and $pollDelaySeconds -gt 0) {
            Start-Sleep -Seconds $pollDelaySeconds
        }
    }
    if ($null -eq $response -or [string]$response.status -cne 'Complete') {
        throw "CloudWatch Logs Insights query '$($Query.Name)' did not complete within the bounded polling window."
    }

    # PowerShell unwraps empty and single-item pipeline output. Force an array
    # so zero-result queries remain successful evidence instead of failing on
    # a missing Count property.
    $rows = @(ConvertFrom-EvidenceCloudWatchQueryRows -Rows $response.results)
    $serviceRowCount = $rows.Count
    $eventTimeField = if ($Query.ContainsKey('EventTimeField')) {
        [string]$Query.EventTimeField
    } else {
        ''
    }
    if ($eventTimeField) {
        $rows = @($rows | Where-Object {
            $property = $_.PSObject.Properties[$eventTimeField]
            if ($null -eq $property -or -not [string]$property.Value) {
                return $false
            }
            try {
                $eventTime = [datetimeoffset]::Parse(
                    [string]$property.Value,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal
                ).UtcDateTime
                return $eventTime -ge $StartTimeUtc -and $eventTime -le $EndTimeUtc
            } catch {
                return $false
            }
        })
    }
    $rowCount = $rows.Count
    $outputRoot = Join-Path (Join-Path $BundleRoot 'results') 'cloudwatch'
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    $outputPath = Join-Path $outputRoot "$($Query.Name).json"
    $document = [ordered]@{
        QueryName = [string]$Query.Name
        QueryFile = [string]$Query.QueryFile
        QuerySha256 = Get-EvidenceStringHash -Value $queryText
        QueryId = $queryId
        LogGroup = $logGroup
        Region = $region
        StartTimeUtc = $StartTimeUtc.ToString('o')
        EndTimeUtc = $EndTimeUtc.ToString('o')
        ScanEndTimeUtc = $scanEndTimeUtc.ToString('o')
        EventTimeField = $eventTimeField
        ServiceRowCount = $serviceRowCount
        Status = [string]$response.status
        Statistics = if ($response.PSObject.Properties.Name -contains 'statistics') {
            $response.statistics
        } else {
            $null
        }
        Rows = $rows
    }
    Write-EvidenceUtf8NoBom `
        -Path $outputPath `
        -Content (Protect-SecurityEvidenceText -Text (
            $document | ConvertTo-Json -Depth $script:EvidenceJsonDepth
        ))

    return [pscustomobject]@{
        Name = [string]$Query.Name
        Type = 'CloudWatchLogsInsights'
        Status = 'Succeeded'
        Detail = "Query complete; rows=$rowCount; serviceRows=$serviceRowCount"
        Items = $rowCount
        Destination = $outputPath
    }
}

function Get-EvidenceFileIndex {
    param(
        [Parameter(Mandatory)][string]$BundleRoot,
        [Parameter(Mandatory)][string]$Algorithm,
        [string[]]$ExcludeNames = @()
    )

    $prefix = $BundleRoot.TrimEnd('\') + '\'
    return @(Get-ChildItem -LiteralPath $BundleRoot -File -Recurse |
        Where-Object {
            $_.FullName -notlike "$(Join-Path $BundleRoot '_tmp')\*" -and
            $_.Name -notin $ExcludeNames
        } |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                Path = $_.FullName.Substring($prefix.Length).Replace('\', '/')
                Length = [long]$_.Length
                Algorithm = $Algorithm
                Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm $Algorithm).Hash
            }
        })
}

function Invoke-SecurityEvidenceCollection {
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

    $now = (Get-Date).ToUniversalTime()
    if (-not $PSBoundParameters.ContainsKey('EndTimeUtc')) {
        $EndTimeUtc = $now
    } else {
        $EndTimeUtc = $EndTimeUtc.ToUniversalTime()
    }
    if (-not $PSBoundParameters.ContainsKey('StartTimeUtc')) {
        $windowMinutes = if ($Config.Evidence.ContainsKey('DefaultWindowMinutes')) {
            [int]$Config.Evidence.DefaultWindowMinutes
        } else {
            60
        }
        $StartTimeUtc = $EndTimeUtc.AddMinutes(-$windowMinutes)
    } else {
        $StartTimeUtc = $StartTimeUtc.ToUniversalTime()
    }
    if ($StartTimeUtc -ge $EndTimeUtc) {
        throw 'Evidence StartTimeUtc must be earlier than EndTimeUtc.'
    }
    $eventEndTimeUtc = $EndTimeUtc.AddSeconds($EventTailSeconds)
    $s3EndTimeUtc = $eventEndTimeUtc.AddMinutes($S3DeliveryGraceMinutes)

    $tokens = @{
        AccountId = [string]$Context.AccountId
        ProjectName = [string]$Context.ProjectName
        PrimaryRegion = [string]$Context.PrimaryRegion
        DrRegion = [string]$Context.DrRegion
        UserHome = [string]$HOME
    }
    $Context.Tokens = $tokens
    if (-not $EvidenceRoot) {
        $EvidenceRoot = Resolve-EvidenceTemplate `
            -Value ([string]$Config.Evidence.RootDefault) `
            -Tokens $tokens
    }
    New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
    $EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path

    if (-not $ExperimentId) {
        $ExperimentId = 'exp-' + $now.ToString('yyyyMMddTHHmmssZ') + '-' +
            [guid]::NewGuid().ToString('N').Substring(0, 8)
    }
    if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
        throw 'ExperimentId contains unsafe path characters.'
    }
    $ScenarioId = [regex]::Replace($ScenarioId, '[^A-Za-z0-9._-]', '_')
    if (-not $ScenarioId) {
        $ScenarioId = 'unspecified'
    }

    $bundleRoot = Join-Path $EvidenceRoot $ExperimentId
    foreach ($directory in @('source', 'queries', 'results', 'screenshots', 'sanitized')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $bundleRoot $directory) | Out-Null
    }
    if ($Config.Evidence.ContainsKey('QueryPackRoot') -and
        [string]$Config.Evidence.QueryPackRoot) {
        $queryPackRoot = Join-Path (
            [string]$Context.TerraformRoot
        ) ([string]$Config.Evidence.QueryPackRoot)
        if (Test-Path -LiteralPath $queryPackRoot -PathType Container) {
            Copy-Item `
                -Path (Join-Path $queryPackRoot '*') `
                -Destination (Join-Path $bundleRoot 'queries') `
                -Recurse `
                -Force
        }
    }

    $started = (Get-Date).ToUniversalTime()
    $results = New-Object System.Collections.Generic.List[object]
    $strictFailures = New-Object System.Collections.Generic.List[string]
    foreach ($collector in @($Config.Evidence.Collectors)) {
        $isRequired = (
            $RequiredCollectorNames -contains [string]$collector.Name
        ) -or (
            $RequiredCollectorNames.Count -eq 0 -and
            $collector.ContainsKey('Required') -and
            [bool]$collector.Required
        )
        try {
            $result = switch ([string]$collector.Type) {
                'S3Prefix' {
                    Invoke-EvidenceS3PrefixCollector `
                        -Collector $collector `
                        -Context $Context `
                        -BundleRoot $bundleRoot `
                        -StartTimeUtc $StartTimeUtc `
                        -EndTimeUtc $s3EndTimeUtc `
                        -Invoker $Invoker
                }
                'CloudWatchLogs' {
                    Invoke-EvidenceCloudWatchLogsCollector `
                        -Collector $collector `
                        -Context $Context `
                        -BundleRoot $bundleRoot `
                        -StartTimeUtc $StartTimeUtc `
                        -EndTimeUtc $eventEndTimeUtc `
                        -Invoker $Invoker
                }
                default {
                    throw "Unsupported collector type: $($collector.Type)"
                }
            }
            $result | Add-Member -NotePropertyName Required -NotePropertyValue $isRequired
            $results.Add($result)
            if ($RequireEvidence -and $isRequired -and $result.Status -ne 'Succeeded') {
                $strictFailures.Add("$($collector.Name): $($result.Status)")
            }
        } catch {
            $safeMessage = Protect-EvidenceScalar -Value $_.Exception.Message
            $results.Add([pscustomobject]@{
                Name = [string]$collector.Name
                Type = [string]$collector.Type
                Status = 'Failed'
                Detail = $safeMessage
                Items = 0
                Destination = ''
                Required = $isRequired
            })
            Write-Warning "Evidence collector failed: $($collector.Name)"
            if ($RequireEvidence -and $isRequired) {
                $strictFailures.Add("$($collector.Name): $safeMessage")
            }
        }
    }

    if ($RunQueries) {
        $configuredQueries = if ($Config.Evidence.ContainsKey('Queries')) {
            @($Config.Evidence.Queries)
        } else {
            @()
        }
        $matchingQueries = @($configuredQueries | Where-Object {
            [string]$ScenarioId -in @($_.ScenarioIds | ForEach-Object {
                [string]$_
            })
        })
        if ($matchingQueries.Count -eq 0) {
            throw "No evidence queries are mapped to ScenarioId '$ScenarioId'."
        }
        foreach ($query in $matchingQueries) {
            $isRequired = $query.ContainsKey('Required') -and [bool]$query.Required
            try {
                $result = switch ([string]$query.Type) {
                    'CloudWatchLogsInsights' {
                        Invoke-EvidenceCloudWatchInsightsQuery `
                            -Query $query `
                            -Config $Config `
                            -Context $Context `
                            -BundleRoot $bundleRoot `
                            -StartTimeUtc $StartTimeUtc `
                            -EndTimeUtc $eventEndTimeUtc `
                            -Invoker $Invoker
                    }
                    default {
                        throw "Unsupported evidence query type: $($query.Type)"
                    }
                }
                $result | Add-Member -NotePropertyName Required -NotePropertyValue $isRequired
                $results.Add($result)
                if ($RequireEvidence -and $isRequired -and $result.Status -ne 'Succeeded') {
                    $strictFailures.Add("$($query.Name): $($result.Status)")
                }
            } catch {
                $safeMessage = Protect-EvidenceScalar -Value $_.Exception.Message
                $results.Add([pscustomobject]@{
                    Name = [string]$query.Name
                    Type = [string]$query.Type
                    Status = 'Failed'
                    Detail = $safeMessage
                    Items = 0
                    Destination = ''
                    Required = $isRequired
                })
                Write-Warning "Evidence query failed: $($query.Name)"
                if ($RequireEvidence -and $isRequired) {
                    $strictFailures.Add("$($query.Name): $safeMessage")
                }
            }
        }
    }

    $algorithm = [string]$Config.Evidence.HashAlgorithm
    $filesBeforeManifest = Get-EvidenceFileIndex `
        -BundleRoot $bundleRoot `
        -Algorithm $algorithm `
        -ExcludeNames @('manifest.json', 'SHA256SUMS.txt')
    $missingContext = @('GitCommit', 'ImageSha', 'ArgoRevision') | Where-Object {
        -not $Context.ContainsKey($_) -or -not [string]$Context[$_]
    }
    $gitCommit = if ($Context.ContainsKey('GitCommit')) {
        [string]$Context.GitCommit
    } else {
        ''
    }
    $imageSha = if ($Context.ContainsKey('ImageSha')) {
        [string]$Context.ImageSha
    } else {
        ''
    }
    $argoRevision = if ($Context.ContainsKey('ArgoRevision')) {
        [string]$Context.ArgoRevision
    } else {
        ''
    }
    $manifest = [ordered]@{
        SchemaVersion = 2
        ExperimentId = $ExperimentId
        ScenarioId = $ScenarioId
        Phase = $Phase
        StartedAtUtc = $started.ToString('o')
        FinishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Window = @{
            StartTimeUtc = $StartTimeUtc.ToString('o')
            EndTimeUtc = $EndTimeUtc.ToString('o')
            EventTailSeconds = $EventTailSeconds
            EventEndTimeUtc = $eventEndTimeUtc.ToString('o')
            S3DeliveryGraceMinutes = $S3DeliveryGraceMinutes
            S3EndTimeUtc = $s3EndTimeUtc.ToString('o')
        }
        Aws = @{
            AccountId = [string]$Context.AccountId
            PrimaryRegion = [string]$Context.PrimaryRegion
            DrRegion = [string]$Context.DrRegion
        }
        GitCommit = $gitCommit
        ImageSha = $imageSha
        ArgoRevision = $argoRevision
        MissingContext = @($missingContext)
        RequireEvidence = [bool]$RequireEvidence
        QueryExecutionRequested = [bool]$RunQueries
        Results = @($results | ForEach-Object { $_ })
        Files = @($filesBeforeManifest)
    }
    $manifestPath = Join-Path $bundleRoot 'manifest.json'
    Write-EvidenceUtf8NoBom `
        -Path $manifestPath `
        -Content ($manifest | ConvertTo-Json -Depth $script:EvidenceJsonDepth)
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm $algorithm).Hash.ToLowerInvariant()
    Write-EvidenceUtf8NoBom `
        -Path "$manifestPath.sha256" `
        -Content "$manifestHash  manifest.json`n"

    $sumEntries = Get-EvidenceFileIndex `
        -BundleRoot $bundleRoot `
        -Algorithm $algorithm `
        -ExcludeNames @('SHA256SUMS.txt')
    $sumLines = @($sumEntries | ForEach-Object {
        "$($_.Hash)  $($_.Path)"
    })
    Write-EvidenceUtf8NoBom `
        -Path (Join-Path $bundleRoot 'SHA256SUMS.txt') `
        -Content (($sumLines -join "`n") + "`n")
    Remove-Item -LiteralPath (Join-Path $bundleRoot '_tmp') -Recurse -Force -ErrorAction SilentlyContinue

    if ($strictFailures.Count -gt 0) {
        throw "Required evidence is incomplete. Runtime teardown was not authorized by Strict Mode:`n$($strictFailures -join "`n")"
    }

    return [pscustomobject]@{
        Root = $EvidenceRoot
        BundleRoot = $bundleRoot
        ManifestPath = $manifestPath
        Results = @($results | ForEach-Object { $_ })
        ExperimentId = $ExperimentId
    }
}

Export-ModuleMember -Function @(
    'Invoke-EvidenceBoundedRetry',
    'Protect-SecurityEvidenceText',
    'Invoke-SecurityEvidenceCollection'
)
