#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [ValidateRange(60,420)][int]$UploadTimeoutSeconds = 300,
    [ValidateRange(1,30)][int]$PollIntervalSeconds = 5,
    [string]$ConfirmUpload = '',
    [switch]$AllowLegacyGt09Dispatcher,
    [switch]$ConsoleOnly,
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ShuffleSocValidatorPackage.ps1')

function Get-SafeShuffleUploadFailureDetail {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ResponseText)

    $bytes = [Text.Encoding]::UTF8.GetBytes($ResponseText)
    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    $fallback = "response_bytes=$($bytes.Length); response_sha256=$hash"
    if (-not $ResponseText -or $bytes.Length -gt 16KB) {
        return $fallback
    }

    try { $parsed = $ResponseText | ConvertFrom-Json -Depth 8 }
    catch { return $fallback }
    foreach ($field in @('reason','message','error')) {
        $property = $parsed.PSObject.Properties[$field]
        if (-not $property -or $property.Value -isnot [string]) { continue }
        $candidate = ([string]$property.Value -replace '\s+', ' ').Trim()
        if (-not $candidate -or $candidate.Length -gt 240) { continue }
        if ($candidate -notmatch '^[\x20-\x7E]+$') { continue }
        if ($candidate -match '(?i)(authorization|bearer|cookie|password|secret|token|api[-_ ]?key|github_pat_|ghp_)') {
            continue
        }
        return "$field=$candidate"
    }
    return $fallback
}

function Get-SocShuffleUploadProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-SocShuffleUploadPropertyNames {
    [CmdletBinding()]
    param([AllowNull()][object]$Object)

    if ($null -eq $Object) { return @() }
    if ($Object -is [Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object { [string]$_ })
    }
    return @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Get-SocShuffleUploadAppItems {
    [CmdletBinding()]
    param([AllowNull()][object]$Response)

    if ($null -eq $Response) { return @() }
    if ($Response -is [array]) { return @($Response) }
    $apps = Get-SocShuffleUploadProperty -Object $Response -Name 'apps'
    if ($null -ne $apps) { return @($apps) }
    $items = Get-SocShuffleUploadProperty -Object $Response -Name 'items'
    if ($null -ne $items) { return @($items) }
    $body = Get-SocShuffleUploadProperty -Object $Response -Name 'body'
    if ($null -ne $body) { return @(Get-SocShuffleUploadAppItems -Response $body) }
    $data = Get-SocShuffleUploadProperty -Object $Response -Name 'data'
    if ($null -ne $data) {
        $nestedApps = Get-SocShuffleUploadProperty -Object $data -Name 'apps'
        if ($null -ne $nestedApps) { return @($nestedApps) }
        $nestedItems = Get-SocShuffleUploadProperty -Object $data -Name 'items'
        if ($null -ne $nestedItems) { return @($nestedItems) }
    }
    return @()
}

function Test-SocShuffleUploadAppListShape {
    [CmdletBinding()]
    param([AllowNull()][object]$Response)

    if ($null -eq $Response) { return $false }
    if ($Response -is [array]) { return $true }
    $names = @(Get-SocShuffleUploadPropertyNames -Object $Response)
    foreach ($name in @('apps','items')) {
        if ($name -notin $names) { continue }
        $value = $null
        if ($Response -is [Collections.IDictionary]) {
            $value = $Response[$name]
        } else {
            $value = $Response.PSObject.Properties[$name].Value
        }
        if ($null -ne $value -and
            $value -is [Collections.IEnumerable] -and
            $value -isnot [string]) {
            return $true
        }
    }
    foreach ($name in @('body','data')) {
        if ($name -notin $names) { continue }
        $value = $null
        if ($Response -is [Collections.IDictionary]) {
            $value = $Response[$name]
        } else {
            $value = $Response.PSObject.Properties[$name].Value
        }
        if ($name -ceq 'data' -and
            $value -is [Collections.IEnumerable] -and
            $value -isnot [string] -and
            $value -isnot [Collections.IDictionary] -and
            $value -isnot [pscustomobject]) {
            # The observed /api/v1/apps response is a top-level array.  Do not
            # accept an unproven direct data sequence that the item extractor
            # cannot identify without ambiguity.
            return $false
        }
        if (Test-SocShuffleUploadAppListShape -Response $value) {
            return $true
        }
    }
    return $false
}

function Test-SocShuffleUploadPaginationFree {
    [CmdletBinding()]
    param([AllowNull()][object]$Container)

    if ($null -eq $Container -or $Container -is [array]) { return $true }
    if ($Container -isnot [Collections.IDictionary] -and
        $Container -isnot [psobject]) { return $false }
    $names = @(Get-SocShuffleUploadPropertyNames -Object $Container)
    foreach ($signal in @('cursor','next_cursor','has_more','more','total')) {
        if (@($names | Where-Object { [string]$_ -ieq $signal }).Count -ne 0) {
            return $false
        }
    }
    foreach ($nestedName in @('body','data')) {
        if (@($names | Where-Object { [string]$_ -ieq $nestedName }).Count -eq 0) {
            continue
        }
        $nested = $null
        if ($Container -is [Collections.IDictionary]) {
            $key = @($Container.Keys | Where-Object {
                [string]$_ -ieq $nestedName
            })[0]
            $nested = $Container[$key]
        } else {
            $property = @($Container.PSObject.Properties | Where-Object {
                [string]$_.Name -ieq $nestedName
            })[0]
            $nested = $property.Value
        }
        if (-not (Test-SocShuffleUploadPaginationFree -Container $nested)) {
            return $false
        }
    }
    return $true
}

function Resolve-SocShuffleCompleteAppListEnvelope {
    [CmdletBinding()]
    param([AllowNull()][object]$Envelope)

    if ($null -eq $Envelope -or $Envelope -is [array]) {
        throw 'The Shuffle App list metadata envelope is missing.'
    }
    $envelopeNames = @(Get-SocShuffleUploadPropertyNames -Object $Envelope)
    if ('body' -notin $envelopeNames -or 'response_headers' -notin $envelopeNames) {
        throw 'The Shuffle App list metadata envelope is incomplete.'
    }
    $body = $null
    $headers = $null
    if ($Envelope -is [Collections.IDictionary]) {
        $body = $Envelope['body']
        $headers = $Envelope['response_headers']
    } else {
        $body = $Envelope.PSObject.Properties['body'].Value
        $headers = $Envelope.PSObject.Properties['response_headers'].Value
    }
    if ($null -eq $body -or $null -eq $headers -or $headers -is [array] -or
        ($headers -isnot [Collections.IDictionary] -and $headers -isnot [psobject])) {
        throw 'The Shuffle App list body or response_headers shape is invalid.'
    }

    $headerNames = @(Get-SocShuffleUploadPropertyNames -Object $headers)
    $truncateNames = @($headerNames | Where-Object {
        [string]$_ -ieq 'X-SHUFFLE_TRUNCATED'
    })
    if ($truncateNames.Count -gt 1) {
        throw 'The Shuffle App list truncation header is ambiguous.'
    }
    if ($truncateNames.Count -eq 1) {
        $truncateValue = $null
        if ($headers -is [Collections.IDictionary]) {
            $key = @($headers.Keys | Where-Object {
                [string]$_ -ieq 'X-SHUFFLE_TRUNCATED'
            })[0]
            $truncateValue = $headers[$key]
        } else {
            $property = @($headers.PSObject.Properties | Where-Object {
                [string]$_.Name -ieq 'X-SHUFFLE_TRUNCATED'
            })[0]
            $truncateValue = $property.Value
        }
        $truncateValues = @($truncateValue)
        if ($truncateValues.Count -ne 1 -or
            $truncateValues[0] -isnot [string] -or
            [string]$truncateValues[0] -cne 'false') {
            throw 'The Shuffle App list was truncated or its truncation state is ambiguous.'
        }
    }
    if (-not (Test-SocShuffleUploadPaginationFree -Container $body) -or
        -not (Test-SocShuffleUploadAppListShape -Response $body)) {
        throw 'The Shuffle App list is paginated or malformed.'
    }
    $items = @(Get-SocShuffleUploadAppItems -Response $body)
    if ($items.Count -ge 1000) {
        throw 'The Shuffle App list reached the fixed completeness ceiling.'
    }
    return [pscustomobject][ordered]@{
        body=$body
        items=$items
    }
}

function Get-SocShuffleUploadExactApps {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Response,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Version
    )

    return @(Get-SocShuffleUploadAppItems -Response $Response | Where-Object {
        $appVersions = @(
            (Get-SocShuffleUploadProperty -Object $_ -Name 'app_version'),
            (Get-SocShuffleUploadProperty -Object $_ -Name 'version')
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        [string](Get-SocShuffleUploadProperty -Object $_ -Name 'name') -ceq $Name -and
        @($appVersions | Where-Object { [string]$_ -ceq $Version }).Count -gt 0
    })
}

function Get-SocShuffleUploadAppIdMatches {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Response,
        [Parameter(Mandatory)][string]$Id
    )

    if ($Id -cnotmatch '^[a-f0-9]{32}$') { return @() }
    return @(Get-SocShuffleUploadAppItems -Response $Response | Where-Object {
        [string](Get-SocShuffleUploadProperty -Object $_ -Name 'id') -ceq $Id
    })
}

function Test-SocShuffleUploadExactBoolean {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Expected
    )

    if ($Name -notin @(Get-SocShuffleUploadPropertyNames -Object $Object)) {
        return $false
    }
    $value = Get-SocShuffleUploadProperty -Object $Object -Name $Name
    return ($value -is [bool] -and [bool]$value -eq $Expected)
}

function New-SocShuffleUploadContractFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'baseline_read','baseline_existing','submission_contract',
            'client_rejected','unexpected_status','readback_read',
            'readback_duplicate','readback_identity','readback_timeout',
            'cleanup_failed'
        )][string]$Category,
        [string]$AppName = '',
        [ValidateRange(0,599)][int]$HttpStatus = 0,
        [string]$SafeDetail = ''
    )

    $suffix = if ($AppName -in @(
        'AWS Topology SOC Validator',
        'AWS Topology SOC GitHub Dispatcher',
        'SOC Rule110 Auto Contain'
    )) { "; app=$AppName" } else { '' }
    $statusSuffix = if ($HttpStatus -ge 100) { "; http_status=$HttpStatus" } else { '' }
    $detailSuffix = if ($SafeDetail -match '^[\x20-\x7E]{1,320}$') {
        "; $SafeDetail"
    } else { '' }
    return "Shuffle App upload failed [$Category$suffix$statusSuffix$detailSuffix]. Raw response, URI, Header, and credential details were withheld."
}

function New-SocShuffleAppPackageContent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$App)

    $bytesProperty = $App.PSObject.Properties['PackageBytes']
    $fileNameProperty = $App.PSObject.Properties['PackageFileName']
    if ($null -eq $bytesProperty -or $bytesProperty.Value -isnot [byte[]] -or
        $bytesProperty.Value.Length -le 0 -or $bytesProperty.Value.Length -gt 5MB -or
        $null -eq $fileNameProperty -or
        [string]$fileNameProperty.Value -cnotmatch '^[A-Za-z0-9._-]+\.zip$') {
        throw 'The verified App byte snapshot contract is invalid.'
    }
    [byte[]]$snapshot = $bytesProperty.Value
    $snapshotHash = Get-SocShuffleValidatorSha256 -Bytes $snapshot
    if ($snapshotHash -cne [string]$App.PackageSha256) {
        throw 'The verified App byte snapshot changed before upload.'
    }
    $fileContent = [Net.Http.ByteArrayContent]::new($snapshot)
    $fileContent.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new(
        'application/zip'
    )
    return $fileContent
}

function Invoke-SocShuffleMultipartSubmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$App,
        [Parameter(Mandatory)][uri]$UploadUri,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$OrgId,
        [ValidateRange(5,60)][int]$TimeoutSeconds = 60
    )

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds($TimeoutSeconds)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $UploadUri)
    $content = [Net.Http.MultipartFormDataContent]::new()
    try {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bearer', $ApiKey
        )
        [void]$request.Headers.TryAddWithoutValidation('Org-Id', $OrgId)
        $fileContent = New-SocShuffleAppPackageContent -App $App
        $content.Add(
            $fileContent,
            'shuffle_file',
            [string]$App.PackageFileName
        )
        $request.Content = $content
        try {
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
        } catch [OperationCanceledException] {
            return [pscustomobject][ordered]@{
                kind='timeout';candidate_id='';candidate_present=$false;
                candidate_valid=$true
            }
        } catch {
            return [pscustomobject][ordered]@{
                kind='transport';candidate_id='';candidate_present=$false;
                candidate_valid=$true
            }
        }
        try {
            $status = [int]$response.StatusCode
            $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($status -ge 200 -and $status -lt 300) {
                $candidateId = ''
                $candidatePresent = $false
                $candidateValid = $true
                try {
                    $parsed = $responseText | ConvertFrom-Json -Depth 8
                    $idValue = Get-SocShuffleUploadProperty -Object $parsed -Name 'id'
                    if (-not [string]::IsNullOrWhiteSpace([string]$idValue)) {
                        $candidatePresent = $true
                        $candidateValid = [string]$idValue -cmatch '^[a-f0-9]{32}$'
                        if ($candidateValid) { $candidateId = [string]$idValue }
                    }
                } catch {
                    $candidatePresent = $false
                    $candidateValid = $true
                }
                return [pscustomobject][ordered]@{
                    kind='http_2xx';candidate_id=$candidateId;
                    candidate_present=$candidatePresent;candidate_valid=$candidateValid
                }
            }
            if ($status -eq 502) { $kind = 'http_502' }
            elseif ($status -ge 500 -and $status -lt 600) { $kind = 'http_5xx' }
            elseif ($status -ge 400 -and $status -lt 500) { $kind = 'http_4xx' }
            else { $kind = 'http_other' }
            return [pscustomobject][ordered]@{
                kind=$kind;candidate_id='';candidate_present=$false;
                candidate_valid=$true;http_status=$status;
                safe_detail=(Get-SafeShuffleUploadFailureDetail -ResponseText $responseText)
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $content.Dispose()
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-SocShuffleUploadCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]
        [Collections.Generic.List[object]]$CleanupRecords,
        [Parameter(Mandatory)][scriptblock]$DeleteApp,
        [Parameter(Mandatory)][scriptblock]$ListApps
    )

    $failed = $false
    for ($index = $CleanupRecords.Count - 1; $index -ge 0; $index--) {
        $record = $CleanupRecords[$index]
        if (-not [bool]$record.eligible) { continue }
        try {
            $beforeDelete = & $ListApps
            $beforeComplete = Resolve-SocShuffleCompleteAppListEnvelope `
                -Envelope $beforeDelete
            $beforeExact = @(Get-SocShuffleUploadExactApps -Response $beforeComplete.body `
                -Name ([string]$record.name) -Version ([string]$record.version))
            $beforeIds = @(Get-SocShuffleUploadAppIdMatches `
                -Response $beforeComplete.body -Id ([string]$record.id))
            if ($beforeExact.Count -eq 0) {
                if ($beforeIds.Count -ne 0) { $failed = $true }
                continue
            }
            if ($beforeExact.Count -ne 1 -or
                [string](Get-SocShuffleUploadProperty -Object $beforeExact[0] -Name 'id') -cne
                    [string]$record.id -or
                $beforeIds.Count -ne 1) {
                $failed = $true
                continue
            }
            [void](& $DeleteApp ([string]$record.id))
            $readback = & $ListApps
            $readbackComplete = Resolve-SocShuffleCompleteAppListEnvelope `
                -Envelope $readback
            $remaining = @(Get-SocShuffleUploadExactApps -Response $readbackComplete.body `
                -Name ([string]$record.name) -Version ([string]$record.version))
            $remainingIds = @(Get-SocShuffleUploadAppIdMatches `
                -Response $readbackComplete.body -Id ([string]$record.id))
            if ($remaining.Count -ne 0 -or $remainingIds.Count -ne 0) {
                $failed = $true
            }
        } catch {
            $failed = $true
        }
    }
    return (-not $failed)
}

function Invoke-SocShuffleAppUploadTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Apps,
        [Parameter(Mandatory)][scriptblock]$ListApps,
        [Parameter(Mandatory)][scriptblock]$UploadApp,
        [Parameter(Mandatory)][scriptblock]$DeleteApp,
        [scriptblock]$UtcNow = { [datetimeoffset]::UtcNow },
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds },
        [ValidateRange(1,420)][int]$PollTimeoutSeconds = 420,
        [ValidateRange(1,30)][int]$PollIntervalSeconds = 5
    )

    if ($Apps.Count -lt 1) {
        throw (New-SocShuffleUploadContractFailure -Category 'submission_contract')
    }
    $identitySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($app in $Apps) {
        $identity = "$( [string]$app.Name)`n$( [string]$app.Version)"
        if (-not $identitySet.Add($identity) -or
            [string]$app.PackageSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw (New-SocShuffleUploadContractFailure -Category 'submission_contract')
        }
    }

    try {
        $baseline = & $ListApps
        $baselineComplete = Resolve-SocShuffleCompleteAppListEnvelope -Envelope $baseline
    }
    catch {
        throw (New-SocShuffleUploadContractFailure -Category 'baseline_read')
    }
    foreach ($app in $Apps) {
        $existing = @(Get-SocShuffleUploadExactApps -Response $baselineComplete.body `
            -Name ([string]$app.Name) -Version ([string]$app.Version))
        if ($existing.Count -ne 0) {
            throw (New-SocShuffleUploadContractFailure -Category 'baseline_existing' `
                -AppName ([string]$app.Name))
        }
    }

    $results = [Collections.Generic.List[object]]::new()
    $cleanupRecords = [Collections.Generic.List[object]]::new()
    try {
        foreach ($app in $Apps) {
            try { $submission = & $UploadApp $app }
            catch {
                $submission = [pscustomobject][ordered]@{
                    kind='transport';candidate_id='';candidate_present=$false;
                    candidate_valid=$true
                }
            }
            $submittedAt = & $UtcNow
            $kind = [string](Get-SocShuffleUploadProperty -Object $submission -Name 'kind')
            $candidateId = [string](Get-SocShuffleUploadProperty -Object $submission -Name 'candidate_id')
            $candidatePresent = Get-SocShuffleUploadProperty -Object $submission -Name 'candidate_present'
            $candidateValid = Get-SocShuffleUploadProperty -Object $submission -Name 'candidate_valid'
            $httpStatus = [int](Get-SocShuffleUploadProperty -Object $submission -Name 'http_status')
            $safeDetail = [string](Get-SocShuffleUploadProperty -Object $submission -Name 'safe_detail')
            if ($kind -ceq 'http_4xx') {
                throw (New-SocShuffleUploadContractFailure -Category 'client_rejected' `
                    -AppName ([string]$app.Name) -HttpStatus $httpStatus `
                    -SafeDetail $safeDetail)
            }
            if ($kind -notin @('http_2xx','http_502','http_5xx','timeout','transport')) {
                throw (New-SocShuffleUploadContractFailure -Category 'unexpected_status' `
                    -AppName ([string]$app.Name))
            }
            if ($candidatePresent -isnot [bool] -or $candidateValid -isnot [bool]) {
                throw (New-SocShuffleUploadContractFailure -Category 'submission_contract' `
                    -AppName ([string]$app.Name))
            }
            $candidateIdentityInvalid = ([bool]$candidatePresent -and
                (-not [bool]$candidateValid -or $candidateId -cnotmatch '^[a-f0-9]{32}$'))
            $deadline = ([datetimeoffset](& $UtcNow)).AddSeconds($PollTimeoutSeconds)
            $cleanupRecord = $null
            $lastReadbackState = 'state=not_visible'
            while ($true) {
                try {
                    $readback = & $ListApps
                    $readbackComplete = Resolve-SocShuffleCompleteAppListEnvelope `
                        -Envelope $readback
                }
                catch {
                    throw (New-SocShuffleUploadContractFailure -Category 'readback_read' `
                        -AppName ([string]$app.Name))
                }
                $exact = @(Get-SocShuffleUploadExactApps -Response $readbackComplete.body `
                    -Name ([string]$app.Name) -Version ([string]$app.Version))
                if ($exact.Count -gt 1) {
                    if ($null -ne $cleanupRecord) { $cleanupRecord.eligible = $false }
                    throw (New-SocShuffleUploadContractFailure -Category 'readback_duplicate' `
                        -AppName ([string]$app.Name))
                }
                if ($exact.Count -eq 1) {
                    $id = [string](Get-SocShuffleUploadProperty -Object $exact[0] -Name 'id')
                    if ($id -cnotmatch '^[a-f0-9]{32}$' -or
                        $candidateIdentityInvalid -or
                        ([bool]$candidatePresent -and $candidateId -cne $id)) {
                        if ($null -ne $cleanupRecord) { $cleanupRecord.eligible = $false }
                        throw (New-SocShuffleUploadContractFailure -Category 'readback_identity' `
                            -AppName ([string]$app.Name))
                    }
                    if ($null -eq $cleanupRecord) {
                        $cleanupRecord = [pscustomobject][ordered]@{
                            name=[string]$app.Name;version=[string]$app.Version;
                            id=$id;eligible=$true
                        }
                        $cleanupRecords.Add($cleanupRecord)
                    } elseif ([string]$cleanupRecord.id -cne $id) {
                        $cleanupRecord.eligible = $false
                        throw (New-SocShuffleUploadContractFailure -Category 'readback_identity' `
                            -AppName ([string]$app.Name))
                    }
                    $ready =
                        (Test-SocShuffleUploadExactBoolean -Object $exact[0] -Name 'activated' -Expected $true) -and
                        (Test-SocShuffleUploadExactBoolean -Object $exact[0] -Name 'is_valid' -Expected $true) -and
                        (Test-SocShuffleUploadExactBoolean -Object $exact[0] -Name 'invalid' -Expected $false)
                    $lastReadbackState = "state=visible; activated=$([string](Get-SocShuffleUploadProperty -Object $exact[0] -Name 'activated')); is_valid=$([string](Get-SocShuffleUploadProperty -Object $exact[0] -Name 'is_valid')); invalid=$([string](Get-SocShuffleUploadProperty -Object $exact[0] -Name 'invalid'))"
                    if ($ready) {
                        $outcome = switch ($kind) {
                            'http_2xx' { 'confirmed_2xx' }
                            'http_502' { 'confirmed_async_502' }
                            'http_5xx' { 'confirmed_async_5xx' }
                            'timeout' { 'confirmed_async_timeout' }
                            'transport' { 'confirmed_async_transport' }
                        }
                        $results.Add([pscustomobject][ordered]@{
                            app_id=$id
                            local_package_sha256=[string]$app.PackageSha256
                            uploaded_at_utc=([datetimeoffset]$submittedAt).ToUniversalTime().ToString('o')
                            readback_at_utc=([datetimeoffset](& $UtcNow)).ToUniversalTime().ToString('o')
                            upload_outcome=$outcome
                        })
                        break
                    }
                }
                if ([datetimeoffset](& $UtcNow) -ge $deadline) {
                    throw (New-SocShuffleUploadContractFailure -Category 'readback_timeout' `
                        -AppName ([string]$app.Name) -SafeDetail $lastReadbackState)
                }
                & $Sleep $PollIntervalSeconds
            }
        }
    } catch {
        $originalMessage = [string]$_.Exception.Message
        $clean = Invoke-SocShuffleUploadCleanup -CleanupRecords $cleanupRecords `
            -DeleteApp $DeleteApp -ListApps $ListApps
        if (-not $clean) {
            throw (New-SocShuffleUploadContractFailure -Category 'cleanup_failed')
        }
        if ($originalMessage -match '^Shuffle App upload failed \[') {
            throw $originalMessage
        }
        throw (New-SocShuffleUploadContractFailure -Category 'submission_contract')
    }
    return @($results)
}

if ($NoRun.IsPresent) { return }

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Shuffle.psm1') -Force

$configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
$resolvedManifest = [IO.Path]::GetFullPath($ManifestPath)
if (-not (Test-Path -LiteralPath $resolvedManifest -PathType Leaf)) {
    throw 'The Shuffle SOC App bundle manifest does not exist.'
}
$manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json -Depth 20
if ([int]$manifest.schema_version -ne 1 -or
    [string]$manifest.artifact_kind -cne 'shuffle-soc-private-app-bundle' -or
    [bool]$manifest.secret_persisted -ne $false) {
    throw 'The Shuffle SOC App bundle manifest contract is invalid.'
}
$contractProperty = $manifest.PSObject.Properties['current_contract']
$legacyIncludedProperty = $manifest.PSObject.Properties['legacy_dispatcher_included']
if ($null -eq $contractProperty -or
    [string]$contractProperty.Value -cnotin @(
        'v2/100104', 'rule100110-auto-containment/v1'
    ) -or
    $null -eq $legacyIncludedProperty) {
    throw 'The Shuffle SOC App bundle contract or legacy inclusion state is invalid.'
}
$isRule100110Bundle = (
    [string]$contractProperty.Value -ceq 'rule100110-auto-containment/v1'
)
$expectedApps = @{
    'AWS Topology SOC Validator' = [pscustomobject]@{
        slug='aws-topology-soc-validator'
        contract_role='current-v2-validator'
        current_v2=$true
        entries=@('Dockerfile','api.yaml','requirements.txt','src/app.py')
    }
    'AWS Topology SOC GitHub Dispatcher' = [pscustomobject]@{
        slug='aws-topology-soc-github-dispatcher'
        contract_role='legacy-gt09-remediation-dispatcher'
        current_v2=$false
        entries=@('Dockerfile','api.yaml','requirements.txt','src/app.py','src/dispatcher.py')
    }
    'SOC Rule110 Auto Contain' = [pscustomobject]@{
        slug='aws-topology-soc-rule100110-auto-containment'
        contract_role='rule100110-auto-containment'
        current_v2=$false
        entries=@('Dockerfile','api.yaml','requirements.txt','src/app.py','src/autocontainment.py')
    }
}
$manifestApps = @($manifest.apps)
if ($manifestApps.Count -lt 1 -or
    @($manifestApps | Where-Object { [string]$_.name -notin $expectedApps.Keys }).Count -ne 0) {
    throw 'The bundle contains an unknown Shuffle App role.'
}
$validatorApps = @($manifestApps | Where-Object {
    [string]$_.name -ceq 'AWS Topology SOC Validator'
})
$legacyDispatcherApps = @($manifestApps | Where-Object {
    [string]$_.name -ceq 'AWS Topology SOC GitHub Dispatcher'
})
$rule100110Apps = @($manifestApps | Where-Object {
    [string]$_.name -ceq 'SOC Rule110 Auto Contain'
})
if ($isRule100110Bundle) {
    if ($manifestApps.Count -ne 1 -or $rule100110Apps.Count -ne 1 -or
        $validatorApps.Count -ne 0 -or $legacyDispatcherApps.Count -ne 0) {
        throw 'The Rule 100110 bundle must contain only its Auto Containment App.'
    }
} elseif ($validatorApps.Count -ne 1 -or $legacyDispatcherApps.Count -gt 1 -or
    $rule100110Apps.Count -ne 0) {
    throw 'The bundle must contain exactly one current v2 Validator and at most one legacy Dispatcher.'
}
$declaredLegacyIncluded = [bool]$legacyIncludedProperty.Value
if ($declaredLegacyIncluded -ne ($legacyDispatcherApps.Count -eq 1)) {
    throw 'The manifest legacy inclusion state does not match its App entries.'
}
if ($legacyDispatcherApps.Count -gt 0 -and -not $AllowLegacyGt09Dispatcher) {
    throw 'The legacy GT09 Dispatcher is excluded by default. Re-run with -AllowLegacyGt09Dispatcher only for legacy review.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$verifiedApps = [Collections.Generic.List[object]]::new()
foreach ($app in $manifestApps) {
    $definition = $expectedApps[[string]$app.name]
    if ([string]$app.version -cne '1.0.0' -or
        [string]$app.slug -cne [string]$definition.slug -or
        [string]$app.contract_role -cne [string]$definition.contract_role -or
        [bool]$app.current_v2 -ne [bool]$definition.current_v2 -or
        [string]$app.package_sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "The App version or package hash is invalid: $([string]$app.name)"
    }
    $packagePath = [IO.Path]::GetFullPath([string]$app.package_path)
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
        throw "A Shuffle App package is missing: $([string]$app.name)"
    }
    $packageInfo = Get-Item -LiteralPath $packagePath
    if ($packageInfo.Length -le 0 -or $packageInfo.Length -gt 5MB) {
        throw "A Shuffle App package is empty or exceeds 5 MiB: $([string]$app.name)"
    }
    [byte[]]$packageBytes = [IO.File]::ReadAllBytes($packagePath)
    if ($packageBytes.Length -le 0 -or $packageBytes.Length -gt 5MB) {
        throw "A Shuffle App package snapshot is empty or exceeds 5 MiB: $([string]$app.name)"
    }
    $actualHash = Get-SocShuffleValidatorSha256 -Bytes $packageBytes
    if ($actualHash -cne [string]$app.package_sha256) {
        throw "A Shuffle App package hash changed after the bundle was built: $([string]$app.name)"
    }
    if ([string]$app.name -ceq 'AWS Topology SOC Validator') {
        $validatorAppRoot = Join-Path $repositoryRoot `
            'observability\shuffle\apps\aws-topology-soc-validator\1.0.0'
        $packageProof = Assert-SocShuffleValidatorPackageSnapshot `
            -PackageBytes $packageBytes -AppRoot $validatorAppRoot
        if ([string]$packageProof.PackageSha256 -cne $actualHash) {
            throw 'The Validator package snapshot proof hash is inconsistent.'
        }
    } else {
        $packageBounds = @{
            'api.yaml'=64KB; 'Dockerfile'=16KB; 'requirements.txt'=16KB;
            'src/app.py'=64KB; 'src/dispatcher.py'=256KB;
            'src/autocontainment.py'=256KB
        }
        $packageStream = [IO.MemoryStream]::new($packageBytes, $false)
        $packageArchive = $null
        try {
            $packageArchive = [IO.Compression.ZipArchive]::new(
                $packageStream,
                [IO.Compression.ZipArchiveMode]::Read,
                $false
            )
            $packageSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($entry in $packageArchive.Entries) {
                $entryName = [string]$entry.FullName
                if ($entryName -cnotin @($definition.entries) -or
                    -not $packageSeen.Add($entryName) -or
                    [string]::IsNullOrEmpty([string]$entry.Name) -or
                    $entry.Length -lt 0 -or
                    $entry.Length -gt [long]$packageBounds[$entryName]) {
                    throw 'The App ZIP path or central-directory length is invalid.'
                }
            }
            if ($packageSeen.Count -ne @($definition.entries).Count) {
                throw 'The App ZIP contains an unexpected or missing file.'
            }
        } catch [IO.InvalidDataException] {
            throw 'The App ZIP snapshot is structurally invalid.'
        } finally {
            if ($packageArchive) { $packageArchive.Dispose() }
            $packageStream.Dispose()
        }
    }
    $verifiedApps.Add([pscustomobject]@{
        Name=[string]$app.name;Version=[string]$app.version;
        PackagePath=$packagePath;PackageFileName=[IO.Path]::GetFileName($packagePath);
        PackageSha256=$actualHash;PackageBytes=$packageBytes;
        ContractRole=[string]$app.contract_role;CurrentV2=[bool]$app.current_v2
    })
}

$baseUri = [uri][string]$configuration.shuffle_api_base
if ($baseUri.Scheme -cne 'https' -or
    ($baseUri.Host -cne 'shuffler.io' -and -not $baseUri.Host.EndsWith('.shuffler.io')) -or
    $baseUri.UserInfo -or $baseUri.Query -or $baseUri.Fragment) {
    throw 'The configured Shuffle API origin is outside the fixed HTTPS allowlist.'
}
$uploadUri = [uri]::new($baseUri, '/api/v1/apps/upload')

if (-not $ConsoleOnly.IsPresent) {
    Write-Host 'Shuffle SOC private App bundle upload preview'
    Write-Host 'Target: configured Shuffle Cloud organization'
    if ($isRule100110Bundle) {
        Write-Host 'Apps: Rule 100110 Auto Containment 1.0.0 only'
        Write-Host 'No GitHub credential is read or uploaded by this invocation.'
    } elseif ($legacyDispatcherApps.Count -gt 0) {
        Write-Host 'Apps: current v2 Validator 1.0.0 + explicitly opted-in legacy GT09 remediation Dispatcher 1.0.0'
        Write-Host 'Dispatcher upload role: legacy-gt09-remediation-dispatcher; EXCLUDED from current v2/100104 GT03-GT06.'
    } else {
        Write-Host 'Apps: current v2 Validator 1.0.0 only'
        Write-Host 'Legacy GT09 Dispatcher: EXCLUDED; no legacy PAT/provenance is uploaded by this invocation.'
    }
    Write-Host 'No Workflow execution, GitHub call, AWS change, or attack is performed.'
}
if ($ConfirmUpload -cne 'UPLOAD SHUFFLE SOC APPS') {
    throw "Preview only. Re-run with -ConfirmUpload 'UPLOAD SHUFFLE SOC APPS'."
}

$apiKey = $null
try {
    $apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $SecretRoot
    $orgId = [string]$configuration.shuffle_org_id
    $listApps = {
        Invoke-ShuffleApiRequest -Method GET -RelativePath '/api/v1/apps' `
            -ApiKey $apiKey -OrgId $orgId -BaseUri $baseUri `
            -RequestHeaders ([ordered]@{truncate='false'}) `
            -IncludeResponseMetadata
    }
    $uploadApp = {
        param([object]$App)
        Invoke-SocShuffleMultipartSubmission -App $App -UploadUri $uploadUri `
            -ApiKey $apiKey -OrgId $orgId -TimeoutSeconds 60
    }
    $deleteApp = {
        param([string]$AppId)
        if ($AppId -cnotmatch '^[a-f0-9]{32}$') {
            throw 'Unsafe App ID.'
        }
        Invoke-ShuffleApiRequest -Method DELETE -RelativePath "/api/v1/apps/$AppId" `
            -ApiKey $apiKey -OrgId $orgId -BaseUri $baseUri
    }
    $uploadResults = @(Invoke-SocShuffleAppUploadTransaction `
        -Apps @($verifiedApps) -ListApps $listApps -UploadApp $uploadApp `
        -DeleteApp $deleteApp -PollTimeoutSeconds $UploadTimeoutSeconds `
        -PollIntervalSeconds $PollIntervalSeconds)
} finally {
    $apiKey = $null
    foreach ($verifiedApp in @($verifiedApps)) {
        try {
            $snapshotProperty = $verifiedApp.PSObject.Properties['PackageBytes']
            if ($null -ne $snapshotProperty -and $snapshotProperty.Value -is [byte[]]) {
                [byte[]]$snapshotToClear = $snapshotProperty.Value
                [Array]::Clear($snapshotToClear, 0, $snapshotToClear.Length)
            }
        } catch {
            # Best-effort memory hygiene must not replace the transaction result.
        }
    }
}

if ($ConsoleOnly.IsPresent) {
    foreach ($result in @($uploadResults)) {
        Write-Host "APP_ID=$([string]$result.app_id)"
        Write-Host "LOCAL_PACKAGE_SHA256=$([string]$result.local_package_sha256)"
        Write-Host "UPLOADED_AT_UTC=$([string]$result.uploaded_at_utc)"
        Write-Host "READBACK_AT_UTC=$([string]$result.readback_at_utc)"
        Write-Host "UPLOAD_OUTCOME=$([string]$result.upload_outcome)"
    }
    return
}

if (-not $EvidenceRoot) {
    if (-not $env:USERPROFILE) { throw 'USERPROFILE is unavailable.' }
    $EvidenceRoot = Join-Path $env:USERPROFILE 'Documents\aws-topology-evidence'
}
$evidenceDirectory = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) 'shuffle-app'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$evidencePath = Join-Path $evidenceDirectory 'soc-private-app-bundle-upload.json'
$evidence = [ordered]@{
    schema_version=1
    artifact_kind='shuffle-soc-private-app-bundle-upload'
    current_contract=[string]$contractProperty.Value
    legacy_dispatcher_included=[bool]$declaredLegacyIncluded
    legacy_dispatcher_excluded_from_current_v2=$true
    organization_id=[string]$configuration.shuffle_org_id
    bundle_manifest_sha256=(Get-FileHash -LiteralPath $resolvedManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    apps=@($uploadResults)
    secret_persisted=$false
}
[IO.File]::WriteAllText(
    $evidencePath,
    (($evidence | ConvertTo-Json -Depth 16) + "`n"),
    [Text.UTF8Encoding]::new($false)
)
Write-Host 'SHUFFLE_SOC_APP_BUNDLE_UPLOADED=yes'
Write-Host "UPLOAD_EVIDENCE=$evidencePath"
