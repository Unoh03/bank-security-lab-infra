#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [ValidateRange(60,600)][int]$UploadTimeoutSeconds = 300,
    [string]$ConfirmUpload = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force

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
$expectedApps = @{
    'AWS Topology SOC Validator' = @(
        'Dockerfile','api.yaml','requirements.txt','src/app.py','src/validator.py'
    )
    'AWS Topology SOC GitHub Dispatcher' = @(
        'Dockerfile','api.yaml','requirements.txt','src/app.py','src/dispatcher.py'
    )
}
$manifestApps = @($manifest.apps)
if ($manifestApps.Count -ne 2 -or
    (@($manifestApps.name | Sort-Object) -join ',') -cne
    (@($expectedApps.Keys | Sort-Object) -join ',')) {
    throw 'The bundle must contain exactly the Validator and GitHub Dispatcher Apps.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$verifiedApps = [Collections.Generic.List[object]]::new()
foreach ($app in $manifestApps) {
    if ([string]$app.version -cne '1.0.0' -or
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
    $actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne [string]$app.package_sha256) {
        throw "A Shuffle App package hash changed after the bundle was built: $([string]$app.name)"
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $entries = @($archive.Entries | ForEach-Object {
            $_.FullName.Replace('\','/').TrimStart('/')
        } | Where-Object { $_ -and -not $_.EndsWith('/') } | Sort-Object)
    } finally {
        $archive.Dispose()
    }
    $expectedEntries = @($expectedApps[[string]$app.name] | Sort-Object)
    if (($entries -join ',') -cne ($expectedEntries -join ',')) {
        throw "A Shuffle App ZIP contains an unexpected or missing file: $([string]$app.name)"
    }
    $verifiedApps.Add([pscustomobject]@{
        Name=[string]$app.name;Version=[string]$app.version;
        PackagePath=$packagePath;PackageSha256=$actualHash
    })
}

$baseUri = [uri][string]$configuration.shuffle_api_base
if ($baseUri.Scheme -cne 'https' -or
    ($baseUri.Host -cne 'shuffler.io' -and -not $baseUri.Host.EndsWith('.shuffler.io')) -or
    $baseUri.UserInfo -or $baseUri.Query -or $baseUri.Fragment) {
    throw 'The configured Shuffle API origin is outside the fixed HTTPS allowlist.'
}
$uploadUri = [uri]::new($baseUri, '/api/v1/apps/upload')

Write-Host 'Shuffle SOC private App bundle upload preview'
Write-Host 'Target: configured Shuffle Cloud organization'
Write-Host 'Apps: Validator 1.0.0 + fixed GitHub Dispatcher 1.0.0'
Write-Host 'No Workflow execution, GitHub call, AWS change, or attack is performed.'
if ($ConfirmUpload -cne 'UPLOAD SHUFFLE SOC APPS') {
    throw "Preview only. Re-run with -ConfirmUpload 'UPLOAD SHUFFLE SOC APPS'."
}

$apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $SecretRoot
$uploadResults = [Collections.Generic.List[object]]::new()
try {
    foreach ($app in $verifiedApps) {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [timespan]::FromSeconds($UploadTimeoutSeconds)
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $uploadUri)
        $content = [Net.Http.MultipartFormDataContent]::new()
        $stream = $null
        try {
            $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
                'Bearer', $apiKey
            )
            [void]$request.Headers.TryAddWithoutValidation(
                'Org-Id', [string]$configuration.shuffle_org_id
            )
            $stream = [IO.File]::OpenRead([string]$app.PackagePath)
            $fileContent = [Net.Http.StreamContent]::new($stream)
            $fileContent.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new(
                'application/zip'
            )
            $content.Add($fileContent, 'shuffle_file', [IO.Path]::GetFileName([string]$app.PackagePath))
            $request.Content = $content
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ($status -lt 200 -or $status -ge 300) {
                    $failureDetail = Get-SafeShuffleUploadFailureDetail -ResponseText $responseText
                    throw "Shuffle App upload failed for $($app.Name): HTTP $status ($failureDetail)"
                }
                try { $result = $responseText | ConvertFrom-Json }
                catch { throw "Shuffle returned a non-JSON App upload response: $($app.Name)" }
                if ([bool]$result.success -ne $true -or
                    [string]$result.id -notmatch '^[a-f0-9]{32}$') {
                    throw "Shuffle did not confirm the private App upload: $($app.Name)"
                }
                $uploadResults.Add([ordered]@{
                    app_name=[string]$app.Name;app_version=[string]$app.Version;
                    app_id=[string]$result.id;package_sha256=[string]$app.PackageSha256;
                    uploaded_at_utc=[datetimeoffset]::UtcNow.ToString('o')
                })
            } finally {
                $response.Dispose()
            }
        } finally {
            $content.Dispose();$request.Dispose()
            if ($stream) { $stream.Dispose() }
            $client.Dispose();$handler.Dispose()
        }
    }
} finally {
    $apiKey = $null
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
