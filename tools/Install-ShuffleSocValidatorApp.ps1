#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagePath,
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$EvidenceRoot = '',
    [string]$ConfirmUpload = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force

$configuration = Read-SocLabConfiguration -Root $ConfigurationRoot
$resolvedPackage = [IO.Path]::GetFullPath($PackagePath)
if (-not (Test-Path -LiteralPath $resolvedPackage -PathType Leaf)) {
    throw 'The Shuffle Validator package does not exist.'
}
$packageInfo = Get-Item -LiteralPath $resolvedPackage
if ($packageInfo.Length -le 0 -or $packageInfo.Length -gt 5MB) {
    throw 'The Shuffle Validator package is empty or exceeds the fixed 5 MiB limit.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($resolvedPackage)
try {
    $entries = @($archive.Entries | ForEach-Object {
        $_.FullName.Replace('\','/').TrimStart('/')
    } | Where-Object { $_ -and -not $_.EndsWith('/') } | Sort-Object)
} finally {
    $archive.Dispose()
}
$expectedEntries = @(
    'Dockerfile','api.yaml','requirements.txt','src/app.py','src/validator.py'
) | Sort-Object
if (($entries -join ',') -cne ($expectedEntries -join ',')) {
    throw 'The Shuffle Validator ZIP contains an unexpected or missing file.'
}

$baseUri = [uri][string]$configuration.shuffle_api_base
if ($baseUri.Scheme -cne 'https' -or
    ($baseUri.Host -cne 'shuffler.io' -and -not $baseUri.Host.EndsWith('.shuffler.io')) -or
    $baseUri.UserInfo -or $baseUri.Query -or $baseUri.Fragment) {
    throw 'The configured Shuffle API origin is outside the fixed HTTPS allowlist.'
}
$uploadUri = [uri]::new($baseUri, '/api/v1/apps/upload')
$packageHash = (Get-FileHash -LiteralPath $resolvedPackage -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host 'Shuffle private Validator App upload preview'
Write-Host 'Target: configured Shuffle Cloud organization'
Write-Host 'App: AWS Topology SOC Validator 1.0.0'
Write-Host "Package SHA-256: $packageHash"
Write-Host 'No Workflow execution, GitHub call, AWS change, or attack is performed.'
if ($ConfirmUpload -cne 'UPLOAD SHUFFLE VALIDATOR') {
    throw "Preview only. Re-run with -ConfirmUpload 'UPLOAD SHUFFLE VALIDATOR'."
}

$apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $SecretRoot
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [timespan]::FromSeconds(60)
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
    $stream = [IO.File]::OpenRead($resolvedPackage)
    $fileContent = [Net.Http.StreamContent]::new($stream)
    $fileContent.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new(
        'application/zip'
    )
    $content.Add($fileContent, 'shuffle_file', [IO.Path]::GetFileName($resolvedPackage))
    $request.Content = $content
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    try {
        $status = [int]$response.StatusCode
        $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($status -lt 200 -or $status -ge 300) {
            throw "Shuffle Validator upload failed: HTTP $status"
        }
        try { $result = $responseText | ConvertFrom-Json }
        catch { throw 'Shuffle returned a non-JSON Validator upload response.' }
        if ([bool]$result.success -ne $true -or [string]$result.id -notmatch '^[a-f0-9]{32}$') {
            throw 'Shuffle did not confirm the private Validator App upload.'
        }
    } finally {
        $response.Dispose()
    }
} finally {
    $apiKey = $null
    $content.Dispose()
    $request.Dispose()
    if ($stream) { $stream.Dispose() }
    $client.Dispose()
    $handler.Dispose()
}

if (-not $EvidenceRoot) {
    if (-not $env:USERPROFILE) { throw 'USERPROFILE is unavailable.' }
    $EvidenceRoot = Join-Path $env:USERPROFILE 'Documents\aws-topology-evidence'
}
$evidenceDirectory = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) 'shuffle-app'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$evidencePath = Join-Path $evidenceDirectory 'validator-app-upload.json'
$evidence = [ordered]@{
    schema_version=1
    app_name='AWS Topology SOC Validator'
    app_version='1.0.0'
    app_id=[string]$result.id
    package_sha256=$packageHash
    uploaded_at_utc=[datetimeoffset]::UtcNow.ToString('o')
    organization_id=[string]$configuration.shuffle_org_id
    secret_persisted=$false
}
[IO.File]::WriteAllText(
    $evidencePath,
    (($evidence | ConvertTo-Json -Depth 8) + "`n"),
    [Text.UTF8Encoding]::new($false)
)
Write-Host 'SHUFFLE_VALIDATOR_UPLOADED=yes'
Write-Host "UPLOAD_EVIDENCE=$evidencePath"

