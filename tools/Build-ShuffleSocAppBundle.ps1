#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$ConfirmBuild = '',
    [switch]$IncludeLegacyGt09Dispatcher,
    [switch]$Rule100110AutoContainmentOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'ShuffleSocValidatorPackage.ps1')

$apps = @(
    [pscustomobject]@{
        name='AWS Topology SOC Validator'
        slug='aws-topology-soc-validator'
        version='1.0.0'
        contract_role='current-v2-validator'
        current_v2=$true
        test='tests.test_soc_shuffle_validator_app'
        files=@('api.yaml','Dockerfile','requirements.txt','src\app.py')
        source_files=@('api.yaml','Dockerfile','requirements.txt','src\app.py','src\validator.py')
    }
)
$legacyDispatcherApp = [pscustomobject]@{
        name='AWS Topology SOC GitHub Dispatcher'
        slug='aws-topology-soc-github-dispatcher'
        version='1.0.0'
        contract_role='legacy-gt09-remediation-dispatcher'
        current_v2=$false
        test='tests.test_soc_shuffle_github_dispatcher_app'
        files=@('api.yaml','Dockerfile','requirements.txt','src\app.py','src\dispatcher.py')
        source_files=@('api.yaml','Dockerfile','requirements.txt','src\app.py','src\dispatcher.py')
}
if ($IncludeLegacyGt09Dispatcher) {
    $apps += $legacyDispatcherApp
}
$rule100110AutoContainmentApp = [pscustomobject]@{
    name='SOC R110 Isolator'
    slug='aws-topology-soc-rule100110-auto-containment'
    version='1.0.0'
    contract_role='rule100110-auto-containment'
    current_v2=$false
    test='tests.test_soc_rule100110_auto_containment'
    files=@('api.yaml','Dockerfile','requirements.txt','src\app.py')
    source_files=@('api.yaml','Dockerfile','requirements.txt','src\app.py','src\autocontainment.py')
}
if ($Rule100110AutoContainmentOnly) {
    if ($IncludeLegacyGt09Dispatcher) {
        throw '-Rule100110AutoContainmentOnly cannot be combined with -IncludeLegacyGt09Dispatcher.'
    }
    $apps = @($rule100110AutoContainmentApp)
}

if (-not $OutputDirectory) {
    if (-not $env:USERPROFILE) {
        throw 'USERPROFILE is unavailable; specify -OutputDirectory explicitly.'
    }
    $OutputDirectory = Join-Path $env:USERPROFILE `
        'Documents\aws-topology-evidence\shuffle-packages'
}
$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
$stamp = [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$manifestPath = Join-Path $resolvedOutput "shuffle-soc-app-bundle-$stamp.json"

Write-Host 'Shuffle SOC private App bundle preview'
if ($Rule100110AutoContainmentOnly) {
    Write-Host 'Apps: Rule 100110 Auto Containment 1.0.0 only'
    Write-Host 'Role: fresh Rule 100110 validation and fixed DVWA quarantine Workflow dispatch.'
} elseif ($IncludeLegacyGt09Dispatcher) {
    Write-Host 'Apps: current v2 Validator 1.0.0 + explicitly opted-in legacy GT09 remediation Dispatcher 1.0.0'
    Write-Host 'Dispatcher role: legacy-gt09-remediation-dispatcher; EXCLUDED from current v2/100104 GT03-GT06.'
} else {
    Write-Host 'Apps: current v2 Validator 1.0.0'
    Write-Host 'Legacy GT09 Dispatcher: EXCLUDED by default; use -IncludeLegacyGt09Dispatcher only for legacy review.'
}
Write-Host "Output directory: $resolvedOutput"
Write-Host 'No Cloud upload, Workflow execution, credential access, GitHub write, AWS change, or attack is performed.'
if ($ConfirmBuild -cne 'BUILD SHUFFLE SOC APPS') {
    throw "Preview only. Re-run with -ConfirmBuild 'BUILD SHUFFLE SOC APPS'."
}

foreach ($app in $apps) {
    $appRoot = Join-Path $repositoryRoot `
        "observability\shuffle\apps\$($app.slug)\$($app.version)"
    foreach ($relativePath in $app.source_files) {
        if (-not (Test-Path -LiteralPath (Join-Path $appRoot $relativePath) -PathType Leaf)) {
            throw "The Shuffle App package source is incomplete: $($app.slug)/$relativePath"
        }
    }
    & python -B -m unittest ([string]$app.test)
    if ($LASTEXITCODE -ne 0) {
        throw "The Shuffle App unit tests failed: $($app.name)"
    }
}

New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$manifestApps = [Collections.Generic.List[object]]::new()
foreach ($app in $apps) {
    $appRoot = Join-Path $repositoryRoot `
        "observability\shuffle\apps\$($app.slug)\$($app.version)"
    $packagePath = Join-Path $resolvedOutput `
        "$($app.slug)-$($app.version)-$stamp.zip"
    $staging = Join-Path ([IO.Path]::GetTempPath()) `
        ("shuffle-soc-app-" + [guid]::NewGuid().ToString('N'))
    $validatorExpectedPackage = $null
    if ([string]$app.slug -ceq 'aws-topology-soc-validator') {
        $validatorExpectedPackage = New-SocShuffleValidatorExpectedPackage `
            -AppRoot $appRoot
    }
    try {
        foreach ($relativePath in $app.files) {
            $destination = Join-Path $staging $relativePath
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) `
                -Force | Out-Null
            if ($null -ne $validatorExpectedPackage) {
                $entryName = ([string]$relativePath).Replace('\','/')
                $entryDefinition = $validatorExpectedPackage.Entries[$entryName]
                if ($null -eq $entryDefinition) {
                    throw "The deterministic Validator package map is missing: $entryName"
                }
                [IO.File]::WriteAllBytes($destination, [byte[]]$entryDefinition.Bytes)
                if ($entryName -ceq 'src/app.py') {
                    & python -B -c `
                        'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1])' `
                        $destination
                    if ($LASTEXITCODE -ne 0) {
                        throw 'The generated Validator src/app.py failed Python AST parsing.'
                    }
                }
            } elseif (
                [string]$app.slug -ceq 'aws-topology-soc-rule100110-auto-containment' -and
                [string]$relativePath -ceq 'src\app.py'
            ) {
                $implementation = Get-Content -LiteralPath (
                    Join-Path $appRoot 'src\autocontainment.py'
                ) -Raw
                $adapter = Get-Content -LiteralPath (
                    Join-Path $appRoot 'src\app.py'
                ) -Raw
                $implementation = $implementation -replace '(?m)^from __future__ import annotations\r?\n', ''
                $adapter = $adapter -replace '(?m)^from shuffle_sdk import AppBase\r?\n', ''
                $adapter = $adapter -replace '(?m)^from autocontainment import dispatch_rule_100110\r?\n', ''
                [IO.File]::WriteAllText(
                    $destination,
                    ("from shuffle_sdk import AppBase`n`n" +
                        $implementation.Trim() + "`n`n" + $adapter.Trim()),
                    [Text.UTF8Encoding]::new($false)
                )
                & python -B -c `
                    'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1])' `
                    $destination
                if ($LASTEXITCODE -ne 0) {
                    throw 'The generated Rule 100110 src/app.py failed Python AST parsing.'
                }
            } else {
                Copy-Item -LiteralPath (Join-Path $appRoot $relativePath) `
                    -Destination $destination
            }
        }
        Compress-Archive -LiteralPath @(
            (Join-Path $staging 'api.yaml'),
            (Join-Path $staging 'Dockerfile'),
            (Join-Path $staging 'requirements.txt'),
            (Join-Path $staging 'src')
        ) -DestinationPath $packagePath -CompressionLevel Optimal
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
    if ($null -ne $validatorExpectedPackage) {
        [byte[]]$builtPackageBytes = [IO.File]::ReadAllBytes($packagePath)
        try {
            $builtPackageProof = Assert-SocShuffleValidatorPackageSnapshot `
                -PackageBytes $builtPackageBytes -AppRoot $appRoot
            $hash = [string]$builtPackageProof.PackageSha256
        } finally {
            [Array]::Clear($builtPackageBytes, 0, $builtPackageBytes.Length)
        }
    } else {
        $hash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifestApps.Add([ordered]@{
        name=[string]$app.name
        slug=[string]$app.slug
        version=[string]$app.version
        contract_role=[string]$app.contract_role
        current_v2=[bool]$app.current_v2
        package_path=$packagePath
        package_sha256=$hash
        entries=@($app.files | ForEach-Object { $_.Replace('\','/') } | Sort-Object)
    })
}

$manifest = [ordered]@{
    schema_version=1
    artifact_kind='shuffle-soc-private-app-bundle'
    current_contract=$(if ($Rule100110AutoContainmentOnly) {
        'rule100110-auto-containment/v1'
    } else {
        'v2/100104'
    })
    legacy_dispatcher_included=[bool]$IncludeLegacyGt09Dispatcher
    legacy_dispatcher_excluded_from_current_v2=$true
    created_at_utc=[datetimeoffset]::UtcNow.ToString('o')
    apps=@($manifestApps)
    secret_persisted=$false
}
[IO.File]::WriteAllText(
    $manifestPath,
    (($manifest | ConvertTo-Json -Depth 16) + "`n"),
    [Text.UTF8Encoding]::new($false)
)
Write-Host 'SHUFFLE_SOC_APP_BUNDLE_READY=yes'
Write-Host "BUNDLE_MANIFEST=$manifestPath"
foreach ($app in $manifestApps) {
    Write-Host "PACKAGE=$($app.package_path)"
    Write-Host "PACKAGE_SHA256=$($app.package_sha256)"
}
