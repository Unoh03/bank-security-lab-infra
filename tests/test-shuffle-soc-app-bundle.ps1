#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildPath = Join-Path $root 'tools\Build-ShuffleSocAppBundle.ps1'
$uploadPath = Join-Path $root 'tools\Install-ShuffleSocAppBundle.ps1'
$compatUploadPath = Join-Path $root 'tools\Install-ShuffleSocValidatorApp.ps1'
$packageHelperPath = Join-Path $root 'tools\ShuffleSocValidatorPackage.ps1'
$buildText = Get-Content -LiteralPath $buildPath -Raw
$uploadText = Get-Content -LiteralPath $uploadPath -Raw
$packageHelperText = Get-Content -LiteralPath $packageHelperPath -Raw
. $packageHelperPath

function Test-SocShuffleValidatorEntrypointContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Source)

    foreach ($pattern in @(
        '(?m)^def[ \t]+validate_sanitized_alert[ \t]*\([ \t]*input_data[ \t]*\)[ \t]*:',
        '(?m)^def[ \t]+classify_dedupe_claim[ \t]*\([ \t]*claim_result[ \t]*,[ \t]*expected_key[ \t]*\)[ \t]*:',
        '(?m)^[ \t]+def[ \t]+validate_sanitized_alert[ \t]*\([ \t]*self[ \t]*,[ \t]*input_data[ \t]*\)[ \t]*:',
        '(?m)^[ \t]+def[ \t]+classify_dedupe_claim[ \t]*\([ \t]*self[ \t]*,[ \t]*claim_result[ \t]*,[ \t]*expected_key[ \t]*\)[ \t]*:',
        '(?m)^class[ \t]+AwsTopologySocValidator[ \t]*\(AppBase\):',
        '(?m)^[ \t]*AwsTopologySocValidator\.run\(\)'
    )) {
        if ($Source -notmatch $pattern) {
            return $false
        }
    }
    if ($Source -match '(?m)^[ \t]*(from|import)[ \t]+validator\b' -or
        $Source -match '(?i)(github_pat_|aws_secret_access_key|password\s*=|secret\s*=)') {
        return $false
    }
    return $true
}

function Get-TestZipEntryBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$EntryName
    )

    $testArchive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $testEntry = $testArchive.GetEntry($EntryName)
        if ($null -eq $testEntry) { throw "Missing test ZIP entry: $EntryName" }
        $testStream = $testEntry.Open()
        $testBytes = [IO.MemoryStream]::new()
        try {
            $testStream.CopyTo($testBytes)
            return ,$testBytes.ToArray()
        } finally {
            $testBytes.Dispose()
            $testStream.Dispose()
        }
    } finally {
        $testArchive.Dispose()
    }
}

function New-TestZipArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][object[]]$Entries
    )

    $zipFile = [IO.File]::Create($ZipPath)
    $zipArchive = $null
    try {
        $zipArchive = [IO.Compression.ZipArchive]::new(
            $zipFile,
            [IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        foreach ($definition in $Entries) {
            $zipEntry = $zipArchive.CreateEntry(
                [string]$definition.Name,
                [IO.Compression.CompressionLevel]::Optimal
            )
            $zipStream = $zipEntry.Open()
            try {
                [byte[]]$zipBytes = $definition.Bytes
                $zipStream.Write($zipBytes, 0, $zipBytes.Length)
            } finally {
                $zipStream.Dispose()
            }
        }
    } finally {
        if ($zipArchive) { $zipArchive.Dispose() }
        $zipFile.Dispose()
    }
}

if ($buildText -notmatch "ConfirmBuild\s+-cne\s+'BUILD SHUFFLE SOC APPS'" -or
    $buildText -notmatch 'tests\.test_soc_shuffle_validator_app' -or
    $buildText -notmatch 'tests\.test_soc_shuffle_github_dispatcher_app' -or
    $buildText -notmatch '\[switch\]\$IncludeLegacyGt09Dispatcher' -or
    $buildText -notmatch 'if\s*\(\$IncludeLegacyGt09Dispatcher\)' -or
    $buildText -notmatch 'Compress-Archive' -or
    $buildText -notmatch 'ShuffleSocValidatorPackage\.ps1' -or
    $buildText -notmatch 'ast\.parse') {
    throw 'The Shuffle SOC App bundle builder lacks its confirmation, tests, or ZIP step.'
}
if ($buildText -notmatch 'legacy-gt09-remediation-dispatcher' -or
    $buildText -notmatch 'EXCLUDED by default' -or
    $buildText -notmatch 'legacy_dispatcher_included' -or
    $buildText -notmatch 'New-SocShuffleValidatorExpectedPackage' -or
    $buildText -notmatch 'Assert-SocShuffleValidatorPackageSnapshot' -or
    $buildText -match '(?m)^function\s+New-SocShuffleValidatorPackagedApp\b' -or
    $buildText -notmatch 'source_files=@') {
    throw 'The Shuffle App bundle builder does not default to current Validator-only packaging with an explicit legacy boundary.'
}
if ($uploadText -notmatch "ConfirmUpload\s+-cne\s+'UPLOAD SHUFFLE SOC APPS'" -or
    $uploadText -notmatch '/api/v1/apps/upload' -or
    $uploadText -notmatch '\[switch\]\$AllowLegacyGt09Dispatcher' -or
    $uploadText -notmatch 'current_contract' -or
    $uploadText -notmatch 'legacy_dispatcher_included' -or
    $uploadText -notmatch 'current_v2' -or
    $uploadText -notmatch "Unprotect-SocSecret\s+-Name\s+'shuffle_api_key'" -or
    $uploadText -notmatch 'Get-SafeShuffleUploadFailureDetail' -or
    $uploadText -notmatch 'response_sha256' -or
    $uploadText -notmatch 'ShuffleSocValidatorPackage\.ps1' -or
    $uploadText -notmatch 'Assert-SocShuffleValidatorPackageSnapshot' -or
    $uploadText -notmatch 'PackageBytes=\$packageBytes' -or
    $uploadText -notmatch 'ByteArrayContent' -or
    $uploadText -notmatch 'Array\]::Clear' -or
    $uploadText -match 'throw[^\r\n]*\$responseText' -or
    $uploadText -match 'Write-Host[^\r\n]*\$apiKey') {
    throw 'The Shuffle SOC App bundle uploader violates its approval, role, or secret contract.'
}
if ($uploadText -notmatch '\[switch\]\$ConsoleOnly' -or
    $uploadText -notmatch 'if\s*\(\$ConsoleOnly\.IsPresent\)' -or
    $uploadText -notmatch 'APP_ID=' -or
    $uploadText -notmatch 'LOCAL_PACKAGE_SHA256=' -or
    $uploadText -notmatch 'UPLOADED_AT_UTC=' -or
    $uploadText -notmatch 'READBACK_AT_UTC=' -or
    $uploadText -notmatch 'UPLOAD_OUTCOME=') {
    throw 'The App bundle uploader lacks the explicit console-only output mode.'
}
$consoleOnlyBlock = [regex]::Match(
    $uploadText,
    'if\s*\(\$ConsoleOnly\.IsPresent\)[\s\S]*?(?=if\s*\(-not\s+\$EvidenceRoot\))'
).Value
if (-not $consoleOnlyBlock -or $consoleOnlyBlock -match 'WriteAllText\(') {
    throw 'Console-only App upload mode can persist durable evidence.'
}
if ($consoleOnlyBlock -match 'SHUFFLE_SOC_APP_BUNDLE_UPLOADED|UPLOAD_EVIDENCE|EvidenceRoot') {
    throw 'Console-only App upload mode prints or references durable evidence output.'
}
if ($uploadText -match 'must contain exactly the Validator and GitHub Dispatcher Apps') {
    throw 'The current bundle uploader still requires the legacy Dispatcher by default.'
}
if ($uploadText -notmatch "entries=@\('Dockerfile','api.yaml','requirements.txt','src/app.py'\)" -or
    $uploadText -notmatch 'validatorAppRoot' -or
    $uploadText -notmatch 'PackageSha256=\$actualHash;PackageBytes=\$packageBytes' -or
    $uploadText -notmatch 'package snapshot proof hash is inconsistent') {
    throw 'The current v2 Validator uploader does not require an exact four-file canonical byte snapshot.'
}
if ($packageHelperText -notmatch '(?m)^function\s+New-SocShuffleValidatorPackagedApp\b' -or
    $packageHelperText -notmatch '(?m)^function\s+New-SocShuffleValidatorExpectedPackage\b' -or
    $packageHelperText -notmatch '(?m)^function\s+Assert-SocShuffleValidatorPackageSnapshot\b' -or
    $packageHelperText -notmatch '(?m)^function\s+Assert-SocShuffleValidatorPackagedAppSource\b' -or
    $packageHelperText -notmatch 'smaller than 9 KiB' -or
    $packageHelperText -notmatch 'StringComparison\]::Ordinal' -or
    $packageHelperText -notmatch 'SHA256\]::HashData' -or
    $packageHelperText -notmatch 'api\[_-\]\?key\|token' -or
    $packageHelperText -match '(?m)^param\s*\(') {
    throw 'The shared Validator package helper is not a library-only deterministic source contract.'
}
$packageReadMatches = [regex]::Matches(
    $uploadText,
    '\[IO\.File\]::ReadAllBytes\(\$packagePath\)'
)
if ($packageReadMatches.Count -ne 1 -or
    $uploadText -match '\[IO\.File\]::OpenRead\(|Compression\.ZipFile\]::OpenRead\(\$packagePath|Net\.Http\.StreamContent' -or
    $uploadText -notmatch 'New-SocShuffleAppPackageContent' -or
    $uploadText -notmatch 'verified App byte snapshot changed before upload') {
    throw 'The canonical uploader can reopen a package path or does not upload its single validated byte snapshot.'
}
$centralLengthGuardIndex = $packageHelperText.IndexOf('$entry.Length -ne [long]$entryExpected.Length')
$boundedAllocationIndex = $packageHelperText.IndexOf('[byte[]]$actualBytes = [byte[]]::new')
if ($centralLengthGuardIndex -lt 0 -or $boundedAllocationIndex -le $centralLengthGuardIndex) {
    throw 'The Validator ZIP verifier can allocate before checking trusted central-directory lengths.'
}
foreach ($relativePath in @(
    'tools\Build-ShuffleSocValidatorApp.ps1',
    'tools\Install-ShuffleSocValidatorApp.ps1'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
        throw "The separate current Validator package path is missing: $relativePath"
    }
}
foreach ($path in @($buildPath,$uploadPath,$packageHelperPath)) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,[ref]$tokens,[ref]$errors
    )
    if (@($errors).Count -ne 0) {
        throw "Parser errors in $path`: $(@($errors.Message) -join '; ')"
    }
}

$uploadTokens = $null
$uploadErrors = $null
$uploadAst = [Management.Automation.Language.Parser]::ParseFile(
    $uploadPath,[ref]$uploadTokens,[ref]$uploadErrors
)
$completeListCommands = @($uploadAst.FindAll({
    param($node)
    if ($node -isnot [Management.Automation.Language.CommandAst] -or
        $node.GetCommandName() -cne 'Invoke-ShuffleApiRequest') {
        return $false
    }
    $text = [string]$node.Extent.Text
    return (
        $text -match "-Method\s+GET" -and
        $text -match "'/api/v1/apps'" -and
        $text -match '-RequestHeaders' -and
        $text -match "truncate\s*=\s*'false'" -and
        $text -match '-IncludeResponseMetadata'
    )
}, $true))
if ($completeListCommands.Count -ne 1) {
    throw 'The production App-list GET does not request non-truncated response metadata exactly once.'
}

if ($uploadText -notmatch 'Invoke-SocShuffleAppUploadTransaction' -or
    $uploadText -notmatch 'baseline_existing' -or
    $uploadText -notmatch 'confirmed_async_502' -or
    $uploadText -notmatch 'Test-SocShuffleUploadExactBoolean' -or
    $uploadText -notmatch 'Invoke-SocShuffleUploadCleanup') {
    throw 'The App uploader lacks its async read-back or rollback contract.'
}

. $uploadPath -ManifestPath 'mock-only' -NoRun

function Assert-UploadTestCondition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function New-UploadTestApp {
    param(
        [string]$Name = 'AWS Topology SOC Validator',
        [string]$Version = '1.0.0',
        [char]$HashCharacter = 'a'
    )
    return [pscustomobject]@{
        Name=$Name;Version=$Version;PackagePath='mock.zip';
        PackageSha256=([string]$HashCharacter * 64);
        ContractRole='test';CurrentV2=$true
    }
}

function New-UploadTestCloudApp {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$Name = 'AWS Topology SOC Validator',
        [string]$Version = '1.0.0',
        [AllowNull()][object]$Activated = $true,
        [AllowNull()][object]$IsValid = $true,
        [AllowNull()][object]$Invalid = $false
    )
    return [pscustomobject][ordered]@{
        id=$Id;name=$Name;app_version=$Version;
        activated=$Activated;is_valid=$IsValid;invalid=$Invalid
    }
}

$snapshotUploadRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'shuffle-soc-upload-snapshot-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $snapshotUploadRoot -Force | Out-Null
try {
    foreach ($pathChange in @('mutated','deleted')) {
        $snapshotPath = Join-Path $snapshotUploadRoot ($pathChange + '.zip')
        [byte[]]$validatedSnapshot = [Text.Encoding]::UTF8.GetBytes(
            'validated-package-snapshot-' + $pathChange
        )
        [IO.File]::WriteAllBytes($snapshotPath, $validatedSnapshot)
        $snapshotApp = [pscustomobject]@{
            PackagePath=$snapshotPath
            PackageFileName='validator-snapshot.zip'
            PackageSha256=(Get-SocShuffleValidatorSha256 -Bytes $validatedSnapshot)
            PackageBytes=$validatedSnapshot
        }
        if ($pathChange -ceq 'mutated') {
            [IO.File]::WriteAllBytes(
                $snapshotPath,
                [Text.Encoding]::UTF8.GetBytes('untrusted-path-mutation')
            )
        } else {
            Remove-Item -LiteralPath $snapshotPath -Force
        }
        $snapshotContent = New-SocShuffleAppPackageContent -App $snapshotApp
        try {
            [byte[]]$submittedBytes = $snapshotContent.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            if (-not (Test-SocShuffleValidatorBytesEqual `
                    -Actual $submittedBytes -Expected $validatedSnapshot)) {
                throw "The $pathChange path change altered the verified upload snapshot."
            }
        } finally {
            $snapshotContent.Dispose()
        }
    }
} finally {
    Remove-Item -LiteralPath $snapshotUploadRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-UploadTestTransaction {
    param(
        [Parameter(Mandatory)][object[]]$Apps,
        [Parameter(Mandatory)][scriptblock]$ListApps,
        [Parameter(Mandatory)][scriptblock]$UploadApp,
        [Parameter(Mandatory)][scriptblock]$DeleteApp,
        [int]$TimeoutSeconds = 4
    )
    $clock = [pscustomobject]@{
        Value=[datetimeoffset]'2026-08-21T00:00:00Z'
    }
    $now = { $clock.Value }
    $sleep = {
        param([int]$Seconds)
        $clock.Value = $clock.Value.AddSeconds($Seconds)
    }
    $sourceListApps = $ListApps
    $completeList = {
        $body = & $sourceListApps
        [pscustomobject][ordered]@{
            body=$body
            response_headers=[pscustomobject]@{}
        }
    }.GetNewClosure()
    return @(Invoke-SocShuffleAppUploadTransaction -Apps $Apps `
        -ListApps $completeList -UploadApp $UploadApp -DeleteApp $DeleteApp `
        -UtcNow $now -Sleep $sleep -PollTimeoutSeconds $TimeoutSeconds `
        -PollIntervalSeconds 1)
}

$testApp = New-UploadTestApp
$legacyTestApp = New-UploadTestApp `
    -Name 'AWS Topology SOC GitHub Dispatcher' -HashCharacter 'b'
$id1 = '1' * 32
$id2 = '2' * 32
$id3 = '3' * 32

$invalidEnvelopeFixtures = @(
    [pscustomobject]@{
        label='missing metadata envelope'
        envelope=[pscustomobject]@{apps=@()}
    },
    [pscustomobject]@{
        label='truncated true'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{apps=@()}
            response_headers=[pscustomobject]@{'X-SHUFFLE_TRUNCATED'=@('true')}
        }
    },
    [pscustomobject]@{
        label='truncation ambiguous'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{apps=@()}
            response_headers=[pscustomobject]@{
                'X-SHUFFLE_TRUNCATED'=@('false','false')
            }
        }
    },
    [pscustomobject]@{
        label='pagination total'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{apps=@();total=0}
            response_headers=[pscustomobject]@{}
        }
    },
    [pscustomobject]@{
        label='nested pagination bypass'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{
                data=[pscustomobject]@{apps=@();has_more=$true}
            }
            response_headers=[pscustomobject]@{}
        }
    },
    [pscustomobject]@{
        label='nested body pagination bypass'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{
                body=[pscustomobject]@{apps=@();next_cursor='unsafe'}
            }
            response_headers=[pscustomobject]@{}
        }
    },
    [pscustomobject]@{
        label='unproven direct data sequence'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{
                data=@(
                    (New-UploadTestCloudApp -Id $id1),
                    (New-UploadTestCloudApp -Id $id2)
                )
            }
            response_headers=[pscustomobject]@{}
        }
    },
    [pscustomobject]@{
        label='fixed item ceiling'
        envelope=[pscustomobject]@{
            body=[pscustomobject]@{apps=@(1..1000 | ForEach-Object {
                [pscustomobject]@{id=('f' * 32);name="ceiling-$_";app_version='0.0.0'}
            })}
            response_headers=[pscustomobject]@{}
        }
    }
)
foreach ($invalidEnvelopeFixture in $invalidEnvelopeFixtures) {
    $invalidEnvelopeState = [pscustomobject]@{Posts=0;Deletes=0}
    $invalidEnvelopeList = { $invalidEnvelopeFixture.envelope }
    $invalidEnvelopeUpload = {
        param($App)
        $invalidEnvelopeState.Posts++
        [pscustomobject]@{kind='http_4xx';candidate_id='';candidate_present=$false;candidate_valid=$true}
    }
    $invalidEnvelopeDelete = { param($Id) $invalidEnvelopeState.Deletes++ }
    $invalidEnvelopeError = ''
    try {
        [void](Invoke-SocShuffleAppUploadTransaction -Apps @($testApp) `
            -ListApps $invalidEnvelopeList -UploadApp $invalidEnvelopeUpload `
            -DeleteApp $invalidEnvelopeDelete)
    } catch { $invalidEnvelopeError = $_.Exception.Message }
    Assert-UploadTestCondition `
        -Condition ($invalidEnvelopeError -match '\[baseline_read' -and
            $invalidEnvelopeState.Posts -eq 0 -and $invalidEnvelopeState.Deletes -eq 0) `
        -Message "The $([string]$invalidEnvelopeFixture.label) list was accepted."
}

$observedArrayEnvelope = [pscustomobject][ordered]@{
    body=@(
        (New-UploadTestCloudApp -Id $id1),
        (New-UploadTestCloudApp -Id $id2 -Name 'Observed second App')
    )
    response_headers=[pscustomobject]@{}
}
$observedArrayComplete = Resolve-SocShuffleCompleteAppListEnvelope `
    -Envelope $observedArrayEnvelope
Assert-UploadTestCondition `
    -Condition (@($observedArrayComplete.items).Count -eq 2 -and
        @(Get-SocShuffleUploadExactApps -Response $observedArrayComplete.body `
            -Name 'AWS Topology SOC Validator' -Version '1.0.0').Count -eq 1) `
    -Message 'The observed non-empty top-level App array was not counted exactly.'

$completeFalseHeaderState = [pscustomobject]@{Posts=0;Deletes=0}
$completeFalseHeaderList = {
    [pscustomobject][ordered]@{
        body=[pscustomobject]@{apps=@()}
        response_headers=[pscustomobject]@{'X-SHUFFLE_TRUNCATED'=@('false')}
    }
}
$completeFalseHeaderUpload = {
    param($App)
    $completeFalseHeaderState.Posts++
    [pscustomobject]@{kind='http_4xx';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$completeFalseHeaderDelete = { param($Id) $completeFalseHeaderState.Deletes++ }
$completeFalseHeaderError = ''
try {
    [void](Invoke-SocShuffleAppUploadTransaction -Apps @($testApp) `
        -ListApps $completeFalseHeaderList -UploadApp $completeFalseHeaderUpload `
        -DeleteApp $completeFalseHeaderDelete)
} catch { $completeFalseHeaderError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($completeFalseHeaderError -match '\[client_rejected' -and
        $completeFalseHeaderState.Posts -eq 1 -and
        $completeFalseHeaderState.Deletes -eq 0) `
    -Message 'An exact single false truncation header was not accepted as complete.'

# The full bundle baseline is frozen before the first POST.
$baselineExistingState = [pscustomobject]@{Posts=0;Deletes=0}
$baselineExistingList = {
    [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1 `
        -Name 'AWS Topology SOC GitHub Dispatcher')}
}
$baselineExistingUpload = {
    param($App)
    $baselineExistingState.Posts++
}
$baselineExistingDelete = {
    param($Id)
    $baselineExistingState.Deletes++
}
$baselineExistingError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp,$legacyTestApp) `
        -ListApps $baselineExistingList -UploadApp $baselineExistingUpload `
        -DeleteApp $baselineExistingDelete)
} catch { $baselineExistingError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($baselineExistingError -match '\[baseline_existing' -and
        $baselineExistingState.Posts -eq 0 -and $baselineExistingState.Deletes -eq 0) `
    -Message 'An existing exact App did not block every POST before mutation.'

# A 2xx response is only a candidate; delayed strict read-back decides success.
$twoXxState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0}
$twoXxList = {
    $twoXxState.Lists++
    if ($twoXxState.Lists -lt 3) { return [pscustomobject]@{apps=@()} }
    return [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1)}
}
$twoXxUpload = {
    param($App)
    $twoXxState.Posts++
    [pscustomobject]@{kind='http_2xx';candidate_id=$id1;candidate_present=$true;candidate_valid=$true}
}
$twoXxDelete = { param($Id) $twoXxState.Deletes++ }
$twoXxResult = @(Invoke-UploadTestTransaction -Apps @($testApp) `
    -ListApps $twoXxList -UploadApp $twoXxUpload -DeleteApp $twoXxDelete)
$expectedResultProperties = @(
    'app_id','local_package_sha256','uploaded_at_utc','readback_at_utc','upload_outcome'
) | Sort-Object
Assert-UploadTestCondition `
    -Condition ($twoXxResult.Count -eq 1 -and
        (@($twoXxResult[0].PSObject.Properties.Name | Sort-Object) -join ',') -ceq
            ($expectedResultProperties -join ',') -and
        [string]$twoXxResult[0].app_id -ceq $id1 -and
        [string]$twoXxResult[0].upload_outcome -ceq 'confirmed_2xx' -and
        $twoXxState.Posts -eq 1 -and $twoXxState.Deletes -eq 0) `
    -Message 'A delayed 2xx App read-back did not produce one verified result.'

# HTTP 502 is an ambiguous single submission, never a retry trigger.
$async502State = [pscustomobject]@{Lists=0;Posts=0;Deletes=0}
$async502List = {
    $async502State.Lists++
    if ($async502State.Lists -lt 4) { return [pscustomobject]@{apps=@()} }
    [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1)}
}
$async502Upload = {
    param($App)
    $async502State.Posts++
    [pscustomobject]@{kind='http_502';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$async502Delete = { param($Id) $async502State.Deletes++ }
$async502Result = @(Invoke-UploadTestTransaction -Apps @($testApp) `
    -ListApps $async502List -UploadApp $async502Upload -DeleteApp $async502Delete)
Assert-UploadTestCondition `
    -Condition ($async502Result.Count -eq 1 -and
        [string]$async502Result[0].upload_outcome -ceq 'confirmed_async_502' -and
        $async502State.Posts -eq 1 -and $async502State.Deletes -eq 0) `
    -Message 'The HTTP 502 delayed-success fixture retried or failed read-back.'

foreach ($ambiguousSuccessFixture in @(
    [pscustomobject]@{kind='http_5xx';outcome='confirmed_async_5xx'},
    [pscustomobject]@{kind='timeout';outcome='confirmed_async_timeout'},
    [pscustomobject]@{kind='transport';outcome='confirmed_async_transport'}
)) {
    $ambiguousSuccessState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0}
    $ambiguousSuccessList = {
        $ambiguousSuccessState.Lists++
        if ($ambiguousSuccessState.Lists -eq 1) {
            return [pscustomobject]@{apps=@()}
        }
        [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1)}
    }
    $ambiguousSuccessUpload = {
        param($App)
        $ambiguousSuccessState.Posts++
        [pscustomobject]@{
            kind=[string]$ambiguousSuccessFixture.kind;candidate_id='';
            candidate_present=$false;candidate_valid=$true
        }
    }
    $ambiguousSuccessDelete = { param($Id) $ambiguousSuccessState.Deletes++ }
    $ambiguousSuccessResult = @(Invoke-UploadTestTransaction -Apps @($testApp) `
        -ListApps $ambiguousSuccessList -UploadApp $ambiguousSuccessUpload `
        -DeleteApp $ambiguousSuccessDelete)
    Assert-UploadTestCondition `
        -Condition ($ambiguousSuccessResult.Count -eq 1 -and
            [string]$ambiguousSuccessResult[0].upload_outcome -ceq
                [string]$ambiguousSuccessFixture.outcome -and
            $ambiguousSuccessState.Posts -eq 1 -and
            $ambiguousSuccessState.Deletes -eq 0) `
        -Message "The $([string]$ambiguousSuccessFixture.kind) fixture retried or failed read-back."
}

# An ambiguous submission that never appears is bounded and is not retried.
$timeoutState = [pscustomobject]@{Posts=0;Deletes=0}
$emptyList = { [pscustomobject]@{apps=@()} }
$timeoutUpload = {
    param($App)
    $timeoutState.Posts++
    [pscustomobject]@{kind='http_502';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$timeoutDelete = { param($Id) $timeoutState.Deletes++ }
$timeoutError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp) `
        -ListApps $emptyList -UploadApp $timeoutUpload -DeleteApp $timeoutDelete `
        -TimeoutSeconds 2)
} catch { $timeoutError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($timeoutError -match '\[readback_timeout' -and
        $timeoutState.Posts -eq 1 -and $timeoutState.Deletes -eq 0) `
    -Message 'The absent HTTP 502 App was retried or was not bounded.'

# A 4xx is a definitive client rejection and never enters polling or deletion.
$fourXxState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0}
$fourXxList = {
    $fourXxState.Lists++
    [pscustomobject]@{apps=@()}
}
$fourXxUpload = {
    param($App)
    $fourXxState.Posts++
    [pscustomobject]@{kind='http_4xx';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$fourXxDelete = { param($Id) $fourXxState.Deletes++ }
$fourXxError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp) `
        -ListApps $fourXxList -UploadApp $fourXxUpload -DeleteApp $fourXxDelete)
} catch { $fourXxError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($fourXxError -match '\[client_rejected' -and
        $fourXxState.Lists -eq 1 -and $fourXxState.Posts -eq 1 -and
        $fourXxState.Deletes -eq 0) `
    -Message 'The HTTP 4xx fixture polled, retried, deleted, or lost its fixed category.'

# Duplicate and candidate-ID mismatch states are ambiguous and are never deleted.
foreach ($identityFixture in @(
    [pscustomobject]@{
        label='duplicate';expected='readback_duplicate';candidate='';present=$false;
        cloud=@(
            (New-UploadTestCloudApp -Id $id1),
            (New-UploadTestCloudApp -Id $id2)
        )
    },
    [pscustomobject]@{
        label='candidate mismatch';expected='readback_identity';candidate=$id1;present=$true;
        cloud=@((New-UploadTestCloudApp -Id $id2))
    }
)) {
    $identityState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0;Fixture=$identityFixture}
    $identityList = {
        $identityState.Lists++
        if ($identityState.Lists -eq 1) { return [pscustomobject]@{apps=@()} }
        [pscustomobject]@{apps=@($identityState.Fixture.cloud)}
    }
    $identityUpload = {
        param($App)
        $identityState.Posts++
        [pscustomobject]@{
            kind='http_2xx';candidate_id=[string]$identityState.Fixture.candidate;
            candidate_present=[bool]$identityState.Fixture.present;candidate_valid=$true
        }
    }
    $identityDelete = { param($Id) $identityState.Deletes++ }
    $identityError = ''
    try {
        [void](Invoke-UploadTestTransaction -Apps @($testApp) `
            -ListApps $identityList -UploadApp $identityUpload -DeleteApp $identityDelete)
    } catch { $identityError = $_.Exception.Message }
    Assert-UploadTestCondition `
        -Condition ($identityError -match "\[$([regex]::Escape([string]$identityFixture.expected))" -and
            $identityState.Posts -eq 1 -and $identityState.Deletes -eq 0) `
        -Message "The $([string]$identityFixture.label) fixture was accepted or auto-deleted."
}

# Missing, null, string, and wrong Boolean fields never become a valid App.
$strictFixtures = @(
    [pscustomobject]@{label='wrong';mutate={param($App) $App.activated=$false}},
    [pscustomobject]@{label='string';mutate={param($App) $App.is_valid='true'}},
    [pscustomobject]@{label='null';mutate={param($App) $App.invalid=$null}},
    [pscustomobject]@{label='missing';mutate={param($App) $App.PSObject.Properties.Remove('activated')}}
)
foreach ($strictFixture in $strictFixtures) {
    $strictState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0;Deleted=$false;Fixture=$strictFixture}
    $strictList = {
        $strictState.Lists++
        if ($strictState.Lists -eq 1 -or $strictState.Deleted) {
            return [pscustomobject]@{apps=@()}
        }
        $cloudApp = New-UploadTestCloudApp -Id $id1
        & $strictState.Fixture.mutate $cloudApp
        [pscustomobject]@{apps=@($cloudApp)}
    }
    $strictUpload = {
        param($App)
        $strictState.Posts++
        [pscustomobject]@{kind='http_502';candidate_id='';candidate_present=$false;candidate_valid=$true}
    }
    $strictDelete = {
        param($Id)
        $strictState.Deletes++
        $strictState.Deleted=$true
    }
    $strictError = ''
    try {
        [void](Invoke-UploadTestTransaction -Apps @($testApp) `
            -ListApps $strictList -UploadApp $strictUpload -DeleteApp $strictDelete `
            -TimeoutSeconds 2)
    } catch { $strictError = $_.Exception.Message }
    Assert-UploadTestCondition `
        -Condition ($strictError -match '\[readback_timeout' -and
            $strictState.Posts -eq 1 -and $strictState.Deletes -eq 1) `
        -Message "The strict Boolean $([string]$strictFixture.label) fixture was accepted or not rolled back."
}

# A multi-App partial failure rolls back only this invocation's proven App.
$legacyApp = $legacyTestApp
$partialState = [pscustomobject]@{
    Posts=0;Deletes=[Collections.Generic.List[string]]::new();
    Cloud=[Collections.Generic.List[object]]::new()
}
$partialList = { [pscustomobject]@{apps=@($partialState.Cloud)} }
$partialUpload = {
    param($App)
    $partialState.Posts++
    if ($partialState.Posts -eq 1) {
        $partialState.Cloud.Add((New-UploadTestCloudApp -Id $id1))
        return [pscustomobject]@{kind='http_2xx';candidate_id=$id1;candidate_present=$true;candidate_valid=$true}
    }
    [pscustomobject]@{kind='http_4xx';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$partialDelete = {
    param($Id)
    $partialState.Deletes.Add([string]$Id)
    for ($index=$partialState.Cloud.Count-1;$index -ge 0;$index--) {
        if ([string]$partialState.Cloud[$index].id -ceq [string]$Id) {
            $partialState.Cloud.RemoveAt($index)
        }
    }
}
$partialError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp,$legacyApp) `
        -ListApps $partialList -UploadApp $partialUpload -DeleteApp $partialDelete)
} catch { $partialError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($partialError -match '\[client_rejected' -and
        $partialState.Posts -eq 2 -and $partialState.Deletes.Count -eq 1 -and
        [string]$partialState.Deletes[0] -ceq $id1 -and $partialState.Cloud.Count -eq 0) `
    -Message 'A partial multi-App failure did not reverse only its proven prior App.'

$reverseState = [pscustomobject]@{
    Deletes=[Collections.Generic.List[string]]::new()
    Cloud=[Collections.Generic.List[object]]::new()
}
$reverseState.Cloud.Add((New-UploadTestCloudApp -Id $id1))
$reverseState.Cloud.Add((New-UploadTestCloudApp -Id $id2 `
    -Name 'AWS Topology SOC GitHub Dispatcher'))
$reverseRecords = [Collections.Generic.List[object]]::new()
$reverseRecords.Add([pscustomobject]@{
    name='AWS Topology SOC Validator';version='1.0.0';id=$id1;eligible=$true
})
$reverseRecords.Add([pscustomobject]@{
    name='AWS Topology SOC GitHub Dispatcher';version='1.0.0';id=$id2;eligible=$true
})
$reverseList = { [pscustomobject]@{apps=@($reverseState.Cloud)} }
$reverseCompleteList = {
    [pscustomobject][ordered]@{
        body=(& $reverseList)
        response_headers=[pscustomobject]@{}
    }
}
$reverseDelete = {
    param($Id)
    $reverseState.Deletes.Add([string]$Id)
    for ($index=$reverseState.Cloud.Count-1;$index -ge 0;$index--) {
        if ([string]$reverseState.Cloud[$index].id -ceq [string]$Id) {
            $reverseState.Cloud.RemoveAt($index)
        }
    }
}
$reverseClean = Invoke-SocShuffleUploadCleanup -CleanupRecords $reverseRecords `
    -DeleteApp $reverseDelete -ListApps $reverseCompleteList
Assert-UploadTestCondition `
    -Condition ($reverseClean -and $reverseState.Deletes.Count -eq 2 -and
        [string]$reverseState.Deletes[0] -ceq $id2 -and
        [string]$reverseState.Deletes[1] -ceq $id1 -and
        $reverseState.Cloud.Count -eq 0) `
    -Message 'Proven newly-created Apps were not deleted in reverse order with zero read-back.'

$renamedCleanupState = [pscustomobject]@{Lists=0;Deletes=0}
$renamedCleanupList = {
    $renamedCleanupState.Lists++
    $body = if ($renamedCleanupState.Lists -eq 1) {
        [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1)}
    } else {
        [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1 `
            -Name 'Renamed Validator After Delete')}
    }
    [pscustomobject][ordered]@{
        body=$body
        response_headers=[pscustomobject]@{}
    }
}
$renamedCleanupDelete = { param($Id) $renamedCleanupState.Deletes++ }
$renamedCleanupRecords = [Collections.Generic.List[object]]::new()
$renamedCleanupRecords.Add([pscustomobject]@{
    name='AWS Topology SOC Validator';version='1.0.0';id=$id1;eligible=$true
})
$renamedCleanupResult = Invoke-SocShuffleUploadCleanup `
    -CleanupRecords $renamedCleanupRecords -DeleteApp $renamedCleanupDelete `
    -ListApps $renamedCleanupList
Assert-UploadTestCondition `
    -Condition (-not $renamedCleanupResult -and
        $renamedCleanupState.Deletes -eq 1) `
    -Message 'Cleanup accepted a deleted target ID that survived under a renamed App.'

# If a once-unique candidate becomes ambiguous, rollback refuses every exact ID.
$ambiguousState = [pscustomobject]@{Lists=0;Posts=0;Deletes=0}
$ambiguousList = {
    $ambiguousState.Lists++
    if ($ambiguousState.Lists -eq 1) { return [pscustomobject]@{apps=@()} }
    if ($ambiguousState.Lists -eq 2) {
        return [pscustomobject]@{apps=@(New-UploadTestCloudApp -Id $id1 -Activated $false)}
    }
    [pscustomobject]@{apps=@(
        (New-UploadTestCloudApp -Id $id1 -Activated $false),
        (New-UploadTestCloudApp -Id $id2 -Activated $false)
    )}
}
$ambiguousUpload = {
    param($App)
    $ambiguousState.Posts++
    [pscustomobject]@{kind='http_502';candidate_id='';candidate_present=$false;candidate_valid=$true}
}
$ambiguousDelete = { param($Id) $ambiguousState.Deletes++ }
$ambiguousError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp) `
        -ListApps $ambiguousList -UploadApp $ambiguousUpload `
        -DeleteApp $ambiguousDelete)
} catch { $ambiguousError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($ambiguousError -match '\[readback_duplicate' -and
        $ambiguousState.Posts -eq 1 -and $ambiguousState.Deletes -eq 0) `
    -Message 'An identity-ambiguous App was automatically deleted.'

# Raw adapter failures are converted to a fixed category without reflection.
$rawState = [pscustomobject]@{Posts=0;Deletes=0}
$rawUpload = {
    param($App)
    $rawState.Posts++
    throw 'raw_uri=https://shuffle.invalid secret=raw-secret header=raw-header'
}
$rawDelete = { param($Id) $rawState.Deletes++ }
$rawError = ''
try {
    [void](Invoke-UploadTestTransaction -Apps @($testApp) `
        -ListApps $emptyList -UploadApp $rawUpload -DeleteApp $rawDelete `
        -TimeoutSeconds 1)
} catch { $rawError = $_.Exception.Message }
Assert-UploadTestCondition `
    -Condition ($rawError -match '\[readback_timeout' -and
        $rawError -notmatch 'shuffle\.invalid|raw-secret|raw-header' -and
        $rawState.Posts -eq 1 -and $rawState.Deletes -eq 0) `
    -Message 'A raw transport error escaped the fixed-category boundary.'

$runtimeRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('shuffle-soc-app-bundle-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
try {
    $buildOutput = & pwsh -NoProfile -File $buildPath `
        -OutputDirectory $runtimeRoot `
        -ConfirmBuild 'BUILD SHUFFLE SOC APPS' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The rebuilt Validator bundle failed: $($buildOutput -join ' ')"
    }
    $builtManifestFile = Get-ChildItem -LiteralPath $runtimeRoot -Filter 'shuffle-soc-app-bundle-*.json' -File |
        Select-Object -First 1
    if ($null -eq $builtManifestFile) {
        throw 'The rebuilt Validator bundle did not produce a manifest.'
    }
    $manifest = Get-Content -LiteralPath $builtManifestFile.FullName -Raw | ConvertFrom-Json -Depth 20
    $validatorManifestApps = @($manifest.apps | Where-Object {
        [string]$_.name -ceq 'AWS Topology SOC Validator'
    })
    if ($validatorManifestApps.Count -ne 1) {
        throw 'The rebuilt Validator bundle manifest does not contain exactly one Validator.'
    }
    $validatorZip = [IO.Path]::GetFullPath([string]$validatorManifestApps[0].package_path)
    if (-not (Test-Path -LiteralPath $validatorZip -PathType Leaf)) {
        throw 'The rebuilt Validator ZIP is missing.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($validatorZip)
    try {
        $entries = @($archive.Entries | Where-Object {
            -not $_.FullName.EndsWith('/')
        } | ForEach-Object { $_.FullName.Replace('\','/') } | Sort-Object)
        $expectedEntries = @('Dockerfile','api.yaml','requirements.txt','src/app.py') | Sort-Object
        if (($entries -join ',') -cne ($expectedEntries -join ',')) {
            throw "The rebuilt Validator ZIP entries are not exactly four files: $($entries -join ',')"
        }
    } finally {
        $archive.Dispose()
    }
    $validatorAppRoot = Join-Path $root `
        'observability\shuffle\apps\aws-topology-soc-validator\1.0.0'
    [byte[]]$validatorPackageSnapshot = [IO.File]::ReadAllBytes($validatorZip)
    try {
        $validatorPackageProof = Assert-SocShuffleValidatorPackageSnapshot `
            -PackageBytes $validatorPackageSnapshot -AppRoot $validatorAppRoot
        if ([string]$validatorPackageProof.PackageSha256 -cne
            [string]$validatorManifestApps[0].package_sha256) {
            throw 'The built Validator manifest hash differs from its canonical byte snapshot proof.'
        }
    } finally {
        [Array]::Clear($validatorPackageSnapshot, 0, $validatorPackageSnapshot.Length)
    }
    [byte[]]$entryBytes = Get-TestZipEntryBytes -ZipPath $validatorZip -EntryName 'src/app.py'
    $expectedEntrySource = New-SocShuffleValidatorPackagedApp -ValidatorSourcePath (
        Join-Path $root 'observability\shuffle\apps\aws-topology-soc-validator\1.0.0\src\validator.py'
    )
    $entryProof = Assert-SocShuffleValidatorPackagedAppSource `
        -ActualBytes $entryBytes -ExpectedSource $expectedEntrySource
    $entrySource = [string]$entryProof.Source
    $compatPreview = (& pwsh -NoProfile -File $compatUploadPath `
        -PackagePath $validatorZip 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0 -or
        $compatPreview -notmatch "Preview only.*UPLOAD SHUFFLE VALIDATOR") {
        throw 'The compatibility installer did not validate the exact package before its legacy confirmation boundary.'
    }
    if (-not (Test-SocShuffleValidatorEntrypointContract -Source $entrySource)) {
        throw 'The rebuilt Validator entrypoint is not self-contained.'
    }
    $entrySourceBytes = [Text.UTF8Encoding]::new($false).GetByteCount($entrySource)
    if ($entrySourceBytes -ge 9KB) {
        throw "The rebuilt Validator src/app.py is not Cloud-minimal: $entrySourceBytes bytes."
    }
    foreach ($forbiddenPattern in @(
        '(?m)^from[ \t]+__future__[ \t]+import\b',
        '(?m)^(from[ \t]+typing[ \t]+import|import[ \t]+typing\b)',
        '(?m)^import[ \t]+hmac\b',
        '(?m)^class[ \t]+(ValidationError|AllowlistError)\b',
        '(?m)^@[ \t]*dataclass\b'
    )) {
        if ($entrySource -match $forbiddenPattern) {
            throw "The rebuilt Validator src/app.py violates its Cloud-minimal source contract: $forbiddenPattern"
        }
    }
    $expectedImportLines = @(
        'import hashlib',
        'import json',
        'import re',
        'from datetime import datetime',
        'from shuffle_sdk import AppBase'
    ) | Sort-Object
    $actualImportLines = @(
        [regex]::Matches($entrySource, '(?m)^(?:from|import)[^\r\n]+$') |
            ForEach-Object { $_.Value.Trim() } |
            Sort-Object
    )
    if (($actualImportLines -join ',') -cne ($expectedImportLines -join ',')) {
        throw 'The rebuilt Validator src/app.py imports outside its exact allowlist.'
    }

    $tamperCases = @(
        [pscustomobject]@{Label='api-bytes';Target='api.yaml';Mode='flip';Injection=''},
        [pscustomobject]@{Label='docker-bytes';Target='Dockerfile';Mode='flip';Injection=''},
        [pscustomobject]@{Label='requirements-bytes';Target='requirements.txt';Mode='flip';Injection=''},
        [pscustomobject]@{Label='app-bytes';Target='src\app.py';Mode='flip';Injection=''},
        [pscustomobject]@{
            Label='duplicate-global';Target='src\app.py';Mode='append'
            Injection="`n`ndef validate_sanitized_alert(input_data):`n    return {'valid': True}`n"
        },
        [pscustomobject]@{
            Label='api-key-token';Target='src\app.py';Mode='append'
            Injection="`nAPI_KEY = 'injected'`nTOKEN = 'injected'`n"
        }
    )
    foreach ($tamperCase in $tamperCases) {
        $tamperRoot = Join-Path $runtimeRoot ('tamper-' + [string]$tamperCase.Label)
        $tamperExpanded = Join-Path $tamperRoot 'expanded'
        $tamperZip = Join-Path $tamperRoot 'tampered-validator.zip'
        $tamperManifestPath = Join-Path $tamperRoot 'updated-manifest.json'
        New-Item -ItemType Directory -Path $tamperRoot -Force | Out-Null
        Expand-Archive -LiteralPath $validatorZip -DestinationPath $tamperExpanded
        $tamperTarget = Join-Path $tamperExpanded ([string]$tamperCase.Target)
        if ([string]$tamperCase.Mode -ceq 'flip') {
            [byte[]]$tamperTargetBytes = [IO.File]::ReadAllBytes($tamperTarget)
            $tamperTargetBytes[0] = $tamperTargetBytes[0] -bxor 1
            [IO.File]::WriteAllBytes($tamperTarget, $tamperTargetBytes)
        } else {
            $tamperTargetText = [IO.File]::ReadAllText(
                $tamperTarget,
                [Text.UTF8Encoding]::new($false, $true)
            )
            [IO.File]::WriteAllText(
                $tamperTarget,
                ($tamperTargetText + [string]$tamperCase.Injection),
                [Text.UTF8Encoding]::new($false)
            )
        }
        Compress-Archive -LiteralPath @(
            (Join-Path $tamperExpanded 'api.yaml'),
            (Join-Path $tamperExpanded 'Dockerfile'),
            (Join-Path $tamperExpanded 'requirements.txt'),
            (Join-Path $tamperExpanded 'src')
        ) -DestinationPath $tamperZip -CompressionLevel Optimal
        $tamperHash = (Get-FileHash -LiteralPath $tamperZip -Algorithm SHA256).Hash.ToLowerInvariant()
        $tamperedManifest = (($manifest | ConvertTo-Json -Depth 20) |
            ConvertFrom-Json -Depth 20)
        $tamperedManifest.apps[0].package_path = $tamperZip
        $tamperedManifest.apps[0].package_sha256 = $tamperHash
        [IO.File]::WriteAllText(
            $tamperManifestPath,
            (($tamperedManifest | ConvertTo-Json -Depth 20) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        $tamperedReadback = Get-Content -LiteralPath $tamperManifestPath -Raw |
            ConvertFrom-Json -Depth 20
        if ([string]$tamperedReadback.apps[0].package_sha256 -cne $tamperHash -or
            (Get-FileHash -LiteralPath ([string]$tamperedReadback.apps[0].package_path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $tamperHash) {
            throw "The $([string]$tamperCase.Label) fixture did not update its manifest hash."
        }
        [byte[]]$tamperedBytes = [IO.File]::ReadAllBytes($tamperZip)
        $tamperError = ''
        try {
            [void](Assert-SocShuffleValidatorPackageSnapshot `
                -PackageBytes $tamperedBytes -AppRoot $validatorAppRoot)
        } catch {
            $tamperError = [string]$_.Exception.Message
        } finally {
            [Array]::Clear($tamperedBytes, 0, $tamperedBytes.Length)
        }
        if ($tamperError -notmatch 'central-directory length is invalid|does not exactly match canonical bytes') {
            throw "The updated-hash $([string]$tamperCase.Label) ZIP was not rejected by package-wide byte proof."
        }
        $canonicalTamperOutput = (& pwsh -NoProfile -File $uploadPath `
            -ManifestPath $tamperManifestPath 2>&1) -join "`n"
        if ($LASTEXITCODE -eq 0 -or
            $canonicalTamperOutput -notmatch 'central-directory length is invalid|does not exactly match canonical bytes') {
            throw "The canonical installer accepted the updated-hash $([string]$tamperCase.Label) ZIP."
        }
        $compatTamperOutput = (& pwsh -NoProfile -File $compatUploadPath `
            -PackagePath $tamperZip 2>&1) -join "`n"
        if ($LASTEXITCODE -eq 0 -or
            $compatTamperOutput -notmatch 'central-directory length is invalid|does not exactly match canonical bytes') {
            throw "The compatibility installer accepted the updated-hash $([string]$tamperCase.Label) ZIP."
        }
    }

    $expectedPackage = New-SocShuffleValidatorExpectedPackage -AppRoot $validatorAppRoot
    foreach ($hugeEntryName in @($expectedPackage.Names)) {
        $hugeZip = Join-Path $runtimeRoot (
            'zip-bomb-' + ($hugeEntryName -replace '[^A-Za-z0-9]','-') + '.zip'
        )
        $hugeDefinitions = [Collections.Generic.List[object]]::new()
        foreach ($entryName in @($expectedPackage.Names)) {
            [byte[]]$fixtureBytes = if ($entryName -ceq $hugeEntryName) {
                [byte[]]::new(1MB)
            } else {
                [byte[]]$expectedPackage.Entries[$entryName].Bytes
            }
            $hugeDefinitions.Add([pscustomobject]@{Name=$entryName;Bytes=$fixtureBytes})
        }
        New-TestZipArchive -ZipPath $hugeZip -Entries @($hugeDefinitions)
        if ((Get-Item -LiteralPath $hugeZip).Length -gt 128KB) {
            throw "The $hugeEntryName zip-bomb fixture is not a small compressed archive."
        }
        [byte[]]$hugePackageBytes = [IO.File]::ReadAllBytes($hugeZip)
        $hugeError = ''
        try {
            [void](Assert-SocShuffleValidatorPackageSnapshot `
                -PackageBytes $hugePackageBytes -AppRoot $validatorAppRoot)
        } catch {
            $hugeError = [string]$_.Exception.Message
        } finally {
            [Array]::Clear($hugePackageBytes, 0, $hugePackageBytes.Length)
        }
        if ($hugeError -notmatch 'central-directory length is invalid') {
            throw "The small ZIP with huge $hugeEntryName content was not rejected before decompression."
        }
    }

    $pathFixtures = @(
        [pscustomobject]@{Label='duplicate';Mode='duplicate'},
        [pscustomobject]@{Label='backslash-path';Mode='path'}
    )
    foreach ($pathFixture in $pathFixtures) {
        $pathZip = Join-Path $runtimeRoot ('zip-path-' + [string]$pathFixture.Label + '.zip')
        $pathDefinitions = [Collections.Generic.List[object]]::new()
        foreach ($entryName in @($expectedPackage.Names)) {
            $fixtureName = if ([string]$pathFixture.Mode -ceq 'path' -and
                $entryName -ceq 'src/app.py') { 'src\app.py' } else { $entryName }
            $pathDefinitions.Add([pscustomobject]@{
                Name=$fixtureName
                Bytes=[byte[]]$expectedPackage.Entries[$entryName].Bytes
            })
        }
        if ([string]$pathFixture.Mode -ceq 'duplicate') {
            $pathDefinitions.Add([pscustomobject]@{
                Name='src/app.py'
                Bytes=[byte[]]$expectedPackage.Entries['src/app.py'].Bytes
            })
        }
        New-TestZipArchive -ZipPath $pathZip -Entries @($pathDefinitions)
        [byte[]]$pathPackageBytes = [IO.File]::ReadAllBytes($pathZip)
        $pathError = ''
        try {
            [void](Assert-SocShuffleValidatorPackageSnapshot `
                -PackageBytes $pathPackageBytes -AppRoot $validatorAppRoot)
        } catch {
            $pathError = [string]$_.Exception.Message
        } finally {
            [Array]::Clear($pathPackageBytes, 0, $pathPackageBytes.Length)
        }
        if ($pathError -notmatch 'duplicate, directory, or non-canonical path') {
            throw "The $([string]$pathFixture.Label) ZIP path fixture was accepted."
        }
    }

    foreach ($invalidEntrypoint in @(
        @'
def validate_sanitized_alert(input_data):
    pass
class AwsTopologySocValidator(AppBase):
    def validate_sanitized_alert(self, input_data):
        pass
'@,
        @'
def validate_sanitized_alert(input_data):
    pass
def classify_dedupe_claim(claim_result, expected_key):
    pass
class AwsTopologySocValidator(AppBase):
    pass
'@,
        @'
class AwsTopologySocValidator(AppBase):
    def validate_sanitized_alert(self, input_data):
        pass
    def classify_dedupe_claim(self, claim_result, expected_key):
        pass
'@,
        @'
def validate_sanitized_alert(input_data: str):
    pass
def classify_dedupe_claim(claim_result: str, expected_key: str):
    pass
class AwsTopologySocValidator(AppBase):
    def validate_sanitized_alert(self, input_data):
        pass
    def classify_dedupe_claim(self, claim_result, expected_key):
        pass
AwsTopologySocValidator.run()
'@
    )) {
        if (Test-SocShuffleValidatorEntrypointContract -Source $invalidEntrypoint) {
            throw 'The Validator self-contained contract accepted a missing, global-only, or wrapper-only fixture.'
        }
    }

    $packageRoot = Join-Path $runtimeRoot 'expanded'
    Expand-Archive -LiteralPath $validatorZip -DestinationPath $packageRoot
    $appRoot = Join-Path $packageRoot 'src'
    $appPath = Join-Path $appRoot 'app.py'
    $fakeSdk = @'
import json
import sys


class AppBase:
    @classmethod
    def run(cls):
        action = next(
            item.split("=", 1)[1]
            for item in sys.argv[1:]
            if item.startswith("--action=")
        )
        parameters = {}
        for item in sys.argv[1:]:
            if item.startswith("--") or "=" not in item:
                continue
            key, value = item.split("=", 1)
            parameters[key] = value
        result = getattr(cls(), action)(**parameters)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'@
    [IO.File]::WriteAllText(
        (Join-Path $appRoot 'shuffle_sdk.py'),
        ($fakeSdk -replace "`r`n", "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $payload = ((& python -B (Join-Path $root 'observability\shuffle\soc_gate_b5_payload.py') `
        --control-id packaged-runtime `
        --nonce packaged-runtime `
        --case valid) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or -not $payload) {
        throw 'The deterministic runtime payload could not be generated.'
    }
    $validationOutput = (& python -B $appPath `
        --standalone `
        --action=validate_sanitized_alert `
        "input_data=$payload" 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "The packaged validate_sanitized_alert standalone action failed: $validationOutput"
    }
    $validationResult = $validationOutput | ConvertFrom-Json -Depth 20
    if ([bool]$validationResult.valid -ne $true) {
        throw 'The packaged validate_sanitized_alert action rejected the valid contract payload.'
    }
    $eventId = [string]((ConvertFrom-Json -InputObject $payload).incident.cloudtrail_event_id)
    $dedupeKey = "CAPITAL-ONE:433048100798:$eventId"
    $claimJson = ([ordered]@{
        success=$true
        keys_existed=@([ordered]@{key=$dedupeKey;existed=$false})
    } | ConvertTo-Json -Compress -Depth 8)
    $classifierOutput = (& python -B $appPath `
        --standalone `
        --action=classify_dedupe_claim `
        "claim_result=$claimJson" `
        "expected_key=$dedupeKey" 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "The packaged classify_dedupe_claim standalone action failed: $classifierOutput"
    }
    $classifierResult = $classifierOutput | ConvertFrom-Json -Depth 20
    if ([bool]$classifierResult.valid -ne $true -or
        [bool]$classifierResult.existed -ne $false) {
        throw 'The packaged classify_dedupe_claim action returned an unexpected result.'
    }
    if (@(Get-ChildItem -LiteralPath $packageRoot -Directory -Filter '__pycache__' -Recurse -Force).Count -ne 0) {
        throw 'The standalone smoke test created pycache in the packaged App tree.'
    }
} finally {
    if (Test-Path -LiteralPath $runtimeRoot) {
        Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
    }
}

Write-Host 'Shuffle SOC private App bundle static tests passed.'
Write-Host 'Shuffle SOC Validator four-file package and standalone smoke tests passed.'
