#requires -Version 7.4

function New-SocShuffleValidatorPackagedApp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ValidatorSourcePath)

    $utf8NoBom = [Text.UTF8Encoding]::new($false, $true)
    $validatorSource = [IO.File]::ReadAllText($ValidatorSourcePath, $utf8NoBom)
    $validatorSource = $validatorSource.Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd()
    if ($validatorSource -match '(?m)^\s*class\s+AwsTopologySocValidator\b' -or
        $validatorSource -match '(?m)^\s*if\s+__name__\s*==\s*["'']__main__["'']\s*:') {
        throw 'The canonical Validator module must contain logic only; AppBase entrypoint code is generated separately.'
    }
    foreach ($functionName in @('validate_sanitized_alert','classify_dedupe_claim')) {
        if ($validatorSource -notmatch "(?m)^def\s+$functionName\s*\(") {
            throw "The canonical Validator module is missing the required function: $functionName"
        }
    }

    $wrapper = @(
        'class AwsTopologySocValidator(AppBase):',
        '    __version__ = "1.0.0"',
        '    app_name = "AWS Topology SOC Validator"',
        '',
        '    def validate_sanitized_alert(self, input_data):',
        '        return validate_sanitized_alert(input_data)',
        '',
        '    def classify_dedupe_claim(self, claim_result, expected_key):',
        '        return classify_dedupe_claim(claim_result, expected_key)',
        '',
        'if __name__ == "__main__":',
        '    AwsTopologySocValidator.run()'
    ) -join "`n"
    $packagedSource = "from shuffle_sdk import AppBase`n`n" + `
        $validatorSource + "`n`n" + $wrapper + "`n"
    if ($utf8NoBom.GetByteCount($packagedSource) -ge 9KB) {
        throw 'The generated Validator src/app.py must remain smaller than 9 KiB.'
    }
    foreach ($forbiddenPattern in @(
        '(?m)^from[ \t]+__future__[ \t]+import\b',
        '(?m)^(from[ \t]+typing[ \t]+import|import[ \t]+typing\b)',
        '(?m)^import[ \t]+hmac\b',
        '(?m)^class[ \t]+(ValidationError|AllowlistError)\b',
        '(?m)^@[ \t]*dataclass\b',
        '(?im)^[ \t]*(api[_-]?key|token|password|secret)[ \t]*='
    )) {
        if ($packagedSource -match $forbiddenPattern) {
            throw "The generated Validator src/app.py violates its Cloud-minimal source contract: $forbiddenPattern"
        }
    }
    return $packagedSource
}

function Get-SocShuffleValidatorSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Test-SocShuffleValidatorBytesEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Actual,
        [Parameter(Mandatory)][byte[]]$Expected
    )

    if ($Actual.Length -ne $Expected.Length) { return $false }
    for ($index = 0; $index -lt $Actual.Length; $index++) {
        if ($Actual[$index] -ne $Expected[$index]) { return $false }
    }
    return $true
}

function New-SocShuffleValidatorExpectedPackage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AppRoot)

    $resolvedAppRoot = [IO.Path]::GetFullPath($AppRoot)
    $rawFiles = [ordered]@{
        'api.yaml'=[pscustomobject]@{RelativePath='api.yaml';MaxBytes=64KB}
        'Dockerfile'=[pscustomobject]@{RelativePath='Dockerfile';MaxBytes=16KB}
        'requirements.txt'=[pscustomobject]@{RelativePath='requirements.txt';MaxBytes=16KB}
    }
    $expected = [ordered]@{}
    foreach ($entryName in $rawFiles.Keys) {
        $definition = $rawFiles[$entryName]
        $sourcePath = Join-Path $resolvedAppRoot ([string]$definition.RelativePath)
        $sourceInfo = Get-Item -LiteralPath $sourcePath
        if ($sourceInfo.Length -le 0 -or $sourceInfo.Length -gt [int]$definition.MaxBytes) {
            throw "The canonical Validator package source is empty or too large: $entryName"
        }
        [byte[]]$sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
        $expected[$entryName] = [pscustomobject][ordered]@{
            Name=$entryName
            Bytes=$sourceBytes
            Length=$sourceBytes.Length
            MaxBytes=[int]$definition.MaxBytes
            Sha256=(Get-SocShuffleValidatorSha256 -Bytes $sourceBytes)
        }
    }

    $validatorSourcePath = Join-Path $resolvedAppRoot 'src\validator.py'
    $packagedSource = New-SocShuffleValidatorPackagedApp `
        -ValidatorSourcePath $validatorSourcePath
    [byte[]]$packagedBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($packagedSource)
    $expected['src/app.py'] = [pscustomobject][ordered]@{
        Name='src/app.py'
        Bytes=$packagedBytes
        Length=$packagedBytes.Length
        MaxBytes=9KB
        Sha256=(Get-SocShuffleValidatorSha256 -Bytes $packagedBytes)
    }
    return [pscustomobject][ordered]@{
        Names=@('api.yaml','Dockerfile','requirements.txt','src/app.py')
        Entries=$expected
    }
}

function Assert-SocShuffleValidatorPackageSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PackageBytes,
        [Parameter(Mandatory)][string]$AppRoot
    )

    if ($PackageBytes.Length -le 0 -or $PackageBytes.Length -gt 5MB) {
        throw 'The Validator ZIP snapshot is empty or exceeds 5 MiB.'
    }
    $expected = New-SocShuffleValidatorExpectedPackage -AppRoot $AppRoot
    $packageStream = [IO.MemoryStream]::new($PackageBytes, $false)
    $archive = $null
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $packageStream,
            [IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $archive.Entries) {
            $entryName = [string]$entry.FullName
            if ($entryName -cnotin @($expected.Names) -or
                -not $seen.Add($entryName) -or
                [string]::IsNullOrEmpty([string]$entry.Name)) {
                throw 'The Validator ZIP contains a duplicate, directory, or non-canonical path.'
            }
            $entryExpected = $expected.Entries[$entryName]
            if ($entry.Length -ne [long]$entryExpected.Length -or
                $entry.Length -gt [long]$entryExpected.MaxBytes -or
                $entry.CompressedLength -lt 0 -or
                $entry.CompressedLength -gt $PackageBytes.Length) {
                throw "The Validator ZIP central-directory length is invalid: $entryName"
            }
        }
        if ($seen.Count -ne @($expected.Names).Count) {
            throw 'The Validator ZIP does not contain exactly four canonical files.'
        }

        $proofEntries = [Collections.Generic.List[object]]::new()
        foreach ($entryName in @($expected.Names)) {
            $entry = $archive.GetEntry($entryName)
            $entryExpected = $expected.Entries[$entryName]
            [byte[]]$actualBytes = [byte[]]::new([int]$entryExpected.Length)
            $entryStream = $entry.Open()
            try {
                $offset = 0
                while ($offset -lt $actualBytes.Length) {
                    $read = $entryStream.Read(
                        $actualBytes,
                        $offset,
                        $actualBytes.Length - $offset
                    )
                    if ($read -le 0) {
                        throw "The Validator ZIP entry ended before its canonical length: $entryName"
                    }
                    $offset += $read
                }
                if ($entryStream.ReadByte() -ne -1) {
                    throw "The Validator ZIP entry exceeds its canonical length: $entryName"
                }
            } finally {
                $entryStream.Dispose()
            }
            $actualSha256 = Get-SocShuffleValidatorSha256 -Bytes $actualBytes
            if (-not (Test-SocShuffleValidatorBytesEqual `
                    -Actual $actualBytes -Expected ([byte[]]$entryExpected.Bytes)) -or
                $actualSha256 -cne [string]$entryExpected.Sha256) {
                throw "The Validator ZIP entry does not exactly match canonical bytes: $entryName"
            }
            $proofEntries.Add([pscustomobject][ordered]@{
                Name=$entryName
                Length=$actualBytes.Length
                Sha256=$actualSha256
            })
        }
        return [pscustomobject][ordered]@{
            PackageSha256=(Get-SocShuffleValidatorSha256 -Bytes $PackageBytes)
            Entries=@($proofEntries)
        }
    } catch [IO.InvalidDataException] {
        throw 'The Validator ZIP snapshot is structurally invalid.'
    } finally {
        if ($archive) { $archive.Dispose() }
        $packageStream.Dispose()
    }
}

function Assert-SocShuffleValidatorPackagedAppSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$ActualBytes,
        [Parameter(Mandatory)][string]$ExpectedSource
    )

    $utf8NoBom = [Text.UTF8Encoding]::new($false, $true)
    $expectedBytes = $utf8NoBom.GetBytes($ExpectedSource)
    try {
        $actualSource = $utf8NoBom.GetString($ActualBytes)
    } catch {
        throw 'The Validator ZIP src/app.py is not strict UTF-8.'
    }
    $actualSha256 = Get-SocShuffleValidatorSha256 -Bytes $ActualBytes
    $expectedSha256 = Get-SocShuffleValidatorSha256 -Bytes $expectedBytes
    $bytesEqual = Test-SocShuffleValidatorBytesEqual `
        -Actual $ActualBytes -Expected $expectedBytes
    if (-not $bytesEqual -or
        -not [string]::Equals($actualSource, $ExpectedSource, [StringComparison]::Ordinal) -or
        $actualSha256 -cne $expectedSha256) {
        throw 'The Validator ZIP src/app.py does not exactly match the deterministic canonical source.'
    }
    return [pscustomobject][ordered]@{
        Source=$actualSource
        SourceSha256=$actualSha256
        SourceBytes=$ActualBytes.Length
    }
}
