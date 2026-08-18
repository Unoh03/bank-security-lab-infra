#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
    Add-Type -AssemblyName System.Security
}

function Assert-SocSafeName {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw "$Label is not a safe SOC identifier."
    }
}

function Get-SocSecretRoot {
    [CmdletBinding()]
    param([string]$Root = '')

    if ($Root) {
        return [IO.Path]::GetFullPath($Root)
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is unavailable; the SOC secret root cannot be resolved.'
    }
    return Join-Path $env:LOCALAPPDATA 'aws-topology\soc-secrets'
}

function Get-SocRuntimeRoot {
    [CmdletBinding()]
    param([string]$Root = '')

    if ($Root) {
        return [IO.Path]::GetFullPath($Root)
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is unavailable; the SOC runtime root cannot be resolved.'
    }
    return Join-Path $env:LOCALAPPDATA 'aws-topology\soc-runtime'
}

function Set-SocPrivateDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ($env:OS -cne 'Windows_NT') {
        throw 'SOC private ACL enforcement currently supports Windows only.'
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    New-Item -ItemType Directory -Path $resolved -Force | Out-Null

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = [string]$identity.User.Value
    if ($currentSid -notmatch '^S-1-[0-9-]+$') {
        throw 'The current Windows user SID could not be resolved safely.'
    }

    $arguments = @(
        $resolved,
        '/inheritance:r',
        '/grant:r',
        "*$currentSid`:(OI)(CI)F",
        '*S-1-5-18:(OI)(CI)F'
    )
    $output = @(& icacls.exe @arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'The SOC private directory ACL could not be applied.'
    }
}

function Get-SocDpapiEntropy {
    param([Parameter(Mandatory)][string]$Name)

    return [Text.Encoding]::UTF8.GetBytes("aws-topology-soc-v1:$Name")
}

function Get-SocRandomBytes {
    param([Parameter(Mandatory)][ValidateRange(1, 1024)][int]$Count)

    $buffer = New-Object byte[] $Count
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($buffer)
    } finally {
        $generator.Dispose()
    }
    return ,$buffer
}

function Get-SocRandomInt {
    param([Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$MaximumExclusive)

    $range = [uint64]4294967296
    $limit = $range - ($range % [uint64]$MaximumExclusive)
    do {
        $bytes = Get-SocRandomBytes -Count 4
        try {
            $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    } while ($value -ge $limit)
    return [int]($value % [uint64]$MaximumExclusive)
}

function Protect-SocSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$PlainText,
        [string]$SecretRoot = '',
        [switch]$Force
    )

    Assert-SocSafeName -Value $Name -Label 'Secret name'
    if ([string]::IsNullOrEmpty($PlainText)) {
        throw 'An empty SOC secret cannot be protected.'
    }

    $root = Get-SocSecretRoot -Root $SecretRoot
    Set-SocPrivateDirectoryAcl -Path $root
    $path = Join-Path $root "$Name.dpapi.json"
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and -not $Force.IsPresent) {
        throw "The protected SOC secret already exists: $Name"
    }

    $plainBytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    try {
        $cipherBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes,
            (Get-SocDpapiEntropy -Name $Name),
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $record = [ordered]@{
            schema_version = 1
            name           = $Name
            protected_at   = [DateTimeOffset]::UtcNow.ToString('o')
            scope          = 'CurrentUser'
            cipher_base64  = [Convert]::ToBase64String($cipherBytes)
        } | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText($path, "$record`n", [Text.UTF8Encoding]::new($false))
    } finally {
        if ($plainBytes) {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    }

    return $path
}

function Unprotect-SocSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$SecretRoot = ''
    )

    Assert-SocSafeName -Value $Name -Label 'Secret name'
    $path = Join-Path (Get-SocSecretRoot -Root $SecretRoot) "$Name.dpapi.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The protected SOC secret is unavailable: $Name"
    }

    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ([int]$record.schema_version -ne 1 -or
        [string]$record.name -cne $Name -or
        [string]$record.scope -cne 'CurrentUser' -or
        [string]::IsNullOrWhiteSpace([string]$record.cipher_base64)) {
        throw "The protected SOC secret record is invalid: $Name"
    }

    $cipherBytes = [Convert]::FromBase64String([string]$record.cipher_base64)
    $plainBytes = $null
    try {
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $cipherBytes,
            (Get-SocDpapiEntropy -Name $Name),
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Text.Encoding]::UTF8.GetString($plainBytes)
    } finally {
        if ($cipherBytes) {
            [Array]::Clear($cipherBytes, 0, $cipherBytes.Length)
        }
        if ($plainBytes) {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    }
}

function New-SocStrongSecret {
    [CmdletBinding()]
    param([ValidateRange(24, 64)][int]$Length = 32)

    $groups = @(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        '.*+?-'
    )
    $alphabet = ($groups -join '')
    $characters = [Collections.Generic.List[char]]::new()

    foreach ($group in $groups) {
        $characters.Add($group[(Get-SocRandomInt -MaximumExclusive $group.Length)])
    }
    while ($characters.Count -lt $Length) {
        $characters.Add($alphabet[(Get-SocRandomInt -MaximumExclusive $alphabet.Length)])
    }
    for ($index = $characters.Count - 1; $index -gt 0; $index--) {
        $swap = Get-SocRandomInt -MaximumExclusive ($index + 1)
        $temporary = $characters[$index]
        $characters[$index] = $characters[$swap]
        $characters[$swap] = $temporary
    }
    return -join $characters
}

function New-SocTakeId {
    [CmdletBinding()]
    param([datetimeoffset]$Now = [datetimeoffset]::UtcNow)

    $suffix = Get-SocRandomBytes -Count 4
    try {
        $hex = ([BitConverter]::ToString($suffix)).Replace('-', '').ToLowerInvariant()
        return 'capital-one-{0}-{1}' -f $Now.ToUniversalTime().ToString('yyyyMMddTHHmmssZ'),$hex
    } finally {
        [Array]::Clear($suffix, 0, $suffix.Length)
    }
}

function Write-SocRuntimeSecretFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Content,
        [string]$RuntimeRoot = ''
    )

    Assert-SocSafeName -Value $SessionId -Label 'SOC runtime session ID'
    if ([IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath -notmatch '^[A-Za-z0-9._-]+([\\/][A-Za-z0-9._-]+)*$') {
        throw 'The SOC runtime secret relative path is unsafe.'
    }

    $root = Get-SocRuntimeRoot -Root $RuntimeRoot
    $sessionPath = Join-Path $root $SessionId
    Set-SocPrivateDirectoryAcl -Path $sessionPath
    $target = Join-Path $sessionPath $RelativePath
    $parent = Split-Path -Parent $target
    if ($parent -and $parent -cne $sessionPath) {
        Set-SocPrivateDirectoryAcl -Path $parent
    }
    [IO.File]::WriteAllText($target, $Content, [Text.UTF8Encoding]::new($false))
    return $target
}

function Remove-SocRuntimeSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [string]$RuntimeRoot = ''
    )

    Assert-SocSafeName -Value $SessionId -Label 'SOC runtime session ID'
    $root = Get-SocRuntimeRoot -Root $RuntimeRoot
    $sessionPath = [IO.Path]::GetFullPath((Join-Path $root $SessionId))
    $expectedPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if (-not $sessionPath.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The SOC runtime session path escaped its approved root.'
    }
    if (Test-Path -LiteralPath $sessionPath) {
        Remove-Item -LiteralPath $sessionPath -Recurse -Force
    }
}

function Find-SocSecretExposure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path)

    $defaultAdmin = 'Secret' + 'Password'
    $defaultApi = 'MyS3cr37P450r.' + '*-'
    $defaultKibanaAssignment = 'DASHBOARD_' + 'PASSWORD\s*=\s*kibanaserver'
    $rules = [ordered]@{
        AwsAccessKey       = '(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'
        GitHubToken        = '(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})(?![A-Za-z0-9_])'
        PrivateKey         = '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        Jwt                = '(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])'
        ShuffleWebhook     = 'https://[^\s''"]*shuffler\.io/api/v1/hooks/[A-Za-z0-9_-]{16,}'
        WazuhDefaultAdmin  = [regex]::Escape($defaultAdmin)
        WazuhDefaultKibana = $defaultKibanaAssignment
        WazuhDefaultApi    = [regex]::Escape($defaultApi)
    }
    $ignoredExtensions = @('.png','.jpg','.jpeg','.gif','.pdf','.zip','.gz','.7z','.exe','.dll','.tfstate')
    $findings = [Collections.Generic.List[object]]::new()

    $files = [Collections.Generic.List[string]]::new()
    foreach ($candidate in $Path) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if ($item.PSIsContainer) {
            foreach ($file in Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force -ErrorAction SilentlyContinue) {
                $files.Add($file.FullName)
            }
        } else {
            $files.Add($item.FullName)
        }
    }

    foreach ($filePath in @($files | Sort-Object -Unique)) {
        $file = Get-Item -LiteralPath $filePath -Force
        if ($file.Length -gt 5MB -or $ignoredExtensions -contains $file.Extension.ToLowerInvariant()) {
            continue
        }
        try {
            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
        } catch {
            continue
        }
        foreach ($entry in $rules.GetEnumerator()) {
            if ($text -match [string]$entry.Value) {
                $findings.Add([pscustomobject]@{
                    Path = $file.FullName
                    Rule = [string]$entry.Key
                })
            }
        }
    }

    return @($findings)
}

Export-ModuleMember -Function @(
    'Get-SocSecretRoot',
    'Get-SocRuntimeRoot',
    'Set-SocPrivateDirectoryAcl',
    'Protect-SocSecret',
    'Unprotect-SocSecret',
    'New-SocStrongSecret',
    'New-SocTakeId',
    'Write-SocRuntimeSecretFile',
    'Remove-SocRuntimeSession',
    'Find-SocSecretExposure'
)
