#requires -Version 7.4
[CmdletBinding()]
param(
    [Alias('WorkflowId')][string]$NewWorkflowId = '',
    [Alias('WebhookId')][string]$NewWebhookId = '',
    [string]$ConfigurationRoot = '',
    [string]$SecretRoot = '',
    [string]$ConfirmSwitch = '',
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SocShuffleV2LibraryOnly = $LibraryOnly.IsPresent
$script:SocShuffleV2UuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$script:SocShuffleV2MutexName = 'Local\AWS-Topology-Soc-Shuffle-V2-Runtime-Switch-v1'
$script:SocShuffleV2MarkerName = 'shuffle-v2-runtime-switch.transaction.json'
$script:SocShuffleV2ThreatBoundary = @'
Private Windows ACLs block other local principals from the fixed SOC roots.
DPAPI CurrentUser does not block a malicious process already running as that
same CurrentUser from decrypting the record. A same-CurrentUser reparse-race
attacker is outside this transaction helper's threat boundary.
'@
$script:SocShuffleV2ConfigFields = @(
    'schema_version','shuffle_api_base','shuffle_org_id','shuffle_workflow_id',
    'shuffle_webhook_id','github_repository','github_ref','containment_workflow',
    'reset_workflow','argo_application','wazuh_root','aws_profile'
)

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Configuration.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Shuffle.psm1') -Force

function Get-SocShuffleV2CurrentUserSid {
    if ($env:OS -cne 'Windows_NT') {
        throw 'The live Shuffle runtime ACL boundary requires Windows.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User -or [string]$identity.User.Value -notmatch '^S-1-[0-9-]+$') {
        throw 'The current Windows SID is unavailable.'
    }
    return [string]$identity.User.Value
}

function Assert-SocShuffleV2PrivatePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Directory','File')][string]$Kind
    )
    if ($env:OS -cne 'Windows_NT') {
        throw 'The live Shuffle runtime ACL boundary requires Windows.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $expectedPathType = if ($Kind -ceq 'Directory') { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $full -PathType $expectedPathType)) {
        throw 'A private SOC ACL target is unavailable.'
    }
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
    $currentSid = Get-SocShuffleV2CurrentUserSid
    $systemSid = 'S-1-5-18'
    $acl = Get-Acl -LiteralPath $full
    $ownerSid = [string]($acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value)
    if ($ownerSid -cne $currentSid) {
        throw 'A private SOC ACL target is not owned by CurrentUser.'
    }
    if ($Kind -ceq 'Directory' -and -not $acl.AreAccessRulesProtected) {
        throw 'A private SOC directory still inherits external ACL entries.'
    }
    $rules = @($acl.GetAccessRules(
        $true,$true,[Security.Principal.SecurityIdentifier]
    ))
    $currentUserCanWrite = $false
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = [string]$rule.IdentityReference.Value
        if ($sid -notin @($currentSid,$systemSid)) {
            throw 'A private SOC ACL grants access to an unapproved local principal.'
        }
        if ($sid -ceq $currentSid -and
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
             ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -ne 0 -or
             ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0)) {
            $currentUserCanWrite = $true
        }
    }
    if (-not $currentUserCanWrite) {
        throw 'CurrentUser lacks the required private SOC write boundary.'
    }
}

function Set-SocShuffleV2PrivateDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
    Set-SocPrivateDirectoryAcl -Path $full
    $currentSid = [Security.Principal.SecurityIdentifier]::new(
        (Get-SocShuffleV2CurrentUserSid)
    )
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true,$false)
    $directoryAcl.SetOwner($currentSid)
    foreach ($sid in @($currentSid,$systemSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$directoryAcl.AddAccessRule($rule)
    }
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
    Set-Acl -LiteralPath $full -AclObject $directoryAcl
    Assert-SocShuffleV2PrivatePathAcl -Path $full -Kind Directory
}

function Assert-SocShuffleV2InheritedPrivateFileAcl {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
    Assert-SocShuffleV2PrivatePathAcl -Path $full -Kind File
    $acl = Get-Acl -LiteralPath $full
    if ($acl.AreAccessRulesProtected) {
        throw 'A private SOC transaction file must inherit its root ACL.'
    }
    $currentSid = Get-SocShuffleV2CurrentUserSid
    $systemSid = 'S-1-5-18'
    $inheritedAllowSids = @($acl.GetAccessRules(
        $true,$true,[Security.Principal.SecurityIdentifier]
    ) | Where-Object {
        $_.IsInherited -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
    } | ForEach-Object { [string]$_.IdentityReference.Value })
    if ($currentSid -notin $inheritedAllowSids -or
        $systemSid -notin $inheritedAllowSids) {
        throw 'A private SOC transaction file did not inherit both approved principals.'
    }
}

function Initialize-SocShuffleV2CanonicalPrivateRoots {
    param(
        [Parameter(Mandatory)][string]$ConfigurationRoot,
        [Parameter(Mandatory)][string]$SecretRoot
    )
    $canonicalConfigurationRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path (Get-SocConfigurationRoot -Root '') -Label 'Live configuration root'
    $canonicalSecretRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path (Get-SocSecretRoot -Root '') -Label 'Live secret root'
    $requestedConfigurationRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path $ConfigurationRoot -Label 'Configuration root'
    $requestedSecretRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path $SecretRoot -Label 'Secret root'
    if ($requestedConfigurationRoot -ine $canonicalConfigurationRoot -or
        $requestedSecretRoot -ine $canonicalSecretRoot) {
        throw 'Private ACL preparation is restricted to the fixed SOC app roots.'
    }
    foreach ($root in @($canonicalConfigurationRoot,$canonicalSecretRoot)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            $parent = Split-Path -Parent $root
            [void](Assert-SocShuffleV2NoReparsePathChain -Path $parent)
            New-Item -ItemType Directory -Path $root | Out-Null
        }
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $root)
        Set-SocShuffleV2PrivateDirectoryAcl -Path $root
    }
}

function New-SocShuffleV2RuntimeFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'configuration','root','mutex','drift','secret','workflow-readback',
            'journal','write','recovery','rollback','simulated-crash'
        )][string]$Category,
        [string]$WorkflowId = '',
        [string]$WebhookId = ''
    )

    $ids = [Collections.Generic.List[string]]::new()
    if ($WorkflowId -match $script:SocShuffleV2UuidPattern) {
        [void]$ids.Add("workflow_id=$WorkflowId")
    }
    if ($WebhookId -match $script:SocShuffleV2UuidPattern) {
        [void]$ids.Add("webhook_id=$WebhookId")
    }
    $suffix = if ($ids.Count -eq 0) { '' } else { " ($($ids -join ';'))" }
    return "Shuffle v2 runtime switch failed [$Category]$suffix. URI, Header, credential, path, and exception details were withheld."
}

function Assert-SocShuffleV2RuntimeUuid {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    if ($Value -cnotmatch $script:SocShuffleV2UuidPattern) {
        throw "$Label is not a canonical UUID."
    }
}

function Get-SocShuffleV2BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Get-SocShuffleV2OrdinaryDosAbsolutePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    # Test and live runtime roots intentionally support only ordinary local
    # drive-letter DOS paths. UNC, device, extended, and Volume GUID aliases
    # are outside this helper's input surface and are rejected before resolve.
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -cnotmatch '^[A-Za-z]:\\') {
        throw "$Label is not an ordinary drive-letter DOS absolute path."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ($full -cnotmatch '^[A-Za-z]:\\' -or
        $root -cnotmatch '^[A-Za-z]:\\$') {
        throw "$Label did not canonicalize to an ordinary drive-letter DOS path."
    }
    return $full
}

function Assert-SocShuffleV2NoReparsePathChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissingLeaf
    )

    $full = [IO.Path]::GetFullPath($Path)
    $pathRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($pathRoot)) {
        throw 'A SOC runtime path has no fixed filesystem root.'
    }
    if (Test-Path -LiteralPath $pathRoot) {
        $rootItem = Get-Item -LiteralPath $pathRoot -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A SOC runtime filesystem root cannot be a reparse point.'
        }
    }
    $separators = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $relative = $full.Substring($pathRoot.Length).Trim($separators)
    $parts = if ($relative) { @($relative.Split($separators,[StringSplitOptions]::RemoveEmptyEntries)) } else { @() }
    $cursor = $pathRoot
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $cursor = Join-Path $cursor $parts[$index]
        $isLeaf = ($index -eq $parts.Count - 1)
        if (-not (Test-Path -LiteralPath $cursor)) {
            if ($AllowMissingLeaf.IsPresent -and $isLeaf) { continue }
            throw 'A SOC runtime path component is unavailable.'
        }
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A SOC runtime path component cannot be a reparse point.'
        }
    }
    return $full
}

function Test-SocShuffleV2PathOverlap {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$ProtectedRoot
    )
    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\','/')
    $protectedFull = [IO.Path]::GetFullPath($ProtectedRoot).TrimEnd('\','/')
    if (-not $candidateFull) { $candidateFull=[IO.Path]::GetPathRoot($Candidate) }
    if (-not $protectedFull) { $protectedFull=[IO.Path]::GetPathRoot($ProtectedRoot) }
    if ($candidateFull -ieq $protectedFull) { return $true }
    $separator = [string][IO.Path]::DirectorySeparatorChar
    return ($candidateFull.StartsWith(
            ($protectedFull+$separator),[StringComparison]::OrdinalIgnoreCase
        ) -or
        $protectedFull.StartsWith(
            ($candidateFull+$separator),[StringComparison]::OrdinalIgnoreCase
        ))
}

function Assert-SocShuffleV2TestRootsIsolated {
    param(
        [Parameter(Mandatory)][string]$ConfigurationRoot,
        [Parameter(Mandatory)][string]$SecretRoot
    )
    if (-not $script:SocShuffleV2LibraryOnly) {
        throw 'Test-root isolation is available only in LibraryOnly mode.'
    }
    $candidates = @(
        (Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path $ConfigurationRoot -Label 'Test configuration root'),
        (Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path $SecretRoot -Label 'Test secret root')
    )
    $liveRoots = @(
        (Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocConfigurationRoot -Root '') -Label 'Live configuration root'),
        (Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocSecretRoot -Root '') -Label 'Live secret root')
    )

    # Lexical overlap is rejected first, before any injected test hook can
    # inspect or mutate a live root. Ancestors are also rejected because they
    # are traversal paths through which a live target could be reached.
    foreach ($candidate in $candidates) {
        foreach ($liveRoot in $liveRoots) {
            if (Test-SocShuffleV2PathOverlap `
                -Candidate $candidate -ProtectedRoot $liveRoot) {
                throw 'A test root overlaps a protected live SOC root.'
            }
        }
    }

    $resolvedLiveRoots = [Collections.Generic.List[string]]::new()
    foreach ($liveRoot in $liveRoots) {
        if (-not (Test-Path -LiteralPath $liveRoot -PathType Container)) {
            continue
        }
        # A reparse component in the protected root makes physical isolation
        # ambiguous, so tests fail closed rather than trying to follow it.
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $liveRoot)
        [void]$resolvedLiveRoots.Add(
            [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $liveRoot).Path)
        )
    }
    foreach ($candidate in $candidates) {
        # Reparse aliases are rejected before Resolve-Path, closing junction or
        # symlink routes to the canonical live roots.
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $candidate)
        $resolvedCandidate = [IO.Path]::GetFullPath(
            (Resolve-Path -LiteralPath $candidate).Path
        )
        foreach ($resolvedLiveRoot in $resolvedLiveRoots) {
            if (Test-SocShuffleV2PathOverlap `
                -Candidate $resolvedCandidate -ProtectedRoot $resolvedLiveRoot) {
                throw 'A resolved test root overlaps a protected live SOC root.'
            }
        }
    }
}

function Get-SocShuffleV2RuntimePaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigurationRoot,
        [Parameter(Mandatory)][string]$SecretRoot,
        [switch]$AllowTestRoots
    )

    if ($AllowTestRoots.IsPresent -and -not $script:SocShuffleV2LibraryOnly) {
        throw 'Test roots are available only when the script is loaded as a library.'
    }
    $configurationRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path $ConfigurationRoot -Label 'Configuration root'
    $secretRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
        -Path $SecretRoot -Label 'Secret root'
    if ($AllowTestRoots.IsPresent) {
        Assert-SocShuffleV2TestRootsIsolated `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot
    } else {
        $canonicalConfigurationRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocConfigurationRoot -Root '') -Label 'Live configuration root'
        $canonicalSecretRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocSecretRoot -Root '') -Label 'Live secret root'
        if ($configurationRoot -ine $canonicalConfigurationRoot -or
            $secretRoot -ine $canonicalSecretRoot) {
            throw 'The live runtime switch requires the canonical LOCALAPPDATA roots.'
        }
    }
    if ($configurationRoot -ieq $secretRoot) {
        throw 'The SOC configuration and DPAPI roots must be different.'
    }
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $configurationRoot)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $secretRoot)

    $configPath = [IO.Path]::GetFullPath((Get-SocConfigurationPath -Root $configurationRoot))
    $secretPath = [IO.Path]::GetFullPath((Join-Path $secretRoot 'shuffle_webhook_url.dpapi.json'))
    $markerPath = [IO.Path]::GetFullPath((Join-Path $configurationRoot $script:SocShuffleV2MarkerName))
    $configPrefix = $configurationRoot.TrimEnd('\') + '\'
    $secretPrefix = $secretRoot.TrimEnd('\') + '\'
    if (-not $configPath.StartsWith($configPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($configPath) -cne 'soc-lab.json' -or
        -not $markerPath.StartsWith($configPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($markerPath) -cne $script:SocShuffleV2MarkerName -or
        -not $secretPath.StartsWith($secretPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($secretPath) -cne 'shuffle_webhook_url.dpapi.json') {
        throw 'A SOC runtime target path escaped its fixed root.'
    }
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $configPath)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $secretPath)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $markerPath -AllowMissingLeaf)
    return [pscustomobject][ordered]@{
        ConfigurationRoot=$configurationRoot
        SecretRoot=$secretRoot
        ConfigurationPath=$configPath
        SecretPath=$secretPath
        MarkerPath=$markerPath
    }
}

function Assert-SocShuffleV2RuntimePathsStable {
    param([Parameter(Mandatory)][object]$Paths)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.ConfigurationRoot)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.SecretRoot)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.ConfigurationPath)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.SecretPath)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.MarkerPath -AllowMissingLeaf)
}

function Get-SocShuffleV2RuntimeFileSnapshot {
    param([Parameter(Mandatory)][string]$Path)
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $Path)
    $bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($Path))
    return [pscustomobject][ordered]@{
        Bytes=$bytes
        Length=$bytes.Length
        Sha256=(Get-SocShuffleV2BytesSha256 -Bytes $bytes)
    }
}

function Read-SocShuffleV2ProtectedWebhookUriFromFile {
    param(
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][scriptblock]$AssertPrivatePath
    )
    $root = [IO.Path]::GetFullPath($SecretRoot)
    $path = [IO.Path]::GetFullPath((Join-Path $root 'shuffle_webhook_url.dpapi.json'))
    $prefix = $root.TrimEnd('\') + '\'
    if (-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($path) -cne 'shuffle_webhook_url.dpapi.json') {
        throw 'The protected Shuffle Webhook read escaped the fixed secret root.'
    }
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $root)
    & $AssertPrivatePath $root 'Directory' $false
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $path)
    & $AssertPrivatePath $path 'File' $false
    $snapshot = Get-SocShuffleV2RuntimeFileSnapshot -Path $path
    Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $snapshot.Bytes
    # Unprotect-SocSecret resolves and opens this exact record again. The
    # same-CurrentUser reparse-race attacker is outside the documented threat
    # boundary; other local principals are excluded by the private root ACL.
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $path)
    return Unprotect-SocSecret -Name 'shuffle_webhook_url' -SecretRoot $root
}

function Assert-SocShuffleV2RuntimeConfigurationShape {
    param([Parameter(Mandatory)][object]$Configuration)
    [void](Assert-SocLabConfiguration -Configuration $Configuration)
    $actual = @($Configuration.PSObject.Properties.Name | Sort-Object)
    $expected = @($script:SocShuffleV2ConfigFields | Sort-Object)
    if (($actual -join ',') -cne ($expected -join ',')) {
        throw 'The SOC configuration contains unknown or missing fields.'
    }
    return $Configuration
}

function Assert-SocShuffleV2RuntimeDpapiRecord {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    try {
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
        $record = $text | ConvertFrom-Json -Depth 8
    } catch {
        throw 'The protected Shuffle Webhook record is not valid JSON.'
    }
    $actual = @($record.PSObject.Properties.Name | Sort-Object)
    $expected = @('cipher_base64','name','protected_at','schema_version','scope') | Sort-Object
    $cipherBytes = $null
    try {
        $cipherBytes = [Convert]::FromBase64String([string]$record.cipher_base64)
    } catch {
        throw 'The protected Shuffle Webhook record cipher is not strict Base64.'
    }
    try {
        if (($actual -join ',') -cne ($expected -join ',') -or
            [int]$record.schema_version -ne 1 -or
            [string]$record.name -cne 'shuffle_webhook_url' -or
            [string]$record.scope -cne 'CurrentUser' -or
            [string]$record.cipher_base64 -notmatch '^[A-Za-z0-9+/]+={0,2}$' -or
            $cipherBytes.Length -eq 0 -or $cipherBytes.Length -gt 1MB -or
            [Convert]::ToBase64String($cipherBytes) -cne [string]$record.cipher_base64) {
            throw 'The protected Shuffle Webhook record has drifted from the fixed DPAPI contract.'
        }
    } finally {
        [Array]::Clear($cipherBytes,0,$cipherBytes.Length)
    }
}

function New-SocShuffleV2CallbackUri {
    param(
        [Parameter(Mandatory)][uri]$BaseUri,
        [Parameter(Mandatory)][string]$WebhookId
    )
    Assert-SocShuffleV2RuntimeUuid -Value $WebhookId -Label 'Shuffle Webhook ID'
    if ($BaseUri.Scheme -cne 'https' -or
        ($BaseUri.Host -cne 'shuffler.io' -and -not $BaseUri.Host.EndsWith('.shuffler.io')) -or
        -not $BaseUri.IsDefaultPort -or $BaseUri.AbsolutePath -cne '/' -or
        $BaseUri.UserInfo -or $BaseUri.Query -or $BaseUri.Fragment) {
        throw 'The Shuffle API origin is outside the fixed HTTPS shuffler.io allowlist.'
    }
    $path = "/api/v1/hooks/webhook_$WebhookId"
    $callback = [uri]::new($BaseUri,$path)
    if ($callback.Scheme -cne 'https' -or $callback.Host -cne $BaseUri.Host -or
        $callback.AbsolutePath -cne $path -or $callback.Query -or $callback.Fragment) {
        throw 'The Shuffle Webhook callback escaped the approved origin or endpoint.'
    }
    return $callback.AbsoluteUri
}

function Write-SocShuffleV2RuntimeAtomicBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [scriptblock]$AssertPrivatePath
    )
    if ($null -eq $AssertPrivatePath) {
        $AssertPrivatePath = {
            param($Target,$Kind)
            Assert-SocShuffleV2PrivatePathAcl -Path $Target -Kind $Kind
        }
    }
    $full = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $full
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $parent)
    & $AssertPrivatePath $parent 'Directory' $false
    if (Test-Path -LiteralPath $full) {
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
        & $AssertPrivatePath $full 'File' $false
    }
    $temporary = Join-Path $parent ('.{0}.{1}.tmp' -f [IO.Path]::GetFileName($full),[guid]::NewGuid().ToString('N'))
    try {
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $temporary -AllowMissingLeaf)
        [IO.File]::WriteAllBytes($temporary,$Bytes)
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $temporary)
        & $AssertPrivatePath $temporary 'File' $false
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $full -AllowMissingLeaf)
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $temporary)
        & $AssertPrivatePath $temporary 'File' $false
        [IO.File]::Move($temporary,$full,$true)
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $full)
        & $AssertPrivatePath $full 'File' $false
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            [void](Assert-SocShuffleV2NoReparsePathChain -Path $temporary)
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Enter-SocShuffleV2RuntimeMutex {
    param([ValidateRange(0,30000)][int]$TimeoutMilliseconds = 5000)
    $mutex = [Threading.Mutex]::new($false,$script:SocShuffleV2MutexName)
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne($TimeoutMilliseconds) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) {
            throw (New-SocShuffleV2RuntimeFailure -Category 'mutex')
        }
        return [pscustomobject]@{Mutex=$mutex;Acquired=$true}
    } catch {
        if (-not $acquired) { $mutex.Dispose() }
        throw
    }
}

function Exit-SocShuffleV2RuntimeMutex {
    param([AllowNull()][object]$Handle)
    if ($null -eq $Handle) { return }
    try {
        if ([bool]$Handle.Acquired) { $Handle.Mutex.ReleaseMutex() }
    } finally {
        $Handle.Mutex.Dispose()
    }
}

function New-SocShuffleV2JournalBytes {
    param(
        [Parameter(Mandatory)][object]$ConfigSnapshot,
        [Parameter(Mandatory)][object]$SecretSnapshot,
        [Parameter(Mandatory)][string]$WorkflowId,
        [Parameter(Mandatory)][string]$WebhookId
    )
    $journal = [ordered]@{
        schema_version=1
        artifact_kind='shuffle-v2-runtime-switch-transaction'
        state='prepared'
        created_at_utc=[DateTimeOffset]::UtcNow.ToString('o')
        target_workflow_id=$WorkflowId
        target_webhook_id=$WebhookId
        configuration_sha256=[string]$ConfigSnapshot.Sha256
        webhook_record_sha256=[string]$SecretSnapshot.Sha256
        configuration_bytes_base64=[Convert]::ToBase64String([byte[]]$ConfigSnapshot.Bytes)
        webhook_record_bytes_base64=[Convert]::ToBase64String([byte[]]$SecretSnapshot.Bytes)
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($journal | ConvertTo-Json -Depth 8) + "`n")
    )
    return ,$bytes
}

function Read-SocShuffleV2Journal {
    param([Parameter(Mandatory)][string]$Path)
    $snapshot = Get-SocShuffleV2RuntimeFileSnapshot -Path $Path
    try {
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($snapshot.Bytes)
        $journal = $text | ConvertFrom-Json -Depth 8
        $configurationBytes = [Convert]::FromBase64String([string]$journal.configuration_bytes_base64)
        $secretBytes = [Convert]::FromBase64String([string]$journal.webhook_record_bytes_base64)
    } catch {
        throw 'The Shuffle runtime transaction marker is invalid.'
    }
    $expected = @(
        'schema_version','artifact_kind','state','created_at_utc','target_workflow_id',
        'target_webhook_id','configuration_sha256','webhook_record_sha256',
        'configuration_bytes_base64','webhook_record_bytes_base64'
    ) | Sort-Object
    $actual = @($journal.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne ($expected -join ',') -or
        [int]$journal.schema_version -ne 1 -or
        [string]$journal.artifact_kind -cne 'shuffle-v2-runtime-switch-transaction' -or
        [string]$journal.state -cne 'prepared' -or
        [string]$journal.target_workflow_id -cnotmatch $script:SocShuffleV2UuidPattern -or
        [string]$journal.target_webhook_id -cnotmatch $script:SocShuffleV2UuidPattern -or
        [string]$journal.configuration_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$journal.webhook_record_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-SocShuffleV2BytesSha256 -Bytes $configurationBytes) -cne [string]$journal.configuration_sha256 -or
        (Get-SocShuffleV2BytesSha256 -Bytes $secretBytes) -cne [string]$journal.webhook_record_sha256) {
        throw 'The Shuffle runtime transaction marker contract or hashes are invalid.'
    }
    Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $secretBytes
    try {
        $configurationText = [Text.UTF8Encoding]::new($false,$true).GetString($configurationBytes)
        $configuration = $configurationText | ConvertFrom-Json -Depth 12
        [void](Assert-SocShuffleV2RuntimeConfigurationShape -Configuration $configuration)
    } catch {
        throw 'The transaction marker does not contain a valid original configuration.'
    }
    return [pscustomobject][ordered]@{
        WorkflowId=[string]$journal.target_workflow_id
        WebhookId=[string]$journal.target_webhook_id
        ConfigurationBytes=$configurationBytes
        ConfigurationSha256=[string]$journal.configuration_sha256
        SecretBytes=$secretBytes
        SecretSha256=[string]$journal.webhook_record_sha256
    }
}

function Remove-SocShuffleV2Journal {
    param(
        [Parameter(Mandatory)][object]$Paths,
        [Parameter(Mandatory)][scriptblock]$AssertPrivatePath
    )
    Assert-SocShuffleV2RuntimePathsStable -Paths $Paths
    if (Test-Path -LiteralPath $Paths.MarkerPath -PathType Leaf) {
        & $AssertPrivatePath $Paths.MarkerPath 'File' $true
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $Paths.MarkerPath)
        Remove-Item -LiteralPath $Paths.MarkerPath -Force
    }
    if (Test-Path -LiteralPath $Paths.MarkerPath) {
        throw 'The Shuffle runtime transaction marker could not be removed.'
    }
}

function Restore-SocShuffleV2RuntimeFromJournal {
    param(
        [Parameter(Mandatory)][object]$Paths,
        [Parameter(Mandatory)][object]$Journal,
        [Parameter(Mandatory)][scriptblock]$AssertPrivatePath
    )
    Assert-SocShuffleV2RuntimePathsStable -Paths $Paths
    [void](Get-SocShuffleV2RuntimeFileSnapshot -Path $Paths.ConfigurationPath)
    [void](Get-SocShuffleV2RuntimeFileSnapshot -Path $Paths.SecretPath)
    Write-SocShuffleV2RuntimeAtomicBytes -Path $Paths.ConfigurationPath `
        -Bytes $Journal.ConfigurationBytes -AssertPrivatePath $AssertPrivatePath
    $configurationReadback = Get-SocShuffleV2RuntimeFileSnapshot -Path $Paths.ConfigurationPath
    if ($configurationReadback.Sha256 -cne $Journal.ConfigurationSha256) {
        throw 'The original configuration bytes were not restored exactly.'
    }
    Assert-SocShuffleV2RuntimePathsStable -Paths $Paths
    [void](Get-SocShuffleV2RuntimeFileSnapshot -Path $Paths.SecretPath)
    Write-SocShuffleV2RuntimeAtomicBytes -Path $Paths.SecretPath `
        -Bytes $Journal.SecretBytes -AssertPrivatePath $AssertPrivatePath
    $secretReadback = Get-SocShuffleV2RuntimeFileSnapshot -Path $Paths.SecretPath
    if ($secretReadback.Sha256 -cne $Journal.SecretSha256) {
        throw 'The original protected Webhook record was not restored exactly.'
    }
}

function Assert-SocShuffleV2RecoveredRuntimeSemantic {
    param(
        [Parameter(Mandatory)][object]$Paths,
        [Parameter(Mandatory)][scriptblock]$ReadConfiguration,
        [Parameter(Mandatory)][scriptblock]$ReadWebhookUri,
        [Parameter(Mandatory)][scriptblock]$AssertPrivatePath
    )
    Assert-SocShuffleV2RuntimePathsStable -Paths $Paths
    & $AssertPrivatePath $Paths.ConfigurationRoot 'Directory' $false
    & $AssertPrivatePath $Paths.SecretRoot 'Directory' $false
    & $AssertPrivatePath $Paths.ConfigurationPath 'File' $false
    & $AssertPrivatePath $Paths.SecretPath 'File' $false
    $configuration = & $ReadConfiguration $Paths.ConfigurationRoot
    [void](Assert-SocShuffleV2RuntimeConfigurationShape -Configuration $configuration)
    $expectedUri = New-SocShuffleV2CallbackUri `
        -BaseUri ([uri][string]$configuration.shuffle_api_base) `
        -WebhookId ([string]$configuration.shuffle_webhook_id)
    $actualUri = & $ReadWebhookUri $Paths.SecretRoot
    if ([string]$actualUri -cne $expectedUri) {
        throw 'The restored DPAPI record did not semantically match its configuration.'
    }
}

function New-SocShuffleV2ProtectedRecordBytes {
    param(
        [Parameter(Mandatory)][string]$SecretRoot,
        [Parameter(Mandatory)][string]$Callback
    )
    [void](Assert-SocShuffleV2NoReparsePathChain -Path $SecretRoot)
    Assert-SocShuffleV2PrivatePathAcl -Path $SecretRoot -Kind Directory
    $stageRoot = [IO.Path]::GetFullPath((Join-Path $SecretRoot ('.shuffle-v2-stage-' + [guid]::NewGuid().ToString('N'))))
    $prefix = [IO.Path]::GetFullPath($SecretRoot).TrimEnd('\') + '\'
    if (-not $stageRoot.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'The protected-record staging root escaped the canonical secret root.'
    }
    $stagedPath = Join-Path $stageRoot 'shuffle_webhook_url.dpapi.json'
    try {
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $stageRoot -AllowMissingLeaf)
        New-Item -ItemType Directory -Path $stageRoot | Out-Null
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $stageRoot)
        Set-SocShuffleV2PrivateDirectoryAcl -Path $stageRoot
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $stageRoot)
        Assert-SocShuffleV2PrivatePathAcl -Path $stageRoot -Kind Directory
        [void](Protect-SocSecret -Name 'shuffle_webhook_url' -PlainText $Callback `
            -SecretRoot $stageRoot)
        [void](Assert-SocShuffleV2NoReparsePathChain -Path $stagedPath)
        Assert-SocShuffleV2PrivatePathAcl -Path $stagedPath -Kind File
        $snapshot = Get-SocShuffleV2RuntimeFileSnapshot -Path $stagedPath
        Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $snapshot.Bytes
        return ,([byte[]]$snapshot.Bytes)
    } finally {
        if (Test-Path -LiteralPath $stagedPath -PathType Leaf) {
            [void](Assert-SocShuffleV2NoReparsePathChain -Path $stagedPath)
            Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stageRoot -PathType Container) {
            [void](Assert-SocShuffleV2NoReparsePathChain -Path $stageRoot)
            Remove-Item -LiteralPath $stageRoot -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-SocShuffleV2RuntimeSwitch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NewWorkflowId,
        [Parameter(Mandatory)][string]$NewWebhookId,
        [Parameter(Mandatory)][string]$ConfigurationRoot,
        [Parameter(Mandatory)][string]$SecretRoot,
        [switch]$AllowTestRoots,
        [ValidateRange(0,30000)][int]$MutexTimeoutMilliseconds = 5000,
        [ValidateSet('none','after-secret','after-config')][string]$SimulatedCrashStage = 'none',
        [scriptblock]$PreparePrivateRoots,
        [scriptblock]$AssertPrivatePath,
        [scriptblock]$ReadConfiguration,
        [scriptblock]$CreateProtectedWebhookRecord,
        [scriptblock]$ReadWebhookUri,
        [scriptblock]$AssertWorkflow
    )
    Assert-SocShuffleV2RuntimeUuid -Value $NewWorkflowId -Label 'Shuffle Workflow ID'
    Assert-SocShuffleV2RuntimeUuid -Value $NewWebhookId -Label 'Shuffle Webhook ID'
    if (($AllowTestRoots.IsPresent -or $SimulatedCrashStage -cne 'none') -and
        -not $script:SocShuffleV2LibraryOnly) {
        throw (New-SocShuffleV2RuntimeFailure -Category 'root' `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    }
    if ($AllowTestRoots.IsPresent) {
        try {
            Assert-SocShuffleV2TestRootsIsolated `
                -ConfigurationRoot $ConfigurationRoot -SecretRoot $SecretRoot
        } catch {
            throw (New-SocShuffleV2RuntimeFailure -Category 'root' `
                -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
        }
    }
    $injectedRuntimeHook = ($null -ne $PreparePrivateRoots -or
        $null -ne $AssertPrivatePath -or $null -ne $ReadConfiguration -or
        $null -ne $CreateProtectedWebhookRecord -or $null -ne $ReadWebhookUri -or
        $null -ne $AssertWorkflow)
    if (-not $AllowTestRoots.IsPresent -and
        ($injectedRuntimeHook -or $SimulatedCrashStage -cne 'none')) {
        throw (New-SocShuffleV2RuntimeFailure -Category 'root' `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    }
    if ($AllowTestRoots.IsPresent -and
        ($null -eq $PreparePrivateRoots -or $null -eq $AssertPrivatePath -or
         $null -eq $ReadConfiguration -or
         $null -eq $CreateProtectedWebhookRecord -or
         $null -eq $ReadWebhookUri -or $null -eq $AssertWorkflow)) {
        throw (New-SocShuffleV2RuntimeFailure -Category 'root' `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    }
    if ($null -eq $PreparePrivateRoots) {
        $PreparePrivateRoots = {
            param($ConfigRoot,$SecretsRoot)
            Initialize-SocShuffleV2CanonicalPrivateRoots `
                -ConfigurationRoot $ConfigRoot -SecretRoot $SecretsRoot
        }
    }
    if ($null -eq $AssertPrivatePath) {
        $AssertPrivatePath = {
            param($Target,$Kind,[bool]$RequireInherited=$false)
            Assert-SocShuffleV2PrivatePathAcl -Path $Target -Kind $Kind
            if ($RequireInherited) {
                Assert-SocShuffleV2InheritedPrivateFileAcl -Path $Target
            }
        }
    }
    if ($null -eq $ReadConfiguration) {
        $ReadConfiguration = {
            param($Root)
            $target = [IO.Path]::GetFullPath((Get-SocConfigurationPath -Root $Root))
            [void](Assert-SocShuffleV2NoReparsePathChain -Path $target)
            & $AssertPrivatePath $target 'File' $false
            return Read-SocLabConfiguration -Root $Root
        }.GetNewClosure()
    }
    if ($null -eq $CreateProtectedWebhookRecord) {
        $CreateProtectedWebhookRecord = {
            param($Root,$Callback)
            return ,(New-SocShuffleV2ProtectedRecordBytes -SecretRoot $Root -Callback $Callback)
        }
    }
    if ($null -eq $ReadWebhookUri) {
        $ReadWebhookUri = {
            param($Root)
            return Read-SocShuffleV2ProtectedWebhookUriFromFile `
                -SecretRoot $Root -AssertPrivatePath $AssertPrivatePath
        }.GetNewClosure()
    }
    if ($null -eq $AssertWorkflow) {
        $AssertWorkflow = {
            param($Configuration,$WorkflowId,$WebhookId,$Root)
            $apiKey = $null
            $headerValue = $null
            try {
                $apiKey = Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot $Root
                $headerValue = Unprotect-SocSecret -Name 'shuffle_webhook_header_key' -SecretRoot $Root
                [void](Get-ShuffleSocWorkflowV2 -WorkflowId $WorkflowId -WebhookId $WebhookId `
                    -ApiKey $apiKey -OrgId ([string]$Configuration.shuffle_org_id) `
                    -ExpectedHeaderValue $headerValue -BaseUri ([uri][string]$Configuration.shuffle_api_base))
            } finally {
                $apiKey = $null
                $headerValue = $null
            }
        }
    }

    $mutexHandle = $null
    $paths = $null
    $simulatedCrash = $false
    $failureCategory = 'configuration'
    $recoveredPriorTransaction = $false
    try {
        $failureCategory = 'mutex'
        $mutexHandle = Enter-SocShuffleV2RuntimeMutex -TimeoutMilliseconds $MutexTimeoutMilliseconds
        $failureCategory = 'root'
        & $PreparePrivateRoots $ConfigurationRoot $SecretRoot
        $paths = Get-SocShuffleV2RuntimePaths `
            -ConfigurationRoot $ConfigurationRoot -SecretRoot $SecretRoot `
            -AllowTestRoots:$AllowTestRoots.IsPresent
        & $AssertPrivatePath $paths.ConfigurationRoot 'Directory' $false
        & $AssertPrivatePath $paths.SecretRoot 'Directory' $false
        & $AssertPrivatePath $paths.ConfigurationPath 'File' $false
        & $AssertPrivatePath $paths.SecretPath 'File' $false

        if (Test-Path -LiteralPath $paths.MarkerPath -PathType Leaf) {
            $failureCategory = 'recovery'
            & $AssertPrivatePath $paths.MarkerPath 'File' $true
            $priorJournal = Read-SocShuffleV2Journal -Path $paths.MarkerPath
            Restore-SocShuffleV2RuntimeFromJournal -Paths $paths `
                -Journal $priorJournal -AssertPrivatePath $AssertPrivatePath
            Assert-SocShuffleV2RecoveredRuntimeSemantic -Paths $paths `
                -ReadConfiguration $ReadConfiguration -ReadWebhookUri $ReadWebhookUri `
                -AssertPrivatePath $AssertPrivatePath
            Remove-SocShuffleV2Journal -Paths $paths `
                -AssertPrivatePath $AssertPrivatePath
            $recoveredPriorTransaction = $true
        }

        $failureCategory = 'drift'
        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        $configSnapshot = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.ConfigurationPath
        $secretSnapshot = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $secretSnapshot.Bytes
        $configuration = & $ReadConfiguration $paths.ConfigurationRoot
        [void](Assert-SocShuffleV2RuntimeConfigurationShape -Configuration $configuration)
        $expectedCurrentCallback = New-SocShuffleV2CallbackUri `
            -BaseUri ([uri][string]$configuration.shuffle_api_base) `
            -WebhookId ([string]$configuration.shuffle_webhook_id)
        $currentCallbackReadback = [string](& $ReadWebhookUri $paths.SecretRoot)
        if ($currentCallbackReadback -cne $expectedCurrentCallback) {
            throw 'The existing protected Webhook record does not semantically match its configuration.'
        }
        # Only a record proven by the live DPAPI file reader is eligible for
        # the journal. AllowTestRoots can substitute an opaque decoder only in
        # LibraryOnly tests and cannot reach the live CLI.
        $callback = New-SocShuffleV2CallbackUri `
            -BaseUri ([uri][string]$configuration.shuffle_api_base) -WebhookId $NewWebhookId

        $updated = [ordered]@{}
        foreach ($field in $script:SocShuffleV2ConfigFields) {
            if ($field -ceq 'shuffle_workflow_id') { $updated[$field]=$NewWorkflowId }
            elseif ($field -ceq 'shuffle_webhook_id') { $updated[$field]=$NewWebhookId }
            else { $updated[$field]=$configuration.$field }
        }
        $updatedConfigBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            (($updated | ConvertTo-Json -Depth 8) + "`n")
        )
        $updatedConfigHash = Get-SocShuffleV2BytesSha256 -Bytes $updatedConfigBytes

        $failureCategory = 'workflow-readback'
        & $AssertWorkflow $configuration $NewWorkflowId $NewWebhookId $paths.SecretRoot

        $failureCategory = 'drift'
        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        $configBeforeJournal = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.ConfigurationPath
        $secretBeforeJournal = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        if ($configBeforeJournal.Sha256 -cne $configSnapshot.Sha256 -or
            $secretBeforeJournal.Sha256 -cne $secretSnapshot.Sha256) {
            throw 'The SOC runtime files changed during preflight.'
        }

        $failureCategory = 'journal'
        $journalBytes = New-SocShuffleV2JournalBytes `
            -ConfigSnapshot $configSnapshot -SecretSnapshot $secretSnapshot `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId
        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        Write-SocShuffleV2RuntimeAtomicBytes -Path $paths.MarkerPath `
            -Bytes $journalBytes -AssertPrivatePath $AssertPrivatePath
        & $AssertPrivatePath $paths.MarkerPath 'File' $true
        [void](Read-SocShuffleV2Journal -Path $paths.MarkerPath)

        $failureCategory = 'secret'
        $newSecretBytes = [byte[]](& $CreateProtectedWebhookRecord $paths.SecretRoot $callback)
        Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $newSecretBytes
        $newSecretHash = Get-SocShuffleV2BytesSha256 -Bytes $newSecretBytes
        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        $configBeforeSecretWrite = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.ConfigurationPath
        $secretBeforeSecretWrite = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        if ($configBeforeSecretWrite.Sha256 -cne $configSnapshot.Sha256 -or
            $secretBeforeSecretWrite.Sha256 -cne $secretSnapshot.Sha256) {
            throw 'The SOC runtime files changed before the protected-record write.'
        }
        Write-SocShuffleV2RuntimeAtomicBytes -Path $paths.SecretPath `
            -Bytes $newSecretBytes -AssertPrivatePath $AssertPrivatePath
        if ($SimulatedCrashStage -ceq 'after-secret') {
            $simulatedCrash = $true
            throw (New-SocShuffleV2RuntimeFailure -Category 'simulated-crash' `
                -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
        }
        $secretReadback = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        if ($secretReadback.Sha256 -cne $newSecretHash -or
            [string](& $ReadWebhookUri $paths.SecretRoot) -cne $callback) {
            throw 'The protected Shuffle Webhook record did not read back semantically.'
        }

        $failureCategory = 'write'
        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        $configBeforeWrite = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.ConfigurationPath
        $secretBeforeConfigWrite = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        if ($configBeforeWrite.Sha256 -cne $configSnapshot.Sha256 -or
            $secretBeforeConfigWrite.Sha256 -cne $newSecretHash) {
            throw 'The SOC runtime files changed before the configuration write.'
        }
        Write-SocShuffleV2RuntimeAtomicBytes -Path $paths.ConfigurationPath `
            -Bytes $updatedConfigBytes -AssertPrivatePath $AssertPrivatePath
        if ($SimulatedCrashStage -ceq 'after-config') {
            $simulatedCrash = $true
            throw (New-SocShuffleV2RuntimeFailure -Category 'simulated-crash' `
                -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
        }

        Assert-SocShuffleV2RuntimePathsStable -Paths $paths
        $configReadback = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.ConfigurationPath
        $secretFinal = Get-SocShuffleV2RuntimeFileSnapshot -Path $paths.SecretPath
        $configurationReadback = & $ReadConfiguration $paths.ConfigurationRoot
        [void](Assert-SocShuffleV2RuntimeConfigurationShape -Configuration $configurationReadback)
        if ($configReadback.Sha256 -cne $updatedConfigHash -or
            $secretFinal.Sha256 -cne $newSecretHash -or
            [string]$configurationReadback.shuffle_workflow_id -cne $NewWorkflowId -or
            [string]$configurationReadback.shuffle_webhook_id -cne $NewWebhookId -or
            [string](& $ReadWebhookUri $paths.SecretRoot) -cne $callback) {
            throw 'The final SOC runtime switch readback did not match.'
        }
        Remove-SocShuffleV2Journal -Paths $paths `
            -AssertPrivatePath $AssertPrivatePath
        return [pscustomobject][ordered]@{
            status='switched'
            workflow_id=$NewWorkflowId
            webhook_id=$NewWebhookId
            old_config_sha256=$configSnapshot.Sha256
            new_config_sha256=$configReadback.Sha256
            old_webhook_record_sha256=$secretSnapshot.Sha256
            new_webhook_record_sha256=$secretFinal.Sha256
            workflow_assertion='pass'
            recovered_prior_transaction=$recoveredPriorTransaction
            rollback='not_required'
        }
    } catch {
        if ($simulatedCrash) { throw }
        if ($null -ne $paths -and
            (Test-Path -LiteralPath $paths.MarkerPath -PathType Leaf)) {
            try {
                & $AssertPrivatePath $paths.MarkerPath 'File' $true
                $journal = Read-SocShuffleV2Journal -Path $paths.MarkerPath
                Restore-SocShuffleV2RuntimeFromJournal -Paths $paths `
                    -Journal $journal -AssertPrivatePath $AssertPrivatePath
                Assert-SocShuffleV2RecoveredRuntimeSemantic -Paths $paths `
                    -ReadConfiguration $ReadConfiguration -ReadWebhookUri $ReadWebhookUri `
                    -AssertPrivatePath $AssertPrivatePath
                Remove-SocShuffleV2Journal -Paths $paths `
                    -AssertPrivatePath $AssertPrivatePath
            } catch {
                throw (New-SocShuffleV2RuntimeFailure -Category 'rollback' `
                    -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
            }
        }
        if ([string]$_.Exception.Message -match '^Shuffle v2 runtime switch failed \[mutex\]') {
            throw
        }
        throw (New-SocShuffleV2RuntimeFailure -Category $failureCategory `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    } finally {
        Exit-SocShuffleV2RuntimeMutex -Handle $mutexHandle
    }
}

if (-not $LibraryOnly.IsPresent) {
    try {
        $canonicalConfigurationRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocConfigurationRoot -Root '') -Label 'Live configuration root'
        $canonicalSecretRoot = Get-SocShuffleV2OrdinaryDosAbsolutePath `
            -Path (Get-SocSecretRoot -Root '') -Label 'Live secret root'
        $requestedConfigurationRoot = if ($ConfigurationRoot) {
            Get-SocShuffleV2OrdinaryDosAbsolutePath `
                -Path $ConfigurationRoot -Label 'Configuration root'
        } else { $canonicalConfigurationRoot }
        $requestedSecretRoot = if ($SecretRoot) {
            Get-SocShuffleV2OrdinaryDosAbsolutePath -Path $SecretRoot -Label 'Secret root'
        } else { $canonicalSecretRoot }
        if ($requestedConfigurationRoot -ine $canonicalConfigurationRoot -or
            $requestedSecretRoot -ine $canonicalSecretRoot) {
            throw 'The requested roots do not equal the fixed live roots.'
        }
    } catch {
        throw (New-SocShuffleV2RuntimeFailure -Category 'root' `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    }
    if ([string]::IsNullOrWhiteSpace($NewWorkflowId) -or
        [string]::IsNullOrWhiteSpace($NewWebhookId)) {
        throw (New-SocShuffleV2RuntimeFailure -Category 'configuration')
    }
    if ($ConfirmSwitch -cne 'SWITCH SHUFFLE SOC V2') {
        throw "Preview only. Re-run with -ConfirmSwitch 'SWITCH SHUFFLE SOC V2'."
    }
    try {
        $result = Invoke-SocShuffleV2RuntimeSwitch `
            -NewWorkflowId $NewWorkflowId -NewWebhookId $NewWebhookId `
            -ConfigurationRoot $canonicalConfigurationRoot -SecretRoot $canonicalSecretRoot
        Write-Host 'SHUFFLE_SOC_V2_RUNTIME_SWITCHED=yes'
        Write-Host "WORKFLOW_ID=$($result.workflow_id)"
        Write-Host "WEBHOOK_ID=$($result.webhook_id)"
        Write-Host "OLD_CONFIG_SHA256=$($result.old_config_sha256)"
        Write-Host "NEW_CONFIG_SHA256=$($result.new_config_sha256)"
        Write-Host "OLD_WEBHOOK_RECORD_SHA256=$($result.old_webhook_record_sha256)"
        Write-Host "NEW_WEBHOOK_RECORD_SHA256=$($result.new_webhook_record_sha256)"
        Write-Host "WORKFLOW_ASSERTION=$($result.workflow_assertion)"
        Write-Host "RECOVERED_PRIOR_TRANSACTION=$($result.recovered_prior_transaction.ToString().ToLowerInvariant())"
        Write-Host "ROLLBACK=$($result.rollback)"
    } catch {
        if ([string]$_.Exception.Message -match '^Shuffle v2 runtime switch failed \[') { throw }
        throw (New-SocShuffleV2RuntimeFailure -Category 'configuration' `
            -WorkflowId $NewWorkflowId -WebhookId $NewWebhookId)
    }
}
