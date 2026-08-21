#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'tools\Switch-SocLabShuffleV2Runtime.ps1'
$scriptText = Get-Content -LiteralPath $scriptPath -Raw

function Assert-TestCondition {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

foreach ($required in @(
    'Local\AWS-Topology-Soc-Shuffle-V2-Runtime-Switch-v1',
    'shuffle-v2-runtime-switch.transaction.json',
    'Enter-SocShuffleV2RuntimeMutex','Restore-SocShuffleV2RuntimeFromJournal',
    'Assert-SocShuffleV2NoReparsePathChain','Get-SocConfigurationRoot -Root',
    'Get-SocShuffleV2OrdinaryDosAbsolutePath',
    'UNC, device, extended, and Volume GUID aliases',
    'Assert-SocShuffleV2TestRootsIsolated','Test-SocShuffleV2PathOverlap',
    'A test root overlaps a protected live SOC root',
    'A resolved test root overlaps a protected live SOC root',
    'Get-SocSecretRoot -Root','New-SocShuffleV2ProtectedRecordBytes',
    'Protect-SocSecret','/api/v1/hooks/webhook_','Get-ShuffleSocWorkflowV2',
    'configuration_bytes_base64','webhook_record_bytes_base64',
    'Write-SocShuffleV2RuntimeAtomicBytes','File]::Move',
    'Initialize-SocShuffleV2CanonicalPrivateRoots',
    'Set-SocPrivateDirectoryAcl','DirectorySecurity',
    'AreAccessRulesProtected','GetAccessRules','GetOwner',
    'Assert-SocShuffleV2InheritedPrivateFileAcl',
    'Read-SocShuffleV2ProtectedWebhookUriFromFile',
    'Assert-SocShuffleV2RecoveredRuntimeSemantic',
    'expectedCurrentCallback','currentCallbackReadback',
    'Only a record proven by the live DPAPI file reader',
    'injectedRuntimeHook',
    'FromBase64String','other local principals','same CurrentUser',
    "outside this transaction helper's threat boundary"
)) {
    Assert-TestCondition ($scriptText -match [regex]::Escape($required)) `
        "Missing v2 runtime switch contract text: $required"
}
foreach ($forbidden in @(
    '\[switch\]\$SkipWorkflowAssertion',
    '\[switch\]\$NoRun',
    'Write-Host[^\r\n]*(?:callback|Callback|apiKey|headerValue|Secret)',
    'Write-Host[^\r\n]*\$readbackUri',
    'Invoke-ShuffleApiRequest\s+-Method\s+(?:POST|PUT|DELETE)'
)) {
    Assert-TestCondition ($scriptText -notmatch $forbidden) `
        "Forbidden v2 runtime switch contract text: $forbidden"
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,[ref]$tokens,[ref]$errors
)
$parseMessages = @($errors | ForEach-Object { [string]$_.Message })
Assert-TestCondition (@($errors).Count -eq 0) `
    "Parser errors: $($parseMessages -join '; ')"

. $scriptPath -LibraryOnly

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('shuffle-v2-switch-' + [guid]::NewGuid().ToString('N'))
$configurationRoot = Join-Path $testRoot 'test-config'
$secretRoot = Join-Path $testRoot 'test-secrets'
$configPath = Join-Path $configurationRoot 'soc-lab.json'
$secretPath = Join-Path $secretRoot 'shuffle_webhook_url.dpapi.json'
$markerPath = Join-Path $configurationRoot 'shuffle-v2-runtime-switch.transaction.json'
$oldWorkflowId = '11111111-1111-4111-8111-111111111111'
$oldWebhookId = '22222222-2222-4222-8222-222222222222'
$newWorkflowId = '33333333-3333-4333-8333-333333333333'
$newWebhookId = '44444444-4444-4444-8444-444444444444'
$organizationId = '55555555-5555-4555-8555-555555555555'

function New-TestDpapiRecordBytes {
    param([Parameter(Mandatory)][string]$CipherBase64)
    $record = [ordered]@{
        schema_version=1
        name='shuffle_webhook_url'
        protected_at='2026-08-21T00:00:00.0000000+00:00'
        scope='CurrentUser'
        # Mock-only opaque bytes. URI resolution belongs to the file-decoder
        # mapping below; the record never embeds a reversible plaintext URI.
        cipher_base64=$CipherBase64
    }
    return ,([Text.UTF8Encoding]::new($false).GetBytes(
        (($record | ConvertTo-Json -Depth 8) + "`n")
    ))
}

function Test-TestBytesContainSequence {
    param(
        [Parameter(Mandatory)][byte[]]$Haystack,
        [Parameter(Mandatory)][byte[]]$Needle
    )
    if ($Needle.Length -eq 0 -or $Needle.Length -gt $Haystack.Length) {
        return $false
    }
    for ($offset=0;$offset -le $Haystack.Length-$Needle.Length;$offset++) {
        $matched=$true
        for ($index=0;$index -lt $Needle.Length;$index++) {
            if ($Haystack[$offset+$index] -ne $Needle[$index]) {
                $matched=$false
                break
            }
        }
        if ($matched) { return $true }
    }
    return $false
}

function Get-TestJsonStringLeaves {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return }
    if ($Value -is [string]) {
        Write-Output ([string]$Value)
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($entryValue in $Value.Values) {
            Get-TestJsonStringLeaves -Value $entryValue
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Get-TestJsonStringLeaves -Value $item }
        return
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            Get-TestJsonStringLeaves -Value $property.Value
        }
    }
}

function Assert-TestNoForbiddenPlaintextRecursive {
    param(
        [Parameter(Mandatory)][byte[]]$RootBytes,
        [Parameter(Mandatory)][string[]]$ForbiddenPlaintext
    )
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([pscustomobject]@{bytes=$RootBytes;depth=0})
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $decodedLayers=0
    while ($queue.Count -gt 0) {
        $item=$queue.Dequeue()
        $bytes=[byte[]]$item.bytes
        $hash=Get-SocShuffleV2BytesSha256 -Bytes $bytes
        if (-not $visited.Add($hash)) { continue }
        foreach ($forbidden in $ForbiddenPlaintext) {
            $needle=[Text.Encoding]::UTF8.GetBytes($forbidden)
            if (Test-TestBytesContainSequence -Haystack $bytes -Needle $needle) {
                throw 'A transaction marker layer contains forbidden plaintext.'
            }
        }
        if ([int]$item.depth -ge 6) { continue }
        try { $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes) }
        catch { continue }
        try { $json=$text | ConvertFrom-Json -Depth 20 }
        catch { continue }
        foreach ($leaf in @(Get-TestJsonStringLeaves -Value $json)) {
            foreach ($forbidden in $ForbiddenPlaintext) {
                if ([string]$leaf -clike "*$forbidden*") {
                    throw 'A decoded transaction marker JSON layer contains forbidden plaintext.'
                }
            }
            if ([string]$leaf -cnotmatch '^[A-Za-z0-9+/]+={0,2}$' -or
                ([string]$leaf).Length % 4 -ne 0) {
                continue
            }
            try { $decoded=[Convert]::FromBase64String([string]$leaf) }
            catch { continue }
            if ($decoded.Length -eq 0 -or
                [Convert]::ToBase64String($decoded) -cne [string]$leaf) {
                continue
            }
            $queue.Enqueue([pscustomobject]@{
                bytes=$decoded
                depth=([int]$item.depth+1)
            })
            $decodedLayers++
        }
    }
    return $decodedLayers
}

foreach ($invalidCipher in @('%%%','')) {
    $invalidRecord = [ordered]@{
        schema_version=1
        name='shuffle_webhook_url'
        protected_at='2026-08-21T00:00:00.0000000+00:00'
        scope='CurrentUser'
        cipher_base64=$invalidCipher
    }
    $invalidBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($invalidRecord | ConvertTo-Json -Depth 8) + "`n")
    )
    $invalidCaught = $false
    try { Assert-SocShuffleV2RuntimeDpapiRecord -Bytes $invalidBytes }
    catch { $invalidCaught = $true }
    Assert-TestCondition $invalidCaught `
        "Strict DPAPI record validation accepted cipher '$invalidCipher'."
}

try {
    New-Item -ItemType Directory -Path $configurationRoot,$secretRoot -Force | Out-Null
    $configuration = New-SocLabConfiguration `
        -ShuffleOrgId $organizationId -ShuffleWorkflowId $oldWorkflowId `
        -ShuffleWebhookId $oldWebhookId
    $oldUri = "https://shuffler.io/api/v1/hooks/webhook_$oldWebhookId"
    $newUri = "https://shuffler.io/api/v1/hooks/webhook_$newWebhookId"
    $oldCipher = [Convert]::ToBase64String(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes('opaque-old-dpapi-fixture')
        )
    )
    $newCipher = [Convert]::ToBase64String(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes('opaque-new-dpapi-fixture')
        )
    )
    $cipherByUri = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal
    )
    $uriByCipher = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal
    )
    $cipherByUri.Add($oldUri,$oldCipher)
    $cipherByUri.Add($newUri,$newCipher)
    $uriByCipher.Add($oldCipher,$oldUri)
    $uriByCipher.Add($newCipher,$newUri)
    $mockHeaderName='X-SOC-Webhook-Key'
    $mockHeaderSecret='header-secret-plaintext-sentinel'
    $mockApiSecret='api-secret-plaintext-sentinel'
    $baselineConfigBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($configuration | ConvertTo-Json -Depth 8) + "`n")
    )
    $baselineSecretBytes = New-TestDpapiRecordBytes -CipherBase64 $oldCipher
    $newSecretBytes = New-TestDpapiRecordBytes -CipherBase64 $newCipher
    $baselineConfigHash = Get-SocShuffleV2BytesSha256 -Bytes $baselineConfigBytes
    $baselineSecretHash = Get-SocShuffleV2BytesSha256 -Bytes $baselineSecretBytes
    $newSecretHash = Get-SocShuffleV2BytesSha256 -Bytes $newSecretBytes

    $readConfiguration = {
        param($Root)
        Get-Content -LiteralPath (Join-Path $Root 'soc-lab.json') -Raw |
            ConvertFrom-Json -Depth 12
    }
    $state = @{assertions=0;create_calls=0;expect_recovered=$false}
    $aclState = @{
        prepare_calls=0
        assertions=[Collections.Generic.List[object]]::new()
    }
    $preparePrivateRoots = {
        param($ConfigRoot,$SecretsRoot)
        if ([IO.Path]::GetFullPath($ConfigRoot) -ine [IO.Path]::GetFullPath($configurationRoot) -or
            [IO.Path]::GetFullPath($SecretsRoot) -ine [IO.Path]::GetFullPath($secretRoot)) {
            throw 'The test ACL preparation hook received unexpected roots.'
        }
        $aclState.prepare_calls++
    }.GetNewClosure()
    $assertPrivatePath = {
        param($Path,$Kind,[bool]$RequireInherited=$false)
        $pathType = if ($Kind -ceq 'Directory') { 'Container' } else { 'Leaf' }
        if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
            throw 'The mock private ACL assertion target is unavailable.'
        }
        [void]$aclState.assertions.Add([pscustomobject]@{
            path=[IO.Path]::GetFullPath($Path)
            kind=$Kind
            require_inherited=$RequireInherited
        })
    }.GetNewClosure()
    $createRecord = {
        param($Root,$Callback)
        $state.create_calls++
        $key = [string]$Callback
        if (-not $cipherByUri.ContainsKey($key)) {
            throw 'The mock DPAPI writer received an unknown canonical URI.'
        }
        return ,([byte[]](New-TestDpapiRecordBytes -CipherBase64 $cipherByUri[$key]))
    }.GetNewClosure()
    $readUri = {
        param($Root)
        $recordPath = Join-Path $Root 'shuffle_webhook_url.dpapi.json'
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json -Depth 8
        $cipher = [string]$record.cipher_base64
        $decoded = [Convert]::FromBase64String($cipher)
        try {
            if (-not $uriByCipher.ContainsKey($cipher)) {
                throw 'The mock DPAPI file decoder received an unknown opaque cipher.'
            }
            return [string]$uriByCipher[$cipher]
        } finally {
            [Array]::Clear($decoded,0,$decoded.Length)
        }
    }.GetNewClosure()
    $assertWorkflow = {
        param($Configuration,$WorkflowId,$WebhookId,$Root)
        if (-not $mockHeaderName -or -not $mockHeaderSecret -or -not $mockApiSecret) {
            throw 'The mock workflow secret fixtures are unavailable.'
        }
        $state.assertions++
        if ($state.expect_recovered) {
            $actualConfigHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $actualSecretHash = (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualConfigHash -cne $baselineConfigHash -or
                $actualSecretHash -cne $baselineSecretHash) {
                throw 'The prior transaction was not recovered before preflight.'
            }
            if ([string](& $readUri $secretRoot) -cne $oldUri) {
                throw 'Crash recovery did not restore semantic URI readback from the record file.'
            }
            $state.expect_recovered = $false
        }
    }.GetNewClosure()

    function Reset-TestFixture {
        [IO.File]::WriteAllBytes($configPath,$baselineConfigBytes)
        [IO.File]::WriteAllBytes($secretPath,$baselineSecretBytes)
        if (Test-Path -LiteralPath $markerPath) { Remove-Item -LiteralPath $markerPath -Force }
        $state.expect_recovered=$false
    }

    # LibraryOnly test hooks and crash simulation must never turn canonical
    # live roots, their children, normalized aliases, or parent traversal paths
    # into writable test fixtures. Isolation runs before every injected hook.
    $liveConfigurationRoot=[IO.Path]::GetFullPath((Get-SocConfigurationRoot -Root ''))
    $liveSecretRoot=[IO.Path]::GetFullPath((Get-SocSecretRoot -Root ''))
    $liveTraversalRoot=Split-Path -Parent $liveConfigurationRoot
    $forbiddenTestRoots=@(
        [pscustomobject]@{config=$liveConfigurationRoot;secret=$liveSecretRoot;label='exact'},
        [pscustomobject]@{
            config=(Join-Path $liveConfigurationRoot 'forbidden-child')
            secret=(Join-Path $liveSecretRoot 'forbidden-child')
            label='child'
        },
        [pscustomobject]@{
            config=(Join-Path $liveConfigurationRoot 'forbidden-child\..')
            secret=(Join-Path $liveSecretRoot 'forbidden-child\..')
            label='normalized'
        },
        [pscustomobject]@{config=$liveTraversalRoot;secret=$liveTraversalRoot;label='traversal'},
        [pscustomobject]@{
            config='\\?\Volume{11111111-1111-1111-1111-111111111111}\aws-topology\soc-config'
            secret='\\?\Volume{11111111-1111-1111-1111-111111111111}\aws-topology\soc-secrets'
            label='volume-guid-alias'
        },
        [pscustomobject]@{
            config='\\?\C:\Users\Unoh\AppData\Local\aws-topology\soc-config'
            secret='\\?\C:\Users\Unoh\AppData\Local\aws-topology\soc-secrets'
            label='extended-device'
        },
        [pscustomobject]@{
            config='\\.\C:\Users\Unoh\AppData\Local\aws-topology\soc-config'
            secret='\\.\C:\Users\Unoh\AppData\Local\aws-topology\soc-secrets'
            label='device'
        },
        [pscustomobject]@{
            config='\\server\share\aws-topology\soc-config'
            secret='\\server\share\aws-topology\soc-secrets'
            label='unc'
        }
    )
    $bypassState=@{calls=0}
    $bypassPrepare={param($A,$B);$bypassState.calls++;throw 'bypass prepare called'}.GetNewClosure()
    $bypassAcl={param($A,$B,$C);$bypassState.calls++;throw 'bypass ACL called'}.GetNewClosure()
    $bypassReadConfig={param($A);$bypassState.calls++;throw 'bypass config read called'}.GetNewClosure()
    $bypassCreate={param($A,$B);$bypassState.calls++;throw 'bypass secret write called'}.GetNewClosure()
    $bypassReadUri={param($A);$bypassState.calls++;throw 'bypass URI read called'}.GetNewClosure()
    $bypassWorkflow={param($A,$B,$C,$D);$bypassState.calls++;throw 'bypass workflow called'}.GetNewClosure()
    foreach ($forbiddenRoots in $forbiddenTestRoots) {
        $liveBypassCaught=$false
        try {
            [void](Invoke-SocShuffleV2RuntimeSwitch `
                -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
                -ConfigurationRoot ([string]$forbiddenRoots.config) `
                -SecretRoot ([string]$forbiddenRoots.secret) `
                -AllowTestRoots -SimulatedCrashStage after-secret `
                -PreparePrivateRoots $bypassPrepare -AssertPrivatePath $bypassAcl `
                -ReadConfiguration $bypassReadConfig `
                -CreateProtectedWebhookRecord $bypassCreate `
                -ReadWebhookUri $bypassReadUri -AssertWorkflow $bypassWorkflow)
        } catch {
            $liveBypassCaught=$true
            Assert-TestCondition ([string]$_.Exception.Message -match '\[root\]') `
                "Live-root bypass $($forbiddenRoots.label) did not fail with root category."
        }
        Assert-TestCondition $liveBypassCaught `
            "Live-root bypass $($forbiddenRoots.label) was accepted."
    }
    Assert-TestCondition ([int]$bypassState.calls -eq 0) `
        'A live-root bypass reached an injected read, write, ACL, or workflow hook.'

    Reset-TestFixture
    $unmockedTestRootCaught = $false
    try {
        [void](Invoke-SocShuffleV2RuntimeSwitch `
            -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
            -AllowTestRoots)
    } catch {
        $unmockedTestRootCaught = $true
        Assert-TestCondition ([string]$_.Exception.Message -match '\[root\]') `
            'Unmocked test roots did not fail with the root category.'
    }
    Assert-TestCondition $unmockedTestRootCaught `
        'Test roots reached live ACL, DPAPI, or workflow defaults without hooks.'

    [IO.File]::WriteAllBytes($secretPath,$newSecretBytes)
    $assertionsBeforeMismatch=[int]$state.assertions
    $createCallsBeforeMismatch=[int]$state.create_calls
    $existingMismatchCaught=$false
    try {
        [void](Invoke-SocShuffleV2RuntimeSwitch `
            -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
            -AllowTestRoots -PreparePrivateRoots $preparePrivateRoots `
            -AssertPrivatePath $assertPrivatePath -ReadConfiguration $readConfiguration `
            -CreateProtectedWebhookRecord $createRecord -ReadWebhookUri $readUri `
            -AssertWorkflow $assertWorkflow)
    } catch {
        $existingMismatchCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match '\[drift\]') `
            'Existing config/record mismatch did not fail with the drift category.'
    }
    Assert-TestCondition $existingMismatchCaught `
        'Existing config/record semantic mismatch was accepted.'
    Assert-TestCondition (-not (Test-Path -LiteralPath $markerPath) -and
        (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baselineConfigHash -and
        (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $newSecretHash -and
        [int]$state.assertions -eq $assertionsBeforeMismatch -and
        [int]$state.create_calls -eq $createCallsBeforeMismatch) `
        'Existing mismatch created a journal, wrote runtime files, or reached later gates.'

    Reset-TestFixture
    $result = Invoke-SocShuffleV2RuntimeSwitch `
        -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
        -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
        -AllowTestRoots -PreparePrivateRoots $preparePrivateRoots `
        -AssertPrivatePath $assertPrivatePath -ReadConfiguration $readConfiguration `
        -CreateProtectedWebhookRecord $createRecord -ReadWebhookUri $readUri `
        -AssertWorkflow $assertWorkflow
    Assert-TestCondition ([string]$result.status -ceq 'switched') 'Normal switch failed.'
    Assert-TestCondition (-not (Test-Path -LiteralPath $markerPath)) `
        'Successful switch retained its transaction marker.'
    $readback = & $readConfiguration $configurationRoot
    Assert-TestCondition ([string]$readback.shuffle_workflow_id -ceq $newWorkflowId -and
        [string]$readback.shuffle_webhook_id -ceq $newWebhookId) `
        'Normal switch did not update both IDs.'
    Assert-TestCondition ([string](& $readUri $secretRoot) -ceq $newUri) `
        'Normal switch did not read the new URI from the record file.'
    Assert-TestCondition ([int]$aclState.prepare_calls -gt 0) `
        'The private root preparation hook was not used.'
    $rootAclPaths = @($aclState.assertions | Where-Object kind -ceq 'Directory' |
        ForEach-Object path | Select-Object -Unique)
    Assert-TestCondition ([IO.Path]::GetFullPath($configurationRoot) -in $rootAclPaths -and
        [IO.Path]::GetFullPath($secretRoot) -in $rootAclPaths) `
        'Both private runtime roots were not asserted.'
    $inheritedMarkerChecks = @($aclState.assertions | Where-Object {
        $_.path -ieq [IO.Path]::GetFullPath($markerPath) -and $_.require_inherited
    })
    Assert-TestCondition ($inheritedMarkerChecks.Count -gt 0) `
        'The transaction marker inherited/private ACL was not asserted.'

    # A semantic failure after the protected-record write must roll back both
    # exact original files and remove the proven transaction marker.
    Reset-TestFixture
    $semanticFailureState = @{rejected_new=$false}
    $readUriRejectNewOnce = {
        param($Root)
        $actual = [string](& $readUri $Root)
        if ($actual -ceq $newUri -and -not $semanticFailureState.rejected_new) {
            $semanticFailureState.rejected_new=$true
            return $oldUri
        }
        return $actual
    }.GetNewClosure()
    $semanticFailureCaught=$false
    try {
        [void](Invoke-SocShuffleV2RuntimeSwitch `
            -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
            -AllowTestRoots -PreparePrivateRoots $preparePrivateRoots `
            -AssertPrivatePath $assertPrivatePath -ReadConfiguration $readConfiguration `
            -CreateProtectedWebhookRecord $createRecord `
            -ReadWebhookUri $readUriRejectNewOnce -AssertWorkflow $assertWorkflow)
    } catch {
        $semanticFailureCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match '\[secret\]') `
            'Semantic readback failure did not retain its fixed failure category.'
    }
    Assert-TestCondition $semanticFailureCaught `
        'A mismatched protected-record semantic readback was accepted.'
    Assert-TestCondition ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baselineConfigHash -and
        (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baselineSecretHash -and
        -not (Test-Path -LiteralPath $markerPath)) `
        'Same-run rollback did not restore exact bytes and remove its marker.'
    Assert-TestCondition ([string](& $readUri $secretRoot) -ceq $oldUri) `
        'Same-run rollback did not restore semantic record-file readback.'

    foreach ($crashStage in @('after-secret','after-config')) {
        Reset-TestFixture
        $crashCaught=$false
        try {
            [void](Invoke-SocShuffleV2RuntimeSwitch `
                -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
                -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
                -AllowTestRoots -SimulatedCrashStage $crashStage `
                -PreparePrivateRoots $preparePrivateRoots `
                -AssertPrivatePath $assertPrivatePath `
                -ReadConfiguration $readConfiguration `
                -CreateProtectedWebhookRecord $createRecord -ReadWebhookUri $readUri `
                -AssertWorkflow $assertWorkflow)
        } catch {
            $crashCaught=$true
            Assert-TestCondition ([string]$_.Exception.Message -match '\[simulated-crash\]') `
                "Crash stage $crashStage did not return the fixed category."
        }
        Assert-TestCondition $crashCaught "Crash stage $crashStage did not stop."
        Assert-TestCondition (Test-Path -LiteralPath $markerPath -PathType Leaf) `
            "Crash stage $crashStage did not retain the recovery marker."
        $markerBytes = [IO.File]::ReadAllBytes($markerPath)
        $markerObject = [Text.UTF8Encoding]::new($false,$true).GetString($markerBytes) |
            ConvertFrom-Json -Depth 20
        $nestedRecordBytes = [Convert]::FromBase64String(
            [string]$markerObject.webhook_record_bytes_base64
        )
        $nestedRecord = [Text.UTF8Encoding]::new($false,$true).GetString($nestedRecordBytes) |
            ConvertFrom-Json -Depth 8
        $nestedCipherBytes = [Convert]::FromBase64String(
            [string]$nestedRecord.cipher_base64
        )
        Assert-TestCondition ($nestedRecordBytes.Length -gt 0 -and
            $nestedCipherBytes.Length -gt 0 -and
            [string]$nestedRecord.cipher_base64 -ceq $oldCipher) `
            'The transaction marker did not retain only the opaque original record cipher.'
        $decodedLayerCount = Assert-TestNoForbiddenPlaintextRecursive `
            -RootBytes $markerBytes -ForbiddenPlaintext @(
                $oldUri,$newUri,'/api/v1/hooks/webhook_',$mockHeaderName,
                $mockHeaderSecret,$mockApiSecret
            )
        Assert-TestCondition ([int]$decodedLayerCount -ge 3) `
            'The journal secret scan did not recursively inspect nested Base64 layers.'
        if ($crashStage -ceq 'after-secret') {
            Assert-TestCondition ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baselineConfigHash) `
                'The after-secret crash changed configuration prematurely.'
        } else {
            Assert-TestCondition ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baselineConfigHash) `
                'The after-config crash did not leave the expected partial state.'
        }

        $state.expect_recovered=$true
        $recoveryResult = Invoke-SocShuffleV2RuntimeSwitch `
            -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
            -AllowTestRoots -PreparePrivateRoots $preparePrivateRoots `
            -AssertPrivatePath $assertPrivatePath -ReadConfiguration $readConfiguration `
            -CreateProtectedWebhookRecord $createRecord -ReadWebhookUri $readUri `
            -AssertWorkflow $assertWorkflow
        Assert-TestCondition ([bool]$recoveryResult.recovered_prior_transaction) `
            "The next run did not report recovery for $crashStage."
        Assert-TestCondition (-not (Test-Path -LiteralPath $markerPath)) `
            "The recovered $crashStage transaction retained its marker."
    }

    # A separate process holds the fixed mutex. The switch must time out before
    # reading or mutating the fixture.
    Reset-TestFixture
    $readyPath = Join-Path $testRoot 'mutex-ready'
    $mutexJob = Start-Job -ArgumentList $script:SocShuffleV2MutexName,$readyPath -ScriptBlock {
        param($Name,$Ready)
        $mutex=[Threading.Mutex]::new($false,$Name)
        $held=$false
        try {
            $held=$mutex.WaitOne(5000)
            if (-not $held) { throw 'mutex hold failed' }
            [IO.File]::WriteAllText($Ready,'ready')
            Start-Sleep -Seconds 3
        } finally {
            if ($held) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
    try {
        $deadline=[DateTimeOffset]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $readyPath) -and [DateTimeOffset]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 50
        }
        Assert-TestCondition (Test-Path -LiteralPath $readyPath) 'Mutex holder did not become ready.'
        $mutexCaught=$false
        try {
            [void](Invoke-SocShuffleV2RuntimeSwitch `
                -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
                -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
                -AllowTestRoots -MutexTimeoutMilliseconds 50 `
                -PreparePrivateRoots $preparePrivateRoots `
                -AssertPrivatePath $assertPrivatePath `
                -ReadConfiguration $readConfiguration `
                -CreateProtectedWebhookRecord $createRecord -ReadWebhookUri $readUri `
                -AssertWorkflow $assertWorkflow)
        } catch {
            $mutexCaught=$true
            Assert-TestCondition ([string]$_.Exception.Message -match '\[mutex\]') `
                'Concurrent switch did not fail with the mutex category.'
        }
        Assert-TestCondition $mutexCaught 'Concurrent switch acquired the held mutex.'
        Assert-TestCondition ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baselineConfigHash) `
            'Mutex refusal changed configuration.'
    } finally {
        Stop-Job -Job $mutexJob -ErrorAction SilentlyContinue
        Remove-Job -Job $mutexJob -Force -ErrorAction SilentlyContinue
    }

    # Live CLI cannot use arbitrary roots and no longer exposes any assertion
    # bypass switch.
    $wrongRootCaught=$false
    try {
        & $scriptPath -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot $configurationRoot -SecretRoot $secretRoot `
            -ConfirmSwitch 'SWITCH SHUFFLE SOC V2'
    } catch {
        $wrongRootCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match '\[root\]') `
            'Live CLI root override did not fail with the root category.'
    }
    Assert-TestCondition $wrongRootCaught 'Live CLI accepted non-canonical roots.'

    $volumeAliasRoots=$forbiddenTestRoots | Where-Object label -ceq 'volume-guid-alias'
    $volumeAliasCliCaught=$false
    try {
        & $scriptPath -NewWorkflowId $newWorkflowId -NewWebhookId $newWebhookId `
            -ConfigurationRoot ([string]$volumeAliasRoots.config) `
            -SecretRoot ([string]$volumeAliasRoots.secret) `
            -ConfirmSwitch 'SWITCH SHUFFLE SOC V2'
    } catch {
        $volumeAliasCliCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match '\[root\]') `
            'Production CLI Volume GUID alias did not fail with root category.'
    }
    Assert-TestCondition $volumeAliasCliCaught `
        'Production CLI accepted a Volume GUID root alias.'

    $skipCaught=$false
    try {
        & $scriptPath -LibraryOnly -SkipWorkflowAssertion
    } catch {
        $skipCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match 'SkipWorkflowAssertion') `
            'Removed workflow assertion bypass did not fail parameter binding.'
    }
    Assert-TestCondition $skipCaught 'The live workflow assertion bypass still exists.'

    $allowTestRootsCliCaught=$false
    try { & $scriptPath -LibraryOnly -AllowTestRoots }
    catch {
        $allowTestRootsCliCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match 'AllowTestRoots') `
            'Production CLI AllowTestRoots bypass did not fail parameter binding.'
    }
    Assert-TestCondition $allowTestRootsCliCaught `
        'Production CLI exposes forbidden AllowTestRoots bypass.'

    $simulatedCrashCliCaught=$false
    try { & $scriptPath -LibraryOnly -SimulatedCrashStage after-secret }
    catch {
        $simulatedCrashCliCaught=$true
        Assert-TestCondition ([string]$_.Exception.Message -match 'SimulatedCrashStage') `
            'Production CLI SimulatedCrashStage bypass did not fail parameter binding.'
    }
    Assert-TestCondition $simulatedCrashCliCaught `
        'Production CLI exposes forbidden SimulatedCrashStage bypass.'
} finally {
    Get-Job -ErrorAction SilentlyContinue | Where-Object Name -like 'Job*' |
        Stop-Job -ErrorAction SilentlyContinue
    Get-Job -ErrorAction SilentlyContinue | Where-Object Name -like 'Job*' |
        Remove-Job -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'Shuffle SOC v2 runtime switch tests passed.'
