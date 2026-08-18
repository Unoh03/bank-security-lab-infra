#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

function Get-SocConfigurationRoot {
    [CmdletBinding()]
    param([string]$Root = '')

    if ($Root) {
        return [IO.Path]::GetFullPath($Root)
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is unavailable; the SOC configuration root cannot be resolved.'
    }
    return Join-Path $env:LOCALAPPDATA 'aws-topology\soc-config'
}

function Get-SocConfigurationPath {
    [CmdletBinding()]
    param([string]$Root = '')

    return Join-Path (Get-SocConfigurationRoot -Root $Root) 'soc-lab.json'
}

function Assert-SocLabConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)

    $required = @(
        'schema_version','shuffle_api_base','shuffle_org_id',
        'shuffle_workflow_id','shuffle_webhook_id','github_repository',
        'github_ref','containment_workflow','reset_workflow',
        'argo_application','wazuh_root','aws_profile'
    )
    foreach ($field in $required) {
        if ($null -eq $Configuration.PSObject.Properties[$field] -or
            [string]::IsNullOrWhiteSpace([string]$Configuration.$field)) {
            throw "SOC configuration field is missing: $field"
        }
    }
    if ([int]$Configuration.schema_version -ne 1) {
        throw 'The SOC configuration schema version is unsupported.'
    }
    foreach ($field in @('shuffle_org_id','shuffle_workflow_id','shuffle_webhook_id')) {
        if ([string]$Configuration.$field -cnotmatch $script:UuidPattern) {
            throw "SOC configuration UUID is not canonical: $field"
        }
    }
    $base = [uri][string]$Configuration.shuffle_api_base
    if ($base.Scheme -cne 'https' -or
        ($base.Host -cne 'shuffler.io' -and -not $base.Host.EndsWith('.shuffler.io')) -or
        -not $base.IsDefaultPort -or $base.AbsolutePath -cne '/' -or
        $base.UserInfo -or $base.Query -or $base.Fragment) {
        throw 'The SOC configuration Shuffle API origin is not approved.'
    }
    $fixed = [ordered]@{
        github_repository   = 'Unoh03/Uns-DVWA'
        github_ref          = 'main'
        containment_workflow = 'soc-contain-dvwa.yml'
        reset_workflow      = 'soc-reset-dvwa.yml'
        argo_application    = 'dvwa'
        aws_profile         = 'terra-user'
    }
    foreach ($entry in $fixed.GetEnumerator()) {
        if ([string]$Configuration.($entry.Key) -cne [string]$entry.Value) {
            throw "SOC configuration fixed field changed: $($entry.Key)"
        }
    }
    $wazuhRoot = [IO.Path]::GetFullPath([string]$Configuration.wazuh_root)
    if ($wazuhRoot -ine [IO.Path]::GetFullPath('D:\Wazuh\wazuh-docker\single-node')) {
        throw 'The SOC configuration Wazuh root is outside the fixed lab location.'
    }
    foreach ($forbidden in @(
        'api_key','token','credential','password','secret','webhook_url',
        'github_pat','cookie'
    )) {
        if ($null -ne $Configuration.PSObject.Properties[$forbidden]) {
            throw "The SOC configuration contains a forbidden secret field: $forbidden"
        }
    }
    return $Configuration
}

function New-SocLabConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ShuffleOrgId,
        [Parameter(Mandatory)][string]$ShuffleWorkflowId,
        [Parameter(Mandatory)][string]$ShuffleWebhookId,
        [uri]$ShuffleApiBase = 'https://shuffler.io/',
        [string]$WazuhRoot = 'D:\Wazuh\wazuh-docker\single-node'
    )

    $configuration = [pscustomobject][ordered]@{
        schema_version       = 1
        shuffle_api_base     = $ShuffleApiBase.AbsoluteUri
        shuffle_org_id       = $ShuffleOrgId
        shuffle_workflow_id  = $ShuffleWorkflowId
        shuffle_webhook_id   = $ShuffleWebhookId
        github_repository    = 'Unoh03/Uns-DVWA'
        github_ref           = 'main'
        containment_workflow = 'soc-contain-dvwa.yml'
        reset_workflow       = 'soc-reset-dvwa.yml'
        argo_application     = 'dvwa'
        wazuh_root           = [IO.Path]::GetFullPath($WazuhRoot)
        aws_profile          = 'terra-user'
    }
    return Assert-SocLabConfiguration -Configuration $configuration
}

function Write-SocLabConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Configuration,
        [string]$Root = ''
    )

    [void](Assert-SocLabConfiguration -Configuration $Configuration)
    $resolvedRoot = Get-SocConfigurationRoot -Root $Root
    New-Item -ItemType Directory -Path $resolvedRoot -Force | Out-Null
    $path = Get-SocConfigurationPath -Root $resolvedRoot
    $temporaryPath = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Configuration | ConvertTo-Json -Depth 8) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $path -Force
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
    return $path
}

function Read-SocLabConfiguration {
    [CmdletBinding()]
    param([string]$Root = '')

    $path = Get-SocConfigurationPath -Root $Root
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "SOC configuration is unavailable: $path"
    }
    $configuration = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    return Assert-SocLabConfiguration -Configuration $configuration
}

Export-ModuleMember -Function @(
    'Get-SocConfigurationRoot',
    'Get-SocConfigurationPath',
    'Assert-SocLabConfiguration',
    'New-SocLabConfiguration',
    'Write-SocLabConfiguration',
    'Read-SocLabConfiguration'
)
