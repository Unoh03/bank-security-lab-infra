#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-WazuhGeneratedPassword {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value.Length -lt 24 -or $Value.Length -gt 64 -or
        $Value -cnotmatch '[A-Z]' -or
        $Value -cnotmatch '[a-z]' -or
        $Value -notmatch '[0-9]' -or
        $Value -notmatch '[.*+?\-]' -or
        $Value -notmatch '^[A-Za-z0-9.*+?\-]+$') {
        throw "$Label does not satisfy the fixed Wazuh generated-password contract."
    }
}

function Get-WazuhPasswordHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Password)

    Assert-WazuhGeneratedPassword -Value $Password -Label 'Wazuh password'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker is unavailable for the Wazuh password hash operation.'
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'docker'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = 'run --rm -i wazuh/wazuh-indexer:4.14.7 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'The bounded Wazuh hash process could not start.'
        }
        $process.StandardInput.WriteLine($Password)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw 'Wazuh password hash generation failed; subprocess output was suppressed.'
        }
        $matches = [regex]::Matches(
            ([string]$stdout + [string]$stderr),
            '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'
        )
        if ($matches.Count -ne 1) {
            throw 'Wazuh password hash generation returned an unexpected result.'
        }
        return [string]$matches[0].Value
    } finally {
        $process.Dispose()
    }
}

function Set-WazuhInternalUserHashText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ValidateSet('admin','kibanaserver')][string]$UserName,
        [Parameter(Mandatory)][string]$Hash
    )

    if ($Hash -notmatch '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$') {
        throw 'The Wazuh password hash has an unexpected bcrypt format.'
    }

    $newline = if ($Text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $endsWithNewline = $Text.EndsWith("`n")
    $lines = @($Text -split "\r?\n")
    if ($endsWithNewline -and $lines.Count -gt 0 -and $lines[-1] -ceq '') {
        $lines = @($lines[0..($lines.Count - 2)])
    }

    $currentUser = ''
    $userBlockCount = 0
    $hashReplaceCount = 0
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        if ($line -match '^([A-Za-z0-9._-]+):\s*$') {
            $currentUser = [string]$Matches[1]
            if ($currentUser -ceq $UserName) {
                $userBlockCount++
            }
            continue
        }
        if ($currentUser -ceq $UserName -and $line -match '^(\s+hash:\s*).*$') {
            $lines[$index] = "$($Matches[1])`"$Hash`""
            $hashReplaceCount++
        }
    }

    if ($userBlockCount -ne 1 -or $hashReplaceCount -ne 1) {
        throw "Wazuh internal_users.yml did not contain exactly one $UserName hash target."
    }

    $result = $lines -join $newline
    if ($endsWithNewline) {
        $result += $newline
    }
    return $result
}

function Set-WazuhDashboardApiPasswordText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Password
    )

    Assert-WazuhGeneratedPassword -Value $Password -Label 'Wazuh API password'
    $newline = if ($Text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $endsWithNewline = $Text.EndsWith("`n")
    $lines = @($Text -split "\r?\n")
    if ($endsWithNewline -and $lines.Count -gt 0 -and $lines[-1] -ceq '') {
        $lines = @($lines[0..($lines.Count - 2)])
    }

    $replaceCount = 0
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ([string]$lines[$index] -match '^(\s+password:\s*).*$') {
            $lines[$index] = "$($Matches[1])`"$Password`""
            $replaceCount++
        }
    }
    if ($replaceCount -ne 1) {
        throw 'Wazuh dashboard wazuh.yml did not contain exactly one password target.'
    }

    $result = $lines -join $newline
    if ($endsWithNewline) {
        $result += $newline
    }
    return $result
}

function ConvertTo-WazuhComposePath {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path).Replace('\','/')
    if ($resolved.Contains('"')) {
        throw 'A Wazuh Runtime path cannot contain a double quote.'
    }
    return $resolved
}

function New-WazuhSecretOverrideText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Admin','Final')][string]$Phase,
        [Parameter(Mandatory)][string]$InternalUsersPath,
        [Parameter(Mandatory)][string]$AdminPassword,
        [string]$KibanaserverPassword = '',
        [string]$ApiPassword = '',
        [string]$DashboardConfigPath = ''
    )

    Assert-WazuhGeneratedPassword -Value $AdminPassword -Label 'Wazuh indexer admin password'
    $internalUsers = ConvertTo-WazuhComposePath -Path $InternalUsersPath

    if ($Phase -ceq 'Admin') {
        return @"
services:
  wazuh.manager:
    environment:
      INDEXER_PASSWORD: "$AdminPassword"

  wazuh.indexer:
    volumes:
      - type: bind
        source: "$internalUsers"
        target: /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml
        read_only: true

  wazuh.dashboard:
    environment:
      INDEXER_PASSWORD: "$AdminPassword"
"@
    }

    Assert-WazuhGeneratedPassword -Value $KibanaserverPassword -Label 'Wazuh indexer kibanaserver password'
    Assert-WazuhGeneratedPassword -Value $ApiPassword -Label 'Wazuh API password'
    if (-not $DashboardConfigPath) {
        throw 'The Final Wazuh phase requires a dashboard API configuration path.'
    }
    $dashboardConfig = ConvertTo-WazuhComposePath -Path $DashboardConfigPath

    return @"
services:
  wazuh.manager:
    environment:
      INDEXER_PASSWORD: "$AdminPassword"
      API_PASSWORD: "$ApiPassword"

  wazuh.indexer:
    volumes:
      - type: bind
        source: "$internalUsers"
        target: /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml
        read_only: true

  wazuh.dashboard:
    environment:
      INDEXER_PASSWORD: "$AdminPassword"
      DASHBOARD_PASSWORD: "$KibanaserverPassword"
      API_PASSWORD: "$ApiPassword"
    volumes:
      - type: bind
        source: "$dashboardConfig"
        target: /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
        read_only: true
"@
}

function Assert-WazuhSocIntegrationXml {
    param([Parameter(Mandatory)][string]$XmlText)

    try {
        [xml]$document = $XmlText
    } catch {
        throw 'The Wazuh SOC integration fragment is not valid XML.'
    }
    if ($document.DocumentElement.Name -cne 'ossec_config') {
        throw 'The Wazuh SOC integration fragment must have one ossec_config root.'
    }
    $nodes = @($document.DocumentElement.SelectNodes('./integration'))
    if ($nodes.Count -ne 1) {
        throw 'The Wazuh SOC integration fragment must contain exactly one integration.'
    }
    $integration = $nodes[0]
    $expected = [ordered]@{
        name         = 'custom-shuffle-soc'
        level        = '10'
        rule_id      = '100103'
        alert_format = 'json'
        timeout      = '10'
        retries      = '1'
    }
    $elementNames = @(
        $integration.ChildNodes |
            Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element } |
            ForEach-Object { [string]$_.Name }
    )
    if ($elementNames.Count -ne $expected.Count -or
        @($elementNames | Where-Object { $_ -notin $expected.Keys }).Count -ne 0) {
        throw 'The Wazuh SOC integration fragment contains an unexpected field.'
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $matches = @($integration.SelectNodes("./$($entry.Key)"))
        if ($matches.Count -ne 1 -or [string]$matches[0].InnerText -cne [string]$entry.Value) {
            throw "The Wazuh SOC integration field is not frozen: $($entry.Key)"
        }
    }
}

function Add-WazuhManagerSocIntegrationText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManagerConfigText,
        [Parameter(Mandatory)][string]$IntegrationXml
    )

    Assert-WazuhSocIntegrationXml -XmlText $IntegrationXml
    $integrationBlocks = @([regex]::Matches(
        $ManagerConfigText,
        '(?is)<integration\b[^>]*>.*?</integration>'
    ))
    $socBlocks = @($integrationBlocks | Where-Object {
        $_.Value -match '(?is)<name>\s*custom-shuffle-soc\s*</name>'
    })
    if ($socBlocks.Count -gt 1) {
        throw 'The Wazuh Manager configuration contains duplicate custom-shuffle-soc integrations.'
    }
    if ($socBlocks.Count -eq 1) {
        Assert-WazuhSocIntegrationXml -XmlText (
            '<ossec_config>' + $socBlocks[0].Value + '</ossec_config>'
        )
        return $ManagerConfigText
    }

    $newline = if ($ManagerConfigText.Contains("`r`n")) { "`r`n" } else { "`n" }
    $result = $ManagerConfigText.TrimEnd("`r", "`n") + $newline + $newline
    $fragmentLines = @($IntegrationXml.Trim() -split '\r?\n')
    $result += ($fragmentLines -join $newline) + $newline
    return $result
}

function New-WazuhSocIntegrationOverrideText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManagerConfigPath,
        [Parameter(Mandatory)][string]$IntegrationScriptPath,
        [Parameter(Mandatory)][string]$WebhookUrlPath,
        [Parameter(Mandatory)][string]$WebhookHeaderKeyPath
    )

    $managerConfig = ConvertTo-WazuhComposePath -Path $ManagerConfigPath
    $integrationScript = ConvertTo-WazuhComposePath -Path $IntegrationScriptPath
    $webhookUrl = ConvertTo-WazuhComposePath -Path $WebhookUrlPath
    $webhookHeaderKey = ConvertTo-WazuhComposePath -Path $WebhookHeaderKeyPath

    return @"
services:
  wazuh.manager:
    volumes:
      - type: bind
        source: "$managerConfig"
        target: /wazuh-config-mount/etc/ossec.conf
        read_only: true
      - type: bind
        source: "$integrationScript"
        target: /soc-bootstrap/custom-shuffle-soc
        read_only: true
      - type: bind
        source: "$webhookUrl"
        target: /var/ossec/soc-secrets/shuffle_webhook_url
        read_only: true
      - type: bind
        source: "$webhookHeaderKey"
        target: /var/ossec/soc-secrets/shuffle_webhook_header_key
        read_only: true
"@
}

Export-ModuleMember -Function @(
    'Get-WazuhPasswordHash',
    'Set-WazuhInternalUserHashText',
    'Set-WazuhDashboardApiPasswordText',
    'New-WazuhSecretOverrideText',
    'Add-WazuhManagerSocIntegrationText',
    'New-WazuhSocIntegrationOverrideText'
)
