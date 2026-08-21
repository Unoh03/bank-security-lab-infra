#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path = Join-Path $root 'observability\scenarios\Invoke-CapitalOneWafReattack.ps1'
$text = Get-Content -LiteralPath $path -Raw

foreach ($contract in @(
    @{Pattern='^#requires\s+-Version\s+7\.4';Message='WAF reattack must require PowerShell 7.4.'},
    @{Pattern='application_url';Message='WAF reattack does not resolve the active application_url.'},
    @{Pattern='Get-DailySessionActiveStatePath[\s\S]*?Read-DailySessionState[\s\S]*?SecurityScenarioProfile[\s\S]*?capital-one-lab';Message='WAF reattack is not bound to the active Daily Runtime.'},
    @{Pattern='applicationUrl\.Scheme\s+-cne\s+''https''';Message='WAF reattack does not enforce HTTPS.'},
    @{Pattern='securityLevel\s+-cne\s+''impossible''';Message='WAF reattack stops without proving an impossible DVWA session.'},
    @{Pattern='169\.254\.169\.254/latest/meta-data/iam/security-credentials/';Message='WAF reattack does not use the fixed IMDS role-discovery target.'},
    @{Pattern='X-SOC-TAKE-ID["'']?\s*[=}]\s*\$ReattackId';Message='WAF reattack does not bind the POST to a fresh reattack identifier.'},
    @{Pattern='ControlTakeId\s*=\s*New-SocTakeId';Message='Normal controls do not use an independent TAKE identifier.'},
    @{Pattern='X-SOC-TAKE-ID["'']?\s*[=}]\s*\$ControlTakeId';Message='Normal Ping can contaminate the reattack downstream-zero correlation.'},
    @{Pattern='ExpectedWafTerminatingRuleId';Message='WAF terminating Rule is not an explicit input contract.'},
    @{Pattern='action\s*=\s*"BLOCK"[\s\S]*?terminatingRuleId';Message='WAF query does not require action BLOCK and terminating Rule.'},
    @{Pattern='httpRequest\.requestId[\s\S]*?wafRequestId\s+-cne\s+\$edgeRequestId';Message='WAF evidence is not correlated to the same CloudFront request.'},
    @{Pattern='httpStatus\s+-ne\s+403';Message='HTTP 403 is not checked as an expected reattack result.'},
    @{Pattern='EarlyRuleId[\s\S]*?ConfirmedRuleId[\s\S]*?Get-ReattackWazuhRuleCount';Message='v2 Rule IDs are not parameterized for the zero-alert observation.'},
    @{Pattern='confirmedRuleCount\s*=\s*Get-ReattackWazuhRuleCount\s+-RuleId\s+\$ConfirmedRuleId\s+`?\s*-AdminPassword';Message='Confirmed Rule zero check incorrectly assumes a DVWA attempt field.'},
    @{Pattern='do \{[\s\S]*?Get-ReattackWazuhRuleCount[\s\S]*?observationDeadline[\s\S]*?while \(\$zeroObservationEnd';Message='v2 zero-alert checks are not held for the bounded observation window.'},
    @{Pattern='earlyRuleCount\s+-ne\s+0[\s\S]*?confirmedRuleCount\s+-ne\s+0';Message='Both v2 Rule zero-alert controls are not fail-closed.'},
    @{Pattern='DownstreamEvidenceProvider[\s\S]*?alb_new_attack_requests[\s\S]*?dvwa_new_command_execution[\s\S]*?push_new_attack_events[\s\S]*?cloudtrail_new_protected_getobject[\s\S]*?additional_automatic_response_count';Message='Downstream zero-count contract is missing.'},
    @{Pattern='HealthEvidenceProvider[\s\S]*?health_event_observed[\s\S]*?pipeline_healthy';Message='Push Health control contract is missing.'},
    @{Pattern='Assert-ReattackProviderBoolean[\s\S]*?\$value\s+-isnot\s+\[bool\]';Message='Push Health booleans are not validated fail-closed.'},
    @{Pattern='/index\.php[\s\S]*?ip=''127\.0\.0\.1''[\s\S]*?normalPing';Message='Normal home and numeric-IP Ping controls are missing.'},
    @{Pattern='response_body_persisted\s*=\s*\$false[\s\S]*?credential_value_observed\s*=\s*\$false[\s\S]*?cookie_persisted\s*=\s*\$false';Message='Sensitive response, credential, and cookie boundaries are missing.'},
    @{Pattern='WazuhAttemptField[\s\S]*?runtime gap|runtime gap[\s\S]*?WazuhAttemptField';Message='The unresolved Wazuh field interface gap is not explicit.'}
)) {
    if ($text -notmatch $contract.Pattern) { throw $contract.Message }
}
if ($text -match '(?im)Write-(Host|Output).*?\$(?:rolePayload|.*(?:payload|response|cookie|credential|token))') {
    throw 'WAF reattack can print a sensitive value.'
}
if ($text -match '(?im)\#requires\s+-Version\s+5\.1') {
    throw 'WAF reattack contains a Windows PowerShell 5.1 path.'
}
if ($text -match '(?i)Invoke-(Terraform|Aws|Waf).*?(apply|destroy|update-web-acl)') {
    throw 'WAF reattack contains an infrastructure or WAF mutation path.'
}
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) {
    throw ('WAF reattack parser errors: ' + (@($errors.Message) -join '; '))
}
Write-Host 'Capital One WAF reattack static tests passed.'
