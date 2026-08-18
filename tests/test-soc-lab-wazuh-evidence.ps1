#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'automation\SocLab.WazuhEvidence.psm1') -Force
$takeId = 'capital-one-20260818T010000Z-deadbeef'

function New-TestHit {
    param([int]$Ordinal)
    $eventTime = [datetimeoffset]'2026-08-18T01:02:03Z'
    return [pscustomobject]@{_source=[pscustomobject]@{
        id="178700000$Ordinal.12345$Ordinal"
        timestamp=$eventTime.AddSeconds($Ordinal).ToString('o')
        rule=[pscustomobject]@{id='100103';level=10}
        data=[pscustomobject]@{
            source='dvwa';transport='push';aws_account_id='433048100798';
            aws_region='ap-northeast-2';event_time=$eventTime.ToString('o');
            event_id="cwl:433048100798:/aws/eks/aws-topology-primary/application:stream:event-$Ordinal-0123456789";
            raw_message_sha256=([string]$Ordinal * 64);
            payload=[pscustomobject]@{
                normalized=$true;take_id=$takeId;event_type='command.execution';
                result='succeeded';route='/vulnerabilities/exec/';
                context=[pscustomobject]@{action='shell_command';resource='ec2_imds';security_level='low'}
            }
        }
    }}
}

$records = @(ConvertTo-SocRule100103Evidence -Hit @((New-TestHit 1),(New-TestHit 2)) -TakeId $takeId)
if ($records.Count -ne 2 -or @($records.event_id | Select-Object -Unique).Count -ne 2 -or
    @($records | Where-Object {$_.latency_seconds -lt 0 -or $_.latency_seconds -gt 120}).Count -ne 0) {
    throw 'The Rule 100103 Evidence validator did not retain two unique bounded alerts.'
}
$three = @(ConvertTo-SocRule100103Evidence `
    -Hit @((New-TestHit 1),(New-TestHit 2),(New-TestHit 3)) `
    -TakeId $takeId -ExpectedCount 3)
if ($three.Count -ne 3) { throw 'The Rule 100103 validator rejected a three-run rehearsal.' }
$duplicate = New-TestHit 1
$duplicateRejected = $false
try {
    [void](ConvertTo-SocRule100103Evidence -Hit @((New-TestHit 1),$duplicate) -TakeId $takeId)
} catch { $duplicateRejected = $_.Exception.Message -match 'uniqueness' }
if (-not $duplicateRejected) { throw 'The Rule 100103 validator accepted a duplicate event_id.' }

$wrong = New-TestHit 2
$wrong._source.data.payload.context.resource = 's3'
$wrongRejected = $false
try {
    [void](ConvertTo-SocRule100103Evidence -Hit @((New-TestHit 1),$wrong) -TakeId $takeId)
} catch { $wrongRejected = $_.Exception.Message -match 'contract' }
if (-not $wrongRejected) { throw 'The Rule 100103 validator accepted the wrong resource.' }

Write-Host 'SOC lab Wazuh Rule 100103 Evidence tests passed.'
