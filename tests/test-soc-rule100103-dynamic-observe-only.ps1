#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$path=Join-Path $root 'observability\scenarios\Invoke-SocRule100103DynamicObserveOnly.ps1'
. $path -LibraryOnly

function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-G4Throws {
    param([scriptblock]$Action,[string]$Category)
    try { & $Action;throw "Expected g4:$Category" }
    catch { if ($_.Exception.Message -cne "g4:$Category") { throw "Expected g4:$Category, got $($_.Exception.Message)" } }
}

function New-TestWorkflowContract {
    return [pscustomobject]@{
        TriggerId='11111111-1111-4111-8111-111111111111'
        ActionId='22222222-2222-4222-8222-222222222222'
        ActionLabel='Change Me'
    }
}

function New-TestWorkflow {
    return [pscustomobject]@{
        id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';name='G4 OBSERVE ONLY';sharing='private';is_valid=$true
        triggers=@([pscustomobject]@{id='11111111-1111-4111-8111-111111111111';trigger_type='WEBHOOK';status='running'})
        actions=@([pscustomobject]@{
            id='22222222-2222-4222-8222-222222222222';label='Change Me';app_name='Shuffle Tools'
            app_version='1.2.0';name='repeat_back_to_me';parameters=@([pscustomobject]@{name='call';value='$exec'})
        })
        branches=@([pscustomobject]@{
            id='33333333-3333-4333-8333-333333333333';source_id='11111111-1111-4111-8111-111111111111'
            destination_id='22222222-2222-4222-8222-222222222222';conditions=@()
        })
    }
}

function New-TestAlert {
    param([string]$TakeId,[int]$Index,[string]$RuleId='100103')
    $eventId="cwl:433048100798:event-$Index-abcdefghijklmnopqrstuv"
    $hash=([char](97+(($Index-1)%20))).ToString()*64
    return [pscustomobject]@{_source=[pscustomobject]@{
        id="1700000000.$Index";timestamp='2026-08-18T00:00:03.000Z'
        rule=[pscustomobject]@{id=$RuleId;level=10}
        data=[pscustomobject]@{
            schema_version=1;source='dvwa';transport='push';aws_account_id='433048100798';aws_region='ap-northeast-2'
            event_id=$eventId;event_time='2026-08-18T00:00:01.000Z';raw_message_sha256=$hash
            payload=[pscustomobject]@{
                normalized=$true;take_id=$TakeId;event_type='command.execution';result='succeeded';route='/vulnerabilities/exec/'
                context=[pscustomobject]@{action='shell_command';resource='ec2_imds';security_level='low'}
            }
        }
    }}
}

function New-TestSource {
    param([object]$Alert)
    $source=$Alert._source;$data=$source.data;$payload=$data.payload
    return [pscustomobject]@{
        take_id=[string]$payload.take_id;event_id=[string]$data.event_id;source='dvwa';transport='push'
        aws_account_id='433048100798';aws_region='ap-northeast-2';normalized=$true;event_type='command.execution'
        result='succeeded';route='/vulnerabilities/exec/';action='shell_command';resource='ec2_imds';security_level='low'
        event_time_utc='2026-08-18T00:00:01.000Z';bridge_received_at_utc='2026-08-18T00:00:02.000Z'
        raw_message_sha256=[string]$data.raw_message_sha256
    }
}

function New-TestPlan {
    param([string]$TakeId,[int]$Count,[string]$RuleId='100103')
    $alerts=[Collections.Generic.List[object]]::new();$sources=[Collections.Generic.List[object]]::new()
    $executions=[Collections.Generic.List[object]]::new();$results=@{}
    for ($i=1;$i -le $Count;$i++) {
        $alert=New-TestAlert -TakeId $TakeId -Index $i -RuleId $RuleId
        $record=Get-G4AlertRecord -Hit $alert -TakeId $TakeId
        $body=New-G4ExpectedBody -AlertRecord $record -SentAtUtc '2026-08-18T00:00:04.000Z'
        $id=('{0:d8}-3333-4333-8333-{1:d12}' -f $i,$i)
        $execution=[pscustomobject]@{
            execution_id=$id;authorization=('{0:d8}-4444-4444-8444-{1:d12}' -f $i,$i)
            status='FINISHED';started_at='2026-08-18T00:00:05.000Z'
            execution_argument=(ConvertTo-G4CanonicalJson $body)
        }
        $result=[pscustomobject]@{execution_id=$id;results=@([pscustomobject]@{
            action=[pscustomobject]@{id='22222222-2222-4222-8222-222222222222';label='Change Me'}
            status='SUCCESS';result=(ConvertTo-G4CanonicalJson $body)
        })}
        $alerts.Add($alert);$sources.Add((New-TestSource $alert));$executions.Add($execution);$results[$id]=$result
    }
    return [pscustomobject]@{TakeId=$TakeId;Sources=@($sources);Alerts=@($alerts);Executions=@($executions);Results=$results;ResultDelay=0}
}

function New-TestOperations {
    param([hashtable]$Plans)
    $state=@{
        Now=[datetimeoffset]'2026-08-18T00:00:00Z';Current='';Triggered=$false;RequestCount=0
        Writes=[Collections.Generic.List[object]]::new();Manifest=$null;ResultCalls=@{}
    }
    $baseline=[pscustomobject]@{execution_id='99999999-9999-4999-8999-999999999999';status='FINISHED'}
    $ops=@{
        Now={ $state.Now }
        Sleep={ param($seconds) $state.Now=$state.Now.AddSeconds([int]$seconds) }
        NewTakeId={ param($phase) $state.Current=$phase;$state.Triggered=$false;[string]$Plans[$phase].TakeId }
        InvokeEvent={ param($takeId) $state.Triggered=$true;$state.RequestCount++ }
        GetSourceEvents={ param($takeId) if ($state.Triggered) {@($Plans[$state.Current].Sources)} else {@()} }
        GetAlerts={ param($takeId) if ($state.Triggered) {@($Plans[$state.Current].Alerts)} else {@()} }
        GetExecutions={ if ($state.Triggered) {@($baseline)+@($Plans[$state.Current].Executions)} else {@($baseline)} }
        GetExecutionResult={ param($execution)
            $id=[string]$execution.execution_id;$key=$state.Current+'/'+$id
            if (-not $state.ResultCalls.ContainsKey($key)) {$state.ResultCalls[$key]=0};$state.ResultCalls[$key]++
            if ($state.ResultCalls[$key] -le [int]$Plans[$state.Current].ResultDelay) {
                return [pscustomobject]@{execution_id=$id;execution_argument=$execution.execution_argument;results=@()}
            }
            $Plans[$state.Current].Results[$id]
        }
        WritePhase={ param($phase,$value) $state.Writes.Add([pscustomobject]@{Phase=$phase;Value=$value}) }
        WriteManifest={ param($value) $state.Manifest=$value }
    }
    foreach ($key in @($ops.Keys)) { $ops[$key]=$ops[$key].GetNewClosure() }
    return [pscustomobject]@{Operations=$ops;State=$state}
}

function New-AllPlans {
    param([int[]]$Counts=@(1,2,4,1))
    $names=@('PILOT','TAKE-1','TAKE-2','TAKE-3');$plans=@{}
    for ($i=0;$i -lt $names.Count;$i++) {
        $take='capital-one-20260818T00000'+$i+'Z-'+(('a'+$i)*8).Substring(0,8)
        $plans[$names[$i]]=New-TestPlan -TakeId $take -Count $Counts[$i]
    }
    return $plans
}

$workflow=New-TestWorkflow
$contract=Assert-G4Workflow -Workflow $workflow -WorkflowId $workflow.id -WebhookId $workflow.triggers[0].id
Assert-True ($contract.ActionLabel -ceq 'Change Me') 'Configured repeat Action label was not preserved.'
$workflow.actions+=@([pscustomobject]@{id='44444444-4444-4444-8444-444444444444';label='unexpected';app_name='HTTP';name='request';parameters=@()})
Assert-G4Throws -Category side_effect -Action {
    Assert-G4Workflow -Workflow $workflow -WorkflowId $workflow.id -WebhookId $workflow.triggers[0].id
}

# Dynamic N is discovered independently in every phase; PILOT is not part of the TAKE aggregate.
$plans=New-AllPlans
$harness=New-TestOperations $plans
$result=Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
    -SourceTimeoutSeconds 10 -DetectionTimeoutSeconds 10 -ShuffleTimeoutSeconds 10 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
$expectedTakeTotal=@('TAKE-1','TAKE-2','TAKE-3')|ForEach-Object{$plans[$_].Sources.Count}|Measure-Object -Sum
Assert-True ($result.runtime_source_event_count -eq $expectedTakeTotal.Sum) 'TAKE source aggregate was hardcoded or included PILOT.'
Assert-True ($result.rule_100103_alert_count -eq $expectedTakeTotal.Sum) 'Dynamic alert cardinality did not match runtime N.'
Assert-True ($result.shuffle_execution_count -eq $expectedTakeTotal.Sum) 'Dynamic execution cardinality did not match runtime N.'
Assert-True ($harness.State.RequestCount -eq 4) 'Each phase must invoke its event source exactly once.'
Assert-True ($result.pilot_excluded_from_take_verdict -and $result.take_completed_count -eq 3) 'PILOT leaked into the TAKE verdict.'
Assert-True (@($harness.State.Writes|Where-Object{$_.Value.status -ceq 'PASS'}).Count -eq 4) 'Per-phase immutable evidence was not written.'

# FINISHED may precede Action-result readiness; bounded result polling must not re-fire the event source.
$plans=New-AllPlans -Counts @(1,1,1,1);$plans.PILOT.ResultDelay=2;$harness=New-TestOperations $plans
$result=Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
    -SourceTimeoutSeconds 10 -DetectionTimeoutSeconds 10 -ShuffleTimeoutSeconds 10 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
$pilotExecutionId=[string]$plans.PILOT.Executions[0].execution_id
Assert-True ($harness.State.ResultCalls['PILOT/'+$pilotExecutionId] -eq 3) 'Result readiness did not use bounded polling.'
Assert-True ($harness.State.RequestCount -eq 4) 'Result readiness polling re-fired an event-source request.'

# Stop immediately at first failed TAKE and never invoke later phases.
$plans=New-AllPlans -Counts @(1,2,1,1)
$plans['TAKE-1'].Alerts=@($plans['TAKE-1'].Alerts|Select-Object -First 1)
$harness=New-TestOperations $plans
Assert-G4Throws -Category alert_missing -Action {
    Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
        -SourceTimeoutSeconds 5 -DetectionTimeoutSeconds 3 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
}
Assert-True ($harness.State.RequestCount -eq 2) 'A phase ran after the first failure.'
Assert-True ($harness.State.Manifest.status -ceq 'FAIL' -and $harness.State.Manifest.failed_phase -ceq 'TAKE-1') 'Safe failure manifest is incomplete.'

# Duplicate source event IDs are rejected before correlation.
$take='capital-one-20260818T001000Z-deadbeef';$plan=New-TestPlan $take 1
Assert-G4Throws -Category source_duplicate -Action {
    Get-G4ValidatedSourceEvents -Events @($plan.Sources[0],$plan.Sources[0]) -TakeId $take
}

$repeatResult=$plan.Results[$plan.Executions[0].execution_id]
$repeatResult.results=@($repeatResult.results[0],$repeatResult.results[0])
Assert-G4Throws -Category repeat_duplicate -Action {
    Get-G4RepeatObservation -Result $repeatResult -WorkflowContract (New-TestWorkflowContract)
}

# Duplicate execution IDs are rejected, and an execution for another rule is never accepted.
$plans=New-AllPlans -Counts @(1,1,1,1)
$plans.PILOT.Executions=@($plans.PILOT.Executions[0],$plans.PILOT.Executions[0])
$harness=New-TestOperations $plans
Assert-G4Throws -Category execution_duplicate -Action {
    Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
        -SourceTimeoutSeconds 5 -DetectionTimeoutSeconds 5 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
}

$plans=New-AllPlans -Counts @(1,1,1,1)
$wrong=$plans.PILOT.Executions[0].execution_argument|ConvertFrom-Json -Depth 100
$wrong.rule.id='100102';$plans.PILOT.Executions[0].execution_argument=ConvertTo-G4CanonicalJson $wrong
$harness=New-TestOperations $plans
Assert-G4Throws -Category other_rule -Action {
    Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
        -SourceTimeoutSeconds 5 -DetectionTimeoutSeconds 5 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
}

# Missing mapping and repeat mismatch remain hard failures.
$plans=New-AllPlans -Counts @(1,1,1,1)
$plans.PILOT.Sources=@()
$harness=New-TestOperations $plans
Assert-G4Throws -Category source_missing -Action {
    Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
        -SourceTimeoutSeconds 3 -DetectionTimeoutSeconds 5 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
}

$plans=New-AllPlans -Counts @(1,1,1,1)
$entry=$plans.PILOT.Results[$plans.PILOT.Executions[0].execution_id].results[0]
$repeat=$entry.result|ConvertFrom-Json -Depth 100;$repeat.incident.result='failed';$entry.result=ConvertTo-G4CanonicalJson $repeat
$harness=New-TestOperations $plans
Assert-G4Throws -Category payload_mismatch -Action {
    Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
        -SourceTimeoutSeconds 5 -DetectionTimeoutSeconds 5 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
}

# Evidence contains only approved projections, never injected runtime secrets or payload copies.
$plans=New-AllPlans -Counts @(1,1,1,1);$harness=New-TestOperations $plans
$harness.State.RuntimeSecret='SENSITIVE-MARKER-X-SOC-Webhook-Key'
$result=Invoke-SocRule100103DynamicCore -Operations $harness.Operations -WorkflowContract (New-TestWorkflowContract) `
    -SourceTimeoutSeconds 5 -DetectionTimeoutSeconds 5 -ShuffleTimeoutSeconds 5 -PollSeconds 1 -StabilityPolls 1 -MaxClockSkewSeconds 60
$evidence=@($harness.State.Writes.Value)+@($harness.State.Manifest)|ConvertTo-Json -Depth 100
Assert-True ($evidence -notmatch 'SENSITIVE-MARKER|X-SOC-Webhook-Key|execution_argument|repeat_result|request_payload') 'Evidence persisted a secret or raw payload field.'

# Static command inspection: no direct integration/replay/logtest or response-capable subsystem invocation.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-True (@($errors).Count -eq 0) ('G4 parser errors: '+(@($errors|ForEach-Object{$_.Message})-join '; '))
$commandNames=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()}|Where-Object{$_})
$forbidden=@(
    'custom-shuffle-soc','wazuh-logtest','Invoke-CapitalOneBaseline.ps1','Test-SocRule100103Rehearsal.ps1',
    'Register-ShuffleSocTake','Remove-ShuffleSocTake','New-ShuffleSocAllowRecord','Get-ShuffleSocOutcome',
    'gh','kubectl','argocd','terraform apply','terraform destroy'
)
foreach ($name in $forbidden) { Assert-True ($name -notin $commandNames) "Forbidden G4 invocation found: $name" }
$text=Get-Content -LiteralPath $path -Raw
Assert-True ($text -notmatch '(?i)source_event_count\s*=\s*[26]|alert_count\s*=\s*[26]|execution_count\s*=\s*[26]') 'Runtime event cardinality is hardcoded.'
Assert-True ($text -notmatch '(?i)terraform\s+(apply|destroy)|gh\s+workflow\s+run|wazuh-logtest|custom-shuffle-soc') 'A forbidden replay, mutation, or direct integration path is present.'
$eventSource=[regex]::Match($text,'(?s)InvokeEvent=\{.*?GetSourceEvents=\{').Value
Assert-True ($eventSource -match 'X-SOC-TAKE-ID' -and $eventSource -match '/vulnerabilities/exec/' -and
    $eventSource -match '169\.254\.169\.254/latest/meta-data/iam/security-credentials/' -and
    ([regex]::Matches($eventSource,'Invoke-WebRequest').Count -eq 1)) 'The one-request verified DVWA event-source path changed.'

Write-Host 'SOC Rule 100103 dynamic OBSERVE_ONLY G4 tests passed.'
