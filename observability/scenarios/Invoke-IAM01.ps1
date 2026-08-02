#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('allowed', 'denied')]
    [string]$ExpectedResult = 'allowed',
    [Parameter(Mandatory)]
    [string]$AwsCliImage,
    [string]$TerraformRoot = '',
    [string]$AwsProfile = 'terra-user',
    [string]$ExpectedAccountId = '433048100798',
    [string]$Region = 'ap-northeast-2',
    [string]$SshHost = 'bas',
    [string]$EvidenceRoot = '',
    [string]$ExperimentId = '',
    [string]$ConfirmRun = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TerraformRoot) {
    $TerraformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $HOME 'Documents\aws-topology-evidence'
}
if (-not $ExperimentId) {
    $ExperimentId = 'iam01-' + $ExpectedResult + '-' +
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}
if ($ExperimentId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$') {
    throw 'ExperimentId contains unsafe path characters.'
}
if ($AwsCliImage -notmatch '^[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$') {
    throw 'AwsCliImage must use an immutable sha256 image digest.'
}

function Invoke-ScenarioNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "$FailureMessage`n$(($output | Out-String).Trim())"
    }
    return ($output | Out-String).Trim()
}

function Write-ScenarioJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 12),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

$identity = Invoke-ScenarioNative -FilePath 'aws' -ArgumentList @(
    'sts', 'get-caller-identity',
    '--profile', $AwsProfile,
    '--region', $Region,
    '--output', 'json'
) -FailureMessage 'AWS identity could not be verified.' | ConvertFrom-Json
if ([string]$identity.Account -cne $ExpectedAccountId) {
    throw "AWS account mismatch: expected=$ExpectedAccountId actual=$($identity.Account)"
}

$bucket = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'primary_application_bucket_name'
) -FailureMessage 'The primary application bucket output is unavailable.'
$podIdentityEnabled = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$TerraformRoot", 'output', '-raw', 'web_s3_pod_identity_enabled'
) -FailureMessage 'The web S3 Pod Identity state output is unavailable.'
$dataEventsEnabled = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
    "-chdir=$(Join-Path $TerraformRoot 'foundation')",
    'output', '-raw', 'project_s3_data_events_enabled'
) -FailureMessage 'The Foundation S3 Data Event output is unavailable.'

if ($bucket -notmatch '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$') {
    throw "Unsafe application bucket output: $bucket"
}
if ($dataEventsEnabled.Trim().ToLowerInvariant() -cne 'true') {
    throw 'IAM-01 requires approved Foundation S3 Data Events before it may run.'
}
$expectedEnabled = $ExpectedResult -eq 'allowed'
if ([System.Convert]::ToBoolean($podIdentityEnabled.Trim()) -ne $expectedEnabled) {
    throw "IAM-01 result/state mismatch: expected=$ExpectedResult podIdentityEnabled=$podIdentityEnabled"
}
$expectedRoleArn = ''
if ($expectedEnabled) {
    $expectedRoleArn = Invoke-ScenarioNative -FilePath 'terraform' -ArgumentList @(
        "-chdir=$TerraformRoot", 'output', '-raw', 'primary_web_s3_role_arn'
    ) -FailureMessage 'The primary Pod Identity role output is unavailable.'
    if ($expectedRoleArn -notmatch '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$') {
        throw 'Unsafe Pod Identity role ARN output.'
    }
}

$namespace = 'dvwa'
$serviceAccount = 'web-app'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$podName = "iam01-canary-$suffix"
$objectKey = "web/experiment-$ExperimentId/canary.txt"
$expectedRoleName = if ($expectedRoleArn) {
    ($expectedRoleArn -split '/')[-1]
} else {
    'association-disabled'
}

Write-Host "IAM-01 cluster path: ssh=$SshHost namespace=$namespace serviceAccount=$serviceAccount"
Write-Host "AWS account/region: $($identity.Account)/$Region"
Write-Host "S3 scope: s3://$bucket/$objectKey"
Write-Host "Expected result: $ExpectedResult"
Write-Host 'Cleanup: canary object, Pod, and script-created ServiceAccount are removed by a bounded trap.'
if ($ConfirmRun -cne 'RUN IAM-01') {
    throw "Preview only. Re-run with -ConfirmRun 'RUN IAM-01' after explicit approval."
}

$remoteTemplate = @'
set -euo pipefail
namespace='__NAMESPACE__'
service_account='__SERVICE_ACCOUNT__'
pod_name='__POD_NAME__'
image='__IMAGE__'
bucket='__BUCKET__'
object_key='__OBJECT_KEY__'
region='__REGION__'
expected_result='__EXPECTED_RESULT__'
expected_role_name='__EXPECTED_ROLE_NAME__'
created_service_account=0
object_created=0
manifest="/tmp/${pod_name}.yaml"
payload="/tmp/${pod_name}-payload.txt"

cleanup() {
  set +e
  if [ "$object_created" -eq 1 ]; then
    kubectl exec -n "$namespace" "$pod_name" -- aws s3api delete-object \
      --bucket "$bucket" --key "$object_key" --region "$region" >/dev/null 2>&1
  fi
  kubectl delete pod -n "$namespace" "$pod_name" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ "$created_service_account" -eq 1 ]; then
    kubectl delete serviceaccount -n "$namespace" "$service_account" --ignore-not-found >/dev/null 2>&1
  fi
  rm -f "$manifest"
}
trap cleanup EXIT

kubectl get namespace "$namespace" >/dev/null
if ! kubectl get serviceaccount -n "$namespace" "$service_account" >/dev/null 2>&1; then
  kubectl create serviceaccount -n "$namespace" "$service_account" >/dev/null
  created_service_account=1
fi

cat >"$manifest" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: iam01-canary
spec:
  serviceAccountName: ${service_account}
  restartPolicy: Never
  automountServiceAccountToken: true
  containers:
    - name: aws-cli
      image: ${image}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "sleep 900"]
      resources:
        requests:
          cpu: 25m
          memory: 64Mi
        limits:
          cpu: 100m
          memory: 128Mi
YAML

kubectl apply -f "$manifest" >/dev/null
kubectl wait -n "$namespace" --for=condition=Ready "pod/$pod_name" --timeout=180s >/dev/null

sts_status='unavailable'
role_arn=''
if role_arn=$(kubectl exec -n "$namespace" "$pod_name" -- \
    aws sts get-caller-identity --query Arn --output text 2>/dev/null); then
  sts_status='succeeded'
fi

kubectl exec -n "$namespace" "$pod_name" -- /bin/sh -c \
  "printf 'iam01-canary\n' > '$payload'"

put_status='technical-error'
put_output=''
set +e
put_output=$(kubectl exec -n "$namespace" "$pod_name" -- \
  aws s3api put-object --bucket "$bucket" --key "$object_key" \
  --body "$payload" --region "$region" 2>&1)
put_exit=$?
set -e
if [ "$put_exit" -eq 0 ]; then
  put_status='allowed'
  object_created=1
else
  case "$put_output" in
    *AccessDenied*|*Forbidden*)
      put_status='denied'
      ;;
    *"Unable to locate credentials"*|*NoCredentialProviders*)
      put_status='no-credentials'
      ;;
  esac
fi

if [ "$expected_result" = 'allowed' ]; then
  case "$role_arn" in
    *":assumed-role/${expected_role_name}/"*) ;;
    *) echo "Unexpected caller role: $role_arn" >&2; exit 31 ;;
  esac
  if [ "$put_status" != 'allowed' ]; then
    printf 'Expected S3 PutObject to succeed; client result was: %s\n' "$put_output" >&2
    exit 32
  fi
  kubectl exec -n "$namespace" "$pod_name" -- \
    aws s3api get-object --bucket "$bucket" --key "$object_key" \
    --region "$region" /tmp/roundtrip.txt >/dev/null
else
  case "$put_status" in
    denied|no-credentials) ;;
    *)
      printf 'Expected an authorization denial; client result was: %s\n' "$put_output" >&2
      exit 33
      ;;
  esac
fi

printf '__IAM01_RESULT__|%s|%s|%s|%s|%s\n' \
  "$expected_result" "$sts_status" "$role_arn" "$put_status" "$created_service_account"
'@

$replacements = [ordered]@{
    '__NAMESPACE__' = $namespace
    '__SERVICE_ACCOUNT__' = $serviceAccount
    '__POD_NAME__' = $podName
    '__IMAGE__' = $AwsCliImage
    '__BUCKET__' = $bucket
    '__OBJECT_KEY__' = $objectKey
    '__REGION__' = $Region
    '__EXPECTED_RESULT__' = $ExpectedResult
    '__EXPECTED_ROLE_NAME__' = $expectedRoleName
}
$remoteScript = $remoteTemplate
foreach ($entry in $replacements.GetEnumerator()) {
    $remoteScript = $remoteScript.Replace([string]$entry.Key, [string]$entry.Value)
}
$encodedScript = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remoteScript))

$startedAt = (Get-Date).ToUniversalTime()
$remoteOutput = Invoke-ScenarioNative -FilePath 'ssh' -ArgumentList @(
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    $SshHost,
    "printf '%s' '$encodedScript' | base64 --decode | bash"
) -FailureMessage 'IAM-01 remote canary failed.'
$finishedAt = (Get-Date).ToUniversalTime()

$resultLine = @($remoteOutput -split "`r?`n" | Where-Object {
    $_ -like '__IAM01_RESULT__|*'
}) | Select-Object -Last 1
if (-not $resultLine) {
    throw 'IAM-01 remote result marker was not returned.'
}
$parts = $resultLine -split '\|', 6
if ($parts.Count -ne 6) {
    throw 'IAM-01 remote result marker was malformed.'
}

$record = [ordered]@{
    SchemaVersion = 1
    ScenarioId = 'IAM-01'
    ExperimentId = $ExperimentId
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $finishedAt.ToString('o')
    AwsAccountId = [string]$identity.Account
    Region = $Region
    Namespace = $namespace
    ServiceAccount = $serviceAccount
    PodName = $podName
    Bucket = $bucket
    ObjectKey = $objectKey
    ExpectedRoleArn = $expectedRoleArn
    ExpectedResult = $parts[1]
    StsStatus = $parts[2]
    CallerArn = $parts[3]
    PutObjectResult = $parts[4]
    ServiceAccountCreatedByScript = ([int]$parts[5] -eq 1)
    CleanupExpected = $true
}
$recordPath = Join-Path $EvidenceRoot "$ExperimentId\source\client\iam-01.json"
Write-ScenarioJson -Path $recordPath -Value $record

Write-Host "IAM-01 client record: $recordPath"
Write-Host 'Collect the matching AWS evidence with:'
Write-Host ".\daily-down.ps1 -EvidenceOnly -RunEvidenceQueries -ExperimentId '$ExperimentId' -ScenarioId 'IAM-01' -EvidenceStartUtc '$($startedAt.ToString('o'))' -EvidenceEndUtc '$($finishedAt.ToString('o'))' -EvidenceEventTailSeconds 2 -EvidenceDeliveryGraceMinutes 5"
