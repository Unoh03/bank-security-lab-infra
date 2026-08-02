[CmdletBinding()]
param(
  [string]$SshHost = "bas",
  [int]$LocalPort = 8080,
  [int]$RemotePort = 18080
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
  throw "OpenSSH client 'ssh' was not found in PATH."
}

$existingListener = Get-NetTCPConnection `
  -State Listen `
  -LocalPort $LocalPort `
  -ErrorAction SilentlyContinue
if ($existingListener) {
  throw "Local port $LocalPort is already in use. Stop that process or choose -LocalPort <other-port>."
}

$passwordCommand = "kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
$password = (& ssh $SshHost $passwordCommand)
if ($LASTEXITCODE -ne 0) {
  throw "Failed to retrieve the Argo CD initial admin password through '$SshHost'."
}

$password = ($password -join "`n").Trim()
if ([string]::IsNullOrWhiteSpace($password)) {
  throw "The Argo CD initial admin password was empty."
}

Set-Clipboard -Value $password
$password = $null

$forward = "${LocalPort}:127.0.0.1:${RemotePort}"
$remoteCommand = "kubectl -n argocd port-forward --address 127.0.0.1 service/argocd-server ${RemotePort}:443"

Write-Host "Argo CD username: admin"
Write-Host "The password was copied to the clipboard and was not printed."
Write-Host "Open https://localhost:$LocalPort manually."
Write-Host "Keep this window open. Press Ctrl+C here to stop both port forwards."
Write-Host "If the remote port is busy, rerun with -RemotePort <other-port>."

& ssh `
  -o ExitOnForwardFailure=yes `
  -L $forward `
  $SshHost `
  $remoteCommand
