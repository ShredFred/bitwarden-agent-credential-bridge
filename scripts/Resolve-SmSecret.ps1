<#
.SYNOPSIS
  Resolve one Bitwarden Secrets Manager secret for HQ scripts (Windows).

.DESCRIPTION
  Invokes the bridge resolve-sm-secret.mjs entrypoint. Returns the plaintext
  value to the pipeline only. Never Write-Host / log the value.
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('mivia', 'private-hq')]
  [string]$Project,

  [Parameter(Mandatory = $true)]
  [string]$Key,

  [string]$BridgeRoot = $env:BITWARDEN_AGENT_BRIDGE_ROOT
)

$ErrorActionPreference = 'Stop'

function Resolve-BridgeRoot {
  param([string]$Hint)
  if (-not [string]::IsNullOrWhiteSpace($Hint) -and (Test-Path -LiteralPath (Join-Path $Hint 'scripts\resolve-sm-secret.mjs'))) {
    return $Hint
  }
  $here = $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $here 'resolve-sm-secret.mjs')) {
    return (Split-Path -Parent $here)
  }
  $candidates = @(
    'F:\Github Repos\bitwarden-agent-credential-bridge',
    (Join-Path $env:USERPROFILE 'Github Repos\bitwarden-agent-credential-bridge')
  )
  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath (Join-Path $c 'scripts\resolve-sm-secret.mjs')) { return $c }
  }
  throw 'bridge_root_absent'
}

$BridgeRoot = Resolve-BridgeRoot -Hint $BridgeRoot
$resolver = Join-Path $BridgeRoot 'scripts\resolve-sm-secret.mjs'
$node = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $node) { throw 'node_absent' }

$bwsDir = Join-Path $env:LOCALAPPDATA 'Programs\Bitwarden'
$env:Path = "$bwsDir;" + $env:Path

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $node.Source
$psi.Arguments = "`"$resolver`" --i-approve-secrets-manager-machine-resolve --project $Project --key $Key"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$proc = [Diagnostics.Process]::Start($psi)
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
if ($proc.ExitCode -ne 0) {
  $err = if ([string]::IsNullOrWhiteSpace($stderr)) { 'resolve_failed' } else { $stderr.Trim() }
  throw $err
}
if ([string]::IsNullOrEmpty($stdout)) { throw 'value_empty' }
return $stdout
