param(
    [Parameter(Mandatory = $true)][string]$MachineId,
    [Parameter(Mandatory = $true)][string]$Purpose
)

$ErrorActionPreference = 'Stop'
$basename = 'bitwarden-agent-sm-machine.credential.xml'
$dir = Join-Path $env:USERPROFILE '.codex\secrets'
$storePath = Join-Path $dir $basename

# Read exactly one token line from stdin. Never echo it.
$token = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($token)) {
    [Console]::Error.Write('token_absent')
    exit 11
}
$token = $token.Trim()
if ($token.Length -lt 16 -or $token.Length -gt 8192) {
    [Console]::Error.Write('invalid_token')
    exit 12
}

New-Item -ItemType Directory -Force -Path $dir | Out-Null

$secure = ConvertTo-SecureString -String $token -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($MachineId, $secure)
$obj = [pscustomobject]@{
    Purpose                 = $Purpose
    SecretsManagerAllowed   = $true
    PersonalVaultAllowed    = $false
    Credential              = $cred
}
$obj | Export-Clixml -LiteralPath $storePath

# Clear plaintext reference best-effort.
$token = $null
[GC]::Collect()
exit 0
