param(
    [Parameter(Mandatory = $true)][ValidateSet('password')][string]$Field,
    [Parameter(Mandatory = $true)][string]$ExpectedPurposeSha256
)

$ErrorActionPreference = 'Stop'
$basename = 'mivia-bitwarden-agent-manager-dev.credential.xml'
$storePath = Join-Path $env:USERPROFILE (Join-Path '.codex\secrets' $basename)

function Get-Sha256Hex([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $storePath)) {
    [Console]::Error.Write('store_absent')
    exit 11
}

try {
    $obj = Import-Clixml -LiteralPath $storePath
}
catch {
    [Console]::Error.Write('store_unreadable')
    exit 12
}

if ($null -eq $obj -or $null -eq $obj.Credential) {
    [Console]::Error.Write('store_malformed')
    exit 13
}

if ([bool]$obj.PersonalVaultAllowed) {
    [Console]::Error.Write('personal_vault_forbidden')
    exit 14
}
if ([bool]$obj.CompanyVaultAllowed) {
    [Console]::Error.Write('company_vault_forbidden')
    exit 15
}

$purpose = [string]$obj.Purpose
if ([string]::IsNullOrEmpty($purpose) -or (Get-Sha256Hex $purpose) -cne $ExpectedPurposeSha256.ToLowerInvariant()) {
    [Console]::Error.Write('purpose_mismatch')
    exit 16
}

$network = $obj.Credential.GetNetworkCredential()
if ($null -eq $network -or [string]::IsNullOrEmpty($network.Password)) {
    [Console]::Error.Write('password_absent')
    exit 17
}

if ($Field -ne 'password') {
    [Console]::Error.Write('unsupported_field')
    exit 18
}

# Emit only the password bytes to stdout. Callers must never log stdout.
[Console]::Out.Write($network.Password)
exit 0
