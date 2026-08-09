param(
    [Parameter(Mandatory = $true)][ValidateSet('password', 'username')][string]$Field,
    [Parameter(Mandatory = $true)][string]$ExpectedPurposeSha256
)

$ErrorActionPreference = 'Stop'
$basename = 'bitwarden-agent-personal.credential.xml'
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

# Personal path requires the personal flag and forbids company.
if (-not [bool]$obj.PersonalVaultAllowed) {
    [Console]::Error.Write('personal_vault_required')
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
if ($null -eq $network) {
    [Console]::Error.Write('credential_absent')
    exit 17
}

if ($Field -eq 'password') {
    if ([string]::IsNullOrEmpty($network.Password)) {
        [Console]::Error.Write('password_absent')
        exit 17
    }
    [Console]::Out.Write($network.Password)
    exit 0
}

if ($Field -eq 'username') {
    if ([string]::IsNullOrEmpty($network.UserName)) {
        [Console]::Error.Write('username_absent')
        exit 19
    }
    [Console]::Out.Write($network.UserName)
    exit 0
}

[Console]::Error.Write('unsupported_field')
exit 18
