param(
    [Parameter(Mandatory = $true)][string]$StorePath,
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'api_key_password',
        'api_secret_password',
        'account_username',
        'account_password',
        'top_username',
        'top_password',
        'nested_username',
        'nested_password',
        'secure_string_file'
    )][string]$Extract,
    [string]$ExpectedPurpose = ''
)

$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Code, [int]$ExitCode) {
    [Console]::Error.Write($Code)
    exit $ExitCode
}

function Get-PlainFromSecureString([SecureString]$Secure) {
    if ($null -eq $Secure) { return $null }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-PlainFromCredential([pscredential]$Cred, [ValidateSet('username', 'password')][string]$Field) {
    if ($null -eq $Cred) { return $null }
    $network = $Cred.GetNetworkCredential()
    if ($null -eq $network) { return $null }
    if ($Field -eq 'username') { return $network.UserName }
    return $network.Password
}

if ([string]::IsNullOrWhiteSpace($StorePath)) {
    Write-Fail 'store_path_absent' 11
}

if (-not (Test-Path -LiteralPath $StorePath)) {
    Write-Fail 'store_absent' 12
}

$mode = $Extract

try {
    if ($mode -eq 'secure_string_file') {
        $encrypted = (Get-Content -LiteralPath $StorePath -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($encrypted)) {
            Write-Fail 'store_empty' 13
        }
        $secure = ConvertTo-SecureString -String $encrypted
        $value = Get-PlainFromSecureString $secure
    }
    else {
        $obj = Import-Clixml -LiteralPath $StorePath
        if ($null -eq $obj) {
            Write-Fail 'store_malformed' 13
        }

        if (-not [string]::IsNullOrWhiteSpace($ExpectedPurpose)) {
            $purpose = [string]$obj.Purpose
            if ([string]::IsNullOrEmpty($purpose) -or $purpose -cne $ExpectedPurpose) {
                Write-Fail 'purpose_mismatch' 16
            }
        }

        switch ($mode) {
            'api_key_password' {
                if ($null -eq $obj.ApiKey -or $obj.ApiKey -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.ApiKey 'password'
            }
            'api_secret_password' {
                if ($null -eq $obj.ApiSecret -or $obj.ApiSecret -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.ApiSecret 'password'
            }
            'account_username' {
                if ($null -eq $obj.Account -or $obj.Account -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.Account 'username'
            }
            'account_password' {
                if ($null -eq $obj.Account -or $obj.Account -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.Account 'password'
            }
            'top_username' {
                if ($obj.PSObject.Properties.Name -contains 'UserName') {
                    $value = [string]$obj.UserName
                }
                elseif ($obj -is [pscredential]) {
                    $value = Get-PlainFromCredential $obj 'username'
                }
                else {
                    Write-Fail 'field_absent' 17
                }
            }
            'top_password' {
                if ($obj.PSObject.Properties.Name -contains 'Password') {
                    if ($obj.Password -is [SecureString]) {
                        $value = Get-PlainFromSecureString $obj.Password
                    }
                    elseif ($obj.Password -is [string]) {
                        $value = [string]$obj.Password
                    }
                    else {
                        Write-Fail 'field_absent' 17
                    }
                }
                elseif ($obj -is [pscredential]) {
                    $value = Get-PlainFromCredential $obj 'password'
                }
                else {
                    Write-Fail 'field_absent' 17
                }
            }
            'nested_username' {
                if ($null -eq $obj.Credential -or $obj.Credential -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.Credential 'username'
            }
            'nested_password' {
                if ($null -eq $obj.Credential -or $obj.Credential -isnot [pscredential]) {
                    Write-Fail 'field_absent' 17
                }
                $value = Get-PlainFromCredential $obj.Credential 'password'
            }
            default {
                Write-Fail 'unsupported_extract' 18
            }
        }
    }
}
catch {
    Write-Fail 'store_unreadable' 14
}

if ([string]::IsNullOrEmpty($value)) {
    Write-Fail 'value_empty' 19
}

if ($value.Length -gt 4096) {
    Write-Fail 'value_too_long' 20
}

# Emit only the secret bytes. Callers must never log stdout.
[Console]::Out.Write($value)
exit 0
