param(
    [Parameter(Mandatory = $true)][string]$StagingRoot,
    [Parameter(Mandatory = $true)][ValidateSet('install','uninstall')][string]$Operation,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true)][ValidateRange(1, 67108864)][long]$ExpectedBinaryByteLength,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$MarkerNonce
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BitwardenAgentCredentialBridgeHelper'
$serviceAccount = 'NT AUTHORITY\LocalService'
$persistentRoot = Join-Path $env:ProgramData 'BitwardenAgentCredentialBridge'
$binaryPath = Join-Path $persistentRoot 'BitwardenAgentCredentialBridgeHelper.exe'
$resultPath = Join-Path $StagingRoot 'result.json'

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-Sha256File([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

function Invoke-Sc([string[]]$ScArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\sc.exe'
    $psi.Arguments = ($ScArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f ($_ -replace '"', '\"') } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $null = $p.StandardOutput.ReadToEnd()
    $null = $p.StandardError.ReadToEnd()
    $p.WaitForExit(60000) | Out-Null
    return $p.ExitCode
}

function Write-Result($Object) {
    [IO.File]::WriteAllText($resultPath, (($Object | ConvertTo-Json -Compress) + "`n"), [Text.UTF8Encoding]::new($false))
}

function Get-ServicePathName([string]$Name) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $null }
    $pathName = [string]$svc.PathName
    if ($pathName.StartsWith('"') -and $pathName.EndsWith('"')) {
        $pathName = $pathName.Substring(1, $pathName.Length - 2)
    }
    return $pathName
}

function Test-BoundIdentity {
    $pathName = Get-ServicePathName $serviceName
    if ($null -eq $pathName) { return $false }
    if ($pathName -cne $binaryPath) { return $false }
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) { return $false }
    return ((Get-Sha256File $binaryPath) -ceq $ExpectedBinarySha256)
}

if (-not (Test-IsElevated)) { throw 'not_elevated' }

$paramsPath = Join-Path $StagingRoot 'params.json'
if (-not (Test-Path -LiteralPath $paramsPath -PathType Leaf)) { throw 'params_missing' }
$params = Get-Content -LiteralPath $paramsPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$params.marker_nonce -cne $MarkerNonce) { throw 'params_marker_mismatch' }
if ([string]$params.expected_sha256 -cne $ExpectedBinarySha256) { throw 'params_digest_mismatch' }
if ([int64]$params.expected_byte_length -ne $ExpectedBinaryByteLength) { throw 'params_length_mismatch' }

$markerPath = Join-Path $StagingRoot 'marker'
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'marker_missing' }
$markerText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($markerPath))
if ($markerText -cne $MarkerNonce) { throw 'marker_mismatch' }

try {
    if ($Operation -eq 'install') {
        if ((Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue)) {
            Write-Result ([ordered]@{
                schema_version = 1; operation = 'install'; verified = $false
                service_present = $true; absence_proven = $false; collision_detected = $true
            })
            exit 0
        }
        if ((Test-Path -LiteralPath $binaryPath) -or (Test-Path -LiteralPath $persistentRoot)) {
            Write-Result ([ordered]@{
                schema_version = 1; operation = 'install'; verified = $false
                service_present = $false; absence_proven = $false; collision_detected = $true
            })
            exit 0
        }

        $payloadPath = Join-Path $StagingRoot 'payload.exe'
        if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) { throw 'payload_missing' }
        $bytes = [IO.File]::ReadAllBytes($payloadPath)
        if ($bytes.LongLength -ne $ExpectedBinaryByteLength) { throw 'length_mismatch' }
        $digest = Get-Sha256Hex $bytes
        if ($digest -cne $ExpectedBinarySha256) { throw 'digest_mismatch' }

        New-Item -ItemType Directory -Path $persistentRoot | Out-Null
        [IO.File]::WriteAllBytes($binaryPath, $bytes)
        $create = Invoke-Sc @('create', $serviceName, 'binPath=', $binaryPath, 'start=', 'demand', 'obj=', $serviceAccount)
        if ($create -ne 0) { throw 'create_failed' }
        $null = Invoke-Sc @('sidtype', $serviceName, 'unrestricted')
        $start = Invoke-Sc @('start', $serviceName)
        $present = $null -ne (Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue)
        $bound = Test-BoundIdentity
        Write-Result ([ordered]@{
            schema_version = 1; operation = 'install'
            verified = ($start -eq 0 -and $present -and $bound); service_present = $present
            absence_proven = $false; collision_detected = $false
        })
    }
    else {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        $binaryExists = Test-Path -LiteralPath $binaryPath -PathType Leaf
        $rootExists = Test-Path -LiteralPath $persistentRoot

        if ($null -eq $svc -and -not $binaryExists -and -not $rootExists) {
            Write-Result ([ordered]@{
                schema_version = 1; operation = 'uninstall'; verified = $true
                service_present = $false; absence_proven = $true; collision_detected = $false
            })
            exit 0
        }

        if (-not (Test-BoundIdentity)) {
            # Refuse to delete a foreign/mismatched service or binary by fixed name alone.
            Write-Result ([ordered]@{
                schema_version = 1; operation = 'uninstall'; verified = $false
                service_present = ($null -ne $svc); absence_proven = $false; collision_detected = $true
            })
            exit 0
        }

        $null = Invoke-Sc @('stop', $serviceName)
        $null = Invoke-Sc @('delete', $serviceName)
        Start-Sleep -Seconds 1
        if (Test-Path -LiteralPath $binaryPath) { Remove-Item -LiteralPath $binaryPath -Force }
        if (Test-Path -LiteralPath $persistentRoot) {
            try { Remove-Item -LiteralPath $persistentRoot -Recurse -Force } catch { }
        }
        $present = $null -ne (Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue)
        $absent = -not $present -and -not (Test-Path -LiteralPath $binaryPath) -and -not (Test-Path -LiteralPath $persistentRoot)
        Write-Result ([ordered]@{
            schema_version = 1; operation = 'uninstall'
            verified = $absent; service_present = $present
            absence_proven = $absent; collision_detected = $false
        })
    }
}
catch {
    Write-Result ([ordered]@{
        schema_version = 1; operation = $Operation; verified = $false
        service_present = $false; absence_proven = $false; collision_detected = $false
    })
}
exit 0
