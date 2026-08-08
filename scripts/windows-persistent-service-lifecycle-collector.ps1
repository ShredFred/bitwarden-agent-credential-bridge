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
$serviceSid = 'S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607'
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
    # When the service object is already absent, still allow digest-bound cleanup
    # of this run's binary/root. When present, PathName must match (quotes stripped).
    if ($null -ne $pathName -and -not $pathName.Equals($binaryPath, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) { return $false }
    return ((Get-Sha256File $binaryPath) -ceq $ExpectedBinarySha256)
}

function Set-BinaryTrustedAcl([string]$Path) {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    # Owner stays the elevated creator (Administrators) — trusted for Phase 9b.
    $idents = @(
        $system,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')),
        (New-Object System.Security.Principal.SecurityIdentifier($serviceSid)),
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19'))
    )
    foreach ($id in $idents) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    # Authenticated Users may read/execute for handle-bound digest probes; no write.
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')),
        'ReadAndExecute', 'Allow')))
    [IO.File]::SetAccessControl($Path, $acl)
}

function Set-DirectoryTrustedAcl([string]$Path) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    # Owner stays the elevated creator (Administrators) — trusted for Phase 9b.
    $full = @(
        $system,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))
    )
    foreach ($id in $full) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19')),
        'ReadAndExecute',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($serviceSid)),
        'Modify,Synchronize',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    # Authenticated Users read/traverse for Phase 9b/9c probes; write remains denied.
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')),
        'ReadAndExecute',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    [IO.Directory]::SetAccessControl($Path, $acl)
}

function Grant-ServiceProcessQueryAccess {
    param([Parameter(Mandatory = $true)][uint32]$ProcessId)
    if ($ProcessId -eq 0) { return $false }
    if (-not ('BridgeServiceProcessQueryDacl' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class BridgeServiceProcessQueryDacl {
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint READ_CONTROL = 0x20000;
    const uint WRITE_DAC = 0x40000;
    const uint SddlRevision1 = 1;
    const int SeKernelObject = 6;
    const uint DaclSecurityInformation = 0x00000004;
    const uint ProtectedDaclSecurityInformation = 0x80000000;
    const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    // Keep SYSTEM/Administrators/LocalService/service-SID strong rights; allow
    // Authenticated Users QUERY_LIMITED so non-elevated Phase 9b/9c can bind tokens.
    const string ProcessSddl =
        "D:P(A;;0x1FFFFF;;;SY)(A;;0x1FFFFF;;;BA)(A;;0x1FFFFF;;;LS)(A;;0x1FFFFF;;;" + ServiceSid +
        ")(A;;0x00001400;;;AU)";

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr sd, out uint size);
    [DllImport("advapi32.dll")]
    static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll")]
    static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);

    public static bool TryGrant(uint pid) {
        IntPtr process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL | WRITE_DAC, false, pid);
        if (process == IntPtr.Zero) return false;
        IntPtr sd = IntPtr.Zero;
        try {
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(ProcessSddl, SddlRevision1, out sd, out size))
                return false;
            bool present; IntPtr dacl; bool defaulted;
            if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero)
                return false;
            return SetSecurityInfo(process, SeKernelObject,
                DaclSecurityInformation | ProtectedDaclSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) == 0;
        } finally {
            if (sd != IntPtr.Zero) LocalFree(sd);
            CloseHandle(process);
        }
    }
}
'@
    }
    return [BridgeServiceProcessQueryDacl]::TryGrant($ProcessId)
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
        Set-DirectoryTrustedAcl $persistentRoot
        Set-BinaryTrustedAcl $binaryPath
        # Probe contracts (Phase 9b / 5h.9) require a quoted ImagePath. Escape
        # quotes for CreateProcess so sc.exe receives literal "path" and stores them.
        $quotedBinaryPath = '\"{0}\"' -f $binaryPath
        $create = Invoke-Sc @('create', $serviceName, 'binPath=', $quotedBinaryPath, 'start=', 'demand', 'obj=', $serviceAccount)
        if ($create -ne 0) { throw 'create_failed' }
        $null = Invoke-Sc @('sidtype', $serviceName, 'unrestricted')
        # SYSTEM/Administrators full; LocalService start/query; Authenticated Users query only.
        $serviceSddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;LCRPLORC;;;AU)'
        if ((Invoke-Sc @('sdset', $serviceName, $serviceSddl)) -ne 0) { throw 'service_acl_lock_failed' }
        $start = Invoke-Sc @('start', $serviceName)
        $present = $null -ne (Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue)
        $bound = Test-BoundIdentity
        # Best-effort elevated grant; ServiceMain also self-grants AU QUERY_LIMITED.
        if ($start -eq 0 -and $present) {
            $svcPid = [uint32](Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
            $null = Grant-ServiceProcessQueryAccess -ProcessId $svcPid
        }
        Write-Result ([ordered]@{
            schema_version = 1; operation = 'install'
            verified = ($start -eq 0 -and $present -and $bound)
            service_present = $present
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
        # The service binary can remain mapped briefly after delete; retry removals.
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            Start-Sleep -Milliseconds 500
            try {
                if (Test-Path -LiteralPath $binaryPath) {
                    Remove-Item -LiteralPath $binaryPath -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $persistentRoot) {
                    Remove-Item -LiteralPath $persistentRoot -Recurse -Force -ErrorAction Stop
                }
            } catch { }
            if (-not (Test-Path -LiteralPath $binaryPath) -and -not (Test-Path -LiteralPath $persistentRoot)) {
                break
            }
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
