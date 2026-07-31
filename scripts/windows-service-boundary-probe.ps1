param(
    [Parameter(Mandatory = $true, Position = 0)][string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true, Position = 1)][long]$ExpectedBinaryByteLength
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BitwardenAgentCredentialBridgeHelper'

function Write-AbsentResult {
    [ordered]@{
        schema_version = 1
        service_present = $false
        account_local_service = $false
        demand_start = $false
        win32_own_process = $false
        service_sid_unrestricted = $false
        caller_service_control_denied = $false
        binary_binding_verified = $false
        binary_chain_reparse_free = $false
        binary_owner_trusted = $false
        caller_binary_control_denied = $false
        snapshot_matches_plan = $false
        authorization_ready = $false
    } | ConvertTo-Json -Compress
}

try {
    if ($ExpectedBinarySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedBinaryByteLength -lt 1 -or $ExpectedBinaryByteLength -gt 67108864) {
        throw 'invalid input'
    }

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (-not (Test-Path -LiteralPath $registryPath -PathType Container)) {
        Write-AbsentResult
        exit 0
    }

    if (-not ('BridgeServiceAccessCheck' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class BridgeServiceAccessCheck {
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const int SecurityImpersonation = 2;
    const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint desired,
        ref GENERIC_MAPPING mapping, IntPtr privileges, ref uint privilegeLength,
        out uint granted, out bool allowed);

    public static bool HasAnyAccess(byte[] descriptor, uint[] rights, bool serviceObject) {
        IntPtr primary = IntPtr.Zero;
        IntPtr duplicate = IntPtr.Zero;
        try {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, out primary))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!DuplicateToken(primary, SecurityImpersonation, out duplicate))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            GENERIC_MAPPING mapping = serviceObject
                ? new GENERIC_MAPPING { GenericRead=0x0002008D, GenericWrite=0x00020002, GenericExecute=0x00020070, GenericAll=0x000F01FF }
                : new GENERIC_MAPPING { GenericRead=0x00120089, GenericWrite=0x00120116, GenericExecute=0x001200A0, GenericAll=0x001F01FF };
            foreach (uint desired in rights) {
                uint privilegeLength = 0;
                uint granted;
                bool allowed;
                AccessCheck(descriptor, duplicate, desired, ref mapping, IntPtr.Zero,
                    ref privilegeLength, out granted, out allowed);
                int firstError = Marshal.GetLastWin32Error();
                if (privilegeLength == 0 || firstError != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(firstError);
                IntPtr privileges = Marshal.AllocHGlobal((int)privilegeLength);
                try {
                    if (!AccessCheck(descriptor, duplicate, desired, ref mapping, privileges,
                        ref privilegeLength, out granted, out allowed))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (allowed && (granted & desired) == desired) return true;
                } finally { Marshal.FreeHGlobal(privileges); }
            }
            return false;
        } finally {
            if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
            if (primary != IntPtr.Zero) CloseHandle(primary);
        }
    }
}
'@
    }

    $config = Get-ItemProperty -LiteralPath $registryPath
    $accountLocalService = [string]$config.ObjectName -ieq 'NT AUTHORITY\LocalService'
    $demandStart = [int]$config.Start -eq 3
    $win32OwnProcess = [int]$config.Type -eq 0x10
    $serviceSidUnrestricted = [int]$config.ServiceSidType -eq 1

    $imageCommand = [Environment]::ExpandEnvironmentVariables([string]$config.ImagePath).Trim()
    if ($imageCommand -match '%[^%]+%') { throw 'unresolved image path' }
    if ($imageCommand -cnotmatch '^"([^"]+)"\s*$') { throw 'invalid image path' }
    $binaryPath = $Matches[1]
    if ($binaryPath -cnotmatch '^[A-Za-z]:\\' -or $binaryPath.StartsWith('\\')) {
        throw 'invalid image path'
    }
    $binaryPath = [System.IO.Path]::GetFullPath($binaryPath)
    if (-not [System.IO.Path]::IsPathRooted($binaryPath) -or
        [System.IO.Path]::GetExtension($binaryPath) -ine '.exe') { throw 'invalid image path' }

    $binaryBindingVerified = $false
    $binaryChainReparseFree = $false
    $binaryOwnerTrusted = $false
    $callerBinaryControlDenied = $false
    if (Test-Path -LiteralPath $binaryPath -PathType Leaf) {
        $binary = Get-Item -LiteralPath $binaryPath -Force
        $digest = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $binaryBindingVerified = [bool](
            $binary.Length -eq $ExpectedBinaryByteLength -and $digest -ceq $ExpectedBinarySha256
        )

        $trustedOwners = @('S-1-5-18', 'S-1-5-32-544')
        foreach ($identityName in @('NT SERVICE\TrustedInstaller', "NT SERVICE\$serviceName")) {
            try {
                $trustedOwners += ([System.Security.Principal.NTAccount]$identityName).Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            } catch { throw 'owner identity unavailable' }
        }
        $forbiddenOwners = @(
            'S-1-5-19',
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        )
        $rights = [uint32[]]@(0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000)
        $chainSafe = $true
        $ownersSafe = $true
        $accessSafe = $true
        $cursor = $binary.FullName
        while ($true) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $chainSafe = $false }
            $security = if ($item.PSIsContainer) {
                [System.IO.Directory]::GetAccessControl(
                    $item.FullName,
                    [System.Security.AccessControl.AccessControlSections]::Access -bor
                    [System.Security.AccessControl.AccessControlSections]::Owner -bor
                    [System.Security.AccessControl.AccessControlSections]::Group
                )
            } else {
                [System.IO.File]::GetAccessControl(
                    $item.FullName,
                    [System.Security.AccessControl.AccessControlSections]::Access -bor
                    [System.Security.AccessControl.AccessControlSections]::Owner -bor
                    [System.Security.AccessControl.AccessControlSections]::Group
                )
            }
            $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($forbiddenOwners -contains $owner -or $trustedOwners -notcontains $owner) { $ownersSafe = $false }
            if ([BridgeServiceAccessCheck]::HasAnyAccess(
                $security.GetSecurityDescriptorBinaryForm(), $rights, $false
            )) { $accessSafe = $false }
            $parent = [System.IO.Path]::GetDirectoryName($cursor)
            if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
            $cursor = $parent
        }
        $binaryChainReparseFree = [bool]$chainSafe
        $binaryOwnerTrusted = [bool]$ownersSafe
        $callerBinaryControlDenied = [bool]$accessSafe
    }

    $scPath = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    $sddlOutput = & $scPath sdshow $serviceName 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'service security unavailable' }
    $sddl = @($sddlOutput | Where-Object { $_ -is [string] -and $_.Trim() -match '^[OGDS]:' })[-1].Trim()
    if ([string]::IsNullOrEmpty($sddl)) { throw 'service security unavailable' }
    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    $descriptorBytes = New-Object byte[] ($raw.BinaryLength)
    $raw.GetBinaryForm($descriptorBytes, 0)
    $serviceRights = [uint32[]]@(0x2, 0x10000, 0x40000, 0x80000)
    $callerServiceControlDenied = -not [BridgeServiceAccessCheck]::HasAnyAccess(
        $descriptorBytes, $serviceRights, $true
    )

    $snapshotMatchesPlan = [bool](
        $accountLocalService -and $demandStart -and $win32OwnProcess -and $serviceSidUnrestricted -and
        $callerServiceControlDenied -and $binaryBindingVerified -and
        $binaryChainReparseFree -and $binaryOwnerTrusted -and $callerBinaryControlDenied
    )
    [ordered]@{
        schema_version = 1
        service_present = $true
        account_local_service = [bool]$accountLocalService
        demand_start = [bool]$demandStart
        win32_own_process = [bool]$win32OwnProcess
        service_sid_unrestricted = [bool]$serviceSidUnrestricted
        caller_service_control_denied = [bool]$callerServiceControlDenied
        binary_binding_verified = [bool]$binaryBindingVerified
        binary_chain_reparse_free = [bool]$binaryChainReparseFree
        binary_owner_trusted = [bool]$binaryOwnerTrusted
        caller_binary_control_denied = [bool]$callerBinaryControlDenied
        snapshot_matches_plan = $snapshotMatchesPlan
        authorization_ready = $false
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    exit 1
}
