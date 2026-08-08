param(
    [Parameter(Mandatory = $true, Position = 0)][string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true, Position = 1)][long]$ExpectedBinaryByteLength
)

$ErrorActionPreference = 'Stop'
$serviceName = 'BitwardenAgentCredentialBridgeHelper'

function Write-Result([hashtable]$values) {
    [ordered]@{
        schema_version = 1
        service_present = [bool]$values.service_present
        binary_digest_matched_via_handle = [bool]$values.binary_digest_matched_via_handle
        binary_chain_reparse_free = [bool]$values.binary_chain_reparse_free
        binary_owner_trusted = [bool]$values.binary_owner_trusted
        caller_binary_control_denied = [bool]$values.caller_binary_control_denied
        caller_service_control_denied = [bool]$values.caller_service_control_denied
        service_dacl_caller_change_denied = [bool]$values.service_dacl_caller_change_denied
        handle_open_used = [bool]$values.handle_open_used
        path_hash_used = [bool]$values.path_hash_used
        authorization_ready = $false
    } | ConvertTo-Json -Compress
}

function Write-AbsentResult {
    Write-Result @{
        service_present = $false
        binary_digest_matched_via_handle = $false
        binary_chain_reparse_free = $false
        binary_owner_trusted = $false
        caller_binary_control_denied = $false
        caller_service_control_denied = $false
        service_dacl_caller_change_denied = $false
        handle_open_used = $false
        path_hash_used = $false
    }
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

    if (-not ('BridgeHandleBoundIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class BridgeHandleBoundIdentity {
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const int SecurityImpersonation = 2;
    const int ERROR_INSUFFICIENT_BUFFER = 122;
    const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    const uint DACL_SECURITY_INFORMATION = 0x00000004;
    static readonly IntPtr INVALID = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFile(string fileName, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr file, byte[] buffer, uint toRead, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(IntPtr file, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint desired,
        ref GENERIC_MAPPING mapping, IntPtr privileges, ref uint privilegeLength,
        out uint granted, out bool allowed);
    [DllImport("advapi32.dll")]
    static extern void MapGenericMask(ref uint accessMask, ref GENERIC_MAPPING mapping);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    public static bool TryHashRegularFile(string path, long expectedLength, string expectedSha256,
        out bool reparseFree, out bool digestMatched, out bool handleOpened) {
        reparseFree = false;
        digestMatched = false;
        handleOpened = false;
        // Running service images are often mapped with READ|DELETE sharing; request the
        // same share mask so medium-IL digest probes can open the handle.
        const uint FILE_SHARE_READ_WRITE_DELETE = 0x00000007;
        IntPtr handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle == INVALID) return false;
        try {
            handleOpened = true;
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info)) return false;
            if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                reparseFree = false;
                return true;
            }
            reparseFree = true;
            long size = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
            if (size != expectedLength || size < 1 || size > 67108864) return true;
            using (var sha = SHA256.Create())
            using (var crypto = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write)) {
                byte[] buffer = new byte[65536];
                long remaining = size;
                while (remaining > 0) {
                    int chunk = remaining > buffer.Length ? buffer.Length : (int)remaining;
                    uint read;
                    if (!ReadFile(handle, buffer, (uint)chunk, out read, IntPtr.Zero) || read == 0) return false;
                    crypto.Write(buffer, 0, (int)read);
                    remaining -= read;
                }
                crypto.FlushFinalBlock();
                string digest = BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
                digestMatched = digest == expectedSha256;
            }
            return true;
        } finally {
            CloseHandle(handle);
        }
    }

    public static bool TryInspectPath(string path, bool directory, string[] trustedOwners,
        string[] forbiddenOwners, out bool reparseFree, out bool ownerTrusted, out bool callerDenied) {
        reparseFree = false;
        ownerTrusted = false;
        callerDenied = false;
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
        IntPtr handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING,
            flags, IntPtr.Zero);
        if (handle == INVALID) return false;
        IntPtr descriptor = IntPtr.Zero;
        try {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info)) return false;
            reparseFree = (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            // AccessCheck requires a complete descriptor (owner+group+dacl).
            if (GetSecurityInfo(handle, 1 /* SE_FILE_OBJECT */,
                OWNER_SECURITY_INFORMATION | 0x00000002 /* GROUP */ | DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out descriptor) != 0 || descriptor == IntPtr.Zero) {
                return false;
            }
            IntPtr ownerString;
            if (!ConvertSidToStringSid(owner, out ownerString)) return false;
            string ownerSid;
            try { ownerSid = Marshal.PtrToStringUni(ownerString); }
            finally { LocalFree(ownerString); }
            ownerTrusted = Array.IndexOf(trustedOwners, ownerSid) >= 0 &&
                Array.IndexOf(forbiddenOwners, ownerSid) < 0;
            int length = GetSecurityDescriptorLength(descriptor);
            byte[] bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, length);
            uint[] rights = new uint[] { 0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000 };
            callerDenied = !HasAnyAccess(bytes, rights, false);
            return true;
        } finally {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
            CloseHandle(handle);
        }
    }

    [DllImport("advapi32.dll")]
    static extern int GetSecurityDescriptorLength(IntPtr descriptor);

    public static bool HasAnyAccess(byte[] descriptor, uint[] rights, bool serviceObject) {
        IntPtr primary = IntPtr.Zero;
        IntPtr duplicate = IntPtr.Zero;
        IntPtr privileges = Marshal.AllocHGlobal(1024);
        try {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, out primary))
                return true; // fail closed: do not claim caller denial
            if (!DuplicateToken(primary, SecurityImpersonation, out duplicate))
                return true;
            GENERIC_MAPPING mapping = serviceObject
                ? new GENERIC_MAPPING { GenericRead=0x0002008D, GenericWrite=0x00020002, GenericExecute=0x00020070, GenericAll=0x000F01FF }
                : new GENERIC_MAPPING { GenericRead=0x00120089, GenericWrite=0x00120116, GenericExecute=0x001200A0, GenericAll=0x001F01FF };
            foreach (uint desired in rights) {
                uint mapped = desired;
                MapGenericMask(ref mapped, ref mapping);
                // PRIVILEGE_SET: PrivilegeCount=0 at offset 0.
                for (int i = 0; i < 1024; i++) Marshal.WriteByte(privileges, i, 0);
                uint privilegeLength = 1024;
                uint granted;
                bool allowed;
                if (!AccessCheck(descriptor, duplicate, mapped, ref mapping, privileges,
                    ref privilegeLength, out granted, out allowed))
                {
                    // Access denied from AccessCheck is success for our denial claim.
                    int err = Marshal.GetLastWin32Error();
                    if (err == 5 /* ERROR_ACCESS_DENIED */) continue;
                    return true; // indeterminate → do not claim denial
                }
                if (allowed && (granted & mapped) == mapped) return true;
            }
            return false;
        } finally {
            Marshal.FreeHGlobal(privileges);
            if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
            if (primary != IntPtr.Zero) CloseHandle(primary);
        }
    }
}
'@
    }

    $config = Get-ItemProperty -LiteralPath $registryPath
    $imageCommand = [Environment]::ExpandEnvironmentVariables([string]$config.ImagePath).Trim()
    if ($imageCommand -match '%[^%]+%') { throw 'unresolved image path' }
    # Accept quoted ImagePath (required by create) and unquoted absolute .exe forms.
    $binaryPath = $null
    if ($imageCommand -cmatch '^"([^"]+\.exe)"\s*$') {
        $binaryPath = $Matches[1]
    } elseif ($imageCommand -cmatch '^([A-Za-z]:\\[^"]+\.exe)\s*$') {
        $binaryPath = $Matches[1]
    } else {
        throw 'invalid image path'
    }
    if ($binaryPath -cnotmatch '^[A-Za-z]:\\' -or $binaryPath.StartsWith('\\')) {
        throw 'invalid image path'
    }
    $binaryPath = [System.IO.Path]::GetFullPath($binaryPath)
    if (-not [System.IO.Path]::IsPathRooted($binaryPath) -or
        [System.IO.Path]::GetExtension($binaryPath) -ine '.exe') { throw 'invalid image path' }

    $trustedOwners = [System.Collections.Generic.List[string]]::new()
    $trustedOwners.Add('S-1-5-18')
    $trustedOwners.Add('S-1-5-32-544')
    # Well-known TrustedInstaller service SID (translation can fail under locked-down hosts).
    $trustedOwners.Add('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    foreach ($identityName in @("NT SERVICE\$serviceName")) {
        try {
            $trustedOwners.Add((
                [System.Security.Principal.NTAccount]$identityName
            ).Translate([System.Security.Principal.SecurityIdentifier]).Value)
        } catch {
            # Service SID may be unavailable briefly after create; continue with other trusted owners.
        }
    }
    $forbiddenOwners = @(
        'S-1-5-19',
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    )

    $digestMatched = $false
    $handleOpened = $false
    $fileReparseFree = $false
    [void][BridgeHandleBoundIdentity]::TryHashRegularFile(
        $binaryPath,
        $ExpectedBinaryByteLength,
        $ExpectedBinarySha256,
        [ref]$fileReparseFree,
        [ref]$digestMatched,
        [ref]$handleOpened
    )

    $chainReparseFree = $true
    $ownersSafe = $true
    $accessSafe = $true
    # Only the helper binary and its ProgramData-class install root are
    # security-relevant. Walking into ProgramData/volume roots falsely fails
    # caller-denial because those containers intentionally allow AU create.
    $programData = $env:ProgramData
    if ([string]::IsNullOrWhiteSpace($programData)) {
        $programData = Join-Path $env:SystemRoot 'ProgramData'
    }
    $bridgeRoot = [IO.Path]::GetFullPath((Join-Path $programData 'BitwardenAgentCredentialBridge'))
    if ($handleOpened) {
        $cursor = $binaryPath
        $isDirectory = $false
        while ($true) {
            $itemReparseFree = $false
            $itemOwnerTrusted = $false
            $itemCallerDenied = $false
            if (-not [BridgeHandleBoundIdentity]::TryInspectPath(
                $cursor, $isDirectory, $trustedOwners.ToArray(), $forbiddenOwners,
                [ref]$itemReparseFree, [ref]$itemOwnerTrusted, [ref]$itemCallerDenied
            )) {
                $chainReparseFree = $false
                $ownersSafe = $false
                $accessSafe = $false
                break
            }
            if (-not $itemReparseFree) { $chainReparseFree = $false }
            if (-not $itemOwnerTrusted) { $ownersSafe = $false }
            if (-not $itemCallerDenied) { $accessSafe = $false }
            $cursorFull = [IO.Path]::GetFullPath($cursor)
            if ($cursorFull.Equals($bridgeRoot, [StringComparison]::OrdinalIgnoreCase)) { break }
            $parent = [System.IO.Path]::GetDirectoryName($cursor)
            if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
            $cursor = $parent
            $isDirectory = $true
        }
        if (-not $fileReparseFree) { $chainReparseFree = $false }
    } else {
        $chainReparseFree = $false
        $ownersSafe = $false
        $accessSafe = $false
    }

    $scPath = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    # Do not pipe native sc.exe into Out-String: with $ErrorActionPreference Stop
    # that throws "Cannot run a document in the middle of a pipeline".
    # Also avoid `@($string | …)` — piping a single-line [string] enumerates chars.
    $sddlOutput = & $scPath sdshow $serviceName 2>$null
    if ($sddlOutput -is [System.Array]) {
        $sddlLines = @($sddlOutput | ForEach-Object { [string]$_ })
    } elseif ($null -eq $sddlOutput) {
        $sddlLines = @()
    } else {
        $sddlLines = @([string]$sddlOutput)
    }
    $callerServiceControlDenied = $false
    if ($LASTEXITCODE -eq 0 -and $sddlLines.Count -gt 0) {
        try {
            $sddl = $null
            foreach ($line in $sddlLines) {
                $trimmed = ([string]$line).Trim()
                if ($trimmed -match '^[OGDS]:') { $sddl = $trimmed }
            }
            if ($null -ne $sddl) {
                # sc sdshow often emits only a DACL. AccessCheck requires owner+group.
                if ($sddl.StartsWith('D:')) { $sddl = 'O:SYG:SY' + $sddl }
                $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
                $descriptorBytes = New-Object byte[] ($raw.BinaryLength)
                $raw.GetBinaryForm($descriptorBytes, 0)
                $serviceRights = [uint32[]]@(0x2, 0x10000, 0x40000, 0x80000)
                $callerServiceControlDenied = -not [BridgeHandleBoundIdentity]::HasAnyAccess(
                    $descriptorBytes, $serviceRights, $true
                )
            }
        } catch {
            $callerServiceControlDenied = $false
        }
    }

    Write-Result @{
        service_present = $true
        binary_digest_matched_via_handle = $digestMatched
        binary_chain_reparse_free = $chainReparseFree
        binary_owner_trusted = $ownersSafe
        caller_binary_control_denied = $accessSafe
        caller_service_control_denied = $callerServiceControlDenied
        service_dacl_caller_change_denied = $callerServiceControlDenied
        handle_open_used = $handleOpened
        path_hash_used = $false
    }
    exit 0
}
catch {
    # Prefer an exact incomplete JSON report over a hard probe crash so the
    # Node collector can brand honest incomplete evidence instead of aborting.
    try {
        if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -PathType Container) {
            Write-Result @{
                service_present = $true
                binary_digest_matched_via_handle = $false
                binary_chain_reparse_free = $false
                binary_owner_trusted = $false
                caller_binary_control_denied = $false
                caller_service_control_denied = $false
                service_dacl_caller_change_denied = $false
                handle_open_used = $false
                path_hash_used = $false
            }
            exit 0
        }
        Write-AbsentResult
        exit 0
    } catch {
        exit 1
    }
}
