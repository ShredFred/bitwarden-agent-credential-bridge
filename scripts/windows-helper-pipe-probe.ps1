param(
    [Parameter(Mandatory = $true, Position = 0)][string]$PipeName,
    [Parameter(Mandatory = $true, Position = 1)][int]$ExpectedClientPid,
    [Parameter(Mandatory = $true, Position = 2)][int]$ExpectedCallerPid,
    [Parameter(Mandatory = $true, Position = 3)][string]$Nonce,
    [Parameter(Mandatory = $true, Position = 4)][string]$RootPath
)

$ErrorActionPreference = 'Stop'
$stage = 'input'

try {
    if ($PipeName -notmatch '^bw-agent-bridge-[0-9a-f]{32}$' -or
        $ExpectedClientPid -le 0 -or $ExpectedCallerPid -le 0 -or
        $Nonce -notmatch '^[0-9a-f]{64}$' -or
        -not [System.IO.Path]::IsPathRooted($RootPath)) { throw 'invalid input' }

    if (-not ('BridgeNativePipe' -as [type])) {
        $stage = 'compile'
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class BridgeNativePipe {
    const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
    const uint PIPE_TYPE_BYTE = 0x00000000;
    const uint PIPE_READMODE_BYTE = 0x00000000;
    const uint PIPE_WAIT = 0x00000000;
    const uint PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const int ERROR_PIPE_CONNECTED = 535;
    const int TokenUser = 1;
    const int TokenIsAppContainer = 29;
    const int SecurityImpersonation = 2;
    const uint FILE_WRITE_DATA = 0x00000002;
    const uint FILE_APPEND_DATA = 0x00000004;
    const uint FILE_WRITE_ATTRIBUTES = 0x00000100;
    const uint FILE_ADD_FILE = 0x00000002;
    const uint FILE_ADD_SUBDIRECTORY = 0x00000004;
    const uint FILE_DELETE_CHILD = 0x00000040;
    const uint DELETE = 0x00010000;
    const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }
    [StructLayout(LayoutKind.Sequential)]
    struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern SafeFileHandle CreateNamedPipe(string name, uint openMode, uint pipeMode,
        uint maxInstances, uint outBufferSize, uint inBufferSize, uint defaultTimeout, IntPtr security);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ConnectNamedPipe(SafeFileHandle pipe, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeClientProcessId(SafeFileHandle pipe, out uint clientPid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe, out uint serverPid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetTokenInformation(IntPtr tokenHandle, int infoClass, IntPtr info,
        uint infoLength, out uint returnLength);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool IsTokenRestricted(IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool DuplicateToken(IntPtr existingToken, int impersonationLevel, out IntPtr duplicateToken);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AccessCheck(byte[] securityDescriptor, IntPtr clientToken, uint desiredAccess,
        ref GENERIC_MAPPING genericMapping, IntPtr privilegeSet, ref uint privilegeSetLength,
        out uint grantedAccess, out bool accessStatus);
    [DllImport("advapi32.dll")]
    static extern void MapGenericMask(ref uint accessMask, ref GENERIC_MAPPING mapping);

    public sealed class TokenFacts {
        public string Sid;
        public bool Restricted;
        public bool AppContainer;
    }

    public static SafeFileHandle CreateLocalOnlyPipe(string shortName) {
        string fullName = @"\\.\pipe\" + shortName;
        SafeFileHandle handle = CreateNamedPipe(fullName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 5000, IntPtr.Zero);
        if (handle == null || handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }

    public static void Connect(SafeFileHandle handle) {
        if (!ConnectNamedPipe(handle, IntPtr.Zero)) {
            int error = Marshal.GetLastWin32Error();
            if (error != ERROR_PIPE_CONNECTED) throw new Win32Exception(error);
        }
    }

    public static uint ClientPid(SafeFileHandle handle) {
        uint value;
        if (!GetNamedPipeClientProcessId(handle, out value)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return value;
    }

    public static uint ServerPid(SafeFileHandle handle) {
        uint value;
        if (!GetNamedPipeServerProcessId(handle, out value)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return value;
    }

    public static TokenFacts ReadToken(uint pid) {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr token = IntPtr.Zero;
        try {
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint needed;
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out needed);
            if (needed == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try {
                if (!GetTokenInformation(token, TokenUser, buffer, needed, out needed))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                TOKEN_USER user = (TOKEN_USER)Marshal.PtrToStructure(buffer, typeof(TOKEN_USER));
                string sid = new SecurityIdentifier(user.User.Sid).Value;
                int appContainer = 0;
                uint appSize = 4;
                IntPtr appBuffer = Marshal.AllocHGlobal(4);
                try {
                    if (!GetTokenInformation(token, TokenIsAppContainer, appBuffer, appSize, out appSize))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    appContainer = Marshal.ReadInt32(appBuffer);
                } finally { Marshal.FreeHGlobal(appBuffer); }
                return new TokenFacts { Sid = sid, Restricted = IsTokenRestricted(token), AppContainer = appContainer != 0 };
            } finally { Marshal.FreeHGlobal(buffer); }
        } finally {
            if (token != IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
    }

    public static string ReadAsciiLine(Stream stream, int maxBytes) {
        MemoryStream value = new MemoryStream();
        while (true) {
            int next = stream.ReadByte();
            if (next < 0) throw new EndOfStreamException();
            if (next == 10) break;
            if (next < 0x20 || next > 0x7e || value.Length >= maxBytes) throw new InvalidDataException();
            value.WriteByte((byte)next);
        }
        return Encoding.ASCII.GetString(value.ToArray());
    }

    public static byte[] ReadExact(Stream stream, int length) {
        if (length < 1 || length > 65536) throw new InvalidDataException();
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = stream.Read(result, offset, length - offset);
            if (count <= 0) throw new EndOfStreamException();
            offset += count;
        }
        return result;
    }

    public static byte[] ReadBounded(Stream stream, int maxBytes) {
        MemoryStream value = new MemoryStream();
        byte[] buffer = new byte[16384];
        while (true) {
            int count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            if (value.Length + count > maxBytes) throw new InvalidDataException();
            value.Write(buffer, 0, count);
        }
        if (value.Length == 0) throw new InvalidDataException();
        return value.ToArray();
    }

    public static bool CanWritePath(uint pid, string rootPath, string targetPath, bool targetIsDirectory) {
        string root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
        string target = Path.GetFullPath(targetPath).TrimEnd(Path.DirectorySeparatorChar);
        string prefix = root + Path.DirectorySeparatorChar;
        if (!target.Equals(root, StringComparison.OrdinalIgnoreCase) &&
            !target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
        if (!Directory.Exists(root) || IsReparse(root)) throw new InvalidDataException();

        string existing = target;
        int missingCount = 0;
        while (!File.Exists(existing) && !Directory.Exists(existing)) {
            missingCount++;
            string parent = Path.GetDirectoryName(existing);
            if (String.IsNullOrEmpty(parent) ||
                (!parent.Equals(root, StringComparison.OrdinalIgnoreCase) &&
                 !parent.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException();
            existing = parent;
        }
        string cursor = existing;
        while (true) {
            if (IsReparse(cursor)) throw new InvalidDataException();
            if (cursor.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            cursor = Path.GetDirectoryName(cursor);
            if (String.IsNullOrEmpty(cursor)) throw new InvalidDataException();
        }

        bool descriptorIsDirectory = Directory.Exists(existing);
        if (missingCount == 0 && descriptorIsDirectory != targetIsDirectory) throw new InvalidDataException();
        uint desired;
        if (missingCount > 0) {
            if (!descriptorIsDirectory) throw new InvalidDataException();
            desired = (missingCount > 1 || targetIsDirectory) ? FILE_ADD_SUBDIRECTORY : FILE_ADD_FILE;
        } else if (targetIsDirectory) {
            desired = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES;
        } else {
            desired = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;
        }

        FileSystemSecurity security = descriptorIsDirectory
            ? (FileSystemSecurity)new DirectoryInfo(existing).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group)
            : (FileSystemSecurity)new FileInfo(existing).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
        return CheckAccess(pid, security.GetSecurityDescriptorBinaryForm(), desired);
    }

    static bool IsReparse(string target) {
        return (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0;
    }

    static bool CheckAccess(uint pid, byte[] descriptor, uint desired) {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr primary = IntPtr.Zero;
        IntPtr impersonation = IntPtr.Zero;
        try {
            if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, out primary)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!DuplicateToken(primary, SecurityImpersonation, out impersonation)) throw new Win32Exception(Marshal.GetLastWin32Error());
            GENERIC_MAPPING mapping = new GENERIC_MAPPING {
                GenericRead = 0x00120089, GenericWrite = 0x00120116,
                GenericExecute = 0x001200A0, GenericAll = 0x001F01FF
            };
            MapGenericMask(ref desired, ref mapping);
            uint privilegeLength = 0;
            uint granted;
            bool allowed;
            AccessCheck(descriptor, impersonation, desired, ref mapping, IntPtr.Zero,
                ref privilegeLength, out granted, out allowed);
            int firstError = Marshal.GetLastWin32Error();
            if (privilegeLength == 0 || firstError != ERROR_INSUFFICIENT_BUFFER)
                throw new Win32Exception(firstError);
            IntPtr privileges = Marshal.AllocHGlobal((int)privilegeLength);
            try {
                if (!AccessCheck(descriptor, impersonation, desired, ref mapping, privileges,
                    ref privilegeLength, out granted, out allowed))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return allowed && (granted & desired) == desired;
            } finally { Marshal.FreeHGlobal(privileges); }
        } finally {
            if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            CloseHandle(process);
        }
    }
}
'@
    }

    $stage = 'pipe'
    $pipe = [BridgeNativePipe]::CreateLocalOnlyPipe($PipeName)
    try {
        [BridgeNativePipe]::Connect($pipe)
        $actualClientPid = [BridgeNativePipe]::ClientPid($pipe)
        $actualServerPid = [BridgeNativePipe]::ServerPid($pipe)
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id

        $stream = New-Object System.IO.FileStream($pipe, [System.IO.FileAccess]::ReadWrite, 4096, $false)
        $pipe = $null
        try {
            $stage = 'request'
            $line = [BridgeNativePipe]::ReadAsciiLine($stream, 64)
            if ($line -cne $Nonce) { throw 'handshake mismatch' }
            $lengthLine = [BridgeNativePipe]::ReadAsciiLine($stream, 8)
            if ($lengthLine -notmatch '^[0-9a-f]{8}$') { throw 'invalid request length' }
            $requestLength = [Convert]::ToInt32($lengthLine, 16)
            $requestBytes = [BridgeNativePipe]::ReadExact($stream, $requestLength)
            $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
            $requestText = $utf8.GetString($requestBytes)
            $request = $requestText | ConvertFrom-Json
            if ($request.protocol_version -ne 1 -or $request.operation -cne 'apply_disposable_manifest' -or
                $request.workspace.platform -cne 'win32' -or
                $request.workspace.root -cne $RootPath -or
                $request.workspace.marker_nonce -cne $Nonce -or
                $request.launcher.transport -cne 'inherited_readonly_handle' -or
                $request.manifest.payload.observed.config_dir -cne 'absent' -or
                $request.manifest.payload.observed.config_file -cne 'absent' -or
                $request.manifest.payload.observed.install_root -cne 'absent' -or
                $request.manifest.payload.observed.bin_dir -cne 'absent' -or
                $request.manifest.payload.observed.launcher.kind -cne 'absent') {
                throw 'request binding mismatch'
            }
            $stage = 'launcher'
            $launcherStream = [Console]::OpenStandardInput()
            $launcherBytes = [BridgeNativePipe]::ReadBounded($launcherStream, 1048576)
            $launcherSha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $launcherDigest = [BitConverter]::ToString($launcherSha.ComputeHash($launcherBytes)).Replace('-', '').ToLowerInvariant()
            }
            finally { $launcherSha.Dispose() }
            $requestVerified = [bool](
                $request.launcher.sha256 -cmatch '^[0-9a-f]{64}$' -and
                [int64]$request.launcher.byte_length -eq $launcherBytes.Length
            )
            $launcherHandleVerified = [bool]($requestVerified -and $request.launcher.sha256 -ceq $launcherDigest)
            if (-not $launcherHandleVerified) { throw 'launcher handle mismatch' }
            $stage = 'token'
            $callerToken = [BridgeNativePipe]::ReadToken([uint32]$ExpectedCallerPid)
            $clientToken = [BridgeNativePipe]::ReadToken([uint32]$actualClientPid)
            $helperToken = [BridgeNativePipe]::ReadToken([uint32]$currentPid)
            $serverToken = [BridgeNativePipe]::ReadToken([uint32]$actualServerPid)
            $stage = 'access'
            $targetSpecs = @(
                @($request.manifest.payload.paths.config_dir, $true),
                @($request.manifest.payload.paths.config_file, $false),
                @($request.manifest.payload.paths.install_root, $true),
                @($request.manifest.payload.paths.bin_dir, $true),
                @($request.manifest.payload.paths.launcher, $false)
            )
            $callerAllDenied = $true
            $helperAllAllowed = $true
            foreach ($spec in $targetSpecs) {
                $target = [string]$spec[0]
                $isDirectory = [bool]$spec[1]
                $stage = 'accesscaller'
                $callerCanWrite = [BridgeNativePipe]::CanWritePath(
                    [uint32]$ExpectedCallerPid, $RootPath, $target, $isDirectory
                )
                $stage = 'accesshelper'
                $helperCanWrite = [BridgeNativePipe]::CanWritePath(
                    [uint32]$currentPid, $RootPath, $target, $isDirectory
                )
                if ($callerCanWrite) { $callerAllDenied = $false }
                if (-not $helperCanWrite) { $helperAllAllowed = $false }
            }
            $stage = 'response'
            $responseBytes = [Text.Encoding]::ASCII.GetBytes("ok`n")
            $stream.Write($responseBytes, 0, $responseBytes.Length)
            $stream.Flush()
        }
        finally { $stream.Dispose() }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $callerDigest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($callerToken.Sid))).Replace('-', '').ToLowerInvariant()
            $helperDigest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($helperToken.Sid))).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha.Dispose() }

        $stage = 'output'
        [ordered]@{
            schema_version = 1
            transport_kind = 'windows_named_pipe'
            remote_clients_rejected = $true
            client_pid_verified = [bool]($actualClientPid -eq [uint32]$ExpectedClientPid)
            server_pid_verified = [bool]($actualServerPid -eq [uint32]$currentPid)
            caller_token_verified = [bool]($actualClientPid -eq [uint32]$ExpectedClientPid -and $callerToken.Sid -ceq $clientToken.Sid)
            helper_token_verified = [bool]($actualServerPid -eq [uint32]$currentPid -and $helperToken.Sid -ceq $serverToken.Sid)
            caller_token_user_sha256 = $callerDigest
            helper_token_user_sha256 = $helperDigest
            caller_is_restricted = [bool]$callerToken.Restricted
            caller_is_app_container = [bool]$callerToken.AppContainer
            acl_checks_verified = $true
            all_targets_checked = [bool]($targetSpecs.Count -eq 5)
            caller_effective_write_denied = [bool]$callerAllDenied
            helper_required_write_allowed = [bool]$helperAllAllowed
            request_verified = [bool]$requestVerified
            launcher_handle_verified = [bool]$launcherHandleVerified
        } | ConvertTo-Json -Compress
        exit 0
    }
    finally { if ($null -ne $pipe) { $pipe.Dispose() } }
}
catch {
    if ($stage.StartsWith('access')) {
        $cause = $_.Exception
        while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
        $kind = $cause.GetType().Name
        if ($kind -eq 'Win32Exception') { $stage = 'accesswin32' }
        elseif ($kind -eq 'MissingMethodException') { $stage = 'accessmethod' }
        elseif ($kind -eq 'UnauthorizedAccessException') { $stage = 'accessdenied' }
        elseif ($kind -eq 'ArgumentException') { $stage = 'accessargument' }
        else { $stage = 'accessother' }
    }
    [Console]::Error.WriteLine("probe_${stage}_failed")
    exit 1
}
