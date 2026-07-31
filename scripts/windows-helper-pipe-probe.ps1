param(
    [Parameter(Mandatory = $true, Position = 0)][string]$PipeName,
    [Parameter(Mandatory = $true, Position = 1)][int]$ExpectedClientPid,
    [Parameter(Mandatory = $true, Position = 2)][int]$ExpectedCallerPid,
    [Parameter(Mandatory = $true, Position = 3)][string]$Nonce
)

$ErrorActionPreference = 'Stop'

try {
    if ($PipeName -notmatch '^bw-agent-bridge-[0-9a-f]{32}$' -or
        $ExpectedClientPid -le 0 -or $ExpectedCallerPid -le 0 -or
        $Nonce -notmatch '^[0-9a-f]{64}$') { throw 'invalid input' }

    if (-not ('BridgeNativePipe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
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
    const int ERROR_PIPE_CONNECTED = 535;
    const int TokenUser = 1;
    const int TokenIsAppContainer = 29;

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

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
}
'@
    }

    $pipe = [BridgeNativePipe]::CreateLocalOnlyPipe($PipeName)
    try {
        [BridgeNativePipe]::Connect($pipe)
        $actualClientPid = [BridgeNativePipe]::ClientPid($pipe)
        $actualServerPid = [BridgeNativePipe]::ServerPid($pipe)
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id

        $stream = New-Object System.IO.FileStream($pipe, [System.IO.FileAccess]::ReadWrite, 4096, $false)
        $pipe = $null
        try {
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.UTF8Encoding]::new($false, $true), $false, 128, $true)
            $writer = New-Object System.IO.StreamWriter($stream, [System.Text.UTF8Encoding]::new($false, $true), 128, $true)
            $writer.AutoFlush = $true
            $line = $reader.ReadLine()
            if ($line -cne $Nonce) { throw 'handshake mismatch' }
            $callerToken = [BridgeNativePipe]::ReadToken([uint32]$ExpectedCallerPid)
            $clientToken = [BridgeNativePipe]::ReadToken([uint32]$actualClientPid)
            $helperToken = [BridgeNativePipe]::ReadToken([uint32]$currentPid)
            $serverToken = [BridgeNativePipe]::ReadToken([uint32]$actualServerPid)
            $writer.WriteLine('ok')
        }
        finally { $stream.Dispose() }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $callerDigest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($callerToken.Sid))).Replace('-', '').ToLowerInvariant()
            $helperDigest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($helperToken.Sid))).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha.Dispose() }

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
            acl_checks_verified = $false
            all_targets_checked = $false
            caller_effective_write_denied = $false
            helper_required_write_allowed = $false
        } | ConvertTo-Json -Compress
        exit 0
    }
    finally { if ($null -ne $pipe) { $pipe.Dispose() } }
}
catch { exit 1 }
