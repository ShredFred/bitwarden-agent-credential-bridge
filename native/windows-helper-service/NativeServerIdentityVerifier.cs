using System;
using System.Runtime.InteropServices;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class NativeServerIdentityVerifier
{
    private const string ServiceName = "BitwardenAgentCredentialBridgeHelper";
    private const string LocalServiceSid = "S-1-5-19";
    private const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUser = 1;
    private const int TokenGroups = 2;
    private const uint SeGroupEnabled = 0x00000004;
    private const uint SeGroupUseForDenyOnly = 0x00000010;
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceRunning = 0x00000004;
    private const uint WaitTimeout = 258;

    internal static int Run()
    {
        if (!NativeDenialPipeClient.TryOpenPipe(out IntPtr pipe))
        {
            return 30;
        }
        try
        {
            bool serverPidBound = false;
            bool serviceRunning = false;
            bool servicePidMatch = false;
            bool serverTokenBound = false;
            bool localServiceUser = false;
            bool serviceSidEnabled = false;

            if (GetNamedPipeServerProcessId(pipe, out uint pipeServerPid) && pipeServerPid != 0)
            {
                IntPtr process = OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, pipeServerPid);
                if (process != IntPtr.Zero)
                {
                    try
                    {
                        serverPidBound = GetProcessId(process) == pipeServerPid;
                        bool firstScm = TryGetRunningServicePid(out uint firstServicePid);
                        if (serverPidBound && OpenProcessToken(process, TokenQuery, out IntPtr token))
                        {
                            serverTokenBound = true;
                            try
                            {
                                localServiceUser = TokenUserMatches(token, LocalServiceSid);
                                serviceSidEnabled = TokenHasEnabledGroup(token, ServiceSid);
                            }
                            finally
                            {
                                _ = CloseHandle(token);
                            }
                        }
                        bool secondScm = TryGetRunningServicePid(out uint secondServicePid);
                        serverPidBound = serverPidBound && GetProcessId(process) == pipeServerPid &&
                            WaitForSingleObject(process, 0) == WaitTimeout;
                        serviceRunning = firstScm && secondScm && firstServicePid == secondServicePid;
                        servicePidMatch = serviceRunning && firstServicePid == pipeServerPid;
                    }
                    finally
                    {
                        _ = CloseHandle(process);
                    }
                }
            }

            bool verified = serverPidBound && serviceRunning && servicePidMatch && serverTokenBound &&
                localServiceUser && serviceSidEnabled;
            Console.Out.Write(
                "{\"schema_version\":1,\"local_pipe_connected\":true," +
                "\"server_pid_bound\":" + Bool(serverPidBound) +
                ",\"scm_service_running\":" + Bool(serviceRunning) +
                ",\"scm_server_pid_match\":" + Bool(servicePidMatch) +
                ",\"server_token_bound\":" + Bool(serverTokenBound) +
                ",\"server_token_user_local_service\":" + Bool(localServiceUser) +
                ",\"service_sid_group_enabled\":" + Bool(serviceSidEnabled) +
                ",\"server_identity_verified\":" + Bool(verified) +
                ",\"request_sent\":false,\"authorization_denied\":true}\n"
            );
            return verified ? 0 : 31;
        }
        finally
        {
            NativeDenialPipeClient.ClosePipe(pipe);
        }
    }

    internal static bool CurrentProcessHasExpectedServiceIdentity()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out IntPtr token))
        {
            return false;
        }
        try
        {
            return TokenUserMatches(token, LocalServiceSid) && TokenHasEnabledGroup(token, ServiceSid);
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    private static string Bool(bool value) => value ? "true" : "false";

    private static bool TryGetRunningServicePid(out uint processId)
    {
        processId = 0;
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return false;
        }
        try
        {
            IntPtr service = OpenService(manager, ServiceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return false;
            }
            try
            {
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out ServiceStatusProcess status,
                        (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _) ||
                    status.ServiceType != ServiceWin32OwnProcess || status.CurrentState != ServiceRunning ||
                    status.ProcessId == 0)
                {
                    return false;
                }
                processId = status.ProcessId;
                return true;
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(manager);
        }
    }

    private static bool TokenUserMatches(IntPtr token, string expectedSidText)
    {
        if (!TryGetTokenInformation(token, TokenUser, out IntPtr buffer, out uint bufferLength))
        {
            return false;
        }
        try
        {
            IntPtr actualSid = Marshal.ReadIntPtr(buffer);
            return BoundedSidMatches(buffer, bufferLength, actualSid, expectedSidText);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TokenHasEnabledGroup(IntPtr token, string expectedSidText)
    {
        if (!TryGetTokenInformation(token, TokenGroups, out IntPtr buffer, out uint bufferLength))
        {
            return false;
        }
        try
        {
            uint count = unchecked((uint)Marshal.ReadInt32(buffer));
            int firstOffset = IntPtr.Size == 8 ? 8 : 4;
            int entrySize = IntPtr.Size == 8 ? 16 : 8;
            if (count > 4096 || (ulong)firstOffset + (ulong)count * (uint)entrySize > bufferLength)
            {
                return false;
            }
            for (uint index = 0; index < count; index += 1)
            {
                int offset = checked(firstOffset + (int)index * entrySize);
                IntPtr sid = Marshal.ReadIntPtr(buffer, offset);
                uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + IntPtr.Size));
                if ((attributes & SeGroupEnabled) != 0 && (attributes & SeGroupUseForDenyOnly) == 0 &&
                    BoundedSidMatches(buffer, bufferLength, sid, expectedSidText))
                {
                    return true;
                }
            }
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryGetTokenInformation(IntPtr token, int informationClass, out IntPtr buffer,
        out uint bufferLength)
    {
        buffer = IntPtr.Zero;
        bufferLength = 0;
        _ = GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out uint required);
        if (required == 0 || required > 1024 * 1024)
        {
            return false;
        }
        buffer = Marshal.AllocHGlobal(checked((int)required));
        if (!GetTokenInformation(token, informationClass, buffer, required, out uint returned) || returned != required)
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            return false;
        }
        bufferLength = returned;
        return true;
    }

    private static bool SidMatches(IntPtr actualSid, string expectedSidText)
    {
        if (actualSid == IntPtr.Zero || !IsValidSid(actualSid) ||
            !ConvertStringSidToSid(expectedSidText, out IntPtr expectedSid))
        {
            return false;
        }
        try
        {
            return EqualSid(actualSid, expectedSid);
        }
        finally
        {
            _ = LocalFree(expectedSid);
        }
    }

    private static bool BoundedSidMatches(IntPtr buffer, uint bufferLength, IntPtr actualSid,
        string expectedSidText)
    {
        long offset = actualSid.ToInt64() - buffer.ToInt64();
        if (actualSid == IntPtr.Zero || offset < 0 || (ulong)offset + 8 > bufferLength)
        {
            return false;
        }
        byte subAuthorityCount = Marshal.ReadByte(actualSid, 1);
        uint encodedLength = checked(8u + 4u * subAuthorityCount);
        if ((ulong)offset + encodedLength > bufferLength || !IsValidSid(actualSid)) return false;
        uint sidLength = GetLengthSid(actualSid);
        return sidLength == encodedLength &&
            SidMatches(actualSid, expectedSidText);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll")]
    private static extern uint GetProcessId(IntPtr process);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int informationClass, IntPtr information,
        uint informationLength, out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr firstSid, IntPtr secondSid);

    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel,
        out ServiceStatusProcess status, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
