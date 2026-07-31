using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class DenialPipeProbe
{
    private const string PipePath = @"\\.\pipe\BitwardenAgentCredentialBridgeHelper.v1.denial";
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeTypeMessage = 0x00000004;
    private const uint PipeReadModeMessage = 0x00000002;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const uint PipeUnlimitedInstances = 255;
    private const uint TokenQuery = 0x0008;
    private const int TokenUser = 1;
    private const int ErrorPipeConnected = 535;
    private const int ErrorIoPending = 997;
    private const uint WaitObject0 = 0;
    private const uint SessionTimeoutMilliseconds = 1500;
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private static readonly byte[] DenialResponse = Encoding.ASCII.GetBytes(
        "{\"schema_version\":1,\"local_transport\":true,\"remote_clients_rejected\":true," +
        "\"first_instance\":true,\"explicit_pipe_dacl_verified\":true," +
        "\"service_sid_ace_verified\":true,\"authenticated_client_narrow_access_ace_verified\":true," +
        "\"client_pid_bound\":true,\"caller_token_bound\":true," +
        "\"helper_token_bound\":true,\"same_token_user\":true,\"different_principal\":false," +
        "\"authorization_denied\":true}\n"
    );
    private static readonly byte[] TrailingJunkResponse = Encoding.ASCII.GetBytes(
        Encoding.ASCII.GetString(DenialResponse) + "junk"
    );

    internal static bool IsCanonicalNonce(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }
        foreach (char character in value)
        {
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    internal static int Run(string expectedNonce)
    {
        return RunCore(expectedNonce, "normal");
    }

    internal static int RunSelfTestServer(string mode, string expectedNonce)
    {
        return RunCore(expectedNonce, mode);
    }

    private static int RunCore(string expectedNonce, string mode)
    {
        if (!PipeSecurity.TryCreateAttributes(out IntPtr attributes, out IntPtr descriptor))
        {
            return 17;
        }
        IntPtr pipe;
        try
        {
            pipe = CreateNamedPipe(
                PipePath,
                PipeAccessDuplex | FileFlagFirstPipeInstance | FileFlagOverlapped,
                PipeTypeMessage | PipeReadModeMessage | PipeWait | PipeRejectRemoteClients,
                PipeUnlimitedInstances,
                4096,
                4096,
                0,
                attributes
            );
        }
        finally
        {
            PipeSecurity.FreeAttributes(attributes, descriptor);
        }
        if (pipe == InvalidHandleValue)
        {
            return 10;
        }

        try
        {
            if (!PipeSecurity.HasExpectedKernelDacl(pipe))
            {
                return 18;
            }
            if (!ConnectWithDeadline(pipe))
            {
                return 11;
            }
            if (!ReadAndMatchNonce(pipe, expectedNonce))
            {
                return 12;
            }
            if (!TryBindSameTokenUser(pipe, out bool sameTokenUser) || !sameTokenUser)
            {
                return 13;
            }
            if (mode == "stall")
            {
                Thread.Sleep(2500);
                return 0;
            }
            if (mode == "trailing")
            {
                return WriteAll(pipe, TrailingJunkResponse) ? 0 : 14;
            }
            if (!WriteAll(pipe, DenialResponse))
            {
                return 14;
            }
            if (!ReadFixedMessage(pipe, "ack\n"))
            {
                return 15;
            }
            _ = DisconnectNamedPipe(pipe);
            return 0;
        }
        finally
        {
            _ = CloseHandle(pipe);
        }
    }

    private static bool ReadAndMatchNonce(IntPtr pipe, string expectedNonce)
    {
        byte[] received = new byte[65];
        IntPtr buffer = Marshal.AllocHGlobal(received.Length);
        try
        {
            if (!ReadMessageWithDeadline(pipe, buffer, (uint)received.Length, out uint read) || read != received.Length)
            {
                return false;
            }
            Marshal.Copy(buffer, received, 0, received.Length);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        if (received[64] != (byte)'\n')
        {
            return false;
        }
        byte[] expected = Encoding.ASCII.GetBytes(expectedNonce);
        int difference = 0;
        for (int index = 0; index < expected.Length; index += 1)
        {
            difference |= received[index] ^ expected[index];
        }
        return difference == 0;
    }

    private static bool ReadFixedMessage(IntPtr pipe, string expectedValue)
    {
        byte[] expected = Encoding.ASCII.GetBytes(expectedValue);
        IntPtr buffer = Marshal.AllocHGlobal(expected.Length);
        try
        {
            if (!ReadMessageWithDeadline(pipe, buffer, (uint)expected.Length, out uint read) || read != expected.Length)
            {
                return false;
            }
            byte[] received = new byte[expected.Length];
            Marshal.Copy(buffer, received, 0, received.Length);
            int difference = 0;
            for (int index = 0; index < expected.Length; index += 1)
            {
                difference |= received[index] ^ expected[index];
            }
            return difference == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ConnectWithDeadline(IntPtr pipe)
    {
        IntPtr waitEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (waitEvent == IntPtr.Zero)
        {
            return false;
        }
        IntPtr overlapped = CreateOverlapped(waitEvent);
        try
        {
            if (ConnectNamedPipe(pipe, overlapped))
            {
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorPipeConnected)
            {
                return true;
            }
            if (error != ErrorIoPending)
            {
                return false;
            }
            if (WaitForSingleObject(waitEvent, SessionTimeoutMilliseconds) != WaitObject0)
            {
                CancelAndDrainOrExit(pipe, overlapped, waitEvent);
                return false;
            }
            return GetOverlappedResult(pipe, overlapped, out _, false);
        }
        finally
        {
            Marshal.FreeHGlobal(overlapped);
            _ = CloseHandle(waitEvent);
        }
    }

    private static bool ReadMessageWithDeadline(IntPtr pipe, IntPtr buffer, uint length, out uint bytesRead)
    {
        bytesRead = 0;
        IntPtr waitEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (waitEvent == IntPtr.Zero)
        {
            return false;
        }
        IntPtr overlapped = CreateOverlapped(waitEvent);
        try
        {
            if (ReadFile(pipe, buffer, length, out bytesRead, overlapped))
            {
                return true;
            }
            if (Marshal.GetLastWin32Error() != ErrorIoPending)
            {
                return false;
            }
            if (WaitForSingleObject(waitEvent, SessionTimeoutMilliseconds) != WaitObject0)
            {
                CancelAndDrainOrExit(pipe, overlapped, waitEvent);
                return false;
            }
            return GetOverlappedResult(pipe, overlapped, out bytesRead, false);
        }
        finally
        {
            Marshal.FreeHGlobal(overlapped);
            _ = CloseHandle(waitEvent);
        }
    }

    private static IntPtr CreateOverlapped(IntPtr waitEvent)
    {
        IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeOverlapped>());
        Marshal.StructureToPtr(new NativeOverlapped { EventHandle = waitEvent }, pointer, false);
        return pointer;
    }

    private static void CancelAndDrainOrExit(IntPtr pipe, IntPtr overlapped, IntPtr waitEvent)
    {
        _ = CancelIoEx(pipe, overlapped);
        if (WaitForSingleObject(waitEvent, SessionTimeoutMilliseconds) != WaitObject0)
        {
            ExitProcess(16);
        }
        _ = GetOverlappedResult(pipe, overlapped, out _, false);
    }

    private static bool TryBindSameTokenUser(IntPtr pipe, out bool sameTokenUser)
    {
        sameTokenUser = false;
        if (!GetNamedPipeClientProcessId(pipe, out uint clientProcessId) || clientProcessId == 0)
        {
            return false;
        }
        if (!ImpersonateNamedPipeClient(pipe))
        {
            return false;
        }
        IntPtr clientToken = IntPtr.Zero;
        bool compared = false;
        try
        {
            if (!OpenThreadToken(GetCurrentThread(), TokenQuery, true, out clientToken))
            {
                return false;
            }
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out IntPtr helperToken))
            {
                return false;
            }
            try
            {
                compared = TryEqualTokenUsers(clientToken, helperToken, out sameTokenUser);
            }
            finally
            {
                _ = CloseHandle(helperToken);
            }
        }
        finally
        {
            if (clientToken != IntPtr.Zero) _ = CloseHandle(clientToken);
            if (!RevertToSelf()) compared = false;
        }
        return compared;
    }

    private static bool TryEqualTokenUsers(IntPtr firstToken, IntPtr secondToken, out bool equal)
    {
        equal = false;
        IntPtr firstBuffer = IntPtr.Zero;
        IntPtr secondBuffer = IntPtr.Zero;
        try
        {
            if (!TryGetTokenUser(firstToken, out firstBuffer) || !TryGetTokenUser(secondToken, out secondBuffer))
            {
                return false;
            }
            IntPtr firstSid = Marshal.ReadIntPtr(firstBuffer);
            IntPtr secondSid = Marshal.ReadIntPtr(secondBuffer);
            if (firstSid == IntPtr.Zero || secondSid == IntPtr.Zero || !IsValidSid(firstSid) || !IsValidSid(secondSid))
            {
                return false;
            }
            equal = EqualSid(firstSid, secondSid);
            return true;
        }
        finally
        {
            if (firstBuffer != IntPtr.Zero) Marshal.FreeHGlobal(firstBuffer);
            if (secondBuffer != IntPtr.Zero) Marshal.FreeHGlobal(secondBuffer);
        }
    }

    private static bool TryGetTokenUser(IntPtr token, out IntPtr buffer)
    {
        buffer = IntPtr.Zero;
        _ = GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out uint length);
        if (length == 0 || length > 65536)
        {
            return false;
        }
        buffer = Marshal.AllocHGlobal(checked((int)length));
        if (!GetTokenInformation(token, TokenUser, buffer, length, out uint returnedLength) || returnedLength != length)
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            return false;
        }
        return true;
    }

    private static bool WriteAll(IntPtr pipe, byte[] bytes)
    {
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            return WriteMessageWithDeadline(pipe, buffer, (uint)bytes.Length);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool WriteMessageWithDeadline(IntPtr pipe, IntPtr buffer, uint length)
    {
        IntPtr waitEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (waitEvent == IntPtr.Zero)
        {
            return false;
        }
        IntPtr overlapped = CreateOverlapped(waitEvent);
        try
        {
            if (WriteFile(pipe, buffer, length, out uint written, overlapped))
            {
                return written == length;
            }
            if (Marshal.GetLastWin32Error() != ErrorIoPending)
            {
                return false;
            }
            if (WaitForSingleObject(waitEvent, SessionTimeoutMilliseconds) != WaitObject0)
            {
                CancelAndDrainOrExit(pipe, overlapped, waitEvent);
                return false;
            }
            return GetOverlappedResult(pipe, overlapped, out written, false) && written == length;
        }
        finally
        {
            Marshal.FreeHGlobal(overlapped);
            _ = CloseHandle(waitEvent);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
        uint outBufferSize, uint inBufferSize, uint defaultTimeout, IntPtr securityAttributes);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr EventHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DisconnectNamedPipe(IntPtr pipe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytesToRead, out uint bytesRead,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(IntPtr handle, IntPtr buffer, uint bytesToWrite, out uint bytesWritten,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr eventAttributes, [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(IntPtr handle, IntPtr overlapped,
        out uint bytesTransferred, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(IntPtr handle, IntPtr overlapped);

    [DllImport("kernel32.dll")]
    private static extern void ExitProcess(uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr threadHandle, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateNamedPipeClient(IntPtr pipeHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
        uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr firstSid, IntPtr secondSid);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);
}
