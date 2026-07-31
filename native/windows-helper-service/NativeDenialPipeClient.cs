using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class NativeDenialPipeClient
{
    private const string PipePath = @"\\.\pipe\BitwardenAgentCredentialBridgeHelper.v1.denial";
    private const uint GenericRead = 0x80000000;
    private const uint FileWriteData = 0x00000002;
    private const uint FileWriteAttributes = 0x00000100;
    private const uint OpenExisting = 3;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeReadModeMessage = 0x00000002;
    private const int ErrorFileNotFound = 2;
    private const int ErrorSemTimeout = 121;
    private const int ErrorPipeBusy = 231;
    private const int ErrorIoPending = 997;
    private const uint WaitObject0 = 0;
    private const uint IoTimeoutMilliseconds = 1500;
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private const string ExpectedServerResponse =
        "{\"schema_version\":1,\"local_transport\":true,\"remote_clients_rejected\":true," +
        "\"first_instance\":true,\"explicit_pipe_dacl_verified\":true," +
        "\"service_sid_ace_verified\":true,\"authenticated_client_narrow_access_ace_verified\":true," +
        "\"client_pid_bound\":true,\"caller_token_bound\":true," +
        "\"helper_token_bound\":true,\"same_token_user\":true,\"different_principal\":false," +
        "\"authorization_denied\":true}\n";
    private const string ClientReport =
        "{\"schema_version\":1,\"narrow_pipe_rights\":true,\"create_pipe_instance_right_absent\":true," +
        "\"response_schema_exact\":true,\"server_identity_verified\":false," +
        "\"authorization_denied\":true}\n";

    internal static int Run(string mode, string nonce)
    {
        if (!TryOpenPipe(out IntPtr pipe))
        {
            return 20;
        }
        try
        {
            if (mode == "idle")
            {
                Thread.Sleep(2500);
                return 0;
            }
            string request = mode switch
            {
                "valid" or "no-ack" or "unread" => nonce + "\n",
                "mismatch" => new string(nonce[0] == 'a' ? 'b' : 'a', 64) + "\n",
                "partial" => nonce[..8] + "\n",
                "crlf" => nonce + "\r\n",
                "oversize" => nonce + "\nextra\n",
                _ => string.Empty,
            };
            if (request.Length == 0 || !WriteExact(pipe, Encoding.ASCII.GetBytes(request)))
            {
                return 22;
            }
            if (mode == "unread")
            {
                Thread.Sleep(2500);
                return 0;
            }
            if (mode != "valid" && mode != "no-ack")
            {
                return 0;
            }
            if (!ReadExact(pipe, Encoding.ASCII.GetByteCount(ExpectedServerResponse), out byte[] response) ||
                Encoding.ASCII.GetString(response) != ExpectedServerResponse)
            {
                return 23;
            }
            if (mode == "no-ack")
            {
                Thread.Sleep(2500);
                return 0;
            }
            if (!WriteExact(pipe, Encoding.ASCII.GetBytes("ack\n")))
            {
                return 24;
            }
            Console.Out.Write(ClientReport);
            return 0;
        }
        finally
        {
            _ = CloseHandle(pipe);
        }
    }

    private static bool WriteExact(IntPtr pipe, byte[] bytes)
    {
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            return RunOverlapped(pipe, buffer, (uint)bytes.Length, false, out uint written) && written == bytes.Length;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ReadExact(IntPtr pipe, int length, out byte[] bytes)
    {
        bytes = new byte[length];
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!RunOverlapped(pipe, buffer, (uint)length, true, out uint read) || read != length)
            {
                return false;
            }
            Marshal.Copy(buffer, bytes, 0, length);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryOpenPipe(out IntPtr pipe)
    {
        pipe = InvalidHandleValue;
        long deadline = Environment.TickCount64 + 10000;
        while (Environment.TickCount64 < deadline)
        {
            if (!WaitNamedPipe(PipePath, 50))
            {
                int waitError = Marshal.GetLastWin32Error();
                if (waitError == ErrorFileNotFound || waitError == ErrorPipeBusy || waitError == ErrorSemTimeout)
                {
                    Thread.Sleep(20);
                    continue;
                }
                return false;
            }
            pipe = CreateFile(PipePath, GenericRead | FileWriteData | FileWriteAttributes, 0, IntPtr.Zero,
                OpenExisting, FileFlagOverlapped, IntPtr.Zero);
            if (pipe != InvalidHandleValue)
            {
                uint readMode = PipeReadModeMessage;
                if (SetNamedPipeHandleState(pipe, ref readMode, IntPtr.Zero, IntPtr.Zero))
                {
                    return true;
                }
                _ = CloseHandle(pipe);
                pipe = InvalidHandleValue;
                return false;
            }
            int openError = Marshal.GetLastWin32Error();
            if (openError != ErrorFileNotFound && openError != ErrorPipeBusy)
            {
                return false;
            }
            Thread.Sleep(20);
        }
        return false;
    }

    private static bool RunOverlapped(IntPtr pipe, IntPtr buffer, uint length, bool read, out uint transferred)
    {
        transferred = 0;
        IntPtr waitEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (waitEvent == IntPtr.Zero)
        {
            return false;
        }
        IntPtr overlapped = Marshal.AllocHGlobal(Marshal.SizeOf<NativeOverlapped>());
        Marshal.StructureToPtr(new NativeOverlapped { EventHandle = waitEvent }, overlapped, false);
        try
        {
            bool completed = read
                ? ReadFile(pipe, buffer, length, out transferred, overlapped)
                : WriteFile(pipe, buffer, length, out transferred, overlapped);
            if (completed)
            {
                return true;
            }
            if (Marshal.GetLastWin32Error() != ErrorIoPending)
            {
                return false;
            }
            if (WaitForSingleObject(waitEvent, IoTimeoutMilliseconds) != WaitObject0)
            {
                CancelAndDrainOrExit(pipe, overlapped, waitEvent);
                return false;
            }
            return GetOverlappedResult(pipe, overlapped, out transferred, false);
        }
        finally
        {
            Marshal.FreeHGlobal(overlapped);
            _ = CloseHandle(waitEvent);
        }
    }

    private static void CancelAndDrainOrExit(IntPtr pipe, IntPtr overlapped, IntPtr waitEvent)
    {
        _ = CancelIoEx(pipe, overlapped);
        if (WaitForSingleObject(waitEvent, IoTimeoutMilliseconds) != WaitObject0)
        {
            ExitProcess(25);
        }
        _ = GetOverlappedResult(pipe, overlapped, out _, false);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr EventHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipe(string name, uint timeout);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetNamedPipeHandleState(IntPtr pipe, ref uint mode,
        IntPtr maxCollectionCount, IntPtr collectDataTimeout);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytesToRead,
        out uint bytesRead, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(IntPtr handle, IntPtr buffer, uint bytesToWrite,
        out uint bytesWritten, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr eventAttributes, [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState, string? name);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(IntPtr handle, IntPtr overlapped,
        out uint bytesTransferred, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(IntPtr handle, IntPtr overlapped);

    [DllImport("kernel32.dll")]
    private static extern void ExitProcess(uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
