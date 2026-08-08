using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
    private const uint ApplyIoTimeoutMilliseconds = 30000;
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private const string ExpectedServerResponse =
        "{\"schema_version\":1,\"local_transport\":true,\"remote_clients_rejected\":true," +
        "\"first_instance\":true,\"explicit_pipe_dacl_verified\":true," +
        "\"service_sid_ace_verified\":true,\"authenticated_client_narrow_access_ace_verified\":true," +
        "\"client_pid_bound\":true,\"caller_token_bound\":true," +
        "\"helper_token_bound\":true,\"same_token_user\":true,\"different_principal\":false," +
        "\"authorization_denied\":true}\n";
    private const string ExpectedServiceDenialResponse =
        "{\"schema_version\":1,\"local_transport\":true,\"remote_clients_rejected\":true," +
        "\"first_instance\":true,\"explicit_pipe_dacl_verified\":true," +
        "\"service_identity_self_verified\":true,\"client_pid_bound\":true," +
        "\"caller_token_bound\":true,\"helper_token_bound\":true," +
        "\"same_token_user\":false,\"different_principal\":true," +
        "\"target_acl_evidence_complete\":false,\"manifest_executor_absent\":true," +
        "\"authorization_denied\":true}\n";
    private const string ClientReport =
        "{\"schema_version\":1,\"narrow_pipe_rights\":true,\"create_pipe_instance_right_absent\":true," +
        "\"response_schema_exact\":true,\"server_identity_verified\":false," +
        "\"authorization_denied\":true}\n";
    private const string ServiceDenialClientReport =
        "{\"schema_version\":1,\"narrow_pipe_rights\":true,\"create_pipe_instance_right_absent\":true," +
        "\"response_schema_exact\":true,\"different_principal\":true,\"authorization_denied\":true}\n";

    internal static int Run(string mode, string nonce)
    {
        return Run(mode, nonce, launcherPath: null);
    }

    internal static int RunServiceApply(string nonce, string launcherPath)
    {
        return Run("service-apply", nonce, launcherPath);
    }

    internal static int Run(string mode, string nonce, string? launcherPath)
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
                "valid" or "service-denial" or "service-apply" or "no-ack" or "unread" => nonce + "\n",
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
            if (mode != "valid" && mode != "service-denial" && mode != "service-apply" && mode != "no-ack")
            {
                return 0;
            }
            if (mode == "service-denial" || mode == "service-apply")
            {
                if (!ReadMessage(pipe, 4096, out byte[] serviceResponse) ||
                    !LooksLikeServiceDenial(Encoding.ASCII.GetString(serviceResponse)))
                {
                    return 23;
                }
            }
            else if (!ReadExact(pipe, Encoding.ASCII.GetByteCount(ExpectedServerResponse), out byte[] response) ||
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
            if (mode == "service-apply")
            {
                return CompleteServiceApply(pipe, launcherPath);
            }
            Console.Out.Write(mode == "service-denial" ? ServiceDenialClientReport : ClientReport);
            return 0;
        }
        finally
        {
            ClosePipe(pipe);
        }
    }

    private static int CompleteServiceApply(IntPtr pipe, string? launcherPath)
    {
        if (string.IsNullOrEmpty(launcherPath) || launcherPath.Length > 512)
        {
            return 26;
        }
        if (!TryReadLauncherBytes(launcherPath, out byte[] launcherBytes))
        {
            return 26;
        }
        if (launcherBytes.Length < 1 || launcherBytes.Length > 1024 * 1024)
        {
            return 26;
        }

        string digest = DisposableFirstInstallApply.Sha256Hex(launcherBytes);
        string authJson =
            "{\"protocol_version\":1,\"request_id\":\"reqapply000001\",\"operation\":\"apply_disposable_manifest\"," +
            "\"workspace\":{\"platform\":\"win32\",\"root_digest\":\"" + digest +
            "\",\"marker_nonce\":\"" + digest + "\"},\"manifest_digest\":\"" + digest +
            "\",\"launcher\":{\"sha256\":\"" + digest + "\",\"byte_length\":" + launcherBytes.Length + "}}";
        if (!WriteExact(pipe, Encoding.UTF8.GetBytes(authJson), ApplyIoTimeoutMilliseconds))
        {
            return 27;
        }
        if (!WriteExact(pipe, Encoding.ASCII.GetBytes(launcherBytes.Length.ToString()), ApplyIoTimeoutMilliseconds))
        {
            return 27;
        }
        if (!WriteExact(pipe, launcherBytes, ApplyIoTimeoutMilliseconds))
        {
            return 27;
        }
        if (!ReadMessage(pipe, 4096, out byte[] applyResponse, ApplyIoTimeoutMilliseconds))
        {
            return 28;
        }
        Console.Out.Write(Encoding.ASCII.GetString(applyResponse));
        string text = Encoding.ASCII.GetString(applyResponse);
        return text.Contains("\"applied\":true", StringComparison.Ordinal) &&
            text.Contains("\"helper_vault_free\":true", StringComparison.Ordinal) &&
            text.Contains("\"paths_created\":5", StringComparison.Ordinal)
            ? 0
            : 29;
    }

    private static bool TryReadLauncherBytes(string path, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        IntPtr file = CreateFile(path, GenericRead, 1 /* FILE_SHARE_READ */, IntPtr.Zero,
            OpenExisting, 0, IntPtr.Zero);
        if (file == InvalidHandleValue)
        {
            return false;
        }
        try
        {
            if (!GetFileSizeEx(file, out long size) || size < 1 || size > 1024 * 1024)
            {
                return false;
            }
            bytes = new byte[(int)size];
            IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                if (!ReadFile(file, buffer, (uint)bytes.Length, out uint read, IntPtr.Zero) ||
                    read != bytes.Length)
                {
                    return false;
                }
                Marshal.Copy(buffer, bytes, 0, bytes.Length);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            _ = CloseHandle(file);
        }
    }

    internal static bool TryAttestDifferentPrincipal(IntPtr pipe)
    {
        byte[] nonceBytes = new byte[32];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = Convert.ToHexString(nonceBytes).ToLowerInvariant();
        if (!WriteExact(pipe, Encoding.ASCII.GetBytes(nonce + "\n")))
        {
            return false;
        }
        if (!ReadMessage(pipe, 4096, out byte[] serviceResponse) ||
            !LooksLikeServiceDenial(Encoding.ASCII.GetString(serviceResponse)))
        {
            return false;
        }
        // Best-effort ack so the service loop can recycle cleanly.
        _ = WriteExact(pipe, Encoding.ASCII.GetBytes("ack\n"));
        return true;
    }

    private static bool WriteExact(IntPtr pipe, byte[] bytes, uint timeoutMilliseconds = IoTimeoutMilliseconds)
    {
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            return RunOverlapped(pipe, buffer, (uint)bytes.Length, false, out uint written, timeoutMilliseconds) &&
                written == bytes.Length;
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

    private static bool ReadMessage(IntPtr pipe, int maxLength, out byte[] bytes,
        uint timeoutMilliseconds = IoTimeoutMilliseconds)
    {
        bytes = Array.Empty<byte>();
        IntPtr buffer = Marshal.AllocHGlobal(maxLength);
        try
        {
            if (!RunOverlapped(pipe, buffer, (uint)maxLength, true, out uint read, timeoutMilliseconds) ||
                read < 1 || read > maxLength)
            {
                return false;
            }
            bytes = new byte[read];
            Marshal.Copy(buffer, bytes, 0, (int)read);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool LooksLikeServiceDenial(string text)
    {
        return text.Contains("\"authorization_denied\":true", StringComparison.Ordinal) &&
            text.Contains("\"different_principal\":true", StringComparison.Ordinal) &&
            text.Contains("\"manifest_executor_absent\":", StringComparison.Ordinal);
    }

    internal static bool TryOpenPipe(out IntPtr pipe)
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

    internal static void ClosePipe(IntPtr pipe)
    {
        if (pipe != InvalidHandleValue && pipe != IntPtr.Zero) _ = CloseHandle(pipe);
    }

    private static bool RunOverlapped(IntPtr pipe, IntPtr buffer, uint length, bool read, out uint transferred,
        uint timeoutMilliseconds = IoTimeoutMilliseconds)
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
            if (WaitForSingleObject(waitEvent, timeoutMilliseconds) != WaitObject0)
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSizeEx(IntPtr file, out long fileSize);

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
