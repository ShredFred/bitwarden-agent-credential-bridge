using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class Program
{
    private const string ServiceName = "BitwardenAgentCredentialBridgeHelper";
    private const int ErrorFailedServiceControllerConnect = 1063;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const uint ServiceControlInterrogate = 0x00000004;
    private const uint ErrorCallNotImplemented = 120;
    private const uint ErrorServiceSpecificError = 1066;
    private const uint ServiceIdentityFailure = 1;
    private const uint ServicePipeFailure = 2;

    private static readonly ManualResetEventSlim StopEvent = new(false);
    private static readonly ServiceMainDelegate ServiceMainRoot = ServiceMain;
    private static readonly HandlerExDelegate HandlerRoot = Handler;
    private static IntPtr _statusHandle;
    private static uint _checkpoint;
    private static int _serviceFailure;
    private static readonly object StatusLock = new();

    public static int Main(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "--self-test", StringComparison.Ordinal))
        {
            Console.Out.Write("{\"schema_version\":1,\"platform_win32\":true,\"service_name_bound\":true,\"scm_entrypoint_compiled\":true,\"scm_lifecycle_live_verified\":false,\"console_denial_pipe_compiled\":true,\"explicit_pipe_dacl_compiled\":true,\"server_identity_verifier_compiled\":true,\"service_identity_self_check_compiled\":true,\"service_pipe_activation_compiled\":true,\"service_pipe_activation_live_verified\":false,\"service_authorize_schema_compiled\":true,\"manifest_executor_absent\":false,\"network_stack_absent\":true,\"vault_client_absent\":true,\"install_gate_eligible\":false}\n");
            return 0;
        }
        if (args.Length == 1 && string.Equals(args[0], "--self-test-authorize-schema", StringComparison.Ordinal))
        {
            return AuthorizeSchemaProbe.RunSelfTestFromStdin();
        }
        if (args.Length == 2 &&
            string.Equals(args[0], "--console-pipe-denial", StringComparison.Ordinal) &&
            DenialPipeProbe.IsCanonicalNonce(args[1]))
        {
            return DenialPipeProbe.Run(args[1]);
        }
        if (args.Length == 3 &&
            string.Equals(args[0], "--self-test-pipe-client", StringComparison.Ordinal) &&
            IsPipeClientMode(args[1]) && DenialPipeProbe.IsCanonicalNonce(args[2]))
        {
            return NativeDenialPipeClient.Run(args[1], args[2]);
        }
        if (args.Length == 4 &&
            string.Equals(args[0], "--self-test-pipe-client", StringComparison.Ordinal) &&
            string.Equals(args[1], "service-apply", StringComparison.Ordinal) &&
            DenialPipeProbe.IsCanonicalNonce(args[2]) &&
            args[3].Length > 0 && args[3].Length <= 512)
        {
            return NativeDenialPipeClient.RunServiceApply(args[2], args[3]);
        }
        if (args.Length == 3 &&
            string.Equals(args[0], "--self-test-pipe-server", StringComparison.Ordinal) &&
            (args[1] == "stall" || args[1] == "trailing") &&
            DenialPipeProbe.IsCanonicalNonce(args[2]))
        {
            return DenialPipeProbe.RunSelfTestServer(args[1], args[2]);
        }
        if (args.Length == 1 && string.Equals(args[0], "--verify-fixed-server-identity", StringComparison.Ordinal))
        {
            return NativeServerIdentityVerifier.Run();
        }
        if (args.Length != 0)
        {
            return 2;
        }

        ServiceTableEntry[] table =
        {
            new() { Name = ServiceName, Main = ServiceMainRoot },
            new() { Name = null, Main = null },
        };
        if (!StartServiceCtrlDispatcher(table))
        {
            return Marshal.GetLastWin32Error() == ErrorFailedServiceControllerConnect ? 3 : 4;
        }
        return _serviceFailure == 0 ? 0 : 5;
    }

    private static bool IsPipeClientMode(string value)
    {
        return value == "valid" || value == "service-denial" || value == "mismatch" || value == "partial" ||
            value == "crlf" || value == "oversize" || value == "idle" || value == "no-ack" || value == "unread";
    }

    private static void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        _ = argumentCount;
        _ = arguments;
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, HandlerRoot, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
        {
            _serviceFailure = Marshal.GetLastWin32Error();
            return;
        }
        if (!ReportStatus(ServiceStartPending, 0, 5000))
        {
            return;
        }
        if (!NativeServerIdentityVerifier.CurrentProcessHasExpectedServiceIdentity())
        {
            _serviceFailure = (int)ServiceIdentityFailure;
            _ = ReportStatus(ServiceStopped, 0, 0, ErrorServiceSpecificError, ServiceIdentityFailure);
            return;
        }
        if (!ReportStatus(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0)) return;
        int pipeResult = DenialPipeProbe.RunServiceLoop(StopEvent);
        if (pipeResult != 0)
        {
            _serviceFailure = pipeResult;
            _ = ReportStatus(ServiceStopped, 0, 0, ErrorServiceSpecificError, ServicePipeFailure);
            return;
        }
        _ = ReportStatus(ServiceStopped, 0, 0);
    }

    private static uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        _ = eventType;
        _ = eventData;
        _ = context;
        if (control == ServiceControlStop || control == ServiceControlShutdown)
        {
            _ = ReportStatus(ServiceStopPending, 0, 5000);
            StopEvent.Set();
            return 0;
        }
        if (control == ServiceControlInterrogate)
        {
            return 0;
        }
        return ErrorCallNotImplemented;
    }

    private static bool ReportStatus(uint state, uint acceptedControls, uint waitHint,
        uint win32ExitCode = 0, uint serviceSpecificExitCode = 0)
    {
        lock (StatusLock)
        {
            uint checkpoint = state == ServiceStartPending || state == ServiceStopPending
                ? unchecked(++_checkpoint)
                : 0;
            ServiceStatus status = new()
            {
                ServiceType = ServiceWin32OwnProcess,
                CurrentState = state,
                ControlsAccepted = acceptedControls,
                Win32ExitCode = win32ExitCode,
                ServiceSpecificExitCode = serviceSpecificExitCode,
                CheckPoint = checkpoint,
                WaitHint = waitHint,
            };
            if (!SetServiceStatus(_statusHandle, ref status))
            {
                _serviceFailure = Marshal.GetLastWin32Error();
                StopEvent.Set();
                return false;
            }
            return true;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
        public ServiceMainDelegate? Main;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerExDelegate(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(
        string serviceName,
        HandlerExDelegate handler,
        IntPtr context
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus serviceStatus);
}
