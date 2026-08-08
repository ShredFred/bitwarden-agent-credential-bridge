using System;
using System.Runtime.InteropServices;

namespace BitwardenAgentCredentialBridgeHelper;

/// <summary>
/// Grants Authenticated Users PROCESS_QUERY_LIMITED_INFORMATION on the current
/// process so non-elevated Phase 9b/9c collectors can bind the LocalService token.
/// Called from ServiceMain after LocalService + service-SID identity is proven.
/// </summary>
internal static class ProcessQueryAcl
{
    private const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    private const uint SddlRevision1 = 1;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    // SYSTEM/Administrators/LocalService/service-SID strong rights; Authenticated Users
    // get PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION so OpenProcessToken
    // succeeds for non-elevated Phase 9b/9c collectors (QUERY_LIMITED alone is insufficient
    // for token open on this host).
    private const string ProcessSddl =
        "D:P(A;;0x1fffff;;;SY)(A;;0x1fffff;;;BA)(A;;0x1fffff;;;LS)(A;;0x1fffff;;;" + ServiceSid +
        ")(A;;0x1400;;;AU)";

    internal static bool TryGrantAuthenticatedUsersQueryLimited()
    {
        IntPtr process = GetCurrentProcess();
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                ProcessSddl, SddlRevision1, out IntPtr descriptor, out _))
        {
            return false;
        }
        try
        {
            // Prefer SetKernelObjectSecurity on the current process pseudo-handle.
            if (SetKernelObjectSecurity(
                    process,
                    DaclSecurityInformation | ProtectedDaclSecurityInformation,
                    descriptor))
            {
                return true;
            }
            // Fallback without PROTECTED bit (some hosts reject protected process DACLs).
            return SetKernelObjectSecurity(process, DaclSecurityInformation, descriptor);
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(
        IntPtr handle, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
