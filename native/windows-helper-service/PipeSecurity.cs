using System;
using System.Runtime.InteropServices;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class PipeSecurity
{
    private const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    private const string SecurityDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;" + ServiceSid + ")(A;;0x12018b;;;AU)";
    private const uint SddlRevision1 = 1;
    private const int SeKernelObject = 6;
    private const uint DaclSecurityInformation = 0x00000004;
    private const ushort SeDaclProtected = 0x1000;
    private const int AclSizeInformation = 2;
    private const byte AccessAllowedAceType = 0;
    private const uint FileAllAccess = 0x001F01FF;
    private const uint PipeClientNarrowAccess = 0x0012018B;

    internal static bool TryCreateAttributes(out IntPtr attributes, out IntPtr descriptor)
    {
        attributes = IntPtr.Zero;
        descriptor = IntPtr.Zero;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                SecurityDescriptor, SddlRevision1, out descriptor, out _))
        {
            return false;
        }
        attributes = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityAttributes>());
        Marshal.StructureToPtr(new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            SecurityDescriptor = descriptor,
            InheritHandle = 0,
        }, attributes, false);
        return true;
    }

    internal static void FreeAttributes(IntPtr attributes, IntPtr descriptor)
    {
        if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
        if (descriptor != IntPtr.Zero) _ = LocalFree(descriptor);
    }

    internal static bool HasExpectedKernelDacl(IntPtr pipe)
    {
        uint result = GetSecurityInfo(pipe, SeKernelObject, DaclSecurityInformation,
            out _, out _, out IntPtr dacl, out _, out IntPtr descriptor);
        if (result != 0 || dacl == IntPtr.Zero || descriptor == IntPtr.Zero)
        {
            if (descriptor != IntPtr.Zero) _ = LocalFree(descriptor);
            return false;
        }
        try
        {
            if (!GetSecurityDescriptorControl(descriptor, out ushort control, out _) ||
                (control & SeDaclProtected) == 0 ||
                !GetAclInformation(dacl, out AclSize size, (uint)Marshal.SizeOf<AclSize>(), AclSizeInformation) ||
                size.AceCount != 3)
            {
                return false;
            }
            return AceMatches(dacl, size.AclBytesInUse, 0, "S-1-5-18", FileAllAccess) &&
                AceMatches(dacl, size.AclBytesInUse, 1, ServiceSid, FileAllAccess) &&
                AceMatches(dacl, size.AclBytesInUse, 2, "S-1-5-11", PipeClientNarrowAccess);
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    private static bool AceMatches(IntPtr dacl, uint aclBytesInUse, uint index, string expectedSid, uint expectedMask)
    {
        if (!GetAce(dacl, index, out IntPtr ace) || ace == IntPtr.Zero ||
            Marshal.ReadByte(ace) != AccessAllowedAceType || Marshal.ReadByte(ace, 1) != 0)
        {
            return false;
        }
        ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
        long aceOffset = ace.ToInt64() - dacl.ToInt64();
        if (aceOffset < 0 || aceSize < 8 || aceOffset + aceSize > aclBytesInUse)
        {
            return false;
        }
        uint mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
        if (mask != expectedMask)
        {
            return false;
        }
        if (!ConvertStringSidToSid(expectedSid, out IntPtr expectedSidPointer))
        {
            return false;
        }
        try
        {
            IntPtr actualSid = IntPtr.Add(ace, 8);
            if (!IsValidSid(actualSid))
            {
                return false;
            }
            uint sidLength = GetLengthSid(actualSid);
            return sidLength > 0 && aceSize == 8 + sidLength && EqualSid(actualSid, expectedSidPointer);
        }
        finally
        {
            _ = LocalFree(expectedSidPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AclSize
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string stringSecurityDescriptor,
        uint revision, out IntPtr securityDescriptor, out uint securityDescriptorSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint securityInformation,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorControl(IntPtr securityDescriptor, out ushort control,
        out uint revision);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(IntPtr acl, out AclSize information, uint informationLength,
        int informationClass);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAce(IntPtr acl, uint aceIndex, out IntPtr ace);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr firstSid, IntPtr secondSid);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
