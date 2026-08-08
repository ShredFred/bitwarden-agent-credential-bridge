using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BitwardenAgentCredentialBridgeHelper;

/// <summary>
/// First-install-only, vault-free apply under the helper's own ProgramData-class
/// install root (parent of the running module). Creates five exclusive paths with
/// service-SID ownership and a narrow DACL at creation time (Phase 5h.54).
/// </summary>
internal static class DisposableFirstInstallApply
{
    private const string EmptyConfig = "{\"version\":1,\"services\":{}}\n";
    private const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    // Protected DACL: SYSTEM/Administrators/service SID full; Authenticated Users
    // read-only (probe READ_CONTROL). Owner is the per-service SID (never shared
    // LocalService TokenUser S-1-5-19).
    private const string TargetSddl =
        "O:" + ServiceSid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ServiceSid + ")(A;;FR;;;AU)";
    private const uint SddlRevision1 = 1;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareNone = 0;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagBackupSemantics = 0x02000000;

    internal static bool TryApplyFirstInstall(byte[] launcherBytes, out int pathsCreated, out string failureCode)
    {
        pathsCreated = 0;
        failureCode = "apply_failed";
        if (launcherBytes == null || launcherBytes.Length < 1 || launcherBytes.Length > 1024 * 1024)
        {
            failureCode = "invalid_launcher";
            return false;
        }

        string? module = Environment.ProcessPath;
        if (string.IsNullOrEmpty(module))
        {
            failureCode = "module_path_absent";
            return false;
        }
        string? root = Path.GetDirectoryName(module);
        if (string.IsNullOrEmpty(root) ||
            root.IndexOf("BitwardenAgentCredentialBridge", StringComparison.OrdinalIgnoreCase) < 0)
        {
            failureCode = "root_not_programdata_class";
            return false;
        }

        string configDir = Path.Combine(root, "config");
        string configFile = Path.Combine(configDir, "config.json");
        string installRoot = Path.Combine(root, "install");
        string binDir = Path.Combine(root, "bin");
        string launcher = Path.Combine(binDir, "launcher");

        IntPtr securityDescriptor = IntPtr.Zero;
        try
        {
            if (Directory.Exists(configDir) || File.Exists(configFile) ||
                Directory.Exists(installRoot) || Directory.Exists(binDir) || File.Exists(launcher))
            {
                failureCode = "targets_not_absent";
                return false;
            }

            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                    TargetSddl, SddlRevision1, out securityDescriptor, out _))
            {
                failureCode = "security_descriptor_invalid";
                return false;
            }

            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = securityDescriptor,
                InheritHandle = false,
            };

            if (!TryCreateExclusiveDirectory(configDir, ref attributes) ||
                !TryCreateExclusiveDirectory(installRoot, ref attributes) ||
                !TryCreateExclusiveDirectory(binDir, ref attributes))
            {
                failureCode = "directory_create_failed";
                return false;
            }
            pathsCreated = 3;

            if (!TryCreateExclusiveFile(configFile, Encoding.UTF8.GetBytes(EmptyConfig), ref attributes) ||
                !TryCreateExclusiveFile(launcher, launcherBytes, ref attributes))
            {
                failureCode = "file_create_failed";
                return false;
            }
            pathsCreated = 5;

            failureCode = "ok";
            return true;
        }
        catch
        {
            failureCode = "apply_exception";
            return false;
        }
        finally
        {
            if (securityDescriptor != IntPtr.Zero)
            {
                _ = LocalFree(securityDescriptor);
            }
        }
    }

    private static bool TryCreateExclusiveDirectory(string path, ref SecurityAttributes attributes)
    {
        if (!CreateDirectory(path, ref attributes))
        {
            return false;
        }
        // Re-open no-follow-ish with backup semantics and confirm ownership bits stick.
        IntPtr handle = CreateFile(
            path, GenericRead, FileShareNone, IntPtr.Zero, 3 /* OPEN_EXISTING */,
            FileFlagBackupSemantics, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return false;
        }
        _ = CloseHandle(handle);
        return true;
    }

    private static bool TryCreateExclusiveFile(string path, byte[] bytes, ref SecurityAttributes attributes)
    {
        IntPtr handle = CreateFile(
            path, GenericRead | GenericWrite, FileShareNone, ref attributes, CreateNew,
            FileAttributeNormal, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return false;
        }
        try
        {
            uint written = 0;
            if (!WriteFile(handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero) ||
                written != (uint)bytes.Length)
            {
                return false;
            }
            return FlushFileBuffers(handle);
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    internal static string Sha256Hex(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string pathName, ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName, uint desiredAccess, uint shareMode, ref SecurityAttributes securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(IntPtr file, byte[] buffer, uint numberOfBytesToWrite,
        out uint numberOfBytesWritten, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(IntPtr file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
