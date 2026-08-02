using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BitwardenAgentCredentialBridgeHelper;

/// <summary>
/// First-install-only, vault-free apply under the helper's own ProgramData-class
/// install root (parent of the running module). Creates five exclusive paths.
/// Parent ACLs are assumed already locked by the elevated installer.
/// </summary>
internal static class DisposableFirstInstallApply
{
    private const string EmptyConfig = "{\"version\":1,\"services\":{}}\n";

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

        try
        {
            if (Directory.Exists(configDir) || File.Exists(configFile) ||
                Directory.Exists(installRoot) || Directory.Exists(binDir) || File.Exists(launcher))
            {
                failureCode = "targets_not_absent";
                return false;
            }

            Directory.CreateDirectory(configDir);
            pathsCreated++;
            Directory.CreateDirectory(installRoot);
            pathsCreated++;
            Directory.CreateDirectory(binDir);
            pathsCreated++;

            WriteExclusiveFile(configFile, Encoding.UTF8.GetBytes(EmptyConfig));
            pathsCreated++;
            WriteExclusiveFile(launcher, launcherBytes);
            pathsCreated++;

            failureCode = "ok";
            return true;
        }
        catch
        {
            failureCode = "apply_exception";
            return false;
        }
    }

    private static void WriteExclusiveFile(string path, byte[] bytes)
    {
        using FileStream stream = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(true);
    }

    internal static string Sha256Hex(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
