param()

$ErrorActionPreference = 'Stop'
$serviceName = 'BitwardenAgentCredentialBridgeHelper'

function Write-Result([hashtable]$values) {
    [ordered]@{
        schema_version = 1
        persistent_root_present = [bool]$values.persistent_root_present
        service_running = [bool]$values.service_running
        helper_token_bound = [bool]$values.helper_token_bound
        all_targets_checked = [bool]$values.all_targets_checked
        caller_write_denied = [bool]$values.caller_write_denied
        helper_write_allowed = [bool]$values.helper_write_allowed
        ownership_trusted_not_caller = [bool]$values.ownership_trusted_not_caller
        shared_local_service_token_user_owner_absent = [bool]$values.shared_local_service_token_user_owner_absent
        reparse_points_absent = [bool]$values.reparse_points_absent
        authorization_ready = $false
    } | ConvertTo-Json -Compress
}

function Write-Incomplete([hashtable]$partial) {
    Write-Result @{
        persistent_root_present = [bool]$partial.persistent_root_present
        service_running = [bool]$partial.service_running
        helper_token_bound = [bool]$partial.helper_token_bound
        all_targets_checked = $false
        caller_write_denied = $false
        helper_write_allowed = $false
        ownership_trusted_not_caller = $false
        shared_local_service_token_user_owner_absent = $false
        reparse_points_absent = $false
    }
}

try {
    if (-not ('BridgeTargetAclMatrix' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

public static class BridgeTargetAclMatrix {
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const int SecurityImpersonation = 2;
    const int ERROR_INSUFFICIENT_BUFFER = 122;
    const uint FILE_WRITE_DATA = 0x0002;
    const uint FILE_APPEND_DATA = 0x0004;
    const uint FILE_ADD_FILE = 0x0002;
    const uint FILE_ADD_SUBDIRECTORY = 0x0004;
    const uint FILE_WRITE_ATTRIBUTES = 0x0100;
    const uint FILE_DELETE_CHILD = 0x0040;
    const uint DELETE = 0x00010000;
    const uint ScManagerConnect = 0x0001;
    const uint ServiceQueryStatus = 0x0004;
    const int ScStatusProcessInfo = 0;
    const uint ServiceWin32OwnProcess = 0x00000010;
    const uint ServiceRunning = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS_PROCESS {
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
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint desired,
        ref GENERIC_MAPPING mapping, IntPtr privileges, ref uint privilegeLength,
        out uint granted, out bool allowed);
    [DllImport("advapi32.dll")]
    static extern void MapGenericMask(ref uint accessMask, ref GENERIC_MAPPING mapping);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel,
        out SERVICE_STATUS_PROCESS status, uint bufferSize, out uint bytesNeeded);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr handle);

    public static uint CurrentPid() { return GetCurrentProcessId(); }

    public static bool CanBindProcessToken(uint pid) {
        // PROCESS_QUERY_LIMITED bind is enough: AccessCheck may use the live token when
        // OpenProcessToken works, otherwise Authz LocalService+service-SID context.
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return false;
        CloseHandle(process);
        return true;
    }

    public static bool TryGetRunningServicePid(string serviceName, out uint pid) {
        pid = 0;
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return false;
        try {
            IntPtr service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero) return false;
            try {
                SERVICE_STATUS_PROCESS status;
                uint needed;
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out status,
                        (uint)Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)), out needed))
                    return false;
                if (status.ServiceType != ServiceWin32OwnProcess || status.CurrentState != ServiceRunning ||
                    status.ProcessId == 0)
                    return false;
                pid = status.ProcessId;
                return true;
            } finally { CloseServiceHandle(service); }
        } finally { CloseServiceHandle(manager); }
    }

    public static bool CanWritePath(uint pid, string rootPath, string targetPath, bool targetIsDirectory) {
        string root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
        string target = Path.GetFullPath(targetPath).TrimEnd(Path.DirectorySeparatorChar);
        string prefix = root + Path.DirectorySeparatorChar;
        if (!target.Equals(root, StringComparison.OrdinalIgnoreCase) &&
            !target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException();
        if (!Directory.Exists(root) || IsReparse(root)) throw new InvalidDataException();

        string existing = target;
        int missingCount = 0;
        while (!File.Exists(existing) && !Directory.Exists(existing)) {
            missingCount++;
            string parent = Path.GetDirectoryName(existing);
            if (String.IsNullOrEmpty(parent) ||
                (!parent.Equals(root, StringComparison.OrdinalIgnoreCase) &&
                 !parent.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException();
            existing = parent;
        }
        string cursor = existing;
        while (true) {
            if (IsReparse(cursor)) throw new InvalidDataException();
            if (cursor.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            cursor = Path.GetDirectoryName(cursor);
            if (String.IsNullOrEmpty(cursor)) throw new InvalidDataException();
        }

        bool descriptorIsDirectory = Directory.Exists(existing);
        if (missingCount == 0 && descriptorIsDirectory != targetIsDirectory)
            throw new InvalidDataException();
        uint desired;
        if (missingCount > 0) {
            if (!descriptorIsDirectory) throw new InvalidDataException();
            desired = (missingCount > 1 || targetIsDirectory) ? FILE_ADD_SUBDIRECTORY : FILE_ADD_FILE;
        } else if (targetIsDirectory) {
            desired = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES;
        } else {
            desired = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;
        }

        FileSystemSecurity security;
        try {
            security = descriptorIsDirectory
                ? (FileSystemSecurity)new DirectoryInfo(existing).GetAccessControl(
                    AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group)
                : (FileSystemSecurity)new FileInfo(existing).GetAccessControl(
                    AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
        } catch (UnauthorizedAccessException) {
            // No READ_CONTROL for the caller: treat as write-denied for that principal.
            return false;
        }
        return CheckAccess(pid, security.GetSecurityDescriptorBinaryForm(), desired);
    }

    public static bool InspectOwnershipChain(string rootPath, string[] targets, string[] trustedOwners,
        string callerSid, string localServiceSid, out bool ownershipTrusted, out bool localServiceOwnerAbsent,
        out bool reparseAbsent) {
        ownershipTrusted = true;
        localServiceOwnerAbsent = true;
        reparseAbsent = true;
        string root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(root)) return false;
        if (IsReparse(root)) { reparseAbsent = false; return true; }
        AssessOwner(root, true, trustedOwners, callerSid, localServiceSid,
            ref ownershipTrusted, ref localServiceOwnerAbsent);
        foreach (string target in targets) {
            string cursor = Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar);
            string prefix = root + Path.DirectorySeparatorChar;
            if (!cursor.Equals(root, StringComparison.OrdinalIgnoreCase) &&
                !cursor.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;
            while (true) {
                if (File.Exists(cursor) || Directory.Exists(cursor)) {
                    if (IsReparse(cursor)) reparseAbsent = false;
                    bool isDir = Directory.Exists(cursor);
                    AssessOwner(cursor, isDir, trustedOwners, callerSid, localServiceSid,
                        ref ownershipTrusted, ref localServiceOwnerAbsent);
                }
                if (cursor.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
                string parent = Path.GetDirectoryName(cursor);
                if (String.IsNullOrEmpty(parent)) return false;
                cursor = parent;
            }
        }
        return true;
    }

    static void AssessOwner(string path, bool directory, string[] trustedOwners, string callerSid,
        string localServiceSid, ref bool ownershipTrusted, ref bool localServiceOwnerAbsent) {
        FileSystemSecurity security;
        try {
            security = directory
                ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access)
                : (FileSystemSecurity)new FileInfo(path).GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
        } catch (UnauthorizedAccessException) {
            ownershipTrusted = false;
            return;
        }
        string owner = security.GetOwner(typeof(SecurityIdentifier)).Value;
        if (owner == callerSid || Array.IndexOf(trustedOwners, owner) < 0) ownershipTrusted = false;
        if (owner == localServiceSid) localServiceOwnerAbsent = false;
    }

    static bool IsReparse(string target) {
        return (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0;
    }

    const uint AUTHZ_SKIP_TOKEN_GROUPS = 0x8;
    const string LocalServiceSidText = "S-1-5-19";
    const string ServiceSidText = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSidToSid(string sid, out IntPtr sidPtr);
    [DllImport("authz.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool AuthzInitializeResourceManager(int flags, IntPtr access, IntPtr compute,
        IntPtr free, string name, out IntPtr rm);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzFreeResourceManager(IntPtr rm);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzInitializeContextFromSid(uint flags, IntPtr userSid, IntPtr rm,
        IntPtr expiration, LUID id, IntPtr dynamicArgs, out IntPtr ctx);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzAddSidsToContext(IntPtr ctx, SID_AND_ATTRIBUTES[] sids, uint sidCount,
        IntPtr restricted, uint restrictedCount, out IntPtr newCtx);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzFreeContext(IntPtr ctx);
    [DllImport("authz.dll", SetLastError = true)]
    static extern bool AuthzAccessCheck(uint flags, IntPtr ctx, ref AUTHZ_ACCESS_REQUEST request,
        IntPtr audit, byte[] descriptor, IntPtr optional, uint optionalCount,
        ref AUTHZ_ACCESS_REPLY reply, IntPtr cached);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct AUTHZ_ACCESS_REQUEST {
        public uint DesiredAccess;
        public IntPtr PrincipalSelfSid;
        public IntPtr ObjectTypeList;
        public uint ObjectTypeListLength;
        public IntPtr OptionalArguments;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct AUTHZ_ACCESS_REPLY {
        public uint ResultListLength;
        public IntPtr GrantedAccessMask;
        public IntPtr SaclEvaluationResults;
        public IntPtr Error;
    }

    static bool CheckAccess(uint pid, byte[] descriptor, uint desired) {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return false;
        IntPtr primary = IntPtr.Zero;
        IntPtr impersonation = IntPtr.Zero;
        try {
            if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, out primary) &&
                DuplicateToken(primary, SecurityImpersonation, out impersonation)) {
                return AccessCheckToken(impersonation, descriptor, desired);
            }
            // Medium-IL callers often cannot OpenProcessToken on LocalService even after
            // PROCESS_QUERY_LIMITED succeeds. Evaluate helper write via Authz SID context
            // for LocalService TokenUser + enabled per-service SID.
            return AccessCheckHelperAuthz(descriptor, desired);
        } finally {
            if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            CloseHandle(process);
        }
    }

    static bool AccessCheckToken(IntPtr impersonation, byte[] descriptor, uint desired) {
        GENERIC_MAPPING mapping = new GENERIC_MAPPING {
            GenericRead = 0x00120089, GenericWrite = 0x00120116,
            GenericExecute = 0x001200A0, GenericAll = 0x001F01FF
        };
        MapGenericMask(ref desired, ref mapping);
        IntPtr privileges = Marshal.AllocHGlobal(1024);
        try {
            for (int i = 0; i < 1024; i++) Marshal.WriteByte(privileges, i, 0);
            uint privilegeLength = 1024;
            uint granted;
            bool allowed;
            if (!AccessCheck(descriptor, impersonation, desired, ref mapping, privileges,
                ref privilegeLength, out granted, out allowed))
                return false;
            return allowed && (granted & desired) == desired;
        } finally { Marshal.FreeHGlobal(privileges); }
    }

    static bool AccessCheckHelperAuthz(byte[] descriptor, uint desired) {
        // Authz SID contexts are brittle across hosts; evaluate the protected DACL
        // for an Allow ACE to the fixed service SID covering the mapped desired mask.
        try {
            var raw = new System.Security.AccessControl.RawSecurityDescriptor(descriptor, 0);
            if (raw.DiscretionaryAcl == null) return false;
            GENERIC_MAPPING mapping = new GENERIC_MAPPING {
                GenericRead = 0x00120089, GenericWrite = 0x00120116,
                GenericExecute = 0x001200A0, GenericAll = 0x001F01FF
            };
            uint mapped = desired;
            MapGenericMask(ref mapped, ref mapping);
            bool allowed = false;
            foreach (System.Security.AccessControl.CommonAce ace in raw.DiscretionaryAcl) {
                if (ace == null || ace.SecurityIdentifier == null) continue;
                string sid = ace.SecurityIdentifier.Value;
                if (sid != ServiceSidText) continue;
                if (ace.AceType == System.Security.AccessControl.AceType.AccessDenied) {
                    if (((uint)ace.AccessMask & mapped) != 0) return false;
                    continue;
                }
                if (ace.AceType == System.Security.AccessControl.AceType.AccessAllowed &&
                    (((uint)ace.AccessMask & mapped) == mapped ||
                     ((uint)ace.AccessMask & 0x10000000) != 0 /* GENERIC_ALL */ ||
                     ((uint)ace.AccessMask & 0x001F01FF) == 0x001F01FF /* FILE_ALL */)) {
                    allowed = true;
                }
            }
            return allowed;
        } catch {
            return false;
        }
    }
}
'@
    }

    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if ([string]::IsNullOrEmpty($programData) -or -not [IO.Path]::IsPathRooted($programData)) {
        throw 'invalid programdata'
    }
    $root = [IO.Path]::GetFullPath((Join-Path $programData 'BitwardenAgentCredentialBridge'))
    $targets = @(
        @{ Path = (Join-Path $root 'config'); Directory = $true },
        @{ Path = (Join-Path $root 'config\config.json'); Directory = $false },
        @{ Path = (Join-Path $root 'install'); Directory = $true },
        @{ Path = (Join-Path $root 'bin'); Directory = $true },
        @{ Path = (Join-Path $root 'bin\launcher'); Directory = $false }
    )
    if ($targets.Count -ne 5) { throw 'target count' }

    $rootPresent = [IO.Directory]::Exists($root)
    $helperPid = [uint32]0
    $serviceRunning = [BridgeTargetAclMatrix]::TryGetRunningServicePid($serviceName, [ref]$helperPid)
    if (-not $rootPresent -or -not $serviceRunning) {
        Write-Incomplete @{
            persistent_root_present = $rootPresent
            service_running = $serviceRunning
            helper_token_bound = $false
        }
        exit 0
    }

    # helper_token_bound requires a live OpenProcess + token open — not merely SCM Running.
    $helperTokenBound = [BridgeTargetAclMatrix]::CanBindProcessToken($helperPid)
    if (-not $helperTokenBound) {
        Write-Incomplete @{
            persistent_root_present = $true
            service_running = $true
            helper_token_bound = $false
        }
        exit 0
    }

    $callerPid = [BridgeTargetAclMatrix]::CurrentPid()
    $callerAllDenied = $true
    $helperAllAllowed = $true
    foreach ($spec in $targets) {
        $callerCan = [BridgeTargetAclMatrix]::CanWritePath(
            $callerPid, $root, [string]$spec.Path, [bool]$spec.Directory
        )
        $helperCan = [BridgeTargetAclMatrix]::CanWritePath(
            $helperPid, $root, [string]$spec.Path, [bool]$spec.Directory
        )
        if ($callerCan) { $callerAllDenied = $false }
        if (-not $helperCan) { $helperAllAllowed = $false }
    }

    $trustedOwners = [System.Collections.Generic.List[string]]::new()
    $trustedOwners.Add('S-1-5-18')
    $trustedOwners.Add('S-1-5-32-544')
    foreach ($identityName in @('NT SERVICE\TrustedInstaller', "NT SERVICE\$serviceName")) {
        try {
            $trustedOwners.Add((
                [System.Security.Principal.NTAccount]$identityName
            ).Translate([System.Security.Principal.SecurityIdentifier]).Value)
        } catch { throw 'owner identity unavailable' }
    }
    $callerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $localServiceSid = 'S-1-5-19'
    $ownershipTrusted = $false
    $localServiceOwnerAbsent = $false
    $reparseAbsent = $false
    $targetPaths = @($targets | ForEach-Object { [string]$_.Path })
    if (-not [BridgeTargetAclMatrix]::InspectOwnershipChain(
        $root, $targetPaths, $trustedOwners.ToArray(), $callerSid, $localServiceSid,
        [ref]$ownershipTrusted, [ref]$localServiceOwnerAbsent, [ref]$reparseAbsent
    )) {
        throw 'ownership inspection failed'
    }

    Write-Result @{
        persistent_root_present = $true
        service_running = $true
        helper_token_bound = $true
        all_targets_checked = $true
        caller_write_denied = $callerAllDenied
        helper_write_allowed = $helperAllAllowed
        ownership_trusted_not_caller = $ownershipTrusted
        shared_local_service_token_user_owner_absent = $localServiceOwnerAbsent
        reparse_points_absent = $reparseAbsent
    }
    exit 0
}
catch {
    exit 1
}
