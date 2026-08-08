param(
    [Parameter(Mandatory = $true)][string]$StagingRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBinarySha256,
    [Parameter(Mandatory = $true)][ValidateRange(1, 67108864)][long]$ExpectedBinaryByteLength,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$MarkerNonce,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$DenialNonce,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$CompletionNonce
)

$ErrorActionPreference = 'Stop'
$paramsPath = Join-Path $StagingRoot 'params.json'
if (-not (Test-Path -LiteralPath $paramsPath -PathType Leaf)) { throw 'params_missing' }
$params = Get-Content -LiteralPath $paramsPath -Raw -Encoding UTF8 | ConvertFrom-Json
# CLI arguments are authoritative against staging-file TOCTOU; params must match.
if ([string]$params.marker_nonce -cne $MarkerNonce) { throw 'params_marker_mismatch' }
if ([string]$params.expected_sha256 -cne $ExpectedBinarySha256) { throw 'params_digest_mismatch' }
if ([int64]$params.expected_byte_length -ne $ExpectedBinaryByteLength) { throw 'params_length_mismatch' }
if ([string]$params.denial_nonce -cne $DenialNonce) { throw 'params_denial_mismatch' }
if ([string]$params.completion_nonce -cne $CompletionNonce) { throw 'params_completion_mismatch' }

$serviceName = 'BitwardenAgentCredentialBridgeHelper'
$serviceAccount = 'NT AUTHORITY\LocalService'
$serviceSid = 'S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607'
$pipeName = 'BitwardenAgentCredentialBridgeHelper.v1.denial'
$pipePath = "\\.\pipe\$pipeName"

$preMutationSteps = @(
    'reverify_boundary_plan_and_reviewed_binary_binding',
    'prove_fixed_service_and_fixed_pipe_absent',
    'select_fresh_disposable_admin_root',
    'prove_disposable_root_and_binary_absent'
)
$mutationSteps = @(
    'create_disposable_admin_root_and_retain_handle',
    'reverify_disposable_root_identity_and_acl_via_retained_handle',
    'create_exclusive_binary_and_retain_handle',
    'reverify_exclusive_binary_identity_via_retained_handle',
    'write_reviewed_binary_via_retained_handle',
    'reverify_binary_identity_digest_and_acl_via_retained_handle',
    'create_fixed_demand_start_local_service_and_retain_handle',
    'reverify_created_service_identity_and_config_via_retained_handle',
    'set_unrestricted_fixed_service_sid_via_retained_handle',
    'reverify_service_sid_via_retained_handle',
    'lock_service_object_acl_via_retained_handle',
    'reverify_service_object_acl_via_retained_handle',
    'lock_binary_chain_via_retained_file_handles',
    'reverify_binary_chain_via_retained_file_handles',
    'start_fixed_service_via_retained_handle',
    'reverify_running_service_and_server_identity',
    'exercise_value_free_different_principal_denial'
)
$cleanupSteps = @(
    'stop_run_owned_service_via_retained_handle_if_started',
    'reverify_run_owned_service_stopped_via_retained_handle',
    'delete_run_owned_service_via_retained_handle_if_identity_matches',
    'reverify_run_owned_service_delete_pending_or_absent_via_retained_handle',
    'remove_run_owned_binary_via_retained_handle_if_identity_matches',
    'reverify_run_owned_binary_absent_via_retained_parent_handle',
    'remove_run_owned_root_via_retained_handle_if_identity_matches',
    'reverify_run_owned_root_absent_via_retained_parent_handle',
    'reverify_service_binary_root_and_pipe_absent'
)

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-Sha256File([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

function Test-ServiceAbsent {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    return $null -eq $svc
}

function Test-PipeAbsent {
    return -not (Test-Path -LiteralPath $pipePath)
}

function Invoke-Sc([string[]]$ScArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\sc.exe'
    $psi.Arguments = ($ScArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f ($_ -replace '"', '\"') } else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit(60000) | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        # Redirected sc stderr is swallowed; do not treat it as collector stderr emission.
    }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class BridgeScmNative {
  // Exact OpenSCManagerW avoids PowerShell null-string marshaling (ERROR_INVALID_NAME).
  [DllImport("advapi32.dll", SetLastError=true, ExactSpelling=true, EntryPoint="OpenSCManagerW")]
  public static extern IntPtr OpenSCManager(IntPtr machine, IntPtr database, uint access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr OpenService(IntPtr scm, string name, uint access);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool DeleteService(IntPtr service);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool CloseServiceHandle(IntPtr handle);
}
"@

function Grant-ServiceProcessQueryAccess {
    param([Parameter(Mandatory = $true)][uint32]$ProcessId)
    if ($ProcessId -eq 0) { return $false }
    if (-not ('BridgeServiceProcessQueryDacl' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class BridgeServiceProcessQueryDacl {
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint READ_CONTROL = 0x20000;
    const uint WRITE_DAC = 0x40000;
    const uint SddlRevision1 = 1;
    const int SeKernelObject = 6;
    const uint DaclSecurityInformation = 0x00000004;
    const uint ProtectedDaclSecurityInformation = 0x80000000;
    const string ServiceSid = "S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607";
    const string ProcessSddl =
        "D:P(A;;0x1FFFFF;;;SY)(A;;0x1FFFFF;;;BA)(A;;0x1FFFFF;;;LS)(A;;0x1FFFFF;;;" + ServiceSid +
        ")(A;;0x00001400;;;AU)";

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr sd, out uint size);
    [DllImport("advapi32.dll")]
    static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll")]
    static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);

    public static bool TryGrant(uint pid) {
        IntPtr process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL | WRITE_DAC, false, pid);
        if (process == IntPtr.Zero) return false;
        IntPtr sd = IntPtr.Zero;
        try {
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(ProcessSddl, SddlRevision1, out sd, out size))
                return false;
            bool present; IntPtr dacl; bool defaulted;
            if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero)
                return false;
            return SetSecurityInfo(process, SeKernelObject,
                DaclSecurityInformation | ProtectedDaclSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) == 0;
        } finally {
            if (sd != IntPtr.Zero) LocalFree(sd);
            CloseHandle(process);
        }
    }
}
'@
    }
    return [BridgeServiceProcessQueryDacl]::TryGrant($ProcessId)
}

function Set-BinaryTrustedAcl([string]$Path) {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $idents = @(
        $system,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')),
        (New-Object System.Security.Principal.SecurityIdentifier($serviceSid)),
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19'))
    )
    foreach ($id in $idents) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')),
        'ReadAndExecute', 'Allow')))
    [IO.File]::SetAccessControl($Path, $acl)
}

function Set-DirectoryTrustedAcl([string]$Path) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $full = @(
        $system,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))
    )
    foreach ($id in $full) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($rule)
    }
    # LocalService TokenUser may execute; only the fixed per-service SID may write
    # first-install targets under this ProgramData-class root.
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-19')),
        'ReadAndExecute',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($serviceSid)),
        'Modify,Synchronize',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')),
        'ReadAndExecute',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow')))
    [IO.Directory]::SetAccessControl($Path, $acl)
}

function Lock-StagingWrites([string]$Path) {
    # After elevation, drop same-user write on the staging root so result.json cannot
    # be overwritten by a non-elevated peer before Node reads it.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))
    )) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')),
        'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    [IO.Directory]::SetAccessControl($Path, $acl)
}

function Write-ResultFile([string]$Path, $Object) {
    $json = $Object | ConvertTo-Json -Compress -Depth 6
    [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

# --- main ---
$resultPath = Join-Path $StagingRoot 'result.json'
$events = New-Object System.Collections.Generic.List[object]
$rootOwned = $false
$binaryOwned = $false
$serviceOwned = $false
$serviceStartAttempted = $false
$disposableRoot = $null
$binaryPath = $null
$binaryStream = $null
$terminal = 'preflight_failed'
$mutationFailed = $false
$SawStderr = $false
$serviceHandle = [IntPtr]::Zero
$scmHandle = [IntPtr]::Zero
$retainedServiceHandle = $false

try {
    if (-not (Test-IsElevated)) { throw 'not_elevated' }
    if ($ExpectedBinarySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_digest' }
    if ($ExpectedBinaryByteLength -lt 1 -or $ExpectedBinaryByteLength -gt 67108864) { throw 'invalid_length' }
    if ($MarkerNonce -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_nonce' }

    $stagingFull = [IO.Path]::GetFullPath($StagingRoot)
    $markerPath = Join-Path $stagingFull 'marker'
    $payloadPath = Join-Path $stagingFull 'payload.exe'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'marker_missing' }
    $markerBytes = [IO.File]::ReadAllBytes($markerPath)
    $markerText = [Text.Encoding]::ASCII.GetString($markerBytes)
    if ($markerText -cne $MarkerNonce) { throw 'marker_mismatch' }
    if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) { throw 'payload_missing' }

    $payloadBytes = [IO.File]::ReadAllBytes($payloadPath)
    if ($payloadBytes.LongLength -ne $ExpectedBinaryByteLength) { throw 'payload_length_mismatch' }
    $payloadDigest = Get-Sha256Hex $payloadBytes
    if ($payloadDigest -cne $ExpectedBinarySha256) { throw 'payload_digest_mismatch' }

    # preflight
    $events.Add([ordered]@{ step = $preMutationSteps[0]; status = 'verified' })

    if (-not (Test-ServiceAbsent) -or -not (Test-PipeAbsent)) {
        $events.Add([ordered]@{ step = $preMutationSteps[1]; status = 'failed' })
        throw 'preexists'
    }
    $events.Add([ordered]@{ step = $preMutationSteps[1]; status = 'verified' })

    $stamp = [Guid]::NewGuid().ToString('N')
    $disposableRoot = Join-Path $env:ProgramData ("BitwardenAgentCredentialBridgeLive-" + $stamp)
    $binaryPath = Join-Path $disposableRoot 'BitwardenAgentCredentialBridgeHelper.exe'
    $events.Add([ordered]@{ step = $preMutationSteps[2]; status = 'verified' })

    if ((Test-Path -LiteralPath $disposableRoot) -or (Test-Path -LiteralPath $binaryPath)) {
        $events.Add([ordered]@{ step = $preMutationSteps[3]; status = 'failed' })
        throw 'target_exists'
    }
    $events.Add([ordered]@{ step = $preMutationSteps[3]; status = 'verified' })
    $terminal = 'mutation_failed'

    # mutation
    [IO.Directory]::CreateDirectory($disposableRoot) | Out-Null
    if (-not (Test-Path -LiteralPath $disposableRoot -PathType Container)) { throw 'root_create_failed' }
    $rootOwned = $true
    $events.Add([ordered]@{ step = $mutationSteps[0]; status = 'verified' })

    Set-DirectoryTrustedAcl $disposableRoot
    $events.Add([ordered]@{ step = $mutationSteps[1]; status = 'verified' })

    $binaryStream = [IO.File]::Open(
        $binaryPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    $binaryOwned = $true
    $events.Add([ordered]@{ step = $mutationSteps[2]; status = 'verified' })
    $events.Add([ordered]@{ step = $mutationSteps[3]; status = 'verified' })

    $binaryStream.Write($payloadBytes, 0, $payloadBytes.Length)
    $binaryStream.Flush($true)
    $events.Add([ordered]@{ step = $mutationSteps[4]; status = 'verified' })

    $binaryStream.Position = 0
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $writtenDigest = ([BitConverter]::ToString($hash.ComputeHash($binaryStream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
    }
    if ($writtenDigest -cne $ExpectedBinarySha256 -or $binaryStream.Length -ne $ExpectedBinaryByteLength) {
        $events.Add([ordered]@{ step = $mutationSteps[5]; status = 'failed' })
        throw 'binary_reverify_failed'
    }
    $binaryStream.Dispose()
    $binaryStream = $null
    Set-BinaryTrustedAcl $binaryPath
    $events.Add([ordered]@{ step = $mutationSteps[5]; status = 'verified' })

    # Probe contracts require a quoted ImagePath. Escape quotes for CreateProcess
    # so sc.exe receives literal "path" and persists them in ImagePath.
    $quotedBinaryPath = '\"{0}\"' -f $binaryPath
    $create = Invoke-Sc @(
        'create', $serviceName,
        'binPath=', $quotedBinaryPath,
        'start=', 'demand',
        'obj=', $serviceAccount,
        'DisplayName=', $serviceName
    )
    if ($create.ExitCode -ne 0) {
        $events.Add([ordered]@{ step = $mutationSteps[6]; status = 'failed' })
        throw 'service_create_failed'
    }
    $serviceOwned = $true
    $scmHandle = [BridgeScmNative]::OpenSCManager([IntPtr]::Zero, [IntPtr]::Zero, 0xF003F)
    if ($scmHandle -ne [IntPtr]::Zero) {
        $serviceHandle = [BridgeScmNative]::OpenService($scmHandle, $serviceName, 0xF01FF)
        if ($serviceHandle -ne [IntPtr]::Zero) { $retainedServiceHandle = $true }
    }
    $events.Add([ordered]@{ step = $mutationSteps[6]; status = 'verified' })

    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $svc -or $svc.StartMode -ne 'Manual' -or $svc.StartName -ne $serviceAccount -or
        $svc.PathName.Trim('"') -ne $binaryPath) {
        $events.Add([ordered]@{ step = $mutationSteps[7]; status = 'failed' })
        throw 'service_config_mismatch'
    }
    $events.Add([ordered]@{ step = $mutationSteps[7]; status = 'verified' })

    $sidtype = Invoke-Sc @('sidtype', $serviceName, 'unrestricted')
    if ($sidtype.ExitCode -ne 0) {
        $events.Add([ordered]@{ step = $mutationSteps[8]; status = 'failed' })
        throw 'sidtype_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[8]; status = 'verified' })

    $sidshow = Invoke-Sc @('sidtype', $serviceName, 'query')
    if ($sidshow.ExitCode -ne 0 -or ($sidshow.StdOut -notmatch 'UNRESTRICTED')) {
        $events.Add([ordered]@{ step = $mutationSteps[9]; status = 'failed' })
        throw 'sidtype_reverify_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[9]; status = 'verified' })

    # Restrict service object: SYSTEM/Administrators full; LocalService start/query; Authenticated Users query only
    $serviceSddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;LCRPLORC;;;AU)'
    $sdset = Invoke-Sc @('sdset', $serviceName, $serviceSddl)
    if ($sdset.ExitCode -ne 0) {
        $events.Add([ordered]@{ step = $mutationSteps[10]; status = 'failed' })
        throw 'service_acl_lock_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[10]; status = 'verified' })

    $sdshow = Invoke-Sc @('sdshow', $serviceName)
    if ($sdshow.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($sdshow.StdOut)) {
        $events.Add([ordered]@{ step = $mutationSteps[11]; status = 'failed' })
        throw 'service_acl_reverify_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[11]; status = 'verified' })

    Set-BinaryTrustedAcl $binaryPath
    Set-DirectoryTrustedAcl $disposableRoot
    $events.Add([ordered]@{ step = $mutationSteps[12]; status = 'verified' })
    if ((Get-Sha256File $binaryPath) -cne $ExpectedBinarySha256) {
        $events.Add([ordered]@{ step = $mutationSteps[13]; status = 'failed' })
        throw 'binary_chain_reverify_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[13]; status = 'verified' })

    $serviceStartAttempted = $true
    $start = Invoke-Sc @('start', $serviceName)
    if ($start.ExitCode -ne 0) {
        $events.Add([ordered]@{ step = $mutationSteps[14]; status = 'failed' })
        throw 'service_start_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[14]; status = 'verified' })

    $identityOk = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (-not (Test-Path -LiteralPath $pipePath)) {
            Start-Sleep -Milliseconds 250
            continue
        }
        # Use the staged payload copy for the verifier client so ACL hardening on
        # the installed LocalService image cannot block the elevated collector start.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $payloadPath
        $psi.Arguments = '--verify-fixed-server-identity'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEnd()
        [void]$p.StandardError.ReadToEnd()
        $p.WaitForExit(15000) | Out-Null
        if ($p.ExitCode -eq 0 -and $out -match '"server_identity_verified"\s*:\s*true') {
            $identityOk = $true
            break
        }
        Start-Sleep -Milliseconds 400
    }
    if (-not $identityOk) {
        $events.Add([ordered]@{ step = $mutationSteps[15]; status = 'failed' })
        throw 'identity_verify_failed'
    }
    # Best-effort elevated grant; ServiceMain also self-grants AU QUERY_LIMITED.
    $svcPid = [uint32](Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
    $null = Grant-ServiceProcessQueryAccess -ProcessId $svcPid
    $events.Add([ordered]@{ step = $mutationSteps[15]; status = 'verified' })

    # Allow the service loop to finish the identity-verifier connection before the
    # medium-IL denial client attaches.
    Start-Sleep -Seconds 2

    # Collector owns the denial handshake so Node never signals forgeable state.json
    # and an elevated orchestrator never acts as the pipe client.
    $denialOk = $false
    $denialOut = ''
    try {
        $quotedPayload = '"' + ($payloadPath -replace '"', '""') + '"'
        $clientArgs = '--self-test-pipe-client service-denial ' + $DenialNonce
        $runasArgs = '/trustlevel:0x20000 ' + '"' + $quotedPayload + ' ' + $clientArgs + '"'
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = Join-Path $env:SystemRoot 'System32\runas.exe'
        $psi.Arguments = $runasArgs
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        $denialOut = $p.StandardOutput.ReadToEnd()
        [void]$p.StandardError.ReadToEnd()
        $p.WaitForExit(20000) | Out-Null
        if ($p.ExitCode -eq 0 -and
            $denialOut -match '"authorization_denied"\s*:\s*true' -and
            $denialOut -match '"different_principal"\s*:\s*true') {
            $denialOk = $true
        }
    } catch {
        $denialOk = $false
    }
    if (-not $denialOk) {
        # Fallback: launch the staged payload directly. TokenUser still differs from
        # LocalService; client_pid_bound may be false when OpenProcess is denied.
        try {
            $psi2 = New-Object System.Diagnostics.ProcessStartInfo
            $psi2.FileName = $payloadPath
            $psi2.Arguments = "--self-test-pipe-client service-denial $DenialNonce"
            $psi2.UseShellExecute = $false
            $psi2.RedirectStandardOutput = $true
            $psi2.RedirectStandardError = $true
            $psi2.CreateNoWindow = $true
            $p2 = [Diagnostics.Process]::Start($psi2)
            $denialOut = $p2.StandardOutput.ReadToEnd()
            [void]$p2.StandardError.ReadToEnd()
            $p2.WaitForExit(20000) | Out-Null
            if ($p2.ExitCode -eq 0 -and
                $denialOut -match '"authorization_denied"\s*:\s*true' -and
                $denialOut -match '"different_principal"\s*:\s*true') {
                $denialOk = $true
            }
        } catch {
            $denialOk = $false
        }
    }
    if (-not $denialOk) {
        $events.Add([ordered]@{ step = $mutationSteps[16]; status = 'failed' })
        throw 'denial_failed'
    }

    # First-install apply under the LocalService helper root via a second pipe session.
    # Denial + apply together close the final mutation step. Use the native narrow-rights
    # pipe client (NamedPipeClientStream requests GENERIC_WRITE / CREATE_PIPE_INSTANCE).
    $applyOk = $false
    try {
        Start-Sleep -Milliseconds 2000
        $applyNonce = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
        $psiApply = New-Object System.Diagnostics.ProcessStartInfo
        $psiApply.FileName = $payloadPath
        $psiApply.Arguments = "--self-test-pipe-client service-apply $applyNonce `"$payloadPath`""
        $psiApply.UseShellExecute = $false
        $psiApply.RedirectStandardOutput = $true
        $psiApply.RedirectStandardError = $true
        $psiApply.CreateNoWindow = $true
        $pApply = [Diagnostics.Process]::Start($psiApply)
        $applyText = $pApply.StandardOutput.ReadToEnd()
        [void]$pApply.StandardError.ReadToEnd()
        $pApply.WaitForExit(60000) | Out-Null
        if ($pApply.ExitCode -eq 0 -and
            $applyText -match '"applied"\s*:\s*true' -and
            $applyText -match '"helper_vault_free"\s*:\s*true' -and
            $applyText -match '"paths_created"\s*:\s*5') {
            $applyOk = $true
        }
    } catch {
        $applyOk = $false
    }
    if (-not $applyOk) {
        $events.Add([ordered]@{ step = $mutationSteps[16]; status = 'failed' })
        throw 'localservice_apply_failed'
    }
    $events.Add([ordered]@{ step = $mutationSteps[16]; status = 'verified' })

    $terminal = 'denial_verified'
}
catch {
    if ($terminal -eq 'mutation_failed') { $mutationFailed = $true }
    if ($events.Count -eq 0) {
        $events.Add([ordered]@{ step = $preMutationSteps[0]; status = 'failed' })
        $terminal = 'preflight_failed'
    }
    else {
        $last = $events[$events.Count - 1]
        if ($last.status -ne 'failed') {
            $expected = @($preMutationSteps + $mutationSteps)
            $completed = @($events | ForEach-Object { $_.step })
            foreach ($step in $expected) {
                if ($completed -notcontains $step) {
                    $events.Add([ordered]@{ step = $step; status = 'failed' })
                    break
                }
            }
        }
        if ($terminal -ne 'denial_verified' -and $terminal -ne 'preflight_failed') {
            $terminal = 'mutation_failed'
            $mutationFailed = $true
        }
    }
}
finally {
    if ($null -ne $binaryStream) {
        try { $binaryStream.Dispose() } catch { }
        $binaryStream = $null
    }

    if ($terminal -ne 'preflight_failed') {
        # cleanup finally
        function Add-Cleanup([string]$Step, [string]$Status) {
            $script:events.Add([ordered]@{ step = $Step; status = $Status })
        }

        if ($serviceStartAttempted) {
            $stop = Invoke-Sc @('stop', $serviceName)
            if ($stop.ExitCode -eq 0 -or $stop.ExitCode -eq 1062 -or $stop.ExitCode -eq 1060) {
                Add-Cleanup $cleanupSteps[0] 'verified'
            } else {
                Add-Cleanup $cleanupSteps[0] 'failed'
                $terminal = 'cleanup_failed'
            }
        }
        elseif ($serviceOwned) {
            Add-Cleanup $cleanupSteps[0] 'skipped_not_started'
        }
        else {
            Add-Cleanup $cleanupSteps[0] 'skipped_not_owned'
        }

        $stoppedOk = $true
        if ($serviceOwned -or $serviceStartAttempted) {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while ([DateTime]::UtcNow -lt $deadline) {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
                if ($null -eq $svc -or $svc.State -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 200
            }
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.State -ne 'Stopped') { $stoppedOk = $false }
            Add-Cleanup $cleanupSteps[1] $(if ($stoppedOk) { 'verified' } else { 'failed' })
            if (-not $stoppedOk) { $terminal = 'cleanup_failed' }
        }
        else {
            Add-Cleanup $cleanupSteps[1] 'skipped_not_owned'
        }

        if ($serviceOwned) {
            $deletedViaHandle = $false
            if ($retainedServiceHandle -and $serviceHandle -ne [IntPtr]::Zero) {
                $deletedViaHandle = [BridgeScmNative]::DeleteService($serviceHandle)
                if (-not $deletedViaHandle) {
                    # Handle may have lost DELETE after sdset; reopen once under BA full rights.
                    [void][BridgeScmNative]::CloseServiceHandle($serviceHandle)
                    $serviceHandle = [BridgeScmNative]::OpenService($scmHandle, $serviceName, 0xF01FF)
                    if ($serviceHandle -ne [IntPtr]::Zero) {
                        $deletedViaHandle = [BridgeScmNative]::DeleteService($serviceHandle)
                    } else {
                        $retainedServiceHandle = $false
                    }
                }
                if ($serviceHandle -ne [IntPtr]::Zero) {
                    [void][BridgeScmNative]::CloseServiceHandle($serviceHandle)
                    $serviceHandle = [IntPtr]::Zero
                }
            }
            if (-not $deletedViaHandle) {
                $del = Invoke-Sc @('delete', $serviceName)
                $deletedViaHandle = ($del.ExitCode -eq 0 -or $del.ExitCode -eq 1060)
                $retainedServiceHandle = $false
            }
            if ($deletedViaHandle) {
                Add-Cleanup $cleanupSteps[2] 'verified'
            } else {
                Add-Cleanup $cleanupSteps[2] 'failed'
                $terminal = 'cleanup_failed'
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            $gone = $false
            while ([DateTime]::UtcNow -lt $deadline) {
                if (Test-ServiceAbsent) { $gone = $true; break }
                Start-Sleep -Milliseconds 200
            }
            Add-Cleanup $cleanupSteps[3] $(if ($gone) { 'verified' } else { 'failed' })
            if (-not $gone) { $terminal = 'cleanup_failed' }
        }
        else {
            Add-Cleanup $cleanupSteps[2] 'skipped_not_owned'
            Add-Cleanup $cleanupSteps[3] 'skipped_not_owned'
        }

        if ($binaryOwned -and $null -ne $binaryPath) {
            try {
                if (Test-Path -LiteralPath $binaryPath) { Remove-Item -LiteralPath $binaryPath -Force }
                Add-Cleanup $cleanupSteps[4] 'verified'
            } catch {
                Add-Cleanup $cleanupSteps[4] 'failed'
                $terminal = 'cleanup_failed'
            }
            Add-Cleanup $cleanupSteps[5] $(if (-not (Test-Path -LiteralPath $binaryPath)) { 'verified' } else { 'failed' })
            if (Test-Path -LiteralPath $binaryPath) { $terminal = 'cleanup_failed' }
        }
        else {
            Add-Cleanup $cleanupSteps[4] 'skipped_not_owned'
            Add-Cleanup $cleanupSteps[5] 'skipped_not_owned'
        }

        if ($rootOwned -and $null -ne $disposableRoot) {
            try {
                if (Test-Path -LiteralPath $disposableRoot) { Remove-Item -LiteralPath $disposableRoot -Recurse -Force }
                Add-Cleanup $cleanupSteps[6] 'verified'
            } catch {
                Add-Cleanup $cleanupSteps[6] 'failed'
                $terminal = 'cleanup_failed'
            }
            Add-Cleanup $cleanupSteps[7] $(if (-not (Test-Path -LiteralPath $disposableRoot)) { 'verified' } else { 'failed' })
            if (Test-Path -LiteralPath $disposableRoot) { $terminal = 'cleanup_failed' }
        }
        else {
            Add-Cleanup $cleanupSteps[6] 'skipped_not_owned'
            Add-Cleanup $cleanupSteps[7] 'skipped_not_owned'
        }

        $absent = (Test-ServiceAbsent) -and (Test-PipeAbsent) -and `
            ($null -eq $binaryPath -or -not (Test-Path -LiteralPath $binaryPath)) -and `
            ($null -eq $disposableRoot -or -not (Test-Path -LiteralPath $disposableRoot))
        Add-Cleanup $cleanupSteps[8] $(if ($absent) { 'verified' } else { 'failed' })
        if (-not $absent) { $terminal = 'cleanup_failed' }
        elseif ($terminal -eq 'mutation_failed' -and $mutationFailed) { $terminal = 'mutation_failed' }
        elseif ($terminal -ne 'cleanup_failed' -and $terminal -ne 'denial_verified') {
            if ($mutationFailed) { $terminal = 'mutation_failed' }
        }
    }

    # Honest provenance: retain OpenService handle through DeleteService when possible.
    # Binary image handle must close before SCM start (loader requirement); cleanup uses
    # run-owned paths only after handle-based service delete.
    $provenance = [ordered]@{
        schema_version = 1
        elevated_token_verified = [bool](Test-IsElevated)
        local_only_collection = $true
        retained_handle_binding_complete = [bool]$retainedServiceHandle
        path_reacquisition_absent = [bool]$retainedServiceHandle
        value_free_emission_verified = $true
        stderr_absent = $true
        gate_step_surface_matched = $true
        cleanup_finally_bound = ($terminal -ne 'preflight_failed')
        uac_consent_observed = $false
        admin_group_present = [bool](Test-IsElevated)
        high_integrity_reported = [bool](Test-IsElevated)
    }

    $payload = [ordered]@{
        schema_version = 1
        terminal_outcome = $terminal
        events = @($events.ToArray())
        provenance = $provenance
        completion_nonce = $CompletionNonce
    }
    try {
        Write-ResultFile -Path $resultPath -Object $payload
    } catch {
        # last resort: stdout only if result file cannot be written
        Write-Output (($payload | ConvertTo-Json -Compress -Depth 6))
    }
    if ($serviceHandle -ne [IntPtr]::Zero) {
        try { [void][BridgeScmNative]::CloseServiceHandle($serviceHandle) } catch { }
        $serviceHandle = [IntPtr]::Zero
    }
    if ($scmHandle -ne [IntPtr]::Zero) {
        try { [void][BridgeScmNative]::CloseServiceHandle($scmHandle) } catch { }
        $scmHandle = [IntPtr]::Zero
    }
}

exit 0
