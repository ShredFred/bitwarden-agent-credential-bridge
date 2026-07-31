param(
    [Parameter(Mandatory = $true, Position = 0)][string]$RootPath,
    [Parameter(Mandatory = $true, Position = 1)][string]$MarkerPath,
    [Parameter(Mandatory = $true, Position = 2)][string]$Nonce,
    [Parameter(Mandatory = $true, Position = 3)][string]$TargetPath,
    [Parameter(Mandatory = $true, Position = 4)][ValidateSet('file', 'directory')][string]$Kind
)

$ErrorActionPreference = 'Stop'

try {
    if ($Nonce -notmatch '^[0-9a-f]{64}$') { throw 'invalid nonce' }
    $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    $marker = [System.IO.Path]::GetFullPath($MarkerPath)
    $target = [System.IO.Path]::GetFullPath($TargetPath).TrimEnd('\')
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $prefix = $root + $separator
    if (-not $target.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'target outside root'
    }
    $expectedMarkerPath = [System.IO.Path]::Combine($root, '.bw-agent-bridge-disposable.json')
    if (-not $marker.Equals($expectedMarkerPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'invalid marker path'
    }
    $expectedMarker = '{"magic":"bitwarden-agent-credential-bridge-disposable","version":1,"platform":"win32","nonce":"' + $Nonce + '"}' + "`n"
    $actualMarker = [System.IO.File]::ReadAllText($marker, [System.Text.Encoding]::UTF8)
    if ($actualMarker -cne $expectedMarker) { throw 'marker mismatch' }

    $rootItem = Get-Item -LiteralPath $root -Force
    $markerItem = Get-Item -LiteralPath $marker -Force
    $targetItem = Get-Item -LiteralPath $target -Force
    if (-not $rootItem.PSIsContainer -or $markerItem.PSIsContainer) { throw 'invalid root or marker' }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reparse point rejected'
    }
    if (($Kind -eq 'directory' -and -not $targetItem.PSIsContainer) -or
        ($Kind -eq 'file' -and $targetItem.PSIsContainer)) { throw 'wrong item type' }

    $cursorPath = $target
    while ($true) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'reparse point rejected'
        }
        if ($cursorPath.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $cursorPath = [System.IO.Path]::GetDirectoryName($cursorPath).TrimEnd('\')
        if ([string]::IsNullOrEmpty($cursorPath)) { throw 'root not reached' }
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl

    if ($Kind -eq 'directory') {
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        foreach ($sid in @($currentSid, $systemSid, $administratorsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, $full, $inheritance, $propagation, $allow
            )
            [void]$security.AddAccessRule($rule)
        }
        $security.SetOwner($currentSid)
        $security.SetAccessRuleProtection($true, $false)
        [System.IO.Directory]::SetAccessControl($target, $security)
    }
    else {
        $security = New-Object System.Security.AccessControl.FileSecurity
        foreach ($sid in @($currentSid, $systemSid, $administratorsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, $full, $allow
            )
            [void]$security.AddAccessRule($rule)
        }
        $security.SetOwner($currentSid)
        $security.SetAccessRuleProtection($true, $false)
        [System.IO.File]::SetAccessControl($target, $security)
    }
    exit 0
}
catch {
    exit 1
}
