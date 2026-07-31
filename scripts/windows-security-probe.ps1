param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetPath
)

$ErrorActionPreference = 'Stop'

try {
    $item = Get-Item -LiteralPath $TargetPath -Force
    $reparsePoint = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    if ($reparsePoint) {
        [ordered]@{
            reparsePoint = $true
            ownerCurrentUser = $false
            writableByOtherUsers = $true
        } | ConvertTo-Json -Compress
        exit 0
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $identity.User.Value
    $acl = if ($item.PSIsContainer) {
        [System.IO.Directory]::GetAccessControl($item.FullName)
    }
    else {
        [System.IO.File]::GetAccessControl($item.FullName)
    }
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

    $trustedWriters = @(
        $currentSid,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    $writeMask =
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::FullControl -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership

    $writableByOtherUsers = $false
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        $hasWrite = ([int64]$rule.FileSystemRights -band [int64]$writeMask) -ne 0
        if ($hasWrite -and $trustedWriters -notcontains $sid) {
            $writableByOtherUsers = $true
            break
        }
    }

    [ordered]@{
        reparsePoint = [bool]$reparsePoint
        ownerCurrentUser = [bool]($ownerSid -eq $currentSid)
        writableByOtherUsers = [bool]$writableByOtherUsers
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    exit 1
}
