param(
    [Parameter(Mandatory = $false)][string]$InstallRoot = ''
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Write-Result([hashtable]$Object, [int]$Code = 0) {
    [Console]::Out.Write(($Object | ConvertTo-Json -Compress))
    exit $Code
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $node) {
    Write-Result @{ ok = $false; code = 'node_missing'; hint = 'Install Node.js 20+ and reopen Setup' } 1
}

$bws = Get-Command bws -ErrorAction SilentlyContinue
$bwsOk = $null -ne $bws

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Bitwarden Agent Bridge Setup'
$form.Size = New-Object System.Drawing.Size(520, 360)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$lblIntro = New-Object System.Windows.Forms.Label
$lblIntro.Location = New-Object System.Drawing.Point(16, 12)
$lblIntro.Size = New-Object System.Drawing.Size(470, 40)
$lblIntro.Text = 'Paste your Secrets Manager machine access token. Cloud is the default. Optional self-host URL only if you need it.'
$form.Controls.Add($lblIntro)

$lblMachine = New-Object System.Windows.Forms.Label
$lblMachine.Location = New-Object System.Drawing.Point(16, 60)
$lblMachine.Size = New-Object System.Drawing.Size(120, 20)
$lblMachine.Text = 'Machine id'
$form.Controls.Add($lblMachine)

$txtMachine = New-Object System.Windows.Forms.TextBox
$txtMachine.Location = New-Object System.Drawing.Point(140, 56)
$txtMachine.Size = New-Object System.Drawing.Size(340, 22)
$hostName = ($env:COMPUTERNAME.ToLower() -replace '[^a-z0-9_-]', '-')
$txtMachine.Text = "pc-$hostName"
$form.Controls.Add($txtMachine)

$lblToken = New-Object System.Windows.Forms.Label
$lblToken.Location = New-Object System.Drawing.Point(16, 96)
$lblToken.Size = New-Object System.Drawing.Size(120, 20)
$lblToken.Text = 'Access token'
$form.Controls.Add($lblToken)

$txtToken = New-Object System.Windows.Forms.TextBox
$txtToken.Location = New-Object System.Drawing.Point(140, 92)
$txtToken.Size = New-Object System.Drawing.Size(340, 22)
$txtToken.UseSystemPasswordChar = $true
$form.Controls.Add($txtToken)

$chkCustom = New-Object System.Windows.Forms.CheckBox
$chkCustom.Location = New-Object System.Drawing.Point(140, 128)
$chkCustom.Size = New-Object System.Drawing.Size(340, 22)
$chkCustom.Text = 'Use self-hosted server URL (advanced)'
$form.Controls.Add($chkCustom)

$lblServer = New-Object System.Windows.Forms.Label
$lblServer.Location = New-Object System.Drawing.Point(16, 164)
$lblServer.Size = New-Object System.Drawing.Size(120, 20)
$lblServer.Text = 'Server URL'
$form.Controls.Add($lblServer)

$txtServer = New-Object System.Windows.Forms.TextBox
$txtServer.Location = New-Object System.Drawing.Point(140, 160)
$txtServer.Size = New-Object System.Drawing.Size(340, 22)
$txtServer.Enabled = $false
$txtServer.Text = 'https://'
$form.Controls.Add($txtServer)

$chkCustom.Add_CheckedChanged({
    $txtServer.Enabled = $chkCustom.Checked
})

$lblBws = New-Object System.Windows.Forms.Label
$lblBws.Location = New-Object System.Drawing.Point(16, 200)
$lblBws.Size = New-Object System.Drawing.Size(470, 40)
if ($bwsOk) {
    $lblBws.Text = 'bws CLI: found on PATH'
} else {
    $lblBws.Text = 'bws CLI: NOT found. Install Bitwarden Secrets Manager CLI and ensure PATH, then re-run Setup.'
}
$form.Controls.Add($lblBws)

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = 'Save'
$btnOk.Location = New-Object System.Drawing.Point(280, 260)
$btnOk.Size = New-Object System.Drawing.Size(90, 28)
$btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnOk)
$form.AcceptButton = $btnOk

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel'
$btnCancel.Location = New-Object System.Drawing.Point(390, 260)
$btnCancel.Size = New-Object System.Drawing.Size(90, 28)
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnCancel)
$form.CancelButton = $btnCancel

$result = $form.ShowDialog()
if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Result @{ ok = $false; code = 'cancelled' } 1
}

$machineId = $txtMachine.Text.Trim().ToLowerInvariant()
$token = $txtToken.Text.Trim()
$serverUrl = ''
if ($chkCustom.Checked) {
    $serverUrl = $txtServer.Text.Trim().TrimEnd('/')
}

if ($machineId -notmatch '^[a-z][a-z0-9_-]{0,63}$') {
    Write-Result @{ ok = $false; code = 'invalid_machine_id' } 1
}
if ($token.Length -lt 16 -or $token.Length -gt 8192) {
    Write-Result @{ ok = $false; code = 'invalid_token' } 1
}
if ($chkCustom.Checked -and $serverUrl -notmatch '^https://') {
    Write-Result @{ ok = $false; code = 'invalid_server_url' } 1
}
if (-not $bwsOk) {
    Write-Result @{ ok = $false; code = 'bws_missing' } 1
}

$root = if ($InstallRoot -ne '') { $InstallRoot } else {
    Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

$apply = Join-Path $root 'scripts\apply-sm-wizard-setup.mjs'
if (-not (Test-Path -LiteralPath $apply)) {
    Write-Result @{ ok = $false; code = 'apply_script_absent' } 1
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $node.Source
$psi.Arguments = "`"$apply`" --i-approve-sm-machine-setup"
$psi.WorkingDirectory = $root
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables['SM_WIZARD_MACHINE_ID'] = $machineId
if ($serverUrl -ne '') {
    $psi.EnvironmentVariables['SM_WIZARD_SERVER_URL'] = $serverUrl
}

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
[void]$proc.Start()
$proc.StandardInput.WriteLine($token)
$proc.StandardInput.Close()
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit(60000) | Out-Null

$token = $null
[GC]::Collect()

if ($proc.ExitCode -ne 0) {
    Write-Result @{
        ok = $false
        code = 'apply_failed'
        detail = if ($stdout) { $stdout.Trim() } else { 'apply_failed' }
    } 1
}

[Console]::Out.Write($stdout.Trim())
exit 0
