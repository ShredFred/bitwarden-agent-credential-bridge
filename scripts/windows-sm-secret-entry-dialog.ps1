# Windows WinForms secret-entry dialog for agent-callable SM writes.
# Reads a value-free form JSON file. Writes secrets via live:sm-write stdin.
# Emits only value-free JSON on stdout. Never prints secret values.
param(
  [Parameter(Mandatory = $true)][string]$FormPath,
  [Parameter(Mandatory = $true)][string]$BridgeRoot,
  [Parameter(Mandatory = $true)][string]$WriteApprovalFlag
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Write-Result([hashtable]$Object, [int]$Code = 0) {
  [Console]::Out.Write(($Object | ConvertTo-Json -Compress -Depth 6))
  exit $Code
}

if (-not (Test-Path -LiteralPath $FormPath)) {
  Write-Result @{ ok = $false; code = 'form_path_absent' } 1
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $node) {
  Write-Result @{ ok = $false; code = 'node_missing' } 1
}

$formRaw = Get-Content -LiteralPath $FormPath -Raw -Encoding UTF8
$formObj = $formRaw | ConvertFrom-Json
if ($null -eq $formObj -or $null -eq $formObj.fields) {
  Write-Result @{ ok = $false; code = 'form_parse_failed' } 1
}

$fields = @($formObj.fields)
if ($fields.Count -lt 1 -or $fields.Count -gt 8) {
  Write-Result @{ ok = $false; code = 'invalid_field_count' } 1
}

$writeScript = Join-Path $BridgeRoot 'scripts\run-secrets-manager-write.mjs'
if (-not (Test-Path -LiteralPath $writeScript)) {
  Write-Result @{ ok = $false; code = 'write_script_absent' } 1
}

# Ensure bws is discoverable for the write child.
$localBws = Join-Path $env:LOCALAPPDATA 'Programs\Bitwarden'
if (Test-Path -LiteralPath $localBws) {
  $env:Path = "$localBws;$env:Path"
}

$ui = New-Object System.Windows.Forms.Form
$ui.Text = [string]$formObj.title
$ui.StartPosition = 'CenterScreen'
$ui.FormBorderStyle = 'FixedDialog'
$ui.MaximizeBox = $false
$ui.MinimizeBox = $false
$ui.ShowInTaskbar = $true
$ui.TopMost = $true
$ui.ShowInTaskbar = $true
$ui.Width = 560
$ui.Add_Shown({
  $ui.TopMost = $true
  $ui.Activate()
  $ui.BringToFront()
  [void][System.Windows.Forms.Application]::DoEvents()
  $first = $inputBoxes.Values | Select-Object -First 1
  if ($null -ne $first) { $first.Box.Focus() }
})

$y = 12
$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Location = New-Object System.Drawing.Point(16, $y)
$lblInfo.Size = New-Object System.Drawing.Size(510, 64)
$lblInfo.Text = [string]$formObj.info
$ui.Controls.Add($lblInfo)
$y += 72

$lblProject = New-Object System.Windows.Forms.Label
$lblProject.Location = New-Object System.Drawing.Point(16, $y)
$lblProject.Size = New-Object System.Drawing.Size(510, 20)
$lblProject.Text = "SM project: $($formObj.project)  |  values go only into Secrets Manager"
$ui.Controls.Add($lblProject)
$y += 28

$inputBoxes = @{}
foreach ($field in $fields) {
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point(16, $y)
  $lbl.Size = New-Object System.Drawing.Size(510, 18)
  $reqMark = if ($field.required -eq $true) { ' *' } else { '' }
  $lbl.Text = "$($field.label)$reqMark  [$($field.sm_key)]"
  $ui.Controls.Add($lbl)
  $y += 20

  if ($null -ne $field.hint -and [string]$field.hint -ne '') {
    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point(16, $y)
    $hint.Size = New-Object System.Drawing.Size(510, 18)
    $hint.ForeColor = [System.Drawing.Color]::DimGray
    $hint.Text = [string]$field.hint
    $ui.Controls.Add($hint)
    $y += 18
  }

  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = New-Object System.Drawing.Point(16, $y)
  $box.Size = New-Object System.Drawing.Size(510, 24)
  if ([string]$field.kind -eq 'password') {
    $box.UseSystemPasswordChar = $true
  }
  $ui.Controls.Add($box)
  $inputBoxes[[string]$field.sm_key] = @{
    Box = $box
    Field = $field
  }
  $y += 34
}

$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point(16, $y)
$status.Size = New-Object System.Drawing.Size(510, 36)
$status.ForeColor = [System.Drawing.Color]::DarkRed
$status.Text = ''
$ui.Controls.Add($status)
$y += 40

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = 'In Secrets Manager speichern'
$btnOk.Location = New-Object System.Drawing.Point(200, $y)
$btnOk.Size = New-Object System.Drawing.Size(200, 30)
$ui.Controls.Add($btnOk)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Abbrechen'
$btnCancel.Location = New-Object System.Drawing.Point(420, $y)
$btnCancel.Size = New-Object System.Drawing.Size(106, 30)
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$ui.Controls.Add($btnCancel)
$ui.CancelButton = $btnCancel
$ui.Height = $y + 80

function Clear-SecretBoxes {
  foreach ($key in @($inputBoxes.Keys)) {
    $inputBoxes[$key].Box.Text = ''
  }
}

$script:SaveOk = $false
$script:WriteReport = $null

$btnOk.Add_Click({
  $status.Text = ''
  $values = @{}
  foreach ($key in @($inputBoxes.Keys)) {
    $meta = $inputBoxes[$key]
    $field = $meta.Field
    $text = [string]$meta.Box.Text
    $required = ($field.required -eq $true)
    $minLen = if ($null -ne $field.min_length) { [int]$field.min_length } else { if ($required) { 1 } else { 0 } }
    $maxLen = if ($null -ne $field.max_length) { [int]$field.max_length } else { 4096 }
    if ($required -and $text.Length -lt 1) {
      $status.Text = "Pflichtfeld fehlt: $($field.label)"
      return
    }
    if ($text.Length -gt 0 -and ($text.Length -lt $minLen -or $text.Length -gt $maxLen)) {
      $status.Text = "Ungültige Länge: $($field.label)"
      return
    }
    if ($text.Length -gt 0) {
      $values[$key] = $text
    }
  }

  if ($values.Count -lt 1) {
    $status.Text = 'Kein Wert eingegeben.'
    return
  }

  $btnOk.Enabled = $false
  $btnCancel.Enabled = $false
  $status.ForeColor = [System.Drawing.Color]::DarkBlue
  $status.Text = 'Speichere…'

  $written = New-Object System.Collections.Generic.List[string]
  $actions = @{}
  $publicValues = @{}
  try {
    foreach ($key in @($values.Keys)) {
      $meta = $inputBoxes[$key]
      $field = $meta.Field
      $isSecret = $true
      if ($null -ne $field.secret) {
        $isSecret = [bool]$field.secret
      } elseif ([string]$field.kind -eq 'text') {
        $isSecret = $false
      }
      if (-not $isSecret) {
        $publicValues[$key] = [string]$values[$key]
      }

      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = $node.Source
      $psi.Arguments = "`"$writeScript`" $WriteApprovalFlag --project `"$($formObj.project)`" --key `"$key`""
      $psi.WorkingDirectory = $BridgeRoot
      $psi.RedirectStandardInput = $true
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError = $true
      $psi.UseShellExecute = $false
      $psi.CreateNoWindow = $true
      if (Test-Path -LiteralPath $localBws) {
        $psi.EnvironmentVariables['Path'] = "$localBws;$env:Path"
      }

      $proc = New-Object System.Diagnostics.Process
      $proc.StartInfo = $psi
      [void]$proc.Start()
      $proc.StandardInput.Write($values[$key])
      $proc.StandardInput.Close()
      $stdout = $proc.StandardOutput.ReadToEnd()
      $null = $proc.StandardError.ReadToEnd()
      if (-not $proc.WaitForExit(90000)) {
        try { $proc.Kill() } catch { }
        throw 'write_timeout'
      }
      if ($proc.ExitCode -ne 0) {
        $code = 'write_failed'
        try {
          $parsed = $stdout | ConvertFrom-Json
          if ($null -ne $parsed.code) { $code = [string]$parsed.code }
        } catch { }
        throw $code
      }
      $action = 'written'
      try {
        $parsed = $stdout | ConvertFrom-Json
        if ($null -ne $parsed.action) { $action = [string]$parsed.action }
      } catch { }
      $written.Add($key) | Out-Null
      $actions[$key] = $action
    }

    $publicValues = @{}
    foreach ($key in @($values.Keys)) {
      $meta = $inputBoxes[$key]
      if ($null -eq $meta) { continue }
      $field = $meta.Field
      $isSecret = $true
      if ($null -ne $field.PSObject.Properties['secret']) {
        $isSecret = [bool]$field.secret
      } elseif ([string]$field.kind -eq 'text') {
        $isSecret = $false
      }
      if (-not $isSecret) {
        $publicValues[$key] = [string]$values[$key]
      }
    }

    $script:SaveOk = $true
    $script:WriteReport = @{
      ok = $true
      cancelled = $false
      project = [string]$formObj.project
      title = [string]$formObj.title
      written = @($written)
      actions = $actions
      public_values = $publicValues
      secret_keys = @($written | Where-Object { -not $publicValues.ContainsKey($_) })
      field_count = $fields.Count
      live_secret_written = $true
      authorization_ready = $false
      helper_vault_free = $true
      agent_secret_visible = $false
      env_inject_forbidden = $true
    }
    $ui.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ui.Close()
  }
  catch {
    $status.ForeColor = [System.Drawing.Color]::DarkRed
    $status.Text = "Speichern fehlgeschlagen ($($_.Exception.Message))."
    $btnOk.Enabled = $true
    $btnCancel.Enabled = $true
  }
  finally {
    foreach ($k in @($values.Keys)) { $values[$k] = $null }
    Clear-SecretBoxes
    [GC]::Collect()
  }
})

$result = $ui.ShowDialog()
Clear-SecretBoxes
[GC]::Collect()

if ($script:SaveOk -eq $true -and $null -ne $script:WriteReport) {
  Write-Result $script:WriteReport 0
}

if ($result -eq [System.Windows.Forms.DialogResult]::Cancel -or $result -eq [System.Windows.Forms.DialogResult]::None) {
  Write-Result @{
    ok = $false
    cancelled = $true
    code = 'cancelled'
    authorization_ready = $false
    helper_vault_free = $true
    agent_secret_visible = $false
  } 1
}

Write-Result @{
  ok = $false
  cancelled = $false
  code = 'dialog_failed'
  authorization_ready = $false
  helper_vault_free = $true
  agent_secret_visible = $false
} 1
