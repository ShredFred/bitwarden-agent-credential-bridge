# Windows WinForms secret-entry dialog for agent-callable SM writes.
# Reads a value-free form JSON file. Writes secrets via live:sm-write stdin.
# Emits only value-free JSON on stdout. Never prints secret values.
# Visual theme: clean modern macOS-inspired layout (calm, structured).
param(
  [Parameter(Mandatory = $true)][string]$FormPath,
  [Parameter(Mandatory = $true)][string]$BridgeRoot,
  [Parameter(Mandatory = $true)][string]$WriteApprovalFlag
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Write-Result([hashtable]$Object, [int]$Code = 0) {
  $json = ($Object | ConvertTo-Json -Compress -Depth 6)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $stdout = [Console]::OpenStandardOutput()
  $stdout.Write($bytes, 0, $bytes.Length)
  exit $Code
}

# Calm Apple-like palette on Windows
$cBg      = [System.Drawing.Color]::FromArgb(246, 246, 248)
$cCard    = [System.Drawing.Color]::FromArgb(255, 255, 255)
$cText    = [System.Drawing.Color]::FromArgb(29, 29, 31)
$cSecondary = [System.Drawing.Color]::FromArgb(110, 110, 115)
$cBorder  = [System.Drawing.Color]::FromArgb(210, 210, 215)
$cAccent  = [System.Drawing.Color]::FromArgb(0, 122, 255)
$cDanger  = [System.Drawing.Color]::FromArgb(255, 59, 48)
$cInputBg = [System.Drawing.Color]::FromArgb(255, 255, 255)
$cBtnSecondaryBg = [System.Drawing.Color]::FromArgb(242, 242, 247)

$fontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 13)
$fontBody  = New-Object System.Drawing.Font('Segoe UI', 9.5)
$fontSmall = New-Object System.Drawing.Font('Segoe UI', 8.5)
$fontLabel = New-Object System.Drawing.Font('Segoe UI Semibold', 9)

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

$localBws = Join-Path $env:LOCALAPPDATA 'Programs\Bitwarden'
if (Test-Path -LiteralPath $localBws) {
  $env:Path = "$localBws;$env:Path"
}

$formWidth = 560
$contentLeft = 28
$contentWidth = 504

$ui = New-Object System.Windows.Forms.Form
$ui.Text = [string]$formObj.title
$ui.StartPosition = 'CenterScreen'
$ui.FormBorderStyle = 'FixedDialog'
$ui.MaximizeBox = $false
$ui.MinimizeBox = $false
$ui.ShowInTaskbar = $true
$ui.TopMost = $true
$ui.BackColor = $cBg
$ui.ForeColor = $cText
$ui.Font = $fontBody
$ui.Width = $formWidth

$y = 24

$title = New-Object System.Windows.Forms.Label
$title.Location = New-Object System.Drawing.Point($contentLeft, $y)
$title.Size = New-Object System.Drawing.Size($contentWidth, 28)
$title.Font = $fontTitle
$title.ForeColor = $cText
$title.Text = [string]$formObj.title
$ui.Controls.Add($title)
$y += 34

$infoText = [string]$formObj.info
$infoLines = @($infoText -split "(`r`n|`n|`r)")
$infoHeight = [Math]::Max(40, (18 * [Math]::Max(1, $infoLines.Count)) + 8)

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Location = New-Object System.Drawing.Point($contentLeft, $y)
$lblInfo.Size = New-Object System.Drawing.Size($contentWidth, $infoHeight)
$lblInfo.Font = $fontBody
$lblInfo.ForeColor = $cSecondary
$lblInfo.Text = $infoText
$ui.Controls.Add($lblInfo)
$y += ($infoHeight + 10)

$lblMeta = New-Object System.Windows.Forms.Label
$lblMeta.Location = New-Object System.Drawing.Point($contentLeft, $y)
$lblMeta.Size = New-Object System.Drawing.Size($contentWidth, 18)
$lblMeta.Font = $fontSmall
$lblMeta.ForeColor = $cSecondary
$lblMeta.Text = ("Project  " + [string]$formObj.project + "    ·    Secrets Manager only")
$ui.Controls.Add($lblMeta)
$y += 28

$inputBoxes = @{}
foreach ($field in $fields) {
  $isSecret = $true
  if ($null -ne $field.PSObject.Properties['secret']) {
    $isSecret = [bool]$field.secret
  } elseif ([string]$field.kind -eq 'text') {
    $isSecret = $false
  }

  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point($contentLeft, $y)
  $lbl.Size = New-Object System.Drawing.Size($contentWidth, 18)
  $lbl.Font = $fontLabel
  $lbl.ForeColor = $cText
  $req = if ($field.required -eq $true) { '' } else { ' (optional)' }
  $lbl.Text = ([string]$field.label + $req)
  $ui.Controls.Add($lbl)
  $y += 20

  $keyHint = New-Object System.Windows.Forms.Label
  $keyHint.Location = New-Object System.Drawing.Point($contentLeft, $y)
  $keyHint.Size = New-Object System.Drawing.Size($contentWidth, 16)
  $keyHint.Font = $fontSmall
  $keyHint.ForeColor = $cSecondary
  $kindNote = if ($isSecret) { 'secret' } else { 'visible to agent' }
  $keyHint.Text = ([string]$field.sm_key + '  ·  ' + $kindNote)
  $ui.Controls.Add($keyHint)
  $y += 18

  if ($null -ne $field.hint -and [string]$field.hint -ne '') {
    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point($contentLeft, $y)
    $hint.Size = New-Object System.Drawing.Size($contentWidth, 16)
    $hint.Font = $fontSmall
    $hint.ForeColor = $cSecondary
    $hint.Text = [string]$field.hint
    $ui.Controls.Add($hint)
    $y += 18
  }

  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = New-Object System.Drawing.Point($contentLeft, $y)
  $box.Size = New-Object System.Drawing.Size($contentWidth, 28)
  $box.Font = $fontBody
  $box.BackColor = $cInputBg
  $box.ForeColor = $cText
  $box.BorderStyle = 'FixedSingle'
  if ([string]$field.kind -eq 'password') {
    $box.UseSystemPasswordChar = $true
  }
  $ui.Controls.Add($box)
  $inputBoxes[[string]$field.sm_key] = @{
    Box = $box
    Field = $field
  }
  $y += 40
}

$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point($contentLeft, $y)
$status.Size = New-Object System.Drawing.Size($contentWidth, 22)
$status.Font = $fontSmall
$status.ForeColor = $cDanger
$status.Text = ''
$ui.Controls.Add($status)
$y += 30

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel'
$btnCancel.Location = New-Object System.Drawing.Point(($contentLeft + $contentWidth - 210), $y)
$btnCancel.Size = New-Object System.Drawing.Size(96, 32)
$btnCancel.FlatStyle = 'Flat'
$btnCancel.FlatAppearance.BorderColor = $cBorder
$btnCancel.FlatAppearance.BorderSize = 1
$btnCancel.BackColor = $cBtnSecondaryBg
$btnCancel.ForeColor = $cText
$btnCancel.Font = $fontBody
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$ui.Controls.Add($btnCancel)
$ui.CancelButton = $btnCancel

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = 'Save'
$btnOk.Location = New-Object System.Drawing.Point(($contentLeft + $contentWidth - 102), $y)
$btnOk.Size = New-Object System.Drawing.Size(102, 32)
$btnOk.FlatStyle = 'Flat'
$btnOk.FlatAppearance.BorderSize = 0
$btnOk.BackColor = $cAccent
$btnOk.ForeColor = [System.Drawing.Color]::White
$btnOk.Font = $fontLabel
$ui.Controls.Add($btnOk)

$ui.Height = $y + 88

$ui.Add_Shown({
  $ui.TopMost = $true
  $ui.Activate()
  $ui.BringToFront()
  [void][System.Windows.Forms.Application]::DoEvents()
  $first = $inputBoxes.Values | Select-Object -First 1
  if ($null -ne $first) { $first.Box.Focus() }
})

function Clear-SecretBoxes {
  foreach ($key in @($inputBoxes.Keys)) {
    $inputBoxes[$key].Box.Text = ''
  }
}

$script:SaveOk = $false
$script:WriteReport = $null

$btnOk.Add_Click({
  $status.ForeColor = $cDanger
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
      $status.Text = ('Required: ' + [string]$field.label)
      return
    }
    if ($text.Length -gt 0 -and ($text.Length -lt $minLen -or $text.Length -gt $maxLen)) {
      $status.Text = ('Invalid length: ' + [string]$field.label)
      return
    }
    if ($text.Length -gt 0) {
      $values[$key] = $text
    }
  }

  if ($values.Count -lt 1) {
    $status.Text = 'Nothing to save.'
    return
  }

  $btnOk.Enabled = $false
  $btnCancel.Enabled = $false
  $status.ForeColor = $cSecondary
  $status.Text = 'Saving...'

  $written = New-Object System.Collections.Generic.List[string]
  $actions = @{}
  try {
    foreach ($key in @($values.Keys)) {
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
    $status.ForeColor = $cDanger
    $status.Text = ('Could not save (' + $_.Exception.Message + ')')
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
