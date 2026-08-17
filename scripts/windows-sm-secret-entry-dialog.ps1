# Windows WinForms secret-entry dialog for agent-callable SM writes.
# Reads a value-free form JSON file. Writes secrets via live:sm-write stdin.
# Emits only value-free JSON on stdout. Never prints secret values.
# Visual theme: warm paper vault ledger. Source is ASCII-only (no mojibake).
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
[System.Windows.Forms.Application]::EnableVisualStyles()

$bwTypes = @'
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public static class BwDraw {
  public static GraphicsPath RoundRect(Rectangle r, int radius) {
    int d = Math.Max(2, radius * 2);
    if (d > r.Width) d = Math.Max(2, r.Width);
    if (d > r.Height) d = Math.Max(2, r.Height);
    GraphicsPath p = new GraphicsPath();
    p.AddArc(r.X, r.Y, d, d, 180, 90);
    p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
    p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
    p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
    p.CloseFigure();
    return p;
  }
}

public static class BwNative {
  [DllImport("user32.dll")]
  public static extern bool SetProcessDPIAware();
  [DllImport("dwmapi.dll")]
  public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
  public static void RoundCorners(IntPtr hwnd) {
    int pref = 2;
    DwmSetWindowAttribute(hwnd, 33, ref pref, 4);
  }
}

public class BwRoundPanel : Panel {
  int _radius = 12;
  int _border = 1;
  int _accent = 0;
  Color _fill = Color.White;
  Color _borderColor = Color.Silver;
  Color _accentColor = Color.Transparent;
  string _caption = "";
  Font _captionFont;
  Color _captionColor = Color.Black;

  public BwRoundPanel() {
    SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
    BackColor = Color.Transparent;
  }

  public int CornerRadius { get { return _radius; } set { _radius = value; Invalidate(); } }
  public int BorderThickness { get { return _border; } set { _border = value; Invalidate(); } }
  public int AccentWidth { get { return _accent; } set { _accent = value; Invalidate(); } }
  public Color FillColor { get { return _fill; } set { _fill = value; Invalidate(); } }
  public Color BorderColor { get { return _borderColor; } set { _borderColor = value; Invalidate(); } }
  public Color AccentColor { get { return _accentColor; } set { _accentColor = value; Invalidate(); } }
  public string Caption { get { return _caption; } set { _caption = value ?? ""; Invalidate(); } }
  public Font CaptionFont { get { return _captionFont; } set { _captionFont = value; Invalidate(); } }
  public Color CaptionColor { get { return _captionColor; } set { _captionColor = value; Invalidate(); } }

  protected override void OnPaintBackground(PaintEventArgs e) { }

  protected override void OnPaint(PaintEventArgs e) {
    e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
    Rectangle r = new Rectangle(0, 0, Math.Max(1, Width - 1), Math.Max(1, Height - 1));
    using (GraphicsPath path = BwDraw.RoundRect(r, _radius))
    using (SolidBrush brush = new SolidBrush(_fill))
    using (Pen pen = new Pen(_borderColor, Math.Max(1, _border))) {
      e.Graphics.FillPath(brush, path);
      if (_accent > 0 && _accentColor.A > 0) {
        e.Graphics.SetClip(path);
        using (SolidBrush ab = new SolidBrush(_accentColor)) {
          e.Graphics.FillRectangle(ab, new Rectangle(r.X, r.Y, _accent, r.Height + 1));
        }
        e.Graphics.ResetClip();
      }
      e.Graphics.DrawPath(pen, path);
    }
    if (!string.IsNullOrEmpty(_caption) && _captionFont != null) {
      TextRenderer.DrawText(
        e.Graphics,
        _caption,
        _captionFont,
        ClientRectangle,
        _captionColor,
        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding
      );
    }
  }
}

public class BwRoundButton : Button {
  bool _hover;
  bool _down;
  public int CornerRadius = 10;
  public Color Fill = Color.Navy;
  public Color FillHover = Color.Blue;
  public Color FillDown = Color.DarkBlue;
  public Color FillDisabled = Color.FromArgb(210, 206, 198);
  public Color BorderColor = Color.Transparent;
  public int BorderThickness = 0;

  public BwRoundButton() {
    SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
    FlatStyle = FlatStyle.Flat;
    FlatAppearance.BorderSize = 0;
    Cursor = Cursors.Hand;
    TabStop = true;
  }

  protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
  protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
  protected override void OnMouseDown(MouseEventArgs e) {
    if (e.Button == MouseButtons.Left) { _down = true; Invalidate(); }
    base.OnMouseDown(e);
  }
  protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
  protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
  protected override void OnPaintBackground(PaintEventArgs e) { }

  protected override void OnPaint(PaintEventArgs e) {
    e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
    Color fill = !Enabled ? FillDisabled : _down ? FillDown : _hover ? FillHover : Fill;
    int inset = _down ? 1 : 0;
    Rectangle r = new Rectangle(inset, inset, Math.Max(1, Width - 1 - inset * 2), Math.Max(1, Height - 1 - inset * 2));
    using (GraphicsPath path = BwDraw.RoundRect(r, CornerRadius))
    using (SolidBrush brush = new SolidBrush(fill)) {
      e.Graphics.FillPath(brush, path);
      if (BorderThickness > 0 && BorderColor.A > 0) {
        using (Pen pen = new Pen(BorderColor, BorderThickness)) {
          e.Graphics.DrawPath(pen, path);
        }
      }
    }
    Color text = Enabled ? ForeColor : Color.FromArgb(140, 134, 126);
    TextRenderer.DrawText(
      e.Graphics,
      Text,
      Font,
      ClientRectangle,
      text,
      TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding
    );
  }
}
'@

function Write-Result([hashtable]$Object, [int]$Code = 0) {
  $json = ($Object | ConvertTo-Json -Compress -Depth 6)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $stdout = [Console]::OpenStandardOutput()
  $stdout.Write($bytes, 0, $bytes.Length)
  exit $Code
}

if (-not ('BwRoundPanel' -as [type])) {
  try {
    $fwDir = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    Add-Type -TypeDefinition $bwTypes -ReferencedAssemblies @(
      (Join-Path $fwDir 'System.Windows.Forms.dll'),
      (Join-Path $fwDir 'System.Drawing.dll'),
      (Join-Path $fwDir 'System.dll')
    )
  } catch {
    Write-Result @{ ok = $false; code = 'dialog_ui_init_failed' } 1
  }
}

try { [void][BwNative]::SetProcessDPIAware() } catch { }

function Measure-UiText([string]$Text, [System.Drawing.Font]$Font, [int]$Width) {
  if ([string]::IsNullOrEmpty($Text)) { return 0 }
  $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor [System.Windows.Forms.TextFormatFlags]::TextBoxControl -bor [System.Windows.Forms.TextFormatFlags]::NoPadding
  $size = [System.Windows.Forms.TextRenderer]::MeasureText(
    $Text,
    $Font,
    (New-Object System.Drawing.Size($Width, 4096)),
    $flags
  )
  return [Math]::Max(16, $size.Height)
}

function New-Chip {
  param(
    [string]$Text,
    [System.Drawing.Color]$Fore,
    [System.Drawing.Color]$Back,
    [System.Drawing.Color]$Border
  )
  $panel = New-Object BwRoundPanel
  $panel.Height = 24
  $panel.CornerRadius = 12
  $panel.FillColor = $Back
  $panel.BorderColor = $Border
  $panel.BorderThickness = 1
  $width = [System.Windows.Forms.TextRenderer]::MeasureText($Text, $fontChip).Width + 20
  $panel.Width = $width
  $panel.Caption = $Text
  $panel.CaptionFont = $fontChip
  $panel.CaptionColor = $Fore
  return $panel
}

# Warm paper vault ledger
$cCanvas     = [System.Drawing.Color]::FromArgb(243, 241, 236)
$cCard       = [System.Drawing.Color]::FromArgb(255, 255, 255)
$cInk        = [System.Drawing.Color]::FromArgb(28, 25, 23)
$cMuted      = [System.Drawing.Color]::FromArgb(92, 86, 80)
$cLine       = [System.Drawing.Color]::FromArgb(228, 223, 215)
$cInput      = [System.Drawing.Color]::FromArgb(250, 248, 244)
$cInputBorder = [System.Drawing.Color]::FromArgb(214, 208, 198)
$cAccent     = [System.Drawing.Color]::FromArgb(30, 64, 175)
$cAccentHover = [System.Drawing.Color]::FromArgb(37, 78, 201)
$cAccentDown = [System.Drawing.Color]::FromArgb(23, 49, 140)
$cAccentSoft = [System.Drawing.Color]::FromArgb(238, 242, 255)
$cPublic     = [System.Drawing.Color]::FromArgb(15, 118, 110)
$cPublicBg   = [System.Drawing.Color]::FromArgb(240, 253, 250)
$cPublicLine = [System.Drawing.Color]::FromArgb(153, 246, 228)
$cSecret     = [System.Drawing.Color]::FromArgb(180, 83, 9)
$cSecretBg   = [System.Drawing.Color]::FromArgb(255, 247, 237)
$cSecretLine = [System.Drawing.Color]::FromArgb(253, 186, 116)
$cDanger     = [System.Drawing.Color]::FromArgb(185, 28, 28)
$cCancelFill = [System.Drawing.Color]::FromArgb(255, 255, 255)
$cCancelHover = [System.Drawing.Color]::FromArgb(250, 248, 244)
$cDisabled   = [System.Drawing.Color]::FromArgb(210, 206, 198)

$fontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 15)
$fontBody  = New-Object System.Drawing.Font('Segoe UI', 9.5)
$fontSmall = New-Object System.Drawing.Font('Segoe UI', 8.5)
$fontChip  = New-Object System.Drawing.Font('Segoe UI Semibold', 8)
$fontLabel = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
$fontMono  = New-Object System.Drawing.Font('Consolas', 8.5)
$fontIcon  = $null
try { $fontIcon = New-Object System.Drawing.Font('Segoe MDL2 Assets', 13) } catch { $fontIcon = $null }

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

$formWidth = 580
$contentLeft = 28
$contentWidth = 524
$cardWidth = 524
$innerPad = 18
$innerLeft = $innerPad + 6
$innerWidth = $cardWidth - $innerLeft - $innerPad

$ui = New-Object System.Windows.Forms.Form
$ui.Text = [string]$formObj.title
$ui.StartPosition = 'CenterScreen'
$ui.FormBorderStyle = 'FixedDialog'
$ui.MaximizeBox = $false
$ui.MinimizeBox = $false
$ui.ShowInTaskbar = $true
$ui.ShowIcon = $false
$ui.TopMost = $true
$ui.BackColor = $cCanvas
$ui.ForeColor = $cInk
$ui.Font = $fontBody
$ui.KeyPreview = $true
$ui.Width = $formWidth

try {
  $prop = $ui.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'Instance,NonPublic')
  if ($null -ne $prop) { $prop.SetValue($ui, $true, $null) }
} catch { }

$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Width = $formWidth
$header.BackColor = $cCanvas
$ui.Controls.Add($header)

$hy = 22
if ($null -ne $fontIcon) {
  $iconHost = New-Object BwRoundPanel
  $iconHost.Location = New-Object System.Drawing.Point($contentLeft, $hy)
  $iconHost.Size = New-Object System.Drawing.Size(40, 40)
  $iconHost.CornerRadius = 12
  $iconHost.FillColor = $cAccentSoft
  $iconHost.BorderColor = [System.Drawing.Color]::FromArgb(199, 210, 254)
  $iconHost.BorderThickness = 1
  $iconHost.Caption = [string][char]0xE72E
  $iconHost.CaptionFont = $fontIcon
  $iconHost.CaptionColor = $cAccent
  $header.Controls.Add($iconHost)
  $titleLeft = $contentLeft + 52
  $titleWidth = $contentWidth - 52
} else {
  $titleLeft = $contentLeft
  $titleWidth = $contentWidth
}

$title = New-Object System.Windows.Forms.Label
$title.Location = New-Object System.Drawing.Point($titleLeft, ($hy + 8))
$title.Size = New-Object System.Drawing.Size($titleWidth, 28)
$title.Font = $fontTitle
$title.ForeColor = $cInk
$title.BackColor = $cCanvas
$title.Text = [string]$formObj.title
$title.AutoEllipsis = $true
$header.Controls.Add($title)
$hy = 74

$infoText = [string]$formObj.info
$infoHeight = Measure-UiText $infoText $fontBody $contentWidth
$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Location = New-Object System.Drawing.Point($contentLeft, $hy)
$lblInfo.Size = New-Object System.Drawing.Size($contentWidth, $infoHeight)
$lblInfo.Font = $fontBody
$lblInfo.ForeColor = $cMuted
$lblInfo.BackColor = $cCanvas
$lblInfo.Text = $infoText
$header.Controls.Add($lblInfo)
$hy += ($infoHeight + 14)

$chipProject = New-Chip -Text ([string]$formObj.project) -Fore $cAccent -Back $cAccentSoft -Border ([System.Drawing.Color]::FromArgb(199, 210, 254))
$chipProject.Location = New-Object System.Drawing.Point($contentLeft, $hy)
$header.Controls.Add($chipProject)

$chipSm = New-Chip -Text 'Secrets Manager' -Fore $cMuted -Back $cCard -Border $cLine
$chipSm.Location = New-Object System.Drawing.Point(($contentLeft + $chipProject.Width + 8), $hy)
$header.Controls.Add($chipSm)
$hy += 36

$rule = New-Object System.Windows.Forms.Panel
$rule.BackColor = $cLine
$rule.Location = New-Object System.Drawing.Point($contentLeft, $hy)
$rule.Size = New-Object System.Drawing.Size($contentWidth, 1)
$header.Controls.Add($rule)
$hy += 12
$header.Height = $hy

$fieldsHost = New-Object System.Windows.Forms.Panel
$fieldsHost.Location = New-Object System.Drawing.Point(0, $header.Height)
$fieldsHost.Width = $formWidth
$fieldsHost.BackColor = $cCanvas
$fieldsHost.AutoScroll = $true
$ui.Controls.Add($fieldsHost)

$fy = 8
$inputBoxes = @{}

foreach ($field in $fields) {
  $isSecret = $true
  if ($null -ne $field.PSObject.Properties['secret']) {
    $isSecret = [bool]$field.secret
  } elseif ([string]$field.kind -eq 'text') {
    $isSecret = $false
  }

  $hintText = ''
  if ($null -ne $field.hint -and [string]$field.hint -ne '') {
    $hintText = [string]$field.hint
  }
  $hintH = 0
  if ($hintText -ne '') {
    $hintH = Measure-UiText $hintText $fontSmall $innerWidth
  }

  $cardH = 14 + 22 + 18 + $(if ($hintH -gt 0) { $hintH + 8 } else { 0 }) + 42 + 16
  $card = New-Object BwRoundPanel
  $card.Location = New-Object System.Drawing.Point($contentLeft, $fy)
  $card.Size = New-Object System.Drawing.Size($cardWidth, $cardH)
  $card.CornerRadius = 14
  $card.FillColor = $cCard
  $card.BorderColor = $cLine
  $card.BorderThickness = 1
  $card.AccentWidth = 5
  if ($isSecret) {
    $card.AccentColor = $cSecret
  } else {
    $card.AccentColor = $cPublic
  }
  $fieldsHost.Controls.Add($card)

  $cy = 14
  $req = if ($field.required -eq $true) { '' } else { '  (optional)' }
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point($innerLeft, $cy)
  $lbl.Size = New-Object System.Drawing.Size(($innerWidth - 88), 22)
  $lbl.Font = $fontLabel
  $lbl.ForeColor = $cInk
  $lbl.BackColor = $cCard
  $lbl.Text = ([string]$field.label + $req)
  $lbl.AutoEllipsis = $true
  $card.Controls.Add($lbl)

  if ($isSecret) {
    $badge = New-Chip -Text 'Secret' -Fore $cSecret -Back $cSecretBg -Border $cSecretLine
  } else {
    $badge = New-Chip -Text 'Public' -Fore $cPublic -Back $cPublicBg -Border $cPublicLine
  }
  $badge.Location = New-Object System.Drawing.Point(($cardWidth - $innerPad - $badge.Width), $cy)
  $card.Controls.Add($badge)
  $cy += 24

  $keyHint = New-Object System.Windows.Forms.Label
  $keyHint.Location = New-Object System.Drawing.Point($innerLeft, $cy)
  $keyHint.Size = New-Object System.Drawing.Size($innerWidth, 16)
  $keyHint.Font = $fontMono
  $keyHint.ForeColor = $cMuted
  $keyHint.BackColor = $cCard
  $keyHint.Text = [string]$field.sm_key
  $card.Controls.Add($keyHint)
  $cy += 20

  if ($hintH -gt 0) {
    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point($innerLeft, $cy)
    $hint.Size = New-Object System.Drawing.Size($innerWidth, $hintH)
    $hint.Font = $fontSmall
    $hint.ForeColor = $cMuted
    $hint.BackColor = $cCard
    $hint.Text = $hintText
    $card.Controls.Add($hint)
    $cy += ($hintH + 8)
  }

  $isPassword = ([string]$field.kind -eq 'password')
  $inputHost = New-Object BwRoundPanel
  $inputHost.Location = New-Object System.Drawing.Point($innerLeft, $cy)
  $inputHost.Size = New-Object System.Drawing.Size($innerWidth, 42)
  $inputHost.CornerRadius = 10
  $inputHost.FillColor = $cInput
  $inputHost.BorderColor = $cInputBorder
  $inputHost.BorderThickness = 1
  $card.Controls.Add($inputHost)

  $toggleW = 0
  if ($isPassword) { $toggleW = 52 }

  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = New-Object System.Drawing.Point(12, 11)
  $box.Size = New-Object System.Drawing.Size(($innerWidth - 24 - $toggleW), 20)
  $box.Font = $fontBody
  $box.BackColor = $cInput
  $box.ForeColor = $cInk
  $box.BorderStyle = 'None'
  $maxLen = if ($null -ne $field.max_length) { [int]$field.max_length } else { 4096 }
  $box.MaxLength = $maxLen
  if ($isPassword) {
    $box.UseSystemPasswordChar = $true
  }
  $inputHost.Controls.Add($box)

  $box.Add_GotFocus({
    $this.Parent.BorderColor = $cAccent
    $this.Parent.Invalidate()
  })
  $box.Add_LostFocus({
    $this.Parent.BorderColor = $cInputBorder
    $this.Parent.Invalidate()
  })

  if ($isPassword) {
    $toggle = New-Object System.Windows.Forms.Button
    $toggle.Text = 'Show'
    $toggle.Font = $fontChip
    $toggle.ForeColor = $cAccent
    $toggle.BackColor = $cInput
    $toggle.FlatStyle = 'Flat'
    $toggle.FlatAppearance.BorderSize = 0
    $toggle.Cursor = [System.Windows.Forms.Cursors]::Hand
    $toggle.Location = New-Object System.Drawing.Point(($innerWidth - 56), 6)
    $toggle.Size = New-Object System.Drawing.Size(48, 30)
    $toggle.TabStop = $false
    $toggle.Tag = $box
    $toggle.Add_Click({
      $target = [System.Windows.Forms.TextBox]$this.Tag
      $target.UseSystemPasswordChar = -not $target.UseSystemPasswordChar
      if ($target.UseSystemPasswordChar) { $this.Text = 'Show' } else { $this.Text = 'Hide' }
    })
    $inputHost.Controls.Add($toggle)
  }

  $inputBoxes[[string]$field.sm_key] = @{
    Box = $box
    Field = $field
  }
  $fy += ($cardH + 12)
}

$fieldsContentH = $fy + 4
$fieldsViewH = [Math]::Min(440, [Math]::Max(120, $fieldsContentH))
$fieldsHost.Height = $fieldsViewH
$fieldsHost.AutoScrollMinSize = New-Object System.Drawing.Size(0, $fieldsContentH)

$footer = New-Object System.Windows.Forms.Panel
$footer.Width = $formWidth
$footer.Height = 96
$footer.BackColor = $cCanvas
$footer.Location = New-Object System.Drawing.Point(0, ($header.Height + $fieldsViewH))
$ui.Controls.Add($footer)

$footRule = New-Object System.Windows.Forms.Panel
$footRule.BackColor = $cLine
$footRule.Location = New-Object System.Drawing.Point($contentLeft, 0)
$footRule.Size = New-Object System.Drawing.Size($contentWidth, 1)
$footer.Controls.Add($footRule)

$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point($contentLeft, 12)
$status.Size = New-Object System.Drawing.Size(($contentWidth - 232), 40)
$status.Font = $fontSmall
$status.ForeColor = $cDanger
$status.BackColor = $cCanvas
$status.Text = ''
$footer.Controls.Add($status)

$btnCancel = New-Object BwRoundButton
$btnCancel.Text = 'Cancel'
$btnCancel.Location = New-Object System.Drawing.Point(($contentLeft + $contentWidth - 220), 40)
$btnCancel.Size = New-Object System.Drawing.Size(100, 40)
$btnCancel.Font = $fontBody
$btnCancel.ForeColor = $cInk
$btnCancel.Fill = $cCancelFill
$btnCancel.FillHover = $cCancelHover
$btnCancel.FillDown = $cLine
$btnCancel.FillDisabled = $cDisabled
$btnCancel.BorderColor = $cInputBorder
$btnCancel.BorderThickness = 1
$btnCancel.CornerRadius = 10
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$footer.Controls.Add($btnCancel)
$ui.CancelButton = $btnCancel

$btnOk = New-Object BwRoundButton
$btnOk.Text = 'Save'
$btnOk.Location = New-Object System.Drawing.Point(($contentLeft + $contentWidth - 108), 40)
$btnOk.Size = New-Object System.Drawing.Size(108, 40)
$btnOk.Font = $fontLabel
$btnOk.ForeColor = [System.Drawing.Color]::White
$btnOk.Fill = $cAccent
$btnOk.FillHover = $cAccentHover
$btnOk.FillDown = $cAccentDown
$btnOk.FillDisabled = $cDisabled
$btnOk.CornerRadius = 10
$footer.Controls.Add($btnOk)
$ui.AcceptButton = $btnOk

$ui.ClientSize = New-Object System.Drawing.Size($formWidth, ($header.Height + $fieldsViewH + $footer.Height))

$ui.Add_Shown({
  try { [BwNative]::RoundCorners($ui.Handle) } catch { }
  $ui.TopMost = $true
  $ui.Activate()
  $ui.BringToFront()
  [void][System.Windows.Forms.Application]::DoEvents()
  $firstKey = [string]$fields[0].sm_key
  if ($inputBoxes.ContainsKey($firstKey)) { $inputBoxes[$firstKey].Box.Focus() }
})

function Clear-SecretBoxes {
  foreach ($key in @($inputBoxes.Keys)) {
    $inputBoxes[$key].Box.Text = ''
  }
}

function Set-DialogBusy([bool]$Busy) {
  $btnOk.Enabled = -not $Busy
  $btnCancel.Enabled = -not $Busy
  foreach ($key in @($inputBoxes.Keys)) {
    $inputBoxes[$key].Box.Enabled = -not $Busy
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
      $meta.Box.Focus()
      return
    }
    if ($text.Length -gt 0 -and ($text.Length -lt $minLen -or $text.Length -gt $maxLen)) {
      $status.Text = ('Invalid length: ' + [string]$field.label)
      $meta.Box.Focus()
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

  Set-DialogBusy $true
  $status.ForeColor = $cMuted
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
    Set-DialogBusy $false
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
