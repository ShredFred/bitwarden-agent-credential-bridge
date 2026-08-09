; Inno Setup script — Bitwarden Agent Credential Bridge (SM same-user)
; Build with ISCC.exe on Windows. See docs/phase15-windows-installer.md

#define MyAppName "Bitwarden Agent Credential Bridge"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Bitwarden Agent Credential Bridge Maintainers"
#define MyAppURL "https://github.com/ShredFred/bitwarden-agent-credential-bridge"
#define MyAppExeName "Setup Bridge.cmd"

[Setup]
AppId={{A7C3E91F-5B2D-4E8A-9F01-BRIDGE15SM0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\BitwardenAgentCredentialBridge
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\dist\installer
OutputBaseFilename=BitwardenAgentCredentialBridge-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayName={#MyAppName}
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut for Setup"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Application tree (no .git, no node_modules — npm ci runs after install)
Source: "..\..\package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\package-lock.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\AGENTS.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\policies\*"; DestDir: "{app}\policies"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\samples\*"; DestDir: "{app}\samples"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "launchers\*"; DestDir: "{app}\installer\windows\launchers"; Flags: ignoreversion

[Icons]
Name: "{group}\Setup Bridge"; Filename: "{app}\installer\windows\launchers\Setup Bridge.cmd"; WorkingDir: "{app}"
Name: "{group}\Start Bridge"; Filename: "{app}\installer\windows\launchers\Start Bridge.cmd"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Setup Bridge"; Filename: "{app}\installer\windows\launchers\Setup Bridge.cmd"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "npm.cmd"; Parameters: "ci"; WorkingDir: "{app}"; StatusMsg: "Installing Node dependencies…"; Flags: runhidden waituntilterminated
Filename: "{app}\installer\windows\launchers\Setup Bridge.cmd"; Description: "Run guided Secrets Manager setup now"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
Filename: "node.exe"; Parameters: "scripts\uninstall-sm-machine.mjs --i-approve-sm-machine-uninstall"; WorkingDir: "{app}"; RunOnceId: "ClearSmLocalState"; Flags: runhidden waituntilterminated skipifdoesntexist

[Code]
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if Exec('node.exe', '-v', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) = False then
  begin
    MsgBox('Node.js 20+ is required. Install Node.js, then re-run this Setup.', mbError, MB_OK);
    Result := False;
  end;
end;
