; Blazma Sandbox installer (Inno Setup 6).
; Built by scripts/publish.ps1 after the app is published to publish\BlazmaSandbox:
;   iscc /DAppVersion=0.1.0 /DSourceDir=..\publish\BlazmaSandbox /DOutputDir=..\publish installer\BlazmaSandbox.iss
;
; Installs for the current user only (no administrator rights), the same least-privilege
; model as the app itself. Analyses and settings in %LocalAppData%\Blazma\Sandbox are kept
; on uninstall so a reinstall or update does not lose the history.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish\BlazmaSandbox"
#endif
#ifndef OutputDir
  #define OutputDir "..\publish"
#endif

#define AppName "Blazma Sandbox"
#define AppExe "BlazmaSandbox.exe"
#define Developer "mr-kateba"

[Setup]
AppId={{6B0E8B7A-3C5D-4E2F-9A61-B1A2C3D4E5F6}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#Developer}
AppPublisherURL=https://github.com/mr-kateba
AppSupportURL=https://github.com/mr-kateba/Blazma-Sandbox
AppUpdatesURL=https://github.com/mr-kateba/Blazma-Sandbox
AppCopyright=Copyright (C) 2026 {#Developer}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#Developer}
VersionInfoProductName={#AppName}
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
SetupIconFile=..\assets\blazma-sandbox.ico
OutputDir={#OutputDir}
OutputBaseFilename=BlazmaSandbox-{#AppVersion}-setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=auto
ChangesEnvironment=yes
CloseApplications=yes

[Languages]
; Arabic first: most users read Arabic. Setup picks the language of Windows when it can.
Name: "ar"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
ar.DesktopIcon=إنشاء اختصار على سطح المكتب
en.DesktopIcon=Create a desktop shortcut
ar.ExplorerMenu=إضافة «تحليل باستخدام Blazma Sandbox» إلى قائمة الزر الأيمن في المستكشف
en.ExplorerMenu=Add "Analyze with Blazma Sandbox" to the Explorer right-click menu
ar.CliPath=إضافة الأمر blazma إلى سطر الأوامر (PATH)
en.CliPath=Add the blazma command to the command line (PATH)
ar.ExplorerMenuText=تحليل باستخدام Blazma Sandbox
en.ExplorerMenuText=Analyze with Blazma Sandbox
ar.Launch=تشغيل Blazma Sandbox
en.Launch=Start Blazma Sandbox
ar.Extras=خيارات إضافية:
en.Extras=Additional options:

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:Extras}"
Name: "explorermenu"; Description: "{cm:ExplorerMenu}"; GroupDescription: "{cm:Extras}"
Name: "clipath"; Description: "{cm:CliPath}"; GroupDescription: "{cm:Extras}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "{#AppName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; The same entry the app writes from Settings → General; removed on uninstall either way.
Root: HKCU; Subkey: "Software\Classes\*\shell\BlazmaSandbox"; ValueType: string; ValueName: ""; ValueData: "{cm:ExplorerMenuText}"; Tasks: explorermenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\BlazmaSandbox"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: explorermenu
Root: HKCU; Subkey: "Software\Classes\*\shell\BlazmaSandbox\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" --analyze ""%1"""; Tasks: explorermenu
Root: HKCU; Subkey: "Software\Classes\*\shell\BlazmaSandbox"; Flags: uninsdeletekey dontcreatekey

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:Launch}"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvKey = 'Environment';

function PathHasDir(Path, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure AddToUserPath(Dir: string);
var
  Path: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then Path := '';
  if PathHasDir(Path, Dir) then exit;
  if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then Path := Path + ';';
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path + Dir);
end;

procedure RemoveFromUserPath(Dir: string);
var
  Path: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then exit;
  Path := ';' + Path + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Path));
  if P = 0 then exit;
  Delete(Path, P, Length(Dir) + 1);
  Path := Copy(Path, 2, Length(Path) - 2);
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('clipath') then
    AddToUserPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromUserPath(ExpandConstant('{app}'));
end;
