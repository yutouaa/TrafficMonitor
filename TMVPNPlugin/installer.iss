[Setup]
AppId=TrafficMonitor-VPN-x64
AppName=TrafficMonitor VPN
AppVersion=1.86
DefaultDirName={autopf}\TrafficMonitor VPN
DefaultGroupName=TrafficMonitor VPN
UninstallDisplayIcon={app}\TrafficMonitor.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.17763
DisableProgramGroupPage=yes
CloseApplications=no
RestartApplications=no
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
LicenseFile={#Payload}\LICENSE.txt

[Files]
Source: "{#Stage}\vc_redist.x64.exe"; Flags: dontcopy noencryption
Source: "{#Payload}\config.ini"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#Payload}\global_cfg.ini"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#Payload}\*"; DestDir: "{app}"; Excludes: "\config.ini,\global_cfg.ini"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\TrafficMonitor VPN"; Filename: "{app}\TrafficMonitor.exe"; WorkingDir: "{app}"

[Code]
function HasVCRuntime: Boolean;
var
  Key: String;
  Installed, Major, Minor, Build: Cardinal;
begin
  Key := 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64';
  Result := RegQueryDWordValue(HKLM64, Key, 'Installed', Installed) and (Installed = 1) and
    RegQueryDWordValue(HKLM64, Key, 'Major', Major) and
    RegQueryDWordValue(HKLM64, Key, 'Minor', Minor) and
    RegQueryDWordValue(HKLM64, Key, 'Bld', Build) and
    ((Major > 14) or ((Major = 14) and
      ((Minor > 51) or ((Minor = 51) and (Build >= 36247)))));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\TrafficMonitor.exe')) and
     not FileExists(ExpandConstant('{app}\package-commit.txt')) then
  begin
    Result := 'Choose a separate folder. The selected folder already contains TrafficMonitor.';
    Exit;
  end;
  if HasVCRuntime then Exit;
  ExtractTemporaryFile('vc_redist.x64.exe');
  if not Exec(ExpandConstant('{tmp}\vc_redist.x64.exe'), '/install /quiet /norestart', '',
              SW_HIDE, ewWaitUntilTerminated, ExitCode) then
  begin
    Result := 'Could not start the Microsoft Visual C++ runtime installer.';
    Exit;
  end;
  if ExitCode = 3010 then
  begin
    NeedsRestart := True;
    Result := 'Restart Windows before running this setup again.';
  end else if ((ExitCode <> 0) and (ExitCode <> 1638)) or not HasVCRuntime then
    Result := 'Microsoft Visual C++ runtime installation failed (exit ' + IntToStr(ExitCode) + ').';
end;
