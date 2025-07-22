[Setup]
AppName=MSP
AppVersion=2.0.0
AppPublisher=Your Name or Company
DefaultDirName={pf}\MD4IoT SSH Ping Check
DefaultGroupName=MD4IoT SSH Ping Check
OutputBaseFilename=MSP_Installer_v2.0.0
Compression=lzma
SolidCompression=yes

[Files]
; Main application EXE and all files in folder
Source: "Desktop\MD4IoT SSH Ping Check\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Desktop Shortcut
Name: "{desktop}\MSP"; Filename: "{app}\MD4IoT SSH Ping Check.exe"; WorkingDir: "{app}"

; Start Menu Shortcut
Name: "{group}\MSP"; Filename: "{app}\MD4IoT SSH Ping Check.exe"; WorkingDir: "{app}"

; Optional: Uninstall Shortcut in Start Menu
Name: "{group}\Uninstall MSP"; Filename: "{uninstallexe}"

[Run]
; Optional: Automatically run after installation
; Filename: "{app}\MD4IoT SSH Ping Check.exe"; Description: "Launch MSP"; Flags: nowait postinstall skipifsilent
