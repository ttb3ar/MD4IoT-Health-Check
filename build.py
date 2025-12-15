"""
Automated build script for MD4IoT SSH Ping Check application
Handles PyInstaller compilation and Inno Setup installer creation
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

class BuildConfig:
    """Build configuration"""
    APP_NAME = "MD4IoT Sensor Health Check"
    APP_VERSION = "2.0.0"
    MAIN_SCRIPT = "MSH.py"
    ICON_FILE = "favicon.ico"
    
    # Directories
    DIST_DIR = "dist"
    BUILD_DIR = "build"
    INSTALLER_OUTPUT = "installer_output"
    
    # PyInstaller settings
    PYINSTALLER_ARGS = [
        "--onedir",
        "--noconsole",
        f"--icon={ICON_FILE}",
        f"--name={APP_NAME}",
        "--add-data", "translations/*.json;translations",
        "--add-data", f"{ICON_FILE};.",
        "--collect-all", "cryptography",
        "--collect-all", "netmiko",
        "--collect-all", "pandas",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "tkinter.scrolledtext",
        MAIN_SCRIPT
    ]


class Builder:
    """Handles the build process"""
    
    def __init__(self):
        self.config = BuildConfig()
        self.root_dir = Path.cwd()
        
    def clean(self):
        """Clean previous build artifacts"""
        print("🧹 Cleaning previous build artifacts...")
        
        dirs_to_clean = [
            self.config.DIST_DIR,
            self.config.BUILD_DIR,
            self.config.INSTALLER_OUTPUT
        ]
        
        for dir_name in dirs_to_clean:
            dir_path = self.root_dir / dir_name
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"   Removed: {dir_name}")
        
        # Remove .spec file
        spec_file = self.root_dir / f"{self.config.APP_NAME}.spec"
        if spec_file.exists():
            spec_file.unlink()
            print(f"   Removed: {spec_file.name}")
    
    def verify_files(self):
        """Verify required files exist"""
        print("🔍 Verifying required files...")
        
        required_files = [
            self.config.MAIN_SCRIPT,
            "core_classes.py",
            self.config.ICON_FILE
        ]
        
        required_dirs = ["translations"]
        
        missing = []
        
        for file in required_files:
            if not (self.root_dir / file).exists():
                missing.append(file)
                print(f"   ❌ Missing: {file}")
            else:
                print(f"   ✓ Found: {file}")
        
        for dir_name in required_dirs:
            if not (self.root_dir / dir_name).exists():
                missing.append(dir_name)
                print(f"   ❌ Missing directory: {dir_name}")
            else:
                print(f"   ✓ Found directory: {dir_name}")
        
        if missing:
            print(f"\n❌ Missing required files/directories: {', '.join(missing)}")
            return False
        
        return True
    
    def check_dependencies(self):
        """Check if required Python packages are installed"""
        print("📦 Checking dependencies...")
        
        # Check PyInstaller via command line (it's a CLI tool, not importable)
        try:
            result = subprocess.run(
                ["pyinstaller", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"   ✓ pyinstaller (version: {result.stdout.strip()})")
            else:
                print(f"   ❌ pyinstaller (not working)")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"   ❌ pyinstaller (not found)")
            print("Install with: pip install pyinstaller")
            return False
        
        # Check other packages via import
        required_packages = [
            "cryptography",
            "netmiko",
            "pandas"
        ]
        
        missing = []
        
        for package in required_packages:
            try:
                __import__(package)
                print(f"   ✓ {package}")
            except ImportError:
                missing.append(package)
                print(f"   ❌ {package}")
        
        if missing:
            print(f"\n⚠️  Missing packages: {', '.join(missing)}")
            print("Install with: pip install " + " ".join(missing))
            return False
        
        return True
    
    def run_pyinstaller(self):
        """Run PyInstaller to create executable"""
        print(f"\n🔨 Building executable with PyInstaller...")
        
        try:
            result = subprocess.run(
                ["pyinstaller"] + self.config.PYINSTALLER_ARGS,
                check=True,
                capture_output=True,
                text=True
            )
            print("   ✓ PyInstaller build successful")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"   ❌ PyInstaller failed:")
            print(e.stderr)
            return False
    
    def verify_build_output(self):
        """Verify the build output exists"""
        print("🔍 Verifying build output...")
        
        exe_path = self.root_dir / self.config.DIST_DIR / self.config.APP_NAME / f"{self.config.APP_NAME}.exe"
        
        if not exe_path.exists():
            print(f"   ❌ Executable not found at: {exe_path}")
            return False
        
        print(f"   ✓ Executable found: {exe_path}")
        
        # Check for translations directory and JSON files in dist
        translations_path = self.root_dir / self.config.DIST_DIR / self.config.APP_NAME / "translations"
        if not translations_path.exists():
            print(f"   ⚠️  Warning: translations directory not found in dist")
        else:
            json_files = list(translations_path.glob("*.json"))
            if not json_files:
                print(f"   ⚠️  Warning: No .json files found in translations directory")
            else:
                print(f"   ✓ Translations directory included with {len(json_files)} language files")
        
        return True
    
    def create_inno_setup_script(self):
        """Generate Inno Setup script"""
        print("📝 Creating Inno Setup script...")
        
        iss_content = f'''[Setup]
; Basic application information
AppName={self.config.APP_NAME}
AppVersion={self.config.APP_VERSION}
AppPublisher=MD4IoT
AppPublisherURL=https://github.com/yourusername/MD4IoT-Health-Check
AppSupportURL=https://github.com/yourusername/MD4IoT-Health-Check/issues
AppUpdatesURL=https://github.com/yourusername/MD4IoT-Health-Check/releases

; Installation directories
DefaultDirName={{autopf}}\\{self.config.APP_NAME}
DefaultGroupName={self.config.APP_NAME}
DisableProgramGroupPage=yes

; Output settings
OutputDir={self.config.INSTALLER_OUTPUT}
OutputBaseFilename=MD4IoT_Sensor_Health_Check_Setup_v{self.config.APP_VERSION}
SetupIconFile={self.config.ICON_FILE}
UninstallDisplayIcon={{app}}\\{self.config.APP_NAME}.exe

; Compression
Compression=lzma2/max
SolidCompression=yes

; Windows version requirements
MinVersion=6.1sp1
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Visual settings
WizardStyle=modern
DisableWelcomePage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\\Japanese.isl"

[Tasks]
Name: "desktopicon"; Description: "{{cm:CreateDesktopIcon}}"; GroupDescription: "{{cm:AdditionalIcons}}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{{cm:CreateQuickLaunchIcon}}"; GroupDescription: "{{cm:AdditionalIcons}}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode

[Files]
; Main application files (from PyInstaller --onedir output)
Source: "{self.config.DIST_DIR}\\{self.config.APP_NAME}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Include example credential file (optional)
; Source: "exampleCred.json"; DestDir: "{{app}}\\examples"; Flags: ignoreversion; Tasks: ; Languages: 

; Include README
; Source: "README.md"; DestDir: "{{app}}"; Flags: ignoreversion isreadme

[Icons]
Name: "{{group}}\\{self.config.APP_NAME}"; Filename: "{{app}}\\{self.config.APP_NAME}.exe"
Name: "{{group}}\\{{cm:UninstallProgram,{self.config.APP_NAME}}}"; Filename: "{{uninstallexe}}"
Name: "{{autodesktop}}\\{self.config.APP_NAME}"; Filename: "{{app}}\\{self.config.APP_NAME}.exe"; Tasks: desktopicon
Name: "{{userappdata}}\\Microsoft\\Internet Explorer\\Quick Launch\\{self.config.APP_NAME}"; Filename: "{{app}}\\{self.config.APP_NAME}.exe"; Tasks: quicklaunchicon

[Run]
Filename: "{{app}}\\{self.config.APP_NAME}.exe"; Description: "{{cm:LaunchProgram,{self.config.APP_NAME}}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up log files and configuration created by the application
Type: files; Name: "{{app}}\\sensor_check.log"
Type: files; Name: "{{app}}\\*.log"
Type: files; Name: "{{app}}\\config.json"
Type: files; Name: "{{app}}\\*.enc"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  // Pre-installation checks can be added here
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Post-installation tasks
    // Could create default config.json here if needed
  end;
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  
  // Ask user if they want to keep configuration and credential files
  if MsgBox('Do you want to keep your configuration files, encrypted credentials, and logs?' + #13#10 + #13#10 + 
            'Choose Yes to preserve your data for future installations.' + #13#10 +
            'Choose No to completely remove all application data.', 
            mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDYES then
  begin
    // User wants to keep files - skip cleanup
    // The [UninstallDelete] section will not execute for these
  end;
end;

[Dirs]
; Ensure application directory exists with proper permissions
Name: "{{app}}"; Permissions: users-modify
Name: "{{app}}\\translations"; Permissions: users-modify

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nMD4IoT Sensor Health Check is a sensor management tool designed for Microsoft Defender for IoT network sensors. It provides health checking capabilities via SSH and ping connectivity tests, with support for multiple languages.%n%nFeatures:%n• Encrypted credential storage%n• Remote sensor health checks%n• Multi-language support%n• Configurable test parameters%n• CSV export of results%n%nIt is recommended that you close all other applications before continuing.

FinishedLabel=Setup has finished installing [name] on your computer.%n%nThe application includes:%n• Support for English and Japanese languages%n• Secure encryption/decryption of sensor credentials%n• Comprehensive logging and reporting%n%nClick Finish to close Setup.
'''
        
        iss_file = self.root_dir / "installer.iss"
        with open(iss_file, 'w', encoding='utf-8') as f:
            f.write(iss_content)
        
        print(f"   ✓ Created: {iss_file.name}")
        return True
    
    def run_inno_setup(self):
        """Run Inno Setup compiler"""
        print("\n📦 Creating installer with Inno Setup...")
        
        # Try to find Inno Setup compiler
        iscc_paths = [
            r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
            r"C:\Program Files\Inno Setup 6\ISCC.exe",
            r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe",
            r"C:\Program Files\Inno Setup 5\ISCC.exe",
        ]
        
        iscc_exe = None
        for path in iscc_paths:
            if os.path.exists(path):
                iscc_exe = path
                break
        
        if not iscc_exe:
            print("   ⚠️  Inno Setup compiler not found at default locations")
            print("   Please run 'installer.iss' manually with Inno Setup")
            return False
        
        try:
            result = subprocess.run(
                [iscc_exe, "installer.iss"],
                check=True,
                capture_output=True,
                text=True
            )
            print("   ✓ Installer created successfully")
            
            # Show output location
            output_dir = self.root_dir / self.config.INSTALLER_OUTPUT
            if output_dir.exists():
                installers = list(output_dir.glob("*.exe"))
                if installers:
                    print(f"   📦 Installer: {installers[0]}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Inno Setup compilation failed:")
            print(e.stderr)
            return False
    
    def build(self):
        """Run the complete build process"""
        print("=" * 60)
        print(f"Building {self.config.APP_NAME} v{self.config.APP_VERSION}")
        print("=" * 60)
        
        # Step 1: Clean
        self.clean()
        
        # Step 2: Verify files
        if not self.verify_files():
            return False
        
        # Step 3: Check dependencies
        if not self.check_dependencies():
            return False
        
        # Step 4: Run PyInstaller
        if not self.run_pyinstaller():
            return False
        
        # Step 5: Verify output
        if not self.verify_build_output():
            return False
        
        # Step 6: Create Inno Setup script
        if not self.create_inno_setup_script():
            return False
        
        # Step 7: Run Inno Setup
        inno_success = self.run_inno_setup()
        
        # Summary
        print("\n" + "=" * 60)
        if inno_success:
            print("✅ BUILD COMPLETE")
            print(f"   Executable: {self.config.DIST_DIR}\\{self.config.APP_NAME}\\")
            print(f"   Installer: {self.config.INSTALLER_OUTPUT}\\")
        else:
            print("⚠️  BUILD PARTIALLY COMPLETE")
            print(f"   Executable: {self.config.DIST_DIR}\\{self.config.APP_NAME}\\")
            print("   Installer: Run 'installer.iss' manually with Inno Setup")
        print("=" * 60)
        
        return True


def main():
    """Main entry point"""
    builder = Builder()
    
    try:
        success = builder.build()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Build cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Build failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()