#!/usr/bin/env python3
"""
Build script to convert app.py to app.exe for Windows
Run: python build_exe.py
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a shell command and handle errors"""
    print(f"\n{'='*60}")
    print(f"→ {description}")
    print(f"{'='*60}\n")
    
    try:
        result = subprocess.run(cmd, check=True, shell=True)
        print(f"\n✓ {description} completato!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Errore durante {description.lower()}")
        print(f"Codice errore: {e.returncode}")
        return False
    except Exception as e:
        print(f"\n✗ Errore: {e}")
        return False

def main():
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    # Get the Python executable from venv
    if sys.platform == "win32":
        python_exe = project_dir / ".venv" / "Scripts" / "python.exe"
    else:
        python_exe = project_dir / ".venv" / "bin" / "python"
    
    if not python_exe.exists():
        print(f"❌ Python executable not found at: {python_exe}")
        print("Make sure the venv is set up correctly.")
        return 1
    
    print(f"🐍 Using Python from: {python_exe}\n")
    
    # Step 1: Install PyInstaller
    print("📦 Step 1: Installing dependencies...")
    cmd_pip = f'"{python_exe}" -m pip install pyinstaller --quiet'
    if not run_command(cmd_pip, "PyInstaller installation"):
        return 1
    
    # Step 2: Build the exe in console mode (foreground)
    print("\n🔨 Step 2: Creating executable...")
    cmd_build = f'"{python_exe}" -m PyInstaller --noconfirm --onefile --console --distpath . --name app --add-data "index.html;." app.py'
    if not run_command(cmd_build, "PyInstaller build"):
        return 1
    
    # Step 3: Check result
    exe_path = project_dir / "app.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n✅ SUCCESS!")
        print(f"   📁 Executable created: {exe_path}")
        print(f"   📊 Size: {size_mb:.2f} MB")
        print(f"\n💡 You can now run: .\\app.exe")
        return 0
    else:
        print(f"\n❌ Error: {exe_path} was not created")
        return 1

if __name__ == "__main__":
    sys.exit(main())
