@echo off
REM Build script to convert app.py to app.exe for Windows

echo Installing PyInstaller in venv...
call .venv\Scripts\python.exe -m pip install pyinstaller

echo.
echo Creating executable with PyInstaller...
call .venv\Scripts\pyinstaller.exe --noconfirm --onefile --console --name app --distpath . --add-data "index.html;." app.py

echo.
echo Done! The executable is located at: app.exe
echo.
pause
