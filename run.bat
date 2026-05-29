@echo off
echo.
echo   ╔══════════════════════════════════════════════╗
echo   ║     CLOUDOSINT TOOLKIT  v3.0                 ║
echo   ║     12 Real Modules — Full Cloud OSINT       ║
echo   ╚══════════════════════════════════════════════╝
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Install Python 3.9+ from python.org
    pause
    exit /b
)

if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
)

echo [*] Activating virtualenv...
call venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -r requirements.txt --quiet

echo.
echo [OK] Starting server...
echo [OK] Open http://127.0.0.1:5000 in your browser
echo.

python app.py
pause
