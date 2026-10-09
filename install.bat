@echo off
REM ==============================================================================
REM RogueByte WhatsApp Forensics Ultimate v2.0 - Windows Native Setup & Launcher
REM Brand: RogueByteOfficial
REM ==============================================================================

echo ╔════════════════════════════════════════════════════════════════════════════════╗
echo ║          ROGUEBYTE WHATSAPP FORENSICS ULTIMATE v2.0 (WINDOWS)                  ║
echo ║                          Brand: RogueByteOfficial                              ║
echo ╚════════════════════════════════════════════════════════════════════════════════╝
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not found in PATH. Please install Python 3.9+ from python.org.
    pause
    exit /b 1
)

echo [*] Python detected. Verifying standard forensic modules...
python -c "import sqlite3, hashlib, struct, unittest, json, pathlib, ipaddress, socket; print('    Core Forensic Standard Modules: OK')"

echo [*] Running automated forensic test verification suite...
set PYTHONPATH=.
python -m unittest discover roguebyte_forensics\tests -v

echo.
echo [✓] Setup Complete.
echo To launch interactive terminal menu:
echo     python roguebyte.py -i
echo.
echo To launch desktop workstation:
echo     npm run dev
echo.
pause
