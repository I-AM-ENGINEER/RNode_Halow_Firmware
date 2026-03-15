@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem --------------------------------------------
rem RNode-HaLow Flasher GUI build for Windows
rem Builds single-file exe via PyInstaller
rem --------------------------------------------

cd /d "%~dp0"

set "APP_PY=rnode-halow-flasher-gui.py"
set "VENV_DIR=.venv"
set "DIST_DIR=dist"
set "BUILD_DIR=build"
set "SPEC_NAME=rnode-halow-flasher-gui"

if not exist "%APP_PY%" (
  echo [!] "%APP_PY%" not found in: %cd%
  exit /b 1
)

if not exist "modules\" (
  echo [!] "modules\" folder not found in: %cd%
  exit /b 1
)

if not exist "embedded_fw\" mkdir "embedded_fw"

rem --- pick python ---
set "PY=python"
where py >nul 2>nul
if %errorlevel%==0 (
  rem Prefer py launcher if present
  set "PY=py -3"
)

rem --- create venv (once) ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
  echo [*] Creating venv: %VENV_DIR%
  %PY% -m venv "%VENV_DIR%"
  if errorlevel 1 exit /b 1
)

set "VPY=%VENV_DIR%\Scripts\python.exe"
set "VPIP=%VENV_DIR%\Scripts\pip.exe"

echo [*] Upgrading pip/setuptools/wheel...
"%VPY%" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 exit /b 1

echo [*] Installing build deps (scapy, pyinstaller)...
"%VPIP%" install --upgrade scapy pyinstaller
if errorlevel 1 exit /b 1

rem --- clean old outputs ---
if exist "%DIST_DIR%\" rmdir /s /q "%DIST_DIR%"
if exist "%BUILD_DIR%\" rmdir /s /q "%BUILD_DIR%"
if exist "%SPEC_NAME%.spec" del /q "%SPEC_NAME%.spec" >nul 2>nul

rem --- build ---
echo [*] Building EXE...
"%VPY%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --noconsole ^
  --name "%SPEC_NAME%" ^
  --icon rns.ico ^
  --add-data "modules;modules" ^
  --add-data "embedded_fw;embedded_fw" ^
  --collect-all scapy ^
  "%APP_PY%"

if errorlevel 1 (
  echo [!] Build failed.
  exit /b 1
)

echo.
echo [OK] Done:
echo     %cd%\%DIST_DIR%\%SPEC_NAME%.exe
echo.
echo Note: On Windows you still need Npcap installed for packet capture (Scapy).
echo       https://npcap.com/dist/
echo.
pause
exit /b 0
