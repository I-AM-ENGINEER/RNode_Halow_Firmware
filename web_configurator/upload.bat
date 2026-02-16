@echo off
setlocal enableextensions

REM --- CONFIG ---
set "PY=python"
set "PACK=%~dp0compress.py"
set "UPLOAD=%~dp0upload_tftpf.py"

set "WWW=%~dp0www"
set "OUTDIR=%~dp0out"
set "OUTHTML=%OUTDIR%\index.html"

REM --- ARGS ---
REM %1 = tftp host/ip (required)
REM %2 = remote path (optional, default: www/index.html)
if "%~1"=="" goto usage
set "HOST=%~1"
set "REMOTE=%~2"
if "%REMOTE%"=="" set "REMOTE=www/index.html"

if not exist "%PACK%" (
  echo error: pack script not found: "%PACK%"
  exit /b 2
)

if not exist "%WWW%" (
  echo error: www dir not found: "%WWW%"
  exit /b 2
)

if not exist "%OUTDIR%" (
  mkdir "%OUTDIR%"
  if errorlevel 1 goto fail
)

echo [*] Packing "%WWW%" -> "%OUTHTML%"
%PY% "%PACK%" --www "%WWW%" --out "%OUTHTML%"
if errorlevel 1 goto fail

if not exist "%OUTHTML%" (
  echo error: packed file not found: "%OUTHTML%"
  goto fail
)

echo [*] Uploading via TFTP to %HOST% : "%REMOTE%"
%PY% "%UPLOAD%" "%HOST%" --local "%OUTHTML%" --remote "%REMOTE%"
if errorlevel 1 goto fail

echo [ok] Done
exit /b 0

:usage
echo Usage:
echo   %~nx0 ^<tftp_host_ip^> [remote_path]
echo Examples:
echo   %~nx0 192.168.1.35
echo   %~nx0 192.168.1.35 www/index.html
exit /b 2

:fail
echo [fail]
exit /b 1
