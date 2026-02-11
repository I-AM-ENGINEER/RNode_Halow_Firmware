@echo off
setlocal enableextensions

REM --- CONFIG ---
set "PY=python"
set "MFS=%~dp0mongoose\mongoose_fs.c"
set "EXTRACT=%~dp0convert_to_html.py"
set "UPLOAD=%~dp0upload_tftpf.py"

set "OUTDIR=%~dp0_extract_tmp"
set "WWW=%~dp0www"
set "SRC=%OUTDIR%\web_root\index.html"
set "DST=%WWW%\index.html"

REM --- ARGS ---
REM %1 = tftp host/ip (required)
REM %2 = remote path (optional, default: www/index.html)
if "%~1"=="" goto usage
set "HOST=%~1"
set "REMOTE=%~2"
if "%REMOTE%"=="" set "REMOTE=www/index.html"

if not exist "%MFS%" (
  echo error: mongoose_fs.c not found: "%MFS%"
  exit /b 2
)

echo [*] Extracting index.html from "%MFS%"
%PY% "%EXTRACT%" "%MFS%" -o "%OUTDIR%" --only "/web_root/index.html.gz"
if errorlevel 1 goto fail

if not exist "%SRC%" (
  echo error: extracted file not found: "%SRC%"
  goto fail
)

if not exist "%WWW%" (
  mkdir "%WWW%"
  if errorlevel 1 goto fail
)

echo [*] Copying "%SRC%" -> "%DST%"
copy /Y "%SRC%" "%DST%" >nul
if errorlevel 1 goto fail

echo [*] Uploading via TFTP to %HOST% : "%REMOTE%"
%PY% "%UPLOAD%" "%HOST%" --local "%DST%" --remote "%REMOTE%"
if errorlevel 1 goto fail

echo [ok] Done
exit /b 0

:usage
echo Usage:
echo   %~nx0 ^<tftp_host_ip^> [remote_path]
echo Examples:
echo   %~nx0 192.168.1.35
echo   %~nx0 192.168.1.35 index.html
exit /b 2

:fail
echo [fail]
exit /b 1
