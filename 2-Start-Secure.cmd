@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Secure launch

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Start-LMStudio-Secure.ps1"
set "script_exit=%ERRORLEVEL%"

if not "%script_exit%"=="0" (
    echo.
    echo Secure launch did not complete. Read the error above.
    echo.
    pause
    exit /b %script_exit%
)

timeout /t 2 /nobreak >nul
exit /b 0
