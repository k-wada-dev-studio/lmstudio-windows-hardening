@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - One-click install and setup

echo ============================================================
echo  LM Studio one-click install and secure setup
echo ============================================================
echo.
echo This single workflow will:
echo   - verify and silently install the approved LM Studio package
echo   - initialize LM Studio without user configuration
echo   - install and select the pinned inference runtime when required
echo   - register the approved shared model
echo   - apply the selected network policy
echo   - open LM Studio with only the approved model loaded
echo.
echo Do not start LM Studio or another setup window while this runs.
echo Windows may request administrator approval for Firewall and model links.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Install-LMStudio.ps1"
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo One-click installation did not complete. Read the error above.
    echo Re-run this same file after correcting the reported cause.
    echo.
    pause
    exit /b %script_exit%
)

echo One-click installation and secure launch completed.
exit /b 0
