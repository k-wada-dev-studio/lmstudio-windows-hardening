@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Restore

echo ============================================================
echo  Restore pre-setup LM Studio configuration
echo ============================================================
echo.
echo Close LM Studio and all model runtimes before continuing.
echo A safety backup will be created before restoration.
echo Safe default: this project's Firewall block will be kept.
echo Full Firewall removal requires an explicit PowerShell option.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Restore-LMStudio.ps1"
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo Restore did not complete. Read the error above.
) else (
    echo Restore completed.
    echo Do not start LM Studio normally. Run 1-Setup.cmd next.
)
echo.
pause
exit /b %script_exit%
