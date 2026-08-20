@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Setup

echo ============================================================
echo  Windows Local AI Hardening - Initial setup
echo ============================================================
echo.
echo Close LM Studio before continuing.
echo The deployment-approved shared model will be registered automatically.
echo You do not need to change LM Studio settings.
echo Windows will ask once for secure model-link setup.
echo Project Firewall ON/OFF is read from the private deployment configuration.
echo When ON, Firewall verification may take several minutes. Do not launch Setup twice.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Setup-LMStudio.ps1"
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo Setup did not complete. Read the error above.
) else (
    echo Setup completed. Use 2-Start-Secure.cmd for normal use.
)
echo.
pause
exit /b %script_exit%
