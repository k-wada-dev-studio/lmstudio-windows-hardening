@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Delete all LM Studio data

echo ============================================================
echo  Delete ALL remaining LM Studio user data
echo ============================================================
echo.
echo Use this only AFTER uninstalling LM Studio.
echo This permanently deletes the current user's complete profile:
echo   %%USERPROFILE%%\.lmstudio
echo.
echo This includes chats, attachments, settings, credentials, models,
echo runtimes, caches, project backups, logs, and setup state.
echo Shared-folder model files are not followed through symbolic links.
echo Project-managed Windows Firewall rules are not changed.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Remove-LMStudio-Profile.ps1" -PreviewOnly
if errorlevel 1 goto failed

echo.
choice /C YN /N /M "Permanently delete the complete LM Studio profile? [Y/N] "
if errorlevel 2 (
    echo.
    echo Cancelled. Nothing was deleted.
    pause
    exit /b 0
)

echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Remove-LMStudio-Profile.ps1" -ConfirmDeletion -RequireTypedConfirmation
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo Complete profile deletion did not finish. Read the error above.
) else (
    echo Complete LM Studio user-data deletion completed.
)
echo.
pause
exit /b %script_exit%

:failed
echo.
echo Safety checks failed. Nothing was deleted.
echo.
pause
exit /b 1
