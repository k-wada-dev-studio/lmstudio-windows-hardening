@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Delete private data

echo ============================================================
echo  Delete LM Studio private data
echo ============================================================
echo.
echo Close LM Studio and all model runtimes before continuing.
echo This permanently deletes:
echo   - chat history
echo   - chat attachments
echo   - LM Studio server logs
echo   - this project's setup and launch logs
echo.
echo Models, runtimes, settings, credentials, backups, and state are kept.
echo This deletion cannot be undone.
echo.

choice /C YN /N /M "Delete the listed private data now? [Y/N] "
if errorlevel 2 (
    echo.
    echo Cancelled. Nothing was deleted.
    pause
    exit /b 0
)

echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Remove-LMStudio-PrivateData.ps1" -ConfirmDeletion
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo Private-data deletion did not complete. Read the error above.
) else (
    echo Private-data deletion completed.
)
echo.
pause
exit /b %script_exit%
