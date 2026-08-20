@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Complete LM Studio uninstall

echo ============================================================
echo  Completely uninstall LM Studio and delete local user data
echo ============================================================
echo.
echo This permanently removes:
echo   - the verified current-user LM Studio application
echo   - the complete %%USERPROFILE%%\.lmstudio profile
echo   - legacy Roaming settings and the updater cache
echo   - this project's Windows Firewall rules
echo.
echo Shared-folder model targets are NOT deleted.
echo Close LM Studio and all runtimes before continuing.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Uninstall-LMStudio.ps1" -PreviewOnly
if errorlevel 1 goto failed

echo.
choice /C YN /N /M "Completely uninstall LM Studio and delete all local data? [Y/N] "
if errorlevel 2 (
    echo.
    echo Cancelled. Nothing was uninstalled or deleted.
    pause
    exit /b 0
)

echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Uninstall-LMStudio.ps1" -ConfirmUninstall -RequireTypedConfirmation
set "script_exit=%ERRORLEVEL%"

echo.
if not "%script_exit%"=="0" (
    echo Complete uninstall did not finish. Read the error above.
) else (
    echo LM Studio and its local user data were completely removed.
)
echo.
pause
exit /b %script_exit%

:failed
echo.
echo Safety preview failed. Nothing was uninstalled or deleted.
echo.
pause
exit /b 1
