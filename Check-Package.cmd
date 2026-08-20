@echo off
setlocal
cd /d "%~dp0"
title Windows Local AI Hardening - Package checks

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tests\Test-Static.ps1"
if errorlevel 1 goto failed

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tests\Test-Behavior.ps1"
if errorlevel 1 goto failed

echo.
echo All package checks passed.
echo.
pause
exit /b 0

:failed
echo.
echo A package check failed. Do not run setup.
echo.
pause
exit /b 1
