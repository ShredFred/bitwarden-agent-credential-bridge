@echo off
REM Run from an elevated console (Right-click PowerShell/CMD -> Run as administrator).
cd /d "%~dp0\.."
node scripts\run-windows-service-lifecycle-live.mjs
echo ExitCode=%ERRORLEVEL%
pause
