@echo off
setlocal
cd /d "%~dp0..\..\.."
node scripts\run-windows-sm-wizard.mjs
if errorlevel 1 pause
endlocal
