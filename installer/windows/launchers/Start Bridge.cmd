@echo off
setlocal
cd /d "%~dp0..\..\.."
node scripts\run-operational-bridge-sm.mjs --i-approve-secrets-manager-machine-resolve
if errorlevel 1 pause
endlocal
