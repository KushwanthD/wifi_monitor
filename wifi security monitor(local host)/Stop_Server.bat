@echo off
echo Stopping WiFi Security Monitor Server...
taskkill /F /IM pythonw.exe /T >nul 2>&1
echo Successfully stopped!
pause
