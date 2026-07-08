@echo off
title WiFi Monitor Server
echo Starting WiFi Monitor in Production mode...
echo Exposing server to local home network on port 8000.
echo.

:: 1. Check if running directly inside the backend directory
if exist "venv\Scripts\python.exe" (
    goto RUN
)

:: 2. Check relative parent backend folder (if run from root directory)
if exist "%~dp0backend\venv\Scripts\python.exe" (
    cd /d "%~dp0backend"
    goto RUN
)

:: 3. Check absolute fallback path E:\vulnerabilities\wifi-security-monitor\backend (if run from Downloads)
if exist "E:\vulnerabilities\wifi-security-monitor\backend\venv\Scripts\python.exe" (
    cd /d "E:\vulnerabilities\wifi-security-monitor\backend"
    goto RUN
)

echo =======================================================================
echo ERROR: Could not locate the WiFi Monitor workspace or virtual env.
echo.
echo Please ensure your project is installed at:
echo E:\vulnerabilities\wifi-security-monitor
echo =======================================================================
echo.
pause
exit

:RUN
echo [INFO] Working directory set to: %CD%
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
pause
