@echo off
title WiFi Monitor - Security Agent
color 0A

echo.
echo  ==========================================================
echo    WiFi Monitor - Remote Security Agent Launcher
echo  ==========================================================
echo.

:: Check if this is the Dev PC (backend exists beside or above this file)
if exist "%~dp0backend\main.py" (
    echo  [DEV] Dev environment detected. Starting local server...
    cd /d "%~dp0backend"
    if exist "venv\Scripts\python.exe" (
        venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    ) else (
        python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    )
    pause
    exit /b 0
)

if exist "%~dp0..\backend\main.py" (
    echo  [DEV] Dev environment detected. Starting local server...
    cd /d "%~dp0..\backend"
    if exist "venv\Scripts\python.exe" (
        venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    ) else (
        python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    )
    pause
    exit /b 0
)

:: Client PC mode: download the agent script and run it
echo  [INFO] Client mode detected. Downloading scan agent...
echo.

:: Set temp path for the downloaded agent script
set "AGENT_PS1=%TEMP%\wifi_agent_%RANDOM%.ps1"

:: Download agent.ps1 from the hosted server
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { (New-Object System.Net.WebClient).DownloadFile('https://wifi-monitor-x7jk.onrender.com/static/agent.ps1', '%AGENT_PS1%'); Write-Host '  [OK] Agent script downloaded.' -ForegroundColor Green } catch { Write-Host ('  [ERROR] Download failed: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"

if not exist "%AGENT_PS1%" (
    echo.
    echo  [ERROR] Could not download the agent script.
    echo  Please check your internet connection and try again.
    echo.
    pause
    exit /b 1
)

echo  [INFO] Launching scan agent...
echo  [INFO] Your Computer Name (Agent ID) is: %COMPUTERNAME%
echo.
echo  Enter "%COMPUTERNAME%" on the dashboard to connect.
echo.

:: Run the clean agent script (no escaping issues!)
powershell -NoProfile -ExecutionPolicy Bypass -File "%AGENT_PS1%" -ServerUrl "https://wifi-monitor-x7jk.onrender.com/api/agent/report"

:: Cleanup
del "%AGENT_PS1%" 2>nul

echo.
echo  Agent stopped.
pause
