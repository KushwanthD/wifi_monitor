@echo off
title WiFi Monitor Bootstrapper
echo =======================================================================
echo                 WiFi Monitor - Local Security Agent
echo =======================================================================
echo.

:: 1. Check if source code exists
if not exist "backend\main.py" if not exist "main.py" (
    echo [INFO] Project files not found. Bootstrapping from GitHub...
    echo Downloading source code zip...
    
    powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/KushwanthD/wifi_monitor/archive/refs/heads/main.zip' -OutFile 'wifi_monitor.zip' } catch { Write-Error $_; exit 1 }"
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to download source code from GitHub.
        echo If this is a private repository, please clone or copy the project manually to this PC.
        echo.
        pause
        exit
    )
    
    echo Extracting files...
    powershell -Command "Expand-Archive -Path 'wifi_monitor.zip' -DestinationPath 'temp_src' -Force"
    
    echo Copying files to workspace...
    xcopy /E /Y /Q temp_src\wifi_monitor-main\* . >nul
    
    echo Cleaning up temporary setup files...
    del wifi_monitor.zip
    rmdir /S /Q temp_src
    echo [SUCCESS] Source code extracted.
    echo.
)

:: Adjust working directory if we are at root or inside backend
if exist "backend\main.py" (
    set "BACKEND_DIR=%CD%\backend"
) else if exist "main.py" (
    set "BACKEND_DIR=%CD%"
) else (
    echo [ERROR] Could not find backend folder. Setup failed.
    pause
    exit
)

cd /d "%BACKEND_DIR%"

:: 2. Check virtual environment
if not exist "venv\Scripts\python.exe" (
    echo [INFO] Python virtual environment (venv) not found. Checking system Python...
    where python >nul 2>nul
    if errorlevel 1 (
        echo =======================================================================
        echo [ERROR] Python is not installed on this PC.
        echo.
        echo Please download and install Python 3 from: https://www.python.org/downloads/
        echo Make sure to check the box: "Add Python to PATH" during installation.
        echo =======================================================================
        echo.
        pause
        exit
    )
    
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit
    )
    
    echo [INFO] Upgrading pip...
    venv\Scripts\python.exe -m pip install --upgrade pip >nul
    
    echo [INFO] Installing required dependencies...
    venv\Scripts\pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install requirements.
        pause
        exit
    )
    echo [SUCCESS] Virtual environment and dependencies installed successfully.
    echo.
)

:: 3. Run the application
echo Starting WiFi Monitor in Production mode...
echo Exposing server to local home network on port 8000.
echo.
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
pause
