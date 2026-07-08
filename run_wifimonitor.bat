@echo off
title WiFi Monitor Server
echo Starting WiFi Monitor in Production mode...
echo Exposing server to local home network on port 8000.
echo.
cd /d "E:\vulnerabilities\wifi-security-monitor\backend"
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
pause
