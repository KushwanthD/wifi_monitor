Write-Host "Installing PyInstaller and dependencies..."
& E:\vulnerabilities\wifi-security-monitor\backend\venv\Scripts\python.exe -m pip install pyinstaller uvicorn fastapi pydantic reportlab

Write-Host "Compiling WiFi Security Monitor into a standalone executable..."
& E:\vulnerabilities\wifi-security-monitor\backend\venv\Scripts\pyinstaller.exe `
  --name "WiFiSecurityMonitor" `
  --onefile `
  --clean `
  --noconsole `
  --add-data "..\frontend;frontend" `
  --hidden-import "uvicorn" `
  --hidden-import "fastapi" `
  --hidden-import "pydantic" `
  --hidden-import "reportlab" `
  E:\vulnerabilities\wifi-security-monitor\backend\main.py

Write-Host "Build complete! Check the 'dist' folder."
