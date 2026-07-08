@echo off
title WiFi Monitor
echo =======================================================================
echo                 WiFi Monitor - Local Security Agent
echo =======================================================================
echo.

:: Check if this is the Dev PC (main.py and venv folder exist)
if exist "%~dp0backend\main.py" if exist "%~dp0backend\venv\Scripts\python.exe" (
    echo [INFO] Dev Workspace detected. Starting local FastAPI server...
    cd /d "%~dp0backend"
    venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    pause
    exit
)

if exist "%~dp0..\backend\main.py" if exist "%~dp0..\backend\venv\Scripts\python.exe" (
    echo [INFO] Dev Workspace detected. Starting local FastAPI server...
    cd /d "%~dp0..\backend"
    venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    pause
    exit
)

:: Otherwise, we are on a Client PC! Run the zero-install PowerShell scanning loop.
echo [INFO] Standalone client mode detected. Running native Wi-Fi scan agent...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$agent_id = $env:COMPUTERNAME;" ^
    "Write-Host 'Your Computer Name (Agent ID) is:' -ForegroundColor Cyan;" ^
    "Write-Host $agent_id -ForegroundColor Green -NoNewline;" ^
    "Write-Host '  (Use this on the website to connect)' -ForegroundColor DarkGray;" ^
    "Write-Host '';" ^
    "Write-Host 'Scanning and uploading network reports every 20 seconds. Press Ctrl+C to stop.' -ForegroundColor DarkYellow;" ^
    "Write-Host '=======================================================================';" ^
    "while ($true) {" ^
    "    try {" ^
    "        $netsh = netsh wlan show interfaces;" ^
    "        $ssid = ''; $bssid = ''; $signal = 0; $auth = 'Open'; $cipher = 'None';" ^
    "        $desc = ''; $mac = ''; $radio = ''; $band = ''; $channel = ''; $receive = '0'; $transmit = '0';" ^
    "        foreach ($line in $netsh) {" ^
    "            if ($line -match '^\s*SSID\s*:\s*(.*)$') { $ssid = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*AP BSSID\s*:\s*(.*)$') { $bssid = $Matches[1].Trim().ToUpper() }" ^
    "            if ($line -match 'Signal\s*:\s*(\d+)') { $signal = [int]$Matches[1] }" ^
    "            if ($line -match '^\s*Authentication\s*:\s*(.*)$') { $auth = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Cipher\s*:\s*(.*)$') { $cipher = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Description\s*:\s*(.*)$') { $desc = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Physical address\s*:\s*(.*)$') { $mac = $Matches[1].Trim().Replace('-', ':').ToUpper() }" ^
    "            if ($line -match '^\s*Radio type\s*:\s*(.*)$') { $radio = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Band\s*:\s*(.*)$') { $band = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Channel\s*:\s*(.*)$') { $channel = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Receive rate \(Mbps\)\s*:\s*(.*)$') { $receive = $Matches[1].Trim() }" ^
    "            if ($line -match '^\s*Transmit rate \(Mbps\)\s*:\s*(.*)$') { $transmit = $Matches[1].Trim() }" ^
    "        }" ^
    "        if ([string]::IsNullOrEmpty($ssid)) { $ssid = 'Not Connected'; $status = 'disconnected' } else { $status = 'connected' }" ^
    "        $host_ip = '';" ^
    "        $ip_config = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Wi-Fi' -ErrorAction SilentlyContinue;" ^
    "        if ($ip_config) { $host_ip = $ip_config.IPAddress } else {" ^
    "            $active_ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' };" ^
    "            if ($active_ips) { $host_ip = $active_ips[0].IPAddress } else { $host_ip = '127.0.0.1' }" ^
    "        }" ^
    "        $devices = @();" ^
    "        $devices += @{ 'ip' = $host_ip; 'mac' = $mac; 'vendor' = 'This Workstation'; 'is_host' = $true };" ^
    "        $arp = arp -a;" ^
    "        foreach ($line in $arp) {" ^
    "            if ($line -match '^\s*([0-9\.]+)\s+([0-9a-fA-F\-]{17})\s+(dynamic|static)') {" ^
    "                $ip = $Matches[1]; $dev_mac = $Matches[2].Replace('-', ':').ToUpper();" ^
    "                if ($dev_mac -ne 'FF:FF:FF:FF:FF:FF' -and $dev_mac -ne $mac) {" ^
    "                    $devices += @{ 'ip' = $ip; 'mac' = $dev_mac; 'vendor' = 'Network Node'; 'is_host' = $false }" ^
    "                }" ^
    "            }" ^
    "        }" ^
    "        $report = @{" ^
    "            'agent_id' = $agent_id;" ^
    "            'wifi' = @{" ^
    "                'status' = $status; 'interface_name' = 'Wi-Fi'; 'description' = $desc; 'mac_address' = $mac;" ^
    "                'ssid' = $ssid; 'bssid' = $bssid; 'band' = $band; 'channel' = $channel;" ^
    "                'radio_type' = $radio; 'authentication' = $auth; 'cipher' = $cipher;" ^
    "                'receive_rate' = $receive; 'transmit_rate' = $transmit; 'signal' = $signal" ^
    "            };" ^
    "            'devices' = $devices" ^
    "        };" ^
    "        $json = $report | ConvertTo-Json -Depth 5;" ^
    "        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
    "        $url = 'https://wifi-monitor-x7jk.onrender.com/api/agent/report';" ^
    "        $res = Invoke-RestMethod -Uri $url -Method Post -Body $json -ContentType 'application/json';" ^
    "        Write-Host ('[' + (Get-Date -Format 'HH:mm:ss') + '] Scan report uploaded successfully to Render. SSID: ' + $ssid) -ForegroundColor Green;" ^
    "    } catch {" ^
    "        Write-Host ('[' + (Get-Date -Format 'HH:mm:ss') + '] Scan upload failed: ' + $_.Exception.Message) -ForegroundColor Red;" ^
    "    }" ^
    "    Start-Sleep -Seconds 20;" ^
    "}"
