# WiFi Sentinel – one-time install (run once, then use the website only)
$AppDir = Join-Path $env:APPDATA 'WiFiSentinel'
$SrcDir = $PSScriptRoot

Write-Host ''
Write-Host '  WiFi Sentinel – Installing local agent...' -ForegroundColor Cyan

New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
Copy-Item (Join-Path $SrcDir 'local_agent.ps1') $AppDir -Force
Copy-Item (Join-Path $SrcDir 'agent.ps1')       $AppDir -Force

$taskName = 'WiFiSentinelBridge'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AppDir\local_agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Limited -Force | Out-Null

Get-Process powershell -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
        if ($cmd -like '*local_agent.ps1*') { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    } catch {}
}

Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AppDir\local_agent.ps1`"" -WindowStyle Hidden

Write-Host '  Done! Open the dashboard and click "Analyze My Network".' -ForegroundColor Green
Write-Host ''
