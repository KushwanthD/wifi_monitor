# WiFi Sentinel – localhost bridge (127.0.0.1:9123)
$Port    = 9123
$AppDir  = Join-Path $env:APPDATA 'WiFiSentinel'
$StopFile = Join-Path $AppDir 'stop.flag'
$PidFile  = Join-Path $AppDir 'worker.pid'
$AgentId  = $env:COMPUTERNAME.Trim().ToUpper()
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $AppDir }

if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir -Force | Out-Null }

function Send-Response($ctx, $code, $body) {
    $origin = $ctx.Request.Headers['Origin']
    if (-not $origin) { $origin = '*' }
    $resp = $ctx.Response
    $resp.StatusCode = $code
    $resp.Headers.Add('Access-Control-Allow-Origin', $origin)
    $resp.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    $resp.Headers.Add('Access-Control-Allow-Headers', 'Content-Type')
    $buf = [System.Text.Encoding]::UTF8.GetBytes($body)
    $resp.ContentType = 'application/json'
    $resp.ContentLength64 = $buf.Length
    $resp.OutputStream.Write($buf, 0, $buf.Length)
    $resp.Close()
}

function Test-WorkerRunning {
    if (-not (Test-Path $PidFile)) { return $false }
    $wpid = Get-Content $PidFile -ErrorAction SilentlyContinue
    return ($wpid -and (Get-Process -Id $wpid -ErrorAction SilentlyContinue))
}

function Start-Worker($serverUrl) {
    if (Test-WorkerRunning) { return }
    Remove-Item $StopFile -Force -ErrorAction SilentlyContinue
    $agentScript = Join-Path $ScriptDir 'agent.ps1'
    if (-not (Test-Path $agentScript)) { $agentScript = Join-Path $AppDir 'agent.ps1' }
    $reportUrl = ($serverUrl.TrimEnd('/')) + '/api/agent/report'
    $args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentScript`" -ServerUrl `"$reportUrl`" -StopFile `"$StopFile`""
    $proc = Start-Process powershell.exe -ArgumentList $args -WindowStyle Hidden -PassThru
    Set-Content -Path $PidFile -Value $proc.Id
}

function Stop-Worker {
    if (Test-Path $StopFile) { 'stop' | Set-Content $StopFile }
    Start-Sleep -Milliseconds 800
    if (Test-Path $PidFile) {
        $wpid = Get-Content $PidFile -ErrorAction SilentlyContinue
        Stop-Process -Id $wpid -Force -ErrorAction SilentlyContinue
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $StopFile -Force -ErrorAction SilentlyContinue
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $path = $req.Url.LocalPath.TrimEnd('/')
    if (-not $path) { $path = '/' }

    if ($req.HttpMethod -eq 'OPTIONS') {
        Send-Response $ctx 204 ''
        continue
    }

    switch ($path) {
        '/health' {
            $scanning = Test-WorkerRunning
            Send-Response $ctx 200 (@{ ok = $true; agent_id = $AgentId; scanning = $scanning } | ConvertTo-Json -Compress)
        }
        '/info' {
            Send-Response $ctx 200 (@{ agent_id = $AgentId; scanning = (Test-WorkerRunning) } | ConvertTo-Json -Compress)
        }
        '/start' {
            $server = 'https://wifi-monitor-x7jk.onrender.com'
            if ($req.HasEntityBody) {
                $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                $raw = $reader.ReadToEnd()
                if ($raw) {
                    try {
                        $parsed = $raw | ConvertFrom-Json
                        if ($parsed.server) { $server = $parsed.server }
                    } catch {}
                }
            }
            Start-Worker $server
            Send-Response $ctx 200 (@{ status = 'started'; agent_id = $AgentId } | ConvertTo-Json -Compress)
        }
        '/stop' {
            Stop-Worker
            Send-Response $ctx 200 (@{ status = 'stopped' } | ConvertTo-Json -Compress)
        }
        default {
            Send-Response $ctx 404 (@{ error = 'not found' } | ConvertTo-Json -Compress)
        }
    }
}
