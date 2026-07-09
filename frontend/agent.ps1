param(
    [string]$ServerUrl = 'http://127.0.0.1:8000/api/agent/report',
    [string]$StopFile  = ''
)

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WifiNative {
    [DllImport("wlanapi.dll")] public static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);
    [DllImport("wlanapi.dll")] public static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);
    [DllImport("wlanapi.dll")] public static extern uint WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);
}
'@ -ErrorAction SilentlyContinue

$agent_id = $env:COMPUTERNAME.Trim().ToUpper()
$api_url  = $ServerUrl
$interface_name = 'Wi-Fi'

while ($true) {
    if ($StopFile -and (Test-Path $StopFile)) { break }
    try {
        # Step 1: Trigger hardware Wi-Fi scan (async - results ready in ~4s)
        try {
            $neg = 0; $h = [IntPtr]::Zero
            if ([WifiNative]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$neg, [ref]$h) -eq 0) {
                $wifi_adp = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
                    $_.Status -eq 'Up' -and (
                        $_.InterfaceDescription -like '*Wi-Fi*' -or $_.InterfaceDescription -like '*Wireless*' -or
                        $_.Name -like '*Wi-Fi*' -or $_.Name -like '*WiFi*' -or $_.Name -like '*Wireless*'
                    )
                }
                if ($wifi_adp) { $interface_name = $wifi_adp[0].Name }
                $guid_str = (Get-NetAdapter -Name $interface_name -ErrorAction SilentlyContinue).InterfaceGuid
                if ($guid_str) {
                    $guid = [Guid]::Parse($guid_str)
                    [void][WifiNative]::WlanScan($h, [ref]$guid, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
                }
                [void][WifiNative]::WlanCloseHandle($h, [IntPtr]::Zero)
            }
        } catch {}

        # Step 2: Parse connected interface info (while scan runs in background)
        $netsh = netsh wlan show interfaces
        $ssid=''; $bssid=''; $signal=0; $auth='Open'; $cipher='None'
        $desc=''; $mac=''; $radio=''; $band=''; $channel=''
        $receive='0'; $transmit='0'; $status='disconnected'
        foreach ($line in $netsh) {
            if ($line -match '^\s*Name\s*:\s*(.+)$')                   { $interface_name = $Matches[1].Trim() }
            if ($line -match '^\s*SSID\s*:\s*(.+)$')                   { $ssid    = $Matches[1].Trim() }
            if ($line -match '^\s*AP BSSID\s*:\s*(.+)$')              { $bssid   = $Matches[1].Trim().ToUpper() }
            if ($line -match 'Signal\s*:\s*(\d+)')                     { $signal  = [int]$Matches[1] }
            if ($line -match '^\s*Authentication\s*:\s*(.+)$')         { $auth    = $Matches[1].Trim() }
            if ($line -match '^\s*Cipher\s*:\s*(.+)$')                 { $cipher  = $Matches[1].Trim() }
            if ($line -match '^\s*Description\s*:\s*(.+)$')            { $desc    = $Matches[1].Trim() }
            if ($line -match '^\s*Physical address\s*:\s*(.+)$')       { $mac     = $Matches[1].Trim().Replace('-',':').ToUpper() }
            if ($line -match '^\s*Radio type\s*:\s*(.+)$')             { $radio   = $Matches[1].Trim() }
            if ($line -match '^\s*Band\s*:\s*(.+)$')                   { $band    = $Matches[1].Trim() }
            if ($line -match '^\s*Channel\s*:\s*(.+)$')                { $channel = $Matches[1].Trim() }
            if ($line -match '^\s*Receive rate \(Mbps\)\s*:\s*(.+)$') { $receive  = $Matches[1].Trim() }
            if ($line -match '^\s*Transmit rate \(Mbps\)\s*:\s*(.+)$'){ $transmit = $Matches[1].Trim() }
        }
        if ($ssid) { $status = 'connected' }

        # Step 3: Get host IP and async-ping the subnet
        $host_ip = ''
        $ip_cfg = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $interface_name -ErrorAction SilentlyContinue
        if ($ip_cfg) {
            $host_ip = ($ip_cfg | Select-Object -First 1).IPAddress
        } else {
            $all_ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }
            if ($all_ips) { $host_ip = $all_ips[0].IPAddress } else { $host_ip = '127.0.0.1' }
        }
        $parts = $host_ip.Split('.')
        $subnet_prefix = ($parts[0] + '.' + $parts[1] + '.' + $parts[2] + '.')
        1..254 | ForEach-Object {
            $sweep_ip = $subnet_prefix + $_
            if ($sweep_ip -ne $host_ip) {
                $p = New-Object System.Net.NetworkInformation.Ping
                [void]$p.SendAsync($sweep_ip, 100, $null)
            }
        }
        Start-Sleep -Milliseconds 200

        # Step 4: Read ARP cache for subnet devices
        $devices = @()
        
        # Helper function for fast TCP port checks
        function Get-OpenPorts($targetIp) {
            $open = @()
            $ports = @(21, 22, 23, 80, 443, 445, 3389)
            foreach ($port in $ports) {
                $tcp = New-Object System.Net.Sockets.TcpClient
                try {
                    $ar = $tcp.BeginConnect($targetIp, $port, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne(45)) {
                        if ($tcp.Connected) {
                            $service = "Unknown"
                            if ($port -eq 21) { $service = "FTP" }
                            elseif ($port -eq 22) { $service = "SSH" }
                            elseif ($port -eq 23) { $service = "Telnet" }
                            elseif ($port -eq 80) { $service = "HTTP" }
                            elseif ($port -eq 443) { $service = "HTTPS" }
                            elseif ($port -eq 445) { $service = "SMB" }
                            elseif ($port -eq 3389) { $service = "RDP" }
                            $open += @{ port=$port; service=$service }
                            $tcp.EndConnect($ar)
                        }
                    }
                } catch {}
                $tcp.Close()
            }
            return $open
        }

        $host_ports = Get-OpenPorts $host_ip
        $devices += @{ ip=$host_ip; mac=$mac; vendor='This Workstation'; hostname=$env:COMPUTERNAME; is_host=$true; latency_ms=0; open_ports=$host_ports }
        
        foreach ($line in (arp -a)) {
            if ($line -match '^\s*([0-9\.]+)\s+([0-9a-fA-F\-]{17})\s+(dynamic|static)') {
                $dev_ip  = $Matches[1]
                $dev_mac = $Matches[2].Replace('-',':').ToUpper()
                if ($dev_ip.StartsWith($subnet_prefix) -and $dev_mac -ne 'FF:FF:FF:FF:FF:FF' -and $dev_mac -ne $mac) {
                    $lat = 'ERR'
                    try {
                        $r = (New-Object System.Net.NetworkInformation.Ping).Send($dev_ip, 120)
                        if ($r.Status -eq 'Success') { $lat = $r.RoundtripTime }
                    } catch {}
                    # Resolve hostname via DNS/NetBIOS (200ms timeout)
                    $hn = ''
                    try {
                        $dns_task = [System.Net.Dns]::GetHostEntryAsync($dev_ip)
                        if ($dns_task.Wait(200)) { $hn = $dns_task.Result.HostName }
                    } catch {}
                    
                    # Fast Port Scan
                    $dev_ports = Get-OpenPorts $dev_ip
                    $devices += @{ ip=$dev_ip; mac=$dev_mac; vendor='Network Node'; hostname=$hn; is_host=$false; latency_ms=$lat; open_ports=$dev_ports }
                }
            }
        }

        # Step 5: Hardware scan is now done (~4s have passed) - read all networks
        Start-Sleep -Seconds 4
        $networks = @()
        $cs=''; $ca='Open'; $cc='None'; $cb=''; $csi=0; $cch=''; $cr=''
        foreach ($line in (netsh wlan show networks mode=bssid)) {
            if ($line -match '^\s*SSID\s+\d+\s*:\s*(.+)$') {
                if ($cs) { $networks += @{ ssid=$cs; authentication=$ca; encryption=$cc; signal=$csi; channel=$cch; bssid=$cb; radio_type=$cr } }
                $cs=$Matches[1].Trim(); $ca='Open'; $cc='None'; $cb=''; $csi=0; $cch=''; $cr=''
            } elseif ($line -match '^\s*Authentication\s*:\s*(.+)$') { $ca=$Matches[1].Trim() }
            elseif  ($line -match '^\s*Encryption\s*:\s*(.+)$')       { $cc=$Matches[1].Trim() }
            elseif  ($line -match '^\s*BSSID\s+\d+\s*:\s*(.+)$')      { $cb=$Matches[1].Trim().ToUpper() }
            elseif  ($line -match '^\s*Signal\s*:\s*(\d+)')            { $csi=[int]$Matches[1] }
            elseif  ($line -match '^\s*Channel\s*:\s*(\d+)')           { $cch=$Matches[1] }
            elseif  ($line -match '^\s*Radio type\s*:\s*(.+)$')        { $cr=$Matches[1].Trim() }
        }
        if ($cs) { $networks += @{ ssid=$cs; authentication=$ca; encryption=$cc; signal=$csi; channel=$cch; bssid=$cb; radio_type=$cr } }

        # Step 6: Build JSON and upload
        $report = @{
            agent_id  = $agent_id
            wifi      = @{ status=$status; interface_name=$interface_name; description=$desc; mac_address=$mac; ssid=$ssid; bssid=$bssid; band=$band; channel=$channel; radio_type=$radio; authentication=$auth; cipher=$cipher; receive_rate=$receive; transmit_rate=$transmit; signal=$signal }
            devices   = $devices
            wifi_scan = $networks
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-RestMethod -Uri $api_url -Method Post -Body ($report | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] OK  SSID: ' + $ssid + '  Devices: ' + $devices.Length + '  Nearby: ' + $networks.Length) -ForegroundColor Green

    } catch {
        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] Error: ' + $_.Exception.Message) -ForegroundColor Red
    }

    Start-Sleep -Seconds 3
}
