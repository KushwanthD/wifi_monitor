import platform
import subprocess
import socket
import asyncio
import uuid
import datetime

# --- Helper Functions ---
def get_os():
    return platform.system()

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
    except Exception:
        return ""

async def check_port(ip, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.05)
        writer.close()
        await writer.wait_closed()
        
        service_map = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}
        return {"port": port, "service": service_map.get(port, "Unknown")}
    except Exception:
        return None

async def scan_ports(ip):
    ports = [21, 22, 23, 80, 443, 445, 3389]
    tasks = [check_port(ip, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

# --- OS Specific Scanners ---
class WindowsScanner:
    def get_current_wifi(self):
        output = run_cmd("netsh wlan show interfaces")
        info = {
            "status": "disconnected", "interface_name": "Wi-Fi", "description": "",
            "mac_address": "", "ssid": "", "bssid": "", "band": "", "channel": "",
            "radio_type": "", "authentication": "Open", "cipher": "None",
            "receive_rate": "0", "transmit_rate": "0", "signal": 0
        }
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Name"): info["interface_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Description"): info["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("Physical address"): info["mac_address"] = line.split(":", 1)[1].strip().replace("-", ":").upper()
            elif line.startswith("State"):
                if line.split(":", 1)[1].strip() == "connected": info["status"] = "connected"
            elif line.startswith("SSID") and not line.startswith("BSSID"): info["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID"): info["bssid"] = line.split(":", 1)[1].strip().upper()
            elif line.startswith("Radio type"): info["radio_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Authentication"): info["authentication"] = line.split(":", 1)[1].strip()
            elif line.startswith("Cipher"): info["cipher"] = line.split(":", 1)[1].strip()
            elif line.startswith("Band"): info["band"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel"): info["channel"] = line.split(":", 1)[1].strip()
            elif line.startswith("Receive rate (Mbps)"): info["receive_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("Transmit rate (Mbps)"): info["transmit_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signal"): 
                sig = line.split(":", 1)[1].strip().replace("%", "")
                info["signal"] = int(sig) if sig.isdigit() else 0
        return info

    def get_nearby_wifi(self):
        run_cmd('powershell -Command "$p=New-Object System.Net.NetworkInformation.Ping; $p.Send(\'127.0.0.1\') | Out-Null"')
        output = run_cmd("netsh wlan show networks mode=bssid")
        networks = []
        current_network = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID ") and ":" in line:
                if current_network and current_network.get("ssid"): networks.append(current_network)
                current_network = {
                    "ssid": line.split(":", 1)[1].strip(), "authentication": "Open", "encryption": "None", 
                    "signal": 0, "channel": "", "bssid": "", "radio_type": ""
                }
            elif current_network:
                if line.startswith("Authentication"): current_network["authentication"] = line.split(":", 1)[1].strip()
                elif line.startswith("Encryption"): current_network["encryption"] = line.split(":", 1)[1].strip()
                elif line.startswith("BSSID"): current_network["bssid"] = line.split(":", 1)[1].strip().upper()
                elif line.startswith("Signal"): 
                    sig = line.split(":", 1)[1].strip().replace("%", "")
                    current_network["signal"] = int(sig) if sig.isdigit() else 0
                elif line.startswith("Radio type"): current_network["radio_type"] = line.split(":", 1)[1].strip()
                elif line.startswith("Channel"): current_network["channel"] = line.split(":", 1)[1].strip()
        if current_network and current_network.get("ssid"): networks.append(current_network)
        return networks
        
    async def get_devices(self, host_mac):
        host_ip = "127.0.0.1"
        try:
            output = run_cmd("ipconfig")
            for line in output.splitlines():
                if "IPv4 Address" in line:
                    ip = line.split(":", 1)[1].strip()
                    if not ip.startswith("169.") and not ip.startswith("127."):
                        host_ip = ip
                        break
        except: pass
        
        devices = []
        host_ports = await scan_ports(host_ip)
        devices.append({
            "ip": host_ip, "mac": host_mac, "vendor": "This Workstation",
            "hostname": socket.gethostname(), "is_host": True, "latency_ms": 0,
            "open_ports": host_ports
        })
        
        arp_output = run_cmd("arp -a")
        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0] and "-" in parts[1]:
                ip = parts[0]
                mac = parts[1].replace("-", ":").upper()
                if mac != "FF:FF:FF:FF:FF:FF" and mac != host_mac:
                    if host_ip != "127.0.0.1" and not ip.startswith(".".join(host_ip.split(".")[:3]) + "."):
                        continue
                    try: hostname = socket.gethostbyaddr(ip)[0]
                    except: hostname = ""
                    dev_ports = await scan_ports(ip)
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": "Network Node",
                        "hostname": hostname, "is_host": False, "latency_ms": "ERR",
                        "open_ports": dev_ports
                    })
        return devices

class MacScanner:
    def get_current_wifi(self):
        output = run_cmd("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I")
        info = {
            "status": "disconnected", "interface_name": "en0", "description": "AirPort",
            "mac_address": "", "ssid": "", "bssid": "", "band": "", "channel": "",
            "radio_type": "", "authentication": "Open", "cipher": "None",
            "receive_rate": "0", "transmit_rate": "0", "signal": 0
        }
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID:"): info["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID:"): info["bssid"] = line.split(":", 1)[1].strip().upper()
            elif line.startswith("agrCtlRSSI:"): info["signal"] = abs(int(line.split(":", 1)[1].strip()))
            elif line.startswith("channel:"): info["channel"] = line.split(":", 1)[1].strip()
            elif line.startswith("lastTxRate:"): info["transmit_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("maxRate:"): info["receive_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("link auth:"): info["authentication"] = line.split(":", 1)[1].strip()
        if info["ssid"]: info["status"] = "connected"
        return info

    def get_nearby_wifi(self):
        output = run_cmd("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s")
        networks = []
        lines = output.splitlines()
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    ssid = line[:32].strip()
                    bssid = parts[-6]
                    try: signal = abs(int(parts[-5]))
                    except: signal = 0
                    channel = parts[-4]
                    auth = parts[-1]
                    networks.append({
                        "ssid": ssid, "authentication": auth, "encryption": auth,
                        "signal": signal, "channel": channel, "bssid": bssid, "radio_type": ""
                    })
        return networks

    async def get_devices(self, host_mac):
        host_ip = "127.0.0.1"
        try:
            output = run_cmd("ipconfig getifaddr en0")
            if output.strip(): host_ip = output.strip()
        except: pass
        host_ports = await scan_ports(host_ip)
        devices = [{
            "ip": host_ip, "mac": host_mac, "vendor": "This Workstation",
            "hostname": socket.gethostname(), "is_host": True, "latency_ms": 0,
            "open_ports": host_ports
        }]
        arp_output = run_cmd("arp -an")
        for line in arp_output.splitlines():
            if " at " in line:
                parts = line.split(" at ")
                ip = parts[0].replace("?", "").strip(" ()")
                mac = parts[1].split()[0].upper()
                if mac != "FF:FF:FF:FF:FF:FF" and mac != host_mac and "incomplete" not in line:
                    dev_ports = await scan_ports(ip)
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": "Network Node",
                        "hostname": "", "is_host": False, "latency_ms": "ERR",
                        "open_ports": dev_ports
                    })
        return devices

class LinuxScanner:
    def get_current_wifi(self):
        info = {
            "status": "disconnected", "interface_name": "wlan0", "description": "Wireless",
            "mac_address": "", "ssid": "", "bssid": "", "band": "", "channel": "",
            "radio_type": "", "authentication": "Open", "cipher": "None",
            "receive_rate": "0", "transmit_rate": "0", "signal": 0
        }
        output = run_cmd("nmcli -t -f ACTIVE,SSID,BSSID,SIGNAL dev wifi")
        for line in output.splitlines():
            line = line.replace(r"\:", "-")
            parts = line.split(":")
            if parts[0] == "yes" and len(parts) >= 4:
                info["status"] = "connected"
                info["ssid"] = parts[1]
                info["bssid"] = parts[2].replace("-", ":")
                try: info["signal"] = int(parts[3])
                except: pass
                break
        return info

    def get_nearby_wifi(self):
        networks = []
        output = run_cmd("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY,CHAN dev wifi")
        for line in output.splitlines():
            line = line.replace(r"\:", "-")
            parts = line.split(":")
            if len(parts) >= 5:
                try: signal = int(parts[2])
                except: signal = 0
                networks.append({
                    "ssid": parts[0], "bssid": parts[1].replace("-", ":"), "signal": signal,
                    "authentication": parts[3], "encryption": parts[3], "channel": parts[4], "radio_type": ""
                })
        return networks

    async def get_devices(self, host_mac):
        host_ip = "127.0.0.1"
        try:
            output = run_cmd("hostname -I")
            if output.strip(): host_ip = output.split()[0]
        except: pass
        host_ports = await scan_ports(host_ip)
        devices = [{
            "ip": host_ip, "mac": host_mac, "vendor": "This Workstation",
            "hostname": socket.gethostname(), "is_host": True, "latency_ms": 0,
            "open_ports": host_ports
        }]
        arp_output = run_cmd("ip neigh")
        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts):
                    mac = parts[mac_idx].upper()
                    if mac != "FF:FF:FF:FF:FF:FF" and mac != host_mac:
                        dev_ports = await scan_ports(ip)
                        devices.append({
                            "ip": ip, "mac": mac, "vendor": "Network Node",
                            "hostname": "", "is_host": False, "latency_ms": "ERR",
                            "open_ports": dev_ports
                        })
        return devices

async def run_scan_loop(agent_id, callback):
    """
    Main loop that runs every 5 seconds. Detects OS and streams data back to the callback.
    """
    os_name = get_os()
    if os_name == "Windows": scanner = WindowsScanner()
    elif os_name == "Darwin": scanner = MacScanner()
    else: scanner = LinuxScanner()

    while True:
        try:
            wifi_info = scanner.get_current_wifi()
            nearby = scanner.get_nearby_wifi()
            devices = await scanner.get_devices(wifi_info["mac_address"])
            
            report = {
                "agent_id": agent_id,
                "wifi": wifi_info,
                "devices": devices,
                "wifi_scan": nearby
            }
            
            # Print a neat console message similar to what the old agent.ps1 did
            time_str = datetime.datetime.now().strftime('%H:%M:%S')
            print(f"  [{time_str}] OK  SSID: {wifi_info.get('ssid','None')}  Devices: {len(devices)}  Nearby: {len(nearby)}")
            
            # Fire callback
            if callback:
                await callback(agent_id, report)
                
        except Exception as e:
            print(f"Agent Scan Error: {e}")
            
        await asyncio.sleep(5)
