import socket
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor

class SecurityAuditor:
    # Common ports to scan on the host
    PORTS_TO_SCAN = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Admin)",
        25: "SMTP (Mail Transfer)",
        80: "HTTP (Web Server)",
        110: "POP3 (Mail Server)",
        135: "RPC (Remote Procedure Call)",
        139: "NetBIOS Session Service",
        443: "HTTPS (Secure Web Server)",
        445: "SMB (Windows File Sharing)",
        1433: "MSSQL Server",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop)",
        8080: "HTTP Alternative",
    }

    @staticmethod
    def scan_port(ip, port):
        """
        Attempts to open a socket on the target port.
        Returns the port number if open, None otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15) # 150ms timeout
                result = s.connect_ex((ip, port))
                if result == 0:
                    return port
        except Exception:
            pass
        return None

    @staticmethod
    def audit_local_ports(local_ip):
        """
        Scans common ports on localhost (127.0.0.1) and the local interface IP.
        """
        open_ports = []
        targets = ["127.0.0.1"]
        if local_ip and local_ip != "127.0.0.1":
            targets.append(local_ip)

        for target in targets:
            with ThreadPoolExecutor(max_workers=20) as executor:
                # Map scanning function across target ports
                results = executor.map(lambda p: SecurityAuditor.scan_port(target, p), SecurityAuditor.PORTS_TO_SCAN.keys())
                for port in results:
                    if port is not None:
                        open_ports.append({
                            "ip": target,
                            "port": port,
                            "service": SecurityAuditor.PORTS_TO_SCAN[port]
                        })
        return open_ports

    @staticmethod
    def get_public_ip_info():
        """
        Calls a public geolocation API to retrieve external IP details.
        Also verifies if the host is exposed directly or via VPN/Proxy.
        """
        try:
            response = requests.get("https://ipapi.co/json/", timeout=2.0)
            if response.status_code == 200:
                data = response.json()
                return {
                    "public_ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country_name"),
                    "org": data.get("org"), # ISP / Organization
                    "vpn_detected": False # Can flag if ISP is a known hosting provider
                }
        except Exception as e:
            return {"error": f"Could not fetch public IP info: {str(e)}"}
        return {"error": "Failed to retrieve external IP info."}

    @staticmethod
    def check_dns_settings():
        """
        Queries active DNS servers in Windows using PowerShell.
        """
        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                ["powershell", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"],
                capture_output=True,
                text=True,
                startupinfo=startupinfo
            )
            if result.returncode == 0:
                servers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                return servers
        except Exception:
            pass
        return ["127.0.0.1"] # Fallback

    @staticmethod
    def run_security_audit(current_connection, local_ip):
        """
        Aggregates security checks into a score and recommendations.
        """
        score = 100
        alerts = []
        
        # 1. WiFi Authentication Check
        auth = current_connection.get("authentication", "Open").upper()
        if "WPA3" in auth:
            # Perfect
            pass
        elif "WPA2" in auth:
            # Good but handshake can be captured
            score -= 10
            alerts.append({
                "severity": "low",
                "category": "WiFi Encryption",
                "message": "Connected using WPA2. While secure, upgrading to WPA3 is recommended for stronger protection against brute-force attacks."
            })
        elif "WEP" in auth or "OPEN" in auth or "NONE" in auth:
            score -= 40
            alerts.append({
                "severity": "critical",
                "category": "WiFi Encryption",
                "message": "Connected to an OPEN or WEP network! Your traffic is unencrypted and vulnerable to eavesdropping."
            })
        else:
            # WPA or other older protocol
            score -= 20
            alerts.append({
                "severity": "medium",
                "category": "WiFi Encryption",
                "message": f"Connected using outdated protocol ({auth}). Upgrade your router configuration."
            })

        # 2. Local Exposed Ports Check
        open_ports = SecurityAuditor.audit_local_ports(local_ip)
        # Filter ports open on the actual network IP, which are more critical than 127.0.0.1
        network_exposed_ports = [p for p in open_ports if p["ip"] == local_ip]
        if network_exposed_ports:
            score -= min(15 * len(network_exposed_ports), 30)
            for p in network_exposed_ports:
                alerts.append({
                    "severity": "high",
                    "category": "Exposed Service",
                    "message": f"Port {p['port']} ({p['service']}) is open on your network IP {local_ip}. Devices on this WiFi can scan and potentially connect to this service."
                })

        # 3. Public IP details
        pub_info = SecurityAuditor.get_public_ip_info()
        dns_servers = SecurityAuditor.check_dns_settings()

        # Check for unencrypted / standard local gateway DNS servers
        local_dns = False
        for srv in dns_servers:
            if srv.startswith("192.168.") or srv.startswith("10.") or srv.startswith("172.16."):
                local_dns = True
                break
        
        if local_dns:
            # Not a critical bug, but good to know
            alerts.append({
                "severity": "info",
                "category": "DNS Configuration",
                "message": "Using local gateway DNS servers. Consider setting up secure DNS (e.g. Cloudflare 1.1.1.1 or Google 8.8.8.8) to prevent DNS hijacking."
            })

        # Clamp score between 0 and 100
        score = max(0, min(100, score))

        return {
            "security_score": score,
            "alerts": alerts,
            "open_ports": open_ports,
            "public_ip_info": pub_info,
            "dns_servers": dns_servers
        }

if __name__ == "__main__":
    print("Running audit...")
    print(SecurityAuditor.run_security_audit({"authentication": "WPA2-Personal"}, "10.252.212.165"))
