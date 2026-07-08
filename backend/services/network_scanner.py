import subprocess
import re
import socket
import psutil
from concurrent.futures import ThreadPoolExecutor
import requests

class NetworkScanner:
    # A short list of common MAC OUIs (first 3 bytes) for offline resolution
    COMMON_VENDORS = {
        "00:00:0C": "Cisco",
        "00:01:42": "Cisco",
        "00:0A:95": "Apple",
        "00:10:FA": "Apple",
        "00:1C:B3": "Apple",
        "00:17:F2": "Apple",
        "00:1E:C2": "Apple",
        "00:23:12": "Apple",
        "00:25:00": "Apple",
        "00:26:BB": "Apple",
        "04:26:65": "Apple",
        "0C:4D:E9": "Apple",
        "10:40:F3": "Apple",
        "14:10:9F": "Apple",
        "14:99:E2": "Apple",
        "18:AF:61": "Apple",
        "24:a0:74": "Apple",
        "28:CF:E9": "Apple",
        "34:15:9E": "Apple",
        "3C:D0:F8": "Apple",
        "40:3C:FC": "Apple",
        "40:A1:08": "Apple",
        "48:43:7C": "Apple",
        "4C:7C:5F": "Apple",
        "54:2A:A2": "Apple",
        "58:55:CA": "Apple",
        "60:03:08": "Apple",
        "64:B9:E8": "Apple",
        "6C:40:08": "Apple",
        "6C:70:9F": "Apple",
        "70:11:24": "Apple",
        "70:81:EB": "Apple",
        "74:E1:B6": "Apple",
        "78:31:C1": "Apple",
        "78:4F:43": "Apple",
        "78:7B:8A": "Apple",
        "7C:11:BE": "Apple",
        "7C:50:49": "Apple",
        "7C:6D:62": "Apple",
        "7C:C5:37": "Apple",
        "80:49:71": "Apple",
        "80:A1:D7": "Apple",
        "84:38:35": "Apple",
        "84:78:AC": "Apple",
        "88:63:DF": "Apple",
        "88:C6:63": "Apple",
        "8C:85:90": "Apple",
        "8C:8E:F2": "Apple",
        "90:B2:1F": "Apple",
        "98:01:A7": "Apple",
        "98:10:E8": "Apple",
        "98:D6:BB": "Apple",
        "A4:31:35": "Apple",
        "A4:D1:8C": "Apple",
        "A8:86:DD": "Apple",
        "AC:7F:3E": "Apple",
        "AC:BC:32": "Apple",
        "B0:35:B4": "Apple",
        "B4:18:D1": "Apple",
        "B8:09:8A": "Apple",
        "B8:78:2E": "Apple",
        "B8:C7:5D": "Apple",
        "BC:54:36": "Apple",
        "BC:9F:EF": "Apple",
        "C0:CC:F8": "Apple",
        "C4:2C:03": "Apple",
        "C4:98:80": "Apple",
        "C8:3C:85": "Apple",
        "C8:B5:B7": "Apple",
        "D0:23:DB": "Apple",
        "D0:25:99": "Apple",
        "D0:81:7A": "Apple",
        "D4:90:9C": "Apple",
        "D8:00:4D": "Apple",
        "D8:30:62": "Apple",
        "D8:A2:5E": "Apple",
        "DC:2B:61": "Apple",
        "DC:37:14": "Apple",
        "DC:A9:04": "Apple",
        "E0:51:63": "Apple",
        "E0:B9:BA": "Apple",
        "E0:F8:47": "Apple",
        "E4:25:E7": "Apple",
        "E4:E4:ab": "Apple",
        "E8:04:0B": "Apple",
        "E8:06:88": "Apple",
        "E8:80:2E": "Apple",
        "EC:35:86": "Apple",
        "F0:76:6F": "Apple",
        "F0:99:B6": "Apple",
        "F0:C1:F1": "Apple",
        "F0:D1:A9": "Apple",
        "F4:0F:24": "Apple",
        "F4:37:B7": "Apple",
        "F4:F9:51": "Apple",
        "FC:E9:98": "Apple",

        "00:26:37": "Samsung",
        "00:12:47": "Samsung",
        "00:12:FB": "Samsung",
        "1C:5A:3E": "Samsung",
        "50:85:69": "Samsung",
        "84:55:A5": "Samsung",
        "94:E9:79": "Samsung",
        "A8:06:00": "Samsung",
        "BC:72:B1": "Samsung",
        "CC:C0:79": "Samsung",
        "D8:90:E8": "Samsung",
        "E4:E0:A6": "Samsung",
        "E8:E5:D6": "Samsung",
        
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:05:69": "VMware",
        
        "00:15:5D": "Microsoft (Hyper-V)",
        "00:03:FF": "Microsoft",
        
        "00:1E:58": "Intel",
        "00:21:5C": "Intel",
        "00:21:6A": "Intel",
        "00:22:FA": "Intel",
        "00:27:0E": "Intel",
        "00:27:10": "Intel",
        "34:6F:24": "Intel",
        "4C:ED:DE": "Intel",
        "9C:67:D6": "Intel",
        "A0:C5:89": "Intel",
        "C8:FF:28": "Intel",
        "D4:3B:04": "Intel",
        "E0:D5:5E": "Intel",
        "FC:77:74": "Intel",
        
        "00:1A:3F": "Intel",
        "00:14:D1": "Linksys",
        "00:1E:E5": "Linksys",
        "00:25:9C": "Linksys",
        
        "00:21:29": "Cisco-Linksys",
        
        "00:19:E3": "D-Link",
        "00:22:B0": "D-Link",
        "18:62:2C": "D-Link",
        "90:94:E4": "D-Link",
        "C0:25:2F": "D-Link",
        
        "00:1D:0F": "TP-Link",
        "00:27:19": "TP-Link",
        "14:CC:20": "TP-Link",
        "3C:83:71": "TP-Link",
        "50:C7:BF": "TP-Link",
        "74:DA:38": "TP-Link",
        "84:16:F9": "TP-Link",
        "A8:57:4E": "TP-Link",
        "C0:25:E9": "TP-Link",
        "D8:44:89": "TP-Link",
        "E8:94:F6": "TP-Link",
        "EC:08:6B": "TP-Link",
        "F4:3E:61": "TP-Link",
        
        "00:17:88": "Philips Hue / Signify",
        "00:1A:22": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "74:83:C2": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "FC:EC:DA": "Ubiquiti",
        
        "00:1A:11": "Google",
        "3C:5A:37": "Google",
        "D8:24:BD": "Google",
        "F4:F5:D8": "Google",
        
        "18:B4:30": "Nest Labs",
        "2C:3A:E8": "Nest Labs",
        
        "24:0A:C4": "Espressif (IoT)",
        "30:AE:A4": "Espressif (IoT)",
        "54:5A:A6": "Espressif (IoT)",
        "68:C6:3A": "Espressif (IoT)",
        "84:F3:EB": "Espressif (IoT)",
        "A4:CF:12": "Espressif (IoT)",
        "C4:4F:33": "Espressif (IoT)",
        "CC:50:E3": "Espressif (IoT)",
        "E8:68:E7": "Espressif (IoT)",
    }

    @staticmethod
    def get_wifi_interface_ip():
        """
        Gets the current IP address and netmask configured on the Wi-Fi adapter.
        """
        try:
            interfaces = psutil.net_if_addrs()
            # On Windows, the wireless adapter is typically named "Wi-Fi"
            wifi_details = interfaces.get("Wi-Fi")
            if not wifi_details:
                # Fallback: search for interface names containing "wifi" or "wlan"
                for name, addrs in interfaces.items():
                    if "wifi" in name.lower() or "wlan" in name.lower():
                        wifi_details = addrs
                        break

            if wifi_details:
                for addr in wifi_details:
                    if addr.family == socket.AddressFamily.AF_INET:
                        return addr.address, addr.netmask
            
            # General fallback: get primary local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip, "255.255.255.0"
        except Exception:
            return None, None

    @staticmethod
    def ping_ip(ip):
        """
        Pings a single IP with 1 packet and 150ms timeout.
        Returns True if reachable, False otherwise.
        """
        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # -n 1: 1 packet, -w 150: 150ms timeout
            res = subprocess.run(
                ["ping", "-n", "1", "-w", "150", ip],
                capture_output=True,
                text=True,
                startupinfo=startupinfo
            )
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def perform_ping_sweep(ip_prefix):
        """
        Pings all 254 addresses in a /24 subnet concurrently using threads.
        """
        ips_to_scan = [f"{ip_prefix}{i}" for i in range(1, 255)]
        
        # Sweep with 60 parallel threads
        with ThreadPoolExecutor(max_workers=60) as executor:
            executor.map(NetworkScanner.ping_ip, ips_to_scan)

    @staticmethod
    def resolve_vendor(mac):
        """
        Resolves the MAC OUI to a manufacturer name.
        Checks local dictionary, falls back to an API if internet is available.
        """
        if not mac or mac == "FF-FF-FF-FF-FF-FF":
            return "Broadcast"

        clean_mac = mac.replace("-", ":").upper()
        oui = clean_mac[:8]
        
        # Check offline db first
        if oui in NetworkScanner.COMMON_VENDORS:
            return NetworkScanner.COMMON_VENDORS[oui]
        
        # Online fallback API (maclookup.app or macvendors.co - maclookup is free without key for light use)
        try:
            url = f"https://api.maclookup.app/v2/macs/{clean_mac}"
            res = requests.get(url, timeout=1.0)
            if res.status_code == 200:
                data = res.json()
                company = data.get("company", "")
                if company:
                    return company
        except Exception:
            pass

        return "Unknown Device"

    @staticmethod
    def get_connected_devices():
        """
        Finds all active devices on the local Wi-Fi interface.
        1. Gets the Wi-Fi IP and mask.
        2. Conducts a fast ping sweep.
        3. Parses the output of 'arp -a' to extract MAC/IP mappings.
        """
        wifi_ip, netmask = NetworkScanner.get_wifi_interface_ip()
        if not wifi_ip:
            return {"error": "WiFi interface is offline or not configured."}

        # Determine the prefix (assumes /24 subnet for local home networks)
        ip_parts = wifi_ip.split(".")
        if netmask == "255.255.255.0" or not netmask:
            ip_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        else:
            # Fallback to /24 prefix of our current IP
            ip_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."

        # Conduct ping sweep to populate ARP cache
        NetworkScanner.perform_ping_sweep(ip_prefix)

        # Query and parse ARP cache
        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo
            )
            
            if result.returncode != 0:
                return {"error": "Failed to read ARP cache."}

            output = result.stdout
            
            devices = []
            current_interface = None
            
            # Regex to match ARP entries: e.g. "  192.168.1.1           00-11-22-33-44-55     dynamic"
            arp_re = re.compile(r"^\s*([\d\.]+)\s+([0-9a-fA-F\-]{17})\s+(\w+)")
            
            for line in output.splitlines():
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                
                # Check for interface header: "Interface: 192.168.1.50 --- 0x3"
                if line_stripped.startswith("Interface:"):
                    current_interface = line_stripped.split("Interface:")[1].split()[0]
                    continue
                
                # We only want entries belonging to the Wi-Fi interface
                if current_interface == wifi_ip:
                    match = arp_re.match(line)
                    if match:
                        ip_addr, mac_addr, entry_type = match.groups()
                        mac_addr = mac_addr.upper().replace("-", ":")
                        
                        # Exclude broadcast and multicast entries
                        if mac_addr.startswith("01:00:5E") or mac_addr == "FF:FF:FF:FF:FF:FF":
                            continue
                            
                        # Exclude loopback/self IP if in ARP table
                        if ip_addr == wifi_ip:
                            continue

                        devices.append({
                            "ip": ip_addr,
                            "mac": mac_addr,
                            "type": entry_type,
                            "vendor": NetworkScanner.resolve_vendor(mac_addr),
                            "is_host": False
                        })

            # Add the current machine itself as a device in the list
            try:
                # Find host MAC address
                host_mac = "UNKNOWN"
                interfaces = psutil.net_if_addrs()
                for name, addrs in interfaces.items():
                    if "wi-fi" in name.lower() or "wlan" in name.lower():
                        for addr in addrs:
                            if getattr(addr.family, 'name', '') == 'AF_LINK' or addr.family == -1: # AF_LINK is link layer (MAC)
                                host_mac = addr.address.upper().replace("-", ":")
                                break
                
                devices.append({
                    "ip": wifi_ip,
                    "mac": host_mac,
                    "type": "static",
                    "vendor": "Host (This Computer)",
                    "is_host": True
                })
            except Exception:
                pass

            return {
                "wifi_ip": wifi_ip,
                "netmask": netmask or "255.255.255.0",
                "devices": devices
            }

        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    print("Scanning network...")
    print(NetworkScanner.get_connected_devices())
