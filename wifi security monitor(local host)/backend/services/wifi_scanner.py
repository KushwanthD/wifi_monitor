import subprocess
import re
import shutil

class WiFiScanner:
    @staticmethod
    def is_netsh_available():
        return shutil.which("netsh") is not None

    @staticmethod
    def get_current_wifi_connection():
        """
        Runs 'netsh wlan show interfaces' and parses the active connection details.
        """
        if not WiFiScanner.is_netsh_available():
            return {"error": "netsh command not available (non-Windows system?)"}

        try:
            # Run command with startupinfo to hide console window if compiled/run as GUI
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo
            )
            
            if result.returncode != 0:
                return {"status": "disconnected", "error": "Failed to query interfaces."}

            output = result.stdout
            
            # Simple parse
            details = {}
            for line in output.splitlines():
                line = line.strip()
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    details[key] = val

            # Check if we are connected
            state = details.get("state", "disconnected")
            if state != "connected":
                return {"status": "disconnected", "details": details}

            # Determine security details
            auth = details.get("authentication", "Open")
            auth_upper = auth.upper()
            
            password_protected = True
            security_level = "Unknown"
            encryption_strength = "Unknown"
            security_details = "Password Protected"

            if "OPEN" in auth_upper or "NONE" in auth_upper or auth_upper == "":
                password_protected = False
                security_level = "Insecure / Public"
                encryption_strength = "None (Vulnerable)"
                security_details = "Open (Unencrypted)"
            elif "WEP" in auth_upper:
                security_level = "Weak / Legacy"
                encryption_strength = "WEP (Vulnerable to exploits)"
                security_details = "Password Protected (WEP)"
            elif "WPA3" in auth_upper:
                security_level = "Strong / Modern"
                encryption_strength = "High (AES-GCMP/CCMP)"
                security_details = "Password Protected (WPA3)"
            elif "WPA2" in auth_upper:
                security_level = "Standard / Secure"
                encryption_strength = "Medium-High (AES-CCMP)"
                security_details = "Password Protected (WPA2)"
            elif "WPA" in auth_upper:
                security_level = "Legacy / Deprecated"
                encryption_strength = "Medium-Low (TKIP)"
                security_details = "Password Protected (WPA)"

            # Map the parsed fields to clean standard keys
            return {
                "status": "connected",
                "interface_name": details.get("name", "Unknown"),
                "description": details.get("description", ""),
                "mac_address": details.get("physical_address", "").upper(),
                "ssid": details.get("ssid", "Unknown"),
                "bssid": details.get("ap_bssid", "").upper(),
                "band": details.get("band", ""),
                "channel": details.get("channel", ""),
                "radio_type": details.get("radio_type", ""),
                "authentication": auth,
                "cipher": details.get("cipher", "None"),
                "receive_rate": details.get("receive_rate_(mbps)", "0"),
                "transmit_rate": details.get("transmit_rate_(mbps)", "0"),
                "signal": int(details.get("signal", "0").replace("%", "").strip()) if "signal" in details else 0,
                "password_protected": password_protected,
                "security_level": security_level,
                "encryption_strength": encryption_strength,
                "security_details": security_details,
            }

        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def get_wifi_scan_results():
        """
        Runs 'netsh wlan show networks mode=bssid' and returns a structured list of networks.
        """
        if not WiFiScanner.is_netsh_available():
            return []

        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo
            )

            if result.returncode != 0:
                return []

            output = result.stdout
            networks = []
            
            # Split output by "SSID "
            # First element is usually general interface info, ignore it
            chunks = output.split("\nSSID ")
            for chunk in chunks[1:]:
                lines = chunk.splitlines()
                if not lines:
                    continue

                # Header line format: "X : SSID_NAME"
                header = lines[0].strip()
                ssid_name = "[Hidden Network]"
                if " : " in header:
                    parts = header.split(" : ", 1)
                    if len(parts) > 1:
                        ssid_name = parts[1].strip()
                
                # Parse network stats (auth, encryption, bssids)
                network_info = {
                    "ssid": ssid_name,
                    "authentication": "Open",
                    "encryption": "None",
                    "bssids": []
                }
                
                current_bssid = None
                
                for line in lines[1:]:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    
                    if ":" in line_stripped:
                        key, val = [p.strip() for p in line_stripped.split(":", 1)]
                        key_lower = key.lower()
                        
                        if key_lower == "authentication":
                            network_info["authentication"] = val
                        elif key_lower == "encryption":
                            network_info["encryption"] = val
                        elif key_lower.startswith("bssid "):
                            # New BSSID block starts
                            current_bssid = {
                                "bssid": val.upper(),
                                "signal": 0,
                                "channel": "0",
                                "band": "",
                                "radio_type": ""
                            }
                            network_info["bssids"].append(current_bssid)
                        elif current_bssid is not None:
                            # We are within a BSSID block
                            if key_lower == "signal":
                                current_bssid["signal"] = int(val.replace("%", "").strip())
                            elif key_lower == "channel":
                                current_bssid["channel"] = val
                            elif key_lower == "band":
                                current_bssid["band"] = val
                            elif key_lower == "radio type":
                                current_bssid["radio_type"] = val
                
                # If there are no BSSIDs (e.g. command output structure variance), add fallback
                if not network_info["bssids"]:
                    continue

                networks.append(network_info)

            return networks

        except Exception as e:
            print(f"Error scanning WiFi: {e}")
            return []

if __name__ == "__main__":
    # Test output
    print("CURRENT wifi:")
    print(WiFiScanner.get_current_wifi_connection())
    print("\nSCAN results:")
    print(WiFiScanner.get_wifi_scan_results())
