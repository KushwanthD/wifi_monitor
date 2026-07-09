"""
correlation.py – Threat Correlation Engine mapping vulnerabilities to cyber exploit scenarios.
"""

from typing import List, Dict, Any

THREAT_MATRIX = {
    "unencrypted_wifi": {
        "vulnerability": "Open / Unencrypted Wi-Fi Network",
        "threat": "Cleartext Eavesdropping & Packet Sniffing",
        "exploit_scenario": "An attacker within radio range runs Wireshark or tcpdump in monitor mode, capturing all unencrypted packets (passwords, emails, and session cookies) in plaintext without needing to associate with the router.",
        "impact": "Critical",
        "impact_class": "badge-danger",
        "likelihood": "High"
    },
    "wep_protocol": {
        "vulnerability": "WEP Security Protocol",
        "threat": "WEP Key Cracking & Full Subnet Access",
        "exploit_scenario": "An attacker captures IV (Initialization Vector) collision packets and runs tools like aircrack-ng to mathematically crack the WEP key in under 60 seconds, gaining total access to the internal network.",
        "impact": "Critical",
        "impact_class": "badge-danger",
        "likelihood": "High"
    },
    "wpa_protocol": {
        "vulnerability": "WPA1 Security Protocol (TKIP)",
        "threat": "Pre-shared Key (PSK) Handshake Cracking",
        "exploit_scenario": "An attacker captures the 4-way authentication handshake and runs offline brute-force or dictionary attacks to crack the weak password hash.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "Medium"
    },
    "tkip_cipher": {
        "vulnerability": "TKIP Encryption Cipher",
        "threat": "Beck-Tews Packet Injection & Decryption",
        "exploit_scenario": "An attacker exploits mathematical flaws in the legacy TKIP cipher to decrypt small packets (like ARP requests) and inject custom frames into your active network connection.",
        "impact": "Medium",
        "impact_class": "badge-yellow",
        "likelihood": "Medium"
    },
    "missing_pmf": {
        "vulnerability": "Protected Management Frames (PMF) Disabled",
        "threat": "Deauthentication Wi-Fi Jamming & Handshake Capture",
        "exploit_scenario": "Because management frames are unencrypted, an attacker sends spoofed disassociation frames to disconnect your workstation, forcing it to automatically reconnect, allowing them to capture the WPA handshake.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "High"
    },
    "wps_enabled": {
        "vulnerability": "WPS (Wi-Fi Protected Setup) Enabled",
        "threat": "WPS PIN Pixie-Dust / Reaver Brute-Force",
        "exploit_scenario": "An attacker brute-forces the 8-digit WPS PIN or exploits low entropy in the router's cryptographic generation to recover the main WPA2 pre-shared key within hours.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "High"
    },
    "default_ssid": {
        "vulnerability": "Default SSID Naming Pattern",
        "threat": "Precomputed WPA2 Rainbow Table Decryption",
        "exploit_scenario": "Using generic SSIDs like 'Linksys' or 'Netgear' allows attackers to use precomputed hash databases (Rainbow Tables) to crack passwords instantly, bypassing the slow on-the-fly computation.",
        "impact": "Medium",
        "impact_class": "badge-yellow",
        "likelihood": "Medium"
    },
    "rogue_ap": {
        "vulnerability": "Rogue Access Point / Evil Twin Active",
        "threat": "Credential Sniffing & Man-in-the-Middle (MitM)",
        "exploit_scenario": "An attacker clones your office network name (SSID). Your devices automatically connect to this rogue twin due to a stronger signal, allowing the attacker to proxy and sniff all login traffic.",
        "impact": "Critical",
        "impact_class": "badge-danger",
        "likelihood": "High"
    },
    "mac_spoofing": {
        "vulnerability": "MAC Address Spoofing Detected",
        "threat": "Access Control Bypass & IP Hijacking",
        "exploit_scenario": "A malicious actor spoofs the MAC address of an approved network device to bypass router-level MAC filters and steal their connection session.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "Medium"
    },
    "open_port_ftp": {
        "vulnerability": "Unencrypted FTP Service Exposed (Port 21)",
        "threat": "Anonymous Login & File Theft",
        "exploit_scenario": "An attacker connects to the exposed FTP port, exploits weak or default passwords, and sniffs transfer traffic to steal confidential files in plaintext.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "Medium"
    },
    "open_port_telnet": {
        "vulnerability": "Insecure Telnet Service Exposed (Port 23)",
        "threat": "Administrative Console Hijacking",
        "exploit_scenario": "Because Telnet does not encrypt passwords, an attacker sniffs network traffic during login or brute-forces the open console to gain full system shell control.",
        "impact": "Critical",
        "impact_class": "badge-danger",
        "likelihood": "High"
    },
    "open_port_smb": {
        "vulnerability": "Exposed Windows SMB File Share (Port 445)",
        "threat": "Ransomware Lateral Movement / EternalBlue Exploit",
        "exploit_scenario": "An attacker scans the local network for port 445 and attempts exploits (like EternalBlue) or uses credential stuffing to compromise network storage and spread ransomware.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "High"
    },
    "open_port_rdp": {
        "vulnerability": "Exposed Remote Desktop (RDP) Service (Port 3389)",
        "threat": "RDP Brute-Force & Session Takeover",
        "exploit_scenario": "An attacker targets exposed RDP interfaces with brute-force dictionary attacks or BlueKeep exploits to gain remote control of corporate workstations.",
        "impact": "High",
        "impact_class": "badge-orange",
        "likelihood": "Medium"
    }
}

class CorrelationEngine:
    @staticmethod
    def correlate(wifi: dict, devices: list, alerts: list) -> List[Dict[str, Any]]:
        """
        Processes active vulnerabilities from the current scan environment and
        returns a list of correlated exploits and threat impact descriptions.
        """
        active_threats = []
        vulnerabilities_detected = set()

        # 1. Analyze Wi-Fi Encryption
        auth = (wifi.get("authentication") or "").upper()
        cipher = (wifi.get("cipher") or "").upper()
        ssid = (wifi.get("ssid") or "").upper()

        if "WEP" in auth:
            vulnerabilities_detected.add("wep_protocol")
        elif "WPA" in auth and "WPA2" not in auth and "WPA3" not in auth:
            vulnerabilities_detected.add("wpa_protocol")
        elif "OPEN" in auth or "NONE" in auth or auth == "":
            vulnerabilities_detected.add("unencrypted_wifi")

        if "TKIP" in cipher:
            vulnerabilities_detected.add("tkip_cipher")

        # 2. Analyze Alerts (Rogue AP, MAC Spoofing, Compliance rules)
        for alert in alerts:
            cat = alert.get("category", "")
            msg = alert.get("message", "")
            
            if "Rogue AP" in cat or "Evil Twin" in cat:
                vulnerabilities_detected.add("rogue_ap")
            if "Spoofing" in cat or "MAC Spoofing" in cat:
                vulnerabilities_detected.add("mac_spoofing")
            if "PMF" in msg:
                vulnerabilities_detected.add("missing_pmf")
            if "WPS" in msg:
                vulnerabilities_detected.add("wps_enabled")
            if "Default SSID" in msg or "SSID naming" in msg:
                vulnerabilities_detected.add("default_ssid")

        # 3. Analyze Exposed Ports on Network Devices
        for dev in devices:
            open_ports = dev.get("open_ports")
            if open_ports:
                # Load ports (could be list or JSON-string)
                import json
                if isinstance(open_ports, str):
                    try:
                        open_ports = json.loads(open_ports)
                    except Exception:
                        open_ports = []
                
                if isinstance(open_ports, list):
                    for port_entry in open_ports:
                        pnum = port_entry if isinstance(port_entry, int) else port_entry.get("port")
                        if pnum == 21:
                            vulnerabilities_detected.add("open_port_ftp")
                        elif pnum == 23:
                            vulnerabilities_detected.add("open_port_telnet")
                        elif pnum == 445:
                            vulnerabilities_detected.add("open_port_smb")
                        elif pnum == 3389:
                            vulnerabilities_detected.add("open_port_rdp")

        # 4. Map detected keys to the Threat Matrix
        for key in sorted(vulnerabilities_detected):
            if key in THREAT_MATRIX:
                active_threats.append(THREAT_MATRIX[key])

        return active_threats
