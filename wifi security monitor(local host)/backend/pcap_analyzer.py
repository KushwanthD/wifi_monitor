"""
pcap_analyzer.py – Pure Python Wireshark PCAP Binary Parser for Traffic Forensics.
"""

import struct
from collections import defaultdict
from typing import BinaryIO, Dict, Any, List

class PcapAnalyzer:
    @staticmethod
    def analyze(stream: BinaryIO) -> Dict[str, Any]:
        """
        Parses a raw binary PCAP stream. Extracts protocols, active IPs, and searches
        for plain-text credentials, insecure protocols, and port scans.
        """
        # Read 24-byte global header
        global_header = stream.read(24)
        if len(global_header) < 24:
            return {"error": "Invalid file size. Not a valid PCAP file."}

        # Unpack global header magic number (first 4 bytes)
        magic = global_header[:4]
        endian = "<"  # Little endian default
        if magic == b"\xa1\xb2\xc3\xd4":
            endian = "<"
        elif magic == b"\xd4\xc3\xb2\xa1":
            endian = ">"
        elif magic == b"\xa1\xb2\x3c\x4d": # Nanosecond PCAP
            endian = "<"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = ">"
        else:
            # Check for PCAPNG magic number (0x0A0D0D0A)
            if magic == b"\x0a\x0d\x0d\x0a":
                return {"error": "PCAPNG format is not supported directly. Please export/convert as standard PCAP in Wireshark."}
            return {"error": "Unsupported magic number. Only standard wiretap PCAP files are supported."}

        # Packet counters
        total_packets = 0
        protocols = defaultdict(int)
        ips_observed = set()
        macs_observed = set()
        
        # Security anomalies
        anomalies = []
        plaintext_logins = []
        
        # Track port scan attempts (source IP -> set of destination ports)
        port_scan_tracker = defaultdict(set)
        
        # Read packet loop
        while True:
            header_bytes = stream.read(16)
            if len(header_bytes) < 16:
                break  # End of file
                
            # Unpack packet header: ts_sec, ts_usec, incl_len, orig_len
            _, _, incl_len, _ = struct.unpack(endian + "IIII", header_bytes)
            
            packet_data = stream.read(incl_len)
            if len(packet_data) < incl_len:
                break # Truncated file
                
            total_packets += 1
            if total_packets > 15000:
                # Cap parsing at 15k packets to prevent timeouts/memory overflow
                break
                
            # Parse Link Layer (Ethernet assumes DLT_EN10MB = 1)
            if len(packet_data) < 14:
                continue
                
            dst_mac_raw = packet_data[0:6]
            src_mac_raw = packet_data[6:12]
            eth_type = struct.unpack(">H", packet_data[12:14])[0]
            
            def format_mac(raw):
                return ":".join(f"{b:02X}" for b in raw)
                
            src_mac = format_mac(src_mac_raw)
            dst_mac = format_mac(dst_mac_raw)
            macs_observed.add(src_mac)
            macs_observed.add(dst_mac)
            
            # We process IPv4 (EtherType = 0x0800)
            if eth_type == 0x0800:
                if len(packet_data) < 34: # Ethernet (14) + min IP (20)
                    continue
                
                ip_header = packet_data[14:34]
                # Protocol offset is byte 9 in IP header
                proto = ip_header[9]
                
                # Source IP (bytes 12-15), Destination IP (bytes 16-19)
                src_ip = ".".join(str(b) for b in ip_header[12:16])
                dst_ip = ".".join(str(b) for b in ip_header[16:20])
                ips_observed.add(src_ip)
                ips_observed.add(dst_ip)
                
                # Extract IP header length
                ip_hl = (ip_header[0] & 0x0F) * 4
                
                # TCP Protocol (6)
                if proto == 6:
                    protocols["TCP"] += 1
                    tcp_offset = 14 + ip_hl
                    if len(packet_data) < tcp_offset + 20:
                        continue
                    
                    # Read ports
                    src_port = struct.unpack(">H", packet_data[tcp_offset:tcp_offset+2])[0]
                    dst_port = struct.unpack(">H", packet_data[tcp_offset+2:tcp_offset+4])[0]
                    
                    # Track port scan sweeps
                    port_scan_tracker[src_ip].add(dst_port)
                    
                    # Detect Insecure Protocol ports
                    if dst_port == 21 or src_port == 21:
                        protocols["FTP"] += 1
                    elif dst_port == 23 or src_port == 23:
                        protocols["Telnet"] += 1
                    elif dst_port == 80 or src_port == 80:
                        protocols["HTTP"] += 1
                        
                    # Extract TCP payload data to check for plain-text logins
                    # TCP data offset is top 4 bits of byte 12 in TCP header
                    data_offset = ((packet_data[tcp_offset + 12] >> 4) & 0x0F) * 4
                    payload_offset = tcp_offset + data_offset
                    if len(packet_data) > payload_offset:
                        payload = packet_data[payload_offset:]
                        try:
                            # Try decoding as ASCII to search for patterns
                            text = payload.decode("ascii", errors="ignore")
                            # Look for unencrypted login strings
                            if "password" in text.lower() or "passwd" in text.lower() or "authorization: basic" in text.lower():
                                # Extract context snippet
                                snippet = text[:80].replace("\r", " ").replace("\n", " ").strip()
                                plaintext_logins.append({
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "port": dst_port,
                                    "snippet": snippet[:100]
                                })
                        except Exception:
                            pass
                            
                # UDP Protocol (17)
                elif proto == 17:
                    protocols["UDP"] += 1
                    udp_offset = 14 + ip_hl
                    if len(packet_data) < udp_offset + 8:
                        continue
                    src_port = struct.unpack(">H", packet_data[udp_offset:udp_offset+2])[0]
                    dst_port = struct.unpack(">H", packet_data[udp_offset+2:udp_offset+4])[0]
                    
                    # Simple DNS tag
                    if dst_port == 53 or src_port == 53:
                        protocols["DNS"] += 1
                        
                # ICMP Protocol (1)
                elif proto == 1:
                    protocols["ICMP"] += 1

        # Check port scan trackers
        for source_ip, ports in port_scan_tracker.items():
            if len(ports) >= 10:
                anomalies.append({
                    "severity": "high",
                    "category": "Subnet Port Sweep",
                    "message": f"Host {source_ip} was observed sweeping {len(ports)} different ports. This matches a network enumeration or Nmap scan signature."
                })

        # Add insecure protocol warnings
        if protocols.get("Telnet", 0) > 0:
            anomalies.append({
                "severity": "critical",
                "category": "Insecure Protocol: Telnet",
                "message": f"Detected {protocols['Telnet']} packet(s) transmitting over unencrypted Telnet (port 23). Attacker can sniff all administrative console commands."
            })
        if protocols.get("FTP", 0) > 0:
            anomalies.append({
                "severity": "high",
                "category": "Insecure Protocol: FTP",
                "message": f"Detected {protocols['FTP']} packet(s) transmitting over unencrypted File Transfer Protocol (FTP, port 21). Transmitted files are vulnerable to eavesdropping."
            })
        if protocols.get("HTTP", 0) > 0:
            anomalies.append({
                "severity": "medium",
                "category": "Insecure Protocol: HTTP",
                "message": f"Detected {protocols['HTTP']} packet(s) communicating over unencrypted HTTP (port 80). Session hijack or Cookie theft is possible."
            })

        # Add plain-text credentials warning
        if plaintext_logins:
            for login in plaintext_logins[:5]: # Limit to top 5
                anomalies.append({
                    "severity": "critical",
                    "category": "Plaintext Credentials Sniffed",
                    "message": f"Detected unencrypted login details transmitted from {login['src_ip']} to {login['dst_ip']} on Port {login['port']}! Context snippet: '{login['snippet']}'"
                })

        # Calculate a basic forensics score (starting at 100, penalties for warnings)
        forensics_score = 100
        for anomaly in anomalies:
            sev = anomaly["severity"]
            if sev == "critical":
                forensics_score -= 30
            elif sev == "high":
                forensics_score -= 15
            elif sev == "medium":
                forensics_score -= 8
        forensics_score = max(0, forensics_score)

        return {
            "total_packets": total_packets,
            "protocols": dict(protocols),
            "ips_count": len(ips_observed),
            "macs_count": len(macs_observed),
            "anomalies": anomalies,
            "security_score": forensics_score
        }
