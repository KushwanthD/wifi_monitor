"""
analysis.py – Threat detection, security assessment and behavioral baselining.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any
import database as db

# ── Severity weights (deducted from base score of 100) ──────────────────────
SEVERITY_WEIGHTS = {
    "critical": 35,
    "high":     20,
    "medium":   10,
    "low":       4,
    "info":      0,
}

SCAN_COUNT_BEFORE_BASELINE = 3   # learn for 3 scans before raising new-AP alerts


def _auth_risk(auth: str) -> tuple[str, int]:
    """Return (severity, score_penalty) for an authentication string."""
    a = (auth or "").upper()
    if "WPA3" in a:
        return ("info", 0)
    if "WPA2" in a:
        return ("low", 10)
    if "WPA" in a:
        return ("medium", 20)
    if "WEP" in a:
        return ("high", 30)
    if "OPEN" in a or "NONE" in a or a == "":
        return ("critical", 40)
    return ("low", 5)


def run_analysis(agent_id: str, wifi: dict, devices: list, wifi_scan: list,
                 scan_count_for_agent: int) -> tuple[int, list]:
    """
    Core analysis function. Returns (security_score, list_of_alert_dicts).
    Also persists new alerts to the database.
    """
    alerts: list[dict] = []
    penalty = 0
    aid = agent_id.upper()

    # ── 1. Connected AP Security Assessment ─────────────────────────────────
    auth = wifi.get("authentication", "")
    cipher = wifi.get("cipher", "")
    sev, auth_penalty = _auth_risk(auth)
    penalty += auth_penalty

    # Set remediation for auth protocol
    auth_remediation = "Access your router administration portal and enable WPA3-Personal (SAE) mode. Ensure Protected Management Frames (PMF) are set to Required or Capable."
    if sev == "critical":
        auth_remediation = "Disconnect immediately. If this is your network, configure WPA2-Personal (AES) or WPA3-Personal encryption with a strong, unique password."
    elif sev == "high":
        auth_remediation = "WEP is highly insecure. Modify the wireless configuration in your access point settings. Change Cipher Type to WPA2-Personal (AES)."

    if sev in ("critical", "high", "medium", "low", "info"):
        msg = _conn_security_msg(auth, wifi.get("ssid", "unknown"))
        alerts.append(_alert(sev, "WiFi Encryption", msg, auth_remediation, {"auth": auth, "ssid": wifi.get("ssid")}))

    # Weak cipher
    if "TKIP" in (cipher or "").upper():
        alerts.append(_alert("medium", "Weak Cipher (TKIP)",
            f"Your connection to '{wifi.get('ssid')}' uses TKIP — a deprecated cipher vulnerable to replay attacks. Configure your router to use AES/CCMP.",
            "Modify the wireless configuration in your access point settings. Change Cipher Type from TKIP or Auto/TKIP+AES to AES-only (CCMP).",
            {"cipher": cipher}))
        penalty += 8

    # ── 2. Airspace Security Assessment (per-nearby-network) ────────────────
    open_nearby = []
    wep_nearby = []
    for ap in (wifi_scan or []):
        ap_auth = (ap.get("authentication") or "").upper()
        if "OPEN" in ap_auth or "NONE" in ap_auth or ap_auth == "":
            open_nearby.append(ap.get("ssid", "Hidden"))
        elif "WEP" in ap_auth:
            wep_nearby.append(ap.get("ssid", "Hidden"))

    if open_nearby:
        alerts.append(_alert("medium", "Open Networks in Airspace",
            f"{len(open_nearby)} open (unencrypted) Wi-Fi network(s) detected nearby: {', '.join(open_nearby[:5])}. These may be honeypots or rogue APs.",
            "Do not connect to open networks without a trusted corporate VPN. Ensure your devices have 'Auto-Connect to open networks' turned off.",
            {"networks": open_nearby}))
        penalty += 5

    if wep_nearby:
        alerts.append(_alert("low", "WEP Networks in Airspace",
            f"{len(wep_nearby)} legacy WEP-protected network(s) nearby: {', '.join(wep_nearby[:3])}. WEP is trivially crackable and poses a neighborhood risk.",
            "Notify owners of WEP access points to upgrade their security settings to WPA2/WPA3 as WEP handshakes can be cracked in under a minute.",
            {"networks": wep_nearby}))

    # ── 3. Behavioral Baseline + Rogue AP / Evil Twin Detection ─────────────
    baseline = db.get_baseline(aid)
    known_bssids: set = set(baseline["known_bssids"])
    known_macs:   set = set(baseline["known_macs"])

    current_bssids = {(ap.get("bssid") or "").upper() for ap in (wifi_scan or []) if ap.get("bssid")}
    current_macs   = {(d.get("mac") or "").upper() for d in devices if not d.get("is_host")}

    # Build SSID → known BSSID map for Evil-Twin check
    ssid_bssid_map: dict[str, list] = {}
    for ap in (wifi_scan or []):
        ssid = ap.get("ssid", "")
        bssid = (ap.get("bssid") or "").upper()
        if ssid and bssid:
            ssid_bssid_map.setdefault(ssid, []).append(bssid)

    # Evil Twin: same SSID seen with a BSSID not previously known
    connected_ssid = wifi.get("ssid", "")
    connected_bssid = (wifi.get("bssid") or "").upper()
    if connected_ssid and known_bssids:
        twins = [
            bssid for bssid in ssid_bssid_map.get(connected_ssid, [])
            if bssid != connected_bssid and bssid not in known_bssids
        ]
        if twins:
            alerts.append(_alert("critical", "Evil Twin AP Detected",
                f"⚠ Multiple BSSIDs detected for '{connected_ssid}'. Unknown MAC(s) {', '.join(twins[:3])} are broadcasting the same SSID as your connected network. This is a strong indicator of an Evil Twin attack.",
                "Do not enter credentials. Disconnect from the network immediately. Inspect the physical area for unauthorized Wi-Fi transmitters, check router logs for spoofed MAC signals, and enable 802.11w Protected Management Frames (PMF).",
                {"ssid": connected_ssid, "known_bssid": connected_bssid, "rogue_bssids": twins}))
            penalty += 35

    # Rogue APs: BSSIDs not in baseline (only after learning period)
    if scan_count_for_agent >= SCAN_COUNT_BEFORE_BASELINE and known_bssids:
        new_bssids = current_bssids - known_bssids
        if new_bssids:
            new_ssids = []
            for ap in (wifi_scan or []):
                if (ap.get("bssid") or "").upper() in new_bssids:
                    new_ssids.append(ap.get("ssid", "Unknown"))
            alerts.append(_alert("high", "New / Rogue Access Points Detected",
                f"{len(new_bssids)} previously unseen access point(s) appeared in your airspace: {', '.join(set(new_ssids[:5]))}. Verify these are legitimate networks before connecting.",
                "Perform a physical sweep to locate the rogue device. If it is an unauthorized employee hotspot, disable it. Check for unrecognized BSSIDs near your facility.",
                {"new_bssids": list(new_bssids), "new_ssids": list(set(new_ssids))}))
            penalty += 15

    # ── 4. Subnet Device Analysis ────────────────────────────────────────────
    whitelist: list = _load_json_file("whitelist.json")
    blacklist: list = _load_json_file("blacklist.json")

    new_devices = []
    blacklisted_count = 0
    unknown_count = 0

    for d in devices:
        mac = (d.get("mac") or "").upper()
        if d.get("is_host"):
            continue
        if mac in blacklist:
            blacklisted_count += 1
        elif mac not in whitelist:
            unknown_count += 1
            if scan_count_for_agent >= SCAN_COUNT_BEFORE_BASELINE and mac not in known_macs:
                new_devices.append(d)

    if blacklisted_count:
        alerts.append(_alert("critical", "Blacklisted Device Active",
            f"CRITICAL: {blacklisted_count} blacklisted device(s) are currently active on your subnet! These are known hostile nodes. Eject them from your router immediately.",
            "Locate the device IP/MAC in your router's client list and block it. Consider changing the Wi-Fi password if the intruder obtained your pre-shared key.",
            {"blacklisted_count": blacklisted_count}))
        penalty += 35 * blacklisted_count

    if unknown_count:
        alerts.append(_alert("high", "Unauthorized Device(s) Detected",
            f"{unknown_count} unrecognized device(s) found on your subnet. Review the Subnet Devices tab and approve or block them.",
            "Review the device IP and MAC address in your Subnet Devices panel. If this is an expected asset, add it to the Approved Whitelist. If it is a threat, block it at your router portal.",
            {"count": unknown_count}))
        penalty += min(10 * unknown_count, 25)

    if new_devices:
        for nd in new_devices[:3]:
            alerts.append(_alert("medium", "New Subnet Node",
                f"A device not previously seen has joined your network: IP {nd.get('ip')} | MAC {nd.get('mac')} | Vendor {nd.get('vendor','Unknown')}. If this device is unknown to you, consider blocking it.",
                "Verify if a colleague has recently connected a new workstation or phone. If unauthorized, move the node to the blacklist immediately.",
                {"ip": nd.get("ip"), "mac": nd.get("mac"), "vendor": nd.get("vendor")}))

    # ── 5. MAC Spoofing Indicator ─────────────────────────────────────────────
    # Flag if we see an IP paired with a different MAC than the baseline
    if known_macs and scan_count_for_agent >= SCAN_COUNT_BEFORE_BASELINE:
        # Read last device→IP map from DB
        prev_ip_mac = _get_prev_ip_mac(aid)
        for d in devices:
            ip = d.get("ip")
            mac = (d.get("mac") or "").upper()
            if ip and mac and ip in prev_ip_mac and prev_ip_mac[ip] != mac:
                alerts.append(_alert("high", "MAC Spoofing Indicator",
                    f"Device at IP {ip} changed MAC from {prev_ip_mac[ip]} to {mac}. This may indicate MAC spoofing or device replacement. Verify the physical device at this IP address.",
                    "Verify if the physical device has been replaced. If not, this IP may be targeted by an ARP spoofing attack. Enable dynamic ARP inspection (DAI) on your managed switches.",
                    {"ip": ip, "old_mac": prev_ip_mac[ip], "new_mac": mac}))
                penalty += 18

    # ── 6. Managed Asset Verification ──────────────────────────────────────────
    assets_dict = {a["mac"].upper(): a for a in db.get_assets()}

    # Check observed devices against expected managed asset vendor
    for d in devices:
        d_mac = d.get("mac", "").upper()
        if d_mac in assets_dict:
            asset = assets_dict[d_mac]
            exp_vendor = asset.get("expected_vendor")
            obs_vendor = d.get("vendor", "")
            if exp_vendor and exp_vendor.upper() not in obs_vendor.upper() and obs_vendor not in ("Network Node", "Unknown Device"):
                alerts.append(_alert("critical", "Asset Mismatch (Vendor)",
                    f"Managed Asset '{asset.get('name')}' (MAC: {d_mac}) reported vendor '{obs_vendor}', but expected '{exp_vendor}'. This indicates potential MAC address spoofing.",
                    "Audit the physical device immediately. Disconnect the node or disable its port, and update your security whitelist/blacklist configuration.",
                    {"observed_vendor": obs_vendor, "expected_vendor": exp_vendor}))
                penalty += 25

    # Check observed APs against expected managed AP configurations
    for ap in (wifi_scan or []):
        ap_bssid = ap.get("bssid", "").upper()
        if ap_bssid in assets_dict:
            asset = assets_dict[ap_bssid]
            exp_channel = asset.get("expected_channel")
            obs_channel = ap.get("channel")
            if exp_channel and obs_channel and str(exp_channel) != str(obs_channel):
                alerts.append(_alert("high", "Asset Mismatch (Channel)",
                    f"Managed AP '{asset.get('name')}' (BSSID: {ap_bssid}) is operating on Channel {obs_channel}, but expected Channel {exp_channel}.",
                    "Verify if network administration changed the channel. If not, scan the area to check for a rogue access point spoofing this network name on a different frequency.",
                    {"observed_channel": obs_channel, "expected_channel": exp_channel}))
                penalty += 15

            exp_enc = asset.get("expected_encryption")
            obs_enc = ap.get("authentication")
            if exp_enc and obs_enc and exp_enc.upper() not in obs_enc.upper():
                alerts.append(_alert("critical", "Asset Mismatch (Encryption)",
                    f"Managed AP '{asset.get('name')}' (BSSID: {ap_bssid}) is running encryption '{obs_enc}', but expected '{exp_enc}'. Security has been degraded!",
                    "Access the AP management console immediately. Re-enable the expected security protocol (WPA2/WPA3) and investigate potential configuration tampering.",
                    {"observed_encryption": obs_enc, "expected_encryption": exp_enc}))
                penalty += 30

    # ── 7. CIS Compliance Auditing ──────────────────────────────────────────
    wpa3 = 1 if "WPA3" in auth.upper() else 0
    wps = 1 if ("WPA3" in auth.upper() or "WPA2" in auth.upper()) and not ("WEP" in auth.upper() or "OPEN" in auth.upper()) else 0
    pmf = 1 if "WPA3" in auth.upper() else 0

    default_ssids = ["NETGEAR", "LINKSYS", "TP-LINK", "ASUS", "DLINK", "WIFI", "HOME", "DEFAULT"]
    default_ssid_found = any(d_ssid in connected_ssid.upper() for d_ssid in default_ssids)
    default_ssid = 0 if default_ssid_found else 1

    open_network = 0 if ("OPEN" in auth.upper() or "NONE" in auth.upper() or auth == "") else 1

    compliance_score = int((wpa3 + wps + pmf + default_ssid + open_network) * 20)
    db.insert_compliance(aid, wpa3, wps, pmf, default_ssid, open_network, compliance_score)

    if default_ssid_found:
        alerts.append(_alert("medium", "Compliance: Default SSID Used",
            f"Connected to '{connected_ssid}' which contains a default manufacturer pattern. Default names help attackers perform targeted credential harvesting.",
            "Rename your SSID to a custom, non-identifying name (e.g. avoid company names or router model names).",
            {"ssid": connected_ssid}))
        penalty += 8

    # ── 8. Update Baseline ───────────────────────────────────────────────────
    merged_bssids = known_bssids | current_bssids
    merged_macs   = known_macs   | current_macs
    db.update_baseline(aid, merged_bssids, merged_macs)

    # ── 9. Persist alerts to DB ──────────────────────────────────────────────
    for a in alerts:
        db.insert_alert(aid, a["severity"], a["category"], a["message"],
                        a.get("remediation"), a.get("evidence"))

    score = max(0, min(100, 100 - penalty))
    return score, alerts


# ── helpers ──────────────────────────────────────────────────────────────────

def _alert(severity: str, category: str, message: str, remediation: str = None, evidence: dict = None) -> dict:
    return {"severity": severity, "category": category, "message": message, "remediation": remediation or "No remediation required.", "evidence": evidence or {}}


def _conn_security_msg(auth: str, ssid: str) -> str:
    a = (auth or "").upper()
    if "OPEN" in a or "NONE" in a or a == "":
        return (f"Your connected network '{ssid}' is OPEN — no encryption or authentication. "
                f"Anyone within range can intercept your traffic. Enable WPA2/WPA3 immediately.")
    if "WEP" in a:
        return (f"Your network '{ssid}' uses WEP which can be cracked in under 60 seconds with freely "
                f"available tools. Upgrade your router to WPA2-AES or WPA3.")
    if "WPA3" in a:
        return (f"Connected to '{ssid}' using WPA3. Your connection is highly secure and protected against modern brute-force techniques.")
    if "WPA2" in a:
        return (f"Connected to '{ssid}' using WPA2. While secure, upgrading your router configuration to WPA3 is recommended for maximum security against brute-force handshake capture.")
    if "WPA" in a:
        return (f"'{ssid}' uses original WPA (TKIP) which is deprecated. Upgrade to WPA2 or WPA3.")
    return f"Connected using security protocol '{auth}' on '{ssid}'."


def _load_json_file(filename: str) -> list:
    import os, json
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), filename))
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _get_prev_ip_mac(agent_id: str) -> dict:
    """Fetch last scan's IP→MAC mapping from device table."""
    try:
        import database as db2
        conn = db2._get_conn()
        last_scan = conn.execute(
            "SELECT id FROM scans WHERE agent_id=? ORDER BY ts DESC LIMIT 1 OFFSET 1",
            (agent_id,)
        ).fetchone()
        if not last_scan:
            return {}
        rows = conn.execute(
            "SELECT ip, mac FROM devices WHERE scan_id=? AND is_host=0",
            (last_scan["id"],)
        ).fetchall()
        return {r["ip"]: r["mac"] for r in rows}
    except Exception:
        return {}


def get_scan_count(agent_id: str) -> int:
    try:
        conn = db._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM scans WHERE agent_id=?", (agent_id,)
        ).fetchone()
        return row["c"] if row else 0
    except Exception:
        return 0
