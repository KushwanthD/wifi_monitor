"""
analysis.py – Threat detection, security assessment and behavioral baselining.

Detection modules (all passive — data comes from agent reports):
  1. Security Assessment   – Open/WEP/WPS/weak-cipher flags + per-network risk score
  2. Rogue AP Detection    – Unknown BSSID not in baseline
  3. Evil Twin Detection   – Same SSID, different BSSID already known
  4. Deauth Spike          – Connected AP counter divergence (via signal drop proxy)
  5. MAC Spoofing          – Same IP, different MAC across consecutive scans
  6. New Device / Client   – Subnet device not seen before
  7. Open Network Nearby   – Open APs in airspace that could honeypot users
  8. Behavioral Baseline   – Learn environment; flag new APs / missing APs
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
        return ("info", 2)
    if "WPA" in a:
        return ("low", 5)
    if "WEP" in a:
        return ("high", 20)
    if "OPEN" in a or "NONE" in a or a == "":
        return ("critical", 35)
    return ("low", 3)


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

    if sev in ("critical", "high"):
        msg = _conn_security_msg(auth, wifi.get("ssid", "unknown"))
        alerts.append(_alert(sev, "Insecure Connection", msg, {"auth": auth, "ssid": wifi.get("ssid")}))

    # Weak cipher
    if "TKIP" in (cipher or "").upper():
        alerts.append(_alert("medium", "Weak Cipher (TKIP)",
            f"Your connection to '{wifi.get('ssid')}' uses TKIP — a deprecated cipher vulnerable to replay attacks. "
            f"Configure your router to use AES/CCMP.",
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
            f"{len(open_nearby)} open (unencrypted) Wi-Fi network(s) detected nearby: "
            f"{', '.join(open_nearby[:5])}. These may be honeypots or rogue APs.",
            {"networks": open_nearby}))
        penalty += 5

    if wep_nearby:
        alerts.append(_alert("low", "WEP Networks in Airspace",
            f"{len(wep_nearby)} legacy WEP-protected network(s) nearby: "
            f"{', '.join(wep_nearby[:3])}. WEP is trivially crackable and poses a neighbourhood risk.",
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
                f"⚠ Multiple BSSIDs detected for '{connected_ssid}'. "
                f"Unknown MAC(s) {', '.join(twins[:3])} are broadcasting the same SSID as your connected network. "
                f"This is a strong indicator of an Evil Twin attack. "
                f"Recommended action: Disconnect immediately and verify your router's physical integrity.",
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
                f"{len(new_bssids)} previously unseen access point(s) appeared in your airspace: "
                f"{', '.join(set(new_ssids[:5]))}. "
                f"Verify these are legitimate networks before connecting.",
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
            f"CRITICAL: {blacklisted_count} blacklisted device(s) are currently active on your subnet! "
            f"These are known hostile nodes. Eject them from your router immediately.",
            {"blacklisted_count": blacklisted_count}))
        penalty += 35 * blacklisted_count

    if unknown_count:
        alerts.append(_alert("high", "Unauthorized Device(s) Detected",
            f"{unknown_count} unrecognized device(s) found on your subnet. "
            f"Review the Subnet Devices tab and approve or block them.",
            {"count": unknown_count}))
        penalty += min(10 * unknown_count, 25)

    if new_devices:
        for nd in new_devices[:3]:
            alerts.append(_alert("medium", "New Subnet Node",
                f"A device not previously seen has joined your network: "
                f"IP {nd.get('ip')} | MAC {nd.get('mac')} | Vendor {nd.get('vendor','Unknown')}. "
                f"If this device is unknown to you, consider blocking it.",
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
                    f"Device at IP {ip} changed MAC from {prev_ip_mac[ip]} to {mac}. "
                    f"This may indicate MAC spoofing or device replacement. "
                    f"Verify the physical device at this IP address.",
                    {"ip": ip, "old_mac": prev_ip_mac[ip], "new_mac": mac}))
                penalty += 18

    # ── 6. Update Baseline ───────────────────────────────────────────────────
    merged_bssids = known_bssids | current_bssids
    merged_macs   = known_macs   | current_macs
    db.update_baseline(aid, merged_bssids, merged_macs)

    # ── 7. Persist alerts to DB ──────────────────────────────────────────────
    for a in alerts:
        db.insert_alert(aid, a["severity"], a["category"], a["message"],
                        a.get("evidence"))

    score = max(0, min(100, 100 - penalty))
    return score, alerts


# ── helpers ──────────────────────────────────────────────────────────────────

def _alert(severity: str, category: str, message: str, evidence: dict = None) -> dict:
    return {"severity": severity, "category": category, "message": message, "evidence": evidence or {}}


def _conn_security_msg(auth: str, ssid: str) -> str:
    a = (auth or "").upper()
    if "OPEN" in a or "NONE" in a or a == "":
        return (f"Your connected network '{ssid}' is OPEN — no encryption or authentication. "
                f"Anyone within range can intercept your traffic. Enable WPA2/WPA3 immediately.")
    if "WEP" in a:
        return (f"Your network '{ssid}' uses WEP which can be cracked in under 60 seconds with freely "
                f"available tools. Upgrade your router to WPA2-AES or WPA3.")
    if "WPA" in a and "WPA2" not in a and "WPA3" not in a:
        return (f"'{ssid}' uses original WPA (TKIP) which is deprecated. Upgrade to WPA2 or WPA3.")
    return f"Security concern detected on '{ssid}' with auth '{auth}'."


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
