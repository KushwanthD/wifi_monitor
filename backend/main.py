import os
import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Any

from services.wifi_scanner import WiFiScanner
from services.network_scanner import NetworkScanner
from services.security_auditor import SecurityAuditor
import database as db
import analysis
from correlation import CorrelationEngine
from pcap_analyzer import PcapAnalyzer

app = FastAPI(title="WiFi Security Monitor API")

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_private_network_headers(request, call_next):
    if request.method == "OPTIONS":
        from fastapi.responses import Response
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = request.headers.get("origin", "*")
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Allow-Private-Network"] = "true"
        return response
    response = await call_next(request)
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response

# ── Paths ─────────────────────────────────────────────────────────────────────
FRONTEND_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
WHITELIST_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "whitelist.json"))
BLACKLIST_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "blacklist.json"))

# ── Whitelist / Blacklist helpers ─────────────────────────────────────────────
def load_whitelist() -> List[str]:
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_whitelist(macs: List[str]):
    try:
        with open(WHITELIST_FILE, "w") as f:
            json.dump(macs, f, indent=4)
    except Exception as e:
        print(f"Error saving whitelist: {e}")

def load_blacklist() -> List[str]:
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_blacklist(macs: List[str]):
    try:
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(macs, f, indent=4)
    except Exception as e:
        print(f"Error saving blacklist: {e}")

# ── Request models ────────────────────────────────────────────────────────────
class WhitelistUpdate(BaseModel):
    macs: List[str]

class BlacklistUpdate(BaseModel):
    macs: List[str]

class AssetModel(BaseModel):
    mac: str
    type: str
    name: str
    expected_vendor: Optional[str] = None
    expected_channel: Optional[str] = None
    expected_encryption: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None

# ── Existing local-scan endpoints (unchanged) ─────────────────────────────────
@app.get("/api/wifi/connection")
def get_wifi_connection():
    return WiFiScanner.get_current_wifi_connection()

@app.get("/api/wifi/scan")
def get_wifi_scan():
    return WiFiScanner.get_wifi_scan_results()

@app.get("/api/network/devices")
def get_devices():
    scan_data = NetworkScanner.get_connected_devices()
    if "error" in scan_data:
        raise HTTPException(status_code=500, detail=scan_data["error"])
    whitelist = load_whitelist()
    blacklist = load_blacklist()
    for dev in scan_data["devices"]:
        dev["is_whitelisted"] = dev["mac"] in whitelist
        dev["is_blacklisted"] = dev["mac"] in blacklist
    return scan_data

@app.get("/api/security/audit")
def run_audit():
    conn = WiFiScanner.get_current_wifi_connection()
    wifi_ip, _ = NetworkScanner.get_wifi_interface_ip()
    audit_data = SecurityAuditor.run_security_audit(conn, wifi_ip)
    devices_data = NetworkScanner.get_connected_devices()
    unwhitelisted_count = 0
    blacklisted_count = 0
    if "devices" in devices_data:
        whitelist = load_whitelist()
        blacklist = load_blacklist()
        for dev in devices_data["devices"]:
            if not dev["is_host"]:
                if dev["mac"] in blacklist:
                    blacklisted_count += 1
                elif dev["mac"] not in whitelist:
                    unwhitelisted_count += 1
    if blacklisted_count > 0:
        audit_data["security_score"] = max(0, audit_data["security_score"] - (30 * blacklisted_count))
        audit_data["alerts"].append({
            "severity": "critical",
            "category": "Blacklisted Node Active",
            "message": f"DETECTED {blacklisted_count} BLACKLISTED INTRUDER(S) ACTIVE ON YOUR WIFI!"
        })
    if unwhitelisted_count > 0:
        audit_data["security_score"] = max(0, audit_data["security_score"] - min(10 * unwhitelisted_count, 30))
        audit_data["alerts"].append({
            "severity": "high",
            "category": "Intruder Alert",
            "message": f"Detected {unwhitelisted_count} unauthorized device(s) on your subnet."
        })
    return audit_data

@app.get("/api/whitelist")
def get_whitelist():
    return load_whitelist()

@app.post("/api/whitelist")
def update_whitelist(payload: WhitelistUpdate):
    save_whitelist([mac.upper() for mac in payload.macs])
    blacklist = load_blacklist()
    new_blacklist = [m for m in blacklist if m.upper() not in [x.upper() for x in payload.macs]]
    save_blacklist(new_blacklist)
    return {"status": "success", "whitelist": load_whitelist()}

@app.get("/api/blacklist")
def get_blacklist():
    return load_blacklist()

@app.post("/api/blacklist")
def update_blacklist(payload: BlacklistUpdate):
    save_blacklist([mac.upper() for mac in payload.macs])
    whitelist = load_whitelist()
    new_whitelist = [m for m in whitelist if m.upper() not in [x.upper() for x in payload.macs]]
    save_whitelist(new_whitelist)
    return {"status": "success", "blacklist": load_blacklist()}

@app.get("/api/network/ping")
def ping_device(ip: str):
    try:
        reports = load_reports()
        for aid, r in reports.items():
            devices = r.get("devices", [])
            for d in devices:
                if d.get("ip") == ip:
                    lat = d.get("latency_ms")
                    if lat is not None and lat != "ERR":
                        try:
                            return {"status": "online", "latency_ms": int(float(lat))}
                        except Exception:
                            pass
    except Exception:
        pass

    import subprocess, re, sys
    try:
        startupinfo = None
        if hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
            
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", startupinfo=startupinfo
        )
        if result.returncode == 0:
            time_match = re.search(r"Average = (\d+)ms|time[=<](\d+)ms|time=(\d+\.?\d*)\s*ms", result.stdout, re.IGNORECASE)
            if time_match:
                latency = time_match.group(1) or time_match.group(2) or time_match.group(3)
                try:
                    return {"status": "online", "latency_ms": int(float(latency))}
                except Exception:
                    return {"status": "online", "latency_ms": 1}
            return {"status": "online", "latency_ms": 1}
        return {"status": "offline", "latency_ms": None}
    except Exception as e:
        return {"status": "error", "message": str(e), "latency_ms": None}

# ── WebSocket Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "refresh":
                await websocket.send_json({"type": "status", "message": "Manual refresh triggered"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Background monitor (local mode) ──────────────────────────────────────────
async def background_network_monitor():
    print("Starting background WiFi & Network Security Monitor task...")
    last_devices = set()
    first_run = True
    while True:
        try:
            conn = WiFiScanner.get_current_wifi_connection()
            devices_data = NetworkScanner.get_connected_devices()
            if "devices" in devices_data:
                current_macs = {d["mac"]: d for d in devices_data["devices"]}
                whitelist = load_whitelist()
                new_macs = set(current_macs.keys()) - last_devices
                if not first_run and new_macs:
                    for mac in new_macs:
                        dev = current_macs[mac]
                        if not dev["is_host"] and mac not in whitelist:
                            await manager.broadcast({
                                "type": "alert",
                                "title": "New Device Detected",
                                "message": f"An unauthorized device has joined: {dev['ip']} ({dev['vendor']})",
                                "device": dev
                            })
                blacklist = load_blacklist()
                await manager.broadcast({
                    "type": "update",
                    "wifi": conn,
                    "devices": [
                        {**d,
                         "is_whitelisted": d["mac"] in whitelist,
                         "is_blacklisted": d["mac"] in blacklist}
                        for d in devices_data["devices"]
                    ]
                })
                last_devices = set(current_macs.keys())
                first_run = False
        except Exception as e:
            print(f"Error in background monitor: {e}")
        await asyncio.sleep(20)

# ── Pydantic models for agent reports ────────────────────────────────────────
class WiFiDetails(BaseModel):
    status: str
    interface_name: str
    description: str = ""
    mac_address: str = ""
    ssid: str = ""
    bssid: str = ""
    band: str = ""
    channel: str = ""
    radio_type: str = ""
    authentication: str = ""
    cipher: str = ""
    receive_rate: str = ""
    transmit_rate: str = ""
    signal: int = 0

class DeviceDetails(BaseModel):
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    is_host: bool = False
    latency_ms: Optional[Any] = "ERR"
    open_ports: Optional[List[Any]] = None

class NearbyNetwork(BaseModel):
    ssid: str = ""
    authentication: str = ""
    encryption: str = ""
    signal: int = 0
    channel: str = ""
    bssid: str = ""
    radio_type: str = ""
    band: str = ""

class AgentReport(BaseModel):
    agent_id: str
    wifi: WiFiDetails
    devices: List[DeviceDetails] = []
    wifi_scan: Optional[List[NearbyNetwork]] = []

# ── Legacy file-based storage (backwards compat) ──────────────────────────────
REPORTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "agent_reports.json"))

def load_reports():
    if os.path.exists(REPORTS_FILE):
        try:
            with open(REPORTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_reports(reports):
    try:
        with open(REPORTS_FILE, "w") as f:
            json.dump(reports, f, indent=4)
    except Exception as e:
        print(f"Error saving reports: {e}")

# ── Agent Report endpoint (main cloud receiver) ───────────────────────────────
@app.post("/api/agent/report")
async def receive_agent_report(payload: AgentReport):
    aid = payload.agent_id.upper()
    wifi = payload.wifi.dict()
    auth_upper = wifi["authentication"].upper()

    # Enrich wifi dict with human-readable security labels
    if "OPEN" in auth_upper or "NONE" in auth_upper or auth_upper == "":
        wifi.update(password_protected=False, security_level="Insecure / Public",
                    encryption_strength="None (Vulnerable)", security_details="Open (Unencrypted)")
    elif "WEP" in auth_upper:
        wifi.update(password_protected=True, security_level="Weak / Legacy",
                    encryption_strength="WEP (Vulnerable)", security_details="Password Protected (WEP)")
    elif "WPA3" in auth_upper:
        wifi.update(password_protected=True, security_level="Strong / Modern",
                    encryption_strength="High (AES-GCMP/CCMP)", security_details="Password Protected (WPA3)")
    elif "WPA2" in auth_upper:
        wifi.update(password_protected=True, security_level="Standard / Secure",
                    encryption_strength="Medium-High (AES-CCMP)", security_details="Password Protected (WPA2)")
    elif "WPA" in auth_upper:
        wifi.update(password_protected=True, security_level="Legacy / Deprecated",
                    encryption_strength="Medium-Low (TKIP)", security_details="Password Protected (WPA)")
    else:
        wifi.update(password_protected=False, security_level="Unknown",
                    encryption_strength="Unknown", security_details="Unknown")

    # Vendor lookup for unknown devices
    whitelist = load_whitelist()
    blacklist = load_blacklist()
    processed_devices = []
    for d in payload.devices:
        dev_mac = d.mac.upper()
        vendor = d.vendor
        if not vendor or vendor in ("Network Node", "Unknown Device"):
            try:
                vendor = NetworkScanner.get_vendor_from_oui(dev_mac)
            except Exception:
                pass
        processed_devices.append({
            "ip": d.ip, "mac": dev_mac, "vendor": vendor or "Unknown",
            "hostname": d.hostname or "",
            "is_host": d.is_host, "latency_ms": d.latency_ms,
            "is_whitelisted": dev_mac in whitelist,
            "is_blacklisted": dev_mac in blacklist,
            "open_ports": d.open_ports
        })

    wifi_scan_list = [n.dict() for n in (payload.wifi_scan or [])]

    # ── Run threat analysis ───────────────────────────────────────────────────
    scan_count = analysis.get_scan_count(aid)
    score, alerts = analysis.run_analysis(
        aid, wifi, processed_devices, wifi_scan_list, scan_count
    )

    # ── Persist to SQLite ─────────────────────────────────────────────────────
    scan_id = db.insert_scan(aid, wifi, score)
    db.insert_aps(scan_id, aid, wifi_scan_list)
    db.insert_devices(scan_id, aid, processed_devices)

    # ── Persist to legacy JSON (backwards compat with /api/agent/report/{id}) ─
    reports = load_reports()
    reports[aid] = {
        "wifi": wifi,
        "devices": processed_devices,
        "wifi_scan": wifi_scan_list,
        "security_score": score,
        "alerts": alerts,
        "score_history": db.get_score_history(aid, 20)
    }
    save_reports(reports)

    # ── Push to all connected WebSocket clients ───────────────────────────────
    await manager.broadcast({
        "type": "agent_update",
        "agent_id": aid,
        "wifi": wifi,
        "devices": processed_devices,
        "wifi_scan": wifi_scan_list,
        "security_score": score,
        "alerts": alerts,
        "score_history": db.get_score_history(aid, 20)
    })

    return {"status": "success", "score": score, "alerts_raised": len(alerts)}

@app.get("/api/agent/report/{agent_id}")
def get_agent_report(agent_id: str):
    aid = agent_id.upper()
    reports = load_reports()
    if aid not in reports:
        raise HTTPException(status_code=404, detail="No scan report found for Agent ID: " + agent_id)
    report = reports[aid]
    # Enrich with persistent alerts from DB
    report["persistent_alerts"] = db.get_alerts(aid, limit=50)
    report["score_history"] = db.get_score_history(aid, 20)
    return report

@app.get("/api/agent/list")
def list_active_agents():
    reports = load_reports()
    return list(reports.keys())

# ── Alert management endpoints ────────────────────────────────────────────────
@app.get("/api/alerts/{agent_id}")
def get_agent_alerts(agent_id: str, limit: int = 50):
    return db.get_alerts(agent_id.upper(), limit)

@app.post("/api/alerts/{alert_id}/dismiss")
def dismiss_alert(alert_id: int):
    db.dismiss_alert(alert_id)
    return {"status": "dismissed"}

@app.get("/api/score-history/{agent_id}")
def get_score_history(agent_id: str):
    return db.get_score_history(agent_id.upper(), 30)

# ── Asset Management Endpoints ──────────────────────────────────────────────
@app.get("/api/assets")
def get_assets():
    return db.get_assets()

@app.post("/api/assets")
def update_asset(payload: AssetModel):
    db.add_asset(
        mac=payload.mac,
        asset_type=payload.type,
        name=payload.name,
        expected_vendor=payload.expected_vendor,
        expected_channel=payload.expected_channel,
        expected_encryption=payload.expected_encryption,
        location=payload.location,
        owner=payload.owner,
        notes=payload.notes
    )
    return {"status": "success", "assets": db.get_assets()}

@app.delete("/api/assets/{mac}")
def delete_asset(mac: str):
    db.delete_asset(mac)
    return {"status": "success", "assets": db.get_assets()}

# ── Compliance Auditing Endpoints ────────────────────────────────────────────
@app.get("/api/compliance/{agent_id}")
def get_compliance(agent_id: str):
    latest = db.get_latest_compliance(agent_id)
    if not latest:
        return {
            "agent_id": agent_id.upper(),
            "ts": "",
            "wpa3_status": 0,
            "wps_status": 0,
            "pmf_status": 0,
            "default_ssid_status": 0,
            "open_network_status": 0,
            "score": 0
        }
    return latest

# ── Threat Correlation Engine ─────────────────────────────────────────────────
@app.get("/api/threat-correlation/{agent_id}")
def get_threat_correlation(agent_id: str):
    aid = agent_id.upper()
    reports = load_reports()
    if aid not in reports:
        return []
    report = reports[aid]
    wifi = report.get("wifi", {})
    devices = report.get("devices", [])
    alerts = report.get("alerts", [])
    return CorrelationEngine.correlate(wifi, devices, alerts)

# ── Wireshark PCAP Traffic Forensics ──────────────────────────────────────────
@app.post("/api/forensics/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    import io
    content = await file.read()
    stream = io.BytesIO(content)
    result = PcapAnalyzer.analyze(stream)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

# ── Airodump-ng CSV Log Ingestion ─────────────────────────────────────────────
@app.post("/api/airspace/import-csv")
async def import_airspace_csv(file: UploadFile = File(...)):
    import io, csv
    content = await file.read()
    try:
        csv_text = content.decode("utf-8", errors="ignore")
        parts = csv_text.split('\n\n')
        aps = []
        if parts:
            ap_data = parts[0]
            reader = csv.reader(io.StringIO(ap_data.strip()))
            headers = []
            for row in reader:
                if not row or len(row) == 0:
                    continue
                if "BSSID" in row[0]:
                    headers = [h.strip() for h in row]
                    continue
                if headers and len(row) >= len(headers):
                    ap_dict = {headers[i]: row[i].strip() for i in range(len(headers))}
                    try:
                        chan = ap_dict.get("channel", "1").strip()
                        chan_num = int(chan) if chan.isdigit() else 1
                    except Exception:
                        chan_num = 1
                    aps.append({
                        "ssid": ap_dict.get("ESSID", "Unknown").strip(),
                        "bssid": ap_dict.get("BSSID").strip(),
                        "channel": str(chan_num),
                        "signal": int(ap_dict.get("Power", "-90").strip() or "-90"),
                        "authentication": ap_dict.get("Privacy", "WPA2").strip(),
                        "encryption": ap_dict.get("Cipher", "CCMP").strip(),
                        "band": "2.4 GHz" if chan_num <= 14 else "5 GHz"
                    })
        return {"status": "success", "aps": aps}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")

# ── Executive Report Exporter ────────────────────────────────────────────────
@app.get("/api/reports/export/{agent_id}")
def export_report(agent_id: str, format: str = "html"):
    aid = agent_id.upper()
    reports = load_reports()
    if aid not in reports:
        raise HTTPException(status_code=404, detail="No scan report found for Agent ID: " + agent_id)
    
    report = reports[aid]
    wifi = report.get("wifi", {})
    devices = report.get("devices", [])
    scan = report.get("wifi_scan", [])
    score = report.get("security_score", 100)
    alerts = report.get("alerts", [])
    compliance = db.get_latest_compliance(aid) or {"score": 0, "wpa3_status":0, "wps_status":0, "pmf_status":0, "default_ssid_status":0, "open_network_status":0}
    
    if format == "csv":
        import csv
        import io
        from fastapi.responses import StreamingResponse
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["REPORT SUMMARY", f"Agent: {aid}", f"Security Score: {score}%"])
        writer.writerow([])
        writer.writerow(["ACTIVE ALERTS"])
        writer.writerow(["Severity", "Category", "Message", "Remediation"])
        for a in alerts:
            writer.writerow([a.get("severity"), a.get("category"), a.get("message"), a.get("remediation", "No remediation recommended.")])
            
        writer.writerow([])
        writer.writerow(["CONNECTED SUBNET DEVICES"])
        writer.writerow(["Status", "IP Address", "MAC Address", "Hostname", "Vendor", "Latency"])
        for d in devices:
            status = "Host" if d.get("is_host") else "Blacklisted" if d.get("is_blacklisted") else "Whitelisted" if d.get("is_whitelisted") else "Unknown"
            writer.writerow([status, d.get("ip"), d.get("mac"), d.get("hostname"), d.get("vendor"), d.get("latency_ms")])
            
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.read().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=WiFi_Sentinel_Report_{aid}.csv"}
        )
        
    else:
        from fastapi.responses import HTMLResponse
        
        alerts_html = "".join([
            f"""
            <div class="alert-box {a.get('severity', 'info')}">
                <h3>{a.get('category')} <span class="badge {a.get('severity')}">{a.get('severity', '').upper()}</span></h3>
                <p><strong>Finding:</strong> {a.get('message')}</p>
                <p class="remediation"><strong>Remediation:</strong> {a.get('remediation')}</p>
            </div>
            """ for a in alerts
        ]) or "<p>No active threats found. Compliance checklist passed.</p>"
        
        devices_rows = "".join([
            f"""
            <tr>
                <td>{"Host" if d.get('is_host') else "Unknown"}</td>
                <td>{d.get('ip')}</td>
                <td>{d.get('mac')}</td>
                <td>{d.get('hostname') or '--'}</td>
                <td>{d.get('vendor')}</td>
            </tr>
            """ for d in devices
        ])
        
        compliance_score = compliance.get("score", 0)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Executive Security Report – {aid}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; background: #fff; margin: 40px; line-height: 1.5; }}
                .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }}
                .title {{ font-size: 24px; font-weight: 700; color: #0f172a; }}
                .meta {{ font-size: 14px; color: #64748b; text-align: right; }}
                .kpi-row {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
                .kpi-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; text-align: center; }}
                .kpi-val {{ font-size: 32px; font-weight: 800; color: #0f172a; margin-top: 5px; }}
                .section {{ margin-bottom: 40px; }}
                .section-title {{ font-size: 18px; font-weight: 700; color: #1e293b; border-left: 4px solid #3b82f6; padding-left: 10px; margin-bottom: 20px; }}
                .alert-box {{ border: 1px solid #e2e8f0; border-left: 5px solid #cbd5e1; border-radius: 6px; padding: 15px; margin-bottom: 15px; }}
                .alert-box.critical {{ border-left-color: #ef4444; background: #fef2f2; }}
                .alert-box.high {{ border-left-color: #f97316; background: #fff7ed; }}
                .alert-box.medium {{ border-left-color: #eab308; background: #fefce8; }}
                .alert-box.low {{ border-left-color: #22c55e; background: #f0fdf4; }}
                .badge {{ font-size: 10px; padding: 3px 8px; border-radius: 4px; font-weight: 700; color: #fff; text-transform: uppercase; float: right; }}
                .badge.critical {{ background: #ef4444; }}
                .badge.high {{ background: #f97316; }}
                .badge.medium {{ background: #eab308; color: #000; }}
                .badge.low {{ background: #22c55e; }}
                .remediation {{ margin-top: 10px; font-size: 13px; color: #0369a1; background: #f0f9ff; padding: 10px; border-radius: 4px; border: 1px dashed #bae6fd; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
                th, td {{ border-bottom: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; }}
                th {{ background: #f8fafc; font-weight: 700; }}
                @media print {{
                    body {{ margin: 0; }}
                    button {{ display: none; }}
                    .no-print {{ display: none; }}
                }}
            </style>
        </head>
        <body>
            <div class="no-print" style="margin-bottom:20px; text-align:right;">
                <button onclick="window.print()" style="padding:10px 20px; background:#3b82f6; color:#fff; border:none; border-radius:6px; cursor:pointer; font-weight:700;">Print Report / Save as PDF</button>
            </div>
            
            <div class="header">
                <div>
                    <div class="title">WiFi Sentinel Security Audit</div>
                    <div style="font-size:14px; color:#64748b; margin-top:5px;">Wireless Operations Platform – Executive Assessment</div>
                </div>
                <div class="meta">
                    <strong>Report ID:</strong> {aid}<br>
                    <strong>Generated:</strong> {compliance.get('ts') or 'N/A'}<br>
                    <strong>Connected SSID:</strong> {wifi.get('ssid', 'Unknown')}
                </div>
            </div>
            
            <div class="kpi-row">
                <div class="kpi-card">
                    <div style="color:#64748b; font-size:14px;">Overall Security Score</div>
                    <div class="kpi-val" style="color:{"#22c55e" if score >= 80 else "#eab308" if score >= 60 else "#ef4444"}">{score}%</div>
                </div>
                <div class="kpi-card">
                    <div style="color:#64748b; font-size:14px;">CIS Compliance Score</div>
                    <div class="kpi-val" style="color:{"#22c55e" if compliance_score >= 80 else "#eab308" if compliance_score >= 60 else "#ef4444"}">{compliance_score}%</div>
                </div>
                <div class="kpi-card">
                    <div style="color:#64748b; font-size:14px;">Total Connected Devices</div>
                    <div class="kpi-val">{len(devices)}</div>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">Active Security Threats & Recommendations</div>
                {alerts_html}
            </div>
            
            <div class="section">
                <div class="section-title">Compliance Metrics Checklist</div>
                <table>
                    <thead>
                        <tr>
                            <th>Security Rule Check</th>
                            <th>Status</th>
                            <th>Target Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>WPA3 Personal Preferred</td>
                            <td><strong>{"PASS" if compliance.get("wpa3_status") else "FAIL"}</strong></td>
                            <td>Use WPA3 to secure against brute-force handshake decryptions.</td>
                        </tr>
                        <tr>
                            <td>WPS Secure (Disabled/Inactive)</td>
                            <td><strong>{"PASS" if compliance.get("wps_status") else "FAIL"}</strong></td>
                            <td>Ensure Wi-Fi Protected Setup is turned off to prevent PIN brute-forcing.</td>
                        </tr>
                        <tr>
                            <td>Management Frame Protection (PMF)</td>
                            <td><strong>{"PASS" if compliance.get("pmf_status") else "FAIL"}</strong></td>
                            <td>Require PMF to prevent wireless deauthentication attacks.</td>
                        </tr>
                        <tr>
                            <td>Non-Default SSID Pattern</td>
                            <td><strong>{"PASS" if compliance.get("default_ssid_status") else "FAIL"}</strong></td>
                            <td>Change SSID name to custom label to obfuscate router model.</td>
                        </tr>
                        <tr>
                            <td>Open/WEP Airspace Mitigation</td>
                            <td><strong>{"PASS" if compliance.get("open_network_status") else "FAIL"}</strong></td>
                            <td>Ensure you are not connecting to unencrypted/WEP local networks.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <div class="section-title">Subnet Node Inventory</div>
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Hostname</th>
                            <th>Vendor</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices_rows}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    db.init_db()
    print("SQLite database initialized.")
    asyncio.create_task(background_network_monitor())

# ── Static frontend ───────────────────────────────────────────────────────────
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def read_root():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend index.html not found"}
else:
    @app.get("/")
    def read_root():
        return {"message": f"Frontend directory not found at {FRONTEND_DIR}"}
