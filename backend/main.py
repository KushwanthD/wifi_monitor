import os
import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
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
    import subprocess, re
    try:
        startupinfo = None
        if hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip],
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", startupinfo=startupinfo
        )
        if result.returncode == 0:
            time_match = re.search(r"Average = (\d+)ms|time[=<](\d+)ms", result.stdout, re.IGNORECASE)
            if time_match:
                latency = time_match.group(1) or time_match.group(2)
                return {"status": "online", "latency_ms": int(latency)}
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
            "is_blacklisted": dev_mac in blacklist
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
