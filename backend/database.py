"""
database.py – SQLite persistence for the Wi-Fi Security Monitor.
Tables: scans, aps, devices, alerts, baselines
"""
import os
import sqlite3
import json
import threading
from datetime import datetime, timezone

# Store DB next to this file so Render can mount a persistent /data volume
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "wifimon.db"))
)

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


def init_db():
    """Create all tables on first run."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id     TEXT NOT NULL,
            ts           TEXT NOT NULL,
            wifi_json    TEXT NOT NULL,
            score        INTEGER NOT NULL DEFAULT 100
        );

        CREATE TABLE IF NOT EXISTS aps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id),
            agent_id    TEXT NOT NULL,
            ts          TEXT NOT NULL,
            ssid        TEXT,
            bssid       TEXT,
            channel     TEXT,
            band        TEXT,
            signal      INTEGER,
            auth        TEXT,
            encryption  TEXT,
            radio_type  TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id),
            agent_id    TEXT NOT NULL,
            ts          TEXT NOT NULL,
            ip          TEXT,
            mac         TEXT,
            vendor      TEXT,
            hostname    TEXT,
            is_host     INTEGER,
            latency_ms  TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            ts          TEXT NOT NULL,
            severity    TEXT NOT NULL,
            category    TEXT NOT NULL,
            message     TEXT NOT NULL,
            remediation TEXT,
            evidence    TEXT,
            dismissed   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS assets (
            mac         TEXT PRIMARY KEY,
            type        TEXT NOT NULL,
            name        TEXT NOT NULL,
            expected_vendor     TEXT,
            expected_channel    TEXT,
            expected_encryption TEXT,
            location    TEXT,
            owner       TEXT,
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS compliance (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            ts          TEXT NOT NULL,
            wpa3_status INTEGER DEFAULT 0,
            wps_status  INTEGER DEFAULT 0,
            pmf_status  INTEGER DEFAULT 0,
            default_ssid_status INTEGER DEFAULT 0,
            open_network_status INTEGER DEFAULT 0,
            score       INTEGER DEFAULT 100
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            ts          TEXT NOT NULL,
            known_bssids TEXT NOT NULL,
            known_macs   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scans_agent  ON scans(agent_id, ts);
        CREATE INDEX IF NOT EXISTS idx_aps_agent    ON aps(agent_id, ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id, ts);
    """)
    try:
        conn.execute("ALTER TABLE alerts ADD COLUMN remediation TEXT")
        conn.commit()
    except Exception:
        pass
    conn.commit()


def insert_scan(agent_id: str, wifi: dict, score: int) -> int:
    conn = _get_conn()
    ts = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO scans(agent_id, ts, wifi_json, score) VALUES(?,?,?,?)",
        (agent_id, ts, json.dumps(wifi), score)
    )
    conn.commit()
    return cur.lastrowid


def insert_aps(scan_id: int, agent_id: str, aps: list):
    if not aps:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    conn.executemany(
        """INSERT INTO aps(scan_id,agent_id,ts,ssid,bssid,channel,band,signal,auth,encryption,radio_type)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        [(scan_id, agent_id, ts,
          a.get("ssid"), a.get("bssid"), a.get("channel"), a.get("band",""),
          a.get("signal", 0), a.get("authentication",""), a.get("encryption",""),
          a.get("radio_type","")) for a in aps]
    )
    conn.commit()


def insert_devices(scan_id: int, agent_id: str, devices: list):
    if not devices:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    conn.executemany(
        """INSERT INTO devices(scan_id,agent_id,ts,ip,mac,vendor,hostname,is_host,latency_ms)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        [(scan_id, agent_id, ts,
          d.get("ip"), d.get("mac"), d.get("vendor"), d.get("hostname",""),
          1 if d.get("is_host") else 0, str(d.get("latency_ms",""))) for d in devices]
    )
    conn.commit()


def insert_alert(agent_id: str, severity: str, category: str, message: str, remediation: str = None, evidence: dict = None):
    conn = _get_conn()
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO alerts(agent_id,ts,severity,category,message,remediation,evidence) VALUES(?,?,?,?,?,?,?)",
        (agent_id, ts, severity, category, message, remediation,
         json.dumps(evidence) if evidence else None)
    )
    conn.commit()


def get_alerts(agent_id: str, limit: int = 50) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE agent_id=? AND dismissed=0 ORDER BY ts DESC LIMIT ?",
        (agent_id, limit)
    ).fetchall()
    result = []
    for r in rows:
        item = dict(r)
        if item.get("evidence"):
            try:
                item["evidence"] = json.loads(item["evidence"])
            except Exception:
                pass
        result.append(item)
    return result


def dismiss_alert(alert_id: int):
    conn = _get_conn()
    conn.execute("UPDATE alerts SET dismissed=1 WHERE id=?", (alert_id,))
    conn.commit()


def get_baseline(agent_id: str) -> dict:
    """Return most recent known bssids and macs for agent."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT known_bssids, known_macs FROM baselines WHERE agent_id=? ORDER BY ts DESC LIMIT 1",
        (agent_id,)
    ).fetchone()
    if not row:
        return {"known_bssids": [], "known_macs": []}
    return {
        "known_bssids": json.loads(row["known_bssids"]),
        "known_macs": json.loads(row["known_macs"])
    }


def update_baseline(agent_id: str, bssids: list, macs: list):
    conn = _get_conn()
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO baselines(agent_id,ts,known_bssids,known_macs) VALUES(?,?,?,?)",
        (agent_id, ts, json.dumps(list(bssids)), json.dumps(list(macs)))
    )
    conn.commit()


def get_score_history(agent_id: str, limit: int = 20) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT ts, score FROM scans WHERE agent_id=? ORDER BY ts DESC LIMIT ?",
        (agent_id, limit)
    ).fetchall()
    return [{"ts": r["ts"], "score": r["score"]} for r in reversed(rows)]


def purge_old_data(retention_days: int = 30):
    """Delete records older than retention_days."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    conn = _get_conn()
    conn.execute("DELETE FROM aps     WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM devices WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM scans   WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM alerts  WHERE ts < ? AND dismissed=1", (cutoff,))
    conn.execute("DELETE FROM baselines WHERE ts < ?", (cutoff,))
    conn.commit()


def add_asset(mac: str, asset_type: str, name: str, expected_vendor: str = None, expected_channel: str = None, expected_encryption: str = None, location: str = None, owner: str = None, notes: str = None):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO assets(mac, type, name, expected_vendor, expected_channel, expected_encryption, location, owner, notes)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (mac.upper(), asset_type, name, expected_vendor, expected_channel, expected_encryption, location, owner, notes)
    )
    conn.commit()


def get_assets() -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM assets").fetchall()
    return [dict(r) for r in rows]


def delete_asset(mac: str):
    conn = _get_conn()
    conn.execute("DELETE FROM assets WHERE mac=?", (mac.upper(),))
    conn.commit()


def insert_compliance(agent_id: str, wpa3: int, wps: int, pmf: int, default_ssid: int, open_network: int, score: int):
    conn = _get_conn()
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO compliance(agent_id, ts, wpa3_status, wps_status, pmf_status, default_ssid_status, open_network_status, score)
           VALUES(?,?,?,?,?,?,?,?)""",
        (agent_id.upper(), ts, wpa3, wps, pmf, default_ssid, open_network, score)
    )
    conn.commit()


def get_latest_compliance(agent_id: str) -> dict:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM compliance WHERE agent_id=? ORDER BY ts DESC LIMIT 1",
        (agent_id.upper(),)
    ).fetchone()
    return dict(row) if row else None
