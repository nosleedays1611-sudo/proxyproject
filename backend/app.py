import ipaddress
import json
import os
import sqlite3
import time
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(os.getenv("REMOTE_BASE_DIR", "/opt/remote"))
DB_PATH = BASE_DIR / "remote.db"
IPS_FILE = BASE_DIR / "mrwanx_system" / "data" / "allowed_ips.json"
FREEZE_FILE = BASE_DIR / "mrwanx_system" / "data" / "freeze_state.json"
SITE_DIR = BASE_DIR / "site"

ADMIN_TOKEN = os.getenv("REMOTE_ADMIN_TOKEN", "")
PROXY_TOKEN = os.getenv("REMOTE_PROXY_TOKEN", "")

app = Flask(__name__, static_folder=None)

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def now():
    return int(time.time())

def atomic_json_write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)

def init_db():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    conn.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ipv4 TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        expires_at INTEGER NOT NULL DEFAULT 0,
        active_profile TEXT NOT NULL DEFAULT 'default',
        settings TEXT NOT NULL DEFAULT '{}',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_clients_ipv4 ON clients(ipv4);
    """)
    conn.commit()
    conn.close()
    if not IPS_FILE.exists():
        atomic_json_write(IPS_FILE, {})
    if not FREEZE_FILE.exists():
        atomic_json_write(FREEZE_FILE, {"frozen": False})

def validate_ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value).strip())
        return str(addr) if addr.version == 4 else None
    except ValueError:
        return None

def parse_settings(value):
    return value if isinstance(value, dict) else {}

def require_admin(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not ADMIN_TOKEN:
            return jsonify({"ok": False, "error": "admin_token_not_configured"}), 503
        if request.headers.get("Authorization", "") != f"Bearer {ADMIN_TOKEN}":
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapped

def require_proxy(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not PROXY_TOKEN:
            return jsonify({"ok": False, "error": "proxy_token_not_configured"}), 503
        if request.headers.get("X-Proxy-Token", "") != PROXY_TOKEN:
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapped

def sync_allowed_ips():
    conn = connect()
    rows = conn.execute("SELECT ipv4, enabled, expires_at FROM clients").fetchall()
    conn.close()
    current = now()
    allowed = {}
    for row in rows:
        if bool(row["enabled"]) and int(row["expires_at"]) > current:
            allowed[row["ipv4"]] = {"expires_at": int(row["expires_at"])}
    atomic_json_write(IPS_FILE, allowed)

def get_freeze_state():
    try:
        return bool(json.loads(FREEZE_FILE.read_text(encoding="utf-8")).get("frozen", False))
    except Exception:
        return False

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "remote-api", "time": now()})

@app.get("/api/internal/config")
@require_proxy
def internal_config():
    ipv4 = validate_ipv4(request.args.get("ip", ""))
    if not ipv4:
        return jsonify({"ok": False, "error": "invalid_ipv4"}), 400

    conn = connect()
    row = conn.execute("SELECT * FROM clients WHERE ipv4 = ?", (ipv4,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": True, "authorized": False, "frozen": get_freeze_state()})

    try:
        settings = json.loads(row["settings"])
    except Exception:
        settings = {}

    frozen = get_freeze_state()
    authorized = (not frozen and bool(row["enabled"]) and int(row["expires_at"]) > now())

    return jsonify({
        "ok": True,
        "authorized": authorized,
        "frozen": frozen,
        "ipv4": row["ipv4"],
        "expires_at": int(row["expires_at"]),
        "active_profile": row["active_profile"],
        "settings": settings,
    })

@app.get("/api/admin/clients")
@require_admin
def list_clients():
    conn = connect()
    rows = conn.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()
    conn.close()

    clients = []
    for row in rows:
        try:
            settings = json.loads(row["settings"])
        except Exception:
            settings = {}
        clients.append({
            "id": row["id"],
            "ipv4": row["ipv4"],
            "enabled": bool(row["enabled"]),
            "expires_at": int(row["expires_at"]),
            "active_profile": row["active_profile"],
            "settings": settings,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        })
    return jsonify({"ok": True, "frozen": get_freeze_state(), "clients": clients})

@app.post("/api/admin/clients")
@require_admin
def upsert_client():
    data = request.get_json(silent=True) or {}
    ipv4 = validate_ipv4(data.get("ipv4", ""))
    if not ipv4:
        return jsonify({"ok": False, "error": "invalid_ipv4"}), 400

    try:
        expires_at = int(data.get("expires_at", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "invalid_expires_at"}), 400

    enabled = bool(data.get("enabled", True))
    active_profile = str(data.get("active_profile", "default")).strip() or "default"
    settings = parse_settings(data.get("settings", {}))
    ts = now()

    conn = connect()
    conn.execute("""
        INSERT INTO clients (
            ipv4, enabled, expires_at, active_profile,
            settings, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ipv4) DO UPDATE SET
            enabled = excluded.enabled,
            expires_at = excluded.expires_at,
            active_profile = excluded.active_profile,
            settings = excluded.settings,
            updated_at = excluded.updated_at
    """, (
        ipv4, int(enabled), expires_at, active_profile,
        json.dumps(settings, separators=(",", ":")), ts, ts
    ))
    conn.commit()
    conn.close()
    sync_allowed_ips()
    return jsonify({"ok": True, "ipv4": ipv4})

@app.patch("/api/admin/clients/<ipv4>/settings")
@require_admin
def update_client_settings(ipv4):
    ipv4 = validate_ipv4(ipv4)
    if not ipv4:
        return jsonify({"ok": False, "error": "invalid_ipv4"}), 400

    data = request.get_json(silent=True) or {}
    conn = connect()
    row = conn.execute("SELECT settings, active_profile FROM clients WHERE ipv4 = ?", (ipv4,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "client_not_found"}), 404

    try:
        settings = json.loads(row["settings"])
    except Exception:
        settings = {}

    settings.update(parse_settings(data.get("settings", {})))
    active_profile = str(data.get("active_profile", row["active_profile"])).strip() or row["active_profile"]

    conn.execute("""
        UPDATE clients SET settings = ?, active_profile = ?, updated_at = ?
        WHERE ipv4 = ?
    """, (json.dumps(settings, separators=(",", ":")), active_profile, now(), ipv4))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "ipv4": ipv4,
        "active_profile": active_profile,
        "settings": settings,
    })

@app.patch("/api/admin/clients/<ipv4>")
@require_admin
def update_client(ipv4):
    ipv4 = validate_ipv4(ipv4)
    if not ipv4:
        return jsonify({"ok": False, "error": "invalid_ipv4"}), 400

    data = request.get_json(silent=True) or {}
    conn = connect()
    row = conn.execute("SELECT * FROM clients WHERE ipv4 = ?", (ipv4,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "client_not_found"}), 404

    enabled = int(bool(data.get("enabled", bool(row["enabled"]))))
    try:
        expires_at = int(data.get("expires_at", row["expires_at"]))
    except (TypeError, ValueError):
        conn.close()
        return jsonify({"ok": False, "error": "invalid_expires_at"}), 400

    conn.execute(
        "UPDATE clients SET enabled = ?, expires_at = ?, updated_at = ? WHERE ipv4 = ?",
        (enabled, expires_at, now(), ipv4),
    )
    conn.commit()
    conn.close()
    sync_allowed_ips()
    return jsonify({"ok": True})

@app.delete("/api/admin/clients/<ipv4>")
@require_admin
def delete_client(ipv4):
    ipv4 = validate_ipv4(ipv4)
    if not ipv4:
        return jsonify({"ok": False, "error": "invalid_ipv4"}), 400

    conn = connect()
    conn.execute("DELETE FROM clients WHERE ipv4 = ?", (ipv4,))
    conn.commit()
    conn.close()
    sync_allowed_ips()
    return jsonify({"ok": True})

@app.get("/api/admin/freeze")
@require_admin
def freeze_status():
    return jsonify({"ok": True, "frozen": get_freeze_state()})

@app.post("/api/admin/freeze")
@require_admin
def set_freeze():
    data = request.get_json(silent=True) or {}
    frozen = bool(data.get("frozen", False))
    atomic_json_write(FREEZE_FILE, {"frozen": frozen})
    return jsonify({"ok": True, "frozen": frozen})

@app.get("/")
def site_index():
    return send_from_directory(SITE_DIR, "index.html")

@app.get("/<path:path>")
def site_files(path):
    if path.startswith("api/"):
        return jsonify({"ok": False, "error": "not_found"}), 404
    return send_from_directory(SITE_DIR, path)

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
