# Server: mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 9999 --set block_global=false
# Multi-Port Support: Each port serves different modifications
# Port 9999: Drag Only
# Port 9998: Antenna hand
# Port 9997: Magic Bullet
# Port 9996: Body 90%
# Port 9995: Drag + Antenna
from mitmproxy import http
import datetime
import time
import json
import os
import re

LOG_FILE = "mitm_log.txt"
LOG_ENABLED = False

# mrwanx Proxy License System
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_BASE_DIR, "mrwanx_system", "data")
IPS_FILE = os.path.join(_DATA_DIR, "allowed_ips.json")
FREEZE_STATE_FILE = os.path.join(_DATA_DIR, "freeze_state.json")
GAME_PATCHES_DIR = os.path.join(_BASE_DIR, "game_patches")

# Allow-list to prevent open-proxy abuse on public port.
ALLOWED_HOST_KEYWORDS = [
    "freefiremobile.com",
    "ggpolarbear.com",
    "ggwhitehawk.com",
    "ggblueshark.com",
    "garena.com",
    "redflamenco.com",
]

def write_log(content):
    if not LOG_ENABLED:
        return
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(content + "\n")

def log(title, data=""):
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_log(f"[{time_str}] {title}: {data[:200]}...")

# Multi-Port Configuration (after log function is defined)
try:
    from proxy_config import get_port_config, get_patch_folder, CURRENT_PORT
    PORT_CONFIG = get_port_config()
    PATCH_SUBFOLDER = get_patch_folder()
    log("PROXY_INIT", f"Running on port {CURRENT_PORT} - Mode: {PORT_CONFIG['name']} - Folder: {PATCH_SUBFOLDER or 'root'}")
except ImportError:
    # Fallback to default if proxy_config.py not found
    CURRENT_PORT = 9999
    PORT_CONFIG = {"name": "DragOnly", "folder": "Drag only", "patches": {"fileinfo": "fileinfo", "drag": "drag"}}
    PATCH_SUBFOLDER = "Drag only"
    log("PROXY_INIT", "Running in default mode (port 9999)")

def _is_loopback_or_private(ip: str) -> bool:
    """True if IP is loopback or RFC1918 — typical when mitm is behind nginx on same host."""
    if not ip:
        return True
    ip = str(ip).strip().strip("[]")
    if ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
        return True
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            a, b = int(parts[0]), int(parts[1])
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
        except ValueError:
            pass
    return False

def get_original_client_ip(flow: http.HTTPFlow):
    """
    License IP must match the **TCP client** (the phone's public IP when it connects to this VPS).
    Do NOT prefer X-Forwarded-For first: many apps send wrong/spoofed XFF (or proxy IP), which breaks license checks.
    Use peer (client_conn) first; only if peer is loopback/private (mitm behind nginx) use XFF / x-real-ip.
    """
    peer = flow.client_conn.peername[0]
    if isinstance(peer, str) and peer.startswith("::ffff:"):
        peer = peer[7:]
    peer_s = str(peer)

    if not _is_loopback_or_private(peer_s):
        return peer_s

    req = flow.request.headers
    xff = req.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip().strip("[]")
        if first:
            return first
    for h in ("x-real-ip", "cf-connecting-ip", "true-client-ip"):
        if h in req:
            v = req[h].strip().strip("[]")
            if v:
                return v
    return peer_s

def check_license(client_ip):
    """Check if client IP has active mrwanx Proxy license"""
    try:
        # Owner freeze feature: pause all keys without consuming time.
        # When frozen, deny all license checks.
        if os.path.exists(FREEZE_STATE_FILE):
            try:
                with open(FREEZE_STATE_FILE, "r", encoding="utf-8") as f:
                    st = json.load(f)
                if st.get("frozen", False):
                    log("LICENSE_FROZEN", f"Frozen state active. Deny IP {client_ip}")
                    return False
            except Exception as e:
                # If freeze file is broken, fall back to normal license checks.
                log("FREEZE_STATE_ERR", str(e))

        if os.path.exists(IPS_FILE):
            with open(IPS_FILE, "r") as f:
                ips_db = json.load(f)
            
            if client_ip in ips_db:
                expires_at = ips_db[client_ip].get('expires_at', 0)
                if expires_at > time.time():
                    log("LICENSE_ACTIVE", f"IP {client_ip} - Valid until {datetime.datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d')}")
                    return True
                else:
                    log("LICENSE_EXPIRED", f"IP {client_ip}")
                    return False
            else:
                log("LICENSE_NOT_FOUND", f"IP {client_ip}")
                return False
        
        log("LICENSE_FILE_ERROR", "IPS file not found")
        return False
    
    except Exception as e:
        log("LICENSE_CHECK_ERROR", f"IP {client_ip} - {str(e)}")
        return False

def decode_hex(hex_str):
    """Decode hex string to bytes"""
    try:
        # Clean: remove all non-hex characters
        cleaned = ''.join(c for c in hex_str if c in '0123456789abcdefABCDEF')
        if len(cleaned) < 2 or (len(cleaned) % 2) != 0:
            return b''
        bytes_data = bytes.fromhex(cleaned)
        return bytes_data
    except Exception as e:
        log("HEX_DECODE_ERROR", str(e))
        return b''

def _looks_like_hex_blob(text: str) -> bool:
    """
    Return True only when the file content is "mostly hex" (spaces/newlines allowed).
    Prevents accidentally decoding banner/text files that happen to contain hex characters.
    """
    if text is None:
        return False
    s = str(text).strip()
    if not s:
        return False
    # Allow only whitespace + hex digits.
    if not re.fullmatch(r"[0-9a-fA-F\s]+", s):
        return False
    cleaned = re.sub(r"\s+", "", s)
    return len(cleaned) >= 2 and (len(cleaned) % 2) == 0

def _looks_like_json_payload(payload: bytes) -> bool:
    """Heuristic: check if payload starts like JSON ('{' or '[')."""
    try:
        s = payload.decode("utf-8", errors="ignore").strip()
    except Exception:
        return False
    return s.startswith("{") or s.startswith("[")

def _resolve_patch_path(filename):
    """
    Match game_patches/[subfolder/]filename or filename.txt
    Supports multi-port: each port can have its own subfolder
    """
    # Try subfolder first (for multi-port support)
    if PATCH_SUBFOLDER:
        subfolder_base = os.path.join(GAME_PATCHES_DIR, PATCH_SUBFOLDER, filename)
        if os.path.exists(subfolder_base):
            return subfolder_base
        subfolder_alt = subfolder_base + ".txt"
        if os.path.exists(subfolder_alt):
            return subfolder_alt
    
    # Fallback to root game_patches folder
    base = os.path.join(GAME_PATCHES_DIR, filename)
    if os.path.exists(base):
        return base
    alt = base + ".txt"
    if os.path.exists(alt):
        return alt
    return None

def load_local_patch(filename):
    """Load game patch from local directory (supports multi-port subfolders)"""
    try:
        filepath = _resolve_patch_path(filename)
        if not filepath:
            return None
        used_name = os.path.basename(filepath)
        folder_info = f" [{PATCH_SUBFOLDER}]" if PATCH_SUBFOLDER else ""
        
        # Read as text to detect hex-only files safely.
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content_text = f.read().strip()

        # Try to decode as hex only when the file is actually hex-like.
        if _looks_like_hex_blob(content_text):
            decoded = decode_hex(content_text)
            if decoded:
                log("PATCH_LOADED", f"{used_name}{folder_info} ({len(decoded)} bytes, decoded from hex)")
                return decoded

        # If not hex, treat as plain text/binary
        with open(filepath, "rb") as f:
            content = f.read()
        log("PATCH_LOADED", f"{used_name}{folder_info} ({len(content)} bytes, binary)")
        return content
    except Exception as e:
        log("PATCH_ERROR", f"{filename} - {str(e)}")
        return None

def _load_hide_report_ios_body(flow: http.HTTPFlow | None = None):
    """
    Body response mẫu cho hideReportIos — lấy từ folder account_id đã resolve.
    Nếu chưa resolve được account_id hoặc thiếu file → trả {}.
    """
    body = b"{}"
    user, account_id = _resolve_user_from_flow(flow)
    client_ip = _get_client_ip(flow) if flow is not None else None
    path = get_hide_report_path(user)
    if account_id and os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                body = f.read()
            log("HIDE_REPORT_LOAD", f"[acc={account_id}][{client_ip}] {path} ({len(body)} bytes)")
        except Exception as e:
            log("HIDE_REPORT_FILE_ERR", str(e))
    else:
        reason = "unresolved_account" if not account_id else "missing_file"
        log("HIDE_REPORT_MISSING", f"[{user}][{client_ip}] reason={reason} — using empty")
    return body

def request(flow: http.HTTPFlow):
    log("REQUEST", flow.request.pretty_url)
    host = (flow.request.host or "").lower()
    url_l = flow.request.pretty_url.lower()

    # Allow game endpoints even on IP-based connections
    ff_paths = [
        "/fileinfo",
        "/assetindexer",
        "/majorlogin",
        "/checkhackbehavior",
        "/getmatchmakingblacklist",
        "hidereportios",
    ]
    if any(p in url_l for p in ff_paths):
        return

    if not any(k in host for k in ALLOWED_HOST_KEYWORDS):
        flow.response = http.Response.make(
            403,
            b"Forbidden: this proxy is only for game traffic.",
            {"Content-Type": "text/plain; charset=utf-8", "Connection": "close"},
        )
        return

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    url_l = url.lower()
    client_ip = get_original_client_ip(flow)
    log("RESPONSE", f"{url} (Client: {client_ip})")

    # Quick match using URL paths instead of domains.
    # This avoids touching domain lists that may cause instability/bans.
    ff_paths = [
        "/fileinfo",
        "/assetindexer",
        "/majorlogin",
        "/checkhackbehavior",
        "/getmatchmakingblacklist",
        "hidereportios",
    ]
    if not any(p in url_l for p in ff_paths):
        return

    # ✅ LICENSE CHECK - Block unauthorized users
    if not check_license(client_ip):
        log("ACCESS_DENIED", f"IP {client_ip} - No active license")
        error_msg = {

            "status": "error",

            "code": 500,

            "message":

            "MrwanX Proxy: No Active License"

            "Your IP does not have an active subscription"

            f"Your IP: {client_ip}"

            "Contact Owner : @MrwanX"

        }
        flow.response = http.Response.make(
            500,
            json.dumps(error_msg).encode("utf-8"),
            {"Content-Type": "application/json; charset=utf-8", "Connection": "close"}
        )
        return

    # ✅ User has valid license, serve patches from local files
    file_name = None
    content_type = "application/octet-stream"
    status = 200
    headers = {"Connection": "close"}

    # Identify which patch to serve based on URL and PORT configuration
    # Each port can serve different modifications from different folders
    if "/fileinfo" in url_l:
        file_name = "fileinfo"
        content_type = "application/json; charset=utf-8"

    elif "/assetindexer" in url_l:
        # Dynamic file selection based on port configuration
        # Port 9999 (Drag Only): drag.txt
        # Port 9998 (Antenna): antenna.txt
        # Port 9997 (Magic Bullet): Magic.txt
        # Port 9996 (Body 90%): body.txt
        # Port 9995 (Drag+Antenna): DragXAntenna.txt
        
        # Get the appropriate file name from port config
        patches = PORT_CONFIG.get("patches", {})
        
        # Try to find the asset file (could be drag, antenna, magic, body, etc.)
        for key, filename in patches.items():
            if key != "fileinfo":  # Skip fileinfo, we handle it separately
                file_name = filename
                break
        
        # Fallback to drag if nothing found
        if not file_name:
            file_name = "drag"
        
        content_type = "application/octet-stream"
        log("assetindexer", f"Port {CURRENT_PORT} serving: {file_name} from folder: {PATCH_SUBFOLDER or 'root'}")

    elif "/majorlogin" in url_l:
        # MajorLogin injection disabled intentionally.
        # We pass-through upstream response to avoid any "data type error".
        return

    else:
        return

    # Load and serve local patch
    if file_name:
        local_patch = load_local_patch(file_name)
        if local_patch:
            # MajorLogin must return JSON. If lo.txt is wrong (e.g. a banner),
            # don't break login: pass through upstream response.
            if file_name == "lo" and not _looks_like_json_payload(local_patch):
                log("LO_PATCH_REJECTED", f"{file_name} payload not JSON; passing through upstream (Client: {client_ip})")
                return

            flow.response = http.Response.make(status, local_patch, {"Content-Type": content_type, **headers})
            port_info = f"Port {CURRENT_PORT} [{PORT_CONFIG['name']}]"
            log("PATCH_SUCCESS", f"{port_info}: {url} -> {file_name} ({len(local_patch)} bytes, Client: {client_ip})")
        else:
            folder_path = os.path.join(GAME_PATCHES_DIR, PATCH_SUBFOLDER) if PATCH_SUBFOLDER else GAME_PATCHES_DIR
            log("PATCH_NOT_FOUND", f"{file_name} not found in {folder_path}, using original response")