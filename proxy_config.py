import os

CURRENT_PORT = int(os.getenv("PROXY_PORT", "9999"))

PORT_CONFIG = {
    "name": "REMOTE",
    "folder": "",
    "patches": {"fileinfo": "fileinfo"},
}

REMOTE_API = os.getenv("REMOTE_API", "http://127.0.0.1:8080")
REMOTE_TOKEN = os.getenv("REMOTE_PROXY_TOKEN", "")

def get_port_config():
    return PORT_CONFIG

def get_patch_folder():
    return ""
