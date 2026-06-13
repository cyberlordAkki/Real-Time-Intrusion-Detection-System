import time
import json
import os

# ✅ FIXED PATH
BLOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocked_ips.json")

def load_blocks(clean_expired=False):
    try:
        with open(BLOCK_FILE, "r") as f:
            data = json.load(f)
    except:
        return {}

    if clean_expired:
        now = time.time()
        cleaned = {ip: info for ip, info in data.items() if info.get("expires_at", 0) > now}
        if len(cleaned) != len(data):                  # something was removed
            save_blocks(cleaned)
        return cleaned

    return data

def save_blocks(data):
    with open(BLOCK_FILE, "w") as f:
        json.dump(data, f, indent=4)

def block_ip(ip, severity):
    blocks = load_blocks(clean_expired=True)   # auto-clean stale entries

    if severity == "Critical":
        duration = 900
    elif severity == "High":
        duration = 300
    else:
        return "Not Blocked"

    blocks[ip] = {
        "blocked_at": time.time(),
        "expires_at": time.time() + duration,
        "severity": severity
    }

    save_blocks(blocks)
    return f"Blocked ({duration//60} min)"
