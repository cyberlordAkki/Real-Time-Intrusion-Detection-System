# ============================================================
# Attack Details — RTIDS (Normal vs DoS)
# Label Encoder sorts alphabetically:
#   0 → DoS | 1 → Normal
# ============================================================

attack_names = {
    0: "DoS",
    1: "Normal",
}

# Codes that represent benign / no-action traffic
NORMAL_CODES = {1}   # Normal = index 1

attack_info = {
    "Normal": {
        "severity": "Low",
        "action":   "No action needed — benign traffic",
    },
    "DoS": {
        "severity": "Critical",
        "action":   "Block source IP, apply rate limiting",
    },
}

SEVERITY_MAP = {name: info["severity"] for name, info in attack_info.items()}
ACTION_MAP   = {name: info["action"]   for name, info in attack_info.items()}
