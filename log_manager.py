import csv, random, os
from datetime import datetime

LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "attack_log.csv"))

countries = [
    ("India",   20.59,  78.96), ("USA",     37.09, -95.71),
    ("Russia",  61.52, 105.31), ("China",   35.86, 104.19),
    ("Germany", 51.16,  10.45), ("Brazil", -14.24, -51.93),
    ("Nigeria",  9.08,   8.67), ("Japan",   36.20, 138.25),
    ("UK",      55.37,  -3.43), ("Iran",    32.42,  53.68),
]

attack_actions = {
    "DoS":    "Block source IP, apply rate limiting",
    "Normal": "No action needed — benign traffic",
}

def generate_fake_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_geo():
    return random.choice(countries)

def log_attack(code, name, severity, action, block_status="Not Blocked"):
    country, lat, lon = random_geo()
    ip = generate_fake_ip()
    entry = {
        "timestamp":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_code":        code, "attack_name": name,
        "severity":           severity, "ip": ip,
        "country":            country,  "lat": lat, "lon": lon,
        "action_recommended": attack_actions.get(name, action),
        "block_status":       block_status,
    }
    write_header = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=entry.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(entry)
    return entry
