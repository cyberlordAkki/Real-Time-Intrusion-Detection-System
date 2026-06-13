# ============================================================
# Real-Time Intrusion Detection & Response System
# NSL-KDD | RTIDS: Normal vs DoS | Flask Dashboard
# ============================================================

from flask import Flask, render_template, redirect, jsonify, request
import pandas as pd
import os, json
from datetime import datetime

from controller import start_realtime, stop_realtime, is_running
from block_engine import block_ip, load_blocks, save_blocks

APP_DIR      = os.path.dirname(os.path.abspath(__file__))
LOG_PATH     = os.path.join(APP_DIR, "attack_log.csv")
RESULTS_PATH = os.path.join(APP_DIR, "results", "final_results.csv")
BLOCK_FILE   = os.path.join(APP_DIR, "blocked_ips.json")

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── Load saved email config if exists ──────────────────────
def _load_email_config():
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_config.json")
    if os.path.exists(cfg_path):
        try:
            import email_alerts, json as _j
            cfg = _j.load(open(cfg_path))
            if cfg.get("recipient"):   email_alerts.ALERT_EMAIL    = cfg["recipient"]
            if cfg.get("sender"):      email_alerts.SENDER_EMAIL   = cfg["sender"]
            if cfg.get("app_password"):email_alerts.SENDER_APPPASS = cfg["app_password"]
            print(f"[IDS] 📧 Email config loaded → {cfg.get('recipient')}")
        except Exception as e:
            print(f"[IDS] Email config load failed: {e}")

_load_email_config()

# ──────────────────────────────────────────────
# JINJA GLOBALS
# ──────────────────────────────────────────────
def attack_badge(name):
    badges = {
        "DoS":    "<span class='badge b-dos'>DoS</span>",
        "Normal": "<span class='badge b-normal'>Normal</span>",
    }
    return badges.get(name, f"<span class='badge b-normal'>{name}</span>")

app.jinja_env.globals["attack_badge"] = attack_badge

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def load_logs(n=20):
    if not os.path.exists(LOG_PATH):
        return []
    df = pd.read_csv(LOG_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values("timestamp", ascending=False).head(n).to_dict("records")


def load_map_data(n=300):
    if not os.path.exists(LOG_PATH):
        return []
    df = pd.read_csv(LOG_PATH)
    df = df.dropna(subset=["lat", "lon"])
    df = df[df["attack_name"] != "Normal"].tail(n)
    return df[["lat","lon","attack_name","severity",
               "ip","country","timestamp","block_status"]].to_dict("records")


def summary_stats():
    empty = {"total":0,"latest_time":"N/A","blocked":0,"not_blocked":0,
             "top_country":"N/A","top_country_count":0,"by_sev":{},"by_attack":{},
             "by_country":{}}
    if not os.path.exists(LOG_PATH):
        return empty
    df = pd.read_csv(LOG_PATH)
    df["timestamp"]   = pd.to_datetime(df["timestamp"], errors="coerce")
    df["severity"]    = df["severity"].astype(str).str.strip()
    df["attack_name"] = df["attack_name"].astype(str).str.strip()

    attacks_only = df[df["attack_name"] != "Normal"]
    normal_rows  = df[df["attack_name"] == "Normal"]
    country_vc   = attacks_only["country"].value_counts() if len(attacks_only) else pd.Series(dtype=int)

    by_sev = df["severity"].value_counts().to_dict()
    actual_low = max(by_sev.get("Low", 0), len(normal_rows))
    by_sev["Low"] = actual_low
    # RTIDS: only Critical and Low
    for _k in ("Critical", "Low"):
        by_sev.setdefault(_k, 0)

    return {
        "total":             len(df),
        "latest_time":       df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                             if not df["timestamp"].isna().all() else "N/A",
        "blocked":           int((df["block_status"] != "Not Blocked").sum()),
        "not_blocked":       int((df["block_status"] == "Not Blocked").sum()),
        "top_country":       country_vc.index[0] if len(country_vc) else "N/A",
        "top_country_count": int(country_vc.iloc[0]) if len(country_vc) else 0,
        "by_sev":            {k: int(v) for k, v in by_sev.items()},
        "by_attack":         {**df["attack_name"].value_counts().to_dict()},
        "by_country":        attacks_only["country"].value_counts().head(8).to_dict(),
    }


def load_model_results():
    if not os.path.exists(RESULTS_PATH):
        return {}
    df = pd.read_csv(RESULTS_PATH, index_col=0).round(2)
    return df.to_dict(orient="index")


def get_blocked_ips():
    """Return currently active (non-expired) blocked IPs."""
    try:
        from block_engine import load_blocks
        return load_blocks(clean_expired=True)
    except Exception as e:
        print(f"[IDS] get_blocked_ips error: {e}")
        return {}


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────
@app.route("/")
def index():
    results = load_model_results()
    names  = list(results.keys())
    best_name     = names[0] if len(names) > 0 else "Best Model"
    baseline_name = names[1] if len(names) > 1 else "Baseline Model"
    return render_template(
        "index.html",
        logs          = load_logs(),
        stats         = summary_stats(),
        running       = is_running(),
        now           = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        model_results = results,
        best_name     = best_name,
        baseline_name = baseline_name,
    )


@app.route("/start")
def start():
    start_realtime()
    results = load_model_results()
    names = list(results.keys())
    bname = names[0] if names else "Best Model"
    bsname = names[1] if len(names) > 1 else "Baseline Model"
    print(f"\n[IDS] ▶  Detection Engine STARTED — using {bname} + {bsname}")
    return redirect("/")


@app.route("/stop")
def stop():
    stop_realtime()
    print("\n[IDS] ⛔  Detection Engine STOPPED")
    return redirect("/")


# ──────────────────────────────────────────────
# API
# ──────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    return jsonify(summary_stats())

@app.route("/api/logs")
def api_logs():
    return jsonify(load_logs(int(request.args.get("n", 20))))

@app.route("/api/map_data")
def api_map_data():
    return jsonify(load_map_data())

@app.route("/api/model_results")
def api_model_results():
    return jsonify(load_model_results())

@app.route("/api/blocked_ips")
def api_blocked_ips():
    return jsonify(get_blocked_ips())

@app.route("/api/running")
def api_running():
    return jsonify({"running": is_running()})

@app.route("/api/block_ip", methods=["POST"])
def api_block_ip():
    data     = request.json or {}
    ip       = data.get("ip", "").strip()
    severity = data.get("severity", "Critical")
    if not ip:
        return jsonify({"status": "error"}), 400
    result = block_ip(ip, severity)
    print(f"[IDS] 🔴 MANUAL BLOCK — {ip} ({severity})")
    return jsonify({"status": "blocked", "ip": ip, "result": result})

@app.route("/api/unblock_ip", methods=["POST"])
def api_unblock_ip():
    data   = request.json or {}
    ip     = data.get("ip", "").strip()
    blocks = get_blocked_ips()
    if ip in blocks:
        del blocks[ip]
        save_blocks(blocks)
        print(f"[IDS] ✅ UNBLOCKED — {ip}")
    return jsonify({"status": "unblocked", "ip": ip})

@app.route("/api/send_test_alert", methods=["POST"])
def api_send_test_alert():
    """Manual test email trigger from dashboard — uses latest real event data"""
    from email_alerts import send_alert_email
    data = request.json or {}
    atk  = data.get("attack", "DoS")
    sev  = data.get("severity", "Critical")

    ip      = "192.168.1.1"
    country = "Unknown"
    action  = "Block source IP, apply rate limiting"
    if os.path.exists(LOG_PATH):
        try:
            df    = pd.read_csv(LOG_PATH)
            match = df[df["attack_name"] == atk]
            row   = match.iloc[-1] if len(match) else df.iloc[-1]
            ip      = str(row.get("ip", ip))
            country = str(row.get("country", country))
            action  = str(row.get("action_recommended", action))
        except Exception:
            pass

    ok = send_alert_email(atk, ip, sev, country, action, force=True)
    return jsonify({"sent": ok, "ip": ip, "country": country})


EMAIL_CONFIG_PATH = os.path.join(APP_DIR, "email_config.json")
_auto_alert_enabled = True

@app.route("/api/set_auto_alert", methods=["POST"])
def api_set_auto_alert():
    global _auto_alert_enabled
    data = request.json or {}
    _auto_alert_enabled = bool(data.get("enabled", True))
    import email_alerts
    email_alerts.AUTO_ALERT_ENABLED = _auto_alert_enabled
    print(f"[IDS] 📧 Auto-alerts {'ENABLED' if _auto_alert_enabled else 'PAUSED'}")
    return jsonify({"enabled": _auto_alert_enabled})

@app.route("/api/get_email_config")
def api_get_email_config():
    try:
        with open(EMAIL_CONFIG_PATH) as f:
            cfg = json.load(f)
        return jsonify({
            "recipient":    cfg.get("recipient", ""),
            "sender":       cfg.get("sender", ""),
            "password_set": bool(cfg.get("app_password", ""))
        })
    except Exception:
        from email_alerts import ALERT_EMAIL, SENDER_EMAIL, SENDER_APPPASS
        return jsonify({
            "recipient":    ALERT_EMAIL,
            "sender":       SENDER_EMAIL,
            "password_set": SENDER_APPPASS not in ("", "YOUR_APP_PASSWORD_HERE")
        })

@app.route("/api/save_email_config", methods=["POST"])
def api_save_email_config():
    data      = request.json or {}
    recipient = data.get("recipient", "").strip()
    sender    = data.get("sender", "").strip()
    password  = data.get("app_password", "").strip()

    if not recipient or not sender:
        return jsonify({"status": "error", "msg": "Email fields required"}), 400

    cfg = {"recipient": recipient, "sender": sender, "app_password": password}
    with open(EMAIL_CONFIG_PATH, "w") as f:
        json.dump(cfg, f)

    import email_alerts
    email_alerts.ALERT_EMAIL  = recipient
    email_alerts.SENDER_EMAIL = sender
    if password:
        email_alerts.SENDER_APPPASS = password

    print(f"[IDS] 📧 Email config updated → {recipient}")
    return jsonify({"status": "saved"})


if __name__ == "__main__":
    _r = load_model_results()
    _n = list(_r.keys())
    _best_n = _n[0] if _n else "Best Model"
    _base_n = _n[1] if len(_n) > 1 else "Baseline Model"
    print("=" * 55)
    print("  RTIDS  →  http://localhost:5000")
    print(f"  Best Model    : {_best_n}")
    print(f"  Baseline Model: {_base_n}")
    print("  Classes       : DoS | Normal  (RTIDS)")
    print("=" * 55)
    app.run(debug=True, port=5000, use_reloader=False)
