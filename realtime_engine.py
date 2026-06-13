
import time, random, os, sys
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_manager import log_attack, random_geo, generate_fake_ip
from block_engine import block_ip
from email_alerts import send_alert_email, ALERT_EMAIL
import email_alerts as _ea

DIR          = os.path.dirname(os.path.abspath(__file__))
BEST_PKL     = os.path.join(DIR, "results", "best_model.pkl")
BASELINE_PKL = os.path.join(DIR, "results", "baseline_model.pkl")
KDD_TEST     = os.path.join(DIR, "kdd_test.csv")

# Load email config from json so subprocess gets dashboard-saved credentials
def _load_email_cfg():
    cfg_path = os.path.join(DIR, "email_config.json")
    try:
        import json
        cfg = json.load(open(cfg_path))
        if cfg.get("recipient"):   _ea.ALERT_EMAIL    = cfg["recipient"]
        if cfg.get("sender"):      _ea.SENDER_EMAIL   = cfg["sender"]
        if cfg.get("app_password"):_ea.SENDER_APPPASS = cfg["app_password"]
        print(f"[IDS] Email config loaded → {_ea.ALERT_EMAIL}")
    except Exception as e:
        print(f"[IDS] Email config load failed: {e}")

_load_email_cfg()

# Binary — alphabetical order from LabelEncoder: DoS=0, Normal=1
CLASS_NAMES = ["DoS", "Normal"]

SEVERITY_MAP = {
    "DoS":    "Critical",
    "Normal": "Low",
}

ACTION_MAP = {
    "DoS":    "Block source IP, apply rate limiting",
    "Normal": "No action needed — benign traffic",
}

# Binary attack map — Probe / R2L / U2R rows will be dropped via dropna
ATTACK_MAP = {
    "normal":       "Normal",
    "neptune":      "DoS", "back":         "DoS", "land":        "DoS",
    "pod":          "DoS", "smurf":        "DoS", "teardrop":    "DoS",
    "mailbomb":     "DoS", "apache2":      "DoS", "processtable":"DoS",
    "udpstorm":     "DoS",
}

COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEV_COLOR = {"Critical": RED, "Low": GREEN}
ATK_COLOR = {"DoS": RED, "Normal": GREEN}

SEP2 = "═" * 64


def _get_model_names():
    """Read best/baseline model names from saved results CSV."""
    try:
        import pandas as _pd
        res_path = os.path.join(DIR, "results", "final_results.csv")
        df = _pd.read_csv(res_path, index_col=0)
        names = list(df.sort_values("Accuracy (%)", ascending=False).index)
        best     = names[0] if len(names) > 0 else "Best Model"
        baseline = names[1] if len(names) > 1 else "Baseline Model"
        return best, baseline
    except Exception:
        return "Best Model", "Baseline Model"

_BEST_NAME, _BASE_NAME = _get_model_names()


def banner():
    print(f"\n{SEP2}")
    print(f"{BOLD}{CYAN}  🛡  NSL-KDD Real-Time Intrusion Detection Engine{RESET}")
    print(f"  Best Model    : {_BEST_NAME}")
    print(f"  Baseline Model: {_BASE_NAME}")
    print(f"  Classes       : Normal | DoS  (RTIDS)")
    print(f"  Alert Email   : {_ea.ALERT_EMAIL}")
    print(f"  Mode          : Real test data, row-by-row")
    print(f"  Press Ctrl+C to stop")
    print(f"{SEP2}\n")


def load_models():
    import joblib
    best     = joblib.load(BEST_PKL)
    baseline = joblib.load(BASELINE_PKL)
    print(f"{GREEN}[✓] Models loaded successfully{RESET}")
    return best, baseline


def load_test_data():
    from sklearn.preprocessing import LabelEncoder, MinMaxScaler

    df = pd.read_csv(KDD_TEST, header=None, names=COLS)
    df = df[df["label"] != "label"]
    df.drop(columns=["difficulty"], inplace=True, errors="ignore")
    df["label"] = df["label"].str.strip().str.replace(r"\.$", "", regex=True)
    df["label"] = df["label"].map(ATTACK_MAP)
    df.dropna(subset=["label"], inplace=True)   # drops Probe / R2L / U2R

    X = df.drop("label", axis=1).copy()
    y = df["label"].values

    for col in ["protocol_type", "service", "flag"]:
        enc = LabelEncoder()
        X[col] = enc.fit_transform(X[col].astype(str))

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    scaler   = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"{GREEN}[✓] Test data loaded: {len(X_scaled)} rows | Binary (DoS / Normal){RESET}\n")
    return X_scaled, y


def print_event(ts, attack, sev, ip, country, action, block_status,
                best_pred, base_pred, agree):
    if attack == "Normal":
        print(f"  {GREEN}✔ [{ts}]  NORMAL  |  {ip}  ({country}){RESET}")
        return

    sc        = SEV_COLOR.get(sev, "")
    agree_str = f"{GREEN}✔ AGREE{RESET}" if agree else f"{YELLOW}≠ DIFFER{RESET}"

    print(f"\n  {BOLD}{sc}⚠  ATTACK DETECTED — {attack}{RESET}")
    print(f"  {BOLD}Time      :{RESET} {ts}")
    print(f"  {BOLD}Severity  :{RESET} {sc}{sev}{RESET}  |  {BOLD}Source:{RESET} {ip}  ({country})")
    print(f"  {BOLD}Action    :{RESET} {action}")
    print(f"  {BOLD}Status    :{RESET} {block_status}")
    print(f"  {BLUE}{_BEST_NAME}{RESET} {ATK_COLOR.get(best_pred,'')}{best_pred}{RESET}  "
          f"| {BLUE}{_BASE_NAME}{RESET} {ATK_COLOR.get(base_pred,'')}{base_pred}{RESET}  "
          f"| {agree_str}")

    if sev == "Critical":
        print(f"  {YELLOW}📧 Alert → {_ea.ALERT_EMAIL} | [{sev}] {attack} from {ip}{RESET}")


_last_email_time = {}
EMAIL_COOLDOWN   = 30

def should_send_email(attack):
    now  = time.time()
    last = _last_email_time.get(attack, 0)
    if now - last > EMAIL_COOLDOWN:
        _last_email_time[attack] = now
        return True
    return False


def run():
    banner()

    try:
        best_model, baseline_model = load_models()
    except Exception as e:
        print(f"{RED}[ERROR] Could not load models: {e}{RESET}")
        print("Run model_evaluation.py first.\n")
        run_simulation()
        return

    try:
        X_test, y_true = load_test_data()
    except Exception as e:
        print(f"{RED}[ERROR] Could not load kdd_test.csv: {e}{RESET}")
        print("Place kdd_test.csv in the project folder.\n")
        run_simulation()
        return

    print(f"{CYAN}{'─'*64}{RESET}")
    print(f"  {BOLD}Streaming real NSL-KDD test data (binary)...{RESET}")
    print(f"{CYAN}{'─'*64}{RESET}\n")

    indices = list(range(len(X_test)))

    while True:
        random.shuffle(indices)
        for idx in indices:
            row = X_test[idx].reshape(1, -1)

            try:
                best_raw  = best_model.predict(row)
                base_raw  = baseline_model.predict(row)
                best_code = int(np.ravel(best_raw)[0])
                base_code = int(np.ravel(base_raw)[0])
            except Exception as e:
                print(f"{RED}[predict error] {e}{RESET}")
                continue

            # Clamp to valid binary range
            best_code = min(best_code, len(CLASS_NAMES) - 1)
            base_code = min(base_code, len(CLASS_NAMES) - 1)

            best_label = CLASS_NAMES[best_code]
            base_label = CLASS_NAMES[base_code]

            attack = best_label
            sev    = SEVERITY_MAP.get(attack, "Low")
            agree  = (best_label == base_label)

            # Model prediction use karo as-is — no artificial filtering

            ip               = generate_fake_ip()
            country, lat, lon = random_geo()
            action           = ACTION_MAP.get(attack, "Monitor")

            block_status = "Not Blocked"
            if sev == "Critical":
                block_status = block_ip(ip, sev)

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            log_attack(
                code         = CLASS_NAMES.index(attack),
                name         = attack,
                severity     = sev,
                action       = action,
                block_status = block_status,
            )

            print_event(ts, attack, sev, ip, country, action,
                        block_status, best_label, base_label, agree)

            # Email alerts — only for DoS (Critical)
            if sev == "Critical":
                if should_send_email(attack):
                    send_alert_email(attack, ip, sev, country, action)

            if attack != "Normal":
                time.sleep(random.uniform(0.6, 1.8))
            else:
                time.sleep(random.uniform(0.2, 0.5))

        print(f"\n{CYAN}[IDS] Test data exhausted — restarting stream...{RESET}\n")


def run_simulation():
    """Fallback simulation when no trained model or data is available."""
    CODES = [0, 1]          # DoS=0, Normal=1
    PROBS = [0.65, 0.35]   # DoS-heavy for demo visibility

    print(f"{YELLOW}[IDS] Running in SIMULATION mode (no real model/data){RESET}\n")

    while True:
        code   = random.choices(CODES, weights=PROBS)[0]
        name   = CLASS_NAMES[code]
        sev    = SEVERITY_MAP[name]
        action = ACTION_MAP[name]
        ip     = generate_fake_ip()
        country, lat, lon = random_geo()

        block_status = "Not Blocked"
        if sev == "Critical":
            block_status = block_ip(ip, sev)

        entry = log_attack(code, name, sev, action, block_status)
        ts    = entry["timestamp"]

        print_event(ts, name, sev, ip, country, action,
                    block_status, name, name, True)

        if sev == "Critical":
            if should_send_email(name):
                send_alert_email(name, ip, sev, country, action)

        time.sleep(random.uniform(0.8, 2.0))


if __name__ == "__main__":
    run()
