# ============================================================
# RTIDS — Email Alert Module
# RTIDS: Normal | DoS
# Sends real email alerts via Gmail SMTP (App Password required)
# ============================================================

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIGURATION — Edit these values
# ──────────────────────────────────────────────
ALERT_EMAIL    = "...."   # Recipient (your email)
SENDER_EMAIL   = "...."   # Sender (same Gmail account)
SENDER_APPPASS = "...."       # Gmail App Password (NOT your login password)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# Global toggle — flipped at runtime via dashboard toggle
AUTO_ALERT_ENABLED = True

# RTIDS: only alert for Critical (DoS). Test alerts bypass this filter.
ALERT_SEVERITIES = {"Critical"}

# ──────────────────────────────────────────────
# EMAIL BUILDER
# ──────────────────────────────────────────────
SEV_EMOJI = {"Critical": "🔴", "Low": "🟢"}
ATK_TIPS  = {
    "DoS":    "Distributed Denial of Service detected. Block IP and apply rate limiting immediately.",
    "Normal": "No anomaly detected. Benign traffic confirmed.",
}


def build_html_email(attack, ip, severity, country, action):
    emoji  = SEV_EMOJI.get(severity, "⚠️")
    tip    = ATK_TIPS.get(attack, action)
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color  = {"Critical": "#ef4444", "Low": "#22c55e"}.get(severity, "#60a5fa")

    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0b0f1a; color: #e2e8f4; margin: 0; padding: 0; }}
    .wrap {{ max-width: 580px; margin: 30px auto; background: #111827; border-radius: 12px; overflow: hidden; border: 1px solid #1e2d45; }}
    .header {{ background: #0b1220; padding: 24px 28px; border-bottom: 2px solid {color}; }}
    .title {{ font-size: 20px; font-weight: 700; color: #fff; letter-spacing: -0.3px; }}
    .subtitle {{ font-size: 12px; color: #5a7192; margin-top: 4px; font-family: monospace; }}
    .body {{ padding: 24px 28px; }}
    .sev-pill {{ display: inline-block; background: {color}22; color: {color}; border: 1px solid {color}55; border-radius: 20px; padding: 3px 14px; font-size: 12px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }}
    .field {{ margin: 14px 0; }}
    .label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: #5a7192; margin-bottom: 3px; }}
    .value {{ font-size: 14px; color: #e2e8f4; font-family: monospace; }}
    .tip {{ background: #1a2235; border-left: 3px solid {color}; border-radius: 0 8px 8px 0; padding: 12px 16px; margin-top: 20px; font-size: 13px; color: #c4cfe4; line-height: 1.6; }}
    .footer {{ background: #0b1220; padding: 14px 28px; text-align: center; font-size: 10px; color: #5a7192; border-top: 1px solid #1e2d45; }}
    .atk-type {{ font-family: monospace; font-size: 22px; font-weight: 700; color: {color}; }}
  </style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="title">{emoji} RTIDS — Security Alert</div>
    <div class="subtitle">NSL-KDD · RTIDS · Real-Time Detection · {ts}</div>
  </div>
  <div class="body">
    <div style="margin-bottom:18px">
      <span class="sev-pill">{severity}</span>
    </div>
    <div class="atk-type">{attack} Attack Detected</div>
    <div class="field">
      <div class="label">Source IP Address</div>
      <div class="value">{ip}</div>
    </div>
    <div class="field">
      <div class="label">Origin Country</div>
      <div class="value">{country}</div>
    </div>
    <div class="field">
      <div class="label">Severity Level</div>
      <div class="value">{severity}</div>
    </div>
    <div class="field">
      <div class="label">Recommended Action</div>
      <div class="value">{action}</div>
    </div>
    <div class="field">
      <div class="label">Detection Time</div>
      <div class="value">{ts}</div>
    </div>
    <div class="tip">
      <strong>⚙️ Analysis:</strong> {tip}
    </div>
  </div>
  <div class="footer">
    RTIDS · NSL-KDD · Auto-generated alert · Do not reply
  </div>
</div>
</body>
</html>
"""


# ──────────────────────────────────────────────
# SEND FUNCTION
# ──────────────────────────────────────────────
def send_alert_email(attack, ip, severity, country="Unknown", action="Monitor", force=False):
    """
    Send a security alert email.
    force=True → bypass severity & auto-alert toggle (used for test alerts from dashboard).
    Returns True if sent successfully, False otherwise.
    """
    if not force and severity not in ALERT_SEVERITIES:
        print(f"[EMAIL] ℹ  Skipping [{severity}] {attack} — not in ALERT_SEVERITIES")
        return False

    if not force and not AUTO_ALERT_ENABLED:
        print(f"[EMAIL] 🔕 Auto-alerts paused — skipping [{severity}] {attack}")
        return False

    if SENDER_APPPASS in ("YOUR_APP_PASSWORD_HERE", "", None):
        print(f"[EMAIL] ⚠  App password not set. Alert would be sent to {ALERT_EMAIL}:")
        print(f"         [{severity}] {attack} attack from {ip} ({country})")
        return False

    try:
        subject   = f"[{severity}] {attack} Attack Detected — {ip}"
        body_html = build_html_email(attack, ip, severity, country, action)
        body_text = f"[{severity}] {attack} attack detected from {ip} ({country}). Action: {action}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = ALERT_EMAIL
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APPPASS)
            server.sendmail(SENDER_EMAIL, ALERT_EMAIL, msg.as_string())

        print(f"[EMAIL] ✅ Alert sent → {ALERT_EMAIL} | [{severity}] {attack} | {ip}")
        return True

    except smtplib.SMTPAuthenticationError:
        print(f"[EMAIL] ❌ Auth failed — check App Password in email_config.json")
        return False
    except smtplib.SMTPException as e:
        print(f"[EMAIL] ❌ SMTP error: {e}")
        return False
    except Exception as e:
        print(f"[EMAIL] ❌ Failed to send alert: {e}")
        return False
