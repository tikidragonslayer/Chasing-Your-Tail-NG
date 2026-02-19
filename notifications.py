"""
notifications.py — SentinelWatch Multi-Channel Alert Dispatcher
Handles Resend.io email + Twilio SMS notifications with level filtering.
"""

import json
import os
from datetime import datetime
from typing import Optional


def _load_config(config_path: str = "config.json") -> dict:
    with open(config_path, "r") as f:
        return json.load(f)


# ──────────────────────────────────────────────
#  Resend.io Email
# ──────────────────────────────────────────────
def send_resend_email(subject: str, body: str, config: dict) -> bool:
    """Send email via Resend.io API. Returns True on success."""
    cfg = config.get("alerts", {}).get("resend", {})
    if not cfg.get("enabled"):
        return False
    api_key = cfg.get("api_key", "")
    if not api_key:
        print("[Resend] No API key configured.")
        return False

    try:
        import resend
        resend.api_key = api_key
        params = {
            "from": cfg.get("from_email", "sentinelwatch@yourdomain.com"),
            "to": [cfg.get("to_email", "")],
            "subject": subject,
            "text": body,
            "html": _format_html_email(subject, body),
        }
        r = resend.Emails.send(params)
        print(f"[Resend] Email sent → {cfg.get('to_email')} (id: {r.get('id','')})")
        return True
    except Exception as e:
        print(f"[Resend] Failed: {e}")
        return False


def _format_html_email(subject: str, body: str) -> str:
    color = "#ff4444" if "CRITICAL" in subject.upper() else "#ff8c00" if "WARNING" in subject.upper() else "#00bfff"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:#0a0a0f;color:#e0e0e0;font-family:system-ui,-apple-system,sans-serif;padding:32px;">
  <div style="max-width:600px;margin:0 auto;background:rgba(255,255,255,0.04);
              border:1px solid rgba(255,255,255,0.1);border-radius:16px;overflow:hidden;">
    <div style="background:{color};padding:20px 28px;">
      <h1 style="margin:0;color:#fff;font-size:20px;font-weight:700;">
        🛡 SentinelWatch Alert
      </h1>
      <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">{ts}</p>
    </div>
    <div style="padding:28px;">
      <h2 style="color:{color};margin-top:0;font-size:16px;">{subject}</h2>
      <p style="line-height:1.7;color:#d0d0d0;white-space:pre-wrap;">{body}</p>
      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.08);margin:24px 0;">
      <p style="font-size:11px;color:#555;margin:0;">
        Sent by SentinelWatch Surveillance Detection System<br>
        <a href="http://localhost:8888" style="color:{color};">Open Dashboard →</a>
      </p>
    </div>
  </div>
</body>
</html>"""


# ──────────────────────────────────────────────
#  Twilio SMS
# ──────────────────────────────────────────────
def send_twilio_sms(message: str, config: dict) -> bool:
    """Send SMS via Twilio. Returns True on success."""
    cfg = config.get("alerts", {}).get("twilio", {})
    if not cfg.get("enabled"):
        return False

    account_sid = cfg.get("account_sid", "")
    auth_token = cfg.get("auth_token", "")
    from_num = cfg.get("from_number", "")
    to_num = cfg.get("to_number", "")

    if not all([account_sid, auth_token, from_num, to_num]):
        print("[Twilio] Incomplete configuration — check config.json")
        return False

    try:
        from twilio.rest import Client
        client = Client(account_sid, auth_token)
        ts = datetime.now().strftime("%H:%M:%S")
        full_msg = f"🛡 SentinelWatch [{ts}]\n{message}\n\nDashboard: http://localhost:8888"
        msg = client.messages.create(body=full_msg, from_=from_num, to=to_num)
        print(f"[Twilio] SMS sent → {to_num} (sid: {msg.sid})")
        return True
    except Exception as e:
        print(f"[Twilio] Failed: {e}")
        return False


# ──────────────────────────────────────────────
#  Main dispatcher
# ──────────────────────────────────────────────
def dispatch_alert(level: str, message: str, config: Optional[dict] = None,
                   config_path: str = "config.json"):
    """
    Fire alert to all enabled channels based on level filtering.
    level: "INFO" | "WARNING" | "CRITICAL"
    """
    if config is None:
        try:
            config = _load_config(config_path)
        except Exception:
            return

    alert_cfg = config.get("alerts", {})

    # ── Resend email ──────────────────────────
    resend_cfg = alert_cfg.get("resend", {})
    if resend_cfg.get("enabled"):
        send_on = [l.upper() for l in resend_cfg.get("send_on", ["CRITICAL"])]
        if level.upper() in send_on:
            subject = f"[{level}] SentinelWatch Alert"
            send_resend_email(subject, message, config)

    # ── Twilio SMS ────────────────────────────
    twilio_cfg = alert_cfg.get("twilio", {})
    if twilio_cfg.get("enabled"):
        send_on = [l.upper() for l in twilio_cfg.get("send_on", ["CRITICAL"])]
        if level.upper() in send_on:
            send_twilio_sms(f"[{level}] {message}", config)


# ──────────────────────────────────────────────
#  Known device arrival notification
# ──────────────────────────────────────────────
def notify_known_arrival(label: str, mac: str, signal: Optional[int],
                          config: Optional[dict] = None, config_path: str = "config.json"):
    """Send arrival notification for a known/labeled device."""
    if config is None:
        try:
            config = _load_config(config_path)
        except Exception:
            return

    if not config.get("alerts", {}).get("known_device_arrival_notify", True):
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sig_str = f" | Signal: {signal} dBm" if signal is not None else ""
    message = (
        f"Known device arrived at {ts}\n\n"
        f"Label : {label}\n"
        f"MAC   : {mac}{sig_str}\n\n"
        f"Device is now within range of your home/office."
    )
    dispatch_alert("INFO", message, config)


# ──────────────────────────────────────────────
#  Unknown SSID linger notification
# ──────────────────────────────────────────────
def notify_unknown_ssid_linger(ssid: str, mac: str, minutes: float, signal: Optional[int],
                                config: Optional[dict] = None, config_path: str = "config.json"):
    """Alert when an unknown SSID has been visible for more than threshold minutes."""
    if config is None:
        try:
            config = _load_config(config_path)
        except Exception:
            return

    if not config.get("alerts", {}).get("unknown_ssid_linger_notify", True):
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sig_str = f" | Signal: {signal} dBm" if signal is not None else ""
    message = (
        f"⚠ Unknown device lingering near home [{ts}]\n\n"
        f"SSID    : {ssid or '(hidden)'}\n"
        f"MAC     : {mac}\n"
        f"Duration: {minutes:.1f} minutes{sig_str}\n\n"
        f"This device is NOT in your whitelist and has been broadcasting\n"
        f"near your location for {minutes:.0f}+ minutes. Possible surveillance."
    )
    dispatch_alert("WARNING", message, config)


# ──────────────────────────────────────────────
#  Watchlist hit — all channels
# ──────────────────────────────────────────────
def notify_watchlist_hit(label: str, mac: str, signal: Optional[int], notes: str,
                          config: Optional[dict] = None, config_path: str = "config.json"):
    """CRITICAL alert when a watchlisted device is detected."""
    if config is None:
        try:
            config = _load_config(config_path)
        except Exception:
            return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sig_str = f"Signal: {signal} dBm" if signal is not None else "Signal: unknown"
    message = (
        f"🚨 WATCHLISTED DEVICE DETECTED [{ts}]\n\n"
        f"Label : {label or '(unlabeled)'}\n"
        f"MAC   : {mac}\n"
        f"{sig_str}\n"
        f"Notes : {notes or 'None'}\n\n"
        f"IMMEDIATE ACTION MAY BE REQUIRED."
    )
    dispatch_alert("CRITICAL", message, config)
