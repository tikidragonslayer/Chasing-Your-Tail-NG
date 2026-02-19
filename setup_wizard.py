"""
setup_wizard.py — SentinelWatch Terminal Setup Wizard (macOS M1)
Run once to configure your system. Run again anytime to reconfigure.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

R = "\033[91m"; G = "\033[92m"; C = "\033[96m"; Y = "\033[93m"
B = "\033[1m"; D = "\033[0m"; GR = "\033[90m"

def h(text): print(f"\n{B}{C}{text}{D}")
def ok(text): print(f"  {G}✓{D} {text}")
def warn(text): print(f"  {Y}⚠{D}  {text}")
def err(text): print(f"  {R}✗{D} {text}")
def ask(prompt, default=""): 
    val = input(f"  {C}→{D} {prompt} [{GR}{default}{D}]: ").strip()
    return val if val else default

def check_command(cmd):
    try:
        subprocess.run([cmd, "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False

def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        err(f"Could not load {CONFIG_PATH}"); sys.exit(1)

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    ok(f"Config saved → {CONFIG_PATH}")

def create_desktop_launcher(cfg):
    """Create a double-clickable .command file on the Desktop."""
    desktop = Path.home() / "Desktop" / "SentinelWatch.command"
    repo = os.path.dirname(os.path.abspath(__file__))
    venv = os.path.join(repo, "venv", "bin", "activate")

    script = f"""#!/bin/bash
# SentinelWatch Desktop Launcher
# Double-click to start the dashboard

cd "{repo}"

# Activate virtualenv
if [ -f "{venv}" ]; then
    source "{venv}"
fi

echo "🛡  Starting SentinelWatch..."
echo "   Dashboard → http://localhost:8888"
echo "   Press Ctrl+C to stop."
echo ""

(sleep 1.5 && open "http://localhost:8888") &
python3 web_ui.py
"""
    with open(desktop, "w") as f:
        f.write(script)
    os.chmod(desktop, 0o755)
    ok(f"Desktop launcher created: ~/Desktop/SentinelWatch.command")
    print(f"  {GR}Double-click it to start SentinelWatch from anywhere.{D}")

def step_system_check():
    h("Step 1 of 6 — System Check (macOS M1)")
    checks = [
        ("python3", "Python 3"),
        ("brew", "Homebrew"),
    ]
    all_ok = True
    for cmd, label in checks:
        if check_command(cmd):
            ok(label)
        else:
            warn(f"{label} not found")
            all_ok = False

    # Check kismet
    kismet_paths = [
        "/opt/homebrew/bin/kismet",
        "/usr/local/bin/kismet",
    ]
    kismet_found = any(os.path.exists(p) for p in kismet_paths)
    if kismet_found:
        ok("Kismet (Homebrew)")
    else:
        warn("Kismet not found. Install: brew install kismet")
        print(f"  {GR}SentinelWatch can still analyze saved .kismet files.{D}")

    # Check pip deps
    missing = []
    for pkg in ["flask", "colorama", "rich"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        warn(f"Missing packages: {', '.join(missing)}")
        install = ask("Auto-install now? (pip install -r requirements.txt)", "yes")
        if install.lower() in ("yes", "y"):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            ok("Packages installed")
    else:
        ok("Python packages OK")
    input(f"\n  {GR}Press Enter to continue…{D}")

def step_kismet(cfg):
    h("Step 2 of 6 — Kismet Configuration")
    print(f"  {GR}Kismet runs at http://localhost:2501 on macOS.{D}")
    
    api = cfg.setdefault("kismet_api", {})
    api["base_url"] = ask("Kismet URL", api.get("base_url", "http://localhost:2501"))
    api["username"] = ask("Kismet username", api.get("username", "kismet"))
    api["password"] = ask("Kismet password (leave blank if none)", api.get("password", ""))

    paths = cfg.setdefault("paths", {})
    default_db = f"/Users/{os.environ.get('USER', 'mistergoodbond')}/*.kismet"
    paths["kismet_logs"] = ask("Kismet .kismet DB glob path", paths.get("kismet_logs", default_db))
    input(f"\n  {GR}Press Enter to continue…{D}")

def step_resend(cfg):
    h("Step 3 of 6 — Resend.io Email Alerts")
    print(f"  {GR}Get a free API key at resend.com — used for email notifications.{D}")
    
    alerts = cfg.setdefault("alerts", {})
    rs = alerts.setdefault("resend", {})

    enable = ask("Enable Resend email alerts? (yes/no)", "yes" if rs.get("enabled") else "no")
    rs["enabled"] = enable.lower() in ("yes", "y")
    
    if rs["enabled"]:
        rs["api_key"] = ask("Resend API Key", rs.get("api_key", ""))
        rs["from_email"] = ask("From email", rs.get("from_email", "sentinelwatch@yourdomain.com"))
        rs["to_email"] = ask("To email (your address)", rs.get("to_email", ""))
        print(f"  Options: CRITICAL / CRITICAL,WARNING / CRITICAL,WARNING,INFO")
        level = ask("Send on levels (comma-separated)", ",".join(rs.get("send_on", ["CRITICAL"])))
        rs["send_on"] = [l.strip().upper() for l in level.split(",")]
        ok(f"Resend enabled → {rs['to_email']}")
    else:
        ok("Resend disabled")
    input(f"\n  {GR}Press Enter to continue…{D}")

def step_twilio(cfg):
    h("Step 4 of 6 — Twilio SMS Alerts")
    print(f"  {GR}Get Twilio credentials at twilio.com — used for SMS/text notifications.{D}")

    alerts = cfg.setdefault("alerts", {})
    tw = alerts.setdefault("twilio", {})

    enable = ask("Enable Twilio SMS alerts? (yes/no)", "yes" if tw.get("enabled") else "no")
    tw["enabled"] = enable.lower() in ("yes", "y")

    if tw["enabled"]:
        tw["account_sid"] = ask("Account SID", tw.get("account_sid", ""))
        tw["auth_token"] = ask("Auth Token", tw.get("auth_token", ""))
        tw["from_number"] = ask("From number (+1xxxxxxxxxx)", tw.get("from_number", ""))
        tw["to_number"] = ask("To number (+1xxxxxxxxxx)", tw.get("to_number", ""))
        tw["send_on"] = ["CRITICAL"]
        ok(f"Twilio enabled → {tw['to_number']}")
    else:
        ok("Twilio disabled")
    input(f"\n  {GR}Press Enter to continue…{D}")

def step_thresholds(cfg):
    h("Step 5 of 6 — Alert Tuning")
    
    alerts = cfg.setdefault("alerts", {})
    timing = cfg.setdefault("timing", {})
    thresh = cfg.setdefault("thresholds", {})

    arr = ask("Notify on known device arrival? (yes/no)", 
              "yes" if alerts.get("known_device_arrival_notify", True) else "no")
    alerts["known_device_arrival_notify"] = arr.lower() in ("yes", "y")

    linger = ask("Alert on unknown SSID linger after (minutes)", 
                 str(timing.get("unknown_ssid_linger_minutes", 5)))
    timing["unknown_ssid_linger_minutes"] = int(linger)

    poi = ask("Person of Interest min encounters", 
              str(thresh.get("person_of_interest_min_encounters", 3)))
    thresh["person_of_interest_min_encounters"] = int(poi)

    stalker = ask("Stalker alert threshold (encounters)", 
                  str(thresh.get("stalker_alert_encounters", 5)))
    thresh["stalker_alert_encounters"] = int(stalker)

    ok("Thresholds saved")
    input(f"\n  {GR}Press Enter to continue…{D}")

def step_finish(cfg):
    h("Step 6 of 6 — Save & Create Desktop Launcher")
    save_config(cfg)

    launcher = ask("Create Desktop launcher? (yes/no)", "yes")
    if launcher.lower() in ("yes", "y"):
        create_desktop_launcher(cfg)

    print(f"""
{B}{G}  ╔═══════════════════════════════════════╗
  ║  ✅  Setup Complete!                   ║
  ╚═══════════════════════════════════════╝{D}

  Start SentinelWatch:
  {C}./start.sh{D}              → Web dashboard (recommended)
  {C}./start.sh home{D}         → Home scan only
  {C}./start.sh roam{D}         → Roam mode (continuous)
  {C}./start.sh doorbell{D}     → Doorbell mode (continuous)
  {C}./start.sh stalker{D}      → Multi-location stalker scan
  {C}~/Desktop/SentinelWatch.command{D}  → One-click launch
""")

def main():
    print(f"""
{B}{C}
  ╔════════════════════════════════════════════╗
  ║  🛡  SentinelWatch Setup Wizard           ║
  ║  macOS M1 Configuration                  ║
  ╚════════════════════════════════════════════╝{D}
""")
    cfg = load_config()
    step_system_check()
    step_kismet(cfg)
    step_resend(cfg)
    step_twilio(cfg)
    step_thresholds(cfg)
    step_finish(cfg)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Y}Setup cancelled. Run again anytime: python3 setup_wizard.py{D}\n")
