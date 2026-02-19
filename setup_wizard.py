"""
setup_wizard.py — SentinelWatch Setup Wizard (macOS M1)
One-click auto-install for all dependencies. Run once to configure.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
REPO_DIR    = os.path.dirname(os.path.abspath(__file__))
VENV_DIR    = os.path.join(REPO_DIR, "venv")

R="\033[91m"; G="\033[92m"; C="\033[96m"; Y="\033[93m"
B="\033[1m";  D="\033[0m";  GR="\033[90m"; M="\033[95m"

REQUIRED_PACKAGES = [
    "requests>=2.28.0",
    "cryptography>=40.0.0",
    "flask>=3.0.0",
    "flask-cors>=4.0.0",
    "colorama>=0.4.6",
    "rich>=13.0.0",
    "resend>=2.0.0",
    "twilio>=9.0.0",
]

BREW_PACKAGES = ["kismet", "python@3.11"]

def h(text):  print(f"\n{B}{C}{'─'*60}\n  {text}\n{'─'*60}{D}")
def ok(t):    print(f"  {G}✓{D}  {t}")
def warn(t):  print(f"  {Y}⚠{D}  {t}")
def err(t):   print(f"  {R}✗{D}  {t}")
def info(t):  print(f"  {GR}›{D}  {t}")
def ask(prompt, default=""):
    val = input(f"\n  {C}→{D} {prompt} {GR}[{default}]{D}: ").strip()
    return val if val else default

def yn(prompt, default_yes=True):
    hint = "Y/n" if default_yes else "y/N"
    val = input(f"\n  {C}→{D} {prompt} {GR}[{hint}]{D}: ").strip().lower()
    if not val: return default_yes
    return val in ("y", "yes")

def run_cmd(cmd, capture=False, timeout=180):
    if capture:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout, r.stderr
    else:
        r = subprocess.run(cmd, timeout=timeout)
        return r.returncode == 0

def has_command(cmd):
    ok_, *_ = run_cmd(["which", cmd], capture=True)
    return ok_

def spinner(msg, duration=1.5):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    t = time.time()
    i = 0
    while time.time() - t < duration:
        print(f"\r  {C}{frames[i % len(frames)]}{D}  {msg}", end="", flush=True)
        time.sleep(0.1); i += 1
    print(f"\r  {G}✓{D}  {msg:<50}")


# ══════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════
def banner():
    print(f"""
{B}{M}
  ╔══════════════════════════════════════════════════╗
  ║   🛡  SentinelWatch — Setup Wizard v1.0         ║
  ║   macOS M1 • One-Click Dependency Installer     ║
  ╚══════════════════════════════════════════════════╝{D}

  This wizard will:
    {G}1.{D} Check and install Homebrew & system tools
    {G}2.{D} Create a Python virtual environment
    {G}3.{D} Auto-install ALL Python dependencies
    {G}4.{D} Check / install Kismet
    {G}5.{D} Configure Kismet, Resend.io, and Twilio
    {G}6.{D} Create a {B}~/Desktop/SentinelWatch.command{D} one-click launcher
""")
    time.sleep(0.5)


# ══════════════════════════════════════════════
#  STEP 1: System checks + Homebrew
# ══════════════════════════════════════════════
def step_homebrew():
    h("Step 1 of 6 — System Check & Homebrew")

    # Python version check
    v = sys.version_info
    if v.major < 3 or v.minor < 9:
        err(f"Python {v.major}.{v.minor} found — need 3.9+")
        info("Install: brew install python@3.11")
        sys.exit(1)
    ok(f"Python {v.major}.{v.minor}.{v.micro}")

    # Homebrew
    if has_command("brew"):
        ok("Homebrew installed")
    else:
        warn("Homebrew NOT found")
        if yn("Install Homebrew automatically? (recommended)", default_yes=True):
            print(f"\n  {C}Installing Homebrew (this may ask for your password)…{D}\n")
            success = run_cmd([
                "/bin/bash", "-c",
                'NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            ])
            if success:
                ok("Homebrew installed successfully")
            else:
                warn("Homebrew install had issues. Try manually: https://brew.sh")
        else:
            warn("Skipping Homebrew — some features may not work")


# ══════════════════════════════════════════════
#  STEP 2: Python venv + pip auto-install
# ══════════════════════════════════════════════
def step_dependencies():
    h("Step 2 of 6 — Python Dependencies (Auto-Install)")

    venv_python = os.path.join(VENV_DIR, "bin", "python3")
    venv_pip    = os.path.join(VENV_DIR, "bin", "pip")

    # Check if venv exists and is healthy
    venv_ok = os.path.exists(venv_python)
    if venv_ok:
        ok(f"Virtual environment found: {VENV_DIR}")
    else:
        warn("No virtual environment found")
        if yn("Create virtual environment now? (recommended)", default_yes=True):
            print(f"\n  {C}Creating venv…{D}")
            success = run_cmd([sys.executable, "-m", "venv", VENV_DIR])
            if success:
                ok("Virtual environment created → venv/")
                venv_python = os.path.join(VENV_DIR, "bin", "python3")
                venv_pip    = os.path.join(VENV_DIR, "bin", "pip")
                venv_ok = True
            else:
                err("Failed to create venv. Try: python3 -m venv venv")
                venv_ok = False
        else:
            info("Using system Python — packages will be installed globally")
            venv_python = sys.executable
            venv_pip = os.path.join(os.path.dirname(sys.executable), "pip3")

    # Always offer to install all deps
    print(f"\n  {B}Required packages:{D}")
    for pkg in REQUIRED_PACKAGES:
        print(f"    {GR}•{D} {pkg}")

    if yn("\n  Install / upgrade all packages now?", default_yes=True):
        print(f"\n  {C}Installing dependencies — this may take 30–90 seconds…{D}\n")
        req_file = os.path.join(REPO_DIR, "requirements.txt")

        pip_cmd = venv_pip if (venv_ok and os.path.exists(venv_pip)) else "pip3"

        success = run_cmd([
            pip_cmd, "install", "--upgrade", "-r", req_file
        ])
        if success:
            ok("All Python packages installed successfully ✨")
        else:
            warn("Some packages may have failed. Check output above.")
            info(f"Manual install: {pip_cmd} install -r requirements.txt")
    else:
        info("Skipped. Run later: pip install -r requirements.txt")

    return venv_ok


# ══════════════════════════════════════════════
#  STEP 3: Kismet
# ══════════════════════════════════════════════
def step_kismet_install():
    h("Step 3 of 6 — Kismet Packet Capture")

    kismet_paths = ["/opt/homebrew/bin/kismet", "/usr/local/bin/kismet"]
    kismet_found = any(os.path.exists(p) for p in kismet_paths)

    if kismet_found:
        ok("Kismet installed (Homebrew)")
    else:
        warn("Kismet NOT found")
        print(f"\n  {GR}Kismet is required for live packet capture.{D}")
        print(f"  {GR}SentinelWatch can still analyze saved .kismet files without it.{D}\n")

        if has_command("brew"):
            if yn("Install Kismet via Homebrew now? (~5 min)", default_yes=True):
                print(f"\n  {C}Running: brew install kismet…{D}\n")
                run_cmd(["brew", "install", "kismet"])
                if any(os.path.exists(p) for p in kismet_paths):
                    ok("Kismet installed successfully!")
                else:
                    warn("Kismet install may have issues. Check brew output.")
        else:
            info("Install manually: brew install kismet")
            info("Or download from: https://www.kismetwireless.net/")

    # Credentials migration check
    migrate = os.path.join(REPO_DIR, "migrate_credentials.py")
    if os.path.exists(migrate):
        if yn("Run secure credential migration? (REQUIRED for first use)", default_yes=True):
            venv_python = os.path.join(VENV_DIR, "bin", "python3")
            py = venv_python if os.path.exists(venv_python) else sys.executable
            run_cmd([py, migrate])
            ok("Credential migration complete")


# ══════════════════════════════════════════════
#  STEP 4: Kismet config
# ══════════════════════════════════════════════
def step_kismet_config(cfg):
    h("Step 4 of 6 — Kismet Connection")

    api = cfg.setdefault("kismet_api", {})
    api["base_url"] = ask("Kismet URL", api.get("base_url", "http://localhost:2501"))
    api["username"] = ask("Kismet username", api.get("username", "kismet"))
    api["password"] = ask("Kismet password (Enter to skip)", api.get("password", ""))

    paths = cfg.setdefault("paths", {})
    home = os.path.expanduser("~")
    default_db = f"{home}/*.kismet"
    paths["kismet_logs"] = ask("Kismet .kismet DB path (glob)", paths.get("kismet_logs", default_db))
    ok("Kismet config saved")


# ══════════════════════════════════════════════
#  STEP 5: Notifications
# ══════════════════════════════════════════════
def step_notifications(cfg):
    h("Step 5 of 6 — Alert Channels")
    alerts = cfg.setdefault("alerts", {})

    # Resend.io
    print(f"\n  {B}📧 Resend.io Email{D} {GR}(free at resend.com){D}")
    rs = alerts.setdefault("resend", {})
    if yn("  Enable email alerts?", default_yes=False):
        rs["enabled"] = True
        rs["api_key"]    = ask("  Resend API Key", rs.get("api_key",""))
        rs["from_email"] = ask("  From email", rs.get("from_email","sentinelwatch@yourdomain.com"))
        rs["to_email"]   = ask("  To email", rs.get("to_email",""))
        level = ask("  Alert levels (CRITICAL / CRITICAL,WARNING / all)", "CRITICAL")
        rs["send_on"] = [l.strip().upper() for l in level.split(",")]
        ok("Resend.io email enabled")
    else:
        rs["enabled"] = False
        ok("Email alerts disabled")

    # Twilio
    print(f"\n  {B}📱 Twilio SMS{D} {GR}(free trial at twilio.com){D}")
    tw = alerts.setdefault("twilio", {})
    if yn("  Enable SMS alerts?", default_yes=False):
        tw["enabled"]     = True
        tw["account_sid"] = ask("  Account SID", tw.get("account_sid",""))
        tw["auth_token"]  = ask("  Auth Token", tw.get("auth_token",""))
        tw["from_number"] = ask("  From number (+1xxxxxxxxxx)", tw.get("from_number",""))
        tw["to_number"]   = ask("  Your number (+1xxxxxxxxxx)", tw.get("to_number",""))
        tw["send_on"]     = ["CRITICAL"]
        ok("Twilio SMS enabled (CRITICAL alerts only)")
    else:
        tw["enabled"] = False
        ok("SMS alerts disabled")

    # Thresholds
    print(f"\n  {B}🔔 Alert Tuning{D}")
    timing = cfg.setdefault("timing", {})
    thresh = cfg.setdefault("thresholds", {})

    arr = yn("  Notify on known device arrival?", default_yes=True)
    alerts["known_device_arrival_notify"] = arr

    linger = ask("  Alert on unknown SSID linger after (minutes)", str(timing.get("unknown_ssid_linger_minutes", 5)))
    timing["unknown_ssid_linger_minutes"] = int(linger)

    poi = ask("  Person of Interest min encounters", str(thresh.get("person_of_interest_min_encounters", 3)))
    thresh["person_of_interest_min_encounters"] = int(poi)


# ══════════════════════════════════════════════
#  STEP 6: Save + Desktop Launcher
# ══════════════════════════════════════════════
def step_finish(cfg):
    h("Step 6 of 6 — Save & Create Desktop Launcher")

    # Save config
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    ok(f"Config saved → {CONFIG_PATH}")

    # Desktop launcher
    desktop = Path.home() / "Desktop" / "SentinelWatch.command"
    venv_activate = os.path.join(VENV_DIR, "bin", "activate")
    script = f"""#!/bin/bash
# SentinelWatch — One-Click Desktop Launcher
# Created by setup_wizard.py
cd "{REPO_DIR}"

# Activate virtual environment
if [ -f "{venv_activate}" ]; then
    source "{venv_activate}"
    echo "✓ Virtual environment activated"
fi

# Quick dependency check
python3 -c "import flask" 2>/dev/null || {{
    echo "⚠  Dependencies missing — installing now..."
    pip install -r requirements.txt
}}

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  🛡  SentinelWatch is starting...   ║"
echo "║      http://localhost:8888           ║"
echo "╚══════════════════════════════════════╝"
echo ""

(sleep 1.5 && open "http://localhost:8888") &
python3 web_ui.py
"""
    with open(desktop, "w") as f:
        f.write(script)
    desktop.chmod(0o755)
    ok(f"Desktop launcher created: ~/Desktop/SentinelWatch.command")

    print(f"""
{B}{G}
  ╔══════════════════════════════════════════════════╗
  ║  ✅  SentinelWatch Setup Complete!              ║
  ╚══════════════════════════════════════════════════╝{D}

  {B}Start the dashboard:{D}
    {C}Double-click{D} ~/Desktop/SentinelWatch.command
    or: {C}./start.sh{D}

  {B}CLI modes:{D}
    {C}./start.sh home{D}       → Scan home network, build whitelist
    {C}./start.sh roam{D}       → Continuous surveillance detection
    {C}./start.sh doorbell{D}   → Arrival/departure monitoring
    {C}./start.sh watchlist{D}  → Alert on specific devices
    {C}./start.sh stalker{D}    → Multi-location GPS stalker ranking

  {B}Re-run wizard:{D}  {C}python3 setup_wizard.py{D}
""")


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════
def main():
    banner()
    if not yn("Ready to start setup?", default_yes=True):
        print(f"\n  {Y}Run anytime: python3 setup_wizard.py{D}\n")
        return

    # Load config
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
    except Exception:
        err(f"Could not load {CONFIG_PATH}")
        sys.exit(1)

    try:
        step_homebrew()
        step_dependencies()
        step_kismet_install()
        step_kismet_config(cfg)
        step_notifications(cfg)
        step_finish(cfg)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Setup cancelled. Run again anytime: python3 setup_wizard.py{D}\n")


if __name__ == "__main__":
    main()
