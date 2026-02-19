# 🛡 SentinelWatch — Pro Surveillance Intelligence

A "Trillion Dollar" enterprise-grade surveillance suite for detecting stalkers, trackers, and unknown devices using Kismet packet capture. Optimized for macOS and Raspberry Pi 4.

## 🚀 Pro Features

### 🖥 Screensaver Detection Mode
Autonomous surveillance. This mode monitors macOS system idle time. If the computer is left unattended (default 60s), SentinelWatch automatically activates scanning to monitor your surroundings. It intelligently pauses when the user returns.

### 🗺 Live Intelligence Map
Interactive Leaflet.js dark-mode maps visualize roam paths and GPS checkpoints, providing spatial context to suspicious device encounters.

### 📄 Professional Intelligence Reports (PDF)
Generate high-fidelity "Surveillance Audit Reports" with one click. Automatically aggregates critical alerts, top persons of interest, and system logs into a professional document.

### 🚗 Multi-Location Stalker Detection
GPS-correlated analytics identify devices that reappear across multiple geocodes, ranking suspects by encounter frequency and proximity.

### 🌡 System Health Monitoring
Real-time tracking of CPU Load, RAM, Disk, and RPi Thermal sensors directly on the glass dashboard.

### 🔔 Smart Multi-Channel Alerts
Branded HTML emails via Resend.io and mission-critical SMS alerts via Twilio.

## 🛠 One-Click Installation (macOS)

SentinelWatch features a fully automated setup wizard that handles Homebrew, Python `venv`, and all dependencies:

```bash
git clone https://github.com/tikidragonslayer/Chasing-Your-Tail-NG.git
cd Chasing-Your-Tail-NG
chmod +x start.sh
./start.sh
```

## 🥧 Raspberry Pi 4 Deployment

1. Install Kismet: `sudo apt install kismet`
2. Run `./start.sh` — the system automatically detects Linux and configures `/var/lib/kismet/` paths and thermal sensors.

## 🛡 Security First

- **SecureKismetDB**: All database queries are hardened against SQL injection using parameterized wrappers.
- **Auto-Maintenance**: Log pruning routines prevent disk saturation on RPi SD cards.
- **PIN-Gate**: UI-level locking for secure network deployment.

---
*Built with precision for the modern surveillance landscape.*