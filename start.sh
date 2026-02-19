#!/bin/bash
# SentinelWatch Launcher
# Usage: ./start.sh [home|roam|doorbell|watchlist|web|wizard|stalker]
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════╗"
echo "  ║  🛡  SentinelWatch  v1.0          ║"
echo "  ║  Surveillance Detection System    ║"
echo "  ╚═══════════════════════════════════╝${NC}"
echo ""

# ── Activate venv ──────────────────────────────
if [ -d "venv" ]; then
    source venv/bin/activate
    echo -e "${GREEN}✓ venv activated${NC}"
elif [ -d ".venv" ]; then
    source .venv/bin/activate
    echo -e "${GREEN}✓ .venv activated${NC}"
else
    echo -e "${RED}⚠  No venv found. Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
fi

# ── Ensure data/ dir ───────────────────────────
mkdir -p data logs

# ── Dispatch mode ──────────────────────────────
MODE="${1:-web}"

case "$MODE" in
  home)
    echo -e "${CYAN}▶ Starting HOME mode…${NC}"
    python3 tail_detector.py home
    ;;
  roam)
    echo -e "${CYAN}▶ Starting ROAM mode (continuous)…${NC}"
    python3 tail_detector.py roam
    ;;
  doorbell)
    echo -e "${CYAN}▶ Starting DOORBELL mode (continuous)…${NC}"
    python3 tail_detector.py doorbell
    ;;
  watchlist)
    echo -e "${CYAN}▶ Starting WATCHLIST scan…${NC}"
    python3 tail_detector.py watchlist
    ;;
  stalker)
    echo -e "${CYAN}▶ Running Multi-Location Stalker Scan…${NC}"
    python3 multi_location_tracker.py scan
    ;;
  wizard)
    echo -e "${CYAN}▶ Running Setup Wizard (terminal)…${NC}"
    python3 setup_wizard.py
    ;;
  web|*)
    echo -e "${CYAN}▶ Starting Web Dashboard at http://localhost:8888${NC}"
    echo -e "   ${GREEN}Open your browser to http://localhost:8888${NC}"
    echo -e "   Press Ctrl+C to stop."
    echo ""
    # Open browser after short delay (macOS)
    (sleep 1.5 && open "http://localhost:8888") &
    python3 web_ui.py
    ;;
esac
