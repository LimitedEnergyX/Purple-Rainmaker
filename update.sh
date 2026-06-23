#!/bin/bash
# ============================================================
# PURPLE RAINMAKER — Update Script
# Safe to run repeatedly. Never overwrites config.py or reports.
# Usage: git pull && bash update.sh
# ============================================================

GRN='\033[0;32m'
YLW='\033[1;33m'
RED='\033[0;31m'
PRP='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/config.py"

echo ""
echo -e "${PRP}  ╔═══════════════════════════════════════╗${NC}"
echo -e "${PRP}  ║     PURPLE RAINMAKER UPDATE           ║${NC}"
echo -e "${PRP}  ╚═══════════════════════════════════════╝${NC}"
echo ""

if [ ! -f "$CONFIG" ]; then
    echo -e "${YLW}[!] No config.py found — run install.sh first.${NC}"
    exit 1
fi

echo -e "${YLW}[*] Updating Python packages...${NC}"
pip install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages -q --upgrade
echo -e "${GRN}[+] Python packages up to date.${NC}"

chmod +x "$SCRIPT_DIR/autopilot.sh"
echo -e "${GRN}[+] Scripts executable.${NC}"

echo -e "${YLW}[*] Restarting Purple Rainmaker...${NC}"
pkill -f "python3.*app.py" 2>/dev/null
sleep 1
cd "$SCRIPT_DIR"
nohup python3 app.py > /tmp/purplerainmaker.log 2>&1 &
sleep 2

if pgrep -f "python3.*app.py" > /dev/null; then
    echo -e "${GRN}[+] Running at http://localhost:5000${NC}"
    echo -e "${GRN}[+] Log: /tmp/purplerainmaker.log${NC}"
else
    echo -e "${RED}[!] Failed to start:${NC}"
    tail -20 /tmp/purplerainmaker.log
fi
echo ""
echo -e "${PRP}  Update complete.${NC}"
echo ""
