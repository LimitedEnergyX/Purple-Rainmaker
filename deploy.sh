#!/bin/bash
# ============================================================
# PURPLE RAINMAKER — Personal Deploy Script (KalDel)
# Copies updated files from ~/Downloads and restarts.
# New users: use install.sh instead.
# ============================================================

GRN='\033[0;32m'
YLW='\033[1;33m'
RED='\033[0;31m'
PRP='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOADS="$HOME/Downloads"

echo ""
echo -e "${PRP}  ╔═══════════════════════════════════════╗${NC}"
echo -e "${PRP}  ║     PURPLE RAINMAKER DEPLOY           ║${NC}"
echo -e "${PRP}  ║     Shawn C. Tovey, RCDD              ║${NC}"
echo -e "${PRP}  ╚═══════════════════════════════════════╝${NC}"
echo ""

echo -e "${YLW}[*] Stopping Purple Rainmaker...${NC}"
pkill -f "python3.*app.py" 2>/dev/null \
    && echo -e "${GRN}[+] Stopped.${NC}" \
    || echo -e "${GRN}[+] Was not running.${NC}"
sleep 1

deploy_file() {
    local src="$DOWNLOADS/$1"
    local dst="$SCRIPT_DIR/$2"
    if [ -f "$src" ]; then
        cp "$src" "$dst"
        echo -e "${GRN}[+] Deployed: $1${NC}"
    else
        echo -e "${YLW}[~] Skipped (not in Downloads): $1${NC}"
    fi
}

echo -e "${YLW}[*] Deploying files from Downloads...${NC}"
deploy_file "app.py"             "app.py"
deploy_file "index.html"         "templates/index.html"
deploy_file "setup.html"         "templates/setup.html"
deploy_file "autopilot.sh"       "autopilot.sh"
deploy_file "generate_report.py" "generate_report.py"
deploy_file "install.sh"         "install.sh"
deploy_file "update.sh"          "update.sh"
deploy_file "deploy.sh"          "deploy.sh"

chmod +x "$SCRIPT_DIR/autopilot.sh" 2>/dev/null

echo ""
echo -e "${YLW}[*] Verifying...${NC}"
[ -f "$SCRIPT_DIR/app.py" ]                  && echo -e "${GRN}[+] app.py OK${NC}"          || echo -e "${RED}[!] app.py MISSING${NC}"
[ -f "$SCRIPT_DIR/templates/index.html" ]    && echo -e "${GRN}[+] index.html OK${NC}"      || echo -e "${RED}[!] index.html MISSING${NC}"
[ -f "$SCRIPT_DIR/templates/setup.html" ]    && echo -e "${GRN}[+] setup.html OK${NC}"      || echo -e "${RED}[!] setup.html MISSING${NC}"
[ -f "$SCRIPT_DIR/autopilot.sh" ]            && echo -e "${GRN}[+] autopilot.sh OK${NC}"    || echo -e "${RED}[!] autopilot.sh MISSING${NC}"
[ -f "$SCRIPT_DIR/generate_report.py" ]      && echo -e "${GRN}[+] generate_report.py OK${NC}" || echo -e "${RED}[!] generate_report.py MISSING${NC}"

echo ""
echo -e "${YLW}[*] Starting Purple Rainmaker...${NC}"
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
echo -e "${PRP}  Deploy complete.${NC}"
echo ""
