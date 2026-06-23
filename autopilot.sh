#!/bin/bash
# ============================================================
# KalDel Autopilot - Network Security Audit
# Project: PURPLE RAINMAKER
# Author: Shawn C. Tovey, RCDD
# Usage: sudo bash autopilot.sh
# Output: ~/playbook/reports/<date>/
# ============================================================

# ── AUTO-DETECT SUBNET ───────────────────────────────────────
# Detect active non-loopback, non-tailscale interface and subnet
detect_subnet() {
    ip -4 route show | grep -v "tailscale\|lo" | \
    awk '/src/ {
        for(i=1;i<=NF;i++) {
            if ($i == "src") { src=$(i+1) }
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ && $i !~ /^127/) { net=$i }
        }
    }
    /^default/ { next }
    /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/ && !/tailscale/ && !/lo/ {
        if ($1 ~ /\//) { print $1; exit }
    }' | head -1
}

SUBNET=$(detect_subnet)

# Fallback: derive from active IP
if [ -z "$SUBNET" ]; then
    IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
    IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1)
    if [ -n "$IP" ]; then
        SUBNET=$(python3 -c "import ipaddress; n=ipaddress.IPv4Network('$IP',strict=False); print(str(n))" 2>/dev/null)
    fi
fi

# Last resort fallback
if [ -z "$SUBNET" ]; then
    SUBNET="192.168.1.0/24"
    echo "[!] WARNING: Could not auto-detect subnet. Using fallback: $SUBNET"
fi

# ── CONFIG ──────────────────────────────────────────────────
# Reports directory is read from config.sh (written at setup time).
# No user-supplied arguments are accepted — eliminates sudoers wildcard.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPORTS="$SCRIPT_DIR/playbook/reports"
CONFIG_SH="$SCRIPT_DIR/config.sh"
if [ -f "$CONFIG_SH" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_SH"
fi
REPORTS_DIR="${PR_REPORTS_DIR:-$DEFAULT_REPORTS}"

BASELINE="$REPORTS_DIR/baseline_devices.txt"
OUTDIR="$REPORTS_DIR/$(date +%Y%m%d_%H%M)"
SUMMARY="$OUTDIR/summary.txt"
FLAGS="$OUTDIR/flags.txt"
START=$(date +%s)

# ── COLORS ──────────────────────────────────────────────────
RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
NC='\033[0m'

# ── HELPERS ─────────────────────────────────────────────────
section() {
    echo ""
    echo -e "${BLU}════════════════════════════════════════${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}════════════════════════════════════════${NC}"
    echo "" >> "$SUMMARY"
    echo "════════════════════════════════════════" >> "$SUMMARY"
    echo "  $1" >> "$SUMMARY"
    echo "════════════════════════════════════════" >> "$SUMMARY"
}

# Top-level flag only — no sub-lines
flag() {
    echo -e "${RED}[!] $1${NC}"
    echo "[!] $1" >> "$SUMMARY"
    echo "[!] $1" >> "$FLAGS"
}

info() {
    echo -e "${GRN}[+] $1${NC}"
    echo "[+] $1" >> "$SUMMARY"
}

warn() {
    echo -e "${YLW}[*] $1${NC}"
    echo "[*] $1" >> "$SUMMARY"
}

# Detail line — no [!] prefix, not written to flags.txt
detail() {
    echo -e "${YLW}    $1${NC}"
    echo "    $1" >> "$SUMMARY"
}

# ── INIT ────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
touch "$SUMMARY" "$FLAGS"

echo "============================================================" | tee "$SUMMARY"
echo "  PURPLE RAINMAKER - Network Security Audit"               | tee -a "$SUMMARY"
echo "  Started: $(date)"                                          | tee -a "$SUMMARY"
echo "  Scanner: $(hostname)"                                      | tee -a "$SUMMARY"
echo "  Target:  $SUBNET"                                          | tee -a "$SUMMARY"
echo "  Output:  $OUTDIR"                                          | tee -a "$SUMMARY"
echo "============================================================" | tee -a "$SUMMARY"

# ── STEP 1: DEVICE DISCOVERY ────────────────────────────────
section "STEP 1 of 3: Device Discovery"
warn "Running ARP scan on $SUBNET..."

sudo arp-scan --localnet \
    --ouifile=/usr/share/arp-scan/ieee-oui.txt \
    --macfile=/etc/arp-scan/mac-vendor.txt \
    2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    grep -v "(DUP:" | tr '\t' ' ' | tee "$OUTDIR/arp_full.txt"

# Extract clean unique IP list
awk '{print $1}' "$OUTDIR/arp_full.txt" | sort -u | \
    grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" > "$OUTDIR/live_hosts.txt"

LIVE_COUNT=$(wc -l < "$OUTDIR/live_hosts.txt")
info "Live hosts: $LIVE_COUNT"

# Compare to baseline
if [ -f "$BASELINE" ]; then
    NEW=$(comm -13 <(sort "$BASELINE") <(sort "$OUTDIR/live_hosts.txt"))
    GONE=$(comm -23 <(sort "$BASELINE") <(sort "$OUTDIR/live_hosts.txt"))

    if [ -n "$NEW" ]; then
        flag "NEW DEVICES DETECTED:"
        while read -r ip; do
            VENDOR=$(grep "^$ip " "$OUTDIR/arp_full.txt" | awk '{print $3}')
            MAC=$(grep "^$ip " "$OUTDIR/arp_full.txt" | awk '{print $2}')
            detail "$ip  $MAC  $VENDOR"
        done <<< "$NEW"
    else
        info "No new devices vs baseline"
    fi

    if [ -n "$GONE" ]; then
        warn "Devices offline vs baseline:"
        while read -r ip; do warn "  $ip offline"; done <<< "$GONE"
    fi
else
    warn "No baseline found - creating now"
    cp "$OUTDIR/live_hosts.txt" "$BASELINE"
    info "Baseline created: $BASELINE"
fi

# ── STEP 2: PORT SCAN ALL LIVE HOSTS ────────────────────────
section "STEP 2 of 3: Port Scan"
warn "Scanning open ports and services on $LIVE_COUNT hosts..."

sudo nmap -sV --open -T4 -iL "$OUTDIR/live_hosts.txt" \
    -oN "$OUTDIR/port_scan.txt" 2>/dev/null

# Flag unusual ports — one flag per port+host pair
UNUSUAL_PORTS="23 21 69 161 512 513 514 1080 3389 4444 5900 6667"
for port in $UNUSUAL_PORTS; do
    # Find all hosts with this port open
    grep -E "^${port}/tcp[[:space:]]+open" "$OUTDIR/port_scan.txt" | while read -r _; do
        # Walk the file: track current host, emit flag when port found
        awk -v p="^${port}/tcp" '
            /Nmap scan report for/ { host=$0; sub(/Nmap scan report for /,"",host) }
            $0 ~ p { print host }
        ' "$OUTDIR/port_scan.txt"
    done | sort -u | while read -r host; do
        flag "UNUSUAL PORT $port OPEN on $host"
    done
done

OPEN_COUNT=$(grep -c "open" "$OUTDIR/port_scan.txt" 2>/dev/null || echo 0)
info "Port scan complete. Open ports found: $OPEN_COUNT"

# ── STEP 3: VULNERABILITY SCAN ──────────────────────────────
section "STEP 3 of 3: Vulnerability Scan"
warn "Running nmap vuln scripts with -T4 (faster)..."

sudo nmap --script vuln -T4 -iL "$OUTDIR/live_hosts.txt" \
    -oN "$OUTDIR/vuln_scan.txt" 2>/dev/null

# Parse CVEs — one flag per unique CVE, with host
CURRENT_HOST=""
declare -A CVE_HOSTS

while IFS= read -r line; do
    # Track current host
    if echo "$line" | grep -q "Nmap scan report for"; then
        CURRENT_HOST=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    fi
    # Extract CVEs
    if echo "$line" | grep -qE "CVE-[0-9]{4}-[0-9]+"; then
        CVES=$(echo "$line" | grep -oE "CVE-[0-9]{4}-[0-9]+" | sort -u)
        while read -r cve; do
            KEY="${cve}:${CURRENT_HOST}"
            if [ -z "${CVE_HOSTS[$KEY]+x}" ]; then
                CVE_HOSTS[$KEY]=1
                flag "CVE $cve on $CURRENT_HOST"
            fi
        done <<< "$CVES"
    fi
done < "$OUTDIR/vuln_scan.txt"

UNIQUE_CVE_COUNT=${#CVE_HOSTS[@]}
if [ "$UNIQUE_CVE_COUNT" -gt 0 ]; then
    info "CVEs found: $UNIQUE_CVE_COUNT unique CVE/host pairs"
else
    info "No CVEs detected"
fi

info "Vuln scan complete: $OUTDIR/vuln_scan.txt"

# ── FINAL SUMMARY ───────────────────────────────────────────
END=$(date +%s)
ELAPSED=$((END - START))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))
FLAG_COUNT=$(wc -l < "$FLAGS")
CVE_UNIQUE=$(grep -c "^\[!\] CVE " "$FLAGS" 2>/dev/null || echo 0)

echo "" | tee -a "$SUMMARY"
echo "============================================================" | tee -a "$SUMMARY"
echo "  AUDIT COMPLETE"                                            | tee -a "$SUMMARY"
echo "  Finished:   $(date)"                                       | tee -a "$SUMMARY"
echo "  Duration:   ${MINUTES}m ${SECONDS}s"                       | tee -a "$SUMMARY"
echo "  Hosts:      $LIVE_COUNT"                                   | tee -a "$SUMMARY"
echo "  Open ports: $OPEN_COUNT"                                   | tee -a "$SUMMARY"
echo "  CVEs:       $CVE_UNIQUE unique"                            | tee -a "$SUMMARY"
echo "  FLAGS:      $FLAG_COUNT"                                   | tee -a "$SUMMARY"
echo "============================================================" | tee -a "$SUMMARY"

if [ "$FLAG_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${RED}════════ FLAGS ════════${NC}"
    cat "$FLAGS"
    echo -e "${RED}═══════════════════════${NC}"
fi

echo ""
echo -e "${GRN}Reports: $OUTDIR${NC}"
echo -e "${GRN}Summary: $SUMMARY${NC}"
echo -e "${GRN}Flags:   $FLAGS${NC}"

# Fix permissions so the user can read/write reports
REAL_USER="${SUDO_USER:-$(whoami)}"
chown -R "$REAL_USER":"$REAL_USER" "$REPORTS_DIR" 2>/dev/null

# Auto-generate PDF report
REPORT_GEN="$SCRIPT_DIR/generate_report.py"
if [ -f "$REPORT_GEN" ]; then
    echo -e "${YLW}[*] Generating PDF report...${NC}"
    sudo -u kaladmin python3 "$REPORT_GEN" "$OUTDIR" && \
        echo -e "${GRN}[+] PDF report generated.${NC}" || \
        echo -e "${RED}[!] PDF generation failed.${NC}"
fi
