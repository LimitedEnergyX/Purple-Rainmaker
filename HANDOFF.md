# PURPLE RAINMAKER — JARVIS HANDOFF PROMPT
## For use with Claude Code on Jarvis (Windows)

---

## WHO YOU ARE TALKING TO

Shawn C. Tovey, RCDD. Network infrastructure professional. First public software release.
This project is being prepared for GitHub publication as v1.0.0 under MIT license.

## BEHAVIOR RULES (follow these always)

- **Always start with claude-sonnet** model
- **Before doing anything:** restate the mission in 1–2 sentences and surface any ambiguity. Wait for confirmation, then execute.
- **Think before coding:** state assumptions, present options when unclear, push back when warranted
- **Simplicity first:** minimum code, no speculative features or abstractions
- **Surgical changes:** touch only what you must, match existing style
- **Goal-driven:** define success criteria and a brief verify plan before starting
- **When prompting with options:** always identify the recommended choice based on security, simplicity, automation, and processing efficiency
- **For any problem, list:** constraint, proposed solution, timeline, and impact

---

## PROJECT OVERVIEW

**Purple Rainmaker** is a local network security awareness platform. It runs on a dedicated Kali Purple machine ("KalDel," Dell Latitude 3505, IP 192.168.1.210) and is being published to GitHub under MIT license.

**Stack:** Python 3 / Flask / flask-sock / weasyprint / nmap / arp-scan

**Project path on KalDel:** `~/Documents/PR/` (flat file structure)

**GitHub plan:** Single clean commit tagged v1.0.0. No changelog until first post-publish change. Pre-publish iterations are treated as internal design phases — history starts clean.

**Runtime architecture:**
- KalDel = scanner runtime (Kali Purple, runs the actual scans)
- Jarvis = Windows dev machine (Claude Code, git, GitHub)
- After publish: KalDel pulls updates via `git pull`; Jarvis pushes via Claude Code

**Workflow on Jarvis:** Edit files in Claude Code → test changes by deploying to KalDel via `scp` or shared folder → KalDel restarts app → verify in browser at `http://127.0.0.1:5000`

---

## FILE STRUCTURE (flat — all in ~/Documents/PR/)

```
app.py                    # Flask backend — main application
autopilot.sh              # 3-step audit script (ARP → port scan → vuln scan)
generate_report.py        # PDF generator (weasyprint)
install.sh                # First-time install
update.sh                 # Safe update script
deploy.sh                 # Author's personal deploy script (KalDel only)
config.py                 # GITIGNORED — credentials + paths (auto-created at setup)
config.sh                 # GITIGNORED — shell config for autopilot.sh
config.example.py         # Template shown to users
requirements.txt
.gitignore
LICENSE                   # MIT, Shawn C. Tovey RCDD, 2026
README.md
templates/
  index.html              # Dashboard UI (lives here, Flask serves it)
  setup.html              # First-run setup page
playbook/reports/         # GITIGNORED — scan output directories
```

---

## CURRENT STATE — WHAT'S DONE

### Security hardening (complete)
- Flask binds to `127.0.0.1` by default; user opts into LAN with `BIND_HOST = '0.0.0.0'` in config.py
- Sudoers entry uses no wildcard — `autopilot.sh` sources `config.sh` instead of reading `$1`
- Interface names validated server-side via `psutil` with regex sanitization
- Tailscale filtered by interface name prefix AND IP range (100.x)

### Core features (complete)
- 3-step automated audit: ARP discovery → port scan → vulnerability assessment
- Live dashboard: terminal output, device inventory, flags, open ports, system health, report history
- WebSocket streaming of scan output, late-joiner replay (200-line buffer)
- Device baseline tracking — detects new and offline devices
- Risk Level card with 4 tiers: Low / Medium / High / Critical (pulses red at Critical)
- CVSS pre-fetch: after scan completes, `app.py` fetches all CVE scores to `cvss_cache.json` before calling `generate_report.py` — no live NVD API calls during PDF generation
- PDF auto-generates at scan completion, auto-opens in new tab (polls `has_pdf` every 2s)
- Differential analysis: scan-over-scan deltas (+/-) on all stat cards and in PDF
- Interface dropdown in header (replaces Tailscale indicator) — shows wlan/eth only
- CLEAR button in header — resets all panels AND stat cards AND Risk Level card
- Hard refresh starts clean — `displayCleared = true` on page load, stat cards stay `--` until scan runs
- Report history: VIEW and PDF buttons; GEN PDF only shown when PDF doesn't exist and not scanning

### Known good behavior
- Port 1080 on Amazon/Echo devices = nmap SOCKS5 probe, "No authentication; connection failed" = probe rejected, NOT confirmed open proxy
- CVE-2007-6750 (Slowloris) on any HTTP server = heuristic, expected false positive
- CVE-2005-3299, CVE-2010-2333 on router = heuristic false positives on Calix hardware
- 192.168.1.126 (62078/tcp iphone-sync) = iPhone with randomized MAC — expected
- 192.168.1.133 = Tesla Powerwall (Quectel cellular, Golang HTTP) — expected
- Locally-administered MACs (f2:xx, 92:xx etc.) = randomized MACs, normal for iOS/Windows

---

## PENDING — MUST COMPLETE BEFORE GITHUB PUSH

These are the remaining tasks in priority order:

### 1. Fix Risk engine — Option B (CRITICAL priority)
**Problem:** "New device detected" can currently co-trigger CRITICAL alongside a critical-tier port. In a home environment, new devices are almost always iPhones reconnecting with randomized MACs. This over-hypes normal environments.

**Decision:** Option B — remove new device as CRITICAL co-trigger entirely.

**New logic:**
- CRITICAL = critical-tier port AND CVSS ≥ 7.0 on the SAME host, OR multiple critical-tier ports on same host
- HIGH = any critical-tier port open, OR any CVE with CVSS ≥ 7.0
- MEDIUM = unusual port (1080, 8888), new device detected, or CVE CVSS 4.0–6.9
- LOW = no significant findings

**Files to change:** `app.py` (inline risk calc in `/api/status`) AND `generate_report.py` (`calculate_risk()` function)

**Critical-tier ports are:** 21, 23, 25, 69, 135, 161, 512, 513, 514, 1080, 3389, 4444, 5900, 6667

### 2. Merge Vendor + MAC Lookup into single "Vendor" column
**Problem:** Two columns answer the same question (who made this device?). Wastes space, confuses users. Especially noticeable at smaller window sizes.

**Decision:** Merge into one "Vendor" column.

**Behavior:**
- Show ARP vendor immediately on live scan row population
- If ARP says "(Unknown)" or contains "locally administered", async MAC Lookup API replaces it when it resolves
- If ARP has a real value, show ARP vendor; MAC Lookup result silently ignored unless it's better
- End state: one clean vendor name per row, colored cyan if enriched

**Files to change:** `templates/index.html` only (dashboard render + `addDeviceLive()` + `renderDevices()`)
**PDF already has single Vendor column** — no change needed to `generate_report.py`

### 3. Fix "NEW DEVICES DETECTED:" in PDF Executive Summary trigger list
**Problem:** The trigger list in the Executive Summary bullet points includes "NEW DEVICES DETECTED:" as a bare item with no device details — it ends with a colon and looks incomplete/broken.

**Fix:** In `generate_report.py` `calculate_risk()`, when building trigger strings, if the trigger is from new device detection, format it as "New device detected on network" (no colon, no blank trailing content). Or filter it from the exec summary trigger list entirely since it's already in the Flags section.

**File:** `generate_report.py`

### 4. Fix CVE description field showing "—" in PDF vulnerability table
**Problem:** The Description column in the PDF vulnerability assessment table shows `—` for all CVEs. The NVD API returns description data but it's not being stored in `cvss_cache.json` or passed through to the PDF template.

**Root cause:** `fetch_cvss()` in `app.py` only stores `score` and `severity` in the cache. Description is in the NVD response under `vulns[0]['cve']['descriptions']` — a list of lang/value objects, take the `en` one.

**Fix:**
- In `app.py` `fetch_cvss()`: also extract and cache `description` field from NVD response
- In `generate_report.py` `fetch_cvss_with_cache()`: pass description through from cache
- In PDF HTML template in `generate_report.py`: render description in the table cell

**Files:** `app.py`, `generate_report.py`

### 5. README screenshot
**Need:** A sanitized screenshot with fake IPs/MACs/hostnames for `docs/screenshot.png`
- Hide or replace: Tailscale IP visible in taskbar (100.86.55.108)
- Replace real IPs with 192.168.1.x placeholders
- Replace real MACs with generic placeholders
- Replace real hostnames with generic names
- This can be done by running a scan, taking screenshot, editing in GIMP or similar

**This is a manual step on KalDel** — Claude Code cannot do this.

### 6. Manual steps on KalDel (do before clean wipe/reinstall)
These cannot be done via code — must be done manually on KalDel:

```bash
# a) Remove sudoers wildcard
sudo visudo -f /etc/sudoers.d/purplerainmaker
# Change: NOPASSWD: /bin/bash /path/to/autopilot.sh *
# To:     NOPASSWD: /bin/bash /path/to/autopilot.sh

# b) Manually create config.sh (since setup was done before this feature existed)
cat > ~/Documents/PR/config.sh << 'EOF'
# Purple Rainmaker shell config — generated at setup, do not edit manually
PR_REPORTS_DIR='/home/kaladmin/Documents/PR/playbook/reports'
EOF
```

### 7. README updates (after code fixes above)
- Update Risk Level table to reflect Option B logic
- Update Sudo access section to remove wildcard mention
- Add `config.sh` to Report storage section
- Verify install instructions still accurate
- Add screenshot once created

### 8. GitHub publish
```bash
cd ~/Documents/PR
git init
git add -A
git commit -m "Initial release — v1.0.0"
git remote add origin https://github.com/scovey/purplerainmaker
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
```

---

## DEPLOY COMMAND (KalDel personal workflow)

```bash
cp ~/Downloads/<file> ~/Documents/PR/<destination> && \
pkill -f "python3.*app.py" && sleep 1 && \
cd ~/Documents/PR && nohup python3 app.py > /tmp/purplerainmaker.log 2>&1 & \
echo "Done"
```

Template destinations:
- `app.py` → `app.py`
- `index.html` → `templates/index.html`
- `generate_report.py` → `generate_report.py`

Verify after deploy:
```bash
sleep 2 && pgrep -f "python3.*app.py" && echo "RUNNING" || echo "FAILED" && tail -5 /tmp/purplerainmaker.log
```

---

## KEY TECHNICAL DETAILS

### app.py
- `BASE_DIR = os.path.dirname(os.path.abspath(__file__))` — all paths relative
- `AUTOPILOT = os.path.join(BASE_DIR, 'autopilot.sh')`
- `REPORT_GEN = os.path.join(BASE_DIR, 'generate_report.py')`
- Runs on `BIND_HOST` from config.py (default `127.0.0.1`)
- `sudo bash autopilot.sh` — NO argument passed (autopilot sources config.sh internally)
- CVSS pre-fetched to `cvss_cache.json` in report dir before calling `generate_report.py`
- `/api/interfaces` — lists non-loopback, non-tailscale interfaces (filters 100.x IPs)
- `/api/interface` POST — saves PREFERRED_IFACE to config.py (validated against psutil)

### autopilot.sh
- Sources `config.sh` for `PR_REPORTS_DIR` — no shell argument, no sudoers wildcard
- Auto-detects subnet from `ip route`, skips tailscale/lo
- Creates baseline on first run, compares subsequent scans
- Unusual ports flagged: 23, 21, 69, 161, 512, 513, 514, 1080, 3389, 4444, 5900, 6667
- `detail()` function writes to `summary.txt` only — NOT `flags.txt` (intentional)

### generate_report.py
- Reads `cvss_cache.json` first via `fetch_cvss_with_cache()`, falls back to live NVD API
- `calculate_risk()` takes `cvss_cache` parameter
- DESCRIPTIONS dict maps tier to human-readable text (was missing, caused KeyError — now fixed)
- CVSSv2 severity: reads from `m['cvssData'].get('baseSeverity') or m.get('baseSeverity', '')`
- PDF stat box deltas: `33 (-1)` format

### index.html
- `displayCleared = true` on page load — hard refresh starts blank
- `clearDisplay()` resets ALL cards including Risk Level, deltas, all panels, sets `displayCleared = true`
- `pollStatus()` skips stat card updates when `displayCleared = true`; CPU/Memory always update
- `startScan()` sets `displayCleared = false`
- `loadReports(populatePanels)` — `populatePanels` only `true` from `scanComplete()`
- Interface dropdown auto-selects first available interface (not "auto") on load
- GEN PDF button hidden during scan in report history

---

## NVD API NOTES

- URL: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`
- User-Agent: `PurpleRainmaker/1.0`
- Timeout: 5 seconds per request
- Rate limited — pre-fetching all CVEs to cache before PDF gen avoids timeout issues
- CVSSv3.1 preferred, fallback to v3.0, fallback to v2
- Some old CVEs (pre-2005) may not have CVSS scores in NVD — show "N/A" gracefully
- Description is in `vulns[0]['cve']['descriptions']` — list of `{lang, value}` dicts, take `lang == 'en'`

---

## PDF ISSUES FOUND IN LATEST REPORT (20260619_1324)

1. **"NEW DEVICES DETECTED:" bare bullet** — trigger list item ends with colon, no details → fix in `calculate_risk()` trigger string formatting
2. **CVSS N/A for old CVEs** — CVE-2010-2333, CVE-2005-3299, CVE-2011-3192 show N/A → expected for old CVEs with no NVD CVSS data; already handled gracefully
3. **Description column all "—"** — cache doesn't store description → fix `fetch_cvss()` to extract and cache description
4. **Long hostname hyphenation in port table** — "amazon-ca20e74a58f93286" wraps mid-word in PDF HOST column → minor CSS fix in PDF HTML template (`word-break: break-all` on host cell)
5. **Duplicate hostname row in port table** — same host appears twice, second row has no port/service → parsing issue in `parse_ports()` when same host has multiple entries

---

## SCAN OUTPUT FILES (per report directory)

```
playbook/reports/20260619_1209/
├── arp_full.txt          # Raw arp-scan output
├── live_hosts.txt        # Just IPs, one per line
├── port_scan.txt         # nmap -sV output
├── vuln_scan.txt         # nmap --script vuln output
├── summary.txt           # Human-readable audit summary
├── flags.txt             # [!] flag lines only
├── cvss_cache.json       # Pre-fetched CVSS scores {cve_id: {score, severity, description}}
└── Network_Security_Audit_20260619_1209.pdf
```

Baseline file: `playbook/reports/baseline_devices.txt` (one IP per line)

---

## WHAT NOT TO TOUCH

- Do not change the flat file structure
- Do not add a database — flat files are intentional
- Do not add authentication beyond HTTP Basic Auth
- Do not add any feature that requires internet access beyond the NVD API CVSS lookup
- Do not change the MIT license or remove author attribution anywhere
- Do not commit config.py, config.sh, or any scan reports

---

## LICENSE

MIT. File already written. No registration required.
© 2026 Shawn C. Tovey, RCDD

The MIT license means: anyone can use, modify, distribute, or sell this software, but they must keep the copyright notice. Shawn's name stays attached permanently.

---

## STARTING POINT FOR THIS SESSION

Start with these tasks in order:

1. **Risk engine Option B** — fix `calculate_risk()` in both `app.py` and `generate_report.py`
2. **Vendor column merge** — merge Vendor + MAC Lookup into single column in `templates/index.html`
3. **"NEW DEVICES DETECTED:" trigger fix** — clean up in `generate_report.py`
4. **CVE description from NVD** — update `fetch_cvss()` in `app.py` to store description, wire through to PDF
5. **README updates** — update Risk Level table, sudo section, verify install instructions
6. **Remind Shawn** about manual KalDel steps (sudoers + config.sh) and screenshot

After all code changes: deploy to KalDel, run a full scan, review the PDF, confirm everything looks right, then push to GitHub.
