#!/usr/bin/env python3
"""
PURPLE RAINMAKER - Network Security Awareness Platform
Author: Shawn C. Tovey, RCDD
https://github.com/scovey/purplerainmaker
"""

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_sock import Sock
from functools import wraps
import subprocess
import threading
import os
import json
import glob
import socket
import re
import psutil
import datetime
import ipaddress
import urllib.request

app = Flask(__name__)
sock = Sock(app)

# ── BASE PATHS ───────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.py')
AUTOPILOT   = os.path.join(BASE_DIR, 'autopilot.sh')
REPORT_GEN  = os.path.join(BASE_DIR, 'generate_report.py')

# ── LOAD CONFIG ──────────────────────────────────────────────
def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            exec(f.read(), cfg)
    return cfg

CONFIG_SH   = os.path.join(BASE_DIR, 'config.sh')

def save_config(username, password, reports_dir, bind_host='127.0.0.1'):
    with open(CONFIG_FILE, 'w') as f:
        f.write(f'AUTH_USERNAME = {repr(username)}\n')
        f.write(f'AUTH_PASSWORD = {repr(password)}\n')
        f.write(f'REPORTS_DIR   = {repr(reports_dir)}\n')
        f.write(f'BIND_HOST     = {repr(bind_host)}\n')
    os.makedirs(reports_dir, exist_ok=True)
    # Write config.sh for autopilot.sh — no shell args needed, no sudoers wildcard
    with open(CONFIG_SH, 'w') as f:
        f.write('# Purple Rainmaker shell config — generated at setup, do not edit manually\n')
        # Sanitize: strip any characters that could escape the shell assignment
        safe_dir = reports_dir.replace("'", "").replace('"', '').replace(';', '').replace('`', '')
        f.write(f"PR_REPORTS_DIR='{safe_dir}'\n")

def is_configured():
    cfg = load_config()
    return all(k in cfg for k in ('AUTH_USERNAME', 'AUTH_PASSWORD', 'REPORTS_DIR'))

def get_reports_dir():
    cfg = load_config()
    default = os.path.join(BASE_DIR, 'playbook', 'reports')
    return os.path.normpath(cfg.get('REPORTS_DIR', default))

def get_auth():
    cfg = load_config()
    return cfg.get('AUTH_USERNAME', ''), cfg.get('AUTH_PASSWORD', '')

# ── AUTH ─────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_configured():
            return Response('Setup required.', 302, {'Location': '/setup'})
        username, password = get_auth()
        auth = request.authorization
        if not auth or auth.username != username or auth.password != password:
            return Response(
                'Authentication required.',
                401,
                {'WWW-Authenticate': 'Basic realm="PURPLE RAINMAKER"'}
            )
        return f(*args, **kwargs)
    return decorated

# ── SCAN STATE ───────────────────────────────────────────────
scan_state = {
    "running": False,
    "current_step": "",
    "start_time": None,
    "last_report_dir": None,
    "log": []
}

# ── NETWORK HELPERS ─────────────────────────────────────────
def get_preferred_iface():
    """Return interface preference from config, or None for auto."""
    cfg = load_config()
    return cfg.get('PREFERRED_IFACE', None)

def get_network_info():
    preferred = get_preferred_iface()
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            # Skip loopback, tailscale (by name or IP range 100.x)
            if iface.startswith(('lo', 'tailscale', 'utun', 'tun')):
                continue
            # If user has a preference, skip non-matching interfaces
            if preferred and iface != preferred:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    # Skip Tailscale IP range (100.64.0.0/10)
                    if addr.address.startswith('100.'):
                        continue
                    ip = addr.address
                    netmask = addr.netmask
                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return {
                        "interface": iface,
                        "ip": ip,
                        "netmask": netmask,
                        "subnet": str(net),
                        "gateway": get_gateway(iface)
                    }
    except Exception:
        pass
    return {"interface": "unknown", "ip": "unknown", "subnet": "unknown", "gateway": "unknown"}

def get_gateway(iface):
    try:
        result = subprocess.run(['ip', 'route', 'show', 'dev', iface],
                                capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                if 'via' in parts:
                    return parts[parts.index('via') + 1]
    except Exception:
        pass
    return "unknown"

def get_tailscale_status():
    try:
        result = subprocess.run(['tailscale', 'status', '--json'],
                                capture_output=True, text=True, timeout=5)
        data = json.loads(result.stdout)
        peers = data.get('Peer', {})
        online = sum(1 for p in peers.values() if not p.get('Offline', True))
        return {"connected": True, "peers_online": online, "ip": data.get('TailscaleIPs', [''])[0]}
    except Exception:
        return {"connected": False, "peers_online": 0, "ip": ""}

# ── CVE HOST MAP ─────────────────────────────────────────────
def parse_cve_host_map(report_dir):
    cve_map = {}
    all_cves = set()
    vuln_path = os.path.join(report_dir, "vuln_scan.txt")
    if not os.path.exists(vuln_path):
        return cve_map, []
    current_ip = None
    with open(vuln_path) as f:
        for line in f:
            hm = re.match(r'Nmap scan report for .+\((\d+\.\d+\.\d+\.\d+)\)', line)
            if not hm:
                hm = re.match(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
            if hm:
                current_ip = hm.group(1)
            cves = re.findall(r'CVE-\d{4}-\d+', line)
            for cve in cves:
                all_cves.add(cve)
                if current_ip:
                    if current_ip not in cve_map:
                        cve_map[current_ip] = []
                    if cve not in cve_map[current_ip]:
                        cve_map[current_ip].append(cve)
    return cve_map, sorted(all_cves)

# ── CVSS LOOKUP (NVD API) ────────────────────────────────────

CVSS_CACHE = {}

def fetch_cvss(cve_id):
    """Fetch CVSS score from NVD API. Returns (score, severity, description) or (None, None, '')."""
    if cve_id in CVSS_CACHE:
        return CVSS_CACHE[cve_id]
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={'User-Agent': 'PurpleRainmaker/1.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            CVSS_CACHE[cve_id] = (None, None, '')
            return None, None, ''
        cve_data = vulns[0].get('cve', {})
        metrics = cve_data.get('metrics', {})
        desc_list = cve_data.get('descriptions', [])
        description = next((d['value'] for d in desc_list if d.get('lang') == 'en'), '')
        # Prefer CVSSv3, fall back to v2
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                if 'cvssData' in m:
                    score = m['cvssData'].get('baseScore')
                    sev   = (m['cvssData'].get('baseSeverity')
                             or m.get('baseSeverity', ''))
                    CVSS_CACHE[cve_id] = (score, sev, description)
                    return score, sev, description
    except Exception:
        pass
    CVSS_CACHE[cve_id] = (None, None, '')
    return None, None, ''

# ── RISK ENGINE ──────────────────────────────────────────────

# Ports that trigger High/Critical tier
CRITICAL_PORTS = {21, 23, 25, 69, 135, 161, 512, 513, 514, 1080, 3389, 4444, 5900, 6667}
# Ports that trigger Medium tier
MEDIUM_PORTS   = {1080, 8888}

def calculate_risk(flags, cve_map, open_ports, new_devices):
    """
    Highest-triggered-tier wins.
    Returns dict: {level, color, triggers, description}
    """
    triggers = []
    tier = 'LOW'   # LOW < MEDIUM < HIGH < CRITICAL

    TIER_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

    def bump(new_tier, reason):
        nonlocal tier
        triggers.append(reason)
        if TIER_ORDER[new_tier] > TIER_ORDER[tier]:
            tier = new_tier

    # ── Critical-tier port exposure ───────────────────────────
    critical_port_hosts = {}   # port -> [hosts]
    for p in open_ports:
        port_num = int(p.get('port', 0))
        if port_num in CRITICAL_PORTS:
            if port_num not in critical_port_hosts:
                critical_port_hosts[port_num] = []
            critical_port_hosts[port_num].append(p.get('host', ''))

    # Multiple critical ports on same host → Critical
    host_critical_counts = {}
    for port_num, hosts in critical_port_hosts.items():
        for h in hosts:
            host_critical_counts[h] = host_critical_counts.get(h, 0) + 1

    for host, count in host_critical_counts.items():
        if count >= 2:
            short = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host)
            ip = short.group(1) if short else host
            bump('CRITICAL', f"Multiple critical-tier ports on {ip}")

    # Single critical port → High
    for port_num, hosts in critical_port_hosts.items():
        for h in hosts:
            short = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', h)
            ip = short.group(1) if short else h
            svc_names = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 69: 'TFTP',
                         135: 'MSRPC', 161: 'SNMP', 512: 'rexec',
                         513: 'rlogin', 514: 'rsh', 1080: 'SOCKS proxy',
                         3389: 'RDP', 4444: 'Backdoor port', 5900: 'VNC',
                         6667: 'IRC'}
            svc = svc_names.get(port_num, f'port {port_num}')
            bump('HIGH', f"{svc} exposed on {ip}")

    # ── CVE scoring ───────────────────────────────────────────
    for ip, cves in cve_map.items():
        for cve in cves:
            score, sev, _ = fetch_cvss(cve)
            if score is None:
                bump('MEDIUM', f"{cve} on {ip} (CVSS unavailable — review recommended)")
            elif score >= 7.0:
                bump('HIGH', f"{cve} on {ip} (CVSS {score} — {sev})")
                # CRITICAL only if same host also has a critical-tier port
                host_has_critical_port = any(
                    ip in str(h)
                    for hosts in critical_port_hosts.values()
                    for h in hosts
                )
                if host_has_critical_port:
                    bump('CRITICAL', f"Critical-tier port and {cve} (CVSS {score}) on {ip}")
            elif score >= 4.0:
                bump('MEDIUM', f"{cve} on {ip} (CVSS {score} — {sev})")

    # ── Medium-tier ports ─────────────────────────────────────
    for p in open_ports:
        port_num = int(p.get('port', 0))
        if port_num in MEDIUM_PORTS:
            short = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', p.get('host',''))
            ip = short.group(1) if short else p.get('host','')
            bump('MEDIUM', f"Port {port_num} open on {ip}")

    # ── New devices ───────────────────────────────────────────
    for d in new_devices:
        bump('MEDIUM', f"New device detected: {d}")

    COLORS = {
        'LOW':      'var(--green)',
        'MEDIUM':   'var(--yellow)',
        'HIGH':     '#ff8c00',
        'CRITICAL': 'var(--red)',
    }
    DESCRIPTIONS = {
        'LOW':      'No significant issues detected. Continue routine monitoring.',
        'MEDIUM':   'Items require review. No immediately exploitable conditions confirmed.',
        'HIGH':     'Significant findings detected. Prompt review recommended.',
        'CRITICAL': 'Critical-tier exposures detected. Immediate attention required.',
    }

    return {
        'level':       tier,
        'color':       COLORS[tier],
        'triggers':    list(dict.fromkeys(triggers)),  # dedupe, preserve order
        'description': DESCRIPTIONS[tier],
    }

# ── DIFFERENTIAL ANALYSIS ────────────────────────────────────

def get_diff(current_report, previous_report):
    """Compare current scan to previous. Returns deltas dict."""
    if not previous_report:
        return {}
    def safe(report, key):
        return len(report.get(key, []))
    return {
        'devices': safe(current_report,'devices') - safe(previous_report,'devices'),
        'ports':   safe(current_report,'open_ports') - safe(previous_report,'open_ports'),
        'cves':    safe(current_report,'cves') - safe(previous_report,'cves'),
        'flags':   safe(current_report,'flags') - safe(previous_report,'flags'),
    }


def list_reports():
    reports_dir = get_reports_dir()
    os.makedirs(reports_dir, exist_ok=True)
    dirs = []
    for d in sorted(glob.glob(os.path.join(reports_dir, "2*")), reverse=True):
        if os.path.isdir(d):
            name = os.path.basename(d)
            flags_path = os.path.join(d, "flags.txt")
            summary_path = os.path.join(d, "summary.txt")
            flags = []
            if os.path.exists(flags_path):
                with open(flags_path) as f:
                    flags = [l.strip() for l in f if l.strip() and l.startswith('[!]')]
            has_pdf = bool(glob.glob(os.path.join(d, "*.pdf")))
            ts = ""
            if os.path.exists(summary_path):
                try:
                    with open(summary_path) as f:
                        for line in f:
                            if "Started:" in line:
                                ts = line.strip()
                                break
                except Exception:
                    pass
            dirs.append({
                "name": name,
                "path": d,
                "flag_count": len(flags),
                "has_summary": os.path.exists(summary_path),
                "has_docx": False,
                "has_pdf": has_pdf,
                "flags": flags[:5],
                "timestamp": ts
            })
    return dirs

def parse_report(report_dir):
    data = {
        "devices": [], "open_ports": [], "flags": [],
        "cves": [], "cve_host_map": {}, "summary": "", "scan_timestamp": ""
    }
    arp_path = os.path.join(report_dir, "arp_full.txt")
    if os.path.exists(arp_path):
        with open(arp_path) as f:
            seen = set()
            for line in f:
                parts = line.strip().split('\t') if '\t' in line else line.strip().split()
                if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                    ip = parts[0]
                    if ip not in seen:
                        seen.add(ip)
                        mac = parts[1] if len(parts) > 1 else ''
                        vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                        data["devices"].append({"ip": ip, "mac": mac, "vendor": vendor})
    hostname_map = {}
    port_path = os.path.join(report_dir, "port_scan.txt")
    if os.path.exists(port_path):
        current_host = ""
        current_ip = ""
        with open(port_path) as f:
            for line in f:
                hm = re.match(r'Nmap scan report for (.+)', line)
                if hm:
                    host_str = hm.group(1).strip()
                    current_host = host_str
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_str)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        hostname = host_str.split('(')[0].strip()
                        if hostname and hostname != current_ip:
                            hostname_map[current_ip] = hostname
                    else:
                        bare = re.match(r'^(\d+\.\d+\.\d+\.\d+)$', host_str)
                        if bare:
                            current_ip = bare.group(1)
                pm = re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
                if pm and current_host:
                    data["open_ports"].append({
                        "host": current_host,
                        "port": pm.group(1),
                        "service": pm.group(2),
                        "version": pm.group(3).strip()
                    })
    flags_path = os.path.join(report_dir, "flags.txt")
    if os.path.exists(flags_path):
        with open(flags_path) as f:
            data["flags"] = [l.strip() for l in f if l.strip() and l.startswith('[!]')]
    cve_map, all_cves = parse_cve_host_map(report_dir)
    data["cves"] = all_cves
    data["cve_host_map"] = cve_map
    for device in data["devices"]:
        ip = device["ip"]
        device["cve_count"] = len(cve_map.get(ip, []))
        device["cves"] = cve_map.get(ip, [])
        device["flagged"] = any(ip in f for f in data["flags"])
        device["hostname"] = hostname_map.get(ip, "")
    sum_path = os.path.join(report_dir, "summary.txt")
    if os.path.exists(sum_path):
        with open(sum_path) as f:
            content = f.read()
            data["summary"] = content
            for line in content.split('\n'):
                if 'Finished:' in line:
                    data["scan_timestamp"] = line.replace('Finished:', '').strip()
                    break
    return data

# ── SYSTEM HEALTH ────────────────────────────────────────────
def get_system_health():
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.expanduser("~"))
    net  = psutil.net_io_counters()
    return {
        "cpu_percent":   cpu,
        "mem_percent":   mem.percent,
        "mem_used_gb":   round(mem.used / 1e9, 1),
        "mem_total_gb":  round(mem.total / 1e9, 1),
        "disk_percent":  disk.percent,
        "disk_free_gb":  round(disk.free / 1e9, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "net_sent_mb":   round(net.bytes_sent / 1e6, 1),
        "net_recv_mb":   round(net.bytes_recv / 1e6, 1),
        "uptime": str(datetime.timedelta(
            seconds=int(datetime.datetime.now().timestamp() - psutil.boot_time())))
    }

# ── SETUP ROUTES ─────────────────────────────────────────────
@app.route('/setup', methods=['GET'])
def setup_page():
    if is_configured():
        return Response('', 302, {'Location': '/'})
    default_reports = os.path.normpath(os.path.join(BASE_DIR, 'playbook', 'reports'))
    return render_template('setup.html', default_reports=default_reports)

@app.route('/setup', methods=['POST'])
def setup_save():
    data = request.get_json()
    username    = (data.get('username') or '').strip()
    password    = (data.get('password') or '').strip()
    reports_dir = (data.get('reports_dir') or '').strip()
    bind_host   = (data.get('bind_host') or '127.0.0.1').strip()
    if not username or not password or not reports_dir:
        return jsonify({"error": "All fields required."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400
    # Validate bind_host — only allow known safe values
    if bind_host not in ('127.0.0.1', '0.0.0.0'):
        bind_host = '127.0.0.1'
    reports_dir = os.path.expanduser(reports_dir)
    reports_dir = os.path.normpath(os.path.abspath(reports_dir))
    try:
        save_config(username, password, reports_dir, bind_host)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── MAIN ROUTES ──────────────────────────────────────────────
@app.route('/')
@require_auth
def index():
    return render_template('index.html')

@app.route('/api/status')
@require_auth
def api_status():
    net     = get_network_info()
    health  = get_system_health()
    reports = list_reports()
    last_report = parse_report(reports[0]["path"]) if reports else {}
    prev_report = parse_report(reports[1]["path"]) if len(reports) > 1 else {}

    # New devices from flags
    new_devs = [f.replace('[!]','').replace('NEW DEVICES DETECTED:','').strip()
                for f in last_report.get('flags',[]) if 'NEW DEVICE' in f]

    risk = calculate_risk(
        last_report.get('flags', []),
        last_report.get('cve_host_map', {}),
        last_report.get('open_ports', []),
        new_devs
    ) if last_report else {'level':'LOW','color':'var(--green)','triggers':[],'description':''}

    diff = get_diff(last_report, prev_report)

    return jsonify({
        "network":           net,
        "health":            health,
        "tailscale":         get_tailscale_status(),
        "scan_running":      scan_state["running"],
        "scan_step":         scan_state["current_step"],
        "report_count":      len(reports),
        "last_report":       reports[0] if reports else None,
        "last_flags":        last_report.get("flags", []),
        "last_device_count": len(last_report.get("devices", [])),
        "last_port_count":   len(last_report.get("open_ports", [])),
        "last_cve_count":    len(last_report.get("cves", [])),
        "risk":              risk,
        "diff":              diff,
    })

@app.route('/api/health')
@require_auth
def api_health():
    return jsonify(get_system_health())

@app.route('/api/reports')
@require_auth
def api_reports():
    return jsonify(list_reports())

@app.route('/api/report/<name>')
@require_auth
def api_report(name):
    report_dir = os.path.join(get_reports_dir(), name)
    if not os.path.exists(report_dir):
        return jsonify({"error": "Not found"}), 404
    return jsonify(parse_report(report_dir))

@app.route('/api/report/<name>/summary')
@require_auth
def api_summary(name):
    path = os.path.join(get_reports_dir(), name, "summary.txt")
    if not os.path.exists(path):
        return jsonify({"error": "Not found"}), 404
    with open(path) as f:
        return jsonify({"summary": f.read()})

@app.route('/api/report/<name>/generate', methods=['POST'])
@require_auth
def api_generate(name):
    report_dir = os.path.join(get_reports_dir(), name)
    if not os.path.exists(report_dir):
        return jsonify({"error": "Report not found"}), 404
    if not os.path.exists(REPORT_GEN):
        return jsonify({"error": f"Report generator not found at {REPORT_GEN}"}), 404
    def run_gen():
        cache_path = os.path.join(report_dir, 'cvss_cache.json')
        if not os.path.exists(cache_path):
            try:
                cve_map, _ = parse_cve_host_map(report_dir)
                all_cves = list({c for cves in cve_map.values() for c in cves})
                cache = {}
                for cve in all_cves:
                    score, sev, desc = fetch_cvss(cve)
                    cache[cve] = {'score': score, 'severity': sev, 'description': desc[:200] if desc else ''}
                with open(cache_path, 'w') as f:
                    json.dump(cache, f)
            except Exception:
                pass
        subprocess.run(['python3', REPORT_GEN, report_dir], capture_output=True, text=True)
    threading.Thread(target=run_gen).start()
    return jsonify({"status": "generating", "report_dir": report_dir})

@app.route('/api/report/<name>/download/pdf')
@require_auth
def api_download(name):
    report_dir = os.path.join(get_reports_dir(), name)
    files = glob.glob(os.path.join(report_dir, "*.pdf"))
    if not files:
        return jsonify({"error": "No PDF found"}), 404
    return send_file(files[0], as_attachment=True)

@app.route('/api/interfaces')
@require_auth
def api_interfaces():
    """Return list of non-loopback, non-tailscale interfaces with IPs."""
    ifaces = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            if iface.startswith(('lo', 'tailscale', 'utun', 'tun')):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '100.')):
                    ifaces.append({"name": iface, "ip": addr.address})
    except Exception:
        pass
    preferred = get_preferred_iface()
    return jsonify({"interfaces": ifaces, "preferred": preferred})

@app.route('/api/interface', methods=['POST'])
@require_auth
def api_set_interface():
    """Save preferred interface to config — validated against actual system interfaces."""
    data = request.get_json()
    iface = (data.get('interface') or '').strip()
    # Validate against actual interfaces — reject anything not on the system
    if iface:
        valid_ifaces = list(psutil.net_if_addrs().keys())
        if iface not in valid_ifaces:
            return jsonify({"ok": False, "error": "Interface not found on this system"}), 400
        # Extra: reject anything that looks like shell injection
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_\-\.]+$', iface):
            return jsonify({"ok": False, "error": "Invalid interface name"}), 400
    cfg = load_config()
    with open(CONFIG_FILE, 'w') as f:
        f.write(f"AUTH_USERNAME = {repr(cfg.get('AUTH_USERNAME',''))}\n")
        f.write(f"AUTH_PASSWORD = {repr(cfg.get('AUTH_PASSWORD',''))}\n")
        f.write(f"REPORTS_DIR   = {repr(cfg.get('REPORTS_DIR',''))}\n")
        f.write(f"BIND_HOST     = {repr(cfg.get('BIND_HOST','127.0.0.1'))}\n")
        if iface:
            f.write(f"PREFERRED_IFACE = {repr(iface)}\n")
    return jsonify({"ok": True, "interface": iface})

@app.route('/api/network')
@require_auth
def api_network():
    return jsonify(get_network_info())

# ── SCAN LOG HELPER ──────────────────────────────────────────
def log_append(msg_type, msg):
    scan_state["log"].append({"type": msg_type, "msg": msg})
    if len(scan_state["log"]) > 200:
        scan_state["log"].pop(0)

# ── WEBSOCKET - LIVE SCAN ────────────────────────────────────
@sock.route('/ws/scan')
def ws_scan(ws):
    if scan_state["running"]:
        ws.send(json.dumps({"type": "catchup", "msg": "Scan in progress — resuming live feed..."}))
        for entry in scan_state["log"]:
            ws.send(json.dumps(entry))
        import time
        last_len = len(scan_state["log"])
        while scan_state["running"]:
            time.sleep(0.5)
            current_len = len(scan_state["log"])
            if current_len > last_len:
                for entry in scan_state["log"][last_len:current_len]:
                    ws.send(json.dumps(entry))
                last_len = current_len
        ws.send(json.dumps({
            "type": "complete",
            "msg": "PURPLE RAINMAKER scan complete.",
            "report_dir": scan_state["last_report_dir"]
        }))
        return

    if not os.path.exists(AUTOPILOT):
        ws.send(json.dumps({"type": "error", "msg": f"autopilot.sh not found at {AUTOPILOT}"}))
        return

    scan_state["running"]    = True
    scan_state["start_time"] = datetime.datetime.now().isoformat()
    scan_state["log"]        = []

    try:
        ws.send(json.dumps({"type": "start", "msg": "PURPLE RAINMAKER initiating scan..."}))
        log_append("start", "PURPLE RAINMAKER initiating scan...")
        proc = subprocess.Popen(
            ['sudo', 'bash', AUTOPILOT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in proc.stdout:
            line = re.sub(r'\x1b\[[0-9;]*m', '', line.rstrip())
            if not line:
                continue
            if line.startswith('SF-Port') or line.startswith('SF:') or line.startswith('==============NEXT'):
                continue
            step_match = re.search(r'STEP (\d+ of \d+): (.+)', line)
            if step_match:
                scan_state["current_step"] = step_match.group(2)
            if line.startswith('[!]'):
                msg_type = "flag"
            elif line.startswith('[+]'):
                msg_type = "success"
            elif line.startswith('[*]'):
                msg_type = "info"
            elif '====' in line:
                msg_type = "section"
            else:
                msg_type = "output"
            log_append(msg_type, line)
            ws.send(json.dumps({"type": msg_type, "msg": line}))

        proc.wait()

        reports = sorted(glob.glob(os.path.join(get_reports_dir(), "2*")), reverse=True)
        if reports:
            scan_state["last_report_dir"] = os.path.basename(reports[0])
            if os.path.exists(REPORT_GEN):
                def run_gen(rdir=reports[0]):
                    # Pre-fetch CVSS for all CVEs and cache to file
                    try:
                        cve_map, _ = parse_cve_host_map(rdir)
                        all_cves = list({c for cves in cve_map.values() for c in cves})
                        cache = {}
                        for cve in all_cves:
                            score, sev, desc = fetch_cvss(cve)
                            cache[cve] = {'score': score, 'severity': sev, 'description': desc[:200] if desc else ''}
                        cache_path = os.path.join(rdir, 'cvss_cache.json')
                        with open(cache_path, 'w') as f:
                            json.dump(cache, f)
                    except Exception:
                        pass
                    subprocess.run(['python3', REPORT_GEN, rdir], capture_output=True, text=True)
                threading.Thread(target=run_gen).start()

        ws.send(json.dumps({
            "type": "complete",
            "msg": "PURPLE RAINMAKER scan complete.",
            "report_dir": scan_state["last_report_dir"]
        }))

    except Exception as e:
        ws.send(json.dumps({"type": "error", "msg": str(e)}))
    finally:
        scan_state["running"]      = False
        scan_state["current_step"] = ""

@sock.route('/ws/health')
def ws_health(ws):
    import time
    try:
        while True:
            ws.send(json.dumps(get_system_health()))
            time.sleep(2)
    except Exception:
        pass

if __name__ == '__main__':
    print("\n  ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗")
    print("  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝")
    print("  ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ")
    print("  ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ")
    print("  ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗")
    print("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝")
    print("  ██████╗  █████╗ ██╗███╗   ██╗███╗   ███╗ █████╗ ██╗  ██╗███████╗██████╗ ")
    print("  ██╔══██╗██╔══██╗██║████╗  ██║████╗ ████║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗")
    print("  ██████╔╝███████║██║██╔██╗ ██║██╔████╔██║███████║█████╔╝ █████╗  ██████╔╝")
    print("  ██╔══██╗██╔══██║██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗")
    print("  ██║  ██║██║  ██║██║██║ ╚████║██║ ╚═╝ ██║██║  ██║██║  ██╗███████╗██║  ██║")
    print("  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝")
    print("\n  Network Security Awareness Platform")
    print("  Shawn C. Tovey, RCDD\n")
    if not is_configured():
        print("  [!] First run detected — open http://localhost:5000/setup to configure.\n")
    bind_host = load_config().get('BIND_HOST', '127.0.0.1')
    app.run(host=bind_host, port=5000, debug=False)
