#!/usr/bin/env python3
"""
PURPLE RAINMAKER - PDF Report Generator
Usage: python3 generate_report.py <report_dir>
Output: <report_dir>/Network_Security_Audit_<date>.pdf
"""

import sys
import os
import re
import json
import urllib.request
from datetime import datetime

# ── CVSS LOOKUP ──────────────────────────────────────────────
_cvss_cache = {}

def load_cvss_cache(report_dir):
    """Load pre-fetched CVSS cache from report directory if available."""
    cache_path = os.path.join(report_dir, 'cvss_cache.json')
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def fetch_cvss(cve_id):
    """Fetch CVSS score and metadata from NVD API."""
    if cve_id in _cvss_cache:
        return _cvss_cache[cve_id]
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={'User-Agent': 'PurpleRainmaker/1.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        vulns = data.get('vulnerabilities', [])
        if vulns:
            metrics = vulns[0].get('cve', {}).get('metrics', {})
            desc_list = vulns[0].get('cve', {}).get('descriptions', [])
            description = next((d['value'] for d in desc_list if d.get('lang') == 'en'), '')
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if 'cvssData' in m:
                        score = m['cvssData'].get('baseScore')
                        # CVSSv3: baseSeverity in cvssData
                        # CVSSv2: baseSeverity on metric object, not in cvssData
                        sev = (m['cvssData'].get('baseSeverity')
                               or m.get('baseSeverity', ''))
                        result = {
                            'score':       score,
                            'severity':    sev,
                            'description': description[:200] if description else '',
                            'confidence':  'High',
                        }
                        _cvss_cache[cve_id] = result
                        return result
    except Exception:
        pass
    result = {'score': None, 'severity': '', 'description': '', 'confidence': 'Medium'}
    _cvss_cache[cve_id] = result
    return result

def fetch_cvss_with_cache(cve_id, cache=None):
    """Fetch CVSS — use pre-fetched cache first, fall back to live API."""
    if cache and cve_id in cache:
        cached = cache[cve_id]
        score = cached.get('score')
        sev   = cached.get('severity', '')
        if score is not None:
            return {'score': score, 'severity': sev,
                    'description': cached.get('description', ''),
                    'confidence': 'High'}
    return fetch_cvss(cve_id)

# ── RISK ENGINE (mirrors app.py) ─────────────────────────────
CRITICAL_PORTS = {21, 23, 25, 69, 135, 161, 512, 513, 514, 1080, 3389, 4444, 5900, 6667}
MEDIUM_PORTS   = {1080, 8888}
TIER_ORDER     = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

def calculate_risk(flags, cve_map, ports, cvss_cache=None):
    tier     = 'LOW'
    triggers = []

    def bump(new_tier, reason):
        nonlocal tier
        triggers.append(reason)
        if TIER_ORDER[new_tier] > TIER_ORDER[tier]:
            tier = new_tier

    new_devices = [f for f in flags if 'NEW DEVICE' in f.upper()]

    # Critical-tier ports
    critical_port_hosts = {}
    for p in ports:
        pnum = int(p.get('port', 0))
        if pnum in CRITICAL_PORTS:
            critical_port_hosts.setdefault(pnum, []).append(p.get('host',''))

    host_counts = {}
    for pnum, hosts in critical_port_hosts.items():
        for h in hosts:
            host_counts[h] = host_counts.get(h, 0) + 1

    for host, count in host_counts.items():
        if count >= 2:
            ip = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host)
            bump('CRITICAL', f"Multiple critical-tier ports on {ip.group(1) if ip else host}")

    svc_names = {21:'FTP', 23:'Telnet', 25:'SMTP', 69:'TFTP', 135:'MSRPC',
                 161:'SNMP', 512:'rexec', 513:'rlogin', 514:'rsh',
                 1080:'SOCKS proxy', 3389:'RDP', 4444:'Backdoor port',
                 5900:'VNC', 6667:'IRC'}
    for pnum, hosts in critical_port_hosts.items():
        for h in hosts:
            ip = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', h)
            svc = svc_names.get(pnum, f'port {pnum}')
            bump('HIGH', f"{svc} exposed on {ip.group(1) if ip else h}")

    for ip, cves in cve_map.items():
        for cve in cves:
            cvss = fetch_cvss_with_cache(cve, cvss_cache)
            score = cvss.get('score')
            sev   = cvss.get('severity','')
            if score is None:
                bump('MEDIUM', f"{cve} on {ip} (CVSS unavailable)")
            elif score >= 7.0:
                bump('HIGH', f"{cve} on {ip} (CVSS {score} — {sev})")
                host_has_critical_port = any(
                    ip in str(h)
                    for hosts in critical_port_hosts.values()
                    for h in hosts
                )
                if host_has_critical_port:
                    bump('CRITICAL', f"Critical-tier port and {cve} (CVSS {score}) on {ip}")
            elif score >= 4.0:
                bump('MEDIUM', f"{cve} on {ip} (CVSS {score} — {sev})")

    for p in ports:
        pnum = int(p.get('port', 0))
        if pnum in MEDIUM_PORTS:
            ip = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', p.get('host',''))
            bump('MEDIUM', f"Port {pnum} open on {ip.group(1) if ip else p.get('host','')}")

    if new_devices:
        bump('MEDIUM', 'New device(s) detected on network')

    DESCRIPTIONS = {
        'LOW':      'No significant issues detected. Continue routine monitoring.',
        'MEDIUM':   'Items require review. No immediately exploitable conditions confirmed.',
        'HIGH':     'Significant findings detected. Prompt review recommended.',
        'CRITICAL': 'Critical-tier exposures detected. Immediate attention required.',
    }

    return {
        'level':       tier,
        'triggers':    list(dict.fromkeys(triggers)),
        'description': DESCRIPTIONS[tier],
    }


def read_file(report_dir, filename):
    path = os.path.join(report_dir, filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return ""

def read_lines(report_dir, filename):
    content = read_file(report_dir, filename)
    return [l.strip() for l in content.split('\n') if l.strip()] if content else []

def parse_arp(report_dir):
    devices = []
    seen = set()
    for line in read_lines(report_dir, "arp_full.txt"):
        parts = line.split()
        if len(parts) >= 2 and re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', parts[0]):
            ip = parts[0]
            if ip not in seen:
                seen.add(ip)
                mac = parts[1] if len(parts) > 1 else ''
                vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
    return devices

def parse_ports(report_dir):
    ports = []
    hostname_map = {}
    current_host = ''
    current_ip = ''
    for line in read_lines(report_dir, "port_scan.txt"):
        hm = re.match(r'Nmap scan report for (.+)', line)
        if hm:
            host_str = hm.group(1).strip()
            current_host = host_str
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_str)
            if ip_m:
                current_ip = ip_m.group(1)
                hostname = host_str.split('(')[0].strip()
                if hostname and hostname != current_ip:
                    hostname_map[current_ip] = hostname
            else:
                bare = re.match(r'^(\d+\.\d+\.\d+\.\d+)$', host_str)
                if bare:
                    current_ip = bare.group(1)
        pm = re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
        if pm and current_host:
            ports.append({
                'host': current_host,
                'port': pm.group(1),
                'service': pm.group(2),
                'version': pm.group(3).strip()
            })
    return ports, hostname_map

def parse_cve_map(report_dir):
    cve_map = {}
    current_ip = None
    for line in read_lines(report_dir, "vuln_scan.txt"):
        hm = re.match(r'Nmap scan report for .+\((\d+\.\d+\.\d+\.\d+)\)', line)
        if not hm:
            hm = re.match(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
        if hm:
            current_ip = hm.group(1)
        cves = re.findall(r'CVE-\d{4}-\d+', line)
        for cve in cves:
            if current_ip:
                if current_ip not in cve_map:
                    cve_map[current_ip] = []
                if cve not in cve_map[current_ip]:
                    cve_map[current_ip].append(cve)
    return cve_map

def parse_flags(report_dir):
    return [l for l in read_lines(report_dir, "flags.txt") if l.startswith('[!]')]

def generate_html(report_dir, prev_report_dir=None):
    report_name = os.path.basename(report_dir)

    devices = parse_arp(report_dir)
    ports, hostname_map = parse_ports(report_dir)
    cve_map = parse_cve_map(report_dir)
    flags   = parse_flags(report_dir)
    summary = read_file(report_dir, "summary.txt")

    # Extract stats from summary
    host_count = len(devices)
    port_count = len(ports)
    cve_count  = sum(len(v) for v in cve_map.values())
    flag_count = len(flags)

    # Differential vs previous scan
    diff = {}
    if prev_report_dir and os.path.exists(prev_report_dir):
        prev_devices = parse_arp(prev_report_dir)
        prev_ports, _ = parse_ports(prev_report_dir)
        prev_cve_map  = parse_cve_map(prev_report_dir)
        prev_flags    = parse_flags(prev_report_dir)
        diff = {
            'devices': len(devices) - len(prev_devices),
            'ports':   len(ports)   - len(prev_ports),
            'cves':    sum(len(v) for v in cve_map.values()) - sum(len(v) for v in prev_cve_map.values()),
            'flags':   len(flags)   - len(prev_flags),
        }

    # Load pre-fetched CVSS cache
    cvss_cache = load_cvss_cache(report_dir)

    # Risk calculation
    risk = calculate_risk(flags, cve_map, ports, cvss_cache)

    # Extract scan duration and timestamps from summary
    duration = ''
    finished = ''
    started = ''
    for line in summary.split('\n'):
        if 'Duration:' in line:
            duration = line.split('Duration:')[-1].strip()
        if 'Finished:' in line:
            finished = line.split('Finished:')[-1].strip()
        if 'Started:' in line:
            started = line.split('Started:')[-1].strip()

    # Use scan start time for report date, fall back to now
    if started:
        date_str = started
    elif finished:
        date_str = finished
    else:
        date_str = datetime.now().strftime('%B %d, %Y at %I:%M %p')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @page {{
    size: letter;
    margin: 1in;
    @top-center {{
      content: "PURPLE RAINMAKER — Network Security Audit Report";
      font-family: 'Courier New', monospace;
      font-size: 8pt;
      color: #666;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-family: 'Courier New', monospace;
      font-size: 8pt;
      color: #666;
    }}
    @bottom-left {{
      content: "© 2026 Shawn C. Tovey, RCDD — CONFIDENTIAL";
      font-family: 'Courier New', monospace;
      font-size: 8pt;
      color: #666;
    }}
  }}
  body {{
    font-family: 'Times New Roman', serif;
    font-size: 11pt;
    color: #000;
    line-height: 1.5;
  }}
  h1 {{
    font-family: 'Courier New', monospace;
    font-size: 18pt;
    text-align: center;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 2px solid #000;
    padding-bottom: 8px;
    margin-bottom: 4px;
  }}
  h2 {{
    font-family: 'Courier New', monospace;
    font-size: 13pt;
    border-bottom: 1px solid #333;
    padding-bottom: 4px;
    margin-top: 24px;
    margin-bottom: 10px;
  }}
  h3 {{
    font-family: 'Courier New', monospace;
    font-size: 11pt;
    margin-top: 16px;
  }}
  .cover {{
    text-align: center;
    margin-bottom: 40px;
    padding-bottom: 20px;
    border-bottom: 1px solid #ccc;
  }}
  .cover .subtitle {{
    font-family: 'Courier New', monospace;
    font-size: 10pt;
    color: #444;
    letter-spacing: 2px;
    margin-top: 6px;
  }}
  .cover .meta {{
    font-size: 10pt;
    color: #555;
    margin-top: 20px;
    line-height: 2;
  }}
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin: 16px 0;
  }}
  .stat-box {{
    border: 1px solid #999;
    padding: 10px;
    text-align: center;
    border-radius: 4px;
  }}
  .stat-box .val {{
    font-family: 'Courier New', monospace;
    font-size: 22pt;
    font-weight: bold;
    display: block;
  }}
  .stat-box .lbl {{
    font-size: 8pt;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #555;
  }}
  .stat-box.red .val {{ color: #cc0000; }}
  .stat-box.green .val {{ color: #006600; }}
  .stat-box.neutral .val {{ color: #222; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin: 10px 0;
  }}
  th {{
    background: #222;
    color: #fff;
    padding: 5px 8px;
    text-align: left;
    font-family: 'Courier New', monospace;
    font-size: 8pt;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  td {{
    padding: 4px 8px;
    border-bottom: 1px solid #ddd;
    font-family: 'Courier New', monospace;
    font-size: 9pt;
  }}
  tr:nth-child(even) td {{ background: #f5f5f5; }}
  .flag-item {{
    padding: 6px 10px;
    margin: 4px 0;
    border-left: 3px solid #cc0000;
    background: #fff5f5;
    font-family: 'Courier New', monospace;
    font-size: 9pt;
  }}
  .flag-clear {{
    padding: 10px;
    border: 1px solid #006600;
    background: #f5fff5;
    text-align: center;
    font-family: 'Courier New', monospace;
    color: #006600;
  }}
  .cve-badge {{
    color: #cc0000;
    font-weight: bold;
  }}
  .disclaimer {{
    font-size: 9pt;
    color: #555;
    font-style: italic;
    border-top: 1px solid #ccc;
    padding-top: 12px;
    margin-top: 24px;
  }}
</style>
</head>
<body>

<div class="cover">
  <h1>Network Security Audit Report</h1>
  <div class="subtitle">PURPLE RAINMAKER — KalDel Workstation</div>
  <div class="meta">
    <strong>Prepared by:</strong> Shawn C. Tovey, RCDD<br>
    <strong>Report ID:</strong> {report_name}<br>
    <strong>Scan Started:</strong> {date_str}<br>
    <strong>Scope:</strong> Auto-detected subnet<br>
    {"<strong>Completed:</strong> " + finished + "<br>" if finished else ""}
    {"<strong>Duration:</strong> " + duration if duration else ""}
  </div>
</div>

<h2>1. Executive Summary</h2>
<p>This report presents findings from an automated network security audit conducted by KalDel, a dedicated security workstation running Kali Purple Linux. The audit performed ARP discovery, port scanning, and vulnerability assessment against the local network subnet.</p>

<div class="stat-grid">
  <div class="stat-box neutral">
    <span class="val">{host_count}{'<span style="font-size:11pt;color:#888;margin-left:6px;">(' + ('+' if diff.get('devices',0)>0 else '') + str(diff['devices']) + ')</span>' if diff.get('devices') else ''}</span>
    <span class="lbl">Live Devices</span>
  </div>
  <div class="stat-box neutral">
    <span class="val">{port_count}{'<span style="font-size:11pt;color:#888;margin-left:6px;">(' + ('+' if diff.get('ports',0)>0 else '') + str(diff['ports']) + ')</span>' if diff.get('ports') else ''}</span>
    <span class="lbl">Open Ports</span>
  </div>
  <div class="stat-box {'red' if cve_count > 0 else 'green'}">
    <span class="val">{cve_count}{'<span style="font-size:11pt;color:#888;margin-left:6px;">(' + ('+' if diff.get('cves',0)>0 else '') + str(diff['cves']) + ')</span>' if diff.get('cves') else ''}</span>
    <span class="lbl">CVEs Found</span>
  </div>
  <div class="stat-box {'red' if flag_count > 0 else 'green'}">
    <span class="val">{flag_count}{'<span style="font-size:11pt;color:#888;margin-left:6px;">(' + ('+' if diff.get('flags',0)>0 else '') + str(diff['flags']) + ')</span>' if diff.get('flags') else ''}</span>
    <span class="lbl">Flags</span>
  </div>
  <div class="stat-box {'red' if risk['level'] in ('HIGH','CRITICAL') else 'neutral' if risk['level']=='MEDIUM' else 'green'}">
    <span class="val" style="font-size:16pt;">{risk['level']}</span>
    <span class="lbl">Risk Level</span>
  </div>
</div>

<div style="margin:12px 0;padding:10px 14px;border-left:4px solid {'#cc0000' if risk['level'] in ('HIGH','CRITICAL') else '#cc8800' if risk['level']=='MEDIUM' else '#006600'};background:{'#fff5f5' if risk['level'] in ('HIGH','CRITICAL') else '#fffbf0' if risk['level']=='MEDIUM' else '#f5fff5'};">
  <strong style="font-family:'Courier New',monospace;font-size:10pt;">RISK LEVEL: {risk['level']}</strong><br>
  <span style="font-size:9pt;color:#555;">{risk['description']}</span>
  {''.join(f'<br><span style="font-size:9pt;">• {t}</span>' for t in risk['triggers'])}
</div>
<p style="font-size:8pt;color:#777;font-style:italic;">Risk Level is a triage indicator based on detected services, vulnerabilities, and inventory changes. It is not a CVSS aggregate score and should not be used as a substitute for a professional security assessment.</p>

<h2>2. Flags Requiring Attention</h2>
"""

    CRITICAL_PAT = re.compile(r'3389|RDP|VNC|telnet|port 23|port 4444|port 6667', re.I)
    MEDIUM_PAT   = re.compile(r'UNUSUAL PORT|NEW DEVICE|CVE|1080|5900|offline', re.I)

    if flags:
        for f in flags:
            txt = f.replace('[!]', '').strip()
            # Clean up "CVE CVE-XXXX" → "CVE-XXXX"
            txt = re.sub(r'^CVE\s+(CVE-)', r'\1', txt)
            if CRITICAL_PAT.search(txt):
                style = 'border-left:3px solid #cc0000;background:#fff5f5;'
                label = '🔴'
            elif MEDIUM_PAT.search(txt):
                style = 'border-left:3px solid #cc8800;background:#fffbf0;'
                label = '🟡'
            else:
                style = 'border-left:3px solid #999;background:#f9f9f9;'
                label = '⚪'
            html += f'<div class="flag-item" style="{style}">{label} {txt}</div>\n'
    else:
        html += '<div class="flag-clear">◉ ALL CLEAR — No flags raised during this audit.</div>\n'

    html += f"""
<h2>3. Device Inventory</h2>
<p>ARP scan identified <strong>{len(devices)}</strong> unique devices on the network.</p>
<table>
  <thead><tr><th>IP Address</th><th>Hostname</th><th>MAC Address</th><th>Vendor</th><th>CVEs</th></tr></thead>
  <tbody>
"""
    for d in devices:
        cves = cve_map.get(d['ip'], [])
        cve_cell = f'<span class="cve-badge">{", ".join(cves)}</span>' if cves else '—'
        hostname = hostname_map.get(d['ip'], '—')
        html += f"    <tr><td>{d['ip']}</td><td>{hostname}</td><td>{d['mac']}</td><td>{d['vendor']}</td><td>{cve_cell}</td></tr>\n"

    html += f"""  </tbody>
</table>

<h2>4. Open Ports and Services</h2>
<p>Port scanning identified <strong>{len(ports)}</strong> open TCP ports across all live hosts.</p>
<table>
  <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr></thead>
  <tbody>
"""
    for p in ports[:60]:
        html += f"    <tr><td>{p['host']}</td><td>{p['port']}/tcp</td><td>{p['service']}</td><td>{p['version'][:50]}</td></tr>\n"
    if len(ports) > 60:
        html += f"    <tr><td colspan='4' style='color:#555;font-style:italic'>... and {len(ports)-60} more. See port_scan.txt for full results.</td></tr>\n"

    html += """  </tbody>
</table>

<h2>5. Vulnerability Assessment</h2>
"""

    if cve_map:
        html += f"<p>The following <strong>{cve_count}</strong> CVE(s) were identified across <strong>{len(cve_map)}</strong> host(s). CVSS scores are sourced from the NVD API where available. Confidence reflects detection method — nmap script detections are heuristic and may include false positives.</p>\n"
        html += "<table>\n  <thead><tr><th>Host</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Confidence</th><th>Description</th></tr></thead>\n  <tbody>\n"
        for ip, cves in sorted(cve_map.items()):
            for cve in cves:
                cvss = fetch_cvss_with_cache(cve, cvss_cache)
                score  = str(cvss['score']) if cvss['score'] else 'N/A'
                sev    = cvss['severity']   if cvss['severity'] else 'N/A'
                conf   = cvss['confidence']
                desc   = cvss['description'][:80] + '...' if len(cvss['description']) > 80 else cvss['description'] or '—'
                sev_color = '#cc0000' if sev in ('HIGH','CRITICAL') else '#cc8800' if sev == 'MEDIUM' else '#555'
                html += f"    <tr><td>{ip}</td><td><span class='cve-badge'>{cve}</span></td><td>{score}</td><td style='color:{sev_color};'>{sev}</td><td>{conf}</td><td style='font-size:8pt;'>{desc}</td></tr>\n"
        html += "  </tbody>\n</table>\n"
        html += "<p>Affected hosts should be patched or mitigated per vendor guidance. Refer to <code>vuln_scan.txt</code> for full nmap script output.</p>\n"
    else:
        html += "<p>No CVEs detected during vulnerability scan.</p>\n"

    # Build context-aware recommendations
    rec_items = []

    if cve_map:
        affected = ', '.join(sorted(cve_map.keys()))
        rec_items.append(f"Patch or mitigate CVE findings on: {affected}. Refer to vendor advisories for each CVE.")

    # Detect unusual ports from flags
    unusual_ports = [f.replace('[!]','').strip() for f in flags if 'UNUSUAL PORT' in f]
    for up in unusual_ports:
        rec_items.append(f"Review service: {up} — disable if not required, or restrict with firewall rules.")

    # Detect new devices from flags
    new_dev_flags = [f for f in flags if 'NEW DEVICE' in f or 'new device' in f.lower()]
    if new_dev_flags:
        rec_items.append("New devices were detected since last baseline. Update baseline_devices.txt after verifying all devices are authorized.")

    # Detect offline devices from flags
    offline_flags = [f for f in flags if 'offline' in f.lower()]
    if offline_flags:
        rec_items.append("Devices appeared offline vs baseline. Confirm whether these are expected removals and update the baseline accordingly.")

    # Standard recommendations always included
    rec_items.append("Update baseline_devices.txt after any authorized network changes.")
    rec_items.append("Ensure all network-connected devices are running current firmware.")
    rec_items.append("Periodically review open ports and disable any unnecessary services.")

    html += """
<h2>6. Recommendations</h2>
<ul>
"""
    for item in rec_items:
        html += f"  <li>{item}</li>\n"

    html += """</ul>

<div class="disclaimer">
This audit was conducted solely against network infrastructure owned and operated by the report author.
Results reflect a point-in-time assessment and do not guarantee the absence of vulnerabilities not detected by the tools employed.
This report is intended for informational purposes and personal security awareness only.
PURPLE RAINMAKER — © 2026 Shawn C. Tovey, RCDD
</div>

</body>
</html>"""

    return html


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 generate_report.py <report_dir>")
        sys.exit(1)

    report_dir = sys.argv[1]
    if not os.path.exists(report_dir):
        print(f"Error: Report directory not found: {report_dir}")
        sys.exit(1)

    # Find previous report for differential analysis
    import glob as _glob
    reports_dir = os.path.dirname(report_dir)
    all_reports = sorted(_glob.glob(os.path.join(reports_dir, "2*")))
    prev_report_dir = None
    for r in reversed(all_reports):
        if os.path.basename(r) < os.path.basename(report_dir):
            prev_report_dir = r
            break

    report_name = os.path.basename(report_dir)
    out_pdf = os.path.join(report_dir, f"Network_Security_Audit_{report_name}.pdf")

    print(f"[*] Generating report for {report_name}...")
    if prev_report_dir:
        print(f"[*] Comparing against previous scan: {os.path.basename(prev_report_dir)}")
    html = generate_html(report_dir, prev_report_dir)

    html_path = os.path.join(report_dir, "_report_temp.html")
    with open(html_path, 'w') as f:
        f.write(html)

    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(out_pdf)
        os.remove(html_path)
        print(f"[+] PDF generated: {out_pdf}")
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        sys.exit(1)
