"""
Pentronix Report Generator — professional penetration testing HTML report.

Generates a self-contained, single-file HTML report with:
  - What process was run (scan/exploit), why and how
  - All findings: open ports, services, versions
  - Risk level per finding (CRITICAL / HIGH / MEDIUM / LOW / INFO)
  - What was found and what it means
  - How to fix it — specific remediation steps
  - Overall recommendations
  - Raw output logs
"""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)

_REPORTS_DIR = Path(__file__).parent.parent / "data" / "reports"

# ── Service-level risk knowledge base ─────────────────────────────────────────
# Maps common service names to (risk_level, what_it_means, how_to_fix)
_SERVICE_RISK: dict[str, tuple[str, str, str]] = {
    "ftp": (
        "HIGH",
        "FTP transmits data and credentials in plaintext. Anonymous access is often enabled by default.",
        "Replace FTP with SFTP or FTPS. Disable anonymous login. Enforce strong passwords and use key-based auth.",
    ),
    "telnet": (
        "CRITICAL",
        "Telnet sends all data including passwords in clear text — trivially intercepted.",
        "Immediately disable Telnet. Replace with SSH. Block port 23 at the firewall.",
    ),
    "ssh": (
        "MEDIUM",
        "SSH is secure but older versions or weak configs can expose the system.",
        "Use SSH v2 only. Disable root login (PermitRootLogin no). Use key-based auth. Restrict to specific IPs.",
    ),
    "http": (
        "HIGH",
        "Unencrypted HTTP exposes all traffic. Web services often have vulnerabilities (SQLi, XSS, RCE).",
        "Force HTTPS (redirect all HTTP to port 443). Install a valid TLS certificate. Apply WAF rules.",
    ),
    "https": (
        "LOW",
        "HTTPS encrypts traffic but the underlying web app may still have vulnerabilities.",
        "Keep TLS/SSL libraries updated. Disable SSLv3/TLS 1.0/1.1. Enable HSTS. Run a web app vulnerability scan.",
    ),
    "smb": (
        "CRITICAL",
        "SMB is a primary attack vector (EternalBlue/MS17-010, ransomware lateral movement).",
        "Patch immediately (MS17-010 / KB4012212). Block SMB (445/TCP) at firewall perimeter. Disable SMBv1.",
    ),
    "rdp": (
        "CRITICAL",
        "RDP is heavily targeted by brute-force, BlueKeep (CVE-2019-0708), and ransomware operators.",
        "Apply BlueKeep patch (KB4499175). Use NLA. Restrict access via VPN/firewall. Enable account lockout.",
    ),
    "mysql": (
        "HIGH",
        "MySQL exposed to network allows credential brute-force and direct data exfiltration.",
        "Bind MySQL to 127.0.0.1 only. Never expose port 3306 externally. Use strong unique passwords.",
    ),
    "mssql": (
        "HIGH",
        "MSSQL may allow xp_cmdshell for OS command execution if misconfigured.",
        "Disable xp_cmdshell. Restrict network access. Use Windows Authentication. Apply all patches.",
    ),
    "postgresql": (
        "HIGH",
        "PostgreSQL exposed externally may allow unauthenticated access or data leakage.",
        "Bind to localhost. Use pg_hba.conf to restrict access. Enforce strong passwords.",
    ),
    "mongo": (
        "CRITICAL",
        "MongoDB is frequently found exposed without authentication, leaking entire databases.",
        "Enable MongoDB authentication. Bind to 127.0.0.1. Review MongoDB security checklist.",
    ),
    "redis": (
        "CRITICAL",
        "Redis has no authentication by default — allows arbitrary command execution.",
        "Enable requirepass in redis.conf. Bind to 127.0.0.1. Use renamed dangerous commands.",
    ),
    "vnc": (
        "HIGH",
        "VNC provides graphical remote access and is often poorly secured.",
        "Use VPN instead of exposing VNC. Enable strong VNC password. Use SSH tunneling for VNC connections.",
    ),
    "smtp": (
        "MEDIUM",
        "Open SMTP relay can be abused for spam and phishing campaigns.",
        "Disable open relay. Implement SPF, DKIM, DMARC. Require authentication for mail submission.",
    ),
    "dns": (
        "MEDIUM",
        "DNS zone transfers and cache poisoning can expose internal infrastructure.",
        "Restrict zone transfers to authorised servers only. Enable DNSSEC.",
    ),
    "snmp": (
        "HIGH",
        "SNMP v1/v2c uses community strings (default 'public') — exposes device config.",
        "Upgrade to SNMPv3 with authentication. Change default community strings. Firewall SNMP (UDP 161).",
    ),
    "ldap": (
        "HIGH",
        "LDAP without TLS exposes directory data including user accounts.",
        "Use LDAPS (port 636). Restrict anonymous binds. Apply least-privilege on directory objects.",
    ),
}

_RISK_COLOUR = {
    "CRITICAL": ("#ff3355", "rgba(255,51,85,.15)"),
    "HIGH":     ("#ff8c00", "rgba(255,140,0,.12)"),
    "MEDIUM":   ("#ffaa00", "rgba(255,170,0,.10)"),
    "LOW":      ("#00ccff", "rgba(0,204,255,.08)"),
    "INFO":     ("#888",    "rgba(136,136,136,.07)"),
}

_RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ── HTML template ──────────────────────────────────────────────────────────────
_CSS = """
:root {
  --bg:#0a0a0f;--surface:#10101a;--border:#1e1e2e;
  --green:#00ff88;--cyan:#00ccff;--amber:#ffaa00;
  --red:#ff3355;--orange:#ff8c00;--text:#e0e0e0;--muted:#666;
  --font:'Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;
     padding:32px;max-width:1100px;margin:auto;line-height:1.6}
a{color:var(--cyan)}
h1{font-size:2rem;color:var(--green);border-bottom:2px solid var(--green);
   padding-bottom:12px;margin-bottom:6px;
   text-shadow:0 0 14px rgba(0,255,136,.35)}
h2{font-size:1.15rem;color:var(--cyan);margin:32px 0 10px;
   border-left:3px solid var(--cyan);padding-left:10px}
h3{font-size:.95rem;color:var(--amber);margin:20px 0 8px}
.meta{color:var(--muted);font-size:.85rem;margin-bottom:28px}
.meta span{color:var(--green)}
/* ── Summary cards ── */
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
.card{flex:1;min-width:130px;background:var(--surface);
      border:1px solid var(--border);border-radius:8px;
      padding:16px;text-align:center}
.card .num{font-size:2rem;font-weight:bold;line-height:1.2}
.card .lbl{font-size:.78rem;color:var(--muted);margin-top:4px}
/* ── Risk badge ── */
.badge{display:inline-block;padding:3px 10px;border-radius:4px;
       font-size:.75rem;font-weight:bold;font-family:var(--font);
       letter-spacing:.06em;vertical-align:middle}
.CRITICAL{background:rgba(255,51,85,.18);color:#ff3355;border:1px solid #ff3355}
.HIGH    {background:rgba(255,140,0,.15);color:#ff8c00;border:1px solid #ff8c00}
.MEDIUM  {background:rgba(255,170,0,.15);color:#ffaa00;border:1px solid #ffaa00}
.LOW     {background:rgba(0,204,255,.12);color:#00ccff;border:1px solid #00ccff}
.INFO    {background:rgba(136,136,136,.12);color:#aaa;border:1px solid #555}
/* ── Finding cards ── */
.finding{margin:18px 0;border-radius:8px;border:1px solid var(--border);
         overflow:hidden}
.finding-header{display:flex;align-items:center;gap:12px;
                padding:12px 16px;border-bottom:1px solid var(--border)}
.finding-body{padding:14px 18px}
.finding-body p{margin:6px 0;font-size:.88rem}
.label{color:var(--muted);font-size:.78rem;margin-bottom:4px}
/* ── Tables ── */
table{width:100%;border-collapse:collapse;background:var(--surface);
      border:1px solid var(--border);border-radius:6px;
      overflow:hidden;margin:14px 0;font-size:.85rem}
th{background:#0c0c18;color:var(--cyan);text-align:left;
   padding:10px 14px;border-bottom:1px solid var(--border)}
td{padding:9px 14px;border-bottom:1px solid var(--border);
   font-family:var(--font)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,204,255,.04)}
.port-n{color:var(--green);font-weight:bold}
.svc   {color:var(--cyan)}
.ver   {color:var(--muted);font-size:.8rem}
/* ── Info boxes ── */
.box{background:var(--surface);border:1px solid var(--border);
     border-radius:6px;padding:14px 18px;margin:12px 0;font-size:.88rem}
.box.green{border-left:4px solid var(--green)}
.box.amber{border-left:4px solid var(--amber)}
.box.red  {border-left:4px solid var(--red)}
.cmd{background:#05050d;border:1px solid var(--border);border-radius:4px;
     padding:10px 14px;font-family:var(--font);font-size:.8rem;
     color:var(--green);margin:10px 0;overflow-x:auto;white-space:pre}
.raw{background:#05050d;border:1px solid var(--border);border-radius:4px;
     padding:12px 16px;font-family:var(--font);font-size:.77rem;
     color:#aaa;overflow:auto;max-height:380px;white-space:pre;margin:10px 0}
ul.recs{margin:10px 0 10px 18px}
ul.recs li{margin:4px 0;font-size:.87rem}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);
       color:var(--muted);font-size:.78rem;text-align:center}
.toc{background:var(--surface);border:1px solid var(--border);
     border-radius:6px;padding:14px 20px;margin:20px 0}
.toc a{display:block;padding:3px 0;font-size:.88rem;color:var(--cyan)}
"""

_HTML_SHELL = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentronix Report — {target}</title>
<style>{css}</style>
</head>
<body>
<h1>🔒 Pentronix Penetration Test Report</h1>
<div class="meta">
  Target: <span>{target}</span> &nbsp;|&nbsp;
  Generated: <span>{timestamp}</span> &nbsp;|&nbsp;
  Tool: <span>Pentronix AI</span>
</div>

{toc}
{overview}
{scan_process}
{findings}
{exploit_section}
{recommendations}
{raw_section}

<footer>
  Generated by Pentronix — AI-Powered Pentesting Platform &nbsp;|&nbsp;
  <strong style="color:#ff3355">For authorised and educational use only.</strong>
  Handle this report with care.
</footer>
</body>
</html>
"""


# ── Public class ───────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generates comprehensive HTML penetration testing reports."""

    def __init__(self) -> None:
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        target: str,
        scan_result=None,       # NmapResult | None
        exploit_results=None,   # list[MsfResult] | None
        ai_summary: str = "",
    ) -> Path:
        """Build and write the full HTML report. Returns the file path."""
        exploit_results = exploit_results or []
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        slug = target.replace("/", "_").replace(".", "-")
        ts_slug = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = _REPORTS_DIR / f"report_{slug}_{ts_slug}.html"

        findings = self._classify_findings(scan_result)
        sessions = sum(len(r.sessions_opened) for r in exploit_results)
        severity = self._overall_severity(findings, sessions, exploit_results)

        content = _HTML_SHELL.format(
            css=_CSS,
            target=html.escape(target),
            timestamp=timestamp,
            toc=self._build_toc(scan_result, exploit_results),
            overview=self._build_overview(target, findings, sessions, severity, ai_summary, scan_result, exploit_results),
            scan_process=self._build_scan_process(scan_result),
            findings=self._build_findings(findings, scan_result),
            exploit_section=self._build_exploit_section(exploit_results),
            recommendations=self._build_recommendations(findings, exploit_results),
            raw_section=self._build_raw(scan_result, exploit_results),
        )

        out_path.write_text(content, encoding="utf-8")
        log.info("Report written: %s", out_path)
        return out_path

    def open_in_browser(self, path: Path) -> None:
        import webbrowser
        webbrowser.open(f"file://{path.resolve()}", new=2)

    # ── Section builders ──────────────────────────────────────────────────────

    def _build_toc(self, scan_result, exploit_results: list) -> str:
        links = [
            '<div class="toc"><strong style="color:var(--cyan)">Contents</strong>',
            '<a href="#overview">1. Overview &amp; Risk Summary</a>',
            '<a href="#process">2. Scan Process &amp; Methodology</a>',
            '<a href="#findings">3. Findings &amp; Vulnerability Analysis</a>',
        ]
        if exploit_results:
            links.append('<a href="#exploitation">4. Exploitation Results</a>')
        links.append('<a href="#recommendations">5. Recommendations</a>')
        links.append('<a href="#raw">6. Raw Tool Output</a>')
        links.append("</div>")
        return "\n".join(links)

    def _build_overview(self, target, findings, sessions, severity, ai_summary, scan_result, exploit_results) -> str:
        port_count = len(scan_result.open_ports) if scan_result else 0
        crit = sum(1 for f in findings if f["risk"] == "CRITICAL")
        high = sum(1 for f in findings if f["risk"] == "HIGH")
        med  = sum(1 for f in findings if f["risk"] == "MEDIUM")
        low  = sum(1 for f in findings if f["risk"] in ("LOW", "INFO"))

        badge = f'<span class="badge {severity}">{severity}</span>'
        summary = ai_summary or (
            f"Pentronix conducted an automated security assessment against <strong>{html.escape(target)}</strong>. "
            f"{'The port scan identified ' + str(port_count) + ' open port(s). ' if scan_result else ''}"
            f"{'Vulnerability analysis found <strong>' + str(crit + high) + ' high-severity finding(s)</strong>. ' if (crit + high) > 0 else ''}"
            f"{'Metasploit exploitation resulted in <strong>' + str(sessions) + ' active session(s)</strong>.' if sessions else ''}"
        )

        return f"""
<h2 id="overview">1. Overview &amp; Risk Summary</h2>
<div class="box green">
  <p>Overall Risk: {badge} &nbsp;&nbsp;
     <span style="color:var(--green)">Open Ports: {port_count}</span> &nbsp;&nbsp;
     <span style="color:#ff8c00">Critical: {crit}</span> &nbsp;&nbsp;
     <span style="color:#ffaa00">High: {high}</span> &nbsp;&nbsp;
     <span style="color:#00ccff">Medium: {med}</span> &nbsp;&nbsp;
     <span style="color:var(--muted)">Low/Info: {low}</span>
  </p>
</div>
<div class="cards">
  <div class="card"><div class="num" style="color:var(--green)">{port_count}</div><div class="lbl">Open Ports</div></div>
  <div class="card"><div class="num" style="color:#ff3355">{crit}</div><div class="lbl">Critical Findings</div></div>
  <div class="card"><div class="num" style="color:#ff8c00">{high}</div><div class="lbl">High Findings</div></div>
  <div class="card"><div class="num" style="color:#00ccff">{med}</div><div class="lbl">Medium Findings</div></div>
  <div class="card"><div class="num" style="color:{'#ff3355' if sessions else 'var(--muted)'}">{sessions}</div><div class="lbl">Active Sessions</div></div>
</div>
<p style="font-size:.9rem;margin-top:10px">{summary}</p>
"""

    def _build_scan_process(self, scan_result) -> str:
        if not scan_result:
            return "<h2 id='process'>2. Scan Process</h2><p style='color:var(--muted)'>No scan data.</p>"

        profile_why = {
            "quick":      "A quick scan checks the most common 1000 ports and identifies running services rapidly. Used to get a fast overview of the target's attack surface.",
            "version":    "A version scan identifies services and their exact version numbers — critical for finding known CVEs and unpatched software.",
            "aggressive": "An aggressive scan combines OS fingerprinting, service version detection, default NSE scripts, and full port coverage. Provides the most complete picture.",
            "vuln":       "A vulnerability scan runs Nmap's NSE vulnerability scripts to actively probe for known CVEs and misconfigurations.",
            "full":       "A full TCP scan covers all 65535 ports with service/OS detection — finds services running on non-standard ports.",
        }
        why = profile_why.get(scan_result.scan_type, "Standard service detection scan.")
        duration = f"{scan_result.duration_seconds:.1f}s"

        os_section = ""
        if scan_result.os_guesses:
            os_section = f"<p><strong>OS Detection:</strong> {html.escape(scan_result.os_guesses[0])}</p>"

        return f"""
<h2 id="process">2. Scan Process &amp; Methodology</h2>
<div class="box amber">
  <p><strong>What was run:</strong> Nmap {html.escape(scan_result.scan_type)} scan against <code>{html.escape(scan_result.target)}</code></p>
  <p><strong>Why:</strong> {why}</p>
  <p><strong>How:</strong> Nmap sent TCP probe packets and analysed responses to identify open ports, service banners, and version strings. NSE scripts were used for deeper service interrogation where applicable.</p>
  <p><strong>Duration:</strong> {duration}</p>
  {os_section}
</div>
<div class="label" style="margin-top:12px">Command executed:</div>
<div class="cmd">$ {html.escape(scan_result.command)}</div>
"""

    def _build_findings(self, findings: list, scan_result) -> str:
        if not findings:
            none_msg = "<p style='color:var(--muted)'>No open ports found on the target.</p>"
            if scan_result and scan_result.error:
                none_msg = f"<p style='color:#ff3355'>Scan error: {html.escape(scan_result.error)}</p>"
            return f"<h2 id='findings'>3. Findings</h2>{none_msg}"

        # Port table
        rows = ""
        for f in findings:
            badge = f'<span class="badge {f["risk"]}">{f["risk"]}</span>'
            rows += f"""
<tr>
  <td class="port-n">{f['port']}/{f['protocol']}</td>
  <td class="svc">{html.escape(f['service'])}</td>
  <td class="ver">{html.escape(f['version'][:60]) if f['version'] else '—'}</td>
  <td>{badge}</td>
</tr>"""

        table = f"""
<table>
  <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

        # Detailed finding cards grouped by risk
        detail_html = "<h3>Detailed Finding Analysis</h3>"
        for risk in _RISK_ORDER:
            risk_findings = [f for f in findings if f["risk"] == risk]
            for f in risk_findings:
                col, bg = _RISK_COLOUR.get(risk, ("#888", "rgba(136,136,136,.07)"))
                what = html.escape(f["what"])
                fix  = html.escape(f["fix"])
                svc  = html.escape(f["service"])
                ver  = html.escape(f["version"]) if f["version"] else "Unknown"
                detail_html += f"""
<div class="finding" style="border-color:{col};background:{bg}">
  <div class="finding-header" style="background:{bg}">
    <span class="badge {risk}">{risk}</span>
    <span style="color:{col};font-weight:bold;font-family:var(--font)">Port {f['port']}/{f['protocol']} — {svc}</span>
    <span style="color:var(--muted);font-size:.8rem;margin-left:auto">{ver}</span>
  </div>
  <div class="finding-body">
    <p><span class="label">🔍 What was found:</span> <strong>{svc}</strong> is running on port {f['port']}.</p>
    <p><span class="label">⚠ What this means:</span> {what}</p>
    <p class="label" style="margin-top:12px">🔧 How to fix it (Remediation):</p>
    <div class="box green" style="margin-top:6px;padding:10px 14px">{fix}</div>
  </div>
</div>"""

        # NSE script results
        script_html = ""
        if scan_result and scan_result.script_results:
            script_html = "<h3>NSE Script Findings</h3>"
            for s in scan_result.script_results[:15]:
                script_html += f"""
<div class="box" style="margin:8px 0">
  <p><strong style="color:var(--amber)">{html.escape(s['name'])}</strong></p>
  <pre style="font-size:.78rem;color:#aaa;white-space:pre-wrap;margin-top:6px">{html.escape(s['output'][:600])}</pre>
</div>"""

        return f"""
<h2 id="findings">3. Findings &amp; Vulnerability Analysis</h2>
<p style="font-size:.88rem;margin-bottom:14px">
  The following open ports and services were discovered on the target.
  Each finding is classified by risk level based on the service type,
  known CVEs, and common attack patterns.
</p>
{table}
{detail_html}
{script_html}
"""

    def _build_exploit_section(self, exploit_results: list) -> str:
        if not exploit_results:
            return ""

        blocks = "<h2 id='exploitation'>4. Exploitation Results</h2>"
        for r in exploit_results:
            status_c = "#00ff88" if r.success else "#ffaa00"
            status_t = "✓ SUCCESS — Session established" if r.success else "✗ No session created"
            sessions_html = ""
            for s in r.sessions_opened:
                sessions_html += f"""
<div class="box green">
  🔓 <strong>Session {s.get('id','?')} opened</strong> — {html.escape(s.get('connection',''))}
  {' [' + s.get('type','meterpreter') + ']' if 'type' in s else ''}
</div>"""
            error_html = f"<p style='color:#ff3355;font-size:.85rem'>Error: {html.escape(r.error)}</p>" if r.error else ""
            blocks += f"""
<div class="box" style="margin:16px 0">
  <p><strong style="color:var(--cyan)">{html.escape(r.module)}</strong>
     &nbsp; <span style="color:{status_c};font-weight:bold">{status_t}</span></p>
  <div class="cmd">$ {html.escape(r.command[:300])}</div>
  {sessions_html}
  {error_html}
  <p style="color:var(--muted);font-size:.8rem;margin-top:8px">Duration: {r.duration_seconds:.1f}s</p>
</div>"""

        return blocks

    def _build_recommendations(self, findings: list, exploit_results: list) -> str:
        recs = []

        # Priority recs based on findings
        critical_svcs = [f["service"] for f in findings if f["risk"] == "CRITICAL"]
        high_svcs     = [f["service"] for f in findings if f["risk"] == "HIGH"]

        if "telnet" in critical_svcs:
            recs.append("🚨 <strong>CRITICAL:</strong> Disable Telnet immediately — replace with SSH.")
        if "smb" in critical_svcs:
            recs.append("🚨 <strong>CRITICAL:</strong> Patch SMB (EternalBlue/MS17-010). Disable SMBv1. Block port 445 at perimeter.")
        if "rdp" in critical_svcs:
            recs.append("🚨 <strong>CRITICAL:</strong> Restrict RDP access — use VPN + NLA. Apply BlueKeep patch.")
        if any(s in critical_svcs for s in ["mongo", "redis"]):
            recs.append("🚨 <strong>CRITICAL:</strong> Exposed NoSQL databases found — enable authentication immediately.")
        if "ftp" in high_svcs or "ftp" in critical_svcs:
            recs.append("⚠ <strong>HIGH:</strong> Replace FTP with SFTP. Disable anonymous access.")
        if "http" in high_svcs:
            recs.append("⚠ <strong>HIGH:</strong> Force HTTPS on all web services. Install valid TLS certificate.")
        if any(s in high_svcs for s in ["mysql", "mssql", "postgresql"]):
            recs.append("⚠ <strong>HIGH:</strong> Database ports exposed — restrict to localhost only. Never expose databases to network.")

        # Session-opened extra recs
        if any(r.sessions_opened for r in exploit_results):
            recs.insert(0, "🚨 <strong>IMMEDIATE ACTION:</strong> Active exploitation succeeded — isolate the target machine now.")

        # General recs always added
        general = [
            "🔒 Apply all pending OS and application security updates.",
            "🛡 Implement a Host-based Firewall (UFW/iptables) with default-deny rules.",
            "👁 Deploy an Intrusion Detection System (IDS/IPS) — e.g., Snort, Suricata.",
            "🔑 Enable multi-factor authentication (MFA) on all remotely accessible services.",
            "📋 Conduct regular penetration testing (quarterly recommended).",
            "📊 Review and segment the network — use VLANs to isolate sensitive services.",
            "🗂 Maintain a vulnerability management programme — track and remediate findings within SLAs.",
        ]
        recs.extend(general)

        li_items = "".join(f"<li>{r}</li>" for r in recs)
        return f"""
<h2 id="recommendations">5. Recommendations</h2>
<div class="box amber">
  <p><strong>Priority Actions (address in order):</strong></p>
  <ul class="recs">
    {li_items}
  </ul>
</div>
"""

    def _build_raw(self, scan_result, exploit_results: list) -> str:
        parts = ["<h2 id='raw'>6. Raw Tool Output</h2>"]
        if scan_result and scan_result.raw_output:
            parts.append(f"<h3>Nmap Raw Output</h3><div class='raw'>{html.escape(scan_result.raw_output[:12000])}</div>")
        for r in exploit_results:
            if r.raw_output:
                parts.append(f"<h3>Metasploit — {html.escape(r.module)}</h3><div class='raw'>{html.escape(r.raw_output[:6000])}</div>")
        if len(parts) == 1:
            parts.append("<p style='color:var(--muted)'>No raw output available.</p>")
        return "\n".join(parts)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _classify_findings(self, scan_result) -> list[dict]:
        """Classify each open port with risk level, what-it-means, and fix."""
        if not scan_result:
            return []
        findings = []
        for p in scan_result.open_ports:
            svc = p.service.lower().rstrip("?")
            # Look up by service name or partial match
            kb = None
            for key in _SERVICE_RISK:
                if key in svc:
                    kb = _SERVICE_RISK[key]
                    break
            if not kb:
                # Port-based fallback
                port_risk = {
                    23: _SERVICE_RISK["telnet"],
                    21: _SERVICE_RISK["ftp"],
                    445: _SERVICE_RISK["smb"],
                    3389: _SERVICE_RISK["rdp"],
                    27017: _SERVICE_RISK["mongo"],
                    6379: _SERVICE_RISK["redis"],
                    3306: _SERVICE_RISK["mysql"],
                    5432: _SERVICE_RISK["postgresql"],
                }
                kb = port_risk.get(p.port)

            if kb:
                risk, what, fix = kb
            else:
                risk = "INFO"
                what = f"Service '{p.service}' is accessible on this port. Review if this port should be publicly reachable."
                fix  = "Close unused ports. Verify this service is intentionally exposed. Apply vendor security hardening guide."

            findings.append({
                "port": p.port,
                "protocol": p.protocol,
                "service": p.service,
                "version": p.version,
                "risk": risk,
                "what": what,
                "fix": fix,
            })
        # Sort by risk severity
        order = {r: i for i, r in enumerate(_RISK_ORDER)}
        findings.sort(key=lambda f: order.get(f["risk"], 99))
        return findings

    def _overall_severity(self, findings, sessions, exploit_results) -> str:
        if sessions or any(r.success for r in exploit_results):
            return "CRITICAL"
        for level in _RISK_ORDER:
            if any(f["risk"] == level for f in findings):
                return level
        return "INFO"


# ── Singleton ─────────────────────────────────────────────────────────────────
_GENERATOR: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """Return the global ReportGenerator singleton."""
    global _GENERATOR
    if _GENERATOR is None:
        _GENERATOR = ReportGenerator()
    return _GENERATOR
