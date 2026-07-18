"""
Pentronix Output Parser — tool-specific intelligence for raw command output.

Extracts structured data (ports, services, vulns, credentials, paths)
from the raw stdout of common Kali Linux tools. Each parser returns a
:class:`ParsedOutput` object consumed by the Brain for smart summarisation
and by the memory layer for persistent target intel storage.
"""

import re
from typing import Optional

from prompts.intent_schema import ParsedOutput
from utils.logger import get_logger

log = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# NMAP PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_nmap(raw: str) -> ParsedOutput:
    """Extract open ports, services, versions, and OS from nmap output."""
    ports: list[dict] = []
    services: list[dict] = []
    os_matches: list[str] = []
    script_results: list[dict] = []

    # Port/service line: "80/tcp   open  http    Apache httpd 2.4.41"
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*?)$",
        re.MULTILINE,
    )
    for m in port_re.finditer(raw):
        port_num = int(m.group(1))
        record = {
            "port": port_num,
            "protocol": m.group(2),
            "state": m.group(3),
            "service": m.group(4),
            "version": m.group(5).strip(),
        }
        ports.append(record)
        if record["state"] == "open":
            services.append(record)

    # OS detection
    os_re = re.compile(r"OS details:\s*(.+)$", re.MULTILINE)
    for m in os_re.finditer(raw):
        os_matches.append(m.group(1).strip())

    # NSE script output
    script_re = re.compile(r"\|\s+([a-z0-9_-]+):\s*(.*?)(?=\n[^\|]|\Z)", re.DOTALL)
    for m in script_re.finditer(raw):
        script_results.append({"script": m.group(1), "output": m.group(2).strip()[:500]})

    return ParsedOutput(
        tool="nmap",
        raw=raw,
        open_ports=ports,
        services=services,
        extra={
            "os_detected": os_matches[0] if os_matches else None,
            "script_results": script_results,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# NIKTO PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_nikto(raw: str) -> ParsedOutput:
    """Extract vulnerabilities and headers from nikto output."""
    vulns: list[dict] = []

    # "+ OSVDB-XXXX: ..." or "+ GET /path: ..."
    finding_re = re.compile(r"^\+\s+(OSVDB-\d+|[A-Z]+(?:-\d+)?|[A-Z]+):\s+(.+)$", re.MULTILINE)
    for m in finding_re.finditer(raw):
        identifier = m.group(1)
        description = m.group(2).strip()
        severity = "MEDIUM"
        if "allow" in description.lower() or "xss" in description.lower():
            severity = "HIGH"
        elif "info" in description.lower():
            severity = "INFO"
        vulns.append({
            "name": identifier,
            "description": description[:300],
            "severity": severity,
        })

    # Generic findings without IDs
    generic_re = re.compile(r"^\+\s+(GET|POST|HEAD|OPTIONS)\s+(.+):\s+(.+)$", re.MULTILINE)
    for m in generic_re.finditer(raw):
        vulns.append({
            "name": f"{m.group(1)} {m.group(2)}",
            "description": m.group(3).strip()[:300],
            "severity": "LOW",
        })

    return ParsedOutput(tool="nikto", raw=raw, vulnerabilities=vulns)


# ═══════════════════════════════════════════════════════════════════════════════
# GOBUSTER / DIRB PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_gobuster(raw: str) -> ParsedOutput:
    """Extract found paths with status codes from gobuster output."""
    paths: list[dict] = []

    # Gobuster: "/path  (Status: 200) [Size: 1234]"
    gobuster_re = re.compile(
        r"(/[\w/._%-]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
        re.MULTILINE,
    )
    for m in gobuster_re.finditer(raw):
        paths.append({
            "path": m.group(1),
            "status": int(m.group(2)),
            "size": int(m.group(3)) if m.group(3) else None,
        })

    # DIRB: "+ http://host/path (CODE:200|SIZE:1234)"
    dirb_re = re.compile(r"\+\s+(https?://[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)", re.MULTILINE)
    for m in dirb_re.finditer(raw):
        paths.append({
            "path": m.group(1),
            "status": int(m.group(2)),
            "size": int(m.group(3)),
        })

    return ParsedOutput(tool="gobuster", raw=raw, paths=paths)


# ═══════════════════════════════════════════════════════════════════════════════
# SQLMAP PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_sqlmap(raw: str) -> ParsedOutput:
    """Extract injection points, DB details, and dumped data from sqlmap output."""
    vulns: list[dict] = []
    extra: dict = {}

    # Injection type lines
    inj_re = re.compile(r"Type:\s+(.+)", re.MULTILINE)
    payload_re = re.compile(r"Payload:\s+(.+)", re.MULTILINE)

    inj_types = inj_re.findall(raw)
    payloads = payload_re.findall(raw)

    if inj_types:
        vulns.append({
            "name": "SQL Injection",
            "description": f"Types: {', '.join(inj_types[:3])}",
            "severity": "CRITICAL",
            "payloads": payloads[:3],
        })

    # Database detected
    db_re = re.compile(r"back-end DBMS:\s+(.+)", re.MULTILINE)
    db_match = db_re.search(raw)
    if db_match:
        extra["dbms"] = db_match.group(1).strip()

    # Databases found
    dbs_re = re.compile(r"\[\*\]\s+(\w+)$", re.MULTILINE)
    extra["databases"] = dbs_re.findall(raw)

    # Credentials / tables
    cred_re = re.compile(r"(\w+):(\$[^\s]+)", re.MULTILINE)
    credentials = [{"username": m.group(1), "hash": m.group(2)} for m in cred_re.finditer(raw)]

    return ParsedOutput(
        tool="sqlmap",
        raw=raw,
        vulnerabilities=vulns,
        credentials=credentials,
        extra=extra,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# HYDRA PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_hydra(raw: str) -> ParsedOutput:
    """Extract valid credentials from hydra output."""
    credentials: list[dict] = []

    # "[port][protocol] host: user, password: pass"
    cred_re = re.compile(
        r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
        re.MULTILINE,
    )
    for m in cred_re.finditer(raw):
        credentials.append({
            "port": int(m.group(1)),
            "protocol": m.group(2),
            "host": m.group(3),
            "username": m.group(4),
            "password": m.group(5),
        })

    return ParsedOutput(tool="hydra", raw=raw, credentials=credentials)


# ═══════════════════════════════════════════════════════════════════════════════
# ENUM4LINUX PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_enum4linux(raw: str) -> ParsedOutput:
    """Extract SMB shares, users, and policies from enum4linux output."""
    extra: dict = {"shares": [], "users": [], "policies": []}
    vulns: list[dict] = []

    # Shares: "//TARGET/SHARE  Mapping: OK Listing: OK"
    share_re = re.compile(r"//[\d.]+/(\S+)\s+Mapping:\s+(\w+)", re.MULTILINE)
    for m in share_re.finditer(raw):
        extra["shares"].append({"name": m.group(1), "accessible": m.group(2) == "OK"})

    # Users
    user_re = re.compile(r"user:\[(\S+)\]\s+rid:\[(\S+)\]", re.MULTILINE)
    for m in user_re.finditer(raw):
        extra["users"].append({"username": m.group(1), "rid": m.group(2)})

    # Anonymous login
    if "anonymous login successful" in raw.lower():
        vulns.append({
            "name": "Anonymous SMB Login",
            "description": "SMB allows anonymous (null session) authentication.",
            "severity": "HIGH",
        })

    return ParsedOutput(tool="enum4linux", raw=raw, vulnerabilities=vulns, extra=extra)


# ═══════════════════════════════════════════════════════════════════════════════
# SEARCHSPLOIT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_searchsploit(raw: str) -> ParsedOutput:
    """Extract matching exploits with EDB IDs from searchsploit output."""
    exploits: list[dict] = []

    # "  Title                              | Path"
    # "  Apache 2.4.41 - RCE               | exploits/linux/remote/12345.py"
    row_re = re.compile(r"^\s{1,4}(.+?)\s{2,}\|\s+(exploits/.+?)\s*$", re.MULTILINE)
    for m in row_re.finditer(raw):
        title = m.group(1).strip()
        path = m.group(2).strip()
        edb_id_match = re.search(r"(\d+)\.\w+$", path)
        exploits.append({
            "title": title,
            "path": path,
            "edb_id": int(edb_id_match.group(1)) if edb_id_match else None,
        })

    return ParsedOutput(tool="searchsploit", raw=raw, exploits=exploits)


# ═══════════════════════════════════════════════════════════════════════════════
# GENERIC / FFUF / WHATWEB PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_generic(tool: str, raw: str) -> ParsedOutput:
    """Fallback parser that returns raw output for AI interpretation."""
    return ParsedOutput(tool=tool, raw=raw)


# ═══════════════════════════════════════════════════════════════════════════════
# DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════

_PARSERS = {
    "nmap":          _parse_nmap,
    "nikto":         _parse_nikto,
    "gobuster":      _parse_gobuster,
    "dirb":          _parse_gobuster,   # Same format
    "ffuf":          _parse_gobuster,   # Similar format
    "sqlmap":        _parse_sqlmap,
    "hydra":         _parse_hydra,
    "enum4linux":    _parse_enum4linux,
    "searchsploit":  _parse_searchsploit,
}


def parse_output(tool: str, raw: str) -> ParsedOutput:
    """Parse raw tool output using the appropriate specialised parser.

    Falls back to the generic parser for unknown tools, which passes
    raw output to the Brain for AI-based interpretation.

    Args:
        tool: Name of the tool that produced the output.
        raw: Full raw stdout + stderr captured from the tool.

    Returns:
        :class:`ParsedOutput` with structured data extracted.
    """
    tool_key = tool.lower().strip()
    parser = _PARSERS.get(tool_key, lambda t, r: _parse_generic(t, r))
    try:
        if parser is _parse_generic:
            result = parser(tool_key, raw)
        else:
            result = parser(raw)
        log.debug(
            "Parsed %s output: %d ports, %d vulns, %d creds, %d paths, %d exploits",
            tool,
            len(result.open_ports),
            len(result.vulnerabilities),
            len(result.credentials),
            len(result.paths),
            len(result.exploits),
        )
        return result
    except Exception as exc:  # noqa: BLE001
        log.error("Error parsing %s output: %s", tool, exc)
        return ParsedOutput(tool=tool, raw=raw)
