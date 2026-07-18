"""
Pentronix Nmap Engine — full nmap integration with real-time streaming.

Provides four scan types (quick, version, aggressive, vuln), real-time
stdout line streaming to a UI callback, structured result parsing, and
proper async subprocess management with timeout and graceful kill.
"""

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Callable, Optional

from utils.logger import get_logger

log = get_logger(__name__)

# ── Scan type definitions ─────────────────────────────────────────────────────
_SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "flags": ["-sV", "--top-ports", "1000", "--open"],
        "description": "Top 1000 ports with service version detection",
        "expected_seconds": 60,
    },
    "version": {
        "flags": ["-sV", "-sC", "--top-ports", "1000", "--open"],
        "description": "Top 1000 ports + default NSE scripts + version detection",
        "expected_seconds": 90,
    },
    "aggressive": {
        "flags": ["-A", "-T4", "--open", "-p-"],
        "description": "All ports + OS detection + version + scripts (aggressive)",
        "expected_seconds": 300,
    },
    "vuln": {
        "flags": ["-sV", "--script", "vuln", "--top-ports", "1000", "--open"],
        "description": "Vulnerability-focused script scan",
        "expected_seconds": 180,
    },
    "full": {
        "flags": ["-sV", "-sC", "-O", "-p-", "-T4", "--open"],
        "description": "Full TCP port scan with OS detection and scripts",
        "expected_seconds": 600,
    },
    "ping_sweep": {
        "flags": ["-sn", "-PE", "-PM", "-PS21,22,23,53,80,443,445,3389"],
        "description": "Ping sweep / Host discovery on subnet (no port scan)",
        "expected_seconds": 30,
    },
    "stealth": {
        "flags": ["-sS", "-T2", "--top-ports", "100", "-f"],
        "description": "Stealth SYN scan with fragmented packets and timing checks",
        "expected_seconds": 120,
    },
    "network_discovery": {
        "flags": ["-sV", "-O", "-F", "--top-ports", "100", "--open"],
        "description": "Fast network discovery of whole subnet with OS detection",
        "expected_seconds": 180,
    }
}


# ── Result structures ─────────────────────────────────────────────────────────
@dataclass
class PortInfo:
    """Single discovered open port with service metadata."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    extra: str = ""


@dataclass
class NmapResult:
    """Aggregated results from a completed nmap scan."""
    target: str
    scan_type: str
    command: str
    open_ports: list[PortInfo] = field(default_factory=list)
    os_guesses: list[str] = field(default_factory=list)
    script_results: list[dict] = field(default_factory=list)
    raw_output: str = ""
    duration_seconds: float = 0.0
    success: bool = True
    error: str = ""

    def ports_summary(self) -> str:
        """One-line human-readable open port summary."""
        if not self.open_ports:
            return "No open ports found."
        parts = [f"{p.port}/{p.protocol} ({p.service})" for p in self.open_ports[:20]]
        return ", ".join(parts)

    def to_report_dict(self) -> dict:
        """Serialise to a plain dict suitable for report generation."""
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "command": self.command,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "extra": p.extra,
                }
                for p in self.open_ports
            ],
            "os_guesses": self.os_guesses,
            "script_results": self.script_results,
            "duration_seconds": round(self.duration_seconds, 1),
            "success": self.success,
            "error": self.error,
        }


class NmapEngine:
    """Manages nmap execution with real-time streaming output.

    Usage::

        engine = NmapEngine()
        result = await engine.scan("192.168.1.1", "version", on_line=print)
    """

    def __init__(self) -> None:
        self._nmap_path = shutil.which("nmap")
        if not self._nmap_path:
            log.warning("nmap not found in PATH — scans will fail")
        self._running_process: Optional[asyncio.subprocess.Process] = None

    @property
    def available(self) -> bool:
        """Return True if nmap is installed on this system."""
        return self._nmap_path is not None

    async def scan(
        self,
        target: str,
        scan_type: str = "version",
        extra_ports: Optional[str] = None,
        timeout: int = 600,
        on_line: Optional[Callable[[str], None]] = None,
    ) -> NmapResult:
        """Run an nmap scan and stream output line by line.

        Args:
            target: IP address, domain, or CIDR range.
            scan_type: One of quick, version, aggressive, vuln, full.
            extra_ports: Optional port spec override (e.g. "22,80,443").
            timeout: Max seconds before the scan is killed.
            on_line: Callback called with each output line in real time.

        Returns:
            :class:`NmapResult` with all parsed data.
        """
        if not self.available:
            return NmapResult(
                target=target,
                scan_type=scan_type,
                command="",
                success=False,
                error="nmap is not installed. Run: sudo apt install nmap",
            )

        # Normalise target — strip URL scheme/path so "https://google.com/x" → "google.com"
        target = _normalise_target(target)

        profile = _SCAN_PROFILES.get(scan_type, _SCAN_PROFILES["version"])
        flags = list(profile["flags"])

        # Port override
        if extra_ports:
            # Remove any existing -p flag so we don't duplicate
            flags = [f for f in flags if not f.startswith("-p")]
            flags += ["-p", extra_ports]

        cmd = [self._nmap_path] + flags + [target]

        # SYN scans, OS detection, and aggressive scans need raw sockets (root).
        # Prepend sudo if available and scan type requires it.
        _needs_root = {"aggressive", "full", "vuln"}
        if scan_type in _needs_root and shutil.which("sudo"):
            cmd = ["sudo", "-n"] + cmd   # -n = non-interactive (no password prompt)

        command_str = " ".join(cmd)
        log.info("Starting nmap: %s", command_str)

        import time
        start = time.monotonic()
        raw_lines: list[str] = []

        try:
            self._running_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            # Stream stdout line by line
            assert self._running_process.stdout is not None
            async def _read_lines() -> None:
                async for raw in self._running_process.stdout:  # type: ignore[union-attr]
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    raw_lines.append(line)
                    if on_line:
                        on_line(line)

            try:
                await asyncio.wait_for(_read_lines(), timeout=timeout)
            except asyncio.TimeoutError:
                log.warning("nmap timed out after %ds — killing", timeout)
                self._running_process.kill()
                await self._running_process.wait()
                return NmapResult(
                    target=target,
                    scan_type=scan_type,
                    command=command_str,
                    raw_output="\n".join(raw_lines),
                    duration_seconds=time.monotonic() - start,
                    success=False,
                    error=f"Scan timed out after {timeout} seconds.",
                )

            await self._running_process.wait()
            duration = time.monotonic() - start

        except (OSError, PermissionError) as exc:
            log.error("nmap execution failed: %s", exc)
            return NmapResult(
                target=target,
                scan_type=scan_type,
                command=command_str,
                success=False,
                error=str(exc),
            )
        finally:
            self._running_process = None

        raw = "\n".join(raw_lines)
        parsed = _parse_nmap_output(raw)
        return NmapResult(
            target=target,
            scan_type=scan_type,
            command=command_str,
            open_ports=parsed["ports"],
            os_guesses=parsed["os_guesses"],
            script_results=parsed["scripts"],
            raw_output=raw,
            duration_seconds=duration,
            success=True,
        )

    async def stop(self) -> None:
        """Kill the currently running nmap process, if any."""
        if self._running_process and self._running_process.returncode is None:
            log.info("Stopping nmap process (pid=%d)", self._running_process.pid)
            self._running_process.terminate()
            try:
                await asyncio.wait_for(self._running_process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._running_process.kill()

    def scan_description(self, scan_type: str) -> str:
        """Return a human-readable description of the scan type."""
        return _SCAN_PROFILES.get(scan_type, {}).get("description", scan_type)

    def expected_duration(self, scan_type: str) -> int:
        """Return estimated scan duration in seconds."""
        return _SCAN_PROFILES.get(scan_type, {}).get("expected_seconds", 120)


# ── Target normaliser ────────────────────────────────────────────────────────

def _normalise_target(raw: str) -> str:
    """Strip URL scheme, path, and query string from a target string.

    Examples::

        "https://google.com/search?q=x" → "google.com"
        "http://192.168.1.1:8080/admin"  → "192.168.1.1"
        "192.168.1.0/24"                 → "192.168.1.0/24"  (unchanged)

    Args:
        raw: Raw target string from user input or LLM.

    Returns:
        Clean hostname or IP string suitable for nmap.
    """
    raw = raw.strip()
    # If it looks like a URL (has scheme), parse it properly
    if raw.startswith(("http://", "https://", "ftp://")):
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        return host.strip()
    # Strip trailing slashes / paths accidentally included
    if "/" in raw and not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", raw):
        # Not a CIDR range — take only the first segment
        return raw.split("/")[0].strip()
    return raw


# ── Output Parser ─────────────────────────────────────────────────────────────

def _parse_nmap_output(raw: str) -> dict:
    """Parse raw nmap stdout into structured data.

    Args:
        raw: Full raw nmap stdout string.

    Returns:
        Dict with keys: ports, os_guesses, scripts.
    """
    ports: list[PortInfo] = []
    os_guesses: list[str] = []
    scripts: list[dict] = []

    # Open port lines: "80/tcp   open  http    Apache httpd 2.4.41"
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*?)$",
        re.MULTILINE,
    )
    for m in port_re.finditer(raw):
        ports.append(PortInfo(
            port=int(m.group(1)),
            protocol=m.group(2),
            state=m.group(3),
            service=m.group(4),
            version=m.group(5).strip()[:120],
        ))

    # OS detection
    for m in re.finditer(r"OS details:\s*(.+)$", raw, re.MULTILINE):
        os_guesses.append(m.group(1).strip())
    # Aggressive OS guesses
    for m in re.finditer(r"Running:\s*(.+)$", raw, re.MULTILINE):
        os_guesses.append(m.group(1).strip())

    # NSE script output blocks
    script_block_re = re.compile(
        r"\|\s+([\w-]+):\s*\n((?:\|.+\n?)*)",
        re.MULTILINE,
    )
    for m in script_block_re.finditer(raw):
        scripts.append({
            "name": m.group(1),
            "output": m.group(2).strip()[:500],
        })

    return {"ports": ports, "os_guesses": os_guesses, "scripts": scripts}


# ── Singleton ─────────────────────────────────────────────────────────────────
_ENGINE: Optional[NmapEngine] = None


def get_nmap_engine() -> NmapEngine:
    """Return the global :class:`NmapEngine` singleton."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = NmapEngine()
    return _ENGINE
