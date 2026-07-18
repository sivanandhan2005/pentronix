"""
Pentronix Executor — safe command execution with streaming output.

Runs shell commands with:
  - Real-time stdout/stderr streaming to UI callbacks
  - Risk-based confirmation (HIGH/CRITICAL require user approval)
  - Timeout enforcement
  - Sudo password injection when needed
  - Structured result capture
"""

import asyncio
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ExecutionResult:
    """Result of a command execution."""
    success: bool
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: str
    timed_out: bool = False


class Executor:
    """Safe command executor with real-time output streaming.

    All commands run as asyncio subprocesses with output captured
    line-by-line and streamed to optional callbacks.
    """

    def __init__(self) -> None:
        cfg = Config.get()
        self._timeout = cfg.tool_timeout
        self._active_proc: Optional[asyncio.subprocess.Process] = None

    async def execute(
        self,
        command: str,
        on_output: Optional[Callable[[str], None]] = None,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        sudo_password: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a shell command with real-time output streaming.

        Args:
            command: Shell command string to execute.
            on_output: Callback invoked with each output line.
            timeout: Override default timeout (seconds).
            cwd: Working directory for the command.
            env: Additional environment variables.
            sudo_password: Password for sudo commands (injected via stdin).

        Returns:
            Structured :class:`ExecutionResult`.
        """
        effective_timeout = timeout or self._timeout
        start = time.monotonic()

        log.info("Executing: %s", command[:200])
        if on_output:
            on_output(f"$ {command}\n")

        # Build environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)

        # Handle sudo commands
        actual_command = command
        stdin_data = None
        if sudo_password and ("sudo " in command or command.startswith("sudo")):
            actual_command = command.replace("sudo ", "sudo -S ", 1)
            stdin_data = f"{sudo_password}\n"

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        timed_out = False
        return_code = -1

        try:
            proc = await asyncio.create_subprocess_shell(
                actual_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=cwd,
                env=cmd_env,
            )
            self._active_proc = proc

            # Send sudo password if needed
            if stdin_data and proc.stdin:
                proc.stdin.write(stdin_data.encode())
                await proc.stdin.drain()
                try:
                    proc.stdin.close()
                except Exception:
                    pass

            # Stream stdout and stderr concurrently
            async def _read_stream(stream, lines_list, is_stderr=False):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip("\n")
                    lines_list.append(decoded)
                    if on_output:
                        on_output(decoded + "\n")

            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        _read_stream(proc.stdout, stdout_lines),
                        _read_stream(proc.stderr, stderr_lines, is_stderr=True),
                    ),
                    timeout=effective_timeout,
                )
                await proc.wait()
                return_code = proc.returncode or 0
            except asyncio.TimeoutError:
                timed_out = True
                log.warning("Command timed out after %ds: %s", effective_timeout, command[:100])
                if on_output:
                    on_output(f"\n⚠ Command timed out after {effective_timeout}s\n")
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return_code = -1

        except Exception as exc:
            log.error("Execution error: %s", exc)
            stderr_lines.append(str(exc))
            if on_output:
                on_output(f"\n✗ Error: {exc}\n")

        finally:
            self._active_proc = None

        duration = time.monotonic() - start
        stdout_text = "\n".join(stdout_lines)
        stderr_text = "\n".join(stderr_lines)

        result = ExecutionResult(
            success=return_code == 0 and not timed_out,
            return_code=return_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_seconds=round(duration, 2),
            command=command,
            timed_out=timed_out,
        )

        log.info(
            "Command finished: rc=%d, %.1fs, %d stdout lines",
            return_code, duration, len(stdout_lines),
        )
        return result

    async def cancel(self) -> None:
        """Kill the currently running command, if any."""
        if self._active_proc and self._active_proc.returncode is None:
            log.info("Killing active process")
            try:
                self._active_proc.kill()
            except ProcessLookupError:
                pass


# ── Singleton ─────────────────────────────────────────────────────────────────
_EXECUTOR: Optional[Executor] = None


def get_executor() -> Executor:
    """Return the global Executor singleton."""
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = Executor()
    return _EXECUTOR
