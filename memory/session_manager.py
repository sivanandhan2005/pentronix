"""
Pentronix Session Manager — tracks the active pentesting session.

Maintains a single active session per process: its UUID, target,
start time, and accumulated state. Provides the session context
string injected into every LLM call.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass
class ActiveSession:
    """In-memory representation of the currently active pentesting session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: datetime = field(default_factory=_utcnow)
    target: Optional[str] = None
    command_count: int = 0
    tools_used: list[str] = field(default_factory=list)
    last_output: str = ""
    last_summary: str = ""
    last_intent: str = ""
    notes: list[str] = field(default_factory=list)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def set_target(self, target: str) -> None:
        """Update the active target for this session.

        Args:
            target: IP address or domain discovered from user input.
        """
        if self.target != target:
            log.info("Session target updated: %s → %s", self.target, target)
        self.target = target

    def record_tool_use(self, tool: str) -> None:
        """Track that a tool was used so the context string stays accurate."""
        if tool and tool not in self.tools_used:
            self.tools_used.append(tool)

    def increment_commands(self) -> None:
        """Increment the command counter."""
        self.command_count += 1

    def store_output(self, output: str, summary: str, intent: str) -> None:
        """Cache the most recent tool output and AI summary.

        Args:
            output: Raw tool stdout.
            summary: AI-generated summary.
            intent: Intent string of the command that produced this output.
        """
        self.last_output = output[:10_000]   # Cap to avoid memory bloat
        self.last_summary = summary
        self.last_intent = intent

    def add_note(self, note: str) -> None:
        """Append an analyst note to the session."""
        self.notes.append(f"[{_utcnow().strftime('%H:%M:%S')}] {note}")

    def uptime_str(self) -> str:
        """Return a human-readable session uptime string."""
        delta = _utcnow() - self.start_time
        total_secs = int(delta.total_seconds())
        hours, rem = divmod(total_secs, 3600)
        mins, secs = divmod(rem, 60)
        if hours:
            return f"{hours}h {mins}m {secs}s"
        if mins:
            return f"{mins}m {secs}s"
        return f"{secs}s"

    def to_context_string(self) -> str:
        """Build a compact context string for LLM injection.

        Returns:
            Formatted multi-line string describing the current session.
        """
        lines = [
            f"Session ID: {self.session_id[:8]}…",
            f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC  "
            f"(uptime: {self.uptime_str()})",
            f"Commands executed: {self.command_count}",
        ]
        if self.target:
            lines.append(f"Active target: {self.target}")
        if self.tools_used:
            lines.append(f"Tools used this session: {', '.join(self.tools_used)}")
        if self.last_intent:
            lines.append(f"Last action: {self.last_intent}")
        if self.last_summary:
            lines.append(f"Last result: {self.last_summary[:300]}")
        return "\n".join(lines)


class SessionManager:
    """Creates and manages the lifecycle of :class:`ActiveSession` objects.

    One SessionManager per Pentronix process; it holds exactly one
    active session at a time and persists session data to SQLite via
    :class:`MemoryManager`.
    """

    def __init__(self) -> None:
        self._session: Optional[ActiveSession] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start_new_session(
        self, target: Optional[str] = None
    ) -> ActiveSession:
        """Create and persist a new active session.

        Args:
            target: Optional initial target for this session.

        Returns:
            The newly created :class:`ActiveSession`.
        """
        from memory.memory_manager import get_memory_manager  # Lazy import

        if self._session is not None:
            await self.close_current_session("Replaced by new session.")

        self._session = ActiveSession(target=target)
        mem = get_memory_manager()
        await mem.create_session(self._session.session_id, target)
        log.info("New session started: %s", self._session.session_id)
        return self._session

    async def close_current_session(self, summary: str = "") -> None:
        """Persist end time and summary for the current session.

        Args:
            summary: AI-generated or user-provided session summary.
        """
        if self._session is None:
            return
        from memory.memory_manager import get_memory_manager

        mem = get_memory_manager()
        await mem.close_session(self._session.session_id, summary)
        log.info("Session closed: %s", self._session.session_id)
        self._session = None

    # ── Active session access ─────────────────────────────────────────────────

    @property
    def active(self) -> Optional[ActiveSession]:
        """Return the current active session, or ``None`` if none started."""
        return self._session

    def require_session(self) -> ActiveSession:
        """Return the active session, raising if none exists.

        Returns:
            The active :class:`ActiveSession`.

        Raises:
            RuntimeError: If no session has been started.
        """
        if self._session is None:
            raise RuntimeError(
                "No active session. Call start_new_session() first."
            )
        return self._session

    async def ensure_session(self) -> ActiveSession:
        """Return the active session, auto-creating if necessary.

        Returns:
            Active or newly created :class:`ActiveSession`.
        """
        if self._session is None:
            return await self.start_new_session()
        return self._session

    # ── Context helpers (pass-through to ActiveSession) ───────────────────────

    def update_target(self, target: str) -> None:
        """Update active session target, creating session if needed synchronously."""
        if self._session:
            self._session.set_target(target)

    def record_command(
        self,
        tool: str,
        output: str,
        summary: str,
        intent: str,
    ) -> None:
        """Update active session state after a command completes."""
        if self._session:
            self._session.record_tool_use(tool)
            self._session.increment_commands()
            self._session.store_output(output, summary, intent)

    def get_context_string(self) -> str:
        """Return session context string for LLM injection."""
        if self._session:
            return self._session.to_context_string()
        return "No active session."

    def get_last_output(self) -> str:
        """Return the raw output from the last executed command."""
        return self._session.last_output if self._session else ""

    def get_last_summary(self) -> str:
        """Return the AI summary of the last executed command."""
        return self._session.last_summary if self._session else ""


# ── Singleton ─────────────────────────────────────────────────────────────────
_SESSION_MGR: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Return the global :class:`SessionManager` singleton."""
    global _SESSION_MGR
    if _SESSION_MGR is None:
        _SESSION_MGR = SessionManager()
    return _SESSION_MGR
