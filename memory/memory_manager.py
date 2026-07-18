"""
Pentronix Memory Manager — persistent memory for the autonomous agent.

Thread-safe SQLite with WAL mode.  Stores EVERYTHING:
  - Full conversation history
  - Agent steps (think/act/observe)
  - Scan results and operations
  - Learned knowledge from internet research
  - Target intelligence
  - User preferences
"""

import asyncio
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from utils.logger import get_logger

log = get_logger(__name__)

_DB_INSTANCE: Optional["MemoryManager"] = None


def _utcnow() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


class MemoryManager:
    """Thread-safe SQLite memory — the agent's persistent brain."""

    def __init__(self, db_path: str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def initialise(self) -> None:
        """Open the database and apply the schema."""
        log.info("Initialising database at %s", self._db_path)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            timeout=10,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._apply_schema()
        log.info("Database ready.")

    def _apply_schema(self) -> None:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            sql = schema_path.read_text(encoding="utf-8")
            self._conn.executescript(sql)
        else:
            log.warning("schema.sql not found — DB tables may be missing")

    def close(self) -> None:
        """Close the database connection cleanly."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            log.error("Database error: %s", exc)
            raise

    async def _execute_write(self, sql: str, params: tuple = ()) -> int:
        async with self._write_lock:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_write, sql, params
            )

    def _sync_write(self, sql: str, params: tuple) -> int:
        with self._cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid

    def _sync_query(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self._conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    # ── Sessions ──────────────────────────────────────────────────────────────

    async def create_session(self, session_id: str, target: Optional[str] = None) -> None:
        await self._execute_write(
            "INSERT OR IGNORE INTO sessions (session_id, start_time, target) VALUES (?,?,?)",
            (session_id, _utcnow(), target),
        )
        log.debug("Session created: %s", session_id)

    async def close_session(self, session_id: str, summary: str = "") -> None:
        await self._execute_write(
            "UPDATE sessions SET end_time=?, summary=? WHERE session_id=?",
            (_utcnow(), summary, session_id),
        )

    def get_all_sessions(self) -> list[dict]:
        return self._sync_query(
            "SELECT * FROM sessions ORDER BY start_time DESC"
        )

    # ── Conversations (full message history) ──────────────────────────────────

    async def log_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_name: Optional[str] = None,
    ) -> int:
        """Log a conversation message.

        Args:
            session_id: Current session ID.
            role: 'user', 'assistant', or 'tool'.
            content: Message content.
            tool_name: Tool name if role is 'tool'.

        Returns:
            Row ID of the inserted message.
        """
        return await self._execute_write(
            "INSERT INTO conversations (session_id, role, content, tool_name, timestamp) VALUES (?,?,?,?,?)",
            (session_id, role, content[:50000], tool_name, _utcnow()),
        )

    def get_conversation_history(
        self, session_id: str, limit: int = 50
    ) -> list[dict]:
        """Get recent conversation messages for a session."""
        return self._sync_query(
            "SELECT role, content, tool_name, timestamp FROM conversations "
            "WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        )[::-1]  # Reverse to chronological order

    def get_all_conversations(self, limit: int = 100) -> list[dict]:
        """Get recent messages across all sessions."""
        return self._sync_query(
            "SELECT * FROM conversations ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    # ── Agent Steps ───────────────────────────────────────────────────────────

    async def log_agent_step(
        self,
        session_id: str,
        step_type: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[dict] = None,
        result: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> int:
        """Log an agent think/act/observe step.

        Args:
            session_id: Current session ID.
            step_type: 'think', 'tool_call', 'tool_result', 'response'.
            tool_name: Tool that was called (if applicable).
            tool_args: Arguments passed to the tool (if applicable).
            result: Result or output text.
            duration_ms: Duration in milliseconds.

        Returns:
            Row ID.
        """
        return await self._execute_write(
            "INSERT INTO agent_steps (session_id, step_type, tool_name, tool_args, result, timestamp, duration_ms) VALUES (?,?,?,?,?,?,?)",
            (
                session_id,
                step_type,
                tool_name,
                json.dumps(tool_args) if tool_args else None,
                result[:50000] if result else None,
                _utcnow(),
                duration_ms,
            ),
        )

    # ── Commands (tool executions — legacy compat + new) ──────────────────────

    async def log_command(
        self,
        session_id: str,
        raw_input: str,
        understood_command: str = "",
        intent: str = "",
        tool_used: str = "",
        command_run: str = "",
        output: str = "",
        ai_summary: str = "",
        risk_level: str = "LOW",
        duration_seconds: float = 0.0,
        success: bool = True,
    ) -> int:
        return await self._execute_write(
            """INSERT INTO commands
               (session_id, raw_input, understood_command, intent, tool_used,
                command_run, output, ai_summary, risk_level, timestamp,
                duration_seconds, success)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                session_id, raw_input, understood_command, intent, tool_used,
                command_run, output[:50000], ai_summary, risk_level,
                _utcnow(), duration_seconds, int(success),
            ),
        )

    async def update_command_output(
        self,
        command_id: int,
        output: str,
        ai_summary: str,
        duration_seconds: float,
        success: bool = True,
    ) -> None:
        await self._execute_write(
            """UPDATE commands
               SET output=?, ai_summary=?, duration_seconds=?, success=?
               WHERE id=?""",
            (output[:50000], ai_summary, duration_seconds, int(success), command_id),
        )

    def get_recent_commands(self, limit: int = 10) -> list[dict]:
        return self._sync_query(
            "SELECT * FROM commands ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_session_commands(self, session_id: str) -> list[dict]:
        return self._sync_query(
            "SELECT * FROM commands WHERE session_id=? ORDER BY timestamp ASC",
            (session_id,),
        )

    # ── Targets ───────────────────────────────────────────────────────────────

    async def upsert_target(
        self,
        ip_or_domain: str,
        open_ports: Optional[list] = None,
        services: Optional[list] = None,
        vulnerabilities: Optional[list] = None,
        os_detected: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        existing = self._sync_query(
            "SELECT * FROM targets WHERE ip_or_domain=?", (ip_or_domain,)
        )
        now = _utcnow()

        if existing:
            row = existing[0]
            merged_ports = _merge_json(row["open_ports"], open_ports)
            merged_services = _merge_json(row["services"], services)
            merged_vulns = _merge_json(row["vulnerabilities"], vulnerabilities)

            await self._execute_write(
                """UPDATE targets SET last_seen=?, open_ports=?, services=?,
                   vulnerabilities=?, os_detected=COALESCE(?,os_detected),
                   notes=COALESCE(?,notes)
                   WHERE ip_or_domain=?""",
                (
                    now,
                    json.dumps(merged_ports),
                    json.dumps(merged_services),
                    json.dumps(merged_vulns),
                    os_detected,
                    notes,
                    ip_or_domain,
                ),
            )
        else:
            await self._execute_write(
                """INSERT INTO targets
                   (ip_or_domain, first_seen, last_seen, open_ports,
                    services, vulnerabilities, os_detected, notes)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    ip_or_domain, now, now,
                    json.dumps(open_ports or []),
                    json.dumps(services or []),
                    json.dumps(vulnerabilities or []),
                    os_detected, notes,
                ),
            )

    def get_target(self, ip_or_domain: str) -> Optional[dict]:
        rows = self._sync_query(
            "SELECT * FROM targets WHERE ip_or_domain=?", (ip_or_domain,)
        )
        return rows[0] if rows else None

    def get_all_targets(self) -> list[dict]:
        return self._sync_query(
            "SELECT * FROM targets ORDER BY last_seen DESC"
        )

    # ── Learned Knowledge ─────────────────────────────────────────────────────

    async def save_knowledge(
        self,
        topic: str,
        content: str,
        sources: Optional[list[str]] = None,
    ) -> int:
        """Save learned knowledge from internet research.

        Args:
            topic: Topic keyword or phrase.
            content: The knowledge content.
            sources: URLs where the knowledge was found.

        Returns:
            Row ID.
        """
        return await self._execute_write(
            "INSERT INTO learned_knowledge (topic, content, sources, learned_at) VALUES (?,?,?,?)",
            (topic, content[:50000], json.dumps(sources or []), _utcnow()),
        )

    def search_knowledge(self, query: str, limit: int = 5) -> list[dict]:
        """Search learned knowledge by topic keyword."""
        return self._sync_query(
            "SELECT * FROM learned_knowledge WHERE topic LIKE ? ORDER BY learned_at DESC LIMIT ?",
            (f"%{query}%", limit),
        )

    async def increment_knowledge_usage(self, knowledge_id: int) -> None:
        """Increment the usage counter for a knowledge entry."""
        await self._execute_write(
            "UPDATE learned_knowledge SET times_used = times_used + 1 WHERE id=?",
            (knowledge_id,),
        )

    # ── Installed Tools ───────────────────────────────────────────────────────

    async def log_tool_install(
        self, name: str, install_command: str
    ) -> None:
        """Record that the agent installed a tool."""
        await self._execute_write(
            "INSERT OR REPLACE INTO installed_tools (name, install_command, installed_at) VALUES (?,?,?)",
            (name, install_command, _utcnow()),
        )

    def get_installed_tools(self) -> list[dict]:
        """Return all agent-installed tools."""
        return self._sync_query(
            "SELECT * FROM installed_tools ORDER BY installed_at DESC"
        )

    # ── Preferences ───────────────────────────────────────────────────────────

    async def set_preference(self, key: str, value: str) -> None:
        await self._execute_write(
            "INSERT OR REPLACE INTO preferences (key, value) VALUES (?,?)",
            (key, value),
        )

    def get_preference(self, key: str, default: str = "") -> str:
        rows = self._sync_query(
            "SELECT value FROM preferences WHERE key=?", (key,)
        )
        return rows[0]["value"] if rows else default

    # ── Context builders for LLM injection ────────────────────────────────────

    def build_memory_context(self, session_id: str, limit: int = 10) -> str:
        """Build a compact memory context for LLM injection.

        Includes recent commands and conversation snippets.
        """
        cmds = self.get_recent_commands(limit)
        if not cmds:
            return ""

        lines: list[str] = []
        for cmd in reversed(cmds):
            ts = cmd["timestamp"][:19].replace("T", " ")
            lines.append(
                f"[{ts}] {cmd.get('understood_command', '?')} "
                f"→ {cmd.get('tool_used', '?')} "
                f"({'✓' if cmd.get('success') else '✗'})"
            )
            if cmd.get("ai_summary"):
                lines.append(f"  Summary: {cmd['ai_summary'][:200]}")
        return "\n".join(lines)

    def build_target_context(self, target: str) -> str:
        """Build intel summary for a specific target."""
        t = self.get_target(target)
        if not t:
            return ""

        ports = json.loads(t.get("open_ports", "[]"))
        vulns = json.loads(t.get("vulnerabilities", "[]"))
        services = json.loads(t.get("services", "[]"))

        lines = [
            f"Target: {t['ip_or_domain']}",
            f"First seen: {t['first_seen'][:10]}  Last seen: {t['last_seen'][:10]}",
        ]
        if t.get("os_detected"):
            lines.append(f"OS: {t['os_detected']}")
        if ports:
            port_strs = [
                f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service', '')})"
                for p in ports[:20]
            ]
            lines.append(f"Open ports: {', '.join(port_strs)}")
        if services:
            svc_strs = [
                f"{s.get('service', '')} {s.get('version', '')}" for s in services[:10]
            ]
            lines.append(f"Services: {', '.join(svc_strs)}")
        if vulns:
            lines.append(f"Vulnerabilities: {len(vulns)} found")
            for v in vulns[:5]:
                lines.append(f"  - {v.get('name', '?')} [{v.get('severity', '?')}]")
        if t.get("notes"):
            lines.append(f"Notes: {t['notes'][:300]}")
        return "\n".join(lines)

    def build_knowledge_context(self, query: str) -> str:
        """Build relevant knowledge context for a query."""
        knowledge = self.search_knowledge(query, limit=3)
        if not knowledge:
            return ""
        lines = []
        for k in knowledge:
            lines.append(f"[{k['topic']}] {k['content'][:500]}")
        return "\n".join(lines)

    # ── Memory recall (JARVIS-style) ──────────────────────────────────────────

    def recall_by_query(self, query: str, limit: int = 10) -> list[dict]:
        """Search across all history — commands, conversations, knowledge, steps.

        Args:
            query: Search keyword(s).
            limit: Max results per table.

        Returns:
            List of dicts with type, content, and timestamp.
        """
        results = []
        pattern = f"%{query}%"

        # Search commands
        for row in self._sync_query(
            "SELECT 'command' AS type, raw_input AS content, output, ai_summary, "
            "tool_used, timestamp FROM commands WHERE "
            "raw_input LIKE ? OR output LIKE ? OR ai_summary LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (pattern, pattern, pattern, limit),
        ):
            results.append(row)

        # Search conversations
        for row in self._sync_query(
            "SELECT 'conversation' AS type, content, role, timestamp "
            "FROM conversations WHERE content LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (pattern, limit),
        ):
            results.append(row)

        # Search agent steps
        for row in self._sync_query(
            "SELECT 'agent_step' AS type, result AS content, tool_name, step_type, timestamp "
            "FROM agent_steps WHERE result LIKE ? OR tool_name LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (pattern, pattern, limit),
        ):
            results.append(row)

        # Search knowledge
        for row in self._sync_query(
            "SELECT 'knowledge' AS type, content, topic, learned_at AS timestamp "
            "FROM learned_knowledge WHERE topic LIKE ? OR content LIKE ? "
            "ORDER BY learned_at DESC LIMIT ?",
            (pattern, pattern, limit),
        ):
            results.append(row)

        # Sort by timestamp (most recent first)
        results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return results[:limit]

    def get_recent_activity(self, n: int = 5) -> list[dict]:
        """Get the last N operations with full details."""
        return self._sync_query(
            "SELECT raw_input, tool_used, command_run, ai_summary, risk_level, "
            "success, duration_seconds, timestamp FROM commands "
            "ORDER BY timestamp DESC LIMIT ?",
            (n,),
        )

    def get_errors(self, session_id: Optional[str] = None, limit: int = 5) -> list[dict]:
        """Retrieve recent errors — tool failures and agent errors."""
        if session_id:
            return self._sync_query(
                "SELECT tool_used, raw_input, output, timestamp FROM commands "
                "WHERE session_id=? AND success=0 ORDER BY timestamp DESC LIMIT ?",
                (session_id, limit),
            )
        return self._sync_query(
            "SELECT tool_used, raw_input, output, timestamp FROM commands "
            "WHERE success=0 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_task_history(self, keyword: str, limit: int = 5) -> list[dict]:
        """Find past tasks matching a keyword."""
        pattern = f"%{keyword}%"
        return self._sync_query(
            "SELECT raw_input, tool_used, ai_summary, risk_level, success, timestamp "
            "FROM commands WHERE raw_input LIKE ? OR ai_summary LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (pattern, pattern, limit),
        )

    def build_full_context(self, user_message: str, session_id: str) -> str:
        """Smart context builder for JARVIS-style memory.

        Detects when the user is asking about past events and injects
        relevant memory. Also includes recent activity for continuity.

        Args:
            user_message: The user's current message.
            session_id: Current session ID.

        Returns:
            Memory context string to inject into LLM prompt.
        """
        msg_lower = user_message.lower()
        parts: list[str] = []

        # Always include last 3 operations for continuity
        recent = self.get_recent_activity(3)
        if recent:
            lines = []
            for op in recent:
                ts = (op.get("timestamp") or "")[:16].replace("T", " ")
                tool = op.get("tool_used") or "unknown"
                status = "✓" if op.get("success") else "✗"
                summary = (op.get("ai_summary") or "")[:150]
                lines.append(f"[{ts}] {tool} ({status}) {summary}")
            parts.append("Recent operations:\n" + "\n".join(lines))

        # Detect memory-recall intent
        recall_keywords = [
            "remember", "earlier", "before", "last time", "yesterday",
            "previous", "history", "what did you", "what happened",
            "show me", "recall", "past", "error", "failed", "result",
            "scan result", "found", "report",
        ]
        is_recall = any(kw in msg_lower for kw in recall_keywords)

        if is_recall:
            # Extract search terms (remove common words)
            stop_words = {"what", "did", "you", "the", "me", "my", "show",
                          "can", "about", "from", "earlier", "before", "last",
                          "time", "any", "were", "there", "do", "have", "has"}
            terms = [w for w in msg_lower.split() if len(w) > 2 and w not in stop_words]

            # Search memory for each relevant term
            for term in terms[:3]:
                results = self.recall_by_query(term, limit=3)
                if results:
                    for r in results:
                        rtype = r.get("type", "")
                        content = (r.get("content") or r.get("ai_summary") or "")[:200]
                        ts = (r.get("timestamp") or "")[:16].replace("T", " ")
                        parts.append(f"[{ts}] ({rtype}) {content}")

            # Also check errors if user asks
            if any(w in msg_lower for w in ["error", "fail", "wrong", "issue", "problem"]):
                errors = self.get_errors(limit=3)
                if errors:
                    lines = []
                    for e in errors:
                        ts = (e.get("timestamp") or "")[:16].replace("T", " ")
                        tool = e.get("tool_used") or "unknown"
                        output = (e.get("output") or "")[:100]
                        lines.append(f"[{ts}] {tool} FAILED: {output}")
                    parts.append("Recent errors:\n" + "\n".join(lines))

        # Target context
        import re
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", user_message)
        if ip_match:
            target_ctx = self.build_target_context(ip_match.group(1))
            if target_ctx:
                parts.append(target_ctx)

        return "\n".join(parts) if parts else ""


# ── Module-level helpers ──────────────────────────────────────────────────────

def _merge_json(existing_str: str, new_items: Optional[list]) -> list:
    """Merge new items into existing JSON list, dedup by 'port' key."""
    existing: list = json.loads(existing_str or "[]")
    if not new_items:
        return existing
    seen = {item.get("port") for item in existing if "port" in item}
    for item in new_items:
        if item.get("port") not in seen:
            existing.append(item)
            seen.add(item.get("port"))
    return existing


def get_memory_manager() -> MemoryManager:
    """Return the global MemoryManager singleton, initialising if needed."""
    global _DB_INSTANCE
    if _DB_INSTANCE is None:
        from utils.config import Config
        cfg = Config.get()
        _DB_INSTANCE = MemoryManager(cfg.db_path)
        _DB_INSTANCE.initialise()
    return _DB_INSTANCE
