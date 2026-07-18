"""
Pentronix Agent — autonomous think → plan → act → observe → learn loop.

This is the brain of Pentronix.  The agent receives a user message,
decides what to do (potentially chaining multiple tool calls), executes
each step, observes results, and adapts its plan in real time.

Architecture:
  1. User message arrives
  2. Build context (memory, tools, target intel, learned knowledge)
  3. Send to LLM with tool definitions
  4. LLM returns tool_calls or text
  5. For each tool_call:
     a. Check risk level — if HIGH/CRITICAL, yield confirmation event
     b. Execute the tool, streaming output
     c. Feed result back to LLM
  6. LLM decides: more steps needed? → loop to step 3
  7. Final text response → yield to UI + TTS
  8. Save everything to memory

Events are yielded as an async generator so the UI can consume them
in real time without blocking.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Callable, Optional

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)


# ── Agent Events ──────────────────────────────────────────────────────────────
# Events are yielded by the agent loop for the UI to consume.

class EventType(str, Enum):
    THINKING = "thinking"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    TOOL_RESULT = "tool_result"
    CONFIRMATION_REQUIRED = "confirmation_required"
    RESPONSE = "response"
    ERROR = "error"
    STATUS = "status"
    INSTALL_TOOL = "install_tool"


@dataclass
class AgentEvent:
    """Single event emitted by the agent loop."""
    type: EventType
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @staticmethod
    def thinking(message: str = "Thinking...") -> "AgentEvent":
        return AgentEvent(type=EventType.THINKING, data={"message": message})

    @staticmethod
    def tool_call(tool_name: str, args: dict, risk_level: str = "LOW") -> "AgentEvent":
        return AgentEvent(
            type=EventType.TOOL_CALL,
            data={"tool_name": tool_name, "args": args or {}, "risk_level": risk_level},
        )

    @staticmethod
    def tool_output(line: str) -> "AgentEvent":
        return AgentEvent(type=EventType.TOOL_OUTPUT, data={"line": line})

    @staticmethod
    def tool_result(tool_name: str, success: bool, summary: str = "") -> "AgentEvent":
        return AgentEvent(
            type=EventType.TOOL_RESULT,
            data={"tool_name": tool_name, "success": success, "summary": summary},
        )

    @staticmethod
    def confirmation_required(
        tool_name: str, args: dict, risk_level: str, description: str
    ) -> "AgentEvent":
        return AgentEvent(
            type=EventType.CONFIRMATION_REQUIRED,
            data={
                "tool_name": tool_name,
                "args": args,
                "risk_level": risk_level,
                "description": description,
            },
        )

    @staticmethod
    def response(message: str) -> "AgentEvent":
        return AgentEvent(type=EventType.RESPONSE, data={"message": message})

    @staticmethod
    def error(message: str) -> "AgentEvent":
        return AgentEvent(type=EventType.ERROR, data={"message": message})

    @staticmethod
    def status(message: str) -> "AgentEvent":
        return AgentEvent(type=EventType.STATUS, data={"message": message})

    @staticmethod
    def install_tool(tool_name: str) -> "AgentEvent":
        return AgentEvent(
            type=EventType.INSTALL_TOOL,
            data={"tool_name": tool_name},
        )


# ── Agent ─────────────────────────────────────────────────────────────────────

class PentronixAgent:
    """Autonomous AI pentesting agent with tool-calling.

    The agent maintains conversation state, session memory, and can chain
    multiple tool calls autonomously to accomplish complex objectives.
    """

    MAX_ITERATIONS = 25      # Max tool-call rounds per user message
    MAX_OUTPUT_CHARS = 8000   # Max chars of tool output fed back to LLM
    MAX_TOOL_DEFS = 18        # Max tool definitions sent to LLM per call
    MAX_HISTORY = 10          # Max conversation messages kept for context

    def __init__(self) -> None:
        from core.brain import get_brain
        from core.executor import get_executor
        from memory.memory_manager import get_memory_manager
        from memory.tool_registry import get_tool_registry

        self._brain = get_brain()
        self._executor = get_executor()
        self._memory = get_memory_manager()
        self._tool_registry = get_tool_registry()

        self._session_id = str(uuid.uuid4())
        self._messages: list[dict] = []  # Full conversation for LLM context
        self._sudo_password: Optional[str] = None
        self._confirmation_future: Optional[asyncio.Future] = None
        self._worker_loop: Optional[asyncio.AbstractEventLoop] = None
        self._cancelled = False

        # Tool instances from the tools package
        self._tool_instances: dict = {}

        log.info("PentronixAgent initialised — session: %s", self._session_id)

    # ── Initialisation ────────────────────────────────────────────────────────

    async def initialise(self) -> None:
        """Initialise the agent: create session, scan tools, load memory."""
        self._worker_loop = asyncio.get_event_loop()
        await self._memory.create_session(self._session_id)

        # Scan system tools if needed
        if self._tool_registry.needs_scan():
            self._tool_registry.scan_all()

        # Discover agent tool modules
        from tools import discover_tools
        self._tool_instances = discover_tools()

        log.info(
            "Agent ready: %d system tools, %d agent tools",
            len(self._tool_registry.get_found()),
            len(self._tool_instances),
        )

    def set_sudo_password(self, password: str) -> None:
        """Set the sudo password for privileged operations."""
        self._sudo_password = password

    def cancel(self) -> None:
        """Cancel the current operation."""
        self._cancelled = True
        # Schedule cancel on the worker's event loop (thread-safe)
        if self._worker_loop and self._worker_loop.is_running():
            self._worker_loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self._executor.cancel())
            )

    def resolve_confirmation(self, approved: bool) -> None:
        """Resolve a pending confirmation request.

        This is called from the Qt main thread but the Future lives on
        the agent worker's asyncio event loop — must use call_soon_threadsafe.
        """
        future = self._confirmation_future
        loop = self._worker_loop
        if future and not future.done() and loop and loop.is_running():
            loop.call_soon_threadsafe(future.set_result, approved)

    # ── Main agent loop ───────────────────────────────────────────────────────

    async def run(
        self, user_message: str
    ) -> AsyncGenerator[AgentEvent, None]:
        """Process a user message through the autonomous agent loop.

        Yields AgentEvent objects for the UI to consume in real time.
        The agent will chain multiple tool calls if needed to complete
        the user's objective.

        Args:
            user_message: The user's text input.

        Yields:
            AgentEvent objects (thinking, tool_call, tool_output, response, etc.)
        """
        self._cancelled = False

        # Log user message
        await self._memory.log_message(
            self._session_id, "user", user_message
        )
        self._messages.append({"role": "user", "content": user_message})

        # Build system prompt with full context
        system_prompt = self._build_system_prompt(user_message)

        # Prepare messages for LLM
        llm_messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history (keep recent for context window)
        if len(self._messages) > self.MAX_HISTORY:
            self._messages = self._messages[-self.MAX_HISTORY:]
        llm_messages.extend(self._messages)

        # Get available tool definitions — smart-selected for this message
        tool_defs = self._get_tool_definitions(user_message)

        yield AgentEvent.thinking()

        # ── Iterative tool-calling loop ───────────────────────────────────
        for iteration in range(self.MAX_ITERATIONS):
            if self._cancelled:
                yield AgentEvent.status("Operation cancelled.")
                break

            try:
                start = time.monotonic()
                response = await self._brain.chat_with_tools(
                    messages=llm_messages,
                    tools=tool_defs,
                    temperature=0.1,
                    max_tokens=4096,
                )
                elapsed_ms = int((time.monotonic() - start) * 1000)

                # Log the thinking step
                await self._memory.log_agent_step(
                    self._session_id,
                    step_type="think",
                    result=response.get("content", "")[:2000],
                    duration_ms=elapsed_ms,
                )

            except Exception as exc:
                log.error("Brain error: %s", exc)
                yield AgentEvent.error(f"AI error: {exc}")
                break

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])

            # ── No tool calls → final response ────────────────────────
            if not tool_calls:
                if content:
                    self._messages.append({"role": "assistant", "content": content})
                    await self._memory.log_message(
                        self._session_id, "assistant", content
                    )
                    yield AgentEvent.response(content)
                break

            # ── Has tool calls → execute each one ─────────────────────
            # Add assistant message with tool_calls to conversation
            assistant_msg = {"role": "assistant", "content": content or ""}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            llm_messages.append(assistant_msg)
            self._messages.append(assistant_msg)

            # Show thinking text if present alongside tool calls
            if content:
                yield AgentEvent.status(content)

            for tc in tool_calls:
                if self._cancelled:
                    break

                func = tc.get("function", {})
                tool_name = func.get("name", "unknown")
                try:
                    tool_args = json.loads(func.get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    tool_args = {}

                # Ensure tool_args is always a dict
                if not isinstance(tool_args, dict):
                    tool_args = {}

                tc_id = tc.get("id", f"call_{iteration}")

                # Execute the tool and collect result
                async for event in self._execute_tool(tool_name, tool_args):
                    yield event

                # Get the result from the last tool_result event
                tool_output = getattr(self, "_last_tool_output", "No output")

                # Add tool result to conversation for LLM
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": str(tool_output)[:self.MAX_OUTPUT_CHARS],
                }
                llm_messages.append(tool_msg)

                await self._memory.log_message(
                    self._session_id, "tool", str(tool_output)[:5000],
                    tool_name=tool_name,
                )

            # Continue loop — LLM will see the tool results and decide next step
            if not self._cancelled:
                yield AgentEvent.thinking("Analyzing results...")

        else:
            # Hit max iterations
            yield AgentEvent.status(
                f"Reached maximum iterations ({self.MAX_ITERATIONS}). "
                "Stopping autonomous execution."
            )

        # Trim conversation to prevent unbounded growth
        if len(self._messages) > 40:
            self._messages = self._messages[-30:]

    # ── Tool execution ────────────────────────────────────────────────────────

    async def _execute_tool(
        self, tool_name: str, tool_args: dict
    ) -> AsyncGenerator[AgentEvent, None]:
        """Execute a single tool call, handling confirmations and output streaming.

        Yields events for each phase: call, output lines, result.
        Sets ``self._last_tool_output`` for the caller.
        """
        from tools import get_tool, RiskLevel

        # Determine risk level
        tool_instance = self._tool_instances.get(tool_name) or get_tool(tool_name)
        risk_level = "LOW"
        if tool_instance:
            risk_level = tool_instance.risk_level.value

        # Override risk for known dangerous patterns in run_command
        if tool_name == "run_command":
            cmd = (tool_args.get("command", "") or "").strip()
            cmd_lower = cmd.lower()
            # Ignore simple echo/cat/ls commands — never dangerous
            first_word = cmd_lower.split()[0] if cmd_lower.split() else ""
            if first_word in ("echo", "cat", "ls", "pwd", "whoami", "id",
                              "hostname", "uname", "date", "uptime", "which",
                              "wc", "head", "tail", "grep", "find", "file"):
                risk_level = "LOW"
            elif any(kw in cmd_lower for kw in [
                "rm -rf", "mkfs", "dd if=", "> /dev/", "format c:",
                "msfvenom ", "msfconsole ", "python -c",
            ]):
                risk_level = "CRITICAL"
            elif any(kw in cmd_lower for kw in [
                "sudo ", "sqlmap ", "hydra ", "ncrack ",
            ]):
                risk_level = "HIGH"

        yield AgentEvent.tool_call(tool_name, tool_args, risk_level)

        # ── Confirmation for dangerous operations ─────────────────────
        if risk_level in ("HIGH", "CRITICAL"):
            desc = self._format_confirmation_description(tool_name, tool_args, risk_level)
            yield AgentEvent.confirmation_required(tool_name, tool_args, risk_level, desc)

            # Wait for user confirmation
            self._confirmation_future = asyncio.get_event_loop().create_future()
            try:
                approved = await asyncio.wait_for(
                    self._confirmation_future, timeout=300
                )
            except asyncio.TimeoutError:
                approved = False
            finally:
                self._confirmation_future = None

            if not approved:
                self._last_tool_output = "Operation cancelled by user."
                yield AgentEvent.tool_result(tool_name, False, "Cancelled by user")
                return

        # ── Execute the tool ──────────────────────────────────────────
        start = time.monotonic()
        output_lines: list[str] = []

        def on_output(line: str) -> None:
            output_lines.append(line)

        try:
            if tool_instance:
                # Use the registered Tool class
                from tools import ToolResult as TR
                result = await tool_instance.execute(
                    on_output=lambda l: output_lines.append(l),
                    **tool_args,
                )
                output_text = result.output
                success = result.success
            else:
                # Fallback: treat as a shell command via built-in handlers
                output_text, success = await self._handle_builtin_tool(
                    tool_name, tool_args, on_output
                )

        except Exception as exc:
            log.error("Tool %s execution error: %s", tool_name, exc)
            output_text = f"Error executing {tool_name}: {exc}"
            success = False

        duration = time.monotonic() - start

        # Stream output lines to UI
        for line in output_lines:
            yield AgentEvent.tool_output(line)

        self._last_tool_output = output_text

        # Log to memory
        await self._memory.log_agent_step(
            self._session_id,
            step_type="tool_result",
            tool_name=tool_name,
            tool_args=tool_args,
            result=output_text[:5000],
            duration_ms=int(duration * 1000),
        )

        await self._memory.log_command(
            session_id=self._session_id,
            raw_input=f"{tool_name}({json.dumps(tool_args)[:200]})",
            tool_used=tool_name,
            command_run=json.dumps(tool_args)[:500],
            output=output_text[:10000],
            risk_level=risk_level,
            duration_seconds=round(duration, 2),
            success=success,
        )

        yield AgentEvent.tool_result(
            tool_name, success,
            f"Completed in {duration:.1f}s" if success else f"Failed after {duration:.1f}s"
        )

    # ── Built-in tool handlers ────────────────────────────────────────────────
    # These handle fundamental operations that don't require external Tool classes.

    async def _handle_builtin_tool(
        self, tool_name: str, args: dict, on_output: Callable
    ) -> tuple[str, bool]:
        """Handle built-in tools that are always available."""

        if tool_name == "run_command":
            result = await self._executor.execute(
                args.get("command", "echo 'no command'"),
                on_output=on_output,
                sudo_password=self._sudo_password,
            )
            return (result.stdout + "\n" + result.stderr).strip(), result.success

        elif tool_name == "write_file":
            path = args.get("path", "/tmp/output.txt")
            content = args.get("content", "")
            try:
                from pathlib import Path
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
                msg = f"File written: {path} ({len(content)} chars)"
                on_output(msg)
                return msg, True
            except Exception as exc:
                return f"Failed to write {path}: {exc}", False

        elif tool_name == "read_file":
            path = args.get("path", "")
            try:
                content = open(path, "r", encoding="utf-8", errors="replace").read()
                truncated = content[:self.MAX_OUTPUT_CHARS]
                on_output(truncated)
                return truncated, True
            except Exception as exc:
                return f"Failed to read {path}: {exc}", False

        elif tool_name == "list_directory":
            path = args.get("path", ".")
            try:
                from pathlib import Path
                entries = sorted(Path(path).iterdir())
                lines = []
                for e in entries[:100]:
                    prefix = "📁" if e.is_dir() else "📄"
                    size = f" ({e.stat().st_size} B)" if e.is_file() else ""
                    lines.append(f"{prefix} {e.name}{size}")
                output = "\n".join(lines) if lines else "(empty directory)"
                on_output(output)
                return output, True
            except Exception as exc:
                return f"Failed to list {path}: {exc}", False

        elif tool_name == "search_web":
            from core.internet_researcher import get_researcher
            researcher = get_researcher()
            results = await researcher.search(args.get("query", ""), max_results=5)
            output = "\n\n".join(
                f"**{r['title']}**\n{r['url']}\n{r['snippet']}"
                for r in results
            ) if results else "No results found."
            on_output(output)
            return output, bool(results)

        elif tool_name == "read_webpage":
            from core.internet_researcher import get_researcher
            researcher = get_researcher()
            text = await researcher.read_webpage(args.get("url", ""))
            on_output(text[:3000])
            return text, bool(text)

        elif tool_name == "install_tool":
            tool = args.get("tool_name", "")
            success = await self._tool_registry.auto_install(
                tool, sudo_password=self._sudo_password, on_output=on_output
            )
            return f"{'Installed' if success else 'Failed to install'} {tool}", success

        elif tool_name == "open_application":
            app = args.get("application", "")
            url = args.get("url", "")
            cmd = app
            if url and app.lower() in ("firefox", "chromium", "google-chrome", "brave-browser"):
                cmd = f"{app} {url}"
            elif url:
                cmd = f"xdg-open {url}"
            result = await self._executor.execute(
                f"nohup {cmd} &>/dev/null &",
                on_output=on_output,
            )
            return f"Opened {app}" + (f" with {url}" if url else ""), True

        elif tool_name == "system_info":
            commands = [
                ("Hostname", "hostname"),
                ("User", "whoami"),
                ("OS", "cat /etc/os-release | head -2"),
                ("Kernel", "uname -r"),
                ("IP Addresses", "ip -4 addr show | grep inet | awk '{print $2}'"),
                ("Network Interfaces", "ip link show | grep '^[0-9]' | awk '{print $2}'"),
                ("Uptime", "uptime -p"),
                ("Memory", "free -h | grep Mem | awk '{print $3\"/\"$2}'"),
                ("Disk", "df -h / | tail -1 | awk '{print $3\"/\"$2\" (\"$5\" used)\"}'"),
            ]
            lines = []
            for label, cmd in commands:
                r = await self._executor.execute(cmd, timeout=5)
                lines.append(f"{label}: {r.stdout.strip()}")
            output = "\n".join(lines)
            on_output(output)
            return output, True

        # ── Screen reading ─────────────────────────────────────────────────
        elif tool_name == "read_screen":
            from tools.screen_reader import read_screen, cleanup_screenshot
            result = read_screen()
            if result["success"]:
                output = f"Screen captured ({result.get('dimensions', '?')}).\n"
                output += f"Text on screen:\n{result['extracted_text'][:2000]}"
                cleanup_screenshot(result.get("screenshot_path", ""))
                on_output(output)
                return output, True
            else:
                return result.get("error", "Screenshot failed"), False

        else:
            return f"Unknown tool: {tool_name}", False

    # ── Context building ──────────────────────────────────────────────────────

    def _build_system_prompt(self, user_message: str = "") -> str:
        """Build system prompt with JARVIS memory context."""
        from prompts.system_prompt import build_system_prompt

        # Smart memory context — detects recall intent and injects relevant history
        memory_ctx = self._memory.build_full_context(user_message, self._session_id)

        return build_system_prompt(
            memory_context=memory_ctx,
        )

    # Keyword→tool relevance map for smart tool selection
    _TOOL_KEYWORDS: dict[str, list[str]] = {
        "nmap_scan": ["scan", "port", "nmap", "recon", "discover", "host", "network", "service"],
        "whois_lookup": ["whois", "domain", "registrar", "owner"],
        "dns_lookup": ["dns", "dig", "mx", "txt", "record", "resolve"],
        "subdomain_enum": ["subdomain", "enum", "discover", "domain"],
        "ping_host": ["ping", "alive", "reachable", "up"],
        "traceroute_host": ["trace", "route", "hop", "path"],
        "arp_scan": ["arp", "local", "lan", "discover", "network"],
        "nikto_scan": ["nikto", "web", "vuln", "http", "server"],
        "nuclei_scan": ["nuclei", "template", "vuln", "cve"],
        "searchsploit": ["exploit", "searchsploit", "cve", "vuln", "edb"],
        "nmap_vuln_scan": ["vuln", "nse", "script", "nmap"],
        "metasploit_run": ["metasploit", "msf", "exploit", "module", "payload"],
        "sqlmap_scan": ["sql", "injection", "sqlmap", "database", "dump"],
        "hydra_bruteforce": ["hydra", "brute", "password", "login", "ssh", "ftp"],
        "msfvenom_generate": ["msfvenom", "payload", "generate", "reverse", "shell", "exe"],
        "create_reverse_shell": ["reverse", "shell", "listener", "connect", "back"],
        "create_custom_script": ["script", "create", "write", "code", "python", "bash"],
        "gobuster_scan": ["gobuster", "directory", "dir", "brute", "web", "path"],
        "ffuf_fuzz": ["fuzz", "ffuf", "parameter", "inject"],
        "whatweb_fingerprint": ["whatweb", "fingerprint", "technology", "cms"],
        "curl_request": ["curl", "http", "request", "api", "get", "post"],
        "wafw00f_detect": ["waf", "firewall", "detect", "bypass"],
        "theharvester_scan": ["harvest", "email", "osint", "subdomain"],
        "google_dork": ["dork", "google", "search", "exposed", "sensitive"],
        "manage_service": ["service", "start", "stop", "restart", "systemctl"],
        "manage_network": ["network", "interface", "wifi", "monitor", "adapter"],
        "process_manager": ["process", "kill", "ps", "running"],
        "open_browser": ["open", "browser", "url", "website", "firefox"],
        "open_app": ["open", "launch", "app", "application", "wireshark", "burp"],
        "play_media": ["play", "youtube", "music", "video", "media"],
        "analyze_binary": ["binary", "analyze", "elf", "pe", "strings", "static"],
        "hash_identify": ["hash", "md5", "sha", "identify", "crack"],
        "log_analysis": ["log", "analyze", "auth", "syslog", "event"],
        "generate_report": ["report", "generate", "summary", "pdf", "html"],
    }

    def _get_tool_definitions(self, user_message: str = "") -> list[dict]:
        """Get tool definitions for LLM, smart-selecting relevant ones.

        Always includes 9 compact builtin tools. Then selects up to
        MAX_TOOL_DEFS - 9 registered tools based on keyword relevance
        to the user's message.
        """
        from tools import get_all_function_definitions

        all_defs = get_all_function_definitions()

        # ── Smart selection: score each tool by keyword relevance ──
        msg_lower = user_message.lower()
        msg_words = set(msg_lower.split())
        max_registered = self.MAX_TOOL_DEFS - 9  # Reserve 9 for builtins

        if not user_message or len(all_defs) <= max_registered:
            selected = all_defs
        else:
            scored: list[tuple[int, dict]] = []
            for tool_def in all_defs:
                name = tool_def.get("function", {}).get("name", "")
                keywords = self._TOOL_KEYWORDS.get(name, [])
                score = sum(1 for kw in keywords if kw in msg_lower)
                # Bonus if tool name itself appears in message
                if name.replace("_", " ") in msg_lower or name.replace("_", "") in msg_lower:
                    score += 5
                scored.append((score, tool_def))

            scored.sort(key=lambda x: x[0], reverse=True)
            selected = [d for _, d in scored[:max_registered]]

        # ── Compact builtin tools (always included) ───────────────
        builtins = [
            self._builtin("run_command", "Execute any shell command.",
                          {"command": ("string", "Shell command to execute")},
                          ["command"]),
            self._builtin("write_file", "Create/overwrite a file.",
                          {"path": ("string", "File path"),
                           "content": ("string", "File content")},
                          ["path", "content"]),
            self._builtin("read_file", "Read a file's contents.",
                          {"path": ("string", "File path")}, ["path"]),
            self._builtin("list_directory", "List directory contents.",
                          {"path": ("string", "Directory path")}, ["path"]),
            self._builtin("search_web", "Search the internet.",
                          {"query": ("string", "Search query")}, ["query"]),
            self._builtin("read_webpage", "Extract text from a URL.",
                          {"url": ("string", "URL to read")}, ["url"]),
            self._builtin("install_tool", "Install a missing tool via apt/pip.",
                          {"tool_name": ("string", "Tool name")}, ["tool_name"]),
            self._builtin("open_application", "Open a GUI app or URL.",
                          {"application": ("string", "App name"),
                           "url": ("string", "Optional URL")},
                          ["application"]),
            self._builtin("system_info", "Get hostname, IP, OS, memory, disk.", {}, []),
            self._builtin("read_screen", "Capture and read text from the screen.", {}, []),
        ]

        return selected + builtins

    @staticmethod
    def _builtin(name: str, desc: str, props: dict, required: list) -> dict:
        """Create a compact builtin tool definition."""
        properties = {}
        for pname, (ptype, pdesc) in props.items():
            properties[pname] = {"type": ptype, "description": pdesc}
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": desc,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    **({"required": required} if required else {}),
                },
            },
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _format_confirmation_description(
        tool_name: str, args: dict, risk_level: str
    ) -> str:
        """Format a human-readable confirmation description."""
        if tool_name == "run_command":
            return (
                f"⚠ {risk_level} RISK — Execute command:\n"
                f"  $ {args.get('command', '?')}\n"
                f"\nThis operation may modify the system or target. Proceed?"
            )
        elif tool_name == "install_tool":
            return (
                f"⚠ {risk_level} RISK — Install tool:\n"
                f"  Tool: {args.get('tool_name', '?')}\n"
                f"\nThis will install software on the system. Proceed?"
            )
        elif tool_name == "write_file":
            return (
                f"⚠ {risk_level} RISK — Write file:\n"
                f"  Path: {args.get('path', '?')}\n"
                f"  Size: {len(args.get('content', ''))} chars\n"
                f"\nProceed?"
            )
        else:
            return (
                f"⚠ {risk_level} RISK — Execute {tool_name}:\n"
                f"  Args: {json.dumps(args, indent=2)[:500]}\n"
                f"\nProceed?"
            )

    @property
    def session_id(self) -> str:
        return self._session_id


# ── Singleton ─────────────────────────────────────────────────────────────────
_AGENT: Optional[PentronixAgent] = None


async def get_agent() -> PentronixAgent:
    """Return the global PentronixAgent singleton, initialising on first call."""
    global _AGENT
    if _AGENT is None:
        _AGENT = PentronixAgent()
        await _AGENT.initialise()
    return _AGENT
