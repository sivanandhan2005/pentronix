"""
Pentronix Tool System — base class and auto-discovery for all agent tools.

Every tool module in this package registers Tool subclasses that the agent
can invoke via LLM function-calling.  At startup the agent calls
``discover_tools()`` to scan this package and collect every concrete Tool.
"""

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from utils.logger import get_logger

log = get_logger(__name__)


# ── Risk levels ───────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def needs_confirmation(self) -> bool:
        return self in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ── Tool result ───────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """Structured result returned by every tool execution."""
    success: bool
    output: str
    error: str = ""
    duration_seconds: float = 0.0
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_llm_string(self) -> str:
        """Compact representation fed back to the LLM."""
        if self.success:
            return self.output[:12000]
        return f"ERROR: {self.error}\n{self.output[:8000]}"


# ── Base Tool class ───────────────────────────────────────────────────────────

class Tool(ABC):
    """Abstract base for every Pentronix tool.

    Subclasses MUST set the class attributes and implement ``execute()``.
    The ``to_function_definition()`` method auto-generates the Groq/OpenAI
    compatible tool schema used for LLM function-calling.
    """

    # ── Subclass must override these ──────────────────────────────────────────
    name: str = ""
    description: str = ""
    parameters: dict = {}           # JSON Schema for the tool's parameters
    risk_level: RiskLevel = RiskLevel.LOW
    system_binary: Optional[str] = None   # e.g. "nmap" — checked for availability

    @abstractmethod
    async def execute(
        self,
        on_output: Optional[Callable[[str], None]] = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Run the tool with the given arguments.

        Args:
            on_output: Optional callback for streaming output lines.
            **kwargs: Tool-specific arguments matching ``self.parameters``.

        Returns:
            Structured :class:`ToolResult`.
        """
        ...

    # ── Auto-generated LLM schema ────────────────────────────────────────────

    def to_function_definition(self) -> dict:
        """Return a Groq/OpenAI-compatible function tool definition."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {"type": "object", "properties": {}},
            },
        }

    @property
    def needs_confirmation(self) -> bool:
        return self.risk_level.needs_confirmation

    def __repr__(self) -> str:
        return f"<Tool {self.name} [{self.risk_level.value}]>"


# ── Tool registry ────────────────────────────────────────────────────────────

_TOOL_INSTANCES: dict[str, Tool] = {}


def register_tool(tool: Tool) -> None:
    """Register a tool instance in the global registry."""
    if not tool.name:
        raise ValueError(f"Tool {tool.__class__.__name__} has no name")
    _TOOL_INSTANCES[tool.name] = tool
    log.debug("Registered tool: %s", tool.name)


def get_tool(name: str) -> Optional[Tool]:
    """Look up a registered tool by name."""
    return _TOOL_INSTANCES.get(name)


def get_all_tools() -> dict[str, Tool]:
    """Return all registered tools."""
    return dict(_TOOL_INSTANCES)


def get_all_function_definitions() -> list[dict]:
    """Return LLM function definitions for every registered tool."""
    return [t.to_function_definition() for t in _TOOL_INSTANCES.values()]


def discover_tools() -> dict[str, Tool]:
    """Auto-discover and register all Tool subclasses in the tools package.

    Scans every module in the ``tools`` package.  Any class that is a
    concrete subclass of :class:`Tool` (i.e. has a non-empty ``name``)
    is instantiated and registered.

    Returns:
        Dict mapping tool name → Tool instance.
    """
    import tools as pkg

    for _importer, mod_name, _ispkg in pkgutil.iter_modules(pkg.__path__):
        if mod_name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"tools.{mod_name}")
            for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, Tool)
                    and obj is not Tool
                    and getattr(obj, "name", "")
                    and obj.name not in _TOOL_INSTANCES
                ):
                    instance = obj()
                    register_tool(instance)
        except Exception as exc:
            log.warning("Failed to load tool module tools.%s: %s", mod_name, exc)

    log.info("Tool discovery complete: %d tools registered", len(_TOOL_INSTANCES))
    return dict(_TOOL_INSTANCES)
