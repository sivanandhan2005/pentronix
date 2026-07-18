"""
Pentronix Intent Schema — Pydantic models for structured LLM output.

Every LLM response is validated against these models before any
command is executed, ensuring type safety and predictable behaviour.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class IntentType(str, Enum):
    """Enumeration of all supported user intents."""

    PORT_SCAN = "port_scan"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    BRUTE_FORCE = "brute_force"
    RECON = "recon"
    WEB_SCAN = "web_scan"
    REPORT = "report"
    HISTORY = "history"
    EXPLAIN = "explain"
    STOP = "stop"
    CUSTOM = "custom"
    TOOL_SCAN = "tool_scan"
    SAVE = "save"
    SETTINGS = "settings"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk classification returned in every intent."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolName(str, Enum):
    """Known Kali Linux tools Pentronix can invoke."""

    NMAP = "nmap"
    METASPLOIT = "metasploit"
    GOBUSTER = "gobuster"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    HYDRA = "hydra"
    JOHN = "john"
    HASHCAT = "hashcat"
    AIRCRACK = "aircrack-ng"
    WFUZZ = "wfuzz"
    DIRB = "dirb"
    ENUM4LINUX = "enum4linux"
    SMBCLIENT = "smbclient"
    WHATWEB = "whatweb"
    WAFW00F = "wafw00f"
    SUBFINDER = "subfinder"
    AMASS = "amass"
    THEHARVESTER = "theharvester"
    NETCAT = "netcat"
    CURL = "curl"
    WGET = "wget"
    WHOIS = "whois"
    DIG = "dig"
    HOST = "host"
    PING = "ping"
    TRACEROUTE = "traceroute"
    ARP_SCAN = "arp-scan"
    MASSCAN = "masscan"
    RUSTSCAN = "rustscan"
    FFUF = "ffuf"
    NUCLEI = "nuclei"
    SEARCHSPLOIT = "searchsploit"
    CUSTOM = "custom"
    NONE = "null"


class IntentResponse(BaseModel):
    """Structured intent parsed from the LLM response.

    Every field is Optional to allow the model to omit fields that do
    not apply to the current intent; the execution engine checks for
    required fields before running commands.
    """

    understood_command: str = Field(
        description="Plain English translation of what the user said."
    )
    intent: IntentType = Field(
        description="Classified user intent."
    )
    target: Optional[str] = Field(
        default=None,
        description="IP address, domain, or CIDR range. Null if not applicable.",
    )
    tool: Optional[str] = Field(
        default=None,
        description="Kali tool to invoke, or null.",
    )
    command: Optional[str] = Field(
        default=None,
        description="Complete shell command to execute.",
    )
    flags: Optional[str] = Field(
        default=None,
        description="Flags and arguments passed to the tool.",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.LOW,
        description="Risk classification of this action.",
    )
    risk_reason: str = Field(
        default="",
        description="Short explanation for the assigned risk level.",
    )
    confirmation_message: Optional[str] = Field(
        default=None,
        description="Message shown to user when HIGH or CRITICAL risk requires confirmation.",
    )
    response_message: str = Field(
        default="",
        description="Friendly conversational response to show user before executing.",
    )
    expected_duration: Optional[int] = Field(
        default=None,
        description="Estimated execution time in seconds.",
    )
    follow_up_suggestions: list[str] = Field(
        default_factory=list,
        description="Suggested next commands after this action completes.",
    )

    @field_validator("command", mode="before")
    @classmethod
    def strip_command(cls, v: Optional[str]) -> Optional[str]:
        """Remove accidental surrounding quotes from LLM-generated commands."""
        if v is None:
            return v
        return v.strip().strip('"').strip("'")

    @field_validator("target", mode="before")
    @classmethod
    def normalise_target(cls, v: Optional[str]) -> Optional[str]:
        """Normalise null-like LLM strings to Python None."""
        if v in (None, "null", "none", "None", "N/A", "n/a", ""):
            return None
        return v.strip()

    @field_validator("tool", mode="before")
    @classmethod
    def normalise_tool(cls, v: Optional[str]) -> Optional[str]:
        """Normalise null-like tool values."""
        if v in (None, "null", "none", "None", "N/A", ""):
            return None
        return v.strip().lower()

    class Config:  # noqa: D106
        use_enum_values = True


class ParsedOutput(BaseModel):
    """Structured data extracted from a tool's raw stdout by :mod:`core.output_parser`."""

    tool: str
    raw: str = Field(description="Full raw stdout/stderr of the tool.")
    open_ports: list[dict] = Field(default_factory=list)
    services: list[dict] = Field(default_factory=list)
    vulnerabilities: list[dict] = Field(default_factory=list)
    credentials: list[dict] = Field(default_factory=list)
    paths: list[dict] = Field(default_factory=list)
    exploits: list[dict] = Field(default_factory=list)
    extra: dict = Field(
        default_factory=dict,
        description="Tool-specific extra fields not covered by generic schema.",
    )
    ai_summary: str = Field(
        default="",
        description="AI-generated natural language summary of the parsed output.",
    )
