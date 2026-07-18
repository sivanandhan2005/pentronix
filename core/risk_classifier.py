"""
Pentronix Risk Classifier — maps intent and command attributes to risk levels.

Provides deterministic classification independent of the LLM so the
execution engine can enforce safety gates even if the model returns an
unexpected or downgraded risk level.
"""

import re
from enum import IntEnum
from typing import Optional

from prompts.intent_schema import IntentResponse, IntentType, RiskLevel
from utils.logger import get_logger

log = get_logger(__name__)


class RiskScore(IntEnum):
    """Numeric representation of risk for comparison operators."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ── Pattern tables ────────────────────────────────────────────────────────────

# Commands / flags that unconditionally raise to CRITICAL
_CRITICAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\brm\s+-rf?\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bshred\b"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/etc/passwd"),
    re.compile(r"/root/"),
    re.compile(r"\breverse.?shell\b", re.IGNORECASE),
    re.compile(r"bash\s+-i\s+>&"),
    re.compile(r"mknod.*\bbackpipe\b"),
    re.compile(r"nc\s+-e\s+/bin/"),
    re.compile(r"python.*socket.*exec"),
]

# Commands / flags that raise to HIGH
_HIGH_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bhydra\b"),
    re.compile(r"\bjohn\b"),
    re.compile(r"\bhashcat\b"),
    re.compile(r"\bsqlmap\b.*--dump"),
    re.compile(r"\bsqlmap\b.*--data"),
    re.compile(r"\bmsfconsole\b"),
    re.compile(r"\bmsfvenom\b"),
    re.compile(r"--exploit"),
    re.compile(r"--attack"),
    re.compile(r"\baircrack"),
]

# Commands / flags that raise to MEDIUM (but not above HIGH)
_MEDIUM_PATTERNS: list[re.Pattern] = [
    re.compile(r"nmap.*-A\b"),
    re.compile(r"nmap.*-O\b"),
    re.compile(r"nmap.*-p-\b"),
    re.compile(r"nmap.*--script"),
    re.compile(r"\bmasscan\b"),
    re.compile(r"\brustscan\b"),
    re.compile(r"\bsqlmap\b"),       # detect-only sqlmap still MEDIUM
    re.compile(r"nikto.*-Tuning"),
    re.compile(r"\barp-scan\b"),
)

# Intents always LOW regardless of tool
_ALWAYS_LOW_INTENTS: set[IntentType] = {
    IntentType.REPORT,
    IntentType.HISTORY,
    IntentType.EXPLAIN,
    IntentType.STOP,
    IntentType.SETTINGS,
    IntentType.SAVE,
    IntentType.TOOL_SCAN,
    IntentType.UNKNOWN,
}


def _level_to_score(level: RiskLevel) -> RiskScore:
    return RiskScore[level.upper()]


def _score_to_level(score: RiskScore) -> RiskLevel:
    return RiskLevel(score.name)


# ── Public API ────────────────────────────────────────────────────────────────

def classify(intent: IntentResponse) -> IntentResponse:
    """Enforce deterministic risk classification on *intent*.

    Compares the LLM-assigned risk level against pattern-based rules
    and always takes the **maximum** (most restrictive) result.

    Args:
        intent: Parsed :class:`IntentResponse` from the LLM.

    Returns:
        The same object with :attr:`risk_level` updated in-place.
    """
    if intent.intent in _ALWAYS_LOW_INTENTS:
        intent.risk_level = RiskLevel.LOW
        intent.risk_reason = f"Intent '{intent.intent}' is read-only, no risk."
        return intent

    determined_score = _level_to_score(intent.risk_level)
    command_str = (intent.command or "") + " " + (intent.flags or "")

    # Check CRITICAL patterns first
    for pat in _CRITICAL_PATTERNS:
        if pat.search(command_str):
            determined_score = max(determined_score, RiskScore.CRITICAL)
            log.warning("CRITICAL pattern matched: %s in '%s'", pat.pattern, command_str[:80])
            break

    # Check HIGH patterns
    for pat in _HIGH_PATTERNS:
        if pat.search(command_str):
            determined_score = max(determined_score, RiskScore.HIGH)
            break

    # Check MEDIUM patterns
    for pat in _MEDIUM_PATTERNS:
        if pat.search(command_str):
            determined_score = max(determined_score, RiskScore.MEDIUM)
            break

    # Exploit / brute_force intent always at least HIGH
    if intent.intent in (IntentType.EXPLOIT, IntentType.BRUTE_FORCE):
        determined_score = max(determined_score, RiskScore.HIGH)

    # Public target check — non-private IP bumps to at least HIGH
    if intent.target and _is_public_ip(intent.target):
        determined_score = max(determined_score, RiskScore.HIGH)
        if determined_score >= RiskScore.HIGH and not intent.confirmation_message:
            intent.confirmation_message = (
                f"⚠ Target {intent.target} appears to be a public IP address. "
                "Only proceed if you have written authorisation to test this system. "
                "Type YES to confirm."
            )

    final_level = _score_to_level(determined_score)
    if final_level != intent.risk_level:
        log.info(
            "Risk level upgraded by classifier: %s → %s for command: %s",
            intent.risk_level,
            final_level,
            (intent.command or "")[:60],
        )
        intent.risk_level = final_level

    # Populate confirmation_message for HIGH/CRITICAL if missing
    if intent.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        if not intent.confirmation_message:
            intent.confirmation_message = _build_confirmation_message(intent)

    return intent


def requires_confirmation(level: RiskLevel) -> bool:
    """Return ``True`` if this risk level requires user confirmation.

    Args:
        level: Risk level to check.

    Returns:
        ``True`` for HIGH and CRITICAL.
    """
    return level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def requires_typed_confirmation(level: RiskLevel) -> bool:
    """Return ``True`` if this risk level requires the user to type 'I CONFIRM'.

    Args:
        level: Risk level to check.

    Returns:
        ``True`` only for CRITICAL.
    """
    return level == RiskLevel.CRITICAL


def _is_public_ip(target: str) -> bool:
    """Heuristic check whether *target* looks like a public IP address."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(target.split("/")[0])
        private_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
        return not any(addr in net for net in private_nets)
    except ValueError:
        return False  # Domain names — treat as needing manual review


def _build_confirmation_message(intent: IntentResponse) -> str:
    """Generate a default confirmation message based on intent context."""
    if intent.risk_level == RiskLevel.CRITICAL:
        return (
            f"🚨 CRITICAL RISK: '{intent.command}'\n"
            "This command could cause irreversible damage or violate laws.\n"
            "Type exactly: I CONFIRM — to proceed."
        )
    return (
        f"⚠ HIGH RISK: The following command will be executed:\n"
        f"  {intent.command}\n"
        f"Reason: {intent.risk_reason}\n"
        "Press YES to continue or NO to cancel."
    )
