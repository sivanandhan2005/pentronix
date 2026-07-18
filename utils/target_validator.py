"""
Pentronix Target Validator — IP/domain/range validation with ethics checks.

Validates scan targets before any command is executed. Enforces
responsible-disclosure warnings when public IPs are targeted and
prevents obviously destructive targets from running silently.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

from utils.logger import get_logger

log = get_logger(__name__)


# ── Private / RFC-1918 Networks ───────────────────────────────────────────────
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space
]

_PRIVATE_V6: list[ipaddress.IPv6Network] = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# ── Regex Patterns ────────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_CIDR_RE = re.compile(r"^[\d.]+/\d{1,2}$")
_IP_RANGE_RE = re.compile(r"^[\d.]+-[\d.]+$")   # e.g. 192.168.1.1-192.168.1.254


class TargetKind(str, Enum):
    """Classification of a validated target string."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Ethical risk level of the target."""

    SAFE = "safe"           # Private / loopback
    WARNING = "warning"     # Public IP — warn but allow with confirmation
    BLOCKED = "blocked"     # Explicitly dangerous / malformed


@dataclass(frozen=True)
class ValidationResult:
    """Immutable result of a target validation check."""

    original: str
    normalised: str
    kind: TargetKind
    is_valid: bool
    is_private: bool
    risk_level: RiskLevel
    message: str
    resolved_ip: Optional[str] = None      # For domains — DNS resolved IP
    cidr_count: Optional[int] = None       # For CIDR — host count


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private_ip(addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Return ``True`` if *addr* falls in any private/reserved range."""
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _PRIVATE_NETWORKS)
    return any(addr in net for net in _PRIVATE_V6)


def _resolve_domain(domain: str) -> Optional[str]:
    """Attempt to resolve *domain* to its first A record.

    Returns:
        IP string or ``None`` on failure.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ── Core Validator ─────────────────────────────────────────────────────────────

def validate_target(raw_target: str) -> ValidationResult:
    """Validate and classify a pentesting target string.

    Performs syntax checking, IP/domain classification, private-range
    detection, and attaches an ethical risk level.

    Args:
        raw_target: Raw user-supplied target string (IP, CIDR, domain …).

    Returns:
        :class:`ValidationResult` with full details.
    """
    target = raw_target.strip().rstrip("/")

    if not target:
        return ValidationResult(
            original=raw_target,
            normalised="",
            kind=TargetKind.UNKNOWN,
            is_valid=False,
            is_private=False,
            risk_level=RiskLevel.BLOCKED,
            message="Target cannot be empty.",
        )

    # ── IPv4 ──────────────────────────────────────────────────────────
    try:
        ip4 = ipaddress.IPv4Address(target)
        private = _is_private_ip(ip4)
        risk = RiskLevel.SAFE if private else RiskLevel.WARNING
        msg = (
            "Private IPv4 — safe to scan."
            if private
            else (
                f"⚠  Public IPv4 {ip4}. Only scan systems you own or have "
                "written authorisation for. Proceed with caution."
            )
        )
        return ValidationResult(
            original=raw_target,
            normalised=str(ip4),
            kind=TargetKind.IPV4,
            is_valid=True,
            is_private=private,
            risk_level=risk,
            message=msg,
        )
    except ValueError:
        pass

    # ── IPv6 ──────────────────────────────────────────────────────────
    try:
        ip6 = ipaddress.IPv6Address(target)
        private = _is_private_ip(ip6)
        risk = RiskLevel.SAFE if private else RiskLevel.WARNING
        msg = "Private IPv6 — safe to scan." if private else f"⚠  Public IPv6 {ip6}."
        return ValidationResult(
            original=raw_target,
            normalised=str(ip6),
            kind=TargetKind.IPV6,
            is_valid=True,
            is_private=private,
            risk_level=risk,
            message=msg,
        )
    except ValueError:
        pass

    # ── CIDR ──────────────────────────────────────────────────────────
    if _CIDR_RE.match(target):
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = net.num_addresses
            private = all(_is_private_ip(h) for h in [net.network_address, net.broadcast_address])
            risk = RiskLevel.SAFE if private else RiskLevel.WARNING
            msg = (
                f"CIDR range {net} — {hosts:,} addresses. "
                + ("Private network." if private else "⚠  Contains public addresses.")
            )
            return ValidationResult(
                original=raw_target,
                normalised=str(net),
                kind=TargetKind.CIDR,
                is_valid=True,
                is_private=private,
                risk_level=risk,
                message=msg,
                cidr_count=hosts,
            )
        except ValueError:
            pass

    # ── IP range A.B.C.D-A.B.C.E ─────────────────────────────────────
    if _IP_RANGE_RE.match(target):
        parts = target.split("-")
        try:
            ipaddress.IPv4Address(parts[0])
            ipaddress.IPv4Address(parts[1])
            return ValidationResult(
                original=raw_target,
                normalised=target,
                kind=TargetKind.IP_RANGE,
                is_valid=True,
                is_private=True,   # Assume — user should verify
                risk_level=RiskLevel.WARNING,
                message=f"IP range {target}.",
            )
        except ValueError:
            pass

    # ── Domain ────────────────────────────────────────────────────────
    if _DOMAIN_RE.match(target):
        resolved = _resolve_domain(target)
        is_private = False
        risk = RiskLevel.WARNING

        if resolved:
            try:
                addr = ipaddress.IPv4Address(resolved)
                is_private = _is_private_ip(addr)
                risk = RiskLevel.SAFE if is_private else RiskLevel.WARNING
            except ValueError:
                pass

        msg = (
            f"Domain {target}"
            + (f" → {resolved}" if resolved else " (DNS resolution failed)")
            + (" [private]" if is_private else " [public — ensure authorisation]")
        )
        return ValidationResult(
            original=raw_target,
            normalised=target.lower(),
            kind=TargetKind.DOMAIN,
            is_valid=True,
            is_private=is_private,
            risk_level=risk,
            message=msg,
            resolved_ip=resolved,
        )

    # ── Unknown / malformed ───────────────────────────────────────────
    log.warning("Unrecognised target format: %r", raw_target)
    return ValidationResult(
        original=raw_target,
        normalised=target,
        kind=TargetKind.UNKNOWN,
        is_valid=False,
        is_private=False,
        risk_level=RiskLevel.BLOCKED,
        message=(
            f"'{raw_target}' is not a recognised IP address, CIDR range, or domain. "
            "Please check the target and try again."
        ),
    )


def extract_target_from_text(text: str) -> Optional[str]:
    """Best-effort extraction of an IP/domain from free-form user input.

    Args:
        text: Raw user input string.

    Returns:
        First plausible target string found, or ``None``.
    """
    # IPv4 pattern
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b", text)
    if ip_match:
        return ip_match.group(1)

    # Domain-like pattern
    dom_match = re.search(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        text,
    )
    if dom_match:
        return dom_match.group(0)

    return None
