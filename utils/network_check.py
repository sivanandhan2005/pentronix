"""
Pentronix Network Check — lightweight internet connectivity probe.

Verifies that the host machine has a working internet connection
before relying on cloud LLM APIs or remote resources.
"""

import asyncio
import socket
import time
from typing import Optional

import aiohttp

from utils.logger import get_logger

log = get_logger(__name__)

# Lightweight hosts to probe — in-order preference
_PROBE_HOSTS: list[tuple[str, int]] = [
    ("8.8.8.8", 53),       # Google DNS
    ("1.1.1.1", 53),       # Cloudflare DNS
    ("9.9.9.9", 53),       # Quad9 DNS
]

_HTTP_PROBES: list[str] = [
    "https://www.google.com",
    "https://api.groq.com",
]

_TIMEOUT_SECONDS: float = 3.0


async def check_tcp(host: str, port: int, timeout: float = _TIMEOUT_SECONDS) -> bool:
    """Attempt a TCP connection to *host:port*.

    Args:
        host: Remote hostname or IP address.
        port: Remote port number.
        timeout: Connection timeout in seconds.

    Returns:
        ``True`` if the connection succeeds, ``False`` otherwise.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def check_http(url: str, timeout: float = _TIMEOUT_SECONDS) -> bool:
    """Perform a lightweight HTTP HEAD request to *url*.

    Args:
        url: Full URL to probe.
        timeout: Request timeout in seconds.

    Returns:
        ``True`` if an HTTP response (any status code) is received.
    """
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                return resp.status < 600
    except Exception:  # noqa: BLE001
        return False


async def is_online(detailed: bool = False) -> bool:
    """Check whether the machine has a working internet connection.

    Probes DNS TCP then HTTP endpoints sequentially.

    Args:
        detailed: If ``True``, log detailed probe results.

    Returns:
        ``True`` if any probe succeeds.
    """
    start = time.monotonic()

    # Fast TCP probes first
    for host, port in _PROBE_HOSTS:
        if await check_tcp(host, port):
            elapsed = time.monotonic() - start
            if detailed:
                log.debug("TCP probe %s:%d OK (%.0f ms)", host, port, elapsed * 1000)
            return True

    # Slower HTTP fallback
    for url in _HTTP_PROBES:
        if await check_http(url):
            elapsed = time.monotonic() - start
            if detailed:
                log.debug("HTTP probe %s OK (%.0f ms)", url, elapsed * 1000)
            return True

    log.warning("All network probes failed — host appears offline")
    return False


def is_online_sync() -> bool:
    """Synchronous wrapper around :func:`is_online`.

    Use this in non-async contexts (e.g. startup checks).

    Returns:
        ``True`` if any probe succeeds.
    """
    try:
        return asyncio.run(is_online())
    except RuntimeError:
        # Already inside an event loop — use a socket fallback
        for host, port in _PROBE_HOSTS:
            try:
                with socket.create_connection((host, port), timeout=_TIMEOUT_SECONDS):
                    return True
            except OSError:
                continue
        return False


async def groq_api_reachable() -> bool:
    """Quick check that the Groq API endpoint is reachable.

    Returns:
        ``True`` if the Groq API host responds to a TCP probe.
    """
    return await check_tcp("api.groq.com", 443)


async def gemini_api_reachable() -> bool:
    """Quick check that the Gemini API endpoint is reachable.

    Returns:
        ``True`` if the Gemini generativelanguage host responds.
    """
    return await check_tcp("generativelanguage.googleapis.com", 443)


async def api_status() -> dict[str, bool]:
    """Return a status dict for all external API endpoints.

    Returns:
        Mapping of service name → reachability boolean.
    """
    groq, gemini = await asyncio.gather(
        groq_api_reachable(),
        gemini_api_reachable(),
    )
    return {
        "internet": groq or gemini,
        "groq": groq,
        "gemini": gemini,
    }
