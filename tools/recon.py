"""
Pentronix Recon Tools — network reconnaissance and discovery.

Provides registered Tool classes for:
  - nmap_scan       — port/service/OS scanning
  - whois_lookup    — domain registration info
  - dns_lookup      — DNS record queries
  - subdomain_enum  — subdomain discovery
  - ping_host       — ICMP reachability
  - traceroute      — network path tracing
  - arp_scan        — local network host discovery
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class NmapScan(Tool):
    name = "nmap_scan"
    description = (
        "Run an nmap scan on a target IP or domain. Supports different scan types: "
        "quick (top 100 ports), version (service detection), aggressive (OS+scripts), "
        "vuln (vulnerability scripts), full (all 65535 ports). Returns open ports, "
        "services, versions, and OS detection results."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address, domain, or CIDR range to scan",
            },
            "scan_type": {
                "type": "string",
                "enum": ["quick", "version", "aggressive", "vuln", "full", "udp", "ping_sweep"],
                "description": "Type of scan to perform. Default: version",
            },
            "ports": {
                "type": "string",
                "description": "Specific ports to scan (e.g. '80,443,8080' or '1-1000'). Optional.",
            },
            "extra_flags": {
                "type": "string",
                "description": "Additional nmap flags to append. Optional.",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "nmap"

    _SCAN_FLAGS = {
        "quick": "-sV --top-ports 100 -T4",
        "version": "-sV --top-ports 1000 -T4",
        "aggressive": "-A -O -T4 --script=default",
        "vuln": "-sV --script vuln -T4",
        "full": "-sV -p- -T4",
        "udp": "-sU --top-ports 50 -T4",
        "ping_sweep": "-sn",
    }

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        scan_type = kwargs.get("scan_type", "version")
        ports = kwargs.get("ports", "")
        extra = kwargs.get("extra_flags", "")

        flags = self._SCAN_FLAGS.get(scan_type, self._SCAN_FLAGS["version"])
        if ports:
            # Remove --top-ports if specific ports given
            flags = flags.replace("--top-ports 100", "").replace("--top-ports 1000", "")
            flags += f" -p {ports}"
        if extra:
            flags += f" {extra}"

        # Aggressive/vuln scans are MEDIUM risk
        if scan_type in ("aggressive", "vuln", "full"):
            self.risk_level = RiskLevel.MEDIUM

        cmd = f"nmap {flags} {target}"
        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output)

        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class WhoisLookup(Tool):
    name = "whois_lookup"
    description = "Look up domain registration information using whois."
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Domain name or IP address to look up",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "whois"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        executor = get_executor()
        result = await executor.execute(f"whois {target}", on_output=on_output, timeout=30)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class DnsLookup(Tool):
    name = "dns_lookup"
    description = (
        "Perform DNS lookups using dig. Query A, AAAA, MX, NS, TXT, CNAME, SOA, "
        "ANY records for a domain."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Domain name to query",
            },
            "record_type": {
                "type": "string",
                "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"],
                "description": "DNS record type. Default: A",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "dig"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        rtype = kwargs.get("record_type", "A")
        executor = get_executor()
        result = await executor.execute(
            f"dig {target} {rtype} +noall +answer +authority",
            on_output=on_output, timeout=15,
        )
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class SubdomainEnum(Tool):
    name = "subdomain_enum"
    description = (
        "Enumerate subdomains for a domain using subfinder or amass. "
        "Discovers hidden subdomains that may have vulnerabilities."
    )
    parameters = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Target domain for subdomain enumeration",
            },
            "tool": {
                "type": "string",
                "enum": ["subfinder", "amass"],
                "description": "Enumeration tool to use. Default: subfinder",
            },
        },
        "required": ["domain"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "subfinder"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        domain = kwargs.get("domain", "")
        tool = kwargs.get("tool", "subfinder")
        executor = get_executor()

        if tool == "amass":
            cmd = f"amass enum -passive -d {domain}"
        else:
            cmd = f"subfinder -d {domain} -silent"

        result = await executor.execute(cmd, on_output=on_output, timeout=120)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class PingHost(Tool):
    name = "ping_host"
    description = "Check if a host is reachable using ICMP ping."
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address or hostname to ping",
            },
            "count": {
                "type": "integer",
                "description": "Number of ping packets. Default: 4",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "ping"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        count = kwargs.get("count", 4)
        executor = get_executor()
        result = await executor.execute(
            f"ping -c {count} -W 3 {target}",
            on_output=on_output, timeout=30,
        )
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class Traceroute(Tool):
    name = "traceroute_host"
    description = "Trace the network path to a target host."
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address or hostname to trace",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "traceroute"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        executor = get_executor()
        result = await executor.execute(
            f"traceroute -m 20 -w 2 {target}",
            on_output=on_output, timeout=60,
        )
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class ArpScan(Tool):
    name = "arp_scan"
    description = (
        "Discover hosts on the local network using ARP scanning. "
        "Finds all active devices on the same subnet."
    )
    parameters = {
        "type": "object",
        "properties": {
            "interface": {
                "type": "string",
                "description": "Network interface to use (e.g. eth0, wlan0). Optional.",
            },
            "subnet": {
                "type": "string",
                "description": "Subnet to scan (e.g. 192.168.1.0/24). Default: local network.",
            },
        },
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "arp-scan"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        interface = kwargs.get("interface", "")
        subnet = kwargs.get("subnet", "--localnet")
        executor = get_executor()

        iface_flag = f"-I {interface}" if interface else ""
        cmd = f"sudo arp-scan {iface_flag} {subnet}"

        result = await executor.execute(cmd, on_output=on_output, timeout=30)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )
