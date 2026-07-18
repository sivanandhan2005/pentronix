"""
Pentronix Vulnerability Scanner Tools — automated vulnerability discovery.

Provides registered Tool classes for:
  - nikto_scan       — web server vulnerability scanning
  - nuclei_scan      — template-based vulnerability scanning
  - searchsploit     — offline Exploit-DB search
  - nmap_vuln_scan   — nmap NSE vulnerability scripts
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class NiktoScan(Tool):
    name = "nikto_scan"
    description = (
        "Run Nikto web server vulnerability scanner against a target. "
        "Checks for dangerous files, outdated software, server misconfigs, "
        "and known vulnerabilities. Supports HTTP and HTTPS."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or IP (e.g. http://192.168.1.1 or example.com)",
            },
            "port": {
                "type": "integer",
                "description": "Target port. Default: 80",
            },
            "ssl": {
                "type": "boolean",
                "description": "Use SSL/TLS. Default: false",
            },
            "tuning": {
                "type": "string",
                "description": "Nikto tuning options (e.g. '123' for interesting files, misconfigs, info disclosure)",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "nikto"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        port = kwargs.get("port", "")
        ssl = kwargs.get("ssl", False)
        tuning = kwargs.get("tuning", "")

        cmd = f"nikto -h {target} -nointeractive"
        if port:
            cmd += f" -p {port}"
        if ssl:
            cmd += " -ssl"
        if tuning:
            cmd += f" -Tuning {tuning}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=180)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class NucleiScan(Tool):
    name = "nuclei_scan"
    description = (
        "Run Nuclei template-based vulnerability scanner. Uses community-maintained "
        "templates to detect CVEs, misconfigurations, exposed panels, default logins, "
        "and more. Very fast and comprehensive."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or IP to scan",
            },
            "templates": {
                "type": "string",
                "description": "Specific template tags to use (e.g. 'cve', 'rce', 'sqli', 'xss'). Optional.",
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Minimum severity level. Default: medium",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "nuclei"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        templates = kwargs.get("templates", "")
        severity = kwargs.get("severity", "medium")

        cmd = f"nuclei -u {target} -severity {severity} -silent"
        if templates:
            cmd += f" -tags {templates}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=300)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class SearchsploitSearch(Tool):
    name = "searchsploit"
    description = (
        "Search the local Exploit-DB database for known exploits. "
        "Finds exploits matching a service name, version, or product. "
        "Works completely offline."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query — service name, version, or CVE (e.g. 'Apache 2.4.49' or 'vsftpd 2.3')",
            },
            "exact": {
                "type": "boolean",
                "description": "Use exact match instead of fuzzy search. Default: false",
            },
        },
        "required": ["query"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "searchsploit"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        query = kwargs.get("query", "")
        exact = kwargs.get("exact", False)

        cmd = f"searchsploit {query}"
        if exact:
            cmd += " --exact"
        cmd += " --colour"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=30)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class NmapVulnScan(Tool):
    name = "nmap_vuln_scan"
    description = (
        "Run nmap with NSE vulnerability detection scripts. "
        "Checks for known vulnerabilities like Heartbleed, EternalBlue, "
        "ShellShock, and many more CVEs."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or domain to scan for vulnerabilities",
            },
            "ports": {
                "type": "string",
                "description": "Specific ports to check (e.g. '80,443,445'). Default: top 1000",
            },
            "scripts": {
                "type": "string",
                "description": "Specific NSE scripts (e.g. 'smb-vuln-*,http-vuln-*'). Default: vuln",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "nmap"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        target = kwargs.get("target", "")
        ports = kwargs.get("ports", "")
        scripts = kwargs.get("scripts", "vuln")

        cmd = f"nmap -sV --script {scripts} -T4"
        if ports:
            cmd += f" -p {ports}"
        cmd += f" {target}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=300)
        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )
