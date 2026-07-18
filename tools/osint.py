"""
Pentronix OSINT Tools — open source intelligence gathering.

Provides:
  - theharvester_scan — email, subdomain, host harvesting
  - google_dork       — Google dorking for information disclosure
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class TheHarvesterScan(Tool):
    name = "theharvester_scan"
    description = (
        "Run theHarvester for OSINT gathering. Collects emails, subdomains, "
        "hosts, employee names, open ports, and banners from different public "
        "sources including search engines, PGP key servers, and SHODAN."
    )
    parameters = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Target domain for OSINT gathering",
            },
            "source": {
                "type": "string",
                "enum": ["all", "google", "bing", "yahoo", "duckduckgo", "baidu", "linkedin", "twitter", "crtsh", "dnsdumpster", "hackertarget", "rapiddns", "sublist3r", "threatcrowd", "urlscan", "virustotal"],
                "description": "Data source to use. Default: all",
            },
            "limit": {
                "type": "integer",
                "description": "Limit number of results. Default: 200",
            },
        },
        "required": ["domain"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "theHarvester"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        domain = kwargs.get("domain", "")
        source = kwargs.get("source", "all")
        limit = kwargs.get("limit", 200)

        cmd = f"theHarvester -d {domain} -b {source} -l {limit}"
        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=180)
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class GoogleDork(Tool):
    name = "google_dork"
    description = (
        "Perform Google dorking to find exposed sensitive information. "
        "Searches for configuration files, login pages, exposed directories, "
        "database dumps, and more using advanced Google search operators."
    )
    parameters = {
        "type": "object",
        "properties": {
            "dork": {
                "type": "string",
                "description": "Google dork query (e.g. 'site:target.com filetype:sql', 'inurl:admin intitle:login')",
            },
            "target_domain": {
                "type": "string",
                "description": "Target domain to restrict search to. Optional.",
            },
        },
        "required": ["dork"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        dork = kwargs.get("dork", "")
        domain = kwargs.get("target_domain", "")

        query = dork
        if domain and f"site:{domain}" not in dork:
            query = f"site:{domain} {dork}"

        from core.internet_researcher import get_researcher
        researcher = get_researcher()
        results = await researcher.search(query, max_results=10)

        if results:
            output_lines = []
            for i, r in enumerate(results, 1):
                output_lines.append(f"\n[{i}] {r['title']}")
                output_lines.append(f"    URL: {r['url']}")
                output_lines.append(f"    {r['snippet']}")
            output = "\n".join(output_lines)
        else:
            output = "No results found for this dork query."

        if on_output:
            on_output(output)

        return ToolResult(success=bool(results), output=output)
