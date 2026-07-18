"""
Pentronix Web Tools — web application security testing.

Provides:
  - gobuster_scan        — directory/file brute forcing
  - ffuf_fuzz            — web fuzzing
  - whatweb_fingerprint  — technology fingerprinting
  - curl_request         — raw HTTP requests
  - wfuzz_scan           — parameter fuzzing
  - wafw00f_detect       — WAF detection
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class GobusterScan(Tool):
    name = "gobuster_scan"
    description = (
        "Run Gobuster for directory and file brute forcing on web servers. "
        "Uses wordlists to discover hidden directories, files, and subdomains. "
        "Supports dir, dns, and vhost modes."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL (e.g. http://192.168.1.1 or http://example.com)",
            },
            "mode": {
                "type": "string",
                "enum": ["dir", "dns", "vhost"],
                "description": "Scan mode: dir (directory), dns (subdomain), vhost (virtual host). Default: dir",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist. Default: /usr/share/wordlists/dirb/common.txt",
            },
            "extensions": {
                "type": "string",
                "description": "File extensions to search for (e.g. 'php,html,txt,bak'). Optional.",
            },
            "status_codes": {
                "type": "string",
                "description": "Status codes to match (e.g. '200,204,301,302,307,401,403'). Optional.",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads. Default: 20",
            },
        },
        "required": ["url"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "gobuster"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        mode = kwargs.get("mode", "dir")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = kwargs.get("extensions", "")
        status_codes = kwargs.get("status_codes", "")
        threads = kwargs.get("threads", 20)

        cmd = f"gobuster {mode} -u {url} -w {wordlist} -t {threads} --no-error -q"
        if extensions and mode == "dir":
            cmd += f" -x {extensions}"
        if status_codes:
            cmd += f" -s {status_codes}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=300)
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class FfufFuzz(Tool):
    name = "ffuf_fuzz"
    description = (
        "Run ffuf (Fuzz Faster U Fool) for fast web fuzzing. "
        "Fuzzes URLs, headers, POST data, and more. Replaces FUZZ keyword "
        "in the target with wordlist entries."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL with FUZZ keyword (e.g. 'http://target.com/FUZZ')",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist. Default: /usr/share/wordlists/dirb/common.txt",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE"],
                "description": "HTTP method. Default: GET",
            },
            "data": {
                "type": "string",
                "description": "POST data with FUZZ keyword (e.g. 'username=FUZZ&password=test'). Optional.",
            },
            "headers": {
                "type": "string",
                "description": "Custom headers (e.g. 'Cookie: session=abc'). Optional.",
            },
            "filter_code": {
                "type": "string",
                "description": "Filter out these status codes (e.g. '404,403'). Optional.",
            },
            "match_code": {
                "type": "string",
                "description": "Match only these status codes (e.g. '200,301'). Optional.",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads. Default: 40",
            },
        },
        "required": ["url"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "ffuf"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        method = kwargs.get("method", "GET")
        data = kwargs.get("data", "")
        headers = kwargs.get("headers", "")
        filter_code = kwargs.get("filter_code", "")
        match_code = kwargs.get("match_code", "")
        threads = kwargs.get("threads", 40)

        cmd = f"ffuf -u {url} -w {wordlist} -t {threads} -X {method}"
        if data:
            cmd += f" -d '{data}'"
        if headers:
            cmd += f" -H '{headers}'"
        if filter_code:
            cmd += f" -fc {filter_code}"
        if match_code:
            cmd += f" -mc {match_code}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=300)
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class WhatwebFingerprint(Tool):
    name = "whatweb_fingerprint"
    description = (
        "Identify web technologies used by a website using WhatWeb. "
        "Detects CMS, web frameworks, server software, JavaScript libraries, "
        "analytics, and more."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or domain",
            },
            "aggression": {
                "type": "integer",
                "description": "Aggression level 1-4 (1=stealthy, 4=heavy). Default: 1",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "whatweb"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        aggression = kwargs.get("aggression", 1)
        executor = get_executor()
        result = await executor.execute(
            f"whatweb -a {aggression} --color=never {target}",
            on_output=on_output, timeout=60,
        )
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class CurlRequest(Tool):
    name = "curl_request"
    description = (
        "Make an HTTP request using curl. Send GET, POST, PUT, DELETE requests "
        "with custom headers, data, and authentication. Useful for API testing, "
        "manual exploitation, and data retrieval."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                "description": "HTTP method. Default: GET",
            },
            "headers": {
                "type": "object",
                "description": "Custom headers as key-value pairs",
            },
            "data": {
                "type": "string",
                "description": "Request body data. Optional.",
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Follow HTTP redirects. Default: true",
            },
            "include_headers": {
                "type": "boolean",
                "description": "Include response headers in output. Default: false",
            },
            "user_agent": {
                "type": "string",
                "description": "Custom User-Agent string. Optional.",
            },
        },
        "required": ["url"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        method = kwargs.get("method", "GET")
        headers = kwargs.get("headers", {})
        data = kwargs.get("data", "")
        follow = kwargs.get("follow_redirects", True)
        include_h = kwargs.get("include_headers", False)
        ua = kwargs.get("user_agent", "")

        cmd = f"curl -s -X {method}"
        if follow:
            cmd += " -L"
        if include_h:
            cmd += " -i"
        if ua:
            cmd += f" -A '{ua}'"
        for k, v in headers.items():
            cmd += f" -H '{k}: {v}'"
        if data:
            cmd += f" -d '{data}'"
        cmd += f" '{url}'"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=30)
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class Wafw00fDetect(Tool):
    name = "wafw00f_detect"
    description = (
        "Detect Web Application Firewalls (WAF) protecting a website. "
        "Identifies specific WAF products like Cloudflare, AWS WAF, Akamai, etc."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or domain",
            },
        },
        "required": ["target"],
    }
    risk_level = RiskLevel.LOW
    system_binary = "wafw00f"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        executor = get_executor()
        result = await executor.execute(
            f"wafw00f {target}", on_output=on_output, timeout=30,
        )
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )
