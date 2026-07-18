"""
Pentronix Browser Tools — open applications, URLs, and media.

Provides:
  - open_browser      — open URL in default browser
  - open_app          — launch system applications
  - play_media        — play YouTube or local media
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class OpenBrowser(Tool):
    name = "open_browser"
    description = (
        "Open a URL in the default web browser. Can also open specific "
        "browsers like Firefox or Chromium with a given URL."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "URL to open (e.g. https://google.com)",
            },
            "browser": {
                "type": "string",
                "description": "Specific browser to use (firefox, chromium, brave-browser). Default: system default",
            },
            "private": {
                "type": "boolean",
                "description": "Open in private/incognito mode. Default: false",
            },
        },
        "required": ["url"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        url = kwargs.get("url", "")
        browser = kwargs.get("browser", "")
        private = kwargs.get("private", False)
        executor = get_executor()

        if browser:
            if private:
                private_flags = {
                    "firefox": "--private-window",
                    "chromium": "--incognito",
                    "brave-browser": "--incognito",
                    "google-chrome": "--incognito",
                }
                flag = private_flags.get(browser, "--private-window")
                cmd = f"nohup {browser} {flag} '{url}' &>/dev/null &"
            else:
                cmd = f"nohup {browser} '{url}' &>/dev/null &"
        else:
            cmd = f"nohup xdg-open '{url}' &>/dev/null &"

        result = await executor.execute(cmd, on_output=on_output, timeout=5)
        msg = f"Opened {url}" + (f" in {browser}" if browser else " in default browser")
        if on_output:
            on_output(msg)
        return ToolResult(success=True, output=msg)


class OpenApp(Tool):
    name = "open_app"
    description = (
        "Launch a system application. Can open any installed GUI or CLI "
        "application like Wireshark, Burp Suite, BeEF, terminal emulators, "
        "text editors, file managers, and more."
    )
    parameters = {
        "type": "object",
        "properties": {
            "application": {
                "type": "string",
                "description": "Application name or command (e.g. wireshark, burpsuite, firefox, terminal, nautilus, gedit)",
            },
            "arguments": {
                "type": "string",
                "description": "Command-line arguments to pass. Optional.",
            },
        },
        "required": ["application"],
    }
    risk_level = RiskLevel.LOW

    # Map common names to actual commands
    _APP_MAP = {
        "wireshark": "wireshark",
        "burpsuite": "burpsuite",
        "burp": "burpsuite",
        "beef": "beef-xss",
        "beef-xss": "beef-xss",
        "terminal": "x-terminal-emulator",
        "term": "x-terminal-emulator",
        "file manager": "nautilus",
        "files": "nautilus",
        "text editor": "gedit",
        "editor": "gedit",
        "code": "code",
        "vscode": "code",
        "ettercap": "ettercap -G",
        "bettercap": "sudo bettercap",
        "maltego": "maltego",
        "autopsy": "autopsy",
        "ghidra": "ghidra",
    }

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        app = kwargs.get("application", "")
        args = kwargs.get("arguments", "")
        executor = get_executor()

        actual_cmd = self._APP_MAP.get(app.lower(), app)
        if args:
            actual_cmd += f" {args}"

        cmd = f"nohup {actual_cmd} &>/dev/null &"
        result = await executor.execute(cmd, on_output=on_output, timeout=5)
        msg = f"Launched {app}"
        if on_output:
            on_output(msg)
        return ToolResult(success=True, output=msg)


class PlayMedia(Tool):
    name = "play_media"
    description = (
        "Search and play media. Can search YouTube and open the result, "
        "or play local media files using the default media player."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "YouTube search query or local file path",
            },
            "source": {
                "type": "string",
                "enum": ["youtube", "local"],
                "description": "Media source. Default: youtube",
            },
        },
        "required": ["query"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        query = kwargs.get("query", "")
        source = kwargs.get("source", "youtube")
        executor = get_executor()

        if source == "youtube":
            # Open YouTube search in browser
            import urllib.parse
            encoded = urllib.parse.quote_plus(query)
            url = f"https://www.youtube.com/results?search_query={encoded}"
            cmd = f"nohup xdg-open '{url}' &>/dev/null &"
            result = await executor.execute(cmd, on_output=on_output, timeout=5)
            msg = f"Opened YouTube search for: {query}"
        else:
            cmd = f"nohup xdg-open '{query}' &>/dev/null &"
            result = await executor.execute(cmd, on_output=on_output, timeout=5)
            msg = f"Playing: {query}"

        if on_output:
            on_output(msg)
        return ToolResult(success=True, output=msg)
