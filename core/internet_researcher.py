"""
Pentronix Internet Researcher — web search and knowledge acquisition.

When the agent doesn't know how to proceed or needs to install a tool,
it uses this module to:
  1. Search the web (DuckDuckGo — no API key needed)
  2. Read and extract content from web pages
  3. Save learned knowledge to persistent memory
"""

import asyncio
import re
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


class InternetResearcher:
    """Search the web and extract knowledge for the agent."""

    async def search(self, query: str, max_results: int = 5) -> list[dict]:
        """Search the web using DuckDuckGo.

        Args:
            query: Search query string.
            max_results: Maximum number of results to return.

        Returns:
            List of dicts with keys: title, url, snippet.
        """
        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                None,
                lambda: self._ddg_search(query, max_results),
            )
            log.info("Web search for '%s': %d results", query[:50], len(results))
            return results
        except Exception as exc:
            log.error("Web search failed: %s", exc)
            return []

    def _ddg_search(self, query: str, max_results: int) -> list[dict]:
        """Synchronous DuckDuckGo search."""
        try:
            from duckduckgo_search import DDGS
            with DDGS() as ddgs:
                raw = list(ddgs.text(query, max_results=max_results))
                return [
                    {
                        "title": r.get("title", ""),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", ""),
                    }
                    for r in raw
                ]
        except ImportError:
            log.warning("duckduckgo-search not installed — using fallback")
            return self._fallback_search(query)
        except Exception as exc:
            log.error("DuckDuckGo search error: %s", exc)
            return self._fallback_search(query)

    def _fallback_search(self, query: str) -> list[dict]:
        """Fallback search using requests + HTML parsing."""
        try:
            import requests
            from bs4 import BeautifulSoup

            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            }
            url = f"https://html.duckduckgo.com/html/?q={query}"
            resp = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")

            results = []
            for item in soup.select(".result")[:5]:
                title_tag = item.select_one(".result__title a")
                snippet_tag = item.select_one(".result__snippet")
                if title_tag:
                    results.append({
                        "title": title_tag.get_text(strip=True),
                        "url": title_tag.get("href", ""),
                        "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                    })
            return results
        except Exception as exc:
            log.error("Fallback search failed: %s", exc)
            return []

    async def read_webpage(self, url: str, max_chars: int = 8000) -> str:
        """Fetch and extract readable text from a webpage.

        Args:
            url: URL to fetch.
            max_chars: Maximum characters to return.

        Returns:
            Extracted text content.
        """
        loop = asyncio.get_event_loop()
        try:
            text = await loop.run_in_executor(
                None,
                lambda: self._fetch_text(url, max_chars),
            )
            log.info("Read webpage: %s (%d chars)", url[:80], len(text))
            return text
        except Exception as exc:
            log.error("Failed to read %s: %s", url, exc)
            return f"Error reading {url}: {exc}"

    def _fetch_text(self, url: str, max_chars: int) -> str:
        """Synchronous webpage text extraction."""
        import requests
        from bs4 import BeautifulSoup

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        }
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # Remove script, style, nav elements
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)
        # Clean up excessive whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text[:max_chars]

    async def research_tool(self, tool_name: str) -> dict:
        """Research how to install and use a specific tool.

        Args:
            tool_name: Name of the tool to research.

        Returns:
            Dict with keys: install_command, description, usage_examples.
        """
        results = await self.search(
            f"{tool_name} install kali linux apt command usage"
        )

        info = {
            "tool_name": tool_name,
            "install_command": f"sudo apt install -y {tool_name}",
            "description": "",
            "usage_examples": [],
            "sources": [],
        }

        # Try to read the top result for better info
        if results:
            info["sources"] = [r["url"] for r in results[:3]]
            info["description"] = results[0].get("snippet", "")

            # Try to determine the correct install command
            for r in results:
                snippet = r.get("snippet", "").lower()
                if "pip install" in snippet:
                    info["install_command"] = f"pip install {tool_name}"
                elif "go install" in snippet:
                    info["install_command"] = f"go install {tool_name}@latest"
                elif "apt install" in snippet or "apt-get install" in snippet:
                    info["install_command"] = f"sudo apt install -y {tool_name}"

        return info


# ── Singleton ─────────────────────────────────────────────────────────────────
_RESEARCHER: Optional[InternetResearcher] = None


def get_researcher() -> InternetResearcher:
    """Return the global InternetResearcher singleton."""
    global _RESEARCHER
    if _RESEARCHER is None:
        _RESEARCHER = InternetResearcher()
    return _RESEARCHER
