"""
Pentronix Browser Agent — Playwright-based autonomous browser control.

Supports: YouTube, Gmail, Google Search, Flipkart, generic web tasks.
Mid-task clarification: pauses and calls clarify_callback(question) → gets user reply.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Callable, Optional

from utils.logger import get_logger

log = get_logger(__name__)

# ── Type alias ────────────────────────────────────────────────────────────────
ClarifyFn = Callable[[str], str]   # ask user a question, blocking until answered
StatusFn  = Callable[[str], None]  # emit a status line to the UI


class BrowserAgent:
    """
    Runs browser automation tasks using Playwright (Chromium).

    Usage:
        agent = BrowserAgent(clarify_fn, status_fn)
        result = agent.run(action, params)
    """

    def __init__(
        self,
        clarify_fn: ClarifyFn,
        status_fn: StatusFn,
        headless: bool = False,
    ) -> None:
        self._clarify = clarify_fn
        self._status  = status_fn
        self._headless = headless
        self._pw   = None
        self._browser = None
        self._page    = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Launch Playwright + Chromium."""
        from playwright.sync_api import sync_playwright  # type: ignore
        self._pw      = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self._headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        self._page = context.new_page()
        log.info("Browser agent started (Chromium)")

    def stop(self) -> None:
        """Close browser and Playwright."""
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:  # noqa: BLE001
            pass
        self._browser = None
        self._page    = None
        self._pw      = None

    # ── Main dispatcher ───────────────────────────────────────────────────────

    def run(self, action: str, params: dict) -> str:
        """
        Run a browser action and return a result summary string.

        Actions:
            youtube_play   — search & play a video
            gmail_read     — login and check inbox
            gmail_compose  — compose and send an email
            gmail_delete   — delete emails matching criteria
            web_search     — Google search and read results
            flipkart_search — search Flipkart and list results
            amazon_search  — search Amazon
            open_url       — navigate to any URL
            generic        — let the LLM guide step-by-step
        """
        self.start()
        try:
            dispatch = {
                "youtube_play":    self._youtube_play,
                "gmail_read":      self._gmail_read,
                "gmail_compose":   self._gmail_compose,
                "gmail_delete":    self._gmail_delete,
                "web_search":      self._web_search,
                "flipkart_search": self._flipkart_search,
                "amazon_search":   self._amazon_search,
                "open_url":        self._open_url,
            }
            fn = dispatch.get(action, self._generic)
            return fn(params)
        except Exception as exc:  # noqa: BLE001
            log.error("Browser agent error: %s", exc)
            return f"Browser task failed: {exc}"
        finally:
            self.stop()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _goto(self, url: str, wait: str = "domcontentloaded") -> None:
        assert self._page
        self._page.goto(url, wait_until=wait, timeout=30000)

    def _fill(self, selector: str, text: str, timeout: int = 8000) -> bool:
        """Try to fill a field. Returns True on success."""
        assert self._page
        try:
            self._page.wait_for_selector(selector, timeout=timeout)
            self._page.fill(selector, text)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _click(self, selector: str, timeout: int = 8000) -> bool:
        assert self._page
        try:
            self._page.wait_for_selector(selector, timeout=timeout)
            self._page.click(selector)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _text(self, selector: str, timeout: int = 5000) -> str:
        assert self._page
        try:
            self._page.wait_for_selector(selector, timeout=timeout)
            return self._page.inner_text(selector)
        except Exception:  # noqa: BLE001
            return ""

    def _wait(self, ms: int = 2000) -> None:
        assert self._page
        self._page.wait_for_timeout(ms)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _youtube_play(self, params: dict) -> str:
        query = params.get("search_query", "")
        if not query:
            query = self._clarify("What would you like me to search on YouTube?")

        self._status(f"🎬 Searching YouTube for: {query}")
        url = f"https://www.youtube.com/results?search_query={urllib.parse.quote_plus(query)}"
        self._goto(url)
        self._wait(2000)

        # Click the first video result
        assert self._page
        try:
            first = self._page.query_selector("ytd-video-renderer a#video-title")
            if first:
                title = first.get_attribute("title") or "video"
                self._status(f"▶ Playing: {title}")
                first.click()
                self._wait(3000)
                # Try to dismiss ads
                try:
                    self._page.click("button.ytp-skip-ad-button", timeout=5000)
                except Exception:  # noqa: BLE001
                    pass
                return f"Now playing: {title}"
            else:
                return "Could not find a video to play."
        except Exception as exc:  # noqa: BLE001
            return f"YouTube play failed: {exc}"

    def _gmail_login(self) -> bool:
        """Handle Gmail login — ask user for credentials mid-task."""
        assert self._page
        self._status("Opening Gmail login page…")
        self._goto("https://accounts.google.com/signin/v2/identifier?service=mail")
        self._wait(2000)

        # Ask for email
        email = self._clarify("Please type your Gmail address (email or phone number):")
        if not email:
            return False

        self._status("Entering email…")
        self._fill("input[type='email']", email)
        self._click("#identifierNext")
        self._wait(2500)

        # Ask for password
        password = self._clarify("Please type your Gmail password (it stays private):")
        if not password:
            return False

        self._status("Entering password…")
        self._fill("input[type='password']", password)
        self._click("#passwordNext")
        self._wait(3500)

        # Check if login succeeded
        if "myaccount.google.com" in self._page.url or "mail.google.com" in self._page.url:
            self._status("✓ Logged in to Gmail")
            return True

        # Navigate to inbox
        self._goto("https://mail.google.com/mail/u/0/#inbox")
        self._wait(4000)
        return "mail.google.com" in self._page.url

    def _gmail_read(self, params: dict) -> str:
        if not self._gmail_login():
            return "Gmail login failed. Please check your credentials."

        self._status("Reading inbox…")
        assert self._page
        self._wait(3000)

        # Read unread email subjects
        try:
            rows = self._page.query_selector_all("tr.zA")  # Gmail inbox rows
            unread = [r for r in rows if "zE" in (r.get_attribute("class") or "")]
            subjects = []
            for row in unread[:5]:
                subj_el = row.query_selector("span.bog")
                sender_el = row.query_selector("span.zF")
                subj = subj_el.inner_text() if subj_el else "No subject"
                sender = sender_el.inner_text() if sender_el else "Unknown"
                subjects.append(f"From {sender}: {subj}")

            if not subjects:
                return "Your inbox has no new unread emails."

            result = f"You have {len(unread)} unread email(s):\n"
            result += "\n".join(f"  {i+1}. {s}" for i, s in enumerate(subjects))
            return result
        except Exception as exc:  # noqa: BLE001
            return f"Could not read inbox: {exc}"

    def _gmail_compose(self, params: dict) -> str:
        if not self._gmail_login():
            return "Gmail login failed."

        # Gather mail details
        to_addr = params.get("to") or self._clarify("Who should I send the email to? (email address)")
        subject = params.get("subject") or self._clarify("What is the subject of the email?")
        body    = params.get("body") or self._clarify("What should the email say?")

        self._status(f"Composing email to {to_addr}…")
        assert self._page

        # Click Compose
        self._click("div[gh='cm']")
        self._wait(1500)

        # Fill To
        self._fill("textarea[name='to']", to_addr)
        self._wait(500)
        # Fill Subject
        self._fill("input[name='subjectbox']", subject)
        self._wait(500)
        # Fill Body
        self._fill("div[aria-label='Message Body']", body)
        self._wait(500)

        # Ask confirmation before sending
        confirm = self._clarify(f"Ready to send email to {to_addr}. Type 'send' to confirm or 'cancel':")
        if confirm.strip().lower() != "send":
            return "Email cancelled — not sent."

        # Click Send
        self._click("div[aria-label='Send ‪(Ctrl-Enter)‬']")
        self._wait(2000)
        return f"Email sent to {to_addr} with subject: {subject}"

    def _gmail_delete(self, params: dict) -> str:
        if not self._gmail_login():
            return "Gmail login failed."

        criteria = params.get("search_query") or self._clarify(
            "Which emails should I delete? (e.g. 'from:spam@example.com' or 'subject:offer')"
        )

        confirm = self._clarify(
            f"I will search for '{criteria}' and delete matching emails. Type 'confirm' to proceed:"
        )
        if confirm.strip().lower() != "confirm":
            return "Delete cancelled."

        assert self._page
        # Search Gmail
        search_url = f"https://mail.google.com/mail/u/0/#search/{urllib.parse.quote_plus(criteria)}"
        self._goto(search_url)
        self._wait(3000)

        # Select all
        self._click("div[title='Select']")
        self._wait(500)
        # Delete
        self._click("div[aria-label='Delete']")
        self._wait(2000)
        return f"Deleted emails matching: {criteria}"

    def _web_search(self, params: dict) -> str:
        query = params.get("search_query", "")
        if not query:
            query = self._clarify("What should I search for on Google?")

        self._status(f"🔍 Searching Google: {query}")
        url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
        self._goto(url)
        self._wait(2000)

        assert self._page
        try:
            # Get top result titles + snippets
            results = self._page.query_selector_all("div.g")
            summaries = []
            for r in results[:4]:
                title_el   = r.query_selector("h3")
                snippet_el = r.query_selector("div.VwiC3b")
                title   = title_el.inner_text()   if title_el   else ""
                snippet = snippet_el.inner_text() if snippet_el else ""
                if title:
                    summaries.append(f"• {title}: {snippet[:120]}")

            if summaries:
                return "Top results:\n" + "\n".join(summaries)
            return "No results found."
        except Exception as exc:  # noqa: BLE001
            return f"Search failed: {exc}"

    def _flipkart_search(self, params: dict) -> str:
        query = params.get("search_query", "")
        if not query:
            query = self._clarify("What should I search for on Flipkart?")

        self._status(f"🛍 Searching Flipkart: {query}")
        url = f"https://www.flipkart.com/search?q={urllib.parse.quote_plus(query)}"
        self._goto(url)
        self._wait(3000)

        assert self._page
        # Dismiss login popup if shown
        try:
            self._page.click("button._2KpZ6l._2doB4z", timeout=3000)
        except Exception:  # noqa: BLE001
            pass

        try:
            # Get product listings
            items = self._page.query_selector_all("div._1AtVbE")
            results = []
            for item in items[:5]:
                name_el  = item.query_selector("div._4rR01T, a.s1Q9rs")
                price_el = item.query_selector("div._30jeq3")
                rating_el = item.query_selector("div._3LWZlK")
                name   = name_el.inner_text()   if name_el   else ""
                price  = price_el.inner_text()  if price_el  else ""
                rating = rating_el.inner_text() if rating_el else ""
                if name:
                    results.append(f"• {name} — {price}" + (f" ⭐{rating}" if rating else ""))

            if results:
                return f"Flipkart results for '{query}':\n" + "\n".join(results)
            return "No products found on Flipkart."
        except Exception as exc:  # noqa: BLE001
            return f"Flipkart search failed: {exc}"

    def _amazon_search(self, params: dict) -> str:
        query = params.get("search_query", "")
        if not query:
            query = self._clarify("What should I search for on Amazon?")

        self._status(f"🛒 Searching Amazon: {query}")
        url = f"https://www.amazon.in/s?k={urllib.parse.quote_plus(query)}"
        self._goto(url)
        self._wait(3000)

        assert self._page
        try:
            items = self._page.query_selector_all("div[data-component-type='s-search-result']")
            results = []
            for item in items[:5]:
                name_el  = item.query_selector("h2 span")
                price_el = item.query_selector("span.a-price-whole")
                rating_el = item.query_selector("span.a-icon-alt")
                name   = name_el.inner_text()   if name_el   else ""
                price  = price_el.inner_text()  if price_el  else ""
                rating = rating_el.inner_text() if rating_el else ""
                if name:
                    results.append(f"• {name[:80]} — ₹{price}" + (f" ({rating})" if rating else ""))

            if results:
                return f"Amazon results for '{query}':\n" + "\n".join(results)
            return "No products found on Amazon."
        except Exception as exc:  # noqa: BLE001
            return f"Amazon search failed: {exc}"

    def _open_url(self, params: dict) -> str:
        url = params.get("url", "")
        if not url:
            url = self._clarify("Which URL should I open?")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self._status(f"🌐 Opening: {url}")
        self._goto(url)
        self._wait(2000)
        assert self._page
        title = self._page.title()
        return f"Opened: {title} ({url})"

    def _generic(self, params: dict) -> str:
        url = params.get("url", "")
        query = params.get("search_query", "")
        if url:
            return self._open_url(params)
        if query:
            return self._web_search(params)
        task = self._clarify("What would you like me to do in the browser?")
        return self._web_search({"search_query": task})
