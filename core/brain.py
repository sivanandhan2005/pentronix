"""
Pentronix Brain — Groq LLM client with function-calling support.

Thin wrapper around the Groq SDK that provides:
  - chat_with_tools()  → LLM call with tool/function definitions
  - chat()             → simple conversational response
  - stream_chat()      → streaming response with chunk callback
  - summarise()        → tool output summarisation

All methods are async-safe.  Retry logic with exponential backoff
handles rate-limit and transient connection errors.
"""

import asyncio
import json
import time
from typing import Any, Callable, Optional

from groq import Groq, APIStatusError, APIConnectionError, RateLimitError

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)


class Brain:
    """Groq-powered LLM brain with native tool-calling support."""

    def __init__(self) -> None:
        cfg = Config.get()
        if not cfg.has_groq():
            raise RuntimeError(
                "GROQ_API_KEY not set. Add it to your .env file and restart."
            )
        self._client = Groq(api_key=cfg.groq_api_key)
        self._model = cfg.groq_model
        log.info("Brain initialised — model: %s", self._model)

    # ── Tool-calling chat ─────────────────────────────────────────────────────

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict:
        """Send a chat completion with tool definitions.

        Args:
            messages: OpenAI-style messages list.
            tools: List of tool definitions (Groq/OpenAI format).
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.

        Returns:
            The full response message dict containing either:
            - ``content`` (text response) and/or
            - ``tool_calls`` (list of tool call requests)
        """
        start = time.monotonic()
        resp = await self._call_groq(
            messages=messages,
            tools=tools if tools else None,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        elapsed = (time.monotonic() - start) * 1000
        log.debug("Brain chat_with_tools: %.0f ms", elapsed)

        msg = resp.choices[0].message

        result = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [],
        }

        if msg.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]

        return result

    # ── Simple chat ───────────────────────────────────────────────────────────

    async def chat(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """Simple conversational chat — returns text response.

        Args:
            messages: OpenAI-style messages list.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.

        Returns:
            Response text string.
        """
        resp = await self._call_groq(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    # ── Streaming chat ────────────────────────────────────────────────────────

    async def stream_chat(
        self,
        messages: list[dict],
        on_chunk: Callable[[str], None],
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """Stream a chat response, calling on_chunk with each text delta.

        Args:
            messages: OpenAI-style messages list.
            on_chunk: Callback invoked with each text delta.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.

        Returns:
            Full accumulated response string.
        """
        loop = asyncio.get_event_loop()
        accumulated: list[str] = []

        def _run() -> str:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    accumulated.append(delta)
                    loop.call_soon_threadsafe(on_chunk, delta)
            return "".join(accumulated)

        return await loop.run_in_executor(None, _run)

    # ── Summarisation ─────────────────────────────────────────────────────────

    async def summarise(
        self,
        tool_name: str,
        raw_output: str,
        target: Optional[str] = None,
        on_chunk: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Summarise raw tool output in concise English.

        Args:
            tool_name: Tool that produced the output.
            raw_output: Raw stdout from the tool.
            target: Optional target that was scanned/exploited.
            on_chunk: Optional streaming callback.

        Returns:
            Summary string.
        """
        target_clause = f" against {target}" if target else ""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are Pentronix, an expert AI pentesting assistant. "
                    "Summarise tool output concisely and factually. "
                    "Mention ports, services, vulnerabilities, and CVEs specifically. "
                    "Speak like you're briefing a security analyst."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Summarise this {tool_name} output{target_clause} in "
                    f"3–5 sentences. Interpret, don't repeat raw output.\n\n"
                    f"OUTPUT:\n{raw_output[:8000]}"
                ),
            },
        ]

        if on_chunk:
            return await self.stream_chat(messages, on_chunk)
        return await self.chat(messages)

    # ── Groq API core ─────────────────────────────────────────────────────────

    async def _call_groq(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        max_retries: int = 3,
    ):
        """Send a blocking chat completion to Groq with retry logic.

        Returns the raw Groq response object.
        """
        loop = asyncio.get_event_loop()
        delay = 1.0
        last_exc: Optional[Exception] = None

        # Clean messages — strip tool_calls from messages to avoid API errors
        clean_messages = []
        for msg in messages:
            clean = {k: v for k, v in msg.items() if k != "tool_calls" or v}
            # If message has tool_calls, keep them
            if msg.get("tool_calls"):
                clean["tool_calls"] = msg["tool_calls"]
            clean_messages.append(clean)

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": self._model,
                    "messages": clean_messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                if tools:
                    kwargs["tools"] = tools
                    kwargs["tool_choice"] = "auto"

                resp = await loop.run_in_executor(
                    None,
                    lambda: self._client.chat.completions.create(**kwargs),
                )
                return resp

            except RateLimitError as exc:
                last_exc = exc
                log.warning(
                    "Groq rate limit (attempt %d/%d) — waiting %.1fs",
                    attempt + 1, max_retries, delay,
                )
                await asyncio.sleep(delay)
                delay *= 2
            except APIConnectionError as exc:
                last_exc = exc
                log.warning(
                    "Groq connection error (attempt %d/%d): %s",
                    attempt + 1, max_retries, exc,
                )
                await asyncio.sleep(delay)
                delay *= 2
            except APIStatusError as exc:
                log.error("Groq API error %d: %s", exc.status_code, exc.message)
                raise RuntimeError(f"Groq API error: {exc.message}") from exc

        raise RuntimeError(
            f"Groq unreachable after {max_retries} attempts: {last_exc}"
        )


# ── Singleton ─────────────────────────────────────────────────────────────────
_BRAIN: Optional[Brain] = None


def get_brain() -> Brain:
    """Return the global Brain singleton, creating it on first call."""
    global _BRAIN
    if _BRAIN is None:
        _BRAIN = Brain()
    return _BRAIN
