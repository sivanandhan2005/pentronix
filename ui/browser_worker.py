"""
Pentronix BrowserWorker — QThread wrapper for BrowserAgent.

Runs a BrowserAgent task on a background thread, emitting Qt signals
for status updates, mid-task clarification requests, and completion.
"""

from __future__ import annotations

import queue
import threading
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from core.browser_agent import BrowserAgent
from utils.logger import get_logger

log = get_logger(__name__)


class BrowserWorker(QThread):
    """
    Background thread that runs a BrowserAgent task.

    Signals:
        status_update(str)    — progress message to show in the UI
        clarify_needed(str)   — question for the user; send answer via reply()
        task_done(str)        — final result summary
        error(str)            — task failed
    """

    status_update  = pyqtSignal(str)
    clarify_needed = pyqtSignal(str)
    task_done      = pyqtSignal(str)
    error          = pyqtSignal(str)

    def __init__(
        self,
        action: str,
        params: dict,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._action = action
        self._params = params
        # Queue used to pass user answers back into the running agent thread
        self._reply_queue: queue.Queue[str] = queue.Queue()

    def reply(self, text: str) -> None:
        """Called from the UI thread to answer a mid-task clarify_needed question."""
        self._reply_queue.put(text)

    def run(self) -> None:
        """Entry point — runs in the background thread."""
        def _status(msg: str) -> None:
            self.status_update.emit(msg)

        def _clarify(question: str) -> str:
            """Emit clarify_needed, then block until UI calls reply()."""
            self.clarify_needed.emit(question)
            # Block the browser thread until the user answers
            try:
                answer = self._reply_queue.get(timeout=120)  # 2-minute timeout
            except queue.Empty:
                answer = ""
            return answer

        agent = BrowserAgent(clarify_fn=_clarify, status_fn=_status, headless=False)
        try:
            result = agent.run(self._action, self._params)
            self.task_done.emit(result)
        except Exception as exc:  # noqa: BLE001
            log.error("BrowserWorker error: %s", exc)
            self.error.emit(str(exc))
