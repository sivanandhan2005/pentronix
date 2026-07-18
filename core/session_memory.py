"""
Pentronix Session Memory — persists the last task/session to disk.

Saved as JSON in data/session_memory.json.
Provides:
    - save_task(intent, description, status)  → write last task
    - load_last_session()                      → dict with last task info
    - mark_complete()                          → flag current task as done
"""

import json
import os
from datetime import datetime
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)

_MEMORY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # project root
    "data", "session_memory.json",
)


def _load_raw() -> dict:
    try:
        if os.path.exists(_MEMORY_FILE):
            with open(_MEMORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as exc:  # noqa: BLE001
        log.warning("session_memory: load failed: %s", exc)
    return {}


def _save_raw(data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_MEMORY_FILE), exist_ok=True)
        with open(_MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("session_memory: save failed: %s", exc)


def save_task(
    intent: str,
    description: str,
    target: Optional[str] = None,
    status: str = "in_progress",
) -> None:
    """Record the start of a new task."""
    data = _load_raw()
    data["last_task"] = {
        "intent": intent,
        "description": description,
        "target": target,
        "status": status,         # "in_progress" | "completed" | "stopped"
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
    _save_raw(data)
    log.debug("session_memory: saved task '%s' (%s)", intent, status)


def mark_complete() -> None:
    """Mark the current task as completed."""
    data = _load_raw()
    if "last_task" in data:
        data["last_task"]["status"] = "completed"
        data["last_task"]["completed_at"] = datetime.now().isoformat(timespec="seconds")
        _save_raw(data)


def mark_stopped() -> None:
    """Mark the current task as stopped/cancelled."""
    data = _load_raw()
    if "last_task" in data:
        data["last_task"]["status"] = "stopped"
        _save_raw(data)


def load_last_session() -> dict:
    """Return info about the last session task, or empty dict."""
    return _load_raw().get("last_task", {})
