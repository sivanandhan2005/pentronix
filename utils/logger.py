"""
Pentronix Logger — structured logging with Rich formatting.

Provides a singleton logger used across all modules with console
and file output, color-coded by level, and structured metadata.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── Theme ────────────────────────────────────────────────────────────────────
_THEME = Theme(
    {
        "logging.level.debug": "dim cyan",
        "logging.level.info": "bright_green",
        "logging.level.warning": "yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold red on white",
    }
)

_console = Console(theme=_THEME, stderr=True)
_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Return a named logger, creating it on first call.

    Args:
        name: Logger name (usually __name__).
        level: Override log level string (DEBUG/INFO/WARNING/ERROR).

    Returns:
        Configured :class:`logging.Logger` instance.
    """
    if name in _loggers:
        return _loggers[name]

    # Import here to avoid circular imports at module load time
    from utils.config import Config  # noqa: PLC0415

    cfg = Config.get()
    effective_level = level or cfg.log_level

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, effective_level.upper(), logging.INFO))
    logger.propagate = False

    if not logger.handlers:
        # Rich console handler
        rich_handler = RichHandler(
            console=_console,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            show_time=True,
            show_path=False,
            markup=True,
        )
        rich_handler.setLevel(getattr(logging, effective_level.upper(), logging.INFO))
        logger.addHandler(rich_handler)

        # File handler if configured
        log_file = cfg.log_file
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)  # Always verbose to file
            fmt = logging.Formatter(
                fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger
