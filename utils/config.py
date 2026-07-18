"""
Pentronix Config — loads and validates environment configuration.

Reads from .env file, validates required fields, and exposes a
typed singleton Config object used across all modules.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field


# Load .env from project root (two levels up from utils/)
_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=False)


class Config(BaseModel):
    """Typed application configuration loaded from environment variables."""

    # LLM
    groq_api_key: Optional[str] = Field(default=None)
    gemini_api_key: Optional[str] = Field(default=None)
    groq_model: str = Field(default="llama-3.3-70b-versatile")
    gemini_model: str = Field(default="gemini-2.0-flash")

    # Voice
    tts_voice: str = Field(default="en-US-GuyNeural")
    tts_rate: str = Field(default="+10%")
    tts_pitch: str = Field(default="+0Hz")

    # Execution
    tool_timeout: int = Field(default=300)

    # UI
    window_position: str = Field(default="bottom-right")

    # Logging
    log_level: str = Field(default="INFO")
    log_file: str = Field(default="pentronix.log")

    # Database
    db_path: str = Field(default="data/pentronix.db")

    @staticmethod
    @lru_cache(maxsize=1)
    def get() -> "Config":
        """Return the singleton Config instance (cached after first call).

        Returns:
            Populated :class:`Config` instance.
        """
        return Config(
            groq_api_key=os.getenv("GROQ_API_KEY"),
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            groq_model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
            tts_voice=os.getenv("TTS_VOICE", "en-US-GuyNeural"),
            tts_rate=os.getenv("TTS_RATE", "+10%"),
            tts_pitch=os.getenv("TTS_PITCH", "+0Hz"),
            tool_timeout=int(os.getenv("TOOL_TIMEOUT", "300")),
            window_position=os.getenv("WINDOW_POSITION", "bottom-right"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "pentronix.log"),
            db_path=os.getenv("DB_PATH", "data/pentronix.db"),
        )

    def has_groq(self) -> bool:
        """Return True if a Groq API key is configured."""
        return bool(self.groq_api_key and self.groq_api_key != "your_groq_api_key_here")

    def has_gemini(self) -> bool:
        """Return True if a Gemini API key is configured."""
        return bool(
            self.gemini_api_key
            and self.gemini_api_key != "your_gemini_api_key_here"
        )

    def has_any_llm(self) -> bool:
        """Return True if at least one LLM API key is configured."""
        return self.has_groq() or self.has_gemini()
