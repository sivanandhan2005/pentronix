"""
Pentronix Voice Speaker v2 — Natural AI voice via edge-tts.

Voice: en-US-AriaNeural — warm, confident, natural female voice.
Pipeline: edge-tts → MP3 temp file → mpg123/ffplay playback.

Features:
  - Natural human-like voice (movie AI style)
  - Interrupt support (stop current speech when user speaks)
  - Text cleanup for spoken English (no markdown, no code blocks)
"""

import asyncio
import os
import re
import subprocess
import tempfile
from typing import Optional

import edge_tts

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)

# ── Voice configuration ───────────────────────────────────────────────────────
# AriaNeural = warm, natural, movie-AI feel
_DEFAULT_VOICE = "en-US-AriaNeural"
_DEFAULT_RATE  = "+5%"     # Slightly faster = more natural
_DEFAULT_PITCH = "-2Hz"    # Slightly deeper = more confident

_VOICE_FALLBACKS = [
    "en-US-AriaNeural",
    "en-US-JennyNeural",
    "en-GB-SoniaNeural",
    "en-IE-EmilyNeural",
]


# ── Audio environment ─────────────────────────────────────────────────────────

def _build_audio_env() -> dict:
    """Build env for PipeWire/PulseAudio compatibility."""
    env = os.environ.copy()
    real_uid = os.getuid()
    if real_uid == 0:
        for uid in range(1000, 1010):
            if os.path.exists(f"/run/user/{uid}/pulse/native"):
                real_uid = uid
                break

    xdg = f"/run/user/{real_uid}"
    pulse_sock = f"{xdg}/pulse/native"

    if os.path.isdir(xdg):
        env.setdefault("XDG_RUNTIME_DIR", xdg)
    if os.path.exists(pulse_sock):
        env.setdefault("PULSE_SERVER", f"unix:{pulse_sock}")
    elif "PULSE_SERVER" not in env:
        env.setdefault("AUDIODRIVER", "alsa")

    return env


def _find_player() -> Optional[str]:
    """Find an available audio player."""
    import shutil
    for p in ["mpg123", "ffplay"]:
        if shutil.which(p):
            return p
    return None


def _play_cmd(player: str, filepath: str) -> list:
    """Build playback command."""
    if player == "mpg123":
        return ["mpg123", "-q", filepath]
    return ["ffplay", "-nodisp", "-autoexit", "-loglevel", "error", filepath]


# ── Text preprocessing ────────────────────────────────────────────────────────
_ANSI_RE     = re.compile(r"\x1b\[[0-9;]*m")
_EMOJI_RE    = re.compile(r"[^\x00-\xFF]+")
_MARKDOWN_RE = re.compile(r"[*_`#~]")
_CODE_BLOCK  = re.compile(r"```[\s\S]*?```")
_IP_RE       = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_URL_RE      = re.compile(r"https?://\S+")
_DASHES_RE   = re.compile(r"-{3,}")
_BULLETS_RE  = re.compile(r"^[\s*•▸●─]+", re.MULTILINE)
_BRACKETS_RE = re.compile(r"\[.*?\]")


def _naturalise(text: str) -> str:
    """Convert text to natural spoken English — no code, no markdown."""
    # Remove code blocks entirely
    text = _CODE_BLOCK.sub("", text)
    # Strip terminal noise
    text = _ANSI_RE.sub("", text)
    text = _EMOJI_RE.sub("", text)
    text = _MARKDOWN_RE.sub("", text)
    text = _BRACKETS_RE.sub("", text)
    text = _URL_RE.sub("a link", text)
    # Pronounce IPs  naturally: "192 dot 168 dot 1 dot 1"
    text = _IP_RE.sub(lambda m: " dot ".join(m.groups()), text)
    text = _DASHES_RE.sub(",", text)
    text = _BULLETS_RE.sub("", text)
    # Clean whitespace
    text = " ".join(text.split())
    # Limit length for natural speech (keep it concise)
    if len(text) > 500:
        cutoff = text[:500].rfind(".")
        text = text[:cutoff + 1] if cutoff > 200 else text[:500].rstrip() + "."
    return text.strip()


# ── Speaker class ─────────────────────────────────────────────────────────────

class Speaker:
    """Natural AI voice — synthesises via edge-tts, plays via mpg123.

    Supports interrupt: calling stop() mid-speech kills playback immediately.
    """

    def __init__(self) -> None:
        cfg = Config.get()
        self._voice = getattr(cfg, "tts_voice", None) or _DEFAULT_VOICE
        self._rate  = getattr(cfg, "tts_rate",  None) or _DEFAULT_RATE
        self._pitch = getattr(cfg, "tts_pitch", None) or _DEFAULT_PITCH
        self._player: Optional[str] = _find_player()
        self._current_proc: Optional[subprocess.Popen] = None
        self._speaking = False

        if not self._player:
            log.warning("No audio player found. Install: sudo apt install mpg123")
        else:
            log.info("Speaker ready — voice=%s player=%s rate=%s",
                     self._voice, self._player, self._rate)

    @property
    def available(self) -> bool:
        return self._player is not None

    @property
    def is_speaking(self) -> bool:
        return self._speaking

    async def speak(self, text: str) -> None:
        """Synthesise and play text naturally. Falls back through voice list."""
        if not text or not text.strip():
            return

        self.stop()  # Interrupt any current speech
        clean = _naturalise(text)
        if not clean:
            return

        log.debug("Speaking: %r…", clean[:80])
        self._speaking = True

        voices = [self._voice] + [v for v in _VOICE_FALLBACKS if v != self._voice]
        try:
            for voice in voices:
                try:
                    await self._synthesise_and_play(clean, voice)
                    return
                except Exception as exc:
                    log.warning("TTS voice %s failed: %s — trying next", voice, exc)
            log.error("All TTS voices failed — silent")
        finally:
            self._speaking = False

    def stop(self) -> None:
        """Kill current playback immediately (interrupt support)."""
        proc = self._current_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
        self._current_proc = None
        self._speaking = False

    async def _synthesise_and_play(self, text: str, voice: str) -> None:
        """Save edge-tts MP3 → play → delete."""
        if not self._player:
            return

        fd, tmp_path = tempfile.mkstemp(suffix=".mp3", prefix="ptrx_tts_")
        os.close(fd)

        try:
            # Synthesise
            communicate = edge_tts.Communicate(
                text=text, voice=voice,
                rate=self._rate, pitch=self._pitch,
            )
            await communicate.save(tmp_path)

            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            if size < 500:
                raise RuntimeError(f"TTS output too small ({size}B) for voice={voice}")

            log.debug("TTS: %d bytes via %s", size, voice)

            # Play
            cmd = _play_cmd(self._player, tmp_path)
            env = _build_audio_env()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            self._current_proc = proc

            # Wait without blocking event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, proc.wait)

        finally:
            self._current_proc = None
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ── Singleton ──────────────────────────────────────────────────────────────────
_SPEAKER: Optional[Speaker] = None


def get_speaker() -> Speaker:
    """Return the global Speaker singleton."""
    global _SPEAKER
    if _SPEAKER is None:
        _SPEAKER = Speaker()
    return _SPEAKER
