"""
Pentronix Voice Listener v2 — Always-on JARVIS-style voice system.

Architecture:
  - Continuous mic stream via parec (PipeWire-Pulse)
  - Wake word detection: short Whisper transcriptions checking for "pentronix"
  - Active listening: VAD-based speech endpointing → full Whisper transcription
  - State machine: IDLE → WAKE_DETECTED → LISTENING → PROCESSING → IDLE

Emits Qt signals for UI integration.
"""

import asyncio
import enum
import io
import os
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import wave
from typing import Callable, Optional

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)

# ── Audio constants ────────────────────────────────────────────────────────────
SAMPLE_RATE    = 16000
CHANNELS       = 1
SAMPLE_WIDTH   = 2   # 16-bit = 2 bytes
CHUNK_MS       = 30
CHUNK_SAMPLES  = int(SAMPLE_RATE * CHUNK_MS / 1000)
CHUNK_BYTES    = CHUNK_SAMPLES * SAMPLE_WIDTH
VAD_MODE       = 3   # Aggressiveness (0-3, 3 = most aggressive)
SILENCE_MS     = 1200  # Silence duration to end recording
MAX_RECORD_SEC = 30
MIN_SPEECH_MS  = 300
WAKE_WINDOW_SEC = 2   # Audio window for wake word detection


class ListenerState(enum.Enum):
    """Voice listener state machine."""
    IDLE = "idle"                    # Waiting for wake word
    WAKE_DETECTED = "wake_detected"  # Wake word heard, transitioning to listen
    LISTENING = "listening"          # Actively recording user speech
    PROCESSING = "processing"       # Sending to STT
    STOPPED = "stopped"             # Listener shut down


# ── Audio environment helpers ──────────────────────────────────────────────────

def _build_audio_env() -> dict:
    """Build environment so parec/mpg123 can reach PipeWire/PulseAudio."""
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


def _activate_pipewire_mic(env: dict) -> bool:
    """Activate PipeWire mic source via pactl profile switch."""
    profiles = [
        "output:analog-stereo+input:analog-stereo",
        "input:analog-stereo",
    ]
    card = "alsa_card.pci-0000_04_00.6"

    for profile in profiles:
        try:
            subprocess.run(
                ["pactl", "set-card-profile", card, profile],
                env=env, capture_output=True, timeout=4,
            )
        except Exception:
            pass

    try:
        r = subprocess.run(
            ["pactl", "list", "sources", "short"],
            env=env, capture_output=True, timeout=4,
        )
        for line in r.stdout.decode(errors="replace").splitlines():
            parts = line.split()
            name = parts[1] if len(parts) > 1 else ""
            if "alsa_input" in name and "monitor" not in name:
                log.info("Audio: PipeWire mic source active — %s", name)
                return True
    except Exception:
        pass
    return False


def _pcm_to_wav(pcm: bytes) -> bytes:
    """Wrap raw s16le PCM bytes in a WAV container."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(SAMPLE_WIDTH)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(pcm)
    return buf.getvalue()


def _pcm_energy(pcm: bytes) -> float:
    """RMS energy of a PCM buffer — crude voice activity check."""
    if len(pcm) < 4:
        return 0.0
    n_samples = len(pcm) // SAMPLE_WIDTH
    samples = struct.unpack(f"<{n_samples}h", pcm[:n_samples * SAMPLE_WIDTH])
    rms = (sum(s * s for s in samples) / n_samples) ** 0.5
    return rms


# ── VoiceListener ──────────────────────────────────────────────────────────────

class VoiceListener:
    """Always-on JARVIS-style voice listener.

    Runs a continuous mic stream in a background thread.
    Detects wake word "pentronix" → records speech → transcribes → emits callback.

    Usage:
        listener = VoiceListener()
        listener.start(on_transcription=my_callback, on_state_change=my_state_cb)
        # ... runs forever ...
        listener.stop()
    """

    def __init__(self) -> None:
        self._state = ListenerState.STOPPED
        self._env = _build_audio_env()
        self._groq_client = None
        self._vad = None
        self._backend = "none"
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_transcription: Optional[Callable[[str], None]] = None
        self._on_state_change: Optional[Callable[[ListenerState], None]] = None
        self._on_wake: Optional[Callable[[], None]] = None
        self._wake_word = "pentronix"

        self._init_audio()

    # ── Initialization ────────────────────────────────────────────────────────

    def _init_audio(self) -> None:
        """Initialize audio backend and Groq client."""
        # Groq client for Whisper STT
        try:
            from groq import Groq
            cfg = Config.get()
            if cfg.has_groq():
                self._groq_client = Groq(api_key=cfg.groq_api_key)
            else:
                log.warning("GROQ_API_KEY not set — voice disabled")
                return
        except Exception as exc:
            log.warning("Groq init failed: %s", exc)
            return

        # Wake word from config
        self._wake_word = getattr(Config.get(), "wake_word", "pentronix").lower()

        # VAD
        try:
            import webrtcvad
            self._vad = webrtcvad.Vad(VAD_MODE)
        except ImportError:
            log.warning("webrtcvad not installed — using energy-based VAD")

        # PipeWire env
        for k in ("XDG_RUNTIME_DIR", "PULSE_SERVER"):
            if k in self._env:
                os.environ[k] = self._env[k]

        # Backend selection: parec > arecord
        if shutil.which("parec") and shutil.which("pactl"):
            _activate_pipewire_mic(self._env)
            self._backend = "parec"
            log.info("Voice: parec/PipeWire backend ready")
        elif shutil.which("arecord"):
            self._backend = "arecord"
            log.info("Voice: arecord/ALSA backend ready")
        else:
            log.error("Voice: no audio capture backend found")
            return

        self._state = ListenerState.IDLE
        log.info("VoiceListener initialized — wake word: '%s'", self._wake_word)

    @property
    def available(self) -> bool:
        return self._state != ListenerState.STOPPED and self._groq_client is not None

    @property
    def state(self) -> ListenerState:
        return self._state

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(
        self,
        on_transcription: Callable[[str], None],
        on_state_change: Optional[Callable[[ListenerState], None]] = None,
        on_wake: Optional[Callable[[], None]] = None,
    ) -> None:
        """Start the always-on voice loop in a background thread."""
        if not self.available:
            log.error("Cannot start — voice listener not available")
            return
        if self._running:
            return

        self._on_transcription = on_transcription
        self._on_state_change = on_state_change
        self._on_wake = on_wake
        self._running = True

        self._thread = threading.Thread(
            target=self._voice_loop, daemon=True, name="PentronixVoice"
        )
        self._thread.start()
        log.info("Voice loop started (always-on)")

    def stop(self) -> None:
        """Stop the voice loop."""
        self._running = False
        self._set_state(ListenerState.STOPPED)
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    # ── State management ──────────────────────────────────────────────────────

    def _set_state(self, new_state: ListenerState) -> None:
        if self._state != new_state:
            self._state = new_state
            log.debug("Voice state: %s", new_state.value)
            if self._on_state_change:
                try:
                    self._on_state_change(new_state)
                except Exception:
                    pass

    # ── Main voice loop ───────────────────────────────────────────────────────

    def _voice_loop(self) -> None:
        """Main always-on loop: wake word detection → active listening → STT."""
        log.info("Voice loop running — listening for '%s'", self._wake_word)

        while self._running:
            try:
                self._set_state(ListenerState.IDLE)

                # Phase 1: Listen for wake word
                if self._detect_wake_word():
                    self._set_state(ListenerState.WAKE_DETECTED)
                    if self._on_wake:
                        try:
                            self._on_wake()
                        except Exception:
                            pass

                    # Phase 2: Record user speech
                    self._set_state(ListenerState.LISTENING)
                    pcm_data = self._record_speech()

                    if pcm_data and len(pcm_data) > MIN_SPEECH_MS * SAMPLE_RATE * SAMPLE_WIDTH // 1000:
                        # Phase 3: Transcribe
                        self._set_state(ListenerState.PROCESSING)
                        text = self._transcribe(pcm_data)

                        if text and text.strip():
                            # Remove the wake word from the beginning if present
                            clean = self._strip_wake_word(text)
                            if clean.strip():
                                log.info("Transcribed: %s", clean[:100])
                                if self._on_transcription:
                                    self._on_transcription(clean)
                            else:
                                log.debug("Only wake word detected, no command")
                    else:
                        log.debug("Recording too short — ignoring")

            except Exception as exc:
                log.error("Voice loop error: %s", exc, exc_info=True)
                time.sleep(1)

        log.info("Voice loop stopped")

    # ── Wake word detection ───────────────────────────────────────────────────

    def _detect_wake_word(self) -> bool:
        """Record short audio clips and check for wake word via Whisper.

        Returns True when the wake word is detected.
        """
        while self._running:
            pcm = self._capture_audio(duration_sec=WAKE_WINDOW_SEC)
            if not pcm:
                time.sleep(0.5)
                continue

            # Quick energy check — skip silent audio
            energy = _pcm_energy(pcm)
            if energy < 300:  # Threshold for background noise
                continue

            # Transcribe short clip and check for wake word
            text = self._transcribe(pcm)
            if text and self._wake_word in text.lower():
                log.info("Wake word detected: '%s'", text[:60])
                return True

        return False

    # ── Active speech recording ───────────────────────────────────────────────

    def _record_speech(self) -> Optional[bytes]:
        """Record until VAD detects silence (or max duration reached).

        Returns raw PCM bytes of the user's speech.
        """
        log.debug("Recording speech...")
        all_pcm = bytearray()
        silence_chunks = 0
        max_chunks = (MAX_RECORD_SEC * 1000) // CHUNK_MS
        silence_threshold = SILENCE_MS // CHUNK_MS

        proc = self._start_capture_process()
        if not proc:
            return None

        try:
            for _ in range(max_chunks):
                if not self._running:
                    break

                chunk = proc.stdout.read(CHUNK_BYTES)
                if not chunk or len(chunk) < CHUNK_BYTES:
                    break

                all_pcm.extend(chunk)

                # VAD or energy-based speech detection
                is_speech = self._is_speech(chunk)
                if is_speech:
                    silence_chunks = 0
                else:
                    silence_chunks += 1

                # End recording after sustained silence (but only after some speech)
                if silence_chunks >= silence_threshold and len(all_pcm) > CHUNK_BYTES * 10:
                    log.debug("Silence detected — ending recording")
                    break

        finally:
            self._kill_process(proc)

        return bytes(all_pcm) if all_pcm else None

    # ── Audio capture ─────────────────────────────────────────────────────────

    def _capture_audio(self, duration_sec: float) -> Optional[bytes]:
        """Capture a fixed-duration audio clip."""
        n_bytes = int(duration_sec * SAMPLE_RATE * SAMPLE_WIDTH)

        proc = self._start_capture_process()
        if not proc:
            return None

        try:
            pcm = proc.stdout.read(n_bytes)
            return pcm if pcm and len(pcm) > 100 else None
        finally:
            self._kill_process(proc)

    def _start_capture_process(self) -> Optional[subprocess.Popen]:
        """Start a mic capture subprocess (parec or arecord)."""
        try:
            if self._backend == "parec":
                cmd = [
                    "parec",
                    "--format=s16le",
                    f"--rate={SAMPLE_RATE}",
                    f"--channels={CHANNELS}",
                    "--raw",
                ]
            elif self._backend == "arecord":
                cmd = [
                    "arecord",
                    "-f", "S16_LE",
                    "-r", str(SAMPLE_RATE),
                    "-c", str(CHANNELS),
                    "-t", "raw",
                    "-q",
                ]
            else:
                return None

            return subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._env,
            )
        except Exception as exc:
            log.error("Failed to start capture: %s", exc)
            return None

    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        """Safely terminate a subprocess."""
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # ── VAD ────────────────────────────────────────────────────────────────────

    def _is_speech(self, chunk: bytes) -> bool:
        """Check if an audio chunk contains speech."""
        if self._vad:
            try:
                return self._vad.is_speech(chunk, SAMPLE_RATE)
            except Exception:
                pass
        # Fallback: energy-based
        return _pcm_energy(chunk) > 500

    # ── STT ────────────────────────────────────────────────────────────────────

    def _transcribe(self, pcm: bytes) -> Optional[str]:
        """Transcribe PCM audio via Groq Whisper."""
        if not self._groq_client:
            return None

        wav_data = _pcm_to_wav(pcm)

        # Write to temp file (Groq SDK needs a file-like object with a name)
        fd, tmp_path = tempfile.mkstemp(suffix=".wav", prefix="ptrx_stt_")
        try:
            os.write(fd, wav_data)
            os.close(fd)

            with open(tmp_path, "rb") as f:
                result = self._groq_client.audio.transcriptions.create(
                    model="whisper-large-v3",
                    file=f,
                    language="en",
                    response_format="text",
                )
            text = result.strip() if isinstance(result, str) else str(result).strip()

            # Filter hallucination patterns (common Whisper artifacts)
            hallucinations = [
                "thank you", "thanks for watching", "subscribe",
                "bye", "silence", "...", "you",
            ]
            if text.lower().strip(".!? ") in hallucinations:
                return None

            return text

        except Exception as exc:
            log.error("STT error: %s", exc)
            return None
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _strip_wake_word(self, text: str) -> str:
        """Remove the wake word from the beginning of transcribed text."""
        lower = text.lower().strip()
        # Handle variations: "pentronix", "pentronix,", "hey pentronix"
        for prefix in [
            f"hey {self._wake_word}",
            f"ok {self._wake_word}",
            self._wake_word,
        ]:
            if lower.startswith(prefix):
                rest = text[len(prefix):].lstrip(" ,.:;!?")
                return rest if rest else ""
        return text


# ── Singleton ──────────────────────────────────────────────────────────────────
_LISTENER: Optional[VoiceListener] = None


def get_listener() -> VoiceListener:
    """Return the global VoiceListener singleton."""
    global _LISTENER
    if _LISTENER is None:
        _LISTENER = VoiceListener()
    return _LISTENER
