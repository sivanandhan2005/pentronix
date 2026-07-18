"""
Pentronix Main Window — black + neon-green hacking terminal UI.

Single-panel terminal interface that displays ALL agent output:
  - Agent thinking / responses (bright neon green)
  - Tool execution output (green, with tool label)
  - User messages (cyan)
  - Confirmation prompts (amber/yellow)
  - Errors (red)

Bottom bar: text input + mic toggle + send button.
Confirmation dialogs appear inline.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import (
    QObject, QThread, Qt, QTimer, pyqtSignal, pyqtSlot, QSize,
)
from PyQt6.QtGui import (
    QColor, QFont, QTextCharFormat, QTextCursor, QIcon, QKeySequence,
    QShortcut,
)
from PyQt6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget,
    QSizePolicy,
)

from utils.config import Config
from utils.logger import get_logger

log = get_logger(__name__)

# ── Colour constants ──────────────────────────────────────────────────────────
_GREEN        = "#00ff41"
_DIM_GREEN    = "#009922"
_CYAN         = "#00e5ff"
_AMBER        = "#ffaa00"
_RED          = "#ff0040"
_WHITE        = "#e0e0e0"
_DARK_BG      = "#000000"
_PANEL_BG     = "#0a0a0f"
_BORDER       = "#003300"
_TIMESTAMP    = "#444444"


# ── Agent Worker (runs in background thread) ──────────────────────────────────

class AgentWorker(QObject):
    """Runs the agent loop in a background thread, emitting Qt signals."""

    # Signals carrying event data to the UI
    event_thinking    = pyqtSignal(str)
    event_tool_call   = pyqtSignal(str, dict, str)    # tool_name, args, risk
    event_tool_output = pyqtSignal(str)                # output line
    event_tool_result = pyqtSignal(str, bool, str)     # tool, success, summary
    event_response    = pyqtSignal(str)                # final response
    event_error       = pyqtSignal(str)
    event_status      = pyqtSignal(str)
    event_confirmation = pyqtSignal(str, dict, str, str)  # tool, args, risk, desc
    event_done        = pyqtSignal()
    event_speak       = pyqtSignal(str)

    # Signal to receive work from the main thread (thread-safe crossing)
    start_processing = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._agent = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.start_processing.connect(self._on_process_message)

    @pyqtSlot(str)
    def _on_process_message(self, message: str) -> None:
        """Process a user message through the agent (runs in worker thread)."""
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

        self._loop.run_until_complete(self._run_agent(message))

    def process_message(self, message: str) -> None:
        """Queue a message for processing (callable from any thread)."""
        self.start_processing.emit(message)

    async def _run_agent(self, message: str) -> None:
        """Run the agent and translate events to Qt signals."""
        try:
            if self._agent is None:
                from core.agent import PentronixAgent
                self._agent = PentronixAgent()
                await self._agent.initialise()

                # Set sudo password if available
                password = os.environ.get("PENTRONIX_SUDO_PW", "")
                if password:
                    self._agent.set_sudo_password(password)

            from core.agent import EventType

            async for event in self._agent.run(message):
                etype = event.type
                data = event.data or {}

                if etype == EventType.THINKING:
                    self.event_thinking.emit(data.get("message") or "Thinking...")
                elif etype == EventType.TOOL_CALL:
                    self.event_tool_call.emit(
                        data.get("tool_name") or "unknown",
                        data.get("args") or {},
                        data.get("risk_level") or "LOW",
                    )
                elif etype == EventType.TOOL_OUTPUT:
                    self.event_tool_output.emit(data.get("line") or "")
                elif etype == EventType.TOOL_RESULT:
                    self.event_tool_result.emit(
                        data.get("tool_name") or "unknown",
                        bool(data.get("success")),
                        data.get("summary") or "",
                    )
                elif etype == EventType.RESPONSE:
                    msg = data.get("message") or ""
                    if msg.strip():
                        self.event_response.emit(msg)
                        self.event_speak.emit(msg)
                elif etype == EventType.ERROR:
                    self.event_error.emit(data.get("message") or "Unknown error")
                elif etype == EventType.STATUS:
                    self.event_status.emit(data.get("message") or "")
                elif etype == EventType.CONFIRMATION_REQUIRED:
                    self.event_confirmation.emit(
                        data.get("tool_name") or "unknown",
                        data.get("args") or {},
                        data.get("risk_level") or "HIGH",
                        data.get("description") or "Confirm this operation?",
                    )
                    # Wait for user response — the UI will call resolve_confirmation
                    # We poll until the future is resolved
                    while (
                        self._agent._confirmation_future
                        and not self._agent._confirmation_future.done()
                    ):
                        await asyncio.sleep(0.1)

        except Exception as exc:
            log.error("AgentWorker error: %s", exc, exc_info=True)
            self.event_error.emit(str(exc))
        finally:
            self.event_done.emit()

    def resolve_confirmation(self, approved: bool) -> None:
        """Resolve a pending confirmation from the UI."""
        if self._agent:
            self._agent.resolve_confirmation(approved)

    def cancel(self) -> None:
        """Cancel the current agent operation."""
        if self._agent:
            self._agent.cancel()


# ── Voice Worker (mic recording in background) ───────────────────────────────

class VoiceWorker(QObject):
    """Records audio and returns transcription."""

    transcription_ready = pyqtSignal(str)
    recording_state     = pyqtSignal(str)   # 'recording', 'processing', 'done', 'error'

    def __init__(self) -> None:
        super().__init__()
        self._stop_event = threading.Event()
        self._listener = None

    @pyqtSlot()
    def start_recording(self) -> None:
        """Start recording audio."""
        self._stop_event.clear()
        self.recording_state.emit("recording")

        try:
            from voice.listener import get_listener
            if self._listener is None:
                self._listener = get_listener()

            if not self._listener.available:
                self.recording_state.emit("error")
                return

            wav_bytes = self._listener.record_until_stopped(self._stop_event)

            if wav_bytes:
                self.recording_state.emit("processing")
                text = self._listener._transcribe(wav_bytes)
                if text:
                    self.transcription_ready.emit(text)
                    self.recording_state.emit("done")
                else:
                    self.recording_state.emit("error")
            else:
                self.recording_state.emit("error")

        except Exception as exc:
            log.error("VoiceWorker error: %s", exc)
            self.recording_state.emit("error")

    def stop_recording(self) -> None:
        """Stop the current recording."""
        self._stop_event.set()


# ── TTS Worker (plays speech in background) ───────────────────────────────────

class TTSWorker(QObject):
    """Speaks agent responses via edge-tts."""

    finished = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self._speaker = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @pyqtSlot(str)
    def speak(self, text: str) -> None:
        """Synthesise and play speech."""
        if not text or not text.strip():
            self.finished.emit()
            return

        try:
            if self._speaker is None:
                from voice.speaker import get_speaker
                self._speaker = get_speaker()

            if not self._speaker.available:
                self.finished.emit()
                return

            # Reuse event loop — creating a new one each time causes issues
            if self._loop is None:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)

            self._loop.run_until_complete(self._speaker.speak(text))

        except Exception as exc:
            log.error("TTSWorker error: %s", exc)
        finally:
            self.finished.emit()


# ── Main Window ───────────────────────────────────────────────────────────────

class PentronixWindow(QMainWindow):
    """Pentronix hacking terminal — single black panel with neon green output.

    All agent interactions, tool outputs, confirmations, and user messages
    are displayed in this single terminal view.
    """

    def __init__(self) -> None:
        super().__init__()
        self._is_recording = False
        self._is_processing = False

        self._setup_ui()
        self._setup_workers()
        self._apply_styles()
        self._print_banner()

    # ── UI Setup ──────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        """Build the terminal interface."""
        self.setWindowTitle("PENTRONIX")
        self.setMinimumSize(900, 600)
        self.resize(1100, 750)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Terminal output area ──────────────────────────────────────
        self._terminal = QTextEdit()
        self._terminal.setObjectName("terminal_output")
        self._terminal.setReadOnly(True)
        self._terminal.setFont(QFont("JetBrains Mono", 13))
        self._terminal.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self._terminal, stretch=1)

        # ── Confirmation bar (hidden by default) ──────────────────────
        self._confirm_frame = QFrame()
        self._confirm_frame.setObjectName("confirm_frame")
        self._confirm_frame.setVisible(False)
        confirm_layout = QHBoxLayout(self._confirm_frame)
        confirm_layout.setContentsMargins(12, 8, 12, 8)

        self._confirm_label = QLabel("Confirm operation?")
        self._confirm_label.setStyleSheet(f"color: {_AMBER}; font-size: 13px;")
        self._confirm_label.setWordWrap(True)
        self._confirm_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        confirm_layout.addWidget(self._confirm_label, stretch=1)

        self._confirm_yes = QPushButton("✓ YES")
        self._confirm_yes.setObjectName("confirm_yes")
        self._confirm_yes.clicked.connect(lambda: self._on_confirmation(True))
        confirm_layout.addWidget(self._confirm_yes)

        self._confirm_no = QPushButton("✗ NO")
        self._confirm_no.setObjectName("confirm_no")
        self._confirm_no.clicked.connect(lambda: self._on_confirmation(False))
        confirm_layout.addWidget(self._confirm_no)

        layout.addWidget(self._confirm_frame)

        # ── Bottom input bar ──────────────────────────────────────────
        input_frame = QFrame()
        input_frame.setStyleSheet(f"background: {_PANEL_BG}; border-top: 1px solid {_BORDER};")
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(12, 8, 12, 8)
        input_layout.setSpacing(8)

        # Mic button
        self._mic_btn = QPushButton("🎤")
        self._mic_btn.setObjectName("mic_button")
        self._mic_btn.setCheckable(True)
        self._mic_btn.setToolTip("Toggle microphone (hold to record)")
        self._mic_btn.clicked.connect(self._on_mic_toggle)
        input_layout.addWidget(self._mic_btn)

        # Text input
        self._input = QLineEdit()
        self._input.setObjectName("input_bar")
        self._input.setPlaceholderText("Type command or press mic to speak...")
        self._input.returnPressed.connect(self._on_send)
        input_layout.addWidget(self._input, stretch=1)

        # Send button
        self._send_btn = QPushButton("➤")
        self._send_btn.setObjectName("send_button")
        self._send_btn.setToolTip("Send message")
        self._send_btn.clicked.connect(self._on_send)
        input_layout.addWidget(self._send_btn)

        layout.addWidget(input_frame)

        # ── Status bar ────────────────────────────────────────────────
        self._status = QLabel("PENTRONIX ready.")
        self._status.setObjectName("status_label")
        layout.addWidget(self._status)

    def _setup_workers(self) -> None:
        """Initialise background workers and threads."""
        # Agent worker
        self._agent_thread = QThread()
        self._agent_worker = AgentWorker()
        self._agent_worker.moveToThread(self._agent_thread)

        self._agent_worker.event_thinking.connect(self._on_thinking)
        self._agent_worker.event_tool_call.connect(self._on_tool_call)
        self._agent_worker.event_tool_output.connect(self._on_tool_output)
        self._agent_worker.event_tool_result.connect(self._on_tool_result)
        self._agent_worker.event_response.connect(self._on_response)
        self._agent_worker.event_error.connect(self._on_error)
        self._agent_worker.event_status.connect(self._on_status)
        self._agent_worker.event_confirmation.connect(self._on_confirmation_request)
        self._agent_worker.event_done.connect(self._on_agent_done)

        self._agent_thread.start()

        # Voice worker
        self._voice_thread = QThread()
        self._voice_worker = VoiceWorker()
        self._voice_worker.moveToThread(self._voice_thread)

        self._voice_worker.transcription_ready.connect(self._on_transcription)
        self._voice_worker.recording_state.connect(self._on_recording_state)

        self._voice_thread.start()

        # TTS worker
        self._tts_thread = QThread()
        self._tts_worker = TTSWorker()
        self._tts_worker.moveToThread(self._tts_thread)

        self._agent_worker.event_speak.connect(self._tts_worker.speak)
        self._tts_thread.start()

    def _apply_styles(self) -> None:
        """Load and apply QSS stylesheet."""
        qss_path = Path(__file__).parent / "styles.qss"
        if qss_path.exists():
            self.setStyleSheet(qss_path.read_text(encoding="utf-8"))
        else:
            # Fallback minimal style
            self.setStyleSheet(f"""
                QMainWindow, QWidget {{ background: {_DARK_BG}; color: {_GREEN}; }}
                QTextEdit {{ background: {_DARK_BG}; color: {_GREEN}; border: none; }}
                QLineEdit {{ background: {_PANEL_BG}; color: {_GREEN}; border: 1px solid {_BORDER}; padding: 8px; }}
            """)

    # ── Banner ────────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        """Display the startup banner."""
        banner = """
 ██████╗ ███████╗███╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗
 ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝
 ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝
 ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗
 ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗
 ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
"""
        self._append_coloured(banner.strip(), _GREEN)
        self._append_coloured("", _GREEN)
        self._append_coloured("  ⬡  Autonomous AI Penetration Testing Assistant", _DIM_GREEN)
        self._append_coloured("  ⬡  Type a command or press the mic button to speak", _DIM_GREEN)
        self._append_coloured("  ⬡  All operations are logged. Dangerous actions require confirmation.", _DIM_GREEN)
        self._append_coloured("─" * 80, _BORDER)
        self._append_coloured("", _GREEN)

    # ── Terminal output helpers ───────────────────────────────────────────────

    def _append_coloured(self, text: str, colour: str) -> None:
        """Append coloured text to the terminal."""
        cursor = self._terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(colour))
        cursor.insertText(text + "\n", fmt)

        self._terminal.setTextCursor(cursor)
        self._terminal.ensureCursorVisible()

    def _append_labelled(self, label: str, text: str, label_colour: str, text_colour: str) -> None:
        """Append text with a coloured label prefix."""
        cursor = self._terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Label
        label_fmt = QTextCharFormat()
        label_fmt.setForeground(QColor(label_colour))
        label_fmt.setFontWeight(700)
        cursor.insertText(f"[{label}] ", label_fmt)

        # Text
        text_fmt = QTextCharFormat()
        text_fmt.setForeground(QColor(text_colour))
        cursor.insertText(text + "\n", text_fmt)

        self._terminal.setTextCursor(cursor)
        self._terminal.ensureCursorVisible()

    # ── User input handling ───────────────────────────────────────────────────

    def _on_send(self) -> None:
        """Handle send button / Enter key."""
        text = self._input.text().strip()
        if not text or self._is_processing:
            return

        self._input.clear()
        self._append_labelled("USER", text, _CYAN, _WHITE)
        self._set_processing(True)

        # Send to agent worker
        QTimer.singleShot(0, lambda: self._agent_worker.process_message(text))

    def _on_mic_toggle(self) -> None:
        """Handle mic button toggle."""
        if self._is_processing:
            self._mic_btn.setChecked(False)
            return

        if self._mic_btn.isChecked():
            # Start recording
            self._is_recording = True
            self._status.setText("🔴 Recording... Click mic again to stop.")
            QTimer.singleShot(0, self._voice_worker.start_recording)
        else:
            # Stop recording
            self._is_recording = False
            self._voice_worker.stop_recording()
            self._status.setText("Processing speech...")

    def _on_transcription(self, text: str) -> None:
        """Handle completed voice transcription."""
        self._mic_btn.setChecked(False)
        self._is_recording = False

        if text and text.strip():
            self._append_labelled("USER", f"🎤 {text}", _CYAN, _WHITE)
            self._set_processing(True)
            QTimer.singleShot(0, lambda: self._agent_worker.process_message(text))

    def _on_recording_state(self, state: str) -> None:
        """Handle voice recording state changes."""
        states = {
            "recording": "🔴 Recording...",
            "processing": "⏳ Transcribing speech...",
            "done": "PENTRONIX ready.",
            "error": "⚠ Voice input failed. Try again.",
        }
        self._status.setText(states.get(state, ""))

        if state in ("error", "done"):
            self._mic_btn.setChecked(False)
            self._is_recording = False

    # ── Agent event handlers ──────────────────────────────────────────────────

    @pyqtSlot(str)
    def _on_thinking(self, message: str) -> None:
        self._append_labelled("PENTRONIX", f"💭 {message}", _GREEN, _DIM_GREEN)
        self._status.setText("Agent thinking...")

    @pyqtSlot(str, dict, str)
    def _on_tool_call(self, tool_name: str, args: dict, risk: str) -> None:
        risk_colour = {
            "LOW": _GREEN, "MEDIUM": _AMBER,
            "HIGH": _RED, "CRITICAL": _RED,
        }.get(risk, _GREEN)

        # Format args concisely
        args_str = ""
        for k, v in args.items():
            val = str(v)[:100]
            args_str += f" {k}={val}"
        args_str = args_str.strip()

        self._append_labelled(
            f"TOOL:{tool_name}", f"▶ {args_str}", risk_colour, _DIM_GREEN
        )
        self._status.setText(f"Running {tool_name}...")

    @pyqtSlot(str)
    def _on_tool_output(self, line: str) -> None:
        if line.strip():
            self._append_coloured(f"  {line.rstrip()}", _DIM_GREEN)

    @pyqtSlot(str, bool, str)
    def _on_tool_result(self, tool_name: str, success: bool, summary: str) -> None:
        icon = "✓" if success else "✗"
        colour = _GREEN if success else _RED
        self._append_labelled(
            f"{icon} {tool_name}", summary, colour, colour
        )

    @pyqtSlot(str)
    def _on_response(self, message: str) -> None:
        self._append_coloured("", _GREEN)
        self._append_labelled("PENTRONIX", message, _GREEN, _GREEN)
        self._append_coloured("", _GREEN)

    @pyqtSlot(str)
    def _on_error(self, message: str) -> None:
        self._append_labelled("ERROR", message, _RED, _RED)
        self._status.setText("Error occurred.")

    @pyqtSlot(str)
    def _on_status(self, message: str) -> None:
        self._append_labelled("STATUS", message, _DIM_GREEN, _DIM_GREEN)

    @pyqtSlot()
    def _on_agent_done(self) -> None:
        self._set_processing(False)
        self._status.setText("PENTRONIX ready.")

    # ── Confirmation handling ─────────────────────────────────────────────────

    @pyqtSlot(str, dict, str, str)
    def _on_confirmation_request(
        self, tool_name: str, args: dict, risk: str, description: str
    ) -> None:
        """Show an inline confirmation prompt."""
        self._append_coloured("", _AMBER)
        self._append_labelled("⚠ CONFIRM", description, _AMBER, _AMBER)

        self._confirm_label.setText(
            f"⚠ {risk} — {tool_name}: Approve this operation?"
        )
        self._confirm_frame.setVisible(True)
        self._input.setEnabled(False)

    def _on_confirmation(self, approved: bool) -> None:
        """Handle user confirmation response."""
        self._confirm_frame.setVisible(False)
        self._input.setEnabled(True)

        if approved:
            self._append_labelled("CONFIRM", "✓ Approved — executing...", _GREEN, _GREEN)
        else:
            self._append_labelled("CONFIRM", "✗ Denied — operation cancelled.", _RED, _RED)

        self._agent_worker.resolve_confirmation(approved)

    # ── State management ──────────────────────────────────────────────────────

    def _set_processing(self, active: bool) -> None:
        """Toggle processing state — disable/enable input."""
        self._is_processing = active
        self._input.setEnabled(not active)
        self._send_btn.setEnabled(not active)

        if active:
            self._input.setPlaceholderText("Agent working...")
            self._status.setText("Agent working...")
        else:
            self._input.setPlaceholderText("Type command or press mic to speak...")
            self._input.setFocus()

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        """Clean up threads on close."""
        self._agent_worker.cancel()

        for thread in (self._agent_thread, self._voice_thread, self._tts_thread):
            thread.quit()
            thread.wait(2000)

        super().closeEvent(event)
