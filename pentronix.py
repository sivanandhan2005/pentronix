"""
Pentronix — Autonomous AI Penetration Testing Assistant.

Entry point. Initialises the Qt application, sets up the environment,
and launches the hacking terminal UI.

Usage:
    python pentronix.py                    # Normal launch
    python pentronix.py --sudo-password    # Prompt for sudo password at startup
    PENTRONIX_SUDO_PW=xxx python pentronix.py  # Pass sudo password via env
"""

import os
import sys
import getpass
import argparse
from pathlib import Path


def _ensure_project_on_path() -> None:
    """Add the project root to sys.path so imports work."""
    project_root = str(Path(__file__).parent.resolve())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


def _ensure_data_dirs() -> None:
    """Create required data directories."""
    root = Path(__file__).parent
    for d in ["data", "data/reports"]:
        (root / d).mkdir(parents=True, exist_ok=True)


def _check_env() -> bool:
    """Validate that essential environment variables are set."""
    _ensure_project_on_path()
    from utils.config import Config
    cfg = Config.get()

    if not cfg.has_any_llm():
        print(
            "\n  ✗ No LLM API key configured.\n"
            "    Add GROQ_API_KEY to your .env file:\n"
            "    echo 'GROQ_API_KEY=gsk_your_key_here' >> .env\n"
        )
        return False

    return True


def main() -> None:
    """Launch Pentronix."""
    parser = argparse.ArgumentParser(description="Pentronix — AI Pentesting Assistant")
    parser.add_argument(
        "--sudo-password", "-s",
        action="store_true",
        help="Prompt for sudo password at startup (for privileged operations)",
    )
    args = parser.parse_args()

    _ensure_project_on_path()
    _ensure_data_dirs()

    # Check environment
    if not _check_env():
        sys.exit(1)

    # Handle sudo password
    if args.sudo_password:
        pw = getpass.getpass("  🔑 Sudo password (for privileged operations): ")
        os.environ["PENTRONIX_SUDO_PW"] = pw
    elif "PENTRONIX_SUDO_PW" not in os.environ:
        # Try to prompt if running interactively
        if sys.stdin.isatty():
            print("  ℹ  Tip: Run with --sudo-password or set PENTRONIX_SUDO_PW for privileged ops.")
            print("  ℹ  You can also type the password when prompted in the UI.\n")

    # Launch Qt application
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QFont, QFontDatabase

    app = QApplication(sys.argv)
    app.setApplicationName("PENTRONIX")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("Pentronix")

    # Try to load JetBrains Mono font
    font_paths = [
        "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
        "/usr/share/fonts/jetbrains-mono/JetBrainsMono-Regular.ttf",
    ]
    for fp in font_paths:
        if os.path.exists(fp):
            QFontDatabase.addApplicationFont(fp)
            break

    # Set default monospace font
    font = QFont("JetBrains Mono", 13)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    # Create and show the main window
    from ui.main_window import PentronixWindow
    window = PentronixWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
