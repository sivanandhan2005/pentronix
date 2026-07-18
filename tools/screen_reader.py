"""
Pentronix Screen Reader — capture and analyze the screen.

Uses scrot/gnome-screenshot for capture and Tesseract OCR for text extraction.
The agent can use this to "see" what's on the display.
"""

import os
import shutil
import subprocess
import tempfile
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


def capture_screen() -> Optional[str]:
    """Take a screenshot and save to temp file.

    Returns:
        Path to the saved screenshot PNG, or None on failure.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".png", prefix="ptrx_screen_")
    os.close(fd)

    # Try capture tools in order
    for cmd in [
        ["scrot", "-o", tmp_path],
        ["gnome-screenshot", "-f", tmp_path],
        ["import", "-window", "root", tmp_path],  # ImageMagick
    ]:
        tool = cmd[0]
        if not shutil.which(tool):
            continue
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 1000:
                log.info("Screenshot captured via %s: %s", tool, tmp_path)
                return tmp_path
        except Exception as exc:
            log.warning("Screenshot via %s failed: %s", tool, exc)

    # Cleanup on failure
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    log.error("No screenshot tool available. Install: sudo apt install scrot")
    return None


def extract_text(image_path: str) -> str:
    """Extract text from screenshot using Tesseract OCR.

    Args:
        image_path: Path to the screenshot PNG.

    Returns:
        Extracted text, or error message.
    """
    if not shutil.which("tesseract"):
        return "[OCR unavailable — install: sudo apt install tesseract-ocr]"

    try:
        result = subprocess.run(
            ["tesseract", image_path, "stdout", "-l", "eng"],
            capture_output=True, timeout=15,
        )
        text = result.stdout.decode(errors="replace").strip()
        return text if text else "[No text detected on screen]"
    except Exception as exc:
        return f"[OCR error: {exc}]"


def read_screen() -> dict:
    """Capture the screen, extract text, and return analysis data.

    Returns:
        Dict with: screenshot_path, extracted_text, success.
    """
    path = capture_screen()
    if not path:
        return {
            "success": False,
            "error": "Failed to capture screenshot",
            "extracted_text": "",
            "screenshot_path": "",
        }

    text = extract_text(path)

    # Get screen dimensions
    dimensions = ""
    try:
        from PIL import Image
        img = Image.open(path)
        dimensions = f"{img.width}x{img.height}"
        img.close()
    except Exception:
        pass

    return {
        "success": True,
        "screenshot_path": path,
        "extracted_text": text[:3000],  # Limit for token budget
        "dimensions": dimensions,
    }


def cleanup_screenshot(path: str) -> None:
    """Delete a temporary screenshot file."""
    try:
        if path and os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass
