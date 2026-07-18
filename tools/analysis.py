"""
Pentronix Analysis Tools — static analysis, binary inspection, log parsing.

Provides:
  - analyze_binary    — file type, strings, metadata extraction
  - hash_identify     — identify hash types
  - log_analysis      — parse and analyze log files
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class AnalyzeBinary(Tool):
    name = "analyze_binary"
    description = (
        "Perform static analysis on a binary file or executable. Extracts "
        "file type, metadata, printable strings, embedded files, and can "
        "run binwalk for firmware analysis. Useful for malware analysis "
        "and reverse engineering."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the file to analyze",
            },
            "analysis_type": {
                "type": "string",
                "enum": ["full", "file_type", "strings", "metadata", "binwalk", "hexdump"],
                "description": "Type of analysis. Default: full (runs all applicable checks)",
            },
            "strings_min_length": {
                "type": "integer",
                "description": "Minimum string length for strings extraction. Default: 6",
            },
        },
        "required": ["path"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        path = kwargs.get("path", "")
        analysis = kwargs.get("analysis_type", "full")
        min_len = kwargs.get("strings_min_length", 6)
        executor = get_executor()

        import os
        if not os.path.exists(path):
            return ToolResult(success=False, output="", error=f"File not found: {path}")

        outputs = []

        if analysis in ("full", "file_type"):
            r = await executor.execute(f"file '{path}'", timeout=10)
            outputs.append(f"=== FILE TYPE ===\n{r.stdout}")

        if analysis in ("full", "metadata"):
            r = await executor.execute(f"exiftool '{path}' 2>/dev/null || echo 'exiftool not available'", timeout=10)
            outputs.append(f"\n=== METADATA ===\n{r.stdout}")

        if analysis in ("full", "strings"):
            r = await executor.execute(f"strings -n {min_len} '{path}' | head -100", timeout=15)
            outputs.append(f"\n=== STRINGS (min {min_len} chars, first 100) ===\n{r.stdout}")

        if analysis in ("full", "binwalk"):
            r = await executor.execute(f"binwalk '{path}' 2>/dev/null || echo 'binwalk not available'", timeout=30)
            outputs.append(f"\n=== BINWALK ===\n{r.stdout}")

        if analysis == "hexdump":
            r = await executor.execute(f"xxd '{path}' | head -50", timeout=10)
            outputs.append(f"\n=== HEXDUMP (first 50 lines) ===\n{r.stdout}")

        # File size and hashes
        if analysis == "full":
            r = await executor.execute(
                f"echo 'Size:' $(stat -c%s '{path}') 'bytes' && "
                f"echo 'MD5:' $(md5sum '{path}' | cut -d' ' -f1) && "
                f"echo 'SHA256:' $(sha256sum '{path}' | cut -d' ' -f1)",
                timeout=15,
            )
            outputs.append(f"\n=== HASHES ===\n{r.stdout}")

        output = "\n".join(outputs)
        if on_output:
            on_output(output)

        return ToolResult(success=True, output=output)


class HashIdentify(Tool):
    name = "hash_identify"
    description = (
        "Identify the type of a hash string. Detects MD5, SHA1, SHA256, "
        "SHA512, NTLM, bcrypt, and many other hash formats. Useful for "
        "choosing the right cracking tool and mode."
    )
    parameters = {
        "type": "object",
        "properties": {
            "hash_value": {
                "type": "string",
                "description": "The hash string to identify",
            },
        },
        "required": ["hash_value"],
    }
    risk_level = RiskLevel.LOW

    _HASH_PATTERNS = {
        32: ["MD5", "NTLM", "MD4", "LM"],
        40: ["SHA1", "MySQL 4.x", "RIPEMD-160"],
        56: ["SHA-224"],
        64: ["SHA-256", "HMAC-SHA256", "Keccak-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "Whirlpool", "SHA3-512"],
    }

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        hash_val = kwargs.get("hash_value", "").strip()

        if not hash_val:
            return ToolResult(success=False, output="", error="No hash provided")

        lines = [f"Hash: {hash_val}", f"Length: {len(hash_val)} characters", ""]

        # Check for specific patterns
        if hash_val.startswith("$2a$") or hash_val.startswith("$2b$") or hash_val.startswith("$2y$"):
            lines.append("Identified: bcrypt")
            lines.append("Hashcat mode: 3200")
        elif hash_val.startswith("$6$"):
            lines.append("Identified: SHA-512 (Unix)")
            lines.append("Hashcat mode: 1800")
        elif hash_val.startswith("$5$"):
            lines.append("Identified: SHA-256 (Unix)")
            lines.append("Hashcat mode: 7400")
        elif hash_val.startswith("$1$"):
            lines.append("Identified: MD5 (Unix)")
            lines.append("Hashcat mode: 500")
        elif hash_val.startswith("$apr1$"):
            lines.append("Identified: Apache APR1-MD5")
            lines.append("Hashcat mode: 1600")
        elif ":" in hash_val and len(hash_val.split(":")[0]) == 32:
            lines.append("Identified: NTLM (with salt) or MySQL")
        else:
            # Match by length
            candidates = self._HASH_PATTERNS.get(len(hash_val), [])
            if candidates:
                lines.append(f"Possible types: {', '.join(candidates)}")
                # Check if all hex
                try:
                    int(hash_val, 16)
                    lines.append("Character set: hexadecimal")
                except ValueError:
                    lines.append("Character set: mixed (may include Base64)")
            else:
                lines.append(f"Unknown hash type (length {len(hash_val)})")

        # Try hash-identifier if available
        executor = get_executor()
        r = await executor.execute(
            f"echo '{hash_val}' | hash-identifier 2>/dev/null | head -15 || true",
            timeout=5,
        )
        if r.stdout.strip() and "not found" not in r.stdout.lower():
            lines.append(f"\nhash-identifier output:\n{r.stdout}")

        output = "\n".join(lines)
        if on_output:
            on_output(output)
        return ToolResult(success=True, output=output)


class LogAnalysis(Tool):
    name = "log_analysis"
    description = (
        "Parse and analyze log files for security-relevant events. "
        "Searches for failed logins, suspicious patterns, IP addresses, "
        "error messages, and attack indicators."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the log file to analyze",
            },
            "analysis_type": {
                "type": "string",
                "enum": ["overview", "failed_logins", "ip_extract", "errors", "custom_grep"],
                "description": "Type of analysis to perform. Default: overview",
            },
            "pattern": {
                "type": "string",
                "description": "Custom grep pattern (for custom_grep type). Optional.",
            },
            "tail_lines": {
                "type": "integer",
                "description": "Number of recent lines to analyze. Default: 500",
            },
        },
        "required": ["path"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        path = kwargs.get("path", "")
        analysis = kwargs.get("analysis_type", "overview")
        pattern = kwargs.get("pattern", "")
        tail = kwargs.get("tail_lines", 500)
        executor = get_executor()

        import os
        if not os.path.exists(path):
            return ToolResult(success=False, output="", error=f"File not found: {path}")

        outputs = []

        if analysis == "overview":
            cmds = [
                (f"wc -l '{path}'", "Total lines"),
                (f"head -5 '{path}'", "First 5 lines"),
                (f"tail -5 '{path}'", "Last 5 lines"),
                (f"tail -{tail} '{path}' | grep -ciE 'error|fail|denied|unauthorized|attack|exploit' || echo 0", "Security events count"),
                (f"tail -{tail} '{path}' | grep -oP '\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}' | sort | uniq -c | sort -rn | head -10", "Top 10 IPs"),
            ]
            for cmd, label in cmds:
                r = await executor.execute(cmd, timeout=15)
                outputs.append(f"=== {label} ===\n{r.stdout}")

        elif analysis == "failed_logins":
            r = await executor.execute(
                f"tail -{tail} '{path}' | grep -iE 'fail|invalid|denied|refused|unauthorized' | tail -30",
                timeout=15,
            )
            outputs.append(f"=== Failed Login Attempts (last 30) ===\n{r.stdout or 'None found'}")

        elif analysis == "ip_extract":
            r = await executor.execute(
                f"tail -{tail} '{path}' | grep -oP '\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}' | sort | uniq -c | sort -rn | head -20",
                timeout=15,
            )
            outputs.append(f"=== IP Addresses (by frequency) ===\n{r.stdout or 'None found'}")

        elif analysis == "errors":
            r = await executor.execute(
                f"tail -{tail} '{path}' | grep -iE 'error|exception|critical|fatal|panic' | tail -30",
                timeout=15,
            )
            outputs.append(f"=== Errors (last 30) ===\n{r.stdout or 'None found'}")

        elif analysis == "custom_grep" and pattern:
            r = await executor.execute(
                f"tail -{tail} '{path}' | grep -iE '{pattern}' | tail -50",
                timeout=15,
            )
            outputs.append(f"=== Pattern: {pattern} ===\n{r.stdout or 'No matches'}")

        output = "\n\n".join(outputs)
        if on_output:
            on_output(output)
        return ToolResult(success=True, output=output)
