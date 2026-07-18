"""
Pentronix Reporting Tools — professional report generation.

Generates comprehensive HTML and Markdown penetration testing reports
from session data, including all scan results, exploitations,
and AI analysis.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from utils.logger import get_logger

log = get_logger(__name__)


class GenerateReport(Tool):
    name = "generate_report"
    description = (
        "Generate a professional penetration testing report from the current "
        "session data. Includes executive summary, scan findings, vulnerability "
        "analysis, exploitation results, and recommendations. Output in HTML "
        "or Markdown format."
    )
    parameters = {
        "type": "object",
        "properties": {
            "format": {
                "type": "string",
                "enum": ["html", "markdown"],
                "description": "Report format. Default: html",
            },
            "title": {
                "type": "string",
                "description": "Report title. Default: 'Pentronix Penetration Test Report'",
            },
            "target": {
                "type": "string",
                "description": "Primary target of the assessment. Optional.",
            },
            "output_path": {
                "type": "string",
                "description": "Custom output path. Optional (defaults to data/reports/)",
            },
        },
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        fmt = kwargs.get("format", "html")
        title = kwargs.get("title", "Pentronix Penetration Test Report")
        target = kwargs.get("target", "")
        output_path = kwargs.get("output_path", "")

        try:
            from memory.memory_manager import get_memory_manager
            mm = get_memory_manager()

            # Gather session data
            commands = mm.get_recent_commands(limit=50)
            targets_data = mm.get_all_targets()

            now = datetime.now(tz=timezone.utc)
            timestamp = now.strftime("%Y-%m-%d_%H%M%S")

            if not output_path:
                reports_dir = Path(__file__).parent.parent / "data" / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                ext = "html" if fmt == "html" else "md"
                output_path = str(reports_dir / f"pentronix_report_{timestamp}.{ext}")

            if fmt == "html":
                content = self._generate_html(title, target, commands, targets_data, now)
            else:
                content = self._generate_markdown(title, target, commands, targets_data, now)

            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(content, encoding="utf-8")

            msg = f"Report generated: {output_path}"
            if on_output:
                on_output(msg)

            return ToolResult(
                success=True,
                output=msg,
                artifacts={"report_path": output_path, "format": fmt},
            )

        except Exception as exc:
            log.error("Report generation failed: %s", exc)
            return ToolResult(success=False, output="", error=str(exc))

    def _generate_html(self, title, target, commands, targets, now) -> str:
        """Generate a professional HTML report."""
        cmd_rows = ""
        for cmd in commands:
            status = "✓" if cmd.get("success") else "✗"
            risk_color = {
                "LOW": "#00ff41", "MEDIUM": "#ffaa00",
                "HIGH": "#ff6600", "CRITICAL": "#ff0040",
            }.get(cmd.get("risk_level", "LOW"), "#00ff41")

            cmd_rows += f"""
            <tr>
                <td>{cmd.get('timestamp', '')[:19]}</td>
                <td>{cmd.get('tool_used', 'N/A')}</td>
                <td><code>{(cmd.get('command_run', '') or '')[:80]}</code></td>
                <td style="color:{risk_color}">{cmd.get('risk_level', 'LOW')}</td>
                <td>{status}</td>
                <td>{(cmd.get('ai_summary', '') or '')[:150]}</td>
            </tr>"""

        target_sections = ""
        for t in targets:
            ports = json.loads(t.get("open_ports", "[]"))
            vulns = json.loads(t.get("vulnerabilities", "[]"))
            port_list = ", ".join(
                f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in ports[:20]
            ) if ports else "None discovered"
            vuln_count = len(vulns)

            target_sections += f"""
            <div class="target-card">
                <h3>{t.get('ip_or_domain', 'Unknown')}</h3>
                <p><strong>First seen:</strong> {t.get('first_seen', '')[:10]}
                   | <strong>Last seen:</strong> {t.get('last_seen', '')[:10]}</p>
                <p><strong>OS:</strong> {t.get('os_detected', 'Unknown')}</p>
                <p><strong>Open Ports:</strong> {port_list}</p>
                <p><strong>Vulnerabilities:</strong> {vuln_count} found</p>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0a0a0f; color: #c0c0c0;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            padding: 40px; line-height: 1.6;
        }}
        h1 {{ color: #00ff41; font-size: 28px; border-bottom: 2px solid #00ff41; padding-bottom: 10px; margin-bottom: 20px; }}
        h2 {{ color: #00cc33; font-size: 20px; margin: 30px 0 15px; }}
        h3 {{ color: #00ff41; font-size: 16px; margin: 10px 0; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header .subtitle {{ color: #555; font-size: 14px; }}
        .meta {{ background: #111118; border: 1px solid #1a1a2e; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .meta p {{ margin: 5px 0; }}
        .meta strong {{ color: #00ff41; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
        th {{ background: #111118; color: #00ff41; padding: 10px 8px; text-align: left; border-bottom: 2px solid #00ff41; }}
        td {{ padding: 8px; border-bottom: 1px solid #1a1a2e; vertical-align: top; }}
        tr:hover {{ background: #0d0d15; }}
        code {{ background: #111118; padding: 2px 6px; border-radius: 3px; color: #00cc33; font-size: 12px; }}
        .target-card {{ background: #111118; border: 1px solid #1a1a2e; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .footer {{ text-align: center; color: #333; margin-top: 40px; padding-top: 20px; border-top: 1px solid #1a1a2e; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⬡ {title}</h1>
        <p class="subtitle">Generated by PENTRONIX AI | {now.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>

    <div class="meta">
        <h2>Assessment Overview</h2>
        <p><strong>Target:</strong> {target or 'Multiple targets'}</p>
        <p><strong>Date:</strong> {now.strftime('%B %d, %Y')}</p>
        <p><strong>Total Operations:</strong> {len(commands)}</p>
        <p><strong>Targets Assessed:</strong> {len(targets)}</p>
        <p><strong>Tool:</strong> PENTRONIX Autonomous AI Pentesting Assistant</p>
    </div>

    <h2>Target Intelligence</h2>
    {target_sections if target_sections else '<p style="color:#555">No target data collected.</p>'}

    <h2>Operations Log</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th><th>Tool</th><th>Command</th>
                <th>Risk</th><th>Status</th><th>Summary</th>
            </tr>
        </thead>
        <tbody>{cmd_rows if cmd_rows else '<tr><td colspan="6">No operations recorded.</td></tr>'}</tbody>
    </table>

    <div class="footer">
        <p>⬡ PENTRONIX — AI-Powered Autonomous Penetration Testing</p>
    </div>
</body>
</html>"""

    def _generate_markdown(self, title, target, commands, targets, now) -> str:
        """Generate a Markdown report."""
        lines = [
            f"# {title}",
            f"*Generated by PENTRONIX AI | {now.strftime('%Y-%m-%d %H:%M:%S UTC')}*",
            "",
            "## Assessment Overview",
            f"- **Target:** {target or 'Multiple targets'}",
            f"- **Date:** {now.strftime('%B %d, %Y')}",
            f"- **Total Operations:** {len(commands)}",
            f"- **Targets Assessed:** {len(targets)}",
            "",
            "## Target Intelligence",
        ]

        for t in targets:
            ports = json.loads(t.get("open_ports", "[]"))
            lines.append(f"\n### {t.get('ip_or_domain', 'Unknown')}")
            lines.append(f"- OS: {t.get('os_detected', 'Unknown')}")
            if ports:
                port_list = ", ".join(f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in ports[:20])
                lines.append(f"- Open Ports: {port_list}")

        lines.extend(["", "## Operations Log", ""])
        lines.append("| Timestamp | Tool | Risk | Status | Summary |")
        lines.append("|-----------|------|------|--------|---------|")

        for cmd in commands:
            status = "✓" if cmd.get("success") else "✗"
            ts = cmd.get("timestamp", "")[:19]
            tool = cmd.get("tool_used", "N/A")
            risk = cmd.get("risk_level", "LOW")
            summary = (cmd.get("ai_summary", "") or "")[:100]
            lines.append(f"| {ts} | {tool} | {risk} | {status} | {summary} |")

        lines.extend(["", "---", "*PENTRONIX — AI-Powered Autonomous Penetration Testing*"])
        return "\n".join(lines)
