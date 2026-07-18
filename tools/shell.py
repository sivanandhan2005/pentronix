"""
Pentronix Shell Tools — system operations, file management, hardware control.

Provides the agent with full system access:
  - run_shell_command   — execute arbitrary commands
  - manage_service      — start/stop/restart system services
  - manage_network      — network interface and wifi card management
  - process_manager     — list/kill processes
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class ManageService(Tool):
    name = "manage_service"
    description = (
        "Manage system services using systemctl. Start, stop, restart, enable, "
        "disable, or check the status of any system service (e.g. apache2, "
        "postgresql, ssh, networking, NetworkManager)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": "Service name (e.g. apache2, ssh, postgresql, networking)",
            },
            "action": {
                "type": "string",
                "enum": ["start", "stop", "restart", "status", "enable", "disable"],
                "description": "Action to perform on the service",
            },
        },
        "required": ["service", "action"],
    }
    risk_level = RiskLevel.MEDIUM
    system_binary = "systemctl"

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        service = kwargs.get("service", "")
        action = kwargs.get("action", "status")

        cmd = f"sudo systemctl {action} {service}"
        if action == "status":
            cmd = f"systemctl {action} {service}"

        executor = get_executor()
        result = await executor.execute(
            cmd, on_output=on_output,
            sudo_password=kwargs.get("_sudo_password"),
            timeout=30,
        )
        return ToolResult(
            success=result.success or action == "status",
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class ManageNetwork(Tool):
    name = "manage_network"
    description = (
        "Manage network interfaces and wireless adapters. Can put wifi cards "
        "into monitor mode, change MAC addresses, bring interfaces up/down, "
        "and list network configuration."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list_interfaces", "interface_up", "interface_down",
                    "monitor_mode_on", "monitor_mode_off",
                    "change_mac", "show_ip", "show_wifi",
                    "scan_wifi",
                ],
                "description": "Network management action to perform",
            },
            "interface": {
                "type": "string",
                "description": "Network interface name (e.g. wlan0, eth0, wlan0mon). Required for most actions.",
            },
            "mac_address": {
                "type": "string",
                "description": "New MAC address (for change_mac action)",
            },
        },
        "required": ["action"],
    }
    risk_level = RiskLevel.MEDIUM

    _ACTION_COMMANDS = {
        "list_interfaces": "ip link show",
        "show_ip": "ip -4 addr show",
        "show_wifi": "iwconfig 2>/dev/null || echo 'iwconfig not available'",
    }

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "list_interfaces")
        interface = kwargs.get("interface", "wlan0")
        mac = kwargs.get("mac_address", "")
        executor = get_executor()
        sudo_pw = kwargs.get("_sudo_password")

        if action in self._ACTION_COMMANDS:
            cmd = self._ACTION_COMMANDS[action]
        elif action == "interface_up":
            cmd = f"sudo ip link set {interface} up"
        elif action == "interface_down":
            cmd = f"sudo ip link set {interface} down"
        elif action == "monitor_mode_on":
            cmd = (
                f"sudo ip link set {interface} down && "
                f"sudo iwconfig {interface} mode monitor && "
                f"sudo ip link set {interface} up"
            )
            self.risk_level = RiskLevel.HIGH
        elif action == "monitor_mode_off":
            cmd = (
                f"sudo ip link set {interface} down && "
                f"sudo iwconfig {interface} mode managed && "
                f"sudo ip link set {interface} up"
            )
        elif action == "change_mac":
            if not mac:
                return ToolResult(success=False, output="", error="MAC address required")
            cmd = (
                f"sudo ip link set {interface} down && "
                f"sudo ip link set {interface} address {mac} && "
                f"sudo ip link set {interface} up"
            )
            self.risk_level = RiskLevel.HIGH
        elif action == "scan_wifi":
            cmd = f"sudo iwlist {interface} scanning 2>/dev/null | head -100"
        else:
            return ToolResult(success=False, output="", error=f"Unknown action: {action}")

        result = await executor.execute(
            cmd, on_output=on_output, sudo_password=sudo_pw, timeout=30,
        )
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )


class ProcessManager(Tool):
    name = "process_manager"
    description = (
        "List running processes or kill a specific process. Useful for managing "
        "long-running tools, finding existing listeners, or cleaning up."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list", "list_listening", "kill", "kill_by_name"],
                "description": "Action: list processes, list listening ports, kill by PID, or kill by name",
            },
            "target": {
                "type": "string",
                "description": "PID (for kill) or process name (for kill_by_name). Optional for list.",
            },
            "filter": {
                "type": "string",
                "description": "Filter string to grep processes. Optional.",
            },
        },
        "required": ["action"],
    }
    risk_level = RiskLevel.LOW

    async def execute(self, on_output: Optional[Callable] = None, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "list")
        target = kwargs.get("target", "")
        filter_str = kwargs.get("filter", "")
        executor = get_executor()

        if action == "list":
            cmd = "ps aux --sort=-%mem | head -30"
            if filter_str:
                cmd = f"ps aux | grep -i '{filter_str}' | grep -v grep"
        elif action == "list_listening":
            cmd = "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
        elif action == "kill":
            if not target:
                return ToolResult(success=False, output="", error="PID required")
            cmd = f"kill -9 {target}"
            self.risk_level = RiskLevel.MEDIUM
        elif action == "kill_by_name":
            if not target:
                return ToolResult(success=False, output="", error="Process name required")
            cmd = f"pkill -f '{target}'"
            self.risk_level = RiskLevel.MEDIUM
        else:
            return ToolResult(success=False, output="", error=f"Unknown action: {action}")

        result = await executor.execute(cmd, on_output=on_output, timeout=10)
        return ToolResult(
            success=result.success, output=result.stdout,
            error=result.stderr, duration_seconds=result.duration_seconds,
        )
