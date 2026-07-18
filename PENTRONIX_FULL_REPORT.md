# PENTRONIX — Full Technical Project Report

> **Project Identity:** PENTRONIX  
> **Role:** AI-powered autonomous security and productivity platform  
> **Persona:** Natural female voice AI (en-US-JennyNeural), modelled on intelligent AI assistants from fiction  
> **Entry Point:** `pentronix.py`  
> **Generated:** 2026-04-13

---

## 1. Project Architecture Overview

```
pentronix/
├── pentronix.py              # App entry point
├── core/
│   ├── brain.py              # LLM intent engine (Groq API)
│   ├── browser_agent.py      # Playwright browser automation
│   ├── nmap_engine.py        # Network scanner integration
│   ├── msf_engine.py         # Metasploit Framework integration
│   ├── report_generator.py   # HTML pentest report builder
│   ├── risk_classifier.py    # Deterministic safety gate
│   └── session_memory.py     # Persistent task memory (NEW)
├── voice/
│   ├── listener.py           # STT via Groq Whisper
│   └── speaker.py            # TTS via edge-tts / mpg123
├── ui/
│   ├── main_window.py        # PyQt6 floating UI (1550+ lines)
│   ├── browser_worker.py     # QThread wrapper for browser tasks
│   └── styles.qss            # Dark hacker-terminal theme
├── utils/
│   ├── config.py             # .env config loader
│   └── logger.py             # Structured logger
├── prompts/
│   └── intent_schema.py      # Pydantic schema for LLM intents
├── data/
│   ├── reports/              # Generated HTML pentest reports
│   └── session_memory.json   # Last session task persistence
├── .env                      # Runtime configuration
└── requirements.txt          # Python dependencies
```

---

## 2. AI & Language Model

### 2.1 Model Used
| Component | Model / Service |
|-----------|----------------|
| Intent Parsing | **Groq API — `llama-3.3-70b-versatile`** |
| Speech-to-Text | **Groq Whisper — `whisper-large-v3`** |
| Text-to-Speech | **Microsoft edge-tts — `en-US-JennyNeural`** |

### 2.2 System Prompt Design (`core/brain.py`)
The brain uses a highly structured system prompt that defines:
- **Persona:** Confident, calm, proactive AI named PENTRONIX — not just a chatbot, an executor.
- **Tanglish Vocabulary:** 35+ Tamil-English mixed command patterns pre-defined for natural Tanglish input (e.g. `scan panu` → run nmap, `exploit panu` → metasploit, `youtube la X podu` → YouTube play)
- **Strict JSON Output Schema:** The model is forced to return ONLY valid JSON — never markdown, never prose.
- **Intent Classification Rules:** 8 intent types, precise extraction rules for IPs/domains, FRIDAY-style voice response guidelines

### 2.3 Intent JSON Schema
```json
{
  "intent": "scan|exploit|report|stop|status|sysinfo|browser_task|chat|clarify",
  "target": "<IP, domain, or null>",
  "scan_type": "quick|version|aggressive|vuln|full|null",
  "sysinfo_action": "local_ip|interfaces|open_tool|system|null",
  "browser_action": "youtube_play|gmail_read|gmail_compose|gmail_delete|web_search|flipkart_search|amazon_search|open_url|generic|null",
  "browser_params": { "search_query": "...", "url": "...", "to": "...", "subject": "...", "body": "..." },
  "msf_module": "<module path or null>",
  "msf_options": { "RHOSTS": "...", "RPORT": "...", "LHOST": "...", "LPORT": "..." },
  "ports": "<port spec or null>",
  "response_message": "<spoken reply — short, confident, action-first>",
  "follow_up": "<optional next-step hint>"
}
```

### 2.4 Brain Methods
| Method | Purpose |
|--------|---------|
| `Brain.parse_intent(text)` | Async — sends text to Groq LLM, returns parsed dict |
| `Brain.chat(text, history)` | Async — conversational response with history |
| `Brain._call_groq(messages)` | Internal — retries with backoff on rate-limit errors |
| `Brain._extract_json(text)` | Regex-based JSON extraction from LLM raw response |

---

## 3. Voice Pipeline

### 3.1 Speech-To-Text (`voice/listener.py`)

**Two-backend auto-selection system:**

| Backend | When Used | How |
|---------|-----------|-----|
| `sounddevice + webrtcvad` | PulseAudio available | Silence-aware VAD recording — stops when 1.5s of silence detected |
| `arecord (ALSA)` | Root / no PulseAudio | Fixed-duration + manual stop-event, auto-detects ALSA card (`plughw:N,0`) |

**Key constants:**
```python
SAMPLE_RATE   = 16000      # Hz
CHUNK_MS      = 30         # VAD frame size
VAD_MODE      = 3          # Aggressive silence detection
SILENCE_MS    = 1500       # Auto-stop after 1.5s silence
MAX_RECORD    = 30s        # Hard ceiling
MIN_FILE_SIZE = 1500 bytes # Reject if too small (fixed in latest patch)
```

**Key methods:**
| Method | Purpose |
|--------|---------|
| `VoiceListener.listen_once(on_state)` | Auto-VAD recording → Whisper transcription |
| `VoiceListener.record_until_stopped(stop_event)` | Manual press-to-stop recording (UI mic button) |
| `VoiceListener._record_arecord_manual(stop_event)` | ALSA fallback recording with device auto-detection |
| `VoiceListener._record_sd_manual(stop_event)` | sounddevice manual recording |
| `VoiceListener._transcribe(wav_bytes)` | Sends WAV to Groq Whisper, returns text |
| `VoiceListener._listen_vad()` | VAD-gated recording via webrtcvad |
| `get_listener()` | Singleton factory |

**Mic button flow (UI → voice):**  
`🎤 Click` → `ManualRecordWorker.run()` → `listener.record_until_stopped(stop_event)` → `⏹ Click` (sets stop_event) → `TranscribeWorker._transcribe(wav)` → `_on_transcribed(text)` → `_process_command(text)`

### 3.2 Text-To-Speech (`voice/speaker.py`)

**Voice:** `en-US-JennyNeural` (Microsoft Edge TTS — most natural conversational female voice)

**Pipeline:** `edge-tts` async synthesis → MP3 stream → `mpg123` low-latency playback

| Setting | Value |
|---------|-------|
| Default voice | `en-US-JennyNeural` |
| Rate | `+0%` (natural speed) |
| Pitch | `+0Hz` (unmodified) |
| Fallback chain | Jenny → Aria → Sara → Nancy (all natural female) |
| Playback engine | `mpg123` (preferred) / `ffplay` (fallback) |

**Key methods:**
| Method | Purpose |
|--------|---------|
| `Speaker.speak(text)` | Async — synthesise + play |
| `Speaker._stream_to_player(text, voice, rate, pitch)` | Core streaming pipeline |
| `Speaker._select_voice()` | Reads .env, validates, falls back gracefully |
| `get_speaker()` | Singleton factory |

---

## 4. Security Engines

### 4.1 Nmap Engine (`core/nmap_engine.py`)

**5 scan profiles:**
| Profile | Flags | Expected Duration |
|---------|-------|-----------|
| `quick` | `-sV --top-ports 1000 --open` | ~60s |
| `version` | `-sV -sC --top-ports 1000 --open` | ~90s |
| `aggressive` | `-A -T4 --open -p-` | ~300s |
| `vuln` | `-sV --script vuln --top-ports 1000 --open` | ~180s |
| `full` | `-sV -sC -O -p- -T4 --open` | ~600s |

**Data structures:**
```python
@dataclass
class PortInfo:
    port: int, protocol: str, state: str, service: str, version: str, extra: str

@dataclass
class NmapResult:
    target: str, scan_type: str, command: str
    open_ports: list[PortInfo]
    os_guesses: list[str]
    script_results: list[dict]
    raw_output: str
    duration_seconds: float
    error: str
```

**Key Methods:**
| Method | Purpose |
|--------|---------|
| `NmapEngine.run_scan(target, scan_type, on_line, timeout)` | Async real-time streaming scan |
| `NmapEngine.stop()` | Gracefully terminates running nmap subprocess |
| `NmapEngine.available` | Property — checks nmap in PATH |
| `_parse_nmap_output(raw)` | Regex parser → list[PortInfo] |
| `get_nmap_engine()` | Singleton factory |

### 4.2 Metasploit Engine (`core/msf_engine.py`)

**Operation:** Non-interactive `msfconsole -q -x "..."` one-liner pattern — no TTY required.

**Service-to-Module map (pre-loaded):** 12 services mapped to recommended modules:
- `smb` → `ms17_010_eternalblue` (EternalBlue)
- `rdp` → `CVE-2019-0708 BlueKeep`
- `ftp` → `vsftpd_234_backdoor`
- `ssh` → `ssh_login` brute force scanner
- `mysql`, `mssql`, `postgres`, `telnet`, `vnc`, `smtp`, `http`, `https`

**Key methods:**
| Method | Purpose |
|--------|---------|
| `MetasploitEngine.run_module(module, options, target, timeout, on_line)` | Async - executes MSF module, streams output |
| `MetasploitEngine.search_exploits(search_term, on_line)` | Searches MSF module DB |
| `MetasploitEngine.stop()` | Kills running msfconsole process |
| `MetasploitEngine.suggest_modules(service)` | Returns recommended modules for a service |
| `MetasploitEngine._build_rc_commands(module, options)` | Builds msfconsole -x command string |
| `_parse_msf_output(raw)` | Regex: detects Meterpreter/shell sessions, success/failure |
| `_parse_msf_search(raw)` | Parses msfconsole search results |

**Auto-payload selection:**
- Windows target → `windows/meterpreter/reverse_tcp`
- Linux target → `linux/x86/meterpreter/reverse_tcp`

### 4.3 Risk Classifier (`core/risk_classifier.py`)

**Purpose:** Deterministic safety gate — overrides LLM risk assignments using regex pattern matching.

**Risk levels:** `LOW → MEDIUM → HIGH → CRITICAL`

**Pattern matching tables:**
| Level | Patterns |
|-------|---------|
| CRITICAL | `rm -rf`, `dd if=`, `mkfs`, `shred`, `/etc/shadow`, reverse shell one-liners, `nc -e /bin/` |
| HIGH | `hydra`, `john`, `hashcat`, `sqlmap --dump`, `msfconsole`, `msfvenom`, `aircrack` |
| MEDIUM | `nmap -A/-O/-p-/--script`, `masscan`, `rustscan`, `sqlmap`, `nikto`, `arp-scan` |

**Special rules:**
- Public IP targets → auto-upgrades to HIGH + shows confirmation prompt
- `exploit` / `brute_force` intent → always at least HIGH
- Typed `I CONFIRM` required for CRITICAL operations

**Key functions:**
| Function | Purpose |
|----------|---------|
| `classify(intent)` | Apply pattern rules, return upgraded intent |
| `requires_confirmation(level)` | True for HIGH + CRITICAL |
| `requires_typed_confirmation(level)` | True only for CRITICAL |
| `_is_public_ip(target)` | Checks against RFC1918 private ranges |

---

## 5. Browser Automation (`core/browser_agent.py`)

**Engine:** Playwright (Chromium) — headless=False by default (visible browser)  
**Viewport:** 1280×800, realistic Chrome user-agent string

### 5.1 Supported Actions
| Action | What It Does |
|--------|-------------|
| `youtube_play` | Search YouTube, click first video, skip ads |
| `gmail_read` | Login mid-task (asks credentials), read 5 unread emails |
| `gmail_compose` | Login, fill To/Subject/Body, ask confirmation before send |
| `gmail_delete` | Login, search criteria, confirm, select all + delete |
| `web_search` | Google search, return top 4 result titles + snippets |
| `flipkart_search` | Search Flipkart, return 5 products with name/price/rating |
| `amazon_search` | Search Amazon.in, return 5 products with name/price/rating |
| `open_url` | Navigate to any URL, return page title |
| `generic` | Uses URL or query, falls back to web_search |

### 5.2 Mid-Task Clarification
The browser agent can **pause mid-task** and call `clarify_fn(question)` → blocking until the user types a response. Used for:
- Asking Gmail email/password
- Confirming email sends
- Confirming delete operations
- Requesting missing search queries

### 5.3 Key Methods
| Method | Purpose |
|--------|---------|
| `BrowserAgent.start()` | Launch Chromium via Playwright |
| `BrowserAgent.stop()` | Close browser |
| `BrowserAgent.run(action, params)` | Main dispatcher → delegates to action handler |
| `BrowserAgent._goto(url)` | Navigate with timeout |
| `BrowserAgent._fill(selector, text)` | Fill input safely |
| `BrowserAgent._click(selector)` | Click safely with timeout |
| `BrowserAgent._text(selector)` | Get inner text safely |
| `BrowserAgent._gmail_login()` | Handles full Gmail auth flow mid-task |

---

## 6. Report Generator (`core/report_generator.py`)

**Output:** Self-contained single-file HTML with embedded CSS — no external dependencies.  
**Saved to:** `data/reports/report_<target>_<timestamp>.html`

### Report Sections
1. **Executive Summary** — Risk badge (LOW/MEDIUM/HIGH/CRITICAL), open port count, active sessions, AI narrative paragraph
2. **Nmap Scan Results** — Table: Port | Protocol | Service | Version + OS detection + NSE script results
3. **Exploitation Results** — Module path, success badge, active sessions, error if any
4. **Raw Output** — Full nmap + msfconsole raw stdout in scrollable terminal-style blocks

**Risk severity auto-calculation:**
- Sessions opened → CRITICAL
- Successful exploit (no session) → HIGH  
- >10 open ports → MEDIUM
- Otherwise → LOW

**Key methods:**
| Method | Purpose |
|--------|---------|
| `ReportGenerator.generate(target, scan_result, exploit_results, ai_summary)` | Build + write HTML |
| `ReportGenerator.open_in_browser(path)` | Open in system browser |
| `_build_executive_summary(...)` | Renders summary section |
| `_build_scan_section(scan_result)` | Renders nmap table |
| `_build_exploit_section(exploit_results)` | Renders MSF section |
| `_build_raw_section(...)` | Renders raw output blocks |

---

## 7. Session Memory (`core/session_memory.py`) — NEW

**Purpose:** PENTRONIX remembers the last task across restarts and reports it during startup.  
**Storage:** `data/session_memory.json` (plain JSON)

### Memory Fields
```json
{
  "last_task": {
    "intent": "scan",
    "description": "nmap scan on 192.168.1.1",
    "target": "192.168.1.1",
    "status": "in_progress",
    "timestamp": "2026-04-13T10:30:00"
  }
}
```

**Statuses:** `in_progress` | `completed` | `stopped`

**Key functions:**
| Function | Purpose |
|----------|---------|
| `save_task(intent, description, target, status)` | Write current task |
| `mark_complete()` | Flag task as completed |
| `mark_stopped()` | Flag task as stopped |
| `load_last_session()` | Returns last task dict for greeting |

---

## 8. UI Layer (`ui/main_window.py`)

**Framework:** PyQt6 floating frameless dark terminal window  
**Theme:** Dark hacker terminal (green/cyan on #0a0a0f) — styled via `styles.qss`

### 8.1 Rich Startup Greeting — NEW
On every startup, PENTRONIX:
1. Says time-aware salutation: `Good morning / afternoon / evening / night, boss`
2. Reads system stats via `psutil`: CPU%, RAM%, Disk%  
3. Loads session memory — reports last task; if unfinished → asks "Shall I continue with X now, boss?"
4. Closes with: "What have you planned to do today, boss?"

### 8.2 Worker Threads (QThread subclasses)
| Class | Purpose |
|-------|---------|
| `ManualRecordWorker` | Press-to-stop mic recording |
| `TranscribeWorker` | Sends WAV to Groq Whisper |
| `SpeakerWorker` | edge-tts synthesis + mpg123 playback |
| `BrainWorker` | Async Groq LLM intent parsing |
| `NmapWorker` | Async nmap scan with live line streaming |
| `MsfWorker` | Async msfconsole execution |
| `BrowserWorker` | Playwright tasks in separate thread |
| `_AsyncWorker` | Base class — runs asyncio event loop in QThread |

### 8.3 Command Processing Pipeline
```
Text input (typed or transcribed)
    ↓
_process_command(text)
    ↓
BrainWorker (Groq LLM) → intent JSON
    ↓
_dispatch_intent(intent)
    ├── "scan"         → _handle_scan()   → NmapWorker
    ├── "exploit"      → _handle_exploit() → MsfWorker
    ├── "report"       → _handle_report() → ReportGenerator
    ├── "browser_task" → _handle_browser() → BrowserWorker
    ├── "sysinfo"      → _handle_sysinfo() → system commands
    ├── "stop"         → stop all workers
    ├── "chat"         → SpeakerWorker (speak response_message)
    └── "clarify"      → SpeakerWorker (ask question, wait)
```

### 8.4 Key UI Methods
| Method | Purpose |
|--------|---------|
| `_tts_startup_test()` | Rich time-aware PENTRONIX greeting with system stats |
| `_on_mic()` | Mic toggle: start → ManualRecordWorker, stop → TranscribeWorker |
| `_on_record_finished(wav)` | Handles captured WAV bytes |
| `_on_transcribed(text)` | Routes transcript to command pipeline |
| `_dispatch_intent(intent)` | Central intent router |
| `_handle_scan(target, scan_type)` | Starts nmap, saves to session memory |
| `_handle_exploit(target, module, options)` | Starts metasploit |
| `_handle_browser(action, params)` | Starts browser agent |
| `_handle_sysinfo(action, target)` | System info (IP, interfaces, launch tools) |
| `_handle_report()` | Generates HTML report |
| `_buffer_line(text, colour)` | Thread-safe batched UI output |
| `_set_busy(state)` | Enable/disable input during processing |

---

## 9. Configuration (`.env`)

```env
GROQ_API_KEY=<api_key>
TTS_VOICE=en-US-JennyNeural
TTS_RATE=+0%
TTS_PITCH=+0Hz
LOG_LEVEL=INFO
BROWSER_HEADLESS=false
```

---

## 10. Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `groq≥0.9.0` | Groq API client (LLaMA 3.3 + Whisper) |
| `PyQt6≥6.7.0` | Desktop UI framework |
| `edge-tts≥6.1.9` | Microsoft Neural TTS |
| `sounddevice≥0.4.6` | PulseAudio microphone recording |
| `webrtcvad≥2.0.10` | Voice Activity Detection |
| `python-dotenv≥1.0.0` | .env config loading |
| `aiohttp≥3.9.0` | Async HTTP (edge-tts streaming) |
| `pydantic≥2.6.0` | Intent schema validation |
| `requests≥2.31.0` | HTTP utility |
| `rich≥13.7.0` | Terminal formatting |
| `numpy≥1.26.0` | Audio buffer processing |
| `playwright` | Browser automation (Chromium) |
| `psutil` | System stats (CPU/RAM/Disk for greeting) |

**System binaries required:**
- `nmap` — network scanner
- `msfconsole` — Metasploit Framework
- `mpg123` or `ffplay` — audio playback for TTS
- `arecord` — ALSA recorder fallback

---

## 11. Summary of All Changes Made in This Session

| Change | File | What Changed |
|--------|------|-------------|
| Voice switch to JennyNeural | `voice/speaker.py` | Default + fallbacks changed from male voices to natural female voices |
| Natural TTS rate/pitch | `.env` + `speaker.py` | Rate=+0%, Pitch=+0Hz (removed artificial modifications) |
| Rich startup greeting | `ui/main_window.py` | Time-aware salutation + psutil system stats + session memory recall |
| PENTRONIX branding restored | `ui/main_window.py` | Title reverted from F.R.I.D.A.Y. to PENTRONIX throughout |
| Session memory module | `core/session_memory.py` | NEW — saves/loads last task to JSON, drives startup recall |
| Tanglish system prompt | `core/brain.py` | Completely rewrote with 35+ Tanglish vocab, FRIDAY-style persona, strict JSON output |
| Mic threshold fix | `voice/listener.py` | Lowered min arecord file size 4096→1500 bytes to stop short speech being rejected |
| Mic device auto-detect | `voice/listener.py` | Parses `arecord -l` card/device numbers, tries fallback chain on failure |
| Startup greeting | `ui/main_window.py` | Replaced static "F.R.I.D.A.Y. online" with dynamic contextual greeting |

---

## 12. How To Run

```bash
cd /home/dictator/Desktop/pentronix
.venv/bin/python pentronix.py
```

**On startup PENTRONIX will:**
1. Speak a time-appropriate greeting ("Good evening, boss. PENTRONIX online.")
2. Report live system stats (CPU, RAM, Disk)
3. Recall the last task from memory if any
4. Ask "What have you planned to do today, boss?"

**Mic usage:**
- Click `🎤` to start recording
- Speak your command (Tanglish or English)
- Click `⏹` to stop — PENTRONIX transcribes and executes

---

*Generated automatically by PENTRONIX development session — 2026-04-13*
