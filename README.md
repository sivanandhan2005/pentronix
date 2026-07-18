
██████╗ ███████╗███╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝

             ⚡ Autonomous AI Penetration Testing Assistant ⚡
                    Voice-First • Always-On • JARVIS-Style


================================================================================
                              WHAT IS PENTRONIX?
================================================================================

PENTRONIX is an autonomous, voice-first AI penetration testing assistant built
for Kali Linux. Think of it as JARVIS for hacking — an always-on AI that
listens for your commands, executes security operations autonomously, speaks
results back naturally, and remembers everything it does.

Say "Pentronix, scan this network" — and it does the rest.

It is NOT a simple chatbot. It is a fully autonomous agent that can:

  • Chain 25+ tool operations without human intervention
  • Install missing tools on-the-fly
  • Research techniques on the internet when stuck
  • Remember all past operations and recall them on demand
  • Read and analyze your screen
  • Speak naturally like a movie AI assistant


================================================================================
                                 FEATURES
================================================================================

VOICE-FIRST INTERACTION
  • Always-on microphone listening (via PipeWire/PulseAudio)
  • Wake word activation — say "Pentronix" to begin
  • Natural female AI voice (Microsoft AriaNeural via edge-tts)
  • Speech-to-text via Groq Whisper API
  • Interrupt support — speak over the AI to stop it

AUTONOMOUS AGENT CORE
  • Think → Decide → Act → Observe loop with 25-iteration chaining
  • Smart tool selection — only loads relevant tools per query
  • Risk-based execution: LOW/MEDIUM auto-execute, HIGH/CRITICAL ask first
  • Token-budgeted for Groq free tier (12K TPM)
  • JARVIS-style conversational persona

43+ SECURITY TOOLS INTEGRATED
  Reconnaissance:
    • nmap_scan — Full port/service/OS detection scanning
    • whois_lookup — Domain registration intel
    • dns_lookup — DNS records (A, AAAA, MX, TXT, NS, CNAME)
    • subdomain_enum — Subdomain discovery
    • ping_host — Host alive detection
    • traceroute_host — Network path tracing
    • arp_scan — Local network device discovery
    • theharvester_scan — Email/subdomain OSINT gathering
    • google_dork — Google dorking for exposed data

  Vulnerability Scanning:
    • nikto_scan — Web server vulnerability scanning
    • nuclei_scan — Template-based vulnerability detection
    • nmap_vuln_scan — NSE script vulnerability scanning
    • searchsploit — Exploit database searching

  Exploitation:
    • metasploit_run — Metasploit module execution
    • sqlmap_scan — SQL injection detection and exploitation
    • hydra_bruteforce — Network service brute forcing
    • msfvenom_generate — Payload generation
    • create_reverse_shell — Reverse shell creation
    • create_custom_script — Custom exploit script generation

  Web Application:
    • gobuster_scan — Directory/file brute forcing
    • ffuf_fuzz — Web fuzzing
    • whatweb_fingerprint — Web technology fingerprinting
    • curl_request — HTTP request crafting
    • wafw00f_detect — Web application firewall detection

  Analysis:
    • analyze_binary — Static binary analysis (ELF/PE)
    • hash_identify — Hash type identification
    • log_analysis — System log analysis
    • read_screen — Screenshot capture + OCR text extraction

  System:
    • run_command — Execute any shell command
    • read_file / write_file — File operations
    • search_web — Internet search via DuckDuckGo
    • read_webpage — Web page content extraction
    • install_tool — Auto-install missing tools
    • open_application — Launch GUI apps / URLs
    • system_info — System hardware and network info
    • generate_report — Professional security report generation

PERSISTENT MEMORY (SQLite)
  • Stores every command, result, error, and conversation
  • Smart recall — ask "what did you scan earlier?" and it remembers
  • Target intel tracking — ports, services, CVEs per target
  • Learned knowledge base — techniques discovered during operations
  • Cross-session memory — survives restarts

SCREEN READING
  • Screenshot capture (scrot/gnome-screenshot/ImageMagick)
  • Tesseract OCR text extraction
  • Say "read my screen" and the AI analyzes what's displayed

HACKING TERMINAL UI (PyQt6)
  • Black background + neon green text — classic hacking aesthetic
  • Voice status indicator (Idle / Listening / Processing / Speaking)
  • Real-time activity log with tool execution streaming
  • Inline confirmation dialogs for high-risk operations
  • Always-on-top floating panel


================================================================================
                              ARCHITECTURE
================================================================================

pentronix/
├── pentronix.py              # Entry point — launches UI + voice loop
├── core/
│   ├── agent.py              # Autonomous agent (Think→Decide→Act→Observe)
│   ├── brain.py              # LLM client (Groq API with function-calling)
│   ├── executor.py           # Secure command executor with sudo injection
│   └── internet_researcher.py # Web research via DuckDuckGo
├── tools/
│   ├── recon.py              # nmap, whois, dns, ping, traceroute, arp
│   ├── vuln_scanner.py       # nikto, nuclei, nmap-vuln, searchsploit
│   ├── exploit.py            # metasploit, sqlmap, hydra
│   ├── web_tools.py          # gobuster, ffuf, whatweb, curl, wafw00f
│   ├── shell.py              # reverse shells, msfvenom payloads
│   ├── osint.py              # theharvester, google dorking
│   ├── analysis.py           # binary analysis, hash ID, log analysis
│   ├── browser.py            # app launching, media playback
│   ├── reporting.py          # security report generation
│   ├── screen_reader.py      # screenshot + OCR
│   └── payload_factory.py    # custom payload creation
├── voice/
│   ├── listener.py           # Always-on mic + wake word detection
│   └── speaker.py            # Natural AI voice (edge-tts AriaNeural)
├── memory/
│   ├── memory_manager.py     # SQLite persistent memory + recall
│   └── tool_registry.py      # Tool catalogue + auto-install
├── prompts/
│   └── system_prompt.py      # JARVIS persona + rules
├── ui/
│   └── main_window.py        # PyQt6 hacking terminal panel
├── utils/
│   ├── config.py             # Environment configuration (Pydantic)
│   └── logger.py             # Structured logging
├── data/
│   └── pentronix.db          # SQLite memory database
├── requirements.txt
├── setup.sh                  # Auto-installer script
└── .env                      # API keys and configuration


================================================================================
                            REQUIREMENTS
================================================================================

OPERATING SYSTEM
  • Kali Linux (recommended) or any Debian-based Linux distro
  • PipeWire or PulseAudio for audio I/O
  • Working microphone and speakers

PYTHON
  • Python 3.11+

API KEYS
  • Groq API Key (free tier) — for LLM (Llama 3.3 70B) + Whisper STT
    Get one at: https://console.groq.com

SYSTEM TOOLS (auto-installed via setup.sh)
  • mpg123 — audio playback
  • scrot — screenshot capture
  • tesseract-ocr — OCR text extraction
  • nmap, nikto, sqlmap, hydra, gobuster — security tools
  • parec (PipeWire) — microphone capture


================================================================================
                             INSTALLATION
================================================================================

1. Clone the repository:

   git clone https://github.com/YOUR_USERNAME/pentronix.git
   cd pentronix

2. Run the setup script (installs everything):

   chmod +x setup.sh
   sudo ./setup.sh

3. Create your .env file:

   cp .env.example .env
   nano .env

   Add your Groq API key:
     GROQ_API_KEY=your_groq_api_key_here

4. Install Python dependencies:

   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt


================================================================================
                              USAGE
================================================================================

LAUNCH:

   cd pentronix
   source .venv/bin/activate
   PENTRONIX_SUDO_PW=your_password python3 pentronix.py

VOICE COMMANDS (examples):

   "Pentronix, hello"
     → Responds with a natural greeting

   "Pentronix, scan 192.168.1.1"
     → Runs nmap scan, reports open ports and services

   "Pentronix, find vulnerabilities on 10.0.0.5"
     → Chains nmap → nikto → nuclei scans autonomously

   "Pentronix, create a reverse shell for Linux"
     → Generates a reverse shell payload

   "Pentronix, brute force SSH on 192.168.1.10"
     → Runs hydra with common credentials

   "Pentronix, what did you find earlier?"
     → Recalls past scan results from memory

   "Pentronix, read my screen"
     → Captures screenshot and reads text via OCR

   "Pentronix, open Wireshark"
     → Launches the application

   "Pentronix, search for CVE-2024-1234"
     → Searches the internet for vulnerability details

   "Pentronix, generate a full report"
     → Creates a professional penetration testing report


================================================================================
                          ENVIRONMENT VARIABLES
================================================================================

   GROQ_API_KEY        — (required) Groq API key for LLM + STT
   PENTRONIX_SUDO_PW   — (required) System password for sudo operations
   TTS_VOICE           — TTS voice (default: en-US-AriaNeural)
   TTS_RATE            — Speech rate (default: +5%)
   GROQ_MODEL          — LLM model (default: llama-3.3-70b-versatile)
   LOG_LEVEL           — Logging level (default: INFO)
   DB_PATH             — Memory database path (default: data/pentronix.db)


================================================================================
                              TECH STACK
================================================================================

   Component          Technology
   ─────────────────  ──────────────────────────────
   LLM                Groq Cloud (Llama 3.3 70B)
   Speech-to-Text     Groq Whisper (whisper-large-v3)
   Text-to-Speech     Microsoft edge-tts (AriaNeural)
   UI Framework       PyQt6
   Database           SQLite (persistent memory)
   Audio Capture      parec (PipeWire) / arecord (ALSA)
   Audio Playback     mpg123 / ffplay
   Web Research       DuckDuckGo Search API
   OCR                Tesseract
   Config             Pydantic + python-dotenv


================================================================================
                               DISCLAIMER
================================================================================

PENTRONIX is designed for AUTHORIZED penetration testing and security research
ONLY. Use this tool only on systems you own or have explicit written permission
to test.

Unauthorized access to computer systems is illegal. The developers assume NO
responsibility for misuse of this software.

Always follow responsible disclosure practices and applicable laws.


================================================================================
                               LICENSE
================================================================================

This project is for educational and authorized security testing purposes only.

================================================================================

                         Built with ⚡ by the Pentronix Team
                     "Your AI-Powered Penetration Testing Partner"

