#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Pentronix Setup Script — Kali Linux compatible (Python venv)
# Usage:  chmod +x setup.sh && sudo ./setup.sh
# ══════════════════════════════════════════════════════════════════════════════
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
AMBER='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${AMBER}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_DIR="$SCRIPT_DIR/.venv"

echo ""
echo -e "${GREEN}  ██████╗ ███████╗███╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗${NC}"
echo -e "${GREEN}  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝${NC}"
echo -e "${GREEN}  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝ ${NC}"
echo -e "${GREEN}  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗ ${NC}"
echo -e "${GREEN}  ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗${NC}"
echo -e "${GREEN}  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝${NC}"
echo ""
echo -e "${CYAN}  AI-Powered Pentesting Assistant — Setup (Kali Linux)${NC}"
echo ""

# ── 1. System dependencies ────────────────────────────────────────────────────
info "Installing system dependencies…"
apt-get update -qq
apt-get install -y -qq \
    python3-venv \
    python3-pip \
    portaudio19-dev \
    libssl-dev \
    python3-dev \
    mpg123 \
    nmap \
    libpulse-dev \
    2>/dev/null || warn "Some apt packages may have already been installed"
ok "System dependencies done"

# ── 2. Create virtual environment ─────────────────────────────────────────────
info "Creating Python virtual environment at .venv …"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
else
    ok "Virtual environment already exists — reusing"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ── 3. Upgrade pip inside venv ───────────────────────────────────────────────
info "Upgrading pip inside venv…"
"$VENV_PYTHON" -m pip install --upgrade pip -q
ok "pip upgraded"

# ── 4. Install requirements inside venv ──────────────────────────────────────
info "Installing Python requirements (this may take 1–2 min)…"
"$VENV_PIP" install -r "$SCRIPT_DIR/requirements.txt" -q
ok "Python packages installed"

# ── 5. Create .env if missing ─────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    info "Created .env from template"

    echo ""
    warn "You need a Groq API key to use Pentronix."
    warn "Get one free at: https://console.groq.com"
    echo ""
    read -rp "  Enter your Groq API key (or press Enter to skip): " GROQ_KEY
    if [ -n "$GROQ_KEY" ]; then
        sed -i "s|your_groq_api_key_here|$GROQ_KEY|g" "$ENV_FILE"
        ok "Groq API key saved to .env"
    else
        warn "Skipped. Edit .env manually before running."
    fi
else
    ok ".env already exists — skipping"
fi

# ── 6. Data directories ───────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/data/reports"
ok "Data directories ready"

# ── 7. Create system launcher at /usr/local/bin/pentronix ────────────────────
info "Creating 'pentronix' system command…"
LAUNCHER="/usr/local/bin/pentronix"

sudo tee "$LAUNCHER" > /dev/null <<LAUNCHER_SCRIPT
#!/usr/bin/env bash
# Pentronix launcher — uses project venv automatically
cd "${SCRIPT_DIR}"
exec "${VENV_PYTHON}" "${SCRIPT_DIR}/pentronix.py" "\$@"
LAUNCHER_SCRIPT

sudo chmod +x "$LAUNCHER"
ok "Command 'pentronix' registered at $LAUNCHER"

# ── 8. Audio check ────────────────────────────────────────────────────────────
info "Checking audio playback…"
if command -v mpg123 &>/dev/null; then
    ok "mpg123 found — TTS playback ready"
else
    warn "mpg123 not found. Install: sudo apt install mpg123"
fi

# ── 9. Import smoke test ──────────────────────────────────────────────────────
info "Running import smoke test…"
"$VENV_PYTHON" -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}')
from core.brain import Brain
from core.nmap_engine import NmapEngine
from core.msf_engine import MetasploitEngine
from core.report_generator import ReportGenerator
from voice.listener import VoiceListener
from voice.speaker import Speaker
from ui.main_window import MainWindow
print('All imports OK')
" && ok "All modules load cleanly" || warn "Some imports failed — check errors above"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Pentronix setup complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Start with:  ${CYAN}pentronix${NC}"
echo -e "  Or:          ${CYAN}cd ${SCRIPT_DIR} && ${VENV_PYTHON} pentronix.py${NC}"
echo ""
echo -e "  Tanglish commands to try:"
echo -e "    ${GREEN}scan 192.168.1.1${NC}              — nmap scan"
echo -e "    ${GREEN}scan panu 10.10.10.5 vuln${NC}     — vulnerability scan"
echo -e "    ${GREEN}exploit panu 192.168.1.10${NC}     — metasploit exploit"
echo -e "    ${GREEN}report kuduu${NC}                  — generate HTML report"
echo -e "    ${GREEN}nusthu${NC}                        — stop current task"
echo ""
