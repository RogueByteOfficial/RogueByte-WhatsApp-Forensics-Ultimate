#!/usr/bin/env bash
# ==============================================================================
# RogueByte WhatsApp Forensics Ultimate v2.0 - Native System Installer
# Brand: RogueByteOfficial
# Platform: Linux & macOS (Bash/Zsh)
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${GREEN}${BOLD}"
echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║          ROGUEBYTE WHATSAPP FORENSICS ULTIMATE v2.0 - INSTALLER                ║"
echo "║               Digital Forensics & Mobile Security Workstation                  ║"
echo "║                          Brand: RogueByteOfficial                              ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}[*] Step 1: Checking Python 3 Environment...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Error: python3 is not installed. Please install Python 3.9+ first.${NC}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[✓] Python detected: v${PY_VER}${NC}"

echo -e "${CYAN}[*] Step 2: Verifying Python Standard Forensic Modules (sqlite3, hashlib, struct, unittest)...${NC}"
python3 -c "import sqlite3, hashlib, struct, unittest, json, pathlib, ipaddress, socket; print('    Core Forensic Standard Modules: OK')"
echo -e "${GREEN}[✓] Forensic engine dependencies satisfied (Zero external pip bloat required for core CLI).${NC}"

echo -e "${CYAN}[*] Step 3: Setting Execution Permissions...${NC}"
chmod +x ./roguebyte.py || true
chmod +x ./install.sh || true
echo -e "${GREEN}[✓] Executable permissions applied to ./roguebyte.py${NC}"

echo -e "${CYAN}[*] Step 4: Running Integrity Self-Test Suite (12 Forensic & Network Tests)...${NC}"
PYTHONPATH=. python3 -m unittest discover roguebyte_forensics/tests -v

echo -e "\n${CYAN}[*] Step 5: Checking Node.js Environment for Desktop GUI Workstation (Optional)...${NC}"
if command -v node &> /dev/null && command -v npm &> /dev/null; then
    NODE_VER=$(node -v)
    echo -e "${GREEN}[✓] Node.js detected: ${NODE_VER}${NC}"
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}[*] Installing Node packages for local desktop interface...${NC}"
        npm install --silent || true
    fi
    echo -e "${GREEN}[✓] Desktop GUI workstation ready.${NC}"
else
    echo -e "${YELLOW}[!] Node.js not detected. CLI/Terminal forensics and HTML reporting will run fully natively without Node.${NC}"
fi

echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}         [✓] INSTALLATION & VERIFICATION COMPLETED SUCCESSFULLY!                ${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "\n${BOLD}Quick Start Guide / طريقة التشغيل:${NC}"
echo -e "  1. ${CYAN}Interactive Menu:${NC}       ./roguebyte.py -i"
echo -e "  2. ${CYAN}Analyze msgstore.db:${NC}    ./roguebyte.py analyze /path/to/msgstore.db"
echo -e "  3. ${CYAN}Carve Deleted Messages:${NC} ./roguebyte.py carve /path/to/msgstore.db"
echo -e "  4. ${CYAN}Analyze PCAP Capture:${NC}   ./roguebyte.py pcap /path/to/traffic.pcap"
echo -e "  5. ${CYAN}Correlate PCAP with DB:${NC} ./roguebyte.py correlate --pcap traffic.pcap --database msgstore.db"
echo -e "  6. ${CYAN}Lookup IP Intelligence:${NC} ./roguebyte.py lookup-ip 157.240.22.35"
echo -e "  7. ${CYAN}Run Synthetic Benchmark:${NC}./roguebyte.py benchmark"
echo -e "  8. ${CYAN}Launch Desktop GUI:${NC}     ./roguebyte.py gui   (or: npm run dev)"
echo -e "\n${YELLOW}Developed by RogueByteOfficial. NIST SP 800-86 Compliant.${NC}\n"
