#!/bin/bash
# CloudOSINT Toolkit v3.0 — Quick Launch

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║     CLOUDOSINT TOOLKIT  v3.0                 ║"
echo "  ║     12 Real Modules — Full Cloud OSINT       ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
echo "  Modules: CRT.sh · Wayback · HackerTarget · VirusTotal"
echo "           DNS · Storage(AWS/Azure/GCP) · GitHub · Shodan"
echo "           Censys · Firebase · Azure AD · AWS IAM"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found. Install Python 3.9+ first."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtualenv..."
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null

echo "[*] Installing dependencies..."
pip install -r requirements.txt --quiet

echo ""
echo "[✓] Ready! Starting server..."
echo "[✓] Open http://127.0.0.1:5000 in your browser"
echo ""
echo "  ⚠  LEGAL: Only scan domains you own or have"
echo "     explicit written permission to test."
echo ""

python3 app.py
