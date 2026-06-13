#!/bin/bash
set -e
echo "[*] Installing AEGIS-NEXUS dependencies..."
pip install -r requirements.txt
echo "[*] Copying config templates..."
cp config/config.example.yaml config/config.yaml
cp config/secrets.example.env ~/.aegis_secrets.env
echo ""
echo "[!] Edit config/config.yaml with your assets"
echo "[!] Edit ~/.aegis_secrets.env with your API keys"
echo "[*] Then run: python3 aegis_nexus.py web"
