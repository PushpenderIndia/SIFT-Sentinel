#!/usr/bin/env bash
#
# SIFT-Sentinel installer — run on a SANS SIFT Workstation.
# Installs the Python package and registers the MCP server.
#
# Usage:  ./install.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] SIFT-Sentinel install"
echo "[*] Working dir: $HERE"

# --- 1. Python check -------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 not found. Install Python >=3.10 first." >&2
    exit 1
fi
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "[*] Python $PYVER detected"

# --- 2. Virtualenv ---------------------------------------------------------
if [ ! -d "$HERE/.venv" ]; then
    echo "[*] Creating virtualenv"
    python3 -m venv "$HERE/.venv"
fi
# shellcheck disable=SC1091
source "$HERE/.venv/bin/activate"

# --- 3. Install ------------------------------------------------------------
echo "[*] Installing sift-sentinel (editable)"
pip install --quiet --upgrade pip
pip install --quiet -e "$HERE[dev]"

# --- 4. Forensic tool availability check (non-fatal) -----------------------
echo "[*] Checking for underlying SIFT forensic tools (warn-only):"
for tool in MFTECmd.exe AmcacheParser.exe PECmd.exe EvtxECmd.exe vol fls mactime yara; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "    [ok]   $tool"
    else
        echo "    [warn] $tool not on PATH (tool wrappers using it will be unavailable)"
    fi
done

echo
echo "[+] Done. Activate with:  source $HERE/.venv/bin/activate"
echo "[+] Run the MCP server:   sift-sentinel-server"
echo "[+] Run the test suite:   pytest"
