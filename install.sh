#!/usr/bin/env bash
#
# SIFT-Sentinel installer — run on a SANS SIFT Workstation.
# Installs the Python package, optional forensic tools, and registers the MCP server.
#
# Usage:
#   ./install.sh                              # evidence root defaults to /mnt/cases
#   ./install.sh --evidence-root /mnt/cases    # explicit evidence root
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Parse args ------------------------------------------------------------
EVIDENCE_ROOT="/mnt/cases"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --evidence-root) EVIDENCE_ROOT="$2"; shift 2 ;;
        *) echo "[!] Unknown argument: $1" >&2; exit 1 ;;
    esac
done

AUDIT_LOG="$HERE/audit/execution-log.jsonl"

echo "[*] SIFT-Sentinel install"
echo "[*] Working dir:    $HERE"
echo "[*] Evidence root:  $EVIDENCE_ROOT"
echo "[*] Audit log:      $AUDIT_LOG"

# --- 1. Python check -------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 not found. Install Python >=3.10 first." >&2
    exit 1
fi
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "[*] Python $PYVER detected"

# --- 2. Ensure python3-venv is available -----------------------------------
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[*] python3-venv not found — installing via apt"
    sudo apt-get update -qq
    sudo apt-get install -y python3-venv python3.12-venv 2>/dev/null \
        || sudo apt-get install -y python3-venv
fi

# --- 3. Virtualenv — handle vboxsf (no symlink support) --------------------
# VirtualBox shared folders don't support symlinks; put the venv on local disk.
FS_TYPE="$(stat -f -c '%T' "$HERE" 2>/dev/null || stat --file-system --format='%T' "$HERE" 2>/dev/null || echo unknown)"
if [[ "$FS_TYPE" == "tmpfs" || "$FS_TYPE" == "vboxsf" ]] || \
   mountpoint -q "$HERE" 2>/dev/null && mount | grep -q "$(df --output=source "$HERE" 2>/dev/null | tail -1) .* vboxsf"; then
    VENV_DIR="$HOME/.local/share/sift-sentinel/.venv"
    echo "[*] Detected vboxsf filesystem — creating venv on local disk: $VENV_DIR"
else
    VENV_DIR="$HERE/.venv"
fi

# Remove a broken partial venv (no pyvenv.cfg = creation failed mid-way)
if [ -d "$VENV_DIR" ] && [ ! -f "$VENV_DIR/pyvenv.cfg" ]; then
    echo "[*] Removing incomplete venv at $VENV_DIR"
    rm -rf "$VENV_DIR"
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtualenv at $VENV_DIR"
    mkdir -p "$(dirname "$VENV_DIR")"
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# --- 4. Install sift-sentinel ----------------------------------------------
echo "[*] Installing sift-sentinel (editable)"
pip install --quiet --upgrade pip
pip install --quiet -e "$HERE[dev]"

# --- 5. Install apt forensic dependencies if missing ----------------------
for pkg_bin in "yara:yara" "sccainfo:libscca-tools"; do
    bin="${pkg_bin%%:*}"
    pkg="${pkg_bin##*:}"
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[*] $bin not found — installing $pkg via apt"
        sudo apt-get install -y "$pkg" 2>/dev/null && echo "    [ok] $bin installed" \
            || echo "    [warn] $pkg install failed — skipping"
    fi
done

# --- 6. Forensic tool availability check (non-fatal) -----------------------
echo "[*] Checking for underlying SIFT forensic tools (warn-only):"
for tool in MFTECmd AmcacheParser EvtxECmd sccainfo vol fls mactime yara; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "    [ok]   $tool"
    else
        echo "    [warn] $tool not on PATH (tool wrappers using it will be unavailable)"
    fi
done

# --- 7. Register MCP server with Claude Code -------------------------------
# Claude Code reads MCP servers from ~/.claude.json (written by `claude mcp add`),
# NOT from settings.json. Use the official CLI so the entry lands in the right
# place and is health-checked. Fall back to editing ~/.claude.json directly if
# the `claude` CLI is not on PATH.
SERVER_BIN="$VENV_DIR/bin/sift-sentinel-server"

if command -v claude >/dev/null 2>&1; then
    echo "[*] Registering MCP server via 'claude mcp add' (user scope)"
    # Remove any stale entry so re-running the installer is idempotent.
    claude mcp remove sift-sentinel -s user >/dev/null 2>&1 || true
    claude mcp add sift-sentinel --scope user --transport stdio \
        -- "$SERVER_BIN" --evidence-root "$EVIDENCE_ROOT" --audit "$AUDIT_LOG" \
        && echo "    [ok] sift-sentinel registered (evidence-root=$EVIDENCE_ROOT)"
else
    echo "[*] 'claude' CLI not found — writing MCP entry into ~/.claude.json directly"
    CLAUDE_JSON="$HOME/.claude.json"
    [ -f "$CLAUDE_JSON" ] || echo '{}' > "$CLAUDE_JSON"
    python3 - "$CLAUDE_JSON" "$SERVER_BIN" "$EVIDENCE_ROOT" "$AUDIT_LOG" <<'PYEOF'
import sys, json

cfg_path, server_bin, evidence_root, audit_log = sys.argv[1:5]

with open(cfg_path) as f:
    cfg = json.load(f)

cfg.setdefault("mcpServers", {})["sift-sentinel"] = {
    "type": "stdio",
    "command": server_bin,
    "args": ["--evidence-root", evidence_root, "--audit", audit_log],
}

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print(f"    [ok] sift-sentinel registered in ~/.claude.json (evidence-root={evidence_root})")
PYEOF
fi

echo
echo "[+] Done."
echo "[+] Venv location:      $VENV_DIR"
echo "[+] Evidence root:      $EVIDENCE_ROOT"
echo "[+] Audit log:          $AUDIT_LOG"
echo "[+] Run the test suite: pytest"
echo "[+] MCP server registered — restart Claude Code and the forensic tools"
echo "[+] will appear automatically. No need to run sift-sentinel-server manually."
