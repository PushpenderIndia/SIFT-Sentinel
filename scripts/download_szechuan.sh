#!/usr/bin/env bash
#
# download_szechuan.sh — fetch, extract, and mount DFIR Madness Case 001
# "Stolen Szechuan Sauce" so that /triage (no args) produces the full report.
#
# After this script completes:
#   /mnt/cases                   = DC01 C-drive  (read-only NTFS via ewfmount)
#   /evidence/base-dc-memory.img = DC01 RAM capture
#
# Then run: /triage     ← no arguments needed; defaults match the above paths.
#
# Usage:
#   sudo ./scripts/download_szechuan.sh             # core set + mount
#   sudo ./scripts/download_szechuan.sh --full      # + pagefiles, autoruns, protected files
#   sudo ./scripts/download_szechuan.sh --dest /data/szechuan
#   sudo ./scripts/download_szechuan.sh --no-mount  # download + extract only (no root needed)
#
# Evidence source
# ───────────────
# All files are hosted directly at https://dfirmadness.com/case001/
# Primary downloader: curl / wget (direct HTTP — no auth, no Google account needed)
# Google Drive (gdown) is kept as an optional fallback.
# CyberDefenders mirror (free account required):
#   https://cyberdefenders.org/blueteam-ctf-challenges/szechuan-sauce/
#
declare -A DIRECT_URLS=(
  ["DC01-E01.zip"]="https://dfirmadness.com/case001/DC01-E01.zip"
  ["DC01-memory.zip"]="https://dfirmadness.com/case001/DC01-memory.zip"
  ["DESKTOP-E01.zip"]="https://dfirmadness.com/case001/DESKTOP-E01.zip"
  ["DESKTOP-SDN1RPT-memory.zip"]="https://dfirmadness.com/case001/DESKTOP-SDN1RPT-memory.zip"
  ["case001-pcap.zip"]="https://dfirmadness.com/case001/case001-pcap.zip"
  ["DC01-pagefile.zip"]="https://dfirmadness.com/case001/DC01-pagefile.zip"
  ["DC01-autorunsc.zip"]="https://dfirmadness.com/case001/DC01-autorunsc.zip"
  ["DC01-ProtectedFiles.zip"]="https://dfirmadness.com/case001/DC01-ProtectedFiles.zip"
  ["Desktop-SDN1RPT-pagefile.zip"]="https://dfirmadness.com/case001/Desktop-SDN1RPT-pagefile.zip"
  ["DESKTOP-SDN1RPT-autorunsc.zip"]="https://dfirmadness.com/case001/DESKTOP-SDN1RPT-autorunsc.zip"
  ["DESKTOP-SDN1RPT-Protected Files.zip"]="https://dfirmadness.com/case001/DESKTOP-SDN1RPT-Protected%20Files.zip"
)

# Google Drive folder ID — optional fallback (gdown --folder)
# Leave empty to skip; populate from https://dfirmadness.com/the-stolen-szechuan-sauce/ if needed.
GDRIVE_FOLDER_ID=""

# Published MD5 hashes (from dfirmadness.com — used for post-download verification)
declare -A KNOWN_MD5=(
  ["DC01-E01.zip"]="E57FC636E833C5F1AB58DFACE873BBDE"
  ["DC01-memory.zip"]="64A4E2CB47138084A5C2878066B2D7B1"
  ["DC01-pagefile.zip"]="964EEAF0009D08CC101DE4A83A4E5D23"
  ["DC01-autorunsc.zip"]="964F2D710687D170C77C94947DA29E66"
  ["DC01-ProtectedFiles.zip"]="AD29830A583EFE49C8C1C35FAFFD264F"
  ["DESKTOP-E01.zip"]="71C5C3509331F472ABCDF81EB6EFFF07"
  ["DESKTOP-SDN1RPT-memory.zip"]="CF31E2635C77811AAA1BB04A92A721E2"
  ["Desktop-SDN1RPT-pagefile.zip"]="45C096F2688A0B5DE0346FB72391B245"
  ["DESKTOP-SDN1RPT-autorunsc.zip"]="3627DCAFA54E1365489A4EC0CC3D6A1C"
  ["DESKTOP-SDN1RPT-Protected Files.zip"]="3E1A358D50003A9351AC2160AE6F0495"
  ["case001-pcap.zip"]="422046B753CF8A4DF49D2C4CE892DB16"
)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
DEST="${SZECHUAN_DEST:-evidence/szechuan_sauce}"
EWF_MOUNT="${EWF_MOUNT:-/mnt/ewf}"
CASES_MOUNT="${CASES_MOUNT:-/mnt/cases}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
MEM_IMAGE_NAME="base-dc-memory.img"

CORE_FILES=(
  "DC01-E01.zip"
  "DC01-memory.zip"
  "DESKTOP-E01.zip"
  "DESKTOP-SDN1RPT-memory.zip"
  "case001-pcap.zip"
)

EXTRA_FILES=(
  "DC01-pagefile.zip"
  "DC01-autorunsc.zip"
  "DC01-ProtectedFiles.zip"
  "Desktop-SDN1RPT-pagefile.zip"
  "DESKTOP-SDN1RPT-autorunsc.zip"
  "DESKTOP-SDN1RPT-Protected Files.zip"
)

DO_FULL=0
DO_MOUNT=1

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;36m[szechuan]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m      %s\n'  "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m    %s\n'  "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m   %s\n'  "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n\033[1;35m══ %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)     DO_FULL=1; shift ;;
    --dest)     DEST="${2:?--dest requires a path}"; shift 2 ;;
    --no-mount) DO_MOUNT=0; shift ;;
    --yes|-y)   shift ;;  # accepted for backwards-compat, no-op
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      die "unknown argument: $1  (run with --help for usage)"
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Dependency auto-installer
# ---------------------------------------------------------------------------
# apt_install <pkg>  — installs a system package quietly, requires root.
apt_install() {
  local pkg="$1"
  log "Installing system package: $pkg"
  if [[ "$(id -u)" -eq 0 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" >/dev/null 2>&1 \
      && ok "Installed: $pkg" \
      || { err "apt-get install $pkg failed"; return 1; }
  else
    warn "Not root — trying sudo for: $pkg"
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -q "$pkg" >/dev/null 2>&1 \
      && ok "Installed: $pkg" \
      || { err "sudo apt-get install $pkg failed (re-run as root if this persists)"; return 1; }
  fi
}

# pip_install <pkg>  — installs a Python package, handles PEP-668 systems.
pip_install() {
  local pkg="$1"
  log "Installing Python package: $pkg"
  # Try pip3 first, then pip
  local pip_cmd=""
  command -v pip3 >/dev/null 2>&1 && pip_cmd="pip3"
  command -v pip  >/dev/null 2>&1 && pip_cmd="${pip_cmd:-pip}"
  [[ -z "$pip_cmd" ]] && { err "pip not found — cannot install $pkg"; return 1; }

  # Try normal install first; if PEP-668 blocks it, use --break-system-packages
  if $pip_cmd install -q "$pkg" 2>/dev/null; then
    ok "Installed (pip): $pkg"
  elif $pip_cmd install -q "$pkg" --break-system-packages 2>/dev/null; then
    ok "Installed (pip --break-system-packages): $pkg"
  else
    # Last resort: pipx
    if command -v pipx >/dev/null 2>&1; then
      pipx install "$pkg" >/dev/null 2>&1 && ok "Installed (pipx): $pkg" || return 1
    else
      err "Could not install $pkg via pip or pipx"
      return 1
    fi
  fi
}

# ---------------------------------------------------------------------------
# Prerequisite checks + auto-install  (before any download)
# ---------------------------------------------------------------------------
step "Checking prerequisites"

MISSING_TOOLS=()

# ── Downloader: curl (primary) → wget → gdown (Google Drive fallback only) ──
HAS_GDOWN=0
HAS_CURL=0
HAS_WGET=0
command -v gdown >/dev/null 2>&1 && HAS_GDOWN=1
command -v curl  >/dev/null 2>&1 && HAS_CURL=1
command -v wget  >/dev/null 2>&1 && HAS_WGET=1

# curl/wget are required for direct HTTP downloads
if [[ "$HAS_CURL" -eq 0 && "$HAS_WGET" -eq 0 ]]; then
  warn "Neither curl nor wget found — attempting to install curl..."
  apt_install curl && { HAS_CURL=1; ok "Installed: curl"; } \
    || MISSING_TOOLS+=("curl (apt-get install -y curl)")
fi

# gdown is optional — used only if GDRIVE_FOLDER_ID is set as a fallback
if [[ "$HAS_GDOWN" -eq 0 && -n "$GDRIVE_FOLDER_ID" ]]; then
  warn "GDRIVE_FOLDER_ID is set but gdown not found — attempting install..."
  if pip_install gdown; then
    export PATH="$HOME/.local/bin:$PATH"
    command -v gdown >/dev/null 2>&1 && HAS_GDOWN=1
  fi
  [[ "$HAS_GDOWN" -eq 0 ]] && warn "gdown install failed — Google Drive fallback unavailable"
fi

# gdown folder download (preferred — handles Drive auth automatically)
# gdown 6.x puts files into a subdir named after the folder; we merge into $DEST.
# Returns 0 only if at least one EXPECTED .zip file (from FILES[]) was downloaded.
folder_fetch() {
  [[ -z "$GDRIVE_FOLDER_ID" ]] && return 1   # no ID configured — skip silently

  local tmp_dir; tmp_dir="$(mktemp -d "$DEST/.gdown_folder_XXXXXX")"
  if ! gdown --folder \
             "https://drive.google.com/drive/folders/${GDRIVE_FOLDER_ID}" \
             -O "$tmp_dir" -c; then
    warn "gdown folder download returned an error"
    rm -rf "$tmp_dir"
    return 1
  fi

  # Move only expected .zip files into $DEST; discard anything else
  local moved=0
  for fname in "${FILES[@]}"; do
    local found; found="$(find "$tmp_dir" -maxdepth 3 -name "$fname" 2>/dev/null | head -1)"
    if [[ -n "$found" ]]; then
      local dest_file="$DEST/$fname"
      [[ -s "$dest_file" ]] || mv "$found" "$dest_file"
      (( moved++ )) || true
    fi
  done

  rm -rf "$tmp_dir"

  if [[ "$moved" -eq 0 ]]; then
    warn "gdown folder download completed but found none of the expected .zip files"
    warn "  The folder ID may be wrong. Check: https://dfirmadness.com/the-stolen-szechuan-sauce/"
    return 1
  fi
  return 0
}

# Per-file gdown fallback (when a GDRIVE_ID is known)
gdrive_fetch_file() {
  local id="$1" out="$2"
  gdown "https://drive.google.com/uc?id=${id}" -O "$out" -c --fuzzy
}

# curl two-pass for large Drive files (no gdown)
curl_gdrive_fetch() {
  local id="$1" out="$2"
  local jar; jar="$(mktemp)"
  local token
  token=$(curl -sc "$jar" \
          "https://drive.google.com/uc?export=download&id=${id}" 2>/dev/null \
          | grep -oP '(?<=confirm=)[^&"]+' | head -1)
  curl -fL --retry 5 --retry-delay 5 -C - \
       -b "$jar" \
       "https://drive.google.com/uc?export=download&id=${id}&confirm=${token}" \
       -o "$out"
  rm -f "$jar"
}

wget_gdrive_fetch() {
  local id="$1" out="$2"
  wget -c --tries=5 \
       "https://drive.google.com/uc?export=download&confirm=t&id=${id}" \
       -O "$out"
}

direct_fetch() {
  if   [[ "$HAS_CURL" -eq 1 ]]; then curl -fL --retry 5 --retry-delay 5 -C - -o "$2" "$1"
  elif [[ "$HAS_WGET" -eq 1 ]]; then wget -c --tries=5 -O "$2" "$1"
  else die "No downloader available"; fi
}

# ── unzip ───────────────────────────────────────────────────────────────────
if ! command -v unzip >/dev/null 2>&1; then
  warn "unzip not found — attempting install..."
  apt_install unzip || MISSING_TOOLS+=("unzip")
fi

# ── 7z ──────────────────────────────────────────────────────────────────────
HAS_7Z=0
if command -v 7z >/dev/null 2>&1; then
  HAS_7Z=1
else
  warn "7z not found — attempting install..."
  apt_install p7zip-full && HAS_7Z=1
fi

# ── Mounting tools (only needed when --no-mount is not set) ─────────────────
if [[ "$DO_MOUNT" -eq 1 ]]; then
  if ! command -v ewfmount >/dev/null 2>&1; then
    warn "ewfmount not found — attempting install..."
    apt_install ewf-tools || apt_install libewf-dev || MISSING_TOOLS+=("ewfmount (apt: ewf-tools)")
  fi
  if ! command -v ntfs-3g >/dev/null 2>&1 && ! command -v mount.ntfs >/dev/null 2>&1; then
    warn "ntfs-3g not found — attempting install..."
    apt_install ntfs-3g || MISSING_TOOLS+=("ntfs-3g")
  fi
  if ! command -v mmls >/dev/null 2>&1; then
    warn "mmls not found — attempting install (sleuthkit)..."
    apt_install sleuthkit || warn "mmls unavailable; partition offset detection will be skipped"
  fi
fi

# ── Abort if anything critical is still missing ─────────────────────────────
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
  err "Could not install the following required tools:"
  for t in "${MISSING_TOOLS[@]}"; do err "  • $t"; done
  echo
  err "Fix manually:  sudo apt-get install -y ewf-tools ntfs-3g unzip p7zip-full sleuthkit"
  err "               pip install gdown"
  exit 1
fi

# ── Report downloader in use ─────────────────────────────────────────────────
if [[ "$HAS_CURL" -eq 1 ]]; then
  ok "Downloader: curl (direct HTTP)"
elif [[ "$HAS_WGET" -eq 1 ]]; then
  ok "Downloader: wget (direct HTTP)"
else
  die "No downloader (curl/wget) available. Install with: sudo apt-get install -y curl"
fi
[[ "$HAS_GDOWN" -eq 1 && -n "$GDRIVE_FOLDER_ID" ]] && ok "Fallback: gdown (Google Drive)"

if [[ "$DO_MOUNT" -eq 1 ]] && [[ "$(id -u)" -ne 0 ]]; then
  die "Mounting requires root. Re-run with: sudo $0 $*"
fi

# ---------------------------------------------------------------------------
# MD5 helper
# ---------------------------------------------------------------------------
if command -v md5sum >/dev/null 2>&1; then
  md5of() { md5sum "$1" | awk '{print $1}'; }
elif command -v md5 >/dev/null 2>&1; then
  md5of() { md5 -q "$1"; }
else
  md5of() { echo "(no md5 tool)"; }
fi

verify_md5() {
  local file="$1" fname; fname="$(basename "$1")"
  local expected="${KNOWN_MD5[$fname]:-}"
  [[ -z "$expected" ]] && return 0   # no hash on record — skip
  local actual; actual="$(md5of "$file" | tr '[:lower:]' '[:upper:]')"
  if [[ "$actual" == "$expected" ]]; then
    ok "  MD5 OK   $fname  ($actual)"
  else
    warn "  MD5 MISMATCH $fname"
    warn "    expected: $expected"
    warn "    actual:   $actual"
    warn "    File may be corrupt or re-uploaded. Compare against:"
    warn "    https://dfirmadness.com/the-stolen-szechuan-sauce/"
  fi
}

# ---------------------------------------------------------------------------
# Build file list
# ---------------------------------------------------------------------------
FILES=("${CORE_FILES[@]}")
[[ "$DO_FULL" -eq 1 ]] && FILES+=("${EXTRA_FILES[@]}")

# ---------------------------------------------------------------------------
# Confirm before starting
# ---------------------------------------------------------------------------
step "Download plan"
log "Destination  : $DEST"
log "Files        : ${#FILES[@]} ($( [[ $DO_FULL -eq 1 ]] && echo 'core + extra' || echo 'core only'))"
log "Mount DC01   : $( [[ $DO_MOUNT -eq 1 ]] && echo "yes → $CASES_MOUNT" || echo 'no (--no-mount)')"
log "Source URL   : https://dfirmadness.com/case001/"
warn "Disk images are multi-GB. Downloads resume automatically if interrupted."
echo

mkdir -p "$DEST"

# ---------------------------------------------------------------------------
# Phase 1: Download
# ---------------------------------------------------------------------------
step "Phase 1 — Download"

DOWNLOADED=()
FAILED=()

# ── Per-file download: direct HTTP (primary) → Google Drive fallback ────────
for fname in "${FILES[@]}"; do
  out="$DEST/$fname"

  if [[ -s "$out" ]]; then
    ok "Already exists — skipping: $fname"
    DOWNLOADED+=("$out")
    continue
  fi

  log "Downloading: $fname"
  direct_url="${DIRECT_URLS[$fname]:-}"

  if [[ -n "$direct_url" ]]; then
    log "  → $direct_url"
    if direct_fetch "$direct_url" "$out.part" && mv "$out.part" "$out"; then
      ok "  ✓ $fname"
      DOWNLOADED+=("$out")
    else
      rm -f "$out.part"
      err "  Direct download failed for: $fname"
      # Google Drive folder fallback (requires GDRIVE_FOLDER_ID + gdown)
      if [[ -n "$GDRIVE_FOLDER_ID" && "$HAS_GDOWN" -eq 1 ]]; then
        warn "  Trying Google Drive fallback..."
        if folder_fetch && [[ -s "$out" ]]; then
          ok "  ✓ $fname (via Google Drive)"
          DOWNLOADED+=("$out")
        else
          err "  Google Drive fallback also failed for: $fname"
          FAILED+=("$fname")
        fi
      else
        err "  Mirror: https://cyberdefenders.org/blueteam-ctf-challenges/szechuan-sauce/"
        FAILED+=("$fname")
      fi
    fi
  else
    err "  No download URL configured for: $fname"
    err "  Mirror: https://cyberdefenders.org/blueteam-ctf-challenges/szechuan-sauce/"
    FAILED+=("$fname")
  fi
done

# MD5 verification of everything downloaded
step "MD5 Verification"
for f in "${DOWNLOADED[@]}"; do
  [[ -f "$f" ]] && verify_md5 "$f"
done

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  warn "${#FAILED[@]} file(s) not downloaded:"
  for f in "${FAILED[@]}"; do warn "  • $f"; done
  warn "Re-run once the issue is resolved — completed files will be skipped."
fi

[[ "${#DOWNLOADED[@]}" -eq 0 ]] && die "No files downloaded. Cannot continue."

# ---------------------------------------------------------------------------
# Phase 2: Extract
# ---------------------------------------------------------------------------
step "Phase 2 — Extract"

EXTRACT_DIR="$DEST/extracted"
mkdir -p "$EXTRACT_DIR"

DC01_E01=""
DC01_MEM=""

for z in "${DOWNLOADED[@]}"; do
  [[ "$z" != *.zip ]] && continue
  base="$(basename "$z")"
  sub="$EXTRACT_DIR/${base%.zip}"
  mkdir -p "$sub"

  if [[ -n "$(ls -A "$sub" 2>/dev/null)" ]]; then
    ok "Already extracted: $base"
  else
    log "Extracting: $base → $sub"
    if ! unzip -n -q "$z" -d "$sub"; then
      warn "unzip reported an issue with $base (may be partial — continuing)"
    fi
    ok "Extracted: $base"
  fi

  # Locate DC01 artifacts for mounting
  if [[ "$base" == "DC01-E01.zip" ]]; then
    DC01_E01="$(find "$sub" -maxdepth 2 -name "*.E01" | head -1)"
    [[ -n "$DC01_E01" ]] && ok "Found DC01 disk image: $DC01_E01"
  fi

  if [[ "$base" == "DC01-memory.zip" ]]; then
    DC01_MEM="$(find "$sub" -maxdepth 2 \
                \( -name "*.mem" -o -name "*.raw" -o -name "*.img" \) | head -1)"
    # Inner 7z (some releases wrap the .mem in a second archive)
    if [[ -z "$DC01_MEM" ]]; then
      inner7z="$(find "$sub" -maxdepth 2 -name "*.7z" | head -1)"
      if [[ -n "$inner7z" && "$HAS_7Z" -eq 1 ]]; then
        log "Extracting inner archive: $(basename "$inner7z")"
        7z x -o"$sub" "$inner7z" -y >/dev/null
        DC01_MEM="$(find "$sub" -maxdepth 3 \
                    \( -name "*.mem" -o -name "*.raw" -o -name "*.img" \) | head -1)"
      elif [[ -n "$inner7z" && "$HAS_7Z" -eq 0 ]]; then
        warn "Memory archive is a .7z but 7z is not installed."
        warn "  sudo apt-get install -y p7zip-full  then re-run."
      fi
    fi
    [[ -n "$DC01_MEM" ]] && ok "Found DC01 memory image: $DC01_MEM"
  fi
done

# ---------------------------------------------------------------------------
# Phase 3: Mount
# ---------------------------------------------------------------------------
if [[ "$DO_MOUNT" -eq 0 ]]; then
  step "Phase 3 — Mount (skipped)"
  warn "--no-mount specified. Re-run without it to complete setup."
else
  step "Phase 3 — Mount evidence"

  # ── Disk ──────────────────────────────────────────────────────────────────
  if [[ -z "$DC01_E01" ]]; then
    warn "DC01 E01 image not found — skipping disk mount."
  else
    mkdir -p "$EWF_MOUNT" "$CASES_MOUNT"

    # Check if already mounted with the same image — skip if so (idempotent)
    STAMP_FILE="$EWF_MOUNT/.mounted_e01"
    if mountpoint -q "$EWF_MOUNT" 2>/dev/null && [[ -f "$STAMP_FILE" ]]; then
      prev="$(cat "$STAMP_FILE")"
      if [[ "$prev" == "$(realpath "$DC01_E01")" ]]; then
        ok "Already mounted (same image) — skipping remount of $CASES_MOUNT"
        DC01_ALREADY_MOUNTED=1
      else
        warn "  $EWF_MOUNT currently holds a DIFFERENT image:"
        warn "    mounted : $prev"
        warn "    new     : $(realpath "$DC01_E01")"
        warn "  Unmounting previous evidence and replacing..."
        umount -l "$CASES_MOUNT" 2>/dev/null || true
        umount -l "$EWF_MOUNT"   2>/dev/null || true
      fi
    elif mountpoint -q "$CASES_MOUNT" 2>/dev/null || mountpoint -q "$EWF_MOUNT" 2>/dev/null; then
      warn "  A previous mount exists at $CASES_MOUNT or $EWF_MOUNT (no stamp found)."
      warn "  Unmounting before proceeding..."
      umount -l "$CASES_MOUNT" 2>/dev/null || true
      umount -l "$EWF_MOUNT"   2>/dev/null || true
    fi

    if [[ "${DC01_ALREADY_MOUNTED:-0}" -eq 0 ]]; then
      log "Mounting: $DC01_E01"
      ewfmount "$DC01_E01" "$EWF_MOUNT" || die "ewfmount failed for $DC01_E01"
      # Write stamp so future runs can detect same-image remount
      realpath "$DC01_E01" > "$STAMP_FILE"
      ok "ewfmount → $EWF_MOUNT"

      EWF1="$EWF_MOUNT/ewf1"
      [[ -f "$EWF1" ]] || die "$EWF1 not found after ewfmount"

      OFFSET="" SECTOR_SIZE=512
      if command -v mmls >/dev/null 2>&1; then
        OFFSET=$(mmls "$EWF1" 2>/dev/null \
                 | awk '/NTFS|Basic data|[Ww]in/{print $3; exit}')
        SECTOR_SIZE=$(mmls "$EWF1" 2>/dev/null \
                      | awk '/^Units/{gsub(/[^0-9]/,"",$NF); print $NF}')
        SECTOR_SIZE=${SECTOR_SIZE:-512}
      fi

      if [[ -n "$OFFSET" ]]; then
        mount -t ntfs-3g \
              -o ro,noexec,nodev,noatime,offset=$(( OFFSET * SECTOR_SIZE )) \
              "$EWF1" "$CASES_MOUNT"
      else
        warn "mmls unavailable or no NTFS partition detected — trying direct mount"
        mount -t ntfs-3g -o ro,noexec,nodev,noatime "$EWF1" "$CASES_MOUNT"
      fi
      ok "Disk mounted read-only → $CASES_MOUNT"
    fi
  fi

  # ── Memory ────────────────────────────────────────────────────────────────
  if [[ -z "$DC01_MEM" ]]; then
    warn "DC01 memory image not found — skipping."
  else
    mkdir -p "$EVIDENCE_DIR"
    TARGET="$EVIDENCE_DIR/$MEM_IMAGE_NAME"
    [[ -L "$TARGET" ]] && rm "$TARGET"
    ln -s "$(realpath "$DC01_MEM")" "$TARGET"
    ok "Memory → $TARGET"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "Done"
echo

DISK_OK=0; MEM_OK=0
mountpoint -q "$CASES_MOUNT" 2>/dev/null && DISK_OK=1
[[ -f "$EVIDENCE_DIR/$MEM_IMAGE_NAME" ]] && MEM_OK=1

if [[ "$DO_MOUNT" -eq 1 && "$DISK_OK" -eq 1 && "$MEM_OK" -eq 1 ]]; then
  ok "Evidence mounted and ready."
  echo
  printf '\033[1;32m  Run triage with no arguments:\033[0m\n'
  printf '\033[1;37m    /triage\033[0m\n'
  echo
  printf '  Defaults resolve to:\n'
  printf '    disk = %s\n'  "$CASES_MOUNT"
  printf '    mem  = %s\n'  "$EVIDENCE_DIR/$MEM_IMAGE_NAME"
else
  if [[ "$DO_MOUNT" -eq 1 ]]; then
    [[ "$DISK_OK" -eq 0 ]] && warn "Disk not mounted — check errors above."
    [[ "$MEM_OK"  -eq 0 ]] && warn "Memory image missing — check errors above."
  fi
  echo "When evidence is ready, run:"
  echo "  /triage disk=$CASES_MOUNT mem=$EVIDENCE_DIR/$MEM_IMAGE_NAME"
fi

echo
log "Teardown when done:  sudo umount $CASES_MOUNT && sudo umount $EWF_MOUNT"
log "Verify MD5s against: https://dfirmadness.com/the-stolen-szechuan-sauce/"
log "Alt mirror (account required): https://cyberdefenders.org/blueteam-ctf-challenges/szechuan-sauce/"
