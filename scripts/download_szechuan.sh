#!/usr/bin/env bash
#
# download_szechuan.sh — fetch the DFIR Madness "Stolen Szechuan Sauce" (Case 001)
# evidence so SIFT-Sentinel can be run against a PUBLIC dataset with a published
# answer key (https://dfirmadness.com/the-stolen-szechuan-sauce/).
#
# Why this dataset: it ships Windows disk images (E01) + memory captures + a pcap,
# which exercise nearly the entire SIFT-Sentinel toolset, and the answers are
# public (https://dfirmadness.com/answers-to-szechuan-case-001/) so accuracy
# numbers are reproducible by judges.
#
# Integrity: this script does NOT hard-code MD5 values (we don't have the
# authoritative ones). It downloads, then PRINTS each file's MD5 so you can
# compare against the hashes shown on the DFIR Madness page. Pass --checksums
# <file> with lines "<md5>  <filename>" to verify automatically.
#
# Usage:
#   ./scripts/download_szechuan.sh                 # core set (disk+memory+pcap)
#   ./scripts/download_szechuan.sh --full          # + pagefiles, autoruns, protected files
#   ./scripts/download_szechuan.sh --dest /data/szechuan
#   ./scripts/download_szechuan.sh --no-extract    # download zips only
#   ./scripts/download_szechuan.sh --checksums md5s.txt
#   ./scripts/download_szechuan.sh --list          # show files and exit
#
set -euo pipefail

BASE_URL="https://dfirmadness.com/case001"
ANSWERS_URL="https://dfirmadness.com/answers-to-szechuan-case-001/"

# Core artifacts SIFT-Sentinel needs (disk + memory + network).
CORE=(
  "DC01-E01.zip"
  "DC01-memory.zip"
  "DESKTOP-E01.zip"
  "DESKTOP-SDN1RPT-memory.zip"
  "case001-pcap.zip"
)

# Supporting artifacts (only with --full). Note the URL-encoded space.
EXTRA=(
  "DC01-pagefile.zip"
  "DC01-autorunsc.zip"
  "DC01-ProtectedFiles.zip"
  "Desktop-SDN1RPT-pagefile.zip"
  "DESKTOP-SDN1RPT-autorunsc.zip"
  "DESKTOP-SDN1RPT-Protected%20Files.zip"
)

DEST="${SZECHUAN_DEST:-evidence/szechuan_sauce}"
DO_FULL=0
DO_EXTRACT=1
ASSUME_YES=0
CHECKSUMS=""

log()  { printf '\033[1;36m[szechuan]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)       DO_FULL=1; shift ;;
    --dest)       DEST="${2:?--dest needs a path}"; shift 2 ;;
    --no-extract) DO_EXTRACT=0; shift ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    --checksums)  CHECKSUMS="${2:?--checksums needs a file}"; shift 2 ;;
    --list)
      echo "Core:";  printf '  %s\n' "${CORE[@]}"
      echo "Extra (--full):"; printf '  %s\n' "${EXTRA[@]}"
      echo "Base URL: $BASE_URL"
      echo "Answers:  $ANSWERS_URL"
      exit 0 ;;
    -h|--help)
      sed -n '2,40p' "$0"; exit 0 ;;
    *) err "unknown argument: $1"; exit 2 ;;
  esac
done

# Pick a downloader with resume support.
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fL --retry 5 --retry-delay 3 -C - -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -c -t 5 -O "$2" "$1"; }
else
  err "need curl or wget on PATH"; exit 1
fi

# Pick an MD5 tool.
if command -v md5sum >/dev/null 2>&1; then
  md5of() { md5sum "$1" | awk '{print $1}'; }
elif command -v md5 >/dev/null 2>&1; then
  md5of() { md5 -q "$1"; }
else
  md5of() { echo "(no md5 tool)"; }
fi

# url-decode %20 etc. for the local filename.
decode() { printf '%b' "${1//%/\\x}"; }

FILES=("${CORE[@]}")
[[ "$DO_FULL" -eq 1 ]] && FILES+=("${EXTRA[@]}")

mkdir -p "$DEST"
log "destination: $DEST"
log "files to fetch: ${#FILES[@]} ($([[ $DO_FULL -eq 1 ]] && echo 'core + extra' || echo 'core'))"
warn "These are LARGE (disk images are multi-GB). Downloads resume if interrupted."
warn "Dataset © DFIR Madness — attribute to DFIR Madness and its authors. Answers: $ANSWERS_URL"

if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "Proceed with download into '$DEST'? [y/N] " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]] || { log "aborted."; exit 0; }
fi

declare -a GOT=()
for remote in "${FILES[@]}"; do
  local_name="$(decode "$remote")"
  out="$DEST/$local_name"
  url="$BASE_URL/$remote"
  if [[ -s "$out" ]]; then
    log "skip (exists): $local_name"
  else
    log "download: $local_name"
    if ! fetch "$url" "$out.part"; then
      err "failed: $url"; rm -f "$out.part"; continue
    fi
    mv "$out.part" "$out"
  fi
  GOT+=("$out")
  log "  md5($local_name) = $(md5of "$out")"
done

# Optional checksum verification.
if [[ -n "$CHECKSUMS" ]]; then
  log "verifying against $CHECKSUMS"
  fail=0
  while read -r want name; do
    [[ -z "${want:-}" || "$want" == \#* ]] && continue
    f="$DEST/$(decode "$name")"
    [[ -f "$f" ]] || { warn "listed but not downloaded: $name"; continue; }
    have="$(md5of "$f")"
    if [[ "$have" == "$want" ]]; then log "  OK   $name"; else err "  BAD  $name (have $have, want $want)"; fail=1; fi
  done < "$CHECKSUMS"
  [[ "$fail" -eq 0 ]] || { err "checksum verification FAILED"; exit 1; }
fi

# Extract.
if [[ "$DO_EXTRACT" -eq 1 ]]; then
  if command -v unzip >/dev/null 2>&1; then
    for z in "${GOT[@]}"; do
      [[ "$z" == *.zip ]] || continue
      sub="$DEST/extracted/$(basename "${z%.zip}")"
      mkdir -p "$sub"
      log "extract: $(basename "$z") -> $sub"
      unzip -n -q "$z" -d "$sub" || warn "unzip issue on $(basename "$z")"
    done
  else
    warn "unzip not found; leaving .zip files in place (re-run with unzip installed)."
  fi
fi

cat <<EOF

[szechuan] done. Files in: $DEST
Next steps:
  1. Compare the printed MD5s against the hashes on
     https://dfirmadness.com/the-stolen-szechuan-sauce/  (or re-run with --checksums).
  2. Mount the disk images READ-ONLY before pointing SIFT-Sentinel at them, e.g.:
       sudo mkdir -p /mnt/ewf /mnt/cases
       sudo ewfmount $DEST/extracted/DC01-E01/<image>.E01 /mnt/ewf
       sudo mount -t ntfs-3g -o ro,noexec,nodev /mnt/ewf/ewf1 /mnt/cases
     (memory image goes under /evidence/ as usual).
  3. Score findings against the published answers:
       $ANSWERS_URL
EOF
