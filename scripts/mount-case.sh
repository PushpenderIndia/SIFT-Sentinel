#!/usr/bin/env bash
# mount-case.sh — attach an E01 disk image (and optionally a memory image) as a
# named case under /mnt/cases/<name>/ so the sift-sentinel agent can triage it
# immediately with:  /triage disk=/mnt/cases/<name> mem=/mnt/cases/<name>/memory.img
#
# Usage:
#   sudo ./mount-case.sh <case-name> <path-to.E01> [path-to-memory-image]
#
# Examples:
#   sudo ./mount-case.sh base-dc /mnt/Findevil/base-dc-cdrive.E01 /evidence/base-dc-memory.img
#   sudo ./mount-case.sh laptop01 /mnt/Findevil/laptop01.E01
#
# Teardown (when done with a case):
#   sudo ./mount-case.sh --umount <case-name>

set -euo pipefail

CASES_BASE="/mnt/cases"
EWF_BASE="/mnt/ewf_mount"

usage() {
    echo "Usage: sudo $0 <case-name> <path-to.E01> [memory-image]"
    echo "       sudo $0 --umount <case-name>"
    exit 1
}

umount_case() {
    local name="$1"
    local case_dir="$CASES_BASE/$name"
    local ewf_dir="$EWF_BASE/$name"

    echo "[*] Unmounting case: $name"
    if mountpoint -q "$case_dir" 2>/dev/null; then
        umount -l "$case_dir" && echo "    [ok] unmounted $case_dir"
    fi
    if mountpoint -q "$ewf_dir" 2>/dev/null; then
        umount -l "$ewf_dir" && echo "    [ok] unmounted $ewf_dir"
    fi
    # remove the symlinked memory image if present
    local mem_link="$case_dir.mem.img"
    [ -L "$mem_link" ] && rm "$mem_link" && echo "    [ok] removed $mem_link"
    echo "[+] Done."
}

mount_case() {
    local name="$1"
    local e01="$2"
    local mem="${3:-}"

    local case_dir="$CASES_BASE/$name"
    local ewf_dir="$EWF_BASE/$name"

    # Validate inputs
    [ -f "$e01" ] || { echo "[!] E01 not found: $e01"; exit 1; }

    echo "[*] Mounting case '$name'"
    echo "    E01  : $e01"
    [ -n "$mem" ] && echo "    Memory: $mem"

    # Create mount dirs
    mkdir -p "$ewf_dir" "$case_dir"

    # Clear any stale mounts on these directories
    mountpoint -q "$case_dir" && { echo "    [!] $case_dir already mounted — unmounting stale"; umount -l "$case_dir"; }
    mountpoint -q "$ewf_dir"  && { echo "    [!] $ewf_dir  already mounted — unmounting stale"; umount -l "$ewf_dir"; }

    # Mount EWF
    ewfmount "$e01" "$ewf_dir"
    echo "    [ok] ewfmount → $ewf_dir"

    # Detect partition (ewf1 is the raw image)
    local ewf1="$ewf_dir/ewf1"
    [ -f "$ewf1" ] || { echo "[!] $ewf1 not found — EWF mount may have failed"; exit 1; }

    # Find the first NTFS/Windows partition offset via mmls
    local offset
    offset=$(mmls "$ewf1" 2>/dev/null | awk '/NTFS|Basic data|[Ww]in/{print $3; exit}')
    if [ -z "$offset" ]; then
        # Fall back: try mounting directly (single-partition image)
        mount -o ro,loop,noexec,noatime "$ewf1" "$case_dir"
    else
        local sector_size
        sector_size=$(mmls "$ewf1" 2>/dev/null | awk '/^Units/{gsub(/[^0-9]/,"",$NF); print $NF}')
        sector_size=${sector_size:-512}
        local byte_offset=$(( offset * sector_size ))
        mount -o ro,loop,noexec,noatime,offset="$byte_offset" "$ewf1" "$case_dir"
    fi
    echo "    [ok] partition → $case_dir (read-only)"

    # Symlink memory image into the case directory so it's inside the evidence root
    if [ -n "$mem" ]; then
        [ -f "$mem" ] || { echo "    [!] memory image not found: $mem — skipping"; }
        local mem_link="$case_dir/memory.img"
        [ -L "$mem_link" ] && rm "$mem_link"
        ln -s "$mem" "$mem_link"
        echo "    [ok] memory → $mem_link → $mem"
    fi

    echo ""
    echo "[+] Case '$name' ready. Run triage with:"
    if [ -n "$mem" ]; then
        echo "    /triage disk=/mnt/cases/$name mem=/mnt/cases/$name/memory.img"
    else
        echo "    /triage disk=/mnt/cases/$name"
    fi
}

# --- main ---
[ $# -lt 1 ] && usage

if [ "$1" = "--umount" ]; then
    [ $# -lt 2 ] && usage
    umount_case "$2"
else
    [ $# -lt 2 ] && usage
    mount_case "$1" "$2" "${3:-}"
fi
