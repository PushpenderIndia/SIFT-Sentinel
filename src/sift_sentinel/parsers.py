"""Raw-output parsers — turn massive tool dumps into compact structured JSON.

This is the heart of the IR-accuracy story (criterion #2). The agent never sees
a 50,000-line CSV. The MCP server parses the underlying tool's raw output into a
small list of typed records *before* it reaches the LLM, so context stays clean
and hallucinations from truncated/garbled dumps are avoided.

Parsers are pure functions (raw text -> structured records), so they are unit
testable against captured fixtures without the real SIFT tools installed.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any


def _read_csv(raw: str) -> list[dict[str, str]]:
    """Parse CSV text into a list of row dicts. Tolerant of trailing blank lines.

    Real tool output (AmcacheParser/MFTECmd/EvtxECmd) sometimes emits ragged rows
    with more fields than the header. ``csv.DictReader`` collects the overflow into
    a list under the ``None`` restkey, so values are not always strings — coerce
    defensively and drop the unnamed restkey column rather than crashing on it.
    """
    if not raw.strip():
        return []
    reader = csv.DictReader(io.StringIO(raw))
    rows: list[dict[str, str]] = []
    for row in reader:
        clean: dict[str, str] = {}
        for k, v in row.items():
            if k is None:  # overflow columns from a ragged row
                continue
            if isinstance(v, list):  # restkey leaked into a named column
                v = ",".join(x for x in v if x)
            clean[(k or "").strip()] = (v or "").strip()
        rows.append(clean)
    return rows


def _first(row: dict[str, str], *names: str) -> str:
    """Return the first present, non-empty column among ``names`` (case-insensitive)."""
    lower = {k.lower(): v for k, v in row.items()}
    for n in names:
        v = lower.get(n.lower(), "")
        if v:
            return v
    return ""


def parse_amcache(raw: str) -> list[dict[str, Any]]:
    """Parse AmcacheParser CSV (Associated file entries) into execution-evidence records.

    Output records: program name, full path, SHA-1 of the binary, and the file
    key last-modified time (a strong "this executed / was present" signal).
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        path = _first(row, "FullPath", "Path")
        if not path:
            continue
        records.append({
            "name": _first(row, "Name", "ApplicationName") or path.rsplit("\\", 1)[-1],
            "path": path,
            "sha1": _first(row, "SHA1", "Sha1").lower() or None,
            "file_key_last_write": _first(row, "FileKeyLastWriteTimestamp",
                                          "LastWriteTimestamp", "FileKeyLastWrite") or None,
            "source": "amcache",
        })
    return records


def parse_mft_timeline(raw: str) -> list[dict[str, Any]]:
    """Parse MFTECmd CSV into timeline records.

    Keeps the standard-information timestamps (created/modified) and the path.
    Entries flagged ``InUse=False`` are surfaced as ``deleted`` — often where the
    interesting evidence lives.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        path = _first(row, "ParentPath")
        name = _first(row, "FileName", "Name")
        full = (path + "\\" + name).replace("\\\\", "\\") if path else name
        if not full:
            continue
        in_use = _first(row, "InUse").lower()
        records.append({
            "path": full,
            "created": _first(row, "Created0x10", "CreatedOn", "Created") or None,
            "modified": _first(row, "LastModified0x10", "LastModifiedOn", "Modified") or None,
            "size": _to_int(_first(row, "FileSize", "Size")),
            "deleted": in_use in ("false", "0", "no"),
            "source": "mft",
        })
    return records


# Executable / scriptable extensions — the file types that *run*.
_EXEC_EXTS = frozenset({
    "exe", "dll", "sys", "com", "scr", "pif", "cpl", "msi",
    "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk",
})

# Directory substrings a user can write to / where droppers stage payloads.
# A signed binary in System32 is noise; the same verb in one of these is signal.
_SUSPICIOUS_DIRS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\",
    "\\users\\public\\", "\\perflogs\\", "$recycle.bin", "\\windows\\temp\\",
)

# A masquerading double extension, e.g. invoice.pdf.exe or photo.jpg.scr.
_DOUBLE_EXT = re.compile(r"\.[a-z0-9]{1,5}\.(exe|scr|com|pif|bat|cmd|js|vbs|hta|ps1|lnk)$")


def _mft_interesting(rec: dict[str, Any]) -> bool:
    """Forensic-triage predicate: is this MFT record worth a human's attention?

    Flags executables/scripts dropped in user-writable locations, masquerading
    double extensions, NTFS alternate data streams, and deleted executables — the
    signal we want surfaced out of a 200k-record timeline, not the first 1,000
    filesystem-metadata rows.
    """
    low = (rec.get("path") or "").lower()
    if not low:
        return False
    name = low.rsplit("\\", 1)[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    exec_ext = ext in _EXEC_EXTS
    if exec_ext and any(d in low for d in _SUSPICIOUS_DIRS):
        return True
    if _DOUBLE_EXT.search(name):
        return True
    if ":" in name:  # alternate data stream (drive letter colon is before any "\")
        return True
    if rec.get("deleted") and exec_ext:
        return True
    return False


def mft_digest(records: list[dict[str, Any]], limit: int = 100) -> dict[str, Any]:
    """Condense a full MFT timeline into a triage digest the LLM can actually use.

    Returns the true total, a deleted count, a created-time histogram by month, and
    a curated list of the forensically-interesting records (capped at ``limit``).
    This is what makes ``extract_mft_timeline`` robust on a real $MFT: the agent
    gets the needles, not a truncated haystack of ``$LogFile``/metadata rows.
    """
    interesting = [r for r in records if _mft_interesting(r)]
    hist: dict[str, int] = {}
    for r in records:
        created = r.get("created") or ""
        bucket = created[:7] if len(created) >= 7 else "unknown"
        hist[bucket] = hist.get(bucket, 0) + 1
    return {
        "total": len(records),
        "deleted": sum(1 for r in records if r.get("deleted")),
        "interesting_count": len(interesting),
        "created_by_month": dict(sorted(hist.items())),
        "interesting": interesting[:limit],
    }


def parse_regripper(raw: str) -> list[dict[str, Any]]:
    """Parse RegRipper (``rip.pl``) plugin text into persistence/autostart records.

    RegRipper plugins emit free text, not CSV. This tolerant parser tracks the
    current registry key and its LastWrite time, then emits one record per
    ``name - value`` (or ``name -> value``) autostart entry beneath it.
    """
    records: list[dict[str, Any]] = []
    cur_key: str | None = None
    cur_lw: str | None = None
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("launching ") or s.startswith("---"):
            continue
        if "lastwrite" in s.lower() and "time" in s.lower():
            cur_lw = s.split("Time", 1)[-1].strip() or None
            continue
        sep = " -> " if " -> " in s else (" - " if " - " in s else None)
        if sep is None and "\\" in s and not s.startswith("("):
            # A bare registry key path (e.g. Software\Microsoft\...\Run).
            cur_key = s
            continue
        if sep:
            name, _, value = s.partition(sep)
            records.append({
                "key": cur_key,
                "last_write": cur_lw,
                "name": name.strip(),
                "value": value.strip(),
                "source": "registry",
            })
    return records


def parse_yara(raw: str) -> list[dict[str, Any]]:
    """Parse default YARA stdout (``<rule> <path>`` per match) into hit records.

    Lines without a filesystem path (e.g. ``-s`` string-detail lines) are skipped,
    so the same parser tolerates verbose output without emitting junk records.
    """
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        rule, _, target = s.partition(" ")
        target = target.strip()
        if not target or ("/" not in target and "\\" not in target):
            continue
        records.append({"rule": rule, "target": target, "source": "yara"})
    return records


def parse_sccainfo(raw: str) -> list[dict[str, Any]]:
    """Parse sccainfo (libscca-tools) text output into execution records.

    sccainfo is the Linux-native apt replacement for PECmd. Parses one .pf file
    at a time; analyze_prefetch calls it per file and aggregates the results.
    """
    record: dict[str, Any] = {"source": "prefetch"}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Executable filename:"):
            record["executable"] = line.split(":", 1)[1].strip()
        elif line.startswith("Last run time:"):
            val = line.split(":", 1)[1].strip()
            record["last_run"] = val.split(".")[0] if val and val != "N/A" else None
        elif line.startswith("Run count:"):
            record["run_count"] = _to_int(line.split(":", 1)[1].strip())
        elif line.startswith("Filename:"):
            record["pf_file"] = line.split(":", 1)[1].strip()
    return [record] if record.get("executable") else []


def parse_prefetch(raw: str) -> list[dict[str, Any]]:
    """Parse PECmd CSV into execution records (kept for fixture-based tests)."""
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        exe = _first(row, "ExecutableName", "SourceFilename")
        if not exe:
            continue
        records.append({
            "executable": exe,
            "run_count": _to_int(_first(row, "RunCount")),
            "last_run": _first(row, "LastRun", "LastRunTime") or None,
            "source": "prefetch",
        })
    return records


def parse_event_logs(raw: str) -> list[dict[str, Any]]:
    """Parse EvtxECmd CSV into event records.

    Keeps the security-relevant fields: event id, time, channel, and the human
    map description (EvtxECmd's decoded summary, e.g. "Logon" for 4624).
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        eid = _first(row, "EventId", "EventID")
        if not eid:
            continue
        records.append({
            "event_id": _to_int(eid),
            "time": _first(row, "TimeCreated", "TimeGenerated") or None,
            "channel": _first(row, "Channel") or None,
            "computer": _first(row, "Computer") or None,
            "description": _first(row, "MapDescription", "Payload") or None,
            "source": "evtx",
        })
    return records


def parse_vol_pslist(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.pslist`` CSV (``-r csv``) into process records."""
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        name = _first(row, "ImageFileName", "Name")
        pid = _first(row, "PID")
        if not name and not pid:
            continue
        records.append({
            "pid": _to_int(pid),
            "ppid": _to_int(_first(row, "PPID")),
            "name": name or None,
            "create_time": _first(row, "CreateTime") or None,
            "source": "memory_pslist",
        })
    return records


def parse_vol_netscan(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.netscan`` CSV into network-connection records.

    Foreign address + owning PID is the C2 signal we correlate against disk.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        foreign = _first(row, "ForeignAddr", "ForeignAddress")
        pid = _first(row, "PID", "Owner")
        if not foreign and not pid:
            continue
        records.append({
            "proto": _first(row, "Proto", "Protocol") or None,
            "local": _first(row, "LocalAddr", "LocalAddress") or None,
            "foreign": foreign or None,
            "foreign_port": _to_int(_first(row, "ForeignPort")),
            "state": _first(row, "State") or None,
            "pid": _to_int(pid),
            "owner": _first(row, "Owner") or None,
            "source": "memory_netscan",
        })
    return records


def _to_int(s: str) -> int | None:
    try:
        return int(s.replace(",", "")) if s else None
    except ValueError:
        return None


def summarize(records: list[dict[str, Any]], kind: str, limit: int = 20) -> str:
    """One-line-per-record human summary, capped at ``limit`` with an overflow note.

    Used for the audit log's ``output_summary`` and for any place we must show a
    bounded preview instead of the full structured payload.
    """
    head = records[:limit]
    lines = [f"{kind}: {len(records)} record(s)"]
    for r in head:
        yara_label = f"{r.get('rule')} -> {r.get('target')}" if r.get("rule") else None
        label = (r.get("path") or r.get("name") or r.get("executable")
                 or yara_label or r.get("foreign")
                 or (str(r.get("event_id")) if r.get("event_id") else None)
                 or str(r))
        lines.append("  - " + label)
    if len(records) > limit:
        lines.append(f"  ... {len(records) - limit} more (truncated; full data in structured output)")
    return "\n".join(lines)
