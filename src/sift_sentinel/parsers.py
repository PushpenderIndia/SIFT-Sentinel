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
from typing import Any


def _read_csv(raw: str) -> list[dict[str, str]]:
    """Parse CSV text into a list of row dicts. Tolerant of trailing blank lines."""
    if not raw.strip():
        return []
    reader = csv.DictReader(io.StringIO(raw))
    return [ {(k or "").strip(): (v or "").strip() for k, v in row.items()}
             for row in reader ]


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


def parse_prefetch(raw: str) -> list[dict[str, Any]]:
    """Parse PECmd CSV into execution records (run count + last-run time).

    Prefetch is strong evidence a program *ran* (vs Amcache, which is presence).
    """
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
        label = (r.get("path") or r.get("name") or r.get("executable")
                 or r.get("foreign") or (str(r.get("event_id")) if r.get("event_id") else None)
                 or str(r))
        lines.append("  - " + label)
    if len(records) > limit:
        lines.append(f"  ... {len(records) - limit} more (truncated; full data in structured output)")
    return "\n".join(lines)
