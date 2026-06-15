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


def _payload_value(blob: str, field: str) -> str | None:
    """Pull one EventData field out of an EvtxECmd payload blob, tolerantly.

    EvtxECmd encodes EventData several ways depending on the map/version. We try,
    in order: the JSON ``"@Name":"Field","#text":"value"`` form, a generic
    ``"Field":"value"`` JSON pair, and the ``PayloadData`` ``Field: value`` /
    ``Field=value`` form. Returns ``None`` if the field is absent.
    """
    if not blob:
        return None
    f = re.escape(field)
    for pat in (
        r'"@Name"\s*:\s*"' + f + r'"\s*,\s*"#text"\s*:\s*"([^"]*)"',
        r'"' + f + r'"\s*:\s*"([^"]*)"',
        f + r'\s*[:=]\s*([^\s,;|]+)',
    ):
        m = re.search(pat, blob, re.IGNORECASE)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def parse_shimcache(raw: str) -> list[dict[str, Any]]:
    """Parse AppCompatCacheParser CSV into ShimCache (AppCompatCache) records.

    ShimCache proves a binary was *present* (path + last-modified), and on some
    Windows versions whether it *executed*. It survives when Prefetch is disabled
    (as on a domain controller), making it a key execution-evidence corroborator.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        path = _first(row, "Path", "FilePath")
        if not path:
            continue
        executed = _first(row, "Executed").lower()
        records.append({
            "path": path,
            "last_modified": _first(row, "LastModifiedTimeUTC", "LastModified") or None,
            "position": _to_int(_first(row, "CacheEntryPosition", "Position")),
            "executed": True if executed in ("true", "yes", "1") else (
                False if executed in ("false", "no", "0") else None),
            "source": "shimcache",
        })
    return records


def parse_srum(raw: str) -> list[dict[str, Any]]:
    """Parse SrumECmd CSV (network/app resource usage) into usage records.

    SRUM ties an executable to bytes sent/received over time — execution evidence
    plus a data-exfiltration signal, even with Prefetch off.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        app = _first(row, "ExeInfo", "AppId", "Application", "ExeInfoDescription")
        if not app:
            continue
        records.append({
            "app": app,
            "timestamp": _first(row, "Timestamp", "TimeStamp", "EventTimestamp") or None,
            "user": _first(row, "UserName", "UserId", "Sid") or None,
            "bytes_sent": _to_int(_first(row, "BytesSent", "BytesWritten")),
            "bytes_received": _to_int(_first(row, "BytesReceived", "BytesRead")),
            "source": "srum",
        })
    return records


def parse_event_logs(raw: str) -> list[dict[str, Any]]:
    """Parse EvtxECmd CSV into event records, with security EventData extracted.

    Keeps event id, time, channel, computer and EvtxECmd's decoded map
    description, and — critically for attribution — pulls the actor/target fields
    out of the payload: account, source IP, logon type, workstation, and (for
    7045 service installs) the service name and image path. Without these, logon
    storms and service persistence cannot be attributed.
    """
    # Account fields differ by event: 4624/4625 carry both a Subject (who
    # requested) and Target (who logged on); the Target is the interesting actor.
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        eid = _first(row, "EventId", "EventID")
        if not eid:
            continue
        blob = " ".join(filter(None, [
            _first(row, "Payload"),
            *[_first(row, f"PayloadData{i}") for i in range(1, 7)],
            _first(row, "MapDescription"),
        ]))
        rec: dict[str, Any] = {
            "event_id": _to_int(eid),
            "time": _first(row, "TimeCreated", "TimeGenerated") or None,
            "channel": _first(row, "Channel") or None,
            "computer": _first(row, "Computer") or None,
            "description": _first(row, "MapDescription", "Payload") or None,
            "source": "evtx",
        }
        enriched = {
            "account": _payload_value(blob, "TargetUserName"),
            "subject_account": _payload_value(blob, "SubjectUserName"),
            "ip": _payload_value(blob, "IpAddress"),
            "logon_type": _payload_value(blob, "LogonType"),
            "workstation": _payload_value(blob, "WorkstationName"),
            "service_name": _payload_value(blob, "ServiceName"),
            "image_path": (_payload_value(blob, "ImagePath")
                           or _payload_value(blob, "ServiceFileName")),
            # PowerShell script-block (4104) / module (4103) logging payloads.
            "script_block": _truncate(_payload_value(blob, "ScriptBlockText"), 2000),
        }
        # Only attach fields that were actually present, keeping records compact.
        rec.update({k: v for k, v in enriched.items() if v})
        records.append(rec)
    return records


def summarize_logons(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate 4624/4625 events by (account, source IP, logon type).

    Turns thousands of raw logon rows into one row per distinct actor tuple, with
    success/failure counts and the first/last time seen — the shape that makes a
    password-spray or brute-force pattern obvious at a glance. Sorted by failures
    then successes (the noisiest, most suspicious tuples first).
    """
    groups: dict[tuple, dict[str, Any]] = {}
    for r in records:
        eid = r.get("event_id")
        if eid not in (4624, 4625):
            continue
        key = (r.get("account"), r.get("ip"), r.get("logon_type"))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "account": r.get("account"),
                "ip": r.get("ip"),
                "logon_type": r.get("logon_type"),
                "success": 0,
                "failure": 0,
                "first_seen": None,
                "last_seen": None,
                "source": "logon_summary",
            }
        if eid == 4624:
            g["success"] += 1
        else:
            g["failure"] += 1
        t = r.get("time")
        if t:
            if g["first_seen"] is None or t < g["first_seen"]:
                g["first_seen"] = t
            if g["last_seen"] is None or t > g["last_seen"]:
                g["last_seen"] = t
    return sorted(groups.values(), key=lambda g: (-g["failure"], -g["success"]))


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


def parse_vol_pstree(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.pstree`` CSV into process-tree records.

    Keeps the parent/child linkage so an orphaned or masquerading process (e.g. a
    ``cmd.exe`` whose parent is not ``explorer.exe``) is visible.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        pid = _first(row, "PID")
        name = _first(row, "ImageFileName", "Name")
        if not pid and not name:
            continue
        records.append({
            "pid": _to_int(pid),
            "ppid": _to_int(_first(row, "PPID")),
            "name": name or None,
            "create_time": _first(row, "CreateTime") or None,
            "source": "memory_pstree",
        })
    return records


def parse_vol_cmdline(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.cmdline`` CSV into command-line records."""
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        pid = _first(row, "PID")
        proc = _first(row, "Process", "ImageFileName")
        if not pid and not proc:
            continue
        records.append({
            "pid": _to_int(pid),
            "process": proc or None,
            "args": _first(row, "Args", "CommandLine") or None,
            "source": "memory_cmdline",
        })
    return records


def parse_vol_malfind(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.malfind`` CSV into injected-region records.

    malfind flags memory regions that look like injected/unbacked code (RWX,
    no file backing) — the classic fileless / process-hollowing signal.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        pid = _first(row, "PID")
        if not pid:
            continue
        records.append({
            "pid": _to_int(pid),
            "process": _first(row, "Process", "ImageFileName") or None,
            "address": _first(row, "Start VPN", "Start", "Address") or None,
            "protection": _first(row, "Protection") or None,
            "source": "memory_malfind",
        })
    return records


def parse_vol_svcscan(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 ``windows.svcscan`` CSV into service records.

    Surfaces services live in memory (incl. ones unhooked from the on-disk
    registry view) with their backing binary — persistence corroboration.
    """
    records: list[dict[str, Any]] = []
    for row in _read_csv(raw):
        name = _first(row, "Name", "ServiceName")
        if not name:
            continue
        records.append({
            "pid": _to_int(_first(row, "PID")),
            "name": name,
            "display": _first(row, "Display", "DisplayName") or None,
            "state": _first(row, "State") or None,
            "start": _first(row, "Start") or None,
            "binary": _first(row, "Binary", "BinaryPath", "ImagePath") or None,
            "source": "memory_svcscan",
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


def _truncate(s: str | None, limit: int) -> str | None:
    """Cap a possibly-large payload string so one event can't blow the budget."""
    if not s:
        return None
    return s if len(s) <= limit else s[:limit] + "...[truncated]"


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
        logon_label = None
        if r.get("source") == "logon_summary":
            logon_label = (f"{r.get('account')}@{r.get('ip')} type={r.get('logon_type')} "
                           f"ok={r.get('success')} fail={r.get('failure')}")
        timeline_label = (f"{r.get('time')} [{r.get('source')}] {r.get('label')}"
                          if r.get("label") and r.get("time") else None)
        label = (timeline_label or r.get("path") or r.get("name") or r.get("executable")
                 or yara_label or logon_label or r.get("foreign")
                 or r.get("app")  # srum records use "app" not "name"
                 or (str(r.get("event_id")) if r.get("event_id") else None)
                 or str(r))
        lines.append("  - " + label)
    if len(records) > limit:
        lines.append(f"  ... {len(records) - limit} more (truncated; full data in structured output)")
    return "\n".join(lines)
