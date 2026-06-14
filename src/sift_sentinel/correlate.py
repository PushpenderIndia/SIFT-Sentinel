"""Super-timeline — merge records from many artifacts into one ordered view.

Cross-source correlation is where INFERRED findings become CONFIRMED: a binary
that appears in Amcache *and* ShimCache *and* an MFT create within the same
minute is execution evidence three ways. Doing that by eye across separate tool
outputs is error-prone; this module normalises each artifact's records to a
common ``(time, source, label, detail)`` shape and sorts them into a single
timeline.

Pure functions only — no evidence access, no subprocess — so it is trivially
testable and adds nothing to the trust boundary.
"""
from __future__ import annotations

from typing import Any

# Per-source preference order for which field carries the event time.
_TIME_FIELDS = {
    "mft": ("created", "modified"),
    "amcache": ("file_key_last_write",),
    "shimcache": ("last_modified",),
    "evtx": ("time",),
    "logon_summary": ("last_seen", "first_seen"),
    "prefetch": ("last_run",),
    "srum": ("timestamp",),
    "registry": ("last_write",),
    "memory_pslist": ("create_time",),
    "memory_pstree": ("create_time",),
}


def _record_time(rec: dict[str, Any]) -> str | None:
    src = rec.get("source") or ""
    for f in _TIME_FIELDS.get(src, ("time", "timestamp", "created")):
        v = rec.get(f)
        if v:
            return str(v)
    return None


def _label(rec: dict[str, Any]) -> str:
    """A short human label for a merged row, source-appropriate."""
    if rec.get("source") == "logon_summary":
        return (f"{rec.get('account')}@{rec.get('ip')} "
                f"ok={rec.get('success')} fail={rec.get('failure')}")
    return str(
        rec.get("path") or rec.get("name") or rec.get("executable")
        or rec.get("app") or rec.get("foreign")
        or (f"event {rec.get('event_id')}" if rec.get("event_id") else None)
        or rec.get("rule") or "?"
    )


def build_super_timeline(
    sources: dict[str, list[dict[str, Any]]],
    *,
    time_prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Merge ``{source_name: records}`` into one time-ordered list.

    Each output row is ``{time, source, label, detail}`` where ``detail`` is the
    original record. Rows without a usable timestamp are dropped (they cannot be
    placed on a timeline). ``time_prefix`` keeps only rows whose timestamp starts
    with it (e.g. ``"2018-09-07"`` to focus an incident window).
    """
    rows: list[dict[str, Any]] = []
    for name, records in sources.items():
        for rec in records:
            t = _record_time(rec)
            if not t:
                continue
            if time_prefix and not t.startswith(time_prefix):
                continue
            rows.append({
                "time": t,
                "source": rec.get("source") or name,
                "label": _label(rec),
                "detail": rec,
            })
    rows.sort(key=lambda r: r["time"])
    return rows
