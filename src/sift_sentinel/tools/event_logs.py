"""parse_event_logs — Windows Event Log (.evtx) triage.

Wraps EvtxECmd. Returns decoded event records (logons 4624/4625, service
installs 7045, PowerShell, etc.). Optional event-id filter narrows re-runs
during self-correction.
"""
from __future__ import annotations

from typing import Optional

from ..parsers import parse_event_logs as _parse_evtx
from ..parsers import summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "parse_event_logs"


def parse_event_logs(ctx: ToolContext, evtx_file: str,
                     event_id: Optional[int] = None) -> ToolResult:
    """Parse an ``.evtx`` file into structured event records.

    ``event_id`` (optional) keeps only matching events — used by the loop to
    zoom in on, e.g., 4624 logons once a suspicious account is identified.
    """
    evtx = str(ctx.resolve_evidence(evtx_file))

    def _post(records):
        if event_id is None:
            return records
        return [r for r in records if r.get("event_id") == event_id]

    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"evtx_file": evtx_file, "event_id": event_id},
        evidence_path=evtx,
        base_argv=["EvtxECmd", "-f", evtx],
        extra_argv=["--csvf", "evtx.csv"],
        # Parse the whole .evtx once and cache it; querying a second event_id
        # against the same Security.evtx (e.g. 4624 then 4625) is then ~free.
        parse=_parse_evtx,
        post=_post,
        cache_family="evtx",
        summarize_kind="evtx",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
