"""parse_event_logs — Windows Event Log (.evtx) triage.

Wraps EvtxECmd. Returns decoded event records (logons 4624/4625, service
installs 7045, PowerShell, etc.). Optional event-id filter narrows re-runs
during self-correction.
"""
from __future__ import annotations

from typing import Optional

from ..evidence import assert_within
from ..parsers import parse_event_logs as _parse_evtx
from ..parsers import summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "parse_event_logs"


def parse_event_logs(ctx: ToolContext, evtx_file: str,
                     event_id: Optional[int] = None) -> ToolResult:
    """Parse an ``.evtx`` file into structured event records.

    ``event_id`` (optional) keeps only matching events — used by the loop to
    zoom in on, e.g., 4624 logons once a suspicious account is identified.
    """
    evtx = str(assert_within(ctx.evidence_root, evtx_file))
    argv = ["EvtxECmd", "-f", evtx, "--csv", "/dev/stdout", "--csvf", "stdout"]

    def _parse(raw: str):
        records = _parse_evtx(raw)
        if event_id is not None:
            records = [r for r in records if r.get("event_id") == event_id]
        return records

    return audited_run(
        ctx,
        tool=TOOL,
        args={"evtx_file": evtx_file, "event_id": event_id},
        evidence_path=evtx,
        argv=argv,
        parse=_parse,
        summarize_kind="evtx",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
