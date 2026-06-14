"""logon_summary — aggregate logon activity by actor, not raw rows.

Wraps EvtxECmd over a Security.evtx but, instead of returning thousands of 4624/
4625 rows, returns one record per (account, source IP, logon type) with success/
failure counts and first/last-seen times. This is what makes a brute-force or
password-spray pattern legible — and it shares the ``evtx`` parse cache with
``parse_event_logs`` so it costs nothing extra after the log is parsed once.
"""
from __future__ import annotations

from ..parsers import parse_event_logs as _parse_evtx
from ..parsers import summarize, summarize_logons
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "logon_summary"


def logon_summary(ctx: ToolContext, evtx_file: str) -> ToolResult:
    """Summarise 4624/4625 logons in ``evtx_file`` grouped by actor tuple."""
    evtx = str(ctx.resolve_evidence(evtx_file))
    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"evtx_file": evtx_file},
        evidence_path=evtx,
        base_argv=["EvtxECmd", "-f", evtx],
        extra_argv=["--csvf", "evtx.csv"],
        # Reuse the same cache family as parse_event_logs: the heavy parse is
        # shared, and aggregation is applied as the cheap in-memory post step.
        parse=_parse_evtx,
        post=summarize_logons,
        cache_family="evtx",
        summarize_kind="logon_summary",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
