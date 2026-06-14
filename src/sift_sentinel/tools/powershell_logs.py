"""powershell_logs — script-block / module logging from PowerShell Operational.

Wraps EvtxECmd over ``Microsoft-Windows-PowerShell%4Operational.evtx`` and keeps
only the logging events that carry attacker commands: 4104 (script block) and
4103 (module/pipeline). The decoded ``ScriptBlockText`` is surfaced per record so
hands-on-keyboard PowerShell is readable, not just countable.
"""
from __future__ import annotations

from typing import Optional

from ..parsers import parse_event_logs as _parse_evtx
from ..parsers import summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "powershell_logs"

# Script-block logging (4104) + module logging (4103) are where commands live.
_PS_EVENT_IDS = frozenset({4103, 4104})


def powershell_logs(ctx: ToolContext, evtx_file: str,
                    event_id: Optional[int] = None) -> ToolResult:
    """Parse a PowerShell Operational ``.evtx`` into command-logging records.

    By default returns both 4103 and 4104; pass ``event_id`` to narrow. Shares the
    ``evtx`` parse cache with the other event-log tools.
    """
    evtx = str(ctx.resolve_evidence(evtx_file))

    def _post(records):
        wanted = {event_id} if event_id is not None else _PS_EVENT_IDS
        return [r for r in records if r.get("event_id") in wanted]

    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"evtx_file": evtx_file, "event_id": event_id},
        evidence_path=evtx,
        base_argv=["EvtxECmd", "-f", evtx],
        extra_argv=["--csvf", "evtx.csv"],
        parse=_parse_evtx,
        post=_post,
        cache_family="evtx",
        summarize_kind="powershell",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
