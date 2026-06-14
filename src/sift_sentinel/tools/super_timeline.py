"""super_timeline — one time-ordered view across multiple artifacts.

Runs the requested source tools (reusing the parse cache) and merges their
records into a single chronological timeline via :mod:`correlate`. Each
underlying tool call is independently audited and citable; this tool adds one
more audit record for the merge itself, listing the contributing ``call_id``s in
``extra`` so a merged row still traces back to the tool that produced it.
"""
from __future__ import annotations

from typing import Any, Optional

from ..correlate import build_super_timeline
from ..parsers import summarize
from .base import ToolContext, ToolResult

TOOL = "super_timeline"


def super_timeline(
    ctx: ToolContext,
    *,
    mft_file: Optional[str] = None,
    amcache_hive: Optional[str] = None,
    system_hive: Optional[str] = None,
    security_evtx: Optional[str] = None,
    prefetch_path: Optional[str] = None,
    time_prefix: Optional[str] = None,
) -> ToolResult:
    """Merge the supplied artifacts into a chronological super-timeline.

    Only the artifacts whose paths are given are run. ``time_prefix`` (e.g.
    ``"2018-09-07"``) narrows the merge to an incident window.
    """
    from .amcache import get_amcache
    from .event_logs import parse_event_logs
    from .mft_timeline import extract_mft_timeline
    from .prefetch import analyze_prefetch
    from .shimcache import shimcache

    sources: dict[str, list[dict[str, Any]]] = {}
    contributing: list[str] = []

    def _add(name: str, res: ToolResult) -> None:
        contributing.append(res.call_id)
        if not res.error:
            sources[name] = res.records

    if mft_file:
        _add("mft", extract_mft_timeline(ctx, mft_file))
    if amcache_hive:
        _add("amcache", get_amcache(ctx, amcache_hive))
    if system_hive:
        _add("shimcache", shimcache(ctx, system_hive))
    if security_evtx:
        _add("evtx", parse_event_logs(ctx, security_evtx))
    if prefetch_path:
        _add("prefetch", analyze_prefetch(ctx, prefetch_path))

    rows = build_super_timeline(sources, time_prefix=time_prefix)

    args = {"mft_file": mft_file, "amcache_hive": amcache_hive,
            "system_hive": system_hive, "security_evtx": security_evtx,
            "prefetch_path": prefetch_path, "time_prefix": time_prefix}
    call_id, start = ctx.audit.start(TOOL, args, input_hash=None)
    summary = summarize(rows, "super_timeline")
    ctx.audit.finish(call_id, start, TOOL, args, input_hash=None,
                     binary="super_timeline", exit_code=0, output_summary=summary,
                     contributing_calls=contributing)
    return ToolResult(
        tool=TOOL, call_id=call_id, records=rows, summary=summary,
        extra={"contributing_calls": contributing,
               "sources": sorted(sources.keys()),
               "time_prefix": time_prefix},
    )
