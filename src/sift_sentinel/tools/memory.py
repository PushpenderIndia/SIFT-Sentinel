"""Memory-forensics tools — Volatility 3 over a RAM capture.

Two read-only plugins that drive the multi-source correlation story:
  mem_pslist  — processes running at capture time
  mem_netscan — network connections (the C2 signal)

A C2 connection in netscan, traced to a PID whose binary the disk MFT shows was
dropped seconds earlier, is the kind of cross-source CONFIRMED finding the
confidence model rewards.
"""
from __future__ import annotations

from ..parsers import parse_vol_netscan, parse_vol_pslist, summarize
from .base import ToolContext, ToolResult, audited_run


def mem_pslist(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.pslist`` over a RAM capture."""
    mem = str(ctx.resolve_evidence(memory_image))
    argv = ["vol", "-q", "-r", "csv", "-f", mem, "windows.pslist"]
    return audited_run(
        ctx,
        tool="mem_pslist",
        args={"memory_image": memory_image},
        evidence_path=mem,
        argv=argv,
        parse=parse_vol_pslist,
        summarize_kind="memory_pslist",
        summarize=lambda recs, kind: summarize(recs, kind),
    )


def mem_netscan(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.netscan`` over a RAM capture."""
    mem = str(ctx.resolve_evidence(memory_image))
    argv = ["vol", "-q", "-r", "csv", "-f", mem, "windows.netscan"]
    return audited_run(
        ctx,
        tool="mem_netscan",
        args={"memory_image": memory_image},
        evidence_path=mem,
        argv=argv,
        parse=parse_vol_netscan,
        summarize_kind="memory_netscan",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
