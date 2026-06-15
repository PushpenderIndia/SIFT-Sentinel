"""Memory-forensics tools — Volatility 3 over a RAM capture.

Read-only plugins driving the multi-source correlation story:
  mem_pslist   — processes running at capture time
  mem_pstree   — the same, with parent/child linkage (masquerade detection)
  mem_cmdline  — per-process command lines
  mem_netscan  — network connections (the C2 signal)
  mem_malfind  — injected / unbacked RWX regions (fileless malware)
  mem_svcscan  — services live in memory (persistence)

A C2 connection in netscan, traced to a PID whose binary the disk MFT shows was
dropped seconds earlier, is the kind of cross-source CONFIRMED finding the
confidence model rewards.

Every entry point validates the image first: a missing or empty capture returns a
clear *error* rather than a silent empty result that reads like "nothing found".
"""
from __future__ import annotations

from typing import Any, Callable

from ..parsers import (
    parse_vol_cmdline, parse_vol_malfind, parse_vol_netscan, parse_vol_pslist,
    parse_vol_pstree, parse_vol_svcscan, summarize,
)
from .base import ToolContext, ToolResult, audited_run


def _validate_image(ctx: ToolContext, tool: str, memory_image: str):
    """Resolve and sanity-check the image; return (path, error_result_or_None)."""
    mem = ctx.resolve_evidence(memory_image)
    args = {"memory_image": memory_image}
    err = None
    if not mem.exists():
        err = f"memory image not found: {memory_image}"
    elif mem.is_file() and mem.stat().st_size == 0:
        err = f"memory image is empty (0 bytes): {memory_image} — capture likely failed"
    if err:
        call_id, start = ctx.audit.start(tool, args, input_hash=None)
        res = ToolResult(tool=tool, call_id=call_id, records=[],
                         summary=err, error=err)
        ctx.audit.finish(call_id, start, tool, args, input_hash=None,
                         tokens=res.response_tokens(), error=err)
        return str(mem), res
    return str(mem), None


def _run_plugin(ctx: ToolContext, tool: str, memory_image: str, plugin: str,
                parse: Callable[[str], list[dict[str, Any]]], kind: str) -> ToolResult:
    mem, err = _validate_image(ctx, tool, memory_image)
    if err is not None:
        return err
    argv = ["vol", "-q", "-r", "csv", "-f", mem, plugin]
    return audited_run(
        ctx,
        tool=tool,
        args={"memory_image": memory_image},
        evidence_path=mem,
        argv=argv,
        parse=parse,
        summarize_kind=kind,
        summarize=lambda recs, k: summarize(recs, k),
    )


def mem_pslist(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.pslist`` over a RAM capture."""
    return _run_plugin(ctx, "mem_pslist", memory_image, "windows.pslist",
                       parse_vol_pslist, "memory_pslist")


def mem_pstree(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.pstree`` — processes with parent/child linkage."""
    return _run_plugin(ctx, "mem_pstree", memory_image, "windows.pstree",
                       parse_vol_pstree, "memory_pstree")


def mem_cmdline(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.cmdline`` — per-process command lines."""
    return _run_plugin(ctx, "mem_cmdline", memory_image, "windows.cmdline",
                       parse_vol_cmdline, "memory_cmdline")


def mem_netscan(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.netscan`` over a RAM capture."""
    return _run_plugin(ctx, "mem_netscan", memory_image, "windows.netscan",
                       parse_vol_netscan, "memory_netscan")


def mem_malfind(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.malfind`` — injected / unbacked RWX regions."""
    return _run_plugin(ctx, "mem_malfind", memory_image, "windows.malfind",
                       parse_vol_malfind, "memory_malfind")


def mem_svcscan(ctx: ToolContext, memory_image: str) -> ToolResult:
    """Volatility 3 ``windows.svcscan`` — services resident in memory."""
    return _run_plugin(ctx, "mem_svcscan", memory_image, "windows.svcscan",
                       parse_vol_svcscan, "memory_svcscan")
