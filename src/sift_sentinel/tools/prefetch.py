"""analyze_prefetch — evidence of execution from Windows Prefetch (.pf) files.

Wraps PECmd. Returns run-count and last-run records. Corroborates Amcache to
promote an "executed" finding from INFERRED to CONFIRMED.
"""
from __future__ import annotations

from ..evidence import assert_within
from ..parsers import parse_prefetch, summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "analyze_prefetch"


def analyze_prefetch(ctx: ToolContext, prefetch_path: str) -> ToolResult:
    """Parse a Prefetch directory (or single ``.pf``) into execution records."""
    target = str(assert_within(ctx.evidence_root, prefetch_path))
    argv = ["PECmd", "-d", target, "--csv", "/dev/stdout", "--csvf", "stdout"]
    return audited_run(
        ctx,
        tool=TOOL,
        args={"prefetch_path": prefetch_path},
        evidence_path=target if target.endswith(".pf") else None,
        argv=argv,
        parse=parse_prefetch,
        summarize_kind="prefetch",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
