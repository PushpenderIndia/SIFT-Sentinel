"""shimcache — AppCompatCache (ShimCache) execution/presence evidence.

Wraps Eric Zimmerman's ``AppCompatCacheParser`` over a SYSTEM hive. ShimCache is
critical when Prefetch is disabled (Windows Server / domain controllers): it still
records the path and last-modified time of binaries the OS saw, and on some
versions whether they executed.
"""
from __future__ import annotations

from ..parsers import parse_shimcache, summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "shimcache"


def shimcache(ctx: ToolContext, system_hive: str) -> ToolResult:
    """Parse a SYSTEM hive's AppCompatCache into presence/execution records."""
    hive = str(ctx.resolve_evidence(system_hive))
    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"system_hive": system_hive},
        evidence_path=hive,
        base_argv=["AppCompatCacheParser", "-f", hive],
        extra_argv=["--csvf", "shimcache.csv"],
        parse=parse_shimcache,
        cache_family="shimcache",
        summarize_kind="shimcache",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
