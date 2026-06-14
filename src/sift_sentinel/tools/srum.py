"""srum — System Resource Usage Monitor (SRUDB.dat) analysis.

Wraps Eric Zimmerman's ``SrumECmd`` over ``SRUDB.dat`` (with the SOFTWARE hive
for app-id resolution). SRUM ties an executable to bytes sent/received over time:
execution evidence *and* a data-exfiltration signal that survives with Prefetch
disabled.
"""
from __future__ import annotations

from typing import Optional

from ..parsers import parse_srum, summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "srum"


def srum(ctx: ToolContext, srudb: str, software_hive: Optional[str] = None) -> ToolResult:
    """Parse ``SRUDB.dat`` into resource-usage records.

    ``software_hive`` (optional) is the SOFTWARE hive SrumECmd uses to resolve
    application ids to names; both must resolve inside the evidence root.
    """
    db = str(ctx.resolve_evidence(srudb))
    extra_argv = ["--csvf", "srum.csv"]
    if software_hive:
        extra_argv = ["-r", str(ctx.resolve_evidence(software_hive)), *extra_argv]
    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"srudb": srudb, "software_hive": software_hive},
        evidence_path=db,
        base_argv=["SrumECmd", "-f", db],
        extra_argv=extra_argv,
        parse=parse_srum,
        cache_family="srum",
        summarize_kind="srum",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
