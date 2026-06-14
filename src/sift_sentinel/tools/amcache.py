"""get_amcache — evidence of program execution/presence from the Amcache hive.

Wraps AmcacheParser. Returns structured execution-evidence records (name, path,
SHA-1, last-write time), never the raw CSV dump.
"""
from __future__ import annotations

from typing import Any

from ..parsers import parse_amcache, summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "get_amcache"


def get_amcache(ctx: ToolContext, amcache_hive: str) -> ToolResult:
    """Parse an Amcache.hve registry hive into execution-evidence records.

    ``amcache_hive`` must resolve inside the evidence root (path-traversal guard).

    AmcacheParser writes several per-category CSVs into the output directory; the
    file-execution evidence lives in ``*FileEntries*.csv`` (Associated +
    Unassociated), which is what we parse.
    """
    hive = str(ctx.resolve_evidence(amcache_hive))
    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"amcache_hive": amcache_hive},
        evidence_path=hive,
        base_argv=["AmcacheParser", "-f", hive],
        extra_argv=["--nl"],
        output_glob="*FileEntries*.csv",
        parse=parse_amcache,
        summarize_kind="amcache",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
