"""get_amcache — evidence of program execution/presence from the Amcache hive.

Wraps AmcacheParser. Returns structured execution-evidence records (name, path,
SHA-1, last-write time), never the raw CSV dump.
"""
from __future__ import annotations

from typing import Any

from ..evidence import assert_within
from ..parsers import parse_amcache, summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "get_amcache"


def get_amcache(ctx: ToolContext, amcache_hive: str) -> ToolResult:
    """Parse an Amcache.hve registry hive into execution-evidence records.

    ``amcache_hive`` must resolve inside the evidence root (path-traversal guard).
    """
    hive = str(assert_within(ctx.evidence_root, amcache_hive))
    argv = ["AmcacheParser", "-f", hive, "--csv", "/dev/stdout", "--nl"]
    return audited_run(
        ctx,
        tool=TOOL,
        args={"amcache_hive": amcache_hive},
        evidence_path=hive,
        argv=argv,
        parse=parse_amcache,
        summarize_kind="amcache",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
