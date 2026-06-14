"""extract_mft_timeline — filesystem timeline from the NTFS $MFT.

Wraps MFTECmd. Returns structured timeline records (path, created, modified,
size, deleted-flag), never the raw CSV. Optionally filters to a path substring
so the agent can re-run narrowly during self-correction.
"""
from __future__ import annotations

from typing import Optional

from ..evidence import assert_within
from ..parsers import parse_mft_timeline, summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "extract_mft_timeline"


def extract_mft_timeline(ctx: ToolContext, mft_file: str,
                         path_filter: Optional[str] = None) -> ToolResult:
    """Parse a ``$MFT`` into timeline records.

    ``path_filter`` (optional, case-insensitive substring) narrows results — used
    by the self-correction loop to zoom in on a suspicious directory without
    re-dumping the whole timeline.
    """
    mft = str(assert_within(ctx.evidence_root, mft_file))
    argv = ["MFTECmd", "-f", mft, "--csv", "/dev/stdout", "--csvf", "stdout"]

    def _parse(raw: str):
        records = parse_mft_timeline(raw)
        if path_filter:
            needle = path_filter.lower()
            records = [r for r in records if needle in (r.get("path") or "").lower()]
        return records

    return audited_run(
        ctx,
        tool=TOOL,
        args={"mft_file": mft_file, "path_filter": path_filter},
        evidence_path=mft,
        argv=argv,
        parse=_parse,
        summarize_kind="mft",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
