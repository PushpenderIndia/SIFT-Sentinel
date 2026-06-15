"""extract_mft_timeline — filesystem timeline from the NTFS $MFT.

Wraps MFTECmd. Returns structured timeline records (path, created, modified,
size, deleted-flag), never the raw CSV. Optionally filters to a path substring
so the agent can re-run narrowly during self-correction.
"""
from __future__ import annotations

import os
from typing import Optional

from ..parsers import mft_digest, parse_mft_timeline, summarize
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "extract_mft_timeline"

# Above this many records, an unfiltered timeline is digested rather than dumped:
# the agent gets the curated "interesting" set + stats, and is told to use
# path_filter to enumerate a specific directory in full. Override with
# SIFT_MFT_DIGEST_THRESHOLD.
DIGEST_THRESHOLD = int(os.environ.get("SIFT_MFT_DIGEST_THRESHOLD", "500"))


def extract_mft_timeline(ctx: ToolContext, mft_file: str,
                         path_filter: Optional[str] = None) -> ToolResult:
    """Parse a ``$MFT`` into timeline records.

    ``path_filter`` (optional, case-insensitive substring) narrows results — used
    by the self-correction loop to zoom in on a suspicious directory without
    re-dumping the whole timeline.
    """
    mft = str(ctx.resolve_evidence(mft_file))

    def _post(records):
        if not path_filter:
            return records
        needle = path_filter.lower()
        return [r for r in records if needle in (r.get("path") or "").lower()]

    def _finalize(res):
        # A narrow (filtered) or small timeline is returned verbatim. An unfiltered
        # full $MFT (200k+ rows) is condensed to a triage digest so the agent gets
        # the forensically-interesting records instead of a head-of-list dump of
        # metadata files. Done inside the audited boundary so the logged token
        # count reflects the digest the agent actually receives; the audit's
        # output_summary still records the complete pre-digest summary.
        if path_filter or len(res.records) <= DIGEST_THRESHOLD:
            return res
        digest = mft_digest(res.records)
        res.extra = {
            "mode": "digest",
            "total": digest["total"],
            "deleted": digest["deleted"],
            "interesting_count": digest["interesting_count"],
            "created_by_month": digest["created_by_month"],
            "note": (
                "Unfiltered timeline digested: 'records' holds the forensically-"
                "interesting entries (executables in user-writable paths, deleted "
                "executables, ADS, double extensions). Re-run with path_filter to "
                "enumerate a specific directory in full."
            ),
        }
        res.records = digest["interesting"]
        res.summary = summarize(res.records, "mft-digest")
        return res

    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"mft_file": mft_file, "path_filter": path_filter},
        evidence_path=mft,
        base_argv=["MFTECmd", "-f", mft],
        extra_argv=["--csvf", "mft.csv"],
        # Parse the whole $MFT once (the 90s cost) and cache it under the file
        # hash; path_filter is applied to the cached records on every re-run.
        parse=parse_mft_timeline,
        post=_post,
        finalize=_finalize,
        cache_family="mft",
        summarize_kind="mft",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
