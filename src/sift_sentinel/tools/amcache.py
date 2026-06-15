"""get_amcache — evidence of program execution/presence from the Amcache hive.

Wraps AmcacheParser. Returns structured execution-evidence records (name, path,
SHA-1, last-write time), never the raw CSV dump.
"""
from __future__ import annotations

from ..parsers import parse_amcache, summarize
from ..reputation import annotate_known_good
from .base import ToolContext, ToolResult, audited_csv_run

TOOL = "get_amcache"


def get_amcache(ctx: ToolContext, amcache_hive: str,
                suppress_known_good: bool = False) -> ToolResult:
    """Parse an Amcache.hve registry hive into execution-evidence records.

    ``amcache_hive`` must resolve inside the evidence root (path-traversal guard).

    AmcacheParser writes several per-category CSVs into the output directory; the
    file-execution evidence lives in ``*FileEntries*.csv`` (Associated +
    Unassociated), which is what we parse.

    Each record is annotated ``known_good`` from its SHA-1 (hash reputation). With
    ``suppress_known_good=True`` the known-good OS binaries are dropped so only the
    anomalies remain; the count of suppressed entries is reported in ``extra``.
    """
    hive = str(ctx.resolve_evidence(amcache_hive))

    def _post(records):
        annotated = annotate_known_good(records)
        if suppress_known_good:
            return [r for r in annotated if not r["known_good"]]
        return annotated

    def _finalize(res):
        good = sum(1 for r in res.records if r.get("known_good"))
        res.extra = {**res.extra, "known_good_count": good,
                     "suppress_known_good": suppress_known_good}
        return res

    return audited_csv_run(
        ctx,
        tool=TOOL,
        args={"amcache_hive": amcache_hive,
              "suppress_known_good": suppress_known_good},
        evidence_path=hive,
        base_argv=["AmcacheParser", "-f", hive],
        extra_argv=["--nl"],
        output_glob="*FileEntries*.csv",
        parse=parse_amcache,
        post=_post,
        # Tally known-good inside the audited boundary so the logged token count
        # reflects the enriched payload the agent actually receives.
        finalize=_finalize,
        cache_family="amcache",
        summarize_kind="amcache",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
