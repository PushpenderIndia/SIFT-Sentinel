"""Known-good hash reputation — suppress signed OS-binary noise.

A real Amcache yields dozens of legitimate Windows binaries (``svchost.exe``,
``conhost.exe``, ...) for every line of interest. Tagging entries whose SHA-1 is
on a known-good list lets the agent (and the response budget) focus on the
anomalies instead of re-triaging the OS every run.

The list is content (hash) based, so it is version-agnostic for the hashes it
contains and never produces a false "known-good" from a path alone — a malware
masquerading as ``svchost.exe`` has a different hash and stays flagged.

Sources, in precedence order:
  1. a newline-delimited SHA-1 file pointed to by ``$SIFT_KNOWN_GOOD`` (e.g. an
     NSRL-derived export), and
  2. a small built-in seed set for offline demos.

This is deliberately *advisory*: entries are annotated (``known_good: true``), not
deleted, so nothing is ever hidden from the audit trail — the caller decides
whether to filter.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

# A tiny seed set (lowercase SHA-1). In production this is dwarfed by the
# $SIFT_KNOWN_GOOD import; it exists so the feature is demonstrable offline.
_BUILTIN_KNOWN_GOOD: frozenset[str] = frozenset({
    # placeholder example hash used by tests / demos
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 of empty input
})


@lru_cache(maxsize=1)
def known_good_hashes() -> frozenset[str]:
    """Load the known-good SHA-1 set once (built-in seed + optional file)."""
    hashes = set(_BUILTIN_KNOWN_GOOD)
    path = os.environ.get("SIFT_KNOWN_GOOD")
    if path:
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                h = line.strip().lower()
                if h and not h.startswith("#"):
                    hashes.add(h)
        except OSError:
            pass
    return frozenset(hashes)


def annotate_known_good(
    records: Iterable[dict[str, Any]],
    *,
    hashes: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Return records with a ``known_good`` flag set from their SHA-1.

    Records without a ``sha1`` are left unflagged (unknown, not good). The input
    is not mutated; new dicts are returned.
    """
    good = hashes if hashes is not None else known_good_hashes()
    out: list[dict[str, Any]] = []
    for r in records:
        sha1 = (r.get("sha1") or "").lower()
        out.append({**r, "known_good": bool(sha1) and sha1 in good})
    return out
