"""Parsed-artifact cache keyed by evidence SHA-256.

The slow part of a triage is not the analysis — it is parsing the same artifact
over and over. During one run a domain controller's ``Security.evtx`` was parsed
*twice* (once per event-id filter, ~350s each) and the ``$MFT`` *three times*
(once per path_filter, ~90s each). Both are the **same bytes** producing the
**same parse**; only the post-filter differs.

This cache stores the *full, unfiltered* parsed record set for an evidence file
under its SHA-256 (which the audit layer already computes for every call). A
second call against the same bytes — a different ``event_id``/``path_filter``, or
simply re-running the whole triage while iterating — skips the subprocess and the
parse entirely and filters the cached records in memory.

Keying on the content hash (not the path) means the cache is correct by
construction: if the evidence changes, the hash changes, and the stale entry is
never read. The cache is read-only with respect to evidence and lives outside the
evidence root, so it does not touch the chain of custody.

Disabled when ``root`` is ``None`` (the default for unit tests, which inject fake
runners); the server enables it by pointing at a writable cache directory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class ParseCache:
    """A tiny content-addressed cache of parsed records on disk.

    Entries are ``<family>-<sha256>.json``. ``family`` namespaces by the kind of
    parse (e.g. ``"mft"``, ``"evtx"``) so the same hive parsed for two purposes
    never collides.
    """

    def __init__(self, root: Optional[str | Path] = None):
        self.root: Optional[Path] = Path(root) if root else None
        if self.root is not None:
            self.root.mkdir(parents=True, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def _path(self, family: str, key: str) -> Path:
        assert self.root is not None
        # key is a hex sha256; family is a short identifier — both filesystem-safe.
        return self.root / f"{family}-{key}.json"

    def get(self, family: str, key: Optional[str]) -> Optional[list[dict[str, Any]]]:
        """Return cached records for ``(family, key)`` or ``None`` on miss."""
        if not self.enabled or not key:
            return None
        p = self._path(family, key)
        if not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None  # corrupt/partial cache entry — treat as a miss
        return data if isinstance(data, list) else None

    def put(self, family: str, key: Optional[str], records: list[dict[str, Any]]) -> None:
        """Store ``records`` for ``(family, key)``. Best-effort; never raises."""
        if not self.enabled or not key:
            return
        tmp = self._path(family, key).with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(records, default=str), encoding="utf-8")
            tmp.replace(self._path(family, key))  # atomic publish
        except OSError:
            pass  # a cache write failure must never break a forensic call
