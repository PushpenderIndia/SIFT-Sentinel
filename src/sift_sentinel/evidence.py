"""Evidence integrity — read-only handling and spoliation proof.

This module is the architectural guardrail for criterion #4 (Constraint
Implementation). Two invariants:

  1. Evidence is opened read-only. Disk images are mounted ``ro,noexec,nodev``;
     raw files are never opened in a writable mode.
  2. Evidence files are SHA-256 hashed before and after file-backed tool calls
     and whole-run ``EvidenceSet`` checks. If a hash changes, the run is flagged
     as spoliated.

The agent has no tool that can mount read-write or write into evidence, so these
invariants hold structurally, not by prompt instruction.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_CHUNK = 1024 * 1024  # 1 MiB


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Stream a file through SHA-256. Constant memory regardless of image size."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class EvidenceFile:
    """An evidence artifact tracked for integrity."""

    path: Path
    sha256: str
    size: int

    @classmethod
    def capture(cls, path: str | os.PathLike[str]) -> "EvidenceFile":
        p = Path(path)
        return cls(path=p, sha256=sha256_file(p), size=p.stat().st_size)


class SpoliationError(RuntimeError):
    """Raised when an evidence file's hash changed during a run."""


class EvidenceSet:
    """Tracks a set of evidence files and verifies integrity across a run.

    Usage::

        ev = EvidenceSet([image_path, mem_path])
        ev.snapshot_before()
        ... run the whole agent ...
        ev.verify_after()   # raises SpoliationError if anything changed
    """

    def __init__(self, paths: Iterable[str | os.PathLike[str]]):
        self.paths = [Path(p) for p in paths]
        self._before: dict[Path, EvidenceFile] = {}
        self._after: dict[Path, EvidenceFile] = {}

    def snapshot_before(self) -> dict[Path, EvidenceFile]:
        self._before = {p: EvidenceFile.capture(p) for p in self.paths}
        return self._before

    def verify_after(self) -> dict[Path, EvidenceFile]:
        """Re-hash and compare. Raises :class:`SpoliationError` on any mismatch."""
        if not self._before:
            raise RuntimeError("snapshot_before() must be called first")
        self._after = {p: EvidenceFile.capture(p) for p in self.paths}
        changed = [
            str(p)
            for p in self.paths
            if self._before[p].sha256 != self._after[p].sha256
        ]
        if changed:
            raise SpoliationError(
                "Evidence modified during run (hash mismatch): " + ", ".join(changed)
            )
        return self._after

    def report(self) -> dict[str, dict]:
        """Machine-readable integrity report for the Accuracy Report (deliverable #6)."""
        out: dict[str, dict] = {}
        for p in self.paths:
            before = self._before.get(p)
            after = self._after.get(p)
            out[str(p)] = {
                "sha256_before": before.sha256 if before else None,
                "sha256_after": after.sha256 if after else None,
                "intact": bool(before and after and before.sha256 == after.sha256),
            }
        return out


def assert_within(base: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> Path:
    """Resolve ``candidate`` and assert it lies within ``base``.

    Guards tool arguments against path traversal so a crafted ``path=`` argument
    cannot escape the mounted evidence and read arbitrary host files.
    """
    base_r = Path(base).resolve()
    cand_r = Path(candidate).resolve()
    if base_r != cand_r and base_r not in cand_r.parents:
        raise ValueError(f"path {cand_r} escapes evidence root {base_r}")
    return cand_r


def assert_within_any(
    bases: Iterable[str | os.PathLike[str]],
    candidate: str | os.PathLike[str],
) -> Path:
    """Resolve ``candidate`` and assert it lies within *any* of ``bases``.

    Evidence is not always under a single mount — e.g. the disk image lives at a
    read-only ``/mnt/cases`` while the RAM capture sits at ``/evidence``. This keeps
    the path-traversal guard a tight explicit allowlist (only the configured roots
    are reachable) rather than widening it to the whole filesystem.
    """
    bases_r = [Path(b).resolve() for b in bases]
    if not bases_r:
        raise ValueError("no evidence roots configured")
    cand_r = Path(candidate).resolve()
    for base_r in bases_r:
        if base_r == cand_r or base_r in cand_r.parents:
            return cand_r
    roots = ", ".join(str(b) for b in bases_r)
    raise ValueError(f"path {cand_r} escapes evidence root(s) {roots}")
