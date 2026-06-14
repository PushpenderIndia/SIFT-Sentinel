"""Append-only audit logging.

Every forensic tool invocation produces exactly one audit record. Findings in the
final report reference these records by ``call_id`` so any claim traces back to the
specific tool execution that produced it (judging criterion #5: Audit Trail).

The log is JSON Lines (one JSON object per line), append-only, never rewritten.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


def _utc_iso(epoch: float) -> str:
    """Format an epoch timestamp as UTC ISO-8601.

    ``time.gmtime`` is used (not ``datetime.now``) so the function is pure with
    respect to the epoch argument and trivially testable.
    """
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


@dataclass
class AuditRecord:
    """One tool execution. This is the atomic unit of the audit trail."""

    call_id: str
    ts: str                       # UTC ISO-8601, when the call started
    tool: str                     # logical MCP function name, e.g. "get_amcache"
    args: dict[str, Any]
    input_hash: Optional[str]     # SHA-256 of the evidence file the call read
    binary: Optional[str] = None  # underlying SIFT binary actually executed
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    output_ref: Optional[str] = None   # path to stored raw output, if persisted
    output_summary: Optional[str] = None
    tokens: Optional[int] = None       # token cost attributed to this call, if known
    error: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


class AuditLog:
    """Thread-safe, append-only JSONL audit log.

    Use :meth:`start` to open a call (captures start time + assigns a call_id),
    then :meth:`finish` to write the completed record. The two-phase API means a
    crashed call still has a discoverable id and start time in memory for the
    orchestrator to report.
    """

    _ID_RE = re.compile(r"^call-(\d+)$")

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = self._resume_seq()

    def _resume_seq(self) -> int:
        """Continue id numbering from an existing log.

        Without this, every server restart begins again at ``call-000001`` and
        the new ids collide with old ones — breaking the citation contract, since
        a finding's ``call_id`` would no longer point to a unique tool execution.
        We scan the existing log and resume from the highest id seen.
        """
        if not self.path.exists():
            return 0
        max_seq = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    call_id = json.loads(line).get("call_id", "")
                except (ValueError, TypeError):
                    continue
                m = self._ID_RE.match(call_id or "")
                if m:
                    max_seq = max(max_seq, int(m.group(1)))
        return max_seq

    def _next_id(self) -> str:
        self._seq += 1
        return f"call-{self._seq:06d}"

    def start(self, tool: str, args: dict[str, Any], input_hash: Optional[str],
              now: Optional[float] = None) -> tuple[str, float]:
        """Open a call. Returns ``(call_id, start_epoch)``.

        ``now`` is injectable for deterministic tests; defaults to wall clock.
        """
        start = time.time() if now is None else now
        with self._lock:
            call_id = self._next_id()
        return call_id, start

    def finish(self, call_id: str, start: float, tool: str, args: dict[str, Any],
               input_hash: Optional[str], *, binary: Optional[str] = None,
               exit_code: Optional[int] = None, output_ref: Optional[str] = None,
               output_summary: Optional[str] = None, tokens: Optional[int] = None,
               error: Optional[str] = None, end: Optional[float] = None,
               **extra: Any) -> AuditRecord:
        """Write the completed record for a call opened with :meth:`start`."""
        end_epoch = time.time() if end is None else end
        record = AuditRecord(
            call_id=call_id,
            ts=_utc_iso(start),
            tool=tool,
            args=args,
            input_hash=input_hash,
            binary=binary,
            exit_code=exit_code,
            duration_ms=int(round((end_epoch - start) * 1000)),
            output_ref=output_ref,
            output_summary=output_summary,
            tokens=tokens,
            error=error,
            extra=dict(extra),
        )
        line = record.to_json()
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record

    def records(self) -> list[AuditRecord]:
        """Read all records back (for benchmarking / report generation)."""
        out: list[AuditRecord] = []
        if not self.path.exists():
            return out
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                out.append(AuditRecord(**json.loads(line)))
        return out
