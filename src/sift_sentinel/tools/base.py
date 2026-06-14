"""Shared plumbing for forensic tools: context, result type, audited execution."""
from __future__ import annotations

import glob
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from ..audit import AuditLog
from ..evidence import assert_within_any, sha256_file
from ..runner import RunResult, run_tool


# A runner is anything that takes argv -> RunResult. Injectable for tests.
RunnerFn = Callable[[Sequence[str]], RunResult]

# Cap on how many records are serialized into a single MCP response. A full $MFT
# yields ~200k+ records (~60 MB of JSON), which exceeds what the stdio transport
# will carry and tears down the connection. We return the true total count plus a
# truncation flag so the agent re-runs narrowly (e.g. with ``path_filter``).
# Override with SIFT_MAX_RECORDS; 0 disables the cap.
MAX_RESPONSE_RECORDS = int(os.environ.get("SIFT_MAX_RECORDS", "1000"))

# Hard byte budget for the serialized ``records`` array. The row cap above is not
# enough on its own: 1,000 *wide* records (e.g. MFT rows with full paths and
# sub-second timestamps) still serialize to ~250 KB, which overruns the transport
# /context window and gets spilled to a temp file — exactly the "50k-line dump"
# the design promises to avoid. This is the final, tool-agnostic safety net: no
# response's record payload exceeds it, regardless of row count or width.
# Override with SIFT_MAX_BYTES; 0 disables the byte budget.
MAX_RESPONSE_BYTES = int(os.environ.get("SIFT_MAX_BYTES", "60000"))


def _fit_to_budget(records: list[dict[str, Any]], budget: int) -> list[dict[str, Any]]:
    """Return the longest prefix of ``records`` whose JSON stays under ``budget``.

    Estimates per-record size from the current serialization to pick a candidate
    length in one shot, then trims one-by-one to settle exactly under budget. Keeps
    at least one record so the agent always sees a concrete example.
    """
    if not budget or not records:
        return records
    blob = json.dumps(records, default=str)
    if len(blob) <= budget:
        return records
    per = max(1, len(blob) // len(records))
    keep = max(1, min(len(records) - 1, budget // per))
    candidate = records[:keep]
    while len(candidate) > 1 and len(json.dumps(candidate, default=str)) > budget:
        candidate = candidate[: len(candidate) - 1]
    return candidate


@dataclass
class ToolContext:
    """Carried into every tool call: where evidence lives and where to audit."""

    evidence_root: Path
    audit: AuditLog
    runner: RunnerFn = run_tool
    output_dir: Optional[Path] = None  # where raw outputs are persisted, if any
    # Additional allowed roots (e.g. a RAM capture mounted outside the disk root).
    # The path-traversal guard accepts any of these, never the wider filesystem.
    extra_roots: tuple[Path, ...] = ()

    def resolve_evidence(self, candidate: str) -> Path:
        """Resolve a tool-supplied path within the configured evidence root(s)."""
        return assert_within_any((self.evidence_root, *self.extra_roots), candidate)


@dataclass
class ToolResult:
    """Structured result returned to the agent. ``call_id`` ties it to the audit log."""

    tool: str
    call_id: str
    records: list[dict[str, Any]]
    summary: str
    input_hash: Optional[str] = None
    error: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total = len(self.records)
        cap = MAX_RESPONSE_RECORDS
        records = self.records[:cap] if cap else list(self.records)
        # Final safety net: enforce the byte budget even when the row cap passed.
        records = _fit_to_budget(records, MAX_RESPONSE_BYTES)
        truncated = len(records) < total
        extra = dict(self.extra)
        if truncated:
            extra["records_truncated"] = True
            extra["records_returned"] = len(records)
            extra["note"] = (
                f"Response truncated to {len(records)} of {total} records to stay "
                "within transport limits. Re-run with a narrower filter "
                "(e.g. path_filter / event_id) to inspect the rest."
            )
        return {
            "tool": self.tool,
            "call_id": self.call_id,
            "input_hash": self.input_hash,
            "record_count": total,
            "summary": self.summary,
            "records": records,
            "error": self.error,
            **({"extra": extra} if extra else {}),
        }


def audited_run(
    ctx: ToolContext,
    *,
    tool: str,
    args: dict[str, Any],
    evidence_path: Optional[str],
    argv: Sequence[str],
    parse: Callable[[str], list[dict[str, Any]]],
    summarize_kind: str,
    summarize: Callable[[list[dict[str, Any]], str], str],
) -> ToolResult:
    """Run an allowlisted binary, parse its output, and write one audit record.

    This single helper guarantees every tool call is logged with timing, the
    input evidence hash, the binary executed, and an output summary — so the
    audit trail is uniform and complete by construction.
    """
    input_hash = sha256_file(evidence_path) if evidence_path else None
    call_id, start = ctx.audit.start(tool, args, input_hash)

    try:
        result: RunResult = ctx.runner(argv)
    except Exception as exc:  # binary missing, disallowed, etc.
        ctx.audit.finish(call_id, start, tool, args, input_hash, error=repr(exc))
        return ToolResult(tool=tool, call_id=call_id, records=[], summary="",
                          input_hash=input_hash, error=repr(exc))

    if result.exit_code != 0 and not result.stdout:
        err = result.stderr.strip() or f"exit code {result.exit_code}"
        ctx.audit.finish(call_id, start, tool, args, input_hash,
                         binary=result.binary, exit_code=result.exit_code, error=err)
        return ToolResult(tool=tool, call_id=call_id, records=[], summary="",
                          input_hash=input_hash, error=err)

    records = parse(result.stdout)
    summary = summarize(records, summarize_kind)
    ctx.audit.finish(call_id, start, tool, args, input_hash,
                     binary=result.binary, exit_code=result.exit_code,
                     output_summary=summary)
    return ToolResult(tool=tool, call_id=call_id, records=records, summary=summary,
                      input_hash=input_hash)


def audited_csv_run(
    ctx: ToolContext,
    *,
    tool: str,
    args: dict[str, Any],
    evidence_path: Optional[str],
    base_argv: Sequence[str],
    parse: Callable[[str], list[dict[str, Any]]],
    summarize_kind: str,
    summarize: Callable[[list[dict[str, Any]], str], str],
    extra_argv: Sequence[str] = (),
    output_glob: str = "*.csv",
) -> ToolResult:
    """Audited run for tools that write CSV to a *directory* (Zimmerman tools).

    Unlike :func:`audited_run`, AmcacheParser/MFTECmd/EvtxECmd cannot stream CSV to
    stdout — ``--csv`` names an output directory. We run the binary into a fresh
    temp dir, then parse every CSV it produced (matching ``output_glob``), parsing
    each file independently so files with differing headers don't get concatenated.

    If no files are produced (e.g. unit tests inject a fake runner that returns
    ``stdout`` instead of writing files) we fall back to parsing ``result.stdout`` —
    keeping the helper backward-compatible with fixture-based tests.
    """
    input_hash = sha256_file(evidence_path) if evidence_path else None
    call_id, start = ctx.audit.start(tool, args, input_hash)

    try:
        with tempfile.TemporaryDirectory(prefix="sift-csv-") as td:
            argv = [*base_argv, "--csv", td, *extra_argv]
            try:
                result: RunResult = ctx.runner(argv)
            except Exception as exc:  # binary missing, disallowed, etc.
                ctx.audit.finish(call_id, start, tool, args, input_hash, error=repr(exc))
                return ToolResult(tool=tool, call_id=call_id, records=[], summary="",
                                  input_hash=input_hash, error=repr(exc))

            csv_files = sorted(glob.glob(os.path.join(td, output_glob)))
            if not csv_files and result.exit_code != 0 and not result.stdout:
                err = result.stderr.strip() or f"exit code {result.exit_code}"
                ctx.audit.finish(call_id, start, tool, args, input_hash,
                                 binary=result.binary, exit_code=result.exit_code, error=err)
                return ToolResult(tool=tool, call_id=call_id, records=[], summary="",
                                  input_hash=input_hash, error=err)

            records: list[dict[str, Any]] = []
            if csv_files:
                for f in csv_files:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        records.extend(parse(fh.read()))
            else:
                records = parse(result.stdout)
    except Exception as exc:  # pragma: no cover - defensive
        ctx.audit.finish(call_id, start, tool, args, input_hash, error=repr(exc))
        return ToolResult(tool=tool, call_id=call_id, records=[], summary="",
                          input_hash=input_hash, error=repr(exc))

    summary = summarize(records, summarize_kind)
    ctx.audit.finish(call_id, start, tool, args, input_hash,
                     binary=result.binary, exit_code=result.exit_code,
                     output_summary=summary)
    return ToolResult(tool=tool, call_id=call_id, records=records, summary=summary,
                      input_hash=input_hash)
