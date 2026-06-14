"""Shared plumbing for forensic tools: context, result type, audited execution."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from ..audit import AuditLog
from ..evidence import sha256_file
from ..runner import RunResult, run_tool


# A runner is anything that takes argv -> RunResult. Injectable for tests.
RunnerFn = Callable[[Sequence[str]], RunResult]


@dataclass
class ToolContext:
    """Carried into every tool call: where evidence lives and where to audit."""

    evidence_root: Path
    audit: AuditLog
    runner: RunnerFn = run_tool
    output_dir: Optional[Path] = None  # where raw outputs are persisted, if any


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
        return {
            "tool": self.tool,
            "call_id": self.call_id,
            "input_hash": self.input_hash,
            "record_count": len(self.records),
            "summary": self.summary,
            "records": self.records,
            "error": self.error,
            **({"extra": self.extra} if self.extra else {}),
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
