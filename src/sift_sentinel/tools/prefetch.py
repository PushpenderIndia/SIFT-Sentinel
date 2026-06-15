"""analyze_prefetch — evidence of execution from Windows Prefetch (.pf) files.

Uses sccainfo (apt: libscca-tools) — the Linux-native Prefetch reader.
Iterates every .pf file in the directory, calls sccainfo on each, and returns
aggregated execution records. Corroborates Amcache to promote INFERRED → CONFIRMED.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..audit import AuditLog
from ..evidence import sha256_file
from ..parsers import parse_sccainfo, summarize
from .base import ToolContext, ToolResult

TOOL = "analyze_prefetch"


def analyze_prefetch(ctx: ToolContext, prefetch_path: str) -> ToolResult:
    """Parse a Prefetch directory (or single ``.pf``) into execution records.

    Uses ``sccainfo`` (``apt install libscca-tools``) — no Windows runtime needed.
    Returns an empty result with a clear message when Prefetch is disabled on the
    target (common on Windows Server / domain controllers).
    """
    target = Path(ctx.resolve_evidence(prefetch_path))
    args = {"prefetch_path": prefetch_path}

    # Collect .pf files to process
    if target.is_dir():
        pf_files = sorted(target.glob("*.pf"))
    elif target.suffix.lower() == ".pf":
        pf_files = [target]
    else:
        pf_files = []

    call_id, start = ctx.audit.start(TOOL, args, input_hash=None)

    if not pf_files:
        msg = f"No .pf files found in {target} — Prefetch may be disabled (common on Windows Server/DC)."
        ctx.audit.finish(call_id, start, TOOL, args, input_hash=None, error=msg)
        return ToolResult(tool=TOOL, call_id=call_id, records=[], summary=msg, error=msg)

    all_records: list[dict] = []
    errors: list[str] = []
    hashes_before = {str(pf): sha256_file(pf) for pf in pf_files}

    for pf in pf_files:
        try:
            result = ctx.runner(["sccainfo", str(pf)])
            if result.exit_code == 0 and result.stdout:
                recs = parse_sccainfo(result.stdout)
                all_records.extend(recs)
            elif result.stderr:
                errors.append(f"{pf.name}: {result.stderr.strip()[:120]}")
        except Exception as exc:
            errors.append(f"{pf.name}: {exc}")

    summary = summarize(all_records, "prefetch")
    if errors:
        summary += f"\n  warnings: {'; '.join(errors[:3])}"

    hashes_after = {str(pf): sha256_file(pf) for pf in pf_files}
    changed = [path for path, before in hashes_before.items() if hashes_after[path] != before]
    integrity = {
        "prefetch_file_count": len(pf_files),
        "input_hash_intact": not changed,
    }
    if changed:
        msg = "evidence hash changed during analyze_prefetch call"
        ctx.audit.finish(call_id, start, TOOL, args, input_hash=None,
                         binary="sccainfo", exit_code=0, output_summary=summary,
                         error=msg, changed_files=changed[:10], **integrity)
        return ToolResult(tool=TOOL, call_id=call_id, records=[], summary=msg,
                          error=msg, extra={**integrity, "changed_files": changed[:10]})

    ctx.audit.finish(call_id, start, TOOL, args, input_hash=None,
                     binary="sccainfo", exit_code=0, output_summary=summary,
                     **integrity)
    return ToolResult(tool=TOOL, call_id=call_id, records=all_records,
                      summary=summary, extra=integrity)
