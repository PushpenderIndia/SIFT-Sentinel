"""yara_scan — known-bad signature matches over evidence files/directories.

Wraps the ``yara`` binary. Returns one structured record per match
(rule + matched path), never raw scanner chatter.

Security note: the *target* must resolve inside the evidence root (path-traversal
guard) because it is evidence. The *rules file* is analyst-supplied tooling, not
evidence, so it is read from any readable path. YARA only reads — it cannot modify
evidence, and the binary is on the runner allowlist — so this stays within the
read-only trust boundary.
"""
from __future__ import annotations

from pathlib import Path

from ..parsers import parse_yara, summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "yara_scan"


def yara_scan(ctx: ToolContext, target: str, rules_file: str) -> ToolResult:
    """Scan ``target`` (a file or directory inside the evidence root) with YARA.

    ``rules_file`` is a ``.yar``/``.yara`` ruleset path. Directories are scanned
    recursively. Returns a clear error result if the ruleset path is missing.
    """
    tgt = Path(ctx.resolve_evidence(target))
    rules = Path(rules_file).expanduser()

    args = {"target": target, "rules_file": rules_file}
    if not rules.is_file():
        call_id, start = ctx.audit.start(TOOL, args, input_hash=None)
        msg = f"rules file not found: {rules_file}"
        ctx.audit.finish(call_id, start, TOOL, args, input_hash=None, error=msg)
        return ToolResult(tool=TOOL, call_id=call_id, records=[], summary=msg, error=msg)

    argv = ["yara", "-w"]
    if tgt.is_dir():
        argv.append("-r")
    argv += [str(rules), str(tgt)]

    return audited_run(
        ctx,
        tool=TOOL,
        args=args,
        # A directory has no single hash; a file does. Either way YARA is read-only.
        evidence_path=str(tgt) if tgt.is_file() else None,
        argv=argv,
        parse=parse_yara,
        summarize_kind="yara",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
