#!/usr/bin/env python3
"""Live triage run: Claude reasons, the loop drives, the typed tools execute.

This is the production entry point — it requires:
  * ANTHROPIC_API_KEY in the environment (model: claude-opus-4-8),
  * the underlying SIFT forensic tools on PATH (MFTECmd, AmcacheParser, ...),
  * evidence mounted READ-ONLY under --evidence-root.

Usage:
    python run_live.py --evidence-root /mnt/case \\
        --case "Triage suspected intrusion on WIN-HOST (disk + memory)."

Nothing here can modify evidence: the tools are read-only and there is no shell
in the action space. Hashes are verified before and after the run.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from sift_sentinel.audit import AuditLog                       # noqa: E402
from sift_sentinel.evidence import EvidenceSet                 # noqa: E402
from sift_sentinel.orchestrator.anthropic_reasoner import (    # noqa: E402
    AnthropicReasoner, DEFAULT_CATALOG,
)
from sift_sentinel.orchestrator.loop import LoopConfig, SelfCorrectingLoop  # noqa: E402
from sift_sentinel.tools.base import ToolContext               # noqa: E402
from sift_sentinel.tools.registry import REGISTRY              # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="SIFT-Sentinel live triage")
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--case", required=True, help="The case prompt for the agent.")
    ap.add_argument("--audit", default="audit/execution-log.jsonl")
    ap.add_argument("--max-iterations", type=int, default=5)
    ap.add_argument("--evidence-files", nargs="*", default=[],
                    help="Files to hash-verify for spoliation (relative to root).")
    args = ap.parse_args()

    import anthropic  # imported here so --help works without the dependency

    root = Path(args.evidence_root).resolve()
    ctx = ToolContext(evidence_root=root, audit=AuditLog(args.audit))

    # Spoliation guard: snapshot hashes before, verify after.
    evset = EvidenceSet([root / f for f in args.evidence_files]) if args.evidence_files else None
    if evset:
        evset.snapshot_before()

    reasoner = AnthropicReasoner(
        client=anthropic.Anthropic(),
        tool_catalog=DEFAULT_CATALOG,
        evidence_hint=str(root),
    )
    loop = SelfCorrectingLoop(
        ctx, REGISTRY, reasoner,
        LoopConfig(max_iterations=args.max_iterations, progress_path="runs/progress.jsonl"),
    )
    report = loop.run(args.case)

    if evset:
        evset.verify_after()  # raises SpoliationError on any hash change
        report["evidence_integrity"] = evset.report()

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
