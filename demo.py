#!/usr/bin/env python3
"""End-to-end demo of the self-correcting loop on bundled fixtures.

No SIFT Workstation or forensic tools required — a fake runner feeds the bundled
sample CSVs through the real parsers, tools, audit log, and orchestrator. Run:

    python demo.py

Outputs:
  runs/progress.jsonl   iteration-over-iteration trace (deliverable #8)
  audit/demo.jsonl      one record per tool call (deliverable #8, audit trail)
  stdout                the final findings report with confidence + citations
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from sift_sentinel.audit import AuditLog                       # noqa: E402
from sift_sentinel.confidence import Confidence, Finding       # noqa: E402
from sift_sentinel.orchestrator.loop import (                  # noqa: E402
    Action, Evaluation, LoopConfig, SelfCorrectingLoop,
)
from sift_sentinel.runner import RunResult                     # noqa: E402
from sift_sentinel.tools.amcache import get_amcache            # noqa: E402
from sift_sentinel.tools.base import ToolContext               # noqa: E402
from sift_sentinel.tools.mft_timeline import extract_mft_timeline  # noqa: E402

FIX = Path(__file__).parent / "tests" / "fixtures"


def build_ctx(root: Path) -> ToolContext:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Amcache.hve").write_text("hive")
    (root / "$MFT").write_text("mft")
    amcache_raw = (FIX / "amcache_sample.csv").read_text()
    mft_raw = (FIX / "mft_sample.csv").read_text()

    def runner(argv):
        raw = amcache_raw if argv[0].startswith("Amcache") else mft_raw
        return RunResult(binary=argv[0], argv=list(argv), exit_code=0,
                         stdout=raw, stderr="", timed_out=False)

    return ToolContext(evidence_root=root, audit=AuditLog("audit/demo.jsonl"), runner=runner)


class DemoReasoner:
    """Deterministic stand-in for the LLM, scripted to show one self-correction."""

    def __init__(self, root: Path):
        self.root = root

    def plan(self, case_prompt):
        print(f"[plan]   {case_prompt}\n[plan]   hypothesis: what executed on this host?")
        return [Action("get_amcache", {"amcache_hive": str(self.root / "Amcache.hve")},
                       "What executed on this host?")]

    def evaluate(self, case_prompt, results, findings):
        used = {r.tool for r in results}
        if "extract_mft_timeline" not in used:
            print("[eval]   amcache shows execution but it is uncorroborated on disk — "
                  "GAP detected, re-running against the $MFT (self-correction)")
            return Evaluation(False, gaps=["execution not corroborated on filesystem"],
                              next_actions=[Action(
                                  "extract_mft_timeline",
                                  {"mft_file": str(self.root / "$MFT"), "path_filter": "Temp"},
                                  "Was evil.exe dropped just before it ran?")])
        print("[eval]   amcache + MFT agree — picture is internally consistent. Done.")
        return Evaluation(True, done=True)

    def synthesize(self, results):
        if not results:
            return []
        srcs = ["amcache" if "amcache" in r.tool else "mft" for r in results if r.records]
        return [Finding(title="evil.exe executed from %TEMP%",
                        description="evil.exe was dropped to AppData\\Local\\Temp and executed",
                        confidence=Confidence.INFERRED, sources=srcs,
                        evidence_calls=[r.call_id for r in results],
                        reasoning="Amcache records execution; MFT shows the binary created "
                                  "seconds earlier in the same path.")]


def main() -> int:
    root = Path("runs/demo-evidence")
    loop = SelfCorrectingLoop(
        build_ctx(root),
        {"get_amcache": get_amcache, "extract_mft_timeline": extract_mft_timeline},
        DemoReasoner(root),
        LoopConfig(max_iterations=5, progress_path="runs/progress.jsonl"),
    )
    report = loop.run("Triage suspected intrusion on WIN-HOST (disk image + Amcache).")

    print("\n===== FINAL REPORT =====")
    print(f"iterations: {report['iterations']}  stop_reason: {report['stop_reason']}")
    for f in report["findings"]:
        print(f"\n  [{f['confidence']}] {f['title']}")
        print(f"      sources : {', '.join(f['sources'])}")
        print(f"      cites   : {', '.join(f['evidence_calls'])}")
        print(f"      reason  : {f['reasoning']}")
    print(f"\ntrace: {report['progress_trace']}   audit: audit/demo.jsonl")
    print("(open those files to trace every finding to the exact tool call)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
