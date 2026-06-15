#!/usr/bin/env python3
"""Regenerate ``audit/demo.jsonl`` through the real audited tool pipeline.

The demo evidence under ``runs/demo-evidence`` are placeholders, and the SIFT
binaries (AmcacheParser, MFTECmd, …) are not installed in CI, so this replay
injects a fake runner that returns the committed fixture CSVs as tool output —
the same technique the test suite uses. Everything else is the production path:
``get_amcache`` / ``extract_mft_timeline`` run through ``audited_csv_run``, hash
the evidence, and write one audit record per call.

The point of regenerating it is to show the ``tokens`` field populated: each
record now carries the estimated token cost of the response payload that call
returned into the agent's context (see ``sift_sentinel.tokens``).

Run from the repo root:  python scripts/regen_demo_log.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from sift_sentinel.audit import AuditLog  # noqa: E402
from sift_sentinel.runner import RunResult  # noqa: E402
from sift_sentinel.tools.amcache import get_amcache  # noqa: E402
from sift_sentinel.tools.base import ToolContext  # noqa: E402
from sift_sentinel.tools.mft_timeline import extract_mft_timeline  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures"
EVIDENCE = REPO / "runs" / "demo-evidence"
LOG_PATH = REPO / "audit" / "demo.jsonl"

# Map the underlying binary the tool invokes to the fixture standing in for its
# output. audited_csv_run falls back to parsing stdout when no CSV is written.
_FIXTURE_BY_BINARY = {
    "AmcacheParser": FIXTURES / "amcache_sample.csv",
    "MFTECmd": FIXTURES / "mft_sample.csv",
}


def _fake_runner(argv):
    fixture = _FIXTURE_BY_BINARY.get(argv[0])
    stdout = fixture.read_text() if fixture else ""
    return RunResult(binary=argv[0], argv=list(argv), exit_code=0,
                     stdout=stdout, stderr="", timed_out=False)


def main() -> int:
    # Start from a clean log so call ids begin at call-000001, mirroring a run.
    if LOG_PATH.exists():
        LOG_PATH.unlink()
    ctx = ToolContext(evidence_root=EVIDENCE, audit=AuditLog(LOG_PATH),
                      runner=_fake_runner)

    amcache = get_amcache(ctx, str(EVIDENCE / "Amcache.hve"))
    mft = extract_mft_timeline(ctx, str(EVIDENCE / "$MFT"), path_filter="Temp")

    for res in (amcache, mft):
        print(f"{res.call_id} {res.tool}: {len(res.records)} record(s), "
              f"~{res.response_tokens()} response tokens")
    print(f"wrote {LOG_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
