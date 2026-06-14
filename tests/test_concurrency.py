"""Tests for the parallel sweep helper."""
import threading
import time

from sift_sentinel.audit import AuditLog
from sift_sentinel.concurrency import run_parallel, triage_sweep
from sift_sentinel.runner import RunResult
from sift_sentinel.tools.base import ToolContext


def test_run_parallel_preserves_order():
    out = run_parallel([lambda: 1, lambda: 2, lambda: 3])
    assert out == [1, 2, 3]


def test_run_parallel_is_concurrent():
    # Three 0.1s sleeps run concurrently should finish well under the 0.3s serial
    # sum. Generous bound to avoid flakiness on a busy CI box.
    def slow():
        time.sleep(0.1)
        return threading.get_ident()

    start = time.time()
    run_parallel([slow, slow, slow])
    assert time.time() - start < 0.25


def test_run_parallel_propagates_exceptions():
    def boom():
        raise ValueError("tool failed")

    try:
        run_parallel([lambda: 1, boom])
    except ValueError as e:
        assert "tool failed" in str(e)
    else:
        raise AssertionError("exception should propagate")


def test_triage_sweep_runs_supplied_artifacts(tmp_path):
    root = tmp_path / "mnt"
    root.mkdir()
    (root / "$MFT").write_text("mft")
    (root / "Amcache.hve").write_text("hive")
    (root / "Prefetch").mkdir()

    def runner(argv):
        return RunResult(binary=argv[0], argv=list(argv), exit_code=0,
                         stdout="", stderr="", timed_out=False)

    ctx = ToolContext(evidence_root=root, audit=AuditLog(tmp_path / "a.jsonl"),
                      runner=runner)

    out = triage_sweep(ctx, mft_file=str(root / "$MFT"),
                       amcache_hive=str(root / "Amcache.hve"),
                       prefetch_path=str(root / "Prefetch"))
    assert set(out) == {"get_amcache", "extract_mft_timeline", "analyze_prefetch"}
    # Each produced a citable call_id.
    assert all(r["call_id"].startswith("call-") for r in out.values())
