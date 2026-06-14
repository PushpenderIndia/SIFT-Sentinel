"""Tests for the parsed-artifact cache (parse-once across re-runs/filters)."""
from conftest import FIXTURES

from sift_sentinel.audit import AuditLog
from sift_sentinel.cache import ParseCache
from sift_sentinel.runner import RunResult
from sift_sentinel.tools.base import ToolContext
from sift_sentinel.tools.mft_timeline import extract_mft_timeline


def _counting_ctx(tmp_path, stdout, *, cache_dir=None):
    root = tmp_path / "mnt"
    root.mkdir()
    calls = {"n": 0}

    def runner(argv):
        calls["n"] += 1
        return RunResult(binary=argv[0], argv=list(argv), exit_code=0,
                         stdout=stdout, stderr="", timed_out=False)

    ctx = ToolContext(
        evidence_root=root,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        runner=runner,
        cache=ParseCache(cache_dir),
    )
    return ctx, root, calls


def test_second_filter_hits_cache_and_skips_subprocess(tmp_path):
    raw = (FIXTURES / "mft_sample.csv").read_text()
    cache_dir = tmp_path / "cache"
    ctx, root, calls = _counting_ctx(tmp_path, raw, cache_dir=cache_dir)
    mft = root / "$MFT"
    mft.write_text("mft-bytes")

    # First call parses (runs the binary once) and populates the cache.
    r1 = extract_mft_timeline(ctx, str(mft), path_filter="Temp")
    assert calls["n"] == 1
    assert not r1.extra.get("cache_hit")

    # Second call with a *different* filter must not re-run the binary.
    r2 = extract_mft_timeline(ctx, str(mft), path_filter="cmd")
    assert calls["n"] == 1  # subprocess NOT invoked again
    assert r2.extra.get("cache_hit") is True
    assert all("cmd" in r["path"].lower() for r in r2.records)

    # The cache hit is recorded in the audit trail.
    assert any(rec.extra.get("cache_hit") for rec in ctx.audit.records())


def test_cache_disabled_by_default_reparses(tmp_path):
    raw = (FIXTURES / "mft_sample.csv").read_text()
    ctx, root, calls = _counting_ctx(tmp_path, raw, cache_dir=None)
    mft = root / "$MFT"
    mft.write_text("mft-bytes")

    extract_mft_timeline(ctx, str(mft), path_filter="Temp")
    extract_mft_timeline(ctx, str(mft), path_filter="cmd")
    assert calls["n"] == 2  # no cache -> parsed each time, behaviour unchanged


def test_cache_invalidates_when_bytes_change(tmp_path):
    raw = (FIXTURES / "mft_sample.csv").read_text()
    cache_dir = tmp_path / "cache"
    ctx, root, calls = _counting_ctx(tmp_path, raw, cache_dir=cache_dir)
    mft = root / "$MFT"
    mft.write_text("mft-bytes")
    extract_mft_timeline(ctx, str(mft))
    assert calls["n"] == 1

    # Different content -> different SHA-256 -> cache miss -> re-parse.
    mft.write_text("DIFFERENT-mft-bytes")
    extract_mft_timeline(ctx, str(mft))
    assert calls["n"] == 2
