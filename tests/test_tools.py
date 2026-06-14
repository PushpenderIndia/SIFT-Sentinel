from conftest import FIXTURES

from sift_sentinel.audit import AuditLog
from sift_sentinel.runner import RunResult
from sift_sentinel.tools.amcache import get_amcache
from sift_sentinel.tools.base import ToolContext
from sift_sentinel.tools.mft_timeline import extract_mft_timeline


def make_ctx(tmp_path, stdout: str):
    root = tmp_path / "mnt"
    root.mkdir()
    audit = AuditLog(tmp_path / "audit.jsonl")

    def fake_runner(argv):
        return RunResult(binary=argv[0], argv=list(argv), exit_code=0,
                         stdout=stdout, stderr="", timed_out=False)

    return ToolContext(evidence_root=root, audit=audit, runner=fake_runner), root


def test_get_amcache_returns_structured_and_audits(tmp_path):
    raw = (FIXTURES / "amcache_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    hive = root / "Amcache.hve"
    hive.write_text("binary-hive-bytes")

    res = get_amcache(ctx, str(hive))
    assert res.error is None
    assert len(res.records) == 3
    assert res.call_id == "call-000001"
    assert res.input_hash is not None

    # Audit trail: the finding can be traced to this exact call.
    rec = ctx.audit.records()[0]
    assert rec.call_id == res.call_id
    assert rec.tool == "get_amcache"
    assert rec.input_hash == res.input_hash


def test_mft_path_filter(tmp_path):
    raw = (FIXTURES / "mft_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    mft = root / "$MFT"
    mft.write_text("mft-bytes")

    res = extract_mft_timeline(ctx, str(mft), path_filter="Temp")
    paths = [r["path"] for r in res.records]
    assert all("Temp" in p for p in paths)
    assert any("evil.exe" in p for p in paths)


def test_path_traversal_rejected_by_tool(tmp_path):
    ctx, root = make_ctx(tmp_path, "")
    outside = tmp_path / "secret.hve"
    outside.write_text("x")
    try:
        get_amcache(ctx, str(outside))
    except ValueError as e:
        assert "escapes evidence root" in str(e)
    else:
        raise AssertionError("expected path-traversal ValueError")
