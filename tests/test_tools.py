from conftest import FIXTURES

from sift_sentinel.audit import AuditLog
from sift_sentinel.runner import RunResult
from sift_sentinel.tools.amcache import get_amcache
from sift_sentinel.tools.base import ToolContext, _fit_to_budget
from sift_sentinel.tools.mft_timeline import extract_mft_timeline
from sift_sentinel.tools.registry_autoruns import registry_autoruns
from sift_sentinel.tools.yara_scan import yara_scan


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


def test_mft_unfiltered_returns_digest(tmp_path):
    # A large, unfiltered timeline must be digested to the interesting records,
    # not dumped — this is the fix for the 200k-row transport blowup.
    header = "ParentPath,FileName,FileSize,Created0x10,LastModified0x10,InUse"
    noise = [
        f"C:\\Windows\\System32,file{i}.dll,1000,2024-01-02 10:00:00,2024-01-02 10:00:00,True"
        for i in range(600)
    ]
    needle = "C:\\Users\\victim\\AppData\\Local\\Temp,evil.exe,2048,2026-06-01 03:13:50,2026-06-01 03:13:50,True"
    raw = "\n".join([header, *noise, needle]) + "\n"

    ctx, root = make_ctx(tmp_path, raw)
    mft = root / "$MFT"
    mft.write_text("mft-bytes")

    res = extract_mft_timeline(ctx, str(mft))
    assert res.extra.get("mode") == "digest"
    assert res.extra["total"] == 601
    paths = [r["path"] for r in res.records]
    assert any("evil.exe" in p for p in paths)
    assert not any("file100.dll" in p for p in paths)  # System32 noise dropped


def test_registry_autoruns_structured(tmp_path):
    raw = (FIXTURES / "regripper_sample.txt").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    hive = root / "SOFTWARE"
    hive.write_text("hive-bytes")

    res = registry_autoruns(ctx, str(hive))
    assert res.error is None
    assert res.input_hash is not None
    assert any(r["name"] == "evil" for r in res.records)
    assert ctx.audit.records()[0].tool == "registry_autoruns"


def test_yara_scan_structured(tmp_path):
    raw = (FIXTURES / "yara_sample.txt").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    target = root / "evil.exe"
    target.write_text("payload")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x { condition: true }")

    res = yara_scan(ctx, str(target), str(rules))
    assert res.error is None
    assert len(res.records) == 2
    assert any(r["rule"] == "Mimikatz_Credential_Theft" for r in res.records)


def test_yara_scan_missing_rules_errors_cleanly(tmp_path):
    ctx, root = make_ctx(tmp_path, "")
    target = root / "evil.exe"
    target.write_text("payload")

    res = yara_scan(ctx, str(target), str(tmp_path / "nope.yar"))
    assert res.error is not None
    assert "rules file not found" in res.error


def test_fit_to_budget_keeps_prefix_under_limit():
    records = [{"path": "X" * 100, "i": i} for i in range(1000)]
    import json
    trimmed = _fit_to_budget(records, budget=2000)
    assert 0 < len(trimmed) < len(records)
    assert len(json.dumps(trimmed, default=str)) <= 2000
    # Budget of 0 disables trimming.
    assert _fit_to_budget(records, budget=0) is records


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
