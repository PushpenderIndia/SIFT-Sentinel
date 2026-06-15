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
    assert rec.extra["input_hash_after"] == res.input_hash
    assert rec.extra["input_hash_intact"] is True


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


def test_logon_summary_aggregates(tmp_path):
    from sift_sentinel.tools.logon_summary import logon_summary
    raw = (FIXTURES / "evtx_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    evtx = root / "Security.evtx"
    evtx.write_text("evtx-bytes")

    res = logon_summary(ctx, str(evtx))
    assert res.error is None
    # rsydow-a 4624 and administrator 4625 become distinct actor rows.
    admin = next(r for r in res.records if r["account"] == "administrator")
    assert admin["failure"] == 1 and admin["success"] == 0
    assert admin["ip"] == "185.220.101.5"
    rsydow = next(r for r in res.records if r["account"] == "rsydow-a")
    assert rsydow["success"] == 1
    # Brute-force tuple (failures) sorts ahead of clean successes.
    assert res.records[0]["failure"] >= res.records[-1]["failure"]


def test_powershell_logs_filters_and_extracts_scriptblock(tmp_path):
    from sift_sentinel.tools.powershell_logs import powershell_logs
    header = "RecordNumber,EventId,TimeCreated,Channel,Computer,MapDescription,Payload"
    rows = [
        '1,4104,2018-09-07 16:36:38,Microsoft-Windows-PowerShell/Operational,BASE-DC,Execute a Remote Command,"{""@Name"":""ScriptBlockText"",""#text"":""Invoke-Mimikatz -DumpCreds""}"',
        '2,4103,2018-09-07 16:36:40,Microsoft-Windows-PowerShell/Operational,BASE-DC,Module Logging,"{""@Name"":""ScriptBlockText"",""#text"":""Get-Process""}"',
        '3,400,2018-09-07 16:30:00,Windows PowerShell,BASE-DC,Engine state,"{}"',
    ]
    raw = "\n".join([header, *rows]) + "\n"
    ctx, root = make_ctx(tmp_path, raw)
    evtx = root / "PSOperational.evtx"
    evtx.write_text("evtx")

    res = powershell_logs(ctx, str(evtx))
    ids = {r["event_id"] for r in res.records}
    assert ids == {4103, 4104}  # the 400 engine event is excluded
    sb = next(r for r in res.records if r["event_id"] == 4104)
    assert "Invoke-Mimikatz" in sb["script_block"]


def test_read_artifact_reads_text_and_audits(tmp_path):
    from sift_sentinel.tools.read_artifact import read_artifact
    ctx, root = make_ctx(tmp_path, "")
    art = root / "PowerShell_transcript.txt"
    art.write_text("line one\nInvoke-Mimikatz\nline three\n")

    res = read_artifact(ctx, str(art))
    assert res.error is None
    assert res.input_hash is not None
    assert any("Invoke-Mimikatz" in r["text"] for r in res.records)
    assert res.extra["lines_total"] == 3
    assert res.extra["input_hash_after"] == res.input_hash
    assert res.extra["input_hash_intact"] is True
    assert ctx.audit.records()[-1].tool == "read_artifact"


def test_read_artifact_rejects_path_traversal(tmp_path):
    from sift_sentinel.tools.read_artifact import read_artifact
    ctx, root = make_ctx(tmp_path, "")
    outside = tmp_path / "secret.txt"
    outside.write_text("classified")
    try:
        read_artifact(ctx, str(outside))
    except ValueError as e:
        assert "escapes evidence root" in str(e)
    else:
        raise AssertionError("expected path-traversal ValueError")


def test_shimcache_tool(tmp_path):
    from sift_sentinel.tools.shimcache import shimcache
    raw = (FIXTURES / "shimcache_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    hive = root / "SYSTEM"
    hive.write_text("hive")
    res = shimcache(ctx, str(hive))
    assert res.error is None
    assert any("evil.exe" in r["path"] for r in res.records)
    assert ctx.audit.records()[0].tool == "shimcache"


def test_srum_tool(tmp_path):
    from sift_sentinel.tools.srum import srum
    raw = (FIXTURES / "srum_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    db = root / "SRUDB.dat"
    db.write_text("db")
    res = srum(ctx, str(db))
    assert res.error is None
    assert any("evil.exe" in r["app"] for r in res.records)


def test_amcache_known_good_flag_and_suppression(tmp_path):
    raw = (FIXTURES / "amcache_sample.csv").read_text()
    ctx, root = make_ctx(tmp_path, raw)
    hive = root / "Amcache.hve"
    hive.write_text("hive")

    res = get_amcache(ctx, str(hive))
    assert "known_good" in res.records[0]
    assert "known_good_count" in res.extra

    # Suppression drops the seed-hash known-good entry (empty-file SHA-1).
    res2 = get_amcache(ctx, str(hive), suppress_known_good=True)
    assert all(not r["known_good"] for r in res2.records)


def test_mem_validation_empty_image_errors(tmp_path):
    from sift_sentinel.tools.memory import mem_pslist
    ctx, root = make_ctx(tmp_path, "")
    img = root / "mem.img"
    img.write_text("")  # 0 bytes
    res = mem_pslist(ctx, str(img))
    assert res.error is not None
    assert "empty" in res.error


def test_mem_validation_missing_image_errors(tmp_path):
    from sift_sentinel.tools.memory import mem_netscan
    ctx, root = make_ctx(tmp_path, "")
    res = mem_netscan(ctx, str(root / "nope.img"))
    assert res.error is not None
    assert "not found" in res.error


def test_mem_cmdline_parses(tmp_path):
    from sift_sentinel.tools.memory import mem_cmdline
    csv = "PID,Process,Args\n4188,powershell.exe,-enc ZQB2AGkAbAA=\n"
    ctx, root = make_ctx(tmp_path, csv)
    img = root / "mem.img"
    img.write_text("RAMCAPTUREBYTES")  # non-empty
    res = mem_cmdline(ctx, str(img))
    assert res.error is None
    assert res.records[0]["process"] == "powershell.exe"
    assert "-enc" in res.records[0]["args"]


def test_super_timeline_merges_sources(tmp_path):
    from sift_sentinel.tools.super_timeline import super_timeline
    mft_csv = ("ParentPath,FileName,Created0x10,InUse\n"
               "C:\\Windows\\Temp,evil.exe,2018-09-07 20:25:57,True\n")
    ctx, root = make_ctx(tmp_path, mft_csv)
    mft = root / "$MFT"
    mft.write_text("mft")
    res = super_timeline(ctx, mft_file=str(mft), time_prefix="2018-09-07")
    assert res.error is None
    assert any("evil.exe" in r["label"] for r in res.records)
    # The merge cites the underlying MFT call.
    assert res.extra["contributing_calls"]
    assert "mft" in res.extra["sources"]


def test_registry_lists_all_new_tools():
    from sift_sentinel.tools.registry import REGISTRY
    for name in ("logon_summary", "powershell_logs", "read_artifact", "shimcache",
                 "srum", "mem_pstree", "mem_cmdline", "mem_malfind", "mem_svcscan",
                 "super_timeline"):
        assert name in REGISTRY, f"{name} missing from REGISTRY"


def test_new_binaries_allowlisted():
    from sift_sentinel.runner import ALLOWED_BINARIES
    for b in ("AppCompatCacheParser", "SrumECmd"):
        assert b in ALLOWED_BINARIES
