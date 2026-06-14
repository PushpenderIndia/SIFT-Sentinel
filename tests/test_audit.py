from sift_sentinel.audit import AuditLog


def test_audit_roundtrip(tmp_path):
    log = AuditLog(tmp_path / "audit" / "exec.jsonl")
    cid, start = log.start("get_amcache", {"amcache_hive": "Amcache.hve"},
                           input_hash="abc123", now=1_000_000.0)
    assert cid == "call-000001"
    rec = log.finish(cid, start, "get_amcache", {"amcache_hive": "Amcache.hve"},
                     input_hash="abc123", binary="AmcacheParser", exit_code=0,
                     output_summary="amcache: 3 record(s)", end=1_000_001.5)
    assert rec.duration_ms == 1500
    assert rec.ts.endswith("Z")

    records = log.records()
    assert len(records) == 1
    assert records[0].call_id == "call-000001"
    assert records[0].tool == "get_amcache"
    assert records[0].input_hash == "abc123"


def test_audit_ids_increment(tmp_path):
    log = AuditLog(tmp_path / "exec.jsonl")
    c1, s1 = log.start("a", {}, None, now=0.0)
    log.finish(c1, s1, "a", {}, None, end=0.0)
    c2, s2 = log.start("b", {}, None, now=0.0)
    log.finish(c2, s2, "b", {}, None, end=0.0)
    assert [r.call_id for r in log.records()] == ["call-000001", "call-000002"]


def test_audit_ids_resume_across_restart(tmp_path):
    path = tmp_path / "exec.jsonl"
    log = AuditLog(path)
    for _ in range(3):
        cid, s = log.start("a", {}, None, now=0.0)
        log.finish(cid, s, "a", {}, None, end=0.0)

    # A fresh AuditLog over the same file (e.g. server restart) must not reuse ids.
    reopened = AuditLog(path)
    cid, s = reopened.start("b", {}, None, now=0.0)
    assert cid == "call-000004"
    log_done = reopened.finish(cid, s, "b", {}, None, end=0.0)
    assert log_done.call_id == "call-000004"
    assert [r.call_id for r in reopened.records()] == [
        "call-000001", "call-000002", "call-000003", "call-000004",
    ]


def test_duplicate_call_ids_detected(tmp_path):
    # Simulate the cross-instance collision: two logs resume independently and
    # both allocate call-000001 against the same file.
    from sift_sentinel.audit import AuditLog
    path = tmp_path / "dup.jsonl"
    a = AuditLog(str(path))
    cid, start = a.start("get_amcache", {}, None)
    a.finish(cid, start, "get_amcache", {}, None, end=start + 0.1)
    b = AuditLog(str(path))  # a separate instance — should resume, but force a clash
    b._seq = 0  # emulate a buggy resume
    cid2, start2 = b.start("extract_mft_timeline", {}, None)
    b.finish(cid2, start2, "extract_mft_timeline", {}, None, end=start2 + 0.1)
    dups = AuditLog(str(path)).duplicate_call_ids()
    assert dups == {"call-000001": 2}


def test_no_duplicates_on_normal_use(tmp_path):
    from sift_sentinel.audit import AuditLog
    log = AuditLog(str(tmp_path / "ok.jsonl"))
    for _ in range(3):
        cid, start = log.start("t", {}, None)
        log.finish(cid, start, "t", {}, None, end=start + 0.1)
    assert log.duplicate_call_ids() == {}
