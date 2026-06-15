"""Token estimation and its propagation into the audit trail."""
from sift_sentinel.tokens import estimate_tokens
from sift_sentinel.audit import AuditLog
from sift_sentinel.runner import RunResult
from sift_sentinel.tools.base import ToolContext, ToolResult, audited_run


def test_estimate_tokens_empty_is_zero():
    # No payload -> no tokens. (An empty JSON container like "[]" is not "no
    # payload" — it serializes to characters and so costs a couple of tokens.)
    assert estimate_tokens("") == 0
    assert estimate_tokens(None) == 0


def test_estimate_tokens_positive_and_monotonic():
    short = estimate_tokens("hello world")
    longer = estimate_tokens("hello world " * 100)
    assert short > 0
    assert longer > short


def test_estimate_tokens_accepts_objects():
    # A dict (a tool response) serializes and estimates without raising.
    payload = {"tool": "get_amcache", "records": [{"path": "c:/windows/evil.exe"}]}
    assert estimate_tokens(payload) > 0


def test_estimate_tokens_deterministic():
    payload = {"a": 1, "b": ["x", "y", "z"], "c": "some text here"}
    assert estimate_tokens(payload) == estimate_tokens(payload)


def test_response_tokens_matches_payload():
    res = ToolResult(tool="t", call_id="call-000001",
                     records=[{"k": "v"}], summary="one record")
    assert res.response_tokens() == estimate_tokens(res.to_dict())
    assert res.response_tokens() > 0


def test_audited_run_records_tokens(tmp_path):
    """Every audited tool call must log a non-null, positive token count."""
    log = AuditLog(tmp_path / "exec.jsonl")
    ctx = ToolContext(evidence_root=tmp_path, audit=log,
                      runner=lambda argv: RunResult(binary=argv[0], argv=list(argv),
                                                    exit_code=0, stdout="line-a\nline-b",
                                                    stderr="", timed_out=False))
    res = audited_run(
        ctx,
        tool="demo_tool",
        args={"x": 1},
        evidence_path=None,
        argv=["fake"],
        parse=lambda out: [{"line": ln} for ln in out.splitlines()],
        summarize_kind="demo",
        summarize=lambda recs, kind: f"demo: {len(recs)} record(s)",
    )
    rec = log.records()[-1]
    assert rec.tokens is not None
    assert rec.tokens > 0
    assert rec.tokens == res.response_tokens()


def test_logged_tokens_match_finalized_payload(tmp_path):
    """tokens must reflect the payload after finalize (digest/enrichment),
    i.e. exactly what the agent receives — not a pre-transform intermediate."""
    from conftest import FIXTURES
    from sift_sentinel.runner import RunResult
    from sift_sentinel.tools.amcache import get_amcache

    root = tmp_path / "mnt"
    root.mkdir()
    log = AuditLog(tmp_path / "exec.jsonl")
    raw = (FIXTURES / "amcache_sample.csv").read_text()
    ctx = ToolContext(evidence_root=root, audit=log,
                      runner=lambda argv: RunResult(binary=argv[0], argv=list(argv),
                                                    exit_code=0, stdout=raw, stderr="",
                                                    timed_out=False))
    hive = root / "Amcache.hve"
    hive.write_text("binary-hive-bytes")

    res = get_amcache(ctx, str(hive))
    # The known_good enrichment lands in the returned payload...
    assert "known_good_count" in res.extra
    rec = log.records()[-1]
    # ...and the logged token count is computed over that same enriched payload.
    assert rec.tokens == res.response_tokens()


def test_audited_run_error_path_also_records_tokens(tmp_path):
    """Error/empty responses still get a token count (field never null)."""
    log = AuditLog(tmp_path / "exec.jsonl")

    def boom(argv):
        raise FileNotFoundError("binary missing")

    ctx = ToolContext(evidence_root=tmp_path, audit=log, runner=boom)
    audited_run(
        ctx,
        tool="demo_tool",
        args={},
        evidence_path=None,
        argv=["missing"],
        parse=lambda out: [],
        summarize_kind="demo",
        summarize=lambda recs, kind: "",
    )
    rec = log.records()[-1]
    assert rec.error is not None
    assert rec.tokens is not None and rec.tokens > 0
