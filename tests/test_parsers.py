from conftest import FIXTURES

from sift_sentinel.parsers import (
    parse_amcache, parse_mft_timeline, parse_prefetch, parse_vol_netscan, summarize,
)


def test_parse_amcache_structured():
    raw = (FIXTURES / "amcache_sample.csv").read_text()
    recs = parse_amcache(raw)
    assert len(recs) == 3
    evil = next(r for r in recs if r["name"] == "evil.exe")
    assert evil["path"].endswith("Temp\\evil.exe")
    assert evil["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert evil["source"] == "amcache"


def test_parse_mft_marks_deleted():
    raw = (FIXTURES / "mft_sample.csv").read_text()
    recs = parse_mft_timeline(raw)
    staging = next(r for r in recs if "staging.zip" in r["path"])
    assert staging["deleted"] is True
    assert staging["size"] == 5242880
    cmd = next(r for r in recs if "cmd.exe" in r["path"])
    assert cmd["deleted"] is False


def test_parse_prefetch_runcount():
    raw = (FIXTURES / "prefetch_sample.csv").read_text()
    recs = parse_prefetch(raw)
    evil = next(r for r in recs if r["executable"] == "EVIL.EXE")
    assert evil["run_count"] == 3
    assert evil["source"] == "prefetch"


def test_parse_netscan_extracts_c2():
    raw = (FIXTURES / "netscan_sample.csv").read_text()
    recs = parse_vol_netscan(raw)
    c2 = next(r for r in recs if r["foreign"] == "185.220.101.5")
    assert c2["pid"] == 4188
    assert c2["foreign_port"] == 443
    assert c2["state"] == "ESTABLISHED"


def test_summarize_truncates():
    recs = [{"path": f"f{i}"} for i in range(50)]
    out = summarize(recs, "mft", limit=10)
    assert "50 record(s)" in out
    assert "40 more" in out
