from conftest import FIXTURES

from sift_sentinel.parsers import (
    mft_digest, parse_amcache, parse_mft_timeline, parse_prefetch,
    parse_regripper, parse_sccainfo, parse_vol_netscan, parse_yara, summarize,
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


def test_parse_sccainfo_runcount():
    raw = (FIXTURES / "sccainfo_sample.txt").read_text()
    recs = parse_sccainfo(raw)
    assert len(recs) == 1
    assert recs[0]["executable"] == "EVIL.EXE"
    assert recs[0]["run_count"] == 3
    assert recs[0]["last_run"] == "2026-06-01 03:14:10"
    assert recs[0]["source"] == "prefetch"


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


def test_mft_digest_surfaces_interesting_records():
    raw = (FIXTURES / "mft_sample.csv").read_text()
    recs = parse_mft_timeline(raw)
    digest = mft_digest(recs)
    assert digest["total"] == len(recs)
    paths = [r["path"] for r in digest["interesting"]]
    # evil.exe (Temp), mimikatz.exe (Downloads), deleted staging.zip is NOT exec.
    assert any("evil.exe" in p for p in paths)
    assert any("mimikatz.exe" in p for p in paths)
    # A signed binary in System32 is noise, not a needle.
    assert not any("System32\\cmd.exe" in p for p in paths)


def test_mft_digest_flags_double_extension_and_ads():
    recs = [
        {"path": "C:\\Users\\v\\Desktop\\invoice.pdf.exe", "deleted": False},
        {"path": "C:\\Users\\v\\notes.txt:hidden.exe", "deleted": False},
        {"path": "C:\\Windows\\System32\\kernel32.dll", "deleted": False},
    ]
    digest = mft_digest(recs)
    flagged = {r["path"] for r in digest["interesting"]}
    assert "C:\\Users\\v\\Desktop\\invoice.pdf.exe" in flagged
    assert "C:\\Users\\v\\notes.txt:hidden.exe" in flagged
    assert "C:\\Windows\\System32\\kernel32.dll" not in flagged


def test_parse_regripper_extracts_autostart():
    raw = (FIXTURES / "regripper_sample.txt").read_text()
    recs = parse_regripper(raw)
    evil = next(r for r in recs if r["name"] == "evil")
    assert evil["value"].endswith("Temp\\evil.exe")
    assert evil["key"] == "Microsoft\\Windows\\CurrentVersion\\Run"
    assert evil["last_write"].startswith("2026-06-01")
    # The "->" separator variant is parsed too.
    cleanup = next(r for r in recs if r["name"] == "cleanup")
    assert cleanup["value"] == "C:\\ProgramData\\update.bat"


def test_parse_yara_extracts_matches_and_skips_detail():
    raw = (FIXTURES / "yara_sample.txt").read_text()
    recs = parse_yara(raw)
    assert len(recs) == 2  # the "0x1a4:$pattern" detail line is skipped
    rules = {r["rule"] for r in recs}
    assert "Mimikatz_Credential_Theft" in rules
    assert all(r["source"] == "yara" for r in recs)
