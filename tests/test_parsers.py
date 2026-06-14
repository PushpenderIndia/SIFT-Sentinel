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


def test_parse_event_logs_extracts_attribution_fields():
    from sift_sentinel.parsers import parse_event_logs as parse_evtx
    raw = (FIXTURES / "evtx_sample.csv").read_text()
    recs = parse_evtx(raw)
    logon = next(r for r in recs if r["event_id"] == 4624)
    assert logon["account"] == "rsydow-a"
    assert logon["ip"] == "10.0.0.5"
    assert logon["logon_type"] == "3"
    assert logon["workstation"] == "WS01"

    failed = next(r for r in recs if r["event_id"] == 4625)
    assert failed["account"] == "administrator"
    assert failed["ip"] == "185.220.101.5"

    svc = next(r for r in recs if r["event_id"] == 7045)
    assert svc["service_name"] == "PSEXESVC"
    assert svc["image_path"].endswith("PSEXESVC.exe")

    # An event with no EventData carries no spurious enrichment keys.
    bare = next(r for r in recs if r["event_id"] == 4672)
    assert "account" not in bare


def test_parse_shimcache():
    from sift_sentinel.parsers import parse_shimcache
    raw = (FIXTURES / "shimcache_sample.csv").read_text()
    recs = parse_shimcache(raw)
    evil = next(r for r in recs if "evil.exe" in r["path"])
    assert evil["executed"] is True
    assert evil["source"] == "shimcache"
    mk = next(r for r in recs if "mimikatz" in r["path"])
    assert mk["executed"] is False


def test_parse_srum():
    from sift_sentinel.parsers import parse_srum
    raw = (FIXTURES / "srum_sample.csv").read_text()
    recs = parse_srum(raw)
    evil = next(r for r in recs if "evil.exe" in r["app"])
    assert evil["bytes_sent"] == 10485760
    assert evil["source"] == "srum"


def test_annotate_known_good():
    from sift_sentinel.reputation import annotate_known_good
    recs = [
        {"name": "a.exe", "sha1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"},
        {"name": "evil.exe", "sha1": "1111111111111111111111111111111111111111"},
        {"name": "no_hash.exe", "sha1": None},
    ]
    out = annotate_known_good(recs)
    assert out[0]["known_good"] is True   # built-in seed hash, case-insensitive
    assert out[1]["known_good"] is False
    assert out[2]["known_good"] is False  # missing hash is unknown, not good


def test_parse_vol_pstree_and_svcscan_and_malfind():
    from sift_sentinel.parsers import (
        parse_vol_pstree, parse_vol_svcscan, parse_vol_malfind)
    tree = parse_vol_pstree("PID,PPID,ImageFileName,CreateTime\n100,4,evil.exe,2018\n")
    assert tree[0]["pid"] == 100 and tree[0]["ppid"] == 4
    svc = parse_vol_svcscan("PID,Name,State,Binary\n0,PSEXESVC,Running,C:\\PSEXESVC.exe\n")
    assert svc[0]["name"] == "PSEXESVC" and svc[0]["binary"].endswith("PSEXESVC.exe")
    mal = parse_vol_malfind("PID,Process,Protection\n4188,evil.exe,PAGE_EXECUTE_READWRITE\n")
    assert mal[0]["protection"] == "PAGE_EXECUTE_READWRITE"
