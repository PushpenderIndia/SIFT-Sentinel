"""Tests for the offline PDF report renderer (sift-sentinel-report)."""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.audit import AuditLog
from sift_sentinel.report import build_report, main


def _seed_audit(tmp_path: Path) -> str:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    cid, start = log.start("get_amcache", {"amcache_hive": "Amcache.hve"}, "abc123")
    log.finish(cid, start, "get_amcache", {"amcache_hive": "Amcache.hve"}, "abc123",
               binary="AmcacheParser", exit_code=0, output_summary="37 records",
               end=start + 0.5)
    cid2, start2 = log.start("extract_mft_timeline", {"mft_file": "$MFT"}, "def456")
    log.finish(cid2, start2, "extract_mft_timeline", {"mft_file": "$MFT"}, "def456",
               binary="MFTECmd", exit_code=0, end=start2 + 1.0)
    return str(log.path)


def test_build_report_emits_valid_pdf(tmp_path):
    audit_path = _seed_audit(tmp_path)
    md = "## Findings\nMalware executed — corroborated by call-000001 and call-000002.\n"
    pdf = build_report(audit_path=audit_path, findings_md=md,
                       case="Test", evidence_root="/mnt/cases")
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    # Cited call_ids that exist in the audit log are present in the document.
    assert b"call-000001" in pdf and b"call-000002" in pdf


def test_integrity_flags_uncited_and_missing(tmp_path):
    audit_path = _seed_audit(tmp_path)
    # Cite a call_id that was never logged -> integrity check must warn.
    md = "## Findings\nClaim based on call-999999 only.\n"
    pdf = build_report(audit_path=audit_path, findings_md=md, case=None,
                       evidence_root=None)
    assert b"WARNING" in pdf
    assert b"call-999999" in pdf


def test_audit_only_report(tmp_path):
    audit_path = _seed_audit(tmp_path)
    pdf = build_report(audit_path=audit_path, findings_md=None, case=None,
                       evidence_root=None)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Audit Trail" in pdf


def test_main_writes_file(tmp_path):
    audit_path = _seed_audit(tmp_path)
    findings = tmp_path / "f.md"
    findings.write_text("## Findings\nSee call-000001.\n", encoding="utf-8")
    out = tmp_path / "out" / "report.pdf"
    rc = main(["--audit", audit_path, "-f", str(findings), "-o", str(out),
               "--case", "Demo"])
    assert rc == 0
    assert out.exists() and out.read_bytes().startswith(b"%PDF-1.4")
