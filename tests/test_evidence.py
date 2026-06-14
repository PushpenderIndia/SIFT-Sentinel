import pytest

from sift_sentinel.evidence import (
    EvidenceSet, SpoliationError, assert_within, sha256_file,
)


def test_sha256_stable(tmp_path):
    f = tmp_path / "img.dd"
    f.write_bytes(b"forensic-bytes")
    assert sha256_file(f) == sha256_file(f)


def test_spoliation_detected(tmp_path):
    f = tmp_path / "img.dd"
    f.write_bytes(b"original")
    ev = EvidenceSet([f])
    ev.snapshot_before()
    # Simulate something modifying the evidence mid-run.
    f.write_bytes(b"tampered")
    with pytest.raises(SpoliationError):
        ev.verify_after()


def test_integrity_intact(tmp_path):
    f = tmp_path / "img.dd"
    f.write_bytes(b"original")
    ev = EvidenceSet([f])
    ev.snapshot_before()
    ev.verify_after()  # no change -> no raise
    rep = ev.report()
    assert rep[str(f)]["intact"] is True


def test_path_traversal_blocked(tmp_path):
    root = tmp_path / "mnt"
    root.mkdir()
    inside = root / "Amcache.hve"
    inside.write_text("x")
    assert assert_within(root, inside) == inside.resolve()
    with pytest.raises(ValueError):
        assert_within(root, tmp_path / "etc" / "passwd")
