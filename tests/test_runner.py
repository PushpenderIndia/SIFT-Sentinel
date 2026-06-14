import pytest

from sift_sentinel.runner import (
    ALLOWED_BINARIES, DisallowedBinaryError, run_tool,
)


def test_disallowed_binary_refused():
    # The crux of criterion #4: an arbitrary command cannot be executed.
    with pytest.raises(DisallowedBinaryError):
        run_tool(["rm", "-rf", "/mnt/case"])
    with pytest.raises(DisallowedBinaryError):
        run_tool(["dd", "if=/dev/zero", "of=/mnt/case/image.dd"])


def test_empty_argv_rejected():
    with pytest.raises(ValueError):
        run_tool([])


def test_allowlist_contains_expected_tools():
    for b in ("MFTECmd", "AmcacheParser", "vol", "yara", "fls"):
        assert b in ALLOWED_BINARIES


def test_allowlisted_but_missing_binary_raises(monkeypatch):
    # 'yara' is allowlisted; if not installed, we get a clear FileNotFoundError,
    # never a silent shell fallback.
    import sift_sentinel.runner as r
    monkeypatch.setattr(r.shutil, "which", lambda b: None)
    with pytest.raises(FileNotFoundError):
        run_tool(["yara", "rules", "target"])
