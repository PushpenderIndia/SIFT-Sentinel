"""Tests for the super-timeline merge."""
from sift_sentinel.correlate import build_super_timeline


def test_merge_orders_by_time_across_sources():
    sources = {
        "mft": [{"path": "C:\\Temp\\evil.exe", "created": "2018-09-07 20:25:57",
                 "source": "mft"}],
        "amcache": [{"name": "evil.exe", "file_key_last_write": "2018-09-07 20:26:01",
                     "source": "amcache"}],
        "evtx": [{"event_id": 7045, "time": "2018-09-07 20:26:00", "source": "evtx"}],
    }
    rows = build_super_timeline(sources)
    times = [r["time"] for r in rows]
    assert times == sorted(times)
    assert rows[0]["label"].endswith("evil.exe")  # MFT create is first
    # Each row carries its source and the original record.
    assert all("detail" in r and "source" in r for r in rows)


def test_time_prefix_filters_window():
    sources = {
        "mft": [
            {"path": "a.exe", "created": "2018-09-07 20:25:00", "source": "mft"},
            {"path": "b.exe", "created": "2016-07-16 13:19:00", "source": "mft"},
        ],
    }
    rows = build_super_timeline(sources, time_prefix="2018-09-07")
    assert len(rows) == 1 and rows[0]["label"] == "a.exe"


def test_records_without_time_are_dropped():
    sources = {"mft": [{"path": "no_time.exe", "source": "mft"}]}
    assert build_super_timeline(sources) == []
