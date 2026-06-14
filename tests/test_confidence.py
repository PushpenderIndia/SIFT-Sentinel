from sift_sentinel.confidence import Confidence, Finding, corroborate


def test_confirmed_requires_two_sources():
    # A single-source finding cannot self-declare CONFIRMED.
    f = Finding(title="evil.exe executed", description="",
                confidence=Confidence.CONFIRMED, sources=["amcache"])
    assert f.confidence == Confidence.INFERRED


def test_corroboration_promotes_to_confirmed():
    findings = [
        Finding(title="evil.exe executed", description="ran from Temp",
                confidence=Confidence.INFERRED, sources=["amcache"],
                evidence_calls=["call-1"]),
        Finding(title="evil.exe executed", description="ran from Temp",
                confidence=Confidence.INFERRED, sources=["prefetch"],
                evidence_calls=["call-2"]),
    ]
    merged = corroborate(findings)
    assert len(merged) == 1
    assert merged[0].confidence == Confidence.CONFIRMED
    assert set(merged[0].sources) == {"amcache", "prefetch"}
    assert set(merged[0].evidence_calls) == {"call-1", "call-2"}
