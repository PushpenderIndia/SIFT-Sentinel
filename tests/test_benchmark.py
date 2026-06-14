from sift_sentinel.benchmark.score import (
    Claim, GroundTruthItem, compare, score,
)


GT = [
    GroundTruthItem(key="C:/Users/victim/AppData/Local/Temp/evil.exe", type="file"),
    GroundTruthItem(key="C:/Users/victim/Downloads/mimikatz.exe", type="file"),
    GroundTruthItem(key="185.220.101.5", type="ip"),
]


def test_perfect_score():
    claims = [Claim(k.key, k.type) for k in GT]
    s = score(claims, GT)
    assert s.true_positives == 3
    assert s.recall == 1.0 and s.precision == 1.0
    assert s.hallucination_rate == 0.0


def test_hallucination_counted():
    claims = [
        Claim("C:/Users/victim/AppData/Local/Temp/evil.exe", "file"),
        Claim("C:/Windows/totally_made_up.dll", "file", exists=False),  # hallucination
    ]
    s = score(claims, GT)
    assert s.true_positives == 1
    assert s.hallucinations == 1
    assert s.false_negatives == 2  # mimikatz + ip missed
    assert s.hallucination_rate == 0.5


def test_compare_delta():
    agent = score([Claim(k.key, k.type) for k in GT], GT)
    baseline = score(
        [Claim(GT[0].key, "file"), Claim("bogus.exe", "file", exists=False)], GT
    )
    cmp = compare(agent, baseline)
    assert cmp["delta"]["hallucination_rate"] < 0  # agent hallucinates less
    assert cmp["delta"]["recall"] > 0
