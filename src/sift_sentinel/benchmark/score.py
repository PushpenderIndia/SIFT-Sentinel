"""Score agent findings against a documented ground-truth answer key.

Produces the metrics the Accuracy Report needs and that Starter Ideas #1/#5 call
for: true/false positives, false negatives, precision/recall, and a
hallucination rate. Designed to run the agent and the Protocol SIFT baseline
through the same scorer for a head-to-head table.

Ground truth is a list of expected artifacts, each with a ``key`` (normalized
identifier) and a ``type`` (e.g. "file", "ip", "registry", "logon"). A finding
matches a ground-truth item when their normalized keys are equal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


def normalize_key(s: str) -> str:
    """Normalize an artifact identifier for comparison.

    Lowercase, strip, collapse path separators. Keeps comparison robust to
    cosmetic differences (``C:\\Windows`` vs ``c:/windows``).
    """
    return s.strip().lower().replace("\\", "/").rstrip("/")


@dataclass
class GroundTruthItem:
    key: str
    type: str
    description: str = ""

    @property
    def nkey(self) -> str:
        return normalize_key(self.key)


@dataclass
class Claim:
    """A single claim the agent (or baseline) made, with the key it asserts.

    ``exists`` records whether the asserted artifact is real. A claim about a
    non-existent artifact is a hallucination, tracked separately from an ordinary
    false positive (a real artifact wrongly deemed malicious).
    """

    key: str
    type: str
    exists: bool = True

    @property
    def nkey(self) -> str:
        return normalize_key(self.key)


@dataclass
class Score:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    hallucinations: int = 0      # claims about artifacts that do not exist
    total_claims: int = 0
    matched_keys: list[str] = field(default_factory=list)
    missed_keys: list[str] = field(default_factory=list)
    spurious_keys: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def hallucination_rate(self) -> float:
        return self.hallucinations / self.total_claims if self.total_claims else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "hallucinations": self.hallucinations,
            "total_claims": self.total_claims,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "hallucination_rate": round(self.hallucination_rate, 4),
            "missed_keys": self.missed_keys,
            "spurious_keys": self.spurious_keys,
        }


def score(claims: Iterable[Claim], ground_truth: Iterable[GroundTruthItem]) -> Score:
    """Compare claims to ground truth and compute the metrics."""
    gt = {item.nkey: item for item in ground_truth}
    claims = list(claims)
    s = Score(total_claims=len(claims))

    seen: set[str] = set()
    for c in claims:
        if not c.exists:
            # Claim about something that doesn't exist at all -> hallucination.
            s.hallucinations += 1
            s.false_positives += 1
            s.spurious_keys.append(c.key)
            continue
        if c.nkey in gt:
            if c.nkey not in seen:
                s.true_positives += 1
                s.matched_keys.append(c.key)
                seen.add(c.nkey)
        else:
            s.false_positives += 1
            s.spurious_keys.append(c.key)

    for nkey, item in gt.items():
        if nkey not in seen:
            s.false_negatives += 1
            s.missed_keys.append(item.key)
    return s


def compare(agent: Score, baseline: Score) -> dict[str, Any]:
    """Head-to-head delta table: SIFT-Sentinel vs Protocol SIFT baseline."""
    return {
        "metrics": ["precision", "recall", "f1", "hallucination_rate"],
        "agent": agent.to_dict(),
        "baseline": baseline.to_dict(),
        "delta": {
            "precision": round(agent.precision - baseline.precision, 4),
            "recall": round(agent.recall - baseline.recall, 4),
            "f1": round(agent.f1 - baseline.f1, 4),
            "hallucination_rate": round(agent.hallucination_rate - baseline.hallucination_rate, 4),
        },
    }
