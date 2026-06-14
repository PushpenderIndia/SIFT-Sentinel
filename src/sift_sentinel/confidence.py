"""Confidence model — separate CONFIRMED facts from INFERRED guesses.

The hackathon exists because Protocol SIFT hallucinates. Our defense is to force
every finding to carry an explicit confidence level and the list of audit
``call_id`` references that support it. A finding with no supporting evidence
references cannot be CONFIRMED — the data model makes an unsupported "confident"
claim unrepresentable.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Confidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"        # >= 2 independent sources agree
    INFERRED = "INFERRED"          # single source, plausible, flagged
    UNCERTAIN = "UNCERTAIN"        # weak / partial evidence
    CONTRADICTION = "CONTRADICTION"  # sources disagree — must be surfaced


@dataclass
class Finding:
    """One analytical claim, always tied back to the evidence that produced it."""

    title: str
    description: str
    confidence: Confidence
    evidence_calls: list[str] = field(default_factory=list)  # audit call_ids
    sources: list[str] = field(default_factory=list)         # logical sources, e.g. "amcache"
    reasoning: str = ""
    artifacts: dict[str, Any] = field(default_factory=dict)  # structured specifics

    def __post_init__(self) -> None:
        if self.confidence == Confidence.CONFIRMED and len(set(self.sources)) < 2:
            # Enforce the rule: CONFIRMED requires corroboration from >=2 sources.
            # Downgrade rather than silently lie.
            self.confidence = Confidence.INFERRED
            self.reasoning = (self.reasoning + " "
                              "[auto-downgraded: CONFIRMED requires >=2 independent sources]").strip()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


def corroborate(findings: list[Finding]) -> list[Finding]:
    """Promote findings to CONFIRMED when independent sources agree.

    Findings are grouped by ``title``; if the union of their sources has >= 2
    distinct entries, the merged finding is CONFIRMED with all evidence calls
    combined. This is the cross-source correlation step (Starter Idea #2).
    """
    by_title: dict[str, list[Finding]] = {}
    for f in findings:
        by_title.setdefault(f.title, []).append(f)

    merged: list[Finding] = []
    for title, group in by_title.items():
        sources = sorted({s for f in group for s in f.sources})
        calls = sorted({c for f in group for c in f.evidence_calls})
        if len(group) == 1 and len(set(group[0].sources)) < 2:
            merged.append(group[0])
            continue
        conf = Confidence.CONFIRMED if len(sources) >= 2 else group[0].confidence
        merged.append(Finding(
            title=title,
            description=group[0].description,
            confidence=conf,
            evidence_calls=calls,
            sources=sources,
            reasoning="; ".join(filter(None, (f.reasoning for f in group))),
            artifacts={k: v for f in group for k, v in f.artifacts.items()},
        ))
    return merged
