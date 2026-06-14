"""AnthropicReasoner — Claude drives the reasoning, our loop drives control flow.

This is the deliberate architecture: the deterministic ``SelfCorrectingLoop`` owns
the control flow (fan-out, max-iterations, logging), while Claude supplies the three
judgement calls — PLAN, SYNTHESIZE, EVALUATE — each as validated structured output.
Claude never gets a shell; it can only choose among the typed forensic tools we
expose, and it must cite the audit ``call_id`` behind every finding.

Model + params follow current guidance: ``claude-opus-4-8`` with adaptive thinking.
The Anthropic SDK import is lazy so the rest of the package (and its tests) run
without the dependency installed.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..confidence import Confidence, Finding
from ..tools.base import ToolResult
from .loop import Action, Evaluation
from .prompts import EVALUATE_SYSTEM, SENIOR_ANALYST_SYSTEM

MODEL = "claude-opus-4-8"


# --- Pydantic schemas for structured output --------------------------------
# Imported lazily inside _schemas() so pydantic/anthropic aren't hard deps.
def _schemas():
    from pydantic import BaseModel, Field

    class ActionModel(BaseModel):
        tool: str = Field(description="Name of a tool from the provided catalog.")
        args_json: str = Field(
            description='JSON object of arguments for the tool, as a string, '
                        'e.g. {"amcache_hive": "/mnt/case/Amcache.hve"}.')
        hypothesis: str = Field(description="What this call is meant to test.")

    class PlanModel(BaseModel):
        actions: list[ActionModel]

    class FindingModel(BaseModel):
        title: str
        description: str
        confidence: str = Field(description="CONFIRMED | INFERRED | UNCERTAIN | CONTRADICTION")
        sources: list[str] = Field(description="Logical sources, e.g. amcache, mft.")
        evidence_calls: list[str] = Field(description="Audit call_ids supporting this.")
        reasoning: str = ""

    class SynthModel(BaseModel):
        findings: list[FindingModel]

    class EvalModel(BaseModel):
        consistent: bool
        gaps: list[str] = []
        contradictions: list[str] = []
        next_actions: list[ActionModel] = []
        done: bool = False

    return ActionModel, PlanModel, FindingModel, SynthModel, EvalModel


def _safe_args(args_json: str) -> dict[str, Any]:
    try:
        val = json.loads(args_json)
        return val if isinstance(val, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _result_digest(results: list[ToolResult], record_cap: int = 40) -> str:
    """Compact, bounded JSON view of accumulated tool output for the prompt.

    Records are capped so a huge timeline never floods the context — the same
    discipline the MCP parsers enforce, applied again at the reasoning layer.
    """
    out = []
    for r in results:
        out.append({
            "tool": r.tool,
            "call_id": r.call_id,
            "record_count": len(r.records),
            "summary": r.summary,
            "records": r.records[:record_cap],
            "error": r.error,
        })
    return json.dumps(out, indent=2)


class AnthropicReasoner:
    """Live reasoner backed by the Claude API.

    Args:
        client: an ``anthropic.Anthropic`` instance (inject for tests/mocks).
        tool_catalog: ``{tool_name: human description}`` — the action space the
            model is allowed to choose from. The model cannot invent tools; the
            loop drops any call whose name isn't registered.
        evidence_hint: a short note about where evidence lives (paths), so the
            model produces valid ``args`` on the first plan.
        model: override the model id (defaults to claude-opus-4-8).
    """

    def __init__(self, client: Any, tool_catalog: dict[str, str],
                 evidence_hint: str = "", model: str = MODEL):
        self.client = client
        self.tool_catalog = tool_catalog
        self.evidence_hint = evidence_hint
        self.model = model
        (self._Action, self._Plan, self._Finding,
         self._Synth, self._Eval) = _schemas()

    # --- the single mockable API seam ------------------------------------
    def _parse(self, system: str, user: str, schema: Any) -> Any:
        """One Claude call returning a validated instance of ``schema``.

        Tests subclass and override this; production hits the API.
        """
        resp = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=system,
            messages=[{"role": "user", "content": user}],
            output_format=schema,
        )
        return resp.parsed_output

    def _catalog_text(self) -> str:
        lines = ["Available tools (you may ONLY use these):"]
        for name, desc in self.tool_catalog.items():
            lines.append(f"  - {name}: {desc}")
        if self.evidence_hint:
            lines.append(f"\nEvidence locations: {self.evidence_hint}")
        return "\n".join(lines)

    # --- Reasoner protocol ----------------------------------------------
    def plan(self, case_prompt: str) -> list[Action]:
        user = (f"{self._catalog_text()}\n\nCase:\n{case_prompt}\n\n"
                "Produce the initial tool sequence. State a hypothesis per call. "
                "Start broad (execution evidence, timeline), then plan to corroborate.")
        out = self._parse(SENIOR_ANALYST_SYSTEM, user, self._Plan)
        return [Action(tool=a.tool, args=_safe_args(a.args_json), hypothesis=a.hypothesis)
                for a in out.actions]

    def synthesize(self, results: list[ToolResult]) -> list[Finding]:
        if not results:
            return []
        user = (f"{self._catalog_text()}\n\nTool output so far (JSON):\n"
                f"{_result_digest(results)}\n\n"
                "Synthesize findings. Every finding MUST cite the call_id(s) it rests on. "
                "Mark CONFIRMED only with >=2 independent sources; otherwise INFERRED. "
                "Surface contradictions explicitly.")
        out = self._parse(SENIOR_ANALYST_SYSTEM, user, self._Synth)
        return [self._to_finding(f) for f in out.findings]

    def evaluate(self, case_prompt: str, results: list[ToolResult],
                 findings: list[Finding]) -> Evaluation:
        user = (f"{self._catalog_text()}\n\nCase:\n{case_prompt}\n\n"
                f"Tool output so far (JSON):\n{_result_digest(results)}\n\n"
                f"Current findings:\n{json.dumps([f.to_dict() for f in findings], indent=2)}\n\n"
                "Evaluate: is the picture internally consistent? What gaps or "
                "contradictions remain? Propose concrete next tool calls to close them. "
                "Set done=true only if nothing meaningful remains.")
        out = self._parse(EVALUATE_SYSTEM, user, self._Eval)
        return Evaluation(
            consistent=out.consistent,
            gaps=list(out.gaps),
            contradictions=list(out.contradictions),
            next_actions=[Action(tool=a.tool, args=_safe_args(a.args_json),
                                 hypothesis=a.hypothesis) for a in out.next_actions],
            done=out.done,
        )

    def _to_finding(self, f: Any) -> Finding:
        try:
            conf = Confidence(f.confidence.strip().upper())
        except (ValueError, AttributeError):
            conf = Confidence.UNCERTAIN
        return Finding(
            title=f.title,
            description=f.description,
            confidence=conf,
            sources=list(f.sources),
            evidence_calls=list(f.evidence_calls),
            reasoning=f.reasoning or "",
        )


# Canonical catalog of the currently-implemented tools, for convenience.
DEFAULT_CATALOG: dict[str, str] = {
    "extract_mft_timeline": "Filesystem timeline from $MFT. args: mft_file, path_filter?",
    "get_amcache": "Program execution/presence evidence from Amcache.hve. args: amcache_hive",
    "analyze_prefetch": "Run-count/last-run execution evidence from Prefetch. args: prefetch_path",
    "parse_event_logs": "Windows event log triage (.evtx). args: evtx_file, event_id?",
    "mem_pslist": "Processes at capture time (Volatility 3). args: memory_image",
    "mem_netscan": "Network connections / C2 (Volatility 3). args: memory_image",
}
