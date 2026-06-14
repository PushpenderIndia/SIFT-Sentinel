"""The self-correcting execution loop.

Framework-agnostic: the actual reasoning model is injected as a ``Reasoner`` so
the same loop works under Claude Code, a raw Anthropic API call, or a stub for
tests. The loop owns the *control flow* the judges care about:

    PLAN -> EXECUTE -> EVALUATE -> DECIDE -> CORRECT -> (loop) -> REPORT

with a hard ``max_iterations`` cap, graceful degradation, and an
iteration-over-iteration trace written to ``progress.jsonl`` (deliverable #8).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from ..confidence import Finding, corroborate
from ..tools.base import ToolContext, ToolResult


# A tool is a callable: (ctx, **args) -> ToolResult. The registry is the action space.
ToolFn = Callable[..., ToolResult]


@dataclass
class Action:
    tool: str
    args: dict[str, Any]
    hypothesis: str = ""


@dataclass
class Evaluation:
    consistent: bool
    gaps: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    next_actions: list[Action] = field(default_factory=list)
    done: bool = False


class Reasoner(Protocol):
    """The pluggable model. Implementations call an LLM; the stub is deterministic."""

    def plan(self, case_prompt: str) -> list[Action]:
        """Initial tool sequence from the case prompt."""

    def evaluate(self, case_prompt: str, results: list[ToolResult],
                 findings: list[Finding]) -> Evaluation:
        """Inspect state, decide consistency / gaps / next actions."""

    def synthesize(self, results: list[ToolResult]) -> list[Finding]:
        """Turn accumulated tool results into findings."""


@dataclass
class LoopConfig:
    max_iterations: int = 5
    progress_path: str = "runs/progress.jsonl"


class SelfCorrectingLoop:
    def __init__(self, ctx: ToolContext, tools: dict[str, ToolFn],
                 reasoner: Reasoner, config: Optional[LoopConfig] = None):
        self.ctx = ctx
        self.tools = tools
        self.reasoner = reasoner
        self.config = config or LoopConfig()
        self._progress = Path(self.config.progress_path)
        self._progress.parent.mkdir(parents=True, exist_ok=True)
        self._iter = 0

    # --- progress trace ---------------------------------------------------
    def _log(self, event: str, **payload: Any) -> None:
        rec = {
            "iteration": self._iter,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **payload,
        }
        with self._progress.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    # --- execution --------------------------------------------------------
    def _run_action(self, action: Action) -> Optional[ToolResult]:
        fn = self.tools.get(action.tool)
        if fn is None:
            self._log("tool_unavailable", tool=action.tool, hypothesis=action.hypothesis)
            return None
        result = fn(self.ctx, **action.args)
        self._log("tool_call", tool=action.tool, args=action.args,
                  hypothesis=action.hypothesis, call_id=result.call_id,
                  record_count=len(result.records), error=result.error)
        return result

    def run(self, case_prompt: str) -> dict[str, Any]:
        """Drive the case to internal consistency or the iteration cap.

        Returns a report dict: findings, iteration count, stop reason, and the
        progress-trace path. Never raises on a single failed tool — it logs and
        keeps going (graceful degradation).
        """
        self._log("plan_start", case=case_prompt)
        actions = self.reasoner.plan(case_prompt)
        results: list[ToolResult] = []
        stop_reason = "converged"

        while True:
            self._iter += 1
            if self._iter > self.config.max_iterations:
                stop_reason = "max_iterations"
                self._log("halt", reason=stop_reason)
                break

            # EXECUTE this iteration's actions
            for action in actions:
                r = self._run_action(action)
                if r is not None:
                    results.append(r)

            # SYNTHESIZE + EVALUATE
            findings = corroborate(self.reasoner.synthesize(results))
            ev = self.reasoner.evaluate(case_prompt, results, findings)
            self._log("evaluate", consistent=ev.consistent, done=ev.done,
                      gaps=ev.gaps, contradictions=ev.contradictions,
                      n_next=len(ev.next_actions))

            # DECIDE
            if ev.done or (ev.consistent and not ev.next_actions):
                stop_reason = "converged"
                self._log("halt", reason=stop_reason)
                break

            # CORRECT: feed next actions into the following iteration
            actions = ev.next_actions

        final = corroborate(self.reasoner.synthesize(results))
        report = {
            "case": case_prompt,
            "iterations": self._iter,
            "stop_reason": stop_reason,
            "findings": [f.to_dict() for f in final],
            "progress_trace": str(self._progress),
        }
        self._log("report", n_findings=len(final), stop_reason=stop_reason)
        return report
