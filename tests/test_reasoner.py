"""AnthropicReasoner mapping logic, with the single API seam mocked.

We don't hit the network. We override ``_parse`` to return canned structured
objects and assert the reasoner maps them onto the loop's dataclasses correctly,
including args-JSON decoding and the CONFIRMED-needs-two-sources rule.
"""
from types import SimpleNamespace

from sift_sentinel.confidence import Confidence
from sift_sentinel.orchestrator.anthropic_reasoner import AnthropicReasoner, DEFAULT_CATALOG
from sift_sentinel.tools.base import ToolResult


def make_reasoner(canned):
    r = AnthropicReasoner(client=None, tool_catalog=DEFAULT_CATALOG,
                          evidence_hint="/mnt/case")

    def fake_parse(system, user, schema):
        if schema is r._Plan:
            return canned["plan"]
        if schema is r._Synth:
            return canned["synth"]
        if schema is r._Eval:
            return canned["eval"]
        raise AssertionError("unexpected schema")

    r._parse = fake_parse
    return r


def test_plan_decodes_args_json():
    canned = {"plan": SimpleNamespace(actions=[
        SimpleNamespace(tool="get_amcache",
                        args_json='{"amcache_hive": "/mnt/case/Amcache.hve"}',
                        hypothesis="what ran?")])}
    r = make_reasoner(canned)
    actions = r.plan("triage host")
    assert len(actions) == 1
    assert actions[0].tool == "get_amcache"
    assert actions[0].args == {"amcache_hive": "/mnt/case/Amcache.hve"}


def test_synthesize_maps_confidence_and_enforces_two_sources():
    canned = {"synth": SimpleNamespace(findings=[
        # Claims CONFIRMED but lists one source -> Finding downgrades to INFERRED.
        SimpleNamespace(title="evil.exe executed", description="ran from temp",
                        confidence="CONFIRMED", sources=["amcache"],
                        evidence_calls=["call-000001"], reasoning="amcache only"),
    ])}
    r = make_reasoner(canned)
    findings = r.synthesize([ToolResult(tool="get_amcache", call_id="call-000001",
                                        records=[{"x": 1}], summary="s")])
    assert findings[0].confidence == Confidence.INFERRED  # auto-downgraded


def test_evaluate_maps_next_actions():
    canned = {"eval": SimpleNamespace(
        consistent=False, gaps=["no disk corroboration"], contradictions=[],
        next_actions=[SimpleNamespace(tool="extract_mft_timeline",
                                      args_json='{"mft_file": "/mnt/case/$MFT"}',
                                      hypothesis="dropped before run?")],
        done=False)}
    r = make_reasoner(canned)
    ev = r.evaluate("case", [], [])
    assert ev.consistent is False
    assert ev.done is False
    assert ev.next_actions[0].tool == "extract_mft_timeline"
    assert ev.next_actions[0].args == {"mft_file": "/mnt/case/$MFT"}


def test_synthesize_empty_results_short_circuits():
    r = make_reasoner({})
    assert r.synthesize([]) == []
