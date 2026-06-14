# SIFT-Sentinel

**Autonomous, evidence-safe incident response for the SANS SIFT Workstation.**
A submission for the *Find Evil!* hackathon — making Protocol SIFT a fully
autonomous IR agent that triages at machine speed *without* hallucinating or
touching the original evidence.

> **Architecture:** Custom MCP Server (architectural trust boundary) + a
> self-correcting agent loop. See [`../STRATEGY.md`](../STRATEGY.md) for the full
> rationale and how each piece maps to the judging criteria.

---

## Why this design

The hackathon exists because Protocol SIFT hallucinates and because a careless
agent can spoliate evidence. SIFT-Sentinel answers both **architecturally**, not
with prompt pleading:

| Problem | Our structural answer |
|---|---|
| Agent could run a destructive command | The MCP server exposes **only typed, read-only tools**. There is no `execute_shell`. It *cannot* run `rm`/`dd`. |
| Evidence gets modified | Images mounted read-only; **SHA-256 verified before & after** every run. A hash change is a hard failure. |
| Hallucinated certainty | Tool output is **parsed to compact JSON before the LLM sees it**; findings carry `CONFIRMED`/`INFERRED` confidence and require ≥2 sources to be CONFIRMED. |
| "Trust me, it found X" | Every tool call is **audit-logged**; every finding cites the `call_id` that produced it. |
| Wrong on the first pass | A **self-correcting loop** evaluates its own output, detects gaps/contradictions, and re-runs — capped by `--max-iterations`. |

The two guardrail layers are kept distinct (the judges grade this): **architectural**
(MCP action space, read-only mounts, hashing — the agent cannot bypass) vs.
**prompt-based** (analyst discipline in the system prompt — quality only, never
relied on for integrity).

## Layout

```
src/sift_sentinel/
  mcp_server.py        # MCP server — the trust boundary; registers typed tools only
  runner.py            # no-shell, allowlist-only subprocess chokepoint
  evidence.py          # read-only handling, SHA-256 spoliation proof, path-traversal guard
  audit.py             # append-only JSONL audit log (one record per tool call)
  confidence.py        # CONFIRMED/INFERRED model + cross-source corroboration
  parsers.py           # raw tool dumps -> compact structured records
  tools/               # the agent's ENTIRE action space (registry.py = source of truth)
    amcache.py         #   get_amcache          (execution evidence)
    mft_timeline.py    #   extract_mft_timeline (filesystem timeline)
    prefetch.py        #   analyze_prefetch     (run-count execution evidence)
    event_logs.py      #   parse_event_logs     (.evtx triage)
    memory.py          #   mem_pslist/mem_netscan (Volatility 3 — disk↔memory)
  orchestrator/        # self-correcting loop + senior-analyst prompts
    loop.py            #   deterministic control flow (fan-out, max-iter, traces)
    anthropic_reasoner.py # Claude (claude-opus-4-8) supplies plan/synthesize/evaluate
  benchmark/score.py   # accuracy vs. ground truth; head-to-head vs. baseline
tests/                 # 29 tests, run without the real SIFT tools (fixtures)
```

## Install (on a SIFT Workstation)

```bash
./install.sh
source .venv/bin/activate
```

## Run

```bash
# Start the MCP server against mounted, read-only evidence:
sift-sentinel-server --evidence-root /mnt/case --audit audit/execution-log.jsonl
```

Point any MCP-capable agent (Claude Code, etc.) at the server. It will see only
`extract_mft_timeline` and `get_amcache` — no shell.

## Test

```bash
pytest            # 29 tests, no forensic tools required
python demo.py    # self-correcting loop end-to-end on bundled fixtures (stub reasoner)
```

`demo.py` drives the full loop with a deterministic stub reasoner over the bundled
sample data — it produces a `runs/progress.jsonl` trace and an `audit/` log so you
can see the audit-trail and self-correction behaviour without a SIFT VM or API key.

## Live run

With `ANTHROPIC_API_KEY` set and the SIFT tools on PATH, Claude reasons over the
real tools (the loop still owns control flow; the action space is still typed):

```bash
python run_live.py --evidence-root /mnt/case \
  --case "Triage suspected intrusion on WIN-HOST (disk + memory)." \
  --evidence-files '$MFT' Amcache.hve memory.raw
```

`--evidence-files` are SHA-256-verified before and after the run; a hash change
aborts with a `SpoliationError`.

## Status

Six typed forensic tools (disk + memory), security core, MCP server, confidence
model, self-correcting loop, **live Claude reasoner** (`claude-opus-4-8`, adaptive
thinking, structured output), and benchmark harness — all tested (29 tests).
Remaining: run against a real ground-truth image and produce the head-to-head
accuracy report vs. the Protocol SIFT baseline (`../STRATEGY.md` §6, Phase 4).

## License

MIT — see [`LICENSE`](LICENSE).
