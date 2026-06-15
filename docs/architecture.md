# SIFT-Sentinel — Architecture

This document describes how SIFT-Sentinel is put together, where its trust
boundary sits, and why each major decision was made. It complements the diagram
in [`architecture.png`](architecture.png).

- **Architectural pattern (one of the four hackathon approaches):** **Custom MCP
  Server.** Claude Code is the reasoning agent; a purpose-built MCP server is the
  trust boundary that decides what the agent can and cannot do.
- **Central claim:** evidence integrity and citation discipline are enforced by
  *what code exists*, not by instructions the model is asked to follow.

---

## 1. The picture

```
┌───────────────────────────────────────────────────────────────────────┐
│  CLAUDE CODE  (reasoning agent)                                         │
│  • Analyst instructions from CLAUDE.md     • Self-corrects, re-runs      │
│  • Sequences tools broad → narrow            narrowly on a gap           │
│  • Cites every finding by call_id          • Confidence model:           │
│                                              CONFIRMED/INFERRED/          │
│                                              UNCERTAIN/CONTRADICTION      │
│  ── Prompt-based guardrails: improve quality, NOT relied on for safety ──│
└───────────────────────────────────────────────────────────────────────┘
                    │  MCP  (stdio / JSON-RPC)   ▲
                    ▼                            │  typed, structured results
┌═════════════════════════════════════════════════════════════════════════┐
║  SIFT-SENTINEL MCP SERVER            ▰ TRUST BOUNDARY ▰                    ║
║  ───────────────────────────────────────────────────────────────────────║
║  • 18 typed, read-only tool functions — no generic command tool           ║
║  • NO execute_shell — destructive actions are not expressible             ║
║  • Allowlist-only subprocess runner — argv list, never shell=True         ║
║  • Path-traversal guard — every path resolved inside an evidence root     ║
║  • SHA-256 hash before & after each call — spoliation detection           ║
║  • Parse raw output → compact typed JSON (model never sees raw CSV)        ║
║  • Byte budget + record cap + MFT digest (200k+ rows → curated set)        ║
║  • Parsed-artifact cache keyed by evidence SHA-256                         ║
║                                                                           ║
║   ╳ execute_shell  (does not exist — there is nothing to misuse)          ║
║                                                                           ║
║   ── Architectural guardrails: enforced by code, cannot be bypassed ──    ║
║                                                                  │        ║
║   append-only audit log (execution-log.jsonl) ───────────────►  │        ║
└═══════════════════════════════════════════════════════════════│═════════┘
                    │  read-only subprocess                       │
                    ▼  (allowlisted argv)                         ▼  OUTPUT PIPELINE
┌───────────────────────────────────────────────────┐   ┌──────────────────────────┐
│  SIFT WORKSTATION TOOLS  (Linux-native)             │   │ 1. audit log (JSONL):    │
│  MFTECmd · AmcacheParser · libscca/sccainfo ·       │   │    one record per call    │
│  EvtxECmd · AppCompatCacheParser · SrumECmd ·       │   │ 2. sift-sentinel-report   │
│  RegRipper/rip.pl · YARA · Volatility 3             │   │    (offline, after run)   │
└───────────────────────────────────────────────────┘   │ 3. triage report with     │
                    │  read-only (ro,noexec,nodev)        │    call_id citations      │
                    ▼                                      └──────────────────────────┘
┌───────────────────────────────────────────────────┐
│  EVIDENCE  (mounted read-only, hashed before/after) │
│  /mnt/cases  — NTFS disk image (base-dc E01)        │
│  /evidence   — RAM capture (.img)                   │
└───────────────────────────────────────────────────┘
```

---

## 2. Components

### 2.1 Claude Code — the reasoning agent

Claude Code drives the investigation by calling the MCP tools. Its behaviour is
shaped by [`CLAUDE.md`](../CLAUDE.md) and the `/triage` workflow, which set the
sequencing (broad → narrow), corroboration, contradiction-surfacing, and
citation rules. Crucially, **this layer carries only *prompt-based* guardrails**:
it improves the quality of reasoning, but the system never depends on the model
obeying it for evidence integrity.

### 2.2 SIFT-Sentinel MCP server — the trust boundary

`src/sift_sentinel/mcp_server.py` registers exactly **18 typed, read-only tool
functions**. Every call is handled by shared, audited plumbing in
`tools/base.py` (`audited_run` / `audited_csv_run`), which guarantees that each
invocation is hashed, executed through the allowlist runner, parsed, summarised,
size-bounded, and written to the audit log — uniformly, by construction.

This is the only place that touches evidence or spawns binaries. Adding a tool
is a deliberate, reviewable change to the boundary (wrapper → typed MCP function
→ `tools/registry.py` entry → `runner.ALLOWED_BINARIES` entry).

### 2.3 SIFT Workstation tools — the underlying binaries

The server shells out (read-only) to Linux-native forensic tools so the whole
pipeline runs on a stock SIFT Workstation with no Windows runtime: Zimmerman
tools (MFTECmd, AmcacheParser, EvtxECmd, AppCompatCacheParser, SrumECmd),
`sccainfo`/libscca for Prefetch, `rip.pl`/RegRipper for the registry, YARA, and
Volatility 3 for memory.

### 2.4 Evidence — read-only data sources

Images are mounted `ro,noexec,nodev`. The disk lives at `/mnt/cases` (an E01
mounted via `ewfmount` → NTFS), and the RAM capture at `/evidence/<image>.img`.

### 2.5 Output pipeline

The append-only audit log (`audit/execution-log.jsonl`) is written as the
investigation runs. After the investigation, the offline `sift-sentinel-report`
command renders a findings report from the narrative plus the audit log. Report
generation is deliberately **out of band** — writing a report is a write
operation, and keeping it separate preserves the read-only action space.

---

## 3. The two guardrail layers (kept distinct on purpose)

| | Architectural guardrails | Prompt-based guardrails |
|---|---|---|
| **Where** | MCP action space, allowlist runner, read-only mounts, hashing | Analyst discipline in `CLAUDE.md` |
| **Examples** | No `execute_shell`; argv-only runner; path guard; SHA-256 before/after | Confidence tagging; broad→narrow sequencing; "cite every finding" |
| **Enforced by** | What code exists — the model cannot get around it | The model choosing to follow instructions |
| **Relied on for integrity?** | **Yes** | **No** — quality only |

With a shell-exposed agent, "do not modify evidence" is a request the model can
ignore. Here the destructive action is **not present in the action space**, so
there is nothing to ignore. That distinction is the whole point of choosing the
Custom MCP Server pattern.

---

## 4. Evidence-integrity controls (architectural)

1. **No destructive verb.** There is no `execute_shell` and no generic command
   tool. Only 18 typed, read-only functions exist.
2. **Allowlist-only runner** (`runner.py`). Every external execution funnels
   through one function that takes an argument *list*, refuses any binary not on
   `ALLOWED_BINARIES`, and never uses `shell=True`. This collapses the
   destructive-command and command-injection surface to one small, auditable
   chokepoint.
3. **Path-traversal guard** (`evidence.py`, `assert_within_any`). Every
   tool-supplied path is resolved and checked to be inside an allowed evidence
   root before use. Multiple roots are supported (e.g. disk + a separately
   mounted RAM capture) without widening to the whole filesystem.
4. **Hash invariance.** Each file-backed artifact is SHA-256 hashed before and
   after a call. A changed post-call hash is returned as an integrity error and
   recorded; whole-investigation `EvidenceSet` checks corroborate that nothing
   was modified.
5. **Read-only mounts.** `ro,noexec,nodev` makes spoliation impossible at the
   filesystem layer, independent of anything the server does.

---

## 5. Accuracy & output handling (architectural answer to hallucination)

- **Parse before the model sees anything.** A full `$MFT` is ~236k records and
  ~60 MB of CSV. The server parses raw output into compact typed JSON, so the
  model reasons over signal instead of doing text-extraction over a truncated
  dump — a known hallucination source.
- **Byte budget + record cap + MFT digest** (`tools/base.py`,
  `tools/mft_timeline.py`). A row cap alone still overran the transport because
  *record width*, not count, is what matters. A hard byte budget guarantees the
  payload fits regardless of width, and the digest returns the
  forensically-interesting records (executables in user-writable paths,
  masquerading double extensions, ADS, deleted executables) instead of volume.
- **Parsed-artifact cache** (`cache.py`), keyed by evidence SHA-256. Expensive
  MFT/EVTX/Amcache/ShimCache/SRUM parses are reused safely when the same evidence
  is queried again with a different filter.
- **Confidence as a data model** (`confidence.py`). `CONFIRMED` requires ≥2
  supporting `call_id`s in the data structure, so an unsupported confident claim
  *cannot be represented*. This is the direct structural answer to hallucinated
  findings.

---

## 6. Auditability

Every tool call writes one immutable JSON Lines record (`audit.py`,
`AuditRecord`) with: `call_id`, `ts` (UTC ISO-8601), `tool`, `args`,
`input_hash`, `binary`, `exit_code`, `duration_ms`, `output_summary`, `tokens`,
`error`, and integrity fields. Properties of this log:

- **Append-only.** JSON Lines is append-only by nature and never needs
  rewriting. `call_id`s resume across server restarts so they stay unique, and a
  duplicate-detection helper guards the citation contract.
- **Traceable.** Every finding cites the `call_id` that produced it; the report
  generator flags missing or duplicate citations.
- **Token accounting, honestly.** A read-only MCP server cannot observe the
  model's own prompt/completion usage, so the `tokens` field records the one cost
  it *can* measure at the boundary: the deterministic, offline-estimated token
  size of the response payload each call returns into the agent's context
  (`tokens.py`), measured over the exact post-budget/post-digest payload the
  agent receives.

---

## 7. Data flow of a single tool call

1. Agent calls a typed function over MCP (e.g.
   `extract_mft_timeline(mft_file=…, path_filter=…)`).
2. The server resolves the path inside an evidence root (path guard) and computes
   the pre-call SHA-256.
3. The allowlist runner executes the underlying binary with an argv list (no
   shell). Cached parses short-circuit the subprocess.
4. Raw output is parsed into typed records; an optional `post` filter and a
   `finalize` step (e.g. the MFT digest, the Amcache known-good tally) shape the
   final agent-facing payload.
5. The response is bounded by the record cap and byte budget.
6. The post-call SHA-256 is compared to the pre-call hash; a mismatch becomes an
   integrity error.
7. One audit record is written (timing, hashes, binary, summary, token estimate),
   and the structured result — tagged with its `call_id` — is returned to the
   agent.

---

## 8. Guardrail bypass testing

Both architectural guardrail layers were tested for bypass resistance during
development. The results below are reproducible from the test suite
(`tests/test_runner.py`, `tests/test_evidence.py`, `tests/test_integrity.py`).

### Allowlist runner — non-allowlisted binary

Passing any binary not in `ALLOWED_BINARIES` raises `DisallowedBinaryError`
before a subprocess is spawned:

```python
>>> from sift_sentinel.runner import run_tool
>>> run_tool(["bash", "-c", "rm -rf /mnt/cases"])
DisallowedBinaryError: binary 'bash' is not on the allowlist; refusing to execute
```

Shell injection via argument manipulation is equally blocked — `shell=False` is
enforced and arguments are passed as a list, so a payload in an argument is
handed to the binary as a literal string and never interpreted by a shell:

```python
>>> run_tool(["MFTECmd", "--input", "/mnt/cases/$MFT; rm -rf /"])
# '; rm -rf /' is a literal argument to MFTECmd — no shell sees it.
# MFTECmd rejects the malformed path. No execution outside the allowlist.
```

### Path-traversal guard — escape attempt

Every tool-supplied path is resolved with `Path.resolve()` (which follows
symlinks) and checked against the allowed evidence roots before the binary is
called. A path that escapes the root is rejected:

```python
>>> from sift_sentinel.evidence import assert_within_any
>>> assert_within_any("/mnt/cases/../../etc/passwd", ["/mnt/cases"])
EvidenceRootViolation: '/etc/passwd' is outside all allowed roots: ['/mnt/cases']

>>> # symlink at /mnt/cases/evil -> /etc/
>>> assert_within_any("/mnt/cases/evil/passwd", ["/mnt/cases"])
EvidenceRootViolation: '/etc/passwd' is outside all allowed roots: ['/mnt/cases']
```

### SHA-256 integrity — post-call hash mismatch

If a file-backed artifact changes between the pre-call and post-call hash (not
possible with `ro,noexec,nodev` mounts in production, but tested with a
deliberately modified fixture copy in `tests/test_integrity.py`), the tool
returns an integrity error logged in the audit record:

```
integrity_error: input hash changed after call
  pre=a3f9…  post=9c21…
  evidence may have been modified — call result untrusted
```

---

## 9. Why this pattern, in one paragraph

We chose a Custom MCP Server over a Direct Agent Extension, a Multi-Agent
Framework, or an Alternative Agentic IDE because it is the only approach where
evidence integrity is a property of the code rather than of the model's
behaviour. Typed functions let the server — not the model — decide which binaries
run and with which arguments, and let the server own the output handling where
the accuracy work happens. The result is an agent that can reason freely over
real disk and memory evidence while being *structurally incapable* of spoliating
it or asserting an uncited finding.

---

## See also

- [`architecture.png`](architecture.png) — the diagram this document describes
- [`tools.md`](tools.md) — per-tool reference (signatures, parameters, returns)
- [`dataset.md`](dataset.md) — evidence dataset documentation and findings
- [`installation.md`](installation.md) — install, mount evidence, run, troubleshoot
- [`devpost_story.md`](devpost_story.md) — the written project description
- [`../README.md`](../README.md) — setup, the 18 tools, and try-it-out steps
- [`../CLAUDE.md`](../CLAUDE.md) — the analyst instructions (prompt-based layer)
- [`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md) — a real run's findings with `call_id` citations
```
