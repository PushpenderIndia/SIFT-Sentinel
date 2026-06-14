# SIFT-Sentinel

**Autonomous, evidence-safe incident response for the SANS SIFT Workstation.**
A submission for the *Find Evil!* hackathon — making Protocol SIFT a fully
autonomous IR agent that triages at machine speed *without* hallucinating or
touching the original evidence.

> **Architecture:** Custom MCP Server (architectural trust boundary) + a
> self-correcting agent loop. 

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

## Deploying on the SIFT Workstation (end-to-end)

The target platform is the SANS SIFT Workstation. On an **x86-64 host (Windows or
Linux)** the OVA runs natively in VMware/VirtualBox — full speed (Apple Silicon
Macs would emulate x86 slowly; use an Intel/Windows host).

### 1. Get the case data (SANS *Find Evil!* sample data)
Use the **`SRL-2018`** scenario — it has paired **disk + memory for the same
hosts**, which is what enables the disk↔memory correlation this agent is built
for. Smallest complete unit:

| File | Size | Why |
|---|---|---|
| `base-dc-memory.7z` | 808 MB | Domain-controller RAM — Volatility `pslist`/`netscan`. Download this first. |
| `base-dc-cdrive.E01` | 11.5 GB | Matching DC disk — MFT, Amcache, Prefetch, EVTX. |

Optional second host for richer endpoint execution artifacts:
`base-wkstn-01-c-drive.E01` (15.8 GB). Two hosts max — don't sprawl.

### 2. Run the SIFT VM
1. Install **VMware Workstation Player** (free) or **VirtualBox**.
2. **File → Import** the SIFT `.ova`; give it **8 GB+ RAM**, **4 vCPU**.
3. Keep the case data on the host and expose it via a **shared folder** (don't
   copy 12 GB into the VM). Login: `sansforensics` / `forensics`.

### 3. Install the Protocol SIFT baseline (the accuracy scoreboard)
```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```
Run it once on the case data and capture its output — its hallucinations are the
baseline we measure against (`benchmark/score.py`).

### 4. Install SIFT-Sentinel
```bash
./install.sh && source .venv/bin/activate
pytest && python demo.py        # verify it runs on the SIFT box
```

### 5. Mount the evidence READ-ONLY (as root: `sudo su -`)
```bash
mkdir -p /mnt/ewf /mnt/case /evidence
ewfmount /path/to/base-dc-cdrive.E01 /mnt/ewf            # E01 -> raw
mount -o ro,loop,show_sys_files /mnt/ewf/ewf1 /mnt/case  # NTFS, read-only
7z x base-dc-memory.7z -o/evidence/                      # -> base-dc-memory.mem
```
Artifacts then live at: `/mnt/case/$MFT`,
`/mnt/case/Windows/appcompat/Programs/Amcache.hve`,
`/mnt/case/Windows/Prefetch/`, the `.evtx` files under
`/mnt/case/Windows/System32/winevt/Logs/`, and `/evidence/base-dc-memory.mem`.

### 6. Run the agent against real evidence
```bash
export ANTHROPIC_API_KEY=...
python run_live.py --evidence-root /mnt/case \
  --case "Triage suspected APT intrusion on the domain controller (disk + memory)." \
  --evidence-files '$MFT' Windows/appcompat/Programs/Amcache.hve
```
Then score against the baseline with `benchmark/score.py` using a ground-truth
answer key for the case.

## Status

Six typed forensic tools (disk + memory), security core, MCP server, confidence
model, self-correcting loop, **live Claude reasoner** (`claude-opus-4-8`, adaptive
thinking, structured output), and benchmark harness — all tested (29 tests).
Remaining: run against a real ground-truth image and produce the head-to-head
accuracy report vs. the Protocol SIFT baseline (`../STRATEGY.md` §6, Phase 4).

## License

MIT — see [`LICENSE`](LICENSE).
