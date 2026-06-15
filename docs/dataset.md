# Evidence Dataset Documentation

This documents the case data SIFT-Sentinel was tested against, where it came
from, and what the agent found. No synthetic or self-authored evidence was used
for the findings below — only the real SANS-provided case image.

---

## Dataset

SIFT-Sentinel was developed and tested against the **SANS Find Evil!
"SRL-2018 Compromised Enterprise Network"** dataset — the case data provided by
SANS for the hackathon.

| Artifact | File | Source | Mounted at |
|---|---|---|---|
| **Disk** | `base-dc-cdrive.E01` | SANS Find Evil! (SRL-2018) | `/mnt/cases` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| **Memory** | `SRL-2018/base-dc-memory.7z` → `base-dc-memory.img` | SANS Find Evil! (SRL-2018) | `/evidence/base-dc-memory.img` |

- **Host:** `base-dc.shieldbase.lan` — a **Windows Server 2016 domain controller**.
- **Acquisition note:** the image was captured by an IR responder, which is
  directly relevant to attribution (see findings).
- **How to obtain:** the SRL-2018 evidence is distributed by SANS to Find Evil!
  participants. It is **not redistributed in this repository** — point the agent
  at your own copy after mounting it read-only.

---

## Key artifacts read

All under `/mnt/cases` unless noted:

- `$MFT` — NTFS master file table (filesystem timeline)
- `Windows/appcompat/Programs/Amcache.hve` — program execution/presence
- `Windows/Prefetch/` — Prefetch `.pf` files (disabled on this DC; see findings)
- `Windows/System32/config/SYSTEM` — ShimCache / services
- `Windows/System32/config/SOFTWARE` — autoruns / app-id resolution
- `Windows/System32/sru/SRUDB.dat` — SRUM resource/network usage
- `Windows/System32/winevt/Logs/Security.evtx` — logons (4624/4625)
- `Windows/System32/winevt/Logs/System.evtx` — service installs (7045)
- `/evidence/base-dc-memory.img` — RAM capture (Volatility 3)

---

## What the agent found

Full report with `call_id` citations:
[`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md).
Raw tool execution log:
[`../audit/execution-log.jsonl`](../audit/execution-log.jsonl).

### CONFIRMED (≥2 independent sources agree)

- **F-Response remote-forensics agent and `Mnemosyne.sys` kernel driver staged in
  `C:\Windows` on 2018-09-06/07.**
  - `subject_srv.exe` — corroborated by the MFT (`call-000025`, size 1,173,936
    bytes) **and** a 7045 service-install event at 22:11:15 (`call-000023`),
    timestamps agreeing to sub-second. `created` (09-06) > PE compile date
    (2018-04-10) = dropped-binary signature.
  - `Mnemosyne.sys` — MFT (`call-000024`) **and** a 7045 install at 20:30:59
    (`call-000023`); installed 3× within 5 minutes.
  - **Attribution:** both are IR / memory-acquisition tooling (F-Response Subject
    + its physical-memory driver), consistent with the responder who captured
    `base-dc-memory.img` — **not** adversary activity. Same TTP an adversary would
    use, attributed correctly via context.

### INFERRED (single source, explicitly flagged)

- **Sustained failed-logon series against the DC** — 163 × event 4625, account
  `BASE-HUNT$`, source `172.16.5.25`, logon type 3, ~10-minute cadence over ~27 h
  (`call-000022`). `172.16.5.25` never appears in a successful logon. Single
  source → INFERRED, with the confirming steps named (System.evtx Netlogon/trust
  errors, machine-account password history, asset-inventory lookup of the source).

### CONTRADICTION (surfaced, not hidden)

- **Memory analysis returned nothing despite a valid image.** `mem_pslist`
  (`call-000019`) and `mem_netscan` (`call-000020`) both returned **0 records with
  `error: null`**, yet the image was located and hashed. A live capture must
  contain processes — 0 is not a credible "clean" result. Flagged as a
  tooling/symbol-resolution failure (a blind spot), **not** evidence of absence;
  C2/injection hypotheses are recorded as **untested**, not cleared.

---

## Reproducibility

1. Mount the two artifacts read-only (see the
   [README "Try it out"](../README.md#try-it-out) steps).
2. Restart Claude Code so the `sift-sentinel` MCP server and its 18 tools appear.
3. Run `/triage` against `/mnt/cases` with memory at
   `/evidence/base-dc-memory.img`.

Every finding traces back to the `call_id`s recorded in
`audit/execution-log.jsonl`, so a judge can locate the exact tool execution
behind any claim above.

---

## See also

- [`../README.md`](../README.md) — setup, the 18 tools, and try-it-out steps
- [`architecture.md`](architecture.md) — how the read-only pipeline is enforced
- [`tools.md`](tools.md) — per-tool reference
- [`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md)
  — the full findings report
