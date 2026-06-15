# Evidence Dataset Documentation

This documents the case data SIFT-Sentinel was tested against, where it came
from, and what the agent found. No synthetic or self-authored evidence was used
for the findings below — only the real SANS-provided case images.

## Dataset

SIFT-Sentinel was developed and tested against the **SANS Find Evil!
"SRL-2018 Compromised Enterprise Network"** dataset — the case data provided by
SANS for the hackathon.

The agent has now been run end-to-end against **two host images from this
dataset** — the domain controller (`base-dc`) and the file server (`base-file`).
Each run is fully self-contained, with its own audit log and triage report. The
`base-file` run is the **most recently added** report set.

### Evaluation runs at a glance

| # | Host | Disk image | Memory image | Audit log | Triage report |
|---|---|---|---|---|---|
| 1 | `base-dc.shieldbase.lan` (Win Server 2016 **domain controller**) | `base-dc-cdrive.E01` | `base-dc-memory.7z` → `.img` | [`execution-log-base-dc.jsonl`](../audit/execution-log-base-dc.jsonl) | [`triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md) |
| 2 | `base-file.shieldbase.lan` (Win Server **file server**) | `base-file-cdrive.E01` | `base-file-memory.7z` → `.img` | [`execution-log-base-file.jsonl`](../audit/execution-log-base-file.jsonl) | [`triage-report-base-file.md`](../audit/triage-report-base-file.md) |

Both hosts belong to the same `shieldbase.lan` domain, so the two runs corroborate
each other (e.g. the same `BASE-HUNT` source `172.16.5.25` and the same F-Response /
`Mnemosyne.sys` IR tooling appear in both).

### Artifacts per run

| Run | Artifact | File | Mounted at |
|---|---|---|---|
| `base-dc` | Disk | `base-dc-cdrive.E01` | `/mnt/cases` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `base-dc` | Memory | `SRL-2018/base-dc-memory.7z` → `base-dc-memory.img` | `/evidence/base-dc-memory.img` |
| `base-file` | Disk | `base-file-cdrive.E01` | `/mnt/file-case` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `base-file` | Memory | `SRL-2018/base-file-memory.7z` → `base-file-memory.img` | `/evidence/base-file-memory.img` |

- **Acquisition note:** the images were captured by an IR responder, which is
  directly relevant to attribution (see findings).
- **How to obtain:** the SRL-2018 evidence is distributed by SANS to Find Evil!
  participants. It is **not redistributed in this repository** — point the agent
  at your own copy after mounting it read-only.

---

## Key artifacts read

Paths below are for the `base-dc` run (all under `/mnt/cases` unless noted); the
`base-file` run reads the same set of artifacts under `/mnt/file-case` with memory
at `/evidence/base-file-memory.img`:

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

## What the agent found — Run 1 (`base-dc`)

Full report with `call_id` citations:
[`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md).
Raw tool execution log:
[`../audit/execution-log-base-dc.jsonl`](../audit/execution-log-base-dc.jsonl).

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

## What the agent found — Run 2 (`base-file`, newly added)

Full report with `call_id` citations:
[`../audit/triage-report-base-file.md`](../audit/triage-report-base-file.md).
Raw tool execution log:
[`../audit/execution-log-base-file.jsonl`](../audit/execution-log-base-file.jsonl).
Demo recording of this run:
[`sans-2018-base-file-demo.mp4`](sans-2018-base-file-demo.mp4).

### CONFIRMED (≥2 independent sources agree)

- **"Microsoft Advanced API 32/64" fake services backed by `msadvapi2_*.exe` and
  a WinPcap `npf.sys` packet-filter driver.** The installers
  (`install_msadvapi2_64.exe` / `_32.exe`) were staged in
  `ProgramData\staging\install_wormhole\` and the payloads extracted to
  `Program Files (x86)\Microsoft Advanced API 32/64\` — corroborated by the MFT
  (`call-000045`/`call-000047`) **and** 7045 service-install events
  (`call-000044`), with rogue CA certs (`lariatca.cer`, `NotVerisign.cer`,
  `NewNotVeriSign.cer`) dropped alongside on 2018-04-26.
- **Same IR tooling as `base-dc`** — F-Response Subject service and the
  `Mnemosyne.sys` kernel driver installed on 2018-09-06 (`call-000044`/`call-000046`),
  cross-corroborating the `base-dc` run and the same responder attribution.

### INFERRED (single source, explicitly flagged)

- **`rsydow-a` 2-minute beacon loop** — 160+ Type 3 logons from `172.16.4.4`
  starting 2018-09-07 03:07:29 UTC running past 08:10 UTC, plus off-subnet
  `cbarton`/`cbarton-a` logons from `10.10.x.x` against a `172.16.0.0/12`
  environment (`call-000042`). Single source → INFERRED.

### CONTRADICTION (surfaced, not hidden)

- **Memory analysis again returned 0 records on a valid, hashed image**
  (`call-000040`/`call-000041`) — same Volatility OS-profile mismatch as the
  `base-dc` run; recorded as a tooling blind spot, not evidence of absence.

---

## Reproducibility

Each run is reproduced independently. Mount the relevant artifacts read-only
(see the [README "Try it out"](../README.md#try-it-out) steps), restart Claude
Code so the `sift-sentinel` MCP server and its 18 tools appear, then:

| Run | Command |
|---|---|
| `base-dc` | `/triage` against `/mnt/cases` with memory at `/evidence/base-dc-memory.img` |
| `base-file` | `/triage` against `/mnt/file-case` with memory at `/evidence/base-file-memory.img` |

Every finding traces back to the `call_id`s recorded in that run's audit log
(`audit/execution-log-base-dc.jsonl` for `base-dc`,
`audit/execution-log-base-file.jsonl` for `base-file`), so a judge can locate the
exact tool execution behind any claim above.

---

## See also

- [`../README.md`](../README.md) — setup, the 18 tools, and try-it-out steps
- [`architecture.md`](architecture.md) — how the read-only pipeline is enforced
- [`tools.md`](tools.md) — per-tool reference
- [`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md)
  — the full findings report
