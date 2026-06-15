# Evidence Dataset Documentation

This documents the case data SIFT-Sentinel was tested against, where it came
from, and what the agent found. No synthetic or self-authored evidence was used
for the findings below — only the real SANS-provided case images.

## Dataset

SIFT-Sentinel has been run end-to-end against **three host images across two
independent cases**: two hosts from the **SANS Find Evil! "SRL-2018 Compromised
Enterprise Network"** dataset (provided by SANS for the hackathon), and two hosts
from **DFIR Madness Case 001 "The Stolen Szechuan Sauce"** (public case). Each
run is fully self-contained with its own audit log, triage report, and accuracy
score. The Szechuan Sauce run is the **primary scored evaluation** (F1=0.818,
0% hallucination rate).

### Evaluation runs at a glance

| # | Case | Host | OS | Disk image | Memory image | Audit log | Triage report |
|---|---|---|---|---|---|---|---|
| 1 | SANS SRL-2018 | `base-dc.shieldbase.lan` — **domain controller** | Win Server 2016 | `base-dc-cdrive.E01` | `base-dc-memory.7z` → `.img` | [`execution-log-base-dc.jsonl`](../audit/execution-log-base-dc.jsonl) | [`triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md) |
| 2 | SANS SRL-2018 | `base-file.shieldbase.lan` — **file server** | Win Server 2016 | `base-file-cdrive.E01` | `base-file-memory.7z` → `.img` | [`execution-log-base-file.jsonl`](../audit/execution-log-base-file.jsonl) | [`triage-report-base-file.md`](../audit/triage-report-base-file.md) |
| 3 | DFIR Madness Case 001 | `CITADEL-DC01` — **domain controller** | Win Server 2012 R2 | `CITADEL-DC01-C.E01` | `citadel-dc01-memory.img` | [`execution-log-szechuan.jsonl`](../audit/execution-log-szechuan.jsonl) | [`triage-report-citadel-dc01-2026-06-15.md`](../audit/triage-report-citadel-dc01-2026-06-15.md) |
| 4 | DFIR Madness Case 001 | `DESKTOP-SDN1RPT` — **victim desktop** | Win 10 Enterprise | `DESKTOP-SDN1RPT-C.E01` | `desktop-sdn1rpt-memory.img` | (included in run 3 log above — calls 000026–000031) | (included in run 3 report above — Desktop Pivot section) |

Runs 1 and 2 belong to the same `shieldbase.lan` domain, so they corroborate
each other (the same `BASE-HUNT` source `172.16.5.25` and F-Response /
`Mnemosyne.sys` IR tooling appear in both). Runs 3 and 4 cover the same intrusion
from two victim perspectives — DC (initial compromise, malware deployment) and
Desktop (lateral movement, data exfiltration).

### Artifacts per run

| Run | Artifact | File | Mounted at |
|---|---|---|---|
| `base-dc` | Disk | `base-dc-cdrive.E01` | `/mnt/cases` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `base-dc` | Memory | `SRL-2018/base-dc-memory.7z` → `base-dc-memory.img` | `/evidence/base-dc-memory.img` |
| `base-file` | Disk | `base-file-cdrive.E01` | `/mnt/file-case` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `base-file` | Memory | `SRL-2018/base-file-memory.7z` → `base-file-memory.img` | `/evidence/base-file-memory.img` |
| `CITADEL-DC01` | Disk | `CITADEL-DC01-C.E01` | `/mnt/cases` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `CITADEL-DC01` | Memory | `citadel-dc01-memory.img` | `/evidence/citadel-dc01-memory.img` |
| `DESKTOP-SDN1RPT` | Disk | `DESKTOP-SDN1RPT-C.E01` | `/mnt/cases-desktop` (E01 → raw via `ewfmount` → NTFS, `ro,noexec,nodev`) |
| `DESKTOP-SDN1RPT` | Memory | `desktop-sdn1rpt-memory.img` | `/evidence/desktop-sdn1rpt-memory.img` |

- **Acquisition note (SRL-2018):** the base-dc and base-file images were captured by an IR
  responder, which is directly relevant to attribution (see findings).
- **Acquisition note (Szechuan Sauce):** DFIR Madness Case 001 is a public training case;
  images are available at https://dfirmadness.com/the-stolen-szechuan-sauce/
- **How to obtain (SRL-2018):** distributed by SANS to Find Evil! participants; not
  redistributed here — point the agent at your own copy after mounting read-only.

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

## What the agent found — Run 3 (`CITADEL-DC01` + `DESKTOP-SDN1RPT`, DFIR Madness Case 001)

Full triage report with `call_id` citations:
[`../audit/triage-report-citadel-dc01-2026-06-15.md`](../audit/triage-report-citadel-dc01-2026-06-15.md).
Raw tool execution log (31 calls, both hosts):
[`../audit/execution-log-szechuan.jsonl`](../audit/execution-log-szechuan.jsonl).
Accuracy report scored against the 29 public answer-key checks:
[`accuracy_report_szechuan.md`](accuracy_report_szechuan.md) — F1=0.818, 0% hallucination rate.

### CONFIRMED (≥2 independent sources agree)

- **`coreupdater.exe` (Meterpreter) deployed to `C:\Windows\System32\` and running
  as a service.** MFT records file creation at 2020-09-19 02:24:12 UTC
  (`call-000017`), Amcache records execution (`call-000001`), ShimCache records
  presence (`call-000004`), `mem_pslist` shows PID 3644 running at capture time
  (`call-000005`), and System.evtx records a 7045 service-install event at
  02:27:49 UTC with `ImagePath=C:\Windows\System32\coreupdater.exe` and start
  type `autostart` (`call-000013`). Five independent sources.

- **C2 channel to `203.78.103.109:443` (Thailand, Netway Communications).**
  `mem_netscan` shows an `ESTABLISHED` TCP socket from PID 3644 (`coreupdater.exe`)
  to `203.78.103.109:443` at capture time (`call-000006`). SRUM records
  `coreupdater.exe` transferring 2,847,291 bytes sent on the Desktop
  (`call-000031`). Memory + SRUM = two independent sources.

- **RDP brute-force from `194.61.24.102` leading to successful Administrator
  logon.** `logon_summary` (`call-000012`) shows 312 failures followed by 1
  success for `Administrator@194.61.24.102` type=10 (RemoteInteractive). Security
  EVTX 4624/4625 (`call-000010`, `call-000011`) corroborate timestamps. Three
  sources.

- **Lateral RDP movement from DC to `DESKTOP-SDN1RPT` (`10.42.85.115`) at
  02:35:54 UTC.** Security.evtx on Desktop records type-10 logon from
  `10.42.85.10` (DC) (`call-000030`); Prefetch on Desktop records `MSTSC.EXE`
  execution (`call-000027`). Two sources.

### INFERRED (single source, explicitly flagged)

- **`spoolsv.exe` process injection (Meterpreter migration).** `mem_malfind`
  returns three RWX unbacked memory regions in `spoolsv.exe` (`call-000007`).
  Single memory source → INFERRED; would require additional YARA/string scan to
  confirm Meterpreter shellcode.

- **Backdoor account `birdman` created.** EID 4720 in Security.evtx (`call-000019`).
  Single source → INFERRED; would confirm with SAM hive or `mem_svcscan` showing
  logon token.

- **`ricksanchez` added to Domain Admins then removed (privilege escalation and
  cover-up).** EID 4756/4732 (`call-000020`). Single source → INFERRED.

- **PowerShell base64+gzip stager used to download and stage the payload.**
  EID 4104 script-block log (`call-000016`) records the encoded command. Single
  source → INFERRED (stager text not decoded in-tool; decoding would confirm
  download URL).

### CONTRADICTION (surfaced, not hidden)

- **[X-1] DC timezone vs. Desktop timezone offset.** All timestamps normalized to
  UTC by EvtxECmd/MFTECmd; registry TZI keys indicate UTC-6 (DC, MST) and UTC-8
  (Desktop, PST). Correlations against any log source using local time must apply
  the appropriate offset. Flagged as a known ambiguity — not resolved silently.

---

## Reproducibility

Each run is reproduced independently. Mount the relevant artifacts read-only
(see the [README "Try it out"](../README.md#try-it-out) steps), restart Claude
Code so the `sift-sentinel` MCP server and its 18 tools appear, then:

| Run | Command |
|---|---|
| `base-dc` | `/triage` against `/mnt/cases` with memory at `/evidence/base-dc-memory.img` |
| `base-file` | `/triage` against `/mnt/file-case` with memory at `/evidence/base-file-memory.img` |
| `CITADEL-DC01` + `DESKTOP-SDN1RPT` | `/triage` against `/mnt/cases` (DC) and `/mnt/cases-desktop` (Desktop) with memory at `/evidence/citadel-dc01-memory.img` and `/evidence/desktop-sdn1rpt-memory.img` |

Every finding traces back to the `call_id`s recorded in that run's audit log, so
a judge can locate the exact tool execution behind any claim above.

---

## See also

- [`../README.md`](../README.md) — setup, the 18 tools, and try-it-out steps
- [`architecture.md`](architecture.md) — how the read-only pipeline is enforced
- [`tools.md`](tools.md) — per-tool reference
- [`accuracy_report_szechuan.md`](accuracy_report_szechuan.md) — scored evaluation against DFIR Madness Case 001 answer key
- [`../audit/triage-report-citadel-dc01-2026-06-15.md`](../audit/triage-report-citadel-dc01-2026-06-15.md) — Szechuan Sauce full findings report
- [`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md) — SRL-2018 base-dc full findings report
