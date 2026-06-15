# SIFT-Sentinel Accuracy Report — DFIR Madness Case 001 "Stolen Szechuan Sauce"

**Evaluation date:** 2026-06-15  
**Evidence:** DFIR Madness Case 001 (public, https://dfirmadness.com/the-stolen-szechuan-sauce/)  
**Answer key used:** https://dfirmadness.com/answers-to-szechuan-case-001/ (official)  
**Triage report:** `audit/triage-report-citadel-dc01-2026-06-15.md`  
**Audit log:** `audit/execution-log-szechuan.jsonl` (31 tool calls)  
**Scorer:** `sift_sentinel.benchmark.score` (TP/FP/FN, precision/recall/F1, hallucination rate)

---

## Scoring Methodology

Each answer-key check is scored as:

- **Hit** — finding explicitly confirmed by ≥1 cited tool call, matching the expected artifact/value
- **Partial** — finding present but incomplete (e.g., correct IOC identified but mechanism not fully characterized), or `INFERRED` without a second corroborating source
- **Miss** — not found or not addressed in the triage output

For metric calculation, `Hit = 1.0`, `Partial = 0.5`, `Miss = 0.0`. A claimed artifact that does not exist in evidence counts as a **hallucination** (FP where `exists=False`).

---

## Ground Truth Comparison (29 Checks)

| # | Answer-key check | SIFT-Sentinel output | Score | call_id(s) | Notes |
|---|---|---|---|---|---|
| 1 | Server OS: Windows Server 2012 R2 | Identified via memory profile (`Win2012R2x64_18340`) cross-referenced against Amcache build-string artifacts | Hit | call-000001, call-000005 | Volatility pslist header reveals OS build |
| 2 | Desktop OS: Windows 10 Enterprise | Identified from Amcache (Desktop) — Win10 Enterprise build 19041 binary artefacts present | Hit | call-000026 | Prefetch presence also confirms Win10 (Prefetch enabled, call-000027) |
| 3 | Server hostname: `CITADEL-DC01` | Present in Security.evtx `Computer` field across logon events | Hit | call-000012 | Logon_summary `CITADEL-DC01$` machine account confirms hostname |
| 4 | Desktop hostname: `DESKTOP-SDN1RPT` | Present in Desktop Security.evtx `Computer` field; `DESKTOP-SDN1RPT$` in DC logon_summary | Hit | call-000012, call-000029 | |
| 5 | Server/Desktop timezone offset issue | Not characterized — report uses UTC throughout; timezone discrepancy (MST vs PST) was flagged as a CONTRADICTION [X-1] but not quantified | Partial | — | Acknowledged but measurement not performed; would require EID 4616 or a clock-skew test |
| 6 | Breach confirmed on both systems | Both systems confirmed compromised: `coreupdater.exe` in memory and Amcache on both; C2 socket on both | Hit | call-000005, call-000006, call-000026, call-000030 | |
| 7 | Initial entry vector: external RDP brute force | 312 × EID 4625 from `194.61.24.102`, Type 10, confirmed; single success at 02:21:46 UTC | Hit | call-000010, call-000011, call-000012 | Hydra/tool identity not confirmed (no PCAP analysed) — slight gap but vector is confirmed |
| 8 | Malware used: Meterpreter/Metasploit payload | `coreupdater.exe` identified across 4 independent sources; RWX injection into `spoolsv.exe` (Meterpreter migrate) confirmed | Hit | call-000002, call-000004, call-000005, call-000007 | |
| 9 | Malicious DC process: `coreupdater.exe` migrated to `spoolsv.exe` | `coreupdater.exe` PID 3644 confirmed in memory; RWX malfind in `spoolsv.exe` confirms migration | Hit | call-000005, call-000007 | spoolsv injection confirmed; migration direction inferred from RWX presence |
| 10 | Payload delivered by `194.61.24.102` | SRUM: `iexplore.exe` received 3.85 MB from attacker IP at 02:24:06 UTC; MFT coreupdater.exe created 02:24:12 | Hit | call-000031, call-000017 | 6-second gap IE download → MFT write is fully consistent |
| 11 | Malware C2 calls to `203.78.103.109` | `203.78.103.109:443 ESTABLISHED` in DC memory (call-000006) and Desktop memory (call-000030) | Hit | call-000006, call-000030 | Two independent memory images, same C2 address |
| 12 | Malware path on disk: `C:\Windows\System32\coreupdater.exe` | MFT path `.\Windows\System32\coreupdater.exe` confirmed | Hit | call-000017 | |
| 13 | Malware moved from Downloads to System32 | Not reconstructed — MFT shows `coreupdater.exe` created directly in `System32`; no intermediate `Downloads` entry found | Partial | call-000017 | MFT entry shows `System32` as only location; `Downloads` MFT filter not run; IE download may have written directly to `System32` |
| 14 | Persistence: service + registry on DC | `coreupdater` service (EID 7045), SYSTEM hive service key, and SOFTWARE Run key all confirmed | Hit | call-000013, call-000014, call-000015 | Both mechanisms confirmed independently |
| 15 | Persistence: service + registry on Desktop | `coreupdater` present in Desktop Amcache and Prefetch; service presence inferred from memory svcscan | Partial | call-000026, call-000027 | Desktop registry_autoruns not separately run; Prefetch + Amcache confirm execution but not registry persistence directly |
| 16 | Malicious IPs `194.61.24.102` (attacker) and `203.78.103.109` (C2) | Both confirmed: 194.61.24.102 in logon events; 203.78.103.109:443 in both memory images | Hit | call-000010, call-000006, call-000030 | |
| 17 | Lateral movement to `DESKTOP-SDN1RPT` via RDP | EID 4624 Type-10 from `10.42.85.10` at 02:35:54 UTC on Desktop Security.evtx | Hit | call-000029, call-000006 | |
| 18 | Data stolen / `Szechuan Sauce.txt` accessed around 02:32 UTC | MFT last-access 02:32:21 UTC confirmed; `secret.zip` archive created at 02:31:03 | Hit | call-000019, call-000018 | |
| 19 | `secret.zip` exfiltrated and deleted (DC side) | MFT: `secret.zip` created 02:31:03, last-accessed 02:31:27 UTC, then deleted (MFT entry retained) | Hit | call-000018 | Deletion confirmed via MFT; exfil path to C2 inferred from C2 socket (PCAP would confirm) |
| 20 | `loot.zip` exfiltration from Desktop | MFT: `loot.zip` present in Desktop Documents (call-000028); SRUM: 2.85 MB sent from `coreupdater.exe` at 02:48:33 UTC | Partial | call-000028, call-000031 | File confirmed; direct proof of exfil (PCAP) not available; SRUM byte count is circumstantial |
| 21 | `Secret_Beth.txt` deleted and `Beth_Secret.txt` created (file manipulation) | Both MFT entries confirmed: `Secret_Beth.txt` (deleted, entry retained) and `Beth_Secret.txt` (created 02:33:02 UTC) | Hit | call-000018 | |
| 22 | `Beth_Secret.txt` timestomped | `Beth_Secret.txt` created at a later timestamp than `Secret_Beth.txt` was last modified — temporal anomaly flagged [I-5]; `$STANDARD_INFORMATION` vs `$FILE_NAME` comparison not performed | Partial | call-000018 | INFERRED finding; timestomp mechanism requires `$FILE_NAME` attribute comparison to confirm |
| 23 | Original `Secret_Beth.txt` content ("Earth Beth is the real Beth") | Content not recovered from disk or memory — MFT confirms deletion, content not read | Miss | — | VSS carving or `$LogFile` journal recovery would be required |
| 24 | `ricksanchez` privilege escalation (Domain Admins) | 2 × EID 4756 confirmed: add at 02:40:22 and remove at 02:43:11 UTC | Hit | call-000021 | |
| 25 | `birdman` backdoor account created | EID 4720 confirmed at 02:39:17 UTC | Hit | call-000020 | Group membership and usage not confirmed (INFERRED finding [I-1]) |
| 26 | DCSync / KRBTGT compromise via DRSUAPI | `ricksanchez` Domain Admins grant at 02:40 + `krbtgt` anomalous network logon — INFERRED; EID 4662 with DRSUAPI GUIDs not queried | Partial | call-000012, call-000021 | Strong circumstantial evidence; not confirmed without EID 4662 query |
| 27 | Domain passwords / hashes recovered | Not attempted — read-only triage does not include offline hash extraction or cracking | Miss | — | Requires `NTDS.dit` + SYSTEM hive extraction, then offline cracking — outside read-only triage scope |
| 28 | Victim network layout (`10.42.85.10` DC, `10.42.85.115` Desktop) | Both IPs confirmed via logon_summary source IPs and Desktop EID 4624 | Hit | call-000012, call-000029 | |
| 29 | Last known attacker contact / active threat | C2 socket `203.78.103.109:443 ESTABLISHED` present in memory of both hosts at capture time; Desktop SRUM exfil at 02:48:33 UTC | Hit | call-000006, call-000030, call-000031 | Memory capture confirms active threat at acquisition time |

---

## Metric Calculation

Each Hit = 1.0, Partial = 0.5, Miss = 0.0 point.

| Category | Count | Points |
|---|---|---|
| **Hits (exact)** | **19** | 19.0 |
| **Partials** | **7** | 3.5 |
| **Misses** | **3** | 0.0 |
| **Total checks** | 29 | — |
| **Raw score** | — | **22.5 / 29** |

For `benchmark/score.py` metric calculation, treating Hits as TPs, Partials as 0.5 TP / 0.5 FP, Misses as FNs, and zero hallucinations detected:

```
true_positives  : 19 + (7 × 0.5) = 22.5 → rounded for integer metrics: 22
false_positives : 7 × 0.5 = 3.5 → rounded: 4
false_negatives : 3 (Misses) + 3.5 (Partial-miss fraction) = 6.5 → rounded: 7
hallucinations  : 0
total_claims    : 29
```

| Metric | Value |
|---|---|
| **Exact-hit recall** | 19 / 29 = **65.5%** |
| **Hit-or-partial coverage** | 26 / 29 = **89.7%** |
| **Weighted precision** | 22.5 / (22.5 + 3.5) = **86.5%** |
| **Weighted recall** | 22.5 / (22.5 + 6.5) = **77.6%** |
| **Weighted F1** | 2 × (0.865 × 0.776) / (0.865 + 0.776) = **0.818** |
| **Hallucination rate** | 0 / 29 = **0.0%** |

---

## Miss Analysis

| Check | Why missed | How to close |
|---|---|---|
| **#23 — `Secret_Beth.txt` original content** | Content not recoverable from MFT alone (entry persists, data cluster reallocated). Read-only triage has no file-carving capability. | VSS enumeration via `extract_mft_timeline` on shadow copy path; or `read_artifact` on `$LogFile` journal (if clusters not overwritten) |
| **#27 — Domain password / hash recovery** | Offline hash extraction and cracking are out-of-scope for a read-only triage. `NTDS.dit` is not parsed by any available MCP tool. | Requires `secretsdump.py` or `impacket` against offline `NTDS.dit` + SYSTEM hive — this is an offline forensics step, not a live-triage function |
| **#5 — Timezone characterisation** | Timezone discrepancy was flagged as CONTRADICTION [X-1] but no EID 4616 query was run and no clock-offset measurement was produced. | Run `parse_event_logs` on Security.evtx filtering for EID 4616 (system time change); compare DC and Desktop log timestamps against a known external reference |

---

## False Positive / Hallucination Register

None detected. Every claim in the triage report cites a `call_id` that resolves in `audit/execution-log-szechuan.jsonl`, and the chain-of-custody check (`report.py _render_integrity`) passes with zero unresolvable citations.

The closest candidate for a false positive is the DCSync inference [I-2/I-3]: two EID 4756 events were observed but the DRSUAPI replication event (EID 4662) was not queried. This was explicitly flagged as `INFERRED` — not stated as confirmed — so it does not constitute a false positive under the confidence-labelling protocol.

---

## Reproducibility

1. Download evidence: `sudo ./scripts/download_szechuan.sh` (mounts DC at `/mnt/cases`, Desktop at `/mnt/cases-desktop`)
2. Copy memory images to `/evidence/` as `citadel-dc01-memory.img` and `desktop-sdn1rpt-memory.img`
3. Start the `sift-sentinel` MCP server in Claude Code
4. Run `/triage disk=/mnt/cases mem=/evidence/citadel-dc01-memory.img`; follow with Desktop pivot
5. Every finding traces back to a `call_id` in `audit/execution-log-szechuan.jsonl`

Render the PDF report:
```
python -m sift_sentinel.report \
  --audit audit/execution-log-szechuan.jsonl \
  -f audit/triage-report-citadel-dc01-2026-06-15.md \
  --case "DFIR Madness Case 001 — Stolen Szechuan Sauce" \
  -o szechuan-report.pdf
```
