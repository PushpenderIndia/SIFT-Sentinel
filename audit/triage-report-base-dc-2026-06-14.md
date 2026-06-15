# SIFT-Sentinel Triage Report

**Date:** 2026-06-14 (updated 2026-06-15)
**Evidence root:** `/mnt/cases`
**Memory image:** `/evidence/base-dc-memory.img`
**Host:** `base-dc.shieldbase.lan` (Windows Server 2016 domain controller)
**Case notes / IOCs supplied:** none (open-ended triage)

---

## Tools Executed (audit call_ids)

### Session 1 — 2026-06-14

| call_id | Tool | Target |
|---|---|---|
| call-000016 | get_amcache | `Windows/appcompat/Programs/Amcache.hve` |
| call-000017 | extract_mft_timeline | `$MFT` (unfiltered digest) |
| call-000018 | analyze_prefetch | `Windows/Prefetch/` |
| call-000019 | mem_pslist | `/evidence/base-dc-memory.img` |
| call-000020 | mem_netscan | `/evidence/base-dc-memory.img` |
| call-000021 | parse_event_logs | `Security.evtx` event_id=4624 |
| call-000022 | parse_event_logs | `Security.evtx` event_id=4625 |
| call-000023 | parse_event_logs | `System.evtx` event_id=7045 |
| call-000024 | extract_mft_timeline | `$MFT` path_filter=`Mnemosyne` |
| call-000025 | extract_mft_timeline | `$MFT` path_filter=`subject_srv` |

### Session 2 — 2026-06-15

| call_id | Tool | Target |
|---|---|---|
| call-000026 | get_amcache | `Windows/appcompat/Programs/Amcache.hve` (known-good suppressed) |
| call-000027 | extract_mft_timeline | `$MFT` (unfiltered digest) |
| call-000028 | analyze_prefetch | `Windows/Prefetch/` |
| call-000029 | mem_pslist | `/evidence/base-dc-memory.img` |
| call-000030 | mem_netscan | `/evidence/base-dc-memory.img` |
| call-000031 | parse_event_logs | `Security.evtx` event_id=4624 |
| call-000032 | parse_event_logs | `Security.evtx` event_id=4625 |
| call-000033 | parse_event_logs | `System.evtx` event_id=7045 |
| call-000034 | extract_mft_timeline | `$MFT` path_filter=`subject_srv` |
| call-000035 | extract_mft_timeline | `$MFT` path_filter=`Mnemosyne` |
| call-000036 | logon_summary | `Security.evtx` (aggregate, all accounts) |
| call-000037 | registry_autoruns | `Windows/System32/config/SYSTEM` (services plugin) |

---

## Timeline of Suspicious / Notable Activity

| Time (UTC) | Event | Source call_id |
|---|---|---|
| 2018-04-20 19:51 | System provisioned; VMware Tools and NIC drivers installed | call-000033 |
| 2018-04-25 20:02 | DC promotion: AD DS, DNS, DFS, KDC, ADWS services installed on `base-dc` | call-000033 |
| 2018-05-08 22:09 | McAfee Agent installed; `mfemactl.exe` staged in `Administrator\AppData\Local\Temp`; three McAfee services registered | call-000027, call-000033 |
| 2018-05-18 21:58 | `wdksetup.exe` (SHA-1: `5bc33f95`) downloaded to `Administrator\Downloads` and extracted into four `C:\Windows\Temp\{GUID}` dirs — anomalous on a production DC | call-000026 |
| 2018-08-08 13:57 | `regedit.exe` executed — anomalous on DC | call-000026 |
| 2018-08-11 22:58 | `win32calc.exe` executed — anomalous on DC | call-000026 |
| 2018-08-16 21:48 | `rsydow-a` opened "Set the time and date" (LNK artifact in Recent) | call-000027 |
| 2018-08-16–17 | `rundll32.exe` (08-16) and `consent.exe` (08-17) executed — UAC elevation event on DC | call-000026 |
| 2018-09-04 12:58 | Earliest Security log event; log coverage begins here despite system active since April 2018 (~4.5-month gap) | call-000036 |
| 2018-09-04 13:11 | `BASE-HUNT$` (172.16.5.25) begins sustained 4625 failure loop — **396 failures total**, metronomic ~15-min cadence, runs until 2018-09-07 10:17 | call-000032, call-000036 |
| 2018-09-04 14:03 | `Administrator` account begins Type-3 network logons to DC **from BASE-AV (172.16.5.20)** — 234 successes over 3 days | call-000036 |
| 2018-09-04 14:18 | `cbarton` (standard account) begins authenticating from `172.16.5.25` (the broken-channel BASE-HUNT machine) | call-000036 |
| 2018-09-06 01:38 | `tyler.oslund` first and only day of activity — 34 logons, last at 12:40 (same calendar day as F-Response deployment) | call-000036 |
| **2018-09-06 22:11:08** | **`cbarton-a` — 13 rapid Type-3 logons in 7 seconds from 172.16.5.25 (BASE-HUNT)** | call-000036 |
| **2018-09-06 22:11:15** | **F-Response Subject service installed; `subject_srv.exe` (1.17 MB) dropped to `C:\Windows\`; Mnemosyne service installed simultaneously** | call-000033, call-000034 |
| 2018-09-07 20:26 | Mnemosyne service re-installed (second install) | call-000033 |
| **2018-09-07 20:30:59** | **Mnemosyne service re-installed (third install); `Mnemosyne.sys` (26 KB) written to `C:\Windows\` — memory capture likely taken immediately after** | call-000033, call-000035 |

---

## Confirmed Findings `[CONFIRMED]`

**[C-1] F-Response forensic collection deployed by `cbarton-a` from BASE-HUNT (172.16.5.25)**  
`subject_srv.exe` dropped to `C:\Windows\` and the "F-Response Subject" service registered at 2018-09-06 22:11:15 UTC. Immediately preceded by `cbarton-a` making 13 Type-3 logons from `172.16.5.25` in a 7-second burst (22:11:08–22:11:15) — consistent with automated authentication during tool deployment. The `cbarton` standard account was also active from `172.16.5.25` from 2018-09-04 onward, confirming this machine was the IR operator's workstation.  
— corroborated by: call-000033 (7045 service install) + call-000034 (MFT file creation, same second) + call-000036 (logon_summary, cbarton-a@172.16.5.25)

**[C-2] Memory acquisition via Mnemosyne kernel driver (IR tooling confirmed)**  
`Mnemosyne.sys` installed as a service three times (call-000033); physical driver written to `C:\Windows\` at 2018-09-07 20:30:59 (call-000035). This is the F-Response memory acquisition driver. The RAM capture at `/evidence/base-dc-memory.img` was taken at this time. Combined with [C-1], both tools are attributed to an IR collection action, not adversary persistence.  
— corroborated by: call-000033 (three 7045 installs of "mnemosyne") + call-000035 (MFT timestamp matches third install to the second)

**[C-3] BASE-HUNT$ Secure Channel failure — machine account password mismatch, 396 failures over 3 days**  
~~163~~ **396** consecutive failed Type-3 logons from `172.16.5.25` against `BASE-HUNT$` spanning 2018-09-04 13:11 through 2018-09-07 10:17. Pattern: ~15-minute cadence with a triple sub-second burst at :56 of each hour — signature of a Windows NetLogon Secure Channel retry loop, not a brute-force attempt. Zero successful logons recorded for this account.  
— corroborated by: call-000032 (4625 analysis, all 209 sampled records = BASE-HUNT$) + call-000036 (logon_summary: 0 successes, 396 failures, first/last timestamps)

**[C-4] Security log coverage starts abruptly on 2018-09-04 — 4.5 months of events missing**  
Earliest 4624/4625 event is 2018-09-04 12:58:52 UTC despite continuous system activity (Amcache, MFT) since April 2018. This is not a retention truncation artefact — a full DC Security log under normal audit policy retains months of data. The log was either cleared or event auditing was not enabled until this date.  
— corroborated by: call-000031 (earliest 4624) + call-000032 (earliest 4625) + call-000036 (all logon_summary first_seen values cluster at 2018-09-04)

**[C-5] Prefetch disabled — all execution evidence is Amcache-only**  
`Windows\Prefetch` returned no `.pf` files (call-000028). Standard on Windows Server/DC. Execution corroboration relies entirely on Amcache (call-000026) + MFT (call-000027) + EVTX (call-000033).  
— corroborated by: call-000018 (session 1) + call-000028 (session 2, same result)

---

## Inferred Findings `[INFERRED]`

**[I-1] Volatility returned 0 processes/connections — symbol resolution failure, not an empty image**  
`mem_pslist` (call-000029) and `mem_netscan` (call-000030) returned 0 records with `error: null`. The image hash is intact (`9679…`). Mnemosyne produces a raw physical-memory format; Volatility 3 requires Windows Server 2016 symbol packs to parse it. Memory is a **blind spot**, not cleared.  
— single source: call-000029/call-000030. Confirmed by: `vol.py -f <image> windows.info` then rerun with correct symbol path

**[I-2] `rsydow-a` is a high-privilege account with anomalous multi-host authentication spread**  
`rsydow-a` logged on from 8+ distinct IPs over the log window: BASE-MAIL (172.16.4.6 / 10.10.4.6), BASE-AV (172.16.5.20 / 10.10.5.21), BASE-FILE (172.16.4.5 / 10.10.4.5), BASE-ELF (172.16.5.21), BASE-ADMIN (172.16.5.26). Total: 1,045+ successful Type-3 logons. A separate `rsydow` standard account also exists (207 logons from BASE-ADMIN). The `-a` suffix pattern matches `cbarton` / `cbarton-a` admin-account pairs, suggesting `rsydow-a` is a privileged admin account. Breadth across 8 hosts is unusual even for admins.  
— single source: call-000036. Confirmed by: AD account creation date / group membership; Amcache/shimcache on each source host

**[I-3] Domain `Administrator` account authenticating from BASE-AV (172.16.5.20) — 234 logons**  
The built-in domain Administrator account made 234 successful Type-3 logons to the DC from the AV server between 2018-09-04 14:03 and 2018-09-07 09:07. AV management consoles occasionally run as local admin but not typically as the domain built-in Administrator. This requires verification against the AV product's service account configuration.  
— single source: call-000036. Confirmed by: registry_autoruns / Amcache on BASE-AV image; check AV console service account

**[I-4] WDK installation on DC (2018-05-18) is anomalous**  
`wdksetup.exe` (SHA-1: `5bc33f95fe980ba44256329007c25bff7397ef27`) downloaded to `Administrator\Downloads` and expanded into four `C:\Windows\Temp\{GUID}` paths. The Windows Driver Kit has no legitimate operational purpose on a production DC; it can be used to compile or sign kernel modules.  
— single source: call-000026 (Amcache). Confirmed by: shimcache for execution corroboration; MFT filter for `.sys` files created 2018-05-18 → 2018-05-30

**[I-5] `tyler.oslund` active only on 2018-09-06 — same day as F-Response deployment**  
34 logons from 172.16.7.16 between 01:38 and 12:40 UTC on 2018-09-06; no activity on any other date in the log window. Whether this is coincidence or pre-staging activity before the 22:11 F-Response deployment is unknown.  
— single source: call-000036. Confirmed by: parse Security log filtered to `tyler.oslund`; check logon types and target machines

**[I-6] `rsydow-a` opened "Set the time and date" on 2018-08-16 — possible clock verification**  
LNK artifact in `rsydow-a\AppData\Roaming\Microsoft\Windows\Recent` at 21:48:37 UTC, 2018-08-16.  
— single source: call-000027 (MFT LNK). Confirmed by: parse Security log for Event ID 4616 (system time changed) around this timestamp

---

## Uncertain / Low-confidence `[UNCERTAIN]`

- **`dayla.watson` — 5 sub-second logons at 13:15:55–56 UTC (2018-09-04):** From 172.16.7.12 (BASE-WKSTN-02). Five Type-3 logons in under 1.3 seconds is not typical of interactive user behaviour; could be a script, SMB multi-connect, or normal application session multiplexing. call-000036.
- **ANONYMOUS LOGON at volume from three hosts:** BASE-ADMIN (345 logons), WKSTN-03 (316), RD-02 (315) over the full 3-day window. High cadence null-session authentication from the admin workstation in particular warrants scrutiny but can be legitimate for legacy Windows infrastructure. call-000036.
- **`BASE-MAIL$` authenticating from 10.10.4.6 (1,275 logons):** Secondary IP alongside primary 172.16.4.6. Likely a multi-homed NIC (BASE-ELF$ shows the same pattern: 172.16.5.21 + 10.10.5.21). Consistent with dual-NIC mail server, but unconfirmed without network inventory. call-000036.

---

## Contradictions `[CONTRADICTION]`

**[X-1] `subject_srv.exe` created vs. modified timestamps diverge**  
MFT `created`: **2018-09-06 22:11:15** (matches service install exactly). MFT `modified`: **2018-04-10 19:29:48** (5 months earlier — likely PE compile timestamp retained in `LastWriteTime`). Cannot distinguish normal binary distribution behaviour from deliberate timestomping without comparing `$STANDARD_INFORMATION` vs. `$FILE_NAME` attributes.  
Source: call-000034.

**[X-2] Security log shows no events before 2018-09-04 despite months of confirmed system activity**  
Amcache (call-000026) and MFT (call-000027) show continuous activity April–September 2018. Security log earliest event: 2018-09-04 12:58 UTC. A DC authenticating hundreds of domain members continuously would generate tens of thousands of 4624 events per day under default audit policy. The 4.5-month gap is not consistent with normal retention — the log was cleared or auditing was not enabled. Event ID 1102 (log cleared) should be present if cleared; its absence or presence must be checked.  
Source: call-000031/call-000032 vs. call-000026/call-000027.

**[X-3] Memory analysis returned 0 results despite a physically valid image**  
`mem_pslist` and `mem_netscan` returned 0 records with `error: null` in both sessions (call-000019/020 and call-000029/030). A live memory capture must contain kernel objects. This is a tooling failure (symbol/profile mismatch for Mnemosyne format), not evidence of an empty or clean system. C2, injection, and process anomalies are **untested**, not cleared.  
Source: call-000019, call-000020, call-000029, call-000030.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1543.003 | Create/Modify System Process: Windows Service | F-Response + Mnemosyne service installs (call-000033) — IR tooling; same TTP an adversary would use |
| T1569.002 | System Services: Service Execution | Service-based execution of dropped binaries (call-000033/034/035) |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mnemosyne kernel driver exposes raw memory including LSASS (call-000033, call-000035) |
| T1005 | Data from Local System | F-Response Subject enables remote disk and memory read over network (call-000034) |
| T1078.002 | Valid Accounts: Domain Accounts | `cbarton-a` deploys tooling; `rsydow-a` spreads across 8+ hosts; `Administrator` from AV server (call-000036) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Security log starts 2018-09-04 — 4.5 months of events absent (X-2) |
| T1588.002 | Obtain Capabilities: Tool | WDK installed on DC — driver kit acquisition, anomalous on production DC (call-000026) |
| T1110.x | Brute Force / credential mis-auth | 396 × 4625 from single source (call-000032) — NetLogon failure, not brute-force |
| T1018 | Remote System Discovery | ANONYMOUS LOGON null-session from BASE-ADMIN (345), WKSTN-03 (316), RD-02 (315) (call-000036) |

---

## Recommended Next Steps (Prioritised)

1. **[CRITICAL] Fix and re-run memory forensics** — Run `vol.py -f /evidence/base-dc-memory.img windows.info` to determine detected OS and correct symbol set. Re-run `mem_pslist`, `mem_netscan`, `mem_malfind`, `mem_pstree`, `mem_svcscan`, and `mem_cmdline`. Memory is the largest open gap — C2, injected code, and in-memory persistence are untested.

2. **[HIGH] Confirm Security log clearing (Event ID 1102)** — Run `parse_event_logs` on `Security.evtx` filtered to EID 1102 and EID 4688. If 1102 exists, record the clearing account and timestamp; this elevates the log-gap from CONTRADICTION to confirmed anti-forensics (T1070.001).

3. **[HIGH] Investigate `Administrator` logons from BASE-AV (172.16.5.20)** — 234 network logons by the domain built-in Administrator originating from the AV server is a high-priority lateral movement indicator. Obtain BASE-AV Amcache, shimcache, and registry autoruns; verify AV service account configuration.

4. **[HIGH] Characterize `rsydow-a` account** — Pull AD account creation date and group membership. Run `registry_autoruns` on `rsydow-a`'s `NTUSER.DAT`. Cross-reference 1,045+ logons from 8 hosts against expected admin duties. If `rsydow-a` is not a defined service account, treat as potential credential compromise.

5. **[MEDIUM] Run `shimcache`** — Amcache is the sole disk-based execution source (Prefetch disabled). Shimcache (AppCompatCache, SYSTEM hive) provides an independent second list. Cross-reference against anomalous Amcache hits: `regedit`, `rundll32`, `win32calc`, `consent.exe`.

6. **[MEDIUM] Investigate WDK installation aftermath** — Run `extract_mft_timeline` with path_filter for `.sys` files in the 2018-05-18 → 2018-05-30 window. A custom kernel module compiled after WDK install would be a critical finding; its absence does not clear the concern without shimcache confirmation.

7. **[MEDIUM] Verify `tyler.oslund` (2018-09-06 activity)** — Run `parse_event_logs` filtered to this account and correlate logon types and target machines with the 22:11 F-Response deployment. Determine whether this account interacted with `base-dc` before the tooling was dropped.

8. **[LOW] Run `powershell_logs`** — Parse EID 4104 ScriptBlock logs. `rundll32.exe` execution on a DC is a LOLBin signal; PowerShell logging (if enabled) may surface staged commands around the August activity window.

9. **[LOW] Pull `super_timeline`** — Merge MFT + Amcache + EVTX into a unified chronological timeline to tighten the 2018-09-04 → 09-07 sequence and surface any ordering relationships currently obscured by per-artifact analysis.

---

## Bottom Line

The DC shows **IR/acquisition tooling (F-Response + Mnemosyne) deployed by `cbarton-a` from `BASE-HUNT` (172.16.5.25) on 2018-09-06 22:11 UTC**, which accounts for the memory image in evidence. Attribution of this action to IR is consistent across three independent sources.

Three concerns are **unresolved and require follow-up before this host can be called clean:**

1. **Memory analysis is dark** — Volatility silently returned 0 results in both sessions; C2, injection, and in-memory persistence are untested hypotheses.
2. **The Security log has a 4.5-month gap** — whether this is cleared-log anti-forensics or an audit-policy misconfiguration must be determined. Event ID 1102 is the deciding artefact.
3. **`Administrator` account making 234 network logons from the AV server** and **`rsydow-a` spreading across 8+ hosts** are anomalous patterns requiring account-level investigation that cannot be completed from the DC evidence alone.
