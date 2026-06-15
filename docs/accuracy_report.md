# SIFT-Sentinel Triage Report

**Date:** 2026-06-15 UTC  
**Evidence root:** `/mnt/cases`  
**Memory image:** `/evidence/base-dc-memory.img`  
**Domain:** `shieldbase.lan` · DC: `base-dc.shieldbase.lan`  
**Log window:** 2018-04-20 through 2018-09-07

---

## Timeline of Suspicious Activity

| UTC Timestamp | Event | Source |
|---|---|---|
| 2018-04-20 19:51 | System provisioned (VMware Tools, drivers) | call-000033 |
| 2018-04-25 20:02 | DC promotion: AD DS, DNS, DFS, KDC services installed | call-000033 |
| 2018-05-08 22:09 | `mfemactl.exe` dropped to `Administrator\AppData\Local\Temp`; McAfee Agent services installed | call-000027, call-000033 |
| 2018-05-18 21:58 | WDK setup downloaded to `Administrator\Downloads`, extracted to multiple `\Windows\Temp` GUIDs — unusual on a DC | call-000026 |
| 2018-08-08 13:57 | `regedit.exe` executed — anomalous on DC | call-000026 |
| 2018-08-11 22:58 | `win32calc.exe` executed — anomalous on DC | call-000026 |
| 2018-08-16 21:48 | `rsydow-a` opened "Set the time and date" (LNK artifact) | call-000027 |
| 2018-08-16–17 | `rundll32.exe` (2018-08-16) and `consent.exe` (2018-08-17) executed — UAC elevation on DC | call-000026 |
| 2018-09-04 12:58 | Earliest Security log event; all log data spans 2018-09-04 → 2018-09-07 only (prior log history absent) | call-000036 |
| 2018-09-04 13:11 | `BASE-HUNT$` (172.16.5.25) begins 396-failure Secure Channel loop; runs until 2018-09-07 10:17 | call-000032, call-000036 |
| 2018-09-04 14:18 | `cbarton` begins authenticating from `172.16.5.25` (same broken-channel machine) | call-000036 |
| 2018-09-05 onward | `cbarton-a` begins separate logon stream from `172.16.5.27` / `172.16.5.28` | call-000036 |
| 2018-09-06 01:38 | `tyler.oslund` first and only day of activity — 34 logons, stops at 12:40 | call-000036 |
| **2018-09-06 22:11:08** | **`cbarton-a` — 13 rapid logons in 7 seconds from 172.16.5.25 (BASE-HUNT)** | call-000036 |
| **2018-09-06 22:11:15** | **`subject_srv.exe` (F-Response Subject, 1.17 MB) dropped to `C:\Windows\`; F-Response + Mnemosyne services installed** | call-000033, call-000034 |
| 2018-09-07 20:26 | Mnemosyne service re-installed (first retry) | call-000033 |
| **2018-09-07 20:30:59** | **Mnemosyne service re-installed; `Mnemosyne.sys` written to `C:\Windows\` — memory capture likely taken** | call-000033, call-000035 |

---

## Confirmed Findings `[CONFIRMED]`

**[C-1] F-Response forensic collection deployed by `cbarton-a` from BASE-HUNT (172.16.5.25)**  
`subject_srv.exe` was dropped to `C:\Windows\` and the "F-Response Subject" service registered at 22:11:15 on 2018-09-06, preceded by 13 rapid network logons from `cbarton-a` at `172.16.5.25` in a 7-second burst.  
— corroborated by: call-000033 (7045 service install) + call-000034 (MFT file creation, same second) + call-000036 (logon_summary, cbarton-a@172.16.5.25 first/last: 22:11:08–22:11:15)

**[C-2] Memory acquisition via Mnemosyne kernel driver**  
`Mnemosyne.sys` was installed as a service three times (call-000033), with the physical driver file written to `C:\Windows\` at 2018-09-07 20:30:59 (call-000035). This is the F-Response memory acquisition driver; the memory image at `/evidence/base-dc-memory.img` was captured at this time.  
— corroborated by: call-000033 (three 7045 installs of "mnemosyne") + call-000035 (MFT timestamp matches third install exactly)

**[C-3] BASE-HUNT$ Secure Channel failure — machine account password mismatch**  
396 consecutive failed Type-3 logons from `172.16.5.25` against `BASE-HUNT$` spanning 2018-09-04 13:11 through 2018-09-07 10:17, with a metronomic ~15-minute cadence and triple-burst at :56 of each hour.  
— corroborated by: call-000032 (4625 pattern analysis, 209 records all BASE-HUNT$) + call-000036 (logon_summary: 0 successes, 396 failures)

**[C-4] Security log coverage starts abruptly on 2018-09-04 — no prior logon history**  
The earliest 4624/4625 event is 2018-09-04 12:58:52 UTC despite system activity since April 2018. This ~4.5-month gap indicates the Security log was cleared or was not configured to retain events beyond a small buffer.  
— corroborated by: call-000031 (earliest 4624 timestamp) + call-000032 (earliest 4625 timestamp) + call-000036 (logon_summary first_seen values)

---

## Inferred Findings `[INFERRED]`

**[I-1] Volatility parsed 0 processes/connections — likely profile mismatch, not an empty capture**  
Both `mem_pslist` (call-000029) and `mem_netscan` (call-000030) returned 0 records with no error. The Mnemosyne acquisition driver produces a raw page-file format; Volatility 3 may require a Windows Server 2016 symbol pack or format conversion.  
— single source: tool return values. Confirmed by: rerun with explicit Volatility symbol path or `vol.py -f <image> windows.info`

**[I-2] `rsydow-a` is a privileged admin account with anomalous lateral spread**  
`rsydow-a` authenticated from 8 distinct IPs including the mail server (172.16.4.6 / 10.10.4.6), AV server (172.16.5.20 / 10.10.5.21), file server (172.16.4.5), ELF server (172.16.5.21), ADMIN workstation (172.16.5.26), and unresolved sources (`-`). Total: 1,045+ successful Type-3 logons over 3 days.  
— single source: call-000036. Confirmed by: shimcache/Amcache on each source host; verify whether `rsydow-a` is a defined service account in AD

**[I-3] Domain `Administrator` account authenticating repeatedly from BASE-AV (172.16.5.20)**  
234 successful Type-3 logons from the AV server as `Administrator` between 2018-09-04 14:03 and 2018-09-07 09:07. The built-in domain Administrator account making network logons to the DC from an AV server is not a normal operational pattern.  
— single source: call-000036. Confirmed by: registry_autoruns on BASE-AV; shimcache/Amcache on BASE-AV; check AV console service account configuration

**[I-4] WDK installation on DC by Administrator in May 2018 is anomalous**  
`wdksetup.exe` (SHA-1: `5bc33f95fe980ba44256329007c25bff7397ef27`) executed from `Administrator\Downloads` and expanded into multiple Temp GUID directories on 2018-05-18. The Windows Driver Kit has no legitimate purpose on a production DC; it may have been used to compile or sign a kernel module.  
— single source: call-000026 (Amcache). Confirmed by: shimcache for execution confirmation; check if any custom `.sys` drivers were installed around 2018-05-18

**[I-5] `rsydow-a` checked "Set the time and date" on 2018-08-16 — possible clock verification or tampering context**  
LNK artifact `Set the time and date.lnk` created in `rsydow-a`'s Recent folder at 2018-08-16 21:48:37.  
— single source: call-000027 (MFT LNK). Confirmed by: parse Security log for Event ID 4616 (system time change) around this timestamp

---

## Contradictions `[CONTRADICTION]`

**[X-1] `subject_srv.exe` created vs. modified timestamps diverge**  
MFT created timestamp: **2018-09-06 22:11:15** (matches service install). MFT modified timestamp: **2018-04-10 19:29:48** (pre-dates deployment by ~5 months). This is consistent with either (a) normal PE compile-time retention in `LastWriteTime`, or (b) deliberate timestomping. Cannot distinguish without `$STANDARD_INFORMATION` vs. `$FILE_NAME` attribute comparison.  
Source: call-000034.

**[X-2] Security log shows no events before 2018-09-04 despite months of system activity**  
Amcache and MFT show continuous activity from April 2018, but the Security log contains zero events before 2018-09-04 12:58 UTC. Either log retention was set to a very small size, or the log was cleared (Event ID 1102 would confirm).  
Source: call-000026/call-000027 vs. call-000036.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1569.002 | System Services: Service Execution | F-Response Subject + Mnemosyne installed as services (call-000033) |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mnemosyne kernel driver provides raw memory access — all process memory including LSASS exposed (call-000033, call-000035) |
| T1005 | Data from Local System | F-Response Subject enables remote read of DC disk and memory over network (call-000034) |
| T1078.002 | Valid Accounts: Domain Accounts | `cbarton-a` used for service deployment; `rsydow-a` spread across 8+ hosts; `Administrator` from AV server (call-000036) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Security log starts abruptly 2018-09-04 — 4.5 months of events missing (call-000036, X-2) |
| T1564.002 | Hide Artifacts: Hidden Users (possible) | `rsydow-a` and `rsydow` are two separate accounts for the same person — admin/user account pair; verify creation dates |
| T1588.002 | Obtain Capabilities: Tool | WDK installed on DC — unusual tool acquisition on a production DC (call-000026) |
| T1018 | Remote System Discovery | ANONYMOUS LOGON null-session from BASE-ADMIN (345 logons), WKSTN-03 (316), RD-02 (315) — potential net view/enumeration cadence (call-000036) |

---

## Recommended Next Steps (Prioritized)

1. **[CRITICAL] Resolve Volatility failure** — Re-run `mem_pslist` and `mem_netscan` with explicit Windows Server 2016 symbol path. Run `vol.py -f <image> windows.info` first to confirm image format and suggested profile. The DC process list and network connections at capture time are currently dark.

2. **[HIGH] Confirm Security log clearing** — Run `parse_event_logs` against `Security.evtx` filtering on **Event ID 1102** (log cleared) and **4688** (process creation, if audited). If 1102 exists, note the account and timestamp.

3. **[HIGH] Investigate `Administrator` logons from BASE-AV (172.16.5.20)** — Run `get_amcache`, `registry_autoruns`, and `shimcache` against a BASE-AV image if available. 234 network logons by the built-in domain Administrator originating from an AV server is a high-priority lateral movement indicator.

4. **[HIGH] Characterize `rsydow-a` account** — Run `registry_autoruns` against `NTUSER.DAT` for `rsydow-a`. Check AD for account creation date and group membership. The 8-IP authentication spread may indicate a compromised admin account or misused service account.

5. **[MEDIUM] Investigate WDK installation (2018-05-18)** — Run targeted MFT filter for `.sys` files created between 2018-05-18 and 2018-05-30. If a custom kernel driver was compiled and installed after the WDK, this is a critical finding.

6. **[MEDIUM] Investigate `tyler.oslund`** — Only active 2018-09-06 01:38–12:40 (same day as F-Response deployment at 22:11). Run `parse_event_logs` filtered to this account to determine whether it was used to stage access before the deployment.

7. **[MEDIUM] Run `shimcache`** — Amcache and Prefetch (disabled) are the only disk-based execution sources parsed. Shimcache (AppCompatCache in SYSTEM hive) would provide a third independent execution list to cross-reference hits for `regedit`, `rundll32`, `win32calc`, and `consent.exe`.

8. **[LOW] Run `powershell_logs`** — Parse PowerShell ScriptBlock logs (Event ID 4104). Given `rundll32.exe` execution on a DC, PowerShell LOLBin activity is plausible.

---

## Tool Call Index

| call_id | Tool | Description |
|---|---|---|
| call-000026 | `get_amcache` | Amcache.hve — 37 records, known-good suppressed |
| call-000027 | `extract_mft_timeline` | Full $MFT — 100 interesting records from 236,778 total |
| call-000028 | `analyze_prefetch` | Prefetch — empty (disabled on DC) |
| call-000029 | `mem_pslist` | Process list from memory image — 0 records |
| call-000030 | `mem_netscan` | Network connections from memory image — 0 records |
| call-000031 | `parse_event_logs` | Security.evtx EID 4624 — 213 of 44,132 records returned |
| call-000032 | `parse_event_logs` | Security.evtx EID 4625 — 209 of 396 records returned |
| call-000033 | `parse_event_logs` | System.evtx EID 7045 — 85 records (complete) |
| call-000034 | `extract_mft_timeline` | $MFT filter: subject_srv — 1 record |
| call-000035 | `extract_mft_timeline` | $MFT filter: Mnemosyne — 1 record |
| call-000036 | `logon_summary` | Security.evtx aggregate — 75 actor tuples |
| call-000037 | `registry_autoruns` | SYSTEM hive services plugin — 0 records |
