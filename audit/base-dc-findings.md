# SIFT-Sentinel Triage Report

**Host:** base-dc.shieldbase.lan (Windows Server 2016 domain controller)
**Evidence root:** /mnt/cases
**Memory image:** /evidence/base-dc-memory.img
**Case notes / IOCs supplied:** none — unbiased full-host sweep

## Tooling Limitations Affecting Confidence

Read these first; they cap the confidence of several findings below.

- The memory image returned 0 records for both mem_pslist (call-000009) and mem_netscan (call-000010), with no error. Live-process and C2 analysis is unavailable: injected processes and external connections can be neither confirmed nor excluded.
- Prefetch is absent (call-000008) — disabled on this DC. The primary cross-corroborator for evidence of execution is gone.
- parse_event_logs exposes only event_id, time, computer, and description — no account name, source IP, logon type, or service name/ImagePath. Logon and service-install attribution is therefore impossible with current tooling, capping several items at UNCERTAIN.

## Timeline of Suspicious / Notable Activity

- 2018-05-08 22:09 — McAfee Agent install (mfemactl.exe in Administrator Temp; Agent dirs). Benign. (call-000007, call-000013, call-000014)
- 2018-08-16 to 2018-09-07 — Recurring interactive PowerShell by rsydow-a on the DC; transcripts on 08-16 (x3), 08-17, 08-28, 09-03, 09-07. (call-000015)
- 2018-09-04 13:11 to 2018-09-05 22:56 — Failed-logon storm, ~15-minute cadence, 204 events. (call-000012)
- 2018-09-05 12:16 / 12:27 — Windows\Temp\DSWBFB8.tmp, DSW5BA0.tmp created. (call-000014)
- 2018-09-06 22:11 (x2) — Clustered service installs, off the normal 2-day cadence. (call-000013)
- 2018-09-07 20:25:57 — Windows\NTDS\temp.edb created (AD database temp). (call-000014)
- 2018-09-07 20:26 to 20:30 (x2) — Clustered service installs. (call-000013)
- 2018-09-07 20:29 to 21:00 — rsydow-a interactive session: GPP Drives.xml, PowerShell transcript (16:36 local), IE history, Cortana/Media caches. (call-000015)

## Confirmed Findings [CONFIRMED]

None meet the two-independent-source bar. Prefetch is gone and the memory image is empty, so the usual corroboration chains (Amcache + Prefetch + MFT) cannot be completed. That degradation of corroboration capacity is itself a finding.

## Inferred Findings [INFERRED]

- Host is substantially a clean DC baseline. Amcache (call-000006, 37 records) is almost entirely signed OS binaries; the only user-writable-path executables are benign installers (wdksetup.exe = Windows Driver Kit, mfemactl.exe = McAfee). The MFT Temp sweep (call-000014, 913 records) found zero deleted executables, zero malware-like binaries, and no double-extensions or ADS in Temp. Confirmed by: a working memory image plus Prefetch would allow ruling out memory-only / fileless implants.
- Automated failed-logon storm, 2018-09-04 13:11 to 2018-09-05 22:56, metronomic ~15-minute cadence with triple-bursts (call-000012). The mechanical regularity points to an automated agent or scheduled task with stale credentials, not interactive brute force. Confirmed by: the account name and source IP from raw 4625 EventData, which current tooling does not expose.
- rsydow-a ran PowerShell interactively on the DC repeatedly (08-16 through 09-07) with transcription enabled (call-000015). The -a suffix implies an admin account; consistent with either legitimate DC administration or hands-on-keyboard activity. Confirmed by: reading the transcript contents via a sanctioned read path.

## Contradictions [CONTRADICTION]

- None surfaced between sources. The only tension is absence vs. expectation: a DC with 26,811 successful logons and an active admin produced an empty memory capture, which is inconsistent with a live host. Treat /evidence/base-dc-memory.img as missing / unreadable / wrong path, not as "no activity."

## Items Needing Follow-up [UNCERTAIN]

- Windows\NTDS\temp.edb created 2018-09-07 20:25:57 immediately before two 7045 service installs (20:26 to 20:30). The pattern matches NTDS.dit / VSS credential-extraction TTPs (ntdsutil IFM), but is equally consistent with routine AD maintenance or reboot. Unattributable and uncorroborated; cannot escalate.
- Off-cadence 7045 clusters on 09-06 22:11 and 09-07 20:26 break the otherwise every-2-days update rhythm, but without service names (tool limitation) their nature is unknown.
- Windows\Temp\DSW*.tmp (09-05): unidentified temp files; not executables.

## MITRE ATT&CK Mapping (candidate, evidence-limited)

- T1110 Brute Force / Credential Stuffing — failed-logon storm (call-000012). Low confidence; could be a misconfigured service account.
- T1059.001 Command and Scripting Interpreter: PowerShell — recurring transcripts for rsydow-a (call-000015).
- T1003.003 OS Credential Dumping: NTDS — hypothesis only, from NTDS\temp.edb plus service-install timing (call-000014, call-000013). Not corroborated.
- T1543.003 Create or Modify System Process: Windows Service — off-cadence 7045 installs (call-000013). Nature unknown.

## Recommended Next Steps (prioritised)

1. Fix the memory evidence. Verify the path/mount of /evidence/base-dc-memory.img and re-run mem_pslist and mem_netscan. An empty DC capture is a collection failure, not a result.
2. Pull raw 4625 / 4624 EventData (TargetUserName, IpAddress, LogonType, WorkstationName) to attribute the failed-logon storm — the single most informative gap.
3. Read the rsydow-a PowerShell transcripts (especially ...20180907163638.txt and the 08-16 set) via the audited read path; they likely contain verbatim commands run on the DC.
4. Retrieve 7045 service names / ImagePaths for the 09-06 22:11 and 09-07 20:26 clusters; correlate against the NTDS\temp.edb write to confirm or deny NTDS.dit extraction.
5. Add an execution corroborator absent Prefetch: pull SRUM, ShimCache (SYSTEM hive), and the full-detail Amcache set to rebuild the execution timeline.

## Bottom Line

No malware, dropped binaries, deleted executables, or C2 were found in the available artifacts. The host looks largely like a clean DC baseline. The three real leads — an automated failed-logon storm, repeated admin PowerShell by rsydow-a, and NTDS/temp plus off-cadence service activity on 09-06/07 — are all currently unattributable because the memory image is empty and the event-log tool omits account/IP/service fields. Resolve those two gaps before drawing conclusions.
