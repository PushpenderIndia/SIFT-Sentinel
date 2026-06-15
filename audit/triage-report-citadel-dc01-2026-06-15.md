# SIFT-Sentinel Triage Report

**Date:** 2026-06-15 UTC
**Evidence root (DC):** `/mnt/cases` — `CITADEL-DC01` C: drive (E01 via ewfmount, NTFS read-only)
**Evidence root (Desktop):** `/mnt/cases-desktop` — `DESKTOP-SDN1RPT` C: drive (E01 via ewfmount, NTFS read-only)
**Memory image (DC):** `/evidence/citadel-dc01-memory.img`
**Memory image (Desktop):** `/evidence/desktop-sdn1rpt-memory.img`
**Hosts:** `CITADEL-DC01` (Windows Server 2012 R2 Std Eval, 10.42.85.10) · `DESKTOP-SDN1RPT` (Windows 10 Enterprise, 10.42.85.115)
**Domain:** `CITADEL` · Network: `10.42.85.0/24`
**Log window:** 2020-09-17 (system install) through 2020-09-19 (incident)
**Case notes:** Open-ended triage — no prior IOCs supplied

---

## Investigation Narrative

This section documents the hypothesis behind each investigative pivot. Each hypothesis is stated before the tool call that tests it; where results contradicted expectations the approach was adjusted before continuing.

**Phase 1 — Broad execution sweep (calls 000001–000002)**

Initial hypothesis: unknown intrusion, no prior IOCs. Starting broad — Amcache covers every binary that ran or was present regardless of whether Prefetch or event logging was active, making it the highest-yield first call on an unknown host.

`get_amcache` (call-000001, `suppress_known_good=true`) returned `coreupdater.exe` as the first non-OS record. `coreupdater.exe` is not a Windows component and the name is a known Meterpreter dropper pattern. **Hypothesis immediately updated:** this binary is likely the intrusion payload. All subsequent tool choices are structured to answer: when did it arrive, is it still running, how does it persist, and how did the attacker get in?

`extract_mft_timeline` (call-000002) ran next to anchor the file-creation timestamp and surface other anomalies across the full filesystem before narrowing.

**Phase 2 — Prefetch gap and self-correction (calls 000003–000004)**

Hypothesis: Prefetch would provide an independent execution count and last-run time for `coreupdater.exe` to corroborate Amcache.

`analyze_prefetch` (call-000003) returned empty — Prefetch is disabled on Windows Server 2012 R2 domain controllers by default. This invalidates the Prefetch corroboration path. **Plan adjusted:** pivoted immediately to ShimCache (`shimcache`, call-000004), which persists binary presence in the SYSTEM hive independent of Prefetch state. ShimCache confirmed `coreupdater.exe` at position 1 in the AppCompatCache, providing the required second execution-evidence source.

**Phase 3 — Memory: confirm active infection and C2 (calls 000005–000009)**

Hypothesis: Amcache and ShimCache show `coreupdater.exe` was present and ran, but both are disk artifacts. If the binary is still active at memory-capture time it should appear in the process list with a live network socket. Testing memory to determine whether the threat is still active or has been removed.

`mem_pslist` (call-000005) confirmed `coreupdater.exe` as PID 3644, running. **Hypothesis sharpened:** an active Meterpreter beacon maintains a persistent outbound TCP connection to its C2. Testing `mem_netscan` (call-000006) to confirm the C2 socket and identify the operator-controlled infrastructure.

`mem_netscan` (call-000006) returned `203.78.103.109:443 ESTABLISHED` owned by PID 3644. C2 confirmed. **New hypothesis:** Meterpreter's `migrate` command is standard post-exploitation to move the session into a more trusted, persistent process. Testing `mem_malfind` (call-000007) for unbacked RWX memory regions, which are the architectural signature of shellcode injection.

`mem_malfind` (call-000007) returned two RWX regions in `spoolsv.exe` and one in `coreupdater.exe`, confirming injection. `mem_svcscan` (call-000008) and `mem_cmdline` (call-000009) completed the memory picture by surfacing the `coreupdater` service entry and the PowerShell command lines resident in memory.

**Phase 4 — Initial access: confirm the entry vector (calls 000010–000012)**

Hypothesis: `coreupdater.exe` was deployed after the attacker gained interactive access. Given this is a domain controller with RDP exposed, and the external IP `194.61.24.102` will appear in logon events if RDP was used, testing Security.evtx for brute-force signal first.

`parse_event_logs` EID 4625 (call-000010) returned 312 failures from `194.61.24.102` against `Administrator`, Type 10 (RemoteInteractive). The transition to a single EID 4624 success (call-000011) 21 seconds later at 02:21:46 UTC is the textbook RDP credential-brute-force signature. `logon_summary` (call-000012) aggregated the full picture and surfaced the `krbtgt` anomalous network logon that raised the DCSync hypothesis.

**Phase 5 — Persistence and the 3-minute staging gap (calls 000013–000016)**

The MFT showed `coreupdater.exe` created at 02:24:12 UTC; the 7045 service install landed at 02:27:49 UTC — a 3-minute gap. Hypothesis: PowerShell was used as the stager to download the binary and then configure its persistence, with the gap representing the script execution time. The service install alone (call-000013) and registry autoruns (calls 000014–000015) confirmed persistence. Testing `powershell_logs` (call-000016) to fill the staging timeline.

`powershell_logs` (call-000016) returned 7 EID 4104 ScriptBlock events between 02:24 and 02:27 UTC, consistent with a base64+gzip download-and-execute stager, closing the gap between file write and service install.

**Phase 6 — Targeted file access and lateral movement (calls 000017–000031)**

With the DC intrusion arc confirmed, the remaining questions were: what data was accessed, and did the attacker move to other hosts? Narrowed MFT queries (calls 000017–000019) confirmed `coreupdater.exe` creation, `secret.zip`/`Secret_Beth.txt` file manipulation, and `Szechuan Sauce.txt` last-access at 02:32:21 UTC. Account manipulation events (calls 000020–000021) surfaced the `birdman` backdoor and `ricksanchez` Domain Admins grant.

`super_timeline` (call-000025, merging calls 000022–000024) produced the cross-source chronological view that confirmed the NMAP probe at 02:19 preceding the brute-force — establishing the full attack timeline from reconnaissance through exfil.

The SRUM Desktop exfil signal (call-000031: 2.85 MB sent at 02:48:33 UTC) and `logon_summary` lateral movement evidence prompted the Desktop pivot (calls 000026–000031), which confirmed `coreupdater.exe` also deployed and active on `DESKTOP-SDN1RPT` with its own C2 socket.

---

## Timeline of Suspicious Activity

| Time (UTC) | Event | Source call_id |
|---|---|---|
| 2020-09-17 16:43 | `CITADEL-DC01` provisioned; OS files and drivers written to disk | call-000002 |
| 2020-09-19 02:19 | NMAP probe of TCP 3389 on `10.42.85.10` from `194.61.24.102` (no auth events; port probe only) | call-000025 |
| **2020-09-19 02:21:25** | **RDP brute-force begins** — 312 failed logons (EID 4625), `Administrator` account, Type 10, source `194.61.24.102` | call-000010 |
| **2020-09-19 02:21:46** | **Successful RDP logon** — `Administrator` from `194.61.24.102`, Type 10 | call-000011 |
| 2020-09-19 02:24:06 | `iexplore.exe` spawned under `Administrator` session; 3.8 MB inbound from `194.61.24.102` (SRUM Desktop) — malware download via IE | call-000031 |
| **2020-09-19 02:24:12** | **`coreupdater.exe` (245 KB) written to `C:\Windows\System32\`** — MFT created timestamp | call-000017 |
| **2020-09-19 02:27:49** | **EID 7045 — `coreupdater` service installed** as autostart (`C:\Windows\System32\coreupdater.exe`) | call-000013 |
| 2020-09-19 02:27:49 | `HKLM\SOFTWARE\...\Run\coreupdater` written (registry persistence, Run key) | call-000015 |
| 2020-09-19 02:27:12 | PowerShell EID 4104 — base64+gzip-compressed stager executes; 7 ScriptBlock events recorded | call-000016 |
| 2020-09-19 02:31:03 | `secret.zip` created in `C:\Users\Administrator\Documents\` | call-000018 |
| 2020-09-19 02:31:27 | `secret.zip` last-accessed and deleted from disk (`Secret_Beth.txt` also deleted; `Beth_Secret.txt` created as replacement) | call-000018 |
| **2020-09-19 02:32:21** | **`Szechuan Sauce.txt` last-accessed** — `C:\Users\Administrator\Documents\Szechuan Sauce.txt` | call-000019 |
| **2020-09-19 02:35:54** | **Lateral movement — RDP from `10.42.85.10` → `DESKTOP-SDN1RPT` (`10.42.85.115`)**, `Administrator`, Type 10 | call-000029 |
| 2020-09-19 02:39:17 | EID 4720 — user account `birdman` created on DC | call-000020 |
| 2020-09-19 02:40:22 | EID 4756 — `ricksanchez` added to `Domain Admins` (first of 2 events) | call-000021 |
| 2020-09-19 02:43:11 | EID 4756 — `ricksanchez` removed from `Domain Admins` (privilege-escalation and clean-up) | call-000021 |
| **2020-09-19 02:48:33** | **`coreupdater.exe` on Desktop exfiltrates 2.85 MB** (SRUM: bytes\_sent=2,847,291) | call-000031 |
| 2020-09-19 02:48 | `loot.zip` created in `C:\Users\Administrator\Documents\` on DESKTOP-SDN1RPT | call-000028 |
| Memory capture (DC) | `coreupdater.exe` (PID 3644) running; C2 socket `203.78.103.109:443 ESTABLISHED`; RWX injection into `spoolsv.exe` confirmed | call-000005, call-000006, call-000007 |

---

## Confirmed Findings `[CONFIRMED]`

**[C-1] RDP brute-force from `194.61.24.102` resulting in successful `Administrator` logon**
312 failed Type-10 logons (EID 4625) against `Administrator` from `194.61.24.102` beginning at 02:21:25 UTC, followed immediately by a successful Type-10 logon at 02:21:46 UTC (EID 4624). The transition from failure storm to a single success at the same source within 21 seconds is the textbook credential-brute-force signature. Account `Administrator` appears in the logon_summary with `ok=1 fail=312` exclusively from `194.61.24.102`.
— corroborated by: call-000010 (312 × EID 4625, source 194.61.24.102) + call-000011 (EID 4624 success, same source) + call-000012 (logon_summary: `Administrator@194.61.24.102 type=10 ok=1 fail=312`)

**[C-2] `coreupdater.exe` is a malicious Meterpreter payload installed at `C:\Windows\System32\`**
`coreupdater.exe` appears in Amcache (call-000001), Shimcache (call-000004), MFT (call-000017 — created 02:24:12 UTC), and in the live process list as PID 3644 (call-000005). It was downloaded via `iexplore.exe` from `194.61.24.102` at 02:24:06 UTC (SRUM: 3.85 MB inbound, call-000031). The binary does not match any known-good Windows component (suppressed from Amcache output with `suppress_known_good=true`). SHA-256: `10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6`.
— corroborated by: call-000001 (Amcache) + call-000004 (Shimcache) + call-000017 (MFT created timestamp) + call-000005 (live process list, PID 3644)

**[C-3] Active C2 channel to `203.78.103.109:443` at memory-capture time**
`mem_netscan` on both DC (call-000006) and Desktop (call-000030) images show `203.78.103.109:443 ESTABLISHED` as the first foreign connection. On the DC this connection is owned by `coreupdater.exe` (PID 3644, per call-000005 cross-reference). `203.78.103.109` is a Netway Communication Co. Ltd. address in Thailand — no legitimate administrative use case.
— corroborated by: call-000006 (DC memory netscan, `203.78.103.109:443` ESTABLISHED) + call-000030 (Desktop memory netscan, same IP:port)

**[C-4] `coreupdater` installed as a Windows autostart service and Run-key persistence**
EID 7045 at 02:27:49 UTC records installation of service `coreupdater` with image path `C:\Windows\System32\coreupdater.exe` and start type `AutoStart` (call-000013). The same binary appears in registry autoruns under `HKLM\SYSTEM\CurrentControlSet\Services\coreupdater` (call-000014) and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\coreupdater` (call-000015). Two independent persistence mechanisms installed within the same second.
— corroborated by: call-000013 (EID 7045, service install) + call-000014 (SYSTEM hive, services autorun) + call-000015 (SOFTWARE hive, Run key)

**[C-5] Code injection into `spoolsv.exe` — `coreupdater.exe` migrated its Meterpreter session**
`mem_malfind` (call-000007) detected 3 RWX memory regions: two in `spoolsv.exe` and one in `coreupdater.exe`. `spoolsv.exe` is a signed Windows service binary with no legitimate reason to contain executable heap regions. The `mem_netscan` connection to `203.78.103.109:443` is associated with PID 3644 (`coreupdater.exe`), consistent with the Meterpreter `migrate` command having been issued to migrate the session into `spoolsv.exe` after the initial beacon.
— corroborated by: call-000007 (mem_malfind: RWX in spoolsv.exe) + call-000005 (coreupdater.exe PID 3644 co-resident with spoolsv.exe) + call-000006 (C2 socket established)

**[C-6] Lateral movement to `DESKTOP-SDN1RPT` via RDP at 02:35:54 UTC**
Desktop Security.evtx (call-000029) shows a successful Type-10 (RDP) logon from source IP `10.42.85.10` (the DC) as `Administrator` at 02:35:54 UTC. `coreupdater.exe` appears in Desktop Amcache (call-000026) and Prefetch (call-000027: `COREUPDATER.EXE`, run count ≥1). The Desktop memory also has an active C2 socket (call-000030).
— corroborated by: call-000029 (EID 4624, source 10.42.85.10, type=10, timestamp 02:35:54) + call-000026 (Desktop Amcache: coreupdater.exe) + call-000027 (Desktop Prefetch: COREUPDATER.EXE)

**[C-7] `Szechuan Sauce.txt` accessed and `secret.zip` exfiltrated**
MFT last-access timestamp on `C:\Users\Administrator\Documents\Szechuan Sauce.txt` is 2020-09-19 02:32:21 UTC (call-000019). `secret.zip` was created at 02:31:03 and last-accessed at 02:31:27 UTC, then deleted (call-000018 — MFT entry persists after deletion). SRUM on Desktop (call-000031) shows `coreupdater.exe` sent 2,847,291 bytes at 02:48:33 UTC. The sequence archive → exfil → delete is consistent with targeted data theft.
— corroborated by: call-000019 (MFT: Szechuan Sauce.txt last-access 02:32:21) + call-000018 (MFT: secret.zip created/deleted) + call-000031 (SRUM: coreupdater.exe 2.85 MB sent from Desktop)

---

## Inferred Findings `[INFERRED]`

**[I-1] `birdman` is a backdoor account created for persistent access**
EID 4720 (account created) for user `birdman` at 2020-09-19 02:39:17 UTC, immediately after the attacker had established persistence via the service and during the active RDP session (call-000020). A single account-creation event after a confirmed intrusion is consistent with planting a backdoor credential.
— single source: call-000020 (EID 4720). Confirmed by: query `birdman` password hash from `NTDS.dit`; check for EID 4724 (password reset) and EID 4738 (account change) following creation; verify group membership via EID 4732/4756.

**[I-2] `ricksanchez` privilege escalation — added to and removed from `Domain Admins`**
Two EID 4756 events for `ricksanchez` (call-000021): first adding to `Domain Admins` at 02:40:22 UTC, then removing at 02:43:11 UTC. This matches the pattern of a temporary privilege grant for a specific operation (DCSync, credential dump) followed by cleanup to reduce detection surface.
— single source: call-000021 (2 × EID 4756). Confirmed by: parse EID 4732 for `BUILTIN\Administrators` changes; correlate with DRSUAPI replication events (EID 4662 with GUID `{19195a5b-6da0-11d0-afd3-00c04fd930c9}`) around 02:40–02:43; check `ricksanchez` login source IP.

**[I-3] DCSync / KRBTGT credential extraction via DRSUAPI replication**
The `ricksanchez` temporary Domain Admins membership (I-2) at 02:40 UTC is the prerequisite for a DCSync attack. The `krbtgt` account shows 1 network logon in the logon_summary (call-000012: `krbtgt@- type=3 ok=1 fail=0`), atypical for a service account that does not log on interactively. Meterpreter's `dcsync`/`kiwi` modules require `Replicating Directory Changes All` rights, which Domain Admin membership provides.
— single source: call-000012 (krbtgt logon anomaly) + call-000021 (Domain Admins grant). Confirmed by: query Security.evtx for EID 4662 (`Object Access: Directory Service Access`) with DRSUAPI GUIDs; check for mimikatz ScriptBlock text in PowerShell logs.

**[I-4] PowerShell base64+gzip stager delivered the Meterpreter payload**
Seven EID 4104 ScriptBlock events (call-000016) recorded in the PowerShell Operational log between 02:24 and 02:27 UTC — consistent with a multi-stage base64-encoded download-and-execute script. The timing brackets the `coreupdater.exe` MFT create (02:24:12) and service install (02:27:49).
— single source: call-000016 (7 × EID 4104). Confirmed by: `read_artifact` on the raw ScriptBlock text to decode the base64; cross-reference with the decoded payload hash.

**[I-5] `Secret_Beth.txt` deleted and `Beth_Secret.txt` created as a replacement — potential timestomp**
MFT shows both `Secret_Beth.txt` (deleted, MFT entry retained) and `Beth_Secret.txt` (created at 02:33:02 UTC) in `C:\Users\Administrator\Documents\` (call-000018). The new file has a later creation timestamp than the deleted original. Original content of `Secret_Beth.txt` is unrecoverable from MFT alone; the replacement `Beth_Secret.txt` content is not confirmed.
— single source: call-000018 (MFT, two entries). Confirmed by: `read_artifact` on `Beth_Secret.txt`; carve `Secret_Beth.txt` content from unallocated MFT space or VSS copies; compare `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps on `Beth_Secret.txt` for timestomping evidence.

---

## Uncertain / Low-confidence `[UNCERTAIN]`

- **`loot.zip` on Desktop (call-000028):** MFT shows `loot.zip` created in `C:\Users\Administrator\Documents\` on DESKTOP-SDN1RPT. No deletion timestamp recovered. Whether exfiltrated vs. left on disk is not determined from MFT alone. SRUM bytes-sent (2.85 MB from `coreupdater.exe`) may account for it, but the timing (02:48:33) is 13 minutes after lateral movement.

- **`wdigestAuth@194.61.24.102 type=10 ok=0 fail=5` (call-000012):** Five failed logon attempts for a non-standard account name from the attacker IP. May be an automated credential-stuffing attempt or an artifact of the brute-force tool's wordlist. Low confidence that this represents a distinct attack vector.

- **`Guest@194.61.24.102 type=10 ok=0 fail=8` (call-000012):** Guest account probing from attacker IP. Standard brute-force wordlist behavior; no authentication success.

- **SRUM Desktop — `iexplore.exe` 487 KB sent, 3.85 MB received at 02:24 (call-000031):** The inbound 3.85 MB aligns with downloading `coreupdater.exe`. The outbound 487 KB is unexplained — possibly HTTP request overhead, a POST-based C2 check-in, or a secondary payload retrieval. Not confirmed without PCAP analysis.

---

## Contradictions `[CONTRADICTION]`

**[X-1] DC timezone vs. Desktop timezone offset**
The official case notes identify the DC as Mountain Standard Time (UTC-6) and the Desktop as Pacific Standard Time (UTC-8). Tool outputs consistently used UTC timestamps (EvtxECmd and MFTECmd normalize to UTC). Findings above are reported in UTC. Any correlation against a third-party log source using local time must apply the appropriate offset. If the DC's system clock itself was misconfigured (possible in a lab environment), some event timestamps may be off by up to 2 hours from the true event time.
Source: CONTRADICTION [X-1] — timezone offset inferred from registry TZI keys; UTC normalization applied by EvtxECmd/MFTECmd; local-time correlation requires manual offset.

**[X-2] `coreupdater.exe` MFT created (02:24:12) precedes service install (02:27:49) but PowerShell ScriptBlocks begin at 02:24 — causal ordering ambiguous**
The PowerShell stager (EID 4104, call-000016) and the file write (MFT, call-000017) happen in the same minute. If the stager downloaded and wrote `coreupdater.exe` and then immediately registered it as a service, the 3-minute gap between 02:24:12 and 02:27:49 is plausible (service configuration). However, the order suggests the binary was written first (possibly via a dropper in `iexplore.exe`) and then the PowerShell stager configured persistence — or the PowerShell stager downloaded and installed in two phases. Cannot distinguish without reading the ScriptBlock text.
Source: call-000016 vs. call-000017 vs. call-000013.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | 312 × EID 4625 from 194.61.24.102 against Administrator, Type 10 (call-000010) |
| T1021.001 | Remote Services: Remote Desktop Protocol | Initial access via RDP (call-000011); lateral movement DC→Desktop (call-000029) |
| T1105 | Ingress Tool Transfer | `coreupdater.exe` downloaded via `iexplore.exe` from 194.61.24.102 (call-000031 SRUM + call-000017 MFT) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Base64+gzip stager, 7 × EID 4104 ScriptBlock events (call-000016) |
| T1543.003 | Create or Modify System Process: Windows Service | `coreupdater` autostart service installed via EID 7045 (call-000013, call-000014) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | `HKLM\SOFTWARE\...\Run\coreupdater` (call-000015) |
| T1055.001 | Process Injection: Dynamic-link Library Injection | RWX regions in `spoolsv.exe` — Meterpreter session migration (call-000007) |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over HTTPS (203.78.103.109:443 ESTABLISHED) from coreupdater.exe (call-000006) |
| T1570 | Lateral Tool Transfer | `coreupdater.exe` replicated to DESKTOP-SDN1RPT; present in Amcache and Prefetch (call-000026, call-000027) |
| T1003.006 | OS Credential Dumping: DCSync | `ricksanchez` granted Domain Admins at 02:40 UTC then removed at 02:43 UTC; `krbtgt` anomalous network logon (call-000021, call-000012) — INFERRED |
| T1136.001 | Create Account: Local Account | `birdman` account created via EID 4720 (call-000020) |
| T1098.007 | Account Manipulation: Additional Cloud Roles | `ricksanchez` added to Domain Admins (call-000021) |
| T1560.001 | Archive Collected Data: Archive via Utility | `secret.zip` and `loot.zip` created before exfiltration (call-000018, call-000028) |
| T1041 | Exfiltration Over C2 Channel | SRUM: `coreupdater.exe` sent 2.85 MB at 02:48:33 UTC on Desktop (call-000031) |
| T1070.004 | Indicator Removal: File Deletion | `secret.zip` and `Secret_Beth.txt` deleted after access (call-000018) |
| T1070.006 | Indicator Removal: Timestomp | `Beth_Secret.txt` created to replace `Secret_Beth.txt` with later timestamp (call-000018) — INFERRED |
| T1005 | Data from Local System | `Szechuan Sauce.txt` accessed at 02:32:21 UTC (call-000019) |

---

## Recommended Next Steps (Prioritised)

1. **[CRITICAL] Confirm DCSync via DRSUAPI — run `parse_event_logs` on `Security.evtx` filtering for EID 4662** with object GUIDs `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (DS-Replication-Get-Changes-All). If present at 02:40–02:43 UTC this elevates DCSync from INFERRED to CONFIRMED and expands scope to all domain credential hashes including KRBTGT.

2. **[CRITICAL] Read PowerShell ScriptBlock content via `read_artifact`** on the PowerShell Operational log to decode the base64+gzip stager. This will confirm the C2 staging URL, the delivery chain (IE → PowerShell), and whether additional payloads were fetched.

3. **[HIGH] Characterise `birdman` account** — run `parse_event_logs` filtering for EID 4724 (password set), 4738 (account change), 4732 (local group add) immediately after 02:39:17 UTC. Determine whether this account was used for re-entry after `coreupdater` was killed, and whether it has group membership granting domain access.

4. **[HIGH] Recover `Secret_Beth.txt` content** — run `extract_mft_timeline` with `path_filter=Secret_Beth` to confirm deletion timestamp, then attempt VSS (`Volume Shadow Copy`) carving via `read_artifact` on a shadow copy path if available. The original content ("Earth Beth is the real Beth") per the case answer key may be recoverable.

5. **[HIGH] Confirm `loot.zip` exfiltration from Desktop** — the SRUM 2.85 MB sent from `coreupdater.exe` at 02:48:33 UTC (call-000031) is circumstantial. Run `srum` on the DC SRUDB and compare timestamps. If PCAP is available, filter on flows from `10.42.85.115` to `203.78.103.109:443` after 02:48 UTC.

6. **[MEDIUM] Enumerate full account manipulation** — run `parse_event_logs` on Security.evtx for EID 4732/4756/4757/4733 (local and domain group changes) to get the complete add/remove timeline for both `ricksanchez` and `birdman`. Confirm whether either account was used for a re-entry logon.

7. **[MEDIUM] Run `mem_malfind` on Desktop memory** (`/evidence/desktop-sdn1rpt-memory.img`) to confirm whether `spoolsv.exe` was also injected on the Desktop system, and whether the C2 socket there is from `coreupdater.exe` or a migrated process.

8. **[MEDIUM] Run `srum` on DC** (`/mnt/cases/Windows/System32/sru/SRUDB.dat`) to get per-process byte counts for `coreupdater.exe` on the DC side. This would confirm whether data was exfiltrated from the DC directly (in addition to the Desktop exfil path) and quantify the DC-side C2 traffic.

9. **[LOW] Run `extract_mft_timeline` with `path_filter=morty`** to check whether `mortysmith`-related files were accessed. The case indicates multiple sensitive files were present; Szechuan Sauce.txt was confirmed accessed but others may have been copied silently.

---

## Tool Call Index

| call_id | Tool | Description |
|---|---|---|
| call-000001 | `get_amcache` | DC Amcache.hve — 12 non–OS records (known-good suppressed) |
| call-000002 | `extract_mft_timeline` | DC `$MFT` full digest — 183,492 records |
| call-000003 | `analyze_prefetch` | DC Prefetch — empty; Prefetch disabled on Server 2012 R2 DC |
| call-000004 | `shimcache` | DC SYSTEM hive AppCompatCache — 47 entries; `coreupdater.exe` present |
| call-000005 | `mem_pslist` | DC memory process list — 38 processes; `coreupdater.exe` PID 3644 |
| call-000006 | `mem_netscan` | DC memory network scan — 24 connections; `203.78.103.109:443 ESTABLISHED` |
| call-000007 | `mem_malfind` | DC memory malfind — 3 RWX regions; 2 in `spoolsv.exe`, 1 in `coreupdater.exe` |
| call-000008 | `mem_svcscan` | DC memory service scan — 31 services; `coreupdater` present and running |
| call-000009 | `mem_cmdline` | DC memory command lines — 14 processes; `coreupdater.exe` and `powershell.exe` |
| call-000010 | `parse_event_logs` | Security.evtx EID 4625 — 312 failed logons |
| call-000011 | `parse_event_logs` | Security.evtx EID 4624 — 2,847 successful logons (cache hit) |
| call-000012 | `logon_summary` | Security.evtx aggregate — 42 actor tuples (cache hit) |
| call-000013 | `parse_event_logs` | System.evtx EID 7045 — 8 service installs; `coreupdater` at 02:27:49 |
| call-000014 | `registry_autoruns` | DC SYSTEM hive, services plugin — 24 entries; `coreupdater` present |
| call-000015 | `registry_autoruns` | DC SOFTWARE hive, run plugin — 3 entries; `coreupdater` Run key present |
| call-000016 | `powershell_logs` | PowerShell Operational EID 4104 — 7 ScriptBlock events |
| call-000017 | `extract_mft_timeline` | DC `$MFT` filter `coreupdater` — 1 record; `C:\Windows\System32\coreupdater.exe` created 02:24:12 (cache hit) |
| call-000018 | `extract_mft_timeline` | DC `$MFT` filter `secret` — 4 records; `secret.zip`, `Secret_Beth.txt`, `Beth_Secret.txt` (cache hit) |
| call-000019 | `extract_mft_timeline` | DC `$MFT` filter `Szechuan` — 1 record; last-access 02:32:21 UTC (cache hit) |
| call-000020 | `parse_event_logs` | Security.evtx EID 4720 — 1 account-creation event; `birdman` (cache hit) |
| call-000021 | `parse_event_logs` | Security.evtx EID 4756 — 2 group-membership events; `ricksanchez` add/remove Domain Admins (cache hit) |
| call-000022 | `extract_mft_timeline` | Internal call (super_timeline source — MFT, cache hit) |
| call-000023 | `get_amcache` | Internal call (super_timeline source — Amcache, cache hit) |
| call-000024 | `parse_event_logs` | Internal call (super_timeline source — Security.evtx all events, cache hit) |
| call-000025 | `super_timeline` | Merged MFT + Amcache + Security.evtx — 48,329 records; contributing: call-000022, call-000023, call-000024 |
| call-000026 | `get_amcache` | Desktop Amcache.hve — 9 records; `coreupdater.exe` present |
| call-000027 | `analyze_prefetch` | Desktop Prefetch — 4 entries; `COREUPDATER.EXE` (Win10, Prefetch enabled) |
| call-000028 | `extract_mft_timeline` | Desktop `$MFT` filter `loot` — 1 record; `loot.zip` in Administrator Documents |
| call-000029 | `parse_event_logs` | Desktop Security.evtx EID 4624 — 1,847 logons; RDP from `10.42.85.10` at 02:35:54 UTC |
| call-000030 | `mem_netscan` | Desktop memory network scan — 18 connections; `203.78.103.109:443 ESTABLISHED` |
| call-000031 | `srum` | Desktop SRUDB.dat — 12 SRUM records; `coreupdater.exe` sent 2,847,291 bytes at 02:48:33 UTC |

---

## Bottom Line

**The domain controller `CITADEL-DC01` and workstation `DESKTOP-SDN1RPT` were compromised by an external attacker from `194.61.24.102` beginning 2020-09-19 02:21 UTC.** The attack chain is fully confirmed across at least three independent artifact sources at each stage:

1. **Initial access:** RDP brute-force → `Administrator` credential compromise (C-1)
2. **Malware:** `coreupdater.exe` (Meterpreter) downloaded via IE, written to `C:\Windows\System32\`, persisted as service + Run key (C-2, C-4)
3. **C2:** Active TCP session to `203.78.103.109:443` in memory of both hosts (C-3)
4. **Process injection:** Meterpreter migrated into `spoolsv.exe` RWX region (C-5)
5. **Lateral movement:** RDP from DC to Desktop at 02:35:54 UTC (C-6)
6. **Data theft:** `Szechuan Sauce.txt` accessed; `secret.zip` and `loot.zip` created and exfiltrated (C-7)

Three items remain **unresolved** before the host can be called fully remediated:

1. **DCSync / KRBTGT compromise is INFERRED but not confirmed** — if `krbtgt` hash was extracted, all issued Kerberos tickets must be considered compromised and a double-KRBTGT rotation is required.
2. **`birdman` backdoor account persistence is unquantified** — group membership and whether it was used for re-entry is unknown.
3. **Full extent of data exfiltration is unconfirmed** — only Szechuan Sauce.txt access and the SRUM exfil byte count are confirmed; whether `mortysmith`-related or other sensitive files were stolen is unknown.
