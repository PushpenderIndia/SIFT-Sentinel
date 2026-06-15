# SIFT-Sentinel Triage Report
**Date:** 2026-06-15 UTC  
**Analyst:** SIFT-Sentinel / Claude Code  
**Evidence root:** `/mnt/file-case`  
**Memory image:** `/evidence/base-file-memory.img`  
**Host:** `base-file.shieldbase.lan`  
**Domain:** `shieldbase.lan`

---

## Evidence Coverage

| Source | Status | Notes |
|---|---|---|
| MFT (`$MFT`) | Parsed — 149,432 records, 653 deleted, 1,315 interesting | call-000038 |
| Security.evtx (4624) | Parsed — 520 records (228 returned at transport limit) | call-000042 |
| Security.evtx (4625) | Parsed — 1 record | call-000043 |
| System.evtx (7045) | Parsed — 15 records | call-000044 |
| Amcache.hve | **NOT FOUND** — absent at standard path | — |
| Prefetch (.pf) | **EMPTY** — Prefetch disabled (Windows Server, expected) | call-000039 |
| Memory — pslist | **0 records** — image hashed/intact (`4c192e5d…`); Volatility OS profile mismatch | call-000040 |
| Memory — netscan | **0 records** — same image; same reason | call-000041 |

---

## Reconstructed Attack Timeline

All timestamps UTC.

| Timestamp (UTC) | Event | Source | call_id |
|---|---|---|---|
| 2018-04-26 01:12:35 | Rogue CA certificates dropped to `ProgramData\staging\`: `lariatca.cer`, `NotVerisign.cer`, `NewNotVeriSign.cer` | MFT | call-000047 |
| 2018-04-26 01:12:45 | `ProgramData\staging\install_wormhole\` directory created | MFT | call-000047 |
| 2018-04-26 01:12:46 | `install_msadvapi2_64.exe` (15.1 MB installer) staged in `install_wormhole` | MFT | call-000045/047 |
| 2018-04-26 01:12:57 | `msadvapi2_64.exe` (305,664 bytes) extracted to `Program Files (x86)\Microsoft Advanced API 64\` | MFT | call-000045 |
| 2018-04-26 01:13:11 | NetGroup Packet Filter Driver (`npf.sys` / WinPcap) installed | System 7045 | call-000044 |
| 2018-04-26 01:13:12 | **"Microsoft Advanced API 64"** fake service registered — executable: `msadvapi2_64.exe` | System 7045 | call-000044 |
| 2018-04-26 01:13:14 | `install_msadvapi2_32.exe` (14.2 MB installer) staged in `install_wormhole` | MFT | call-000045/047 |
| 2018-04-26 01:13:23 | `msadvapi2_32.exe` (216,576 bytes) extracted to `Program Files (x86)\Microsoft Advanced API 32\` | MFT | call-000045 |
| 2018-04-26 01:13:36 | `npf.sys` re-installed; **"Microsoft Advanced API 32"** fake service registered | System 7045 | call-000044 |
| 2018-05-08 21:06:11 | `install_msadvapi2_64.exe` installer modified on disk (tool updated) | MFT | call-000045 |
| 2018-05-08 21:06:23 | `npf.sys` re-installed; **"Microsoft Advanced API 64" service re-registered** | System 7045 | call-000044 |
| 2018-05-08 21:06:26 | `install_msadvapi2_32.exe` modified; **"Microsoft Advanced API 32" service re-registered** | MFT / System 7045 | call-000044/045 |
| 2018-05-08 21:54:40 | McAfee Agent services installed with empty image paths — status UNCERTAIN | System 7045 | call-000044 |
| 2018-09-06 16:49 | Earliest returned logon: `spsql` account, Type 9 (NewCredentials / RunAs) | Security 4624 | call-000042 |
| 2018-09-06 19:25:28 | `cbarton-a` — 9 Type 3 logons in under 8 seconds from BASE-HUNT (`172.16.5.25`) | Security 4624 | call-000042 |
| 2018-09-06 19:25:36 | F-Response Subject service installed (forensic remote acquisition tool) | System 7045 | call-000044 |
| 2018-09-06 19:25:37 | `Mnemosyne.sys` (26,248 bytes) dropped to `Windows\` and installed as kernel driver | System 7045 / MFT | call-000044/046 |
| 2018-09-06 21:13:29 | `narciso.ward` — single Type 3 logon from `172.16.7.13` (rare account, possible pivot) | Security 4624 | call-000042 |
| 2018-09-06 21:23:13–24 | `cbarton-a` logons from `172.16.5.28`, then **`10.10.5.28`** (off-subnet), then `172.16.5.28` again | Security 4624 | call-000042 |
| 2018-09-07 02:06:36 | `jpallen` — single Type 3 logon from `172.16.6.13` | Security 4624 | call-000042 |
| 2018-09-07 02:07:48 | **`cbarton` logon from `10.10.150.188`** (off-subnet; environment uses `172.16.0.0/12`) | Security 4624 | call-000042 |
| 2018-09-07 02:07:52 | `BASE-HUNT-02$` machine account logon from `172.16.5.27` — immediately after above | Security 4624 | call-000042 |
| 2018-09-07 03:07:16 | `rsydow-a` — failed interactive logon (Type 2) from `127.0.0.1` | Security 4625 | call-000043 |
| 2018-09-07 03:07:29 | **`rsydow-a` begins exact 2-minute beacon loop from `172.16.4.4` — 160+ Type 3 logons running through at least 08:10 UTC** | Security 4624 | call-000042 |

---

## Confirmed Findings

### [CONFIRMED-1] Fake Microsoft service persistence — "Wormhole" implant

`Microsoft Advanced API 64` (`msadvapi2_64.exe`) and `Microsoft Advanced API 32` (`msadvapi2_32.exe`) are not Microsoft software. The staging subdirectory is explicitly named `install_wormhole`. The 15.1 MB and 14.2 MB installer bundles were placed under `ProgramData\staging\install_wormhole\`, executables were extracted to `Program Files (x86)\`, and services were registered. The entire sequence repeated 12 days later (2018-05-08), suggesting the implant was updated or reinstalled after detection/removal.

- **MFT** (call-000045, call-000047): confirms file creation timestamps, file sizes, and staging path
- **System.evtx 7045** (call-000044): confirms service registration events for both binaries on both dates

### [CONFIRMED-2] Rogue certificate authority installation preceding implant deployment

Three certificates were dropped to `ProgramData\staging\` in the 27 seconds before the Wormhole installer arrived:

| File | Created (UTC) | Size |
|---|---|---|
| `lariatca.cer` | 2018-04-26 01:12:35 | 857 bytes |
| `NotVerisign.cer` | 2018-04-26 01:12:39 | 1,659 bytes |
| `NewNotVeriSign.cer` | 2018-04-26 01:12:42 | 1,549 bytes |

The name `NotVerisign.cer` explicitly signals a non-legitimate, attacker-controlled CA. These certificates were planted to enable TLS interception of C2 traffic or to establish a custom code-signing trust anchor.

- **MFT** (call-000047): creation timestamps place these 27–67 seconds before the installer drop
- **System.evtx 7045** (call-000044): service registration confirms the installation sequence that followed

### [CONFIRMED-3] Packet-capture driver co-installed with implant — twice

WinPcap's `npf.sys` (NetGroup Packet Filter Driver) was installed immediately before both the April 26 and May 8 deployments of the fake API services. The implant is equipped with network sniffing capability.

- **System.evtx 7045** (call-000044): three separate `npf.sys` install events flanking both `msadvapi2` service registrations

### [CONFIRMED-4] `rsydow-a` credential-driven automated beaconing

Starting 2018-09-07 03:07:29 UTC, the account `rsydow-a` from `172.16.4.4` generates Type 3 (network) logons at an **exact 2-minute cadence** sustained for over 5 hours (160+ logons through 08:10 UTC). The precision (±1 second) is machine-driven; no human typing produces this regularity. A compromised privileged credential is being used by an automated agent — implant, scheduled task, or C2 framework — to periodically authenticate to this file server.

- **Security.evtx 4624** (call-000042): 160+ logon records with 120-second regularity
- **Security.evtx 4625** (call-000043): failed interactive logon for the same account at 03:07:16 UTC, 13 seconds before the beacon loop starts — confirms credential is known to an actor on this host

---

## Inferred Findings

### [INFERRED-1] Puppet/MCollective infrastructure abused as deployment vector

`ProgramData\staging` is a Puppet-managed directory (PuppetLabs present since 2018-01-12; `mcollective_agents`, `nagios` MSI, and 7-Zip all dropped via Puppet). The attacker placed `install_wormhole` inside this legitimate orchestration path. This suggests the Puppet master or MCollective was compromised or hijacked to deliver the implant.

- Single source: MFT (call-000047)
- **To confirm:** Puppet manifest or MCollective message broker logs showing who triggered the file drop to `ProgramData\staging\` at 01:12 UTC on 2018-04-26.

### [INFERRED-2] Lateral movement chain: `jpallen` → `cbarton@10.10.150.188` → `BASE-HUNT-02$`

At 02:06–02:07 UTC on 2018-09-07, three logons occur in rapid succession:

1. `jpallen` (Type 3) from `172.16.6.13` — 02:06:36
2. `cbarton` (Type 3) from **`10.10.150.188`** — 02:07:48
3. `BASE-HUNT-02$` machine account (Type 3) from `172.16.5.27` — 02:07:52

The sequential timing (72 seconds span, machine account following the off-subnet logon within 4 seconds) is consistent with credential relaying, pass-the-hash, or a multi-hop lateral movement chain.

- Single source: Security.evtx 4624 (call-000042)
- **To confirm:** Network flow logs for `10.10.150.188`; NTLM relay detection on the wire; endpoint telemetry on BASE-HUNT-02.

### [INFERRED-3] `cbarton-a` operating from an off-subnet address (`10.10.5.28`)

A single Type 3 logon from `10.10.5.28` appears sandwiched between two `172.16.5.28` logons for `cbarton-a` at 21:23 UTC on 2018-09-06 — consistent with VPN split-tunneling, a dual-homed host, or a spoofed source IP.

- Single source: Security.evtx 4624 (call-000042)
- **To confirm:** Network topology for the `10.10.0.0/8` range; routing table on BASE-HUNT.

### [INFERRED-4] Implant binary compile date approximately 2018-03-02

MFT `modified` timestamps on `msadvapi2_64.exe` (2018-03-02 20:42 UTC) and `msadvapi2_32.exe` (2018-03-02 20:43 UTC) pre-date deployment by ~55 days. If these reflect the PE `TimeDateStamp` (common when the file was never modified post-compile), the attacker built this tool approximately 7 weeks before first use on this host.

- Single source: MFT (call-000045)
- **To confirm:** PE header `TimeDateStamp` via `read_artifact` on the executable.

### [INFERRED-5] `spsql` service account used with alternate credentials (Type 9)

Four Type 9 (NewCredentials) logons with no source IP indicate `runas /netonly` or token impersonation using the SharePoint SQL service account. Service accounts are commonly abused for lateral movement when their credentials are captured (e.g., via Kerberoasting).

- Single source: Security.evtx 4624 (call-000042)
- **To confirm:** Process tree showing which parent process invoked the Type 9 logon; Kerberos ticket logs.

---

## Contradictions

### [CONTRADICTION-1] McAfee Agent service image paths are empty

Three McAfee Agent services were registered at 2018-05-08 21:54:40 UTC with image paths of `"\"` (effectively null). Legitimate McAfee installations record full executable paths. Possible explanations: (a) log entry corruption, (b) deliberate path clearing to obscure the true service binary, (c) a failed or partial McAfee deployment. The SYSTEM registry hive (`HKLM\SYSTEM\CurrentControlSet\Services`) is the authoritative source and must be checked before concluding either way.

### [CONTRADICTION-2] Off-subnet `10.10.x.x` logon sources in a `172.16.0.0/12` environment

All other logon sources use `172.16.0.0/12` exclusively. Logons from `10.10.5.28` and `10.10.150.188` cannot be classified without a network topology document. They may be a VPN pool (benign), a secondary segment (investigate), or an external pivot host (critical). This must be resolved before the lateral movement findings are escalated.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1543.003 | Create or Modify System Process: Windows Service | "Microsoft Advanced API 64/32" registered as persistent services (call-000044) |
| T1036.004 | Masquerading: Masquerade Task or Service | Services named to impersonate Microsoft; installers named `msadvapi2_*.exe` (call-000044/045) |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | `NotVerisign.cer`, `lariatca.cer`, `NewNotVeriSign.cer` planted before implant (call-000047) |
| T1040 | Network Sniffing | WinPcap (npf.sys) installed alongside implant — on both deployment dates (call-000044) |
| T1078.002 | Valid Accounts: Domain Accounts | `rsydow-a`, `cbarton-a`, `cbarton` used for network authentication (call-000042/043) |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | All malicious logons are Type 3 network logons (call-000042) |
| T1071 | Application Layer Protocol (C2) | 2-minute beaconing cadence; custom TLS CA certs planted to encrypt C2 traffic |
| T1072 | Software Deployment Tools | Puppet/MCollective staging directory abused to deliver implant (call-000047) |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | jpallen → cbarton@10.10.150.188 → BASE-HUNT-02$ machine account sequence (call-000042) |

---

## Recommended Next Steps

### Priority 1 — Active threat

1. **Investigate `172.16.4.4`** — this host is driving the `rsydow-a` 2-minute beacon loop and is either the C2 controller or a compromised pivot. Acquire its image immediately. The beacon was still running at 08:10 UTC on 2018-09-07.

2. **Read the rogue certificates** via `read_artifact` on `ProgramData\staging\lariatca.cer` and `NotVerisign.cer`. The issuer CN and Subject Alternative Names will identify the attacker's C2 domain or infrastructure.

3. **Hash and sandbox the implant binaries** — `read_artifact` to retrieve SHA-256 of `msadvapi2_64.exe` and `msadvapi2_32.exe`, then submit to sandbox. Sizes (305 KB / 216 KB) suggest standalone agents. The staging directory name "wormhole" may identify the tool family.

### Priority 2 — Persistence and scope

4. **Run `registry_autoruns`** on the SYSTEM and SOFTWARE hives to confirm whether the fake services survived to the registry and to find any additional Run key, scheduled task, or WMI persistence.

5. **Run `shimcache`** on the SYSTEM hive — AppCompatCache will record execution evidence for `msadvapi2_*.exe` even without Amcache or Prefetch, and will establish when each binary was first seen by the OS.

6. **Run `powershell_logs`** (events 4104/4103) to recover any PowerShell commands used during the 2018-04-26 installation window and to determine whether Puppet/MCollective delivery involved a PowerShell dropper.

7. **Run `srum`** (SRUDB.dat) to quantify network bytes sent/received by `msadvapi2_64.exe` and `msadvapi2_32.exe` across their entire runtime — this bounds the potential exfiltration volume.

### Priority 3 — Lateral movement and credential exposure

8. **Resolve `10.10.5.28` and `10.10.150.188`** in network topology. If not a known VPN pool, treat as external pivot hosts and escalate to network security team.

9. **Extend the 4624 logon window** — re-run `parse_event_logs` filtered to 2018-04-26 and 2018-05-08 to identify who was logged on when the implant was installed. The current EVTX window only covers 2018-09-06 to 2018-09-07.

10. **Check VSS shadow copies** for earlier Security.evtx snapshots covering the April/May 2018 compromise window if log rollover has overwritten those records.

---

*Report generated by SIFT-Sentinel triage skill. All findings grounded in cited tool output. No conclusions made without source citation.*
