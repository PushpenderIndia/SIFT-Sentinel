# SIFT-Sentinel Triage Report

**Date:** 2026-06-14
**Evidence root:** `/mnt/cases`
**Memory image:** `/evidence/base-dc-memory.img`
**Host:** `base-dc.shieldbase.lan` (Windows Server 2016 domain controller)
**Case notes / IOCs supplied:** none (open-ended triage)

## Tools executed (audit call_ids)

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

## Timeline of Suspicious / Notable Activity

| Time (UTC) | Event | Source call_id |
|---|---|---|
| 2018-05-08 22:09 | McAfee Agent installed; `mfemactl.exe` staged in `…\AppData\Local\Temp\…` then `Program Files\McAfee` | call-000017, call-000023 |
| 2018-09-04 12:58–13:20 | Burst of network logons (4624, type 3) to the DC — mostly machine accounts | call-000021 |
| 2018-09-04 13:11 → 09-05 16:11 | **163 failed logons (4625)**, all `BASE-HUNT$` from `172.16.5.25`, type 3, steady ~10-min cadence over 27 h | call-000022 |
| 2018-09-06 22:11:15 | **F-Response Subject** service installed; `subject_srv.exe` dropped to `C:\Windows` | call-000023, call-000025 |
| 2018-09-07 20:26–20:31 | **mnemosyne** service (re)installed 3×; `Mnemosyne.sys` dropped to `C:\Windows` | call-000023, call-000024 |

## Confirmed Findings  [CONFIRMED]

- **F-Response remote-forensics agent installed on the DC (2018-09-06).** `subject_srv.exe`
  present in `C:\Windows` (MFT call-000025, size 1,173,936 bytes) **and** service-install
  event 7045 at 22:11:15 (call-000023). Timestamps agree to sub-second. `created` (09-06) >
  `modified` (2018-04-10 PE compile date) = dropped-binary signature.
- **`mnemosyne` kernel driver installed (2018-09-07).** `Mnemosyne.sys` present in
  `C:\Windows` (MFT call-000024) **and** 7045 install at 20:30:59 (call-000023), timestamps
  matching. Installed 3× within 5 minutes.
- *Interpretation:* both are **incident-response / memory-acquisition tooling** (F-Response
  Subject + its physical-memory driver), consistent with the responder who captured
  `base-dc-memory.img`. Attributed to IR, **not** adversary — validation step below.

## Inferred Findings  [INFERRED]

- **Sustained failed-logon series against the DC** — 163 × event 4625, account `BASE-HUNT$`,
  source `172.16.5.25`, logon type 3, regular cadence (call-000022). `172.16.5.25` never
  appears in successful logons. Single source. Consistent with a hunt/IR workstation with a
  broken machine-account trust **or** automated network-auth against the DC.
  **Confirmed by:** System.evtx Netlogon/trust errors in that window, the DC machine-account
  password history, and identifying `172.16.5.25` / `BASE-HUNT` in the asset inventory.
- **Prefetch unavailable** — `Windows\Prefetch` empty (call-000018); Prefetch disabled
  (normal on Server/DC). Execution corroboration therefore relies on Amcache + MFT + EVTX.

## Uncertain / Low-confidence  [UNCERTAIN]

- `ANONYMOUS LOGON` ×6 and off-subnet source `10.10.4.6` ×8 among successful type-3 logons
  (call-000021). Common for SMB null sessions / cross-segment service traffic; confirm
  `10.10.4.6` is an expected host.
- `wdksetup.exe` (Windows Driver Kit) downloaded by Administrator and staged in multiple
  `C:\Windows\Temp\{GUID}` dirs (call-000016), same SHA-1 throughout. Benign developer
  tooling, but unusual on a production DC.

## Contradictions  [CONTRADICTION]

- **Memory analysis returned nothing despite a valid image.** `mem_pslist` (call-000019) and
  `mem_netscan` (call-000020) both returned **0 records with `error: null`**, yet the image
  was located and hashed (`input_hash 9679…`). A live capture must contain processes — 0 is
  not a credible "clean" result. Per documented behavior (a missing/empty capture should
  return a *clear error*), this is a tooling/symbol-resolution failure, **not** evidence of
  absence. Memory is currently a blind spot; C2/injection hypotheses are **untested**, not
  cleared.

## MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|---|---|---|
| T1543.003 | Create/Modify System Process: Windows Service | F-Response + mnemosyne service installs (call-000023) — IR tooling; same TTP an adversary would use |
| T1569.002 | System Services: Service Execution | service-based execution of dropped binaries (call-000023/000024/000025) |
| T1110.x | Brute Force / credential mis-auth | 163 × 4625 from a single source (call-000022) — low-confidence |
| T1078 / T1135 | Valid Accounts / Network Share Discovery | `ANONYMOUS LOGON` + machine-account type-3 logons (call-000021) |

## Recommended Next Steps (prioritised)

1. **Fix and re-run memory forensics** — resolve the Volatility symbol/profile issue, then
   re-run `mem_pslist`/`mem_netscan` (and `mem_malfind`, `mem_pstree`, `mem_svcscan`). Largest
   open gap.
2. **Confirm the F-Response/mnemosyne attribution** — verify with the IR team that
   `subject_srv.exe` / `Mnemosyne.sys` (09-06/07) are authorized acquisition tooling. If not,
   treat as adversary persistence and pivot. Hash both files and check reputation.
3. **Resolve `BASE-HUNT$` / `172.16.5.25`** — identify the asset, check System log for Netlogon
   trust failures in that window and the machine-account password-set history; determine
   whether the 163 failures are a broken trust or hostile auth.
4. **Validate `10.10.4.6` and the `ANONYMOUS LOGON` sources** against expected topology for
   `shieldbase.lan`.
5. **Pull a full `super_timeline`** merging MFT + Amcache + EVTX to tighten the 09-04 → 09-07
   sequence, and run `parse_event_logs` for 4672 (special privileges) and 4688 / PowerShell
   logging around the failed-logon window.

## Bottom Line

This DC reads as a **baseline domain controller with IR/acquisition tooling staged on it
(F-Response + mnemosyne, 09-06/07)** rather than a host with clear adversary compromise. The
one real anomaly needing a human decision is the **163-failure `BASE-HUNT$` logon series**, and
the one real blind spot is **memory analysis, which silently failed and must be re-run before
this host can be called clean.**
