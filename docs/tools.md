# SIFT-Sentinel — Tool Reference

The agent's entire action space is the **18 typed, read-only MCP functions** below
(`src/sift_sentinel/mcp_server.py`). There is no `execute_shell` and no generic
command tool — the destructive verb does not exist to call.

This page is the per-tool reference: signature, parameters, and what each call
answers. For *how* the tools connect and why, see [`architecture.md`](architecture.md);
for the forensic-question overview table, see the [README](../README.md).

---

## Shared guarantees (true of every call)

Every tool routes through the same audited boundary, so these hold uniformly and
are **not** repeated per tool below:

- **Read-only.** No tool can write, delete, or execute against evidence.
- **Path-guarded.** Every path argument is resolved and must sit inside an
  allowed evidence root; traversal outside is refused.
- **Allowlisted execution.** Any underlying binary runs via an argv list through
  the allowlist runner — never a shell.
- **Hash-checked.** File-backed artifacts are SHA-256 hashed before and after the
  call; a changed hash is returned as an integrity error.
- **Audited & citable.** One append-only audit record per call (`call_id`,
  timestamp, args, input hash, binary, duration, output summary, token estimate).
- **Size-bounded.** Responses are capped by a record count **and** a byte budget,
  so a call can never overrun the transport.

### Common return shape

Every tool returns a JSON object:

```jsonc
{
  "tool": "extract_mft_timeline",
  "call_id": "call-000017",        // cite this in any finding
  "input_hash": "4b829ec6…",       // pre-call SHA-256 (null for dir/memory tools)
  "record_count": 236778,          // true total before truncation
  "summary": "mft: 236778 record(s) …",
  "records": [ /* typed records, possibly truncated/digested */ ],
  "error": null,
  "extra": { /* tool-specific: integrity flags, digest stats, cache_hit, … */ }
}
```

When `records` is truncated to fit the budget, `extra` carries
`records_truncated`, `records_returned`, and a note to re-run with a narrower
filter.

---

## Disk: filesystem & execution evidence

### `extract_mft_timeline(mft_file, path_filter=None)`
NTFS filesystem timeline from the `$MFT` — when files were created/modified.
- `mft_file` — path to a `$MFT` inside the evidence root.
- `path_filter` — optional case-insensitive substring to narrow results (used
  during self-correction to zoom into a directory).
- **Note:** an unfiltered full `$MFT` (200k+ rows) is returned as a *digest* —
  curated interesting records (executables in user-writable paths, masquerading
  double extensions, ADS, deleted executables) plus stats — not a raw dump. Use
  `path_filter` to enumerate a specific directory in full.

### `get_amcache(amcache_hive, suppress_known_good=False)`
Program execution/presence from `Amcache.hve` (name, path, SHA-1, last-write).
- `amcache_hive` — path to an `Amcache.hve`.
- `suppress_known_good` — drop entries whose SHA-1 is on the known-good list
  (signed OS binaries), leaving only anomalies. `extra.known_good_count` reports
  how many were known-good.

### `analyze_prefetch(prefetch_path)`
Execution count + last-run times from Prefetch `.pf` files (libscca/`sccainfo`).
- `prefetch_path` — a Prefetch directory or a single `.pf` file.
- **Note:** returns a clear "Prefetch may be disabled" message (common on
  Servers/DCs) rather than an error when no `.pf` files are present.

### `shimcache(system_hive)`
Binary presence/execution from AppCompatCache — survives when Prefetch is off.
- `system_hive` — path to a `SYSTEM` hive.

### `srum(srudb, software_hive=None)`
Per-app resource usage and network bytes from SRUM (`SRUDB.dat`) — exfil signal.
- `srudb` — path to `SRUDB.dat`.
- `software_hive` — optional `SOFTWARE` hive for application-id resolution.

---

## Event logs

### `parse_event_logs(evtx_file, event_id=None)`
Windows Event Log triage with actor fields extracted (target/subject account,
source IP, workstation, logon type, service name, image path).
- `evtx_file` — path to an `.evtx`.
- `event_id` — optional filter, e.g. `4624` (logon), `4625` (failed logon),
  `7045` (service install).

### `logon_summary(evtx_file)`
4624/4625 aggregated by `(account, source IP, logon type)` with success/failure
counts and first/last-seen — the compact view that exposes brute-force / spray.
- `evtx_file` — path to a `Security.evtx`.

### `powershell_logs(evtx_file, event_id=None)`
PowerShell script-block/module logging with command text.
- `evtx_file` — path to `Microsoft-Windows-PowerShell%4Operational.evtx`.
- `event_id` — optional filter (`4104` script block, `4103` module).

---

## Registry / persistence

### `registry_autoruns(hive_file, plugin="run")`
Persistence / autostart entries via RegRipper.
- `hive_file` — a registry hive (`SOFTWARE`, `NTUSER.DAT`, `SYSTEM`, …).
- `plugin` — RegRipper plugin matching the hive (`run` for Run/RunOnce;
  `services` for `SYSTEM`; etc.).

---

## Memory (Volatility 3)

All memory tools take a single `memory_image` argument (path to a RAM capture
inside the evidence root) and validate the image first — a missing/empty capture
returns a clear error, never a silent empty result.

### `mem_pslist(memory_image)`
Processes running at capture time (flat list).

### `mem_pstree(memory_image)`
Processes with parent/child linkage — masquerade detection.

### `mem_cmdline(memory_image)`
Per-process command lines.

### `mem_netscan(memory_image)`
Network connections — the C2 signal.

### `mem_malfind(memory_image)`
Injected / unbacked RWX memory regions — fileless malware.

### `mem_svcscan(memory_image)`
Services resident in memory — persistence.

---

## Scanning & reading

### `yara_scan(target, rules_file)`
Known-bad signature matches over evidence (one record per match: rule + path).
- `target` — file or directory inside the evidence root (directories scanned
  recursively).
- `rules_file` — a YARA ruleset (`.yar`/`.yara`); analyst-supplied tooling, read
  from any readable path.

### `read_artifact(artifact_path)`
Read a **text** evidence artifact (e.g. a PowerShell transcript) — path-guarded,
SHA-256 hashed, and audited like every tool. One record per line, byte-capped;
binary files are rejected.
- `artifact_path` — path to a text file inside the evidence root.

---

## Correlation

### `super_timeline(mft_file=None, amcache_hive=None, system_hive=None, security_evtx=None, prefetch_path=None, time_prefix=None)`
Merge whichever artifacts are supplied into one chronological, cross-source
timeline (reusing the parse cache).
- Each path argument is optional; only the sources you pass are run.
- `time_prefix` — e.g. `"2018-09-07"` to narrow the merge to an incident window.
- **Note:** each underlying tool call is separately audited and citable;
  `extra.contributing_calls` lists the `call_id`s that fed the merge.

---

## Typical sequence

A representative triage uses these in roughly this order (see the analyst
discipline in [`../CLAUDE.md`](../CLAUDE.md)):

1. `get_amcache`, `extract_mft_timeline`, `analyze_prefetch` / `shimcache` —
   broad execution + filesystem picture.
2. `parse_event_logs` / `logon_summary` / `powershell_logs` — logons, service
   installs, scripting.
3. `mem_pslist` → `mem_pstree` → `mem_netscan` / `mem_malfind` / `mem_svcscan` —
   pivot into memory.
4. `registry_autoruns` — persistence.
5. `extract_mft_timeline(path_filter=…)` / `parse_event_logs(event_id=…)` —
   narrow re-runs to corroborate a hypothesis (self-correction).
6. `super_timeline` — stitch the confirmed events into one window.

A finding is only `CONFIRMED` when ≥2 of these tools agree, each cited by its
`call_id`.
```
