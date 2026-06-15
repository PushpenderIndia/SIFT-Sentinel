# Installation & Try-It-Out

**Deployment model: local only.** The agent is Claude Code driving the
`sift-sentinel` MCP server over stdio against read-only evidence mounts — there is
no hosted URL, no API key, and no extra service to stand up. This is by design:
the read-only trust boundary depends on local mounts and the absence of any
network/shell surface, so there is nothing to deploy remotely.

---

## Prerequisites

- The **SANS SIFT Workstation** (Ubuntu-based; Zimmerman tools, Volatility 3,
  `ewfmount`, `ntfs-3g`, and `7z` pre-installed).
- **Claude Code** installed and signed in.
- The **provided dataset**: SANS Find Evil! "SRL-2018 Compromised Enterprise
  Network" — `base-dc-cdrive.E01` (disk) and `SRL-2018/base-dc-memory.7z`
  (memory). See [`dataset.md`](dataset.md).

---

## 1. Install

```bash
git clone https://github.com/PushpenderIndia/SIFT-Sentinel
cd SIFT-Sentinel
./install.sh
```

`install.sh` creates a virtualenv (on local disk if it detects a vboxsf shared
folder), installs the package and dev dependencies, installs `yara` via apt if
missing, and registers the `sift-sentinel` MCP server in Claude Code's MCP
configuration.

Optional — pin the evidence root at install time:

```bash
./install.sh --evidence-root /mnt/cases
```

![](installation.png)

---

## 2. Mount the provided evidence read-only

```bash
# Disk image: E01 -> raw -> NTFS, mounted read-only
sudo mkdir -p /mnt/ewf /mnt/cases
sudo ewfmount /path/to/base-dc-cdrive.E01 /mnt/ewf
sudo mount -t ntfs-3g -o ro,noexec,nodev /mnt/ewf/ewf1 /mnt/cases

# Memory capture
sudo mkdir -p /evidence
sudo 7z x /path/to/base-dc-memory.7z -o/evidence/
```

After mounting, the artifacts live at:

- `/mnt/cases/$MFT`
- `/mnt/cases/Windows/appcompat/Programs/Amcache.hve`
- `/mnt/cases/Windows/Prefetch/`
- `/mnt/cases/Windows/System32/config/SYSTEM` and `SOFTWARE`
- `/mnt/cases/Windows/System32/sru/SRUDB.dat`
- `/mnt/cases/Windows/System32/winevt/Logs/`
- `/evidence/base-dc-memory.img`

---

## 3. Triage

Restart Claude Code so the MCP server starts and the 18 tools appear, then run
`/triage` or ask directly:

```
Triage the domain controller evidence at /mnt/cases with memory at
/evidence/base-dc-memory.img. Start with execution evidence and the MFT
timeline, then check memory, logons, and persistence. Cross-reference across
sources and flag anything CONFIRMED. Cite the call_id for every finding.
```

---

## What judges should see

- The agent works **broad → narrow**, citing a `call_id` for every claim.
- An **append-only audit log** at `audit/execution-log.jsonl` — one record per
  tool call (timestamp, args, input hash, binary, duration, output summary, token
  estimate).
- Findings matching the reference run in
  [`../audit/triage-report-base-dc-2026-06-14.md`](../audit/triage-report-base-dc-2026-06-14.md):
  - **CONFIRMED** — the F-Response / `Mnemosyne.sys` staging in `C:\Windows`,
    each corroborated by MFT **and** a 7045 service-install event;
  - **INFERRED** — the 163 failed `BASE-HUNT$` logons from `172.16.5.25`;
  - **CONTRADICTION** — the silent memory-tooling failure, flagged as a blind
    spot rather than a clean host.

---

## 4. Verify without the dataset

The test suite runs fully offline — no forensic tools, no mounted evidence, and
no API key — using captured fixtures and an injected fake runner:

```bash
source .venv/bin/activate
pytest
```

---

## Troubleshooting

- **Tools don't appear in Claude Code** — restart Claude Code after `install.sh`
  so the MCP server is (re)launched, and confirm `sift-sentinel` is listed in
  Claude Code's MCP configuration.
- **`mount: permission denied` / wrong device** — `ewfmount` exposes the raw
  image as `/mnt/ewf/ewf1`; mount *that* path with `ntfs-3g`, not the `.E01`.
- **Prefetch returns "may be disabled"** — expected on a domain controller;
  execution evidence falls back to Amcache + ShimCache + MFT + EVTX.
- **Memory tools return nothing** — a Volatility symbol/profile mismatch surfaces
  as a `CONTRADICTION` in the report (a known blind spot in the reference run),
  not a silent empty result.

---

## See also

- [`../README.md`](../README.md#try-it-out) — the condensed try-it-out steps
- [`dataset.md`](dataset.md) — evidence dataset documentation and findings
- [`architecture.md`](architecture.md) — how the read-only pipeline is enforced
- [`tools.md`](tools.md) — per-tool reference
