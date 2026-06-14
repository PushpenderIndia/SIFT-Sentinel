"""MCP server — the trust boundary.

Exposes ONLY typed, read-only forensic functions over MCP. There is deliberately
no ``execute_shell`` / ``run_command`` tool. The agent's entire action space is
the functions registered below; it physically cannot issue a destructive command
because no such tool exists to call.

Run with::

    sift-sentinel-server --evidence-root /mnt/case --audit ./audit/execution-log.jsonl

Uses the official MCP Python SDK (FastMCP). If the SDK is not installed, importing
this module raises a clear error; the rest of the package (tools, parsers, audit)
works without it.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from .audit import AuditLog
from .cache import ParseCache
from .tools.amcache import get_amcache as _get_amcache
from .tools.base import ToolContext
from .tools.event_logs import parse_event_logs as _parse_event_logs
from .tools.logon_summary import logon_summary as _logon_summary
from .tools.memory import mem_cmdline as _mem_cmdline
from .tools.memory import mem_malfind as _mem_malfind
from .tools.memory import mem_netscan as _mem_netscan
from .tools.memory import mem_pslist as _mem_pslist
from .tools.memory import mem_pstree as _mem_pstree
from .tools.memory import mem_svcscan as _mem_svcscan
from .tools.mft_timeline import extract_mft_timeline as _extract_mft_timeline
from .tools.powershell_logs import powershell_logs as _powershell_logs
from .tools.prefetch import analyze_prefetch as _analyze_prefetch
from .tools.read_artifact import read_artifact as _read_artifact
from .tools.registry_autoruns import registry_autoruns as _registry_autoruns
from .tools.shimcache import shimcache as _shimcache
from .tools.srum import srum as _srum
from .tools.super_timeline import super_timeline as _super_timeline
from .tools.yara_scan import yara_scan as _yara_scan


def build_context(evidence_root: str | list[str], audit_path: str,
                  cache_dir: str | None = None) -> ToolContext:
    """Build the tool context from one or more allowed evidence roots.

    The first root is primary; any extras (e.g. a RAM capture mounted outside the
    disk root) extend the path-traversal allowlist without widening it to the
    whole filesystem.

    ``cache_dir`` enables the parsed-artifact cache (keyed by evidence SHA-256) so
    re-running a triage or querying the same big artifact twice skips re-parsing.
    """
    roots = [evidence_root] if isinstance(evidence_root, str) else list(evidence_root)
    resolved = [Path(r).resolve() for r in roots]
    return ToolContext(
        evidence_root=resolved[0],
        extra_roots=tuple(resolved[1:]),
        audit=AuditLog(audit_path),
        cache=ParseCache(cache_dir),
    )


def create_server(ctx: ToolContext):
    """Construct a FastMCP server with the typed tools registered.

    Imported lazily so the package is usable (and testable) without the MCP SDK.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "The 'mcp' package is required to run the server. Install with: pip install mcp"
        ) from exc

    mcp = FastMCP("sift-sentinel")

    @mcp.tool()
    def extract_mft_timeline(mft_file: str, path_filter: str | None = None) -> dict:
        """Filesystem timeline from an NTFS $MFT. Read-only.

        Args:
            mft_file: path to a $MFT file inside the evidence root.
            path_filter: optional case-insensitive substring to narrow results.
        """
        return _extract_mft_timeline(ctx, mft_file, path_filter).to_dict()

    @mcp.tool()
    def get_amcache(amcache_hive: str, suppress_known_good: bool = False) -> dict:
        """Program execution/presence evidence from an Amcache.hve hive. Read-only.

        Args:
            amcache_hive: path to an Amcache.hve file inside the evidence root.
            suppress_known_good: drop entries whose SHA-1 is on the known-good
                reputation list (signed OS binaries), leaving only anomalies.
        """
        return _get_amcache(ctx, amcache_hive, suppress_known_good).to_dict()

    @mcp.tool()
    def analyze_prefetch(prefetch_path: str) -> dict:
        """Run-count / last-run execution evidence from Prefetch (.pf). Read-only.

        Args:
            prefetch_path: Prefetch directory or a single .pf file in the evidence root.
        """
        return _analyze_prefetch(ctx, prefetch_path).to_dict()

    @mcp.tool()
    def parse_event_logs(evtx_file: str, event_id: int | None = None) -> dict:
        """Windows Event Log (.evtx) triage. Read-only.

        Args:
            evtx_file: path to an .evtx file inside the evidence root.
            event_id: optional filter, e.g. 4624 (logon), 7045 (service install).
        """
        return _parse_event_logs(ctx, evtx_file, event_id).to_dict()

    @mcp.tool()
    def registry_autoruns(hive_file: str, plugin: str = "run") -> dict:
        """Persistence / autostart entries from a registry hive (RegRipper). Read-only.

        Args:
            hive_file: path to a registry hive (e.g. SOFTWARE, NTUSER.DAT, SYSTEM)
                inside the evidence root.
            plugin: RegRipper plugin matching the hive (default ``run`` for
                Run/RunOnce autostart keys; e.g. ``services`` for SYSTEM).
        """
        return _registry_autoruns(ctx, hive_file, plugin).to_dict()

    @mcp.tool()
    def yara_scan(target: str, rules_file: str) -> dict:
        """Known-bad signature matches over evidence via YARA. Read-only.

        Args:
            target: file or directory inside the evidence root to scan
                (directories are scanned recursively).
            rules_file: path to a YARA ruleset (.yar/.yara).
        """
        return _yara_scan(ctx, target, rules_file).to_dict()

    @mcp.tool()
    def mem_pslist(memory_image: str) -> dict:
        """Processes running at capture time, via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_pslist(ctx, memory_image).to_dict()

    @mcp.tool()
    def mem_netscan(memory_image: str) -> dict:
        """Network connections (C2 signal), via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_netscan(ctx, memory_image).to_dict()

    @mcp.tool()
    def logon_summary(evtx_file: str) -> dict:
        """Aggregate 4624/4625 logons by account + source IP + logon type. Read-only.

        Returns one row per actor tuple with success/failure counts and first/last
        seen times — the compact view that exposes brute-force / password-spray.

        Args:
            evtx_file: path to a Security.evtx inside the evidence root.
        """
        return _logon_summary(ctx, evtx_file).to_dict()

    @mcp.tool()
    def powershell_logs(evtx_file: str, event_id: int | None = None) -> dict:
        """PowerShell script-block/module logging (4104/4103). Read-only.

        Args:
            evtx_file: path to Microsoft-Windows-PowerShell%4Operational.evtx.
            event_id: optional filter (4104 script block, 4103 module).
        """
        return _powershell_logs(ctx, evtx_file, event_id).to_dict()

    @mcp.tool()
    def read_artifact(artifact_path: str) -> dict:
        """Read a text evidence artifact (e.g. a PowerShell transcript). Read-only.

        Path-guarded, SHA-256 hashed and audited like every tool. Text only.

        Args:
            artifact_path: path to a text file inside the evidence root.
        """
        return _read_artifact(ctx, artifact_path).to_dict()

    @mcp.tool()
    def shimcache(system_hive: str) -> dict:
        """ShimCache (AppCompatCache) presence/execution evidence. Read-only.

        Survives when Prefetch is disabled (servers/DCs).

        Args:
            system_hive: path to a SYSTEM hive inside the evidence root.
        """
        return _shimcache(ctx, system_hive).to_dict()

    @mcp.tool()
    def srum(srudb: str, software_hive: str | None = None) -> dict:
        """SRUM (SRUDB.dat) per-app resource usage / exfil signal. Read-only.

        Args:
            srudb: path to SRUDB.dat inside the evidence root.
            software_hive: optional SOFTWARE hive for app-id resolution.
        """
        return _srum(ctx, srudb, software_hive).to_dict()

    @mcp.tool()
    def mem_pstree(memory_image: str) -> dict:
        """Process tree with parent/child linkage, via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_pstree(ctx, memory_image).to_dict()

    @mcp.tool()
    def mem_cmdline(memory_image: str) -> dict:
        """Per-process command lines, via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_cmdline(ctx, memory_image).to_dict()

    @mcp.tool()
    def mem_malfind(memory_image: str) -> dict:
        """Injected / unbacked RWX regions (fileless malware), via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_malfind(ctx, memory_image).to_dict()

    @mcp.tool()
    def mem_svcscan(memory_image: str) -> dict:
        """Services resident in memory (persistence), via Volatility 3. Read-only.

        Args:
            memory_image: path to a RAM capture inside the evidence root.
        """
        return _mem_svcscan(ctx, memory_image).to_dict()

    @mcp.tool()
    def super_timeline(mft_file: str | None = None, amcache_hive: str | None = None,
                       system_hive: str | None = None, security_evtx: str | None = None,
                       prefetch_path: str | None = None,
                       time_prefix: str | None = None) -> dict:
        """Merge multiple artifacts into one chronological timeline. Read-only.

        Runs whichever sources are supplied (reusing the parse cache) and orders
        their records by time for cross-source correlation. ``time_prefix`` (e.g.
        "2018-09-07") narrows to an incident window. Each underlying call is
        separately audited and citable.
        """
        return _super_timeline(
            ctx, mft_file=mft_file, amcache_hive=amcache_hive,
            system_hive=system_hive, security_evtx=security_evtx,
            prefetch_path=prefetch_path, time_prefix=time_prefix,
        ).to_dict()

    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SIFT-Sentinel MCP server")
    parser.add_argument("--evidence-root", action="append", dest="evidence_root",
                        help="Directory containing mounted, read-only evidence. "
                             "Repeatable to allow several roots (e.g. disk + RAM capture).")
    parser.add_argument("--audit", default=os.environ.get("SIFT_AUDIT", "audit/execution-log.jsonl"),
                        help="Path to the append-only audit log (JSONL).")
    parser.add_argument("--cache-dir", default=os.environ.get("SIFT_CACHE_DIR", ".sift-cache"),
                        help="Directory for the parsed-artifact cache (keyed by "
                             "evidence SHA-256). Pass an empty string to disable.")
    args = parser.parse_args(argv)

    roots = args.evidence_root or [os.environ.get("SIFT_EVIDENCE_ROOT", ".")]
    ctx = build_context(roots, args.audit, cache_dir=args.cache_dir or None)
    server = create_server(ctx)
    server.run()  # stdio transport
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
