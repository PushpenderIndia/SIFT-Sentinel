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
from .tools.amcache import get_amcache as _get_amcache
from .tools.base import ToolContext
from .tools.event_logs import parse_event_logs as _parse_event_logs
from .tools.memory import mem_netscan as _mem_netscan
from .tools.memory import mem_pslist as _mem_pslist
from .tools.mft_timeline import extract_mft_timeline as _extract_mft_timeline
from .tools.prefetch import analyze_prefetch as _analyze_prefetch


def build_context(evidence_root: str, audit_path: str) -> ToolContext:
    return ToolContext(
        evidence_root=Path(evidence_root).resolve(),
        audit=AuditLog(audit_path),
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
    def get_amcache(amcache_hive: str) -> dict:
        """Program execution/presence evidence from an Amcache.hve hive. Read-only.

        Args:
            amcache_hive: path to an Amcache.hve file inside the evidence root.
        """
        return _get_amcache(ctx, amcache_hive).to_dict()

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

    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SIFT-Sentinel MCP server")
    parser.add_argument("--evidence-root", default=os.environ.get("SIFT_EVIDENCE_ROOT", "."),
                        help="Directory containing mounted, read-only evidence.")
    parser.add_argument("--audit", default=os.environ.get("SIFT_AUDIT", "audit/execution-log.jsonl"),
                        help="Path to the append-only audit log (JSONL).")
    args = parser.parse_args(argv)

    ctx = build_context(args.evidence_root, args.audit)
    server = create_server(ctx)
    server.run()  # stdio transport
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
