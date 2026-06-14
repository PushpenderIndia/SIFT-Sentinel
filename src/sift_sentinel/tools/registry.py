"""Single registry of the agent's action space.

Both the MCP server (what Claude can call over the protocol) and the
orchestrator loop (what the reasoner's chosen actions resolve to) read this map.
Adding a forensic capability is one entry here + one allowlist entry in
``runner.ALLOWED_BINARIES`` — a small, reviewable change to the trust boundary.
"""
from __future__ import annotations

from typing import Callable

from .amcache import get_amcache
from .base import ToolResult
from .event_logs import parse_event_logs
from .logon_summary import logon_summary
from .memory import (
    mem_cmdline, mem_malfind, mem_netscan, mem_pslist, mem_pstree, mem_svcscan,
)
from .mft_timeline import extract_mft_timeline
from .powershell_logs import powershell_logs
from .prefetch import analyze_prefetch
from .read_artifact import read_artifact
from .registry_autoruns import registry_autoruns
from .shimcache import shimcache
from .srum import srum
from .super_timeline import super_timeline
from .yara_scan import yara_scan

ToolFn = Callable[..., ToolResult]

REGISTRY: dict[str, ToolFn] = {
    # disk / filesystem & execution evidence
    "extract_mft_timeline": extract_mft_timeline,
    "get_amcache": get_amcache,
    "analyze_prefetch": analyze_prefetch,
    "shimcache": shimcache,
    "srum": srum,
    # event logs
    "parse_event_logs": parse_event_logs,
    "logon_summary": logon_summary,
    "powershell_logs": powershell_logs,
    # registry / persistence
    "registry_autoruns": registry_autoruns,
    # signatures & raw artifacts
    "yara_scan": yara_scan,
    "read_artifact": read_artifact,
    # memory
    "mem_pslist": mem_pslist,
    "mem_pstree": mem_pstree,
    "mem_cmdline": mem_cmdline,
    "mem_netscan": mem_netscan,
    "mem_malfind": mem_malfind,
    "mem_svcscan": mem_svcscan,
    # correlation
    "super_timeline": super_timeline,
}
