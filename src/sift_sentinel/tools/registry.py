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
from .memory import mem_netscan, mem_pslist
from .mft_timeline import extract_mft_timeline
from .prefetch import analyze_prefetch
from .registry_autoruns import registry_autoruns
from .yara_scan import yara_scan

ToolFn = Callable[..., ToolResult]

REGISTRY: dict[str, ToolFn] = {
    "extract_mft_timeline": extract_mft_timeline,
    "get_amcache": get_amcache,
    "analyze_prefetch": analyze_prefetch,
    "parse_event_logs": parse_event_logs,
    "registry_autoruns": registry_autoruns,
    "yara_scan": yara_scan,
    "mem_pslist": mem_pslist,
    "mem_netscan": mem_netscan,
}
