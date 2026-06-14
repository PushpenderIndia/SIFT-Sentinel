"""registry_autoruns — persistence / autostart evidence from a registry hive.

Wraps RegRipper (``rip.pl``). Returns structured autostart records (key,
LastWrite time, entry name, command), never the raw plugin text. Default plugin
is ``run`` (the classic Run/RunOnce autostart keys); override to target services,
scheduled tasks, etc. on the appropriate hive.
"""
from __future__ import annotations

from ..parsers import parse_regripper, summarize
from .base import ToolContext, ToolResult, audited_run

TOOL = "registry_autoruns"


def registry_autoruns(ctx: ToolContext, hive_file: str, plugin: str = "run") -> ToolResult:
    """Parse a registry hive into persistence/autostart records via RegRipper.

    ``hive_file`` must resolve inside the evidence root (path-traversal guard).
    ``plugin`` selects the RegRipper plugin — it must match the hive (e.g. ``run``
    for SOFTWARE/NTUSER, ``services`` for SYSTEM). Self-correction can re-run with
    a different plugin once a hive is identified.
    """
    hive = str(ctx.resolve_evidence(hive_file))
    return audited_run(
        ctx,
        tool=TOOL,
        args={"hive_file": hive_file, "plugin": plugin},
        evidence_path=hive,
        argv=["rip.pl", "-r", hive, "-p", plugin],
        parse=parse_regripper,
        summarize_kind="registry",
        summarize=lambda recs, kind: summarize(recs, kind),
    )
