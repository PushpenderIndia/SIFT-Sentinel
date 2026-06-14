"""Run independent forensic tool calls concurrently.

A triage starts with a *broad sweep* of mutually independent reads — Amcache, the
MFT, Prefetch, and (if present) the two memory plugins. Run serially they sum to
the wall-clock total; in the last run that was ~17 minutes of tool time, almost
all of it spent waiting on subprocesses that don't depend on each other.

Each tool call spends its time in a subprocess (``runner`` -> ``subprocess.run``),
which releases the GIL, so a thread pool gives real parallelism here without any
of the complexity of multiprocessing. The audit log is already thread-safe
(``AuditLog`` guards id allocation and the append with a lock), so concurrent
calls produce a correct, interleaved trail.

This module provides the primitive (:func:`run_parallel`) and a convenience
fan-out (:func:`triage_sweep`) for the standard broad sweep.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional, Sequence, TypeVar

T = TypeVar("T")

# Cap pool width so we don't spawn an unbounded number of heavy subprocesses on a
# workstation. Override with SIFT_MAX_WORKERS.
MAX_WORKERS = int(os.environ.get("SIFT_MAX_WORKERS", "6"))


def run_parallel(
    tasks: Sequence[Callable[[], T]],
    *,
    max_workers: Optional[int] = None,
) -> list[T]:
    """Execute zero-arg callables concurrently and return results in input order.

    Exceptions are not swallowed: if a task raises, the exception propagates from
    :meth:`Future.result`, so a broken tool surfaces loudly rather than silently
    dropping a finding. Order of the returned list matches ``tasks``.
    """
    if not tasks:
        return []
    workers = max_workers or min(MAX_WORKERS, len(tasks))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(t) for t in tasks]
        return [f.result() for f in futures]


def triage_sweep(ctx, *, mft_file: str, amcache_hive: str,
                 prefetch_path: str, memory_image: Optional[str] = None,
                 security_evtx: Optional[str] = None) -> dict[str, Any]:
    """Fan out the independent broad-sweep reads concurrently.

    Returns a dict of ``{tool_name: ToolResult.to_dict()}``. Only the artifacts
    whose paths are supplied are run. Wall time collapses from the sum of the
    calls to roughly the slowest single call.
    """
    # Imported here to avoid a circular import (tools import nothing from here).
    from .tools.amcache import get_amcache
    from .tools.event_logs import parse_event_logs
    from .tools.memory import mem_netscan, mem_pslist
    from .tools.mft_timeline import extract_mft_timeline
    from .tools.prefetch import analyze_prefetch

    jobs: list[tuple[str, Callable[[], Any]]] = [
        ("get_amcache", lambda: get_amcache(ctx, amcache_hive)),
        ("extract_mft_timeline", lambda: extract_mft_timeline(ctx, mft_file)),
        ("analyze_prefetch", lambda: analyze_prefetch(ctx, prefetch_path)),
    ]
    if memory_image:
        jobs.append(("mem_pslist", lambda: mem_pslist(ctx, memory_image)))
        jobs.append(("mem_netscan", lambda: mem_netscan(ctx, memory_image)))
    if security_evtx:
        jobs.append(("parse_event_logs",
                     lambda: parse_event_logs(ctx, security_evtx)))

    results = run_parallel([fn for _, fn in jobs])
    return {name: res.to_dict() for (name, _), res in zip(jobs, results)}
