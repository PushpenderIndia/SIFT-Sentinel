"""Constrained subprocess runner — no shell, whitelist only.

The MCP server never gives the agent a generic ``execute_shell`` tool. Internally,
tool wrappers still need to invoke real SIFT binaries (MFTECmd, AmcacheParser,
Volatility, ...). This module is the *only* place a subprocess is spawned, and it:

  * accepts an argument **list**, never a shell string (no ``shell=True``);
  * refuses any binary not on the explicit allowlist;
  * enforces a timeout and captures stdout/stderr;
  * never interpolates untrusted input into a shell.

Because every external execution funnels through here, the destructive-command
attack surface is a single, auditable chokepoint.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence


# Binaries the system is permitted to execute. Anything else raises.
# Extend deliberately as tools are added — this list IS the action space.
ALLOWED_BINARIES: frozenset[str] = frozenset({
    # disk / filesystem
    "fls", "mactime", "icat", "mmls",
    "MFTECmd.exe", "MFTECmd",
    # registry / execution evidence
    "AmcacheParser.exe", "AmcacheParser",
    "PECmd.exe", "PECmd",
    "EvtxECmd.exe", "EvtxECmd",
    "rip.pl", "regripper",
    # memory
    "vol", "vol.py", "volatility3",
    # signatures
    "yara",
})


class DisallowedBinaryError(RuntimeError):
    """Raised when a non-allowlisted binary is requested."""


@dataclass
class RunResult:
    binary: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


def run_tool(
    argv: Sequence[str],
    *,
    timeout: float = 300.0,
    cwd: Optional[str] = None,
    input_text: Optional[str] = None,
) -> RunResult:
    """Execute an allowlisted binary with no shell.

    ``argv[0]`` is the binary name; it must be in :data:`ALLOWED_BINARIES`.
    Raises :class:`DisallowedBinaryError` otherwise.
    """
    if not argv:
        raise ValueError("argv must be non-empty")
    binary = argv[0]
    if binary not in ALLOWED_BINARIES:
        raise DisallowedBinaryError(
            f"binary {binary!r} is not on the allowlist; refusing to execute"
        )
    # Resolve to an absolute path but keep the logical name for auditing.
    resolved = shutil.which(binary)
    if resolved is None:
        raise FileNotFoundError(
            f"allowlisted binary {binary!r} not found on PATH (is the SIFT tool installed?)"
        )

    timed_out = False
    try:
        proc = subprocess.run(
            [resolved, *argv[1:]],
            shell=False,                 # never a shell
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=input_text,
            check=False,
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")) \
            + f"\n[runner] timed out after {timeout}s"

    return RunResult(
        binary=binary,
        argv=list(argv),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )
