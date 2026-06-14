"""read_artifact — sanctioned, read-only reader for text evidence artifacts.

Some of the most valuable evidence is a plain text file the structured tools don't
cover — most importantly PowerShell **transcripts** (``PowerShell_transcript.*.txt``),
which record verbatim what an operator typed. This tool reads such an artifact
*through the same trust boundary as every other tool*:

  * the path must resolve inside the evidence root (path-traversal guard);
  * the file is SHA-256 hashed and the read is written to the audit log, so the
    transcript's contents are citable by ``call_id`` like any other finding;
  * it only ever opens the file read-only and never spawns a subprocess.

A byte cap keeps a hostile or huge file from blowing the response budget. Binary
files are rejected (this is a *text* reader) so it can't be abused to exfiltrate
arbitrary blobs.
"""
from __future__ import annotations

import os

from .base import ToolContext, ToolResult
from ..evidence import sha256_file

TOOL = "read_artifact"

# Default cap on how much of the artifact we read into the response.
MAX_BYTES = int(os.environ.get("SIFT_ARTIFACT_MAX_BYTES", "131072"))  # 128 KiB
# Cap on lines returned as records, independent of the byte cap.
MAX_LINES = int(os.environ.get("SIFT_ARTIFACT_MAX_LINES", "1000"))


def read_artifact(ctx: ToolContext, artifact_path: str,
                  max_bytes: int = MAX_BYTES) -> ToolResult:
    """Read a text artifact inside the evidence root, audited and hashed.

    Returns one record per line (capped at ``MAX_LINES``); ``extra`` reports the
    true size and whether the read was truncated.
    """
    path = ctx.resolve_evidence(artifact_path)
    args = {"artifact_path": artifact_path, "max_bytes": max_bytes}

    if not path.is_file():
        call_id, start = ctx.audit.start(TOOL, args, input_hash=None)
        msg = f"not a file: {artifact_path}"
        ctx.audit.finish(call_id, start, TOOL, args, input_hash=None, error=msg)
        return ToolResult(tool=TOOL, call_id=call_id, records=[], summary=msg, error=msg)

    input_hash = sha256_file(path)
    call_id, start = ctx.audit.start(TOOL, args, input_hash)

    size = path.stat().st_size
    with open(path, "rb") as fh:
        blob = fh.read(max_bytes)
    truncated = size > len(blob)

    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = blob.decode("utf-16")  # PowerShell transcripts are often UTF-16
        except UnicodeDecodeError:
            msg = "artifact is not UTF-8/UTF-16 text; read_artifact handles text only"
            ctx.audit.finish(call_id, start, TOOL, args, input_hash,
                             binary="read_artifact", error=msg)
            return ToolResult(tool=TOOL, call_id=call_id, records=[], summary=msg,
                              input_hash=input_hash, error=msg)

    lines = text.splitlines()
    records = [{"line_no": i + 1, "text": ln, "source": "artifact"}
               for i, ln in enumerate(lines[:MAX_LINES])]
    summary = (f"read_artifact: {len(records)} line(s) of {len(lines)} from "
               f"{path.name} ({size} bytes)")
    ctx.audit.finish(call_id, start, TOOL, args, input_hash,
                     binary="read_artifact", exit_code=0, output_summary=summary)
    return ToolResult(
        tool=TOOL, call_id=call_id, records=records, summary=summary,
        input_hash=input_hash,
        extra={"bytes_total": size, "bytes_read": len(blob),
               "lines_total": len(lines),
               "truncated": truncated or len(lines) > MAX_LINES},
    )
