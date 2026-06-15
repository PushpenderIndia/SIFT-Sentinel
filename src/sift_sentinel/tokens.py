"""Deterministic, offline token estimation for the audit trail.

A single-agent submission is asked to log *token usage* per tool call. The catch
is that the ``sift-sentinel`` MCP server is read-only and stateless with respect
to the model: it never sees the agent's prompt or completion, so it cannot report
the LLM's own prompt/completion token counts. Inventing those would be a
hallucinated number — exactly what this project refuses to do.

What the server *can* measure honestly is the token cost it imposes on the agent:
the size, in tokens, of the structured response payload each tool call returns
into the model's context. That is the quantity attributable to the call at the
trust boundary, and it is what we record in ``AuditRecord.tokens`` (clearly the
*response* token cost, see the field doc in :mod:`sift_sentinel.audit`).

The estimate is deterministic and dependency-free so the test suite still runs
with no API key and no network. It approximates a GPT-style BPE tokenizer well
enough for budgeting and audit purposes: roughly four characters per token for
mixed JSON/English text, with a small correction so that whitespace- and
punctuation-dense payloads (which BPE splits into more tokens) are not
under-counted.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

# Boundaries BPE tokenizers tend to split on: runs of word characters, and each
# non-space, non-word character (punctuation/symbols) as its own piece.
_PIECE_RE = re.compile(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]")

# Characters-per-token for the contiguous word/number runs above. ~4 matches the
# commonly cited GPT ratio for English; JSON keys and hex hashes sit close to it.
_CHARS_PER_WORD_TOKEN = 4.0


def _to_text(value: Any) -> str:
    """Serialize an arbitrary response payload to the text the model will see."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, default=str, separators=(",", ":"), sort_keys=True)


def estimate_tokens(value: Any) -> int:
    """Estimate the token count of a response payload.

    Accepts a string or any JSON-serializable object (e.g. the dict a tool
    returns to the agent). Returns 0 for empty input, otherwise a positive
    integer. The number is an *estimate* — see the module docstring — not a
    reading from the model, and is recorded as such.
    """
    text = _to_text(value)
    if not text:
        return 0
    total = 0
    for piece in _PIECE_RE.findall(text):
        if len(piece) == 1 and not piece.isalnum() and piece != "_":
            # A lone punctuation/symbol char is (about) one token.
            total += 1
        else:
            total += max(1, math.ceil(len(piece) / _CHARS_PER_WORD_TOKEN))
    return total
