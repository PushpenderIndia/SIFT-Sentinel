"""Typed forensic tools — the agent's entire action space.

Each module here exposes one or more read-only forensic functions. They are the
ONLY operations the agent can perform; there is deliberately no generic shell.
Adding a capability means adding a typed function here and allowlisting its
binary in ``runner.ALLOWED_BINARIES`` — a reviewable, auditable change.
"""
