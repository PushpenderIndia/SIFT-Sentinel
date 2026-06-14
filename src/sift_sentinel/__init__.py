"""SIFT-Sentinel — autonomous, evidence-safe incident response on the SIFT Workstation.

Architecture (see STRATEGY.md):
  Custom MCP server (architectural trust boundary) + self-correcting agent loop.

The package never exposes a generic shell to the agent. Only typed, read-only
forensic functions are reachable. Evidence is mounted read-only and hashed
before and after every run to prove zero spoliation.
"""

__version__ = "0.1.0"
