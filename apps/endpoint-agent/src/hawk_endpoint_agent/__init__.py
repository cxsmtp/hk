"""Hawk Endpoint Inline Control functional agent.

An additive endpoint surface providing discovery and verified local adapters for
interaction security, data transfer, AI-IAM/agent actions, MCP tools, supported
SDK routes, and AI-notetaker controls.

Design invariants (enforced throughout the package):

1. Server-authoritative — the agent emits *signals*; the Hawk backend returns the
   *decision*. The agent never invents a verdict, which is what keeps enforcement
   free of drift and hallucination.
2. Evidence before inline claims — only action-scoped pre-action mediation earns
   authorization coverage. Other observations remain detect/telemetry-only.
3. Fail-secure — if the backend is unreachable, the agent resolves against a
   signed, TTL-bounded cached policy and a configured fail-secure default.
"""

__version__ = "0.2.1"

AGENT_NAME = "hawk-endpoint-agent"
