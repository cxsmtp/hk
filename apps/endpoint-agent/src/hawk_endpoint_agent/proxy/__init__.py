"""Local intercepting proxy — inline coverage for LLM / MCP / browser traffic.

Pointing apps and browsers at the agent's loopback proxy lets a single agent
enforce what previously required the standalone LLM gateway, MCP gateway, and
browser extension. TLS destinations get host-level allow/block (no decryption);
readable requests get full content inspection routed to the Hawk gateways.
"""
