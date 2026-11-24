"""TLS interception — optional deep content inspection of encrypted AI traffic.

Off by default. Requires (a) the optional ``cryptography`` dependency to mint
certificates and (b) the agent's CA to be trusted on the endpoint — which is a
deliberate MDM step (push the CA to the system/browser trust store). Without both,
the proxy degrades to host-level TLS control (allow/block by destination) and says
so, rather than pretending to inspect content it cannot read.

Scope guard: only hosts classified as AI traffic are ever intercepted. Non-AI
destinations (banking, health, etc.) are tunneled untouched.
"""
