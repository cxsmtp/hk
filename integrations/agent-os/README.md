# Agent OS endpoint binding

This integration registers Agent OS with Hawk's enrolled endpoint agent and
requires a device-signed pre-action decision before Ollama, Gmail, or Tavily is
called. It supports both the current Composio Gmail transport and a direct Google
transport without putting OAuth tokens, API keys, email addresses, message bodies,
or search queries into registration or decision receipts.

Required runtime configuration:

- `HAWK_ENDPOINT_SOCKET_PATH`: enrolled Hawk endpoint-agent Unix socket.
- `HAWK_ENDPOINT_TRUSTED_DEVICE_THUMBPRINT`: enrolled endpoint public-key pin.
- `HAWK_AGENT_AI_SYSTEM_ID`: registered Hawk AI-system ID used for every
  pre-action decision. Missing configuration fails closed before the endpoint
  or provider is called.
- `HAWK_AGENT_CAPABILITY_TOKEN`: short-lived capability token supplied at process
  launch or by a token-provider callback; never persist it in the project.
- `HAWK_AGENT_MODE`: `monitor` or `enforce`; monitor decisions do not authorize
  callback execution in the fail-closed binding.
- `GMAIL_TRANSPORT`: optional explicit `composio` or `google_direct`. If omitted,
  the current Composio key presence is detected without reading the key value.

Registration remains `monitor_only`. Only a later signed endpoint decision for an
explicitly bound pre-action path can establish authorization coverage.
