# Meta / Llama


- Verified native capability: None for a universal Llama hook. Enforcement is modeled at the runtime/orchestration layer.
- Verified fallbacks: `endpoint_runtime` for `explicit-hawk-client-binding-v1`; `gateway_inline` for Direct API `hawk-openai-compatible-v1`.
- Can block: Explicitly bound runtime tool/command/file/network actions; gateway-routed model/tool requests.
- Observe only: Runtime and gateway post-execution visibility; not universal external verification.
- Binding: Identity, parameters, and target on bound runtime; destination also on gateway.
- Blind spots: Unbound processes, alternate runtimes, and direct routes outside Hawk.
- Permissions: `endpoint.authorize`, `runtime.observe`, or gateway permissions.
- Privacy: Runtime uses canonical metadata per endpoint policy; gateway content traverses Hawk.
- Degraded behavior: Agent unhealthy/client binding removed/runtime bypass makes endpoint point ineligible.
- Provenance: Hawk runtime and gateway conformance evidence; provider-native hook not claimed.
