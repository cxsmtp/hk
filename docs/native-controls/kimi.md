# Moonshot Kimi

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


- Verified native capability: None for Kimi Coding; native lifecycle enforcement is `unverified`.
- Verified fallbacks: `endpoint_runtime` for `explicit-hawk-client-binding-v1`; `gateway_inline` for Direct API `hawk-openai-compatible-v1`.
- Can block: Explicitly bound runtime tool/command/file/network actions and gateway-routed model/tool requests.
- Observe only: Runtime/gateway execution visibility.
- Binding: Identity, parameters, and target on runtime; gateway additionally binds destination.
- Blind spots: Unbound Kimi processes, unmanaged runtimes, and direct API bypass.
- Permissions: Endpoint/runtime or gateway permissions according to selected method.
- Privacy: Metadata follows endpoint policy; routed content follows gateway policy.
- Degraded behavior: No automatic native fallback after binding/health/policy/version failure.
- Provenance: Hawk runtime/gateway conformance evidence; native verification required.
