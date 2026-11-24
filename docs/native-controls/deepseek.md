# DeepSeek

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


- Verified native capability: None for DeepSeek Agent; native lifecycle enforcement is `unverified`.
- Verified fallbacks: `endpoint_runtime` for `explicit-hawk-client-binding-v1`; `gateway_inline` for Direct API `hawk-openai-compatible-v1`.
- Can block: Explicitly bound runtime tool/command/file/network actions and gateway-routed model/tool requests.
- Observe only: Runtime/gateway execution visibility.
- Binding: Identity, parameters, and target on runtime; destination binding on gateway.
- Blind spots: Unbound local processes, alternate runtimes, and direct provider bypass.
- Permissions: Endpoint/runtime or gateway permissions according to selected point.
- Privacy: Endpoint metadata follows local policy; gateway content traverses Hawk.
- Degraded behavior: No protected claim when binding, validation, policy, configuration, health, or version is invalid.
- Provenance: Hawk runtime/gateway conformance evidence; native verification required.
