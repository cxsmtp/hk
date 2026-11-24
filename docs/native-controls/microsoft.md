# Microsoft

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


- Verified local capability: the exact Microsoft Agent Framework `1.15.0` Function middleware proof path verifies local Function-tool, parameter and target binding only. It does not verify a provider-native lifecycle, Foundry hosted model/runtime, hosted tools/MCP, APIM, or generic Microsoft-wide control surface.
- Verified fallback: Hawk `gateway_inline` for Direct API, version `hawk-openai-compatible-v1`.
- Can block: only the Hawk-routed model request/response path before provider invocation. The generic route does not authorize tools, MCP, parameters, targets, destinations, hosted execution, or endpoint consequences.
- Observe only: provider-reported response evidence on the routed model path; it is not independent execution verification.
- Binding: the generic gateway records a bound model route only. It does not establish provider-native account, tenant, parameter, target, destination, or remote-execution binding.
- Direct/cloud contracts: Microsoft Foundry hosted model/runtime is a separate `UNVERIFIED` / `NOT_TESTED` remote-runtime profile. It does not inherit direct Azure or generic gateway coverage. See `docs/native-controls/direct-cloud-provider-contracts.md`.
- Blind spots: Agent Framework actions, Foundry hosted tool/MCP execution, account/tenant/deployment drift, direct/alternate routes, and Microsoft API routes not independently accepted by Hawk.
- Permissions: `gateway.intercept`, `policy.evaluate`.
- Privacy: Routed content and action metadata traverse Hawk.
- Degraded behavior: Failed health, policy freshness, validation, or version checks remove eligibility.
- Provenance: Repository gateway conformance evidence; native verification required.
