# Azure AI Foundry


- Verified native capability: None for AI Foundry; native lifecycle enforcement is `unverified`.
- Verified fallback: Hawk `gateway_inline` for Direct API, version `hawk-openai-compatible-v1`.
- Can block: only the Hawk-routed model request/response path before provider invocation. It does not authorize provider tools, MCP, parameters, targets, destinations, hosted execution, or endpoint consequences.
- Observe only: provider-reported response state on the routed model path; it is not independent execution verification.
- Binding: the generic gateway records a bound model route only. It does not establish exact provider-native account, tenant, parameter, target, destination, or remote-execution binding.
- Direct/cloud contracts: Azure OpenAI direct API and Microsoft Foundry hosted model/runtime are separate `UNVERIFIED` / `NOT_TESTED` profiles. They require exact tenant/cloud acceptance and never inherit generic gateway coverage. See `docs/native-controls/direct-cloud-provider-contracts.md`.
- Blind spots: Foundry runtime/actions, Azure API routes, account/tenant/deployment drift, direct/alternate routes, and all tool paths outside their independently accepted Hawk boundaries.
- Permissions: `gateway.intercept`, `policy.evaluate`.
- Privacy: Routed prompt/response and action metadata traverse Hawk.
- Degraded behavior: Do not enforce after validation, callback, policy, config, or version failure.
- Provenance: Repository gateway conformance evidence; Foundry native verification required.
