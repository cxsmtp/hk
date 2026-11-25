# OpenAI


- Verified native capability: None for Codex. Lifecycle callbacks are not treated as action permissions.
- Verified fallback: Hawk `gateway_inline` for Direct API, version `hawk-openai-compatible-v1`.
- Can block: only the existing OpenAI Direct API adapter's Hawk-routed model request/response path before provider invocation. Model tool proposals and exact tool execution remain separate action classes.
- Observe only: provider-reported response state; provider success does not become verified execution.
- Binding: the generic gateway route does not establish provider-native tool, parameter, target, destination, account, tenant, or remote-execution binding.
- Direct API ownership: OpenAI Direct API remains the existing action-class-specific adapter. Hawk does not create a duplicate OpenAI direct-provider contract for protocol-compatible or cloud-provider paths.
- Blind spots: Codex/local actions, hosted tools/MCP, and Direct API routes outside the exact Hawk-bound route.
- Permissions: `gateway.intercept`, `policy.evaluate`.
- Privacy: Prompt/response and canonical action metadata traverse Hawk when routed through the gateway.
- Degraded behavior: Bypass, stale policy, version drift, or failed validation removes eligibility.
- Provenance: Repository gateway conformance evidence; Codex native-hook verification required.
