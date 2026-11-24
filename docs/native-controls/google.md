# Google / Gemini


- Gemini CLI native adapter: exact-version capability evidence exists for `0.54.4`; the adapter remains `experimental` and is not production eligible.
- Verified on that exact binary: prompt/turn block, model-request block, tool, shell, file and benign MCP pre-action control, destination binding for the fixture MCP server, provider-reported post-tool correlation, tamper/bypass detection, signed callback authentication and replay rejection.
- Newly verified mechanics: tail calls re-enter Hawk `BeforeTool` and can be blocked; interactive permission flow emits advisory `Notification` before the pending action executes. Competing-hook testing proved a later hook can mutate post-Hawk parameters, so any detected competing security hook makes Enforce ineligible.
- Still unverified: tool-selection `NONE` with a real model, response mutation/redaction, tenant-backed Enterprise Admin Controls, and actual managed-launcher MDM deployment. The hash-pinned launcher artifact is locally verified but is not deployment evidence.
- Verified fallback: Hawk `gateway_inline` for Direct API, version `hawk-openai-compatible-v1`.
- Can block: only the Hawk-routed model request/response path before provider invocation. This generic gateway route does not authorize a provider tool proposal or any tool execution.
- Observe only: provider-reported response evidence on the routed model path; it is not independent execution verification.
- Binding: the generic gateway records the bound model-request route. It does not establish provider-native tool, MCP, parameter, target, destination, account, tenant, or remote-execution binding.
- Direct/cloud contracts: Gemini API and Vertex AI are distinct `UNVERIFIED` / `NOT_TESTED` profiles. A verified generic gateway route does not promote either one. See `docs/native-controls/direct-cloud-provider-contracts.md`.
- Blind spots: other Gemini CLI versions, direct API traffic, Vertex AI routes, redirected system settings without the MDM launcher, disabled/removed hooks, competing security hooks, absent tenant Admin evidence, and absent endpoint-bound MDM evidence.
- Permissions: `gateway.intercept`, `policy.evaluate`.
- Privacy: Routed content and action metadata traverse Hawk.
- Degraded behavior: Ineligible on bypass, stale policy, failed validation, or version mismatch.
- Provenance: `docs/evidence/gemini-cli-0.54.4-acceptance-result.json`, `docs/evidence/gemini-cli-acceptance-registry.json`, plus repository gateway conformance evidence.
- Detailed native deployment semantics: `docs/native-controls/google-gemini-cli.md`.
