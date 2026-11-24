# Anthropic

- Verified native capabilities: exactly Claude Code `2.1.183` through Hawk adapter `1.2.0`. Real-binary evidence verifies tool, command, file read/write, prompt non-delivery on block, real local MCP read/write prevention, Agent creation control, observational subagent lineage, exact parameter binding, interactive provider permission context, external Hawk approval binding and correlation, success/failure post correlation, session lifecycle, permission-mode block behavior, background blocking, timeout fail-closed behavior, deny precedence, tamper detection and safe uninstall. This is capability-level verification, not a coarse “Claude verified” claim. Every other Claude Code version is a version mismatch until a new reviewed exact-version registry entry and acceptance artifact exist.
- Verified fallback: Hawk `gateway_inline` for Direct API, version `hawk-openai-compatible-v1`.
- Can block: Validated Claude Code tool/command/file actions through `PreToolUse`, plus model requests on the explicitly routed Hawk gateway path before provider invocation. The generic gateway does **not** authorize provider tools, MCP, parameters, targets, destinations, or endpoint consequences. MCP normalization is implemented but remains Experimental until a benign real MCP fixture passes this binary path.
- Observe only: Post-execution status; it is not externally verified execution proof.
- Binding: Claude callbacks bind installation credential, detected provider version, event, tool/action metadata and payload hash. The generic gateway records the bound model-request route; it does not establish exact provider tool, parameter, target, or destination binding.
- Surfaces: Native hooks cover Claude Code CLI, local Desktop Code, IDE, and Remote Control. Web/remote Code requires a repository or server-managed hook with a live callback. Ordinary Desktop/web/mobile chat and direct API calls use Hawk MCP/endpoint, browser/MCP, governed-connector, or LLM Gateway/SDK paths and are not native-hook claims.
- Blind spots: any Claude Code version other than `2.1.183`, `--bare`, `--safe-mode` without an administrator-managed hook, removed/tampered hooks, unobserved remote Code sessions, ordinary chat actions outside a bound Hawk surface, and Direct API traffic bypassing Hawk. Interactive `PermissionRequest` is verified provider context, not authorization: Hawk approvals deny at `PreToolUse`, are resolved out of band, and require an exact-action retry. Exact parameter binding is inline-bound; target binding remains Observe. `ConfigChange`, prompt authorization and real MCP execution remain Experimental.
- Permissions: `claude.settings.write` or managed deployment permission, installation-scoped callback identity, `gateway.intercept`, and `policy.evaluate` as applicable.
- Privacy: Native callbacks export normalized event metadata and a local payload hash. Prompt/response content traverses Hawk only on the configured gateway/browser path.
- Degraded behavior: Unsupported or unvalidated version, missing callback, configuration drift, gateway bypass, stale policy, or protocol mismatch makes the point ineligible; protected native pre-actions fail closed.
- Provenance: Real installed Claude Code `2.1.183` signed allow/block/non-execution acceptance plus provider-neutral conformance and current lifecycle health. Promotion is exact-version and capability-by-capability, never inherited by future versions.

## Enterprise provider-hosted boundaries

Hawk now represents two **separate, unverified** Anthropic Enterprise
boundaries: `enterprise_inference_hook` for a provider-hosted model-request
hook, and `tenant_restrictions` for managed-route/account filtering. Neither
is a Claude Code hook, generic gateway route, personal-account control, tool
authorization, parameter/target binding, MCP control, or endpoint floor.

Both remain `NOT_TESTED` and ineligible for Enforce until the customer’s
approved Enterprise organization produces tenant-bound evidence for the exact
route/configuration: real allow, block, and protected non-execution. Personal
and unapproved-organization accounts are rejected before either profile can be
considered. The model-request boundary and tool-action boundary remain
independent capabilities.
