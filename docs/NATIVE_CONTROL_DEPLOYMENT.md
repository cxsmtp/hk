# Native Control Deployment


## Database

Apply additive migrations `0049_native_control_framework` and `0050_native_control_health_observations`. They create capability profile, integration, workload credential, validation, replay, selection, and append-only measured-health tables. They do not rename Browser, Endpoint, Runtime, or SaaS & APIs and do not manufacture historical protection.

## Flags

Native enforcement executes inside Authorization Kernel V2. Configure the kernel first:

1. Set a distinct `CANONICAL_ACTION_BINDING_KEY` of at least 32 characters.
2. `AUTHORIZATION_KERNEL_V2_ENABLED=true`
3. `AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED=true`
4. `AUTHORIZATION_KERNEL_V2_ENFORCE=true`
5. Set an explicit tenant/surface rollout, for example:

```text
AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT={"TENANT_UUID":["llm_gateway","mcp_gateway"]}
```

Then enable native control progressively:

1. `NATIVE_CONTROL_FRAMEWORK=true`
2. `CONTROL_CAPABILITY_MATRIX=true`
3. `TRUSTED_CONTROL_SELECTOR=true`
4. `NATIVE_CONTROL_MONITOR=true`
5. one provider flag such as `NATIVE_CONTROL_OPENAI=true`
6. only after safe validation, `NATIVE_CONTROL_ENFORCE=true`

All flags default false. Authoritative coverage requires the kernel V2 tenant/surface rollout, the global native enforce flag, the matching provider flag, and a current route binding. A missing gate reports Unknown/Not Covered and cannot produce a green inline assertion.

## Tenant route bindings

`NATIVE_CONTROL_ROUTE_BINDINGS_JSON` is tenant scoped and server owned. Every binding pins provider, product, provider version, adapter version, allowed method (derived from the surface), and exact integration IDs:

```text
NATIVE_CONTROL_ROUTE_BINDINGS_JSON={"TENANT_UUID":{"llm_gateway":{"integration_instance_ids":["INTEGRATION_UUID"],"provider":"openai","provider_version":"hawk-openai-compatible-v1","adapter_version":"1.0.0","product":"direct_api"},"mcp_gateway":{"integration_instance_ids":["INTEGRATION_UUID"],"provider":"openai","provider_version":"hawk-openai-compatible-v1","adapter_version":"1.0.0","product":"direct_api"}}}
```

Expected methods are fixed by surface: `llm_gateway` and `mcp_gateway` require `gateway_inline`; `runtime_control` permits `endpoint_runtime` and a compatible, version-bound, runtime-validated `native_hook`. A multi-provider LLM gateway may use a list of provider-specific binding objects under `llm_gateway`; the LLM service selects only the binding matching its server-resolved outbound provider. MCP/runtime requests do not trust caller provider claims and fail closed if a multi-provider route is ambiguous.

## Lifecycle

1. Create an integration using an exact provider/product/method manifest.
2. Register a per-installation P-256 public workload credential with bounded event types and expiry.
3. Perform one real provider action through the installed hook or explicitly bound endpoint runtime. The public callback endpoint authenticates the signed installation event, prevents replay, evaluates policy before execution, emits evidence, and records observed latency.
4. Run `POST /native-controls/integrations/{id}/validate/run`. The server verifies the current credential epoch, recent authenticated callback, evidence flow, observed latency, route observation, configuration integrity, and its own side-effect-free allow/block probes. Client claims cannot replace this proof.
5. Enter monitor and perform one more real action through that bound surface.
6. Revalidate after any credential, configuration, provider, adapter, route, or policy change. Only a current passed server validation bound to the active credential can proceed.
7. Review coverage, health, blind spots, and findings.
8. Enter enforce only when every transition invariant and rollout gate passes.

Rotate by registering a higher-epoch installation credential. It remains `rotating` while the old credential stays active. A passed validation signed by the new credential promotes it and atomically revokes the earlier active/rotating credentials. Revoking the final active credential immediately degrades the integration, removes protected coverage, and emits evidence/finding state.

## Rollback

Disable the integration, its provider flag, the global native enforce flag, or the kernel tenant/surface rollout. Existing Hawk browser, gateway, MCP, endpoint, and runtime controls remain in place. Reconcile Deployment Surfaces so authorization coverage becomes Unknown/Not Covered instead of retaining a stale green state.

Software rollback is a separate signed update operation with an explicit rollback version; it cannot be delivered through policy/helper messages.

## Provider hook installation

The endpoint package provides idempotent, reversible installer/callback plumbing for these documented contracts:

- Claude Code: the full installed lifecycle configured by Hawk (`PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, and `ConfigChange`). Only exact version `2.1.183` is eligible with Hawk adapter `1.1.0`; every other version is a version mismatch until a reviewed exact-version manifest and acceptance report exist. Per-capability status still applies: provider permission context, external Hawk approval binding/correlation and exact parameter binding are Verified; provider-native approval, prompt authorization, MCP execution and `ConfigChange` remain Experimental; target binding remains Observe; independent post-execution verification is Unavailable.
- Gemini CLI: `BeforeTool`, `AfterTool`, and `BeforeModel` for `gemini-cli-hooks-2026-04-10`.

Install with an explicit scope:

```text
hawk-native-control install --provider claude_code --scope user ...
hawk-native-control install --provider claude_code --scope project --project-root /path/to/repository ...
sudo hawk-native-control install --provider claude_code --scope managed ...
```

The user scope writes `~/.claude/settings.json`. Project scope writes `.claude/settings.json` in the selected repository. On macOS the managed scope writes `/Library/Application Support/ClaudeCode/managed-settings.json`; Linux and Windows use the provider's documented managed-settings locations. Web/remote Claude Code must use repository or server-managed settings and demonstrate a live callback; a workstation user hook is not evidence for that remote execution surface.

Run the detected binary acceptance before lifecycle validation:

```text
hawk-native-control validate-claude --binary /absolute/path/to/claude
```

The command exits nonzero if the binary does not pass signed allow/block, blocked non-execution, post correlation, hook ordering, timeout, tamper, uninstall, and bypass checks. A successful local report is still not Enforce authority until the backend validation is current and bound to the same detected provider version and credential epoch.

The installer preserves existing hook configuration and refuses an unsafe helper path. The helper exports only normalized event metadata and a local payload hash, signs the canonical callback with the device identity, fails closed before protected actions, and never stores an API access token. These facts prove Hawk's plumbing, not universal provider compatibility. `--bare` deliberately skips Claude hooks and must be reported as bypass/not covered unless a separately verified endpoint or network launch control blocks it. `--safe-mode` is covered only when the Hawk hook is administrator-managed. Direct provider API calls, ordinary Claude chat surfaces, unsupported client versions, application chrome that does not traverse the documented hook contract, and provider binaries that have not passed runtime validation remain outside native-hook coverage.

## Continuous reconciliation

Run both the Celery worker and beat scheduler. `app.jobs.native_control_jobs.reconcile_native_controls` executes every 60 seconds and evaluates callback recency, evidence flow, measured p95 latency, policy freshness, configuration integrity, credential state, capability/version drift, bypass, execution drift, and approval invalidation. It opens or resolves idempotent findings and degrades unhealthy Enforce/Monitor integrations. Recovery returns an integration to Monitor only; it never automatically restores Enforce.

## Production signer helper

Device keys may use opaque `kms://`, `hsm://`, or `pkcs11://` references. Production helper transport supports an authenticated Unix-domain socket (`unix:///var/run/hawk/kms-signer.sock`) and a Windows named pipe (`pipe://...`), with framed bounded requests, request-ID/key binding, peer/authentication checks, and rejection of responses containing private or secret material. The remote signer service, bank HSM policy, attestation, packaging, and operational key ceremony remain deployment responsibilities and must be conformance-tested with the target bank infrastructure.
