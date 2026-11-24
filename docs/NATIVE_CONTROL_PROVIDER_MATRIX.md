# Native Control Provider Matrix

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


This is the human-readable view of the versioned backend registry. The API and database profile are authoritative.

| Provider | Product | Method | Status | Tested version | Enforceable truth / blind spot |
|---|---|---|---|---|---|
| Anthropic | Claude Code | Native hook | Capability-level verification only for exact version 2.1.183 and adapter 1.2.0 | 2.1.183 | Real-binary acceptance passed signed tool/command/file allow/block, prompt non-delivery on block, a real local MCP read plus blocked write non-execution, Agent creation allow/block, observational subagent lineage, exact parameter binding, interactive `PermissionRequest`, external Hawk approval binding/correlation, provider-reported success/failure correlation, permission modes, mutator deny precedence, timeout, tamper and uninstall. Provider-native approval is not Hawk authorization. `ConfigChange`, Remote Control on this binary, cloud Code and managed `--safe-mode` remain Unverified/Experimental; target binding remains Observe; independent execution proof is Unavailable. Every other version is `VERSION_MISMATCH`. `--bare` bypasses hooks. See `docs/evidence/2026-08-12-claude-code-2.1.183-closure.md`. |
| Anthropic | Direct API | Gateway inline | Verified model request/response route only | hawk-openai-compatible-v1 | Direct bypass remains outside control; provider tool, MCP, parameter, target and destination binding are unavailable/unverified on this generic route. |
| Cursor | Cursor | Native hook | Experimental adapter with capability-level verification | Agent CLI `2026.08.11-e8db854`; signed desktop package `3.15.6` | The exact CLI release passed real interactive prompt allow/block, signed shell allow/block with non-execution, file-read control, benign MCP read plus blocked write, pre/post correlation, fail-closed timeout, replay/forgery rejection, hook-order deny precedence, mutation-attempt resistance, tamper detection and customer-hook preservation. Only the thirteen capabilities in the hash-checked registry are Verified. Desktop Agent Chat, Tab, cloud, subagent, generic tool, file-write pre-control, external endpoint-observation correlation and enterprise/MDM loading remain unverified, so the adapter is not production eligible. |
| Cursor | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| OpenAI | Agents SDK | SDK middleware | Experimental adapter; exact function-tool capability Verified | 0.20.0 | Function-tool input guardrail allow/block, non-execution, exact parameter/target reauthorization, and hash-only output correlation passed against the real SDK. Lifecycle hooks are Observe-only. HITL and every hosted/MCP/shell/patch/computer/agent-as-tool/handoff class remain independent and Experimental, Unverified, or Unavailable. |
| OpenAI | Codex | Native hook | Experimental; no promoted capabilities | Detected 0.137.0, accepted versions none | Hook normalization, Codex response serialization, tamper-aware local installation, and managed-only requirements rendering pass repository tests. Three safe real-binary noninteractive attempts did not emit `UserPromptSubmit`; the model ran instead. No native Codex protection is claimed until interactive and exact tool allow/block acceptance succeeds. Hosted tools do not traverse local tool hooks. |
| OpenAI | Direct API | Gateway inline | Verified only for the bound Hawk route | hawk-openai-compatible-v1 | Request control is Verified for routed traffic. Response/stream coverage is tracked separately as partial; customer-owned tool-loop authorization is a separate Experimental method. Direct bypass remains outside control. |
| Google | Gemini CLI | Native hook | Experimental adapter with capability-level verification | 0.54.4 only | The exact official 0.54.4 binary passed signed/replay-protected callback, prompt/model/tool pre-action blocks, shell/file/MCP allow-block, post-tool correlation, all approval modes including yolo, explicit exit-code-2, callback-loss fail-closed, policy-deny monotonicity, tail-call re-entry/block, interactive Notification observation, tamper and uninstall tests. Provider malformed hook output was warning/fail-open, so Hawk's independent serializer guard is required. Competing-hook testing proved post-Hawk parameter mutation is possible and therefore Enforce-ineligible. Real-model NONE, tenant Admin Controls, and MDM launcher deployment remain unverified, so the adapter is not production eligible. |
| Google | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| Microsoft | Agent Framework | Native hook | Unverified | None | No native protection claim |
| Microsoft | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| Azure | AI Foundry | Native hook | Unverified | None | No native protection claim |
| Azure | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| AWS | Bedrock Model API | API intercept | Unverified / not tested | None | A customer-owned invocation route is a possible model-request boundary only; direct provider invocation remains an explicit bypass. |
| AWS | Bedrock Guardrails | SaaS control API | Unverified / not tested external content policy | None | Input/output content evaluation only; never exact function, parameter, target, subject, approval, or execution authorization. Provider deny is monotonic; only `NONE` and `GUARDRAIL_INTERVENED` are accepted outcomes. |
| AWS | Bedrock AgentCore | SaaS control API | Unverified / not tested | None | Hosting/runtime context does not infer Hawk tool, MCP, target, customer-subject, approval, or execution authority. |
| AWS | Bedrock Action Runtime | Function middleware | Unverified / not tested | None | The customer action executor is the possible pre-execution boundary; post-Lambda evidence cannot prevent a completed consequence. |
| AWS | Bedrock MCP | Tool-loop intercept | Unverified / not tested | None | Customer-cloud generic MCP boundary only; it is not local MCP and does not inherit provider-hosted authority. |
| AWS | AgentCore Gateway MCP | SaaS control API | Unverified / not tested provider-hosted MCP | None | Separate hosted MCP tool-policy boundary; exact Hawk parameter, target, subject, approval, and execution binding remains unavailable. |
| AWS | Bedrock Knowledge Base | SaaS control API | Unverified / not tested observation/context | None | Retrieval/context observation only; it is not content inspection, tool control, or target-service authorization. |
| AWS | Bedrock Agents Classic | Agent middleware | Unverified / not tested compatibility only | None | Classic is separate and inherits no AgentCore, action-runtime, or MCP claim. |
| AWS | Custom Bedrock Agent | Agent middleware | Unverified / not tested | None | Customer action loop requires independent route, action, identity, allow/block, and non-execution acceptance. |
| AWS | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| Meta | Llama | Native hook | Unverified | None | Enforcement belongs at runtime/orchestration |
| Meta | Self-hosted | Endpoint runtime | Verified | explicit-hawk-client-binding-v1 | Unbound runtimes remain outside inline control |
| Meta | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| Moonshot | Kimi Coding | Native hook | Unverified | None | No native protection claim |
| Moonshot | Self-hosted | Endpoint runtime | Verified | explicit-hawk-client-binding-v1 | Unbound runtimes remain outside inline control |
| Moonshot | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| Alibaba | Qwen Agent | Native hook | Unverified | None | No native protection claim |
| Alibaba | Self-hosted | Endpoint runtime | Verified | explicit-hawk-client-binding-v1 | Unbound runtimes remain outside inline control |
| Alibaba | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |
| DeepSeek | Agent | Native hook | Unverified | None | No native protection claim |
| DeepSeek | Self-hosted | Endpoint runtime | Verified | explicit-hawk-client-binding-v1 | Unbound runtimes remain outside inline control |
| DeepSeek | Direct API | Gateway inline | Verified | hawk-openai-compatible-v1 | Direct bypass remains outside control |

## Direct and cloud provider contract boundaries

| Provider | Product | Method | Status | Tested version | Enforceable truth / blind spot |
|---|---|---|---|---|---|
| Anthropic | Direct API | API intercept | Unverified / not tested | None | Separate from Claude Code, Enterprise controls and generic gateway. Potential model route only; provider tools, MCP, parameters, targets, destinations and remote execution are not authorized. |
| Google | Gemini API | API intercept | Unverified / not tested | None | Separate from Gemini CLI and Vertex AI. Potential provider-hosted model route only; generic gateway coverage does not transfer. |
| Google | Vertex AI | API intercept | Unverified / not tested | None | Separate customer-cloud project/runtime route; model, deployment, account and tenant context require exact acceptance. |
| Azure | Azure OpenAI direct API | API intercept | Unverified / not tested | None | Separate from Microsoft Agent Framework and Foundry hosted runtime; no tool, MCP or hosted execution authority. |
| Microsoft | Foundry hosted model/runtime | SaaS control API | Unverified / not tested | None | Separate remote-hosted model/runtime boundary; local Function middleware and direct Azure routes do not transfer. |

All five rows require immutable exact tenant/cloud acceptance for account/tenant,
provider/product/runtime, model, route and deployment identity plus allow,
block and protected non-execution. They are never Enforce eligible merely
because the generic Hawk gateway is verified for a different routed
model-request/response path. See `docs/native-controls/direct-cloud-provider-contracts.md`.

Verified generic gateway rows control only the Hawk-routed model request/response path before provider invocation. They do not establish provider tool, MCP, parameter, target, destination, or endpoint-consequence control. Post-execution is observed, not externally verified. Endpoint-runtime rows shown as observation-only do not establish tool/command/file/network authorization or provider-native semantics.

Claude Code CLI, the local Desktop Code tab, IDE integrations, and Remote Control use the Claude Code lifecycle and are eligible for the native hook. Claude web/remote sessions require a repository or server-managed hook and a live observed callback because they do not read the workstation's user settings. Ordinary Claude Desktop chat, claude.ai chat, mobile chat, and direct Anthropic API calls do not expose the Claude Code hook lifecycle: Hawk governs those through the MCP Gateway and endpoint, browser companion and MCP Gateway, governed connectors, or LLM Gateway/bound SDK respectively. Hawk never converts those fallbacks into a native-hook claim.

The installed `2.1.183` binary with adapter `1.2.0` is the only verified Claude version. The hash-checked registry at `docs/evidence/claude-code-acceptance-registry.json` is authoritative. No range or future-version compatibility is inferred. Any other, malformed, bypassed, unhealthy, stale, or unvalidated version contributes no protected coverage and is ineligible for Enforce until Hawk ships a reviewed exact-version entry backed by a fresh binary acceptance artifact. Gemini CLI 0.54.4 has a hash-checked partial acceptance entry at `docs/evidence/gemini-cli-acceptance-registry.json`: only the listed capabilities are Verified, while the adapter remains Experimental and ineligible for production selection until its explicit promotion blockers close.

Cursor adapter `0.2.0` has a hash-checked partial acceptance entry at `docs/evidence/cursor-acceptance-registry.json` for Agent CLI `2026.08.11-e8db854`, inspected alongside the signed Cursor `3.15.6` desktop package. Only the registry-listed capabilities are Verified. The manifest remains Experimental and production selection remains disabled until the enterprise/MDM source and the separately listed Cursor surfaces are accepted. No version range or future-release compatibility is inferred.

## Self-hosted runtime boundary contracts

Customer Meta Llama, Qwen, DeepSeek, and Kimi runtimes; Llama Stack, Ollama,
vLLM, and TGI serving stacks; Qwen, DeepSeek, and Kimi provider APIs;
Qwen-Agent, DeepSeek customer tool-loop/agent-framework, and Kimi coding tool
loops; Unknown OpenAI-Compatible and Unknown Anthropic-Compatible runtimes;
and Custom Model Runtime are independent
profiles. All are reviewed but `UNVERIFIED` and `NOT_TESTED`; none are Enforce
eligible. Model/API/serving profiles use `API_INTERCEPT`; the three customer tool
loops use `TOOL_LOOP_INTERCEPT`. No profile infers its model provider/model
from the serving runtime. A protocol shape or model tool-call text never
grants a provider-native hook, tool/MCP, parameter, target, destination,
provider-account, or hosted-execution capability.

The verified generic Hawk Gateway remains a separate, bound model
request/response route.  It does not transfer to these runtime contracts, a
direct or alternate endpoint, sidecar, remote executor, or unknown compatible
server.  Exact customer runtime/version/route allow, block, protected
non-execution, latency, failure-mode, and bypass acceptance is required before
any of these profiles can progress beyond Monitor. The canonical acceptance
scope also binds the exact model provider, model, route identity, and
deployment identity; drift in any of those fields is Enforce-ineligible. See
`docs/native-controls/self-hosted-runtimes.md`.

OpenAI is represented by three product adapters, not a universal provider adapter. The action-class matrix is authoritative for Agents SDK, Codex, and Direct API selection. A function-tool capability never propagates to hosted tools, MCP, shell, patch, computer, Agent-as-tool, handoff, or an unknown action. See `docs/evidence/2026-08-12-openai-provider-family-acceptance.md`.
