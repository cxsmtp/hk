# OpenAI provider-family control acceptance — 2026-08-12

## Decision

Hawk now represents OpenAI with three independent adapters:

- `OpenAIAgentsSDKControlAdapter` — SDK middleware and lifecycle observation.
- `CodexNativeControlAdapter` — Codex lifecycle hooks only.
- `OpenAIDirectAPIControlAdapter` — bound gateway, API intercept, and customer-owned tool-loop paths only.

There is no `OpenAIUniversalProtectedAdapter`, and no provider-wide protected claim.

## Action-class gate

Selection narrows OpenAI capabilities using the exact action class before evaluating a control point. Missing or unknown classes are conservative. Function-tool control cannot propagate to hosted web/file search, code interpreter, image generation, hosted or local MCP, local or hosted shell, computer, patch, Agent-as-tool, handoff, Codex tools, or unknown tools.

Model request, model response, function tool, hosted tool, MCP, shell, patch, computer, delegation, Codex-local tool, and unknown classes have independent profiles. Response coverage is recorded as `complete`, `partial`, `request_only`, `post_execution`, or `unknown`.

## OpenAI Agents SDK

Exact package accepted: `openai-agents==0.20.0`.

The package was installed only in `/private/tmp/hawk-openai-agents-acceptance`; Hawk's API environment was not changed. The acceptance used the real `ToolInputGuardrail`, `ToolOutputGuardrail`, `ToolGuardrailFunctionOutput`, `FunctionTool`, `ToolContext`, and SDK tool-execution guardrail functions.

Observed result:

```json
{"adapter":"OpenAIAgentsSDKControlAdapter","allow_executed_once":true,"block_non_execution":true,"lifecycle_authorization_capable":false,"local_acceptance_latency_ms":0.518,"output_evidence":"provider_reported_hash_only","sdk_context_binding_enforced":true,"sdk_version":"0.20.0"}
```

Promoted only for exact 0.20.0 function tools with both Hawk guardrails explicitly attached:

- pre-execution function-tool control;
- exact argument and application-resolved target binding;
- the SDK `ToolContext` tool name, tool-call ID, and parsed arguments must exactly match the Hawk binding before authorization;
- changed argument, target, or destination forces reauthorization;
- block trips the SDK input guardrail before the tool function is called;
- output is correlated to the same Hawk action using hash-only, provider-reported evidence.

Not promoted:

- HITL remains Experimental. Hawk approval binding is implemented, but a real interrupted SDK run/resume was not accepted here.
- `RunHooks` lifecycle events are evidence-only and explicitly report `authorization_capable: false`.
- hosted tools, MCP variants, shell variants, patch, computer, tool search, Agent-as-tool, and handoff remain separate action classes. None inherits function-tool verification.
- output callbacks do not provide independent proof that a remote or hosted side effect occurred.

Official SDK contract used: [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-python/guardrails/), [tools](https://openai.github.io/openai-agents-python/tools/), and [MCP](https://openai.github.io/openai-agents-python/mcp/).

## Codex

Installed binary detected: `codex-cli 0.137.0`.

Implemented and repository-tested:

- `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, session, compact, subagent, and stop event installation;
- privacy-safe prompt/action/result hashing;
- separate shell, `apply_patch`, local MCP, other local function-tool, subagent, hosted-tool, and unknown classifications;
- documented Codex deny/allow output shapes; unsupported `PreToolUse ask` is never emitted;
- callback loss fails closed for pre-model, pre-tool, and permission boundaries;
- idempotent atomic local installation, drift detection, tamper detection, and Hawk-only uninstall;
- managed-only `requirements.toml` rendering with `[features].hooks = true` and `allow_managed_hooks_only = true`; the CLI refuses to overwrite an unrelated administrator requirements file and requires MDM merge.

Real-binary gate: **failed, no promotion**.

Three safe noninteractive attempts used project hooks, a session config override, and an isolated `HOME`/`CODEX_HOME`. In all three cases Codex 0.137.0 did not emit `UserPromptSubmit`; it continued to the model. No callback, signed envelope, block, or callback latency was observed. Therefore:

- `exact_verified_versions` remains empty;
- Codex remains Experimental;
- shell, patch, MCP, local function-tool, prompt, permission, and post-action capabilities are not Verified;
- hosted tools and cloud execution remain outside the local hook path.

The next promotion gate is a real interactive `UserPromptSubmit` and `PreToolUse` allow/block run using the installed managed hook, followed by non-execution, ordering, competing-mutation, timeout, signed-backend verification, and post-action correlation for each individual action class.

Official contract used: [Codex hooks documentation](https://developers.openai.com/codex/config-advanced#hooks). The current manual states that local Bash, `apply_patch`, MCP, and other local function tools use `PreToolUse`/`PostToolUse`, while hosted tools such as WebSearch do not.

## Direct API

The Direct API adapter does not claim a native hook. Its verified control point is the existing, explicitly bound Hawk gateway/API route. Direct traffic that bypasses Hawk is outside control.

Acceptance:

- response-control chain, authorization-surface parity, and gateway security regressions initially passed `103/103`. The final rerun passed `102/103`; the remaining test failed because the pre-existing Presidio setup attempted to install a missing spaCy model from an API venv without pip and held the SQLite evidence database lock. No OpenAI adapter assertion failed.
- one existing third-party Click/spaCy deprecation warning remained;
- response coverage is `partial` for gateway streaming, `request_only` for an API intercept without a bound response phase, and `complete` only for the customer-owned tool-loop phase represented by that exact method;
- provider-proposed tool execution still requires a separate customer-owned pre-execution callback. Model request control does not imply tool execution control.

## Repository verification

- OpenAI adapter, matrix, selector, manifest, bridge, and persistence tests: passing.
- Codex hook, callback, installer, and existing provider regression tests: passing.
- Direct API targeted regressions: one clean `103 passed` run; final rerun `102 passed, 1 unrelated environment/database-lock failure`.
- Real Agents SDK 0.20.0 bounded acceptance: passed.
- Real Codex 0.137.0 bounded noninteractive acceptance: failed honestly; no capability promoted.

Local acceptance latency is not production network latency. No result above is used to infer future-version compatibility.
