# Claude Code 2.1.183 native adapter acceptance

> Historical adapter `1.1.0` baseline. The current authoritative `1.2.0` closure is `docs/evidence/2026-08-12-claude-code-2.1.183-closure.md`, backed by the hash-checked acceptance registry. This document must not be used to infer the current MCP, prompt, Agent, remote, or managed-mode status.

Status: **VERIFIED for exactly Claude Code 2.1.183**  
Adapter: `anthropic.claude-code.command-hooks`  
Adapter version: `1.1.0`  
Date: 2026-08-11

## Acceptance boundary

The installed `/Users/ayushmaandang/.local/bin/claude` binary reported `2.1.183` and was exercised through its real command-hook engine. Noninteractive cases observed `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `SessionStart`, and `SessionEnd`. A controlling PTY was then used to exercise Claude's real interactive `PermissionRequest`; the event correlated to `PreToolUse` by the same privacy-safe action hash and exact parameter hash. `ConfigChange` is installed but was not emitted in this acceptance, so it remains Experimental. The model transport was an isolated loopback Anthropic-compatible fixture, so the acceptance used no external credentials or customer content. Hawk used a separate opaque-key Unix signer and a signature-verifying callback server; the callback did not trust unsigned decisions.

This evidence verifies the Claude binary/hook integration and Hawk adapter behavior for exactly the detected `2.1.183` binary. Any other version is `VERSION_MISMATCH` and is not eligible for Enforce until Hawk ships a new reviewed manifest and that exact binary passes acceptance. It does not broaden native-hook verification to ordinary Claude chat, direct Anthropic API calls, or removed hooks. The acceptance explicitly verifies that a user hook is bypassed by `--bare` and by `--safe-mode`; production `--safe-mode` coverage therefore requires an administrator-managed Hawk hook.

## Measured result

| Gate | Result |
|---|---|
| Signed pre-action allow | Passed |
| Allowed action executed | Passed |
| Signed pre-action block | Passed |
| Blocked action did not execute | Passed |
| Post-action correlation | Passed |
| Failed-tool correlation (`PostToolUseFailure`) | Passed |
| Post-action evidence quality | `provider_reported` |
| Default permission mode | Pre-action block passed |
| `acceptEdits` permission mode | Pre-action block passed |
| `bypassPermissions` permission mode | Pre-action block passed |
| `--dangerously-skip-permissions` | Pre-action block passed |
| Plan mode | Provider prevented execution before a Hawk tool hook, or Hawk blocked when emitted; never promoted as ordinary tool authorization |
| Hawk approval gate | Passed; `require_approval` denied at `PreToolUse`, marker never executed, approval must be resolved out of band and retried |
| File `Read` allow plus post correlation | Passed |
| File `Write` allow plus post correlation | Passed |
| Background Bash action | Pre-action block passed; marker was not created |
| `SessionStart` / `SessionEnd` | Both observed |
| `PermissionRequest` | Observed through real interactive PTY; provider permission context and exact-action correlation passed |
| Provider permission allow versus Hawk block | Provider permission is context only; competing provider allows did not weaken Hawk's canonical `PreToolUse` deny |
| Material action change | Produced a different approval action hash; prior approval could not authorize the changed action |
| Hawk `updatedInput` mutation | Disabled in verified v1; exact parameter binding is `INLINE_BOUND`, target binding remains Observe |
| `ConfigChange` | Installed but not emitted; visibility remains Experimental and Hawk's settings fingerprint remains authoritative |
| MCP tool lifecycle | Unit-normalized but no real benign MCP fixture in this run; remains EXPERIMENTAL |
| Competing input mutator listed before Hawk | Hawk deny remained effective |
| Competing input mutator listed after Hawk | Hawk deny remained effective |
| Callback timeout behavior | Failed closed; action did not execute |
| Configuration tamper detection | Passed |
| Uninstall preserved customer hooks | Passed |
| `--safe-mode` with user hook | Hook bypass observed; requires managed hook for coverage |
| `--bare` | Hook bypass observed; reported as bypass/not covered |
| Runtime report version binding | Passed; report bound to detected `2.1.183` |
| Measured signed-callback latency | Final passing run: 67 signed callback samples; p50 8.815 ms, p95 15.563 ms, p99 25.012 ms on local loopback. This is not production network latency. |
| Diagnostics | None |

## Capability-level result

| Capability | Level | Verification | Evidence boundary |
|---|---|---|---|
| Tool, command and file pre-action control | `INLINE_BOUND` | Verified | Exact version `2.1.183`; signed `PreToolUse`; no marker execution on deny |
| Exact parameter binding | `INLINE_BOUND` | Verified | Canonical parameter hash and approval action hash matched across pre-action and provider permission context |
| Target binding | Observe | Verified | Target hashes are evidence; universal target authorization is not claimed |
| Provider permission context | Observe | Verified | Real interactive `PermissionRequest`; never treated as Hawk authorization |
| Hawk approval binding | External | Verified | Hawk approval gates deny at `PreToolUse`; exact-action retry required after out-of-band approval |
| Approval correlation | Observe | Verified | Material parameter change produced a different approval action hash |
| Success/failure visibility and correlation | Observe | Verified | `PostToolUse` and `PostToolUseFailure`; evidence is provider-reported |
| `UserPromptSubmit` visibility | Observe | Verified | Lifecycle callback observed; prompt-control promotion remains Experimental |
| `ConfigChange` visibility | Observe | Experimental | Not emitted in the real-binary run; configuration fingerprint is authoritative |
| Independent execution proof | Unavailable | Verified limitation | Provider post events are not independent proof |

## Reproducible evidence

- `apps/endpoint-agent/tests/test_claude_binary_acceptance.py`
- `apps/api/tests/test_native_control_claude_adapter.py`
- `apps/endpoint-agent/tests/test_native_hook_callback.py`
- `apps/endpoint-agent/tests/test_native_hook_installer.py`
- `apps/endpoint-agent/tests/test_kms_hsm_provider.py`

The provider-neutral conformance suite is also required. Production eligibility remains gated by exact provider/product/version resolution, adapter version `1.1.0`, live signed callback health, current validation, configuration integrity, policy freshness, route binding, measured latency, and Hawk's adapter-enforcement feature flag. Post events prove provider-reported evidence flow, not independent execution verification.
