# Anthropic Claude Code native control acceptance


Date: 2026-08-11  
Adapter: `anthropic.claude-code.command-hooks` `1.2.0`

## A. Claude version tested

Exact installed binary: `~/.local/bin/claude`, version `2.1.183`. This is the only verified version. Every other Claude Code version is `VERSION_MISMATCH` until a reviewed exact-version manifest and real-binary acceptance report are shipped.

## B. Adapter maturity

The adapter is Production maturity for its explicitly Verified capabilities on exact version `2.1.183`. Maturity does not promote Experimental, Observe, or Unavailable capability rows.

## C. Verified capabilities

- Signed workload identity and lifecycle callback authentication.
- `PreToolUse` pre-action authorization for tool, Bash command, file Read, and file Write actions.
- Deny before execution in default, `acceptEdits`, `bypassPermissions`, and `--dangerously-skip-permissions` execution modes.
- Successful `PostToolUse` and failed `PostToolUseFailure` correlation by the same signed session/tool correlation identifiers.
- `SessionStart` and `SessionEnd` lifecycle visibility.
- Real interactive `PermissionRequest` visibility with privacy-safe exact-action and parameter correlation to `PreToolUse`.
- External Hawk approval binding: review/approval/redaction outcomes deny at `PreToolUse`, are resolved by Hawk, and require an exact-action retry.
- `UserPromptSubmit` allow and block, including proof that a blocked prompt produced no model request.
- Real local MCP client/server execution: a read-only tool ran with correlated pre/post evidence, while a write-marker tool was denied before the server received it.
- Agent creation control at `PreToolUse:Agent`, with provider-reported `SubagentStart`/`SubagentStop` lineage on allow and no child-start event on deny.
- Background Bash pre-action denial in the tested fixture.
- Configuration fingerprint/drift detection, non-weakening deny precedence, bounded timeout fail-closed behavior, and reversible uninstall that preserves unrelated customer hooks.

## D. Unverified capabilities

- Provider-native approval as Hawk authorization. Claude's `PermissionRequest` is verified context only; Hawk approvals remain external to Claude's prompt.
- Managed-policy `ConfigChange` blocking, remote/web Code execution, and managed `--safe-mode` coverage.
- Generalized persistent-side-effect control outside the exact accepted tool families.

## E. Unavailable capabilities

- Independent proof that a provider-reported post action actually happened.
- Universal target binding. Exact parameter binding is verified; target binding remains Observe.
- Native-hook control for ordinary Claude Desktop chat, claude.ai chat, mobile chat, or direct Anthropic API traffic.

## F. Exact Hawk to Claude decision mapping

| Hawk decision | `PreToolUse` response | `PermissionRequest` response | Status |
|---|---|---|---|
| `allow` | `permissionDecision: allow` | `behavior: allow` | Implemented |
| `block` | `permissionDecision: deny` | `behavior: deny` if emitted | Real PreTool block verified |
| `warn` | `permissionDecision: ask` | `behavior: allow` | Real interactive provider context verified; this is not Hawk approval |
| `review`, `require_approval`, `require_second_approval`, `redact` | deny | deny if emitted | Hawk resolves approval out of band; an exact-action retry is required |
| callback error/timeout on a protected pre-event | deny | deny | Implemented and timeout verified |
| post/session event | no provider permission output | no provider permission output | Evidence/context only |

Hawk emits no `updatedInput` in verified v1. Claude's stricter deny precedence remains authoritative.

## G. Real allow test result

Passed. A signed Bash allow executed exactly once and created only its temporary marker. File Read and Write allow paths also executed, and each produced correlated signed post-action evidence.

## H. Real block test result

Passed. Signed deny prevented both the original Bash action and a competing hook's mutated action. The block remained effective with the competing mutator before and after Hawk in configuration order.

## I. Approval test result

Passed at the granular boundaries. A real interactive PTY caused Claude Code `2.1.183` to emit `PermissionRequest`. Hawk correlated it to `PreToolUse` using the same privacy-safe action hash and exact parameter hash. A materially changed command produced a different action hash. Separately, Hawk `require_approval` denied at `PreToolUse` and the marker did not execute. Claude's provider permission response is therefore Verified context, while the Hawk approval gate is a Verified external binding; provider-native approval as Hawk authorization remains unavailable by design.

## J. Post-execution correlation result

Passed for both success and failure. Pre/post events matched on signed correlation and parameter hashes. Evidence quality is `provider_reported`; independent execution verification remains Unavailable.

## K. Hook ordering result

Passed for denial non-weakening. Hawk deny won when a separate mutating allow hook appeared both before and after Hawk. Exact normalized parameter binding is `INLINE_BOUND`; target binding remains Observe and no universal target claim is made.

## L. Configuration tamper result

Passed. Hook timeout/config modification changed the settings fingerprint and validation failed. `disableAllHooks`, removed hooks, count/order changes, helper changes, and settings corruption are surfaced as drift. Managed-policy changes are not claimed blockable.

## M. Timeout and degraded behavior

A deliberately delayed callback exceeded the hook budget and the protected action did not execute. Pre-tool, permission, prompt, and configuration callback failures fail closed in the helper. Post/session failures emit no prevention claim. A missing/stale/unhealthy/version-mismatched integration is ineligible for Enforce.

## N. Latency p50/p95/p99

The final passing acceptance observed 95 signed callback samples: p50 `10.43 ms`, p95 `21.36 ms`, and p99 `32.737 ms` on local loopback. These are acceptance-path measurements, not production-network latency or an SLA.

## O. Conformance suite result

Passed. The Claude adapter satisfies the provider-neutral manifest, normalization, decision, limitation, timeout, and non-overclaim conformance gates for the promoted capabilities.

## P. Regression test result

- Native Control API suite: `162 passed`.
- Full endpoint-agent suite: `334 passed` using `--basetemp=/tmp/h` to stay within the macOS Unix-socket path limit.
- Installed Claude Code real-binary acceptance is included in the endpoint result and completed with no report diagnostics.
- Python compilation passed for real source files after excluding AppleDouble `._*.py` artifacts.
- UI code was not changed or revalidated in this adapter-only closure.

## Q. Control Coverage impact

For an exact `2.1.183` installation with adapter `1.2.0`, a healthy signed callback, current validation, intact configuration, fresh policy, route binding, and Enforce enabled, Hawk can truthfully count the tested Claude Code tool/command/file, prompt, MCP, and Agent creation paths as authorization covered. Exact parameter binding is inline-bound; provider permission context and subagent lifecycle are observed; correlated post events are provider-reported evidence. Provider-native approval as Hawk authorization, universal persistent actions, universal target binding, `ConfigChange`, Remote Control, cloud Code, managed safe mode, and independent execution proof retain their explicit Experimental, Observe, Unverified, or Unavailable states. No percentage is hardcoded.

## R. Known blind spots

- Any Claude Code version other than `2.1.183`.
- `--bare` skips hooks and is Not Covered by this path.
- `--safe-mode` bypasses user hooks; it requires a live administrator-managed hook to claim coverage.
- Removed/tampered/disabled hooks, unobserved remote sessions, or a direct provider path.
- Ordinary Claude chat and direct Anthropic API surfaces.
- Provider permission context cannot grant Hawk authorization; approval is resolved out of band and retried against the exact action.
- Target mutation by parallel hooks; Hawk `updatedInput` mutation is deliberately disabled.
- Provider-reported post evidence is not independent execution proof.

## S. Files modified

The implementation changes the Claude adapter and manifest, authenticated callback lifecycle projection, endpoint hook normalizer/decision translator, installer/CLI scopes and lifecycle configuration, real-binary acceptance harness/tests, native-control tests, and the Anthropic capability/runbook/evidence documents. The Git working tree remains intentionally unclean because unrelated user changes were preserved.

## T. Truthful promotion status

**YES — individual Claude Code capabilities can be shown as VERIFIED, PROTECTED, or ENFORCEMENT-CAPABLE only for exact version `2.1.183` and only while all live health and validation gates are satisfied. The product must not display a coarse “Claude verified” claim.**

It cannot be shown as universally protected across all Claude versions or surfaces. Prompt, MCP and Agent creation control are Verified only for the exact accepted fixture paths on 2.1.183; provider permission context, Hawk approval binding, approval correlation, exact parameter binding, subagent lineage, and success/failure correlation retain their granular results. Provider-native approval, generalized persistent-side-effect control, universal target binding, `ConfigChange`, Remote Control, cloud Code, managed safe mode, and independent post-execution verification retain their explicit non-Verified or non-inline states.

## Installation scope and safe uninstall

Supported settings scopes are user (`~/.claude/settings.json`), project (`.claude/settings.json`), local project (`.claude/settings.local.json`), and managed OS policy paths. Hawk installs `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `SessionStart`, `SessionEnd`, and `ConfigChange` entries atomically, idempotently, and before unrelated rows. `SubagentStart`/`SubagentStop` are evidence-only; Agent creation is authorized at `PreToolUse:Agent`. Uninstall removes only Hawk-marked rows and preserves customer configuration.

## Upgrade behavior

On binary version change, Hawk does not inherit compatibility. Enforce eligibility is removed until the new exact version has a reviewed manifest, real-binary acceptance evidence, and current server-side validation. Rollback to `2.1.183` still requires healthy current evidence; version alone is never sufficient.
