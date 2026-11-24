# Claude Code 2.1.183 native and fallback closure

Status: **capability-level VERIFIED for exactly Claude Code 2.1.183 with adapter 1.2.0**  
Evidence time: `2026-08-11T20:47:35Z`  
Binary SHA-256: `6218efccd06194ea0bc381121bf03040a027a04d991eaed886da02a00449ad0f`  
Acceptance artifact SHA-256: `ec10a989a17bcb5ab52697429bf7cf3c4c0e711f6597fecf389d71167bd52232`

## Evidence boundary

The installed macOS arm64 Claude Code binary reported `2.1.183`. Hawk exercised its real command-hook engine with isolated local callback, signer, Anthropic-compatible model, PTY, filesystem markers, and stdio MCP fixtures. The fixtures used no external credentials, provider data, customer prompts, repositories, or messages.

Only capabilities listed below are promoted. Every other Claude Code version, adapter version, launch path, deployment mode, or application surface remains unsupported or separately evidenced. Ordinary Claude Desktop/web/mobile chat is not a Claude Code native-hook surface.

## Exact results

| Gate | Result |
|---|---|
| Signed tool allow and execution | Passed |
| Signed tool block and non-execution | Passed |
| Mutator before/after Hawk | Deny remained effective; neither original nor mutated marker executed |
| Callback timeout | Failed closed; marker absent |
| Permission modes | Default, `acceptEdits`, `bypassPermissions`, dangerous-skip all blocked pre-action |
| Interactive `PermissionRequest` | Observed and correlated to the exact action; provider allow could not override Hawk deny |
| Prompt allow | Reached the local model |
| Prompt block | Signed `UserPromptSubmit` block; model request count did not increase |
| MCP read | Claude's real MCP client initialized the local stdio server, invoked `read_fixture`, and emitted correlated pre/post events |
| MCP write | Hawk denied `write_marker`; the server call log and marker both remained absent |
| Agent allow | `PreToolUse:Agent`, `SubagentStart`, and `SubagentStop` observed with privacy-safe child correlation |
| Agent block | `PreToolUse:Agent` denied; no `SubagentStart` was emitted |
| File read/write | Executed with correlated provider-reported post evidence |
| Failed tool | Correlated `PostToolUseFailure` observed |
| Session lifecycle | `SessionStart` and `SessionEnd` observed |
| `ConfigChange` | Not emitted; remains Experimental |
| `--safe-mode` with user settings | User hook bypass proved; not covered without an administrator-managed source |
| `--bare` | Hook bypass proved; Not Covered |
| Remote Control | `Unverified: not_supported_by_binary` for installed 2.1.183 |
| Managed safe mode | `Unverified: managed_access_required`; no managed customer policy was modified |
| Diagnostics | None |

## Measured local acceptance latency

The final adapter `1.2.0` run observed 95 signed callbacks: p50 `10.43 ms`, p95 `21.36 ms`, p99 `32.737 ms`. These are loopback acceptance measurements, not production network latency and not an SLA.

## Capability decisions

- Verified inline-bound: tested tool, Bash command, file read/write, prompt, MCP, and Agent-creation actions.
- Verified context/evidence: interactive provider permission context, external Hawk approval binding, exact parameter correlation, subagent lifecycle, successful/failed post correlation.
- Experimental: `ConfigChange`, background and generalized persistent-side-effect generalization beyond accepted fixtures.
- Observe only: universal target binding and provider-reported post events.
- Unverified: Remote Control, cloud Code, managed safe mode, and any untested exact binary.
- Unavailable from this path: independent execution proof and ordinary Claude Desktop/web/mobile chat governance.

## Fallback truth

- Claude Desktop local MCP is covered only through a signed Hawk MCP Gateway route.
- Ordinary Desktop device behavior needs an explicit endpoint binding; process presence alone is discovery, not action authorization.
- Claude web custom connectors need a publicly reachable, tenant-bound Hawk MCP Gateway.
- Claude web prompt/upload/copy-paste controls need the managed Hawk browser companion.
- Direct Anthropic API traffic needs Hawk LLM Gateway or a bound SDK.

Fallback evidence never upgrades the Claude Code native-hook capability matrix.

## Reproduction and registry

- Binary test: `apps/endpoint-agent/tests/test_claude_binary_acceptance.py`
- MCP fixture: `apps/endpoint-agent/src/hawk_endpoint_agent/native_control/claude_mcp_fixture.py`
- Endpoint hook tests: `apps/endpoint-agent/tests/test_native_hook_installer.py` and `test_native_hook_callback.py`
- API adapter tests: `apps/api/tests/test_native_control_claude_adapter.py`
- Surface truth tests: `apps/api/tests/test_native_control_claude_surfaces.py`
- Machine result: `docs/evidence/claude-code-2.1.183-acceptance-result.json`
- Exact-version registry: `docs/evidence/claude-code-acceptance-registry.json`

The registry entry is accepted only when the provider version and adapter version match exactly, the entry is reviewed, required fields are present, latency is bounded, and the referenced artifact SHA-256 matches its bytes.

## Verification result

- Native-control API: `162 passed`.
- Full endpoint agent: `334 passed` in one run with `--basetemp=/tmp/h` to respect the macOS Unix-socket path limit.
- Focused endpoint Claude closure: `21 passed`.
- Real Python source compilation: passed, excluding AppleDouble `._*.py` files.
- UI: unchanged and not revalidated by this closure.
