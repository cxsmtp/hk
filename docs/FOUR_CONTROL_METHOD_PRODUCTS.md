# Four control-method products

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


These four methods have distinct controls and acceptance boundaries. A passing
repository check establishes only the behavior it exercised. It does not imply
that a customer installation, managed host, or production release is accepted.

| Product | Controls available | Repository and isolated-run evidence | Current acceptance |
|---|---|---|---|
| Browser extension | Discovery prompts, clipboard and upload signals, and backend allow, warn, and block decisions. | The extension build passed. Pinned Playwright Chromium revision 1208 passed the complete deterministic spec twice (20 of 20 checks), using two distinct OS-assigned `127.0.0.1` mock ports without touching the live API on port 8000. This is synthetic fixture evidence. | `target_required` for managed Chrome/Edge installation and lifecycle acceptance. |
| MCP gateway | Governed child processes, tool calls, repositories, and sessions. | Local package checks and a fresh eight-check strict Hawk lab passed. The official MCP TypeScript SDK `1.29.0` and actual Codex CLI `0.154.0` each completed three fresh read-only connections: allow, restart and reconnect allow, then exact `agent_session_revoked` denial. Each run had distinct correlated Hawk evidence and child call counts of 1, 2, 2. The original write tool remains blocked by its normal policy. Actual Claude Code connected and advertised the read tool but did not invoke it; its installed native hook signed the synthetic before-agent request, then the unchanged callback returned HTTP 500 and the hook failed closed with `policy_service_unavailable`. A rollback-only diagnostic did not reach the callback handler: native PostgreSQL on port 55432 rejected the connection with `could not open file` / `No such file or directory`; the file is unidentified. Claude lifecycle evidence is absent. | `target_required` for Claude Code compatibility, Codex and MCP on supported customer hosts, interactive approval, and release lifecycle. |
| LLM gateway | Governed requests and responses, redaction, pre-request blocking, restricted output mutation, and provider-failure receipts. | Five selected API tests passed with provider doubles. The exact local Ollama `qwen3.5:9b` digest, adapter preflight, and all eight isolated Hawk strict checks passed. A fresh local run then proved the sensitive pre-provider block, benign real-provider allow, controlled output from the fragmented `api_key` canary, and a second benign allow after API restart, with four distinct Hawk evidence IDs. This is local Ollama evidence. | `target_required` for production provider and release lifecycle acceptance. |
| Endpoint agent | Identity health, native permit binding, local allow and deny decisions, and old-token revocation. | The selected 45 local identity and permit tests and 10 API tests passed. These checks do not establish signed enrollment or enrolled-device behavior. | `blocked`: the signed enrollment path uses an untrusted ad hoc helper that blocks reenrollment proof. |

Both Hawk gateway routers require a healthy control plane before accepting
requests. The earlier SQLite attempt did not establish strict readiness. The
new isolated harness did: password-auth PostgreSQL, private Redis, real
migrations, worker, beat, component identities, artifact storage, and API
readiness passed without changing demo services. Downstream MCP correlation
is proved locally through the official SDK and Codex CLI for a synthetic read-only tool;
Claude Code compatibility remains unproved. The
isolated LLM run passed its local controls, with the local HTTP exception
scoped to the exact loopback Ollama provider and global controls enabled.

All four `release_ready` gates remain false. The verifier reports
`repository_checks_passed` separately from manifest `acceptance_state`,
`target_check`, and unchanged lifecycle gates. SHA-256 digests bind the
manifest, each version source, and each declared source or test file. Passing
local checks cannot promote unresolved target gates.

The fixed `promotion_requirements` contract requires clean install, upgrade,
rollback, evidence capture, and at least two distinct successful operations on
the intended target. Upgrade and rollback require distinct current and previous
verified artifacts; reinstalling the same version does not count. No verified
"last stable" release artifact is available in this repository. Browser needs
current and previous signed managed packages; MCP needs current and previous
artifacts plus a supported target host; LLM needs two immutable API image or
build digests and migration/backup recovery proof; Endpoint needs valid Developer
ID signing, notarization, MDM, and enrollment. Local browser, Claude Code, or
Ollama tests cannot supply those release artifacts.

The verifier runs only declared repository checks without a shell, under
per-check and combined timeout caps. It rejects paths outside the repository,
missing sources or roots, unapproved environment keys, invalid lifecycle
states or reasons, and weakened promotion metadata. Its output is capped and
records each check's result and duration. The isolated runners use separate
private PostgreSQL and Redis instances on OS-assigned loopback ports; their sanitized reports contain
only status, version/model identity, hashed IDs, decisions, and counts.

## Lifecycle matrix

`repo` means repository evidence covers that particular behavior; `target`
means managed-target or customer proof remains required; `blocked` means a
known prerequisite prevents acceptance. Clean install means installing the
product on its intended target. Rollback means returning a deployed release
to a prior verified version.

| Method | Install | Restart | Reconnect | Allow | Deny | Approval | Revocation | Outage | Upgrade | Rollback | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Browser extension | target | target | target | repo | repo | target | target | target | target | target | repo |
| MCP gateway | target | target | target | repo | repo | target | target | repo | target | target | repo |
| LLM gateway | target | target | target | repo | repo | target | target | repo | target | target | repo |
| Endpoint agent | blocked | target | target | repo | repo | target | repo | repo | target | target | repo |
