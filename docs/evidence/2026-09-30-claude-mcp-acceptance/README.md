# Claude MCP three-phase acceptance passed

Installed Claude Code **2.1.183** passed the complete isolated acceptance run. All three processes connected to Hawk, advertised and invoked the exact permitted synthetic tool once, and produced distinct correlated Hawk event/evidence hashes.

| Check | Hawk decision | Cumulative child executions |
| --- | --- | --- |
| Allowed call | Allow | 1 |
| Fresh client reconnect after Hawk API restart and strict readiness | Allow | 2 |
| Call after persisted session revocation | Block: `agent_session_revoked` | 2 |

This proves CLI reconnect after server restart with a fresh client, not recovery of a continuously running Claude Desktop session. The third invocation reached Hawk, but the underlying tool did not execute. The disposable installation was cleaned up. `release_ready` remains false; this does not promote an endpoint package or establish Protected status.

## Repairs and verification

The earlier failure is now identified: the second Claude process began its first turn while `hawk_lab` was still `pending`, before the tool was advertised. Its normal model completion was not evidence of a successful MCP call. The runner now sets `MCP_CONNECTION_NONBLOCKING=0` and `MCP_CONNECT_TIMEOUT_MS=30000` only in the scrubbed Claude child environment. These are supported by the installed binary and documented in [Anthropic's environment reference](https://code.claude.com/docs/en/env-vars). No client upgrade, extra prompt, blind retry, hook disablement, permission bypass, or global configuration change was used. The existing 120-second process deadline and $0.05 per-process cap remain.

The diagnostic runner retains bounded, sanitized connection timelines, stderr categories and partial phase evidence. Raw prompts, completions, credentials and identifiers are not exported. The saved success and pending-failure reports both pass their strict validators.

A separate setup failure came from a macOS AppleDouble metadata file being mistaken for a migration. The migration runner now uses a private temporary copy that excludes only `._*` and `__pycache__`, preserves real migration contents, and cleans up on success or failure. The verified source sidecar was preserved in private quarantine; no real migration was changed. A fresh disposable PostgreSQL preflight reached migration `0092_github_repository_runtime_controls` with zero model calls and completed cleanup.

Focused verification: **15 Claude tests and 5 migration-runner tests passed**; scoped whitespace checks passed. The final live run exited zero and satisfied the unchanged full acceptance validator. Final review also corrected a parser overwrite so tools advertised within the Hawk server details remain visible in the final result; the nested-tool regression and all 15 Claude tests passed afterward, without another live call.

## Separate demo readiness issue

The main demo reports **503: database schema out of date**, unchanged before and after the final isolated run. Its durable database is consistently at `0091_exec_mcp_device_auth`; the two new `0092` schema objects are absent. Migration `0092` belongs to unapproved repository-control work and was intentionally not applied to the demo. No demo API restart or database migration was performed.

The malformed metadata previously prevented expected-head discovery, which the existing schema-health logic can reduce to a note and incorrectly report healthy. Quarantining it exposed the real source/database mismatch. This acceptance work does not claim that readiness defect or the separate repository-control rollout is complete.

## Evidence

- [Complete three-phase client report](accepted-three-phase.json)
- [Retained pending-connection failure](pending-before-connection-wait.json)
- [Earlier result before detailed connection diagnostics](prior-unknown-reconnect-result.json)
- [Current summary and review status](result.json)
