# Hawk Endpoint Agent POC

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


> Superseded safety notice: the legacy `infra/scripts/endpoint_agent.py` and
> `endpoint_proxy_guard.py` commands are not the approved endpoint deployment.
> Do not pass reusable Hawk access tokens in command arguments and do not enable
> a macOS system proxy for this POC.

The current user-scoped endpoint agent is implemented in
`apps/endpoint-agent`. Its supported local-development installer, security
model, operation commands, and rollback steps are documented in
`apps/endpoint-agent/README.md`.

Manual user-action acceptance for Chrome, Codex MCP, LLM/SDK,
developer-agent, Foundry, data transfer, discovery, evidence, and coverage is
defined in `docs/deployment/endpoint-agent-manual-test-matrix.md`.

## Current security contract

- Enrollment consumes a single-use authorization through standard input. It is
  not accepted in command arguments, environment variables, or package files.
- The device uses a hardware-backed signing identity and short-lived DPoP
  sessions. Access tokens are held only in the encrypted in-memory vault.
- Before launchd starts, the installer reopens the enrolled hardware identity
  in separate helper processes, checks the backend-issued public thumbprint,
  signs a fresh random challenge, and verifies the signature locally. Failure
  leaves the agent stopped; Hawk never falls back to an exportable software key.
- A recovery may select a new versioned Secure Enclave identity with
  `--device-key-tag com.hawk.endpoint-agent.device-key.<version>` while retaining
  the unusable reference as timestamped operator evidence.
- Local broker responses are signed. Chrome, MCP, and SDK endpoint bindings
  verify the enrolled public device-key pin before trusting a decision.
- The default mode is monitor. Monitor observations never claim inline
  authorization or prevention.
- Enforce coverage exists only for an explicitly bound pre-action client path.
  Direct or bypassed traffic remains Unknown or Not Covered.
- Raw prompts, clipboard text, MCP arguments, credentials, and private keys are
  not persisted in endpoint state or receipts.
- The agent does not change the macOS system proxy, install a TLS trust anchor,
  or activate transparent routing by default.

## Production boundary

The repository contains fail-closed build and evidence contracts for signing,
notarization, attestation, EDR coexistence, managed routing, and non-macOS
hardware identities. They do not constitute bank readiness.

Production still requires Apple Developer ID signing/notarization/stapling, a
functional narrowly scoped Network Extension relay authorized through MDM,
customer remote-attestation verification, formal EDR coexistence evidence, and
physical Windows TPM/CNG and Linux TPM2 validation. Until those artifacts exist,
system-wide endpoint authorization coverage must remain Not Covered.
