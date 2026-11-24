# Cursor native control


## Current truth

- Adapter: `cursor.cursor.command-hooks` version `0.2.0`.
- Overall maturity: **Experimental**. It is not eligible for production adapter selection.
- Exact verified Cursor Agent CLI release: `2026.08.11-e8db854`.
- Approved signed desktop package inspected alongside the CLI: Cursor `3.15.6`, commit `a1f686545fd0ce8917bbd2449f733551a9bce420`.
- Installed locations: `/Users/hawk-operator/Applications/Cursor.app` and `/Users/hawk-operator/.local/share/cursor-agent/versions/2026.08.11-e8db854/cursor-agent` (with `agent` and `cursor-agent` links in `~/.local/bin`).
- Acceptance scope: the local Cursor Agent CLI using a tenant-bound ES256 Hawk hook in a user hook source. Desktop Agent Chat, Tab, cloud agents, subagents and the enterprise/MDM source are not covered by this result.

## Individually verified capabilities

- Interactive prompt allow and block through `beforeSubmitPrompt`; the blocked prompt did not reach the backend.
- Signed shell allow and block through `beforeShellExecution`; the blocked command did not execute.
- File-read pre-action authorization through `beforeReadFile`.
- Benign MCP read plus blocked MCP write through `beforeMCPExecution`; the blocked write did not execute.
- Provider-reported shell and MCP post-action correlation.
- Parameter, target and MCP destination binding using signed hashes.
- Fail-closed timeout behavior.
- Forged callback and replay rejection.
- Deny precedence with customer hooks before and after Hawk.
- A customer input-mutation attempt could not override Hawk's deny.
- Hook configuration drift detection and preservation of customer hooks during install/uninstall.
- Signed endpoint-native to MCP pre/post correlation without a second policy evaluation.

These are the only capabilities marked `verified` in the manifest. Generic tool control, file-write pre-control, delegation, provider approvals, desktop/Tab/cloud execution and independent execution verification remain Experimental or Unavailable.

## Evidence and release identity

- Evidence registry: `docs/evidence/cursor-acceptance-registry.json`.
- Acceptance result: `docs/evidence/cursor-2026.08.11-e8db854-acceptance-result.json`.
- Desktop DMG SHA-256: `deaef4ff90e235c7f4c0aa3b7c4bd89e471c827a954586da2aace0ef44bb40a8`.
- Agent CLI package SHA-256: `46044d6d7bcbd7b49a0cf1cd01aa4ca79aaa2ea5f2c7a32965fc0ebe29841790`.
- Conservative maximum observed signed-callback p95: `23.187 ms`. This is callback latency, not total model or network latency.

## Enrollment and privacy

The acceptance hook was bound to an isolated acceptance tenant, integration and credential ID. ES256 signing used a helper-backed key reference; no private key or access token was stored in the repository or hook file. Cursor credentials were kept in an isolated temporary home.

Hawk exports bounded metadata and stable hashes. It does not export raw prompts, source or file content, shell output, MCP output, transcript paths, account email, repository paths, attachments, or agent-thought content.

## Deployment sources

Cursor supports user (`~/.cursor/hooks.json`), project (`.cursor/hooks.json`), team/cloud and enterprise system hook sources. The intended bank deployment is the enterprise source delivered by the customer's MDM:

- macOS: `/Library/Application Support/Cursor/hooks.json`
- Linux/WSL: `/etc/cursor/hooks.json`
- Windows: `C:\ProgramData\Cursor\hooks.json`

The repository builds this managed installation plan, but this acceptance did not write or execute the macOS enterprise source. Cursor documents enterprise priority over team, project and user sources; Hawk does not claim the source is deployed until an MDM installation heartbeat and fingerprint are observed.

## Repeatable acceptance

Run the acceptance gate only with the exact reviewed artifacts and an isolated authenticated Cursor home:

```bash
hawk-native-control validate-cursor \
  --binary /absolute/path/to/cursor-agent \
  --acceptance-home /absolute/path/to/isolated-cursor-home \
  --desktop-app /absolute/path/to/Cursor.app
```

The gate exits non-zero for a version/signature mismatch or when a required verified local capability fails. Capabilities outside the accepted set remain unpromoted even when this command passes.

## Remaining before production promotion

1. Deploy and execute the enterprise hook through the bank's real MDM with tenant production credentials and hardware-backed signing.
2. Run separate acceptance for desktop Agent Chat, Tab, workspace lifecycle, subagents and cloud agents.
3. Validate generic tool and file-write pre-action controls before promoting them.
4. Correlate real external endpoint observations with native/MCP events; the current proof covers the endpoint-resident native hook and its MCP pre/post events.
5. Repeat the full gate for every additional Cursor version. No compatible-version inference is allowed.

Official hook behavior and distribution constraints: [Cursor Hooks documentation](https://cursor.com/docs/hooks).
