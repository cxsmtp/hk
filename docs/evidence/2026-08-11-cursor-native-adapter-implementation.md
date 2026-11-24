# Cursor native adapter exact-release checkpoint — updated 2026-08-12

## Outcome

The Cursor adapter is no longer an all-unverified placeholder. An official Cursor desktop release and Agent CLI were installed in isolated temporary locations, authenticated with an isolated Cursor home, and exercised against tenant-bound signed Hawk callbacks.

The full exact-release local CLI acceptance gate passed. Thirteen capabilities are promoted individually to `verified`; the adapter remains **Experimental** and production-ineligible because the enterprise/MDM source and other Cursor surfaces were not exercised.

## Accepted release

- Cursor desktop: `3.15.6`.
- Desktop commit: `a1f686545fd0ce8917bbd2449f733551a9bce420`.
- Cursor Agent CLI: `2026.08.11-e8db854`.
- Desktop signature: deep/strict verification passed; notarization ticket stapled; Gatekeeper accepted the package.
- Final full matrix: `1 passed in 170.38s`.
- Conservative maximum observed signed-callback p95: `23.187 ms`.

## Proven behavior

- Real interactive prompt allow and pre-backend block.
- Real signed shell allow and block with blocked-action non-execution.
- File-read pre-action control.
- Benign MCP read and blocked MCP write with non-execution.
- Signed pre/post correlation for shell and MCP.
- Timeout fail-closed behavior.
- Replay and forged-callback rejection.
- Hook order deny precedence and mutation-attempt resistance.
- Configuration drift detection and customer-hook preservation.
- Exact version and signed package identity checks.

## Security boundary

The acceptance configuration contains only tenant, integration, credential and hardware-key references. Signing occurs through a helper-backed ES256 key; no private key or bearer token is persisted in the hook file, evidence artifacts or repository. The hook exports only bounded metadata and hashes.

## Promotion boundary

Verified manifest capabilities are limited to prompt, MCP, command and file-read control; parameter, target and destination binding; post-action visibility and correlation; persistent side-effect control and visibility; bypass detection; and configuration integrity.

Not promoted: desktop Agent Chat runtime, Tab, workspace lifecycle, cloud agents, subagents, generic tool control, file-write pre-control, approval binding, response control, external endpoint-observation correlation, independent post-execution verification, and enterprise/MDM source loading.

## Remaining deployment work

- Enroll production tenant credentials using the bank's hardware-backed key provider.
- Deliver the enterprise hook and helper through the customer's MDM and prove its source fingerprint and heartbeat.
- Run the unverified surfaces independently against the same exact-version and evidence rules.
- Add a new reviewed registry entry for every additional Cursor release; never widen by version range inference.
