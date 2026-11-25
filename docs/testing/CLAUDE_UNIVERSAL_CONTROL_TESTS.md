# Claude Universal Control Manual Tests


This runbook separates Claude Code native-hook coverage from ordinary Claude chat and direct API coverage. A test passes only when the action traverses the stated Hawk control point and the dashboard shows matching evidence. Do not use real bank data or credentials.

## Coverage truth

| Claude surface | Hawk control path | Native hook? | Required proof before Enforce |
|---|---|---:|---|
| Claude Code CLI | Claude lifecycle hooks | Yes | Exact verified version `2.1.183`, successful binary acceptance, managed/user hook callback, current server validation |
| Claude Desktop Code tab, local session | Same Claude Code hook engine and local settings | Yes | Same as CLI; test the action in the Desktop Code tab |
| Claude IDE integration | Same Claude Code hook engine | Yes | Same as CLI; test from the IDE |
| Claude Code Remote Control | Hook on its underlying local Claude Code session | Yes | Live callback from that exact session |
| Claude Code web or Desktop remote session | Repository or server-managed hook | Yes, but not from workstation user settings | Live remote callback plus version-bound validation |
| Ordinary Claude Desktop chat | Hawk MCP Gateway and endpoint binding | No | Governed MCP action or verified endpoint decision |
| claude.ai web chat | Hawk browser companion and MCP Gateway | No | Browser pre-action evidence or governed MCP action |
| Claude mobile chat | Governed MCP connectors only | No | Governed connector action evidence |
| Direct Anthropic API | Hawk LLM Gateway or explicitly bound SDK | No | Request/response traverses the bound gateway/SDK |

## 1. Validate the installed Claude Code binary

Run this once from the repository; the governed actions in later tests are performed by you in Claude:

```bash
cd "/path/to/hawk-checkout/apps/endpoint-agent"
PYTHONPATH=src python3 -m hawk_endpoint_agent.native_control.cli \
  validate-claude --binary "$HOME/.local/bin/claude"
```

Pass requires JSON containing `"passed": true`, `provider_version: "2.1.183"`, the same `runtime_binding_version`, signed allow/block success, blocked non-execution, successful and failed post correlation, file read/write correlation, permission-mode and background blocks, session lifecycle evidence, and observed `safe_mode_user_hook_bypassed` and `bare_mode_hook_bypassed` facts. The measured latency is local acceptance latency, not a production-network SLA.

Do not Enforce another installed version. The current manifest is exact to `2.1.183`; another version remains `VERSION_MISMATCH` until Hawk ships a reviewed manifest and acceptance evidence for that exact binary.

## 2. Claude Code CLI native allow and block

1. Install the Hawk hook at user or managed scope and confirm its integration is in Monitor.
2. In Claude Code CLI, ask for a harmless read of a synthetic file. Confirm the allow/warn result and that a signed `PreToolUse` callback appears.
3. Change the Hawk policy to block writes to the selected synthetic path.
4. Ask Claude Code to write `HAWK DEMO ONLY` to that path.
5. Confirm Claude reports the block and the file was not created or changed.

Dashboard: open `http://localhost:3001/surface-coverage`. The Anthropic/Claude Code point must show the detected provider version, callback health, evidence flow, validation, mode, and measured p95. Follow its evidence link to `http://localhost:3001/evidence` or the decision feed under `http://localhost:3001/observe`.

## 3. Claude Desktop Code tab

1. Fully quit and reopen Claude Desktop after installing the hook.
2. Open the **Code** tab and select a synthetic test folder.
3. Request the same harmless read, then the same policy-blocked write from test 2.
4. Confirm the read follows policy and the blocked write never changes the file.
5. Confirm the callback identifies the Claude Code product and detected version. Do not treat the floating Hawk companion overlay as proof by itself.

Ordinary Claude Desktop chat is a different test: use a Hawk-wrapped MCP server and perform a real read plus a policy-blocked write. That proves the MCP Gateway path, not the Claude native hook.

## 4. Claude IDE and Remote Control

Run the same read/write pair inside the Claude IDE integration. For Remote Control, start the session from the governed local Claude Code process and repeat the pair remotely. Both tests pass only if the backend receives the lifecycle callback from the exact session and records the detected version.

## 5. Claude Code web or Desktop remote

1. Put the Hawk hook in the test repository's `.claude/settings.json` or deploy it as server-managed settings. A workstation-only `~/.claude/settings.json` is insufficient.
2. Start a remote Code session and perform the read/write pair.
3. Confirm `$CLAUDE_CODE_REMOTE=true` is represented in bounded session evidence and a live callback is received.
4. If no callback is observed, Hawk must show Unknown/Not Covered and Enforce must remain unavailable.

## 6. `--safe-mode`, `--bare`, tamper, and uninstall

- Start Claude with `--safe-mode`. A user hook is expected to be bypassed; this surface is covered only if the administrator-managed Hawk hook still produces a callback.
- Start Claude with `--bare`. Claude intentionally skips hooks. Hawk must mark the session as a bypass/not covered; never report a native block. A separately validated endpoint/network policy may prevent this launch, but that is a different control claim.
- Remove or alter the Hawk hook. Configuration integrity must fail, the point must degrade, and Enforce coverage must disappear.
- Run the reversible uninstall. Customer hooks must remain unchanged and Hawk must no longer claim the native path is protected.

## 7. claude.ai browser upload, paste, and prompt controls

1. In managed Chrome, open claude.ai.
2. Paste a synthetic value such as `DEMO_CUSTOMER_001 demo@example.invalid` into the prompt box.
3. Attempt to upload a text file containing only `DEMO_API_KEY=FAKE-NOT-A-SECRET`.
4. Submit a prompt that matches a configured Hawk browser policy.
5. Confirm each decision occurs before paste/upload/submit when configured to block.

Dashboard: use `http://localhost:3001/observe` for the decision/evidence and `http://localhost:3001/surface-coverage` for Browser coverage. These actions do not pass through Claude Code hooks.

## 8. Claude Desktop chat MCP read and blocked write

1. Configure Claude Desktop with a Hawk-wrapped MCP server, not the direct upstream server.
2. Ask it to list or read one harmless public resource.
3. Ask it to perform a write action that a Hawk policy denies.
4. Confirm the read result is returned, the write reports Hawk's block exactly, and no upstream write occurs.

Dashboard: verify the MCP control point and its decision/evidence. Do not label it as endpoint or native-hook authorization unless that separate path was actually used.

## 9. Direct Anthropic API through the LLM Gateway

Send a synthetic request using the Hawk LLM Gateway URL and a configured provider credential. Test one allowed request and one policy-blocked request. A direct request sent to Anthropic's URL bypasses this path and must remain Not Covered unless the application is explicitly bound to the Hawk SDK/endpoint adapter.

Dashboard: use `http://localhost:3001/surface-coverage` for the LLM Gateway point and `http://localhost:3001/observe` for the pre-action decision. Post-action evidence remains `provider_reported` unless an independent execution verifier exists.

## Acceptance criteria

1. Every protected action has an authenticated pre-action decision from the correct control path.
2. A blocked action has direct non-execution proof; a warning is not a block.
3. The detected client version is exactly `2.1.183` and is bound to a passed validation before Enforce.
4. Claude Code and ordinary Claude chat are never collapsed into one coverage claim.
5. Removed hooks, `--bare`, unobserved remote sessions, direct API bypass, stale validation, unhealthy callback, or unknown version show Unknown/Not Covered.
6. `PostToolUse` is classified `provider_reported`; Hawk does not claim independent execution proof.
7. A companion badge/overlay is presentation only. The decision receipt and backend evidence are authoritative.
