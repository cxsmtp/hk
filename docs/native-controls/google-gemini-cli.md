# Google Gemini CLI native control


## Promotion state

The Hawk adapter is **Experimental with capability-level verification**. The only reviewed binary is official npm package `@google/gemini-cli@0.54.4`, bound to adapter `1.0.0`. Tail-call re-entry and interactive `Notification` emission are verified, and the competing-hook outcome is now known. It is still ineligible for production selection because real-model `NONE`, tenant-backed Enterprise Admin Controls, and managed launcher deployment lack external acceptance evidence.

The hash-checked sources of truth are:

- `docs/evidence/gemini-cli-0.54.4-acceptance-result.json`
- `docs/evidence/gemini-cli-acceptance-registry.json`
- `docs/evidence/2026-08-12-gemini-cli-0.54.4-native-adapter-acceptance.md`

No compatibility range is inferred. Any version other than `0.54.4` is a version mismatch and contributes no native protected coverage.

## Installation and scope

The installer preserves customer configuration and installs Hawk handlers for `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`, `AfterTool`, `PreCompress`, and `Notification`. Tool matchers use `.*`; lifecycle matchers use `*`; timeouts are 5,000 ms because Gemini expresses hook timeout in milliseconds.

Supported paths are user `~/.gemini/settings.json`, project `<workspace>/.gemini/settings.json`, and managed system override paths: macOS `/Library/Application Support/GeminiCli/settings.json`, Linux `/etc/gemini-cli/settings.json`, and Windows `C:\ProgramData\gemini-cli\settings.json`.

Bank deployment must use a managed system override plus an MDM-controlled launcher that pins the real binary, pinned runtime, control files, and `GEMINI_CLI_SYSTEM_SETTINGS_PATH`. Hawk now renders and tamper-tests that launcher and verifies the staged binary reports the reviewed exact version before rendering. This is an artifact proof, not deployment proof: coverage remains Unverified until Hawk validates a tenant- and endpoint-bound MDM receipt.

## Security semantics

- `BeforeTool` is the exact pre-action boundary. Real allow and block tests passed for shell, file, and benign local MCP tools; blocked markers did not execute.
- `BeforeAgent` blocks the turn but never authorizes a later tool. A real block stopped the flow before model or tool events.
- `BeforeModel` controls the model request only. A real block stopped the flow before tool execution.
- `BeforeToolSelection` filters tools; it is not exact action authorization. Real fixture evidence confirmed whitelist union behavior. `NONE` remains unverified because a fake model response cannot prove real-model compliance; the credential-gated acceptance path is implemented but has not been run with a real provider credential.
- `AfterTool` is provider-reported evidence. Pre/post parameter hashes correlated, but it cannot reverse side effects.
- `AfterModel` was observed at a chunk boundary. Full-stream response blocking/redaction is not verified.
- `AfterAgent`, `SessionEnd`, and `PreCompress` are advisory/provider-reported. A real interactive permission flow emitted `Notification` with the pending action still absent. Notification remains advisory and never authorizes the action.

Hawk performs no tool-input mutation in adapter v1. Exact composition testing proved that a later competing `BeforeTool` hook can replace parameters after Hawk evaluates them. Therefore parameter/target binding is not accepted in that configuration, and a detected competing handler on `BeforeTool`, `AfterTool`, `BeforeToolSelection`, `BeforeModel`, or `AfterModel` makes integrity verification fail and Enforce ineligible. Customer hooks are preserved during install/uninstall, but preservation is not trust.

## Strict helper output and degradation

Stdout is restricted to one compact JSON object. Diagnostics use stderr. The exact 0.54.4 provider treated plain-text pollution, truncated JSON, multiple JSON objects, and an unexpected top-level type as warning/fail-open cases. Hawk therefore does not rely on provider parsing for safety: its independent serializer guard converts a validation failure at `BeforeTool`, `BeforeAgent`, or `BeforeModel` into an intentional exit-code-2 block with no partial stdout.

Both JSON deny and exit code 2 prevented the test action. Callback timeout and unavailable-backend cases failed closed. SIGTERM produced no partial stdout. Hawk never treats an accidental nonzero exit as an authorization decision.

## Policy and approval modes

Hawk `BeforeTool` blocked in `default`, `auto_edit`, `plan`, and `yolo` modes. A provider-native deny remained monotonic when Hawk allowed the callback. Provider policy can add a deny floor but cannot replace Hawk policy.

The local acceptance identity could not activate a real enterprise Admin tier. Strict Mode, immutable enterprise MCP controls, required servers, and organization allowlists must stay Unverified until tested with tenant evidence. Provider `trust: true` never equals Hawk authorization.

## MCP, shell, and file evidence

The real CLI launched a local no-network MCP fixture. Hawk resolved `mcp_hawkfixture_read_marker` and `mcp_hawkfixture_write_marker` to one existing MCP asset, observed the read, allowed the harmless write, and blocked the same write before execution. Shell and file write tests used only temporary markers; file read did not export file contents.

The exact binary accepted an `AfterTool` tail request, re-entered Hawk `BeforeTool` with tail-call provenance, and Hawk blocked the generated shell action before its marker existed. This verifies tail-call re-entry only for exact version `0.54.4`; it does not extend to other versions.

## Capability truth

Verified only for exact version `0.54.4`: tool control, command control, file-read control, file-write control, MCP control, MCP destination binding, prompt control, persistent-side-effect control, provider-reported post-execution visibility/correlation, config integrity, bypass detection, and verified absence of independent post-execution enforcement.

Experimental or unverified: exact parameter/target binding in the presence of competing hooks, response control, tool-result control, real-model tool-selection `NONE`, Enterprise Admin Controls, managed MDM deployment, approval binding, tool failure visibility, delegation, containment, and independent execution verification. Tail re-entry and Notification observation are verified mechanics, not additional authorization capabilities.

## Upgrade and uninstall

Auto-update does not inherit verification. A new binary must run the exact acceptance gate and receive a new reviewed, hash-bound registry entry. Uninstall removes only Hawk-owned fragments and preserves customer hooks/settings. Removing, disabling, modifying, redirecting, timing out, or version-mismatching the native hook must lower health and coverage; no stale Protected state is allowed.
