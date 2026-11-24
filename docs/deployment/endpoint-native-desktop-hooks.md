# Codex and Claude Code through the endpoint agent

Status: endpoint transport implemented and tested with synthetic events. Not activated or marked protected on this Mac. Ordinary Claude Chat is not covered by these hooks.

## Request path

Supported application hook → packaged `hawk-native-hook` → local endpoint socket → existing signed native-control callback → Hawk decision → signed endpoint response → provider-native block/no-objection output.

The endpoint holds each registered provider's callback configuration. The hook client holds only its provider family, absolute socket path and enrolled device public-key thumbprint. It cannot choose the backend URL, tenant, integration or signing key. Responses require a valid pinned signature and matching random request ID. No direct-server fallback exists in endpoint mode. Legacy direct callbacks remain available for existing installations.

The agent normalizes events using the existing privacy-safe native callback schema. Raw prompts/tool inputs transit local IPC in memory; the existing callback exports hashes and classification metadata. This change does not introduce full-content DLP, attachment extraction or output inspection. Native integration policy decides enforce versus monitor; this broker does not reinterpret a monitoring decision as enforcement.

## Deploy after enrollment and native integration registration

1. Deploy the updated endpoint package normally. Both the hook and native-control Python modules are included by the existing package/installer.
2. Register the Codex and Claude Code integrations through the existing Hawk native-control workflow. Their runtime JSON files must use the endpoint's exact `tenant_id` and `api_base_url` (stored as `api_url` in native runtime), correct provider family (`openai` or `anthropic`), approved product/version, integration/credential IDs and hardware signing-key references. Files must be private, non-symlinks. Do not invent credentials or weaken the bank identity profile.
3. In endpoint-agent configuration, add `native_hook_runtime_configs`, mapping `codex` and/or `claude_code` to the **absolute paths** of those registered runtime JSON files. Restart the agent through the deployment's normal service manager.
4. Install hooks with the packaged interpreter. Example for an already enrolled macOS runtime:

```bash
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
PYTHONPATH="$HAWK_ROOT/runtime/app" "$HAWK_ROOT/runtime/venv/bin/python" \
  -m hawk_endpoint_agent.native_control.cli install-endpoint \
  --provider codex \
  --endpoint-config "$HAWK_ROOT/state/endpoint-agent.json" \
  --helper "$HAWK_ROOT/runtime/bin/hawk-native-hook" \
  --config "$HAWK_ROOT/state/codex-endpoint-hook.json"
```

Repeat with `--provider claude_code` and a distinct `claude-endpoint-hook.json`. Default settings are `~/.codex/hooks.json` and `~/.claude/settings.json`. Existing unrelated settings/hooks are preserved. `--scope project --project-root /absolute/project` is also available. Endpoint installation checks the registered binding and signed live endpoint identity before writing hooks; it refuses an unavailable agent. Installation reports `protection_status: unverified`.

This is a Unix-domain-socket path for local sessions. Remote/SSH/cloud execution needs an endpoint on the execution host and separately validated configuration. User/project hooks are not tamper-resistant managed enforcement. Enterprise policy must govern installation, hook trust, disablement and removal; do not treat user-writable settings as an OS security boundary.

## Decisions and failure behavior

- A Hawk allow returns no permission override: the app's normal permission checks still apply.
- Enforced block, review, approval-required or redact decisions withhold supported pre-actions. The adapter does not pretend to apply an unsupported redaction.
- Invalid/unavailable/unsigned/stale/uncorrelated responses cause the hook to emit a blocking result for supported pre-action events. IPC waits up to three seconds, within the existing five-second pre-action hook configuration.
- Lifecycle/post-action hooks cannot undo an action already performed. Hook process failure, removal, or a provider-enforced timeout may cause the provider to continue; the adapter's error handling cannot override an absent hook.
- The installer does not claim arbitrary attachments, generated answers, every tool, ordinary Claude Chat or every desktop execution mode is covered.

## Verification and remaining gates

Synthetic tests cover both hook executables through the agent's actual signed socket with a stubbed backend policy response, allow/block, wrong key pin, provider isolation, unavailable agent, invalid decisions, local-only client configuration, and preserving native permissions. These are integration tests, not a live enterprise deployment.

Observed CLI versions: Codex 0.154.0 and Claude Code 2.1.183. These are not proof of the embedded engines in either desktop app. Live version/action acceptance remains required. Endpoint enrollment remains blocked in this session, so live settings were not changed.

The Claude lifecycle hash regression was repaired on 2026-09-24: pre-tool, permission, post-tool and failed-tool events with the same exact tool-use ID and action material share an approval hash. Missing tool IDs retain fresh callback identity and require reauthorization; content similarity alone must not attach a permission event to another invocation. The old test expecting that unsafe match was corrected. Different tool IDs or changed parameters remain separate.

Live activation remains blocked: the installed macOS identity helper is ad-hoc signed with no Team ID, and the host has no valid code-signing identity. Deploy a helper signed under the required trusted identity before attempting bank-profile enrollment. Do not relax identity verification or install blocking hooks against an unavailable endpoint. Desktop acceptance remains outstanding.

Uninstall using the existing `native_control.cli uninstall --provider ... --config ... --helper ...` command with matching scope/settings. It removes Hawk-managed hook rows and retains runtime configuration. Remove the endpoint mapping separately through managed configuration when retiring the integration.

References: [Codex hooks](https://learn.chatgpt.com/docs/hooks), [Claude Code Desktop shared hooks](https://code.claude.com/docs/en/desktop), [Claude hook failure behavior](https://code.claude.com/docs/en/hooks).
