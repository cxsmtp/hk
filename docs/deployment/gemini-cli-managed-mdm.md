# Gemini CLI managed launcher and MDM deployment


## Truth boundary

Hawk can render and locally verify a hash-pinned Gemini CLI launcher. Hawk does not claim that launcher is deployed, that Google Enterprise Admin Controls are active, or that an endpoint is protected until the backend validates a signed tenant- and endpoint-bound receipt.

The managed launcher prevents a user-supplied `GEMINI_CLI_SYSTEM_SETTINGS_PATH` from redirecting Gemini away from the administrator settings file. Before rendering, Hawk invokes the staged binary through its pinned runtime and requires the exact reviewed version. The rendered launcher then verifies the SHA-256 of the Gemini entry point, pinned runtime, Hawk hook, Hawk runtime configuration, and system settings before every launch. Any mismatch exits with code `78` before Gemini starts.

## Required macOS files

Deploy these as administrator-owned, non-symlink files:

| Artifact | Recommended path | Mode |
|---|---|---:|
| Pinned Gemini CLI entry point | `/Library/Hawk/lib/gemini-cli/0.54.4/index.js` | `0555` |
| Pinned Node runtime | `/Library/Hawk/runtime/node` | `0555` |
| Hawk native hook | `/Library/Hawk/bin/hawk-native-hook` | `0555` |
| Hawk runtime configuration | `/Library/Hawk/etc/native-control.json` | `0600` |
| Gemini system settings | `/Library/Application Support/GeminiCli/settings.json` | `0600` |
| Generated launcher | `/Library/Hawk/bin/hawk-gemini` | `0555` |

The runtime configuration contains tenant/integration/credential identifiers and a KMS/HSM key reference. It must not contain a provider API key, OAuth token, Hawk bearer token, private key, or refresh token.

The managed Gemini settings must disable auto-update and must contain the Hawk handlers for all supported events. Version changes require a new exact-binary acceptance artifact and reviewed registry entry before rollout.

## Render the launcher

After the files are staged at their final paths, render the final launcher from the endpoint-agent package:

```bash
python -m hawk_endpoint_agent.native_control.cli render-gemini-managed \
  --binary "/Library/Hawk/lib/gemini-cli/0.54.4/index.js" \
  --runtime "/Library/Hawk/runtime/node" \
  --settings "/Library/Application Support/GeminiCli/settings.json" \
  --helper "/Library/Hawk/bin/hawk-native-hook" \
  --config "/Library/Hawk/etc/native-control.json" \
  --expected-version "0.54.4" \
  --output "/Library/Hawk/bin/hawk-gemini"
```

The renderer refuses missing files, symlinks, group/world-writable files, non-executable code artifacts, an exact-version mismatch, and an `/usr/bin/env` entry point without a separately pinned runtime. It never discovers Gemini through `PATH`.

## MDM order

1. Deliver the pinned runtime, Gemini entry point, Hawk hook, system settings, and token-free runtime configuration.
2. Set administrator ownership and the modes above.
3. Render or deliver the reviewed launcher and set it to `0555`.
4. Expose only the launcher to users through the managed application/package path; do not expose an alternate mutable Gemini executable.
5. Run `hawk-gemini --version` and one harmless allow/block acceptance action.
6. Collect a signed `google-gemini-managed-launcher-evidence/1.0` receipt containing tenant ID, endpoint ID, `provider: google`, `product: gemini_cli`, `source: enterprise_mdm`, a timezone-aware observation timestamp, exact provider version, the MDM profile ID hash, all required hash checks, the enforced system-settings override check, and evidence references.
7. Submit the receipt to Hawk's normal receipt verifier. Coverage remains **Unknown / Not covered** until verification succeeds.

## Real-model `NONE` acceptance

The deterministic fixture proves hook merging but cannot prove model compliance. On an approved acceptance endpoint, provide `GEMINI_API_KEY` only in the invoking process environment and run:

```bash
python -m hawk_endpoint_agent.native_control.cli validate-gemini \
  --binary "/Library/Hawk/lib/gemini-cli/0.54.4/index.js" \
  --runtime "/Library/Hawk/runtime/node" \
  --real-model-none
```

The harness uses an isolated home, does not persist or report the key, invokes no fake-response transport for this case, requests one harmless temporary marker action, and verifies that `BeforeToolSelection` emitted while `BeforeTool` and the marker remained absent. A missing/invalid credential or provider failure remains Unverified.

## Enterprise Admin Controls

Google Enterprise Admin Controls are a separate provider control plane. Hawk accepts them only through `google-gemini-admin-controls-evidence/1.0` with a tenant-bound signed receipt verified by the authoritative integration. Local settings, a CLI `--admin-policy` file, screenshots, or a payload field that merely says `signature_verified: true` cannot establish this claim.

Until that receipt proves Strict Mode, YOLO prevention, MCP allowlist enforcement, and required MCP server enforcement, Hawk reports Enterprise Admin Controls as **Unverified**.
