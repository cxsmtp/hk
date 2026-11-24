# Hawk Endpoint Inline Control

Managed macOS deployment starts in monitor mode and activation remains an
explicit MDM/installer action. The Endpoint Security path uses exact signed
resource and destination maps plus bounded Claude process-family lineage.
Network child-process attribution stays unverified until signed target-host
acceptance proves it. Source compilation, pending approval, stale policy, or a
missing receipt reports `Needs attention`; it never reports `Protected`.

The managed policy compiler verifies the existing signed endpoint policy and
an independently signed exact macOS binding manifest before producing native
wire-v2 bytes. External KMS/HSM signatures and MDM delivery remain required.
Fresh target acceptance is a separate signed, device- and artifact-bound input;
neither an enabled Network Extension manager nor unsigned release JSON raises
the display state. Source builds and this software closure remain unverified on
a customer Mac until the Apple, MDM, and target-test gates complete.

An optional Endpoint-family deployment surface for managed laptops in SASE/ZTNA
environments. It adds device discovery and verified local control paths while
collaborating with Hawk's browser extension, MCP Gateway, LLM Gateway, SDK, and
provider-native controls. It does not replace those surfaces.

## Reproducible development environment

From this directory, with Python 3.11+ and uv 0.11.6 or a compatible release:

```sh
uv sync --locked --extra dev --extra fast
uv run --locked --extra dev --extra fast python -m pytest tests \
  --deselect=tests/test_claude_binary_acceptance.py::test_installed_claude_2_1_183_honors_signed_hawk_allow_block_and_timeout \
  --deselect=tests/test_gemini_binary_acceptance.py::test_installed_gemini_binary_acceptance \
  --deselect=tests/test_cursor_binary_acceptance.py::test_exact_cursor_release_runs_signed_capability_level_acceptance \
  --deselect=tests/test_chatgpt_desktop_live_install.py::test_installed_chatgpt_identity_matches_manifest_and_fails_closed_on_invalid_signature
```

The verified software environment is macOS 26 with Xcode 26.6 (macOS SDK 26.5),
plus Node 20 and Git. The endpoint CI workflow runs this selection with
an isolated home and temporary directory. These four exclusions require real
installed providers and separately configured acceptance; they are unverified,
not passing software tests. Running on Linux alone does not validate the Apple
compiler and packaging checks. Unit fixtures inject the banner UI and use a
fixed policy clock while retaining expiry, signature and identity denials.

`uv.lock` pins the complete dependency graph, including optional extras. Package
version ranges remain the supported library contract. Run Windows packaging on
the target Windows architecture with `--extra windows-build`; resolution on macOS
does not validate Windows binaries, device enrollment or hardware-backed signing.

## What the functional macOS build provides

- monitor-first browser, MCP, LLM, supported SDK, developer-agent, Foundry-bound,
  and data-transfer evaluation through authenticated per-user IPC or an explicitly
  configured loopback proxy;
- action-scoped `inline_prevented`/`inline_allowed` evidence only when a request
  reached a verified pre-action adapter;
- privacy-safe local baseline aggregates and deterministic policy-pack proposals;
- centrally managed monitor/enforce switching, with an explicit same-user control
  only in the local-development profile;
- bounded evidence queues that drop monitor observations before decision receipts;
- process/network/application discovery and AI-notetaker controls from the existing
  endpoint foundation;
- balanced resource gates: idle <=100 MB/1% CPU and active <=200 MB/5% CPU; and
- a reversible per-user launchd installation.

All local decision responses are signed by the enrolled P-256 device identity.
Chrome's native host, the MCP proxy, and the Node endpoint SDK verify the signed
payload against the enrollment-created public thumbprint before treating a
decision as endpoint-authorized. A socket pathname or same-user file permission
is never treated as sufficient proof by itself.

The functional build does not install a kernel extension, inject into processes,
alter the macOS system proxy, or trust a TLS CA by default. Bank mode requires a
Developer ID hardened signature for the small Secure Enclave helper. The
repository includes fail-closed packaging, notarization, remote-attestation,
EDR-evidence, Windows TPM/CNG, Linux TPM2, and Network Extension gate contracts.
Actual fleet readiness still requires customer Developer ID/notarization
credentials, a deployed remote attestation verifier, signed EDR certification,
and MDM approval. The Network Extension deliberately refuses activation until a
functional TCP/UDP relay is supplied and proven; it does not black-hole traffic
or claim transparent coverage from source code alone.

## Truthful coverage

Endpoint installation and service health mean `ready`, not `inline_allowed`.
Authorization coverage is earned per adapter only after a pre-action decision.
Direct SDK calls, unmanaged MCP clients, bypassed browser companions, pinned TLS,
and other uninstrumented paths remain `Unknown`, `Not Covered`, or `detected_only`.

## Privacy boundary

Raw prompts, responses, MCP/tool arguments, API keys, credentials, clipboard text,
documents, cookies, and decrypted TLS bodies are not persisted in baselines,
receipts, logs, or heartbeats. Local state contains bounded categories, hashes,
counts, identity references, reason codes, adapter health, and evidence references.

## Secretless authentication

The endpoint stores no API key, bearer token, refresh token, password, enrollment
secret, or exportable device private key. An admin creates a five-minute,
single-use enrollment authorization in Hawk. Paste that JSON into the installer
through standard input. After enrollment, Secure Enclave signs single-use
challenges; five-minute device tokens stay AES-GCM encrypted between API calls and
every request carries a fresh proof-of-possession signature.

Run backend migration `0048_endpoint_device_identity` before enrollment.

## Install on macOS

The default mode is monitor.

Monitor mode is passive: it records would-allow/warn/block decisions but never
opens a modal warning, terminates a process, or applies notetaker eviction.
Notetaker eviction and same-user process termination are opt-in even in enforce
mode. Renderer feature flags are token-matched so generic Claude/Chrome flags
such as `chorusIn3p` and `WebAssembly` cannot be treated as app identity.

For a local Mac test, first create an enrollment authorization from the Hawk UI or
the authenticated admin route `POST /endpoint-agent/enrollment-authorizations`.
Then run this command, paste the returned JSON when prompted, and press Control-D:

```bash
cd apps/endpoint-agent
./scripts/install_macos_user.sh \
  --api-url "http://127.0.0.1:8000" \
  --tenant-id "<tenant-id>" \
  --ai-system-id "<registered-hawk-ai-system-id>" \
  --extension-id "eoinkdemimeonbdgifiojhncooompnda" \
  --security-profile development
```

Bank installation uses an HTTPS API and a Developer ID Application identity:

```bash
./scripts/install_macos_user.sh \
  --api-url "https://hawk-api.customer.example" \
  --tenant-id "<tenant-id>" \
  --ai-system-id "<registered-hawk-ai-system-id>" \
  --codesign-identity "Developer ID Application: ORGANIZATION (TEAMID)"
```

The installer creates:

- runtime: `~/Library/Application Support/Hawk/EndpointAgent/runtime`
- privacy-safe state: `~/Library/Application Support/Hawk/EndpointAgent/state`
- bounded launchd logs: `~/Library/Application Support/Hawk/EndpointAgent/logs`
- service: `~/Library/LaunchAgents/com.hawk.endpoint-agent.plist`

Enrollment also writes the public device-key pin as
`ipc_trusted_device_thumbprint` in `state/endpoint-agent.json`. It is safe to pass
that public value to local MCP/SDK clients. Do not replace it with an API token.

## Operate and test

For endpoint-brokered Codex and Claude Code hooks, including registration,
installation and the limits of desktop coverage, see
[endpoint native desktop hooks](../../docs/deployment/endpoint-native-desktop-hooks.md).

```bash
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
HAWK_CONTROL="$HAWK_ROOT/runtime/bin/hawk-endpoint-control"
HAWK_CONFIG="$HAWK_ROOT/state/endpoint-agent.json"

"$HAWK_CONTROL" --config "$HAWK_CONFIG" status
"$HAWK_CONTROL" --config "$HAWK_CONFIG" propose

# Monitor-mode would-block examples
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface browser --risk sensitive
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface mcp --risk high_impact
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface llm --risk sensitive
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface sdk --risk sensitive
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface developer_agent --risk high_impact
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface foundry --risk sensitive

# Enable enforcement and roll back
"$HAWK_CONTROL" --config "$HAWK_CONFIG" mode enforce
"$HAWK_CONTROL" --config "$HAWK_CONFIG" test-action --surface mcp --risk high_impact
"$HAWK_CONTROL" --config "$HAWK_CONFIG" mode monitor
```

Local mode mutation succeeds only for an explicitly configured development
profile whose config is owned by the current user and mode `0600`. Bank profiles
return `managed_authorization_required`; switch them through central policy/MDM.

The test-action command performs a live pre-action decision through the installed
Unix socket. It does not claim that an unconfigured third-party application is
routed through Hawk.

## Uninstall

```bash
./scripts/uninstall_macos_user.sh
```

The default uninstall preserves state and moves removed runtime/service material
to Trash. To move state to Trash as well:

```bash
./scripts/uninstall_macos_user.sh --purge-data
```

## Tests

```bash
PYTHONPATH=src ../api/.venv/bin/python -m pytest -q
```

The Windows deployment and TPM provider contracts are platform-neutral and are
included in the macOS test suite. Real hardware-key and installer validation must
still be repeated on the target Windows/Linux hardware before deployment.

## Managed Windows endpoint agent

The Windows build is a managed-machine deployment surface, not a replacement for
Hawk's browser, MCP, LLM, SDK, or provider-native controls. It adds a local,
binary-scoped minimum floor for actions that Windows can authorize reliably:

- minifilter pre-operation control for file open/read/write/create/rename/delete;
- `PsSetCreateProcessNotifyRoutineEx` control for governed child-process creation;
- WFP ALE authorization for governed outbound IPv4 and IPv6 connections;
- a small LocalSystem service that verifies short-lived Ed25519 policy envelopes
  and hands a bounded immutable policy snapshot to the kernel; and
- TPM/CNG device identity with no exportable private key or persistent bearer token.

An allow from Hawk's WFP callout returns `CONTINUE`, so Windows Firewall, IPsec,
EDR, and other WFP controls retain their own authority. Hawk clears the action-write
right only for a proven block. The runtime keeps short-lived DPoP access tokens
AES-GCM encrypted between requests, locks the ephemeral wrapping-key page with
`VirtualLock` when Windows permits it, and zeroizes the key on shutdown. Plaintext
exists only for the bounded duration of an authenticated request and is never
persisted.

Before Enforce can arm, the service seeds the kernel with the canonical image
identity of every live process and verifies that the seed completed. A known,
ungoverned binary is allowed; an identity lookup failure while Enforce is armed
fails closed instead of becoming a bypass. Every non-allow rule must be bound to
the canonical Windows path hash of an explicitly governed binary. Application-
specific semantic actions—prompt text, clipboard meaning,
MCP arguments, model/tool selection—still require the corresponding Hawk adapter.

The current kernel/user path fold is deliberately ASCII-only. A governed binary
whose canonical NT path contains non-ASCII characters is rejected by the policy
compiler and remains Uncovered until identical target-backed Unicode normalization
is accepted; Hawk does not publish a rule that may silently fail to match.
Kernel-originated minifilter requests are outside this user-binary floor so an
unknown system request cannot become a machine-wide denial. Memory-mapped and
other kernel-delegated file behavior remains Unverified until Windows acceptance.

### Build prerequisites

- Windows 11 x64 or ARM64 build host matching the target architecture;
- Visual Studio 2022, Windows SDK, and WDK in Developer PowerShell;
- Python 3.11+ and `python -m pip install -e .[windows-build]`;
- a Microsoft-allocated minifilter altitude (the placeholder is never accepted);
- an Authenticode code-signing certificate for Hawk user-mode binaries; and
- for production, the driver package returned by Microsoft Hardware Dev Center.

PyInstaller is pinned and must run on Windows because it is not a cross-compiler.
From `apps/endpoint-agent`:

```powershell
python -m pip install -e ".[windows-build]"

.\scripts\windows\build_managed_agent.ps1 `
  -Platform x64 `
  -MinifilterAltitude "<microsoft-allocated-altitude>" `
  -SigningCertificateThumbprint "<hawk-publisher-thumbprint>" `
  -ConfirmMicrosoftAllocatedAltitude `
  -BuildProfile Production `
  -MicrosoftSignedDriverDirectory "C:\Hawk\MicrosoftSignedDriver"
```

The output is a signed, cataloged package. Build creation refuses a placeholder
altitude, architecture mismatch, unpinned packager, invalid kernel signature, or
missing Microsoft-signed production driver.

### Required managed configuration

MDM must stage `%ProgramData%\Hawk\EndpointAgent\endpoint-agent.json`. It contains
public identifiers and verification keys only. Relevant fields are:

```json
{
  "api_base_url": "https://hawk-api.customer.example",
  "tenant_id": "<tenant-id>",
  "endpoint_id": "<device-id>",
  "default_ai_system_id": "<registered-ai-asset-id>",
  "os_type": "windows",
  "deployment_mode": "managed_machine",
  "security_profile": "bank",
  "key_provider": "windows_tpm_cng",
  "device_key_tag": "HawkEndpointAgentDeviceKey",
  "agent_mode": "monitor",
  "windows_native_enforcement_enabled": true,
  "windows_floor_policy_path": "C:\\ProgramData\\Hawk\\EndpointAgent\\endpoint-floor-policy.json",
  "windows_floor_replay_state_path": "C:\\ProgramData\\Hawk\\EndpointAgent\\state\\windows-floor-replay-state.json",
  "windows_floor_device_path": "\\\\.\\HawkEndpointFloor",
  "endpoint_floor_policy_public_keys": {
    "<key-id>": "<base64-raw-32-byte-ed25519-public-key>"
  }
}
```

The installer writes the fixed `identity_helper_path` and the exact
`identity_helper_sha256` from the verified staged package. Do not preconfigure a
different helper path. Bank mode rejects a missing digest, a helper environment
override, an Authenticode failure, or a digest substitution.

When a Windows path is omitted, the runtime keeps policy cache, baseline,
evidence queue, mode, endpoint-floor receipt, local socket, and install state
under `%ProgramData%\Hawk\EndpointAgent`; it does not use the signed-in user's
profile. The installer applies a non-inheriting LocalSystem-write / administrator-
read ACL to that tree.

The signing key corresponding to that Ed25519 public key belongs in Hawk's
KMS/HSM. Never put it in this config or in the package.

### Install and enroll

Run the installer elevated. It verifies the signed package catalog, publisher,
driver chain, manifest digests, state ACLs, driver load, service registration,
and config parse. It leaves enforcement disarmed and the service stopped:

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoProfile -NonInteractive -ExecutionPolicy AllSigned `
  -File "C:\Hawk\windows-managed-x64\staging\install_managed_agent.ps1" `
  -PackagePath "C:\Hawk\windows-managed-x64\staging" `
  -ConfigPath "C:\Hawk\endpoint-agent.json" `
  -ExpectedPublisherThumbprint "<hawk-publisher-thumbprint>"
```

The installer refuses to overwrite an existing managed installation, rejects a
package for the wrong OS architecture, and accepts only a production Hardware
Dev Center package by default. `-AllowDevelopmentPackage` exists solely for an
isolated test-signing VM and must never be used for a bank deployment. The
Windows service declares `HawkEndpointFloor` as an SCM dependency, so the native
floor is loaded again before the agent after a reboot.

Create a five-minute, single-use endpoint enrollment authorization in Hawk. The
enrollment script must run as LocalSystem through Intune/SCCM/MDM so the key has
the same machine identity as the service. Stream the authorization on standard
input from the MDM secret broker; never place it in an argument, environment
variable, package, config, or persistent file. For an interactive lab, open a
LocalSystem PowerShell with the customer's approved administration tool, then
paste the compact JSON into a secure prompt:

```powershell
$Enrollment = Read-Host "Paste the one-time Hawk enrollment JSON" -AsSecureString
$Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Enrollment)
try {
  [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer) | `
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
      -NoProfile -NonInteractive -ExecutionPolicy AllSigned `
      -File "$env:ProgramFiles\Hawk\EndpointAgent\enroll_managed_agent.ps1"
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
  $Enrollment = $null
}

& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoProfile -NonInteractive -ExecutionPolicy AllSigned `
  -File "$env:ProgramFiles\Hawk\EndpointAgent\verify_managed_agent.ps1"
```

Enrollment creates/proves the non-exportable machine-scoped TPM/CNG key, relocks
the state directory, enables service autostart, and starts it. Native enforcement
stays disarmed in monitor mode; switching centrally to Enforce arms only a current,
tenant/device-bound, correctly signed policy.

The signed Windows kernel envelope deliberately supports only conditions the
driver can prove locally: an exact canonical binary identity plus file
open/read/write/create/rename/delete, child-process creation, or outbound network
connect. Classification may be omitted or explicitly `unknown`. Policies using
user, business-purpose, application-asset, AI-asset, non-unknown classification,
process-exec, listen/send/receive, upload/download, or other unbound conditions
are rejected instead of being silently broadened. Semantic prompt, clipboard,
tool, and SaaS action controls remain with Hawk's browser, MCP, LLM, SDK, or
provider-native surfaces.

Every Windows floor policy must also carry a positive, signed
`policy_sequence`. The agent persists the accepted sequence and canonical policy
digest in the protected machine state tree. Lower sequences, signing-key or content
collisions at the same sequence, and wall-clock rollback are rejected. A service or
driver restart may republish the same committed policy only when its signed sequence and
canonical fingerprint exactly match the protected high-water record; the service
then reseeds live process identities and verifies the kernel status before arming.

The envelope may arrive as the authenticated endpoint policy's
`endpoint_floor_policy` field or as the MDM-managed
`endpoint-floor-policy.json`. Until the server-side KMS/HSM signer is connected,
deploy the pre-signed file by atomic MDM replacement. The endpoint stores only
the Ed25519 public verification key. Monitor mode disarms on any envelope error.
In Enforce, a previously armed snapshot is not silently disarmed by a missing,
invalid, expired, replayed, or wrong-scope replacement; the kernel blocks the
governed binaries after expiry and Hawk reports the policy as stale/incomplete.
A fresh boot with no valid snapshot remains unarmed and explicitly uncovered.

### Manual acceptance on the Windows test host

Use a dedicated test VM and a policy scoped only to the test application's exact
canonical binary identity. Restart the governed application after driver install
only when specifically validating the process-creation callback; the agent seeds
already-running process identities before Enforce can arm.

Generate that identity on the target Windows host; do not hash the displayed DOS
path yourself because the process callback uses the exact NT device namespace:

```powershell
& "$env:ProgramFiles\Hawk\EndpointAgent\hawk-endpoint-agent-runtime.exe" `
  --config "$env:ProgramData\Hawk\EndpointAgent\endpoint-agent.json" `
  --windows-binary-identity "C:\Program Files\Manus\Manus.exe"
```

Place only the returned `windows_path_sha256:...` value in the signed policy.

1. **Monitor:** start the governed app; open/write a test file, start a benign
   child process, and call an approved test HTTPS endpoint. All execute. Verification
   shows `policy_loaded=true`, `policy_current=true`, `enforcement_armed=false`.
2. **File block:** centrally switch to Enforce with a block rule for the governed
   binary and test-file primitive. The operation must return Access Denied and the
   target must remain unchanged.
3. **Process block:** start a harmless child from the governed app. Creation must
   fail and the child PID must never appear.
4. **Network block:** call the controlled destination from the governed app. The
   TCP/UDP connect must fail while an ungoverned app remains unaffected.
5. **Expiry/tamper:** expire or alter one byte of the signed envelope. In Monitor,
   the service must reject and disarm it. In Enforce, it must reject the replacement,
   retain the last armed snapshot, report stale/`POLICY_REJECTED`, and fail closed
   for governed binaries after that snapshot expires. Neither mode may claim current
   authorization coverage.
6. **Rollback:** return to Monitor and confirm `enforcement_armed=false`; then run
   the uninstaller and confirm service, filter, and published INF are removed.

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "$env:ProgramFiles\Hawk\EndpointAgent\verify_managed_agent.ps1" -RequireCurrentPolicy -RequireEnforce
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "$env:ProgramFiles\Hawk\EndpointAgent\uninstall_managed_agent.ps1"
```

The build remains **UNVERIFIED** until these real target-host allow/block and
non-execution tests, Driver Verifier, supported-Windows-version coverage, latency,
resource use, rollback, remote attestation, MDM, and formal EDR coexistence are
recorded. Source code and macOS-host unit tests never promote that claim.


### Managed macOS routing and release checks

Managed macOS uses a tenant-signed routing scope cross-bound to the canonical
policy and native envelope. The existing hardware device key renews routing
receipts on normal ticks (maximum 120 seconds; renewal within 30 seconds of
expiry). The host receives one checked binary-plist stdin snapshot through fixed
monitor/enforce commands, with tenant trust read independently from the protected
`/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json` file.
Runtime receipts remain at most 60 seconds and cannot outlive routing authority.

This transport is a scoped **direct transparent relay**, not an upstream gateway
or semantic inspection service. A require-gateway policy remains unavailable
until a gateway URL and transport/authentication contract are configured; there
is no silent direct fallback. The local content filter's signed exact destination
policy continues to govern allow/block decisions.

The read-only release verifier checks actual Apple staple/Gatekeeper assessment,
safely extracts the package without execution, and verifies its four signed
components against build evidence, installed bytes and signed target acceptance.
Unsigned build success does not establish `Monitoring` or `Protected`.
See [macOS deployment](native/macos/DEPLOYMENT.md) for signing order, MDM inputs,
trust-anchor protection, renewal behavior and external acceptance requirements.
