# Hawk macOS Endpoint Enforcement Floor

Managed rollout is monitor-first. MDM supplies the signed policy at
`/Library/Application Support/Hawk/EndpointAgent/endpoint-floor-policy.bin`
and protected preferences at
`/Library/Managed Preferences/ai.hawk.endpoint.host.plist`. Installation alone
does not activate a System Extension. Exact signed path and destination maps
are used; they do not claim recursive folder or prefix coverage. Endpoint
Security keeps Claude descendants in a bounded native lineage table, while
network child/grandchild attribution remains `Needs attention` until target
acceptance proves the OS-provided responsible-application identity.

The package embeds all three exact `.systemextension` bundles under
`Contents/Library/SystemExtensions`. A source build cannot promote runtime
status: without a current hardware-signed target receipt the display state is
`Needs attention` / `UNVERIFIED`. Rollback moves to monitor, removes MDM
configuration, deactivates extensions, verifies inactivity, and then removes
the host.

The software staging path is `scripts/compile_managed_macos_policy.py`. It
renders signing bytes for an exact binding manifest, verifies that manifest
under the same tenant Ed25519 policy key as the canonical v2 endpoint policy,
renders native wire-v2 bytes, verifies an externally supplied P-256 signature,
and emits a managed plist only from that verified envelope. Neither script nor
endpoint holds a production policy private key. The staged policy and plist
must be delivered by managed administration; this workflow never installs them.
The binding manifest signs the source-policy digest, tenant/device, UTC bounds,
version/epoch, monitor/enforce mode, delivery sequence, exact code identities,
and exact classification references. Unsupported source semantics fail
projection rather than silently broadening a native rule.

`scripts/assemble_macos_target_acceptance.py` verifies an external detached
Ed25519 target-test signature and strict v2 build/notarization evidence before
staging a short-lived acceptance envelope. The running endpoint reads that
protected envelope, rechecks the installed four-component digest, Team ID,
bundle IDs, OS build, signed policy, and individual allow/deny outcomes.
Monitoring requires matching current observation evidence; Protected also
requires enforce-mode denial, non-execution, and non-transfer results. The
acceptance expires within ten minutes and does not replace live health checks.
Until such an envelope exists and matches this Mac, network flow coverage and
Claude descendant attribution remain unverified.

This directory is source-ready packaging for the Hawk host, Endpoint Security
System Extension, content-filter System Extension, and managed-routing System
Extension. Every primitive remains **UNVERIFIED** until a signed target-host
acceptance receipt proves the corresponding OS allow, deny, non-execution,
health, rollback, and performance behavior.

## Apple-controlled prerequisites

Production packaging requires all of the following. They are not bypassable
repository settings:

- Apple Developer Team membership and a Developer ID Application certificate;
- Apple approval for the Endpoint Security entitlement;
- Apple approval for each required Network Extension entitlement;
- a provisioning profile for the host and each System Extension, with the
  explicit entitlement files in this directory;
- hardened-runtime signing with the designated Team ID and bundle identifiers;
- Apple notarization of the release package and successful stapling;
- user approval for local development, or MDM approval for enterprise rollout;
- MDM PPPC/Full Disk Access configuration for the Endpoint Security extension;
- MDM System Extension policy allowing the exact Team ID and bundle IDs;
- MDM content-filter and transparent-proxy configuration for the exact provider
  bundle identifiers;
- formal EDR, VPN, firewall, DLP, and OS-version coexistence acceptance.

The Xcode project reads the team, signing identity, and provisioning profile
names from `HAWK_APPLE_TEAM_ID`, `HAWK_CODE_SIGN_IDENTITY`,
`HAWK_HOST_PROVISIONING_PROFILE`,
`HAWK_ENDPOINT_SECURITY_PROVISIONING_PROFILE`,
`HAWK_CONTENT_FILTER_PROVISIONING_PROFILE`, and
`HAWK_ROUTING_PROVISIONING_PROFILE`. No signing identity or profile is hidden
in source control.

## Policy and health boundary

Authorization callbacks use the bounded local C evaluator only. Policy delivery
is accepted only after the containing signed extension authenticates its peer,
pins the peer signer, verifies the detached policy signature, verifies
configuration integrity, and supplies a strictly increasing delivery sequence.
The bridge deep-copies rules and permits into fixed in-extension storage. It
rejects oversized material, policy rollback, delivery replay, stale scope, and
malformed actions. It has no cloud, filesystem, process-spawn, dynamic-module,
or arbitrary-command path.

Native component health contains policy version/epoch, integrity flags,
delivery counters, bounded digests, lineage occupancy/overflow, and capability
state only. Lineage overflow marks file/process health unverified until the
next policy epoch clears the table. The existing
Hawk endpoint identity signs the bounded runtime receipt before publication.
Raw policy, secrets, prompts, file contents, cookies, and access tokens are not
health fields.

## Rollout

Use `DISCOVER → VALIDATE → MONITOR → SHADOW ENFORCE → ENFORCE`. Installation
does not activate enforcement. MDM must approve components, the local policy
must be current and signed, and real-device validation must pass before Enforce.
An unhealthy mandatory floor changes coverage immediately and follows the
primitive-specific degradation policy; it never leaves a stale green state.

## Upgrade, rollback, and uninstall

- Upgrade only to a same-bundle, correctly signed, non-decreasing version.
- Canary the package and preserve the last signed package and policy bundle.
- A rollback requires an enterprise-authorized, separately signed recovery
  policy and an explicitly approved older software release; policy epoch
  rollback is rejected by the running bridge.
- Uninstall first moves the deployment out of Enforce, records the change,
  removes MDM network/filter configuration, submits System Extension
  deactivation, verifies the extensions are inactive, then removes the host.
- Break-glass is authenticated, scoped, audited, time-limited, and expires
  automatically. There is no unauthenticated local bypass.

Notarization, stapling, MDM activation, entitlement grant, and real OS
acceptance are remaining deployment evidence. Source compilation alone does
not promote any Control Capability Matrix dimension.


## Tenant routing authority and renewal

The routing transport in this release is `direct_transparent_relay`: selected
applications and destination suffixes are forwarded directly using the existing
TCP/UDP relay. It is not an upstream enterprise gateway and performs no semantic
inspection. A mandatory-gateway or semantic-inspection policy is unsupported and
must remain `Needs attention`; it must never silently select direct relay. A
future gateway requires a configured managed URL, its transport and authentication
contract, TLS trust and availability policy. No URL or gateway credentials are
invented by this release.

Signing order is fixed:

1. Compile the real canonical endpoint policy and obtain its existing tenant
   Ed25519 signature. Obtain the same tenant key's native-bindings signature.
2. Use `compile_managed_macos_policy.py render`, then obtain the existing native
   P-256 authority's detached signature and run `assemble`.
3. Run `routing-signing-bytes` with those source/binding/native envelopes, public
   native key, agent configuration and `--destination-suffixes` JSON list. The
   output uses domain `hawk.macos-routing-scope.v1` followed by NUL. Obtain the
   existing tenant Ed25519 signature over these exact bytes. The strict envelope
   is `{schema, version, key_id, algorithm, payload, signature}`, with schema
   `hawk.macos-routing-scope-envelope`, version 1, algorithm Ed25519, and base64
   canonical payload/signature. The key ID must match source and bindings.
4. `managed-config` requires the signed routing envelope, original source and
   native-binding envelopes, broker public key, existing root-signed broker-key
   authorization and signature, routing trust-root public key, native envelope,
   public native key and Team ID. It stages the binary plist only at an explicit
   non-installation path. It never signs and never accepts private keys.

The plist carries `HawkSourcePolicyEnvelopeJSON`, `HawkNativeBindingEnvelopeJSON`,
`HawkRoutingScopeEnvelopeJSON`, `HawkRoutingReceiptPublicKeyX963`,
`HawkRoutingBrokerKeyAuthorization`,
`HawkRoutingBrokerKeyAuthorizationSignatureDER`, and
`HawkRoutingTrustRootPublicKeyX963`, alongside native-policy metadata. It contains
no tenant verification key or empty routing-provider configuration. Raw suffixes
are authorized explicitly by the tenant signature; application IDs must equal
the signing IDs used by the signed network rules. Wildcards, IP literals,
noncanonical lists, stale scopes and semantic-inspection requests are rejected.

MDM separately provisions the root-owned, non-group/world-writable file
`/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json`. The package
must not contain that tenant-specific file. The LaunchAgent's `HAWK_AGENT_CONFIG`
uses this exact path. In bank native mode, tenant/device/deployment/security
identity environment overrides are forbidden. The host reads this fixed file
through one protected descriptor (maximum 262144 bytes) to obtain the matching
`endpoint_floor_policy_public_keys` entry. It never accepts a tenant public key
from stdin, the managed plist, or provider preferences. MDM can atomically rotate
the existing bounded multi-key map; changed-during-read or invalid anchors fail.

Each normal agent tick reconciles current policy and routing. The existing
Secure Enclave device-key helper signs a routing receipt lasting at most 120
seconds and never beyond policy, routing scope or broker-key authorization.
The broker trust root must equal the signed routing extension's embedded root.
Unchanged configuration is checked through read-only status while more than 30
seconds remain; renewal or a changed configuration triggers one apply. Python
caches only the applied configuration digest and receipt expiry. Runtime posture
receipts remain hardware-signed, at most 60 seconds, and cannot outlive routing.

Monitor-first deployment uses `apply-managed-monitor-policy`; enforce uses
`apply-managed-enforce-policy`. Both consume one bounded binary-plist stdin
request containing schema/version, expected native-envelope digest, managed
configuration bytes and the freshly signed provider configuration. The host
checks command mode, digest, tenant/native chains, broker authorization and
receipt before any delivery. The same parsed configuration is used for Endpoint
Security and both Network Extension managers; apply never rereads managed
policy/plist files. Renewal does not replay an already-current native sequence.
Status requires enabled managers plus a current verified saved routing receipt;
this remains `active_unverified` until fresh signed target acceptance exists.
Missing keys, scope, hardware signer, helper, native host or successful renewal
keeps posture at `Needs attention`. Raw app IDs and suffixes are not health output.

## Read-only packaged release verification

`verify_managed_macos.sh` delegates actual package assessment to `macos_release`.
It requires strict v2 evidence, the exact current stapled-package digest,
Developer ID Installer/Team ID verification, successful `xcrun stapler validate`
and Gatekeeper install assessment. It validates paths before extraction, rejects
scripts and ambiguous component structure, and uses an isolated temporary tree
and fixed absolute extraction tool with traversal protections. It never installs
or executes a package. The extracted host and exact three extensions must match
build hashes/versions and actual Developer ID Application signatures, Team ID,
hardened runtime, entitlements and unexpired provisioning profiles. The component
set must equal both the installed verified set and its signed target acceptance.
Pre-staple package hashes and Apple submission IDs are audit fields only.

An unsigned build is software evidence only. Release acceptance still requires
Apple signing identities/profiles, MDM approvals, the production tenant/native
signatures and broker authorization, enrolled hardware identity, a notarized and
stapled package, and fresh signed acceptance for the exact device, OS build,
policy and installed four-component set. None of these can be replaced by an
unsigned JSON assertion, an enabled preference, or this build's success.
