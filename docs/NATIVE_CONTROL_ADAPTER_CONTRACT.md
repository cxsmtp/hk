# Native Control Adapter Contract

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Required base contract

`NativeControlAdapter` requires only:

- static `AdapterDescriptor`
- static `CapabilityManifest`
- `normalize_event()`
- `format_decision_response()`
- structured `limitations()`

Optional behavior is declared through composable protocols: detection, installation, managed configuration, synchronous blocking, post-execution capture, approval pause/resume, tool/MCP/command/file/network awareness, bounded containment, local policy, provider-signed events, health, and version awareness. Unsupported operations are absent, not successful no-ops.

## Descriptor

The descriptor binds adapter ID, provider/product family, adapter version, deployment families, enforcement methods, event schema, minimum Hawk version, maturity, and description. REFERENCE maturity is test-only.

## Manifest

`CapabilityManifest` is static Hawk-shipped security input. Provider callbacks cannot supply or modify it. It includes version range, exact verified versions, verification state/evidence, capability claims, security properties, event semantics, permissions, structured blind spots, failure/degradation/install modes, execution-evidence quality, and non-security selection cost.

Conformance rejects:

- malformed version ranges or verification state
- duplicate/mismatched descriptor identity
- `INLINE_BOUND` parameter claims without canonical parameters, stable hash, pre-execution timing, and correlation
- target binding without canonical target/hash/correlation
- blocking without a synchronous mechanism and bounded timeout budget
- post-execution verification without a capture behavior and evidence-quality semantics
- unstructured blind spots

## Decisions and errors

Hawk decisions are ALLOW, WARN, REQUIRE_APPROVAL, REQUIRE_SECOND_APPROVAL, and BLOCK. Translation cannot weaken BLOCK or approval into continuation. Unsupported semantics produce `ENFORCEMENT_SEMANTIC_UNAVAILABLE`.

Adapter errors are normalized codes. Arbitrary provider exception text never becomes policy input or customer authority.

## Secrets

Configuration accepts opaque `kms://`, `hsm://`, `pkcs11://`, `secret://`, or `vault://` references only. Raw provider keys, OAuth tokens, private keys, hook signing keys, and workload tokens do not belong in adapter configuration.
