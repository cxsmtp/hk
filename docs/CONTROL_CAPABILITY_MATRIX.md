# Control Capability Matrix


The matrix is a versioned backend contract persisted in `control_capability_profiles`. It is not a marketing lookup table.

Each profile records provider, product, control method, adapter and tested versions, verification status and source, dimension-level capability claims, security properties, required permissions, health requirements, degradation modes, privacy impact, failure modes, fallbacks, blind spots, and documentation provenance.

## Capability levels

`inline_bound`, `inline`, `external`, `observe`, `unavailable`, and `unknown` are ordered security claims. A level is usable in enforcement only when its claim and the profile are `verified`.

## Verification states

`verified`, `experimental`, `unverified`, `broken`, and `removed` are explicit. `experimental` requires future explicit administrative enablement; this build does not silently admit it. `unverified`, `broken`, and `removed` are ineligible.

## Dimensions

Discovery, identity, prompt/response/tool/MCP/command/file/network/approval controls, parameter/target/destination/delegation binding, post-execution visibility and verification, persistent side effects, containment, bypass detection, and configuration integrity are independent claims.

## Assurance

- A0 Unknown
- A1 Discovered
- A2 Observed
- A3 Inline
- A4 Bound
- A5 Verified

Assurance is calculated from verified capabilities and security properties. It is not supplied by a provider or client.

## Truth rule

A green protected state requires an active profile, verified claims, supported provider and adapter versions, a healthy integration, current safe validation, authenticated callback identity, intact configuration, and fresh policy. Missing evidence resolves to Unknown or Not Covered.

The current provider/product rows and intentionally unverified claims are documented in [NATIVE_CONTROL_PROVIDER_MATRIX.md](NATIVE_CONTROL_PROVIDER_MATRIX.md).
