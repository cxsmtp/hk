# Native Control Adapter Developer Guide


## Adding a provider

1. Implement the smallest `NativeControlAdapter` contract and only the optional protocols the provider genuinely supports.
2. Add a static `AdapterDescriptor`. Never use REFERENCE maturity for a real integration.
3. Add a static `CapabilityManifest` sourced from official provider/version evidence. Start EXPERIMENTAL or UNVERIFIED.
4. Normalize authenticated provider input into `NativeControlEvent`; never trust provider tenant, role, risk, approval, or policy fields.
5. Use `NativeControlAdapterPipeline`. Do not call a separate policy/risk/approval/evidence engine.
6. If installable, return an `InstallationPlan`, preserve customer configuration, own one explicit fragment, fingerprint before/after state, validate, roll back on failure, and uninstall only Hawk material.
7. Declare structured blind spots and exact hook ordering.
8. Implement safe allow/deny, replay, privacy, event, config, version, and execution-correlation probes appropriate to claimed capabilities.
9. Run `NativeControlAdapterConformanceSuite` and the existing selector/coverage/security suites.
10. Request VERIFIED status only after real provider binary/version acceptance, signed callback evidence, runtime validation, health, and security review.

## Adapter-owned code

Allowed: environment detection, provider capability declaration, install/config mechanics, event normalization, provider response formatting, provider version/health checks, execution-result extraction, and limitations.

Forbidden: independent authorization, risk scoring, approval authority, tenant/RBAC, replay, evidence/receipt semantics, selector ranking, coverage calculation, arbitrary listeners, remote shell, provider-supplied plugins, and raw secret storage.

## First production provider gate

Claude Code is the first verified provider adapter. Adapter `1.1.0` wraps the documented hook contract; installed version `2.1.183` passed signed real-binary tool/command/file allow/block, blocked non-execution, success/failure post correlation, lifecycle, permission-mode, background, ordering, timeout, tamper, uninstall and bypass acceptance plus the conformance suite. Do not copy its VERIFIED status to another binary or to an Experimental capability. Every other version is a version mismatch until Hawk ships a reviewed exact-version manifest and acceptance report. Ordinary Claude chat and direct API surfaces do not expose this hook lifecycle and must use their explicitly bound Hawk browser, MCP, endpoint, LLM Gateway, or SDK control path.
