# Native Control Adapter Security

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Invariants

1. Provider events are untrusted before Hawk transport authentication and tenant/integration binding.
2. Provider payload tenant, role, risk, approval, and policy fields have no authority.
3. Adapters cannot implement authorization, approvals, evidence, replay, selection, RBAC, tenant resolution, or coverage.
4. Raw payloads are bounded, parsed, normalized, redacted, and discarded unless existing retention policy explicitly retains a safe derivative.
5. Duplicate provider events do not create duplicate AI Actions or evidence.
6. BLOCK and approval responses cannot be translated into continuation.
7. REFERENCE, EXPERIMENTAL, UNVERIFIED, BROKEN, and REMOVED states are not production enforceable by default.
8. Local helper messages are declarative. No shell, command execution, plugin loading, dynamic import, arbitrary file/process control, or download-and-execute operation exists.
9. Software update is a separate signed channel and is never carried in policy/helper control messages.
10. Installation owns only its Hawk fragment, fingerprints it, preserves customer configuration, and removes only that fragment on uninstall.

## Callback ownership

Hawk owns mTLS/workload authentication, request signatures, tenant/integration resolution, nonce replay defense, body/depth limits, deadlines, rate limiting, and audit. Provider adapters receive an authenticated `AdapterPipelineContext`; they cannot choose a tenant or open listener ports.

## Ordering and TOCTOU

Manifests explicitly state hook ordering. If an untrusted mutator can change parameters/target after Hawk authorization, bound assurance is invalid and the selector must reject or reduce the point. A provider-reported success is `PROVIDER_REPORTED`, not external verification.

## Plugin policy

Production adapters are Hawk-shipped, reviewed, version-controlled components. There is no customer-uploaded executable adapter or runtime marketplace.
