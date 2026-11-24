# Control Coverage API and methodology


Control Coverage answers how much of the AI activity Hawk has observed can be discovered, attributed, authorized before execution, and proved after execution. It is an operational control metric derived from tenant telemetry and Hawk evidence. It must not be used to estimate unobserved estate or as a substitute for risk severity.

## Version and measured population

- Methodology: `control-coverage/1.0`
- Path-key version: `1.0`
- Default observation window: 30 days; accepted range: 1–90 days
- Evidence-current lifetime: 24 hours from the source observation
- Snapshot freshness: a materialized snapshot older than 30 minutes is returned as `stale`
- Deployment health: point-in-time state evaluated at calculation time, not a 30-day average

The scoring unit is one unique, tenant-scoped path:

```text
asset → identity → runtime → deployment surface → destination/tool
```

The deterministic path key is SHA-256 over the normalized seven-component tuple: asset reference, identity type, identity reference, runtime reference, deployment-surface reference, destination type, and destination reference. Explicit `unknown_*` placeholders participate in the key. Asset and identity drilldowns are filtered projections of the same paths; they are never added to the headline a second time.

Only paths observed by Hawk inside the selected window enter the measured population. Unobserved activity is not silently added or counted as covered. Every response therefore carries this limitation:

> Scores apply only to unique AI paths observed by Hawk in the selected window; unobserved estate remains outside the measured denominator.

## Formula and states

For a dimension, and for the unweighted headline across all path-dimension assertions:

```text
score = covered / (covered + not_covered + unknown) × 100
```

`unknown` remains in the denominator. `not_applicable` is excluded. When there is no applicable population, the score is JSON `null`; Hawk does not emit zero or infer protection. There are no customer-specific or hidden dimension weights.

State meanings:

| State | Meaning |
|---|---|
| `covered` | Current evidence proves the dimension for this path. |
| `not_covered` | Current evidence proves the path is unmanaged, monitor-only, missing proof, offline, or otherwise outside the asserted control. |
| `unknown` | Evidence is missing, stale, conflicting, or insufficient. |
| `not_applicable` | The dimension does not apply to this path and is excluded from the denominator. |

Conservative dimension rules:

| Dimension | Covered only when | Not covered when confirmed | Unknown when |
|---|---|---|---|
| Discovery | A current discovery observation identifies the path. | Current telemetry confirms an unmanaged path. | Discovery evidence is absent, stale, or conflicting. |
| Identity | A server-resolved user, agent, or service identity is bound to the path. | Activity is confirmed anonymous or unbound. | Attribution cannot be verified. |
| Authorization | A verified pre-execution Decision Receipt is bound to an `inline_*` control mode. | Observed execution is telemetry-only, detected-only, post-execution, monitor-only, or requires an external control. | Inline receipt or control-mode evidence is missing, stale, or conflicting. |
| Evidence | A verified Execution Receipt or evidence bundle is bound to the path. | Execution was observed without verifiable execution proof. | Execution/proof status cannot be verified. |
| Deployment | A mapped control-capable surface is currently healthy. | A mapped surface is offline, degraded, or monitor-only. | Surface mapping, capability, or health cannot be verified. |
| Runtime | Current evidence binds a known runtime to Hawk governance. | The runtime is confirmed unmanaged or passively monitored. | Runtime state cannot be verified. |
| Bypass | Bypass detection is operational for the path, including a detector that has observed a bypass. | A bypass is observed without an operational detector covering the path. | Detector status and bypass evidence are insufficient. |

Reason codes returned with assertions are:

- Discovery: `verified_discovery_observation`, `confirmed_unmanaged_path`, `insufficient_evidence`.
- Identity: `verified_identity_binding`, `missing_identity_binding`, `insufficient_evidence`.
- Authorization: `verified_inline_decision`, `monitor_only_surface`, `insufficient_evidence`.
- Evidence: `verified_execution_evidence`, `missing_execution_proof`, `insufficient_evidence`.
- Deployment: `deployment_surface_active`, `surface_offline`, `monitor_only_surface`, `surface_capability_unknown`.
- Runtime: `runtime_governance_verified`, `runtime_unmanaged`, `insufficient_evidence`.
- Bypass: `bypass_detector_operational`, `bypass_observed`, `insufficient_evidence`.
- Any dimension can return `conflicting_evidence` or `stale_evidence`, both as `unknown`.

Surface summary labels are intentionally separate: `protected`, `monitor_only`, `outside_control`, `offline`, and `unknown`. A detected or monitor-only event is never labeled as prevented or inline-authorized.

## Read-only API

All routes require authenticated tenant context and at least the `viewer` role. Tenant identity is resolved server-side. Cross-tenant identifiers return no data or 404. When `CONTROL_COVERAGE_API_ENABLED=false`, the entire route group returns 404.

| Method and path | Purpose |
|---|---|
| `GET /control-coverage?window_days=30` | Headline, seven dimensions, surface summary, blind spots, deployment improvements, watermarks, freshness, and diagnostics. |
| `GET /control-coverage/paths` | Paginated observed paths with their current assertions. |
| `GET /control-coverage/paths/{path_id}` | One tenant-scoped path and assertion evidence. |
| `GET /control-coverage/assets/{asset_ref}` | Paths projected for one asset. |
| `GET /control-coverage/identities/{identity_type}/{identity_ref}` | Paths projected for one `user`, `agent`, `service_identity`, or `unknown` identity. |
| `GET /control-coverage/methodology` | Version, dimensions, formula, window limits, and denominator semantics. |

`/paths` accepts `page` (default 1), `page_size` (default 50, maximum 200), `dimension`, `state`, `asset_ref`, `identity_ref`, `identity_type`, `runtime_ref`, `surface_ref`, `application`, `destination`, and `tool`. Results are newest-observation first. Asset and identity routes use the same pagination limits.

An empty or not-yet-materialized summary remains typed and explicit:

```json
{
  "methodology_version": "control-coverage/1.0",
  "window_days": 30,
  "freshness_status": "unknown",
  "headline": {
    "score": null,
    "counts": {
      "covered": 0,
      "not_covered": 0,
      "unknown": 0,
      "not_applicable": 0,
      "denominator": 0
    }
  },
  "diagnostics": [
    {
      "code": "snapshot_missing",
      "message": "No materialized Control Coverage snapshot exists for this window."
    }
  ]
}
```

Identifiers in examples and responses are references, not raw content. Evidence references are restricted to bounded identifiers such as `runtime_event:<id>`, `ai_action:<id>`, `decision_receipt:<id>`, `execution_receipt:<id>`, `evidence:<id>`, and `finding:<id>`.

## Freshness, blind spots, and improvements

Source assertions become `unknown` after 24 hours unless refreshed. Source-deleted paths are retained inside the requested observation window with lifecycle `source_missing`; their assertions become stale/`unknown`. Surface heartbeat health is `degraded` after two minutes and `offline` after 15 minutes. Snapshot computation is idempotent for identical tenant, window, watermarks, paths, and assertions.

A blind spot is emitted only when tenant evidence links a finding or uncovered assertion to an observed path. Missing catalog capability alone is not evidence of a blind spot. Deployment improvements are ranked only over current, addressable uncovered/unknown assertions and a closed capability profile. Improvement language is conditional; projected uplift is not reported as guaranteed coverage.

## Privacy boundary

The projection stores normalized references and bounded source/evidence identifiers. It excludes raw prompts, model responses, receipt signatures, authorization headers, credentials, query strings, URL fragments, and full resource values. Secret-shaped, URL-shaped, long, or otherwise unsafe identifiers are SHA-256 hashed before persistence. Destination URLs are reduced to a hostname when safe; target resources are hashed.

## Rollout and rollback

All new behavior defaults off:

```dotenv
CONTROL_COVERAGE_MATERIALIZATION_ENABLED=false
CONTROL_COVERAGE_SNAPSHOT_ENABLED=false
CONTROL_COVERAGE_API_ENABLED=false
CONTROL_COVERAGE_UI_ENABLED=false
NEXT_PUBLIC_CONTROL_COVERAGE_UI_ENABLED=false
CONTROL_COVERAGE_ROLLOUT={}
CONTROL_COVERAGE_DEFAULT_WINDOW_DAYS=30
CONTROL_COVERAGE_SNAPSHOT_INTERVAL_MINUTES=15
```

`CONTROL_COVERAGE_ROLLOUT` is a JSON object mapping exact tenant IDs to booleans, for example `{"tenant-a":true}`. Snapshot refresh requires both materialization and snapshot flags plus an enabled tenant. `CONTROL_COVERAGE_UI_ENABLED` records server-side rollout intent; the Next.js bundle enforces `NEXT_PUBLIC_CONTROL_COVERAGE_UI_ENABLED`. Keep both UI flags aligned. Enable API and UI exposure only after the additive migration is applied and the tenant has a current snapshot.

Rollback procedure:

1. Set both UI flags and the API flag to false, then rebuild/restart the web bundle; the existing Deployment page and enforcement paths continue to operate.
2. Set snapshot and materialization flags to false; the periodic job stops enqueueing tenant refreshes.
3. Keep stored projections for audit/recovery, or on an approved disposable/maintenance database downgrade migration `0045_control_coverage` to `0044_canonical_evidence_bundles`.

Control Coverage runs outside the authorization path and does not change existing allow, block, approval, receipt, evidence, or policy decisions.
