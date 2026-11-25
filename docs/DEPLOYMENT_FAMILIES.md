# Deployment Families


This document defines Hawk's approved customer-facing deployment-family contract. It groups existing technical Deployment Surfaces into four understandable families without renaming those surfaces or claiming capabilities that Hawk cannot verify.

## Availability

The deployment-family experience is an additive program. At the 2026-07-27
D5 implementation snapshot:

- the four flag-gated, read-only D3 `/deployments/*` inventory APIs are implemented;
- the two separately flag-gated, read-only D4 family-coverage APIs are implemented with the six-dimension `deployment-family-coverage/1.0` methodology;
- the bounded D5 blind-spot and health reads and verified decision-time action
  linkage are implemented and accepted; family cards, drilldowns, full
  operational-health UI, setup, administration, and deployment-family UI
  remain unimplemented;
- existing technical Deployment Surfaces and the `/surface-coverage` experience remain authoritative;
- `control-coverage/1.0` remains the accepted implementation and technical proof methodology, but defaults off, is tenant-gated, and requires its migration, aligned feature enablement, and a current tenant snapshot;
- family inventory and coverage reads remain unavailable until their separate flags are explicitly enabled; family UI remains unavailable until its implementation, tenant rollout, and evidence prerequisites are complete.

`GET /deployments/blind-spots` requires the parent experience and coverage
flags; `GET /deployments/health` requires only the parent experience flag.
Both are viewer-or-higher, tenant-scoped, read-only, and nonrevealing when
unavailable. The blind-spot schema retains the closed 13-type allowlist, while
policy-stale remains intentionally un-emitted until a real evidence producer
exists.

The intended rollout flags default to false:

```dotenv
DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=false
DEPLOYMENT_FAMILY_COVERAGE_ENABLED=false
DEPLOYMENT_MONITOR_FIRST_ADMIN_ENABLED=false
NEXT_PUBLIC_DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=false
```

Do not interpret the contract below as proof that a deployment instance is active, healthy, or inline.

## Four separate deployment concepts

Hawk keeps these fields distinct:

| Concept | Purpose | Example |
|---|---|---|
| `deployment_family` | Customer-facing grouping | `runtime` |
| `technical_surface_type` | Exact integration or enforcement surface | `mcp_gateway` |
| `deployment_mode` | Existing control posture or surface mode | inline, monitor-only, connector, endpoint metadata, or managed extension |
| `hosting_mode` | Where the Hawk component runs | `hybrid` |

`deployment_family` never replaces `technical_surface_type`. `hosting_mode` never replaces or changes the meaning of the existing `deployment_mode`.

Approved hosting modes are:

- `saas`
- `hybrid`
- `private_cloud`
- `on_premises`
- `unknown`

Air-gapped deployment remains a roadmap item. It must not appear as a live hosting mode until private deployment and signed offline bundles work.

## Family taxonomy

Internal values and customer labels are closed:

| Internal value | Customer label | Purpose |
|---|---|---|
| `browser` | Browser | Show browser-resident observation and control surfaces. |
| `endpoint` | Endpoint | Show endpoint, developer-workstation, local proxy, and local runtime surfaces. |
| `runtime` | Runtime | Show model, agent, MCP, SDK, gateway, platform, and internal authorization surfaces. |
| `saas_api` | SaaS & APIs | Show enterprise SaaS, API, connector, SIEM, and webhook surfaces. |
| `unknown` | Unknown | Preserve an unmapped or unverifiable technical surface without assigning capability. |

Names and fuzzy matching cannot grant a family. Only the closed technical mapping below can do so.

## Exact technical-surface mapping

### Browser

The Browser family contains only:

- `browser_extension`
- `browser_agent`
- `managed_browser`
- `browser_automation_control`

### Endpoint

The Endpoint family contains only:

- `endpoint_agent`
- `endpoint_discovery`
- `local_agent_telemetry`
- `desktop_ai_control`
- `local_ai_proxy`
- `local_proxy`
- `ide_companion`
- `developer_endpoint`
- `local_mcp_runtime`
- `cli_agent_runtime`
- `mdm_discovery`

### Runtime

The Runtime family contains only:

- `llm_gateway`
- `mcp_gateway`
- `sdk`
- `sdk_app_embed`
- `runtime_mesh`
- `azure_foundry`
- `azure_apim`
- `kong`
- `envoy`
- `kubernetes`
- `aks`
- `container_apps`
- `custom_agent_runtime`
- `internal_api_authorization`

### SaaS & APIs

The SaaS & APIs family contains only:

- `microsoft_365`
- `copilot`
- `google_workspace`
- `slack`
- `salesforce`
- `service_now`
- `github`
- `gitlab`
- `saas_connector`
- `saas_ai_connector`
- `oauth_app_connector`
- `siem_connector`
- `webhook`
- `custom_connector`

Any other technical value maps to `unknown`. An Unknown family mapping grants no family, control, evidence, containment, or bypass-detection capability. It does not erase independently verified health on the underlying technical surface; that health remains available in the technical drilldown.

## Normalized deployment-instance view

The family experience will project each deployment instance with:

- `id`
- `tenant_id`
- `name`
- `deployment_family`
- `technical_surface_type`
- `deployment_mode`
- `hosting_mode`
- `environment`
- `provider`
- `region`
- `status`
- `feature_flag`
- `first_seen_at`
- `last_seen_at`
- `last_health_check_at`
- `policy_bundle_version`
- `collector_version`
- `control_capability`
- `evidence_capability`
- `containment_capability`
- `bypass_detection_capability`
- `health_status`
- `health_reason`

Historical or ambiguous source data remains nullable or Unknown. Backfill is allowed only from the exact mapping and authoritative source metadata.

### Capability vocabulary

Capability fields are derived from authoritative metadata and current evidence. They are not administrator-authored claims.

| Capability | Closed values |
|---|---|
| Control | `inline`, `warn_only`, `monitor_only`, `external_required`, `unknown` |
| Evidence | `complete`, `partial`, `metadata_only`, `none`, `unknown` |
| Containment | `direct`, `surface_limited`, `external`, `none`, `unknown` |
| Bypass detection | `supported`, `unsupported`, `unknown` |

A configured or registered integration does not by itself prove any of these capabilities.

### Health vocabulary

Family APIs use:

- `healthy`
- `warning`
- `degraded`
- `offline`
- `stale`
- `unknown`

Existing persisted health values remain readable. `stale` is derived only from explicit age or freshness evidence; it is not silently converted to `offline`. When freshness or health cannot be verified, the result is `unknown`.

The D5 health read exposes only nullable allowlisted health fields and count
rollups. These rollups do not prove protection, alter coverage, or introduce
weights.

## What a family card must show

The Deployment page will contain exactly four customer-facing cards: Browser, Endpoint, Runtime, and SaaS & APIs. Each card must show:

- a concise purpose;
- active instances;
- current health;
- Discovery, Authorization, and Evidence coverage;
- containment capability;
- evidence-backed blind spots;
- one primary setup, test, or investigation action.

Counts and status come from tenant-scoped data. Registration, inventory presence, or a configured feature flag cannot be displayed as protection.

A known or inventoried endpoint asset that lacks a current accepted observation can be Unknown or Not Covered according to its evidence. Truly unobserved estate remains outside the measured population and denominator.

### Exact drilldown

Each family card expands or routes within the existing Deployment experience. The drilldown preserves:

- every exact `technical_surface_type` and deployment instance;
- `hosting_mode` separately from `deployment_mode`;
- current health and policy state;
- actual capabilities and limitations;
- evidence-backed coverage and blind spots;
- setup, test, and monitor actions.

The existing technical cards become drilldown content. They are not renamed one-for-one into the families. Deployment and Runtime technical coverage remain available as diagnostics under the accepted technical coverage methodology.

## Coverage and protection language

Use the following rules everywhere:

- Inline means a verified pre-execution Hawk authorization path exists for the eligible action.
- Monitor-only, shadow, detected-only, connector registration, inventory, and telemetry do not mean inline.
- Evidence exists only when the required canonical action, policy, receipt or integrity material, and evidence reference verify.
- Containment exists only when current evidence proves a direct, surface-limited, or verified external action path.
- An operational bypass detector remains Covered when it observes a bypass; the detection creates a blind spot and makes the affected protection or authorization path Not Covered.
- Bypass Detection is Not Covered only when other evidence establishes a bypass while the applicable Hawk detector is absent or nonoperational.
- Missing, stale, conflicting, or insufficient evidence is Unknown.
- A zero eligible population is `insufficient_data`, not 0% and not 100%.

Family dimension counts reconcile as:

```text
total_known_eligible_count
= covered_count + not_covered_count + unknown_count
```

`excluded_count` remains outside `total_known_eligible_count`.

Per-dimension confidence is `high` only with sufficient current verified evidence, no Unknown assertion, and no stale or conflicting evidence; `medium` when evidence is sufficient and current but includes at least one Unknown assertion without partial, metadata-only, stale, or conflicting evidence; `low` when a sufficient denominator includes partial or metadata-only current evidence; and `unknown` for insufficient, stale, or conflicting evidence. Overall confidence is the most conservative of all six required dimensions; if any dimension is `unknown`, overall confidence is `unknown`.

See [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md) for the two versioned coverage methodologies and [DEPLOYMENT_QUICK_STARTS.md](DEPLOYMENT_QUICK_STARTS.md) for monitor-first onboarding.

## Rollout and rollback

Rollout order is:

1. Project family and hosting fields without UI.
2. Enable read-only family APIs for selected test tenants.
3. Enable family cards with the existing technical coverage drilldown.
4. Enable quick starts.
5. Enable monitor-first administrative actions only after RBAC, audit, and rollback are in place.

Rollback disables the family UI and APIs by feature flag while retaining additive data and existing technical reads. The introducing release must not contract existing Deployment Surface schemas, routes, or `control-coverage/1.0`.
