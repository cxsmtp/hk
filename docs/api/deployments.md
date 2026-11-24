# Deployment inventory, family coverage, blind spots, and health API


Hawk exposes four tenant-scoped, read-only deployment inventory routes when
`DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=true`:

- `GET /deployments/overview`
- `GET /deployments/families`
- `GET /deployments/instances`
- `GET /deployments/instances/{id}`

Two additive family-coverage reads are available only when both
`DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=true` and
`DEPLOYMENT_FAMILY_COVERAGE_ENABLED=true`:

- `GET /deployments/coverage`
- `GET /deployments/coverage/{family}`
- `GET /deployments/blind-spots`

One bounded operational-health read requires only
`DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=true`:

- `GET /deployments/health`

Both flags default to `false`. While the applicable flag is disabled, the
route returns the same nonrevealing `404 Not found` response. There is no
tenant query parameter: callers authenticate normally and supply their
selected tenant through the required `X-Tenant-ID` header. The caller must be
a member of that tenant with the `viewer`, `operator`, `auditor`, `admin`, or
`owner` role.

## Stored-state contract

These routes read the normalized `deployment_surfaces` inventory. Reads never
reconcile sources, calculate Control Coverage, derive a family from a technical
surface, or derive health from timestamps. In particular:

- persisted `unknown` family values remain `unknown`, even when a technical
  surface name resembles a known mapping;
- persisted `stale` health remains `stale`;
- an old `last_seen_at` alone does not become `stale` or `offline`;
- legacy invalid closed values normalize conservatively to `unknown`;
- `technical_surface_type` is the exact stored `surface_type` value.

Overview counts are inventory counts, not protection or coverage scores. Its
`family_counts` always has `browser`, `endpoint`, `runtime`, `saas_api`, and
`unknown`. Its `health_counts` always has `healthy`, `warning`, `degraded`,
`offline`, `stale`, and `unknown`.

## Families

`GET /deployments/families` returns a paginated object:

```json
{"items": [], "total": 5, "page": 1, "page_size": 50}
```

The closed order is Browser, Endpoint, Runtime, SaaS & APIs, and Unknown. Zero
count buckets are included. Each item contains `family`, `label`,
`instance_count`, `technical_surface_counts`, `deployment_mode_counts`,
`hosting_mode_counts`, fixed six-key `health_counts`, and `status_counts`.

`page` defaults to 1. `page_size` defaults to 50 and is limited to 1 through
200. An out-of-range page is successful with empty `items` and the unchanged
`total`.

## Instances

`GET /deployments/instances` uses the same pagination bounds and sorts
deterministically by `last_seen_at` descending, then `id` ascending. Filters
are conjunctive, case-sensitive SQL equality only. Hawk does not trim, fold
case, fuzz, or interpret wildcard characters.

Supported filters are:

| Filter | Contract |
|---|---|
| `deployment_family` | closed family value |
| `technical_surface_type` | exact stored `surface_type`, 1-64 characters |
| `deployment_mode` | exact stored value, 1-64 characters |
| `hosting_mode` | `saas`, `hybrid`, `private_cloud`, `on_premises`, or `unknown` |
| `environment` | exact stored value, 1-64 characters |
| `provider` | exact stored value, 1-128 characters |
| `region` | exact stored value, 1-64 characters |
| `status` | exact stored value, 1-32 characters |
| `feature_flag` | exact stored value, 1-128 characters |
| `health_status` | `healthy`, `warning`, `degraded`, `offline`, `stale`, or `unknown` |

List items and `GET /deployments/instances/{id}` use the same projection:
`id`, `tenant_id`, `name`, `deployment_family`, `technical_surface_type`,
`deployment_mode`, `hosting_mode`, `environment`, `provider`, `region`,
`status`, `feature_flag`, `first_seen_at`, `last_seen_at`,
`last_health_check_at`, `policy_bundle_version`, `collector_version`,
`control_capability`, `evidence_capability`, `containment_capability`,
`bypass_detection_capability`, `health_status`, and `health_reason`.

Missing and foreign-tenant instance IDs return the same `404 Not found`
response. Source identifiers, source metadata, capability source material, and
heartbeat internals are intentionally excluded.

## Family coverage

The coverage reads implement the bounded
`deployment-family-coverage/1.0` methodology. They project the same current
path-native population used by `control-coverage/1.0` into Browser, Endpoint,
Runtime, SaaS & APIs, and Unknown. The six independently calculated
dimensions are Discovery, Identity, Authorization, Evidence, Containment, and
Bypass Detection.

Each dimension exposes covered, not-covered, Unknown, excluded, and known
eligible counts; a nullable percentage; status; confidence; methodology;
bounded evidence references; and calculation time. Unknown remains in the
denominator. Excluded assertions do not. An overall family result is omitted
unless all six dimensions have sufficient data, and it is a count-based
microaggregate without hidden weights.

`GET /deployments/coverage` returns all five family buckets.
`GET /deployments/coverage/{family}` returns the same metadata plus exactly
one valid family bucket. The top-level response includes freshness,
calculation time, bounded input watermarks, a known-estate limitation,
confidence basis, and diagnostics.

The reads never materialize, reconcile, or mutate coverage. They require a
compatible `control-coverage/1.0` snapshot. Missing, conflicting,
future-dated, incoherent, or materially changed proof returns a typed
insufficient result rather than inferred protection. Stale known eligible
assertions remain in the measured population as Unknown. A versioned
surface-projection digest binds the path-to-surface relationship and the
family, containment, health, source-identity, and bypass-profile inputs used
by this projection.

## Blind spots

`GET /deployments/blind-spots` emits only evidence-backed results from this
closed allowlist:

- `UNPROTECTED_LLM_ROUTE`
- `UNPROTECTED_MCP_ROUTE`
- `DEPLOYMENT_SURFACE_OFFLINE`
- `DEPLOYMENT_POLICY_STALE`
- `DEPLOYMENT_IDENTITY_UNRESOLVED`
- `EVIDENCE_SOURCE_MISSING`
- `UNMANAGED_AI_ACCOUNT`
- `UNKNOWN_AI_RUNTIME`
- `UNKNOWN_MCP_SERVER`
- `GATEWAY_BYPASS_SUSPECTED`
- `DISCOVERY_COVERAGE_GAP`
- `AUTHORIZATION_COVERAGE_GAP`
- `CONTAINMENT_COVERAGE_GAP`

Unsupported, unevidenced, stale, conflicting, or ambiguously linked facts are
not inferred. Twelve types currently have canonical projection paths.
`DEPLOYMENT_POLICY_STALE` remains in the closed schema but is intentionally
not emitted until a real producer supplies current, verifiable policy-state
evidence. Bypass findings preserve the accepted distinction: an operational
detector can remain Covered while its observed bypass creates a blind spot.

## Health

`GET /deployments/health` returns bounded, paginated per-surface operational
state and fixed family count rollups. Values are nullable and limited to the
approved health allowlist. Missing or invalid facts remain null or Unknown.
The result is operational state, not protection or coverage, and introduces
no score or weight.

## AI Action linkage

D5 adds no new action endpoint. Verified deployment instance, technical
surface, family, collector, authorization path, control mode, and evidence
capability at decision time are projected through the existing action path.
Caller telemetry cannot upgrade inline authority. Historical unverified
linkage remains Unknown; current configuration is not projected backward, and
D5 adds no migration or backfill.

## Explicit exclusions

D5 adds only the two bounded reads and existing-path linkage projection
described above. It adds no family-detail endpoint, mutation, test/mode/posture
API, setup flow, card, drilldown, UI, full operational-health administration,
production-rollout, or live-reachability claim.
