# Control Coverage


Control Coverage answers an operational question:

> How much of the AI estate Hawk has observed can Hawk discover, attribute, authorize before execution, prove after execution, contain, and monitor for bypass?

It is not another risk score and it is not an estimate of unobserved estate. Coverage must be backed by current tenant telemetry, authoritative metadata, and verifiable evidence. Hawk must not infer protection.

## Availability and methodology coexistence

Hawk uses two versioned views over the same current evidence:

| Methodology | Status at the 2026-07-27 implementation snapshot | Purpose |
|---|---|---|
| `control-coverage/1.0` | Accepted implementation and technical methodology; default-off and tenant-gated | Seven-dimension, path-native analysis and exact asset, identity, runtime, surface, destination, and tool drilldown. |
| `deployment-family-coverage/1.0` | Accepted bounded backend/read implementation; default-off; customer UI and rollout remain pending | Six-dimension executive projection grouped into Browser, Endpoint, Runtime, SaaS & APIs, and an explicit Unknown bucket. |

The family projection does not replace, relabel, or independently reinterpret `control-coverage/1.0`. It is derived from the same current path population, technical assertions, Deployment Surface capability and health evidence, receipts, findings, and evidence references.

Acceptance of `control-coverage/1.0` does not make it universally available. Its reads require the additive migration, aligned materialization, snapshot, API, and UI feature enablement, tenant rollout enablement, and a current tenant snapshot. Without those prerequisites, the feature remains disabled or reports the typed missing/stale state defined by its API contract.

The D4 coverage reads and D5 blind-spot read require both default-off
deployment-family flags. The bounded D5 health read requires only
`DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED`. All accepted reads are
viewer-or-higher, tenant-scoped, read-only, and nonrevealing when gated. D5
does not claim customer family cards, full operational-health UI, setup flows,
administrative mutations, production rollout, or live API reachability.

The existing legacy `/coverage` result is compatibility-only. Its four-surface observed-event average is never an input to either conservative coverage methodology.

## Technical path-native proof: `control-coverage/1.0`

The technical scoring unit is one unique tenant-scoped path:

```text
asset → identity → runtime → deployment surface → destination/tool
```

Asset and identity views are filtered projections of these same paths. They are never added to the headline a second time. Users can drill from an individual asset, human, agent, application, or service identity to the exact runtime, deployment surface, destination, tool, assertions, and evidence for that path.

The seven technical dimensions are:

1. Discovery
2. Identity
3. Authorization
4. Evidence
5. Deployment
6. Runtime
7. Bypass

Technical assertion states are:

- `covered`
- `not_covered`
- `unknown`
- `not_applicable`

The technical formula is:

```text
covered
/
(covered + not_covered + unknown)
```

`not_applicable` is excluded. Unknown remains in the denominator. No applicable population produces a nullable score, never inferred coverage.

The existing `/control-coverage/*` endpoints remain the exact technical and historical drilldown. Full API fields, freshness rules, filters, and privacy boundaries are documented in [api/control-coverage.md](api/control-coverage.md).

## Family executive projection: `deployment-family-coverage/1.0`

The family projection groups the same current path and evidence population by the closed mapping in [DEPLOYMENT_FAMILIES.md](DEPLOYMENT_FAMILIES.md). It has six executive dimensions:

1. Discovery
2. Identity
3. Authorization
4. Evidence
5. Containment
6. Bypass Detection

Deployment and Runtime do not disappear. They remain technical diagnostics in the `control-coverage/1.0` drilldown and provide evidence inputs to the family projection. Containment is the explicit sixth executive dimension.

### Per-dimension contract

Each family dimension exposes:

- `name`
- `status`
- `covered_count`
- `not_covered_count`
- `total_known_eligible_count`
- `unknown_count`
- `excluded_count`
- `percentage_nullable`
- `confidence`
- `methodology`
- `evidence_refs`
- `calculated_at`

Dimension status is:

- `sufficient_data`
- `insufficient_data`

The percentage is:

```text
covered_count
/
(covered_count + not_covered_count + unknown_count)
```

`not_applicable` contributes to `excluded_count`. Unknown stays in the denominator. A zero eligible denominator returns:

```text
percentage_nullable = null
status = insufficient_data
```

The counts must reconcile as:

```text
total_known_eligible_count
= covered_count + not_covered_count + unknown_count
```

`excluded_count` remains outside `total_known_eligible_count`.

Unknown is not zero, not silently excluded, and not Not Covered.

### Evidence rule for each dimension

| Dimension | Covered only when |
|---|---|
| Discovery | A current accepted discovery observation or equivalent current source evidence exists for the path or asset. |
| Identity | Observed activity is attributed to a resolved human, agent, application, service identity, or verified delegation authority. |
| Authorization | A verified pre-execution Decision Receipt proves the eligible action traversed a real inline Hawk authorization path. |
| Evidence | The required canonical action, policy snapshot, decision explanation, receipt or integrity material, and evidence reference exist and verify for the eligible action. |
| Containment | Current evidence proves the action class can be stopped directly, stopped within its actual surface, or acted on through a verified external integration. |
| Bypass Detection | Current telemetry proves the applicable bypass detector is operational for the known path, including when that detector observes a bypass. |

Registration, configured capability, inventory, or simulated reach alone is not proof. When an operational detector observes a bypass, Bypass Detection remains Covered; the bypass creates a blind spot and makes the affected protection or authorization path Not Covered. Bypass Detection is Not Covered only when other evidence establishes a bypass while the applicable Hawk detector is absent or nonoperational. Missing detector status or other insufficient evidence is Unknown.

## Containment translation

Family containment values are:

- `direct`
- `surface_limited`
- `external`
- `none`
- `unknown`

Existing verified capability translates conservatively:

| Existing value | Family containment |
|---|---|
| `end_to_end` | `direct` |
| `surface` | `surface_limited` |
| `none` | `none` |
| `unknown`, invalid, or missing | `unknown` |

`external` is allowed only when an integrated external action path and its evidence exist. Connector registration cannot grant external containment.

## Overall family score

All six dimensions are displayed independently. Hawk emits an overall family score only when all six required dimensions have `sufficient_data`.

The unweighted formula is:

```text
all covered applicable family path-dimension assertions
/
(all covered + all not covered + all unknown applicable family path-dimension assertions)
```

There are no hidden or customer-specific weights.

Every result discloses:

- covered, not-covered, unknown, and excluded counts;
- estate Unknown percentage;
- methodology version;
- calculation time and input watermarks;
- the known-estate limitation;
- the confidence basis.

The accepted read implementation also binds the exact scored
path-to-surface projection into the source snapshot through the versioned
`deployment-family-surface-projection/1.0` material digest. A later change to
the path binding, source identity, family, containment, health, or
bypass-profile input fails closed instead of being mixed with the earlier
snapshot.

Coverage applies only to the known estate and paths Hawk has observed. A known or inventoried endpoint asset that lacks a current accepted observation can be Unknown or Not Covered according to its evidence. Truly unobserved estate remains outside the measured population and denominator and must be stated as a limitation.

## Confidence

Confidence explains the evidence state; it is not a second score.

| Confidence | Required basis |
|---|---|
| `high` | The dimension has sufficient current verified evidence, no Unknown assertion, and no stale or conflicting evidence. |
| `medium` | The dimension has sufficient current verified evidence and at least one Unknown assertion, with no partial, metadata-only, stale, or conflicting evidence. |
| `low` | The dimension has a sufficient denominator, but at least one applicable assertion relies on partial or metadata-only current evidence. |
| `unknown` | The dimension has insufficient data, or any applicable evidence is stale or conflicting. |

Stale or conflicting evidence therefore makes that dimension's confidence `unknown`. Overall confidence is the most conservative confidence of the six required dimensions; if any dimension is `unknown`, overall confidence is `unknown`.

## Blind spots and deployment improvements

The accepted bounded D5 read emits a family blind spot only when current
canonical evidence supports its exact fact. Each blind spot includes:

- finding ID and type;
- observed fact and observing source;
- reason coverage is missing;
- confidence and freshness;
- affected family and exact technical surface;
- path and assertion IDs;
- control mode;
- evidence references;
- recommended deployment action;
- explicit conditional wording.

Supported types are emitted only when their evidence exists:

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

Recommendations describe what could improve current evidence-backed gaps. They never guarantee uplift.

The API schema retains the closed 13-type allowlist. Twelve types currently
have a canonical projection path. `DEPLOYMENT_POLICY_STALE` is intentionally
not emitted until a real producer supplies current, verifiable policy-staleness
evidence.

D5 health fields are nullable and allowlisted, and health count rollups are
operational summaries rather than coverage inputs. D5 changes no scoring
formula and introduces no weights.

## Family read APIs

The implemented, default-off read-only API contract is tenant-scoped and
requires authenticated viewer-or-higher access:

- `GET /deployments/overview`
- `GET /deployments/families`
- `GET /deployments/instances`
- `GET /deployments/instances/{id}`
- `GET /deployments/coverage`
- `GET /deployments/coverage/{family}`
- `GET /deployments/blind-spots`
- `GET /deployments/health`

The blind-spot read requires the parent experience and family-coverage flags;
the health read requires only the parent experience flag. Both retain the
viewer floor, tenant isolation, read-only behavior, and nonrevealing 404s.
Existing integration-management, surface-coverage, legacy coverage, and
`/control-coverage/*` routes remain compatible.

Administrative test, mode, and posture APIs belong to later slices. They require admin RBAC, audit, rollback, and monitor-first semantics before exposure.

## How to improve coverage safely

Use evidence-backed gaps, not the headline alone:

1. Open the affected family and exact technical-surface drilldown.
2. Inspect its observed paths, identities, health, policy state, and evidence references.
3. Confirm whether the gap is Not Covered, Unknown, stale, or outside the observed estate.
4. Follow the conditional deployment action attached to the finding.
5. Connect and test in monitor or shadow mode.
6. Recalculate only after current observations and evidence verify the changed state.

Adding a connector, changing a setting, or passing a simulation does not immediately create coverage.

## Privacy, history, and rollback

The family projection uses bounded references and tenant-safe evidence. It must not expose raw prompts, model responses, credentials, receipt signatures, or unrestricted resource values.

D5 projects the deployment instance, technical surface, family, collector,
authorization path, control mode, and decision-time evidence capability
through the existing action path only when those facts are verified.
Historical actions without verified linkage remain Unknown, current
configuration is not projected backward, and D5 adds no migration or backfill.

Disabling the family experience leaves `control-coverage/1.0`, existing enforcement paths, and stored additive data intact. Methodology versions remain immutable.
