# AI Exposure Reasoning Methodology


**Methodology:** `ai-exposure-reasoning/1.2`  
**Reasoning rules:** `1.2.0`  
**Category catalog:** `1.1.0`

## Purpose and boundary

AI Exposure Reasoning is a tenant-scoped, read-only projection over Hawk's
existing Discovery, attribution, ERG, Control Coverage, deployment and evidence
authorities. It answers which capabilities and reachable resources an AI asset
can currently affect, why Hawk believes that conclusion, and which governance
path can improve the evidence or control.

Exposure is **not risk**. The evaluator does not read, copy or transform an
existing risk score. It does not create a replacement asset, graph, event,
inventory, score, table or persisted exposure fact. Every response is computed
from current source evidence and carries its source-input digest, methodology
version, catalog version, rule version, calculation status and limitations.

## Extent semantics

| Extent | Meaning | Minimum rule condition |
| --- | --- | --- |
| `none` | Current evidence proves that the qualified capability is not reachable. | A current qualifying capability and current, verified non-reachability, with no verified positive reach. |
| `limited` | Current verified constraints bound the exposure path. | A qualified capability with complete required evidence and a verified permission or reach constraint. |
| `material` | Capability, usable authority and reach are currently supported. | All required dimensions are current and verified, without a limiting or broadening condition. |
| `broad` | Broad reach, consequential authority and scale are currently supported. | Verified broad reach and authority with high usage on one exact path, or two independently verified broad paths. |
| `unknown` | Hawk cannot prove one exact extent. | Required evidence is missing, stale, expired, unverified, contradicted or unavailable. |

`unknown` is never converted to zero, `none`, green status or an exposure
percentage. A `proven_lower_bound` may be returned when current evidence proves
at least a limited path while withholding a more specific extent.

## Category qualification

The versioned category catalog qualifies a category only when at least one
current capability factor exactly matches that category's approved capability
allowlist. Display names, provider names, risk scores and temporal proximity do
not qualify a category. If no approved category matches, Hawk evaluates the
explicit `unknown_exposure` category.

Each category declares:

- exact qualifying capabilities;
- required dimensions;
- optional dimensions; and
- approved recommendation capabilities.

Required dimensions are evaluated independently. Current `1.2.0` dimensions
include capability, data, runtime, provider, model, identity, permission,
reachability, usage, governance, Control Coverage and exact AI Action evidence.

## Source and association rules

Every source read is scoped by both tenant and exact asset identifier. Exact
foreign keys, ERG relationship nodes/edges and source references are accepted;
display-name-only associations are rejected. Decision Receipts can affect only
the exact AI Action to which they are bound. A blocked action does not erase an
asset's broader capability, permission or reachability.

Source records retain authority, type, stable source identifier, dimension,
normalized state, evidence references, related source references, confidence,
verification state, freshness, observation/validation times, methodology,
collector group and limitations. Reads are bounded per authority; truncation is
reported and never silently treated as complete evidence. A truncated source
projection preserves only a proven lower bound; every exact extent becomes
`unknown`. Oversized persisted reference collections are deterministically
bounded and trigger the same partial/unknown behavior.

ERG relationships are authority only when both their node class and
relationship type are on the reviewed dimension allowlist. Exposure selects
the current as-of edge in an append-only predecessor chain; superseded edges,
contradictions, historical matches, potential matches and observation-only
relationships cannot silently create permission, identity, reach or data
authority. Control Coverage similarly selects the current as-of assertion per
path and dimension across methodology versions.

Reasoning is path-native. A category is evaluated separately for every exact
`ControlCoveragePath` referenced by its qualifying capability evidence. A
permission from one path cannot satisfy a reachability gap on another path.
Display names never create a path association. Shared evidence is not attached
to multiple paths unless it has one unique exact binding. Decision Receipts are
joined by their exact AI Action identifier, never merely by a shared evidence
bundle. Multiple paths are combined only
after each path has an independent result; an uncertain path withholds the
combined exact extent. A single path reaches `broad` only with verified broad
reach, broad authority and high usage. Two independently verified broad paths
also establish scale; duplicate facts on one path do not.

## Deterministic rules and monotonicity

The rule engine uses named predicates and ordered deterministic branches. It
does not use hidden weights or machine-learning inference.

1. Fresh verified contradictions in required dimensions force `unknown`.
2. Current capability plus exclusively verified non-reachability yields `none`.
3. Missing or stale required evidence yields `unknown`.
4. Verified denied or constrained permissions, or constrained reach, yield
   `limited`.
5. Complete usable authority and reach yield `material`.
6. Verified broad reach plus broad authority plus high usage on one exact path,
   or two independently verified broad paths, yield `broad`.
7. Verified identity or permission removal constrains the result; missing
   identity evidence remains `unknown` and is not treated as removal.
8. Any required contributor below `verified` withholds the exact extent as
   `unknown`, even when a lower bound can be stated.

Adding broader verified capability, authority, reach or scale can only preserve
or increase an exact extent. A reduction requires current evidence of an actual
constraint or removal; missing evidence does not count as reduction. Governance
or Control Coverage improvement changes the control truth but does not pretend
that the underlying capability disappeared.

## Confidence and evidence quality

When every required contributing factor supplies confidence, category
confidence is the conservative minimum of those values. If any required
confidence is unavailable, confidence is `null` and the limitation
`required_confidence_unavailable` is returned.

Collector diversity is the number of distinct contributing collector groups.
No second evidence-quality formula is invented: `evidence_quality` remains
`null` until an authoritative upstream evidence-quality method exists.

## Contradictions and freshness

Fresh verified positive and negative reach, or a contradicted required factor,
are represented explicitly in `contradictions`. Hawk returns `unknown` rather
than choosing the more convenient source. Stale and expired required evidence
does not support an exact extent. Missing evidence is not negative evidence.

## Control Coverage mapping

Exposure reuses existing Control Coverage paths and assertions. It keeps four
questions separate:

- **Discover:** is the path currently visible?
- **Authorize:** can Hawk decide before execution?
- **Prove:** does current verifiable evidence exist after execution?
- **Contain:** does a current deployment surface provide verified containment?

Monitor-only is never authorization. Deployment presence alone is never
containment. Stale, expired, conflicting or unverified assertions return
`unknown`. A verified external containment dependency returns `not_covered`
with the dependency named; it does not become native Hawk containment. Any
nested path/assertion-reference truncation propagates to the category and
top-level projection as partial/truncated.

## Timeline and graph derivation

The graph and timeline are ephemeral projections. Graph nodes and edges carry
exact source/evidence references and are capped at 200 nodes and 400 edges.
Graph truncation is explicit, including internal evidence/source-reference
truncation rather than only node/edge count overflow.

Timeline events require authoritative adjacent source states. Current source
authorities do not all retain immutable before/after versions, so the timeline
endpoint returns no events together with
`historical_exposure_state_unavailable`. This is not presented as proof that no
changes occurred. The deterministic timeline builder remains bounded to 200
events and supports the approved change types for the point at which adjacent
state evidence becomes available.

## Calculation status

- `complete`: all queried authorities returned and the projection completed.
- `partial`: at least one authority failed or truncation/required evidence
  prevents a complete projection.
- `unavailable`: the source projection could not be computed, for example after
  a bounded source timeout. The API returns no exposure conclusions and does not
  manufacture zero exposure.

## Recommendations

Recommendations are deterministic qualitative routes to existing Hawk
capabilities. The allowlist is defined in the category catalog and maps only to
existing Deploy, Protect, AI IAM and Surface Coverage pages. No percentage or
numeric expected effect is claimed without evidence. A recommendation never
claims that executing it removes a capability. Recommendation identity binds
the category version, reasoning-rule version, exact control path and complete
bounded grounding references. If exact path grounding cannot fit the contract,
the recommendation is withheld.

## Known limitations

- Customer-estate completeness depends on current customer source coverage.
- The projection does not independently prove byte-level data transfer.
- Exact action evidence does not generalize to other actions.
- Containment remains unknown or externally dependent unless current deployment
  evidence proves it.
- Historical exposure extent is unavailable when source history cannot establish
  an adjacent before/after state.
- No aggregate exposure score exists by design.
