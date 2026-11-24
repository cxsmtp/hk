# AI Exposure Category Catalog Governance

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


**Catalog ID:** `hawk-ai-exposure-categories`  
**Current catalog version:** `1.1.0`  
**Canonical file:** `apps/api/app/services/hmair/exposure/catalog/exposure_categories.v1.json`

## Governance objective

The category catalog is the reviewed allowlist that connects exact discovered
capabilities to customer-facing exposure categories. It is data, not executable
policy. It cannot add a database schema, calculate risk, run code, issue a
control decision or broaden an asset association.

## Validated schema

The loader rejects unknown fields and requires:

- a canonical catalog identifier;
- semantic catalog and category versions;
- unique canonical category identifiers;
- a bounded label and description;
- at least one qualifying capability for every category except
  `unknown_exposure`;
- disjoint required and optional dimension lists; and
- recommendation capabilities drawn only from the reviewed allowlist.

Definitions and selectors are normalized and sorted before a SHA-256 catalog
digest is calculated. Duplicate category IDs, unsupported recommendations,
invalid semantic versions, malformed JSON and unbounded values fail closed.

Every qualifying selector must also exist in the reviewed source-binding map.
That map uses the canonical lower-case capability vocabulary emitted by
Discovery capabilities, runtime events, exact AI Actions and bounded shadow-AI
classifications. A catalog alias with no reachable source authority is rejected
at load time rather than appearing as a category that can never qualify.

## Versioning

Catalog and category versions use semantic versioning:

- **Patch:** wording or non-semantic metadata only; no qualification, required
  dimension or recommendation behavior changes.
- **Minor:** additive category or capability mapping whose existing category
  conclusions remain unchanged.
- **Major:** removal, reassignment, required-dimension change or any change that
  can alter an existing category conclusion.

Any semantic catalog change also requires a reasoning-rules compatibility
review. Production must retain the previous reviewed catalog artifact so a
software rollback restores the matching catalog and rules together.

## Required review and evidence

Every catalog change requires:

1. a named security/product reviewer;
2. validation of capability names against existing Hawk Discovery authorities;
3. validation of recommendation capabilities and their existing product routes;
4. cross-tenant and name-only association regression tests;
5. the full mandatory exposure simulation; and
6. a new reviewed canonical simulation artifact and digest.

The simulation approval is invalidated when qualifying capabilities, required
dimensions, category semantics, recommendation allowlists, rule behavior or the
canonical digest changes. A reviewer must not carry forward a prior Sol verdict
without rerunning the complete pack.

## Current categories

| Category | Qualification summary |
| --- | --- |
| Coding | Code execution or filesystem read/write |
| Research | Browser, web-search or external retrieval |
| Customer Data | Customer, CRM or PII access |
| Financial | Financial data, payment or trade capability |
| Cloud | Cloud API, administration or resource mutation |
| Identity | Credential, delegation or identity administration |
| Database | Database read/write or query execution |
| Secrets | Credential, secret or token access |
| MCP | MCP client, server or tool invocation |
| Model | Model configuration, hosting or inference |
| Runtime | Agent, runtime or local-model execution |
| External AI | External AI or provider API access |
| Shadow AI | Unmanaged or unknown AI use |
| Developer | Repository, code execution or developer tooling |
| Workflow | Workflow automation or external side effects |
| Persistent Side Effect | Filesystem write, process execution or external side effect |
| Unknown | No approved category can currently be resolved |

The canonical JSON remains the authoritative exact capability and dimension
list. This table is explanatory and must not be parsed as a second catalog.

## Recommendation allowlist

Only these capabilities may appear in category recommendations:

- runtime governance;
- browser governance;
- MCP restriction;
- filesystem restriction;
- sandbox;
- approval;
- owner assignment;
- Control Coverage;
- identity review; and
- personal-account removal.

Each capability maps to an existing Hawk route and prerequisites. Adding a new
capability requires code review of the allowlist and route; catalog data alone
cannot invent a product action.

## Rollback behavior

Rollback replaces the catalog and compatible rule implementation with their
previous reviewed release artifact. It does not rewrite or delete source
evidence because exposure is computed only. A rollback changes future
projections and reports the restored catalog/rule versions and input digest.
Historical source evidence remains unchanged.
