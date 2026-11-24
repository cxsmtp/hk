# HMAIR Privacy

**Status:** Normative H6 privacy and retention operating contract.

## Data minimization

HMAIR discovery collects bounded metadata required to identify AI assets,
capabilities, usage classes, identities, reachability, controls, and evidence.
Raw prompts, credentials, cookies, browser history, arbitrary source files,
database records, embeddings, messages, and tool arguments are excluded by
default. Sensitive identifiers are pseudonymized or hashed where the existing
identity authority does not require a named reference.

## Permissions and source behavior

Every active and passive collector declares permissions, sensitive-data access,
privacy exclusions, data residency, evidence mode, limitations, and blind spots.
Active scanning requires explicit customer authority, a registered target,
allowed methods, a safety profile, rate limits, and cancellation. Unsupported or
unavailable fields remain unknown; a lower-depth provider is not represented as
equivalent to a higher-depth source.

## Confidence, access, and tenancy

Confidence describes evidence quality, not user risk. Tenant isolation is
enforced in the service and data-access layers. Named-user access, evidence
detail, and scan mutations reuse existing RBAC and audit. Discovery never
produces employee productivity, performance, sentiment, personality, or intent
scores. Individual access remains auditable.

## Retention and compaction

Canonical observations, evidence claims, resolution history, assets,
fingerprints, capabilities, usage, attribution, reachability, findings, and
audit records stay under their existing immutable or governed retention
authorities. H6 compaction affects only old terminal scan warning, error, and
coverage summaries after an owner/admin previews a deterministic plan. It
preserves confidence, freshness, unsupported sources, unknown sources,
exclusions, denominator truth, counts, lifecycle timestamps, and an original
digest. It never deletes authoritative evidence.

## Blind spots and requests

Privacy restrictions can reduce discovery depth. Those blind spots are surfaced
as explicit unsupported, inaccessible, partial, stale, excluded, or unknown
states. Customer retention, residency, access, and deletion requests must follow
the authoritative record type's policy; scan-summary compaction is not a general
data-deletion mechanism.
