# HMAIR Active Scan Safety

**Status:** H1 Task 11 normative safety boundary, documented 2026-08-02.
This document records the safe operating contract for the H1 discovery
substrate. It does not accept a concrete collector, enable active scanning, or
prove that the scan API or user experience is complete.

## 1. H1 safety boundary

H1 supplies orchestration and observation persistence only.
No active collector is enabled by H1.
Dry-run validates scope, collectors, permissions, exclusions, and rate limits
without collecting target data.
Cancellation is cooperative and retains accepted evidence.
No exploitation, guessing, unauthorized authentication, destructive calls,
jailbreaks, intrusive probing, source upload, raw-record extraction, or
configuration change is permitted.

These statements are hard boundaries. A configured target, registered
collector declaration, healthy status, successful validation, or queued scan
does not show that Hawk contacted a source, collected evidence, discovered an
asset, or gained control over an AI path.

## 2. Dry-run is validation, not collection

Dry-run and data collection are different operations:

| Operation | Permitted result | Prohibited conclusion |
|---|---|---|
| Dry-run | Validate the tenant-bound request, target scope, collector declarations, required permissions, exclusions, safety profile, and rate limits. | It cannot emit discovery observations or claim that an asset exists, was used, is reachable, or is controlled. |
| Data collection | A later, explicitly enabled native collector may execute only its declared, authorized, bounded methods and emit sanitized observation inputs. | Registration, configuration, or dry-run success cannot substitute for collected evidence. |

A dry-run must not invoke inventory, configuration, usage, identity-hint,
relationship-hint, or observation-emission collection methods. A bounded,
non-mutating connectivity preflight may occur only when the applicable tenant,
RBAC, permission, permitted-method, and source-contact gates expressly allow
it; such a preflight is still validation and must not be represented as target
data or discovery evidence.

H1 does not enable a native active collector. Consequently, this safety
contract does not claim that H1 can perform active collection. Active source
access remains default-off and requires both the applicable platform flag and
explicit tenant authorization in a later accepted collector slice.

## 3. Active and passive discovery

An operation is **active** when it initiates a source query or enumeration to
gather current target state, even when that request is read-only. An operation
is **passive** only when it consumes telemetry, events, or snapshots already
delivered to Hawk without initiating a source request.

Neither label grants authority. Every source interaction remains bounded by
tenant ownership, role-based access, declared permissions, permitted methods,
scope, exclusions, safety profile, active-scan setting, source rate limits, and
cooperative cancellation. Unsupported source depth is reported explicitly; it
must not be converted to an empty successful result.

## 4. Cooperative cancellation and evidence retention

Cancellation takes effect at a cooperative boundary between collector steps
and scope items. It is not a destructive rollback or a claim that an in-flight
source request was forcibly terminated. After cancellation is requested:

- no new collector step starts after the next cancellation check;
- the assignment and scan retain their auditable cancelled state;
- observations already accepted by the idempotent ingestion boundary remain
  immutable and available as evidence; and
- work that did not produce accepted evidence remains unknown and cannot be
  reported as discovered, absent, or covered.

Retaining accepted evidence preserves provenance and scan history. It does not
upgrade a partial or cancelled scan to complete coverage.

## 5. Evidence, privacy, and fail-closed reporting

Every accepted observation is a bounded claim, not a final AI Asset or a proof
of use, reachability, authorization, containment, or coverage. Before
persistence, observation content must pass tenant and scope validation, schema
bounds, secret and personal-data sanitization, sensitivity and retention
classification, and evidence hashing.

H1 must not collect secrets, credentials, raw prompts, source uploads, raw
database records, or unrestricted source payloads merely to establish
discovery. Credential references remain opaque. Repository collection is
limited to paths, dependency names, hashes, and approved safe snippets;
database collection is limited to metadata and auditable telemetry by default.

If Hawk cannot verify a conclusion from accepted evidence, the result is
**Unknown**, **Unsupported**, **Permission denied**, **Stale**, or another exact
non-success state supported by the contract. It is never silently promoted to
discovered, absent, authorized, protected, or covered.

## 6. Audit and later enablement

Any future active collector must have a native declaration that states its
permissions, active and passive capabilities, sensitive-data access, data
residency, health, and limitations. It must pass source-specific tests and an
acceptance checkpoint before enablement. The H1 compatibility bridge alone
cannot satisfy execution permission or privacy gates.

The operational safety experience—customer dry-run controls, exclusions,
safety profiles, cancellation controls, and complete audit presentation—
remains later HMAIR work. This document defines its safety boundary; it does
not report that experience as implemented.

## 7. H4 passive-source safety

H4 profiles have no active capability. Their collection operations are
read-only metadata acquisition behind the existing active-scan orchestration
gate; that gate authorizes a bounded run, not intrusive probing. The catalog
does not permit source mutation, arbitrary code execution, credential guessing,
raw-content acquisition, vulnerability probing, or fallback to a broader
source when a named provider is unavailable.

An unconnected, unauthorized, stale, partial, or unsupported source terminates
with its exact safe state. Adapter registration and an empty successful method
cannot create a completion or coverage claim. Live coverage additionally needs
the source-owned denominator and per-unit completion evidence described in
`docs/HMAIR_H4_COLLECTOR_COVERAGE.md`.

## H6 operator interpretation

Permissions, evidence, privacy, confidence, unsupported states, active and
passive behavior, and every known blind spot remain visible in scan diagnostics.
Dry run performs admission checks without invoking collection. `read_only` and
`metadata_only` are the only H6 UI safety profiles; neither permits mutation,
credential discovery, raw prompt collection, or intrusive probing.
