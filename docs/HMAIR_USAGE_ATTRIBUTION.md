# HMAIR Usage Attribution

**Status:** H6 operational contract for accepted H1/H5 usage projections.

## What usage means

Usage is recorded only when evidence shows an event attributable to a human,
agent, service, workload, automation, or unknown actor. Installed or configured
software alone is not active usage. Supported states are no usage observed,
historical, active, high frequency, service usage, and unknown usage.

## Evidence and confidence

Evidence can include managed-browser identity, endpoint user or process owner,
enterprise identity, SaaS audit logs, gateway identity, owner-mapped key hashes,
service principals, managed identities, repository ownership, workload identity,
session metadata, and traces. Each fact preserves source surface, time window,
event count, confidence, freshness, verification state, methodology, and blind
spots. Incomplete telemetry produces unknown rather than zero usage.

## Permissions, privacy, and source modes

Active and passive collectors declare their permissions independently. Usage
attribution stores pseudonymous actor references and categorical scope, not raw
prompts, credentials, messages, source files, or database records. Named-user
resolution remains governed by existing RBAC and privacy policy. Unsupported
identity mappings remain unknown and cross-tenant attribution is prohibited.

## Operational limitations

Shared accounts, shared endpoints, service-token reuse, identity rotation,
offline activity, personal accounts, and unconnected providers are material
blind spots. Counts reflect the selected evidence window, not productivity,
performance, intent, or total employee activity. Active and passive observations
must agree before a stronger attribution is promoted.
