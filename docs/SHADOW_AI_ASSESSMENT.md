# Shadow AI assessment


Open **Discovery → Scans** and use **Shadow AI assessment**. Owner/admin access is required to preview or import telemetry.

1. Choose Microsoft Defender DeviceNetworkEvents CSV or normalized SWG CSV, a stable source name and a collection window. The end is exclusive. UI dates are local time; CSV timestamps require a timezone.
2. Select an export with at most 500 rows and 1 MiB. Preview validates and classifies without saving discovery records.
3. Review matched, duplicate, unclassified and out-of-window counts. Import persists new observations; use the evidence link to review an application instance.

Required Defender columns: `Timestamp,ReportId,DeviceId,RemoteUrl`.
Optional: `InitiatingProcessFileName,InitiatingProcessAccountUpn`.

Required normalized SWG columns: `timestamp,event_id,device_id,destination`.
Optional: `process_name,account_id`.

Example normalized SWG row:

```csv
timestamp,event_id,device_id,destination,process_name,account_id
2026-09-01T12:00:00Z,event-001,device-001,api.openai.com,python.exe,
```

Only catalog-matched AI destinations are imported in this slice. Unmatched destinations are counted as unclassified, not asserted to be safe. This is an export import, not a scheduled Defender/SWG connector or a full enterprise scan. A device identifier is required; IP-only exports must first obtain an authoritative device mapping rather than treating a shared NAT address as one device.

Raw export contents, URL credentials/paths/queries and command-line columns are not persisted. External device/account identifiers are tenant-scoped hashes, not verified Hawk identities. Customer-uploaded evidence is explicitly attributed as such. Source-instance names must be stable across repeat exports for deduplication. Changing a source instance starts a distinct evidence namespace.

Imports serialize per tenant on PostgreSQL and reject conflicting metadata for the same source event identity. They create signals and evidence nodes, not runtime invocations or usage records. Device/account instances keep separate approval state. No fleet percentage or enforcement claim is inferred from an export.

Endpoint source changes add ChatGPT Desktop, Claude Desktop, Ollama and LM Studio installation checks in fixed product locations. Presence is not use. Configured MCP servers report bounded transport/hostname and recognized executable names; arbitrary arguments, environment values and headers remain excluded. The API accepts older snapshots without these optional fields. Deploy the API before updated endpoint collectors.

The endpoint network collector now reports `complete`, `partial` or `unavailable` with a fixed error code in runtime posture. Completeness refers only to connections visible to that agent process. It does not assert all-device or all-network visibility. The local endpoint's existing Developer ID signing prerequisite remains separate.

Follow-up scope: scheduled connectors, authoritative fleet denominators, publisher-verified desktop inventory, SaaS OAuth permission graphs and native cloud inventory acceptance.
