# HMAIR Entity Resolution

**Status:** H6 operational contract for the accepted H1/H3 canonical resolver.

## Resolution contract

Collectors emit observations and never create final assets. The resolver uses
same-tenant evidence such as exact provider, workspace, deployment, device,
repository, workload, MCP, process, package, and destination identifiers. Its
decisions are create, attach, merge, reject, or manual review and retain matched
signals, conflicts, confidence, algorithm version, evidence, and time.

## Active and passive evidence

Active and passive observations enter the identical canonical path. Source
permissions and privacy limits travel with each observation. An active scan has
no greater resolution authority than its evidence supports; a passive audit
event can be stronger when it contains an authoritative source identifier.

## Safety and privacy

Resolution is tenant-scoped. It does not use raw prompts, credentials, source
files, database records, or employee-content similarity. Hashes and categorical
signals are bounded. Unsupported identifiers are ignored rather than guessed.
Low-confidence candidates stay separate and visible as unknown or ambiguous.

## Explainability and blind spots

Public projections show the decision, confidence band, evidence categories,
conflicting signals, methodology summary, freshness, and limitations without
revealing private weights. Merge and split history is append-only and preserves
prior evidence. Blind spots include identifier rotation, incomplete provider
metadata, shared machines, NAT/proxy ambiguity, unconnected runtime paths, and
source records whose permitted fields cannot distinguish two candidates.
