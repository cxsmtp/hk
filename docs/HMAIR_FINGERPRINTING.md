# HMAIR Fingerprinting

**Status:** H6 operational contract for the accepted H3 fingerprint engine.

## Purpose and evidence

HMAIR combines versioned executable, package, dependency, configuration,
provider, model, protocol, runtime, network, capability, identity, and behavior
components. Each component carries a hash, evidence category, observed time,
freshness, confidence, and supersession state. A fingerprint is an identity
signal; it is not permission, approval, compromise, or proof of active usage.

## Active and passive sources

Passive sources may report signed endpoint inventory, managed-browser metadata,
gateway metadata, provider inventory, repository manifests, or existing audit
events. Active collection is limited to an explicitly authorized read-only or
metadata-only target. Permissions are declared per collector and target. HMAIR
does not fetch arbitrary source files, guess credentials, execute discovered
software, or probe unsupported endpoints.

## Privacy and unsupported conclusions

Fingerprint inputs exclude raw prompts, cookies, credentials, source files,
database records, embeddings, and tool arguments. Only bounded categorical
metadata and hashes persist. The private combination and weighting algorithms
are not returned through public APIs. Public results expose methodology version,
confidence band, evidence categories, conflicts, limitations, and blind spots.

Unsupported or missing components remain unknown. A new or changed fingerprint
is not labelled malicious. Cross-device or cross-tenant matches are never made
without same-tenant authoritative identifiers and evidence.

## Operations and blind spots

Drift is append-only and retains the prior and successor fingerprint. Operators
review conflicting or low-confidence candidates through the existing resolution
workflow. Blind spots include unconnected endpoints, unmanaged browsers,
encrypted traffic outside a connected control point, provider APIs without an
approved connection, and locally executed tools that emit no signed metadata.
