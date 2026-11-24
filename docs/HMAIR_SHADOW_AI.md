# HMAIR Shadow AI

**Status:** H6 operational contract for the accepted H5 classification model.

## Classification

HMAIR uses eight explainable states: approved, approved but uncontrolled, known
unapproved, suspected shadow, confirmed shadow, personal account, owner unknown,
and unknown. Common behavior never becomes approved behavior. New software or a
new destination is not automatically malicious or shadow AI.

## Evidence and confidence

Classification considers approved catalog state, accountable owner, enterprise
tenant identity, license, Control Coverage, destination, installation, active
usage, admin visibility, repository ownership, and policy registration. Every
result carries evidence, confidence, freshness, limitations, and the conditions
that would change it. Two independent sources are required where the method
promotes suspected activity to confirmed shadow.

## Active and passive collection

Both active and passive observations use the same canonical classifier. Source
permissions, privacy boundaries, and confidence apply unchanged. Unsupported or
unconnected sources remain blind spots and cannot be treated as negative
evidence. A passive browser observation does not imply endpoint or runtime
coverage; an active inventory result does not prove usage.

## Privacy and operator use

The classifier does not store raw prompts, credentials, source files, database
records, personality inferences, or productivity scores. User detail remains
RBAC-protected. Operators use findings and existing approval/ownership workflows
to resolve unknown state; HMAIR does not silently block or approve an asset based
only on a shadow classification.
