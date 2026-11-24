# Phase 5 Vertical-Agnostic Audit

## Status

Pre-build baseline audit. WorkUnit A must update this file after compatibility
refactoring; WorkUnit J verifies the final result.

## Method

Search shared/core code for banking, customer-account, beneficiary,
transaction-amount, patient, citizen, project-specific, and provider-specific
semantics. Classify every result as reference profile, fixture, UI projection,
legacy compatibility, or improper core dependency. Do not blindly rename valid
domain examples.

## Baseline findings

| Area | Classification | Required action |
|---|---|---|
| `banking_*` models/services/routes/tests | Reference profile/adapter and fixtures | Preserve behind profile/adapter boundary |
| Banking transport target and route resolution | Reference adapter | Feed generic resolver and canonical interfaces |
| `SubjectExecutionContext.approved_account_ids` | Improper generic-core dependency | Replace core semantics with typed resource scopes; keep deprecated banking alias in adapter |
| Banking/mobile/customer provenance literals in subject context | Improper generic-core dependency | Move to generic authoritative-source/provenance fields and compatibility mapping |
| Sector lexicons in `policy_service.py` | Reference profile data | Keep out of canonical/core authorization fields |
| Banking examples in generic tests | Fixture | Retain only if paired with non-banking fixtures and no hardcoded production shortcut |
| Provider names in core fixtures | Fixture/projection | Ensure provider label never selects authority without exact adapter/runtime contract |

## Acceptance

- Shared core imports no banking adapter/model.
- Core subject/resource/authority/value/action types contain no required banking,
  healthcare, government, property, energy, or SaaS-specific field.
- Six profiles use one engine and the same canonical/receipt/permit interfaces.
- Deprecated legacy fields map only through explicit adapters and never infer
  unknown relationships.
- Source scan plus cross-vertical tests provide evidence for every remaining
  classified occurrence.

