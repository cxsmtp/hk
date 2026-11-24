from __future__ import annotations

import pytest


def test_effect_dag_preserves_uncertainty_and_requires_independent_recovery() -> None:
    from app.services.action_integrity.complex_actions import next_persistent_effect_state
    assert next_persistent_effect_state(current_state="CREATED", requested_state="UNKNOWN", evidence_quality="UNKNOWN") == "UNKNOWN"
    with pytest.raises(ValueError, match="independent"):
        next_persistent_effect_state(current_state="UNKNOWN", requested_state="VERIFIED_RECOVERED", evidence_quality="PROVIDER_REPORTED", remediation_verified=True)
    assert next_persistent_effect_state(current_state="UNKNOWN", requested_state="VERIFIED_RECOVERED", evidence_quality="INDEPENDENTLY_VERIFIED", remediation_verified=True) == "VERIFIED_RECOVERED"
    with pytest.raises(ValueError, match="illegal"):
        next_persistent_effect_state(current_state="VERIFIED_RECOVERED", requested_state="ACTIVE", evidence_quality="INDEPENDENTLY_VERIFIED")


def test_effect_transition_is_signed_and_requires_correct_predecessor_shape() -> None:
    from datetime import datetime, timezone
    from app.services.action_integrity.complex_actions import issue_persistent_effect_transition
    from app.services.action_integrity.signing import LocalSigningKeyProvider, verify_signed_object
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="persistent_effect_signing", tenant_id="tenant-effect", key_id="effect", secret=b"e" * 32)
    transition = issue_persistent_effect_transition(provider, tenant_id="tenant-effect", effect_id="effect-1", sequence=1, current_state="CREATED", requested_state="ACTIVE", prior_state_version=0, prior_transition_id=None, prior_transition_hash=None, evidence_quality="INDEPENDENTLY_VERIFIED", observed_at=datetime(2026, 8, 25, tzinfo=timezone.utc), idempotency_key="effect:1", evidence_refs=["evidence:a"])
    assert transition["new_state_version"] == 1 and transition["signature"]
    assert verify_signed_object(provider, purpose="persistent_effect_signing", domain="hawk:persistent-effect-transition:v1", tenant_id="tenant-effect", value=transition, current_authority=True)
    with pytest.raises(ValueError, match="predecessor"):
        issue_persistent_effect_transition(provider, tenant_id="tenant-effect", effect_id="effect-1", sequence=2, current_state="ACTIVE", requested_state="MODIFIED", prior_state_version=1, prior_transition_id=None, prior_transition_hash=None, evidence_quality="INDEPENDENTLY_VERIFIED", observed_at=datetime(2026, 8, 25, tzinfo=timezone.utc), idempotency_key="effect:2")
