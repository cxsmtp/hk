from __future__ import annotations

import pytest


EXPECTED_PROFILE_IDS = {
    "financial-services",
    "healthcare",
    "government",
    "real-estate-construction",
    "energy-critical-infrastructure",
    "multi-tenant-saas",
}


def test_phase5_profile_catalog_is_complete_reviewed_and_declarative() -> None:
    from app.services.action_integrity.domain_profiles import load_reviewed_profile_definitions, runtime_p0_materiality_hash

    profiles = load_reviewed_profile_definitions()

    assert set(profiles) == EXPECTED_PROFILE_IDS
    for profile_id, profile in profiles.items():
        assert profile["profile_id"] == profile_id
        assert profile["schema_version"] == "1.0"
        assert profile["status"] == "reviewed"
        assert profile["version"]
        assert profile["evidence_refs"]
        assert profile["materiality_profile_id"] == "phase5-p0"
        assert profile["materiality_profile_version"] == "1.0"
        assert profile["materiality_profile_hash"] == runtime_p0_materiality_hash()
        assert profile["tenant_id"] == "profile-catalog"
        assert profile["algorithm"] == "ES256"
        assert profile["signing_key_id"]
        assert profile["signature"]
        assert "materiality" not in profile
        assert profile["domain_invariants"]
        assert all(invariant["operator"] in {"EQ", "NOT_EQ", "IN", "NOT_IN", "SUBSET_OF", "RANGE", "RELATIONSHIP", "AUTHORITY_AT_LEAST"} for invariant in profile["domain_invariants"])
        assert all({"version", "applies_to_action_classes", "required", "satisfied_reason_code", "violated_reason_code", "unknown_reason_code"} <= set(invariant) for invariant in profile["domain_invariants"])
        for resolver_group in ("target_resolvers", "destination_resolvers", "resource_resolvers", "value_resolvers"):
            assert profile[resolver_group]
            assert all(resolver["resolver_id"] and resolver["resolver_version"] for resolver in profile[resolver_group])
    matrices = {tuple(invariant["operator"] for invariant in profile["domain_invariants"]) for profile in profiles.values()}
    assert len(matrices) == len(profiles)


def test_phase5_profile_validation_is_fail_closed_and_forbids_permit_logic() -> None:
    from app.services.action_integrity.domain_profiles import ProfileValidationError, load_reviewed_profile_definitions, profile_content_hash, validate_profile_definition

    with pytest.raises(ProfileValidationError):
        validate_profile_definition({"profile_id": "incomplete"})

    with pytest.raises(ProfileValidationError, match="permit"):
        validate_profile_definition({
            "schema_version": "1.0",
            "profile_id": "unsafe",
            "name": "Unsafe",
            "industry": "test",
            "version": "1",
            "status": "reviewed",
            "subject_types": ["person"],
            "resource_types": ["record"],
            "counterparty_types": [],
            "domain_action_types": ["read"],
            "vocabulary_mapping": {},
            "action_mappings": {},
            "target_resolvers": [{"resolver_id": "target", "resolver_version": "1"}],
            "destination_resolvers": [{"resolver_id": "destination", "resolver_version": "1"}],
            "resource_resolvers": [{"resolver_id": "resource", "resolver_version": "1"}],
            "value_resolvers": [{"resolver_id": "value", "resolver_version": "1"}],
            "materiality": {"profile_id": "phase5-p0", "version": "1.0", "additional_profile_paths": []},
            "domain_invariants": [{"invariant_id": "purpose", "left_path": "business_purpose", "operator": "PRESENT", "right_literal": True}],
            "approval_renderers": [], "outcome_verifiers": [], "persistence_mappings": {}, "redaction_rules": {},
            "policy_template_refs": [], "owner_ref": "owner", "approver_ref": "approver",
            "issued_at": "2026-08-24T00:00:00Z", "effective_at": "2026-08-24T00:00:00Z", "expires_at": "2027-08-24T00:00:00Z",
            "review_evidence_refs": ["evidence://profile-review"], "execution_permit": {"allow": True},
        })
    reviewed = load_reviewed_profile_definitions()["financial-services"]
    assert profile_content_hash(reviewed) == profile_content_hash({**reviewed, "signature": "different-signature"})
    with pytest.raises(ProfileValidationError, match="unsupported fields"):
        validate_profile_definition({**reviewed, "authorization_decision": "allow"})


def test_reviewed_catalog_profiles_are_cryptographically_bound_and_tamper_fails() -> None:
    from app.services.action_integrity.domain_profiles import ProfileValidationError, load_reviewed_profile_definitions, validate_profile_definition

    reviewed = load_reviewed_profile_definitions()["financial-services"]
    validate_profile_definition(reviewed)
    with pytest.raises(ProfileValidationError, match="signature"):
        validate_profile_definition({**reviewed, "name": "Tampered Financial Services"})


def test_non_catalog_profile_requires_an_explicit_cryptographic_verifier() -> None:
    from app.services.action_integrity.domain_profiles import ProfileValidationError, load_reviewed_profile_definitions, validate_profile_definition

    profile = {
        **load_reviewed_profile_definitions()["financial-services"],
        "tenant_id": "tenant-a", "signature": "A" * 86,
    }
    with pytest.raises(ProfileValidationError, match="verifier"):
        validate_profile_definition(profile)
    assert validate_profile_definition(profile, signature_verifier=lambda candidate: candidate["signature"] == "A" * 86)["tenant_id"] == "tenant-a"

def test_domain_invariant_unknown_input_is_not_satisfied() -> None:
    from app.services.action_integrity.domain_profiles import evaluate_domain_invariant

    invariant = {
        "invariant_id": "authority", "operator": "AUTHORITY_AT_LEAST", "applies_to_action_classes": ["transfer"],
        "satisfied_reason_code": "authority_ok", "violated_reason_code": "authority_low", "unknown_reason_code": "authority_unknown",
    }
    result = evaluate_domain_invariant(invariant=invariant, profile_id="financial-services", profile_version="1.0.0", action_class="transfer", left=None, right="write", evidence_refs=["evidence://resolution"])
    assert result.status == "UNKNOWN"
    assert result.reason_code == "authority_unknown"
    assert result.profile_id == "financial-services"
    assert len(result.normalized_input_hash) == 64
    assert result.evidence_refs == ("evidence://resolution",)
