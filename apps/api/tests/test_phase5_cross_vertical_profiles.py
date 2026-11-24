from __future__ import annotations

import pytest


def _values_for(operator: str) -> tuple[object, object, object]:
    if operator == "IN": return "allowed", ["allowed"], "blocked"
    if operator == "NOT_IN": return "allowed", ["blocked"], "blocked"
    if operator == "SUBSET_OF": return ["a"], ["a", "b"], ["outside"]
    if operator == "RANGE": return 5, [0, 10], 11
    if operator == "RELATIONSHIP": return {"relation": "owner"}, "owner", {"relation": "other"}
    if operator == "AUTHORITY_AT_LEAST": return "admin", "write", "read"
    if operator == "EQ": return "same", "same", "different"
    if operator == "NOT_EQ": return "different", "same", "same"
    raise AssertionError(operator)


def test_all_six_profile_matrices_have_observed_violated_and_unresolved_boundaries() -> None:
    from app.services.action_integrity.domain_profiles import evaluate_domain_invariant, load_reviewed_profile_definitions

    profiles = load_reviewed_profile_definitions()
    assert set(profiles) == {
        "financial-services", "healthcare", "government", "real-estate-construction",
        "energy-critical-infrastructure", "multi-tenant-saas",
    }
    required_boundaries = {
        "financial-services": "account-beneficiary-value", "healthcare": "patient-care-purpose-disclosure",
        "government": "citizen-case-classification", "real-estate-construction": "property-project-threshold-reversibility",
        "energy-critical-infrastructure": "asset-safety-authority", "multi-tenant-saas": "same-tenant-admin-scope",
    }
    for profile in profiles.values():
        invariant = profile["domain_invariants"][0]
        assert required_boundaries[profile["profile_id"]] in invariant["invariant_id"]
        left, right, violation = _values_for(invariant["operator"])
        action_class = invariant["applies_to_action_classes"][0]
        shared = {"invariant": invariant, "profile_id": profile["profile_id"], "profile_version": profile["version"], "action_class": action_class}
        assert evaluate_domain_invariant(**shared, left=left, right=right).status == "SATISFIED"
        assert evaluate_domain_invariant(**shared, left=violation, right=right).status == "VIOLATED"
        unknown = evaluate_domain_invariant(**shared, left="UNRESOLVED", right=right)
        assert unknown.status == "UNKNOWN"
        assert unknown.resolution_state == "UNRESOLVED"


def test_range_out_of_range_is_violated_and_unresolved_sentinels_are_unknown() -> None:
    from app.services.action_integrity.domain_profiles import evaluate_domain_invariant

    invariant = {"invariant_id": "range", "operator": "RANGE", "applies_to_action_classes": ["determine"], "satisfied_reason_code": "ok", "violated_reason_code": "bad", "unknown_reason_code": "unknown"}
    common = {"invariant": invariant, "profile_id": "government", "profile_version": "1.0", "action_class": "determine", "right": [0, 10]}
    assert evaluate_domain_invariant(**common, left=11).status == "VIOLATED"
    for sentinel in (None, "UNKNOWN", "UNRESOLVED", {"state": "UNKNOWN"}):
        assert evaluate_domain_invariant(**common, left=sentinel).status == "UNKNOWN"
