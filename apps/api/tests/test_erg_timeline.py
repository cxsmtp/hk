from app.services.hmair.erg.evidence_timeline import EvidenceTimeline


def test_all_required_drift_families_have_explicit_categories() -> None:
    timeline = EvidenceTimeline()
    assert {
        timeline.drift_category(event)
        for event in (
            "capability_added", "dependency_added", "marketplace_changed",
            "configuration_changed", "permission_changed", "identity_changed",
            "usage_changed", "model_changed", "provider_changed",
            "repository_changed", "runtime_changed",
        )
    } == {
        "capability_drift", "dependency_drift", "marketplace_drift",
        "configuration_drift", "permission_drift", "identity_drift",
        "usage_drift", "model_drift", "provider_drift",
        "repository_drift", "runtime_drift",
    }
