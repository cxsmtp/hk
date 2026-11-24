from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

EXPECTED_CODES = {
    "SUBJECT_BOUNDARY_VIOLATION", "RESOURCE_SCOPE_VIOLATION", "PURPOSE_MISMATCH", "AUTHORITY_EXCEEDED",
    "DELEGATION_AUTHORITY_EXPANDED", "TOOL_FINGERPRINT_CHANGED", "ACTION_PARAMETER_DRIFT", "ACTION_TARGET_DRIFT",
    "ACTION_DESTINATION_DRIFT", "ACTION_VALUE_DRIFT", "APPROVAL_INVALIDATED", "EXECUTION_PERMIT_MISMATCH",
    "EXECUTION_DRIFT_DETECTED", "EXECUTION_UNVERIFIED", "PERSISTENT_EFFECT_CREATED", "PERSISTENT_EFFECT_DRIFT",
    "CONTROL_PLAN_DOWNGRADED", "DOMAIN_INVARIANT_FAILED", "OUTCOME_MISMATCH", "UNKNOWN_ACTION_SEMANTICS",
}


def test_phase5_finding_catalog_has_exact_contract_codes_and_evidence_requirements() -> None:
    from app.services.native_control.findings import FINDING_PROFILES, PHASE5_FINDING_CATALOG

    assert set(PHASE5_FINDING_CATALOG) == EXPECTED_CODES
    assert EXPECTED_CODES <= set(FINDING_PROFILES)
    for code, definition in PHASE5_FINDING_CATALOG.items():
        assert definition["severity"] in {"medium", "high", "critical"}
        assert definition["required_evidence"]
        assert FINDING_PROFILES[code][0] == definition["severity"]


def test_phase5_finding_aliases_are_compatibility_only() -> None:
    from app.services.native_control.findings import FINDING_TYPE_ALIASES, canonical_finding_type

    assert canonical_finding_type("APPROVAL_BINDING_INVALIDATED") == "APPROVAL_INVALIDATED"
    assert "APPROVAL_INVALIDATED" not in FINDING_TYPE_ALIASES


def test_phase5_finding_storage_is_canonical_requires_evidence_and_dedupes_by_material_field(tmp_path) -> None:
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.native_control.findings import record_native_control_finding

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'phase5-findings.sqlite3'}")
    session_factory = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    try:
        with session_factory.begin() as db:
            tenant = Tenant(name="Finding tenant", slug="finding-tenant", is_active=True)
            other_tenant = Tenant(name="Other finding tenant", slug="other-finding-tenant", is_active=True)
            db.add_all([tenant, other_tenant])
            db.flush()
            kwargs = {
                "finding_type": "ACTION_PARAMETER_DRIFT", "integration_id": "ignored-for-phase5", "action_id": "action-1",
                "provider": "test", "policy_version": "policy-1", "evidence_node_ids": ["evidence-1"],
                "reason_codes": ["parameter_changed"], "material_field_or_effect": "action_semantics.safe_parameters",
                "evidence_kinds": ["authorized_actual_field_diff"], "authority_refs": ["receipt:1"],
                "profile_ref": "financial-services@1.0.0", "lifecycle_ref": "comparison:1", "evidence_classification": "independent",
            }
            first = record_native_control_finding(db, tenant_id=tenant.id, **kwargs)
            same = record_native_control_finding(db, tenant_id=tenant.id, **{**kwargs, "integration_id": "different-integration", "evidence_node_ids": ["evidence-2"]})
            distinct = record_native_control_finding(db, tenant_id=tenant.id, **{**kwargs, "material_field_or_effect": "action_semantics.target"})
            cross_tenant = record_native_control_finding(db, tenant_id=other_tenant.id, **kwargs)
            assert first is same
            assert first.finding_type == "ACTION_PARAMETER_DRIFT"
            assert first.occurrence_count == 2
            assert first.evidence_status == "independent"
            assert {"material:action_semantics.safe_parameters", "authority:receipt:1", "profile:financial-services@1.0.0", "lifecycle:comparison:1"} <= set(first.related_control_ids)
            assert distinct.dedupe_key != first.dedupe_key
            assert cross_tenant.dedupe_key != first.dedupe_key
            with pytest.raises(ValueError, match="required_evidence"):
                record_native_control_finding(db, tenant_id=tenant.id, **{**kwargs, "evidence_kinds": []})
            for code in EXPECTED_CODES:
                with pytest.raises(ValueError):
                    record_native_control_finding(
                        db, tenant_id=tenant.id, finding_type=code, integration_id="legacy", action_id="action-required",
                        provider="test", policy_version=None, evidence_node_ids=[], reason_codes=[],
                    )
            alias = record_native_control_finding(db, tenant_id=tenant.id, **{
                **kwargs, "finding_type": "APPROVAL_BINDING_INVALIDATED", "material_field_or_effect": "approval_binding",
                "evidence_kinds": ["approval_binding", "invalidating_material_or_currentness_change"],
            })
            assert alias.finding_type == "APPROVAL_INVALIDATED"
            alias.finding_type = "APPROVAL_BINDING_INVALIDATED"
            alias.dedupe_key = "historical-alias-key"
            alias.related_control_ids = ["APPROVAL_BINDING_INVALIDATED"]
            db.flush()
            merged = record_native_control_finding(db, tenant_id=tenant.id, **{
                **kwargs, "finding_type": "APPROVAL_INVALIDATED", "material_field_or_effect": "approval_binding",
                "evidence_kinds": ["approval_binding", "invalidating_material_or_currentness_change"],
            })
            assert merged is alias
            assert merged.finding_type == "APPROVAL_INVALIDATED"
            assert merged.dedupe_key != "historical-alias-key"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
