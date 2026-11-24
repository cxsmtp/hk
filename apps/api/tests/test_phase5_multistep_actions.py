from __future__ import annotations

from datetime import timedelta

import pytest

from test_phase5_execution_receipt_v2 import NOW


def test_signed_ordered_plan_rejects_inserted_child_and_unmet_predecessor() -> None:
    from app.services.action_integrity.complex_actions import issue_action_plan, validate_planned_child, verify_action_plan
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="action_plan_signing", tenant_id="tenant-plan", key_id="plan", secret=b"p" * 32)
    plan = issue_action_plan(provider, tenant_id="tenant-plan", parent_action_id="root", issued_at=NOW, expires_at=NOW + timedelta(minutes=1), steps=[
        {"step_id": "one", "child_action_id": "child-one", "authority_mode": "SEPARATE_DECISION", "unbound_material_fields_hash": "a" * 64},
        {"step_id": "two", "child_action_id": "child-two", "authority_mode": "SCOPED_PARENT_PERMIT", "unbound_material_fields_hash": "b" * 64, "permitted_predecessor_step_ids": ["one"]},
    ])
    assert verify_action_plan(provider, plan)
    with pytest.raises(PermissionError, match="predecessor"):
        validate_planned_child(plan, child_action_id="child-two", step_id="two", unbound_material_fields_hash="b" * 64, now=NOW)
    assert validate_planned_child(plan, child_action_id="child-two", step_id="two", unbound_material_fields_hash="b" * 64, completed_step_ids={"one"}, now=NOW)["step_id"] == "two"
    plan["steps"].append(dict(plan["steps"][0]))
    assert not verify_action_plan(provider, plan)
