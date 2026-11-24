from __future__ import annotations

from test_phase5_execution_receipt_v2 import NOW, _action, _provider


def test_comparator_never_marks_unresolved_or_extra_material_as_matched() -> None:
    from app.services.action_integrity.execution_proof import compare_authorized_to_executed, signed_execution_comparison, verify_execution_comparison
    authorized, executed = _action(), _action(unresolved=["action_semantics.target_refs"])
    comparison = compare_authorized_to_executed(authorized, executed)
    assert comparison["result"] == "UNVERIFIED"
    assert comparison["unresolved_fields"]
    signed = signed_execution_comparison(_provider(), tenant_id="tenant-exec", attempt_id="attempt-1", authorized=authorized, executed=executed, issued_at=NOW)
    provider = _provider()
    signed = signed_execution_comparison(provider, tenant_id="tenant-exec", attempt_id="attempt-1", authorized=authorized, executed=executed, issued_at=NOW)
    assert verify_execution_comparison(provider, signed)
    signed["result"] = "MATCHED"
    assert not verify_execution_comparison(provider, signed)


def test_comparator_detects_actual_only_material_field() -> None:
    from app.services.action_integrity.execution_proof import compare_authorized_to_executed
    executed = _action()
    executed["action_semantics"] = {**executed["action_semantics"], "target_refs": ["target:other"]}
    result = compare_authorized_to_executed(_action(), executed)
    assert result["result"] == "DRIFTED"
    assert result["drift_fields"] and result["difference_hashes"]
