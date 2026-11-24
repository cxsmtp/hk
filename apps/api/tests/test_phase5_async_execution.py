from __future__ import annotations

import pytest


def test_async_execution_dag_requires_real_evidence_for_success_or_block() -> None:
    from app.services.action_integrity.complex_actions import next_execution_state
    assert next_execution_state(current_state="PERMIT_ISSUED", requested_state="QUEUED") == "QUEUED"
    assert next_execution_state(current_state="QUEUED", requested_state="EXECUTION_STARTED") == "EXECUTION_STARTED"
    with pytest.raises(ValueError, match="evidence"):
        next_execution_state(current_state="EXECUTION_STARTED", requested_state="EXECUTED")
    with pytest.raises(ValueError, match="non-invocation"):
        next_execution_state(current_state="PERMIT_ISSUED", requested_state="BLOCKED")
