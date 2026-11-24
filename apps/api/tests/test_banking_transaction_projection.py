from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_fail_safe_is_action_specific_and_never_silently_downgrades() -> None:
    from app.services.banking_transaction_projection_service import (
        BankingFailSafeContext,
        resolve_banking_fail_safe,
    )

    local_read = resolve_banking_fail_safe(
        BankingFailSafeContext(
            action_class="low_risk_read",
            subject_binding=True,
            target_binding=True,
            policy_available=False,
            signed_local_policy_available=True,
            mandatory_control_plan_healthy=True,
        )
    )
    sensitive = resolve_banking_fail_safe(
        BankingFailSafeContext(
            action_class="sensitive_customer_read",
            subject_binding=True,
            target_binding=False,
            policy_available=False,
            signed_local_policy_available=True,
            mandatory_control_plan_healthy=True,
        )
    )
    financial_write = resolve_banking_fail_safe(
        BankingFailSafeContext(
            action_class="financial_write",
            subject_binding=True,
            target_binding=True,
            policy_available=True,
            signed_local_policy_available=True,
            mandatory_control_plan_healthy=False,
        )
    )

    assert (local_read.decision, local_read.reason_code) == (
        "allow_local_policy",
        "SIGNED_LOCAL_POLICY_FALLBACK",
    )
    assert sensitive.decision == "control_requirement_unsatisfied"
    assert financial_write.decision == "control_requirement_unsatisfied"


def test_async_state_never_treats_queued_as_executed_and_is_monotonic() -> None:
    from app.services.banking_transaction_projection_service import (
        advance_banking_async_state,
    )

    assert advance_banking_async_state("authorized", "queued") == "queued"
    assert advance_banking_async_state("queued", "started") == "started"
    assert advance_banking_async_state("started", "completed") == "completed"
    with pytest.raises(ValueError):
        advance_banking_async_state("queued", "completed")
    with pytest.raises(ValueError):
        advance_banking_async_state("completed", "started")


def test_sentinel_projection_contains_required_transaction_fields_without_raw_pii() -> None:
    from app.services.banking_transaction_projection_service import (
        BankingCoverageDimension,
        BankingTimelineEvent,
        BankingTransactionProjection,
        banking_transaction_siem_event,
    )

    projection = BankingTransactionProjection(
        tenant_id="tenant-a",
        ai_transaction_id="transaction-001",
        subject_reference="hmac-sha256:" + "1" * 64,
        subject_type="customer",
        agent_chain=("bank-agent",),
        model="unknown",
        business_purpose="own-account-summary",
        action_class="tool_execution",
        transport="function",
        target_class="banking_resource",
        destination_class="internal",
        decision="allow",
        selected_controls=("runtime_control:function",),
        decision_receipt_ids=("decision-001",),
        execution_receipt_ids=("execution-001",),
        integrity_status="matched",
        drift_flags=(),
        finding_ids=(),
        coverage={
            "subject": BankingCoverageDimension(
                status="covered",
                reason="signed subject bound",
                evidence_refs=("decision-001",),
            ),
            "mcp": BankingCoverageDimension(
                status="not_applicable",
                reason="MCP not used",
                evidence_refs=(),
            ),
        },
        coverage_complete=False,
        timeline=(
            BankingTimelineEvent(
                stage="hawk_decision",
                state="observed",
                occurred_at="2026-08-14T10:00:00Z",
                evidence_refs=("decision-001",),
            ),
        ),
    )
    event = banking_transaction_siem_event(projection)
    serialized = str(event)

    for field in (
        "ai_transaction_id",
        "subject_reference",
        "subject_type",
        "agent_chain",
        "model",
        "business_purpose",
        "action_class",
        "transport",
        "target_class",
        "destination_class",
        "decision_receipt_id",
        "execution_receipt_id",
        "integrity_status",
        "coverage_status",
    ):
        assert field in event
    assert "customer-001" not in serialized
    assert "acct-001" not in serialized
    assert event["coverage_status"] == "incomplete"


def test_coverage_complete_requires_each_required_dimension_not_an_average() -> None:
    from app.services.banking_transaction_projection_service import (
        BankingCoverageDimension,
        coverage_is_complete,
    )

    coverage = {
        "subject": BankingCoverageDimension("covered", "ok", ("a",)),
        "identity": BankingCoverageDimension("covered", "ok", ("a",)),
        "target_binding": BankingCoverageDimension("unknown", "no proof", ()),
    }

    assert coverage_is_complete(coverage) is False


def test_latency_summary_reports_percentiles_errors_timeouts_and_max() -> None:
    from app.services.banking_transaction_projection_service import (
        BankingLatencySample,
        summarize_banking_latency_samples,
    )

    summary = summarize_banking_latency_samples(
        (
            BankingLatencySample(1.0, "success"),
            BankingLatencySample(2.0, "success"),
            BankingLatencySample(3.0, "error"),
            BankingLatencySample(10.0, "timeout"),
        )
    )

    assert summary.count == 4
    assert summary.p50_ms == 2.5
    assert summary.p95_ms == 8.95
    assert summary.p99_ms == 9.79
    assert summary.max_ms == 10.0
    assert summary.error_rate == 0.5
    assert summary.timeout_count == 1


def test_unknown_transport_never_defaults_to_function_coverage() -> None:
    from app.services.banking_transaction_projection_service import (
        _transport_coverage_dimensions,
    )

    coverage = _transport_coverage_dimensions(
        transport="unknown",
        decision_receipt_ids=("decision-001",),
        transport_reason="unknown",
        canonical_refs=("node-001",),
    )

    assert coverage["function"].status == "unknown"
    assert coverage["mcp"].status == "unknown"
    assert coverage["direct_api"].status == "unknown"


def test_model_coverage_requires_receipt_bound_to_the_model_node() -> None:
    from app.services.banking_transaction_projection_service import (
        _has_bound_model_receipt,
    )

    assert _has_bound_model_receipt(
        model_node_ids=("model-node",),
        decision_node_ids=("function-node",),
    ) is False
    assert _has_bound_model_receipt(
        model_node_ids=("model-node",),
        decision_node_ids=("function-node", "model-node"),
    ) is True


def test_route_receipts_are_filtered_to_the_exact_execution_node() -> None:
    from app.services.banking_transaction_projection_service import (
        _receipts_bound_to_nodes,
    )

    receipts = (
        SimpleNamespace(
            receipt_id="model-decision",
            canonical_action_evidence_node_id="model-node",
        ),
        SimpleNamespace(
            receipt_id="function-decision",
            canonical_action_evidence_node_id="function-node",
        ),
    )

    bound = _receipts_bound_to_nodes(receipts, node_ids=("function-node",))

    assert tuple(receipt.receipt_id for receipt in bound) == ("function-decision",)


def test_schema_reference_is_unknown_until_name_and_version_are_observed() -> None:
    from app.services.banking_transaction_projection_service import (
        _versioned_schema_reference,
    )

    assert _versioned_schema_reference("unknown", "unknown") == "unknown"
    assert _versioned_schema_reference("bank-action", "unknown") == "unknown"
    assert _versioned_schema_reference("bank-action", "1.0") == "bank-action/1.0"


def test_ciso_window_reports_distinct_transaction_limit_truncation() -> None:
    from app.services.banking_transaction_projection_service import (
        _recent_banking_transaction_ids,
    )

    nodes = [
        SimpleNamespace(
            payload={
                "canonical_action": {
                    "actor": {"ai_transaction_id": f"transaction-{index:02d}"},
                }
            }
        )
        for index in range(26)
    ]

    class _ScalarResult:
        def all(self):
            return nodes

    class _Db:
        def scalars(self, _statement):
            return _ScalarResult()

    transaction_ids, scanned_count, truncated = _recent_banking_transaction_ids(
        _Db(),
        tenant_id="tenant-a",
        scan_limit=2_000,
        transaction_limit=25,
    )

    assert len(transaction_ids) == 25
    assert scanned_count == 26
    assert truncated is True
