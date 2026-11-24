from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.api.routers import native_controls as router


NOW = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
CONFIGURATION_HASH = "c" * 64


class _Rows:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self._rows = rows

    def all(self) -> list[SimpleNamespace]:
        return self._rows


class _EvidenceDB:
    def __init__(
        self,
        rows: list[SimpleNamespace],
        *,
        block_execution: object | None = None,
    ) -> None:
        self.rows = rows
        self.scalar_results = iter(
            (
                SimpleNamespace(
                    decision="allow",
                    policy_snapshot_id="policy-v1",
                    target_resource_hash="a" * 64,
                    signature="signed-allow",
                    signing_key_id="receipt-key",
                ),
                SimpleNamespace(
                    decision="block",
                    policy_snapshot_id="policy-v1",
                    target_resource_hash="b" * 64,
                    signature="signed-block",
                    signing_key_id="receipt-key",
                ),
                SimpleNamespace(actual_target_resource_hash="a" * 64),
                block_execution,
            )
        )

    def scalars(self, _statement: object) -> _Rows:
        return _Rows(self.rows)

    def scalar(self, _statement: object) -> object | None:
        return next(self.scalar_results)


def _node(
    identifier: str,
    *,
    node_type: str,
    signal_type: str,
    correlation_id: str,
    created_offset: int,
    payload: dict[str, object],
) -> SimpleNamespace:
    return SimpleNamespace(
        id=identifier,
        node_type=node_type,
        signal_type=signal_type,
        correlation_id=correlation_id,
        created_at=NOW + timedelta(seconds=created_offset),
        payload=payload,
    )


def _proof_rows() -> list[SimpleNamespace]:
    common = {
        "integration_id": "integration-1",
        "provider": "anthropic",
        "product": "claude_code",
        "provider_version": "2.1.183",
        "adapter_version": "1.2.0",
        "credential_id": "credential-1",
        "credential_epoch": 7,
        "signature_algorithm": "ES256",
        "adapter_dispatch": "exact",
        "adapter_resolution": "exact_match",
        "adapter_enforcement_eligible": True,
        "route_binding_current": True,
        "integration_contract_hash": "d" * 64,
        "integration_configuration_fingerprint": CONFIGURATION_HASH,
        "policy_snapshot_id": "policy-v1",
        "target_confirmation": "hash_bound",
        "evidence_grade": "signed_provider_callback",
        "deduplicated": False,
        "deduplication_conflict": False,
    }
    allow = _node(
        "allow-node",
        node_type="native_control_callback",
        signal_type="authenticated_native_adapter",
        correlation_id="allow-correlation",
        created_offset=0,
        payload={
            **common,
            "provider_event_type": "before_tool",
            "provider_event_id_hash": "1" * 64,
            "acceptance_challenge_id_hash": "2" * 64,
            "target_resource_hash": "a" * 64,
            "decision": "allow",
            "would_decision": "allow",
            "decision_receipt_id": "allow-receipt",
        },
    )
    block = _node(
        "block-node",
        node_type="native_control_callback",
        signal_type="authenticated_native_adapter",
        correlation_id="block-correlation",
        created_offset=1,
        payload={
            **common,
            "provider_event_type": "before_tool",
            "provider_event_id_hash": "3" * 64,
            "acceptance_challenge_id_hash": "4" * 64,
            "target_resource_hash": "b" * 64,
            "decision": "block",
            "would_decision": "block",
            "decision_receipt_id": "block-receipt",
            "enforced": True,
        },
    )
    allow_execution = _node(
        "allow-execution-node",
        node_type="native_control_callback",
        signal_type="authenticated_native_adapter",
        correlation_id="allow-correlation",
        created_offset=2,
        payload={
            **common,
            "provider_event_type": "after_tool",
            "provider_event_id_hash": "5" * 64,
            "acceptance_challenge_id_hash": "2" * 64,
            "target_resource_hash": "a" * 64,
            "correlated_pre_action_evidence_ref": "evidence:allow-node",
            "decision": "allow",
            "would_decision": "allow",
            "execution_evidence_quality": "provider_reported",
            "evidence_grade": "provider_reported_execution",
            "execution_receipt_id": "execution-receipt",
            "input_mutation_detected": False,
        },
    )
    allow_effect = _node(
        "allow-effect-node",
        node_type="native_control_execution_effect",
        signal_type="endpoint_observed_execution_effect",
        correlation_id="allow-correlation",
        created_offset=3,
        payload={
            **common,
            "evidence_version": "native-control-real-binary-evidence/1.0",
            "allow_evidence_ref": "evidence:allow-node",
            "allow_correlation_id": "allow-correlation",
            "allow_execution_evidence_ref": "evidence:allow-execution-node",
            "allow_decision_receipt_id": "allow-receipt",
            "acceptance_challenge_id_hash": "2" * 64,
            "target_resource_hash": "a" * 64,
            "execution_observed": True,
            "expected_target_state_verified": True,
            "evidence_quality": "endpoint_observed",
            "observer_class": "trusted_endpoint_monitor",
            "target_confirmation": "endpoint_observed_exact",
            "observer_attestation_verified": True,
            "server_verified": True,
        },
    )
    non_execution = _node(
        "non-execution-node",
        node_type="native_control_non_execution",
        signal_type="endpoint_observed_non_execution",
        correlation_id="block-correlation",
        created_offset=3,
        payload={
            **common,
            "evidence_version": "native-control-real-binary-evidence/1.0",
            "block_evidence_ref": "evidence:block-node",
            "block_decision_receipt_id": "block-receipt",
            "block_correlation_id": "block-correlation",
            "acceptance_challenge_id_hash": "4" * 64,
            "target_resource_hash": "b" * 64,
            "execution_observed": False,
            "execution_receipt_id": None,
            "evidence_quality": "endpoint_observed",
            "observer_class": "trusted_endpoint_monitor",
            "target_confirmation": "endpoint_observed_exact",
            "observer_attestation_verified": True,
            "server_verified": True,
        },
    )
    return [non_execution, allow_effect, allow_execution, block, allow]


def _verify(
    monkeypatch: pytest.MonkeyPatch,
    rows: list[SimpleNamespace],
    *,
    block_execution: object | None = None,
) -> tuple[dict[str, bool], dict[str, SimpleNamespace]]:
    monkeypatch.setattr(
        router,
        "integration_configuration_fingerprint",
        lambda _integration: CONFIGURATION_HASH,
    )
    return router._real_binary_acceptance_evidence(
        _EvidenceDB(rows, block_execution=block_execution),
        integration=SimpleNamespace(
            tenant_id="tenant-1",
            id="integration-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            contract_hash="d" * 64,
            policy_version="policy-v1",
        ),
        credential=SimpleNamespace(
            credential_id="credential-1",
            credential_epoch=7,
        ),
        current=NOW + timedelta(seconds=4),
    )


def test_acceptance_verifier_requires_complete_independent_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checks, selected = _verify(monkeypatch, _proof_rows())
    assert all(checks.values())
    assert set(selected) == {
        "allow",
        "allow_execution",
        "allow_target_effect",
        "block",
        "non_execution",
    }


def test_acceptance_verifier_rejects_duplicate_challenge_and_mismatched_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = _proof_rows()
    duplicate[-2].payload["acceptance_challenge_id_hash"] = "2" * 64
    duplicate_checks, _ = _verify(monkeypatch, duplicate)
    assert duplicate_checks["distinct_acceptance_challenges"] is False

    mismatched = _proof_rows()
    mismatched[-2].payload["credential_epoch"] = 6
    mismatched_checks, _ = _verify(monkeypatch, mismatched)
    assert mismatched_checks["signed_block_receipt_observed"] is False


def test_acceptance_verifier_rejects_block_execution_and_unattested_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed_checks, _ = _verify(
        monkeypatch,
        _proof_rows(),
        block_execution=SimpleNamespace(receipt_id="unexpected-block-execution"),
    )
    assert executed_checks["block_execution_absent"] is False
    assert executed_checks["attested_non_execution_observed"] is False

    unattested = _proof_rows()
    unattested[0].payload["server_verified"] = False
    unattested[1].payload["observer_attestation_verified"] = False
    unattested_checks, _ = _verify(monkeypatch, unattested)
    assert unattested_checks["attested_non_execution_observed"] is False
    assert unattested_checks["attested_allow_target_effect_observed"] is False
