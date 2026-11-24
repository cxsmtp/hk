from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from itertools import count
from threading import Barrier

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import EndpointPrimitive
from hawk_endpoint_agent.endpoint_floor.permits import (
    EndpointPermitBroker,
    SQLiteEndpointAuthorityReplayStore,
)
from hawk_endpoint_agent.native_control.endpoint_permit_binding import (
    CallableNativeAuthorityVerifier,
    ClaudeCodePreToolUsePermitBinding,
    NativeAuthorityClaim,
    NativeEndpointOperation,
    VerifiedNativeEndpointAuthority,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def _broker(
    replay_store: SQLiteEndpointAuthorityReplayStore | None = None,
) -> EndpointPermitBroker:
    nonces = count(1)
    return EndpointPermitBroker(
        tenant_id="tenant-1",
        device_id="device-1",
        active_policy_epoch=12,
        integrity_key=b"p" * 32,
        nonce_factory=lambda: f"native-proof-{next(nonces)}",
        authority_replay_store=(
            replay_store or SQLiteEndpointAuthorityReplayStore(":memory:")
        ),
    )


def _binding(**changes: object) -> ClaudeCodePreToolUsePermitBinding:
    material = {
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "process_instance_id": "claude-process-1",
        "action_id": "action-1",
        "canonical_action_hash": "a" * 64,
        "primitive": EndpointPrimitive.FILE_READ,
        "requested_rights": ("read_data",),
        "target_identity": "object-sha256:file-1",
        "destination_identity": "destination-sha256:local",
        "control_plan_id": "plan-1",
        "control_plan_digest": "b" * 64,
        "decision_receipt_id": "decision-receipt-1",
        "decision_receipt_binding_hash": "c" * 64,
        "policy_version": "policy-12",
        "policy_epoch": 12,
    }
    material.update(changes)
    return ClaudeCodePreToolUsePermitBinding(**material)


def _authority(**changes: object) -> VerifiedNativeEndpointAuthority:
    material = {
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "process_instance_id": "claude-process-1",
        "action_id": "action-1",
        "canonical_action_hash": "a" * 64,
        "primitive": EndpointPrimitive.FILE_READ,
        "requested_rights": ("read_data",),
        "target_identity": "object-sha256:file-1",
        "destination_identity": "destination-sha256:local",
        "control_plan_id": "plan-1",
        "control_plan_digest": "b" * 64,
        "decision_receipt_id": "decision-receipt-1",
        "decision_receipt_binding_hash": "c" * 64,
        "authority_reference": "authority-sha256:operator-1",
        "purpose_reference": "purpose-sha256:development-1",
        "policy_version": "policy-12",
        "policy_epoch": 12,
        "decision_issued_at": NOW - timedelta(seconds=1),
        "decision_expires_at": NOW + timedelta(minutes=2),
        "verification_reference": "verified-decision-receipt:decision-receipt-1",
    }
    material.update(changes)
    return VerifiedNativeEndpointAuthority(**material)


class _Verifier:
    def __init__(self, authority: VerifiedNativeEndpointAuthority | None) -> None:
        self.authority = authority
        self.claims: list[NativeAuthorityClaim] = []

    def resolve(self, claim: NativeAuthorityClaim) -> VerifiedNativeEndpointAuthority | None:
        self.claims.append(claim)
        if self.authority is None:
            return None
        expected = NativeAuthorityClaim(
            tenant_id=self.authority.tenant_id,
            device_id=self.authority.device_id,
            process_instance_id=self.authority.process_instance_id,
            action_id=self.authority.action_id,
            canonical_action_hash=self.authority.canonical_action_hash,
            primitive=self.authority.primitive,
            requested_rights=self.authority.requested_rights,
            target_identity=self.authority.target_identity,
            destination_identity=self.authority.destination_identity,
            policy_version=self.authority.policy_version,
            policy_epoch=self.authority.policy_epoch,
            control_plan_id=self.authority.control_plan_id,
            control_plan_digest=self.authority.control_plan_digest,
            decision_receipt_id=self.authority.decision_receipt_id,
            decision_receipt_binding_hash=self.authority.decision_receipt_binding_hash,
        )
        return self.authority if claim == expected else None


def _verifier(**changes: object) -> _Verifier:
    return _Verifier(_authority(**changes))


def _operation(**changes: object) -> NativeEndpointOperation:
    material = {
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "process_instance_id": "claude-process-1",
        "action_id": "action-1",
        "canonical_action_hash": "a" * 64,
        "primitive": EndpointPrimitive.FILE_READ,
        "requested_rights": ("read_data",),
        "target_identity": "object-sha256:file-1",
        "destination_identity": "destination-sha256:local",
    }
    material.update(changes)
    return NativeEndpointOperation(**material)


def _issue(
    binding: ClaudeCodePreToolUsePermitBinding,
    broker: EndpointPermitBroker,
    *,
    verifier: _Verifier | None = None,
):
    exact_verifier = verifier or _verifier(
        device_id=binding.device_id,
        process_instance_id=binding.process_instance_id,
        action_id=binding.action_id,
        canonical_action_hash=binding.canonical_action_hash,
        primitive=binding.primitive,
        requested_rights=binding.requested_rights,
        target_identity=binding.target_identity,
        destination_identity=binding.destination_identity,
        policy_version=binding.policy_version,
        policy_epoch=binding.policy_epoch,
        control_plan_id=binding.control_plan_id,
        control_plan_digest=binding.control_plan_digest,
        decision_receipt_id=binding.decision_receipt_id,
        decision_receipt_binding_hash=binding.decision_receipt_binding_hash,
    )
    return binding.issue_to(broker, verifier=exact_verifier, now=NOW)


def test_local_issue_requires_a_verifier_backed_existing_receipt_and_exact_plan() -> None:
    broker = _broker()

    with pytest.raises(TypeError):
        _binding().issue_to(broker, now=NOW)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="verified_native_authority_required"):
        _binding().issue_to(broker, verifier=_Verifier(None), now=NOW)
    with pytest.raises(ValueError, match="verified_native_authority_required"):
        _binding(decision_receipt_id="nonexistent-receipt").issue_to(
            broker,
            verifier=_verifier(),
            now=NOW,
        )
    with pytest.raises(ValueError, match="verified_native_authority_required"):
        _binding(control_plan_digest="d" * 64).issue_to(
            broker,
            verifier=_verifier(),
            now=NOW,
        )


def test_claude_pretool_permit_consumes_once_without_a_second_policy_decision() -> None:
    broker = _broker()
    binding = _binding()
    verifier = _verifier()

    issued = binding.issue_to(broker, verifier=verifier, now=NOW)
    first = binding.consume_from(broker, issued.permit_id, _operation(), now=NOW + timedelta(seconds=1))
    replay = binding.consume_from(broker, issued.permit_id, _operation(), now=NOW + timedelta(seconds=2))

    assert verifier.claims == [
        NativeAuthorityClaim(
            tenant_id="tenant-1",
            device_id="device-1",
            process_instance_id="claude-process-1",
            action_id="action-1",
            canonical_action_hash="a" * 64,
            primitive=EndpointPrimitive.FILE_READ,
            requested_rights=("read_data",),
            target_identity="object-sha256:file-1",
            destination_identity="destination-sha256:local",
            policy_version="policy-12",
            policy_epoch=12,
            control_plan_id="plan-1",
            control_plan_digest="b" * 64,
            decision_receipt_id="decision-receipt-1",
            decision_receipt_binding_hash="c" * 64,
        )
    ]
    assert issued.accepted is True
    assert issued.evidence["source_control_point"] == "claude_code:pre_tool_use"
    assert issued.evidence["control_plan_digest"] == "b" * 64
    assert issued.evidence["decision_receipt_id"] == "decision-receipt-1"
    assert first.allowed is True
    assert first.reason == "permit_consumed"
    assert first.evidence["policy_re_evaluated"] is False
    assert first.evidence["verification_status"] == "experimental"
    assert first.evidence["os_floor_consumption_verified"] is False
    assert replay.allowed is False
    assert replay.reason == "permit_replay"


def test_one_receipt_binding_cannot_mint_multiple_local_permits() -> None:
    broker = _broker()
    binding = _binding()
    issued = _issue(binding, broker)

    with pytest.raises(ValueError, match="decision_receipt_authority_already_bound"):
        _issue(binding, broker)
    assert binding.consume_from(
        broker,
        issued.permit_id,
        _operation(),
        now=NOW + timedelta(seconds=1),
    ).allowed is True
    with pytest.raises(ValueError, match="decision_receipt_authority_already_bound"):
        _issue(binding, broker)


def test_native_authority_requires_durable_replay_store() -> None:
    nonces = count(1)
    broker = EndpointPermitBroker(
        tenant_id="tenant-1",
        device_id="device-1",
        active_policy_epoch=12,
        integrity_key=b"p" * 32,
        nonce_factory=lambda: f"no-store-{next(nonces)}",
    )

    with pytest.raises(RuntimeError, match="durable_authority_replay_store_required"):
        _issue(_binding(), broker)


def test_native_authority_replay_is_rejected_after_expiry_and_broker_restart(
    tmp_path,
) -> None:
    store_path = tmp_path / "native-authority-replay.sqlite3"
    first_store = SQLiteEndpointAuthorityReplayStore(store_path)
    first_broker = _broker(first_store)
    binding = _binding()
    assert _issue(binding, first_broker).accepted is True
    first_broker.close()
    first_store.close()

    restarted_store = SQLiteEndpointAuthorityReplayStore(store_path)
    restarted_broker = _broker(restarted_store)
    with pytest.raises(ValueError, match="decision_receipt_authority_already_bound"):
        binding.issue_to(
            restarted_broker,
            verifier=_verifier(),
            now=NOW + timedelta(seconds=31),
        )
    restarted_broker.close()
    restarted_store.close()


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"target_identity": "object-sha256:file-2"}, "resource_mismatch"),
        ({"primitive": EndpointPrimitive.PROCESS_EXECUTE, "requested_rights": ("execute",), "target_identity": "command-sha256:changed"}, "primitive_mismatch"),
        ({"destination_identity": "destination:external"}, "destination_mismatch"),
        ({"tenant_id": "tenant-2"}, "tenant_mismatch"),
        ({"device_id": "device-2"}, "device_mismatch"),
        ({"process_instance_id": "claude-process-2"}, "process_instance_mismatch"),
    ],
)
def test_changed_os_operation_denies_without_spending_authority(
    changes: dict[str, object], reason: str
) -> None:
    broker = _broker()
    binding = _binding()
    issued = _issue(binding, broker)

    denied = binding.consume_from(broker, issued.permit_id, _operation(**changes), now=NOW + timedelta(seconds=1))
    exact_retry = binding.consume_from(broker, issued.permit_id, _operation(), now=NOW + timedelta(seconds=2))

    assert denied.allowed is False
    assert denied.reason == reason
    assert exact_retry.allowed is True


@pytest.mark.parametrize(
    "changes",
    [
        {"target_identity": None},
        {"destination_identity": None},
        {
            "primitive": EndpointPrimitive.PROCESS_EXECUTE,
            "requested_rights": ("execute",),
            "target_identity": None,
        },
        {
            "primitive": EndpointPrimitive.NETWORK_CONNECT,
            "requested_rights": ("connect",),
            "target_identity": None,
            "destination_identity": None,
        },
    ],
)
def test_consequential_primitive_missing_required_material_never_issues(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="required"):
        _issue(_binding(**changes), _broker())


def test_receipt_clock_and_policy_epoch_invalidate_authority() -> None:
    broker = _broker()

    with pytest.raises(ValueError, match="verified_native_authority_not_current"):
        _binding().issue_to(
            broker,
            verifier=_verifier(decision_expires_at=NOW),
            now=NOW,
        )
    with pytest.raises(ValueError, match="verified_native_authority_not_current"):
        _binding().issue_to(
            broker,
            verifier=_verifier(decision_issued_at=NOW + timedelta(seconds=1)),
            now=NOW,
        )

    current = _issue(_binding(), broker)
    assert broker.activate_policy_epoch(13) == 1
    assert _binding().consume_from(
        broker,
        current.permit_id,
        _operation(),
        now=NOW + timedelta(seconds=1),
    ).reason == "permit_policy_invalidated"


@pytest.mark.parametrize(
    "changes",
    [
        {"device_id": "device-2"},
        {"process_instance_id": "claude-process-2"},
        {"primitive": EndpointPrimitive.PROCESS_EXECUTE, "requested_rights": ("execute",), "target_identity": "command-sha256:arbitrary"},
        {"target_identity": "object-sha256:file-2"},
        {"destination_identity": "destination:external"},
        {"policy_version": "policy-13"},
        {"policy_epoch": 13},
        {"decision_receipt_binding_hash": "d" * 64},
    ],
)
def test_real_receipt_cannot_be_rebound_to_a_different_endpoint_consequence(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="verified_native_authority_required"):
        _binding(**changes).issue_to(_broker(), verifier=_verifier(), now=NOW)


def test_command_and_destination_are_bound_exactly() -> None:
    broker = _broker()
    binding = _binding(
        primitive=EndpointPrimitive.PROCESS_EXECUTE,
        requested_rights=("execute",),
        target_identity="command-sha256:git-status",
        destination_identity="destination:approved-local-mcp",
    )
    exact = _operation(
        primitive=EndpointPrimitive.PROCESS_EXECUTE,
        requested_rights=("execute",),
        target_identity="command-sha256:git-status",
        destination_identity="destination:approved-local-mcp",
    )
    exact_issued = _issue(binding, broker)
    assert binding.consume_from(
        broker, exact_issued.permit_id, exact, now=NOW + timedelta(seconds=1)
    ).allowed is True

    changed_broker = _broker()
    changed_issued = _issue(binding, changed_broker)
    changed_command = binding.consume_from(
        changed_broker,
        changed_issued.permit_id,
        _operation(
            primitive=EndpointPrimitive.PROCESS_EXECUTE,
            requested_rights=("execute",),
            target_identity="command-sha256:curl-external",
            destination_identity="destination:approved-local-mcp",
        ),
        now=NOW + timedelta(seconds=1),
    )
    assert changed_command.reason == "resource_mismatch"
    changed_destination = binding.consume_from(
        changed_broker,
        changed_issued.permit_id,
        _operation(
            primitive=EndpointPrimitive.PROCESS_EXECUTE,
            requested_rights=("execute",),
            target_identity="command-sha256:git-status",
            destination_identity="destination:external",
        ),
        now=NOW + timedelta(seconds=2),
    )
    assert changed_destination.reason == "destination_mismatch"


def test_permit_consumption_is_atomic_under_concurrency() -> None:
    broker = _broker()
    binding = _binding()
    issued = _issue(binding, broker)
    barrier = Barrier(16)

    def consume(_: int):
        barrier.wait()
        return binding.consume_from(
            broker,
            issued.permit_id,
            _operation(),
            now=NOW + timedelta(seconds=1),
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        decisions = list(executor.map(consume, range(16)))

    assert sum(decision.allowed for decision in decisions) == 1
    assert [decision.reason for decision in decisions].count("permit_replay") == 15


def test_returned_evidence_is_immutable_and_cannot_promote_capability() -> None:
    broker = _broker()
    binding = _binding()
    issued = _issue(binding, broker)
    decision = binding.consume_from(
        broker,
        issued.permit_id,
        _operation(),
        now=NOW + timedelta(seconds=1),
    )

    with pytest.raises(TypeError):
        issued.evidence["decision_receipt_id"] = "forged"  # type: ignore[index]
    with pytest.raises(TypeError):
        decision.evidence["verification_status"] = "verified"  # type: ignore[index]
    with pytest.raises(TypeError):
        decision.evidence["os_floor_consumption_verified"] = True  # type: ignore[index]
    copied = dict(decision.evidence)
    copied["verification_status"] = "verified"
    assert decision.evidence["verification_status"] == "experimental"


def test_opaque_permit_result_does_not_expose_nonce_key_or_authority_material() -> None:
    issued = _issue(_binding(), _broker())
    rendered = repr(issued)

    assert "native-proof-1" not in rendered
    assert "pppppppp" not in rendered
    assert "authority-sha256:operator-1" not in rendered
    assert "purpose-sha256:development-1" not in rendered
    assert issued.permit_id.startswith("ep-")


def test_binding_refuses_non_claude_non_pretool_and_noncanonical_hashes() -> None:
    with pytest.raises(ValueError, match="claude_code_pre_tool_use_required"):
        _binding(provider="openai")
    with pytest.raises(ValueError, match="claude_code_pre_tool_use_required"):
        _binding(provider_event="PermissionRequest")
    with pytest.raises(ValueError, match="canonical_action_hash"):
        _binding(canonical_action_hash="A" * 64)


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "unknown"},
        {"device_id": "unknown"},
        {"process_instance_id": "unknown"},
        {"action_id": "unknown"},
        {"target_identity": "unknown"},
        {"policy_version": "unknown"},
        {"control_plan_id": "unknown"},
        {"decision_receipt_id": "unknown"},
    ],
)
def test_unknown_placeholders_cannot_enter_exact_native_authority(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="exact"):
        _binding(**changes)


def test_unknown_destination_cannot_enter_network_authority() -> None:
    with pytest.raises(ValueError, match="exact"):
        _binding(
            primitive=EndpointPrimitive.NETWORK_CONNECT,
            requested_rights=("connect",),
            target_identity=None,
            destination_identity="unknown",
        )


def test_os_observation_rejects_unknown_or_incomplete_exact_material() -> None:
    with pytest.raises(ValueError, match="exact"):
        _operation(process_instance_id="unknown")
    with pytest.raises(ValueError, match="required"):
        _operation(target_identity=None)
    with pytest.raises(ValueError, match="exact"):
        _operation(
            primitive=EndpointPrimitive.NETWORK_CONNECT,
            requested_rights=("connect",),
            target_identity=None,
            destination_identity="unknown",
        )


def test_callable_authority_verifier_sends_full_claim_and_rejects_rebound_projection() -> None:
    calls: list[dict[str, object]] = []

    def transport(payload: dict[str, object]) -> dict[str, object]:
        calls.append(payload)
        authority = _authority()
        return {
            "tenant_id": authority.tenant_id,
            "device_id": authority.device_id,
            "process_instance_id": authority.process_instance_id,
            "action_id": authority.action_id,
            "canonical_action_hash": authority.canonical_action_hash,
            "primitive": authority.primitive.value,
            "requested_rights": list(authority.requested_rights),
            "target_identity": authority.target_identity,
            "destination_identity": authority.destination_identity,
            "control_plan_id": authority.control_plan_id,
            "control_plan_digest": authority.control_plan_digest,
            "decision_receipt_id": authority.decision_receipt_id,
            "decision_receipt_binding_hash": authority.decision_receipt_binding_hash,
            "authority_reference": authority.authority_reference,
            "purpose_reference": authority.purpose_reference,
            "policy_version": authority.policy_version,
            "policy_epoch": authority.policy_epoch,
            "decision_issued_at": authority.decision_issued_at.isoformat(),
            "decision_expires_at": authority.decision_expires_at.isoformat(),
            "verification_reference": authority.verification_reference,
        }

    verifier = CallableNativeAuthorityVerifier(transport=transport)
    assert verifier.resolve(_binding().authority_claim) == _authority()
    assert calls == [
        {
            "tenant_id": "tenant-1",
            "device_id": "device-1",
            "process_instance_id": "claude-process-1",
            "action_id": "action-1",
            "canonical_action_hash": "a" * 64,
            "primitive": "file_read",
            "requested_rights": ["read_data"],
            "target_identity": "object-sha256:file-1",
            "destination_identity": "destination-sha256:local",
            "policy_version": "policy-12",
            "policy_epoch": 12,
            "control_plan_id": "plan-1",
            "control_plan_digest": "b" * 64,
            "decision_receipt_id": "decision-receipt-1",
            "decision_receipt_binding_hash": "c" * 64,
        }
    ]

    def rebound(_: dict[str, object]) -> dict[str, object]:
        payload = transport({})
        payload["device_id"] = "device-2"
        return payload

    assert CallableNativeAuthorityVerifier(transport=rebound).resolve(
        _binding().authority_claim
    ) is None


def test_callable_authority_verifier_fails_closed_on_malformed_response() -> None:
    verifier = CallableNativeAuthorityVerifier(
        transport=lambda _payload: {"tenant_id": "unknown"}
    )
    assert verifier.resolve(_binding().authority_claim) is None
