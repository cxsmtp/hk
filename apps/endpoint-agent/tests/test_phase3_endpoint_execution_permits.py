from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import count

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import EndpointPrimitive
from hawk_endpoint_agent.endpoint_floor.permits import (
    EndpointExecutionPermitRequest,
    EndpointPermitBroker,
    EndpointPermitConsumption,
    EndpointPermitStep,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def _step(
    *,
    step_id: str = "read-file",
    primitive: EndpointPrimitive = EndpointPrimitive.FILE_READ,
    rights: tuple[str, ...] = ("read_data",),
    resource: str | None = "sha256:file-a",
    destination: str | None = None,
    maximum_uses: int = 1,
) -> EndpointPermitStep:
    return EndpointPermitStep(
        step_id=step_id,
        primitive=primitive,
        requested_rights=rights,
        stable_resource_identity=resource,
        destination_identity=destination,
        maximum_uses=maximum_uses,
    )


def _request(*, steps: tuple[EndpointPermitStep, ...] | None = None) -> EndpointExecutionPermitRequest:
    return EndpointExecutionPermitRequest(
        tenant_id="tenant-1",
        device_id="device-1",
        process_instance_id="process-instance-1",
        action_id="action-1",
        canonical_action_hash="sha256:canonical-action",
        steps=steps or (_step(),),
        authority_reference="authority:user-1",
        purpose_reference="purpose:approved-development",
        policy_version="policy-8",
        policy_epoch=8,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        source_control_point="claude_code:pre_tool_use",
    )


def _consumption(
    *,
    primitive: EndpointPrimitive = EndpointPrimitive.FILE_READ,
    rights: tuple[str, ...] = ("read_data",),
    resource: str | None = "sha256:file-a",
    destination: str | None = None,
    tenant: str = "tenant-1",
    device: str = "device-1",
    process: str = "process-instance-1",
    action: str = "action-1",
    action_hash: str = "sha256:canonical-action",
    authority: str = "authority:user-1",
    purpose: str = "purpose:approved-development",
    policy_version: str = "policy-8",
    policy_epoch: int = 8,
) -> EndpointPermitConsumption:
    return EndpointPermitConsumption(
        tenant_id=tenant,
        device_id=device,
        process_instance_id=process,
        action_id=action,
        canonical_action_hash=action_hash,
        primitive=primitive,
        requested_rights=rights,
        stable_resource_identity=resource,
        destination_identity=destination,
        authority_reference=authority,
        purpose_reference=purpose,
        policy_version=policy_version,
        policy_epoch=policy_epoch,
    )


def _broker() -> EndpointPermitBroker:
    nonces = count(1)
    return EndpointPermitBroker(
        tenant_id="tenant-1",
        device_id="device-1",
        active_policy_epoch=8,
        integrity_key=b"k" * 32,
        nonce_factory=lambda: f"nonce-{next(nonces)}",
    )


def test_single_use_permit_is_broker_owned_and_replay_resistant() -> None:
    broker = _broker()
    issued = broker.issue(_request(), now=NOW)

    assert issued.accepted is True
    assert issued.permit_id.startswith("ep-")
    assert "nonce-1" not in repr(issued)
    assert "kkkk" not in repr(issued)
    assert issued.evidence["action_id"] == "action-1"
    assert issued.evidence["persisted_secret_material"] is False

    first = broker.consume(issued.permit_id, _consumption(), now=NOW + timedelta(seconds=1))
    replay = broker.consume(issued.permit_id, _consumption(), now=NOW + timedelta(seconds=2))

    assert first.allowed is True
    assert first.reason == "permit_consumed"
    assert first.evidence["lifecycle"] == "consumed"
    assert replay.allowed is False
    assert replay.reason == "permit_replay"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"tenant": "tenant-2"}, "tenant_mismatch"),
        ({"device": "device-2"}, "device_mismatch"),
        ({"process": "process-instance-2"}, "process_instance_mismatch"),
        ({"action": "action-2"}, "action_mismatch"),
        ({"action_hash": "sha256:mutated"}, "canonical_action_mismatch"),
        ({"primitive": EndpointPrimitive.FILE_WRITE}, "primitive_mismatch"),
        ({"rights": ("read_data", "write_data")}, "requested_rights_mismatch"),
        ({"resource": "sha256:file-b"}, "resource_mismatch"),
        ({"destination": "destination:external"}, "destination_mismatch"),
        ({"authority": "authority:admin"}, "authority_mismatch"),
        ({"purpose": "purpose:other"}, "purpose_mismatch"),
        ({"policy_version": "policy-9"}, "policy_version_mismatch"),
        ({"policy_epoch": 9}, "policy_epoch_mismatch"),
    ],
)
def test_material_drift_blocks_without_consuming_authority(
    changes: dict[str, object], reason: str
) -> None:
    broker = _broker()
    issued = broker.issue(_request(), now=NOW)

    denied = broker.consume(
        issued.permit_id,
        _consumption(**changes),
        now=NOW + timedelta(seconds=1),
    )
    exact_retry = broker.consume(
        issued.permit_id,
        _consumption(),
        now=NOW + timedelta(seconds=2),
    )

    assert denied.allowed is False
    assert denied.reason == reason
    assert exact_retry.allowed is True


def test_expiry_and_policy_epoch_change_invalidate_authority() -> None:
    broker = _broker()
    expired = broker.issue(_request(), now=NOW)
    assert broker.consume(
        expired.permit_id,
        _consumption(),
        now=NOW + timedelta(seconds=31),
    ).reason == "permit_expired"

    current = broker.issue(_request(), now=NOW)
    invalidated = broker.activate_policy_epoch(9)
    assert invalidated == 1
    assert broker.consume(
        current.permit_id,
        _consumption(policy_epoch=9, policy_version="policy-9"),
        now=NOW + timedelta(seconds=1),
    ).reason == "permit_policy_invalidated"


def test_bounded_multistep_permit_enforces_sequence_and_use_limits() -> None:
    steps = (
        _step(maximum_uses=2),
        _step(
            step_id="send-destination",
            primitive=EndpointPrimitive.NETWORK_CONNECT,
            rights=("connect",),
            resource=None,
            destination="destination:approved",
        ),
    )
    broker = _broker()
    issued = broker.issue(_request(steps=steps), now=NOW)

    out_of_order = broker.consume(
        issued.permit_id,
        _consumption(
            primitive=EndpointPrimitive.NETWORK_CONNECT,
            rights=("connect",),
            resource=None,
            destination="destination:approved",
        ),
        now=NOW + timedelta(seconds=1),
    )
    first_read = broker.consume(issued.permit_id, _consumption(), now=NOW + timedelta(seconds=2))
    second_read = broker.consume(issued.permit_id, _consumption(), now=NOW + timedelta(seconds=3))
    network = broker.consume(
        issued.permit_id,
        _consumption(
            primitive=EndpointPrimitive.NETWORK_CONNECT,
            rights=("connect",),
            resource=None,
            destination="destination:approved",
        ),
        now=NOW + timedelta(seconds=4),
    )

    assert out_of_order.reason == "primitive_mismatch"
    assert first_read.allowed is True
    assert first_read.evidence["remaining_step_uses"] == 1
    assert second_read.allowed is True
    assert second_read.evidence["next_step_id"] == "send-destination"
    assert network.allowed is True
    assert network.evidence["permit_complete"] is True


def test_issue_rejects_wrong_scope_epoch_unbounded_ttl_and_broad_step() -> None:
    broker = _broker()
    with pytest.raises(ValueError, match="broker scope"):
        broker.issue(replace(_request(), device_id="device-2"), now=NOW)
    with pytest.raises(ValueError, match="active policy epoch"):
        broker.issue(replace(_request(), policy_epoch=7), now=NOW)
    with pytest.raises(ValueError, match="maximum lifetime"):
        broker.issue(
            replace(_request(), expires_at=NOW + timedelta(hours=1)),
            now=NOW,
        )
    with pytest.raises(ValueError, match="at least one requested right"):
        _step(rights=())
