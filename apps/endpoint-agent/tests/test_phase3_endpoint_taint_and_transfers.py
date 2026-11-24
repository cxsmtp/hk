from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import (
    EndpointPrimitive,
    EndpointProcessIdentity,
)
from hawk_endpoint_agent.endpoint_floor.taint import (
    DownloadEvidenceAccumulator,
    EndpointTaintRegistry,
    TaintConfidence,
    TaintPropagationState,
)


NOW = datetime(2026, 8, 15, 13, 0, tzinfo=UTC)


def _process(
    *,
    pid: int = 10,
    start: int = 100,
    parent_instance: str | None = None,
    session: str = "session-1",
) -> EndpointProcessIdentity:
    return EndpointProcessIdentity(
        process_id=pid,
        parent_process_id=1,
        process_start_time_ns=start,
        binary_path=f"/Applications/TestAI-{pid}.app/Contents/MacOS/TestAI",
        binary_signature="TEAM:test.ai",
        binary_hash_reference=f"sha256:binary-{pid}",
        bundle_or_package_identity="test.ai",
        user_id="user-1",
        device_id="device-1",
        session_id=session,
        tenant_id="tenant-1",
        platform="macos",
        parent_process_instance_id=parent_instance,
    )


def _registry() -> EndpointTaintRegistry:
    return EndpointTaintRegistry(
        tenant_id="tenant-1",
        device_id="device-1",
        maximum_ttl=timedelta(minutes=10),
    )


def test_origin_taint_is_bounded_and_policy_action_bound() -> None:
    registry = _registry()
    context = registry.create_origin(
        process=_process(),
        source_reference="sha256:file-sensitive",
        classification="highly_confidential",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        action_id="action-1",
        chain_reference="chain-1",
        purpose_reference="purpose:security-investigation",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:1",),
    )

    assert context.confidence is TaintConfidence.CONFIRMED
    assert context.propagation_state is TaintPropagationState.ORIGIN
    assert context.process_instance_id == _process().process_instance_id
    assert context.policy_epoch == 8
    assert "file contents" not in repr(context).lower()


def test_child_and_local_mcp_propagation_require_identity_and_evidence() -> None:
    registry = _registry()
    parent = _process()
    origin = registry.create_origin(
        process=parent,
        source_reference="sha256:file-sensitive",
        classification="restricted",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        action_id="action-1",
        chain_reference="chain-1",
        purpose_reference="purpose:approved",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:1",),
    )
    child = _process(pid=11, start=200, parent_instance=parent.process_instance_id)

    propagated = registry.propagate(
        origin.taint_id,
        target_process=child,
        state=TaintPropagationState.CHILD,
        confidence=TaintConfidence.STRONG_CORRELATION,
        observed_at=NOW + timedelta(seconds=1),
        evidence_refs=("os:process-child:1",),
    )
    mcp = registry.propagate(
        propagated.taint_id,
        target_process=child,
        state=TaintPropagationState.LOCAL_MCP,
        confidence=TaintConfidence.CONFIRMED,
        observed_at=NOW + timedelta(seconds=2),
        evidence_refs=("semantic:mcp-session:1",),
    )

    assert propagated.parent_taint_id == origin.taint_id
    assert propagated.propagation_state is TaintPropagationState.CHILD
    assert mcp.confidence is TaintConfidence.CONFIRMED


def test_timing_alone_never_becomes_confirmed_causality() -> None:
    registry = _registry()
    source = registry.create_origin(
        process=_process(),
        source_reference="sha256:file-sensitive",
        classification="restricted",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        action_id="action-1",
        chain_reference="chain-1",
        purpose_reference="purpose:approved",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:1",),
    )

    with pytest.raises(ValueError, match="authoritative evidence"):
        registry.propagate(
            source.taint_id,
            target_process=_process(),
            state=TaintPropagationState.NETWORK,
            confidence=TaintConfidence.CONFIRMED,
            observed_at=NOW + timedelta(milliseconds=1),
            evidence_refs=("temporal:within-window",),
        )


def test_taint_expires_and_clears_by_process_session_and_action() -> None:
    registry = _registry()
    process = _process()
    first = registry.create_origin(
        process=process,
        source_reference="sha256:file-a",
        classification="restricted",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(seconds=2),
        action_id="action-1",
        chain_reference="chain-1",
        purpose_reference="purpose:approved",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:1",),
    )
    second = registry.create_origin(
        process=process,
        source_reference="sha256:file-b",
        classification="restricted",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        action_id="action-2",
        chain_reference="chain-2",
        purpose_reference="purpose:approved",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:2",),
    )

    assert registry.expire(now=NOW + timedelta(seconds=3)) == (first.taint_id,)
    assert registry.clear_action("action-2", observed_at=NOW + timedelta(seconds=4)) == (
        second.taint_id,
    )
    assert registry.active_for_process(process.process_instance_id) == ()


def test_isolated_process_does_not_inherit_taint_without_lineage() -> None:
    registry = _registry()
    source_process = _process()
    registry.create_origin(
        process=source_process,
        source_reference="sha256:file-a",
        classification="restricted",
        access_operation=EndpointPrimitive.FILE_READ,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        action_id="action-1",
        chain_reference="chain-1",
        purpose_reference="purpose:approved",
        policy_version="policy-8",
        policy_epoch=8,
        evidence_refs=("os:file-open:1",),
    )
    isolated = _process(pid=20, start=500, session="isolated-session")

    assert registry.active_for_process(isolated.process_instance_id) == ()


def test_download_accumulator_emits_one_bounded_action_not_packet_or_write_flood() -> None:
    accumulator = DownloadEvidenceAccumulator(maximum_actions=32, maximum_evidence_refs=16)
    process = _process()
    for evidence_ref in (
        "net:flow:1",
        "net:packet:2",
        "file:create:1",
        "file:write:2",
        "file:write:2",
    ):
        result = accumulator.record(
            action_id="download-action-1",
            process_instance_id=process.process_instance_id,
            source_reference="destination:approved-download",
            target_resource_identity="sha256:download-file",
            evidence_ref=evidence_ref,
            observed_at=NOW,
            semantic_binding=evidence_ref == "net:flow:1",
        )

    assert result.action_id == "download-action-1"
    assert result.confidence is TaintConfidence.CONFIRMED
    assert result.observation_count == 4
    assert result.evidence_refs == (
        "net:flow:1",
        "net:packet:2",
        "file:create:1",
        "file:write:2",
    )
