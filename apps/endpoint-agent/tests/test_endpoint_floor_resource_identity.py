from __future__ import annotations

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import (
    EndpointFileIdentity,
    EndpointProcessFamily,
    EndpointProcessIdentity,
    ProcessFamilyConfidence,
)


def _process(*, start: int = 100, path: str = "/Applications/TestAI.app/Contents/MacOS/TestAI") -> EndpointProcessIdentity:
    return EndpointProcessIdentity(
        process_id=900,
        parent_process_id=1,
        process_start_time_ns=start,
        binary_path=path,
        binary_signature="TEAMID:ai.hawk.test",
        binary_hash_reference="sha256:binary",
        bundle_or_package_identity="ai.hawk.test",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        tenant_id="tenant-1",
        platform="macos",
        architecture="arm64",
        integrity_or_trust_level="developer_signed",
        responsible_application_identity="bundle:ai.hawk.test",
    )


def test_process_instance_evidence_is_versioned_and_not_pid_only() -> None:
    first = _process(start=100)
    reused = _process(start=200)

    assert first.process_instance_id != reused.process_instance_id
    assert first.canonical_identity != reused.canonical_identity
    evidence = first.as_evidence()
    assert evidence["schema_version"] == "2.0"
    assert evidence["tenant_id"] == "tenant-1"
    assert evidence["platform"] == "macos"
    assert evidence["architecture"] == "arm64"
    assert evidence["responsible_application_identity"] == "bundle:ai.hawk.test"


def test_process_family_requires_evidence_stronger_than_a_similar_name() -> None:
    process = _process()
    with pytest.raises(ValueError, match="name-only"):
        EndpointProcessFamily(
            tenant_id="tenant-1",
            device_id="device-1",
            family_id="family-1",
            root_process_instance_id=process.process_instance_id,
            member_process_instance_ids=(process.process_instance_id,),
            responsible_application_identity="bundle:ai.hawk.test",
            confidence=ProcessFamilyConfidence.CONFIRMED,
            evidence_basis=("process_name:TestAI",),
        )

    family = EndpointProcessFamily(
        tenant_id="tenant-1",
        device_id="device-1",
        family_id="family-1",
        root_process_instance_id=process.process_instance_id,
        member_process_instance_ids=(process.process_instance_id,),
        responsible_application_identity="bundle:ai.hawk.test",
        confidence=ProcessFamilyConfidence.CONFIRMED,
        evidence_basis=("code_signing:TEAMID:ai.hawk.test", "bundle:ai.hawk.test"),
    )
    assert family.member_process_instance_ids == (process.process_instance_id,)


def test_file_identity_uses_object_identity_and_detects_replacement() -> None:
    original = EndpointFileIdentity(
        tenant_id="tenant-1",
        device_id="device-1",
        platform="macos",
        volume_identity="volume:apfs-1",
        filesystem_object_id="inode:1001",
        file_version="generation:7",
        canonical_path="/Users/example/Documents/Acquisition_Model.xlsx",
        original_path="/Users/example/Documents/Acquisition_Model.xlsx",
        resolved_path="/Users/example/Documents/Acquisition_Model.xlsx",
        owner_reference="user:1",
        classification_reference="classification:highly-confidential",
    )
    renamed = EndpointFileIdentity(
        tenant_id="tenant-1",
        device_id="device-1",
        platform="macos",
        volume_identity="volume:apfs-1",
        filesystem_object_id="inode:1001",
        file_version="generation:7",
        canonical_path="/Users/example/Documents/Renamed.xlsx",
        original_path="/Users/example/Documents/Acquisition_Model.xlsx",
        resolved_path="/Users/example/Documents/Renamed.xlsx",
    )
    replacement = EndpointFileIdentity(
        tenant_id="tenant-1",
        device_id="device-1",
        platform="macos",
        volume_identity="volume:apfs-1",
        filesystem_object_id="inode:2002",
        file_version="generation:1",
        canonical_path="/Users/example/Documents/Acquisition_Model.xlsx",
    )

    assert original.binding_quality == "stable_object"
    assert original.stable_object_identity == renamed.stable_object_identity
    assert original.same_object_as(renamed) is True
    assert original.same_object_as(replacement) is False
    assert original.canonical_identity != replacement.canonical_identity


def test_path_only_file_context_is_never_reported_as_stable_object_binding() -> None:
    path_only = EndpointFileIdentity(
        tenant_id="tenant-1",
        device_id="device-1",
        platform="windows",
        canonical_path="C:\\Users\\example\\Desktop\\report.txt",
    )

    assert path_only.binding_quality == "path_context"
    assert path_only.stable_object_identity is None
    assert path_only.as_evidence()["binding_quality"] == "path_context"


def test_file_paths_are_bounded_unicode_normalized_context_not_resolved_io() -> None:
    file_identity = EndpointFileIdentity(
        tenant_id="tenant-1",
        device_id="device-1",
        platform="macos",
        canonical_path="/tmp/Cafe\u0301.txt" + "x" * 5000,
    )

    assert "Café.txt" in file_identity.canonical_path
    assert len(file_identity.canonical_path) <= 2048
    assert "raw_content" not in file_identity.as_evidence()
