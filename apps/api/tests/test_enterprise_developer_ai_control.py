from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.services.native_control.acceptance_versions import REAL_BINARY_ACCEPTANCE_VERSION

from app.services.enterprise_developer_ai_control import (
    APPROVED_DEVELOPER_AI_REQUIREMENTS,
    build_enterprise_developer_ai_control,
    derive_account_device_summary,
    derive_meeting_ai_summary,
    derive_provider_capability_manifests,
    decide_repository_boundary,
    normalize_repository_reference,
    _repository_from_sessions,
)


def test_repository_identity_normalizes_common_github_references_without_name_only_trust() -> None:
    approved = {
        "provider": "github",
        "host": "github.com",
        "organization_login": "ACME",
        "repository_name": "trinya-corporate-code",
        "repository_id": "987654321",
        "node_id": "R_kgDOExample",
        "visibility": "private",
        "archived": False,
        "installation_id": "12345",
    }

    for value in (
        "https://github.com/ACME/trinya-corporate-code",
        "https://github.com/acme/trinya-corporate-code.git",
        "git@github.com:ACME/trinya-corporate-code.git",
        "ssh://git@github.com/ACME/trinya-corporate-code.git",
    ):
        resolved = normalize_repository_reference(value, verified_repositories=[approved])
        assert resolved["matched_immutable_identity"] is True
        assert resolved["repository_id"] == "987654321"

    lookalike = normalize_repository_reference(
        "https://github.com/ACM3/trinya-corporate-code",
        verified_repositories=[approved],
    )
    assert lookalike["matched_immutable_identity"] is False
    assert lookalike["classification"] == "external_or_unknown"


def test_strict_single_repository_boundary_allows_approved_repo_and_blocks_unapproved_or_public() -> None:
    policy = {
        "mode": "SINGLE_REPOSITORY_STRICT",
        "repository_identity": {
            "provider": "github",
            "host": "github.com",
            "organization_login": "ACME",
            "repository_name": "trinya-corporate-code",
            "repository_id": "987654321",
            "node_id": "R_kgDOExample",
            "visibility": "private",
            "archived": False,
            "installation_id": "12345",
        },
        "allowed_operations": ["REPOSITORY_PULL", "REPOSITORY_PUSH", "REPOSITORY_PULL_REQUEST_CREATE"],
        "default_branch_behavior": "BLOCK_DIRECT_PUSH",
        "force_push_behavior": "BLOCK",
        "fork_behavior": "BLOCK",
    }

    allowed = decide_repository_boundary(
        policy,
        repository_reference="https://github.com/acme/trinya-corporate-code.git",
        operation="REPOSITORY_PULL",
        branch="feature/demo",
        device_assurance="MANAGED_COMPLIANT",
    )
    assert allowed["decision"] == "ALLOW"
    assert allowed["reason"] == "approved_repository_operation"
    assert allowed["repository_identity"]["repository_id"] == "987654321"

    public_clone = decide_repository_boundary(
        policy,
        repository_reference="https://github.com/github/github-mcp-server",
        operation="REPOSITORY_PULL",
        branch="main",
        device_assurance="MANAGED_COMPLIANT",
    )
    assert public_clone["decision"] == "BLOCK"
    assert public_clone["reason"] == "repository_not_approved"

    main_push = decide_repository_boundary(
        policy,
        repository_reference="git@github.com:ACME/trinya-corporate-code.git",
        operation="REPOSITORY_PUSH",
        branch="main",
        device_assurance="MANAGED_COMPLIANT",
    )
    assert main_push["decision"] == "BLOCK"
    assert main_push["reason"] == "direct_default_branch_push_blocked"


def test_control_package_reports_requirement_traceability_and_no_fake_provider_coverage() -> None:
    payload = build_enterprise_developer_ai_control(
        tenant_id="tenant-1",
        now=datetime(2026, 9, 9, 12, tzinfo=UTC),
        repository_identity={
            "provider": "github",
            "host": "github.com",
            "organization_login": "ACME",
            "repository_name": "trinya-corporate-code",
            "repository_id": "987654321",
            "node_id": "R_kgDOExample",
            "visibility": "private",
            "archived": False,
            "installation_id": "12345",
            "last_verified_at": "2026-09-09T11:58:00Z",
        },
        entitled_developers=12,
        connected_developers=3,
        active_developers=2,
        ai_assisted_developers=2,
        unauthorized_attempts=[
            {
                "repository": "github.com/personal/side-project",
                "operation": "REPOSITORY_PUSH",
                "tool": "Codex CLI",
                "surface": "CLI",
                "decision": "BLOCK",
                "evidence_quality": "OBSERVED",
            }
        ],
        verified_paths={"Codex CLI": {"CLI/IDE": "VERIFIED", "GitHub scope": "VERIFIED"}},
    )

    assert payload["policy"]["mode"] == "SINGLE_REPOSITORY_STRICT"
    assert payload["summary"]["entitled_developers"] == 12
    assert payload["summary"]["uncovered_developers"] == 9
    assert payload["unauthorized_attempts"][0]["decision"] == "BLOCK"
    assert set(payload["requirement_traceability"]) == set(APPROVED_DEVELOPER_AI_REQUIREMENTS)
    assert payload["requirement_traceability"]["GIT-01"]["status"] == "PASS"
    assert payload["requirement_traceability"]["GIT-04"]["status"] == "PARTIAL"
    assert payload["provider_surface_coverage"]["Claude Code"]["CLI/IDE"] == "UNVERIFIED"
    assert payload["provider_surface_coverage"]["ChatGPT"]["Prompt visibility"] == "PARTIAL"
    assert "raw_prompt" not in str(payload).lower()
    assert "source code content" not in str(payload).lower()


def test_session_observation_never_becomes_an_immutable_repository_identity() -> None:
    session = SimpleNamespace(
        session_id="mcp_sess_sensitive_internal_identifier",
        start_time=datetime(2026, 9, 14, 8, tzinfo=UTC),
        metadata_json={
            "bound_context": {
                "allowed_resources": ["https://github.com/acme/example"],
            }
        },
    )
    db = SimpleNamespace(
        scalars=lambda _query: SimpleNamespace(all=lambda: [session]),
    )

    repository = _repository_from_sessions(db, tenant_id="tenant-1")

    assert repository is not None
    assert repository["organization_login"] == "acme"
    assert repository["repository_name"] == "example"
    assert repository["repository_id"] is None
    assert repository["evidence_quality"] == "OBSERVED"
    assert "mcp_sess" not in str(repository)


def test_unmanaged_device_strict_account_policy_denies_access_when_download_control_is_absent() -> None:
    policy = {
        "mode": "SINGLE_REPOSITORY_STRICT",
        "repository_identity": {
            "provider": "github",
            "host": "github.com",
            "organization_login": "ACME",
            "repository_name": "trinya-corporate-code",
            "repository_id": "987654321",
            "node_id": "R_kgDOExample",
            "visibility": "private",
            "archived": False,
            "installation_id": "12345",
        },
        "allowed_operations": ["REPOSITORY_PULL"],
        "unmanaged_device_corporate_account": "BLOCK_LOGIN_IF_DOWNLOAD_CONTROL_UNAVAILABLE",
    }

    denied = decide_repository_boundary(
        policy,
        repository_reference="https://github.com/acme/trinya-corporate-code",
        operation="REPOSITORY_PULL",
        branch="feature/demo",
        device_assurance="UNMANAGED",
        corporate_account=True,
        download_control_available=False,
    )

    assert denied["decision"] == "BLOCK"
    assert denied["reason"] == "corporate_account_requires_managed_device"


def test_provider_capability_requires_exact_current_tenant_acceptance() -> None:
    now = datetime(2026, 9, 9, 12, tzinfo=UTC)
    session_only = derive_provider_capability_manifests(
        now=now,
        sessions=(
            SimpleNamespace(
                ai_app="Claude Code",
                source_surface="runtime",
                ai_model="claude-sonnet",
                start_time=now,
                metadata_json={"client_version": "2.1.183"},
                user_id="user-1",
            ),
        ),
    )
    claude = next(
        row
        for row in session_only
        if row["provider"] == "anthropic"
        and row["product"] == "claude_code"
        and row["method"] == "native_hook"
    )
    assert claude["tenant_state"] == "CONNECTED_UNVERIFIED"
    assert claude["validation_tier"] == "CONFORMANCE_VERIFIED"
    assert claude["exact_version"] == "2.1.183"

    integration = SimpleNamespace(
        id="integration-codex",
        capability_profile_id="profile-codex",
        provider="openai",
        product="codex",
        integration_method="native_hook",
        state="enforcing",
        mode="enforce",
        health_state="healthy",
        provider_version="0.154.0",
        adapter_version="1.0.0",
        contract_hash="b" * 64,
        last_health_check_at=now,
        last_validated_at=now,
        known_blind_spots=[],
    )
    validation = SimpleNamespace(
        integration_instance_id="integration-codex",
        provider="openai",
        product="codex",
        result="passed",
        acceptance_state="REAL_BINARY_ACCEPTED",
        validation_version=REAL_BINARY_ACCEPTANCE_VERSION,
        safe_synthetic=False,
        allow_result="passed",
        block_result="passed",
        non_execution_result="passed",
        provider_version="0.154.0",
        adapter_version="1.0.0",
        contract_hash="b" * 64,
        action_classes=["prompt"],
        control_methods=["native_hook"],
        checks={
            "capabilities": {
                "discovery": "passed",
                "identity": "passed",
                "prompt_control": "passed",
                "post_execution_visibility": "passed",
                "bypass_detection": "passed",
                "config_integrity": "passed",
            }
        },
        validated_at=now,
        evidence_refs=["native-validation:codex-0154"],
    )
    health = SimpleNamespace(
        integration_instance_id="integration-codex",
        callback_authenticated=True,
        evidence_flowing=True,
        observed_at=now,
        expires_at=now.replace(hour=13),
        evidence_ref="native-health:codex-0154",
    )
    accepted = derive_provider_capability_manifests(
        now=now,
        integrations=(integration,),
        validations=(validation,),
        health_observations=(health,),
        capability_profiles=(
            SimpleNamespace(
                id="profile-codex",
                provider="openai",
                product="codex",
                integration_method="native_hook",
                adapter_version="1.0.0",
                current_verified_version="0.154.0",
                supported_action_classes=["prompt"],
                contract_hash="b" * 64,
            ),
        ),
    )
    codex = next(
        row
        for row in accepted
        if row["provider"] == "openai"
        and row["product"] == "codex"
        and row["method"] == "native_hook"
    )
    assert codex["tenant_state"] == "VERIFIED"
    assert codex["validation_tier"] == "LOCAL_INTEGRATION_VERIFIED"
    assert codex["exact_version"] == "0.154.0"
    assert codex["evidence_age_seconds"] == 0
    assert set(codex["dimensions"].values()) <= {"VERIFIED", "UNSUPPORTED", "UNKNOWN"}

    mismatched = derive_provider_capability_manifests(
        now=now,
        integrations=(integration,),
        validations=(
            SimpleNamespace(
                **{
                    **validation.__dict__,
                    "provider_version": "0.147.0",
                }
            ),
        ),
        health_observations=(health,),
        capability_profiles=(
            SimpleNamespace(
                id="profile-codex",
                provider="openai",
                product="codex",
                integration_method="native_hook",
                adapter_version="1.0.0",
                current_verified_version="0.154.0",
                supported_action_classes=["prompt"],
                contract_hash="b" * 64,
            ),
        ),
    )
    mismatched_codex = next(
        row
        for row in mismatched
        if row["provider"] == "openai"
        and row["product"] == "codex"
        and row["method"] == "native_hook"
    )
    assert mismatched_codex["tenant_state"] == "PARTIAL"
    assert mismatched_codex["validation_tier"] == "UNVERIFIED"
    assert "VERIFIED" not in mismatched_codex["dimensions"].values()


def test_account_device_and_meeting_summaries_use_observed_controls_only() -> None:
    now = datetime(2026, 9, 9, 12, tzinfo=UTC)
    account_device = derive_account_device_summary(
        endpoints=(
            SimpleNamespace(
                endpoint_id="managed-1",
                metadata_json={"device_assurance": "MANAGED_COMPLIANT"},
            ),
            SimpleNamespace(
                endpoint_id="hostname-is-not-authority",
                metadata_json={},
            ),
        ),
        actions=(
            SimpleNamespace(
                action_type="download_output",
                enforcement_action="block",
                metadata_json={"device_assurance": "UNMANAGED"},
            ),
        ),
        account_receipts=(
            SimpleNamespace(
                decision="BLOCK_UNKNOWN",
                account_class="ENTERPRISE_MANAGED",
                provider="anthropic",
                product="claude",
                surface="browser",
                issued_at=now,
                control_point="managed_browser",
                blind_spots=["download_control_unavailable"],
            ),
        ),
    )
    assert account_device["managed_compliant_devices"] == 1
    assert account_device["unknown_devices"] == 1
    assert account_device["blocked_sensitive_downloads"] == 1
    assert account_device["corporate_session_denials"] == 1

    meeting = derive_meeting_ai_summary(
        signals=(
            SimpleNamespace(
                signal_type="browser.meeting_ai_notetaker_detected",
                payload={"notetaker_provider": "fireflies", "meeting_surface": "teams"},
                created_at=now,
            ),
            SimpleNamespace(
                signal_type="browser.meeting_ai_notetaker_block_requested",
                payload={"notetaker_provider": "fireflies", "meeting_surface": "teams"},
                created_at=now,
            ),
        ),
        platform_evidence=(
            SimpleNamespace(
                signal_type="endpoint.notetaker.platform_action",
                payload={
                    "platform": "teams",
                    "provider_control_path": "microsoft_graph",
                    "action": "remove_meeting_participant",
                    "notetaker_label": "Fireflies.ai",
                    "notetaker_email": "bot@fireflies.ai",
                    "performed": True,
                    "control_mode": "external_action_triggered",
                    "status_code": 204,
                    "source_detection_evidence_id": "evidence-calendar-1",
                    "graph_operation": {
                        "method": "POST",
                        "path": "/teams/meeting-123/participants/participant-456/remove",
                    },
                },
                created_at=now,
            ),
        ),
    )
    assert meeting["detected_attempts"] == 1
    assert meeting["block_requests"] == 1
    assert meeting["performed_platform_actions"] == 1
    assert meeting["teams_enforcement_state"] == "VERIFIED"
    assert meeting["physical_recording_blind_spot"] == "UNSUPPORTED"
