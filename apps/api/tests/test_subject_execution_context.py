from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError


def _now() -> datetime:
    return datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


def _resource_scope(*, expires_at: datetime | None = None):
    from app.services.subject_execution_context_service import AuthorizedResourceScope

    return AuthorizedResourceScope(
        resource_type="account",
        resource_reference="acct-ref-001",
        relationship_to_subject="owner",
        allowed_operations=("read_summary", "list_transactions"),
        expires_at=expires_at or (_now() + timedelta(minutes=5)),
        source_of_authority="bank_api_gateway",
    )


def _subject_context():
    from app.services.subject_execution_context_service import SubjectExecutionContext

    return SubjectExecutionContext(
        tenant_id="tenant-a",
        subject_type="customer",
        subject_id="customer-001",
        authenticated_principal_id="principal-001",
        session_id="session-001",
        channel="mobile_banking",
        device_trust_ref="device-trust-001",
        approved_resource_scopes=(_resource_scope(),),
        approved_account_ids=("acct-ref-001",),
        purpose_id="own-account-summary",
        authority_scope=("account.read_summary", "account.list_transactions"),
        auth_time=_now() - timedelta(minutes=1),
        issued_at=_now(),
        expires_at=_now() + timedelta(minutes=5),
        nonce="nonce-0000000001",
        provenance="bank_api_gateway",
        trust_level="hardware_bound_session",
        source_system="bank-mobile-api",
        policy_version="bank-policy-v2",
    )


def test_subject_execution_context_is_immutable_and_contains_no_token_fields() -> None:
    context = _subject_context()

    with pytest.raises(ValidationError):
        context.subject_id = "attacker-subject"

    serialized = context.model_dump(mode="json")
    assert serialized["subject_id"] == "customer-001"
    assert not {"access_token", "refresh_token", "subject_assertion"} & set(serialized)


@pytest.mark.parametrize(
    "provenance",
    ("prompt", "tool_argument", "rag_document", "model_response", "agent_memory"),
)
def test_untrusted_provenance_cannot_establish_authoritative_subject(
    provenance: str,
) -> None:
    from app.services.subject_execution_context_service import SubjectExecutionContext

    payload = _subject_context().model_dump()
    payload["provenance"] = provenance

    with pytest.raises(ValidationError, match="authoritative provenance"):
        SubjectExecutionContext.model_validate(payload)


def test_resource_authorization_requires_exact_resource_operation_and_fresh_scope() -> None:
    from app.services.subject_execution_context_service import authorize_scoped_resource

    context = _subject_context()
    allowed = authorize_scoped_resource(
        context,
        resource_type="account",
        resource_reference="acct-ref-001",
        operation="read_summary",
        now=_now(),
    )
    wrong_resource = authorize_scoped_resource(
        context,
        resource_type="account",
        resource_reference="acct-ref-999",
        operation="read_summary",
        now=_now(),
    )
    wrong_operation = authorize_scoped_resource(
        context,
        resource_type="account",
        resource_reference="acct-ref-001",
        operation="transfer",
        now=_now(),
    )
    expired_payload = context.model_dump()
    expired_payload["approved_resource_scopes"] = (
        _resource_scope(expires_at=_now() - timedelta(seconds=1)),
    )
    expired = authorize_scoped_resource(
        type(context).model_validate(expired_payload),
        resource_type="account",
        resource_reference="acct-ref-001",
        operation="read_summary",
        now=_now(),
    )

    assert (allowed.authorized, allowed.reason_code) == (True, "RESOURCE_SCOPE_MATCHED")
    assert (wrong_resource.authorized, wrong_resource.reason_code) == (
        False,
        "RESOURCE_OUTSIDE_SUBJECT_SCOPE",
    )
    assert (wrong_operation.authorized, wrong_operation.reason_code) == (
        False,
        "OPERATION_OUTSIDE_SUBJECT_SCOPE",
    )
    assert (expired.authorized, expired.reason_code) == (
        False,
        "RESOURCE_SCOPE_EXPIRED",
    )


def test_authority_attenuation_blocks_child_expansion() -> None:
    from app.services.subject_execution_context_service import attenuate_authority

    assert attenuate_authority(
        parent_authority=("account.read_summary", "account.list_transactions"),
        requested_child_authority=("account.read_summary",),
    ) == ("account.read_summary",)

    with pytest.raises(ValueError, match="AUTHORITY_EXPANSION"):
        attenuate_authority(
            parent_authority=("account.read_summary",),
            requested_child_authority=("account.read_summary", "account.transfer"),
        )


@pytest.mark.parametrize(
    ("identity_type", "authentication_mode", "expected_quality", "shared"),
    (
        ("published_agent", "managed_identity", "dedicated_agent_identity", False),
        ("project_managed_identity", "managed_identity", "project_shared_identity", True),
        ("oauth_passthrough_user", "oauth_passthrough", "verified_end_user", False),
        ("service_principal", "client_credential", "application_identity", False),
        ("shared_credential", "api_key", "shared_credential", True),
        ("anonymous", "none", "anonymous", True),
    ),
)
def test_microsoft_identity_quality_is_server_derived_and_shared_state_is_honest(
    identity_type: str,
    authentication_mode: str,
    expected_quality: str,
    shared: bool,
) -> None:
    from app.services.subject_execution_context_service import resolve_execution_identity

    identity = resolve_execution_identity(
        tenant_id="tenant-a",
        identity_type=identity_type,
        principal_reference=f"principal:{identity_type}",
        authentication_mode=authentication_mode,
        source_system="microsoft_entra",
        provenance="verified_entra_claims",
    )

    assert identity.identity_quality == expected_quality
    assert identity.shared_authority is shared
    assert identity.authoritative is (identity_type not in {"anonymous", "shared_credential"})


def test_subject_expiry_and_revocation_fail_closed() -> None:
    from app.services.subject_execution_context_service import validate_subject_liveness

    context = _subject_context()
    assert validate_subject_liveness(context, now=_now()).active is True

    expired_payload = context.model_dump()
    expired_payload["auth_time"] = _now() - timedelta(minutes=2)
    expired_payload["issued_at"] = _now() - timedelta(minutes=1)
    expired_payload["expires_at"] = _now() - timedelta(seconds=1)
    expired_payload["approved_resource_scopes"] = (
        _resource_scope(expires_at=_now() - timedelta(seconds=1)),
    )
    expired = type(context).model_validate(expired_payload)
    assert validate_subject_liveness(expired, now=_now()).reason_code == "SUBJECT_CONTEXT_EXPIRED"

    revoked_payload = context.model_dump()
    revoked_payload["revoked_at"] = _now() - timedelta(seconds=1)
    revoked = type(context).model_validate(revoked_payload)
    assert validate_subject_liveness(revoked, now=_now()).reason_code == "SUBJECT_CONTEXT_REVOKED"
