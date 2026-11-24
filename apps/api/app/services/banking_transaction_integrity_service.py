from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_engine.authorization import (
    AuthorizationDecision,
    AuthorizationRequest,
    AuthorizationResponse,
    authorize_ai_action,
)
from app.db.models.banking_transaction import BankingExecutionGrant
from app.db.models.evidence import (
    DecisionReceipt,
    EvidenceNode,
    ExecutionIntegrityResult,
    ExecutionReceipt,
)
from app.db.models.policy import ToolFingerprint
from app.services.banking_transport_control_service import (
    BankingTransportAction,
    BankingTransportBinding,
    BankingTransportProjection,
    canonicalize_banking_transport_action,
)
from app.services.banking_subject_context_service import (
    BankingSubjectContextError,
    ValidatedBankingSubject,
    fingerprint_banking_value,
    validate_and_bind_banking_subject_context,
)
from app.services.banking_response_assurance_service import (
    BankingEvidenceSource,
    BankingResponseAssurancePolicy,
    BankingResponseAssuranceRequest,
    BankingResponseAssuranceResult,
    BankingStructuredResultEnvelope,
    assure_banking_response,
    build_banking_response_evidence_node,
)
from app.services.receipt_service import (
    canonical_action_from_authorization,
    create_execution_receipt,
    persist_pre_execution_decision_isolated,
    validate_pre_execution,
    verify_decision_receipt,
)
from app.services.subject_execution_context_service import (
    ExecutionIdentity,
    resolve_execution_identity,
)


BANKING_COLLECTOR_ID = "banking-dotnet-sdk"
MAX_ARGUMENT_BYTES = 65_536
EXECUTION_GRANT_LIFETIME_SECONDS = 30


class BankingActionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_assertion: str = Field(min_length=32, max_length=16_384, repr=False)
    ai_transaction_id: str = Field(min_length=1, max_length=64)
    action_id: str = Field(min_length=1, max_length=64)
    chain_id: str = Field(min_length=1, max_length=64)
    ai_system_id: str = Field(min_length=1, max_length=64)
    source_agent_id: str = Field(min_length=1, max_length=128)
    delegated_agent_ids: tuple[str, ...] = Field(default=(), max_length=32)
    action_type: Literal["tool_execution", "api_call"]
    operation_type: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=255)
    tool_version: str = Field(min_length=1, max_length=64)
    tool_schema_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    arguments: dict[str, Any]
    requested_customer_subject_id: str = Field(min_length=1, max_length=256, repr=False)
    requested_account_id: str = Field(min_length=1, max_length=256, repr=False)
    requested_resource: str = Field(min_length=1, max_length=512, repr=False)
    destination: str = Field(min_length=1, max_length=512)
    workload_identity: str = Field(min_length=1, max_length=256)
    workload_identity_type: Literal[
        "published_agent",
        "project_managed_identity",
        "oauth_passthrough_user",
        "service_principal",
        "application_identity",
        "shared_credential",
        "anonymous",
        "unknown",
    ]
    workload_authentication_mode: str = Field(min_length=1, max_length=64)
    workload_identity_source: str = Field(min_length=1, max_length=128)
    workload_identity_provenance: Literal[
        "verified_entra_claims",
        "verified_oidc_claims",
        "bank_identity_service",
        "trusted_session_broker",
    ]
    side_effect_class: Literal["read_only", "reversible", "persistent"]
    policy_snapshot_id: str = Field(min_length=1, max_length=64)
    transport_binding: BankingTransportBinding | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_json_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("banking action arguments must be canonical JSON") from exc
        if len(encoded) > MAX_ARGUMENT_BYTES:
            raise ValueError("banking action arguments exceed maximum size")
        return value


class BankingAuthorizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ai_transaction_id: str
    action_id: str
    chain_id: str
    decision: AuthorizationDecision
    reason_code: str
    control_mode: str
    decision_receipt_id: str
    canonical_action: dict[str, Any]
    subject: ValidatedBankingSubject


class BankingPreExecutionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_receipt_id: str = Field(min_length=1, max_length=36)
    execution_attempt_id: str = Field(min_length=1, max_length=128)
    final_action: BankingActionPayload


class BankingPreExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    executable: bool
    integrity_result_id: str | None = None
    execution_grant_id: str | None = None
    grant_expires_at: datetime | None = None


class BankingExecutionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_receipt_id: str = Field(min_length=1, max_length=36)
    execution_grant_id: str = Field(min_length=1, max_length=36)
    execution_attempt_id: str = Field(min_length=1, max_length=128)
    execution_status: Literal["success", "failure"]


class BankingExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_receipt_id: str
    integrity_result_id: str
    integrity: str
    drift_fields: tuple[str, ...] = ()


class BankingModelRequestPayload(BaseModel):
    """Prompt-free model-path material authorized before provider invocation."""

    model_config = ConfigDict(extra="forbid")

    subject_assertion: str = Field(min_length=32, max_length=16_384, repr=False)
    ai_transaction_id: str = Field(min_length=1, max_length=64)
    action_id: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    chain_id: str = Field(min_length=1, max_length=64)
    ai_system_id: str = Field(min_length=1, max_length=64)
    source_agent_id: str = Field(min_length=1, max_length=128)
    delegated_agent_ids: tuple[str, ...] = Field(default=(), max_length=32)
    provider: str = Field(min_length=1, max_length=128)
    deployment: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=128)
    request_classification: Literal[
        "public",
        "internal",
        "confidential",
        "restricted",
    ]
    session_id: str = Field(min_length=1, max_length=128, repr=False)
    streaming: bool = False
    destination: str = Field(min_length=1, max_length=512)
    request_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    workload_identity: str = Field(min_length=1, max_length=256)
    workload_identity_type: Literal[
        "published_agent",
        "project_managed_identity",
        "oauth_passthrough_user",
        "service_principal",
        "application_identity",
        "shared_credential",
        "anonymous",
        "unknown",
    ]
    workload_authentication_mode: str = Field(min_length=1, max_length=64)
    workload_identity_source: str = Field(min_length=1, max_length=128)
    workload_identity_provenance: Literal[
        "verified_entra_claims",
        "verified_oidc_claims",
        "bank_identity_service",
        "trusted_session_broker",
    ]
    policy_snapshot_id: str = Field(min_length=1, max_length=64)


class BankingModelAuthorizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ai_transaction_id: str
    action_id: str
    chain_id: str
    decision: AuthorizationDecision
    reason_code: str
    control_mode: str
    decision_receipt_id: str
    model_binding_verified: bool
    streaming_covered: bool


class BankingModelResponsePayload(BaseModel):
    """Response text never crosses this boundary; only classification and SHA-256 do."""

    model_config = ConfigDict(extra="forbid")

    decision_receipt_id: str = Field(min_length=1, max_length=36)
    ai_transaction_id: str = Field(min_length=1, max_length=64)
    action_id: str = Field(min_length=1, max_length=64)
    chain_id: str = Field(min_length=1, max_length=64)
    response_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_classification: Literal[
        "public",
        "internal",
        "confidential",
        "restricted",
    ]
    streaming: bool = False
    finish_reason: str = Field(min_length=1, max_length=64)


class BankingModelResponseResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal["allow", "redact", "regenerate", "safe_fallback", "block"]
    reason_code: str
    control_mode: str
    safe_response: str | None = None
    evidence_complete: bool
    decision_receipt_id: str


class BankingStructuredResponsePayload(BaseModel):
    """Client material only; response policy is always selected server-side."""

    model_config = ConfigDict(extra="forbid")

    decision_receipt_id: str = Field(min_length=1, max_length=36)
    authorized_customer_fingerprint: str
    authorized_account_fingerprint: str
    trusted_result: BankingStructuredResultEnvelope
    candidate_claims: dict[str, Any]
    regeneration_attempt: int = Field(default=0, ge=0, le=1)
    evidence_source: BankingEvidenceSource


class BankingStructuredResponseResult(BankingResponseAssuranceResult):
    """Response release decision plus its safe existing-EvidenceNode projection."""

    evidence_node_id: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class _DerivedBankingTarget:
    account_id: str
    resource: str
    resource_type: str
    operation: str
    declaration_matches_execution: bool


@dataclass(frozen=True)
class _BankingEvaluation:
    subject: ValidatedBankingSubject
    request: AuthorizationRequest
    response: AuthorizationResponse
    reason_code: str


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _server_policy_profile(settings_obj: Any) -> dict[str, Any]:
    try:
        profile = json.loads(
            str(getattr(settings_obj, "banking_transaction_policy_profile_json", "{}"))
        )
    except json.JSONDecodeError as exc:
        raise BankingSubjectContextError("banking transaction policy profile is invalid") from exc
    if not isinstance(profile, dict) or not profile:
        raise BankingSubjectContextError("banking transaction policy profile is unavailable")
    return profile


def _derive_banking_target(
    profile: dict[str, Any],
    *,
    payload: BankingActionPayload,
) -> _DerivedBankingTarget:
    approved_tools = profile.get("approved_tools")
    tool = approved_tools.get(payload.tool_name) if isinstance(approved_tools, dict) else None
    binding = tool.get("target_binding") if isinstance(tool, dict) else None
    if not isinstance(binding, dict):
        return _DerivedBankingTarget(
            account_id="unresolved-account-target",
            resource="unresolved-resource-target",
            resource_type="unknown",
            operation="unknown",
            declaration_matches_execution=False,
        )
    account_argument = binding.get("account_argument")
    configured_resource = binding.get("resource")
    customer_source = binding.get("customer_source")
    resource_type = str(binding.get("resource_type") or "").strip()
    operation = str(binding.get("operation") or "").strip()
    raw_account = (
        payload.arguments.get(account_argument)
        if isinstance(account_argument, str) and account_argument
        else None
    )
    account_id = str(raw_account).strip() if isinstance(raw_account, str) else ""
    resource = (
        str(configured_resource).strip()
        if isinstance(configured_resource, str)
        else ""
    )
    valid = bool(
        account_id
        and len(account_id) <= 256
        and resource
        and len(resource) <= 512
        and customer_source == "signed_subject"
        and resource_type
        and len(resource_type) <= 64
        and operation
        and len(operation) <= 128
        and payload.operation_type == operation
    )
    return _DerivedBankingTarget(
        account_id=account_id or "invalid-account-target",
        resource=resource or "invalid-resource-target",
        resource_type=resource_type or "invalid-resource-type",
        operation=operation or "invalid-operation",
        declaration_matches_execution=bool(
            valid
            and payload.requested_account_id == account_id
            and payload.requested_resource == resource
        ),
    )


def _runtime_binding_matches(
    profile: dict[str, Any],
    *,
    payload: BankingActionPayload,
    subject: ValidatedBankingSubject,
) -> bool:
    approved_systems = profile.get("approved_ai_system_ids")
    approved_tools = profile.get("approved_tools")
    approved_destinations = profile.get("approved_destinations")
    approved_workloads = profile.get("approved_workload_identities")
    approved_identity_types = profile.get("approved_workload_identity_types")
    approved_auth_modes = profile.get("approved_workload_authentication_modes")
    approved_operations = profile.get("approved_operation_types")
    allowed_purposes = profile.get("allowed_purpose_ids")
    expected_snapshot = profile.get("policy_snapshot_id")
    tool = approved_tools.get(payload.tool_name) if isinstance(approved_tools, dict) else None
    return bool(
        isinstance(approved_systems, list)
        and payload.ai_system_id in approved_systems
        and isinstance(tool, dict)
        and tool.get("version") == payload.tool_version
        and tool.get("schema_fingerprint") == payload.tool_schema_fingerprint
        and isinstance(approved_destinations, list)
        and payload.destination in approved_destinations
        and isinstance(approved_workloads, list)
        and payload.workload_identity in approved_workloads
        and isinstance(approved_identity_types, list)
        and payload.workload_identity_type in approved_identity_types
        and isinstance(approved_auth_modes, list)
        and payload.workload_authentication_mode in approved_auth_modes
        and isinstance(approved_operations, list)
        and payload.operation_type in approved_operations
        and isinstance(allowed_purposes, list)
        and subject.purpose_id in allowed_purposes
        and isinstance(expected_snapshot, str)
        and bool(expected_snapshot)
        and payload.policy_snapshot_id == expected_snapshot
    )


def _transport_projection(
    db: Session,
    *,
    tenant_id: str,
    payload: BankingActionPayload,
    subject: ValidatedBankingSubject,
    derived_target: _DerivedBankingTarget,
) -> BankingTransportProjection:
    binding = payload.transport_binding or BankingTransportBinding(
        transport="function",
        route_id=f"microsoft-agent-framework:{payload.tool_name}",
        authentication_mode=payload.workload_authentication_mode,
        direct_bypass=False,
        function_manifest_id=(
            f"function:{payload.tool_name}:{payload.tool_version}:"
            f"{payload.tool_schema_fingerprint}"
        ),
    )
    inventory_record: ToolFingerprint | None = None
    if binding.transport in {"mcp", "toolbox"}:
        inventory_record = db.scalar(
            select(ToolFingerprint).where(
                ToolFingerprint.tenant_id == tenant_id,
                ToolFingerprint.id == binding.mcp_tool_fingerprint_id,
            )
        )
    projection = canonicalize_banking_transport_action(
        BankingTransportAction(
            tenant_id=tenant_id,
            ai_transaction_id=payload.ai_transaction_id,
            action_id=payload.action_id,
            chain_id=payload.chain_id,
            business_purpose_id=subject.purpose_id,
            operation_type=payload.operation_type,
            tool_name=payload.tool_name,
            tool_version=payload.tool_version,
            tool_schema_fingerprint=payload.tool_schema_fingerprint,
            arguments=payload.arguments,
            target_resource_type=derived_target.resource_type,
            target_resource_reference=derived_target.account_id,
            target_resolver_version="bank-policy-target-binding-v1",
            destination=payload.destination,
            identity_type=payload.workload_identity_type,
            side_effect_class=payload.side_effect_class,
            persistent_side_effect=payload.side_effect_class == "persistent",
            idempotency_key_hash=_sha256(
                {
                    "ai_transaction_id": payload.ai_transaction_id,
                    "action_id": payload.action_id,
                }
            ),
            transport_binding=binding,
        ),
        mcp_inventory_record=inventory_record,
    )
    if binding.authentication_mode != payload.workload_authentication_mode:
        return projection.model_copy(
            update={
                "control_requirement_satisfied": False,
                "reason_code": "TRANSPORT_IDENTITY_BINDING_MISMATCH",
            }
        )
    return projection


def _destination_class(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "internal" or normalized.endswith(".internal"):
        return "internal"
    return "external"


def _authorization_request(
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingActionPayload,
    subject: ValidatedBankingSubject,
    precondition_block: bool,
    target_binding_verified: bool,
    boundary_verified: bool,
    runtime_binding_verified: bool,
    transport_projection: BankingTransportProjection,
    policy_profile: dict[str, Any],
    requested_customer_hash: str,
    requested_account_hash: str,
    requested_resource_hash: str,
    destination_hash: str,
    workload_identity_hash: str,
    execution_identity: ExecutionIdentity,
) -> AuthorizationRequest:
    profile = dict(policy_profile)
    if precondition_block:
        profile = {
            **profile,
            "base_decision": "block",
            "dependencies_healthy": True,
            "degraded_behavior": "block",
            "triggered_controls": sorted(
                {
                    *list(profile.get("triggered_controls") or []),
                    (
                        "BANK_EXECUTABLE_TARGET_BINDING"
                        if not target_binding_verified
                        else (
                            "BANK_CUSTOMER_SCOPE_BOUNDARY"
                            if not boundary_verified
                            else (
                                "BANK_RUNTIME_BINDING"
                                if not runtime_binding_verified
                                else "BANK_TRANSPORT_BINDING"
                            )
                        )
                    ),
                }
            ),
        }
    target_binding_hash = _sha256(
        {
            "customer_subject_hash": requested_customer_hash,
            "account_hash": requested_account_hash,
            "resource_hash": requested_resource_hash,
        }
    )
    destination_class = _destination_class(payload.destination)
    parameter_hash = transport_projection.semantic_action_hash
    transport = payload.transport_binding or BankingTransportBinding(
        transport="function",
        route_id=f"microsoft-agent-framework:{payload.tool_name}",
        authentication_mode=payload.workload_authentication_mode,
        direct_bypass=False,
        function_manifest_id=(
            f"function:{payload.tool_name}:{payload.tool_version}:"
            f"{payload.tool_schema_fingerprint}"
        ),
    )
    return AuthorizationRequest(
        tenant_id=tenant_id,
        environment="production",
        collector_id=BANKING_COLLECTOR_ID,
        action_id=payload.action_id,
        chain_id=payload.chain_id,
        surface="runtime_control",
        actor={
            "identity_id": subject.customer_subject_hash,
            "user_id": actor_user_id,
            "customer_subject_hash": subject.customer_subject_hash,
            "subject_type": subject.subject_type,
            "authenticated_principal_hash": subject.authenticated_principal_hash,
            "subject_provenance": subject.identity_provenance,
            "subject_context_digest": subject.context_digest,
            "mobile_session_hash": subject.mobile_session_hash,
            "ai_transaction_id": payload.ai_transaction_id,
            "source_agent_id": payload.source_agent_id,
            "delegated_agent_ids": list(payload.delegated_agent_ids),
        },
        authority={
            "authority_type": "customer_delegated_workload",
            "authority_source": "signed_banking_subject_context",
            "verified": True,
            "originating_customer_hash": subject.customer_subject_hash,
            "requested_customer_hash": requested_customer_hash,
            "approved_account_hashes": list(subject.approved_account_hashes),
            "requested_account_hash": requested_account_hash,
            "executable_target_binding_verified": target_binding_verified,
            "workload_identity_hash": workload_identity_hash,
            "permission_scope": list(subject.approved_resource_hashes),
            "authority_scope": list(subject.authority_scope),
            "device_trust_hash": subject.device_trust_hash,
            "workload_identity_type": execution_identity.identity_type,
            "workload_identity_quality": execution_identity.identity_quality,
            "workload_authentication_mode": execution_identity.authentication_mode,
            "workload_identity_source": execution_identity.source_system,
            "workload_identity_provenance": execution_identity.provenance,
            "workload_identity_authoritative": execution_identity.authoritative,
            "shared_authority": execution_identity.shared_authority,
            "transport_identity_quality": transport_projection.identity_quality,
            "transport_shared_authority": transport_projection.shared_authority,
            "transport_authentication_mode": transport.authentication_mode,
        },
        runtime={
            "runtime_instance_id": payload.ai_system_id,
            "session_id": subject.mobile_session_hash,
            "ai_transaction_id": payload.ai_transaction_id,
        },
        purpose={
            "declared_purpose": subject.purpose_id,
            "purpose_id": subject.purpose_id,
            "purpose_status": "verified",
            "context_digest": subject.context_digest,
            "requested_policy_snapshot_id": payload.policy_snapshot_id,
        },
        action={
            "action_type": payload.action_type,
            "operation_type": payload.operation_type,
            "risk_level": (
                "high"
                if precondition_block or payload.side_effect_class != "read_only"
                else "low"
            ),
            "side_effect_class": payload.side_effect_class,
            "ai_transaction_id": payload.ai_transaction_id,
            "semantic_action_hash": transport_projection.semantic_action_hash,
            "transport_binding_verified": (
                transport_projection.control_requirement_satisfied
            ),
        },
        tool={
            "name": payload.tool_name,
            "version": payload.tool_version,
            "fingerprint_id": transport_projection.execution_binding_hash,
            "schema_fingerprint": payload.tool_schema_fingerprint,
        },
        parameters={"parameter_hash": parameter_hash},
        target={
            "resource": "banking_resource",
            "resource_hash": target_binding_hash,
            "destination": destination_class,
            "destination_hash": destination_hash,
        },
        data_context={
            "input_sensitivity": "confidential",
            "customer_scoped": True,
            "raw_customer_data_persisted": False,
        },
        approval_context={},
        jit_context={},
        taint_context={"taint_labels": ["bank_customer_data"]},
        side_effect_context={
            "side_effect_class": payload.side_effect_class,
            "persistent_side_effect": payload.side_effect_class == "persistent",
        },
        discovery_context={
            "application": "microsoft-agent-framework",
            "provider": "microsoft",
            "model": "foundry-agent",
            "asset_status": "approved" if runtime_binding_verified else "unknown",
            "transport": transport.transport,
            "route_id": transport.route_id,
            "destination_class": destination_class,
            "execution_binding_hash": transport_projection.execution_binding_hash,
            "transport_reason_code": transport_projection.reason_code,
        },
        policy_snapshot_id=str(policy_profile.get("policy_snapshot_id") or ""),
        policy_profile=profile,
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
            "execution_prevented": precondition_block,
            "telemetry_observation": False,
            "native_control_requirement_satisfied": (
                transport_projection.control_requirement_satisfied
            ),
        },
    )


def _evaluate_banking_action(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingActionPayload,
    settings_obj: Any,
) -> _BankingEvaluation:
    subject = validate_and_bind_banking_subject_context(
        db,
        tenant_id=tenant_id,
        ai_transaction_id=payload.ai_transaction_id,
        compact_assertion=payload.subject_assertion,
        settings_obj=settings_obj,
    )
    policy_profile = _server_policy_profile(settings_obj)
    derived_target = _derive_banking_target(policy_profile, payload=payload)
    requested_customer_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="customer_subject",
        value=payload.requested_customer_subject_id,
        settings_obj=settings_obj,
    )
    requested_account_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="account",
        value=derived_target.account_id,
        settings_obj=settings_obj,
    )
    requested_resource_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="resource",
        value=derived_target.resource,
        settings_obj=settings_obj,
    )
    destination_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="destination",
        value=payload.destination,
        settings_obj=settings_obj,
    )
    workload_identity_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="workload_identity",
        value=payload.workload_identity,
        settings_obj=settings_obj,
    )
    execution_identity = resolve_execution_identity(
        tenant_id=tenant_id,
        identity_type=payload.workload_identity_type,
        principal_reference=payload.workload_identity,
        authentication_mode=payload.workload_authentication_mode,
        source_system=payload.workload_identity_source,
        provenance=payload.workload_identity_provenance,
    )
    target_binding_verified = derived_target.declaration_matches_execution
    resource_scope_verified = any(
        scope.get("resource_type") == derived_target.resource_type
        and scope.get("resource_reference_hash") == requested_account_hash
        and derived_target.operation in list(scope.get("allowed_operations") or [])
        and datetime.fromisoformat(str(scope.get("expires_at")))
        > datetime.now(timezone.utc)
        for scope in subject.resource_scope_hashes
    )
    boundary_verified = bool(
        requested_customer_hash == subject.customer_subject_hash
        and requested_account_hash in subject.approved_account_hashes
        and requested_resource_hash in subject.approved_resource_hashes
        and resource_scope_verified
    )
    runtime_binding_verified = _runtime_binding_matches(
        policy_profile,
        payload=payload,
        subject=subject,
    )
    transport_projection = _transport_projection(
        db,
        tenant_id=tenant_id,
        payload=payload,
        subject=subject,
        derived_target=derived_target,
    )
    precondition_block = not (
        target_binding_verified
        and boundary_verified
        and runtime_binding_verified
        and transport_projection.control_requirement_satisfied
    )
    request = _authorization_request(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        payload=payload,
        subject=subject,
        precondition_block=precondition_block,
        target_binding_verified=target_binding_verified,
        boundary_verified=boundary_verified,
        runtime_binding_verified=runtime_binding_verified,
        transport_projection=transport_projection,
        policy_profile=policy_profile,
        requested_customer_hash=requested_customer_hash,
        requested_account_hash=requested_account_hash,
        requested_resource_hash=requested_resource_hash,
        destination_hash=destination_hash,
        workload_identity_hash=workload_identity_hash,
        execution_identity=execution_identity,
    )
    response = authorize_ai_action(request)
    if precondition_block and response.decision != "block":
        raise BankingSubjectContextError("banking precondition failed closed")
    reason_code = (
        "bank_executable_target_mismatch"
        if not target_binding_verified
        else (
            "bank_customer_scope_mismatch"
            if not boundary_verified
            else (
                "bank_runtime_binding_mismatch"
                if not runtime_binding_verified
                else (
                    "bank_transport_binding_unverified"
                    if not transport_projection.control_requirement_satisfied
                    else response.reason
                )
            )
        )
    )
    return _BankingEvaluation(
        subject=subject,
        request=request,
        response=response,
        reason_code=reason_code,
    )


def authorize_banking_action(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingActionPayload,
    settings_obj: Any,
) -> BankingAuthorizationResult:
    evaluation = _evaluate_banking_action(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        payload=payload,
        settings_obj=settings_obj,
    )

    # Consuming a valid nonce is durable even if a later authorization dependency fails.
    # This also releases the transaction before the existing isolated receipt writer runs.
    db.commit()
    receipt, canonical_action = persist_pre_execution_decision_isolated(
        db,
        request=evaluation.request,
        response=evaluation.response,
        settings_obj=settings_obj,
    )
    if receipt is None:
        raise BankingSubjectContextError("banking decision receipt is unavailable")
    return BankingAuthorizationResult(
        ai_transaction_id=payload.ai_transaction_id,
        action_id=payload.action_id,
        chain_id=payload.chain_id,
        decision=evaluation.response.decision,
        reason_code=evaluation.reason_code,
        control_mode=evaluation.response.control_mode,
        decision_receipt_id=receipt.receipt_id,
        canonical_action=canonical_action,
        subject=evaluation.subject,
    )


def validate_banking_pre_execution(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingPreExecutionPayload,
    settings_obj: Any,
) -> BankingPreExecutionResult:
    evaluation = _evaluate_banking_action(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        payload=payload.final_action,
        settings_obj=settings_obj,
    )
    actual_canonical_action = canonical_action_from_authorization(
        evaluation.request,
        evaluation.response,
    )
    allowed, integrity = validate_pre_execution(
        db,
        tenant_id=tenant_id,
        decision_receipt_id=payload.decision_receipt_id,
        actual_canonical_action=actual_canonical_action,
        settings_obj=settings_obj,
    )
    executable = bool(
        allowed and evaluation.response.decision in {"allow", "warn"}
    )
    if not executable:
        db.commit()
        return BankingPreExecutionResult(
            executable=False,
            integrity_result_id=integrity.result_id if integrity else None,
        )

    when = datetime.now(timezone.utc)
    canonical_hash = str(actual_canonical_action.get("canonical_action_hash") or "")
    if len(canonical_hash) != 64:
        raise BankingSubjectContextError("banking canonical action hash is unavailable")
    existing = db.scalar(
        select(BankingExecutionGrant)
        .where(
            BankingExecutionGrant.tenant_id == tenant_id,
            BankingExecutionGrant.decision_receipt_id
            == payload.decision_receipt_id,
            BankingExecutionGrant.execution_attempt_id
            == payload.execution_attempt_id,
        )
        .with_for_update()
    )
    if existing is not None:
        if existing.canonical_action_hash != canonical_hash:
            raise BankingSubjectContextError(
                "banking execution attempt material conflict"
            )
        if existing.consumed_at is not None:
            raise BankingSubjectContextError("banking execution grant is already consumed")
        if _utc(existing.expires_at) <= when:
            raise BankingSubjectContextError("banking execution grant is expired")
        grant = existing
    else:
        grant = BankingExecutionGrant(
            tenant_id=tenant_id,
            decision_receipt_id=payload.decision_receipt_id,
            execution_attempt_id=payload.execution_attempt_id,
            canonical_action=deepcopy(actual_canonical_action),
            canonical_action_hash=canonical_hash,
            issued_at=when,
            expires_at=when + timedelta(seconds=EXECUTION_GRANT_LIFETIME_SECONDS),
        )
        db.add(grant)
        db.flush()
    db.commit()
    return BankingPreExecutionResult(
        executable=True,
        integrity_result_id=None,
        execution_grant_id=grant.id,
        grant_expires_at=_utc(grant.expires_at),
    )


def report_banking_execution(
    db: Session,
    *,
    tenant_id: str,
    payload: BankingExecutionPayload,
    settings_obj: Any,
) -> BankingExecutionResult:
    when = datetime.now(timezone.utc)
    grant = db.scalar(
        select(BankingExecutionGrant)
        .where(
            BankingExecutionGrant.id == payload.execution_grant_id,
            BankingExecutionGrant.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if grant is None:
        raise ValueError("banking execution grant is missing")
    if (
        grant.decision_receipt_id != payload.decision_receipt_id
        or grant.execution_attempt_id != payload.execution_attempt_id
    ):
        raise ValueError("banking execution grant binding is invalid")
    if grant.consumed_at is not None:
        if (
            grant.execution_status != payload.execution_status
            or not grant.execution_receipt_id
            or not grant.integrity_result_id
        ):
            raise ValueError("banking execution grant is already consumed")
        integrity = db.get(ExecutionIntegrityResult, grant.integrity_result_id)
        if integrity is None:
            raise ValueError("execution integrity result is unavailable")
        return BankingExecutionResult(
            execution_receipt_id=grant.execution_receipt_id,
            integrity_result_id=grant.integrity_result_id,
            integrity=integrity.result,
            drift_fields=tuple(integrity.drift_fields or []),
        )
    if _utc(grant.expires_at) <= when:
        raise ValueError("banking execution grant is expired")

    try:
        execution, integrity = create_execution_receipt(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=payload.decision_receipt_id,
            actual_canonical_action=deepcopy(grant.canonical_action),
            execution_status=payload.execution_status,
            collector_id=BANKING_COLLECTOR_ID,
            settings_obj=settings_obj,
            execution_attempt_id=payload.execution_attempt_id,
        )
    except ValueError as exc:
        if "blocked or denied decision" in str(exc):
            raise ValueError(
                "blocked or denied decision cannot proceed to execution"
            ) from exc
        raise
    grant.consumed_at = when
    grant.execution_status = payload.execution_status
    grant.execution_receipt_id = execution.receipt_id
    grant.integrity_result_id = integrity.result_id
    db.commit()
    if integrity is None:
        raise ValueError("execution integrity result is unavailable")
    return BankingExecutionResult(
        execution_receipt_id=execution.receipt_id,
        integrity_result_id=integrity.result_id,
        integrity=integrity.result,
        drift_fields=tuple(integrity.drift_fields or []),
    )


def _model_binding_matches(
    profile: dict[str, Any],
    *,
    payload: BankingModelRequestPayload,
    subject: ValidatedBankingSubject,
) -> bool:
    approved_models = profile.get("approved_models")
    model_match = bool(
        isinstance(approved_models, dict)
        and any(
            isinstance(candidate, dict)
            and candidate.get("provider") == payload.provider
            and candidate.get("deployment") == payload.deployment
            and candidate.get("model") == payload.model
            for candidate in approved_models.values()
        )
    )
    return bool(
        model_match
        and payload.ai_system_id in list(profile.get("approved_ai_system_ids") or [])
        and payload.destination
        in list(profile.get("approved_model_destinations") or [])
        and payload.request_classification
        in list(profile.get("allowed_model_request_classifications") or [])
        and payload.workload_identity
        in list(profile.get("approved_workload_identities") or [])
        and payload.workload_identity_type
        in list(profile.get("approved_workload_identity_types") or [])
        and payload.workload_authentication_mode
        in list(profile.get("approved_workload_authentication_modes") or [])
        and subject.purpose_id in list(profile.get("allowed_purpose_ids") or [])
        and payload.policy_snapshot_id == profile.get("policy_snapshot_id")
    )


def _model_authorization_request(
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingModelRequestPayload,
    subject: ValidatedBankingSubject,
    execution_identity: ExecutionIdentity,
    policy_profile: dict[str, Any],
    precondition_block: bool,
    settings_obj: Any,
) -> AuthorizationRequest:
    profile = dict(policy_profile)
    if precondition_block:
        profile = {
            **profile,
            "base_decision": "block",
            "dependencies_healthy": True,
            "degraded_behavior": "block",
            "triggered_controls": sorted(
                {
                    *list(profile.get("triggered_controls") or []),
                    "BANK_MODEL_RUNTIME_BINDING",
                }
            ),
        }
    destination_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="model_destination",
        value=payload.destination,
        settings_obj=settings_obj,
    )
    workload_identity_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="workload_identity",
        value=payload.workload_identity,
        settings_obj=settings_obj,
    )
    session_hash = fingerprint_banking_value(
        tenant_id=tenant_id,
        kind="model_session",
        value=payload.session_id,
        settings_obj=settings_obj,
    )
    model_fingerprint = _sha256(
        {
            "provider": payload.provider,
            "deployment": payload.deployment,
            "model": payload.model,
            "streaming": payload.streaming,
        }
    )
    return AuthorizationRequest(
        tenant_id=tenant_id,
        environment="production",
        collector_id=BANKING_COLLECTOR_ID,
        action_id=payload.action_id,
        chain_id=payload.chain_id,
        surface="sdk",
        actor={
            "identity_id": subject.customer_subject_hash,
            "user_id": actor_user_id,
            "customer_subject_hash": subject.customer_subject_hash,
            "subject_type": subject.subject_type,
            "authenticated_principal_hash": subject.authenticated_principal_hash,
            "subject_context_digest": subject.context_digest,
            "subject_provenance": subject.identity_provenance,
            "ai_transaction_id": payload.ai_transaction_id,
            "run_id": payload.run_id,
            "source_agent_id": payload.source_agent_id,
            "delegated_agent_ids": list(payload.delegated_agent_ids),
        },
        authority={
            "authority_type": "customer_delegated_workload",
            "authority_source": "signed_banking_subject_context",
            "verified": True,
            "originating_customer_hash": subject.customer_subject_hash,
            "authority_scope": list(subject.authority_scope),
            "workload_identity_hash": workload_identity_hash,
            "workload_identity_type": execution_identity.identity_type,
            "workload_identity_quality": execution_identity.identity_quality,
            "workload_authentication_mode": execution_identity.authentication_mode,
            "workload_identity_source": execution_identity.source_system,
            "workload_identity_provenance": execution_identity.provenance,
            "workload_identity_authoritative": execution_identity.authoritative,
            "shared_authority": execution_identity.shared_authority,
        },
        runtime={
            "runtime_instance_id": payload.ai_system_id,
            "session_id": session_hash,
            "ai_transaction_id": payload.ai_transaction_id,
            "run_id": payload.run_id,
            "provider": payload.provider,
            "deployment": payload.deployment,
            "model": payload.model,
            "streaming": payload.streaming,
        },
        purpose={
            "declared_purpose": subject.purpose_id,
            "purpose_id": subject.purpose_id,
            "purpose_status": "verified",
            "context_digest": subject.context_digest,
        },
        action={
            "action_type": "model_request",
            "operation_type": "model_inference",
            "risk_level": "high" if precondition_block else "low",
            "side_effect_class": "read_only",
            "streaming": payload.streaming,
            "ai_transaction_id": payload.ai_transaction_id,
        },
        tool={
            "name": f"model:{payload.provider}:{payload.model}",
            "version": (
                "buffered_streaming" if payload.streaming else "non_streaming"
            ),
            "fingerprint_id": model_fingerprint,
        },
        parameters={"parameter_hash": payload.request_hash},
        target={
            "resource": "model_endpoint",
            "resource_hash": _sha256(
                {
                    "provider": payload.provider,
                    "deployment": payload.deployment,
                    "model": payload.model,
                }
            ),
            "destination": _destination_class(payload.destination),
            "destination_hash": destination_hash,
        },
        data_context={
            "input_sensitivity": payload.request_classification,
            "customer_scoped": True,
            "raw_prompt_persisted": False,
        },
        approval_context={},
        jit_context={},
        taint_context={"taint_labels": ["bank_customer_data"]},
        side_effect_context={
            "side_effect_class": "read_only",
            "persistent_side_effect": False,
        },
        discovery_context={
            "application": "microsoft-agent-framework",
            "provider": payload.provider,
            "model": payload.model,
            "asset_status": "approved" if not precondition_block else "unknown",
        },
        policy_snapshot_id=str(policy_profile.get("policy_snapshot_id") or ""),
        policy_profile=profile,
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
            "execution_prevented": precondition_block,
            "telemetry_observation": False,
        },
    )


def authorize_banking_model_request(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    payload: BankingModelRequestPayload,
    settings_obj: Any,
) -> BankingModelAuthorizationResult:
    subject = validate_and_bind_banking_subject_context(
        db,
        tenant_id=tenant_id,
        ai_transaction_id=payload.ai_transaction_id,
        compact_assertion=payload.subject_assertion,
        settings_obj=settings_obj,
    )
    profile = _server_policy_profile(settings_obj)
    execution_identity = resolve_execution_identity(
        tenant_id=tenant_id,
        identity_type=payload.workload_identity_type,
        principal_reference=payload.workload_identity,
        authentication_mode=payload.workload_authentication_mode,
        source_system=payload.workload_identity_source,
        provenance=payload.workload_identity_provenance,
    )
    model_binding_verified = _model_binding_matches(
        profile,
        payload=payload,
        subject=subject,
    )
    streaming_covered = bool(
        payload.streaming and profile.get("allow_buffered_streaming") is True
    )
    precondition_block = bool(
        not model_binding_verified or (payload.streaming and not streaming_covered)
    )
    request = _model_authorization_request(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        payload=payload,
        subject=subject,
        execution_identity=execution_identity,
        policy_profile=profile,
        precondition_block=precondition_block,
        settings_obj=settings_obj,
    )
    response = authorize_ai_action(request)
    if precondition_block and response.decision != "block":
        raise BankingSubjectContextError("banking model precondition failed closed")
    reason_code = (
        "bank_streaming_not_covered"
        if payload.streaming and not streaming_covered
        else (
            "bank_model_binding_mismatch"
            if not model_binding_verified
            else response.reason
        )
    )
    db.commit()
    receipt, _ = persist_pre_execution_decision_isolated(
        db,
        request=request,
        response=response,
        settings_obj=settings_obj,
    )
    if receipt is None:
        raise BankingSubjectContextError("banking model decision receipt is unavailable")
    return BankingModelAuthorizationResult(
        ai_transaction_id=payload.ai_transaction_id,
        action_id=payload.action_id,
        chain_id=payload.chain_id,
        decision=response.decision,
        reason_code=reason_code,
        control_mode=response.control_mode,
        decision_receipt_id=receipt.receipt_id,
        model_binding_verified=model_binding_verified,
        streaming_covered=streaming_covered,
    )


def validate_banking_model_response(
    db: Session,
    *,
    tenant_id: str,
    payload: BankingModelResponsePayload,
    settings_obj: Any,
) -> BankingModelResponseResult:
    receipt = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.receipt_id == payload.decision_receipt_id,
        )
    )
    if receipt is None or not verify_decision_receipt(
        receipt,
        tenant_id=tenant_id,
        settings_obj=settings_obj,
        db=db,
    ):
        raise ValueError("banking model decision receipt is invalid")
    if receipt.decision not in {"allow", "warn"}:
        raise ValueError("blocked model request cannot release a response")
    if receipt.action_id != payload.action_id or receipt.chain_id != payload.chain_id:
        raise ValueError("banking model response correlation is invalid")
    canonical_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == receipt.canonical_action_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    canonical = (
        dict((canonical_node.payload or {}).get("canonical_action") or {})
        if canonical_node is not None
        else {}
    )
    actor = canonical.get("actor") if isinstance(canonical, Mapping) else None
    action = canonical.get("action") if isinstance(canonical, Mapping) else None
    if not isinstance(actor, Mapping) or not isinstance(action, Mapping):
        raise ValueError("banking model canonical evidence is unavailable")
    if actor.get("ai_transaction_id") != payload.ai_transaction_id:
        raise ValueError("banking model transaction correlation is invalid")
    if action.get("action_type") != "model_request":
        raise ValueError("decision receipt is not a model request")
    expected_streaming_version = (
        "buffered_streaming" if payload.streaming else "non_streaming"
    )
    if action.get("tool_version") != expected_streaming_version:
        raise ValueError("banking model streaming correlation is invalid")

    profile = _server_policy_profile(settings_obj)
    blocked = payload.response_classification in list(
        profile.get("blocked_model_response_classifications") or []
    )
    return BankingModelResponseResult(
        decision="block" if blocked else "allow",
        reason_code=(
            "bank_model_response_classification_blocked"
            if blocked
            else "bank_model_response_allowed"
        ),
        control_mode="inline_prevented" if blocked else "inline_allowed",
        safe_response=None,
        evidence_complete=True,
        decision_receipt_id=receipt.receipt_id,
    )


def _banking_evidence_attestation_keys(settings_obj: Any) -> dict[str, str]:
    try:
        decoded = json.loads(
            str(getattr(settings_obj, "banking_evidence_attestation_keys_json", "{}"))
        )
    except json.JSONDecodeError as exc:
        raise ValueError("banking evidence attestation keyring is invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("banking evidence attestation keyring is invalid")
    keys: dict[str, str] = {}
    for raw_key_id, raw_secret in decoded.items():
        key_id = str(raw_key_id or "").strip()
        secret = str(raw_secret or "").strip()
        if not key_id or len(key_id) > 64 or len(secret) < 32:
            raise ValueError("banking evidence attestation keyring is incomplete")
        keys[key_id] = secret
    return keys


def assure_banking_structured_response(
    db: Session,
    *,
    tenant_id: str,
    payload: BankingStructuredResponsePayload,
    settings_obj: Any,
) -> BankingStructuredResponseResult:
    """Apply server policy to a response only after matched function execution proof."""

    receipt = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.receipt_id == payload.decision_receipt_id,
        )
    )
    if receipt is None or not verify_decision_receipt(
        receipt,
        tenant_id=tenant_id,
        settings_obj=settings_obj,
        db=db,
    ):
        raise ValueError("banking response decision receipt is invalid")
    if receipt.decision not in {"allow", "warn"}:
        raise ValueError("blocked banking action cannot release a response")
    execution = db.scalar(
        select(ExecutionReceipt)
        .where(
            ExecutionReceipt.tenant_id == tenant_id,
            ExecutionReceipt.decision_receipt_id == receipt.receipt_id,
            ExecutionReceipt.execution_status == "success",
        )
        .order_by(ExecutionReceipt.executed_at.desc())
    )
    if execution is None:
        raise ValueError("banking response requires successful execution evidence")
    integrity = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.tenant_id == tenant_id,
            ExecutionIntegrityResult.decision_receipt_id == receipt.receipt_id,
            ExecutionIntegrityResult.execution_receipt_id == execution.receipt_id,
            ExecutionIntegrityResult.result == "matched",
        )
    )
    if integrity is None:
        raise ValueError("banking response requires matched execution evidence")

    canonical_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == receipt.canonical_action_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    canonical = (
        dict((canonical_node.payload or {}).get("canonical_action") or {})
        if canonical_node is not None
        else {}
    )
    actor = canonical.get("actor") if isinstance(canonical, Mapping) else None
    authority = canonical.get("authority") if isinstance(canonical, Mapping) else None
    action = canonical.get("action") if isinstance(canonical, Mapping) else None
    if not all(isinstance(value, Mapping) for value in (actor, authority, action)):
        raise ValueError("banking response canonical evidence is unavailable")
    if (
        receipt.action_id != payload.trusted_result.action_id
        or actor.get("ai_transaction_id")
        != payload.trusted_result.ai_transaction_id
        or actor.get("customer_subject_hash")
        != payload.authorized_customer_fingerprint
        or payload.authorized_account_fingerprint
        not in list(authority.get("approved_account_hashes") or [])
        or action.get("tool_fingerprint_id")
        != payload.trusted_result.tool_fingerprint
    ):
        raise ValueError("banking response receipt binding is invalid")

    profile = _server_policy_profile(settings_obj)
    raw_policy = profile.get("response_assurance")
    if not isinstance(raw_policy, Mapping):
        raise ValueError("banking response assurance policy is unavailable")
    policy = BankingResponseAssurancePolicy.model_validate(dict(raw_policy))
    request = BankingResponseAssuranceRequest(
        decision_receipt_id=payload.decision_receipt_id,
        authorized_customer_fingerprint=payload.authorized_customer_fingerprint,
        authorized_account_fingerprint=payload.authorized_account_fingerprint,
        trusted_result=payload.trusted_result,
        candidate_claims=payload.candidate_claims,
        regeneration_attempt=payload.regeneration_attempt,
        policy=policy,
        evidence_source=payload.evidence_source,
    )
    result = assure_banking_response(
        request,
        attestation_keys=_banking_evidence_attestation_keys(settings_obj),
    )
    evidence = build_banking_response_evidence_node(
        tenant_id=tenant_id,
        request=request,
        result=result,
    )
    db.add(evidence)
    db.flush()
    response = BankingStructuredResponseResult(
        **result.model_dump(mode="python"),
        evidence_node_id=evidence.id,
        evidence=deepcopy(evidence.payload),
    )
    db.commit()
    return response
