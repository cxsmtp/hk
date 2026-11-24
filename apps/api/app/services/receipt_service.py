from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import event, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.evidence import (
    DecisionReceipt,
    EvidenceNode,
    ExecutionIntegrityResult,
    ExecutionReceipt,
)
from app.db.models.activity_audit import AIAction
from app.db.models.finding import Finding
from app.db.models.policy import ApprovalBinding
from app.db.models.native_control import NativeControlSelection
from app.db.models.runtime_intelligence import RuntimeEvent
from app.core.control_engine.authorization import (
    ALLOWED_DECISIONS,
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.core.control_engine.canonical_action import canonical_action_hash
from app.core.control_engine.canonical_action import ALLOWED_CONTROL_MODES
from app.core.observability import get_correlation_id
from app.services.evidence_service import create_evidence_node
from app.services.privacy_sanitizer import sanitize_privacy_payload


MAX_RECEIPT_MATERIAL_BYTES = 65_536
MAX_DOWNSTREAM_OBJECTS = 128
MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS = 128
ALLOWED_DOWNSTREAM_OBJECT_TYPES = frozenset(
    {
        "webhook",
        "scheduled_job",
        "workflow_automation",
        "oauth_application",
        "api_token",
        "service_account",
        "role_assignment",
        "mailbox_forwarding",
        "shared_link",
        "persistent_memory",
        "external_callback",
        "queue_subscription",
        "cicd_scheduled_trigger",
        "stored_instruction",
        "unknown",
        "other",
    }
)
DRIFT_FINDINGS = {
    "chain_id": "AGENT_CHAIN_DRIFT_AFTER_APPROVAL",
    "actor_hash": "ACTOR_DRIFT_AFTER_APPROVAL",
    "purpose_hash": "PURPOSE_DRIFT_AFTER_APPROVAL",
    "parameter_hash": "ARGUMENT_DRIFT_AFTER_APPROVAL",
    "target_resource_hash": "TARGET_DRIFT_AFTER_APPROVAL",
    "tool_fingerprint": "TOOL_VERSION_DRIFT_AFTER_APPROVAL",
    "authority_hash": "AUTHORITY_DRIFT_AFTER_APPROVAL",
    "destination_hash": "DESTINATION_DRIFT_AFTER_APPROVAL",
    "side_effect_class": "SIDE_EFFECT_DRIFT_AFTER_APPROVAL",
    "policy_snapshot_id": "POLICY_SNAPSHOT_DRIFT_AFTER_APPROVAL",
}
ALLOWED_EXECUTION_STATUSES = frozenset({"success", "failure", "unverified"})
EXECUTABLE_DECISIONS = frozenset({"allow", "warn", "redact"})
logger = logging.getLogger(__name__)


class ExecutionAttemptConflictError(ValueError):
    """A terminal execution attempt was reused with different material."""


def _refresh_canonical_bundle(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
) -> None:
    from app.services.canonical_evidence_bundle_service import (
        link_bundle_to_runtime_projections,
    )

    link_bundle_to_runtime_projections(
        db,
        tenant_id=tenant_id,
        decision_receipt_id=decision_receipt_id,
        settings_obj=settings_obj,
    )


def _safe_refresh_canonical_bundle(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    execution_attempt_id: str | None = None,
    execution_receipt_id: str | None = None,
    evidence_node_id: str | None = None,
) -> str:
    """Append bundle state without making signed terminal proof subordinate to it."""

    db.flush()
    try:
        with db.begin_nested():
            _refresh_canonical_bundle(
                db,
                tenant_id=tenant_id,
                decision_receipt_id=decision_receipt_id,
                settings_obj=settings_obj,
            )
            db.flush()
        status = "complete"
    except Exception as exc:
        status = "incomplete"
        logger.error(
            "canonical evidence bundle refresh incomplete",
            extra={
                "tenant_id": tenant_id,
                "decision_receipt_id": decision_receipt_id,
                "bundle_refresh_status": status,
                "reason_code": "bundle_refresh_failed",
                "error_type": exc.__class__.__name__,
            },
        )
        if execution_attempt_id and evidence_node_id:
            decision = db.scalar(
                select(DecisionReceipt).where(
                    DecisionReceipt.tenant_id == tenant_id,
                    DecisionReceipt.receipt_id == decision_receipt_id,
                )
            )
            if decision is not None:
                finding = _finding(
                    db,
                    tenant_id=tenant_id,
                    action_id=decision.action_id,
                    decision_receipt_id=decision_receipt_id,
                    execution_receipt_id=execution_receipt_id,
                    execution_attempt_id=execution_attempt_id,
                    evidence_node_id=evidence_node_id,
                    finding_type="EVIDENCE_BUNDLE_REFRESH_INCOMPLETE",
                )
                finding.severity = "medium"
                finding.risk_category = "evidence_bundle_integrity"
                finding.decision = "allow"
                finding.recommended_action = (
                    "Retry canonical evidence bundle projection from signed receipt evidence."
                )
                finding.evidence_status = "incomplete"
                if decision.evidence_bundle_id:
                    finding.evidence_node_ids = list(
                        dict.fromkeys(
                            [
                                *list(finding.evidence_node_ids or []),
                                decision.evidence_bundle_id,
                            ]
                        )
                    )
                _project_bundle_refresh_status_incomplete(
                    db,
                    decision=decision,
                )
                db.flush()
    db.info.setdefault("canonical_bundle_refresh_status", {})[
        decision_receipt_id
    ] = status
    return status


def _project_bundle_refresh_status_incomplete(
    db: Session, *, decision: DecisionReceipt
) -> None:
    runtime_rows = list(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == decision.tenant_id,
                RuntimeEvent.chain_id == decision.chain_id,
            )
            .order_by(RuntimeEvent.event_id)
            .limit(MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS + 1)
        ).all()
    )
    if len(runtime_rows) > MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS:
        runtime_rows = runtime_rows[:MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS]
    runtime_ids: list[str] = []
    for runtime in runtime_rows:
        metadata = dict(runtime.metadata_json or {})
        metadata["canonical_evidence_bundle_refresh_status"] = "incomplete"
        runtime.metadata_json = metadata
        runtime_ids.append(runtime.event_id)
    activity_filters = [AIAction.action_id == decision.action_id]
    if runtime_ids:
        activity_filters.append(AIAction.runtime_event_id.in_(runtime_ids))
    activities = list(
        db.scalars(
            select(AIAction)
            .where(
                AIAction.tenant_id == decision.tenant_id,
                or_(*activity_filters),
            )
            .order_by(AIAction.action_id)
            .limit(MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS + 1)
        ).all()
    )
    for activity in activities[:MAX_BUNDLE_REFRESH_STATUS_PROJECTIONS]:
        metadata = dict(activity.metadata_json or {})
        metadata["canonical_evidence_bundle_refresh_status"] = "incomplete"
        activity.metadata_json = metadata


def _text(value: Any, *, max_len: int = 255) -> str:
    return str(value or "").strip()[:max_len]


def _strict_text(value: Any, *, field: str, max_len: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    token = value.strip()
    if required and not token:
        raise ValueError(f"{field} is required")
    if len(token) > max_len:
        raise ValueError(f"{field} exceeds maximum length")
    return token


def _strict_mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    result = dict(value)
    _canonical_json(result)
    return result


def _utc(value: datetime | None = None) -> datetime:
    resolved = value or datetime.now(timezone.utc)
    if resolved.tzinfo is None:
        return resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def _canonical_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > MAX_RECEIPT_MATERIAL_BYTES:
        raise ValueError("receipt material exceeds maximum size")
    return encoded


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _keyring(settings_obj: Any) -> tuple[str, dict[str, str]]:
    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        return "", {}
    active = _strict_text(
        getattr(settings_obj, "receipt_signing_active_key_id", ""),
        field="receipt signing active key ID",
        max_len=64,
    )
    duplicate_key_ids: set[str] = set()

    def _keyring_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                duplicate_key_ids.add(key)
            value[key] = item
        return value
    try:
        decoded = json.loads(
            str(getattr(settings_obj, "receipt_signing_keys_json", "{}") or "{}"),
            object_pairs_hook=_keyring_object,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("receipt signing keyring is invalid") from exc
    if not isinstance(decoded, dict) or not active or duplicate_key_ids:
        raise ValueError("receipt signing keyring is unavailable")
    keys: dict[str, str] = {}
    for raw_key, raw_secret in decoded.items():
        key = _strict_text(raw_key, field="receipt signing key ID", max_len=64)
        if key in keys:
            raise ValueError("receipt signing keyring has normalized duplicate key IDs")
        if not isinstance(raw_secret, str):
            raise ValueError("receipt signing key material must be a string")
        keys[key] = raw_secret.strip()
    if active not in keys or any(not key or len(secret) < 32 for key, secret in keys.items()):
        raise ValueError("receipt signing keyring is incomplete")
    if len(set(keys.values())) != len(keys):
        raise ValueError("receipt signing keyring is ambiguous")
    return active, keys


def _sign(body: Mapping[str, Any], *, key_id: str, keys: Mapping[str, str]) -> str:
    secret = keys.get(key_id)
    if not secret:
        raise ValueError("receipt signing key ID is unavailable")
    return hmac.new(secret.encode("utf-8"), _canonical_json(dict(body)).encode("utf-8"), hashlib.sha256).hexdigest()


def _approval_binding_hash(binding: ApprovalBinding) -> str:
    return _hash(
        {
            "tenant_id": binding.tenant_id,
            "approval_binding_id": binding.id,
            "approval_id": binding.approval_id,
            "canonical_action_hash": binding.canonical_action_hash,
            "receipt_material_hash": binding.receipt_material_hash,
            "signed_receipt": binding.signed_receipt,
            "material_fields_hash": _hash(binding.material_fields or {}),
            "approver_user_id": binding.approver_user_id,
            "approved_at": _utc(binding.approved_at).isoformat(),
            "expires_at": _utc(binding.expires_at).isoformat() if binding.expires_at else None,
        }
    )


_OPAQUE_PROVENANCE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_ACTOR_PROVENANCE_ID_FIELDS = frozenset(
    {
        "identity_id",
        "user_id",
        "agent_id",
        "session_id",
        "machine_id",
        "acting_on_behalf_of_user_id",
    }
)
_AUTHORITY_PROVENANCE_ID_FIELDS = frozenset({"authority_owner", "jit_grant_id"})
_AUTHORITY_PSEUDONYMOUS_DIGEST_LIST_FIELDS = frozenset(
    {"approved_account_hashes", "approved_resource_hashes", "permission_scope"}
)
_PSEUDONYMOUS_DIGEST_RE = re.compile(r"^(?:hmac-sha256:)?[a-f0-9]{64}$")


def _trusted_provenance_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token or len(token.encode("utf-8")) > 128:
        return None
    try:
        UUID(token)
        return token
    except ValueError:
        return token if _OPAQUE_PROVENANCE_ID_RE.fullmatch(token) else None


def _project_provenance_identifiers(
    sanitized: dict[str, Any],
    source: Mapping[str, Any],
    *,
    fields: frozenset[str],
) -> None:
    for field in fields:
        value = source.get(field)
        if value is None:
            sanitized[field] = None
            continue
        trusted = _trusted_provenance_identifier(value)
        sanitized[field] = trusted if trusted is not None else f"sha256:{_hash(value)}"


def _project_pseudonymous_digest_lists(
    sanitized: dict[str, Any],
    source: Mapping[str, Any],
    *,
    fields: frozenset[str],
) -> None:
    """Restore only schema-valid pseudonymous digests after generic PII redaction."""

    for field in fields:
        source_values = source.get(field)
        sanitized_values = sanitized.get(field)
        if not isinstance(source_values, list | tuple) or not isinstance(
            sanitized_values, list
        ):
            continue
        if len(source_values) != len(sanitized_values):
            continue
        sanitized[field] = [
            source_value
            if isinstance(source_value, str)
            and _PSEUDONYMOUS_DIGEST_RE.fullmatch(source_value)
            else sanitized_value
            for source_value, sanitized_value in zip(
                source_values,
                sanitized_values,
                strict=True,
            )
        ]


def _receipt_canonical_projection(canonical_action: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact, redaction-safe canonical spine persisted and reverified."""

    projection: dict[str, Any] = {}
    for key in (
        "schema_name",
        "schema_version",
        "action_id",
        "tenant_id",
        "chain_id",
        "actor",
        "authority",
        "purpose",
        "surface",
        "action",
        "policy",
        "transformations",
        "provenance",
    ):
        if key in canonical_action:
            projection[key] = deepcopy(canonical_action[key])
    policy = projection.get("policy")
    if isinstance(policy, Mapping):
        stable_policy = dict(policy)
        native_plan = stable_policy.get("native_control_plan")
        if isinstance(native_plan, Mapping):
            # Approval bindings authorize the semantic action and selected
            # control composition. Retry-time validity timestamps and their
            # envelope digest are bound by the signed V2 decision/permit
            # authority, not by the legacy V1 approval hash.
            stable_plan = dict(native_plan)
            for field in (
                "issued_at",
                "expires_at",
                "expiry",
                "selector_plan_id",
                "plan_digest",
            ):
                stable_plan.pop(field, None)
            stable_policy["native_control_plan"] = stable_plan
        projection["policy"] = stable_policy
    approval = canonical_action.get("approval")
    projection["approval"] = {
        "approval_binding_id": (
            dict(approval).get("approval_binding_id") if isinstance(approval, Mapping) else None
        )
    }
    safe_projection = sanitize_privacy_payload(projection)
    actor_source = dict(projection.get("actor") or {})
    authority_source = dict(projection.get("authority") or {})
    actor_projection = dict(safe_projection.get("actor") or {})
    authority_projection = dict(safe_projection.get("authority") or {})
    _project_provenance_identifiers(
        actor_projection,
        actor_source,
        fields=_ACTOR_PROVENANCE_ID_FIELDS,
    )
    _project_provenance_identifiers(
        authority_projection,
        authority_source,
        fields=_AUTHORITY_PROVENANCE_ID_FIELDS,
    )
    _project_pseudonymous_digest_lists(
        authority_projection,
        authority_source,
        fields=_AUTHORITY_PSEUDONYMOUS_DIGEST_LIST_FIELDS,
    )
    safe_projection["actor"] = actor_projection
    safe_projection["authority"] = authority_projection
    _canonical_json(safe_projection)
    return safe_projection


def _tool_provenance_reference_projection(value: Any) -> dict[str, Any]:
    """Keep only bounded references and digests at the signed receipt seam."""
    source = dict(value) if isinstance(value, Mapping) else {}
    tool = dict(source.get("tool_identity") or {})
    instructions = dict(source.get("instruction_provenance") or {})
    text = lambda item, maximum: _text(item, max_len=maximum) or None
    record_ids = [text(item, 64) for item in list(instructions.get("record_ids") or [])[:128]]
    return {
        "tool_binding_id": text(source.get("tool_binding_id"), 64),
        "tool_identity": {
            "tool_identity_hash": text(tool.get("tool_identity_hash"), 64),
            "material_fingerprint": text(tool.get("material_fingerprint"), 64),
            "schema_fingerprint": text(tool.get("schema_fingerprint"), 64),
            "lifecycle_version": text(tool.get("lifecycle_version"), 64),
        },
        "instruction_provenance": {
            "provenance_set_id": text(instructions.get("provenance_set_id"), 64),
            "record_ids": [item for item in record_ids if item],
        },
    }


def _approval_material(material: Mapping[str, str]) -> dict[str, str]:
    return {
        "receipt_material_schema": "1.0",
        "action_id": material["action_id"],
        "tool_fingerprint": material["tool_fingerprint"],
        "arguments_hash": material["parameter_hash"],
        "target_resource_hash": material["target_resource_hash"],
        "destination_hash": material["destination_hash"],
        "authority_hash": material["authority_hash"],
        "side_effect_class": material["side_effect_class"],
    }


def approval_binding_contract(
    canonical_action: Mapping[str, Any], *, tenant_id: str
) -> dict[str, Any]:
    """Return the sole receipt-compatible approval material contract."""

    material = _canonical_material(canonical_action, tenant_id=tenant_id)
    receipt_material = _approval_material(material)
    return {
        "receipt_material_schema": "1.0",
        "canonical_action_hash": material["canonical_action_hash"],
        "material_fields": receipt_material,
        "receipt_material_hash": _hash(receipt_material),
    }


def _approval_binding_consume_conditions(
    *,
    binding_id: str,
    tenant_id: str,
    action_id: str,
    chain_id: str,
    canonical_action_hash_value: str,
    receipt_material_hash: str,
    consume_now: datetime,
) -> tuple[Any, ...]:
    """Return portable scalar-only CAS predicates for approval consumption."""

    return (
        ApprovalBinding.id == binding_id,
        ApprovalBinding.tenant_id == tenant_id,
        ApprovalBinding.action_id == action_id,
        ApprovalBinding.chain_id == chain_id,
        ApprovalBinding.canonical_action_hash == canonical_action_hash_value,
        ApprovalBinding.receipt_material_hash == receipt_material_hash,
        ApprovalBinding.status == "active",
        or_(ApprovalBinding.expires_at.is_(None), ApprovalBinding.expires_at > consume_now),
    )


def _canonical_material(canonical_action: Mapping[str, Any], *, tenant_id: str) -> dict[str, str]:
    if not isinstance(canonical_action, Mapping):
        raise ValueError("canonical_action must be an object")
    action_tenant = _strict_text(canonical_action.get("tenant_id"), field="tenant_id", max_len=64)
    action_id = _strict_text(canonical_action.get("action_id"), field="action_id", max_len=64)
    if not action_id or action_tenant != tenant_id:
        raise ValueError("canonical action tenant/action binding is invalid")
    projection = _receipt_canonical_projection(canonical_action)
    action = _strict_mapping(projection.get("action"), field="action")
    actor = _strict_mapping(projection.get("actor"), field="actor")
    authority = _strict_mapping(projection.get("authority"), field="authority")
    purpose = _strict_mapping(projection.get("purpose"), field="purpose")
    approval = _strict_mapping(projection.get("approval"), field="approval")
    policy = _strict_mapping(projection.get("policy"), field="policy")
    computed_canonical_hash = canonical_action_hash(projection)
    embedded_value = canonical_action.get("canonical_action_hash")
    embedded_canonical_hash = (
        _strict_text(embedded_value, field="canonical_action_hash", max_len=64)
        if embedded_value is not None
        else ""
    )
    if embedded_canonical_hash and embedded_canonical_hash != computed_canonical_hash:
        raise ValueError("embedded canonical action hash is invalid")
    return {
        "action_id": action_id,
        "chain_id": _strict_text(canonical_action.get("chain_id"), field="chain_id", max_len=64),
        "canonical_action_hash": computed_canonical_hash,
        "actor_hash": _hash(actor),
        "authority_hash": _hash(authority),
        "purpose_hash": _hash(purpose),
        "tool_fingerprint": _strict_text(
            action.get("tool_fingerprint_id") or action.get("tool_fingerprint"),
            field="tool_fingerprint",
            max_len=128,
        ),
        "parameter_hash": _strict_text(action.get("parameter_hash"), field="parameter_hash", max_len=128),
        "target_resource_hash": _strict_text(
            action.get("target_resource_hash"), field="target_resource_hash", max_len=128
        ),
        "destination_hash": _strict_text(
            action.get("destination_hash"), field="destination_hash", max_len=128
        ),
        "side_effect_class": _strict_text(
            action.get("side_effect_class"), field="side_effect_class", max_len=64
        ),
        "approval_binding_hash": "unknown",
        "approval_binding_id": (
            _strict_text(approval.get("approval_binding_id"), field="approval_binding_id", max_len=36)
            if approval.get("approval_binding_id") is not None
            else ""
        ),
        "policy_snapshot_id": _strict_text(
            policy.get("policy_snapshot_id"), field="policy_snapshot_id", max_len=64
        ),
    }


def _decision_body(receipt: DecisionReceipt) -> dict[str, Any]:
    return {
        "schema_version": receipt.schema_version or "1.0",
        "receipt_id": receipt.receipt_id,
        "tenant_id": receipt.tenant_id,
        "action_id": receipt.action_id,
        "chain_id": receipt.chain_id,
        "canonical_action_hash": receipt.canonical_action_hash,
        "actor_hash": receipt.actor_hash,
        "authority_hash": receipt.authority_hash,
        "purpose_hash": receipt.purpose_hash,
        "tool_fingerprint": receipt.tool_fingerprint,
        "parameter_hash": receipt.parameter_hash,
        "target_resource_hash": receipt.target_resource_hash,
        "destination_hash": receipt.destination_hash,
        "side_effect_class": receipt.side_effect_class,
        "approval_binding_hash": receipt.approval_binding_hash,
        "approval_binding_id": receipt.approval_binding_id,
        "policy_snapshot_id": receipt.policy_snapshot_id,
        "decision": receipt.decision,
        "control_mode": receipt.control_mode,
        "transformations": list(receipt.transformations or []),
        "expires_at": _utc(receipt.expires_at).isoformat(),
        "issued_at": _utc(receipt.issued_at).isoformat(),
        "collector_id": receipt.collector_id,
        "canonical_action_evidence_node_id": receipt.canonical_action_evidence_node_id,
        "evidence_node_id": receipt.evidence_node_id,
        "idempotency_key": receipt.idempotency_key,
        "signing_key_id": receipt.signing_key_id,
    }


def _execution_body(receipt: ExecutionReceipt) -> dict[str, Any]:
    body = {
        "schema_version": receipt.schema_version or "1.0",
        "receipt_id": receipt.receipt_id,
        "tenant_id": receipt.tenant_id,
        "action_id": receipt.action_id,
        "decision_receipt_id": receipt.decision_receipt_id,
        "execution_attempt_id": receipt.execution_attempt_id,
        "actual_tool_fingerprint": receipt.actual_tool_fingerprint,
        "actual_parameter_hash": receipt.actual_parameter_hash,
        "actual_target_resource_hash": receipt.actual_target_resource_hash,
        "actual_destination_hash": receipt.actual_destination_hash,
        "actual_authority_hash": receipt.actual_authority_hash,
        "actual_side_effect_class": receipt.actual_side_effect_class,
        "downstream_objects": list(receipt.downstream_objects or []),
        "execution_status": receipt.execution_status,
        "executed_at": _utc(receipt.executed_at).isoformat(),
        "collector_id": receipt.collector_id,
        "evidence_node_id": receipt.evidence_node_id,
        "idempotency_key": receipt.idempotency_key,
        "signing_key_id": receipt.signing_key_id,
    }
    if receipt.schema_version == "1.1":
        body.update(
            {
                "actual_chain_id": receipt.actual_chain_id,
                "actual_actor_hash": receipt.actual_actor_hash,
                "actual_purpose_hash": receipt.actual_purpose_hash,
                "actual_policy_snapshot_id": receipt.actual_policy_snapshot_id,
            }
        )
    return body


def _receipt_evidence(
    db: Session,
    *,
    tenant_id: str,
    receipt: Any,
    receipt_type: str,
    evidence_node_id: str | None = None,
) -> EvidenceNode:
    body = _decision_body(receipt) if receipt_type == "decision" else _execution_body(receipt)
    node = EvidenceNode(
        **({"id": evidence_node_id} if evidence_node_id is not None else {}),
        tenant_id=tenant_id,
        correlation_id=get_correlation_id(),
        node_type=f"{receipt_type}_receipt",
        signal_type=f"authorization.{receipt_type}_receipt",
        label=f"Signed {receipt_type} receipt",
        payload={
            "receipt_id": receipt.receipt_id,
            "action_id": receipt.action_id,
            "receipt_type": receipt_type,
            "receipt_body_hash": _hash(body),
            "signature": receipt.signature,
            "signing_key_id": receipt.signing_key_id,
        },
    )
    db.add(node)
    db.flush()
    return node


def _native_control_plan_for_receipt(value: Any) -> dict[str, Any]:
    """Project a digest-verified persisted plan into bounded receipt material."""

    if not isinstance(value, Mapping):
        raise ValueError("persisted native control plan is malformed")

    def text(name: str, maximum: int = 128, *, required: bool = False) -> str:
        projected = _text(value.get(name), max_len=maximum)
        if required and not projected:
            raise ValueError(f"persisted native control plan {name} is malformed")
        return projected

    def hashes(name: str) -> dict[str, str]:
        raw = value.get(name)
        if not isinstance(raw, Mapping):
            return {}
        result: dict[str, str] = {}
        for key, item in list(raw.items())[:32]:
            key_text = _text(key, max_len=128)
            item_text = _text(item, max_len=64)
            if not key_text or not re.fullmatch(r"[0-9a-f]{64}", item_text):
                raise ValueError("persisted native control plan contract hashes are malformed")
            result[key_text] = item_text
        return dict(sorted(result.items()))

    def string_list(name: str, maximum: int = 32) -> list[str]:
        raw = value.get(name)
        if not isinstance(raw, list) or len(raw) > maximum:
            raise ValueError(f"persisted native control plan {name} is malformed")
        result = [_text(item, max_len=128) for item in raw[:maximum]]
        if any(not item for item in result):
            raise ValueError(f"persisted native control plan {name} is malformed")
        return result

    def runtime_requirements() -> dict[str, list[str]]:
        raw = value.get("provider_runtime_requirements")
        if not isinstance(raw, Mapping):
            raise ValueError("persisted native control plan runtime requirements are malformed")
        result: dict[str, list[str]] = {}
        for field in ("required_account_modes", "required_tenant_modes"):
            modes = raw.get(field)
            if modes is None:
                continue
            if not isinstance(modes, list) or len(modes) > 32:
                raise ValueError("persisted native control plan runtime requirements are malformed")
            normalized = [_text(mode, max_len=128) for mode in modes[:32]]
            safe_modes = sorted({mode for mode in normalized if mode and mode != "unknown"})
            if safe_modes:
                result[field] = safe_modes
        return result

    def floors(name: str) -> list[dict[str, Any]]:
        raw = value.get(name)
        if not isinstance(raw, list) or len(raw) > 16:
            raise ValueError(f"persisted native control plan {name} is malformed")
        result: list[dict[str, Any]] = []
        for item in raw[:16]:
            if not isinstance(item, Mapping):
                raise ValueError(f"persisted native control plan {name} is malformed")
            floor_id = _text(item.get("floor_id"), max_len=128)
            control_point_id = _text(item.get("control_point_id"), max_len=128)
            capability = _text(item.get("capability"), max_len=128)
            minimum_level = _text(item.get("minimum_level"), max_len=64)
            allowed_methods = item.get("allowed_methods")
            if floor_id and control_point_id:
                result.append(
                    {"floor_id": floor_id, "control_point_id": control_point_id}
                )
            elif floor_id and capability and minimum_level and isinstance(allowed_methods, list):
                methods = [
                    _text(method, max_len=64)
                    for method in allowed_methods[:16]
                    if _text(method, max_len=64)
                ]
                try:
                    maximum_latency_ms = int(item.get("maximum_latency_ms"))
                except (TypeError, ValueError):
                    raise ValueError(f"persisted native control plan {name} is malformed")
                if not methods or maximum_latency_ms < 1 or maximum_latency_ms > 5_000:
                    raise ValueError(f"persisted native control plan {name} is malformed")
                result.append(
                    {
                        "floor_id": floor_id,
                        "capability": capability,
                        "minimum_level": minimum_level,
                        "allowed_methods": methods,
                        "maximum_latency_ms": maximum_latency_ms,
                    }
                )
        return result

    def rejected_candidates() -> list[dict[str, Any]]:
        raw = value.get("rejected_candidates")
        if not isinstance(raw, list) or len(raw) > 64:
            raise ValueError("persisted native control plan rejected candidates are malformed")
        projected: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, Mapping):
                raise ValueError("persisted native control plan rejected candidates are malformed")
            control_point_id = _text(item.get("control_point_id"), max_len=128)
            reasons = item.get("reason_codes")
            if not control_point_id or not isinstance(reasons, list) or len(reasons) > 32:
                raise ValueError("persisted native control plan rejected candidates are malformed")
            safe_reasons = [_text(reason, max_len=128) for reason in reasons]
            if any(not reason for reason in safe_reasons):
                raise ValueError("persisted native control plan rejected candidates are malformed")
            projected.append(
                {"control_point_id": control_point_id, "reason_codes": safe_reasons}
            )
        return projected

    def rejected_floor_candidates() -> dict[str, list[dict[str, Any]]]:
        raw = value.get("rejected_mandatory_floor_candidates")
        if not isinstance(raw, Mapping) or len(raw) > 16:
            raise ValueError("persisted native control plan floor rejections are malformed")
        projected: dict[str, list[dict[str, Any]]] = {}
        for floor_id, rows in raw.items():
            safe_floor = _text(floor_id, max_len=128)
            if not safe_floor or not isinstance(rows, list) or len(rows) > 64:
                raise ValueError("persisted native control plan floor rejections are malformed")
            safe_rows: list[dict[str, Any]] = []
            for item in rows:
                if not isinstance(item, Mapping):
                    raise ValueError("persisted native control plan floor rejections are malformed")
                control_point_id = _text(item.get("control_point_id"), max_len=128)
                reasons = item.get("reason_codes")
                if not control_point_id or not isinstance(reasons, list) or len(reasons) > 32:
                    raise ValueError("persisted native control plan floor rejections are malformed")
                safe_reasons = [_text(reason, max_len=128) for reason in reasons]
                if any(not reason for reason in safe_reasons):
                    raise ValueError("persisted native control plan floor rejections are malformed")
                safe_rows.append(
                    {"control_point_id": control_point_id, "reason_codes": safe_reasons}
                )
            projected[safe_floor] = safe_rows
        return dict(sorted(projected.items()))

    def degradation_policy() -> dict[str, Any]:
        raw = value.get("degradation_policy")
        if not isinstance(raw, Mapping) or len(raw) > 32:
            raise ValueError("persisted native control plan degradation policy is malformed")
        try:
            serialized = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("persisted native control plan degradation policy is malformed") from exc
        if len(serialized.encode("utf-8")) > 8_192:
            raise ValueError("persisted native control plan degradation policy is malformed")
        return json.loads(serialized)

    plan_id = text("plan_id", 64, required=True)
    plan_digest = text("plan_digest", 64, required=True)
    canonical_hash = text("canonical_action_hash", 64, required=True)
    if not re.fullmatch(r"[0-9a-f]{64}", plan_digest) or not re.fullmatch(
        r"[0-9a-f]{64}", canonical_hash
    ):
        raise ValueError("persisted native control plan hashes are malformed")
    runtime_context = value.get("provider_runtime_context")
    if not isinstance(runtime_context, Mapping):
        raise ValueError("persisted native control plan runtime context is malformed")
    safe_runtime_context = {
        field: _text(runtime_context.get(field), max_len=128)
        for field in (
            "provider",
            "product",
            "runtime",
            "action_class",
            "runtime_location",
            "provider_version",
            "adapter_version",
            "control_method",
            "environment",
            "application",
            "application_version",
            "runtime_version",
            "model_provider",
            "model",
            "route_identity",
            "deployment_identity",
            "deployment_reference",
            "lifecycle_stage",
            "account_mode",
            "tenant_mode",
            "route_evidence_ref",
        )
    }
    safe_runtime_context["route_evidence_fresh"] = (
        runtime_context.get("route_evidence_fresh") is True
    )
    try:
        minimum_assurance = int(value.get("minimum_assurance"))
    except (TypeError, ValueError) as exc:
        raise ValueError("persisted native control plan assurance is malformed") from exc
    if minimum_assurance < 0 or minimum_assurance > 5:
        raise ValueError("persisted native control plan assurance is malformed")
    projected = {
        "schema_version": text("schema_version", 64, required=True),
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "canonical_action_hash": canonical_hash,
        "issued_at": text("issued_at", 64, required=True),
        "expires_at": text("expires_at", 64, required=True),
        "provider_runtime_context": safe_runtime_context,
        "provider_runtime_fingerprint": text(
            "provider_runtime_fingerprint", 64, required=True
        ),
        "provider_runtime_requirements": runtime_requirements(),
        "mandatory_enforcement_floor_requirements": floors(
            "mandatory_enforcement_floor_requirements"
        ),
        "mandatory_enforcement_floors": floors("mandatory_enforcement_floors"),
        "semantic_primary_control_point_id": text(
            "semantic_primary_control_point_id", 128
        ),
        "secondary_context_points": string_list("secondary_context_points"),
        "verification_points": string_list("verification_points"),
        "containment_points": string_list("containment_points"),
        "unsatisfied_mandatory_floors": string_list("unsatisfied_mandatory_floors"),
        "rejected_mandatory_floor_candidates": rejected_floor_candidates(),
        "control_requirement_unsatisfied": value.get("control_requirement_unsatisfied") is True,
        "reason_codes": string_list("reason_codes"),
        "selection_reason": text("selection_reason", 128, required=True),
        "rejected_candidates": rejected_candidates(),
        "required_capabilities": string_list("required_capabilities"),
        "satisfied_capabilities": string_list("satisfied_capabilities"),
        "unsatisfied_capabilities": string_list("unsatisfied_capabilities"),
        "minimum_assurance": minimum_assurance,
        "degradation_policy": degradation_policy(),
        "failure_behavior": text("failure_behavior", 64, required=True),
        "expiry": text("expiry", 64, required=True),
        "blind_spots": string_list("blind_spots"),
        "selector_version": text("selector_version", 128, required=True),
        "matrix_version": text("matrix_version", 128, required=True),
        "policy_version": text("policy_version", 128, required=True),
        "semantic_control_profile_version": text(
            "semantic_control_profile_version", 128
        ),
        "contract_hashes": hashes("contract_hashes"),
    }
    policy_epoch = value.get("policy_epoch")
    if policy_epoch is not None:
        if type(policy_epoch) is not int or policy_epoch <= 0:
            raise ValueError("persisted native control plan policy epoch is malformed")
        projected["policy_epoch"] = policy_epoch
    return projected


def canonical_action_from_authorization(
    request: AuthorizationRequest,
    response: AuthorizationResponse,
    *,
    db: Session | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Project one server-normalized kernel evaluation into receipt-bound canonical material."""

    policy_material: dict[str, Any] = {
        "policy_snapshot_id": response.policy_snapshot_id,
        "decision": response.decision,
        "control_mode": response.control_mode,
    }
    selection_id = _text(request.path_evidence.get("native_control_selection_id"), max_len=64)
    if selection_id:
        if db is None:
            raise ValueError("persisted native control plan is required")
        selection = db.scalar(
            select(NativeControlSelection).where(
                NativeControlSelection.tenant_id == request.tenant_id,
                NativeControlSelection.action_id == request.action_id,
                NativeControlSelection.selection_id == selection_id,
            )
        )
        if selection is None:
            raise ValueError("persisted native control plan is required")
        from app.services.native_control.selection_service import (
            canonical_native_control_action_hash,
            verify_control_plan_material,
        )

        expected_action_hash = canonical_native_control_action_hash(request)
        if (
            selection.canonical_action_hash != expected_action_hash
            or selection.policy_version != request.policy_snapshot_id
            or selection.policy_version != response.policy_snapshot_id
        ):
            raise ValueError("persisted native control plan action binding mismatch")
        verified_plan = verify_control_plan_material(
            selection.control_plan_material,
            expected_digest=selection.control_plan_digest,
            expected_plan_id=selection.control_plan_id,
            expected_canonical_action_hash=expected_action_hash,
            now=now or datetime.now(timezone.utc),
        )
        issued_at = datetime.fromisoformat(str(verified_plan["issued_at"]).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(verified_plan["expires_at"]).replace("Z", "+00:00"))
        if (
            _utc(selection.plan_issued_at) != _utc(issued_at)
            or _utc(selection.plan_expires_at) != _utc(expires_at)
        ):
            raise ValueError("persisted native control plan time binding mismatch")
        policy_material.update(
            {
                "native_control_selection_id": selection.selection_id,
                "native_primary_control_point": selection.primary_control_point_id,
                "native_selector_version": selection.selector_version,
                "native_matrix_version": selection.matrix_version,
                "native_control_profile_version": selection.control_profile_version,
                "native_control_assurance": int(selection.assurance_level),
                "native_control_requirement_satisfied": not (
                    selection.control_requirement_unsatisfied
                ),
                "native_control_plan": _native_control_plan_for_receipt(verified_plan),
            }
        )
    canonical = {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": request.action_id,
        "tenant_id": request.tenant_id,
        "chain_id": request.chain_id,
        "actor": dict(request.actor),
        "authority": dict(request.authority),
        "purpose": dict(request.purpose),
        "surface": {
            "surface_type": request.surface,
            **dict(request.discovery_context),
        },
        "action": {
            "action_type": request.action.get("action_type") or "unknown",
            "action_category": request.action.get("risk_level") or "unknown",
            "tool_name": request.tool.get("name") or "unknown",
            "tool_version": request.tool.get("version") or "unknown",
            "tool_fingerprint_id": request.tool.get("fingerprint_id") or "unknown",
            "parameter_hash": request.parameters.get("parameter_hash") or "unknown",
            "target_resource_hash": request.target.get("resource_hash") or "unknown",
            "destination_hash": request.target.get("destination_hash") or "unknown",
            "side_effect_class": request.side_effect_context.get("side_effect_class") or "unknown",
        },
        "approval": {
            "approval_binding_id": request.approval_context.get("approval_binding_id"),
        },
        "provenance": _tool_provenance_reference_projection(request.path_evidence),
        "policy": policy_material,
        "transformations": list(response.transformations or []),
    }
    canonical["canonical_action_hash"] = canonical_action_hash(
        _receipt_canonical_projection(canonical)
    )
    return canonical


def create_decision_receipt_from_authorization(
    db: Session,
    *,
    request: AuthorizationRequest,
    response: AuthorizationResponse,
    settings_obj: Any,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> tuple[DecisionReceipt | None, dict[str, Any]]:
    canonical = canonical_action_from_authorization(
        request,
        response,
        db=db,
        now=issued_at,
    )
    receipt = create_decision_receipt(
        db,
        tenant_id=request.tenant_id,
        canonical_action=canonical,
        decision=response.decision,
        control_mode=response.control_mode,
        collector_id=request.collector_id,
        settings_obj=settings_obj,
        transformations=list(response.transformations or []),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    provenance = _tool_provenance_reference_projection(request.path_evidence)
    if receipt is not None and provenance["tool_binding_id"] and provenance["instruction_provenance"]["provenance_set_id"]:
        from app.services.instruction_tool_provenance import InstructionToolProvenanceService

        InstructionToolProvenanceService(
            db,
            now=lambda: issued_at or datetime.now(timezone.utc),
            signing_provider=db.info.get("phase5_signing_provider"),
        ).bind_action(
            tenant_id=request.tenant_id,
            action_id=request.action_id,
            binding_id=provenance["tool_binding_id"],
            provenance_set_id=provenance["instruction_provenance"]["provenance_set_id"],
            decision_receipt_id=receipt.receipt_id,
            execution_permit_id=_text(request.path_evidence.get("execution_permit_id"), max_len=255) or None,
            execution_receipt_id=None,
            actual_tool_identity_hash=None,
            actual_material_fingerprint=None,
        )
    return receipt, canonical


def persist_pre_execution_decision_isolated(
    db: Session,
    *,
    request: AuthorizationRequest,
    response: AuthorizationResponse,
    settings_obj: Any,
) -> tuple[DecisionReceipt | None, dict[str, Any]]:
    """Durably bind one selected authorization before an external side effect."""

    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        return None, canonical_action_from_authorization(
            request,
            response,
            db=db,
        )
    # SQLite permits only one writer. The selected authorization path requires
    # the receipt to be durably committed before any provider side effect, so a
    # caller transaction holding the SQLite writer lock must end before the
    # isolated receipt session starts. PostgreSQL keeps the independent
    # transaction behavior without this compatibility boundary.
    if db.get_bind().dialect.name == "sqlite" and db.in_transaction():
        db.commit()
    isolated = sessionmaker(
        bind=db.get_bind(), autocommit=False, autoflush=False, expire_on_commit=False
    )()
    try:
        receipt, canonical = create_decision_receipt_from_authorization(
            isolated,
            request=request,
            response=response,
            settings_obj=settings_obj,
        )
        if receipt is None:
            isolated.rollback()
            return None, canonical
        if response.decision in EXECUTABLE_DECISIONS:
            allowed, _ = validate_pre_execution(
                isolated,
                tenant_id=request.tenant_id,
                decision_receipt_id=receipt.receipt_id,
                actual_canonical_action=canonical,
                settings_obj=settings_obj,
            )
            if not allowed:
                isolated.commit()
                raise ValueError("execution blocked by pre-execution receipt validation")
        else:
            record_execution_incomplete(
                isolated,
                tenant_id=request.tenant_id,
                decision_receipt_id=receipt.receipt_id,
                settings_obj=settings_obj,
            )
        isolated.commit()
        return receipt, canonical
    except Exception:
        isolated.rollback()
        raise
    finally:
        isolated.close()


def persist_pre_execution_decision_in_transaction(
    db: Session,
    *,
    request: AuthorizationRequest,
    response: AuthorizationResponse,
    settings_obj: Any,
    issued_at: datetime | None = None,
) -> tuple[DecisionReceipt | None, dict[str, Any]]:
    """Bind a pre-action receipt in the caller's authoritative transaction.

    This is for control paths that first persist a native selection in the
    same transaction.  A second session cannot observe an uncommitted
    selection on PostgreSQL, so it must not be used to build the receipt.
    The caller commits before returning the provider callback result, which
    remains before the provider is permitted to execute the consequence.
    """

    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        return None, canonical_action_from_authorization(
            request,
            response,
            db=db,
            now=issued_at,
        )
    receipt, canonical = create_decision_receipt_from_authorization(
        db,
        request=request,
        response=response,
        settings_obj=settings_obj,
        issued_at=issued_at,
    )
    if receipt is None:
        return None, canonical
    if response.decision in EXECUTABLE_DECISIONS:
        allowed, _ = validate_pre_execution(
            db,
            tenant_id=request.tenant_id,
            decision_receipt_id=receipt.receipt_id,
            actual_canonical_action=canonical,
            settings_obj=settings_obj,
            evaluated_at=issued_at,
        )
        if not allowed:
            raise ValueError("execution blocked by pre-execution receipt validation")
    else:
        record_execution_incomplete(
            db,
            tenant_id=request.tenant_id,
            decision_receipt_id=receipt.receipt_id,
            settings_obj=settings_obj,
        )
    db.flush()
    return receipt, canonical


def persist_execution_receipt_isolated(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    actual_canonical_action: Mapping[str, Any],
    execution_status: str,
    collector_id: str,
    settings_obj: Any,
    downstream_objects: list[Any] | None = None,
    executed_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> tuple[str, str]:
    """Persist post-side-effect proof without joining or poisoning the caller transaction."""

    isolated = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)()
    try:
        execution, integrity = create_execution_receipt(
            isolated,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            actual_canonical_action=actual_canonical_action,
            execution_status=execution_status,
            collector_id=collector_id,
            settings_obj=settings_obj,
            downstream_objects=downstream_objects,
            executed_at=executed_at,
            execution_attempt_id=execution_attempt_id,
        )
        bundle_refresh_status = str(
            getattr(integrity, "bundle_refresh_status", "incomplete")
        )
        isolated.commit()
        db.info.setdefault("canonical_bundle_refresh_status", {})[
            decision_receipt_id
        ] = bundle_refresh_status
        return execution.receipt_id, integrity.result_id
    except ExecutionAttemptConflictError:
        isolated.rollback()
        persist_execution_attempt_conflict_finding_isolated(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            execution_attempt_id=_strict_text(
                execution_attempt_id,
                field="execution_attempt_id",
                max_len=128,
            ),
        )
        raise
    except Exception:
        isolated.rollback()
        raise
    finally:
        isolated.close()


def persist_execution_incomplete_isolated(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    evaluated_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> str:
    isolated = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)()
    try:
        integrity = record_execution_incomplete(
            isolated,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            settings_obj=settings_obj,
            evaluated_at=evaluated_at,
            execution_attempt_id=execution_attempt_id,
        )
        isolated.commit()
        return integrity.result_id
    except Exception:
        isolated.rollback()
        raise
    finally:
        isolated.close()


def persist_execution_failure_fallback_isolated(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    evaluated_at: datetime,
    execution_attempt_id: str,
) -> str:
    """Best-effort durable proof that post-execution receipt persistence itself failed."""

    isolated = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)()
    try:
        integrity = record_execution_incomplete(
            isolated,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            settings_obj=settings_obj,
            evaluated_at=evaluated_at,
            execution_attempt_id=execution_attempt_id,
        )
        _finding(
            isolated,
            tenant_id=tenant_id,
            action_id=integrity.action_id,
            decision_receipt_id=decision_receipt_id,
            execution_receipt_id=None,
            execution_attempt_id=execution_attempt_id,
            evidence_node_id=integrity.evidence_bundle_id,
            finding_type="EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
        isolated.commit()
        return integrity.result_id
    except Exception:
        isolated.rollback()
        raise
    finally:
        isolated.close()


def queue_post_execution_receipt(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    actual_canonical_action: Mapping[str, Any],
    execution_status: str | None,
    collector_id: str,
    settings_obj: Any,
    downstream_objects: list[Any] | None = None,
    observed_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> None:
    """Write post-effect proof only after the caller transaction reaches a terminal state."""

    queue = db.info.setdefault("decision_execution_receipt_queue", [])
    item = {
            "tenant_id": tenant_id,
            "decision_receipt_id": decision_receipt_id,
            "actual_canonical_action": dict(actual_canonical_action),
            "execution_status": execution_status,
            "collector_id": collector_id,
            "settings_obj": settings_obj,
            "downstream_objects": list(downstream_objects or []),
            "executed_at": _utc(observed_at),
            "execution_attempt_id": _strict_text(
                execution_attempt_id or str(uuid4()),
                field="execution_attempt_id",
                max_len=128,
            ),
        }
    queue_key = _hash(
        [tenant_id, decision_receipt_id, item["actual_canonical_action"], execution_status,
         collector_id, item["downstream_objects"], item["executed_at"].isoformat(),
         item["execution_attempt_id"]]
    )
    if not any(existing.get("queue_key") == queue_key for existing in queue):
        queue.append({**item, "queue_key": queue_key})
    if db.info.get("decision_execution_receipt_listeners_installed"):
        return
    db.info["decision_execution_receipt_listeners_installed"] = True

    def _persist_pending(committed_session: Session) -> None:
        pending = list(
            committed_session.info.pop("decision_execution_receipt_queue", [])
        )
        for item in pending:
            try:
                if item["execution_status"] is None:
                    persist_execution_incomplete_isolated(
                        committed_session,
                        tenant_id=item["tenant_id"],
                        decision_receipt_id=item["decision_receipt_id"],
                        settings_obj=item["settings_obj"],
                        evaluated_at=item["executed_at"],
                        execution_attempt_id=item["execution_attempt_id"],
                    )
                else:
                    receipt_item = {key: value for key, value in item.items() if key != "queue_key"}
                    persist_execution_receipt_isolated(committed_session, **receipt_item)
            except Exception:
                logger.exception("post-commit execution receipt persistence failed")
                try:
                    persist_execution_failure_fallback_isolated(
                        committed_session,
                        tenant_id=item["tenant_id"],
                        decision_receipt_id=item["decision_receipt_id"],
                        settings_obj=item["settings_obj"],
                        evaluated_at=item["executed_at"],
                        execution_attempt_id=item["execution_attempt_id"],
                    )
                except Exception:
                    logger.exception("post-commit receipt failure fallback failed")
                    continue

    def _after_commit(committed_session: Session) -> None:
        # after_commit fires before SQLite releases its writer lock. Defer the
        # isolated durable write until the outer transaction has fully ended.
        committed_session.info["decision_execution_receipt_terminal"] = "commit"

    def _after_rollback(rolled_back_session: Session) -> None:
        rolled_back_session.info["decision_execution_receipt_terminal"] = "rollback"

    def _after_transaction_end(ended_session: Session, transaction: Any) -> None:
        if transaction.parent is not None:
            return
        terminal = ended_session.info.pop(
            "decision_execution_receipt_terminal", None
        )
        if terminal in {"commit", "rollback"}:
            _persist_pending(ended_session)

    event.listen(db, "after_commit", _after_commit)
    event.listen(db, "after_rollback", _after_rollback)
    event.listen(db, "after_transaction_end", _after_transaction_end)


def create_decision_receipt(
    db: Session,
    *,
    tenant_id: str,
    canonical_action: Mapping[str, Any],
    decision: str,
    control_mode: str,
    collector_id: str,
    settings_obj: Any,
    transformations: list[str] | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> DecisionReceipt | None:
    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        return None
    active_key_id, keys = _keyring(settings_obj)
    decision_value = _strict_text(decision, field="decision", max_len=32)
    if decision_value not in ALLOWED_DECISIONS:
        raise ValueError("decision is invalid")
    control_mode_value = _strict_text(control_mode, field="control_mode", max_len=32)
    if control_mode_value not in ALLOWED_CONTROL_MODES:
        raise ValueError("control_mode is invalid")
    collector_value = _strict_text(collector_id, field="collector_id", max_len=128)
    transformation_values = [
        _strict_text(item, field="transformation", max_len=128)
        for item in list(transformations or [])
    ]
    if len(transformation_values) > 64:
        raise ValueError("transformations exceeds maximum items")
    material = _canonical_material(canonical_action, tenant_id=tenant_id)
    clock_fn = clock or (lambda: datetime.now(timezone.utc))
    issued = _utc(issued_at if issued_at is not None else clock_fn())
    all_bindings = list(
        db.scalars(
            select(ApprovalBinding).where(
                ApprovalBinding.tenant_id == tenant_id,
                ApprovalBinding.action_id == material["action_id"],
                ApprovalBinding.chain_id == material["chain_id"],
            )
        ).all()
    )
    bindings = [
        binding
        for binding in all_bindings
        if binding.status == "active"
        if binding.expires_at is None or _utc(binding.expires_at) > issued
    ]
    if len(bindings) > 1:
        raise ValueError("approval binding resolution is ambiguous")
    expected_approval_material = _approval_material(material)
    expected_approval_material_hash = _hash(expected_approval_material)
    binding = bindings[0] if bindings else None
    if binding is None and all_bindings:
        matching_consumed = [
            item
            for item in all_bindings
            if item.canonical_action_hash == material["canonical_action_hash"]
            and item.receipt_material_hash == expected_approval_material_hash
            and dict(item.material_fields or {}) == expected_approval_material
        ]
        if len(matching_consumed) > 1:
            raise ValueError("approval binding resolution is ambiguous")
        binding = matching_consumed[0] if matching_consumed else all_bindings[0]
    if binding is not None and (
        binding.canonical_action_hash != material["canonical_action_hash"]
        or binding.receipt_material_hash != expected_approval_material_hash
        or dict(binding.material_fields or {}) != expected_approval_material
    ):
        raise ValueError("approval canonical action or material does not match exact action semantics")
    claimed_binding_id = material["approval_binding_id"]
    if claimed_binding_id and (binding is None or binding.id != claimed_binding_id):
        raise ValueError("approval binding is unavailable for exact tenant/action/chain")
    if binding is not None:
        material["approval_binding_id"] = binding.id
        material["approval_binding_hash"] = _approval_binding_hash(binding)
    expiry = _utc(expires_at) if expires_at is not None else issued + timedelta(minutes=5)
    if binding is not None and binding.expires_at is not None:
        expiry = min(expiry, _utc(binding.expires_at))
    if expiry <= issued:
        raise ValueError("decision receipt expiry must follow issue time")
    idempotency_key = _hash(
        {
            "tenant_id": tenant_id,
            **material,
            "decision": decision_value,
            "control_mode": control_mode_value,
            "collector_id": collector_value,
            "transformations": transformation_values,
            "signing_key_id": active_key_id,
        }
    )
    existing = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        # Explicit ``issued_at`` is used by deterministic replay and historical
        # ingestion.  Compare an existing receipt with that same evaluation
        # instant; when ``issued_at`` is omitted, ``issued`` is the live clock.
        if _utc(existing.expires_at) <= issued:
            raise ValueError("expired decision receipt cannot be reused; use a new action_id")
        status = _safe_refresh_canonical_bundle(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=existing.receipt_id,
            settings_obj=settings_obj,
        )
        setattr(existing, "bundle_refresh_status", status)
        return existing
    if binding is not None and binding.status != "active":
        raise ValueError("approval binding was already consumed; obtain a new approval")
    receipt_id = str(uuid5(NAMESPACE_URL, f"hawk:decision:{tenant_id}:{idempotency_key}"))
    receipt_evidence_id = str(
        uuid5(NAMESPACE_URL, f"hawk:decision-receipt-evidence:{tenant_id}:{receipt_id}")
    )
    canonical_evidence_id = str(
        uuid5(
            NAMESPACE_URL,
            f"hawk:canonical-action-evidence:{tenant_id}:{material['action_id']}:{material['canonical_action_hash']}",
        )
    )
    receipt = DecisionReceipt(
        receipt_id=receipt_id,
        tenant_id=tenant_id,
        action_id=material["action_id"],
        chain_id=material["chain_id"],
        canonical_action_hash=material["canonical_action_hash"],
        actor_hash=material["actor_hash"],
        authority_hash=material["authority_hash"],
        purpose_hash=material["purpose_hash"],
        tool_fingerprint=material["tool_fingerprint"],
        parameter_hash=material["parameter_hash"],
        target_resource_hash=material["target_resource_hash"],
        destination_hash=material["destination_hash"],
        side_effect_class=material["side_effect_class"],
        approval_binding_hash=material["approval_binding_hash"],
        approval_binding_id=material["approval_binding_id"] or None,
        policy_snapshot_id=material["policy_snapshot_id"],
        decision=decision_value,
        control_mode=control_mode_value,
        transformations=transformation_values,
        expires_at=expiry,
        issued_at=issued,
        signature="pending",
        signing_key_id=active_key_id,
        collector_id=collector_value,
        canonical_action_evidence_node_id=canonical_evidence_id,
        evidence_node_id=receipt_evidence_id,
        idempotency_key=idempotency_key,
    )
    receipt.signature = _sign(_decision_body(receipt), key_id=active_key_id, keys=keys)
    try:
        with db.begin_nested():
            if binding is not None and decision_value in EXECUTABLE_DECISIONS:
                consume_now = _utc(clock_fn())
                consumed = db.execute(
                    update(ApprovalBinding)
                    .where(*_approval_binding_consume_conditions(
                        binding_id=binding.id,
                        tenant_id=tenant_id,
                        action_id=material["action_id"],
                        chain_id=material["chain_id"],
                        canonical_action_hash_value=material["canonical_action_hash"],
                        receipt_material_hash=expected_approval_material_hash,
                        consume_now=consume_now,
                    ))
                    .values(status="used")
                    .execution_options(synchronize_session=False)
                )
                if consumed.rowcount != 1:
                    raise ValueError("approval binding was already consumed; obtain a new approval")
                post_consume_now = _utc(clock_fn())
                if binding.expires_at is not None and _utc(binding.expires_at) <= post_consume_now:
                    raise ValueError("approval binding expired during consumption")
            canonical_evidence = db.get(EvidenceNode, canonical_evidence_id)
            if canonical_evidence is None:
                # Canonical actions contain only schema-validated authorization
                # metadata. Preserve provenance IDs/hashes exactly: generic PII
                # heuristics can misclassify UUID digit runs and break replay.
                db.add(
                    EvidenceNode(
                        id=canonical_evidence_id,
                        tenant_id=tenant_id,
                        correlation_id=get_correlation_id(),
                        node_type="canonical_ai_action",
                        signal_type="authorization.canonical_action",
                        label="Receipt-bound canonical AI action",
                        payload={
                            "schema_version": "1.0",
                            "action_id": material["action_id"],
                            "canonical_action_hash": material["canonical_action_hash"],
                            "canonical_action": _receipt_canonical_projection(canonical_action),
                        },
                    )
                )
                # There is intentionally no ORM relationship here; flush the
                # canonical EvidenceNode first so the composite FK is satisfied.
                db.flush()
            receipt_evidence = db.get(EvidenceNode, receipt_evidence_id)
            if receipt_evidence is None:
                _receipt_evidence(
                    db,
                    tenant_id=tenant_id,
                    receipt=receipt,
                    receipt_type="decision",
                    evidence_node_id=receipt_evidence_id,
                )
            db.add(receipt)
            db.flush()
    except IntegrityError:
        winner = db.scalar(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == tenant_id,
                DecisionReceipt.idempotency_key == idempotency_key,
            )
        )
        if winner is not None:
            return winner
        raise
    status = _safe_refresh_canonical_bundle(
        db,
        tenant_id=tenant_id,
        decision_receipt_id=receipt.receipt_id,
        settings_obj=settings_obj,
    )
    setattr(receipt, "bundle_refresh_status", status)
    return receipt


def verify_decision_receipt(
    receipt: DecisionReceipt,
    *,
    tenant_id: str,
    settings_obj: Any,
    now: datetime | None = None,
    db: Session | None = None,
) -> bool:
    if receipt.tenant_id != tenant_id or _utc(receipt.expires_at) <= _utc(now):
        return False
    try:
        _, keys = _keyring(settings_obj)
        expected = _sign(_decision_body(receipt), key_id=receipt.signing_key_id, keys=keys)
    except ValueError:
        return False
    if not hmac.compare_digest(receipt.signature, expected):
        return False
    if db is None:
        return True
    canonical_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == receipt.canonical_action_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    payload = dict(canonical_node.payload or {}) if canonical_node is not None else {}
    canonical_payload = payload.get("canonical_action")
    if not isinstance(canonical_payload, Mapping):
        return False
    try:
        canonical_material = _canonical_material(canonical_payload, tenant_id=tenant_id)
    except (TypeError, ValueError):
        return False
    if (
        payload.get("action_id") != receipt.action_id
        or payload.get("canonical_action_hash") != receipt.canonical_action_hash
        or canonical_material["action_id"] != receipt.action_id
        or canonical_material["chain_id"] != receipt.chain_id
        or canonical_material["canonical_action_hash"] != receipt.canonical_action_hash
        or canonical_material["actor_hash"] != receipt.actor_hash
        or canonical_material["authority_hash"] != receipt.authority_hash
        or canonical_material["purpose_hash"] != receipt.purpose_hash
        or canonical_material["tool_fingerprint"] != receipt.tool_fingerprint
        or canonical_material["parameter_hash"] != receipt.parameter_hash
        or canonical_material["target_resource_hash"] != receipt.target_resource_hash
        or canonical_material["destination_hash"] != receipt.destination_hash
        or canonical_material["side_effect_class"] != receipt.side_effect_class
    ):
        return False
    if receipt.approval_binding_id:
        binding = db.scalar(
            select(ApprovalBinding).where(
                ApprovalBinding.id == receipt.approval_binding_id,
                ApprovalBinding.tenant_id == tenant_id,
                ApprovalBinding.action_id == receipt.action_id,
                ApprovalBinding.chain_id == receipt.chain_id,
            )
        )
        verification_time = _utc(now)
        if (
            binding is None
            or binding.status not in {"active", "used"}
            or (
                binding.expires_at is not None
                and _utc(binding.expires_at) <= verification_time
            )
            or _utc(receipt.expires_at)
            > (_utc(binding.expires_at) if binding.expires_at is not None else _utc(receipt.expires_at))
            or binding.canonical_action_hash != receipt.canonical_action_hash
            or binding.receipt_material_hash != _hash(_approval_material(canonical_material))
            or dict(binding.material_fields or {}) != _approval_material(canonical_material)
            or _approval_binding_hash(binding) != receipt.approval_binding_hash
        ):
            return False
    return True


def verify_execution_receipt(
    receipt: ExecutionReceipt,
    *,
    tenant_id: str,
    settings_obj: Any,
) -> bool:
    if receipt.tenant_id != tenant_id or _execution_actual_material(receipt) is None:
        return False
    try:
        _, keys = _keyring(settings_obj)
        expected = _sign(_execution_body(receipt), key_id=receipt.signing_key_id, keys=keys)
    except ValueError:
        return False
    return hmac.compare_digest(receipt.signature, expected)


def _redacted_downstream_objects(values: list[Any] | None) -> list[dict[str, str]]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("downstream_objects must be a list")
    if len(values) > MAX_DOWNSTREAM_OBJECTS:
        raise ValueError("downstream_objects exceeds maximum items")
    output: list[dict[str, str]] = []
    for value in values:
        _canonical_json(value)
        if isinstance(value, Mapping):
            raw_type = value.get("object_type") or value.get("type") or "unknown"
            normalized_type = str(raw_type).strip().lower().replace("-", "_")
            if normalized_type in ALLOWED_DOWNSTREAM_OBJECT_TYPES:
                output.append(
                    {
                        "object_type": normalized_type,
                        "object_hash": _hash(value),
                    }
                )
            else:
                output.append(
                    {
                        "object_type": "other",
                        "object_type_hash": _hash(str(raw_type)),
                        "object_hash": _hash(value),
                    }
                )
        else:
            output.append({"object_type": "unknown", "object_hash": _hash(value)})
    return output


def _drift_fields(
    decision: DecisionReceipt,
    actual: Mapping[str, str],
    *,
    allow_legacy_schema: bool = False,
) -> list[str]:
    expected = {
        "chain_id": decision.chain_id,
        "actor_hash": decision.actor_hash,
        "purpose_hash": decision.purpose_hash,
        "tool_fingerprint": decision.tool_fingerprint,
        "parameter_hash": decision.parameter_hash,
        "target_resource_hash": decision.target_resource_hash,
        "destination_hash": decision.destination_hash,
        "authority_hash": decision.authority_hash,
        "side_effect_class": decision.side_effect_class,
        "policy_snapshot_id": decision.policy_snapshot_id,
    }
    legacy_fields = {
        "tool_fingerprint",
        "parameter_hash",
        "target_resource_hash",
        "destination_hash",
        "authority_hash",
        "side_effect_class",
    }
    required_fields = legacy_fields if allow_legacy_schema else set(expected)
    missing = sorted(required_fields - set(actual))
    if missing:
        raise ValueError(
            "execution material is missing required drift fields: "
            + ", ".join(missing)
        )
    return sorted(
        field
        for field in required_fields
        if actual[field] != expected[field]
    )


def _execution_actual_material(receipt: ExecutionReceipt) -> dict[str, str] | None:
    actual = {
        "tool_fingerprint": receipt.actual_tool_fingerprint,
        "parameter_hash": receipt.actual_parameter_hash,
        "target_resource_hash": receipt.actual_target_resource_hash,
        "destination_hash": receipt.actual_destination_hash,
        "authority_hash": receipt.actual_authority_hash,
        "side_effect_class": receipt.actual_side_effect_class,
    }
    if receipt.schema_version != "1.1":
        return actual
    extended = {
        "chain_id": receipt.actual_chain_id,
        "actor_hash": receipt.actual_actor_hash,
        "purpose_hash": receipt.actual_purpose_hash,
        "policy_snapshot_id": receipt.actual_policy_snapshot_id,
    }
    if any(not isinstance(value, str) or not value for value in extended.values()):
        return None
    actual.update(extended)  # type: ignore[arg-type]
    return actual


def _integrity_evidence(
    db: Session,
    *,
    tenant_id: str,
    action_id: str,
    decision_receipt_id: str,
    execution_receipt_id: str | None,
    execution_attempt_id: str,
    result: str,
    drift_fields: list[str],
    result_id: str,
    severity: str,
    response_action: str,
    evaluated_at: datetime,
    signature: str,
    signing_key_id: str,
    evidence_node_id: str,
    idempotency_key: str,
    superseded_evidence_node_id: str | None = None,
    superseded_integrity_body_hash: str | None = None,
    superseded_integrity_signature: str | None = None,
    supersession_evidence_node_id: str | None = None,
) -> EvidenceNode:
    body = {
        "schema_version": "1.0",
        "result_id": result_id,
        "tenant_id": tenant_id,
        "action_id": action_id,
        "decision_receipt_id": decision_receipt_id,
        "execution_receipt_id": execution_receipt_id,
        "execution_attempt_id": execution_attempt_id,
        "result": result,
        "drift_fields": drift_fields,
        "severity": severity,
        "response_action": response_action,
        "evaluated_at": _utc(evaluated_at).isoformat(),
        "evidence_bundle_id": evidence_node_id,
        "superseded_evidence_node_id": superseded_evidence_node_id,
        "superseded_integrity_body_hash": superseded_integrity_body_hash,
        "superseded_integrity_signature": superseded_integrity_signature,
        "supersession_evidence_node_id": supersession_evidence_node_id,
        "idempotency_key": idempotency_key,
        "signing_key_id": signing_key_id,
    }
    node = EvidenceNode(
        id=evidence_node_id,
        tenant_id=tenant_id,
        correlation_id=get_correlation_id(),
        node_type="execution_integrity_result",
        signal_type="authorization.execution_integrity",
        label=f"Execution integrity: {result}",
        payload={**body, "integrity_body_hash": _hash(body), "signature": signature},
    )
    db.add(node)
    db.flush()
    return node


def _integrity_body(integrity: ExecutionIntegrityResult) -> dict[str, Any]:
    return {
        "schema_version": integrity.schema_version or "1.0",
        "result_id": integrity.result_id,
        "tenant_id": integrity.tenant_id,
        "action_id": integrity.action_id,
        "decision_receipt_id": integrity.decision_receipt_id,
        "execution_receipt_id": integrity.execution_receipt_id,
        "execution_attempt_id": integrity.execution_attempt_id,
        "result": integrity.result,
        "drift_fields": list(integrity.drift_fields or []),
        "severity": integrity.severity,
        "response_action": integrity.response_action,
        "evaluated_at": _utc(integrity.evaluated_at).isoformat(),
        "evidence_bundle_id": integrity.evidence_bundle_id,
        "superseded_evidence_node_id": integrity.superseded_evidence_node_id,
        "superseded_integrity_body_hash": integrity.superseded_integrity_body_hash,
        "superseded_integrity_signature": integrity.superseded_integrity_signature,
        "supersession_evidence_node_id": integrity.supersession_evidence_node_id,
        "idempotency_key": integrity.idempotency_key,
        "signing_key_id": integrity.signing_key_id,
    }


def _finding(
    db: Session,
    *,
    tenant_id: str,
    action_id: str,
    decision_receipt_id: str,
    execution_receipt_id: str | None,
    execution_attempt_id: str,
    evidence_node_id: str,
    finding_type: str,
) -> Finding:
    dedupe_key = (
        "receipt-drift:"
        f"{_hash([tenant_id, action_id, decision_receipt_id, execution_attempt_id, finding_type])[:96]}"
    )
    existing = db.scalar(
        select(Finding).where(Finding.tenant_id == tenant_id, Finding.dedupe_key == dedupe_key)
    )
    if existing is not None:
        return existing
    related_ids = [action_id, decision_receipt_id]
    if execution_receipt_id:
        related_ids.append(execution_receipt_id)
    finding = Finding(
        tenant_id=tenant_id,
        source_surface="receipt",
        ai_tool="execution_integrity",
        severity="high",
        finding_type=finding_type,
        risk_category="approval_execution_drift",
        decision="block",
        status="open",
        recommended_action="Re-authorize the exact canonical action before execution.",
        policy_id="decision_execution_receipts",
        evidence_node_ids=[evidence_node_id],
        related_event_ids=related_ids,
        related_control_ids=["PARAMETER_BINDING_CONTROL", "TOOL_CALL_VALIDATION"],
        remediation_action_ids=[],
        evidence_status="complete",
        canonical_action_id=action_id,
        execution_attempt_id=execution_attempt_id,
        dedupe_key=dedupe_key,
        occurrence_count=1,
    )
    db.add(finding)
    db.flush()
    return finding


def persist_execution_attempt_conflict_finding_isolated(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    execution_attempt_id: str,
) -> str:
    isolated = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)()
    try:
        decision = isolated.scalar(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == tenant_id,
                DecisionReceipt.receipt_id == decision_receipt_id,
            )
        )
        execution = isolated.scalar(
            select(ExecutionReceipt).where(
                ExecutionReceipt.tenant_id == tenant_id,
                ExecutionReceipt.decision_receipt_id == decision_receipt_id,
                ExecutionReceipt.execution_attempt_id == execution_attempt_id,
            )
        )
        if decision is None or execution is None:
            raise RuntimeError("execution attempt conflict evidence is unavailable")
        evidence_node_id = execution.evidence_node_id or decision.evidence_node_id
        if not evidence_node_id:
            raise RuntimeError("execution attempt conflict evidence link is unavailable")
        finding = _finding(
            isolated,
            tenant_id=tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision_receipt_id,
            execution_receipt_id=execution.receipt_id,
            execution_attempt_id=execution_attempt_id,
            evidence_node_id=evidence_node_id,
            finding_type="EXECUTION_ATTEMPT_CONFLICT",
        )
        isolated.commit()
        return finding.finding_id
    except Exception:
        isolated.rollback()
        raise
    finally:
        isolated.close()


def _persist_integrity(
    db: Session,
    *,
    decision: DecisionReceipt,
    execution_receipt_id: str | None,
    execution_attempt_id: str,
    result: str,
    drift_fields: list[str],
    evaluated_at: datetime,
    settings_obj: Any,
) -> ExecutionIntegrityResult:
    if result not in ExecutionIntegrityResult.ALLOWED_RESULTS:
        raise ValueError("execution integrity result is invalid")
    idempotency_key = _hash(
        [
            decision.tenant_id,
            decision.receipt_id,
            execution_receipt_id,
            execution_attempt_id,
            result,
            drift_fields,
        ]
    )
    existing = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.tenant_id == decision.tenant_id,
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
            ExecutionIntegrityResult.execution_attempt_id == execution_attempt_id,
        )
    )
    active_key_id, keys = _keyring(settings_obj)
    terminal_results = {"matched", "drift_detected"}
    provisional_results = {"execution_unknown", "incomplete"}
    reconciled = False
    if existing is not None:
        if existing.idempotency_key == idempotency_key:
            status = _safe_refresh_canonical_bundle(
                db,
                tenant_id=decision.tenant_id,
                decision_receipt_id=decision.receipt_id,
                settings_obj=settings_obj,
                execution_attempt_id=existing.execution_attempt_id,
                execution_receipt_id=existing.execution_receipt_id,
                evidence_node_id=existing.evidence_bundle_id,
            )
            setattr(existing, "bundle_refresh_status", status)
            return existing
        if existing.result in terminal_results:
            if result in provisional_results:
                return existing
            _finding(
                db,
                tenant_id=decision.tenant_id,
                action_id=decision.action_id,
                decision_receipt_id=decision.receipt_id,
                execution_receipt_id=existing.execution_receipt_id,
                execution_attempt_id=execution_attempt_id,
                evidence_node_id=existing.evidence_bundle_id,
                finding_type="EXECUTION_ATTEMPT_CONFLICT",
            )
            raise ExecutionAttemptConflictError("execution attempt terminal state conflict")
        if result in provisional_results:
            return existing
        old_evidence_id = existing.evidence_bundle_id
        old_integrity_body = _integrity_body(existing)
        old_integrity_body_hash = _hash(old_integrity_body)
        old_integrity_signature = existing.signature
        new_evidence_id = str(
            uuid5(
                NAMESPACE_URL,
                f"hawk:integrity-reconciled-evidence:{decision.tenant_id}:{existing.result_id}:{idempotency_key}",
            )
        )
        severity = "high" if result == "drift_detected" else "low"
        response_action = "block" if result == "drift_detected" else "none"
        existing.execution_receipt_id = execution_receipt_id
        existing.result = result
        existing.drift_fields = drift_fields
        existing.severity = severity
        existing.response_action = response_action
        existing.evaluated_at = evaluated_at
        existing.evidence_bundle_id = new_evidence_id
        supersession_evidence_id = str(
            uuid5(
                NAMESPACE_URL,
                f"hawk:integrity-supersession:{decision.tenant_id}:{existing.result_id}:{idempotency_key}",
            )
        )
        existing.superseded_evidence_node_id = old_evidence_id
        existing.superseded_integrity_body_hash = old_integrity_body_hash
        existing.superseded_integrity_signature = old_integrity_signature
        existing.supersession_evidence_node_id = supersession_evidence_id
        existing.idempotency_key = idempotency_key
        existing.signing_key_id = active_key_id
        existing.signature = _sign(
            _integrity_body(existing), key_id=active_key_id, keys=keys
        )
        _integrity_evidence(
            db,
            tenant_id=decision.tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_receipt_id=execution_receipt_id,
            execution_attempt_id=execution_attempt_id,
            result=result,
            drift_fields=drift_fields,
            result_id=existing.result_id,
            severity=severity,
            response_action=response_action,
            evaluated_at=evaluated_at,
            signature=existing.signature,
            signing_key_id=active_key_id,
            evidence_node_id=new_evidence_id,
            idempotency_key=idempotency_key,
            superseded_evidence_node_id=old_evidence_id,
            superseded_integrity_body_hash=old_integrity_body_hash,
            superseded_integrity_signature=old_integrity_signature,
            supersession_evidence_node_id=supersession_evidence_id,
        )
        db.add(EvidenceNode(
            id=supersession_evidence_id,
            tenant_id=decision.tenant_id,
            correlation_id=get_correlation_id(),
            node_type="execution_integrity_supersession",
            signal_type="receipt.execution_integrity.superseded",
            label="Provisional execution integrity evidence superseded",
            payload={
                "schema_version": "1.0",
                "decision_receipt_id": decision.receipt_id,
                "execution_attempt_id": execution_attempt_id,
                "superseded_evidence_node_id": old_evidence_id,
                "superseded_integrity_body_hash": old_integrity_body_hash,
                "superseded_integrity_signature": old_integrity_signature,
                "current_evidence_node_id": new_evidence_id,
                "current_result_id": existing.result_id,
                "current_result": result,
                "current_integrity_signature": existing.signature,
            },
        ))
        db.flush()
        integrity = existing
        reconciled = True
    else:
        integrity = None
    result_id = str(uuid5(NAMESPACE_URL, f"hawk:integrity:{decision.tenant_id}:{idempotency_key}"))
    evidence_bundle_id = str(
        uuid5(
            NAMESPACE_URL,
            f"hawk:integrity-evidence:{decision.tenant_id}:{result_id}",
        )
    )
    severity = "high" if result == "drift_detected" else "low"
    response_action = "block" if result == "drift_detected" else "none"
    if not reconciled:
        integrity = ExecutionIntegrityResult(
            result_id=result_id,
            tenant_id=decision.tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_receipt_id=execution_receipt_id,
            execution_attempt_id=execution_attempt_id,
            result=result,
            drift_fields=drift_fields,
            severity=severity,
            response_action=response_action,
            evidence_bundle_id=evidence_bundle_id,
            signature="pending",
            signing_key_id=active_key_id,
            evaluated_at=evaluated_at,
            idempotency_key=idempotency_key,
        )
        integrity.signature = _sign(
            _integrity_body(integrity), key_id=active_key_id, keys=keys
        )
        try:
            with db.begin_nested():
                if db.get(EvidenceNode, evidence_bundle_id) is None:
                    _integrity_evidence(
                        db,
                        tenant_id=decision.tenant_id,
                        action_id=decision.action_id,
                        decision_receipt_id=decision.receipt_id,
                        execution_receipt_id=execution_receipt_id,
                        execution_attempt_id=execution_attempt_id,
                        result=result,
                        drift_fields=drift_fields,
                        result_id=result_id,
                        severity=severity,
                        response_action=response_action,
                        evaluated_at=evaluated_at,
                        signature=integrity.signature,
                        signing_key_id=active_key_id,
                        evidence_node_id=evidence_bundle_id,
                        idempotency_key=idempotency_key,
                    )
                db.add(integrity)
                db.flush()
        except IntegrityError:
            winner = db.scalar(
                select(ExecutionIntegrityResult).where(
                    ExecutionIntegrityResult.tenant_id == decision.tenant_id,
                    ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
                    ExecutionIntegrityResult.execution_attempt_id == execution_attempt_id,
                )
            )
            if winner is not None:
                return _persist_integrity(
                    db,
                    decision=decision,
                    execution_receipt_id=execution_receipt_id,
                    execution_attempt_id=execution_attempt_id,
                    result=result,
                    drift_fields=drift_fields,
                    evaluated_at=evaluated_at,
                    settings_obj=settings_obj,
                )
            raise
    evidence = db.get(EvidenceNode, integrity.evidence_bundle_id)
    if evidence is None:
        raise ValueError("execution integrity evidence is unavailable")
    if result == "drift_detected":
        if decision.approval_binding_id:
            db.execute(
                update(ApprovalBinding)
                .where(
                    ApprovalBinding.id == decision.approval_binding_id,
                    ApprovalBinding.tenant_id == decision.tenant_id,
                    ApprovalBinding.status.in_(("active", "used")),
                )
                .values(status="invalidated", invalidation_reason="approval_execution_drift")
                .execution_options(synchronize_session=False)
            )
        _finding(
            db,
            tenant_id=decision.tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_receipt_id=execution_receipt_id,
            execution_attempt_id=execution_attempt_id,
            evidence_node_id=evidence.id,
            finding_type="APPROVAL_EXECUTION_DRIFT",
        )
        for field in drift_fields:
            finding_type = DRIFT_FINDINGS.get(field)
            if finding_type:
                _finding(
                    db,
                    tenant_id=decision.tenant_id,
                    action_id=decision.action_id,
                    decision_receipt_id=decision.receipt_id,
                    execution_receipt_id=execution_receipt_id,
                    execution_attempt_id=execution_attempt_id,
                    evidence_node_id=evidence.id,
                    finding_type=finding_type,
                )
    status = _safe_refresh_canonical_bundle(
        db,
        tenant_id=decision.tenant_id,
        decision_receipt_id=decision.receipt_id,
        settings_obj=settings_obj,
        execution_attempt_id=integrity.execution_attempt_id,
        execution_receipt_id=integrity.execution_receipt_id,
        evidence_node_id=integrity.evidence_bundle_id,
    )
    setattr(integrity, "bundle_refresh_status", status)
    return integrity


def validate_pre_execution(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    actual_canonical_action: Mapping[str, Any],
    settings_obj: Any,
    evaluated_at: datetime | None = None,
) -> tuple[bool, ExecutionIntegrityResult | None]:
    """Recanonicalize immediately before execution and block material drift."""

    when = _utc(evaluated_at)
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
    )
    if decision is None or not verify_decision_receipt(
        decision, tenant_id=tenant_id, settings_obj=settings_obj, now=when, db=db
    ):
        raise ValueError("decision receipt is missing, expired, or invalid")
    if decision.decision not in EXECUTABLE_DECISIONS:
        raise ValueError("blocked or denied decision cannot proceed to execution")
    material = _canonical_material(actual_canonical_action, tenant_id=tenant_id)
    if material["action_id"] != decision.action_id:
        raise ValueError("execution action does not match decision receipt")
    actual = {
        "chain_id": material["chain_id"],
        "actor_hash": material["actor_hash"],
        "purpose_hash": material["purpose_hash"],
        "tool_fingerprint": material["tool_fingerprint"],
        "parameter_hash": material["parameter_hash"],
        "target_resource_hash": material["target_resource_hash"],
        "destination_hash": material["destination_hash"],
        "authority_hash": material["authority_hash"],
        "side_effect_class": material["side_effect_class"],
        "policy_snapshot_id": material["policy_snapshot_id"],
    }
    drift = _drift_fields(decision, actual)
    if not drift:
        return True, None
    integrity = _persist_integrity(
        db,
        decision=decision,
        execution_receipt_id=None,
        execution_attempt_id=f"prevalidation:{decision.receipt_id}",
        result="drift_detected",
        drift_fields=drift,
        evaluated_at=when,
        settings_obj=settings_obj,
    )
    return False, integrity


def create_execution_receipt(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    actual_canonical_action: Mapping[str, Any],
    execution_status: str,
    collector_id: str,
    settings_obj: Any,
    downstream_objects: list[Any] | None = None,
    executed_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> tuple[ExecutionReceipt, ExecutionIntegrityResult]:
    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        raise ValueError("decision/execution receipts are disabled")
    execution_status_value = _strict_text(
        execution_status, field="execution_status", max_len=32
    )
    if execution_status_value not in ALLOWED_EXECUTION_STATUSES:
        raise ValueError("execution_status is invalid")
    collector_value = _strict_text(collector_id, field="collector_id", max_len=128)
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
    )
    when = _utc(executed_at)
    if decision is None or not verify_decision_receipt(
        decision, tenant_id=tenant_id, settings_obj=settings_obj, now=when, db=db
    ):
        raise ValueError("decision receipt is missing, expired, or invalid")
    if decision.decision not in EXECUTABLE_DECISIONS:
        raise ValueError("blocked or denied decision cannot have an execution receipt")
    # This is the post-execution observer. It must record what actually happened,
    # even when it differs from the prevalidated material.
    material = _canonical_material(actual_canonical_action, tenant_id=tenant_id)
    if material["action_id"] != decision.action_id:
        raise ValueError("execution action does not match decision receipt")
    actual = {
        "chain_id": material["chain_id"],
        "actor_hash": material["actor_hash"],
        "purpose_hash": material["purpose_hash"],
        "tool_fingerprint": material["tool_fingerprint"],
        "parameter_hash": material["parameter_hash"],
        "target_resource_hash": material["target_resource_hash"],
        "destination_hash": material["destination_hash"],
        "authority_hash": material["authority_hash"],
        "side_effect_class": material["side_effect_class"],
        "policy_snapshot_id": material["policy_snapshot_id"],
    }
    redacted_objects = _redacted_downstream_objects(downstream_objects)
    attempt_value = _strict_text(
        execution_attempt_id
        or f"legacy:{_hash([tenant_id, decision.receipt_id, actual, execution_status_value, collector_value, redacted_objects])[:96]}",
        field="execution_attempt_id",
        max_len=128,
    )
    idempotency_key = _hash(
        [
            tenant_id,
            decision.receipt_id,
            attempt_value,
            actual,
            execution_status_value,
            collector_value,
            redacted_objects,
        ]
    )
    existing = db.scalar(
        select(ExecutionReceipt).where(
            ExecutionReceipt.tenant_id == tenant_id,
            ExecutionReceipt.decision_receipt_id == decision.receipt_id,
            ExecutionReceipt.execution_attempt_id == attempt_value,
        )
    )
    if existing is not None and existing.idempotency_key != idempotency_key:
        _finding(
            db,
            tenant_id=tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_receipt_id=existing.receipt_id,
            execution_attempt_id=attempt_value,
            evidence_node_id=existing.evidence_node_id or decision.evidence_node_id,
            finding_type="EXECUTION_ATTEMPT_CONFLICT",
        )
        raise ExecutionAttemptConflictError("execution attempt terminal material conflict")
    if existing is None:
        active_key_id, keys = _keyring(settings_obj)
        receipt_id = str(uuid5(NAMESPACE_URL, f"hawk:execution:{tenant_id}:{idempotency_key}"))
        evidence_node_id = str(
            uuid5(NAMESPACE_URL, f"hawk:execution-receipt-evidence:{tenant_id}:{receipt_id}")
        )
        existing = ExecutionReceipt(
            receipt_id=receipt_id,
            schema_version="1.1",
            tenant_id=tenant_id,
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_attempt_id=attempt_value,
            actual_chain_id=actual["chain_id"],
            actual_actor_hash=actual["actor_hash"],
            actual_purpose_hash=actual["purpose_hash"],
            actual_tool_fingerprint=actual["tool_fingerprint"],
            actual_parameter_hash=actual["parameter_hash"],
            actual_target_resource_hash=actual["target_resource_hash"],
            actual_destination_hash=actual["destination_hash"],
            actual_authority_hash=actual["authority_hash"],
            actual_side_effect_class=actual["side_effect_class"],
            actual_policy_snapshot_id=actual["policy_snapshot_id"],
            downstream_objects=redacted_objects,
            execution_status=execution_status_value,
            executed_at=when,
            collector_id=collector_value,
            signature="pending",
            signing_key_id=active_key_id,
            evidence_node_id=evidence_node_id,
            idempotency_key=idempotency_key,
        )
        existing.signature = _sign(_execution_body(existing), key_id=active_key_id, keys=keys)
        try:
            with db.begin_nested():
                if db.get(EvidenceNode, evidence_node_id) is None:
                    _receipt_evidence(
                        db,
                        tenant_id=tenant_id,
                        receipt=existing,
                        receipt_type="execution",
                        evidence_node_id=evidence_node_id,
                    )
                db.add(existing)
                db.flush()
        except IntegrityError:
            winner = db.scalar(
                select(ExecutionReceipt).where(
                    ExecutionReceipt.tenant_id == tenant_id,
                    ExecutionReceipt.decision_receipt_id == decision.receipt_id,
                    ExecutionReceipt.execution_attempt_id == attempt_value,
                )
            )
            if winner is None:
                raise
            if winner.idempotency_key != idempotency_key:
                raise ExecutionAttemptConflictError("execution attempt terminal material conflict")
            existing = winner
    drift = _drift_fields(decision, actual)
    integrity = _persist_integrity(
        db,
        decision=decision,
        execution_receipt_id=existing.receipt_id,
        execution_attempt_id=existing.execution_attempt_id,
        result="drift_detected" if drift else "matched",
        drift_fields=drift,
        evaluated_at=when,
        settings_obj=settings_obj,
    )
    setattr(
        existing,
        "bundle_refresh_status",
        getattr(integrity, "bundle_refresh_status", "incomplete"),
    )
    provenance = dict(actual_canonical_action.get("provenance") or {}) if isinstance(actual_canonical_action, Mapping) else {}
    tool = dict(provenance.get("tool_identity") or {})
    if provenance.get("tool_binding_id"):
        from app.db.models.instruction_tool_provenance import ToolActionProvenanceBinding

        binding = db.scalar(
            select(ToolActionProvenanceBinding).where(
                ToolActionProvenanceBinding.tenant_id == tenant_id,
                ToolActionProvenanceBinding.decision_receipt_id == decision_receipt_id,
                ToolActionProvenanceBinding.tool_binding_id == str(provenance["tool_binding_id"]),
            )
        )
        if binding is not None:
            identity = _text(tool.get("actual_tool_identity_hash"), max_len=64) or None
            material_fingerprint = _text(tool.get("actual_material_fingerprint"), max_len=64) or None
            if bool(identity) != bool(material_fingerprint):
                raise ValueError("execution tool identity observation is incomplete")
            if identity and material_fingerprint:
                from app.services.instruction_tool_provenance import InstructionToolProvenanceService

                InstructionToolProvenanceService(
                    db,
                    signing_provider=db.info.get("phase5_signing_provider"),
                ).assert_action_binding_current(
                    tenant_id=tenant_id,
                    action_binding_id=binding.id,
                    actual_tool_identity_hash=identity,
                    actual_material_fingerprint=material_fingerprint,
                )
            binding.execution_receipt_id = existing.receipt_id
            db.flush()
    return existing, integrity


def record_execution_unknown(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    evaluated_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> ExecutionIntegrityResult:
    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        raise ValueError("decision/execution receipts are disabled")
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
    )
    if decision is None:
        raise ValueError("decision receipt not found for tenant")
    return _persist_integrity(
        db,
        decision=decision,
        execution_receipt_id=None,
        execution_attempt_id=execution_attempt_id or f"unknown:{decision.receipt_id}",
        result="execution_unknown",
        drift_fields=[],
        evaluated_at=_utc(evaluated_at),
        settings_obj=settings_obj,
    )


def record_execution_incomplete(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    evaluated_at: datetime | None = None,
    execution_attempt_id: str | None = None,
) -> ExecutionIntegrityResult:
    if not bool(getattr(settings_obj, "decision_execution_receipts_enabled", False)):
        raise ValueError("decision/execution receipts are disabled")
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
    )
    if decision is None:
        raise ValueError("decision receipt not found for tenant")
    return _persist_integrity(
        db,
        decision=decision,
        execution_receipt_id=None,
        execution_attempt_id=execution_attempt_id or f"incomplete:{decision.receipt_id}",
        result="incomplete",
        drift_fields=[],
        evaluated_at=_utc(evaluated_at),
        settings_obj=settings_obj,
    )


def verify_receipt_evidence(
    db: Session,
    *,
    tenant_id: str,
    receipt: DecisionReceipt | ExecutionReceipt,
) -> bool:
    if receipt.tenant_id != tenant_id or not receipt.evidence_node_id:
        return False
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == receipt.evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    if evidence is None:
        return False
    receipt_type = "decision" if isinstance(receipt, DecisionReceipt) else "execution"
    body = _decision_body(receipt) if receipt_type == "decision" else _execution_body(receipt)
    expected = {
        "receipt_id": receipt.receipt_id,
        "action_id": receipt.action_id,
        "receipt_type": receipt_type,
        "receipt_body_hash": _hash(body),
        "signature": receipt.signature,
        "signing_key_id": receipt.signing_key_id,
    }
    # These are schema-validated provenance fields, not arbitrary content. Keep
    # hashes/signatures exact so privacy heuristics cannot rewrite their digits.
    return dict(evidence.payload or {}) == expected


def verify_integrity_evidence(
    db: Session,
    *,
    tenant_id: str,
    integrity: ExecutionIntegrityResult,
    settings_obj: Any,
) -> bool:
    if (
        integrity.tenant_id != tenant_id
        or not integrity.evidence_bundle_id
        or integrity.result not in ExecutionIntegrityResult.ALLOWED_RESULTS
    ):
        return False
    current_count = db.scalar(
        select(func.count(ExecutionIntegrityResult.result_id)).where(
            ExecutionIntegrityResult.tenant_id == tenant_id,
            ExecutionIntegrityResult.decision_receipt_id == integrity.decision_receipt_id,
            ExecutionIntegrityResult.execution_attempt_id == integrity.execution_attempt_id,
        )
    )
    if current_count != 1:
        return False
    try:
        _, keys = _keyring(settings_obj)
        expected_signature = _sign(
            _integrity_body(integrity), key_id=integrity.signing_key_id, keys=keys
        )
    except ValueError:
        return False
    if not hmac.compare_digest(integrity.signature, expected_signature):
        return False
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.receipt_id == integrity.decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
    )
    if (
        decision is None
        or decision.action_id != integrity.action_id
        or not verify_decision_receipt(
            decision,
            tenant_id=tenant_id,
            settings_obj=settings_obj,
            now=integrity.evaluated_at,
            db=db,
        )
        or not verify_receipt_evidence(db, tenant_id=tenant_id, receipt=decision)
    ):
        return False
    if integrity.execution_receipt_id is None:
        if integrity.result not in {"execution_unknown", "incomplete"} or integrity.drift_fields:
            return False
    else:
        execution = db.scalar(
            select(ExecutionReceipt).where(
                ExecutionReceipt.receipt_id == integrity.execution_receipt_id,
                ExecutionReceipt.tenant_id == tenant_id,
            )
        )
        if (
            execution is None
            or execution.action_id != integrity.action_id
            or execution.decision_receipt_id != decision.receipt_id
            or execution.execution_attempt_id != integrity.execution_attempt_id
            or not verify_execution_receipt(
                execution, tenant_id=tenant_id, settings_obj=settings_obj
            )
            or not verify_receipt_evidence(db, tenant_id=tenant_id, receipt=execution)
        ):
            return False
        actual = _execution_actual_material(execution)
        if actual is None:
            return False
        drift = _drift_fields(
            decision,
            actual,
            allow_legacy_schema=execution.schema_version != "1.1",
        )
        expected_result = "drift_detected" if drift else "matched"
        if integrity.result != expected_result or list(integrity.drift_fields or []) != drift:
            return False
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == integrity.evidence_bundle_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    if evidence is None:
        return False
    body = _integrity_body(integrity)
    if dict(evidence.payload or {}) != {
        **body,
        "integrity_body_hash": _hash(body),
        "signature": integrity.signature,
    }:
        return False
    transition_values = (
        integrity.superseded_evidence_node_id,
        integrity.superseded_integrity_body_hash,
        integrity.superseded_integrity_signature,
        integrity.supersession_evidence_node_id,
    )
    if not any(transition_values):
        return True
    if not all(transition_values):
        return False
    old_evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == integrity.superseded_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type == "execution_integrity_result",
        )
    )
    supersession = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == integrity.supersession_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type == "execution_integrity_supersession",
        )
    )
    if old_evidence is None or supersession is None:
        return False
    old_payload = dict(old_evidence.payload or {})
    old_signature = old_payload.pop("signature", None)
    old_body_hash = old_payload.pop("integrity_body_hash", None)
    if (
        old_signature != integrity.superseded_integrity_signature
        or old_body_hash != integrity.superseded_integrity_body_hash
        or _hash(old_payload) != integrity.superseded_integrity_body_hash
        or old_payload.get("tenant_id") != tenant_id
        or old_payload.get("decision_receipt_id") != integrity.decision_receipt_id
        or old_payload.get("execution_attempt_id") != integrity.execution_attempt_id
        or old_payload.get("result_id") != integrity.result_id
        or old_payload.get("result") not in {"execution_unknown", "incomplete"}
    ):
        return False
    old_key_id = old_payload.get("signing_key_id")
    try:
        expected_old_signature = _sign(old_payload, key_id=old_key_id, keys=keys)
    except (TypeError, ValueError):
        return False
    if not hmac.compare_digest(str(old_signature), expected_old_signature):
        return False
    expected_supersession = {
        "schema_version": "1.0",
        "decision_receipt_id": integrity.decision_receipt_id,
        "execution_attempt_id": integrity.execution_attempt_id,
        "superseded_evidence_node_id": integrity.superseded_evidence_node_id,
        "superseded_integrity_body_hash": integrity.superseded_integrity_body_hash,
        "superseded_integrity_signature": integrity.superseded_integrity_signature,
        "current_evidence_node_id": integrity.evidence_bundle_id,
        "current_result_id": integrity.result_id,
        "current_result": integrity.result,
        "current_integrity_signature": integrity.signature,
    }
    return dict(supersession.payload or {}) == expected_supersession


__all__ = [
    "ExecutionAttemptConflictError",
    "approval_binding_contract",
    "canonical_action_from_authorization",
    "create_decision_receipt",
    "create_decision_receipt_from_authorization",
    "create_execution_receipt",
    "persist_execution_receipt_isolated",
    "persist_execution_incomplete_isolated",
    "persist_execution_attempt_conflict_finding_isolated",
    "persist_pre_execution_decision_in_transaction",
    "persist_pre_execution_decision_isolated",
    "queue_post_execution_receipt",
    "record_execution_incomplete",
    "record_execution_unknown",
    "validate_pre_execution",
    "verify_decision_receipt",
    "verify_execution_receipt",
    "verify_integrity_evidence",
    "verify_receipt_evidence",
]
