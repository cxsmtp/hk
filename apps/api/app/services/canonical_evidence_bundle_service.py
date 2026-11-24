from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction
from app.db.models.evidence import (
    DecisionReceipt,
    EvidenceEdge,
    EvidenceNode,
    ExecutionIntegrityResult,
    ExecutionReceipt,
)
from app.db.models.finding import Finding
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent
from app.core.observability import log_structured
from app.services.privacy_sanitizer import sanitize_privacy_payload


POLICY_NODE_TYPE = "canonical_policy_snapshot_v1"
BUNDLE_ROOT_TYPE = "canonical_evidence_bundle_v1"
BUNDLE_MANIFEST_TYPE = "canonical_evidence_bundle_manifest_v1"
MAX_EXECUTION_RECEIPTS = 64
MAX_INTEGRITY_RESULTS = 64
MAX_FINDINGS = 64
MAX_RUNTIME_TRACES = 128
MAX_FINDING_EVIDENCE_REFS = 32
MAX_TOTAL_MANIFEST_MEMBERS = 256
MAX_MANIFEST_HISTORY = 256
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PROJECTION_ROWS = 64
# SQL storage timestamps are lifecycle metadata, not evidence authority. Canonical
# captured/generated timestamps live in signed payloads; these fields are
# intentionally excluded from `_node_body` and therefore from member hashes.
NON_AUTHORITATIVE_NODE_STORAGE_FIELDS = frozenset({"created_at", "updated_at"})
INTEGRITY_TYPED_NODE_TYPES = frozenset(
    {
        "decision_receipt",
        "execution_receipt",
        "execution_integrity_result",
        "execution_integrity_supersession",
        "canonical_ai_action",
        POLICY_NODE_TYPE,
        BUNDLE_ROOT_TYPE,
        BUNDLE_MANIFEST_TYPE,
    }
)


def _receipt_contract():
    from app.services import receipt_service

    return receipt_service


def _utc(value: datetime | None) -> datetime:
    resolved = value or datetime.now(timezone.utc)
    if resolved.tzinfo is None:
        return resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def _node_body(node: EvidenceNode) -> dict[str, Any]:
    payload = dict(node.payload or {})
    if node.node_type not in INTEGRITY_TYPED_NODE_TYPES:
        payload = sanitize_privacy_payload(payload)
    return {
        "id": node.id,
        "tenant_id": node.tenant_id,
        "correlation_id": node.correlation_id,
        "node_type": node.node_type,
        "signal_type": node.signal_type,
        "label": node.label,
        "payload": payload,
    }


def _bounded_rows(
    db: Session,
    model: Any,
    *,
    filters: tuple[Any, ...],
    order_by: tuple[Any, ...],
    limit: int,
    category: str,
) -> list[Any]:
    count = int(
        db.scalar(select(func.count()).select_from(model).where(*filters)) or 0
    )
    if count > limit:
        raise ValueError(f"canonical evidence bundle {category} limit exceeded")
    rows = list(
        db.scalars(
            select(model).where(*filters).order_by(*order_by).limit(limit + 1)
        ).all()
    )
    if len(rows) > limit:
        raise ValueError(f"canonical evidence bundle {category} limit exceeded")
    return rows


def _canonical_json_size(value: Mapping[str, Any]) -> int:
    return len(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    )


def _signed_payload(body: Mapping[str, Any], *, settings_obj: Any) -> dict[str, Any]:
    contract = _receipt_contract()
    key_id, keys = contract._keyring(settings_obj)
    normalized = sanitize_privacy_payload(dict(body))
    return {
        **normalized,
        "body_hash": contract._hash(normalized),
        "signing_key_id": key_id,
        "signature": contract._sign(normalized, key_id=key_id, keys=keys),
    }


def _verify_signed_payload(payload: Mapping[str, Any], *, settings_obj: Any) -> bool:
    contract = _receipt_contract()
    body = dict(payload)
    signature = body.pop("signature", None)
    signing_key_id = body.pop("signing_key_id", None)
    body_hash = body.pop("body_hash", None)
    try:
        _, keys = contract._keyring(settings_obj)
        expected_hash = contract._hash(body)
        expected_signature = contract._sign(body, key_id=signing_key_id, keys=keys)
        return bool(
            isinstance(body_hash, str)
            and isinstance(signature, str)
            and hmac.compare_digest(body_hash, expected_hash)
            and hmac.compare_digest(signature, expected_signature)
        )
    except (TypeError, ValueError):
        return False


def _policy_source_material(policy: PolicyVersion, pack: PolicyPack | None) -> dict[str, Any]:
    created_at = policy.created_at
    return {
        "policy_version_id": policy.id,
        "tenant_id": policy.tenant_id,
        "pack_id": policy.pack_id,
        "pack_name": pack.name if pack is not None else None,
        "pack_status": pack.status if pack is not None else None,
        "version": policy.version,
        "created_at": _utc(created_at).isoformat() if isinstance(created_at, datetime) else str(created_at),
        "scope": dict(policy.scope or {}),
        "enforcement_defaults": dict(policy.enforcement_defaults or {}),
        "guardian_contracts": list(policy.guardian_contracts or []),
        "contract_json": dict(policy.contract_json or {}),
    }


def create_policy_snapshot(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str,
    captured_at: datetime,
    settings_obj: Any,
) -> EvidenceNode:
    contract = _receipt_contract()
    policy = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == tenant_id,
        )
    )
    pack = (
        db.scalar(
            select(PolicyPack).where(
                PolicyPack.id == policy.pack_id,
                PolicyPack.tenant_id == tenant_id,
            )
        )
        if policy is not None
        else None
    )
    if policy is None:
        source_material = {
            "policy_version_id": policy_version_id,
            "tenant_id": tenant_id,
            "authority_unavailable": True,
        }
        source_kind = "server_policy_reference"
        authoritative = False
    else:
        source_material = _policy_source_material(policy, pack)
        source_kind = "policy_version"
        authoritative = True
    source_hash = contract._hash(source_material)
    captured_at_iso = _utc(captured_at).isoformat()
    node_id = str(
        uuid5(
            NAMESPACE_URL,
            f"hawk:policy-snapshot:{tenant_id}:{policy_version_id}:{source_hash}:{captured_at_iso}",
        )
    )
    body = {
        "schema_name": "hawk.policy_snapshot",
        "schema_version": "1.0",
        "snapshot_id": node_id,
        "tenant_id": tenant_id,
        "policy_version_id": policy_version_id,
        "source_kind": source_kind,
        "authoritative": authoritative,
        "source_material_hash": source_hash,
        "source_material": sanitize_privacy_payload(source_material),
        "captured_at": captured_at_iso,
    }
    expected = _signed_payload(body, settings_obj=settings_obj)
    existing = db.get(EvidenceNode, node_id)
    if existing is not None:
        if existing.tenant_id != tenant_id or dict(existing.payload or {}) != expected:
            raise ValueError("policy snapshot idempotency conflict")
        return existing
    node = EvidenceNode(
        id=node_id,
        tenant_id=tenant_id,
        node_type=POLICY_NODE_TYPE,
        signal_type="authorization.policy.snapshot",
        label=f"Policy snapshot {policy_version_id}",
        payload=expected,
    )
    db.add(node)
    db.flush()
    return node


def verify_policy_snapshot(
    db: Session,
    *,
    tenant_id: str,
    snapshot: EvidenceNode,
    settings_obj: Any,
) -> dict[str, bool]:
    payload = dict(snapshot.payload or {})
    signature_valid = bool(
        snapshot.tenant_id == tenant_id
        and snapshot.node_type == POLICY_NODE_TYPE
        and snapshot.signal_type == "authorization.policy.snapshot"
        and snapshot.label == f"Policy snapshot {payload.get('policy_version_id')}"
        and payload.get("snapshot_id") == snapshot.id
        and snapshot.id
        == str(
            uuid5(
                NAMESPACE_URL,
                "hawk:policy-snapshot:"
                f"{tenant_id}:{payload.get('policy_version_id')}:"
                f"{payload.get('source_material_hash')}:{payload.get('captured_at')}",
            )
        )
        and payload.get("tenant_id") == tenant_id
        and _verify_signed_payload(payload, settings_obj=settings_obj)
    )
    source_current = False
    if signature_valid and payload.get("source_kind") == "policy_version":
        policy = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == payload.get("policy_version_id"),
                PolicyVersion.tenant_id == tenant_id,
            )
        )
        if policy is not None:
            pack = db.scalar(
                select(PolicyPack).where(
                    PolicyPack.id == policy.pack_id,
                    PolicyPack.tenant_id == tenant_id,
                )
            )
            source_current = (
                _receipt_contract()._hash(_policy_source_material(policy, pack))
                == payload.get("source_material_hash")
            )
    return {
        "signature_valid": signature_valid,
        "source_current": source_current,
        "valid": signature_valid,
    }


def _edge(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str,
    to_node_id: str,
    edge_type: str,
    payload: dict[str, Any],
) -> EvidenceEdge:
    for node_id in (from_node_id, to_node_id):
        node = db.get(EvidenceNode, node_id)
        if node is None or node.tenant_id != tenant_id:
            raise ValueError("evidence edge tenant/member mismatch")
    expected_payload = sanitize_privacy_payload(payload)
    integrity_key, edge_id = _canonical_edge_identity(
        tenant_id=tenant_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        payload=expected_payload,
    )
    existing = db.get(EvidenceEdge, edge_id)
    if existing is not None:
        if (
            existing.tenant_id != tenant_id
            or existing.from_node_id != from_node_id
            or existing.to_node_id != to_node_id
            or existing.edge_type != edge_type
            or existing.integrity_key != integrity_key
            or dict(existing.payload or {}) != expected_payload
        ):
            raise ValueError(
                "evidence edge idempotency conflict: "
                f"{edge_type}:{from_node_id}:{to_node_id}:"
                f"existing={dict(existing.payload or {})}:expected={expected_payload}"
            )
        return existing
    edge = EvidenceEdge(
        id=edge_id,
        tenant_id=tenant_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        integrity_key=integrity_key,
        payload=expected_payload,
    )
    try:
        with db.begin_nested():
            db.add(edge)
            db.flush()
        return edge
    except IntegrityError:
        db.expire_all()
        winner = db.get(EvidenceEdge, edge_id)
        if winner is None:
            raise
        if (
            winner.tenant_id != tenant_id
            or winner.from_node_id != from_node_id
            or winner.to_node_id != to_node_id
            or winner.edge_type != edge_type
            or winner.integrity_key != integrity_key
            or dict(winner.payload or {}) != expected_payload
        ):
            raise ValueError("evidence edge concurrent idempotency conflict")
        return winner


def _canonical_edge_identity(
    *,
    tenant_id: str,
    from_node_id: str,
    to_node_id: str,
    edge_type: str,
    payload: Mapping[str, Any],
) -> tuple[str, str]:
    expected_payload = sanitize_privacy_payload(dict(payload))
    integrity_key = _receipt_contract()._hash(
        {
            "tenant_id": tenant_id,
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "edge_type": edge_type,
            "payload": expected_payload,
        }
    )
    edge_id = str(
        uuid5(
            NAMESPACE_URL,
            "hawk:evidence-edge:"
            f"{tenant_id}:{from_node_id}:{to_node_id}:{edge_type}:"
            f"{integrity_key}",
        )
    )
    return integrity_key, edge_id


def _edge_identity_valid(edge: EvidenceEdge) -> bool:
    integrity_key, edge_id = _canonical_edge_identity(
        tenant_id=edge.tenant_id,
        from_node_id=edge.from_node_id,
        to_node_id=edge.to_node_id,
        edge_type=edge.edge_type,
        payload=sanitize_privacy_payload(dict(edge.payload or {})),
    )
    return bool(edge.integrity_key == integrity_key and edge.id == edge_id)


def _bounded_edges(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str,
    edge_type: str,
    limit: int,
    category: str,
) -> list[EvidenceEdge]:
    return _bounded_rows(
        db,
        EvidenceEdge,
        filters=(
            EvidenceEdge.tenant_id == tenant_id,
            EvidenceEdge.from_node_id == from_node_id,
            EvidenceEdge.edge_type == edge_type,
        ),
        order_by=(EvidenceEdge.id,),
        limit=limit,
        category=category,
    )


def _bundle_members(
    db: Session,
    *,
    decision: DecisionReceipt,
    policy_snapshot: EvidenceNode,
    bundle_id: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    contract = _receipt_contract()
    candidates: list[dict[str, Any]] = [
        {"role": "canonical_action", "node_id": decision.canonical_action_evidence_node_id},
        {"role": "decision_receipt", "node_id": decision.evidence_node_id},
        {"role": "policy_snapshot", "node_id": policy_snapshot.id},
    ]
    executions = _bounded_rows(
        db,
        ExecutionReceipt,
        filters=(
            ExecutionReceipt.tenant_id == decision.tenant_id,
            ExecutionReceipt.decision_receipt_id == decision.receipt_id,
        ),
        order_by=(ExecutionReceipt.execution_attempt_id,),
        limit=MAX_EXECUTION_RECEIPTS,
        category="execution receipts",
    )
    integrities = _bounded_rows(
        db,
        ExecutionIntegrityResult,
        filters=(
            ExecutionIntegrityResult.tenant_id == decision.tenant_id,
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
        ),
        order_by=(ExecutionIntegrityResult.execution_attempt_id,),
        limit=MAX_INTEGRITY_RESULTS,
        category="integrity results",
    )
    downstream_refs: list[dict[str, Any]] = []
    for execution in executions:
        candidates.append(
            {
                "role": "execution_receipt",
                "node_id": execution.evidence_node_id,
                "execution_attempt_id": execution.execution_attempt_id,
            }
        )
        downstream = list(execution.downstream_objects or [])
        if len(downstream) > contract.MAX_DOWNSTREAM_OBJECTS:
            raise ValueError("canonical evidence bundle downstream objects limit exceeded")
        for value in downstream:
            if not isinstance(value, Mapping):
                raise ValueError("canonical evidence bundle downstream object is not redaction-safe")
            object_hash = str(value.get("object_hash") or "").strip()
            if not object_hash:
                raise ValueError("canonical evidence bundle downstream object hash is missing")
        if downstream:
            mapping = {
                "execution_attempt_id": execution.execution_attempt_id,
                "execution_receipt_id": execution.receipt_id,
                "object_count": len(downstream),
                "aggregate_hash": contract._hash(downstream),
            }
            downstream_refs.append(mapping)
            candidates.append(
                {
                    "role": "downstream_objects",
                    "node_id": execution.evidence_node_id,
                    **mapping,
                }
            )
    for integrity in integrities:
        candidates.append(
            {
                "role": "current_execution_integrity",
                "node_id": integrity.evidence_bundle_id,
                "execution_attempt_id": integrity.execution_attempt_id,
            }
        )
        if integrity.superseded_evidence_node_id:
            candidates.append(
                {
                    "role": "superseded_evidence",
                    "node_id": integrity.superseded_evidence_node_id,
                    "execution_attempt_id": integrity.execution_attempt_id,
                }
            )
        if integrity.supersession_evidence_node_id:
            candidates.append(
                {
                    "role": "supersession_evidence",
                    "node_id": integrity.supersession_evidence_node_id,
                    "execution_attempt_id": integrity.execution_attempt_id,
                }
            )
    findings = _bounded_rows(
        db,
        Finding,
        filters=(
            Finding.tenant_id == decision.tenant_id,
            Finding.canonical_action_id == decision.action_id,
        ),
        order_by=(Finding.finding_id,),
        limit=MAX_FINDINGS,
        category="findings",
    )
    finding_refs: list[dict[str, Any]] = []
    for finding in sorted(findings, key=lambda item: item.finding_id):
        evidence_ids = sorted({str(item) for item in list(finding.evidence_node_ids or []) if str(item)})
        if len(evidence_ids) > MAX_FINDING_EVIDENCE_REFS:
            raise ValueError("canonical evidence bundle finding evidence refs limit exceeded")
        finding_body = {
            "finding_id": finding.finding_id,
            "finding_type": finding.finding_type,
            "execution_attempt_id": finding.execution_attempt_id,
            "evidence_node_ids": evidence_ids,
        }
        finding_refs.append({**finding_body, "finding_hash": contract._hash(finding_body)})
        candidates.extend(
            {
                "role": "finding_evidence",
                "node_id": node_id,
                "finding_id": finding.finding_id,
            }
            for node_id in evidence_ids
        )
    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        role = str(candidate["role"])
        node_id = candidate.get("node_id")
        context = {
            key: value
            for key, value in candidate.items()
            if key not in {"role", "node_id"}
        }
        member_identity = contract._hash(
            {"role": role, "node_id": node_id, "context": context}
        )
        if not node_id or member_identity in seen:
            continue
        node = db.get(EvidenceNode, node_id)
        if node is None or node.tenant_id != decision.tenant_id:
            raise ValueError("bundle member is missing or belongs to another tenant")
        seen.add(member_identity)
        members.append(
            {
                "role": role,
                "node_id": node.id,
                "node_type": node.node_type,
                "member_hash": contract._hash(_node_body(node)),
                **context,
            }
        )
        if len(members) > MAX_TOTAL_MANIFEST_MEMBERS:
            raise ValueError("canonical evidence bundle total members limit exceeded")
    members.sort(key=lambda item: contract._hash(item))
    execution_by_attempt = {item.execution_attempt_id: item for item in executions}
    attempts = [
        {
            "execution_attempt_id": item.execution_attempt_id,
            "execution_receipt_id": (
                execution_by_attempt[item.execution_attempt_id].receipt_id
                if item.execution_attempt_id in execution_by_attempt
                else None
            ),
            "integrity_result_id": item.result_id,
            "integrity_result": item.result,
        }
        for item in integrities
    ]
    runtime_rows = _bounded_rows(
        db,
        RuntimeEvent,
        filters=(
            RuntimeEvent.tenant_id == decision.tenant_id,
            or_(
                RuntimeEvent.chain_id == decision.chain_id,
                RuntimeEvent.evidence_bundle_id == bundle_id,
            ),
        ),
        order_by=(RuntimeEvent.event_id,),
        limit=MAX_RUNTIME_TRACES,
        category="runtime traces",
    )
    trace_refs = [
        {
            "runtime_event_id": item.event_id,
            "correlation_id": item.correlation_id,
            "chain_id": item.chain_id,
        }
        for item in sorted(runtime_rows, key=lambda item: item.event_id)
    ]
    downstream_refs.sort(key=lambda item: item["execution_attempt_id"])
    return members, attempts, finding_refs, trace_refs, downstream_refs


def _integrity_status(attempts: list[dict[str, Any]], *, authoritative_policy: bool) -> str:
    if not authoritative_policy:
        return "incomplete"
    results = {str(item.get("integrity_result")) for item in attempts}
    if "drift_detected" in results:
        return "drift_detected"
    if "incomplete" in results:
        return "incomplete"
    if "execution_unknown" in results:
        return "execution_unknown"
    if results and results <= {"matched"}:
        return "complete"
    return "incomplete"


def _manifest_node_id(
    *, bundle_id: str, state_hash: str, manifest_version: int, previous_manifest_id: str | None
) -> str:
    return str(
        uuid5(
            NAMESPACE_URL,
            "hawk:evidence-bundle-manifest:"
            f"{bundle_id}:{state_hash}:{manifest_version}:{previous_manifest_id or 'GENESIS'}",
        )
    )


def _load_manifest_history(
    db: Session,
    *,
    tenant_id: str,
    root: EvidenceNode,
    settings_obj: Any,
) -> list[EvidenceNode]:
    contract = _receipt_contract()
    edges = _bounded_edges(
        db,
        tenant_id=tenant_id,
        from_node_id=root.id,
        edge_type="bundle_manifest",
        limit=MAX_MANIFEST_HISTORY,
        category="manifest history",
    )
    manifests: list[EvidenceNode] = []
    for edge in edges:
        if not _edge_identity_valid(edge):
            raise ValueError("canonical evidence bundle manifest edge identity is invalid")
        manifest = db.get(EvidenceNode, edge.to_node_id)
        if manifest is None or manifest.tenant_id != tenant_id:
            raise ValueError("canonical evidence bundle manifest is missing")
        payload = dict(manifest.payload or {})
        expected_id = _manifest_node_id(
            bundle_id=root.id,
            state_hash=str(payload.get("state_hash") or ""),
            manifest_version=int(payload.get("manifest_version") or 0),
            previous_manifest_id=payload.get("previous_manifest_id"),
        )
        expected_edge_payload = {
            "manifest_version": payload.get("manifest_version"),
            "manifest_hash": contract._hash(_node_body(manifest)),
        }
        if (
            manifest.id != expected_id
            or payload.get("manifest_id") != manifest.id
            or manifest.node_type != BUNDLE_MANIFEST_TYPE
            or manifest.signal_type != "authorization.evidence.bundle.manifest"
            or manifest.label != f"Evidence bundle manifest v{payload.get('manifest_version')}"
            or not _verify_signed_payload(payload, settings_obj=settings_obj)
            or payload.get("bundle_id") != root.id
            or dict(edge.payload or {}) != expected_edge_payload
        ):
            raise ValueError("canonical evidence bundle manifest identity/history is invalid")
        manifests.append(manifest)
    manifests.sort(key=lambda item: int(dict(item.payload or {}).get("manifest_version") or 0))
    previous_id: str | None = None
    for expected_version, manifest in enumerate(manifests, start=1):
        payload = dict(manifest.payload or {})
        if (
            int(payload.get("manifest_version") or 0) != expected_version
            or payload.get("previous_manifest_id") != previous_id
        ):
            raise ValueError("canonical evidence bundle manifest chain is not contiguous")
        previous_id = manifest.id
    return manifests


def _integrity_evidence_node_valid(
    db: Session, node: EvidenceNode, *, tenant_id: str, settings_obj: Any
) -> bool:
    contract = _receipt_contract()
    payload = dict(node.payload or {})
    integrity = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.tenant_id == tenant_id,
            ExecutionIntegrityResult.result_id == payload.get("result_id"),
        )
    )
    if integrity is None:
        return False
    body = dict(payload)
    signature = body.pop("signature", None)
    body_hash = body.pop("integrity_body_hash", None)
    try:
        _, keys = contract._keyring(settings_obj)
        inner_signature_valid = bool(
            isinstance(body_hash, str)
            and isinstance(signature, str)
            and hmac.compare_digest(body_hash, contract._hash(body))
            and hmac.compare_digest(
                signature,
                contract._sign(
                    body, key_id=body.get("signing_key_id"), keys=keys
                ),
            )
        )
    except (TypeError, ValueError):
        inner_signature_valid = False
    provisional_id = str(
        uuid5(
            NAMESPACE_URL,
            f"hawk:integrity-evidence:{tenant_id}:{integrity.result_id}",
        )
    )
    if node.id == integrity.evidence_bundle_id:
        expected_id = str(
            uuid5(
                NAMESPACE_URL,
                (
                    "hawk:integrity-reconciled-evidence:"
                    f"{tenant_id}:{integrity.result_id}:{integrity.idempotency_key}"
                    if integrity.superseded_evidence_node_id
                    else f"hawk:integrity-evidence:{tenant_id}:{integrity.result_id}"
                ),
            )
        )
        typed_valid = bool(
            node.id == expected_id
            and inner_signature_valid
            and contract.verify_integrity_evidence(
                db,
                tenant_id=tenant_id,
                integrity=integrity,
                settings_obj=settings_obj,
            )
        )
    else:
        typed_valid = bool(
            node.id == provisional_id
            and integrity.superseded_evidence_node_id == node.id
            and integrity.superseded_integrity_body_hash
            and integrity.superseded_integrity_signature
            and inner_signature_valid
        )
    return bool(
        node.tenant_id == tenant_id
        and node.node_type == "execution_integrity_result"
        and node.signal_type == "authorization.execution_integrity"
        and node.label == f"Execution integrity: {payload.get('result')}"
        and payload.get("evidence_bundle_id") == node.id
        and payload.get("tenant_id") == tenant_id
        and typed_valid
    )


def _manifest_topology_valid(
    db: Session,
    *,
    tenant_id: str,
    manifest: EvidenceNode,
    settings_obj: Any,
) -> tuple[bool, bool]:
    """Verify one immutable revision against its exact signed edge topology."""

    contract = _receipt_contract()
    payload = dict(manifest.payload or {})
    members_value = payload.get("members")
    if not isinstance(members_value, list) or len(members_value) > MAX_TOTAL_MANIFEST_MEMBERS:
        return False, False
    if not all(isinstance(item, Mapping) for item in members_value):
        return False, False
    members = [dict(item) for item in members_value]
    structure_valid = payload.get("members_root_hash") == contract._hash(members)
    try:
        member_edges = _bounded_edges(
            db,
            tenant_id=tenant_id,
            from_node_id=manifest.id,
            edge_type="bundle_member",
            limit=MAX_TOTAL_MANIFEST_MEMBERS,
            category="manifest members",
        )
    except ValueError:
        return False, False

    expected_edges: list[tuple[str, str, str, dict[str, Any]]] = []
    for member in members:
        node_id = str(member.get("node_id") or "")
        edge_payload = {
            key: value
            for key, value in member.items()
            if key not in {"node_id", "node_type"}
        }
        integrity_key, edge_id = _canonical_edge_identity(
            tenant_id=tenant_id,
            from_node_id=manifest.id,
            to_node_id=node_id,
            edge_type="bundle_member",
            payload=edge_payload,
        )
        expected_edges.append((edge_id, node_id, integrity_key, edge_payload))
    actual_edges = [
        (edge.id, edge.to_node_id, str(edge.integrity_key or ""), dict(edge.payload or {}))
        for edge in member_edges
    ]
    structure_valid = bool(
        structure_valid
        and all(_edge_identity_valid(edge) for edge in member_edges)
        and sorted(expected_edges, key=lambda item: item[0])
        == sorted(actual_edges, key=lambda item: item[0])
    )

    source_current = True
    for member in members:
        node = db.get(EvidenceNode, member.get("node_id"))
        if (
            node is None
            or node.tenant_id != tenant_id
            or member.get("node_type") != node.node_type
            or member.get("member_hash") != contract._hash(_node_body(node))
        ):
            structure_valid = False
            continue
        role = member.get("role")
        if role == "canonical_action":
            node_payload = dict(node.payload or {})
            expected_id = str(
                uuid5(
                    NAMESPACE_URL,
                    "hawk:canonical-action-evidence:"
                    f"{tenant_id}:{node_payload.get('action_id')}:"
                    f"{node_payload.get('canonical_action_hash')}",
                )
            )
            structure_valid = bool(
                structure_valid
                and node.node_type == "canonical_ai_action"
                and node.signal_type == "authorization.canonical_action"
                and node.label == "Receipt-bound canonical AI action"
                and node.id == expected_id
            )
        elif role == "policy_snapshot":
            policy_result = verify_policy_snapshot(
                db, tenant_id=tenant_id, snapshot=node, settings_obj=settings_obj
            )
            structure_valid = bool(structure_valid and policy_result["signature_valid"])
            source_current = bool(source_current and policy_result["source_current"])
        elif role == "decision_receipt":
            decision = db.scalar(
                select(DecisionReceipt).where(
                    DecisionReceipt.tenant_id == tenant_id,
                    DecisionReceipt.evidence_node_id == node.id,
                )
            )
            structure_valid = bool(
                structure_valid
                and decision is not None
                and node.id
                == str(
                    uuid5(
                        NAMESPACE_URL,
                        f"hawk:decision-receipt-evidence:{tenant_id}:{decision.receipt_id}",
                    )
                )
                and contract.verify_decision_receipt(
                    decision,
                    tenant_id=tenant_id,
                    settings_obj=settings_obj,
                    now=decision.issued_at,
                    db=db,
                )
                and contract.verify_receipt_evidence(
                    db, tenant_id=tenant_id, receipt=decision
                )
            )
        elif role in {"execution_receipt", "downstream_objects"}:
            execution = db.scalar(
                select(ExecutionReceipt).where(
                    ExecutionReceipt.tenant_id == tenant_id,
                    ExecutionReceipt.evidence_node_id == node.id,
                )
            )
            structure_valid = bool(
                structure_valid
                and execution is not None
                and node.id
                == str(
                    uuid5(
                        NAMESPACE_URL,
                        f"hawk:execution-receipt-evidence:{tenant_id}:{execution.receipt_id}",
                    )
                )
                and contract.verify_execution_receipt(
                    execution, tenant_id=tenant_id, settings_obj=settings_obj
                )
                and contract.verify_receipt_evidence(
                    db, tenant_id=tenant_id, receipt=execution
                )
            )
        elif role == "current_execution_integrity":
            structure_valid = bool(
                structure_valid
                and _integrity_evidence_node_valid(
                    db, node, tenant_id=tenant_id, settings_obj=settings_obj
                )
            )
    return structure_valid, source_current


def refresh_evidence_bundle(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
) -> tuple[EvidenceNode, EvidenceNode]:
    contract = _receipt_contract()
    decision = db.scalar(
        select(DecisionReceipt)
        .where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if decision is None:
        raise ValueError("decision receipt tenant mismatch or not found")
    # SQLite ignores FOR UPDATE. This coordination write is deliberately on the
    # mutable receipt projection, never on immutable evidence nodes or edges.
    db.execute(
        update(DecisionReceipt)
        .where(
            DecisionReceipt.receipt_id == decision_receipt_id,
            DecisionReceipt.tenant_id == tenant_id,
        )
        .values(evidence_bundle_id=DecisionReceipt.evidence_bundle_id)
        .execution_options(synchronize_session=False)
    )
    db.refresh(decision)
    snapshot = (
        db.get(EvidenceNode, decision.policy_snapshot_evidence_node_id)
        if decision.policy_snapshot_evidence_node_id
        else None
    )
    if snapshot is None:
        snapshot = create_policy_snapshot(
            db,
            tenant_id=tenant_id,
            policy_version_id=decision.policy_snapshot_id,
            captured_at=decision.issued_at,
            settings_obj=settings_obj,
        )
        decision.policy_snapshot_evidence_node_id = snapshot.id
        db.flush()
    root_id = str(uuid5(NAMESPACE_URL, f"hawk:evidence-bundle:{tenant_id}:{decision.receipt_id}"))
    root_body = {
        "schema_name": "hawk.evidence_bundle",
        "schema_version": "1.0",
        "bundle_id": root_id,
        "tenant_id": tenant_id,
        "decision_receipt_id": decision.receipt_id,
        "action_id": decision.action_id,
        "created_at": _utc(decision.issued_at).isoformat(),
        "append_only": True,
    }
    root_payload = _signed_payload(root_body, settings_obj=settings_obj)
    root = db.get(EvidenceNode, root_id)
    if root is None:
        candidate = EvidenceNode(
            id=root_id,
            tenant_id=tenant_id,
            node_type=BUNDLE_ROOT_TYPE,
            signal_type="authorization.evidence.bundle",
            label=f"Canonical evidence bundle {decision.action_id}",
            payload=root_payload,
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            root = candidate
        except IntegrityError:
            db.expire_all()
            root = db.scalar(
                select(EvidenceNode)
                .where(EvidenceNode.id == root_id, EvidenceNode.tenant_id == tenant_id)
                .with_for_update()
            )
            if root is None or root.node_type != BUNDLE_ROOT_TYPE:
                raise ValueError("evidence bundle concurrent root conflict")
    if (
        root.tenant_id != tenant_id
        or root.node_type != BUNDLE_ROOT_TYPE
        or root.signal_type != "authorization.evidence.bundle"
        or root.label != f"Canonical evidence bundle {decision.action_id}"
        or dict(root.payload or {}) != root_payload
    ):
        raise ValueError("canonical evidence bundle root identity conflict")
    history = _load_manifest_history(
        db, tenant_id=tenant_id, root=root, settings_obj=settings_obj
    )
    current_manifest = history[-1] if history else None
    members, attempts, findings, trace_refs, downstream_refs = _bundle_members(
        db, decision=decision, policy_snapshot=snapshot, bundle_id=root.id
    )
    snapshot_authoritative = bool(dict(snapshot.payload or {}).get("authoritative"))
    state = {
        "members": members,
        "execution_attempts": attempts,
        "findings": findings,
        "trace_refs": trace_refs,
        "downstream_objects": downstream_refs,
        "integrity_status": _integrity_status(
            attempts, authoritative_policy=snapshot_authoritative
        ),
    }
    state_hash = contract._hash(state)
    if current_manifest is not None and dict(current_manifest.payload or {}).get("state_hash") == state_hash:
        decision.evidence_bundle_id = root.id
        db.flush()
        return root, current_manifest
    previous_manifest_id = current_manifest.id if current_manifest is not None else None
    manifest_version = len(history) + 1
    manifest_id = _manifest_node_id(
        bundle_id=root.id,
        state_hash=state_hash,
        manifest_version=manifest_version,
        previous_manifest_id=previous_manifest_id,
    )
    integrity_rows = _bounded_rows(
        db,
        ExecutionIntegrityResult,
        filters=(
            ExecutionIntegrityResult.tenant_id == tenant_id,
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
        ),
        order_by=(ExecutionIntegrityResult.execution_attempt_id,),
        limit=MAX_INTEGRITY_RESULTS,
        category="integrity results",
    )
    evaluated_at_values = [_utc(item.evaluated_at) for item in integrity_rows]
    manifest_body = {
        "schema_name": "hawk.evidence_bundle_manifest",
        "schema_version": "1.0",
        "manifest_id": manifest_id,
        "bundle_id": root.id,
        "tenant_id": tenant_id,
        "decision_receipt_id": decision.receipt_id,
        "action_id": decision.action_id,
        "manifest_version": manifest_version,
        "previous_manifest_id": previous_manifest_id,
        "policy_snapshot_evidence_node_id": snapshot.id,
        "members": members,
        "members_root_hash": contract._hash(members),
        "execution_attempts": attempts,
        "findings": findings,
        "trace_refs": trace_refs,
        "downstream_objects": downstream_refs,
        "integrity_status": state["integrity_status"],
        "state_hash": state_hash,
        "captured_at": max([_utc(decision.issued_at), *evaluated_at_values]).isoformat(),
    }
    if _canonical_json_size(manifest_body) > MAX_MANIFEST_BYTES:
        raise ValueError("canonical evidence bundle manifest material exceeds 64KiB")
    manifest_payload = _signed_payload(manifest_body, settings_obj=settings_obj)
    manifest = db.get(EvidenceNode, manifest_id)
    if manifest is None:
        candidate = EvidenceNode(
            id=manifest_id,
            tenant_id=tenant_id,
            node_type=BUNDLE_MANIFEST_TYPE,
            signal_type="authorization.evidence.bundle.manifest",
            label=f"Evidence bundle manifest v{manifest_version}",
            payload=manifest_payload,
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            manifest = candidate
        except IntegrityError:
            db.expire_all()
            manifest = db.get(EvidenceNode, manifest_id)
            if manifest is None:
                raise
            if (
                manifest.tenant_id != tenant_id
                or manifest.node_type != BUNDLE_MANIFEST_TYPE
                or dict(manifest.payload or {}) != manifest_payload
            ):
                raise ValueError("evidence bundle concurrent manifest conflict")
    elif dict(manifest.payload or {}) != manifest_payload:
        raise ValueError("evidence bundle manifest idempotency conflict")
    _edge(
        db,
        tenant_id=tenant_id,
        from_node_id=root.id,
        to_node_id=manifest.id,
        edge_type="bundle_manifest",
        payload={
            "manifest_version": manifest_version,
            "manifest_hash": contract._hash(_node_body(manifest)),
        },
    )
    for member in members:
        _edge(
            db,
            tenant_id=tenant_id,
            from_node_id=manifest.id,
            to_node_id=member["node_id"],
            edge_type="bundle_member",
            payload={
                key: value
                for key, value in member.items()
                if key not in {"node_id", "node_type"}
            },
        )
    decision.evidence_bundle_id = root.id
    db.flush()
    return root, manifest


def link_bundle_to_runtime_projections(
    db: Session,
    *,
    tenant_id: str,
    decision_receipt_id: str,
    settings_obj: Any,
    runtime_event_id: str | None = None,
) -> EvidenceNode:
    root, manifest = refresh_evidence_bundle(
        db,
        tenant_id=tenant_id,
        decision_receipt_id=decision_receipt_id,
        settings_obj=settings_obj,
    )
    decision = db.get(DecisionReceipt, decision_receipt_id)
    runtime_rows: list[RuntimeEvent] = []
    if runtime_event_id:
        row = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.event_id == runtime_event_id,
                RuntimeEvent.tenant_id == tenant_id,
            )
        )
        if row is not None:
            runtime_rows.append(row)
    chain_rows = _bounded_rows(
        db,
        RuntimeEvent,
        filters=(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.chain_id == decision.chain_id,
        ),
        order_by=(RuntimeEvent.event_id,),
        limit=MAX_RUNTIME_TRACES,
        category="runtime traces",
    )
    seen_runtime_ids = {item.event_id for item in runtime_rows}
    runtime_rows.extend(
        item for item in chain_rows if item.event_id not in seen_runtime_ids
    )
    if len(runtime_rows) > MAX_RUNTIME_TRACES:
        raise ValueError("canonical evidence bundle runtime traces limit exceeded")
    for runtime in runtime_rows:
        runtime.evidence_bundle_id = root.id
        runtime.evidence_node_ids = list(
            dict.fromkeys([*list(runtime.evidence_node_ids or []), root.id])
        )
    db.flush()
    root, manifest = refresh_evidence_bundle(
        db,
        tenant_id=tenant_id,
        decision_receipt_id=decision_receipt_id,
        settings_obj=settings_obj,
    )
    verification = verify_evidence_bundle(
        db,
        tenant_id=tenant_id,
        bundle=root,
        settings_obj=settings_obj,
    )
    canonical_summary = {
        "evidence_bundle_id": root.id,
        "manifest_id": manifest.id,
        "bundle_hash": _receipt_contract()._hash(_node_body(manifest)),
        "integrity_status": dict(manifest.payload or {}).get("integrity_status"),
        "verified": bool(verification["valid"]),
        "verification_status": (
            "verified" if verification["valid"] else "verification_failed"
        ),
        "canonical_authority": bool(verification["valid"]),
        "authority_source": "canonical_evidence_bundle_verifier",
        "display_only": True,
        "schema_version": "1.0",
    }
    for runtime in runtime_rows:
        activity_count = int(
            db.scalar(
                select(func.count())
                .select_from(AIAction)
                .where(
                    AIAction.tenant_id == tenant_id,
                    AIAction.runtime_event_id == runtime.event_id,
                )
            )
            or 0
        )
        activities = list(
            db.scalars(
                select(AIAction)
                .where(
                    AIAction.tenant_id == tenant_id,
                    AIAction.runtime_event_id == runtime.event_id,
                )
                .order_by(AIAction.action_id)
                .limit(MAX_PROJECTION_ROWS + 1)
            ).all()
        )
        projection_overflow = (
            activity_count > MAX_PROJECTION_ROWS
            or len(activities) > MAX_PROJECTION_ROWS
        )
        if projection_overflow:
            activities = []
            log_structured(
                "canonical_evidence_bundle_projection_incomplete",
                level="error",
                tenant_id=tenant_id,
                decision_receipt_id=decision_receipt_id,
                evidence_bundle_id=root.id,
                runtime_event_id=runtime.event_id,
                projection_row_count=activity_count,
                projection_row_limit=MAX_PROJECTION_ROWS,
            )
        runtime_summary = {
            **canonical_summary,
            "projection_status": (
                "incomplete_row_limit" if projection_overflow else "complete"
            ),
        }
        runtime.evidence_bundle_id = root.id
        runtime.evidence_node_ids = list(
            dict.fromkeys([*list(runtime.evidence_node_ids or []), root.id])
        )
        metadata = dict(runtime.metadata_json or {})
        metadata["canonical_evidence_bundle"] = runtime_summary
        metadata["evidence_bundle"] = {
            **dict(metadata.get("evidence_bundle") or {}),
            **runtime_summary,
        }
        ai_action = dict(metadata.get("ai_action") or {})
        if ai_action:
            ai_action["evidence_bundle"] = {
                **dict(ai_action.get("evidence_bundle") or {}),
                **runtime_summary,
            }
            metadata["ai_action"] = ai_action
        runtime.metadata_json = metadata
        for activity in activities:
            activity.evidence_bundle_id = root.id
            activity_metadata = dict(activity.metadata_json or {})
            activity_metadata["canonical_evidence_bundle"] = runtime_summary
            activity_metadata["evidence_bundle"] = {
                **dict(activity_metadata.get("evidence_bundle") or {}),
                **runtime_summary,
            }
            activity_ai_action = dict(activity_metadata.get("ai_action") or {})
            if activity_ai_action:
                activity_ai_action["evidence_bundle"] = {
                    **dict(activity_ai_action.get("evidence_bundle") or {}),
                    **runtime_summary,
                }
                activity_metadata["ai_action"] = activity_ai_action
            activity.metadata_json = activity_metadata
    db.flush()
    return root


def verify_evidence_bundle(
    db: Session,
    *,
    tenant_id: str,
    bundle: EvidenceNode,
    settings_obj: Any,
) -> dict[str, Any]:
    contract = _receipt_contract()
    root_payload = dict(bundle.payload or {})
    expected_root_id = str(
        uuid5(
            NAMESPACE_URL,
            "hawk:evidence-bundle:"
            f"{tenant_id}:{root_payload.get('decision_receipt_id')}",
        )
    )
    root_signature_valid = bool(
        bundle.tenant_id == tenant_id
        and bundle.node_type == BUNDLE_ROOT_TYPE
        and bundle.signal_type == "authorization.evidence.bundle"
        and bundle.label == f"Canonical evidence bundle {root_payload.get('action_id')}"
        and bundle.id == expected_root_id
        and root_payload.get("bundle_id") == bundle.id
        and root_payload.get("tenant_id") == tenant_id
        and _verify_signed_payload(root_payload, settings_obj=settings_obj)
    )
    if not root_signature_valid:
        return {"valid": False, "signature_valid": False, "source_current": False, "integrity_status": "invalid"}
    try:
        history = _load_manifest_history(
            db, tenant_id=tenant_id, root=bundle, settings_obj=settings_obj
        )
    except ValueError:
        return {"valid": False, "signature_valid": False, "source_current": False, "integrity_status": "invalid"}
    if not history:
        return {"valid": False, "signature_valid": True, "source_current": False, "integrity_status": "invalid"}
    manifest = history[-1]
    manifest_payload = dict(manifest.payload or {})
    structure_valid = True
    source_current = True
    for historical_manifest in history:
        revision_valid, revision_source_current = _manifest_topology_valid(
            db,
            tenant_id=tenant_id,
            manifest=historical_manifest,
            settings_obj=settings_obj,
        )
        structure_valid = bool(structure_valid and revision_valid)
        source_current = bool(source_current and revision_source_current)
    members = list(manifest_payload.get("members") or [])
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.receipt_id == root_payload.get("decision_receipt_id"),
        )
    )
    policy_snapshot = db.get(
        EvidenceNode, manifest_payload.get("policy_snapshot_evidence_node_id")
    )
    if decision is None or policy_snapshot is None:
        structure_valid = False
    else:
        try:
            expected_members, expected_attempts, expected_findings, expected_traces, expected_downstream = _bundle_members(
                db,
                decision=decision,
                policy_snapshot=policy_snapshot,
                bundle_id=bundle.id,
            )
            expected_state = {
                "members": expected_members,
                "execution_attempts": expected_attempts,
                "findings": expected_findings,
                "trace_refs": expected_traces,
                "downstream_objects": expected_downstream,
                "integrity_status": _integrity_status(
                    expected_attempts,
                    authoritative_policy=bool(
                        dict(policy_snapshot.payload or {}).get("authoritative")
                    ),
                ),
            }
            structure_valid = bool(
                structure_valid
                and members == expected_members
                and list(manifest_payload.get("execution_attempts") or []) == expected_attempts
                and list(manifest_payload.get("findings") or []) == expected_findings
                and list(manifest_payload.get("trace_refs") or []) == expected_traces
                and list(manifest_payload.get("downstream_objects") or []) == expected_downstream
                and manifest_payload.get("state_hash") == contract._hash(expected_state)
                and manifest_payload.get("integrity_status") == expected_state["integrity_status"]
            )
        except ValueError:
            structure_valid = False
    return {
        "valid": bool(root_signature_valid and structure_valid),
        "signature_valid": bool(root_signature_valid),
        "source_current": source_current,
        "integrity_status": manifest_payload.get("integrity_status") or "invalid",
    }


__all__ = [
    "create_policy_snapshot",
    "link_bundle_to_runtime_projections",
    "refresh_evidence_bundle",
    "verify_evidence_bundle",
    "verify_policy_snapshot",
]
