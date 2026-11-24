from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.platform_mode_service import get_tenant_platform_mode


router = APIRouter(prefix="/onprem", tags=["onprem"])


class OnPremPolicyVersion(BaseModel):
    id: str
    pack_id: str
    pack_name: str
    version: str
    created_at: datetime
    scope: dict
    enforcement_defaults: dict
    guardian_contract_count: int


class OnPremPolicySyncResponse(BaseModel):
    tenant_id: str
    platform_mode: str
    synced_at: datetime
    policy_hash: str
    active_policy_versions: list[OnPremPolicyVersion]


class OnPremEvidenceEntry(BaseModel):
    entry_id: str
    timestamp: str
    signal_type: str
    payload: dict = Field(default_factory=dict)
    payload_hash: str
    prev_hash: str
    entry_hash: str


class OnPremEvidenceBundle(BaseModel):
    schema_name: str = "hawk.source_evidence_bundle"
    schema_version: str = "1.0"
    provenance_role: str = "source_provenance"
    canonical_authority: bool = False
    bundle_id: str
    tenant_id: str
    gateway_id: str
    generated_at: str
    source_metadata: dict = Field(default_factory=dict)
    entries: list[OnPremEvidenceEntry] = Field(default_factory=list)
    root_hash: str
    signature_algorithm: str = "hmac-sha256"
    signature: str


class OnPremBundleIngestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bundle_id: str
    accepted_entries: int
    root_evidence_node_id: str
    evidence_node_ids: list[str]


def _json_canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _compute_payload_hash(payload: dict) -> str:
    return _sha256_hex(_json_canonical(payload))


def _compute_entry_hash(
    *,
    entry_id: str,
    timestamp: str,
    signal_type: str,
    payload_hash: str,
    prev_hash: str,
) -> str:
    material = "|".join(
        [
            str(entry_id),
            str(timestamp),
            str(signal_type),
            str(payload_hash),
            str(prev_hash),
        ]
    )
    return _sha256_hex(material)


def _compute_root_hash(entries: list[OnPremEvidenceEntry]) -> str:
    if not entries:
        return _sha256_hex("empty")
    return entries[-1].entry_hash


def _bundle_signature_payload(bundle: OnPremEvidenceBundle) -> dict[str, Any]:
    return {
        "schema_name": bundle.schema_name,
        "schema_version": bundle.schema_version,
        "provenance_role": bundle.provenance_role,
        "canonical_authority": bundle.canonical_authority,
        "bundle_id": bundle.bundle_id,
        "tenant_id": bundle.tenant_id,
        "gateway_id": bundle.gateway_id,
        "generated_at": bundle.generated_at,
        "source_metadata": bundle.source_metadata,
        "entries": [row.model_dump() for row in bundle.entries],
        "root_hash": bundle.root_hash,
        "signature_algorithm": bundle.signature_algorithm,
    }


def _sign_bundle(bundle: OnPremEvidenceBundle, secret: str) -> str:
    payload = _json_canonical(_bundle_signature_payload(bundle))
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_bundle(bundle: OnPremEvidenceBundle) -> tuple[bool, str]:
    if (
        bundle.schema_name != "hawk.source_evidence_bundle"
        or bundle.schema_version != "1.0"
        or bundle.provenance_role != "source_provenance"
        or bundle.canonical_authority is not False
    ):
        return False, "On-prem bundle must remain source provenance, not canonical authority"
    if bundle.signature_algorithm != "hmac-sha256":
        return False, "Unsupported signature algorithm"

    if bundle.root_hash != _compute_root_hash(bundle.entries):
        return False, "Root hash mismatch"

    prev_hash = "GENESIS"
    for entry in bundle.entries:
        expected_payload_hash = _compute_payload_hash(entry.payload)
        if entry.payload_hash != expected_payload_hash:
            return False, f"Payload hash mismatch for entry {entry.entry_id}"
        if entry.prev_hash != prev_hash:
            return False, f"Hash chain mismatch for entry {entry.entry_id}"
        expected_entry_hash = _compute_entry_hash(
            entry_id=entry.entry_id,
            timestamp=entry.timestamp,
            signal_type=entry.signal_type,
            payload_hash=entry.payload_hash,
            prev_hash=entry.prev_hash,
        )
        if entry.entry_hash != expected_entry_hash:
            return False, f"Entry hash mismatch for entry {entry.entry_id}"
        prev_hash = entry.entry_hash

    secret = settings.onprem_bundle_signing_secret
    expected_signature = _sign_bundle(bundle, secret)
    if not hmac.compare_digest(bundle.signature, expected_signature):
        return False, "Signature mismatch"
    return True, "ok"


@router.get("/policy-sync", response_model=OnPremPolicySyncResponse)
def onprem_policy_sync(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    packs = db.scalars(
        select(PolicyPack).where(
            PolicyPack.tenant_id == ctx.tenant.id,
            PolicyPack.status == "active",
        )
    ).all()
    rows: list[OnPremPolicyVersion] = []
    for pack in sorted(packs, key=lambda row: (row.name, row.id)):
        version = db.scalar(
            select(PolicyVersion)
            .where(
                PolicyVersion.tenant_id == ctx.tenant.id,
                PolicyVersion.pack_id == pack.id,
            )
            .order_by(desc(PolicyVersion.created_at))
            .limit(1)
        )
        if version is None:
            continue
        rows.append(
            OnPremPolicyVersion(
                id=version.id,
                pack_id=pack.id,
                pack_name=pack.name,
                version=version.version,
                created_at=version.created_at,
                scope=version.scope or {},
                enforcement_defaults=version.enforcement_defaults or {},
                guardian_contract_count=len(version.guardian_contracts or []),
            )
        )

    synced_at = datetime.now(timezone.utc)
    policy_hash = _sha256_hex(
        _json_canonical(
            {
                "tenant_id": ctx.tenant.id,
                "platform_mode": get_tenant_platform_mode(db, tenant_id=ctx.tenant.id),
                "active_policy_versions": [row.model_dump(mode="json") for row in rows],
            }
        )
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="system",
        action="onprem.policy_sync",
        resource_type="tenant",
        resource_id=ctx.tenant.id,
        payload={
            "active_policy_versions": [row.id for row in rows],
            "policy_hash": policy_hash,
        },
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="onprem_policy_sync",
        signal_type="onprem.policy.sync",
        label="On-prem policy sync snapshot",
        payload={
            "tenant_id": ctx.tenant.id,
            "active_policy_versions": [row.id for row in rows],
            "policy_hash": policy_hash,
        },
    )
    db.commit()
    return OnPremPolicySyncResponse(
        tenant_id=ctx.tenant.id,
        platform_mode=get_tenant_platform_mode(db, tenant_id=ctx.tenant.id),
        synced_at=synced_at,
        policy_hash=policy_hash,
        active_policy_versions=rows,
    )


@router.post("/evidence-bundles/ingest", response_model=OnPremBundleIngestResponse)
def ingest_onprem_bundle(
    bundle: OnPremEvidenceBundle,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    if bundle.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bundle tenant mismatch")

    valid, reason = _verify_bundle(bundle)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    root = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="onprem_evidence_bundle",
        signal_type="onprem.bundle.ingested",
        label=f"On-prem evidence bundle {bundle.bundle_id}",
        payload={
            "schema_name": bundle.schema_name,
            "schema_version": bundle.schema_version,
            "provenance_role": bundle.provenance_role,
            "canonical_authority": False,
            "bundle_id": bundle.bundle_id,
            "gateway_id": bundle.gateway_id,
            "generated_at": bundle.generated_at,
            "source_metadata": bundle.source_metadata,
            "entry_count": len(bundle.entries),
            "root_hash": bundle.root_hash,
            "source_provenance_hash": bundle.root_hash,
            "signature": bundle.signature,
            "signature_algorithm": bundle.signature_algorithm,
        },
    )
    entry_node_ids: list[str] = []
    for entry in bundle.entries:
        node = create_evidence_node(
            db,
            tenant_id=ctx.tenant.id,
            node_type="onprem_signal",
            signal_type=entry.signal_type,
            label=f"On-prem signal {entry.signal_type}",
            payload={
                "bundle_id": bundle.bundle_id,
                "gateway_id": bundle.gateway_id,
                "entry_id": entry.entry_id,
                "timestamp": entry.timestamp,
                "payload": entry.payload,
                "payload_hash": entry.payload_hash,
                "prev_hash": entry.prev_hash,
                "entry_hash": entry.entry_hash,
                "source_metadata": bundle.source_metadata,
            },
        )
        entry_node_ids.append(node.id)
        link_evidence_nodes(
            db,
            tenant_id=ctx.tenant.id,
            from_node_id=root.id,
            to_node_id=node.id,
            edge_type="contains",
            payload={"bundle_id": bundle.bundle_id, "entry_id": entry.entry_id},
        )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="system",
        action="onprem.bundle.ingest",
        resource_type="onprem_bundle",
        resource_id=bundle.bundle_id,
        payload={
            "gateway_id": bundle.gateway_id,
            "entry_count": len(bundle.entries),
            "root_hash": bundle.root_hash,
            "root_evidence_node_id": root.id,
            "entry_evidence_node_ids": entry_node_ids,
        },
    )
    db.commit()
    return OnPremBundleIngestResponse(
        bundle_id=bundle.bundle_id,
        accepted_entries=len(bundle.entries),
        root_evidence_node_id=root.id,
        evidence_node_ids=[root.id, *entry_node_ids],
    )
