"""Tenant-bound instruction provenance and dynamic-tool exposure controls.

The service intentionally accepts an already-computed policy result.  It does
not authorize actions; it prevents unvalidated metadata from becoming model
input and binds the selected tool principal to Hawk's existing receipts.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.control_coverage import ControlCoverageAssessment
from app.db.models.external_capability_integrity import ExternalCapabilityIdentity
from app.db.models.instruction_tool_provenance import (
    InstructionProvenanceRecord,
    InstructionProvenanceSet,
    OpenWeightAttributionEvidence,
    ToolActionProvenanceBinding,
    ToolLifecycleEvent,
    ToolPrincipalBinding,
)
from app.services.external_capability_integrity import ExternalCapabilityIntegrityService
from app.services.action_integrity.signing import SigningKeyProvider, verify_signed_object
from app.services.native_control.inference_control import (
    InferenceCapabilityStatus,
    InferenceLifecycleEvent,
    build_default_inference_control_registry,
)


_COSMETIC_KEYS = frozenset({"display_name", "label", "icon", "color", "ui", "ui_metadata"})
_AUTHORITY_SOURCES = frozenset(
    {"SYSTEM", "DEVELOPER", "USER", "REPRESENTED_SUBJECT", "AUTHORIZED_ENTERPRISE_CONTEXT"}
)
_AUTHORITY_TRUST = frozenset({"VERIFIED", "TRUSTED_CURRENT"})
_PRINCIPAL_ASSERTION_PURPOSE = "tool_principal_binding"
_PRINCIPAL_ASSERTION_DOMAIN = "hawk:tool-principal-assertion:v1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _text(value: Any, *, maximum: int, fallback: str = "unknown") -> str:
    normalized = str(value or "").strip()
    return (normalized or fallback)[:maximum]


def _refs(values: Sequence[str] | None) -> list[str]:
    return sorted({_text(value, maximum=512) for value in (values or ()) if str(value or "").strip()})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash(domain: str, value: Any) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(_canonical(value))
    return digest.hexdigest()


def _principal(principal: Mapping[str, Any]) -> dict[str, str]:
    normalized = {
        "principal_type": _text(principal.get("principal_type"), maximum=64),
        "principal_ref": _text(principal.get("principal_ref"), maximum=255),
        "origin": _text(principal.get("origin"), maximum=512),
        "runtime_ref": _text(principal.get("runtime_ref"), maximum=255),
        "application_ref": _text(principal.get("application_ref"), maximum=255),
        "publisher_ref": _text(principal.get("publisher_ref"), maximum=255),
        "registration_source": _text(principal.get("registration_source"), maximum=255),
    }
    if normalized["principal_ref"] == "unknown":
        raise ValueError("tool principal_ref is required")
    return normalized


def _bundle(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    name = _text(bundle.get("name"), maximum=255)
    if name == "unknown":
        raise ValueError("tool name is required")
    material: dict[str, Any] = {
        "name": name,
        "description": _text(bundle.get("description"), maximum=4096, fallback=""),
        "schema": dict(bundle.get("schema") or {}),
        "instructions": [
            _text(item, maximum=2048, fallback="") for item in list(bundle.get("instructions") or [])[:64]
        ],
        "capabilities": sorted(_refs(list(bundle.get("capabilities") or []))),
        "resource_declarations": sorted(_refs(list(bundle.get("resource_declarations") or []))),
        "target_declarations": sorted(_refs(list(bundle.get("target_declarations") or []))),
        "destination_declarations": sorted(_refs(list(bundle.get("destination_declarations") or []))),
        "lifecycle_version": _text(bundle.get("lifecycle_version"), maximum=64),
    }
    cosmetic = {key: bundle[key] for key in sorted(_COSMETIC_KEYS) if key in bundle}
    return material, cosmetic


class InstructionToolProvenanceService:
    def __init__(
        self,
        db: Session,
        *,
        now: Callable[[], datetime] | None = None,
        signing_provider: SigningKeyProvider | None = None,
    ) -> None:
        self.db = db
        self._now = now or _now
        self._signing_provider = signing_provider
        self._integrity = ExternalCapabilityIntegrityService()

    @staticmethod
    def _bundle_for_assertion(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        return _bundle(bundle)

    @staticmethod
    def _tool_identity_hash(principal: Mapping[str, Any], material: Mapping[str, Any]) -> str:
        return _hash(
            "hawk:tool-principal-identity:v1",
            {"principal": _principal(principal), "tool_name": _text(material.get("name"), maximum=255)},
        )

    @staticmethod
    def _material_fingerprint(material: Mapping[str, Any]) -> str:
        return _hash("hawk:tool-material:v1", material)

    def register_tool(
        self,
        *,
        tenant_id: str,
        principal: Mapping[str, Any],
        bundle: Mapping[str, Any],
        evidence_quality: str,
        evidence_refs: Sequence[str] = (),
        principal_assertion: Mapping[str, Any] | None = None,
    ) -> ToolPrincipalBinding:
        principal_data = _principal(principal)
        material, cosmetic = _bundle(bundle)
        identity_hash = self._tool_identity_hash(principal_data, material)
        material_fingerprint = self._material_fingerprint(material)
        schema_fingerprint = _hash("hawk:tool-schema:v1", material["schema"])
        assertion = self._validate_principal_assertion(
            tenant_id=tenant_id,
            principal=principal_data,
            tool_identity_hash=identity_hash,
            material_fingerprint=material_fingerprint,
            principal_assertion=principal_assertion,
            existing_binding_id=None,
        )
        capability_ref = f"dynamic-tool:{identity_hash}"
        observed_at = self._monotonic_observed_at(
            tenant_id=tenant_id,
            asset_ref=f"external-capability:{capability_ref}",
        )
        integrity = self._integrity.observe_mcp_capability(
            self.db,
            tenant_id=tenant_id,
            capability_ref=capability_ref,
            observation=self._integrity_observation(principal_data, material),
            observed_at=observed_at,
            evidence_refs=list(evidence_refs),
            evidence_quality=_text(evidence_quality, maximum=64),
        )
        row = self.db.scalar(
            select(ToolPrincipalBinding)
            .where(
                ToolPrincipalBinding.tenant_id == tenant_id,
                ToolPrincipalBinding.tool_identity_hash == identity_hash,
            )
            .with_for_update()
        )
        if row is None:
            row = ToolPrincipalBinding(
                tenant_id=tenant_id,
                visible_name=material["name"],
                **principal_data,
                tool_identity_hash=identity_hash,
                material_fingerprint=material_fingerprint,
                schema_fingerprint=schema_fingerprint,
                material_bundle=material,
                cosmetic_metadata=cosmetic,
                lifecycle_version=material["lifecycle_version"],
                lifecycle_state="QUARANTINED",
                state_version=1,
                capability_ref=capability_ref,
                trust_state=integrity.trust_state,
                evidence_quality=_text(evidence_quality, maximum=64),
                evidence_refs=_refs(evidence_refs),
                **assertion,
            )
            self.db.add(row)
            self.db.flush()
            self._event(
                row,
                from_state="DISCOVERED",
                to_state="QUARANTINED",
                prior_fingerprint=None,
                actor_ref="collector:dynamic-tool-registration",
                reason="new dynamic tool requires validation before exposure",
                evidence_refs=evidence_refs,
            )
            self.db.flush()
            return row

        if row.revoked or row.lifecycle_state == "REVOKED":
            row.trust_state = "REVOKED"
            self.db.flush()
            return row
        prior_fingerprint = row.material_fingerprint
        row.cosmetic_metadata = cosmetic
        row.evidence_quality = _text(evidence_quality, maximum=64)
        row.evidence_refs = _refs(list(row.evidence_refs or []) + list(evidence_refs))
        row.trust_state = integrity.trust_state
        # A structural registration is deliberately quarantined on the dynamic
        # execution path until a current signed principal assertion accompanies it.
        assertion = self._validate_principal_assertion(
            tenant_id=tenant_id,
            principal=principal_data,
            tool_identity_hash=identity_hash,
            material_fingerprint=material_fingerprint,
            principal_assertion=principal_assertion,
            existing_binding_id=row.id,
        )
        for field, value in assertion.items():
            setattr(row, field, value)
        if prior_fingerprint != material_fingerprint:
            prior_state = row.lifecycle_state
            row.material_fingerprint = material_fingerprint
            row.schema_fingerprint = schema_fingerprint
            row.material_bundle = material
            row.lifecycle_version = material["lifecycle_version"]
            row.lifecycle_state = "QUARANTINED"
            row.state_version += 1
            row.last_verified_at = None
            self._event(
                row,
                from_state=prior_state,
                to_state="QUARANTINED",
                prior_fingerprint=prior_fingerprint,
                actor_ref="collector:dynamic-tool-registration",
                reason="material tool metadata changed; prior validation is invalid",
                evidence_refs=evidence_refs,
            )
        elif not bool(assertion["principal_assertion_valid"]):
            # No signed proof is not an error for discovery/legacy scan callers,
            # but it may not retain a previous execution-capable availability.
            row.lifecycle_state = "QUARANTINED"
            row.state_version += 1
            row.last_verified_at = None
        self.db.flush()
        return row

    def validate_tool(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        expected_version: int,
        actor_ref: str,
        metadata_verdict: str,
        policy_allowed: bool,
        evidence_refs: Sequence[str] = (),
    ) -> ToolPrincipalBinding:
        row = self._binding(tenant_id=tenant_id, binding_id=binding_id, for_update=True)
        if row.state_version != expected_version:
            raise RuntimeError("stale tool lifecycle version")
        if row.revoked or row.lifecycle_state == "REVOKED":
            raise PermissionError("revoked tool requires explicit recovery workflow")
        prior_state = row.lifecycle_state
        verdict = _text(metadata_verdict, maximum=32).upper()
        if (
            verdict == "SAFE"
            and policy_allowed
            and row.principal_ref != "unknown"
            and self._assertion_current(row)
        ):
            integrity = self._integrity.accept_current_baseline(
                self.db,
                tenant_id=tenant_id,
                capability_ref=row.capability_ref,
                actor_ref=_text(actor_ref, maximum=255),
                reason="instruction and tool provenance validation accepted exact material",
                accepted_at=self._now(),
            )
            row.lifecycle_state = "AVAILABLE"
            row.trust_state = integrity.trust_state
            row.last_verified_at = self._now()
            reason = "validated material is available for exposure"
        else:
            row.lifecycle_state = "REJECTED"
            row.trust_state = "REGRESSED"
            reason = "metadata validation, signed principal proof, or supplied policy result rejected tool"
        row.state_version += 1
        row.evidence_refs = _refs(list(row.evidence_refs or []) + list(evidence_refs))
        self._event(
            row,
            from_state=prior_state,
            to_state=row.lifecycle_state,
            prior_fingerprint=row.material_fingerprint,
            actor_ref=actor_ref,
            reason=reason,
            evidence_refs=evidence_refs,
        )
        self.db.flush()
        return row

    def expose_tools(
        self,
        *,
        tenant_id: str,
        binding_ids: Sequence[str] | None = None,
        execution_capable: bool,
    ) -> list[dict[str, Any]]:
        query = select(ToolPrincipalBinding).where(ToolPrincipalBinding.tenant_id == tenant_id)
        if binding_ids is not None:
            if not binding_ids:
                return []
            query = query.where(ToolPrincipalBinding.id.in_(list(binding_ids)))
        rows = self.db.scalars(query).all()
        result: list[dict[str, Any]] = []
        for row in rows:
            integrity = self.db.scalar(
                select(ExternalCapabilityIdentity).where(
                    ExternalCapabilityIdentity.tenant_id == tenant_id,
                    ExternalCapabilityIdentity.capability_ref == row.capability_ref,
                )
            )
            if (
                row.lifecycle_state != "AVAILABLE"
                or row.revoked
                or integrity is None
                or integrity.trust_state != "TRUSTED_CURRENT"
                or not self._assertion_current(row)
            ):
                continue
            if execution_capable and not row.last_verified_at:
                continue
            result.append(
                {
                    "binding_id": row.id,
                    "tool_identity_hash": row.tool_identity_hash,
                    "principal_ref": row.principal_ref,
                    "material_fingerprint": row.material_fingerprint,
                    "schema_fingerprint": row.schema_fingerprint,
                    "lifecycle_version": row.lifecycle_version,
                    "bundle": dict(row.material_bundle or {}),
                }
            )
        return sorted(result, key=lambda item: (item["principal_ref"], item["tool_identity_hash"]))

    def quarantine_tool(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        expected_version: int,
        actor_ref: str,
        reason: str,
        evidence_refs: Sequence[str] = (),
    ) -> ToolPrincipalBinding:
        row = self._binding(tenant_id=tenant_id, binding_id=binding_id, for_update=True)
        if row.state_version != expected_version:
            raise RuntimeError("stale tool lifecycle version")
        if row.revoked or row.lifecycle_state == "REVOKED":
            raise PermissionError("revoked tool cannot be returned to quarantine")
        prior_state = row.lifecycle_state
        row.lifecycle_state = "QUARANTINED"
        row.last_verified_at = None
        row.state_version += 1
        row.evidence_refs = _refs(list(row.evidence_refs or []) + list(evidence_refs))
        self._event(
            row,
            from_state=prior_state,
            to_state="QUARANTINED",
            prior_fingerprint=row.material_fingerprint,
            actor_ref=actor_ref,
            reason=reason,
            evidence_refs=evidence_refs,
        )
        self.db.flush()
        return row

    def revoke_tool(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        expected_version: int,
        actor_ref: str,
        reason: str,
    ) -> ToolPrincipalBinding:
        row = self._binding(tenant_id=tenant_id, binding_id=binding_id, for_update=True)
        if row.state_version != expected_version:
            raise RuntimeError("stale tool lifecycle version")
        if row.lifecycle_state == "REVOKED":
            return row
        prior_state = row.lifecycle_state
        self._integrity.revoke_capability(
            self.db,
            tenant_id=tenant_id,
            capability_ref=row.capability_ref,
            actor_ref=_text(actor_ref, maximum=255),
            reason=_text(reason, maximum=512),
            revoked_at=self._now(),
        )
        row.lifecycle_state = "REVOKED"
        row.trust_state = "REVOKED"
        row.revoked = True
        row.state_version += 1
        self._event(
            row,
            from_state=prior_state,
            to_state="REVOKED",
            prior_fingerprint=row.material_fingerprint,
            actor_ref=actor_ref,
            reason=reason,
            evidence_refs=(),
        )
        self.db.flush()
        return row

    def record_instruction(
        self,
        *,
        tenant_id: str,
        run_id: str,
        action_id: str,
        source_type: str,
        source_ref: str,
        originating_principal_ref: str,
        represented_subject_ref: str | None,
        trust_state: str,
        requested_semantic: str,
        instruction_fingerprint: str,
        evidence_refs: Sequence[str] = (),
        derivation_refs: Sequence[str] = (),
    ) -> InstructionProvenanceRecord:
        source = _text(source_type, maximum=64).upper()
        trust = _text(trust_state, maximum=32).upper()
        requested = _text(requested_semantic, maximum=64).upper()
        principal_ref = _text(originating_principal_ref, maximum=255)
        authority_granted = (
            requested == "AUTHORIZED_ACTION_SOURCE"
            and source in _AUTHORITY_SOURCES
            and trust in _AUTHORITY_TRUST
            and principal_ref != "unknown"
        )
        if authority_granted:
            semantic = "AUTHORIZED_ACTION_SOURCE"
        elif requested == "CONTEXT_ONLY":
            semantic = "CONTEXT_ONLY"
        else:
            semantic = "INFLUENCE_ONLY"
        provenance_set = self._provenance_set(
            tenant_id=tenant_id,
            run_id=run_id,
            action_id=action_id,
        )
        fingerprint = _text(instruction_fingerprint, maximum=64)
        if len(fingerprint) != 64:
            raise ValueError("instruction_fingerprint must be a 64-character digest")
        row = InstructionProvenanceRecord(
            tenant_id=tenant_id,
            provenance_set_id=provenance_set.id,
            source_type=source,
            source_ref=_text(source_ref, maximum=512),
            originating_principal_ref=principal_ref,
            represented_subject_ref=(
                _text(represented_subject_ref, maximum=255) if represented_subject_ref else None
            ),
            trust_state=trust,
            requested_semantic=requested,
            authority_semantic=semantic,
            influenced=True,
            authority_granted=authority_granted,
            instruction_fingerprint=fingerprint,
            evidence_refs=_refs(evidence_refs),
            derivation_refs=_refs(derivation_refs),
            observed_at=self._now(),
        )
        self.db.add(row)
        self.db.flush()
        return row

    def propagate_handoff(
        self,
        *,
        tenant_id: str,
        source_set_id: str,
        target_run_id: str,
        target_action_id: str,
        handoff_ref: str,
    ) -> InstructionProvenanceSet:
        source_set = self.db.scalar(
            select(InstructionProvenanceSet).where(
                InstructionProvenanceSet.tenant_id == tenant_id,
                InstructionProvenanceSet.id == source_set_id,
            )
        )
        if source_set is None:
            raise PermissionError("instruction provenance tenant binding is invalid")
        inherited = list(
            self.db.scalars(
                select(InstructionProvenanceRecord.id).where(
                    InstructionProvenanceRecord.tenant_id == tenant_id,
                    InstructionProvenanceRecord.provenance_set_id == source_set_id,
                )
            ).all()
        )
        row = InstructionProvenanceSet(
            tenant_id=tenant_id,
            run_id=_text(target_run_id, maximum=255),
            action_id=_text(target_action_id, maximum=255),
            parent_set_id=source_set.id,
            handoff_ref=_text(handoff_ref, maximum=255),
            inherited_record_ids=inherited,
            created_at=self._now(),
        )
        self.db.add(row)
        self.db.flush()
        return row

    def record_open_weight_attribution(
        self,
        *,
        tenant_id: str,
        provenance_set_id: str,
        source_record_id: str,
        attribution_ref: str,
        confidence: str,
        evidence_refs: Sequence[str] = (),
    ) -> OpenWeightAttributionEvidence:
        source = self.db.scalar(
            select(InstructionProvenanceRecord).where(
                InstructionProvenanceRecord.tenant_id == tenant_id,
                InstructionProvenanceRecord.provenance_set_id == provenance_set_id,
                InstructionProvenanceRecord.id == source_record_id,
            )
        )
        if source is None:
            raise PermissionError("instruction attribution tenant binding is invalid")
        row = OpenWeightAttributionEvidence(
            tenant_id=tenant_id,
            provenance_set_id=provenance_set_id,
            source_record_id=source_record_id,
            attribution_ref=_text(attribution_ref, maximum=512),
            confidence=_text(confidence, maximum=32),
            evidence_class="ADVISORY_CORRELATED",
            can_grant_authority=False,
            evidence_refs=_refs(evidence_refs),
            observed_at=self._now(),
        )
        self.db.add(row)
        self.db.flush()
        return row

    def bind_action(
        self,
        *,
        tenant_id: str,
        action_id: str,
        binding_id: str,
        provenance_set_id: str,
        decision_receipt_id: str | None,
        execution_permit_id: str | None,
        execution_receipt_id: str | None,
        actual_tool_identity_hash: str | None,
        actual_material_fingerprint: str | None,
    ) -> ToolActionProvenanceBinding:
        binding = self._binding(tenant_id=tenant_id, binding_id=binding_id)
        if binding.lifecycle_state != "AVAILABLE" or binding.revoked or not self._assertion_current(binding):
            raise PermissionError("tool is not available for action binding")
        provenance_set = self.db.scalar(
            select(InstructionProvenanceSet).where(
                InstructionProvenanceSet.tenant_id == tenant_id,
                InstructionProvenanceSet.id == provenance_set_id,
            )
        )
        if provenance_set is None:
            raise PermissionError("instruction provenance tenant binding is invalid")
        actual_observed = bool(actual_tool_identity_hash and actual_material_fingerprint)
        if actual_observed and (
            actual_tool_identity_hash != binding.tool_identity_hash
            or actual_material_fingerprint != binding.material_fingerprint
        ):
            raise PermissionError("actual tool identity or fingerprint does not match authorization")
        record_ids = list(
            self.db.scalars(
                select(InstructionProvenanceRecord.id).where(
                    InstructionProvenanceRecord.tenant_id == tenant_id,
                    InstructionProvenanceRecord.provenance_set_id == provenance_set_id,
                )
            ).all()
        )
        row = self.db.scalar(
            select(ToolActionProvenanceBinding).where(
                ToolActionProvenanceBinding.tenant_id == tenant_id,
                ToolActionProvenanceBinding.action_id == _text(action_id, maximum=255),
            )
        )
        if row is not None:
            if (
                row.tool_binding_id != binding.id
                or row.provenance_set_id != provenance_set_id
                or row.material_fingerprint != binding.material_fingerprint
            ):
                raise PermissionError("tool action binding conflicts with the selected current tool")
            row.decision_receipt_id = decision_receipt_id or row.decision_receipt_id
            row.execution_permit_id = execution_permit_id or row.execution_permit_id
            row.execution_receipt_id = execution_receipt_id or row.execution_receipt_id
            if actual_observed:
                row.actual_tool_identity_hash = actual_tool_identity_hash
                row.actual_material_fingerprint = actual_material_fingerprint
                row.actual_identity_observed = True
                row.comparison_state = "MATCHED"
            self.db.flush()
            return row
        row = ToolActionProvenanceBinding(
            tenant_id=tenant_id,
            action_id=_text(action_id, maximum=255),
            tool_binding_id=binding.id,
            provenance_set_id=provenance_set_id,
            tool_identity_hash=binding.tool_identity_hash,
            material_fingerprint=binding.material_fingerprint,
            schema_fingerprint=binding.schema_fingerprint,
            lifecycle_version=binding.lifecycle_version,
            provenance_record_ids=record_ids,
            decision_receipt_id=decision_receipt_id,
            execution_permit_id=execution_permit_id,
            execution_receipt_id=execution_receipt_id,
            actual_tool_identity_hash=actual_tool_identity_hash,
            actual_material_fingerprint=actual_material_fingerprint,
            actual_identity_observed=actual_observed,
            comparison_state="MATCHED" if actual_observed else "UNVERIFIED",
            created_at=self._now(),
        )
        self.db.add(row)
        self.db.flush()
        return row

    def action_reference_projection(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        action_id: str,
        tool_name: str,
        tool_fingerprint_id: str | None,
    ) -> dict[str, Any]:
        """Resolve only reference material for the authorization hash boundary."""
        binding = self._binding(tenant_id=tenant_id, binding_id=binding_id)
        if (
            binding.lifecycle_state != "AVAILABLE"
            or binding.revoked
            or not self._assertion_current(binding)
            or binding.visible_name != _text(tool_name, maximum=255)
        ):
            raise PermissionError("tool principal binding is not available or does not match authorization")
        claimed_fingerprint = _text(tool_fingerprint_id, maximum=64, fallback="")
        if (
            len(claimed_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in claimed_fingerprint)
            or claimed_fingerprint != binding.material_fingerprint
        ):
            raise PermissionError("tool principal material fingerprint does not match authorization")
        provenance = self._provenance_set(
            tenant_id=tenant_id,
            run_id=f"mcp-binding:{binding.id}",
            action_id=action_id,
        )
        return {
            "tool_binding_id": binding.id,
            "tool_identity": {
                "tool_identity_hash": binding.tool_identity_hash,
                "material_fingerprint": binding.material_fingerprint,
                "schema_fingerprint": binding.schema_fingerprint,
                "lifecycle_version": binding.lifecycle_version,
            },
            "instruction_provenance": {
                "provenance_set_id": provenance.id if provenance is not None else None,
                "record_ids": [],
            },
        }

    def assert_action_binding_current(
        self,
        *,
        tenant_id: str,
        action_binding_id: str,
        actual_tool_identity_hash: str,
        actual_material_fingerprint: str,
    ) -> ToolActionProvenanceBinding:
        row = self.db.scalar(
            select(ToolActionProvenanceBinding).where(
                ToolActionProvenanceBinding.tenant_id == tenant_id,
                ToolActionProvenanceBinding.id == action_binding_id,
            )
        )
        if row is None:
            raise PermissionError("tool action tenant binding is invalid")
        binding = self._binding(tenant_id=tenant_id, binding_id=row.tool_binding_id)
        if (
            binding.lifecycle_state != "AVAILABLE"
            or binding.material_fingerprint != row.material_fingerprint
            or binding.tool_identity_hash != row.tool_identity_hash
            or actual_tool_identity_hash != row.tool_identity_hash
            or actual_material_fingerprint != row.material_fingerprint
        ):
            row.comparison_state = "DRIFTED"
            self.db.flush()
            raise PermissionError("tool fingerprint changed after authorization")
        row.actual_tool_identity_hash = actual_tool_identity_hash
        row.actual_material_fingerprint = actual_material_fingerprint
        row.actual_identity_observed = True
        row.comparison_state = "MATCHED"
        self.db.flush()
        return row

    def attach_execution_permit(
        self,
        *,
        tenant_id: str,
        decision_receipt_id: str,
        execution_permit_id: str,
    ) -> ToolActionProvenanceBinding | None:
        row = self.db.scalar(
            select(ToolActionProvenanceBinding).where(
                ToolActionProvenanceBinding.tenant_id == tenant_id,
                ToolActionProvenanceBinding.decision_receipt_id == _text(decision_receipt_id, maximum=255),
            )
        )
        if row is None:
            return None
        row.execution_permit_id = _text(execution_permit_id, maximum=255)
        self.db.flush()
        return row

    def provider_timing_coverage(
        self,
        *,
        provider: str,
        product: str,
        runtime: str,
        repository_pre_exposure_gate: bool,
    ) -> dict[str, str]:
        pre_exposure = "VERIFIED" if repository_pre_exposure_gate else "UNVERIFIED"
        pre_execution = "UNVERIFIED"
        try:
            record = build_default_inference_control_registry().resolve(
                provider=provider,
                product=product,
                runtime=runtime,
            )
        except LookupError:
            return {"pre_exposure": pre_exposure, "pre_execution": pre_execution}
        if not repository_pre_exposure_gate:
            pre_exposure = self._event_status(record.manifest.for_event(InferenceLifecycleEvent.PRE_TOOL_SELECTION))
        pre_execution = self._event_status(record.manifest.for_event(InferenceLifecycleEvent.PRE_TOOL_EXECUTION))
        return {"pre_exposure": pre_exposure, "pre_execution": pre_execution}

    def _validate_principal_assertion(
        self,
        *,
        tenant_id: str,
        principal: Mapping[str, str],
        tool_identity_hash: str,
        material_fingerprint: str,
        principal_assertion: Mapping[str, Any] | None,
        existing_binding_id: str | None,
    ) -> dict[str, Any]:
        empty = {
            "principal_assertion_algorithm": None,
            "signing_key_id": None,
            "assertion_digest": None,
            "assertion_signature": None,
            "assertion_assurance": None,
            "assertion_nonce": None,
            "assertion_issued_at": None,
            "assertion_expires_at": None,
            "principal_assertion_valid": False,
        }
        if not principal_assertion or self._signing_provider is None:
            return empty
        value = dict(principal_assertion)
        try:
            issued_at = self._assertion_datetime(value.get("issued_at"))
            expires_at = self._assertion_datetime(value.get("expires_at"))
            nonce = _text(value.get("nonce"), maximum=255)
            assurance = _text(value.get("assurance"), maximum=64)
            if (
                nonce == "unknown"
                or assurance == "unknown"
                or issued_at > self._now()
                or expires_at <= self._now()
                or expires_at <= issued_at
                or value.get("tenant_id") != tenant_id
                or value.get("principal") != dict(principal)
                or value.get("tool_identity_hash") != tool_identity_hash
                or value.get("material_fingerprint") != material_fingerprint
                or not verify_signed_object(
                    self._signing_provider,
                    purpose=_PRINCIPAL_ASSERTION_PURPOSE,
                    domain=_PRINCIPAL_ASSERTION_DOMAIN,
                    tenant_id=tenant_id,
                    value=value,
                    current_authority=True,
                )
            ):
                return empty
            prior = self.db.scalar(
                select(ToolPrincipalBinding).where(
                    ToolPrincipalBinding.tenant_id == tenant_id,
                    ToolPrincipalBinding.assertion_nonce == nonce,
                )
            )
            if prior is not None and prior.id != existing_binding_id:
                raise PermissionError("principal assertion nonce replay or conflict")
            return {
                "principal_assertion_algorithm": _text(value.get("algorithm"), maximum=16),
                "signing_key_id": _text(value.get("signing_key_id"), maximum=255),
                "assertion_digest": _hash(_PRINCIPAL_ASSERTION_DOMAIN, value),
                "assertion_signature": _text(value.get("signature"), maximum=1024),
                "assertion_assurance": assurance,
                "assertion_nonce": nonce,
                "assertion_issued_at": issued_at,
                "assertion_expires_at": expires_at,
                "principal_assertion_valid": True,
            }
        except (TypeError, ValueError):
            return empty

    @staticmethod
    def _assertion_datetime(value: Any) -> datetime:
        if not isinstance(value, str):
            raise ValueError("assertion time is invalid")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("assertion time must be timezone-aware")
        return parsed.astimezone(timezone.utc)

    def _assertion_current(self, row: ToolPrincipalBinding) -> bool:
        if not row.principal_assertion_valid or self._signing_provider is None:
            return False
        expires_at = row.assertion_expires_at
        if expires_at is None:
            return False
        # SQLite can round-trip a timezone-aware SQLAlchemy DateTime as a
        # naive value, while PostgreSQL retains the offset.  Assertions are
        # stored as UTC and must receive identical expiry treatment after a
        # request/session boundary on both engines.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at = expires_at.astimezone(timezone.utc)
        if expires_at <= self._now():
            return False
        def serialized_assertion_time(value: datetime | None) -> str | None:
            if value is None:
                return None
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat()

        value = {
            "tenant_id": row.tenant_id,
            "principal": {
                "principal_type": row.principal_type,
                "principal_ref": row.principal_ref,
                "origin": row.origin or "unknown",
                "runtime_ref": row.runtime_ref or "unknown",
                "application_ref": row.application_ref or "unknown",
                "publisher_ref": row.publisher_ref or "unknown",
                "registration_source": row.registration_source or "unknown",
            },
            "tool_identity_hash": row.tool_identity_hash,
            "material_fingerprint": row.material_fingerprint,
            "nonce": row.assertion_nonce,
            "issued_at": serialized_assertion_time(row.assertion_issued_at),
            "expires_at": serialized_assertion_time(row.assertion_expires_at),
            "assurance": row.assertion_assurance,
            "algorithm": row.principal_assertion_algorithm,
            "signing_key_id": row.signing_key_id,
            "signature": row.assertion_signature,
        }
        return verify_signed_object(
            self._signing_provider,
            purpose=_PRINCIPAL_ASSERTION_PURPOSE,
            domain=_PRINCIPAL_ASSERTION_DOMAIN,
            tenant_id=row.tenant_id,
            value=value,
            current_authority=True,
        )

    @staticmethod
    def _event_status(capability: Any) -> str:
        status = capability.verification_status
        if status == InferenceCapabilityStatus.UNSUPPORTED and capability.pre_execution_blocking != InferenceCapabilityStatus.UNSUPPORTED:
            status = capability.pre_execution_blocking
        return status.value

    def _provenance_set(self, *, tenant_id: str, run_id: str, action_id: str) -> InstructionProvenanceSet:
        normalized_run = _text(run_id, maximum=255)
        normalized_action = _text(action_id, maximum=255)
        row = self.db.scalar(
            select(InstructionProvenanceSet).where(
                InstructionProvenanceSet.tenant_id == tenant_id,
                InstructionProvenanceSet.run_id == normalized_run,
                InstructionProvenanceSet.action_id == normalized_action,
            )
        )
        if row is None:
            row = InstructionProvenanceSet(
                tenant_id=tenant_id,
                run_id=normalized_run,
                action_id=normalized_action,
                inherited_record_ids=[],
                created_at=self._now(),
            )
            self.db.add(row)
            self.db.flush()
        return row

    def _binding(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        for_update: bool = False,
    ) -> ToolPrincipalBinding:
        statement = select(ToolPrincipalBinding).where(ToolPrincipalBinding.id == binding_id)
        if for_update:
            statement = statement.with_for_update()
        row = self.db.scalar(statement)
        if row is None or row.tenant_id != tenant_id:
            raise PermissionError("tool principal tenant binding is invalid")
        return row

    def _monotonic_observed_at(self, *, tenant_id: str, asset_ref: str) -> datetime:
        """Keep successive immutable projections ordered when clocks collide."""
        observed_at = self._now()
        previous = self.db.scalar(
            select(func.max(ControlCoverageAssessment.assessed_at)).where(
                ControlCoverageAssessment.tenant_id == tenant_id,
                ControlCoverageAssessment.asset_ref == asset_ref,
            )
        )
        if previous is None:
            return observed_at
        if previous.tzinfo is None:
            previous = previous.replace(tzinfo=timezone.utc)
        if observed_at <= previous:
            return previous + timedelta(microseconds=1)
        return observed_at

    def _event(
        self,
        row: ToolPrincipalBinding,
        *,
        from_state: str,
        to_state: str,
        prior_fingerprint: str | None,
        actor_ref: str,
        reason: str,
        evidence_refs: Sequence[str],
    ) -> None:
        sequence = (
            self.db.scalar(
                select(func.max(ToolLifecycleEvent.sequence)).where(
                    ToolLifecycleEvent.tenant_id == row.tenant_id,
                    ToolLifecycleEvent.binding_id == row.id,
                )
            )
            or 0
        ) + 1
        self.db.add(
            ToolLifecycleEvent(
                tenant_id=row.tenant_id,
                binding_id=row.id,
                sequence=sequence,
                from_state=_text(from_state, maximum=32),
                to_state=_text(to_state, maximum=32),
                prior_material_fingerprint=prior_fingerprint,
                current_material_fingerprint=row.material_fingerprint,
                actor_ref=_text(actor_ref, maximum=255),
                reason=_text(reason, maximum=512),
                evidence_refs=_refs(evidence_refs),
                observed_at=self._now(),
            )
        )

    @staticmethod
    def _integrity_observation(principal: Mapping[str, str], material: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "configured_locator": principal["origin"],
            "registry_source": principal["registration_source"],
            "registry_identity": principal["principal_ref"],
            "publisher_identity": principal["publisher_ref"],
            "observed_endpoint": principal["origin"],
            "domain": principal["origin"],
            "transport": "repository-native",
            "auth_mode": "tenant-bound-principal",
            "server_metadata": {
                "name": principal["principal_ref"],
                "version": material["lifecycle_version"],
            },
            "protocol_version": "tool-provenance/1.0",
            "tools": [
                {
                    "name": material["name"],
                    "version": material["lifecycle_version"],
                    "description": material["description"],
                    "inputSchema": material["schema"],
                    "annotations": {
                        "capabilities": material["capabilities"],
                        "resource_declarations": material["resource_declarations"],
                        "target_declarations": material["target_declarations"],
                        "destination_declarations": material["destination_declarations"],
                    },
                }
            ],
            "instructions": material["instructions"],
        }
