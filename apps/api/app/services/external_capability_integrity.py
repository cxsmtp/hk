"""External Capability Integrity service.

The service keeps external capability identity, observed material state and
trusted baselines separate. It reuses Phase 6 drift, Phase 7 lineage and Phase
8 coverage projections; it does not authorize actions by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_lineage import ActivityLineage, LineageNode
from app.db.models.continuous_assurance import ControlAssertion
from app.db.models.control_coverage import (
    ControlCoverageAssessment,
    ControlCoverageSnapshot,
    CoverageScope,
)
from app.db.models.external_capability_integrity import (
    ExternalCapabilityBaseline,
    ExternalCapabilityDrift,
    ExternalCapabilityIdentity,
    ExternalCapabilityValidationLink,
)
from app.services.continuous_assurance import ContinuousAssuranceService


MATERIAL_TOOL_KEYS = ("name", "version", "description", "inputSchema", "annotations")
MATERIAL_SERVER_KEYS = ("name", "version", "protocolVersion")
NON_MATERIAL_KEYS = {"displayName", "display_name", "label", "ui", "icon", "color"}
TRUST_TO_LEGACY_STATUS = {
    "UNKNOWN": "unknown",
    "TRUSTED_CURRENT": "approved",
    "STALE": "changed",
    "REGRESSED": "blocked",
    "REVOKED": "blocked",
}


@dataclass(frozen=True, slots=True)
class ExternalCapabilityState:
    capability_id: str
    capability_ref: str
    capability_type: str
    configured_locator: str
    observed_endpoint: str | None
    material_fingerprint: str
    component_fingerprints: dict[str, Any]
    tool_fingerprints: dict[str, dict[str, str]]
    baseline_id: str | None
    baseline_material_fingerprint: str | None
    trust_state: str
    capability_epoch: int
    evidence_quality: str
    drift_summary: dict[str, Any]
    last_observed_at: datetime
    last_verified_at: datetime | None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("ECI timestamps must be timezone-aware")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _text(value: Any, *, maximum: int = 255, fallback: str = "unknown") -> str:
    if isinstance(value, str):
        normalized = " ".join(value.split())
    elif value is None:
        normalized = ""
    else:
        normalized = " ".join(str(value).split())
    return (normalized[:maximum] if normalized else fallback)


def _refs(value: list[str] | tuple[str, ...] | None) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(dict.fromkeys(_text(item, maximum=255, fallback="") for item in value if item))[:100]


def _canonical_hash(domain: str, value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            {"domain": domain, "value": value},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _strip_non_material(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _strip_non_material(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in NON_MATERIAL_KEYS
        }
    if isinstance(value, list):
        return [_strip_non_material(item) for item in value]
    return value


def _bounded_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    annotations = tool.get("annotations") or {}
    return _strip_non_material(
        {
            "name": _text(tool.get("name"), maximum=128),
            "version": _text(tool.get("version"), maximum=64, fallback="unknown"),
            "description": _text(tool.get("description"), maximum=1000, fallback=""),
            "inputSchema": schema if isinstance(schema, Mapping) else {},
            "annotations": annotations if isinstance(annotations, Mapping) else {},
        }
    )


def _normalize_mcp_observation(observation: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    tools = []
    for item in observation.get("tools") or []:
        if isinstance(item, Mapping):
            tools.append(_bounded_tool(item))
    tools = sorted(tools, key=lambda row: (row["name"], row["version"]))
    server_metadata = observation.get("server_metadata")
    server = _strip_non_material(
        {
            "name": _text((server_metadata or {}).get("name") if isinstance(server_metadata, Mapping) else None, maximum=128),
            "version": _text((server_metadata or {}).get("version") if isinstance(server_metadata, Mapping) else None, maximum=64, fallback="unknown"),
            "protocolVersion": _text(observation.get("protocol_version"), maximum=64, fallback="unknown"),
        }
    )
    resources = [
        _strip_non_material(item)
        for item in observation.get("resources") or []
        if isinstance(item, Mapping)
    ][:64]
    instructions = [
        _canonical_hash("hawk:eci:mcp-instruction:v1", _text(item, maximum=4000, fallback=""))
        for item in observation.get("instructions") or []
    ][:64]
    component_fingerprints = {
        "server": _canonical_hash("hawk:eci:mcp-server:v1", server),
        "tools": {
            str(tool["name"]): {
                "version": str(tool["version"]),
                "fingerprint": _canonical_hash("hawk:eci:mcp-tool:v1", tool),
                "schema_fingerprint": _canonical_hash("hawk:eci:mcp-tool-schema:v1", tool.get("inputSchema") or {}),
            }
            for tool in tools
        },
        "resources": _canonical_hash("hawk:eci:mcp-resources:v1", resources),
        "instructions": _canonical_hash("hawk:eci:mcp-instructions:v1", instructions),
        "provenance": _canonical_hash(
            "hawk:eci:mcp-provenance:v1",
            {
                "registry_source": _text(observation.get("registry_source"), maximum=255, fallback=""),
                "registry_identity": _text(observation.get("registry_identity"), maximum=255, fallback=""),
                "publisher_identity": _text(observation.get("publisher_identity"), maximum=255, fallback=""),
                "domain": _text(observation.get("domain"), maximum=255, fallback=""),
                "transport": _text(observation.get("transport"), maximum=64, fallback=""),
                "auth_mode": _text(observation.get("auth_mode"), maximum=64, fallback=""),
            },
        ),
    }
    material = {
        "server": server,
        "tools": tools,
        "resources_hash": component_fingerprints["resources"],
        "instructions_hash": component_fingerprints["instructions"],
        "provenance_hash": component_fingerprints["provenance"],
    }
    observed_identity = {
        "locator": _text(observation.get("configured_locator"), maximum=512, fallback=""),
        "observed_endpoint": _text(observation.get("observed_endpoint"), maximum=512, fallback=""),
        "registry_source": _text(observation.get("registry_source"), maximum=255, fallback=""),
        "registry_identity": _text(observation.get("registry_identity"), maximum=255, fallback=""),
        "publisher_identity": _text(observation.get("publisher_identity"), maximum=255, fallback=""),
        "domain": _text(observation.get("domain"), maximum=255, fallback=""),
        "transport": _text(observation.get("transport"), maximum=64, fallback=""),
        "auth_mode": _text(observation.get("auth_mode"), maximum=64, fallback=""),
        "protocol_version": _text(observation.get("protocol_version"), maximum=64, fallback=""),
    }
    return observed_identity, {
        "material_fingerprint": _canonical_hash("hawk:eci:mcp-capability:v1", material),
        "component_fingerprints": component_fingerprints,
    }


def _state(row: ExternalCapabilityIdentity) -> ExternalCapabilityState:
    components = dict(row.component_fingerprints or {})
    tools = components.get("tools") if isinstance(components.get("tools"), dict) else {}
    return ExternalCapabilityState(
        capability_id=row.id,
        capability_ref=row.capability_ref,
        capability_type=row.capability_type,
        configured_locator=row.configured_locator,
        observed_endpoint=row.observed_endpoint,
        material_fingerprint=row.material_fingerprint,
        component_fingerprints=components,
        tool_fingerprints=dict(tools),
        baseline_id=row.baseline_id,
        baseline_material_fingerprint=row.baseline_material_fingerprint,
        trust_state=row.trust_state,
        capability_epoch=row.capability_epoch,
        evidence_quality=row.evidence_quality,
        drift_summary=dict(row.drift_summary or {}),
        last_observed_at=row.last_observed_at,
        last_verified_at=row.last_verified_at,
    )


def _diff_components(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    changed: list[str] = []
    keys = set(previous) | set(current)
    for key in sorted(keys):
        if previous.get(key) != current.get(key):
            changed.append(str(key))
    previous_tools = previous.get("tools") if isinstance(previous.get("tools"), Mapping) else {}
    current_tools = current.get("tools") if isinstance(current.get("tools"), Mapping) else {}
    for tool_name in sorted(set(previous_tools) | set(current_tools)):
        if previous_tools.get(tool_name) != current_tools.get(tool_name):
            changed.append(f"tool:{tool_name}")
            old_schema = (previous_tools.get(tool_name) or {}).get("schema_fingerprint") if isinstance(previous_tools.get(tool_name), Mapping) else None
            new_schema = (current_tools.get(tool_name) or {}).get("schema_fingerprint") if isinstance(current_tools.get(tool_name), Mapping) else None
            if old_schema != new_schema:
                changed.append(f"schema:{tool_name}")
    return sorted(set(changed))


def _drift_type(changed_fields: list[str]) -> str:
    if any(item.startswith("schema:") for item in changed_fields):
        return "SCHEMA_DRIFT"
    if any(item.startswith("tool:") or item == "tools" for item in changed_fields):
        return "TOOL_DRIFT"
    if "provenance" in changed_fields:
        return "CAPABILITY_PROVENANCE_DRIFT"
    if "server" in changed_fields:
        return "MCP_DRIFT"
    return "CAPABILITY_IDENTITY_DRIFT"


class ExternalCapabilityIntegrityService:
    def observe_mcp_capability(
        self,
        db: Session,
        *,
        tenant_id: str,
        capability_ref: str,
        observation: Mapping[str, Any],
        observed_at: datetime,
        evidence_refs: list[str] | tuple[str, ...] | None = None,
        evidence_quality: str = "HAWK_RUNTIME_OBSERVED",
        observation_mode: Literal["CONFIGURATION_INVENTORY", "GATEWAY_ATTESTED_INVOCATION", "INFERRED"] = "CONFIGURATION_INVENTORY",
    ) -> ExternalCapabilityState:
        at = _utc(observed_at)
        observed_identity, fingerprint_bundle = _normalize_mcp_observation(observation)
        material_fingerprint = str(fingerprint_bundle["material_fingerprint"])
        components = dict(fingerprint_bundle["component_fingerprints"])
        row = db.scalar(
            select(ExternalCapabilityIdentity)
            .where(
                ExternalCapabilityIdentity.tenant_id == tenant_id,
                ExternalCapabilityIdentity.capability_ref == capability_ref,
            )
            .with_for_update()
        )
        if row is not None and _utc(row.last_observed_at) > at:
            return _state(row)
        if row is None:
            row = ExternalCapabilityIdentity(
                tenant_id=tenant_id,
                capability_ref=_text(capability_ref, maximum=255),
                capability_type="MCP_SERVER",
                configured_locator=_text(observation.get("configured_locator"), maximum=512, fallback="unknown"),
                registry_source=observed_identity.get("registry_source") or None,
                registry_identity=observed_identity.get("registry_identity") or None,
                publisher_identity=observed_identity.get("publisher_identity") or None,
                observed_endpoint=observed_identity.get("observed_endpoint") or None,
                observed_identity=observed_identity,
                component_fingerprints=components,
                material_fingerprint=material_fingerprint,
                trust_state="UNKNOWN",
                capability_epoch=1,
                evidence_quality=evidence_quality,
                evidence_refs=_refs(evidence_refs),
                drift_summary={},
                last_observed_at=at,
                last_observed_sequence=1,
            )
            db.add(row)
            db.flush()
            return _state(row)

        previous_material = row.material_fingerprint
        previous_components = dict(row.component_fingerprints or {})
        material_changed = previous_material != material_fingerprint
        row.configured_locator = _text(observation.get("configured_locator"), maximum=512, fallback=row.configured_locator)
        row.registry_source = observed_identity.get("registry_source") or row.registry_source
        row.registry_identity = observed_identity.get("registry_identity") or row.registry_identity
        row.publisher_identity = observed_identity.get("publisher_identity") or row.publisher_identity
        row.observed_endpoint = observed_identity.get("observed_endpoint") or row.observed_endpoint
        row.observed_identity = observed_identity
        row.component_fingerprints = components
        row.material_fingerprint = material_fingerprint
        row.evidence_quality = evidence_quality
        row.evidence_refs = _refs(list(row.evidence_refs or []) + _refs(evidence_refs))
        row.last_observed_at = at
        row.last_observed_sequence = int(row.last_observed_sequence or 0) + 1
        if row.revoked or row.trust_state == "REVOKED":
            row.trust_state = "REVOKED"
            db.flush()
            return _state(row)
        if row.baseline_material_fingerprint and material_changed:
            changed_fields = _diff_components(previous_components, components)
            row.trust_state = "STALE"
            row.capability_epoch += 1
            row.drift_summary = {
                "changed_fields": changed_fields,
                "previous_fingerprint": previous_material,
                "current_fingerprint": material_fingerprint,
            }
            self._record_material_drift(
                db,
                capability=row,
                previous_fingerprint=previous_material,
                current_fingerprint=material_fingerprint,
                changed_fields=changed_fields,
                observed_at=at,
                evidence_refs=_refs(evidence_refs),
            )
        elif row.baseline_material_fingerprint == material_fingerprint and row.trust_state == "STALE":
            if observation_mode == "GATEWAY_ATTESTED_INVOCATION" and evidence_quality == "CONFIRMED":
                row.trust_state = "TRUSTED_CURRENT"
                row.drift_summary = {}
            else:
                row.drift_summary = {
                    "reason": "trust_recovery_requires_gateway_attested_confirmed_observation",
                    "observation_mode": observation_mode,
                }
        db.flush()
        return _state(row)

    def accept_current_baseline(
        self,
        db: Session,
        *,
        tenant_id: str,
        capability_ref: str,
        actor_ref: str,
        reason: str,
        accepted_at: datetime,
    ) -> ExternalCapabilityState:
        at = _utc(accepted_at)
        row = db.scalar(
            select(ExternalCapabilityIdentity)
            .where(
                ExternalCapabilityIdentity.tenant_id == tenant_id,
                ExternalCapabilityIdentity.capability_ref == capability_ref,
            )
            .with_for_update()
        )
        if row is None:
            raise PermissionError("external capability tenant binding is invalid")
        if row.revoked or row.trust_state == "REVOKED":
            raise PermissionError("revoked capability requires recovery workflow")
        version = (
            db.scalar(
                select(ExternalCapabilityBaseline.baseline_version)
                .where(
                    ExternalCapabilityBaseline.tenant_id == tenant_id,
                    ExternalCapabilityBaseline.capability_id == row.id,
                )
                .order_by(ExternalCapabilityBaseline.baseline_version.desc())
                .limit(1)
            )
            or 0
        ) + 1
        row.capability_epoch += 1 if row.baseline_id else 0
        baseline = ExternalCapabilityBaseline(
            tenant_id=tenant_id,
            capability_id=row.id,
            baseline_version=version,
            material_fingerprint=row.material_fingerprint,
            component_fingerprints=dict(row.component_fingerprints or {}),
            observed_identity=dict(row.observed_identity or {}),
            verification_source=_text(reason, maximum=255),
            evidence_quality=row.evidence_quality,
            evidence_refs=list(row.evidence_refs or []),
            control_assertion_ids=[],
            capability_epoch=row.capability_epoch,
            trust_state="TRUSTED_CURRENT",
            accepted_by_ref=_text(actor_ref, maximum=255),
            accepted_at=at,
        )
        db.add(baseline)
        db.flush()
        row.baseline_id = baseline.id
        row.baseline_material_fingerprint = baseline.material_fingerprint
        row.trust_state = "TRUSTED_CURRENT"
        row.last_verified_at = at
        row.drift_summary = {}
        assertion = self._ensure_assertion(db, capability=row)
        baseline.control_assertion_ids = [assertion.id]
        self._project_coverage(db, capability=row, assertion=assertion, assessed_at=at)
        db.flush()
        return _state(row)

    def complete_targeted_revalidation(
        self,
        db: Session,
        *,
        tenant_id: str,
        capability_ref: str,
        outcome: str,
        evidence_refs: list[str] | tuple[str, ...],
        completed_at: datetime,
        validation_run_id: str | None = None,
    ) -> ExternalCapabilityState:
        at = _utc(completed_at)
        row = db.scalar(
            select(ExternalCapabilityIdentity)
            .where(
                ExternalCapabilityIdentity.tenant_id == tenant_id,
                ExternalCapabilityIdentity.capability_ref == capability_ref,
            )
            .with_for_update()
        )
        if row is None:
            raise PermissionError("external capability tenant binding is invalid")
        drift = db.scalar(
            select(ExternalCapabilityDrift)
            .where(
                ExternalCapabilityDrift.tenant_id == tenant_id,
                ExternalCapabilityDrift.capability_id == row.id,
                ExternalCapabilityDrift.status == "OPEN",
            )
            .order_by(ExternalCapabilityDrift.observed_at.desc())
            .limit(1)
        )
        normalized = _text(outcome, maximum=32).upper()
        if row.revoked or row.trust_state == "REVOKED":
            normalized = "REVOKED"
        elif normalized == "TRUSTED_CURRENT":
            accepted = self.accept_current_baseline(
                db,
                tenant_id=tenant_id,
                capability_ref=capability_ref,
                actor_ref="system:targeted-revalidation",
                reason="targeted revalidation accepted current capability",
                accepted_at=at,
            )
            row = db.scalar(
                select(ExternalCapabilityIdentity).where(
                    ExternalCapabilityIdentity.tenant_id == tenant_id,
                    ExternalCapabilityIdentity.id == accepted.capability_id,
                )
            )
            if drift is not None:
                drift.status = "REVALIDATED"
        elif normalized == "REGRESSED":
            row.trust_state = "REGRESSED"
            row.capability_epoch += 1
        else:
            raise ValueError("unsupported external capability validation outcome")
        if drift is not None and normalized in {"REGRESSED", "REVOKED"}:
            drift.status = "REVOKED" if normalized == "REVOKED" else "OPEN"
        link = ExternalCapabilityValidationLink(
            tenant_id=tenant_id,
            capability_id=row.id,
            validation_run_id=validation_run_id or f"eci:{uuid4()}",
            drift_id=drift.id if drift is not None else None,
            outcome=normalized,
            evidence_refs=_refs(evidence_refs),
            observed_at=at,
        )
        db.add(link)
        assertion = self._ensure_assertion(db, capability=row)
        assertion.assurance_state = "REGRESSED" if row.trust_state == "REGRESSED" else "CURRENT" if row.trust_state == "TRUSTED_CURRENT" else "STALE"
        self._project_coverage(db, capability=row, assertion=assertion, assessed_at=at)
        db.flush()
        return _state(row)

    def revoke_capability(
        self,
        db: Session,
        *,
        tenant_id: str,
        capability_ref: str,
        actor_ref: str,
        reason: str,
        revoked_at: datetime,
    ) -> ExternalCapabilityState:
        at = _utc(revoked_at)
        row = db.scalar(
            select(ExternalCapabilityIdentity)
            .where(
                ExternalCapabilityIdentity.tenant_id == tenant_id,
                ExternalCapabilityIdentity.capability_ref == capability_ref,
            )
            .with_for_update()
        )
        if row is None:
            raise PermissionError("external capability tenant binding is invalid")
        row.trust_state = "REVOKED"
        row.revoked = True
        row.revoked_by_ref = _text(actor_ref, maximum=255)
        row.revoked_at = at
        row.capability_epoch += 1
        row.drift_summary = {"reason": _text(reason, maximum=512), "revoked_at": at.isoformat()}
        assertion = self._ensure_assertion(db, capability=row)
        assertion.assurance_state = "REGRESSED"
        self._project_coverage(db, capability=row, assertion=assertion, assessed_at=at)
        db.flush()
        return _state(row)

    def resolve_for_mcp_tool(
        self,
        db: Session,
        *,
        tenant_id: str,
        tool_fingerprint: str | None,
    ) -> dict[str, Any]:
        if not tool_fingerprint:
            return {"trust_state": "UNKNOWN", "reason": "missing_external_capability_fingerprint"}
        rows = db.scalars(
            select(ExternalCapabilityIdentity).where(ExternalCapabilityIdentity.tenant_id == tenant_id)
        ).all()
        for row in rows:
            tools = (row.component_fingerprints or {}).get("tools")
            if not isinstance(tools, Mapping):
                continue
            for tool_name, material in tools.items():
                if isinstance(material, Mapping) and material.get("fingerprint") == tool_fingerprint:
                    return {
                        "capability_id": row.id,
                        "capability_ref": row.capability_ref,
                        "capability_type": row.capability_type,
                        "configured_locator": row.configured_locator,
                        "observed_endpoint": row.observed_endpoint,
                        "tool_name": tool_name,
                        "material_fingerprint": row.material_fingerprint,
                        "baseline_material_fingerprint": row.baseline_material_fingerprint,
                        "trust_state": row.trust_state,
                        "capability_epoch": row.capability_epoch,
                    }
        try:
            from app.db.models.policy import ToolFingerprint

            fingerprint_row = db.scalar(
                select(ToolFingerprint).where(
                    ToolFingerprint.tenant_id == tenant_id,
                    ToolFingerprint.id == tool_fingerprint,
                )
            )
        except Exception:  # noqa: BLE001 - ECI must fail closed without exposing internals
            fingerprint_row = None
        if fingerprint_row is not None:
            capability_ref = f"mcp:{fingerprint_row.mcp_server_id}"
            row = db.scalar(
                select(ExternalCapabilityIdentity).where(
                    ExternalCapabilityIdentity.tenant_id == tenant_id,
                    ExternalCapabilityIdentity.capability_ref == capability_ref,
                )
            )
            if row is not None:
                tools = (row.component_fingerprints or {}).get("tools")
                material = (
                    tools.get(fingerprint_row.tool_name)
                    if isinstance(tools, Mapping)
                    else None
                )
                if (
                    isinstance(material, Mapping)
                    and str(material.get("version") or "unknown")
                    == str(fingerprint_row.tool_version or "unknown")
                ):
                    return {
                        "capability_id": row.id,
                        "capability_ref": row.capability_ref,
                        "capability_type": row.capability_type,
                        "configured_locator": row.configured_locator,
                        "observed_endpoint": row.observed_endpoint,
                        "tool_name": fingerprint_row.tool_name,
                        "material_fingerprint": row.material_fingerprint,
                        "baseline_material_fingerprint": row.baseline_material_fingerprint,
                        "trust_state": row.trust_state,
                        "capability_epoch": row.capability_epoch,
                    }
        return {"trust_state": "UNKNOWN", "reason": "external_capability_not_observed"}

    def _ensure_assertion(self, db: Session, *, capability: ExternalCapabilityIdentity) -> ControlAssertion:
        key = f"eci:{_canonical_hash('hawk:eci:assertion-key:v1', capability.capability_ref)[:48]}"
        service = ContinuousAssuranceService()
        existing = db.scalar(
            select(ControlAssertion).where(
                ControlAssertion.tenant_id == capability.tenant_id,
                ControlAssertion.assertion_key == key,
            )
        )
        if existing is not None:
            return existing
        return service.create_assertion(
            db,
            tenant_id=capability.tenant_id,
            assertion_key=key,
            assertion_type="external_capability_integrity",
            asset_ref=f"external-capability:{capability.capability_ref}",
            action_class="mcp_tool_execution",
            required_capability="external_capability_integrity",
            expected_outcome="PASS_DETECTED",
            required_evidence_level="HAWK_RUNTIME_OBSERVED",
            dependencies={f"tool_mcp_fingerprint:{capability.capability_ref}": capability.material_fingerprint},
        )

    def _record_material_drift(
        self,
        db: Session,
        *,
        capability: ExternalCapabilityIdentity,
        previous_fingerprint: str,
        current_fingerprint: str,
        changed_fields: list[str],
        observed_at: datetime,
        evidence_refs: list[str],
    ) -> ExternalCapabilityDrift:
        assertion = self._ensure_assertion(db, capability=capability)
        assertion.assurance_state = "STALE"
        service = ContinuousAssuranceService()
        signal = service.record_drift(
            db,
            tenant_id=capability.tenant_id,
            category="tool_mcp_fingerprint",
            dependency_key=capability.capability_ref,
            previous_digest=previous_fingerprint,
            current_digest=current_fingerprint,
            source_ref=f"external-capability:{capability.id}",
            observed_at=observed_at,
        )
        drift_hash = _canonical_hash(
            "hawk:eci:drift:v1",
            {
                "tenant_id": capability.tenant_id,
                "capability_id": capability.id,
                "previous": previous_fingerprint,
                "current": current_fingerprint,
                "fields": changed_fields,
            },
        )
        drift = db.scalar(
            select(ExternalCapabilityDrift).where(
                ExternalCapabilityDrift.tenant_id == capability.tenant_id,
                ExternalCapabilityDrift.drift_hash == drift_hash,
            )
        )
        if drift is None:
            drift = ExternalCapabilityDrift(
                tenant_id=capability.tenant_id,
                capability_id=capability.id,
                drift_hash=drift_hash,
                drift_type=_drift_type(changed_fields),
                previous_fingerprint=previous_fingerprint,
                current_fingerprint=current_fingerprint,
                changed_fields=changed_fields,
                affected_assertion_ids=[assertion.id],
                drift_signal_id=signal.id,
                evidence_refs=evidence_refs,
                status="OPEN",
                observed_at=observed_at,
            )
            db.add(drift)
        self._project_lineage_drift(db, capability=capability, drift=drift, observed_at=observed_at)
        self._project_coverage(db, capability=capability, assertion=assertion, assessed_at=observed_at)
        db.flush()
        return drift

    def _project_lineage_drift(
        self,
        db: Session,
        *,
        capability: ExternalCapabilityIdentity,
        drift: ExternalCapabilityDrift,
        observed_at: datetime,
    ) -> None:
        lineage_key = _canonical_hash("hawk:eci:lineage:v1", {"capability_id": capability.id})[:64]
        lineage = db.scalar(
            select(ActivityLineage).where(
                ActivityLineage.tenant_id == capability.tenant_id,
                ActivityLineage.lineage_key == lineage_key,
            )
        )
        if lineage is None:
            lineage = ActivityLineage(
                tenant_id=capability.tenant_id,
                lineage_key=lineage_key,
                source_watermark=drift.current_fingerprint,
                schema_version="1.0",
                seed_action_id=f"external-capability:{capability.id}",
                seed_runtime_event_id=drift.id,
                root_action_id=f"external-capability:{capability.id}",
                status="PARTIAL",
                blind_spots=["direct_bypass_paths_require_existing_runtime_or_endpoint_evidence"],
            )
            db.add(lineage)
            db.flush()
        node_key = _canonical_hash("hawk:eci:drift-node:v1", {"drift": drift.id})
        existing = db.scalar(
            select(LineageNode).where(
                LineageNode.tenant_id == capability.tenant_id,
                LineageNode.lineage_id == lineage.id,
                LineageNode.node_key == node_key,
            )
        )
        if existing is None:
            db.add(
                LineageNode(
                    tenant_id=capability.tenant_id,
                    lineage_id=lineage.id,
                    node_key=node_key,
                    node_type="DRIFT_SIGNAL",
                    authority_type="ExternalCapabilityDrift",
                    authority_id=drift.id,
                    label="External capability material drift",
                    certainty="CONFIRMED",
                    evidence_quality=capability.evidence_quality,
                    evidence_refs=list(drift.evidence_refs or []),
                    safe_attributes={
                        "capability_ref": capability.capability_ref,
                        "drift_type": drift.drift_type,
                        "changed_fields": list(drift.changed_fields or []),
                    },
                    ordinal=1,
                    occurred_at=observed_at,
                )
            )

    def _project_coverage(
        self,
        db: Session,
        *,
        capability: ExternalCapabilityIdentity,
        assertion: ControlAssertion,
        assessed_at: datetime,
    ) -> None:
        scope = db.scalar(
            select(CoverageScope).where(
                CoverageScope.tenant_id == capability.tenant_id,
                CoverageScope.scope_type == "asset",
                CoverageScope.scope_key == f"external-capability:{capability.capability_ref}",
            )
        )
        if scope is None:
            scope = CoverageScope(
                tenant_id=capability.tenant_id,
                scope_type="asset",
                scope_key=f"external-capability:{capability.capability_ref}",
                display_name=capability.capability_ref,
                filters={"external_capability_ref": capability.capability_ref},
                active=True,
            )
            db.add(scope)
            db.flush()
        input_digest = _canonical_hash(
            "hawk:eci:coverage-snapshot:v1",
            {
                "capability": capability.id,
                "epoch": capability.capability_epoch,
                "fingerprint": capability.material_fingerprint,
                "trust_state": capability.trust_state,
                "assessed_at": assessed_at.isoformat(),
            },
        )
        snapshot = ControlCoverageSnapshot(
            tenant_id=capability.tenant_id,
            methodology_version="eci-coverage/1.0",
            window_start=assessed_at,
            window_end=assessed_at,
            input_digest=input_digest,
            headline_counts={"external_capabilities": 1},
            headline_score=None,
            dimension_summaries={"external_capability_integrity": capability.trust_state},
            input_watermarks={"capability_epoch": capability.capability_epoch},
            diagnostics=[] if capability.trust_state == "TRUSTED_CURRENT" else [f"external_capability_{capability.trust_state.lower()}"],
            freshness_status="current" if capability.trust_state == "TRUSTED_CURRENT" else "stale",
            scope_id=scope.id,
            previous_snapshot_id=None,
            snapshot_kind="external_capability_integrity",
            source_versions={"external_capability_integrity": "1.0"},
            assessment_totals={"applicable": 1},
            applicable_requirement_count=1,
            unknown_population=1 if capability.trust_state == "UNKNOWN" else 0,
            gap_summary={},
            comparison_summary={},
            computed_at=assessed_at,
        )
        db.add(snapshot)
        db.flush()
        assurance = {
            "TRUSTED_CURRENT": ("current", "verified", "covered_current"),
            "STALE": ("stale", "partial", "covered_stale"),
            "REGRESSED": ("regressed", "unverified", "regressed"),
            "REVOKED": ("regressed", "unverified", "regressed"),
            "UNKNOWN": ("unknown", "unknown", "unknown"),
        }[capability.trust_state]
        db.add(
            ControlCoverageAssessment(
                tenant_id=capability.tenant_id,
                scope_id=scope.id,
                snapshot_id=snapshot.id,
                assessment_key=_canonical_hash("hawk:eci:coverage-assessment:v1", {"capability": capability.id, "snapshot": snapshot.id})[:128],
                asset_ref=f"external-capability:{capability.capability_ref}",
                action_class="mcp_tool_execution",
                action_path_ref=f"mcp:{capability.capability_ref}",
                domain_profile_ref=None,
                deployment_surface="runtime",
                dimension="external_capability_integrity",
                requirement_ref="external_capability_material_identity_current",
                applicability_state="applicable",
                applicability_reason="MCP capability identity can be observed through existing Hawk MCP/runtime evidence.",
                deployment_state="present",
                capability_state=assurance[1],
                assurance_state=assurance[0],
                evidence_quality=capability.evidence_quality,
                coverage_state=assurance[2],
                reason_code=f"external_capability_{capability.trust_state.lower()}",
                explanation="External capability trust is derived from observed material fingerprints and the accepted baseline.",
                control_plan_ref=None,
                expected_control_points=["mcp_gateway", "phase6_targeted_revalidation"],
                contributing_control_points=["mcp_gateway"] if capability.trust_state != "UNKNOWN" else [],
                missing_contributions=[] if capability.trust_state == "TRUSTED_CURRENT" else ["current_revalidation"],
                bypass_refs=["direct_api_route_unknown"],
                evidence_refs=list(capability.evidence_refs or []),
                validation_refs=[assertion.id],
                lineage_refs=[],
                source_versions={"external_capability_integrity": "1.0"},
                criticality="high",
                assessed_at=assessed_at,
            )
        )
