"""Backend services for the Hawk unified endpoint agent.

Provides the server-authoritative side of the endpoint agent: the endpoint policy
bundle, the AI-notetaker decision, and heartbeat/evidence ingestion. Decisions are
made here (not on the device) so endpoint posture never drifts from central policy.

Additive and non-breaking: reuses the existing evidence and audit services and the
shared extension policy builder.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.services.audit_service import write_audit_log
from app.services.browser_extension_service import build_extension_policy_sync
from app.services.evidence_service import create_evidence_node
from app.services.action_integrity.execution_authority import install_generic_seam_authority, invoke_final_seam
from app.services.action_integrity.canonical_v2 import domain_hash
from app.services.google_workspace_integration_service import (
    execute_google_meet_notetaker_action,
)
from app.services.microsoft_graph_integration_service import (
    execute_microsoft_teams_notetaker_graph_action,
)
from app.services.zoom_integration_service import execute_zoom_notetaker_action


_FLOOR_CONTROLS = (
    "file_control",
    "process_control",
    "network_control",
    "semantic_proxy",
)
_MANDATORY_FLOOR_CONTROLS = _FLOOR_CONTROLS[:3]
_FLOOR_STATUS = {
    "inline",
    "inline_bound",
    "external",
    "observe",
    "not_covered",
    "unavailable",
    "unknown",
}
_FLOOR_VERIFICATION = {"verified", "experimental", "unverified"}
_FLOOR_HEALTH = {"healthy", "degraded", "unhealthy", "stale", "unknown"}
_LOCAL_POLICY_STATUS = {"active", "disabled", "invalid", "unavailable", "unknown"}
_LOCAL_POLICY_FRESHNESS = {"fresh", "stale", "expired", "unknown"}


def _utc_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _unknown_floor_control() -> dict[str, Any]:
    return {
        "status": "unknown",
        "verification": "unverified",
        "health": "unknown",
        "observed_latency_ms": None,
        "evidence_refs": [],
    }


def _normalize_floor_control(value: Any, *, stale: bool) -> tuple[dict[str, Any], list[str]]:
    if stale or not isinstance(value, dict):
        return _unknown_floor_control(), []
    status = str(value.get("status") or "unknown").strip().lower()
    verification = str(value.get("verification") or "unverified").strip().lower()
    health = str(value.get("health") or "unknown").strip().lower()
    if status not in _FLOOR_STATUS:
        status = "unknown"
    if verification not in _FLOOR_VERIFICATION:
        verification = "unverified"
    if health not in _FLOOR_HEALTH:
        health = "unknown"
    latency_value = value.get("observed_latency_ms")
    observed_latency_ms = None
    if (
        isinstance(latency_value, (int, float))
        and not isinstance(latency_value, bool)
        and math.isfinite(float(latency_value))
    ):
        observed_latency_ms = max(0, min(60_000, int(latency_value)))
    evidence_refs = sorted(
        {
            str(item)[:256]
            for item in value.get("evidence_refs") or []
            if isinstance(item, str) and item.strip()
        }
    )[:32]
    reasons: list[str] = []
    if status in {"inline", "inline_bound"} and not (
        verification == "verified" and health == "healthy" and evidence_refs
    ):
        status = "unknown"
        reasons.append("runtime_evidence_missing")
    return {
        "status": status,
        "verification": verification,
        "health": health,
        "observed_latency_ms": observed_latency_ms,
        "evidence_refs": evidence_refs,
    }, reasons


def _normalize_local_policy(value: Any, *, stale: bool) -> tuple[dict[str, Any], bool, list[str]]:
    if stale:
        return {
            "status": "unknown",
            "freshness": "stale",
            "policy_version": None,
            "signature_verified": False,
            "evidence_refs": [],
        }, False, ["runtime_evidence_missing:local_policy"]
    if not isinstance(value, dict):
        return {
            "status": "unknown",
            "freshness": "unknown",
            "policy_version": None,
            "signature_verified": False,
            "evidence_refs": [],
        }, False, ["runtime_evidence_missing:local_policy"]

    status = str(value.get("status") or "unknown").strip().lower()
    freshness = str(value.get("freshness") or "unknown").strip().lower()
    if status not in _LOCAL_POLICY_STATUS:
        status = "unknown"
    if freshness not in _LOCAL_POLICY_FRESHNESS:
        freshness = "unknown"
    policy_version = value.get("policy_version")
    if policy_version is not None:
        policy_version = str(policy_version).strip()[:128] or None
    signature_verified = value.get("signature_verified") is True
    evidence_refs = sorted(
        {
            str(item)[:256]
            for item in value.get("evidence_refs") or []
            if isinstance(item, str) and item.strip()
        }
    )[:32]
    proved = bool(
        status == "active"
        and freshness == "fresh"
        and signature_verified
        and evidence_refs
    )
    reasons: list[str] = []
    if not proved:
        reasons.append("runtime_evidence_missing:local_policy")
        if status == "active":
            status = "unknown"
    return {
        "status": status,
        "freshness": freshness,
        "policy_version": policy_version,
        "signature_verified": signature_verified,
        "evidence_refs": evidence_refs,
    }, proved, reasons


def project_endpoint_floor_status(
    nodes: list[Any] | tuple[Any, ...],
    *,
    now: datetime | None = None,
    heartbeat_ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Project latest authenticated heartbeats without trusting aggregate claims."""
    observed_now = _utc_datetime(now or datetime.now(UTC))
    latest: dict[str, Any] = {}
    for node in sorted(
        nodes,
        key=lambda item: (_utc_datetime(getattr(item, "created_at", datetime.min.replace(tzinfo=UTC))), str(getattr(item, "id", ""))),
        reverse=True,
    ):
        payload = getattr(node, "payload", {})
        if not isinstance(payload, dict):
            continue
        endpoint_id = str(payload.get("endpoint_id") or "").strip()
        if endpoint_id and endpoint_id not in latest:
            latest[endpoint_id] = node

    endpoints: list[dict[str, Any]] = []
    for endpoint_id, node in sorted(latest.items()):
        payload = node.payload
        created_at = _utc_datetime(node.created_at)
        stale = (observed_now - created_at).total_seconds() > max(1, heartbeat_ttl_seconds)
        posture = payload.get("posture") if isinstance(payload.get("posture"), dict) else {}
        floor = posture.get("endpoint_enforcement_floor") if isinstance(posture, dict) else {}
        floor = floor if isinstance(floor, dict) else {}
        provided_controls = floor.get("controls") if isinstance(floor.get("controls"), dict) else {}
        controls: dict[str, dict[str, Any]] = {}
        reasons = [str(item)[:256] for item in floor.get("reason_codes") or [] if isinstance(item, str)]
        for control_name in _FLOOR_CONTROLS:
            normalized, normalization_reasons = _normalize_floor_control(
                provided_controls.get(control_name),
                stale=stale,
            )
            controls[control_name] = normalized
            if "runtime_evidence_missing" in normalization_reasons:
                reasons.append(f"runtime_evidence_missing:{control_name}")
        local_policy, local_policy_proved, local_policy_reasons = _normalize_local_policy(
            floor.get("local_policy"),
            stale=stale,
        )
        reasons.extend(local_policy_reasons)
        if stale:
            reasons.append("endpoint_floor_heartbeat_stale")
        minimum_satisfied = (
            not stale
            and local_policy_proved
            and all(
                controls[name]["status"] in {"inline", "inline_bound"}
                and controls[name]["verification"] == "verified"
                and controls[name]["health"] == "healthy"
                and bool(controls[name]["evidence_refs"])
                for name in _MANDATORY_FLOOR_CONTROLS
            )
        )
        semantic = controls["semantic_proxy"]
        semantic_available = bool(
            semantic["status"] in {"inline", "inline_bound"}
            and semantic["verification"] == "verified"
            and semantic["health"] == "healthy"
            and semantic["evidence_refs"]
        )
        if stale:
            health = "stale"
        elif minimum_satisfied:
            health = "healthy"
        elif any(control["status"] == "not_covered" for control in controls.values()):
            health = "degraded"
        else:
            health = "unknown"
        blind_spots = sorted(
            {
                str(item)[:256]
                for item in floor.get("blind_spots") or []
                if isinstance(item, str) and item.strip()
            }
        )[:64]
        if not local_policy_proved:
            blind_spots = sorted({*blind_spots, "signed_local_policy_unproved"})[:64]
        evidence_refs = sorted(
            {
                ref
                for control in controls.values()
                for ref in control["evidence_refs"]
            }
            | set(local_policy["evidence_refs"])
        )
        endpoints.append(
            {
                "endpoint_id": endpoint_id,
                "hostname": str(payload.get("hostname") or endpoint_id)[:255],
                "os_type": str(payload.get("os_type") or "unknown")[:64],
                "last_seen_at": created_at.isoformat(),
                "health": health,
                "minimum_floor_satisfied": minimum_satisfied,
                "semantic_control_available": semantic_available,
                "controls": controls,
                "local_policy": local_policy,
                "reason_codes": list(dict.fromkeys(reasons)),
                "blind_spots": blind_spots,
                "evidence_refs": evidence_refs,
            }
        )
    protected = sum(1 for endpoint in endpoints if endpoint["minimum_floor_satisfied"])
    degraded = sum(1 for endpoint in endpoints if endpoint["health"] in {"degraded", "stale"})
    return {
        "schema_version": "1.0",
        "generated_at": observed_now.isoformat(),
        "summary": {
            "total": len(endpoints),
            "protected": protected,
            "degraded": degraded,
            "unknown": len(endpoints) - protected - degraded,
        },
        "endpoints": endpoints,
    }


def get_endpoint_floor_status(
    db: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
    heartbeat_ttl_seconds: int = 300,
) -> dict[str, Any]:
    nodes = list(
        db.scalars(
            select(EvidenceNode)
            .where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.node_type == "endpoint_agent_heartbeat",
            )
            .order_by(EvidenceNode.created_at.desc(), EvidenceNode.id.desc())
            .limit(500)
        ).all()
    )
    return project_endpoint_floor_status(
        nodes,
        now=now,
        heartbeat_ttl_seconds=heartbeat_ttl_seconds,
    )


def get_endpoint_health_status(
    db: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
    heartbeat_ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Return operator-facing endpoint identity and control health.

    This view is deliberately derived from the existing identity table and
    signed endpoint heartbeat evidence. It does not infer command enforcement
    or policy freshness when the endpoint has not produced current receipts.
    """

    observed_now = _utc_datetime(now or datetime.now(UTC))
    identities = list(
        db.scalars(
            select(EndpointDeviceIdentity)
            .where(EndpointDeviceIdentity.tenant_id == tenant_id)
            .order_by(EndpointDeviceIdentity.endpoint_id.asc())
            .limit(1_000)
        ).all()
    )
    floor_status = get_endpoint_floor_status(
        db,
        tenant_id=tenant_id,
        now=observed_now,
        heartbeat_ttl_seconds=heartbeat_ttl_seconds,
    )
    floor_by_endpoint = {
        endpoint["endpoint_id"]: endpoint for endpoint in floor_status.get("endpoints", [])
    }

    devices: list[dict[str, Any]] = []
    for identity in identities:
        floor = floor_by_endpoint.get(identity.endpoint_id)
        last_heartbeat_at = floor.get("last_seen_at") if floor else None
        heartbeat_freshness = "missing"
        if last_heartbeat_at:
            heartbeat_at = _utc_datetime(last_heartbeat_at)
            heartbeat_freshness = (
                "fresh"
                if (observed_now - heartbeat_at).total_seconds()
                <= max(1, heartbeat_ttl_seconds)
                else "stale"
            )
        last_authenticated_at = (
            _utc_datetime(identity.last_authenticated_at).isoformat()
            if identity.last_authenticated_at
            else None
        )
        renewal_state = "not_seen"
        if identity.status != "active":
            renewal_state = "disabled"
        elif identity.last_authenticated_at:
            auth_age_seconds = (
                observed_now - _utc_datetime(identity.last_authenticated_at)
            ).total_seconds()
            renewal_state = "recent" if auth_age_seconds <= 600 else "stale"

        policy = floor.get("local_policy") if floor else None
        minimum_floor = bool(floor.get("minimum_floor_satisfied")) if floor else False
        command_acceptance = "accepted" if minimum_floor else "not_accepted"
        if heartbeat_freshness == "missing":
            command_acceptance = "missing_heartbeat"
        elif heartbeat_freshness == "stale":
            command_acceptance = "stale_heartbeat"
        if identity.status != "active":
            command_acceptance = "identity_not_active"

        devices.append(
            {
                "identity_id": identity.id,
                "endpoint_id": identity.endpoint_id,
                "assigned_user_id": identity.assigned_user_id,
                "status": identity.status,
                "key_provider": identity.key_provider,
                "key_thumbprint": identity.key_thumbprint,
                "scopes": list(identity.scopes or []),
                "last_authenticated_at": last_authenticated_at,
                "auto_renewal": {
                    "supported": True,
                    "state": renewal_state,
                    "token_ttl_seconds": 300,
                    "explanation": (
                        "Endpoint tokens are short-lived and renewed through signed challenge-response."
                    ),
                },
                "signed_heartbeat": {
                    "last_seen_at": last_heartbeat_at,
                    "freshness": heartbeat_freshness,
                    "fresh_within_seconds": heartbeat_ttl_seconds,
                    "evidence_refs": list(floor.get("evidence_refs", [])) if floor else [],
                },
                "policy_freshness": {
                    "status": policy.get("status") if isinstance(policy, dict) else "unknown",
                    "freshness": policy.get("freshness") if isinstance(policy, dict) else "unknown",
                    "policy_version": policy.get("policy_version") if isinstance(policy, dict) else None,
                    "signature_verified": (
                        policy.get("signature_verified") is True
                        if isinstance(policy, dict)
                        else False
                    ),
                    "evidence_refs": (
                        list(policy.get("evidence_refs", []))
                        if isinstance(policy, dict)
                        else []
                    ),
                },
                "command_enforcement_acceptance": {
                    "state": command_acceptance,
                    "minimum_floor_satisfied": minimum_floor,
                    "semantic_control_available": (
                        bool(floor.get("semantic_control_available")) if floor else False
                    ),
                    "reason_codes": list(floor.get("reason_codes", [])) if floor else [],
                    "blind_spots": list(floor.get("blind_spots", [])) if floor else [],
                },
            }
        )

    active = sum(1 for item in devices if item["status"] == "active")
    fresh = sum(
        1 for item in devices if item["signed_heartbeat"]["freshness"] == "fresh"
    )
    accepted = sum(
        1
        for item in devices
        if item["command_enforcement_acceptance"]["state"] == "accepted"
    )
    return {
        "schema_version": "1.0",
        "generated_at": observed_now.isoformat(),
        "summary": {
            "total": len(devices),
            "active": active,
            "fresh_signed_heartbeat": fresh,
            "command_enforcement_accepted": accepted,
            "needs_reenrollment": sum(
                1 for item in devices if item["status"] != "active"
            ),
        },
        "devices": devices,
    }


# Default notetaker posture: always warn + banner + offer eviction. Fleets can make
# this stricter (block / auto_evict) via tenant policy metadata.
_DEFAULT_NOTETAKER_POLICY = {
    "action": "warn",
    "banner": True,
    "allow_eviction": True,
    "auto_evict": False,
}

_NOTETAKER_SIGNATURES = {
    "fireflies": ("fireflies.ai", "fireflies"),
    "otter": ("otter.ai", "otter"),
    "read_ai": ("read.ai", "read ai", "read.ai"),
    "fathom": ("fathom.video", "fathom"),
    "avoma": ("avoma.com", "avoma"),
    "tldv": ("tldv.io", "tl;dv", "tldv"),
    "meetgeek": ("meetgeek.ai", "meetgeek"),
    "sembly": ("sembly.ai", "sembly"),
    "supernormal": ("supernormal.com", "supernormal.ai", "supernormal"),
    "granola": ("granola.ai", "granola"),
    "krisp": ("krisp.ai", "krisp"),
    "fellow": ("fellow.app", "fellow"),
}

_SENSITIVE_MEETING_LABELS = ("confidential", "restricted", "sensitive", "secret", "internal")

_HIGH_RISK_NOTETAKER_SCOPE_MARKERS = (
    "calendar",
    "calendars.readwrite",
    "onlinemeetings",
    "online_meetings",
    "callrecords",
    "call_records",
    "meeting",
    "meetings",
    "transcript",
    "transcription",
    "recording",
    "mail.read",
    "mail.readwrite",
    "gmail",
    "drive",
    "files.read",
    "offline_access",
    "user.read.all",
    "directory.read.all",
)


def _as_dict(payload: Any) -> dict[str, Any]:
    """Normalize a PolicySyncPayload (pydantic) or dict to a plain dict."""
    if isinstance(payload, dict):
        return payload
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    if hasattr(payload, "dict"):
        return payload.dict()
    return dict(getattr(payload, "__dict__", {}) or {})


def build_endpoint_policy(
    db: Session,
    *,
    tenant_id: str,
    hmair_metadata_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the endpoint-agent policy bundle (server is the source of truth)."""
    shared = _as_dict(build_extension_policy_sync(db, tenant_id=tenant_id))
    platform_mode = str(shared.get("platform_mode") or "enforce")
    notetaker_policy = _resolve_notetaker_policy(shared)
    policy = {
        "tenant_id": tenant_id,
        "platform_mode": platform_mode,
        "policy_version": shared.get("policy_version"),
        "notetaker_policy": notetaker_policy,
        "modules": {
            "interaction_security": True,
            "data_transfer": True,
            "shadow_ai": True,
            "agent_runtime": True,
            "notetaker": True,
        },
        "blocked_domains": shared.get("blocked_domains") or [],
        "warn_domains": shared.get("warn_domains") or [],
    }
    if hmair_metadata_inventory is not None:
        policy["hmair_metadata_inventory"] = hmair_metadata_inventory
    return policy


def _resolve_notetaker_policy(shared_policy: dict[str, Any]) -> dict[str, Any]:
    policy = dict(_DEFAULT_NOTETAKER_POLICY)
    override = shared_policy.get("notetaker_policy")
    if isinstance(override, dict):
        policy.update({k: v for k, v in override.items() if v is not None})
    return policy


def _detect_calendar_notetakers(attendees: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for attendee in attendees:
        email = str(attendee.get("email") or "").strip()
        display_name = str(attendee.get("display_name") or attendee.get("name") or "").strip()
        haystack = f"{email} {display_name}".lower()
        if not haystack.strip():
            continue
        for provider, markers in _NOTETAKER_SIGNATURES.items():
            matched = next((marker for marker in markers if marker in haystack), None)
            if not matched:
                continue
            key = (provider, email.lower() or display_name.lower())
            if key in seen:
                break
            seen.add(key)
            detections.append(
                {
                    "provider": provider,
                    "email": email or None,
                    "display_name": display_name or None,
                    "participant_id": str(attendee.get("participant_id") or "").strip() or None,
                    "participant_identity_hash": domain_hash(
                        "hawk:meeting-participant:v1",
                        str(attendee.get("participant_id") or "").strip()
                        or email.strip().lower(),
                    ),
                    "matched_on": "email" if email and matched in email.lower() else "display_name",
                }
            )
            break
    return detections


def _detect_notetaker_provider_from_values(*values: Any) -> str | None:
    haystack = " ".join(str(value or "") for value in values).lower()
    if not haystack.strip():
        return None
    for provider, markers in _NOTETAKER_SIGNATURES.items():
        if any(marker in haystack for marker in markers):
            return provider
    return None


def _high_risk_notetaker_scopes(scopes: list[Any]) -> list[str]:
    high_risk: list[str] = []
    seen: set[str] = set()
    for scope in scopes:
        raw_scope = str(scope or "").strip()
        if not raw_scope:
            continue
        normalized = raw_scope.lower()
        if normalized in seen:
            continue
        if any(marker in normalized for marker in _HIGH_RISK_NOTETAKER_SCOPE_MARKERS):
            seen.add(normalized)
            high_risk.append(raw_scope)
    return high_risk


def _is_sensitive_meeting(payload: dict[str, Any]) -> bool:
    label = str(payload.get("sensitivity_label") or "").lower()
    return (
        any(marker in label for marker in _SENSITIVE_MEETING_LABELS)
        or bool(payload.get("recording_enabled"))
        or bool(payload.get("transcription_enabled"))
    )


def _string_values_from_dicts(items: list[Any], *keys: str) -> list[str]:
    values: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = str(item.get(key) or "").strip()
            if value:
                values.append(value)
    return values


def _short_dedupe_key(*parts: str) -> str:
    return ":".join(str(part or "none") for part in parts)[:128]


def ingest_notetaker_calendar_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Ingest calendar/meeting invite evidence for AI notetakers.

    This is detection and governance evidence, not direct meeting enforcement.
    If a notetaker is found, the control mode is external_required because actual
    removal/blocking must be performed through Microsoft/Google/Zoom controls.
    """
    source = str(payload.get("source") or "calendar").strip().lower()
    platform = str(payload.get("platform") or "calendar").strip().lower()
    meeting_id = str(payload.get("meeting_id") or payload.get("event_id") or "unknown").strip()
    title = str(payload.get("title") or "").strip()
    organizer_email = str(payload.get("organizer_email") or "").strip() or None
    attendees = [attendee for attendee in payload.get("attendees") or [] if isinstance(attendee, dict)]
    detections = _detect_calendar_notetakers(attendees)
    detected = bool(detections)
    sensitive_meeting = _is_sensitive_meeting(payload)
    control_mode = "external_required" if detected else "detected_only"
    recommended_actions = []
    if detected:
        recommended_actions.extend(
            [
                "Review meeting attendee list before the meeting starts.",
                "Use Microsoft/Google meeting controls to remove or lobby AI notetaker attendees.",
                "Disable recording/transcription unless explicitly approved.",
            ]
        )

    evidence = None
    finding_ids: list[str] = []
    finding_types: list[str] = []
    if detected:
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="meeting_notetaker_calendar_signal",
            signal_type="endpoint.notetaker.calendar_signal",
            label=f"AI notetaker calendar signal: {platform}:{meeting_id}",
            payload={
                "source": source,
                "platform": platform,
                "meeting_id": meeting_id,
                "title_present": bool(title),
                "organizer_email": organizer_email,
                "sensitivity_label": payload.get("sensitivity_label"),
                "recording_enabled": bool(payload.get("recording_enabled")),
                "transcription_enabled": bool(payload.get("transcription_enabled")),
                "attendee_count": len(attendees),
                "detections": detections,
                "control_mode": control_mode,
                "recommended_actions": recommended_actions,
            },
        )
        evidence_id = getattr(evidence, "id", None)
        first_provider = str(detections[0].get("provider") or "meeting_ai_notetaker")
        finding_specs = [
            (
                "AI_NOTETAKER_DETECTED",
                "high",
                "AI notetaker was invited to or detected in meeting metadata. Review or remove before sensitive discussion.",
                ["CTRL-MEETING-AI-NOTETAKER-001"],
            )
        ]
        if sensitive_meeting:
            finding_specs.append(
                (
                    "SENSITIVE_MEETING_WITH_AI_ENABLED",
                    "high",
                    "Sensitive meeting has an AI notetaker, recording, or transcription signal. Require organizer review.",
                    ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-MEETING-TRANSCRIPTION-001"],
                )
            )
        for finding_type, severity, recommended_action, controls in finding_specs:
            finding = Finding(
                tenant_id=tenant_id,
                source_surface="connector",
                ai_tool=first_provider,
                user_id=actor_user_id,
                user_email=organizer_email,
                application=platform,
                severity=severity,
                finding_type=finding_type,
                risk_category="meeting_ai_notetaker",
                data_classification="sensitive" if sensitive_meeting else None,
                decision="warn",
                status="open",
                recommended_action=recommended_action,
                evidence_node_ids=[evidence_id] if evidence_id else [],
                related_control_ids=controls,
                dedupe_key=_short_dedupe_key(
                    "calendar_notetaker",
                    tenant_id,
                    platform,
                    meeting_id,
                    finding_type,
                    first_provider,
                ),
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.finding_id)
            finding_types.append(finding_type)

        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="agent",
            action="endpoint.notetaker.calendar_signal",
            resource_type="meeting_notetaker_calendar_signal",
            resource_id=meeting_id,
            payload={
                "source": source,
                "platform": platform,
                "meeting_id": meeting_id,
                "control_mode": control_mode,
                "detection_count": len(detections),
                "finding_types": finding_types,
            },
        )
        db.commit()

    return {
        "status": "ok",
        "detected": detected,
        "control_mode": control_mode,
        "source": source,
        "platform": platform,
        "meeting_id": meeting_id,
        "detections": detections,
        "finding_types": finding_types,
        "finding_ids": finding_ids,
        "evidence_node_id": getattr(evidence, "id", None) if evidence else None,
        "recommended_actions": recommended_actions,
    }


def ingest_notetaker_oauth_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Ingest Microsoft/Google OAuth app grant evidence for AI notetakers.

    This is not inline meeting removal. OAuth/app grants require Microsoft,
    Google, or IdP admin action, so detected notetaker apps are labeled
    external_required with metadata-only evidence.
    """
    source = str(payload.get("source") or "oauth").strip().lower()
    provider = str(payload.get("provider") or "").strip().lower() or "unknown"
    app_id = str(payload.get("app_id") or payload.get("tenant_app_id") or "").strip() or None
    client_id = str(payload.get("client_id") or "").strip() or None
    name = str(payload.get("name") or payload.get("display_name") or "").strip()
    publisher = str(payload.get("publisher") or payload.get("publisher_name") or "").strip()
    homepage_url = str(payload.get("homepage_url") or payload.get("homepage") or "").strip()
    scopes = [scope for scope in payload.get("scopes") or []]
    users = [user for user in payload.get("users") or []]

    notetaker_provider = _detect_notetaker_provider_from_values(
        name,
        publisher,
        homepage_url,
        app_id,
        client_id,
    )
    high_risk_scopes = _high_risk_notetaker_scopes(scopes)
    detected = bool(notetaker_provider)
    control_mode = "external_required" if detected else "detected_only"
    recommended_actions: list[str] = []
    if detected:
        recommended_actions.extend(
            [
                "Review OAuth consent and assigned users for the AI notetaker app.",
                "Revoke the app grant or restrict consent in Microsoft Entra/Google Workspace if unapproved.",
                "Remove high-risk calendar, meeting, mail, recording, or offline scopes unless explicitly approved.",
            ]
        )

    evidence = None
    finding_ids: list[str] = []
    finding_types: list[str] = []
    if detected:
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="meeting_notetaker_oauth_signal",
            signal_type="endpoint.notetaker.oauth_signal",
            label=f"AI notetaker OAuth signal: {provider}:{name or app_id or client_id or 'unknown'}",
            payload={
                "source": source,
                "provider": provider,
                "app_id": app_id,
                "client_id_present": bool(client_id),
                "name": name or None,
                "publisher": publisher or None,
                "homepage_url": homepage_url or None,
                "notetaker_provider": notetaker_provider,
                "scope_count": len(scopes),
                "high_risk_scopes": high_risk_scopes,
                "users_count": len(users),
                "control_mode": control_mode,
                "recommended_actions": recommended_actions,
            },
        )
        evidence_id = getattr(evidence, "id", None)
        finding_specs = [
            (
                "UNAPPROVED_AI_NOTETAKER",
                "high",
                "AI notetaker OAuth app grant was detected. Review app approval and revoke or restrict if unapproved.",
                ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-OAUTH-GRANT-001"],
            )
        ]
        if high_risk_scopes:
            finding_specs.append(
                (
                    "OAUTH_NOTETAKER_APP_OVER_SCOPED",
                    "high",
                    "AI notetaker OAuth app has high-risk calendar, meeting, mail, recording, or offline scopes.",
                    ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-OAUTH-SCOPE-001"],
                )
            )

        for finding_type, severity, recommended_action, controls in finding_specs:
            finding = Finding(
                tenant_id=tenant_id,
                source_surface="connector",
                ai_tool=notetaker_provider,
                user_id=actor_user_id,
                application=provider,
                severity=severity,
                finding_type=finding_type,
                risk_category="meeting_ai_notetaker",
                data_classification="sensitive" if high_risk_scopes else None,
                decision="warn",
                status="open",
                recommended_action=recommended_action,
                evidence_node_ids=[evidence_id] if evidence_id else [],
                related_control_ids=controls,
                dedupe_key=_short_dedupe_key(
                    "oauth_notetaker",
                    tenant_id,
                    provider,
                    app_id or client_id or name,
                    finding_type,
                    notetaker_provider or "unknown",
                ),
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.finding_id)
            finding_types.append(finding_type)

        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="agent",
            action="endpoint.notetaker.oauth_signal",
            resource_type="meeting_notetaker_oauth_signal",
            resource_id=app_id or client_id or name or "unknown",
            payload={
                "source": source,
                "provider": provider,
                "notetaker_provider": notetaker_provider,
                "control_mode": control_mode,
                "high_risk_scope_count": len(high_risk_scopes),
                "users_count": len(users),
                "finding_types": finding_types,
            },
        )
        db.commit()

    return {
        "status": "ok",
        "detected": detected,
        "control_mode": control_mode,
        "source": source,
        "provider": provider,
        "notetaker_provider": notetaker_provider,
        "high_risk_scopes": high_risk_scopes,
        "finding_types": finding_types,
        "finding_ids": finding_ids,
        "evidence_node_id": getattr(evidence, "id", None) if evidence else None,
        "recommended_actions": recommended_actions,
    }


def ingest_notetaker_hidden_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Ingest secondary evidence for local/incognito AI notetakers.

    This path covers notetakers that are not visible in a Teams/Meet/Zoom roster
    but leave endpoint-level hints such as a known recorder process, domain,
    audio device, or transcript artifact while a meeting is active. This is not
    inline meeting enforcement, so hidden suspicion is labeled incomplete.
    """
    source = str(payload.get("source") or "local_agent").strip().lower()
    endpoint_id = str(payload.get("endpoint_id") or "unknown").strip()
    hostname = str(payload.get("hostname") or "").strip() or None
    platform = str(payload.get("meeting_platform") or payload.get("platform") or "unknown").strip().lower()
    meeting_id = str(payload.get("meeting_id") or payload.get("event_id") or "unknown").strip()
    active_meeting = bool(payload.get("active_meeting"))
    visible_in_roster = payload.get("visible_in_roster")
    visible_bool = bool(visible_in_roster) if visible_in_roster is not None else None
    local_audio_capture = bool(payload.get("local_audio_capture"))
    microphone_active = bool(payload.get("microphone_active"))
    transcription_artifact_count = int(payload.get("transcription_artifact_count") or 0)
    processes = [process for process in payload.get("processes") or [] if isinstance(process, dict)]
    domains = [str(domain or "").strip() for domain in payload.get("domains") or [] if str(domain or "").strip()]
    audio_devices = [
        str(device or "").strip() for device in payload.get("audio_devices") or [] if str(device or "").strip()
    ]

    process_values = _string_values_from_dicts(processes, "name", "process_name", "bundle_id", "path")
    notetaker_provider = _detect_notetaker_provider_from_values(
        *process_values,
        *domains,
        *audio_devices,
        payload.get("notetaker_label"),
        payload.get("notetaker_provider"),
    )

    evidence_signals: list[str] = []
    if active_meeting:
        evidence_signals.append("active_meeting")
    if visible_bool is False:
        evidence_signals.append("not_visible_in_roster")
    if local_audio_capture:
        evidence_signals.append("local_audio_capture")
    if microphone_active:
        evidence_signals.append("microphone_active")
    if notetaker_provider:
        evidence_signals.append("known_notetaker_process")
    if transcription_artifact_count:
        evidence_signals.append("transcription_artifact")

    detected = bool(notetaker_provider) and (
        active_meeting or local_audio_capture or microphone_active or transcription_artifact_count > 0
    )
    hidden_suspected = detected and active_meeting and visible_bool is False
    control_mode = "incomplete" if hidden_suspected else "detected_only"
    recommended_actions: list[str] = []
    if detected:
        recommended_actions.extend(
            [
                "Ask the organizer or user to verify meeting roster, recording, and transcription status.",
                "Review the local endpoint audio-capture process and disable the notetaker app through endpoint controls if unapproved.",
                "Use Microsoft/Google/Zoom admin policies to restrict recording, transcription, anonymous join, and meeting bot access.",
            ]
        )

    evidence = None
    finding_ids: list[str] = []
    finding_types: list[str] = []
    if detected:
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="meeting_notetaker_hidden_signal",
            signal_type="endpoint.notetaker.hidden_signal",
            label=f"Hidden AI notetaker signal: {platform}:{meeting_id}",
            payload={
                "source": source,
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "meeting_platform": platform,
                "meeting_id": meeting_id,
                "active_meeting": active_meeting,
                "visible_in_roster": visible_bool,
                "local_audio_capture": local_audio_capture,
                "microphone_active": microphone_active,
                "process_count": len(processes),
                "domain_count": len(domains),
                "audio_device_count": len(audio_devices),
                "transcription_artifact_count": transcription_artifact_count,
                "notetaker_provider": notetaker_provider,
                "hidden_suspected": hidden_suspected,
                "evidence_signals": evidence_signals,
                "control_mode": control_mode,
                "recommended_actions": recommended_actions,
            },
        )
        evidence_id = getattr(evidence, "id", None)
        finding_specs = [
            (
                "AI_NOTETAKER_DETECTED",
                "high",
                "AI notetaker endpoint evidence was detected. Review the local app/process and meeting policy posture.",
                ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-ENDPOINT-AUDIO-CAPTURE-001"],
            )
        ]
        if hidden_suspected:
            finding_specs.insert(
                0,
                (
                    "HIDDEN_NOTETAKER_SUSPECTED",
                    "high",
                    "Secondary endpoint evidence suggests a notetaker may be listening without appearing in the meeting roster.",
                    ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-ENDPOINT-AUDIO-CAPTURE-001"],
                ),
            )

        for finding_type, severity, recommended_action, controls in finding_specs:
            finding = Finding(
                tenant_id=tenant_id,
                source_surface="endpoint",
                ai_tool=notetaker_provider,
                user_id=actor_user_id,
                machine_id=endpoint_id,
                application=platform,
                severity=severity,
                finding_type=finding_type,
                risk_category="meeting_ai_notetaker",
                decision="warn",
                status="open",
                recommended_action=recommended_action,
                evidence_node_ids=[evidence_id] if evidence_id else [],
                related_control_ids=controls,
                dedupe_key=_short_dedupe_key(
                    "hidden_notetaker",
                    tenant_id,
                    endpoint_id,
                    platform,
                    meeting_id,
                    finding_type,
                    notetaker_provider or "unknown",
                ),
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.finding_id)
            finding_types.append(finding_type)

        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="agent",
            action="endpoint.notetaker.hidden_signal",
            resource_type="meeting_notetaker_hidden_signal",
            resource_id=f"{endpoint_id}:{meeting_id}",
            payload={
                "source": source,
                "endpoint_id": endpoint_id,
                "meeting_platform": platform,
                "meeting_id": meeting_id,
                "notetaker_provider": notetaker_provider,
                "hidden_suspected": hidden_suspected,
                "control_mode": control_mode,
                "evidence_signals": evidence_signals,
                "finding_types": finding_types,
            },
        )
        db.commit()

    return {
        "status": "ok",
        "detected": detected,
        "hidden_suspected": hidden_suspected,
        "control_mode": control_mode,
        "source": source,
        "endpoint_id": endpoint_id,
        "meeting_platform": platform,
        "meeting_id": meeting_id,
        "notetaker_provider": notetaker_provider,
        "evidence_signals": evidence_signals,
        "finding_types": finding_types,
        "finding_ids": finding_ids,
        "evidence_node_id": getattr(evidence, "id", None) if evidence else None,
        "recommended_actions": recommended_actions,
    }


def ingest_notetaker_artifact_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Ingest meeting artifacts after or during a meeting.

    Attendance reports, transcript artifacts, and recording artifacts are useful
    secondary evidence when a bot was not caught in the live roster. This path is
    honest about control mode: artifacts require Microsoft/Google/Zoom admin
    controls, so risky artifacts are external_required, while benign attendance
    reports stay detected_only.
    """
    source = str(payload.get("source") or "meeting_artifact").strip().lower()
    platform = str(payload.get("platform") or payload.get("meeting_platform") or "unknown").strip().lower()
    meeting_id = str(payload.get("meeting_id") or payload.get("event_id") or "unknown").strip()
    title = str(payload.get("title") or "").strip()
    organizer_email = str(payload.get("organizer_email") or "").strip() or None
    participants = [
        participant
        for participant in (
            payload.get("attendance_participants")
            or payload.get("participants")
            or payload.get("attendees")
            or []
        )
        if isinstance(participant, dict)
    ]
    detections = _detect_calendar_notetakers(participants)

    transcript_artifact_count = int(
        payload.get("transcript_artifact_count")
        or payload.get("transcription_artifact_count")
        or len(payload.get("transcription_artifacts") or [])
        or 0
    )
    recording_artifact_count = int(
        payload.get("recording_artifact_count") or len(payload.get("recording_artifacts") or []) or 0
    )
    transcription_signal = bool(payload.get("transcription_enabled")) or transcript_artifact_count > 0
    recording_signal = bool(payload.get("recording_enabled")) or recording_artifact_count > 0
    attendance_report_present = bool(payload.get("attendance_report_present"))
    external_participant_count = int(payload.get("external_participant_count") or 0)
    sensitive_meeting = _is_sensitive_meeting(payload) or external_participant_count > 0

    artifact_types: list[str] = []
    if attendance_report_present:
        artifact_types.append("attendance_report")
    if detections:
        artifact_types.append("notetaker_attendance")
    if transcription_signal:
        artifact_types.append("transcript")
    if recording_signal:
        artifact_types.append("recording")

    detected = bool(artifact_types)
    policy_triggered = bool(detections or transcription_signal or recording_signal)
    control_mode = "external_required" if policy_triggered else "detected_only"
    recommended_actions: list[str] = []
    if policy_triggered:
        recommended_actions.extend(
            [
                "Review attendance, recording, and transcript artifacts for meeting policy violations.",
                "Use Microsoft/Google/Zoom controls to remove notetakers and disable recording or transcription where unapproved.",
                "Restrict external attendees, anonymous join, transcription, and recording for sensitive meetings.",
            ]
        )

    evidence = None
    finding_ids: list[str] = []
    finding_types: list[str] = []
    if policy_triggered:
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="meeting_notetaker_artifact_signal",
            signal_type="endpoint.notetaker.artifact_signal",
            label=f"AI notetaker artifact signal: {platform}:{meeting_id}",
            payload={
                "source": source,
                "platform": platform,
                "meeting_id": meeting_id,
                "title_present": bool(title),
                "organizer_email": organizer_email,
                "sensitivity_label": payload.get("sensitivity_label"),
                "participant_count": len(participants),
                "external_participant_count": external_participant_count,
                "attendance_report_present": attendance_report_present,
                "notetaker_visible_in_roster": payload.get("notetaker_visible_in_roster"),
                "transcription_enabled": bool(payload.get("transcription_enabled")),
                "recording_enabled": bool(payload.get("recording_enabled")),
                "transcript_artifact_count": transcript_artifact_count,
                "recording_artifact_count": recording_artifact_count,
                "artifact_types": artifact_types,
                "detections": detections,
                "control_mode": control_mode,
                "recommended_actions": recommended_actions,
            },
        )
        evidence_id = getattr(evidence, "id", None)
        first_provider = str(detections[0].get("provider") or "meeting_artifact")
        finding_specs: list[tuple[str, str, str, list[str]]] = []
        if detections:
            finding_specs.append(
                (
                    "AI_NOTETAKER_DETECTED",
                    "high",
                    "AI notetaker appeared in attendance or meeting artifact evidence. Review or remove before sensitive discussion.",
                    ["CTRL-MEETING-AI-NOTETAKER-001"],
                )
            )
        if transcription_signal or recording_signal:
            finding_specs.append(
                (
                    "MEETING_TRANSCRIPTION_POLICY_VIOLATION",
                    "high",
                    "Meeting artifact evidence shows transcription or recording activity. Review meeting policy and disable if unapproved.",
                    ["CTRL-MEETING-TRANSCRIPTION-001"],
                )
            )
        if sensitive_meeting and policy_triggered:
            finding_specs.append(
                (
                    "SENSITIVE_MEETING_WITH_AI_ENABLED",
                    "high",
                    "Sensitive or externally attended meeting has AI notetaker, recording, or transcription evidence.",
                    ["CTRL-MEETING-AI-NOTETAKER-001", "CTRL-MEETING-TRANSCRIPTION-001"],
                )
            )

        for finding_type, severity, recommended_action, controls in finding_specs:
            finding = Finding(
                tenant_id=tenant_id,
                source_surface="connector",
                ai_tool=first_provider,
                user_id=actor_user_id,
                user_email=organizer_email,
                application=platform,
                severity=severity,
                finding_type=finding_type,
                risk_category="meeting_ai_notetaker",
                data_classification="sensitive" if sensitive_meeting else None,
                decision="warn",
                status="open",
                recommended_action=recommended_action,
                evidence_node_ids=[evidence_id] if evidence_id else [],
                related_control_ids=controls,
                dedupe_key=_short_dedupe_key(
                    "artifact_notetaker",
                    tenant_id,
                    platform,
                    meeting_id,
                    finding_type,
                    first_provider,
                ),
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.finding_id)
            finding_types.append(finding_type)

        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="agent",
            action="endpoint.notetaker.artifact_signal",
            resource_type="meeting_notetaker_artifact_signal",
            resource_id=meeting_id,
            payload={
                "source": source,
                "platform": platform,
                "meeting_id": meeting_id,
                "control_mode": control_mode,
                "artifact_types": artifact_types,
                "detection_count": len(detections),
                "finding_types": finding_types,
            },
        )
        db.commit()

    return {
        "status": "ok",
        "detected": detected,
        "policy_triggered": policy_triggered,
        "control_mode": control_mode,
        "source": source,
        "platform": platform,
        "meeting_id": meeting_id,
        "detections": detections,
        "artifact_types": artifact_types,
        "finding_types": finding_types,
        "finding_ids": finding_ids,
        "evidence_node_id": getattr(evidence, "id", None) if evidence else None,
        "recommended_actions": recommended_actions,
    }


def evaluate_notetaker(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    hostname: str,
    signal: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Server-authoritative AI-notetaker decision + evidence/audit record.

    Every detected notetaker is warned with a banner and an eviction option — even
    a local recorder capturing laptop audio rather than joined to the meeting.
    Policy may escalate to block/auto-evict.
    """
    policy = _resolve_notetaker_policy(_as_dict(build_extension_policy_sync(db, tenant_id=tenant_id)))
    attributes = signal.get("attributes") if isinstance(signal.get("attributes"), dict) else {}
    local_audio = bool(attributes.get("local_audio_capture"))
    in_meeting = bool(attributes.get("in_meeting"))
    label = str(attributes.get("name") or signal.get("subject") or "AI notetaker")

    action = str(policy.get("action") or "warn")
    auto_evict = bool(policy.get("auto_evict"))
    # A recorder actively capturing during a live meeting is the highest-risk case.
    if action == "warn" and local_audio and in_meeting and policy.get("escalate_in_meeting"):
        action = "block"
        auto_evict = True

    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="endpoint_notetaker_detection",
        signal_type="endpoint.notetaker.detected",
        label=f"AI notetaker detected: {label}",
        payload={
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "notetaker": signal.get("subject"),
            "local_audio_capture": local_audio,
            "in_meeting": in_meeting,
            "decision": action,
            "attributes": attributes,
        },
    )
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="agent",
        action="endpoint.notetaker.evaluate",
        resource_type="endpoint_notetaker",
        resource_id=str(signal.get("subject") or "notetaker"),
        payload={"decision": action, "endpoint_id": endpoint_id, "label": label},
    )
    db.commit()

    return {
        "decision": action,
        "reason": f"notetaker_policy:{'local_audio' if local_audio else 'meeting'}",
        "banner": bool(policy.get("banner", True)),
        "eviction_allowed": bool(policy.get("allow_eviction", True)),
        "auto_evict": auto_evict,
        "label": label,
        "evidence_node_id": getattr(evidence, "id", None),
        "audit_log_id": getattr(audit, "id", None),
    }


def execute_notetaker_platform_action(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    hostname: str,
    platform: str,
    action: str,
    payload: dict[str, Any],
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    """Attempt a backend-mediated notetaker platform control.

    This is intentionally honest: if Microsoft Graph / Google Workspace is not
    configured or cannot execute the action, the result remains
    external_required/incomplete rather than pretending that Hawk ejected the
    notetaker.
    """
    platform_token = str(platform or "").strip().lower()
    action_token = str(action or "").strip().lower()
    teams_platforms = {"teams", "microsoft_teams"}
    google_platforms = {"google_meet", "google_meet_web", "google_workspace", "google_calendar", "meet"}
    zoom_platforms = {"zoom", "zoom_meeting", "zoom_web"}
    if platform_token in teams_platforms:
        provider_path = "microsoft_graph"
    elif platform_token in google_platforms:
        provider_path = "google_workspace"
    elif platform_token in zoom_platforms:
        provider_path = "zoom"
    else:
        provider_path = "unknown"

    source_detection_evidence_id = str(
        payload.get("source_detection_evidence_id") or ""
    ).strip()
    source_detection = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == source_detection_evidence_id,
            EvidenceNode.signal_type == "endpoint.notetaker.calendar_signal",
        )
    ) if source_detection_evidence_id else None
    source_payload = (
        source_detection.payload
        if source_detection is not None and isinstance(source_detection.payload, dict)
        else {}
    )
    requested_participant_id = str(payload.get("participant_id") or "").strip().lower()
    requested_email = str(payload.get("notetaker_email") or "").strip().lower()
    requested_identity_hashes = {
        domain_hash("hawk:meeting-participant:v1", value)
        for value in (requested_participant_id, requested_email)
        if value
    }
    detection_matches = any(
        str(item.get("participant_identity_hash") or "")
        in requested_identity_hashes
        for item in source_payload.get("detections", ())
        if isinstance(item, dict)
    )
    source_matches = bool(
        source_detection is not None
        and str(source_payload.get("platform") or "").strip().lower() == platform_token
        and str(source_payload.get("meeting_id") or "").strip()
        == str(payload.get("meeting_id") or "").strip()
        and detection_matches
    )

    execution_payload = {
        **payload,
        "endpoint_id": endpoint_id,
        "hostname": hostname,
        "platform": platform_token,
        "action": action_token,
    }
    if not source_matches:
        provider_executor = lambda: {
            "provider_control_path": provider_path,
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "correlated_notetaker_detection_required",
        }
    elif platform_token in teams_platforms:
        provider_executor = lambda: execute_microsoft_teams_notetaker_graph_action(action=action_token, payload=execution_payload)
    elif platform_token in google_platforms:
        provider_executor = lambda: execute_google_meet_notetaker_action(action=action_token, payload=execution_payload)
    elif platform_token in zoom_platforms:
        provider_executor = lambda: execute_zoom_notetaker_action(action=action_token, payload=execution_payload)
    else:
        provider_executor = lambda: {
            "provider_control_path": provider_path,
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "unsupported_meeting_platform_control",
        }
    install_generic_seam_authority(
        db, tenant_id=tenant_id, seam_ref="endpoint.platform_invocation", action_id=f"endpoint:{endpoint_id}:{action_token}",
        chain_id=endpoint_id, actor_principal=f"user:{actor_user_id or 'unknown'}", executing_principal="service:endpoint-agent",
        operation=action_token, tool_or_service_ref=provider_path, parameter_hash=domain_hash("hawk:endpoint-platform-payload:v1", execution_payload),
        target_ref=f"endpoint:{endpoint_id}",
    )
    result = invoke_final_seam(db, seam_ref="endpoint.platform_invocation", executor=provider_executor)
    provider_operation = result.get("graph_operation") or result.get("google_operation") or result.get("zoom_operation")

    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="meeting_notetaker_platform_action",
        signal_type="endpoint.notetaker.platform_action",
        label=f"AI notetaker platform action: {platform_token}:{action_token}",
        payload={
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "platform": platform_token,
            "provider_control_path": result.get("provider_control_path") or provider_path,
            "action": action_token,
            "control_mode": result.get("control_mode"),
            "performed": bool(result.get("performed")),
            "reason": result.get("reason"),
            "status_code": result.get("status_code"),
            "graph_operation": provider_operation,
            "notetaker_label": payload.get("notetaker_label"),
            "notetaker_email": payload.get("notetaker_email"),
            "participant_id": payload.get("participant_id"),
            "source_detection_evidence_id": source_detection_evidence_id or None,
        },
    )
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="agent",
        action="endpoint.notetaker.platform_action",
        resource_type="meeting_notetaker_control",
        resource_id=f"{platform_token}:{action_token}",
        payload={
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "control_mode": result.get("control_mode"),
            "performed": bool(result.get("performed")),
            "reason": result.get("reason"),
        },
    )
    db.commit()

    return {
        "status": "ok",
        "platform": platform_token,
        "provider_control_path": result.get("provider_control_path") or provider_path,
        "action": action_token,
        "control_mode": result.get("control_mode") or "external_required",
        "performed": bool(result.get("performed")),
        "reason": result.get("reason") or "unknown",
        "graph_operation": provider_operation,
        "status_code": result.get("status_code"),
        "source_detection_bound": source_matches,
        "evidence_node_id": getattr(evidence, "id", None),
        "audit_log_id": getattr(audit, "id", None),
    }


def record_heartbeat(
    db: Session, *, tenant_id: str, endpoint_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="endpoint_agent_heartbeat",
        signal_type="endpoint.agent.heartbeat",
        label=f"Endpoint agent heartbeat: {payload.get('hostname') or endpoint_id}",
        payload={"endpoint_id": endpoint_id, **payload},
    )
    db.commit()
    return {"status": "ok", "evidence_node_id": getattr(node, "id", None)}


def record_evidence(
    db: Session, *, tenant_id: str, endpoint_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="endpoint_agent_evidence",
        signal_type="endpoint.agent.evidence",
        label=f"Endpoint agent evidence: {payload.get('event_type') or 'event'}",
        payload={"endpoint_id": endpoint_id, **payload},
    )
    db.commit()
    return {"status": "ok", "evidence_node_id": getattr(node, "id", None)}
