from __future__ import annotations

import base64
import binascii
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..auth.device_key import DeviceKeyProvider
from .local_policy import canonical_policy_bytes


_RECEIPT_FIELDS = {
    "schema",
    "version",
    "tenant_id",
    "device_id",
    "issued_at",
    "expires_at",
    "controls",
    "local_policy",
    "reason_codes",
    "blind_spots",
}
_CONTROL_FIELDS = {"status", "verification", "health", "evidence_refs"}
_CONTROL_NAMES = ("file_control", "process_control", "network_control", "semantic_proxy")
_CONTROL_STATUS = {"inline", "inline_bound", "external", "observe", "not_covered", "unavailable", "unknown"}
_CONTROL_VERIFICATION = {"verified", "experimental", "unverified"}
_CONTROL_HEALTH = {"healthy", "degraded", "unhealthy", "stale", "unknown"}
_LOCAL_POLICY_FIELDS = {"status", "freshness", "policy_version", "signature_verified", "evidence_refs"}
_DISPLAY_STATES = {"Protected", "Monitoring", "Needs attention"}
_MAC_BUNDLE_IDS = (
    "ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
    "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing",
)
_NATIVE_AUTHORITY_FIELDS = {
    "mode", "policy_digest", "policy_epoch", "team_id", "bundle_ids",
    "issued_at_unix_seconds", "expires_at_unix_seconds",
    "artifact_sha256", "target_acceptance_artifact_sha256",
    "target_acceptance_verified", "network_child_attribution_verified",
}


def _utc(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(UTC)


def _bounded_references(value: Any, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("reference list invalid")
    return list(
        dict.fromkeys(
            str(item).strip()[:256]
            for item in value
            if isinstance(item, str) and item.strip()
        )
    )


def _rejected_posture(os_type: str, reason: str) -> dict[str, Any]:
    posture = default_floor_posture(os_type)
    posture["reason_codes"] = list(
        dict.fromkeys([*posture["reason_codes"], f"runtime_receipt_rejected:{reason}"])
    )
    posture["blind_spots"] = list(
        dict.fromkeys([*posture["blind_spots"], "signed_native_runtime_receipt_unavailable"])
    )
    return posture


def _verify_receipt_signature(
    *,
    algorithm: str,
    key: bytes,
    signature: bytes,
    payload: bytes,
) -> None:
    if algorithm == "Ed25519":
        if len(key) != 32 or len(signature) != 64:
            raise ValueError("Ed25519 key or signature length")
        Ed25519PublicKey.from_public_bytes(key).verify(signature, payload)
        return
    if algorithm == "ES256":
        public_key = serialization.load_pem_public_key(key)
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError("ES256 requires a P-256 public key")
        if not 8 <= len(signature) <= 80:
            raise ValueError("ES256 signature length")
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        return
    raise ValueError("unsupported runtime-receipt algorithm")


def _validate_publishable_payload(payload: Mapping[str, Any], endpoint_id: str) -> bytes:
    if not isinstance(payload, Mapping) or set(payload) not in (
        _RECEIPT_FIELDS, _RECEIPT_FIELDS | {"display_state"},
        _RECEIPT_FIELDS | {"native_authority"},
    ):
        raise ValueError("runtime receipt payload schema is invalid")
    if payload.get("schema") != "hawk.endpoint-floor-runtime-receipt" or payload.get("version") != 1:
        raise ValueError("runtime receipt payload version is invalid")
    if str(payload.get("device_id") or "") != endpoint_id:
        raise ValueError("runtime receipt device scope does not match the signing identity")
    if "display_state" in payload and payload.get("display_state") not in _DISPLAY_STATES:
        raise ValueError("runtime receipt display state is invalid")
    if not str(payload.get("tenant_id") or "").strip():
        raise ValueError("runtime receipt tenant scope is required")
    issued_at = _utc(payload.get("issued_at"))
    expires_at = _utc(payload.get("expires_at"))
    if expires_at <= issued_at:
        raise ValueError("runtime receipt expiry is invalid")
    controls = payload.get("controls")
    if not isinstance(controls, Mapping) or set(controls) != set(_CONTROL_NAMES):
        raise ValueError("runtime receipt controls are invalid")
    for control in controls.values():
        if not isinstance(control, Mapping) or set(control) != _CONTROL_FIELDS:
            raise ValueError("runtime receipt control schema is invalid")
        if str(control.get("status") or "") not in _CONTROL_STATUS:
            raise ValueError("runtime receipt control status is invalid")
        if str(control.get("verification") or "") not in _CONTROL_VERIFICATION:
            raise ValueError("runtime receipt control verification is invalid")
        if str(control.get("health") or "") not in _CONTROL_HEALTH:
            raise ValueError("runtime receipt control health is invalid")
        _bounded_references(control.get("evidence_refs"), maximum=32)
    local_policy = payload.get("local_policy")
    if not isinstance(local_policy, Mapping) or set(local_policy) != _LOCAL_POLICY_FIELDS:
        raise ValueError("runtime receipt local policy is invalid")
    _bounded_references(local_policy.get("evidence_refs"), maximum=32)
    _bounded_references(payload.get("reason_codes"), maximum=64)
    _bounded_references(payload.get("blind_spots"), maximum=64)
    if "native_authority" in payload:
        _validate_native_authority(payload["native_authority"])
    canonical = canonical_policy_bytes(payload)
    if len(canonical) > 128 * 1024:
        raise ValueError("runtime receipt payload is oversized")
    return canonical


def _validate_native_authority(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _NATIVE_AUTHORITY_FIELDS:
        raise ValueError("native authority schema is invalid")
    if (value["mode"] not in {"monitor", "enforce"} or
            not isinstance(value["policy_digest"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["policy_digest"]) is None or
            type(value["policy_epoch"]) is not int or value["policy_epoch"] <= 0 or
            not isinstance(value["team_id"], str) or
            re.fullmatch(r"[A-Z0-9]{10}", value["team_id"]) is None or
            value["bundle_ids"] != list(_MAC_BUNDLE_IDS)):
        raise ValueError("native identity binding is invalid")
    issued = value["issued_at_unix_seconds"]
    expires = value["expires_at_unix_seconds"]
    if type(issued) is not int or type(expires) is not int or issued <= 0 or expires <= issued:
        raise ValueError("native UTC bounds are invalid")
    for key in ("target_acceptance_verified", "network_child_attribution_verified"):
        if type(value[key]) is not bool:
            raise ValueError("native evidence flag is invalid")
    for key in ("artifact_sha256", "target_acceptance_artifact_sha256"):
        if not isinstance(value[key], str) or (value[key] and re.fullmatch(r"[0-9a-f]{64}", value[key]) is None):
            raise ValueError("native artifact binding is invalid")
    return dict(value)


def publish_signed_runtime_floor_posture(
    *,
    payload: Mapping[str, Any],
    receipt_path: str | Path,
    provider: DeviceKeyProvider,
    endpoint_id: str,
    require_hardware_backed: bool = True,
) -> dict[str, Any]:
    """Atomically publish bounded ES256 health using the endpoint device key.

    The envelope contains no credentials or native policy material. Production
    profiles reject software-only identities and unsigned helper paths through
    the existing DeviceKeyProvider status contract.
    """

    normalized_endpoint = str(endpoint_id or "").strip()
    if not normalized_endpoint:
        raise ValueError("endpoint identity is required")
    canonical = _validate_publishable_payload(payload, normalized_endpoint)
    status = provider.status()
    identity = provider.ensure_key(normalized_endpoint)
    if not status.available or not identity.public_key_pem:
        raise ValueError("endpoint device identity is unavailable")
    if require_hardware_backed and (
        not status.hardware_backed
        or not identity.hardware_backed
        or not status.signed_helper
    ):
        raise ValueError("runtime receipt requires a signed hardware-backed identity")
    signature = provider.sign(canonical)
    if not 8 <= len(signature) <= 80:
        raise ValueError("endpoint device identity returned an invalid ES256 signature")
    envelope = {
        "key_id": identity.key_thumbprint,
        "algorithm": "ES256",
        "payload": json.loads(canonical.decode("ascii")),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    encoded = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    destination = Path(receipt_path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return {
        "algorithm": "ES256",
        "key_id": identity.key_thumbprint,
        "receipt_path": str(destination),
        "hardware_backed": identity.hardware_backed,
    }


def _control(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "verification": "unverified",
        "health": "unknown",
        "evidence_refs": [],
    }


def default_floor_posture(os_type: str) -> dict[str, Any]:
    """Return honest posture until authenticated native receipts are present.

    The Python service cannot infer Endpoint Security, Network Extension,
    minifilter, WFP, or process-notify activation from source files or process
    names. Native components must replace these values with signed runtime
    evidence before the backend can count a primitive as protected.
    """
    normalized = str(os_type or "").strip().lower()
    supported = normalized in {"darwin", "macos", "windows"}
    if supported:
        controls = {
            "file_control": _control("unknown"),
            "process_control": _control("unknown"),
            "network_control": _control("unknown"),
            "semantic_proxy": _control("unavailable"),
        }
        reasons = [
            "CONTROL_REQUIREMENT_UNSATISFIED:file",
            "CONTROL_REQUIREMENT_UNSATISFIED:process",
            "CONTROL_REQUIREMENT_UNSATISFIED:network",
        ]
        blind_spots = [
            "native_runtime_acceptance_missing",
            "signed_component_health_missing",
            "semantic_http_control_unavailable",
        ]
    else:
        controls = {
            "file_control": _control("unavailable"),
            "process_control": _control("unavailable"),
            "network_control": _control("unavailable"),
            "semantic_proxy": _control("unavailable"),
        }
        reasons = ["ENDPOINT_FLOOR_OS_UNSUPPORTED"]
        blind_spots = ["endpoint_floor_os_unsupported"]
    return {
        "schema_version": "1.0",
        "minimum_floor_satisfied": False,
        "display_state": "Needs attention",
        "health": "unknown" if supported else "unavailable",
        "controls": controls,
        "local_policy": {
            "status": "unknown" if supported else "unavailable",
            "freshness": "unknown",
            "policy_version": None,
            "signature_verified": False,
            "evidence_refs": [],
        },
        "reason_codes": reasons,
        "blind_spots": blind_spots,
        "evidence_refs": [],
    }


def load_signed_runtime_floor_posture(
    *,
    os_type: str,
    receipt_path: str | Path,
    trusted_public_keys: Mapping[str, bytes],
    expected_tenant_id: str,
    expected_device_id: str,
    now: datetime | None = None,
    maximum_bytes: int = 256 * 1024,
) -> dict[str, Any]:
    """Load an authenticated native-component receipt without trusting aggregates.

    The receipt contains only bounded posture and evidence references. It has no
    credential material. Any parse, signature, scope, freshness, or schema error
    returns the conservative default posture for the operating system.
    """
    normalized_os = str(os_type or "").strip().lower()
    if normalized_os not in {"darwin", "macos", "windows"}:
        return default_floor_posture(os_type)
    path = Path(receipt_path).expanduser()
    maximum = max(1024, min(int(maximum_bytes), 1024 * 1024))
    try:
        if path.stat().st_size > maximum:
            return _rejected_posture(os_type, "oversized")
        raw = path.read_bytes()
        if len(raw) > maximum:
            return _rejected_posture(os_type, "oversized")
        envelope = json.loads(raw.decode("utf-8", errors="strict"))
    except FileNotFoundError:
        return _rejected_posture(os_type, "missing")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _rejected_posture(os_type, "malformed")

    if not isinstance(envelope, dict) or set(envelope) != {"key_id", "algorithm", "payload", "signature"}:
        return _rejected_posture(os_type, "envelope_schema")
    algorithm = str(envelope.get("algorithm") or "")
    key = trusted_public_keys.get(str(envelope.get("key_id") or ""))
    payload = envelope.get("payload")
    if not isinstance(key, bytes) or not 16 <= len(key) <= 16 * 1024 or not isinstance(payload, dict):
        return _rejected_posture(os_type, "trust_binding")
    try:
        signature = base64.b64decode(str(envelope.get("signature") or ""), validate=True)
        _verify_receipt_signature(
            algorithm=algorithm,
            key=key,
            signature=signature,
            payload=canonical_policy_bytes(payload),
        )
    except (ValueError, TypeError, InvalidSignature, binascii.Error):
        return _rejected_posture(os_type, "signature")

    observed_now = now or datetime.now(UTC)
    observed_now = observed_now.astimezone(UTC) if observed_now.tzinfo else observed_now.replace(tzinfo=UTC)
    try:
        if set(payload) not in (
            _RECEIPT_FIELDS, _RECEIPT_FIELDS | {"display_state"},
            _RECEIPT_FIELDS | {"native_authority"},
        ):
            raise ValueError("payload schema")
        if payload.get("schema") != "hawk.endpoint-floor-runtime-receipt" or payload.get("version") != 1:
            raise ValueError("payload version")
        if payload.get("tenant_id") != expected_tenant_id or payload.get("device_id") != expected_device_id:
            raise ValueError("scope")
        issued_at = _utc(payload.get("issued_at"))
        expires_at = _utc(payload.get("expires_at"))
        if expires_at <= issued_at or observed_now < issued_at or observed_now >= expires_at:
            raise ValueError("freshness")

        provided_controls = payload.get("controls")
        if not isinstance(provided_controls, dict) or set(provided_controls) != set(_CONTROL_NAMES):
            raise ValueError("controls schema")
        controls: dict[str, dict[str, Any]] = {}
        for name in _CONTROL_NAMES:
            control = provided_controls[name]
            if not isinstance(control, dict) or set(control) != _CONTROL_FIELDS:
                raise ValueError("control schema")
            status = str(control.get("status") or "").strip().lower()
            verification = str(control.get("verification") or "").strip().lower()
            health = str(control.get("health") or "").strip().lower()
            if status not in _CONTROL_STATUS or verification not in _CONTROL_VERIFICATION or health not in _CONTROL_HEALTH:
                raise ValueError("control state")
            controls[name] = {
                "status": status,
                "verification": verification,
                "health": health,
                "evidence_refs": _bounded_references(control.get("evidence_refs"), maximum=32),
            }

        provided_policy = payload.get("local_policy")
        if not isinstance(provided_policy, dict) or set(provided_policy) != _LOCAL_POLICY_FIELDS:
            raise ValueError("policy schema")
        policy_version = provided_policy.get("policy_version")
        local_policy = {
            "status": str(provided_policy.get("status") or "").strip().lower(),
            "freshness": str(provided_policy.get("freshness") or "").strip().lower(),
            "policy_version": str(policy_version).strip()[:128] if policy_version is not None else None,
            "signature_verified": provided_policy.get("signature_verified") is True,
            "evidence_refs": _bounded_references(provided_policy.get("evidence_refs"), maximum=32),
        }
        if local_policy["status"] not in {"active", "disabled", "invalid", "unavailable", "unknown"}:
            raise ValueError("policy status")
        if local_policy["freshness"] not in {"fresh", "stale", "expired", "unknown"}:
            raise ValueError("policy freshness")
        reason_codes = _bounded_references(payload.get("reason_codes"), maximum=64)
        blind_spots = _bounded_references(payload.get("blind_spots"), maximum=64)
        requested_display_state = payload.get("display_state", "Needs attention")
        if requested_display_state not in _DISPLAY_STATES:
            raise ValueError("display state")
        native_authority = (
            _validate_native_authority(payload["native_authority"])
            if "native_authority" in payload else None
        )
    except (TypeError, ValueError):
        return _rejected_posture(os_type, "payload")

    def control_proved(name: str) -> bool:
        control = controls[name]
        return bool(
            control["status"] in {"inline", "inline_bound"}
            and control["verification"] == "verified"
            and control["health"] == "healthy"
            and control["evidence_refs"]
        )

    local_policy_proved = bool(
        local_policy["status"] == "active"
        and local_policy["freshness"] == "fresh"
        and local_policy["signature_verified"]
        and local_policy["evidence_refs"]
    )
    controls_satisfied = local_policy_proved and all(
        control_proved(name) for name in _CONTROL_NAMES[:3]
    )
    native_current = bool(
        native_authority is not None and algorithm == "ES256" and
        native_authority["issued_at_unix_seconds"] <= int(observed_now.timestamp()) <
            native_authority["expires_at_unix_seconds"] and
        f"native:policy:{native_authority['policy_digest']}" in local_policy["evidence_refs"] and
        native_authority["network_child_attribution_verified"]
    )
    minimum_satisfied = controls_satisfied and (
        native_current if normalized_os in {"darwin", "macos"} else True
    )
    if normalized_os in {"darwin", "macos"}:
        if minimum_satisfied and native_authority["mode"] == "monitor":
            derived_display_state = "Monitoring"
        elif (minimum_satisfied and native_authority["mode"] == "enforce" and
              native_authority["target_acceptance_verified"] and
              native_authority["artifact_sha256"] and
              native_authority["artifact_sha256"] ==
                  native_authority["target_acceptance_artifact_sha256"]):
            derived_display_state = "Protected"
        else:
            derived_display_state = "Needs attention"
    else:
        derived_display_state = (
            requested_display_state if minimum_satisfied and requested_display_state in {"Protected", "Monitoring"}
            else "Needs attention"
        )
    semantic_available = control_proved("semantic_proxy")
    if not minimum_satisfied:
        reason_codes = list(dict.fromkeys([*reason_codes, "CONTROL_REQUIREMENT_UNSATISFIED:endpoint_floor"]))
    evidence_refs = sorted(
        {
            reference
            for control in controls.values()
            for reference in control["evidence_refs"]
        }
        | set(local_policy["evidence_refs"])
    )
    return {
        "schema_version": "1.0",
        "minimum_floor_satisfied": minimum_satisfied,
        "health": "healthy" if minimum_satisfied else "degraded",
        "display_state": derived_display_state,
        "semantic_control_available": semantic_available,
        "controls": controls,
        "local_policy": local_policy,
        "reason_codes": reason_codes,
        "blind_spots": blind_spots,
        "evidence_refs": evidence_refs,
    }


def configured_runtime_floor_posture(
    *,
    os_type: str,
    receipt_path: str | Path,
    trusted_public_keys: Mapping[str, str | bytes],
    expected_tenant_id: str,
    expected_device_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    decoded: dict[str, bytes] = {}
    for key_id, value in trusted_public_keys.items():
        try:
            if isinstance(value, bytes):
                raw = value
            elif "-----BEGIN PUBLIC KEY-----" in value:
                raw = value.encode("ascii")
            else:
                raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError, binascii.Error):
            continue
        if isinstance(key_id, str) and key_id.strip() and 16 <= len(raw) <= 16 * 1024:
            decoded[key_id.strip()[:128]] = raw
    return load_signed_runtime_floor_posture(
        os_type=os_type,
        receipt_path=receipt_path,
        trusted_public_keys=decoded,
        expected_tenant_id=expected_tenant_id,
        expected_device_id=expected_device_id,
        now=now,
    )
