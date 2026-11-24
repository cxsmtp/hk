from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


MAX_POLICY_LIFETIME = timedelta(hours=24)
ALLOWED_DECISIONS = {"allow", "warn", "require_approval", "block"}
PROHIBITED_POLICY_KEYS = {
    "command",
    "shell",
    "script",
    "executable",
    "binary",
    "module",
    "plugin",
    "dynamic_import",
    "native_extension",
    "update_artifact",
}


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("policy_timestamp_invalid")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (TypeError, ValueError) as exc:
        raise ValueError("policy_signature_invalid") from exc


@dataclass(frozen=True, slots=True)
class PolicyVerificationKey:
    key_id: str
    key_role: str
    public_key_pem: str
    tenant_id: str


@dataclass(frozen=True, slots=True)
class SignedPolicySnapshot:
    tenant_id: str
    integration_instance_id: str
    scope: dict[str, object]
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    supported_action_classes: tuple[str, ...]
    key_id: str
    signature_algorithm: str
    signature: str

    def as_dict(self, *, include_signature: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "integration_instance_id": self.integration_instance_id,
            "scope": self.scope,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "supported_action_classes": self.supported_action_classes,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
        }
        if include_signature:
            payload["signature"] = self.signature
        return payload


def canonical_policy_body(snapshot: SignedPolicySnapshot) -> bytes:
    payload = snapshot.as_dict(include_signature=False)
    payload["issued_at"] = _utc(snapshot.issued_at).isoformat()
    payload["expires_at"] = _utc(snapshot.expires_at).isoformat()
    payload["supported_action_classes"] = list(snapshot.supported_action_classes)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _validate_declarative_scope(scope: dict[str, object], supported: tuple[str, ...]) -> None:
    if set(scope) != {"default_decision", "rules"}:
        raise ValueError("policy_scope_schema_invalid")
    default = str(scope.get("default_decision") or "")
    if default not in ALLOWED_DECISIONS:
        raise ValueError("policy_default_decision_invalid")
    rules = scope.get("rules")
    if not isinstance(rules, list) or len(rules) > 64:
        raise ValueError("policy_rules_invalid")
    seen: set[str] = set()
    supported_set = set(supported)
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"action_class", "decision"}:
            raise ValueError("policy_rule_schema_invalid")
        if set(rule) & PROHIBITED_POLICY_KEYS:
            raise ValueError("policy_executable_material_forbidden")
        action_class = str(rule.get("action_class") or "")
        decision = str(rule.get("decision") or "")
        if not action_class or len(action_class) > 128 or action_class not in supported_set:
            raise ValueError("policy_action_class_invalid")
        if action_class in seen:
            raise ValueError("policy_action_class_duplicate")
        if decision not in ALLOWED_DECISIONS:
            raise ValueError("policy_decision_invalid")
        seen.add(action_class)


def _load_public_key(pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("policy_key_invalid") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("policy_key_invalid")
    return key


def validate_policy_snapshot(
    snapshot: SignedPolicySnapshot,
    *,
    key: PolicyVerificationKey,
    tenant_id: str,
    integration_instance_id: str,
    now: datetime,
) -> SignedPolicySnapshot:
    if key.key_role != "policy_signing":
        raise ValueError("policy_key_role_invalid")
    if key.key_id != snapshot.key_id or key.tenant_id != tenant_id:
        raise ValueError("policy_key_binding_invalid")
    if snapshot.tenant_id != tenant_id or snapshot.integration_instance_id != integration_instance_id:
        raise ValueError("policy_integration_binding_invalid")
    if snapshot.signature_algorithm != "ES256":
        raise ValueError("policy_signature_algorithm_invalid")
    issued_at = _utc(snapshot.issued_at)
    expires_at = _utc(snapshot.expires_at)
    current = _utc(now)
    if issued_at > current + timedelta(seconds=60):
        raise ValueError("policy_issued_in_future")
    if expires_at < current:
        raise ValueError("policy_expired")
    if expires_at <= issued_at or expires_at - issued_at > MAX_POLICY_LIFETIME:
        raise ValueError("policy_lifetime_invalid")
    if not snapshot.policy_version or len(snapshot.policy_version) > 128:
        raise ValueError("policy_version_invalid")
    if not snapshot.supported_action_classes or len(snapshot.supported_action_classes) > 64:
        raise ValueError("policy_action_classes_invalid")
    if len(set(snapshot.supported_action_classes)) != len(snapshot.supported_action_classes):
        raise ValueError("policy_action_classes_duplicate")
    _validate_declarative_scope(snapshot.scope, snapshot.supported_action_classes)
    try:
        _load_public_key(key.public_key_pem).verify(
            _b64url_decode(snapshot.signature),
            canonical_policy_body(snapshot),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("policy_signature_invalid") from exc
    return snapshot


def evaluate_local_policy(snapshot: SignedPolicySnapshot, *, action_class: str) -> str:
    """Evaluate only the bounded declarative subset; everything else stays remote."""

    if action_class not in snapshot.supported_action_classes:
        return "REMOTE_EVALUATION_REQUIRED"
    rules = snapshot.scope.get("rules")
    if not isinstance(rules, list):
        return "REMOTE_EVALUATION_REQUIRED"
    for rule in rules:
        if isinstance(rule, dict) and rule.get("action_class") == action_class:
            return str(rule.get("decision") or "block")
    return str(snapshot.scope.get("default_decision") or "block")
