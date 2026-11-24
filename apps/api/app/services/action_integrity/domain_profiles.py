"""Reviewed, declarative Phase 5 domain profiles and non-authorizing invariants."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .canonical_v2 import canonical_json_bytes, domain_hash
from .signing import _decode_strict, _valid_asymmetric_signature
from .materiality import MATERIALITY_PROFILE_ID, MATERIALITY_PROFILE_VERSION, MATERIAL_COLLECTION_SEMANTICS, MATERIAL_PATHS


PROFILE_DIRECTORY = Path(__file__).with_name("profiles")
REQUIRED_PHASE5_PROFILE_IDS = frozenset({
    "financial-services", "healthcare", "government", "real-estate-construction",
    "energy-critical-infrastructure", "multi-tenant-saas",
})
_PROFILE_FIELDS = frozenset({
    "schema_version", "profile_id", "tenant_id", "name", "industry", "version", "status",
    "subject_types", "resource_types", "counterparty_types", "domain_action_types",
    "vocabulary_mapping", "action_mappings", "target_resolvers", "destination_resolvers",
    "resource_resolvers", "value_resolvers", "materiality_profile_id",
    "materiality_profile_version", "materiality_profile_hash", "domain_invariants",
    "approval_renderers", "outcome_verifiers", "persistence_mappings", "redaction_rules",
    "policy_template_refs", "owner_ref", "approver_ref", "issued_at", "effective_at",
    "expires_at", "evidence_refs", "algorithm", "signing_key_id", "signature",
})
_REQUIRED_PROFILE_FIELDS = _PROFILE_FIELDS
_RESOLVER_FIELDS = frozenset({"resolver_id", "resolver_version", "resource_type", "evidence_requirements"})
_INVARIANT_FIELDS = frozenset({
    "invariant_id", "version", "applies_to_action_classes", "left_path", "operator",
    "right_path", "right_literal", "required", "satisfied_reason_code",
    "violated_reason_code", "unknown_reason_code",
})
_INVARIANT_OPERATORS = frozenset({"EQ", "NOT_EQ", "IN", "NOT_IN", "SUBSET_OF", "RANGE", "RELATIONSHIP", "AUTHORITY_AT_LEAST"})
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset({"code", "module", "command", "expression", "url", "permit", "authorization", "authorization_decision", "policy_decision", "allow", "deny", "block"})
_PROFILE_SIGNATURE_DOMAIN = "hawk:domain-semantic-profile:v1"
_CATALOG_SIGNING_KEY_ID = "catalog-domain-profile-v1"
_CATALOG_ES256_PUBLIC_KEY = "BNmMBtVz7o_IZrqdiwjCR1Zt8oEEB-wl1Opp8NT0CVMJTfW65JB8Pm5b3JvseeQeZFTY8WsqYAesTeTLSTm6gJU"


class ProfileValidationError(ValueError):
    """Profile input is not a reviewed declarative Phase 5 definition."""


@dataclass(frozen=True, slots=True)
class InvariantEvaluationResult:
    invariant_id: str
    profile_id: str
    profile_version: str
    status: str
    resolution_state: str
    normalized_input_hash: str
    reason_code: str
    evidence_refs: tuple[str, ...]


def runtime_p0_materiality_hash() -> str:
    """Derive the P0 hash from the one frozen runtime materiality registry."""
    return domain_hash(
        "hawk:materiality-profile-content:v1",
        {
            "schema_version": "1.0",
            "profile_id": MATERIALITY_PROFILE_ID,
            "version": MATERIALITY_PROFILE_VERSION,
            "required_core_paths": list(MATERIAL_PATHS),
            "additional_profile_paths": [],
            "non_material_paths": ["correlation_id", "created_at", "evidence_refs"],
            "collection_semantics": MATERIAL_COLLECTION_SEMANTICS,
            "issued_at": "2026-08-24T00:00:00.000000Z",
        },
    )


def _contains_forbidden_key(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            if normalized in _FORBIDDEN_KEYS or "permit" in normalized or "authoriz" in normalized:
                return normalized
            nested = _contains_forbidden_key(child)
            if nested:
                return nested
    elif isinstance(value, list):
        for child in value:
            nested = _contains_forbidden_key(child)
            if nested:
                return nested
    return None


def _is_unresolved(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().upper() in {"UNKNOWN", "UNRESOLVED"}
    if isinstance(value, Mapping):
        return any(_is_unresolved(child) for child in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_is_unresolved(child) for child in value)
    return False


def _require_list(profile: Mapping[str, Any], field: str, *, nonempty: bool = True) -> list[Any]:
    value = profile.get(field)
    if not isinstance(value, list) or (nonempty and not value):
        raise ProfileValidationError(f"profile {field} must be {'a nonempty ' if nonempty else 'a '}list")
    return value


def _validate_timestamp_order(profile: Mapping[str, Any]) -> None:
    timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
    if any(not isinstance(profile.get(key), str) or not timestamp_pattern.fullmatch(profile[key]) for key in ("issued_at", "effective_at", "expires_at")):
        raise ProfileValidationError("profile timestamps must be exact UTC microseconds")
    try:
        values = [datetime.fromisoformat(str(profile[key]).replace("Z", "+00:00")) for key in ("issued_at", "effective_at", "expires_at")]
    except (TypeError, ValueError) as exc:
        raise ProfileValidationError("profile timestamps must be ISO-8601") from exc
    if any(value.tzinfo is None for value in values) or not values[0] <= values[1] < values[2]:
        raise ProfileValidationError("profile effective period is invalid")


def profile_signature_bytes(profile: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in profile.items() if key != "signature"}
    return _PROFILE_SIGNATURE_DOMAIN.encode("ascii") + b"\0" + canonical_json_bytes(unsigned)


def _catalog_public_key() -> ec.EllipticCurvePublicKey:
    raw = _decode_strict(_CATALOG_ES256_PUBLIC_KEY, expected_length=87)
    if raw is None:
        raise RuntimeError("catalog signing public key is malformed")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def verify_catalog_profile_signature(profile: Mapping[str, Any]) -> bool:
    """Verify the reviewed, immutable catalog envelope before it is selectable."""
    if profile.get("tenant_id") != "profile-catalog" or profile.get("algorithm") != "ES256" or profile.get("signing_key_id") != _CATALOG_SIGNING_KEY_ID:
        return False
    signature = profile.get("signature")
    if not isinstance(signature, str) or not _valid_asymmetric_signature("ES256", signature):
        return False
    raw = _decode_strict(signature, expected_length=86)
    if raw is None:
        return False
    try:
        _catalog_public_key().verify(
            encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            profile_signature_bytes(profile),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def _validate_resolvers(profile: Mapping[str, Any]) -> None:
    for field in ("target_resolvers", "destination_resolvers", "resource_resolvers", "value_resolvers"):
        for resolver in _require_list(profile, field):
            if not isinstance(resolver, Mapping) or set(resolver) - _RESOLVER_FIELDS:
                raise ProfileValidationError(f"profile {field} contains unsupported resolver fields")
            if not isinstance(resolver.get("resolver_id"), str) or not isinstance(resolver.get("resolver_version"), str):
                raise ProfileValidationError(f"profile {field} must contain versioned resolver bindings")


def _validate_invariants(profile: Mapping[str, Any]) -> None:
    for invariant in _require_list(profile, "domain_invariants"):
        if not isinstance(invariant, Mapping) or set(invariant) - _INVARIANT_FIELDS:
            raise ProfileValidationError("profile invariant contains unsupported fields")
        missing = _INVARIANT_FIELDS.difference(invariant)
        # The absent right operand is the one allowed omission.
        missing -= {"right_path", "right_literal"}
        if missing or invariant.get("operator") not in _INVARIANT_OPERATORS:
            raise ProfileValidationError("profile invariant is invalid")
        if not isinstance(invariant.get("invariant_id"), str) or not isinstance(invariant.get("version"), str):
            raise ProfileValidationError("profile invariant id and version are required")
        if not isinstance(invariant.get("applies_to_action_classes"), list) or not all(isinstance(value, str) and value for value in invariant["applies_to_action_classes"]):
            raise ProfileValidationError("profile invariant action classes are invalid")
        if not isinstance(invariant.get("left_path"), str) or not invariant["left_path"] or not isinstance(invariant.get("required"), bool):
            raise ProfileValidationError("profile invariant left path or required flag is invalid")
        if ("right_path" in invariant) == ("right_literal" in invariant):
            raise ProfileValidationError("invariant must have exactly one right operand")
        if not all(isinstance(invariant.get(field), str) and invariant[field] for field in ("satisfied_reason_code", "violated_reason_code", "unknown_reason_code")):
            raise ProfileValidationError("profile invariant reason codes are required")


def validate_profile_definition(
    profile: Mapping[str, Any],
    *,
    signature_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Strictly validate a data-only catalog profile; it never decides policy."""

    if not isinstance(profile, Mapping):
        raise ProfileValidationError("profile must be an object")
    unknown_fields = set(profile) - _PROFILE_FIELDS
    if unknown_fields:
        raise ProfileValidationError(f"profile contains unsupported fields: {', '.join(sorted(unknown_fields))}")
    forbidden = _contains_forbidden_key(profile)
    if forbidden:
        raise ProfileValidationError(f"profile contains authorization-like or permit key: {forbidden}")
    missing = _REQUIRED_PROFILE_FIELDS.difference(profile)
    if missing:
        raise ProfileValidationError(f"profile missing required fields: {', '.join(sorted(missing))}")
    if profile.get("schema_version") != "1.0" or profile.get("status") != "reviewed":
        raise ProfileValidationError("profile must be reviewed schema 1.0")
    if not all(isinstance(profile.get(field), str) and profile[field] for field in ("profile_id", "tenant_id", "name", "industry", "version", "materiality_profile_id", "materiality_profile_version", "owner_ref", "approver_ref", "algorithm", "signing_key_id", "signature")):
        raise ProfileValidationError("profile identifiers are invalid")
    if not _HEX_256.fullmatch(str(profile.get("materiality_profile_hash", ""))):
        raise ProfileValidationError("profile materiality_profile_hash must be a lowercase SHA-256 digest")
    if profile["materiality_profile_id"] != MATERIALITY_PROFILE_ID or profile["materiality_profile_version"] != MATERIALITY_PROFILE_VERSION or profile["materiality_profile_hash"] != runtime_p0_materiality_hash():
        raise ProfileValidationError("profile must bind the current runtime P0 materiality hash")
    for field in ("subject_types", "resource_types", "domain_action_types", "evidence_refs"):
        _require_list(profile, field)
    _validate_resolvers(profile)
    _validate_invariants(profile)
    _validate_timestamp_order(profile)
    if profile["tenant_id"] == "profile-catalog":
        if signature_verifier is not None or not verify_catalog_profile_signature(profile):
            raise ProfileValidationError("profile signature is invalid")
    elif signature_verifier is None:
        raise ProfileValidationError("non-catalog profile requires an explicit cryptographic verifier")
    elif not bool(signature_verifier(profile)):
        raise ProfileValidationError("profile signature is invalid")
    return dict(profile)


def profile_content_hash(profile: Mapping[str, Any]) -> str:
    """Hash the complete canonical profile envelope, excluding only signature."""

    return domain_hash("hawk:domain-semantic-profile-content:v1", {key: value for key, value in profile.items() if key != "signature"})


def load_reviewed_profile_definitions() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(PROFILE_DIRECTORY.glob("*.json")):
        if path.name.startswith("._"):
            continue
        try:
            profile = validate_profile_definition(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileValidationError(f"profile file is unreadable: {path.name}") from exc
        profile_id = str(profile["profile_id"])
        if profile_id in profiles:
            raise ProfileValidationError(f"duplicate profile_id: {profile_id}")
        profiles[profile_id] = profile
    if set(profiles) != REQUIRED_PHASE5_PROFILE_IDS:
        raise ProfileValidationError("reviewed Phase 5 profile catalog is incomplete or ambiguous")
    return profiles


def _status_for(operator: str, left: Any, right: Any) -> str:
    if _is_unresolved(left) or _is_unresolved(right):
        return "UNKNOWN"
    try:
        if operator == "EQ": return "SATISFIED" if left == right else "VIOLATED"
        if operator == "NOT_EQ": return "SATISFIED" if left != right else "VIOLATED"
        if operator == "IN": return "SATISFIED" if left in right else "VIOLATED"
        if operator == "NOT_IN": return "SATISFIED" if left not in right else "VIOLATED"
        if operator == "SUBSET_OF": return "SATISFIED" if set(left).issubset(set(right)) else "VIOLATED"
        if operator == "RANGE":
            lower, upper = right if isinstance(right, (list, tuple)) and len(right) == 2 else (None, None)
            if lower is None or upper is None:
                return "UNKNOWN"
            return "SATISFIED" if lower <= left <= upper else "VIOLATED"
        if operator == "RELATIONSHIP": return "SATISFIED" if isinstance(left, Mapping) and left.get("relation") == right else "VIOLATED"
        if operator == "AUTHORITY_AT_LEAST":
            ranks = {"none": 0, "read": 1, "write": 2, "admin": 3}
            return "SATISFIED" if ranks.get(str(left).lower(), -1) >= ranks.get(str(right).lower(), 99) else "VIOLATED"
    except (TypeError, ValueError):
        return "UNKNOWN"
    return "UNKNOWN"


def evaluate_domain_invariant(*, invariant: Mapping[str, Any], profile_id: str, profile_version: str, action_class: str | None, left: Any, right: Any, evidence_refs: tuple[str, ...] | list[str] = ()) -> InvariantEvaluationResult:
    """Return a typed observation, never an authorization decision."""

    invariant_id = str(invariant.get("invariant_id", "unknown"))
    input_hash = domain_hash("hawk:domain-invariant-input:v1", {"left": left, "right": right, "action_class": action_class})
    if action_class is not None and action_class not in invariant.get("applies_to_action_classes", []):
        status, reason = "NOT_APPLICABLE", "not_applicable"
    elif _is_unresolved(left) or _is_unresolved(right):
        status, reason = "UNKNOWN", str(invariant.get("unknown_reason_code", "invariant_input_unknown"))
    else:
        status = _status_for(str(invariant.get("operator", "")), left, right)
        reason = str(invariant.get("satisfied_reason_code") if status == "SATISFIED" else invariant.get("violated_reason_code") if status == "VIOLATED" else invariant.get("unknown_reason_code", "invariant_input_unknown"))
    return InvariantEvaluationResult(invariant_id, profile_id, profile_version, status, "UNRESOLVED" if status == "UNKNOWN" else "RESOLVED", input_hash, reason, tuple(sorted({str(ref) for ref in evidence_refs if ref})))


def evaluate_invariant(*, left: Any, operator: str, right: Any) -> InvariantEvaluationResult:
    """Compatibility wrapper returning the frozen structured result shape."""
    invariant = {"invariant_id": "inline", "operator": operator, "applies_to_action_classes": [], "satisfied_reason_code": "satisfied", "violated_reason_code": "violated", "unknown_reason_code": "unknown"}
    return evaluate_domain_invariant(invariant=invariant, profile_id="inline", profile_version="1.0", action_class=None, left=left, right=right)


@dataclass(frozen=True, slots=True)
class DomainSemanticProfile:
    profile_id: str
    tenant_id: str
    version: str
    status: str
    issued_at: datetime
    effective_at: datetime
    expires_at: datetime
    content: Mapping[str, Any]

    @property
    def content_hash(self) -> str:
        envelope = {"schema_version": "1.0", "profile_id": self.profile_id, "tenant_id": self.tenant_id, "version": self.version, "status": self.status, "issued_at": self.issued_at.isoformat(), "effective_at": self.effective_at.isoformat(), "expires_at": self.expires_at.isoformat(), **dict(self.content)}
        return profile_content_hash(envelope)


@dataclass(frozen=True, slots=True)
class TenantProfileSelection:
    tenant_id: str
    profile_id: str
    profile_content_hash: str
    policy_epoch: int


def select_profile(profile: DomainSemanticProfile, *, tenant_id: str, policy_epoch: int, now: datetime) -> TenantProfileSelection:
    current = now.astimezone(timezone.utc)
    if profile.tenant_id != tenant_id or profile.status != "reviewed":
        raise ValueError("profile is not eligible for this tenant")
    if policy_epoch <= 0 or not (profile.issued_at <= profile.effective_at <= current < profile.expires_at):
        raise ValueError("profile selection is not current")
    return TenantProfileSelection(tenant_id=tenant_id, profile_id=profile.profile_id, profile_content_hash=profile.content_hash, policy_epoch=policy_epoch)
