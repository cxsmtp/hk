from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import unicodedata
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_verification import (
    DiscoveryVerificationPolicy,
    DiscoveryVerificationPolicyRequirement,
)
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.verification_service import SAFE_METHODS, TASK_TYPES


class VerificationPolicyConflict(RuntimeError):
    """A verification policy is invalid, ambiguous, or replayed differently."""


_REQUIREMENT_KEYS = {
    "requirement_id", "task_type", "accepted_methods", "evidence_class",
    "independence_group", "required", "minimum_result_count",
    "maximum_age_seconds", "applicability",
}
_APPLICABILITY_KEYS = {"ecosystem_classes", "environments"}


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cs"} for character in value)


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationPolicyConflict(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    """SQLite drops offsets; persisted ADV timestamps are defined as UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _identifiers(
    values: Sequence[str], *, field: str, maximum: int = 64
) -> tuple[str, ...]:
    if len(values) > maximum:
        raise VerificationPolicyConflict(f"{field} exceeds its item budget")
    normalized = tuple(values)
    if any(
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 128
        or _contains_control(value)
        for value in normalized
    ) or len(set(normalized)) != len(normalized):
        raise VerificationPolicyConflict(f"{field} contains invalid identifiers")
    return normalized


def _requirements(
    values: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    if not values or len(values) > 64:
        raise VerificationPolicyConflict("verification policy requires bounded requirements")
    output: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in values:
        if set(value) != _REQUIREMENT_KEYS:
            raise VerificationPolicyConflict("verification requirement fields are invalid")
        requirement_id = value["requirement_id"]
        task_type = value["task_type"]
        if (
            type(requirement_id) is not str or not requirement_id
            or requirement_id != requirement_id.strip()
            or len(requirement_id) > 128 or requirement_id in seen
            or _contains_control(requirement_id)
        ):
            raise VerificationPolicyConflict("verification requirement identifier is invalid")
        seen.add(requirement_id)
        if task_type not in TASK_TYPES:
            raise VerificationPolicyConflict("verification requirement task type is unsupported")
        method_values = value["accepted_methods"]
        if not isinstance(method_values, (list, tuple)):
            raise VerificationPolicyConflict("verification requirement methods are invalid")
        methods = _identifiers(method_values, field="accepted methods", maximum=16)
        if not methods or any(method not in SAFE_METHODS for method in methods):
            raise VerificationPolicyConflict("verification requirement method is unsafe")
        evidence_class = value["evidence_class"]
        independence_group = value["independence_group"]
        if type(evidence_class) is not str or not evidence_class or len(evidence_class) > 64 or _contains_control(evidence_class):
            raise VerificationPolicyConflict("verification requirement evidence class is invalid")
        if type(independence_group) is not str or not independence_group or len(independence_group) > 128 or _contains_control(independence_group):
            raise VerificationPolicyConflict("verification requirement independence group is invalid")
        if type(value["required"]) is not bool:
            raise VerificationPolicyConflict("verification requirement required flag is invalid")
        minimum = value["minimum_result_count"]
        maximum_age = value["maximum_age_seconds"]
        if type(minimum) is not int or not 1 <= minimum <= 32:
            raise VerificationPolicyConflict("verification requirement count is invalid")
        if type(maximum_age) is not int or not 60 <= maximum_age <= 31_536_000:
            raise VerificationPolicyConflict("verification requirement maximum age is invalid")
        raw_applicability = value["applicability"]
        if not isinstance(raw_applicability, Mapping) or not set(raw_applicability) <= _APPLICABILITY_KEYS:
            raise VerificationPolicyConflict("verification requirement applicability is invalid")
        applicability: dict[str, list[str]] = {}
        for key in sorted(raw_applicability):
            items = raw_applicability[key]
            if not isinstance(items, (list, tuple)):
                raise VerificationPolicyConflict("verification requirement applicability is invalid")
            applicability[key] = list(_identifiers(items, field=f"applicability {key}"))
        output.append(
            {
                "requirement_id": requirement_id,
                "task_type": task_type,
                "accepted_methods": list(methods),
                "evidence_class": evidence_class,
                "independence_group": independence_group,
                "required": value["required"],
                "minimum_result_count": minimum,
                "maximum_age_seconds": maximum_age,
                "applicability": applicability,
            }
        )
    return tuple(sorted(output, key=lambda item: str(item["requirement_id"])))


def _digest(material: Mapping[str, object], domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(dict(material))).hexdigest()


def create_verification_policy(
    db: Session,
    *,
    tenant_id: str,
    policy_id: str,
    version: int,
    ecosystem_classes: Sequence[str],
    environments: Sequence[str],
    minimum_evidence_quality: float,
    minimum_confidence: float,
    minimum_source_diversity: int,
    assertion_ttl_seconds: int,
    rescan_interval_seconds: int,
    effective_from: datetime,
    effective_until: datetime | None,
    requirements: Sequence[Mapping[str, object]],
    actor_id: str,
    idempotency_key: str,
    methodology_version: str = "1.0.0",
) -> DiscoveryVerificationPolicy:
    if not tenant_id or not policy_id or len(policy_id) > 128:
        raise VerificationPolicyConflict("verification policy identity is invalid")
    if type(version) is not int or version < 1:
        raise VerificationPolicyConflict("verification policy version is invalid")
    classes = _identifiers(ecosystem_classes, field="ecosystem classes")
    targets = _identifiers(environments, field="environments")
    if not classes or not targets:
        raise VerificationPolicyConflict("verification policy scope cannot be implicit")
    for name, value in (
        ("minimum evidence quality", minimum_evidence_quality),
        ("minimum confidence", minimum_confidence),
    ):
        if type(value) not in {int, float} or isinstance(value, bool) or not 0 <= value <= 1:
            raise VerificationPolicyConflict(f"{name} is invalid")
    if type(minimum_source_diversity) is not int or not 1 <= minimum_source_diversity <= 64:
        raise VerificationPolicyConflict("minimum source diversity is invalid")
    if any(
        type(value) is not int or not 60 <= value <= 31_536_000
        for value in (assertion_ttl_seconds, rescan_interval_seconds)
    ):
        raise VerificationPolicyConflict("verification policy time bounds are invalid")
    start = _utc(effective_from, field="effective_from")
    end = _utc(effective_until, field="effective_until") if effective_until else None
    if end is not None and end <= start:
        raise VerificationPolicyConflict("verification policy effective interval is invalid")
    if not actor_id or len(actor_id) > 128 or not idempotency_key or len(idempotency_key) > 128:
        raise VerificationPolicyConflict("verification policy audit identity is invalid")
    normalized_requirements = _requirements(requirements)
    material: dict[str, object] = {
        "tenant_id": tenant_id, "policy_id": policy_id, "version": version,
        "ecosystem_classes": list(classes), "environments": list(targets),
        "minimum_evidence_quality": float(minimum_evidence_quality),
        "minimum_confidence": float(minimum_confidence),
        "minimum_source_diversity": minimum_source_diversity,
        "assertion_ttl_seconds": assertion_ttl_seconds,
        "rescan_interval_seconds": rescan_interval_seconds,
        "effective_from": start.isoformat(),
        "effective_until": end.isoformat() if end else None,
        "requirements": normalized_requirements,
        "actor_id": actor_id, "methodology_version": methodology_version,
    }
    input_digest = _digest(material, b"hawk:discovery:verification-policy:v1")
    existing = db.scalar(
        select(DiscoveryVerificationPolicy).where(
            DiscoveryVerificationPolicy.tenant_id == tenant_id,
            DiscoveryVerificationPolicy.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != input_digest:
            raise VerificationPolicyConflict("verification policy idempotency conflict")
        return existing
    predecessor = None
    if version > 1:
        predecessor = db.scalar(
            select(DiscoveryVerificationPolicy).where(
                DiscoveryVerificationPolicy.tenant_id == tenant_id,
                DiscoveryVerificationPolicy.policy_id == policy_id,
                DiscoveryVerificationPolicy.version == version - 1,
            )
        )
        if predecessor is None:
            raise VerificationPolicyConflict("verification policy predecessor is missing")
    row = DiscoveryVerificationPolicy(
        policy_record_id=str(uuid4()), tenant_id=tenant_id, policy_id=policy_id,
        version=version,
        predecessor_policy_record_id=predecessor.policy_record_id if predecessor else None,
        ecosystem_classes_json=list(classes), environments_json=list(targets),
        minimum_evidence_quality=float(minimum_evidence_quality),
        minimum_confidence=float(minimum_confidence),
        minimum_source_diversity=minimum_source_diversity,
        assertion_ttl_seconds=assertion_ttl_seconds,
        rescan_interval_seconds=rescan_interval_seconds,
        effective_from=start, effective_until=end,
        methodology_version=methodology_version, actor_id=actor_id,
        idempotency_key=idempotency_key, input_digest=input_digest,
    )
    for item in normalized_requirements:
        requirement_id = str(item["requirement_id"])
        row.requirements.append(
            DiscoveryVerificationPolicyRequirement(
                requirement_record_id=str(uuid4()), tenant_id=tenant_id,
                requirement_id=requirement_id, task_type=str(item["task_type"]),
                accepted_methods_json=list(item["accepted_methods"]),
                evidence_class=str(item["evidence_class"]),
                independence_group=str(item["independence_group"]),
                required=bool(item["required"]),
                minimum_result_count=int(item["minimum_result_count"]),
                maximum_age_seconds=int(item["maximum_age_seconds"]),
                applicability_json=dict(item["applicability"]),
                idempotency_key=f"{idempotency_key}:requirement:{requirement_id}",
                input_digest=_digest(
                    {"policy_input_digest": input_digest, **item},
                    b"hawk:discovery:verification-requirement:v1",
                ),
            )
        )
    db.add(row)
    db.flush()
    return row


def _applies(
    requirement: DiscoveryVerificationPolicyRequirement,
    ecosystem_class: str,
    environment: str,
) -> bool:
    applicability = requirement.applicability_json or {}
    classes = applicability.get("ecosystem_classes", [])
    environments = applicability.get("environments", [])
    return (not classes or ecosystem_class in classes) and (
        not environments or environment in environments
    )


@dataclass(frozen=True)
class VerificationPolicySelection:
    policy: DiscoveryVerificationPolicy
    requirements: tuple[DiscoveryVerificationPolicyRequirement, ...]
    required_requirement_ids: tuple[str, ...]
    optional_requirement_ids: tuple[str, ...]
    substitutions: tuple[str, ...] = ()


class VerificationPolicyResolver:
    def resolve(
        self,
        db: Session,
        *,
        tenant_id: str,
        ecosystem_class: str,
        environment: str,
        at: datetime,
    ) -> VerificationPolicySelection:
        evaluated_at = _utc(at, field="policy resolution time")
        policies = tuple(
            db.scalars(
                select(DiscoveryVerificationPolicy).where(
                    DiscoveryVerificationPolicy.tenant_id == tenant_id,
                    DiscoveryVerificationPolicy.effective_from <= evaluated_at,
                )
            ).all()
        )
        candidates: list[tuple[int, DiscoveryVerificationPolicy]] = []
        for policy in policies:
            if policy.effective_until is not None and _stored_utc(
                policy.effective_until
            ) <= evaluated_at:
                continue
            classes = tuple(policy.ecosystem_classes_json or ())
            targets = tuple(policy.environments_json or ())
            if ecosystem_class not in classes or environment not in targets:
                continue
            score = int(len(classes) == 1) + int(len(targets) == 1)
            candidates.append((score, policy))
        if not candidates:
            raise VerificationPolicyConflict("no applicable verification policy")
        score = max(item[0] for item in candidates)
        selected_rows = [policy for value, policy in candidates if value == score]
        if len(selected_rows) != 1:
            raise VerificationPolicyConflict("verification policy selection is ambiguous")
        selected = selected_rows[0]
        applicable = tuple(
            item for item in selected.requirements
            if _applies(item, ecosystem_class, environment)
        )
        if not any(item.required for item in applicable):
            raise VerificationPolicyConflict("applicable policy has no required requirements")
        return VerificationPolicySelection(
            policy=selected,
            requirements=applicable,
            required_requirement_ids=tuple(
                item.requirement_id for item in applicable if item.required
            ),
            optional_requirement_ids=tuple(
                item.requirement_id for item in applicable if not item.required
            ),
        )


__all__ = [
    "VerificationPolicyConflict", "VerificationPolicyResolver",
    "VerificationPolicySelection", "create_verification_policy",
]
