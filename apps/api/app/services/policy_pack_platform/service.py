"""Compile tenant-safe policy packs into the existing deterministic policy path.

This service deliberately owns configuration, lineage, rollout gates, group
resolution, and explanation only. It does not decide live AI actions: emitted
rules are normalized ``PolicyVersion`` scoped rules and are evaluated by
``policy_scope_service`` at the existing enforcement seam.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Iterable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction, UserRegistry
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import (
    PACK_DEFINITION_STATES,
    PACK_INSTANCE_STATES,
    PACKAGE_TIERS,
    PolicyPackAssignment,
    PolicyPackDefinition,
    PolicyPackException,
    PolicyPackGroupMembership,
    PolicyPackInstance,
    PolicyPackPlatformEntitlement,
    PolicyPackSimulation,
    PolicyPackTemplate,
    PolicyPackUpdate,
    PolicyPackUserGroup,
)
from app.db.models.tenant import Tenant
from app.db.models.user import UserTenantRole
from app.services.audit_service import write_audit_log
from app.services.maturity_curve.policy_conditions import ALLOWED_FIELDS, normalize_condition_tree
from app.services.policy_scope_service import (
    CANONICAL_DECISIONS,
    normalize_scoped_rule_list,
    resolve_scoped_policy_rules,
    validate_scoped_rule_list,
)


class PolicyPackPlatformError(ValueError):
    """Expected service boundary error without a sensitive detail payload."""


@dataclass(frozen=True)
class PolicyPackApplyResult:
    instance: PolicyPackInstance
    runtime_pack: PolicyPack
    policy_version: PolicyVersion
    capability_report: dict[str, Any]


PACKAGE_RANK = {tier: index for index, tier in enumerate(PACKAGE_TIERS)}
ACTIVE_INSTANCE_STATES = {"MONITORING", "WARNING", "APPROVAL_ENFORCED", "ENFORCED"}
REFERENCE_MAPPING_STATUSES = {
    "CURRENT_REFERENCE",
    "PROVISIONAL_REFERENCE",
    "CUSTOMER_SPECIFIC",
    "NOT_APPLICABLE",
    "REVIEW_REQUIRED",
}
PARAMETER_MARKER_PREFIX = "$parameter:"
SURFACE_NAMES = {
    "browser",
    "endpoint",
    "runtime",
    "saas_api",
    "provider_native_hook",
    "mcp_gateway",
    "ai_api_gateway",
    "target_service_integration",
}
ASSIGNMENT_FIELD_MAP = {
    "legal_entity": "legal_entity",
    "business_unit": "business_unit",
    "department": "actor_department",
    "directory_group": "actor_group",
    "dynamic_group": "actor_group",
    "group": "actor_group",
    "user": "actor_user_id",
    "role": "actor_role",
    "persona": "actor_role",
    "application": "application",
    "account_class": "account_class",
    "provider": "provider",
    "model": "model",
    "agent": "agent_id",
    "tool": "tool_name",
    "mcp": "mcp_server",
    "deployment_surface": "source_surface",
    "environment": "environment",
    "action_class": "action_class",
    "resource": "resource_ref",
}
ALLOWED_ASSIGNMENT_KEYS = set(ASSIGNMENT_FIELD_MAP) | {
    "organization",
    "non_overridable",
    "explicit_revocation",
    "inherited_path",
}
GROUP_ATTRIBUTE_FIELDS = {"department", "role", "user_id", "application", "privileged"}
GROUP_BEHAVIOUR_EVENTS = {
    "personal_ai_account",
    "coding_agent",
    "unknown_mcp_tool",
    "restricted_external_destination",
    "runtime_agent_owner",
    "privileged_ai_administrator",
}
OVERRIDE_FIELDS = {"decision", "condition_tree", "applicable_surfaces", "obligations", "criticality"}


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)


def _text(value: Any, *, maximum: int = 255) -> str:
    result = str(value or "").strip()
    if len(result) > maximum:
        raise PolicyPackPlatformError("policy_pack_value_too_long")
    return result


def _token(value: Any, *, maximum: int = 128) -> str:
    result = _text(value, maximum=maximum).lower()
    if not result:
        raise PolicyPackPlatformError("policy_pack_value_required")
    return result


def _bounded_tokens(value: Any, *, maximum: int = 64, item_maximum: int = 255) -> list[str]:
    raw = value if isinstance(value, list) else ([] if value is None else [value])
    if len(raw) > maximum:
        raise PolicyPackPlatformError("policy_pack_list_too_large")
    return sorted({_token(item, maximum=item_maximum) for item in raw if _text(item, maximum=item_maximum)})


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return sha256(encoded).hexdigest()


def _normalize_reference_mappings(value: Any) -> dict[str, Any]:
    """Accept legacy mappings and validate the structured mapping form.

    Mappings are informative configuration.  Structured references give the
    UI a stable status without turning a policy pack into a compliance claim.
    Existing vendor/customer mappings such as ``{"NIST": ["AI.RM-2"]}``
    remain readable for backwards compatibility.
    """

    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyPackPlatformError("policy_pack_reference_mappings_invalid")
    if "references" not in value:
        return deepcopy(value)
    references = value.get("references")
    if not isinstance(references, list) or len(references) > 64:
        raise PolicyPackPlatformError("policy_pack_reference_mappings_invalid")
    normalized: list[dict[str, str]] = []
    for item in references:
        if not isinstance(item, dict) or set(item) - {"id", "title", "status", "url"}:
            raise PolicyPackPlatformError("policy_pack_reference_mapping_invalid")
        identifier = _token(item.get("id"), maximum=128)
        title = _text(item.get("title"), maximum=512)
        status = _text(item.get("status"), maximum=64).upper()
        if not title:
            raise PolicyPackPlatformError("policy_pack_reference_mapping_title_required")
        if status not in REFERENCE_MAPPING_STATUSES:
            raise PolicyPackPlatformError("policy_pack_reference_mapping_status_invalid")
        normalized_item = {"id": identifier, "title": title, "status": status}
        if item.get("url") is not None:
            normalized_item["url"] = _text(item.get("url"), maximum=2_000)
        normalized.append(normalized_item)
    if len({item["id"] for item in normalized}) != len(normalized):
        raise PolicyPackPlatformError("policy_pack_reference_mapping_id_duplicate")
    result: dict[str, Any] = {"references": normalized}
    if value.get("disclaimer") is not None:
        result["disclaimer"] = _text(value.get("disclaimer"), maximum=2_000)
    return result


def _validate_parameter_value(*, key: str, value: Any, schema: dict[str, Any]) -> Any:
    value_type = str(schema.get("type") or "")
    if value_type == "array":
        if not isinstance(value, list) or len(value) > 64:
            raise PolicyPackPlatformError("policy_pack_parameter_type_invalid")
        normalized = [_text(item, maximum=255) for item in value]
        if any(not item for item in normalized) or (schema.get("minItems", 0) and len(normalized) < int(schema["minItems"])):
            raise PolicyPackPlatformError("policy_pack_parameter_value_invalid")
        return normalized
    if value_type == "string":
        normalized = _text(value, maximum=255)
        if not normalized:
            raise PolicyPackPlatformError("policy_pack_parameter_value_invalid")
        return normalized
    if value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyPackPlatformError("policy_pack_parameter_type_invalid")
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if (minimum is not None and value < int(minimum)) or (maximum is not None and value > int(maximum)):
            raise PolicyPackPlatformError("policy_pack_parameter_value_invalid")
        return value
    raise PolicyPackPlatformError("policy_pack_parameter_schema_invalid")


def _effective_customer_parameters(
    definitions: Iterable[PolicyPackDefinition],
    customer_parameters: dict[str, Any],
) -> dict[str, Any]:
    """Merge typed defaults with customer values without evaluating expressions."""

    if not isinstance(customer_parameters, dict):
        raise PolicyPackPlatformError("policy_pack_customization_invalid")
    defaults: dict[str, Any] = {}
    properties: dict[str, dict[str, Any]] = {}
    strict = False
    for definition in definitions:
        if isinstance(definition.default_parameters, dict):
            defaults.update(deepcopy(definition.default_parameters))
        schema = definition.customization_schema if isinstance(definition.customization_schema, dict) else {}
        declared = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for raw_key, raw_schema in declared.items():
            if isinstance(raw_schema, dict):
                properties[str(raw_key)] = deepcopy(raw_schema)
        strict = strict or (bool(declared) and schema.get("additionalProperties") is False)
    if not properties:
        # Legacy definitions stored parameters for audit only.  Preserve their
        # established behavior because they have no catalog bindings to apply.
        return deepcopy(customer_parameters)
    normalized: dict[str, Any] = {}
    for raw_key, value in customer_parameters.items():
        key = _text(raw_key, maximum=128)
        schema = properties.get(key)
        if schema is None:
            if strict:
                raise PolicyPackPlatformError("policy_pack_parameter_not_allowed")
            normalized[key] = deepcopy(value)
            continue
        normalized[key] = _validate_parameter_value(key=key, value=value, schema=schema)
    effective = deepcopy(defaults)
    effective.update(normalized)
    return effective


def _parameter_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith(PARAMETER_MARKER_PREFIX):
        return None
    suffix = value.removeprefix(PARAMETER_MARKER_PREFIX)
    if not suffix or value != f"{PARAMETER_MARKER_PREFIX}{suffix}":
        raise PolicyPackPlatformError("policy_pack_parameter_marker_invalid")
    return _token(suffix, maximum=128)


def _bind_condition_parameters(tree: dict[str, Any], *, parameters: dict[str, Any]) -> dict[str, Any]:
    """Replace exact static parameter markers in typed condition values only."""

    def resolve(name: str) -> Any:
        if name not in parameters:
            raise PolicyPackPlatformError("policy_pack_parameter_missing")
        return deepcopy(parameters[name])

    def bind(node: dict[str, Any]) -> dict[str, Any]:
        if "field" in node:
            updated = deepcopy(node)
            marker = _parameter_name(updated.get("value"))
            if updated["operator"] == "in":
                expanded: list[Any] = []
                for item in list(updated["value"]):
                    item_marker = _parameter_name(item)
                    if item_marker is None:
                        expanded.append(item)
                        continue
                    replacement = resolve(item_marker)
                    if not isinstance(replacement, list):
                        raise PolicyPackPlatformError("policy_pack_parameter_type_invalid")
                    expanded.extend(replacement)
                if not expanded:
                    raise PolicyPackPlatformError("policy_pack_parameter_value_invalid")
                updated["value"] = expanded
            elif marker is not None:
                replacement = resolve(marker)
                if isinstance(replacement, (dict, list)):
                    raise PolicyPackPlatformError("policy_pack_parameter_type_invalid")
                updated["value"] = replacement
            return updated
        if "not" in node:
            return {"not": bind(node["not"])}
        if "all" in node:
            return {"all": [bind(child) for child in node["all"]]}
        if "any" in node:
            return {"any": [bind(child) for child in node["any"]]}
        raise PolicyPackPlatformError("policy_pack_condition_invalid")

    return bind(deepcopy(tree))


def _require_entitlement(db: Session, *, tenant_id: str, needed_tier: str) -> PolicyPackPlatformEntitlement:
    needed = _token(needed_tier, maximum=16)
    if needed not in PACKAGE_RANK:
        raise PolicyPackPlatformError("policy_pack_unknown_entitlement")
    entitlement = db.scalar(
        select(PolicyPackPlatformEntitlement).where(PolicyPackPlatformEntitlement.tenant_id == tenant_id)
    )
    if entitlement is None or not entitlement.enabled:
        raise PolicyPackPlatformError("policy_pack_entitlement_disabled")
    if PACKAGE_RANK.get(entitlement.package_tier, -1) < PACKAGE_RANK[needed]:
        raise PolicyPackPlatformError("policy_pack_entitlement_forbidden")
    return entitlement


def provision_policy_pack_entitlement(
    db: Session,
    *,
    tenant_id: str,
    package_tier: str,
) -> tuple[PolicyPackPlatformEntitlement, int]:
    """Provision a tenant's catalog access from a trusted operator boundary.

    This deliberately creates no policy instance, assignment, simulation, or
    enforcement change. It only enables the existing entitlement record and
    materializes the vendor-owned typed catalog.
    """

    normalized_tenant_id = _text(tenant_id, maximum=128)
    tier = _token(package_tier, maximum=16)
    if tier not in PACKAGE_RANK:
        raise PolicyPackPlatformError("policy_pack_unknown_entitlement")
    if not normalized_tenant_id or db.scalar(select(Tenant.id).where(Tenant.id == normalized_tenant_id)) is None:
        raise PolicyPackPlatformError("policy_pack_tenant_not_found")

    entitlement = db.scalar(
        select(PolicyPackPlatformEntitlement).where(
            PolicyPackPlatformEntitlement.tenant_id == normalized_tenant_id
        )
    )
    if entitlement is None:
        entitlement = PolicyPackPlatformEntitlement(
            tenant_id=normalized_tenant_id,
            package_tier=tier,
            enabled=True,
        )
        db.add(entitlement)
    else:
        # Provisioning may restore access but cannot silently lower an
        # already-provisioned tier.
        if PACKAGE_RANK.get(entitlement.package_tier, -1) <= PACKAGE_RANK[tier]:
            entitlement.package_tier = tier
        entitlement.enabled = True
    db.flush()

    ensure_builtin_policy_pack_catalog(db)
    catalog_count = len(
        list(
            db.scalars(
                select(PolicyPackDefinition).where(
                    PolicyPackDefinition.publisher_tenant_id.is_(None),
                    PolicyPackDefinition.state != "WITHDRAWN",
                )
            ).all()
        )
    )
    return entitlement, catalog_count


def _definition_for_tenant(db: Session, *, tenant_id: str, definition_id: str) -> PolicyPackDefinition:
    definition = db.scalar(
        select(PolicyPackDefinition).where(
            PolicyPackDefinition.id == definition_id,
            or_(
                PolicyPackDefinition.publisher_tenant_id.is_(None),
                PolicyPackDefinition.publisher_tenant_id == tenant_id,
            ),
        )
    )
    if definition is None:
        raise PolicyPackPlatformError("policy_pack_definition_not_found")
    if definition.state == "WITHDRAWN":
        raise PolicyPackPlatformError("policy_pack_definition_withdrawn")
    return definition


def _instance_for_tenant(db: Session, *, tenant_id: str, instance_id: str) -> PolicyPackInstance:
    instance = db.scalar(
        select(PolicyPackInstance).where(
            PolicyPackInstance.tenant_id == tenant_id,
            PolicyPackInstance.id == instance_id,
        )
    )
    if instance is None:
        raise PolicyPackPlatformError("policy_pack_instance_not_found")
    return instance


def _template_specs(definition: PolicyPackDefinition, templates: Iterable[PolicyPackTemplate]) -> list[dict[str, Any]]:
    return [
        {
            "template_id": row.template_id,
            "title": row.title,
            "reason": row.reason,
            "condition_tree": deepcopy(row.condition_tree or {}),
            "decision": row.decision,
            "obligations": deepcopy(row.obligations or {}),
            "applicable_surfaces": list(row.applicable_surfaces or []),
            "required_fields": list(row.required_fields or []),
            "required_control_capabilities": list(row.required_control_capabilities or []),
            "default_mode": row.default_mode,
            "recommended_mature_mode": row.recommended_mature_mode,
            "criticality": row.criticality,
            "override_behavior": row.override_behavior,
            "exception_rules": deepcopy(row.exception_rules or {}),
            "simulation_expectations": deepcopy(row.simulation_expectations or {}),
            "evidence_requirements": list(row.evidence_requirements or []),
            "human_explanation": row.human_explanation,
            "reference_mappings": deepcopy(row.reference_mappings or {}),
            "non_overridable": bool(row.non_overridable),
            "explicit_revocation": bool(row.explicit_revocation),
        }
        for row in templates
    ]


def _condition_fields(tree: dict[str, Any]) -> set[str]:
    if "field" in tree:
        return {str(tree["field"])}
    if "not" in tree and isinstance(tree["not"], dict):
        return _condition_fields(tree["not"])
    children = tree.get("all") if isinstance(tree.get("all"), list) else tree.get("any", [])
    return {field for child in children if isinstance(child, dict) for field in _condition_fields(child)}


def _normalize_template_spec(raw: dict[str, Any], *, require_full: bool = True) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyPackPlatformError("policy_pack_template_invalid")
    allowed = {
        "template_id", "title", "reason", "condition_tree", "decision", "obligations", "applicable_surfaces",
        "required_fields", "required_control_capabilities", "default_mode", "recommended_mature_mode", "criticality",
        "override_behavior", "exception_rules", "simulation_expectations", "evidence_requirements",
        "human_explanation", "reference_mappings", "non_overridable", "explicit_revocation",
    }
    unexpected = set(raw) - allowed
    if unexpected:
        raise PolicyPackPlatformError("policy_pack_template_field_not_allowed")
    template_id = _token(raw.get("template_id"))
    title = _text(raw.get("title"), maximum=255)
    if require_full and not title:
        raise PolicyPackPlatformError("policy_pack_template_title_required")
    decision = _token(raw.get("decision"), maximum=32)
    if decision not in CANONICAL_DECISIONS:
        raise PolicyPackPlatformError("policy_pack_template_decision_invalid")
    tree = normalize_condition_tree(raw.get("condition_tree"))
    required_fields = _bounded_tokens(raw.get("required_fields"), maximum=32, item_maximum=128)
    if any(field not in ALLOWED_FIELDS for field in required_fields):
        raise PolicyPackPlatformError("policy_pack_template_required_field_invalid")
    if not set(required_fields).issubset(_condition_fields(tree)):
        raise PolicyPackPlatformError("policy_pack_template_required_field_not_bound")
    surfaces = _bounded_tokens(raw.get("applicable_surfaces"), maximum=16, item_maximum=64)
    if any(surface not in SURFACE_NAMES for surface in surfaces):
        raise PolicyPackPlatformError("policy_pack_template_surface_invalid")
    non_overridable = bool(raw.get("non_overridable", False))
    explicit_revocation = bool(raw.get("explicit_revocation", False))
    if (non_overridable or explicit_revocation) and decision not in {"block", "require_approval", "hold_for_approval"}:
        raise PolicyPackPlatformError("policy_pack_non_overridable_must_protect")
    for json_key in ("obligations", "exception_rules", "simulation_expectations"):
        if raw.get(json_key) is not None and not isinstance(raw.get(json_key), dict):
            raise PolicyPackPlatformError("policy_pack_template_json_invalid")
    return {
        "template_id": template_id,
        "title": title or template_id,
        "reason": _text(raw.get("reason"), maximum=2_000),
        "condition_tree": tree,
        "decision": decision,
        "obligations": deepcopy(raw.get("obligations") or {}),
        "applicable_surfaces": surfaces,
        "required_fields": required_fields,
        "required_control_capabilities": _bounded_tokens(raw.get("required_control_capabilities"), maximum=32, item_maximum=64),
        "default_mode": _token(raw.get("default_mode") or "monitor", maximum=32),
        "recommended_mature_mode": _token(raw.get("recommended_mature_mode") or "enforce", maximum=32),
        "criticality": _token(raw.get("criticality") or "medium", maximum=32),
        "override_behavior": _token(raw.get("override_behavior") or "customer_override_allowed", maximum=64),
        "exception_rules": deepcopy(raw.get("exception_rules") or {}),
        "simulation_expectations": deepcopy(raw.get("simulation_expectations") or {}),
        "evidence_requirements": _bounded_tokens(raw.get("evidence_requirements"), maximum=32, item_maximum=128),
        "human_explanation": _text(raw.get("human_explanation"), maximum=2_000),
        "reference_mappings": _normalize_reference_mappings(raw.get("reference_mappings")),
        "non_overridable": non_overridable,
        "explicit_revocation": explicit_revocation,
    }


def create_policy_pack_definition(
    db: Session,
    *,
    publisher_tenant_id: str | None,
    stable_pack_id: str,
    version: str,
    name: str,
    description: str,
    vertical: str,
    department_persona: str,
    pack_family: str,
    maturity_status: str,
    package_entitlement: str,
    templates: list[dict[str, Any]],
    applicable_jurisdictions: list[str] | None = None,
    framework_mappings: dict[str, Any] | None = None,
    inherited_pack_refs: list[str] | None = None,
    required_signals: list[str] | None = None,
    required_control_capabilities: list[str] | None = None,
    supported_deployment_surfaces: list[str] | None = None,
    default_parameters: dict[str, Any] | None = None,
    customization_schema: dict[str, Any] | None = None,
    simulation_required: bool = True,
    default_rollout: str = "MONITORING",
    exception_guidance: str = "",
    known_blind_spots: list[str] | None = None,
    owner_publisher: str = "trinya",
    release_notes: str = "",
    state: str = "PUBLISHED",
) -> PolicyPackDefinition:
    """Create an immutable catalog version containing only typed configuration."""

    pack_id = _token(stable_pack_id)
    pack_version = _text(version, maximum=64)
    if not pack_version:
        raise PolicyPackPlatformError("policy_pack_version_required")
    tier = _token(package_entitlement, maximum=16)
    if tier not in PACKAGE_RANK:
        raise PolicyPackPlatformError("policy_pack_unknown_entitlement")
    normalized_state = _token(state, maximum=16).upper()
    if normalized_state not in PACK_DEFINITION_STATES:
        raise PolicyPackPlatformError("policy_pack_definition_state_invalid")
    publisher_ref = "trinya" if publisher_tenant_id is None else f"tenant:{publisher_tenant_id}"
    existing = db.scalar(
        select(PolicyPackDefinition).where(
            PolicyPackDefinition.publisher_ref == publisher_ref,
            PolicyPackDefinition.stable_pack_id == pack_id,
            PolicyPackDefinition.version == pack_version,
        )
    )
    if existing is not None:
        return existing
    normalized_templates = [_normalize_template_spec(item) for item in templates]
    normalized_inherited_refs = _bounded_tokens(inherited_pack_refs, maximum=32, item_maximum=128)
    if not normalized_templates and not normalized_inherited_refs:
        raise PolicyPackPlatformError("policy_pack_templates_required")
    ids = [item["template_id"] for item in normalized_templates]
    if len(ids) != len(set(ids)):
        raise PolicyPackPlatformError("policy_pack_template_id_duplicate")
    declared_surfaces = _bounded_tokens(supported_deployment_surfaces, maximum=16, item_maximum=64)
    if any(surface not in SURFACE_NAMES for surface in declared_surfaces):
        raise PolicyPackPlatformError("policy_pack_surface_invalid")
    for spec in normalized_templates:
        if declared_surfaces and not set(spec["applicable_surfaces"]).issubset(set(declared_surfaces)):
            raise PolicyPackPlatformError("policy_pack_template_surface_outside_definition")
    definition = PolicyPackDefinition(
        publisher_tenant_id=publisher_tenant_id,
        publisher_ref=publisher_ref,
        stable_pack_id=pack_id,
        version=pack_version,
        name=_text(name, maximum=255),
        description=_text(description, maximum=4_000),
        vertical=_token(vertical, maximum=128),
        department_persona=_token(department_persona, maximum=128),
        pack_family=_token(pack_family, maximum=128),
        maturity_status=_token(maturity_status, maximum=32),
        package_entitlement=tier,
        applicable_jurisdictions=_bounded_tokens(applicable_jurisdictions, maximum=64, item_maximum=64),
        framework_mappings=_normalize_reference_mappings(framework_mappings),
        inherited_pack_refs=normalized_inherited_refs,
        required_signals=_bounded_tokens(required_signals, maximum=64, item_maximum=128),
        required_control_capabilities=_bounded_tokens(required_control_capabilities, maximum=32, item_maximum=64),
        supported_deployment_surfaces=declared_surfaces,
        default_parameters=deepcopy(default_parameters or {}),
        customization_schema=deepcopy(customization_schema or {}),
        simulation_required=bool(simulation_required),
        default_rollout=_token(default_rollout, maximum=32).upper(),
        exception_guidance=_text(exception_guidance, maximum=4_000),
        known_blind_spots=[_text(item, maximum=1_000) for item in (known_blind_spots or [])[:32]],
        owner_publisher=_text(owner_publisher, maximum=255),
        release_notes=_text(release_notes, maximum=8_000),
        state=normalized_state,
    )
    db.add(definition)
    db.flush()
    for spec in normalized_templates:
        db.add(PolicyPackTemplate(definition_id=definition.id, **spec))
    db.flush()
    return definition


def ensure_builtin_policy_pack_catalog(db: Session) -> PolicyPackDefinition:
    """Idempotently seed the legacy baseline and the versioned vendor library."""

    legacy = db.scalar(
        select(PolicyPackDefinition).where(
            PolicyPackDefinition.publisher_tenant_id.is_(None),
            PolicyPackDefinition.stable_pack_id == "trinya:universal-ai-data-handling",
            PolicyPackDefinition.version == "1.0.0",
        )
    )
    if legacy is None:
        legacy = create_policy_pack_definition(
            db,
            publisher_tenant_id=None,
            stable_pack_id="trinya:universal-ai-data-handling",
            version="1.0.0",
            name="Universal AI Data Handling",
            description="A controlled starting point for sensitive data transfers to external AI destinations.",
            vertical="universal",
            department_persona="all",
            pack_family="data_handling",
            maturity_status="reviewed",
            package_entitlement="secure",
            applicable_jurisdictions=["global"],
            framework_mappings={"NIST": ["AI.RM-2"]},
            templates=[
                {
                    "template_id": "restricted-external-transfer",
                    "title": "Restricted external transfer",
                    "reason": "Restricted data needs a controlled destination.",
                    "condition_tree": {
                        "all": [
                            {"field": "data_classification", "operator": "equals", "value": "restricted"},
                            {"field": "destination_class", "operator": "in", "value": ["external", "public"]},
                        ]
                    },
                    "decision": "block",
                    "applicable_surfaces": ["browser", "runtime", "saas_api"],
                    "required_fields": ["data_classification", "destination_class"],
                    "required_control_capabilities": ["pre_execution_block"],
                    "default_mode": "monitor",
                    "recommended_mature_mode": "enforce",
                    "criticality": "high",
                    "override_behavior": "customer_override_allowed",
                    "exception_rules": {"max_hours": 8},
                    "simulation_expectations": {"minimum_sample_count": 1},
                    "evidence_requirements": ["decision_receipt"],
                    "human_explanation": "Block restricted data transfers to unmanaged external AI destinations.",
                    "reference_mappings": {"NIST": ["AI.RM-2"]},
                }
            ],
            required_signals=["data_classification", "destination_class"],
            required_control_capabilities=["pre_execution_block"],
            supported_deployment_surfaces=["browser", "runtime", "saas_api"],
            default_parameters={"approved_destination_classes": ["internal"]},
            customization_schema={"parameters": ["approved_destination_classes"]},
            simulation_required=True,
            default_rollout="MONITORING",
            exception_guidance="Use a reviewed, exact-scope, time-limited exception.",
            known_blind_spots=["URL and content semantics depend on the selected deployment surface."],
            owner_publisher="trinya",
            release_notes="Initial universal data-handling pack.",
        )

    from app.services.policy_pack_platform.vendor_catalog import vendor_policy_pack_specs

    for spec in vendor_policy_pack_specs():
        create_policy_pack_definition(db, **spec)
    return legacy


def list_policy_pack_definitions(
    db: Session,
    *,
    tenant_id: str,
    vertical: str | None = None,
    department_persona: str | None = None,
    surface: str | None = None,
    package_tier: str | None = None,
) -> list[PolicyPackDefinition]:
    _require_entitlement(db, tenant_id=tenant_id, needed_tier="secure")
    ensure_builtin_policy_pack_catalog(db)
    rows = list(
        db.scalars(
            select(PolicyPackDefinition).where(
                or_(PolicyPackDefinition.publisher_tenant_id.is_(None), PolicyPackDefinition.publisher_tenant_id == tenant_id),
                PolicyPackDefinition.state != "WITHDRAWN",
            )
        ).all()
    )
    if vertical:
        rows = [row for row in rows if row.vertical == _token(vertical, maximum=128)]
    if department_persona:
        rows = [row for row in rows if row.department_persona == _token(department_persona, maximum=128)]
    if surface:
        wanted = _token(surface, maximum=64)
        rows = [row for row in rows if wanted in (row.supported_deployment_surfaces or [])]
    if package_tier:
        wanted_tier = _token(package_tier, maximum=16)
        rows = [row for row in rows if row.package_entitlement == wanted_tier]
    return sorted(rows, key=lambda row: (row.stable_pack_id, row.version, row.publisher_ref))


def _framework_jurisdiction(reference_id: str, title: str) -> str:
    lowered = f"{reference_id} {title}".lower()
    if any(marker in lowered for marker in ("rbi", "meity", "dpdp", "sebi", "india")):
        return "India"
    if "imda" in lowered:
        return "Singapore"
    if "eu-ai-act" in lowered or "eu ai act" in lowered:
        return "European Union"
    if "uae" in lowered:
        return "UAE"
    return "Global"


def _framework_family(reference_id: str, title: str) -> str:
    lowered = f"{reference_id} {title}".lower()
    if any(marker in lowered for marker in ("mitre", "owasp")):
        return "Threat and adversarial AI"
    if any(marker in lowered for marker in ("rbi", "sebi", "bfsi", "capital markets")):
        return "Sector governance"
    if any(marker in lowered for marker in ("dpdp", "privacy", "personal data")):
        return "Privacy and data protection"
    if any(marker in lowered for marker in ("imda", "agentic")):
        return "Agentic AI governance"
    if any(marker in lowered for marker in ("eu-ai-act", "eu ai act", "nist", "iso")):
        return "AI governance and risk management"
    return "Governance reference"


def _framework_recommendations(reference_id: str, title: str) -> list[str]:
    family = _framework_family(reference_id, title)
    base = [
        "Preview mapped policy packs before rollout.",
        "Run historical simulation before Warn, Approval, or Enforce.",
    ]
    if family == "Threat and adversarial AI":
        return [
            "Prioritize prompt-injection, tool-abuse, delegation, MCP, and data-exfiltration controls.",
            *base,
        ]
    if family == "Sector governance":
        return [
            "Start with Monitor for sector teams, then require human review for consequential actions.",
            *base,
        ]
    if family == "Privacy and data protection":
        return [
            "Map personal-data classes, purposes, destinations, retention, and exception expiry.",
            *base,
        ]
    if family == "Agentic AI governance":
        return [
            "Bind agent authority, tool identity, side effects, persistence, and rollback evidence.",
            *base,
        ]
    return base


def _framework_links(reference_id: str) -> dict[str, Any]:
    encoded = reference_id.replace(":", "%3A")
    return {
        "control_coverage": {
            "state": "framework_mapped",
            "href": f"/deployment/surface-coverage?framework={encoded}",
            "note": "Framework-driven control coverage uses mapped controls and current surface capability evidence.",
        },
        "simulation_links": [
            {
                "label": "Run framework-driven simulation",
                "href": f"/simulations?framework={encoded}",
            }
        ],
        "evidence_href": f"/evidence?framework={encoded}",
    }


def framework_atlas(db: Session, *, tenant_id: str) -> dict[str, Any]:
    """Return framework-to-pack mappings for governance-first navigation.

    The atlas is a derived view over typed policy-pack definitions.  It gives
    administrators a framework entry point into the existing preview/apply
    workflow without creating a second policy model or implying legal
    compliance.
    """

    definitions = list_policy_pack_definitions(db, tenant_id=tenant_id)
    definition_ids = [definition.id for definition in definitions]
    templates_by_definition: dict[str, list[PolicyPackTemplate]] = {definition_id: [] for definition_id in definition_ids}
    if definition_ids:
        for template in db.scalars(select(PolicyPackTemplate).where(PolicyPackTemplate.definition_id.in_(definition_ids))).all():
            templates_by_definition.setdefault(template.definition_id, []).append(template)

    grouped: dict[str, dict[str, Any]] = {}
    for definition in definitions:
        mappings = definition.framework_mappings or {}
        references = mappings.get("references") if isinstance(mappings, dict) else None
        if not isinstance(references, list):
            continue
        for reference in references:
            if not isinstance(reference, dict):
                continue
            reference_id = _text(reference.get("id"), maximum=128)
            if not reference_id:
                continue
            item = grouped.setdefault(
                reference_id,
                {
                    "framework_id": reference_id,
                    "title": _text(reference.get("title"), maximum=512),
                    "status": _text(reference.get("status"), maximum=64).upper() or "UNKNOWN",
                    "jurisdiction": _framework_jurisdiction(reference_id, _text(reference.get("title"), maximum=512)),
                    "framework_family": _framework_family(reference_id, _text(reference.get("title"), maximum=512)),
                    "policy_pack_stable_ids": [],
                    "policy_pack_definition_ids": [],
                    "policy_pack_names": [],
                    "verticals": [],
                    "departments": [],
                    "surfaces": [],
                    "pack_families": [],
                    "mapped_control_families": [],
                    "policy_recommendations": _framework_recommendations(reference_id, _text(reference.get("title"), maximum=512)),
                    "evidence_requirements": ["Decision receipts and execution evidence"],
                    "recommended_action": "Preview pack, simulate, then apply in Draft or Monitor.",
                    "claim_boundary": "Informative mapping only; not a compliance certification.",
                    "compliance_note": "These are mapped controls and evidence requirements; they do not mean the tenant is certified compliant.",
                    **_framework_links(reference_id),
                },
            )
            if not item["title"]:
                item["title"] = _text(reference.get("title"), maximum=512)
            if not item["status"] or item["status"] == "UNKNOWN":
                item["status"] = _text(reference.get("status"), maximum=64).upper() or "UNKNOWN"
            for key, value in (
                ("policy_pack_stable_ids", definition.stable_pack_id),
                ("policy_pack_definition_ids", definition.id),
                ("policy_pack_names", definition.name),
                ("verticals", definition.vertical),
                ("departments", definition.department_persona),
                ("pack_families", definition.pack_family),
            ):
                if value and value not in item[key]:
                    item[key].append(value)
            for surface in definition.supported_deployment_surfaces or []:
                if surface and surface not in item["surfaces"]:
                    item["surfaces"].append(surface)
            for template in templates_by_definition.get(definition.id, []):
                control_label = _text(template.title, maximum=255) or _text(template.template_id, maximum=128)
                if control_label and control_label not in item["mapped_control_families"]:
                    item["mapped_control_families"].append(control_label)
                for evidence in template.evidence_requirements or []:
                    evidence_text = _text(evidence, maximum=255)
                    if evidence_text and evidence_text not in item["evidence_requirements"]:
                        item["evidence_requirements"].append(evidence_text)

    items = []
    for item in grouped.values():
        for key in (
            "policy_pack_stable_ids",
            "policy_pack_definition_ids",
            "policy_pack_names",
            "verticals",
            "departments",
            "surfaces",
            "pack_families",
            "mapped_control_families",
            "evidence_requirements",
        ):
            item[key] = sorted(item[key])
        items.append(item)
    items.sort(key=lambda item: (item["framework_id"], item["title"]))
    return {
        "items": items,
        "count": len(items),
        "disclaimer": "Framework mappings are informative references that route administrators to policy-pack preview, simulation, and rollout. They do not certify compliance.",
    }


def _normalize_assignment_targets(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyPackPlatformError("policy_pack_assignment_invalid")
    unknown = set(raw) - ALLOWED_ASSIGNMENT_KEYS
    if unknown:
        raise PolicyPackPlatformError("policy_pack_assignment_dimension_invalid")
    normalized: dict[str, Any] = {}
    for key in ASSIGNMENT_FIELD_MAP:
        if key in raw and raw[key] is not None:
            values = _bounded_tokens(raw[key], maximum=64, item_maximum=255)
            if values:
                normalized[key] = values
    organization = raw.get("organization")
    if organization is not None:
        normalized["organization"] = _bounded_tokens(organization, maximum=4, item_maximum=128) or ["all"]
    normalized["non_overridable"] = bool(raw.get("non_overridable", False))
    normalized["explicit_revocation"] = bool(raw.get("explicit_revocation", False))
    inherited = raw.get("inherited_path")
    if inherited is not None:
        normalized["inherited_path"] = [_text(item, maximum=128) for item in inherited if _text(item, maximum=128)][:16]
    if not any(key in normalized for key in ASSIGNMENT_FIELD_MAP) and "organization" not in normalized:
        normalized["organization"] = ["all"]
    return normalized


def _assignment_precedence(targets: dict[str, Any]) -> tuple[int, list[str]]:
    if targets.get("non_overridable"):
        return 10_000, ["non_overridable_safety"]
    if targets.get("explicit_revocation"):
        return 9_000, ["explicit_revocation"]
    layers = [(1_000, "organization_baseline", {"organization"}), (2_000, "jurisdiction_vertical", {"legal_entity"}), (3_000, "business_department", {"business_unit", "department"}), (4_000, "group_role", {"directory_group", "dynamic_group", "group", "role", "persona"}), (5_000, "specific_overlay", {"user", "application", "account_class", "provider", "model", "agent", "tool", "mcp", "deployment_surface", "environment", "action_class", "resource"})]
    applicable = [(priority, label) for priority, label, keys in layers if keys.intersection(targets)]
    if not applicable:
        return 1_000, ["organization_baseline"]
    priority, label = max(applicable)
    path = list(targets.get("inherited_path") or []) + [label]
    return priority, path[:16]


def _assignment_condition_tree(*, tenant_id: str, targets: dict[str, Any]) -> dict[str, Any]:
    parts: list[dict[str, Any]] = [{"field": "tenant_id", "operator": "equals", "value": tenant_id}]
    for assignment_field, policy_field in ASSIGNMENT_FIELD_MAP.items():
        values = targets.get(assignment_field)
        if not values:
            continue
        operator = "contains" if policy_field == "actor_group" else ("equals" if len(values) == 1 else "in")
        parts.append({"field": policy_field, "operator": operator, "value": values[0] if operator == "equals" else values})
    return parts[0] if len(parts) == 1 else {"all": parts}


def _combine_conditions(*trees: dict[str, Any]) -> dict[str, Any]:
    present = [tree for tree in trees if isinstance(tree, dict) and tree]
    if not present:
        raise PolicyPackPlatformError("policy_pack_condition_required")
    return present[0] if len(present) == 1 else {"all": present}


def _effective_decision(decision: str, *, state: str) -> str:
    if state in {"MONITORING", "WARNING"} and decision not in {"allow", "warn"}:
        return "warn"
    if state == "APPROVAL_ENFORCED" and decision in {"block", "redact"}:
        return "require_approval"
    return decision


def _definition_for_inheritance_ref(
    db: Session,
    *,
    tenant_id: str,
    stable_pack_id: str,
) -> PolicyPackDefinition | None:
    """Select a readable current parent without allowing tenant shadowing.

    Vendor IDs are pinned to the vendor publisher.  Customer-owned parent
    definitions may be used only for non-vendor IDs and remain tenant-scoped.
    The resolved record is subsequently pinned in the customer instance's
    lineage, so later catalog publication never mutates a running instance.
    """

    stable_id = _token(stable_pack_id, maximum=128)
    query = select(PolicyPackDefinition).where(
        PolicyPackDefinition.stable_pack_id == stable_id,
        PolicyPackDefinition.state != "WITHDRAWN",
    )
    if stable_id.startswith("trinya:"):
        query = query.where(PolicyPackDefinition.publisher_tenant_id.is_(None))
    else:
        query = query.where(
            or_(
                PolicyPackDefinition.publisher_tenant_id == tenant_id,
                PolicyPackDefinition.publisher_tenant_id.is_(None),
            )
        )
    rows = list(db.scalars(query.order_by(PolicyPackDefinition.created_at.desc(), PolicyPackDefinition.id.desc())).all())
    if not rows:
        return None
    if not stable_id.startswith("trinya:"):
        tenant_owned = [row for row in rows if row.publisher_tenant_id == tenant_id]
        if tenant_owned:
            return tenant_owned[0]
    return rows[0]


def _resolve_definition_lineage(
    db: Session,
    *,
    tenant_id: str,
    definition: PolicyPackDefinition,
) -> list[PolicyPackDefinition]:
    """Resolve parent packs base-to-child with deterministic cycle rejection."""

    ordered: list[PolicyPackDefinition] = []
    emitted: set[str] = set()
    visiting: set[str] = set()

    def visit(current: PolicyPackDefinition) -> None:
        if current.id in visiting:
            raise PolicyPackPlatformError("policy_pack_inheritance_cycle")
        if current.id in emitted:
            return
        visiting.add(current.id)
        for reference in list(current.inherited_pack_refs or []):
            parent = _definition_for_inheritance_ref(db, tenant_id=tenant_id, stable_pack_id=str(reference))
            if parent is None:
                raise PolicyPackPlatformError("policy_pack_inherited_definition_not_found")
            visit(parent)
        visiting.remove(current.id)
        emitted.add(current.id)
        ordered.append(current)

    visit(definition)
    return ordered


def _lineage_metadata(definitions: Iterable[PolicyPackDefinition], *, root_definition_id: str) -> list[dict[str, Any]]:
    return [
        {
            "definition_id": definition.id,
            "stable_pack_id": definition.stable_pack_id,
            "version": definition.version,
            "publisher_ref": definition.publisher_ref,
            "inherited": definition.id != root_definition_id,
        }
        for definition in definitions
    ]


def _definition_lineage_for_instance(db: Session, *, instance: PolicyPackInstance) -> list[PolicyPackDefinition]:
    """Use the apply-time lineage when available; resolve legacy instances once."""

    raw_lineage = (instance.lineage or {}).get("definition_lineage") if isinstance(instance.lineage, dict) else None
    if isinstance(raw_lineage, list) and raw_lineage:
        definitions: list[PolicyPackDefinition] = []
        for item in raw_lineage:
            definition_id = str(item.get("definition_id") or "") if isinstance(item, dict) else ""
            if not definition_id:
                raise PolicyPackPlatformError("policy_pack_instance_lineage_invalid")
            row = db.scalar(
                select(PolicyPackDefinition).where(
                    PolicyPackDefinition.id == definition_id,
                    or_(
                        PolicyPackDefinition.publisher_tenant_id.is_(None),
                        PolicyPackDefinition.publisher_tenant_id == instance.tenant_id,
                    ),
                )
            )
            if row is None:
                raise PolicyPackPlatformError("policy_pack_instance_lineage_not_found")
            definitions.append(row)
        return definitions
    root = _definition_for_tenant(db, tenant_id=instance.tenant_id, definition_id=instance.definition_id)
    return _resolve_definition_lineage(db, tenant_id=instance.tenant_id, definition=root)


def _definition_template_entries(
    db: Session,
    *,
    definitions: Iterable[PolicyPackDefinition],
    root_definition_id: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return template specs once with source-pack provenance.

    Template IDs are global inside a resolved pack graph.  A duplicate is
    rejected rather than silently allowing a child catalog version to replace
    a safety rule from a parent.
    """

    entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen: set[str] = set()
    for definition in definitions:
        persisted = list(
            db.scalars(
                select(PolicyPackTemplate)
                .where(PolicyPackTemplate.definition_id == definition.id)
                .order_by(PolicyPackTemplate.template_id.asc())
            ).all()
        )
        source = {
            "definition_id": definition.id,
            "stable_pack_id": definition.stable_pack_id,
            "version": definition.version,
            "inherited": definition.id != root_definition_id,
        }
        for spec in _template_specs(definition, persisted):
            template_id = spec["template_id"]
            if template_id in seen:
                raise PolicyPackPlatformError("policy_pack_inherited_template_id_duplicate")
            seen.add(template_id)
            entries.append((spec, source))
    return entries


def resolved_definition_templates(
    db: Session,
    *,
    tenant_id: str,
    definition: PolicyPackDefinition,
) -> dict[str, Any]:
    """Expose local versus inherited templates for catalog explainability."""

    definitions = _resolve_definition_lineage(db, tenant_id=tenant_id, definition=definition)
    entries = _definition_template_entries(db, definitions=definitions, root_definition_id=definition.id)
    local: list[dict[str, Any]] = []
    inherited: list[dict[str, Any]] = []
    for spec, source in entries:
        payload = {**deepcopy(spec), "source_pack": deepcopy(source)}
        (inherited if source["inherited"] else local).append(payload)
    return {
        "definition_lineage": _lineage_metadata(definitions, root_definition_id=definition.id),
        "local_templates": local,
        "inherited_templates": inherited,
    }


def _templates_for_instance(db: Session, *, instance: PolicyPackInstance) -> list[dict[str, Any]]:
    definitions = _definition_lineage_for_instance(db, instance=instance)
    if not definitions:
        raise PolicyPackPlatformError("policy_pack_instance_lineage_not_found")
    root_definition_id = instance.definition_id
    parameters = _effective_customer_parameters(definitions, instance.customer_parameters or {})
    entries = _definition_template_entries(db, definitions=definitions, root_definition_id=root_definition_id)
    for custom in instance.added_customer_templates or []:
        entries.append(
            (
                _normalize_template_spec(custom),
                {
                    "definition_id": None,
                    "stable_pack_id": "customer_template",
                    "version": "local",
                    "inherited": False,
                },
            )
        )
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    disabled = set(instance.disabled_template_ids or [])
    overrides = instance.local_overrides if isinstance(instance.local_overrides, dict) else {}
    for spec, source in entries:
        template_id = spec["template_id"]
        if template_id in seen:
            raise PolicyPackPlatformError("policy_pack_template_id_duplicate")
        seen.add(template_id)
        if template_id in disabled:
            continue
        override = overrides.get(template_id) if isinstance(overrides.get(template_id), dict) else {}
        unexpected = set(override) - OVERRIDE_FIELDS
        if unexpected:
            raise PolicyPackPlatformError("policy_pack_override_field_not_allowed")
        merged = deepcopy(spec)
        for key, value in override.items():
            merged[key] = deepcopy(value)
        merged["condition_tree"] = _bind_condition_parameters(merged["condition_tree"], parameters=parameters)
        merged = _normalize_template_spec(merged)
        merged["_hawk_source_policy_pack"] = deepcopy(source)
        output.append(merged)
    if not output:
        raise PolicyPackPlatformError("policy_pack_templates_required")
    return sorted(output, key=lambda item: item["template_id"])


def _active_assignments(db: Session, *, instance: PolicyPackInstance) -> list[PolicyPackAssignment]:
    rows = list(
        db.scalars(
            select(PolicyPackAssignment).where(
                PolicyPackAssignment.tenant_id == instance.tenant_id,
                PolicyPackAssignment.instance_id == instance.id,
                PolicyPackAssignment.active.is_(True),
            )
        ).all()
    )
    return sorted(rows, key=lambda item: (-item.precedence_layer, item.assignment_key))


def _compile_policy_version(
    db: Session,
    *,
    instance: PolicyPackInstance,
    runtime_pack: PolicyPack,
    state: str,
) -> PolicyVersion:
    templates = _templates_for_instance(db, instance=instance)
    assignments = _active_assignments(db, instance=instance)
    if not assignments:
        raise PolicyPackPlatformError("policy_pack_assignments_required")
    scoped_rules: list[dict[str, Any]] = []
    lineage: list[dict[str, Any]] = []
    for assignment in assignments:
        targets = assignment.targets if isinstance(assignment.targets, dict) else {}
        assignment_tree = _assignment_condition_tree(tenant_id=instance.tenant_id, targets=targets)
        for template in templates:
            source = template.get("_hawk_source_policy_pack") if isinstance(template.get("_hawk_source_policy_pack"), dict) else {}
            applicable_surfaces = list(template.get("applicable_surfaces") or [])
            surface_tree = (
                {"field": "source_surface", "operator": "in", "value": applicable_surfaces}
                if applicable_surfaces
                else {}
            )
            non_overridable = bool(template["non_overridable"] or targets.get("non_overridable"))
            explicit_revocation = bool(template["explicit_revocation"] or targets.get("explicit_revocation"))
            decision = _effective_decision(template["decision"], state=state)
            # Monitor and warning rollout intentionally downshift a protective
            # template to a would-block warning. The invariant applies to the
            # authored template, not that non-enforcing rollout projection.
            if (non_overridable or explicit_revocation) and template["decision"] not in {"block", "require_approval", "hold_for_approval"}:
                raise PolicyPackPlatformError("policy_pack_non_overridable_must_protect")
            rule_id = f"pack:{instance.id[:8]}:{assignment.id[:8]}:{template['template_id']}"
            metadata = {
                "policy_pack_platform": {
                    "instance_id": instance.id,
                    "source_pack": source.get("stable_pack_id") or instance.source_pack_id,
                    "source_version": source.get("version") or instance.source_pack_version,
                    "source_definition_id": source.get("definition_id"),
                    "inherited_template": bool(source.get("inherited", False)),
                    "template_id": template["template_id"],
                    "assignment_id": assignment.id,
                    "assignment_scope": targets,
                    "inherited_path": assignment.inherited_path,
                    "customer_override": template["template_id"] in (instance.local_overrides or {}),
                    "non_overridable": non_overridable,
                    "explicit_revocation": explicit_revocation,
                    "control_point": applicable_surfaces or ["unknown"],
                    "obligations": template.get("obligations") or {},
                    "evidence_requirements": template.get("evidence_requirements") or [],
                }
            }
            scoped_rules.append(
                {
                    "rule_id": rule_id,
                    "enabled": True,
                    "priority": assignment.precedence_layer,
                    "description": template["human_explanation"] or template["reason"],
                    "condition_tree": _combine_conditions(template["condition_tree"], assignment_tree, surface_tree),
                    "effect": {
                        "decision": decision,
                        "reason_code": f"policy_pack:{instance.source_pack_id}:{template['template_id']}",
                        "explanation": template["human_explanation"] or template["reason"],
                        "recommended_action": "policy_pack_guidance",
                        "priority": assignment.precedence_layer,
                    },
                    "metadata": metadata,
                }
            )
            lineage.append(metadata["policy_pack_platform"])
    normalized_rules = normalize_scoped_rule_list(scoped_rules)
    errors = validate_scoped_rule_list(normalized_rules)
    if errors:
        raise PolicyPackPlatformError("policy_pack_compilation_invalid")
    version = PolicyVersion(
        tenant_id=instance.tenant_id,
        pack_id=runtime_pack.id,
        version=f"pack-{instance.id[:8]}-{int(_now().timestamp())}",
        created_by=None,
        scope={
            "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "applies_to_ai_system_ids": None,
            "applies_to_actor_types": ["human", "agent", "system"],
            "scoped_rules": normalized_rules,
        },
        enforcement_defaults={"default_decision": "allow", "escalation": "notify"},
        guardian_contracts=[],
        contract_json={
            "profile": "policy_pack_platform",
            "policy_pack_platform": {
                "instance_id": instance.id,
                "source_pack": instance.source_pack_id,
                "source_version": instance.source_pack_version,
                "state": state,
                "definition_lineage": deepcopy((instance.lineage or {}).get("definition_lineage", [])),
                "template_lineage": lineage,
            },
        },
    )
    db.add(version)
    db.flush()
    return version


def _capability_rows(db: Session, *, tenant_id: str, surfaces: list[str]) -> dict[str, list[DeploymentSurface]]:
    rows = list(db.scalars(select(DeploymentSurface).where(DeploymentSurface.tenant_id == tenant_id)).all())
    grouped: dict[str, list[DeploymentSurface]] = {surface: [] for surface in surfaces}
    for row in rows:
        family = _token(row.deployment_family, maximum=64) if row.deployment_family else "unknown"
        if family in grouped:
            grouped[family].append(row)
    return grouped


def capability_report_for_policy_pack(
    db: Session,
    *,
    tenant_id: str,
    definition: PolicyPackDefinition,
    selected_surfaces: list[str] | None = None,
) -> dict[str, Any]:
    requested = _bounded_tokens(selected_surfaces or definition.supported_deployment_surfaces, maximum=16, item_maximum=64)
    if not requested:
        requested = list(definition.supported_deployment_surfaces or [])
    rows_by_surface = _capability_rows(db, tenant_id=tenant_id, surfaces=requested)
    surfaces: list[dict[str, Any]] = []
    supported_block: set[str] = set()
    blind_spots = list(definition.known_blind_spots or [])
    for surface in requested:
        rows = rows_by_surface.get(surface, [])
        healthy = [row for row in rows if row.health_status in {"healthy", "warning"} and row.status not in {"disabled", "offline", "retired", "uninstalled"}]
        inline = [row for row in healthy if row.control_capability == "inline"]
        warn = [row for row in healthy if row.control_capability in {"inline", "warn_only"}]
        evidence = [row for row in healthy if row.evidence_capability in {"complete", "partial"}]
        verified = [row for row in healthy if bool((row.capability_profile or {}).get("independent_verification"))]
        if inline:
            supported_block.add(surface)
        if not rows:
            blind_spots.append(f"{surface}: no connected deployment surface is registered")
        elif not inline:
            blind_spots.append(f"{surface}: pre-execution block is not verified on the selected surface")
        surfaces.append(
            {
                "surface": surface,
                "visibility": "available" if healthy else "unknown",
                "warning": "available" if warn else "not_available",
                "redaction": "available" if any(bool((row.capability_profile or {}).get("redaction")) for row in healthy) else "unknown",
                "approval": "available" if inline else "not_available",
                "pre_execution_block": "available" if inline else "not_available",
                "post_execution_evidence": "available" if any(row.evidence_capability == "complete" for row in evidence) else ("partial" if evidence else "not_available"),
                "independent_verification": "available" if verified else "unknown",
                "health": sorted({row.health_status for row in rows}) or ["unknown"],
                "known_blind_spots": [item for item in blind_spots if item.startswith(f"{surface}:")],
            }
        )
    return {
        "surfaces": surfaces,
        "verified_pre_execution_block_surfaces": sorted(supported_block),
        "known_blind_spots": sorted(set(blind_spots)),
    }


def apply_policy_pack(
    db: Session,
    *,
    tenant_id: str,
    definition_id: str,
    assignments: list[dict[str, Any]],
    customer_parameters: dict[str, Any],
    local_overrides: dict[str, Any],
    disabled_template_ids: list[str],
    added_customer_templates: list[dict[str, Any]],
    requested_state: str,
    requested_by_ref: str,
) -> PolicyPackApplyResult:
    definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=definition_id)
    _require_entitlement(db, tenant_id=tenant_id, needed_tier=definition.package_entitlement)
    state = _token(requested_state, maximum=32).upper()
    aliases = {"MONITOR": "MONITORING", "WARN": "WARNING", "APPROVAL": "APPROVAL_ENFORCED", "ENFORCE": "ENFORCED"}
    state = aliases.get(state, state)
    if state not in PACK_INSTANCE_STATES:
        raise PolicyPackPlatformError("policy_pack_instance_state_invalid")
    if state in {"ENFORCED", "APPROVAL_ENFORCED"}:
        raise PolicyPackPlatformError("policy_pack_enforcement_requires_approved_transition")
    if not isinstance(customer_parameters, dict) or not isinstance(local_overrides, dict):
        raise PolicyPackPlatformError("policy_pack_customization_invalid")
    normalized_assignments = [_normalize_assignment_targets(item) for item in assignments]
    if not normalized_assignments:
        raise PolicyPackPlatformError("policy_pack_assignments_required")
    custom_templates = [_normalize_template_spec(item) for item in added_customer_templates]
    disabled = _bounded_tokens(disabled_template_ids, maximum=128, item_maximum=128)
    definition_lineage = _resolve_definition_lineage(db, tenant_id=tenant_id, definition=definition)
    _effective_customer_parameters(definition_lineage, customer_parameters)
    source_entries = _definition_template_entries(
        db,
        definitions=definition_lineage,
        root_definition_id=definition.id,
    )
    source_template_ids = {spec["template_id"] for spec, _source in source_entries}
    custom_template_ids = {item["template_id"] for item in custom_templates}
    if source_template_ids.intersection(custom_template_ids) or len(custom_template_ids) != len(custom_templates):
        raise PolicyPackPlatformError("policy_pack_template_id_duplicate")
    allowed_template_ids = source_template_ids | custom_template_ids
    if not set(local_overrides).issubset(allowed_template_ids) or not set(disabled).issubset(allowed_template_ids):
        raise PolicyPackPlatformError("policy_pack_template_not_found")
    capability = capability_report_for_policy_pack(
        db, tenant_id=tenant_id, definition=definition, selected_surfaces=list(definition.supported_deployment_surfaces or [])
    )
    runtime_pack = PolicyPack(
        tenant_id=tenant_id,
        name=f"Managed Pack: {definition.name}",
        description=f"Compiled from {definition.stable_pack_id}@{definition.version}.",
        status="draft" if state not in ACTIVE_INSTANCE_STATES else "active",
    )
    db.add(runtime_pack)
    db.flush()
    instance = PolicyPackInstance(
        tenant_id=tenant_id,
        definition_id=definition.id,
        source_pack_id=definition.stable_pack_id,
        source_pack_version=definition.version,
        selected_vertical=definition.vertical,
        selected_department_persona=definition.department_persona,
        selected_applications=sorted({value for item in normalized_assignments for value in item.get("application", [])}),
        selected_surfaces=sorted({value for item in normalized_assignments for value in item.get("deployment_surface", [])} or set(definition.supported_deployment_surfaces or [])),
        customer_parameters=deepcopy(customer_parameters),
        local_overrides=deepcopy(local_overrides),
        disabled_template_ids=disabled,
        added_customer_templates=custom_templates,
        rollout={"state": state, "mode": state.lower()},
        runtime_policy_pack_id=runtime_pack.id,
        owner_ref=_text(requested_by_ref, maximum=255),
        state=state,
        lineage={
            "definition_id": definition.id,
            "source_pack": definition.stable_pack_id,
            "source_version": definition.version,
            "definition_lineage": _lineage_metadata(definition_lineage, root_definition_id=definition.id),
        },
    )
    db.add(instance)
    db.flush()
    for targets in normalized_assignments:
        precedence, path = _assignment_precedence(targets)
        assignment = PolicyPackAssignment(
            tenant_id=tenant_id,
            instance_id=instance.id,
            assignment_key=_json_digest(targets),
            targets=targets,
            precedence_layer=precedence,
            inherited_path=path,
            active=True,
        )
        db.add(assignment)
    db.flush()
    version = _compile_policy_version(db, instance=instance, runtime_pack=runtime_pack, state=state)
    instance.effective_policy_version_id = version.id
    db.flush()
    return PolicyPackApplyResult(instance=instance, runtime_pack=runtime_pack, policy_version=version, capability_report=capability)


def _event_contexts(db: Session, *, tenant_id: str, maximum: int = 500) -> list[dict[str, Any]]:
    rows = list(
        db.scalars(
            select(AIAction).where(AIAction.tenant_id == tenant_id).order_by(AIAction.timestamp.desc()).limit(maximum)
        ).all()
    )
    contexts: list[dict[str, Any]] = []
    for row in rows:
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        contexts.append(
            {
                "actor_user_id": row.user_id,
                "source_surface": metadata.get("source_surface") or metadata.get("surface") or "unknown",
                "application": row.ai_app,
                "provider": metadata.get("provider") or metadata.get("provider_name"),
                "model": metadata.get("model") or row.ai_model,
                "tool_name": metadata.get("tool_name") or metadata.get("tool"),
                "action_type": row.action_type,
                "data_classification": metadata.get("data_classification") or row.data_classification,
                "destination_class": metadata.get("destination_class"),
                "account_class": metadata.get("account_class"),
                "environment": metadata.get("environment"),
            }
        )
    return contexts


def simulate_policy_pack(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    historical_events: list[dict[str, Any]] | None = None,
) -> PolicyPackSimulation:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    _require_entitlement(db, tenant_id=tenant_id, needed_tier="secure")
    version = db.scalar(
        select(PolicyVersion).where(PolicyVersion.tenant_id == tenant_id, PolicyVersion.id == instance.effective_policy_version_id)
    )
    if version is None:
        raise PolicyPackPlatformError("policy_pack_effective_version_not_found")
    events = historical_events if historical_events is not None else _event_contexts(db, tenant_id=tenant_id)
    if len(events) > 1_000:
        raise PolicyPackPlatformError("policy_pack_simulation_too_large")
    scoped_rules = list((version.scope or {}).get("scoped_rules") or [])
    counts: Counter[str] = Counter()
    surface_counts: Counter[str] = Counter()
    for raw in events:
        context = dict(raw) if isinstance(raw, dict) else {}
        resolution = resolve_scoped_policy_rules(
            db,
            tenant_id=tenant_id,
            policy_version_id=version.id,
            context=context,
            rules=scoped_rules,
        )
        counts[resolution.decision or "unknown"] += 1
        surface = _token(context.get("source_surface") or "unknown", maximum=64)
        surface_counts[surface] += 1
    digest = _json_digest({"version": version.id, "events": events})
    existing = db.scalar(
        select(PolicyPackSimulation).where(
            PolicyPackSimulation.tenant_id == tenant_id,
            PolicyPackSimulation.instance_id == instance.id,
            PolicyPackSimulation.input_digest == digest,
        )
    )
    if existing is not None:
        return existing
    definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=instance.definition_id)
    templates = _templates_for_instance(db, instance=instance)
    required_samples = max(
        [int((item.get("simulation_expectations") or {}).get("minimum_sample_count", 0) or 0) for item in templates] or [0]
    )
    status = "PASSED" if len(events) >= required_samples else "PARTIAL"
    simulation = PolicyPackSimulation(
        tenant_id=tenant_id,
        instance_id=instance.id,
        policy_version_id=version.id,
        input_digest=digest,
        sample_count=len(events),
        outcome_counts=dict(sorted(counts.items())),
        scope_breakdown={"source_surface": dict(sorted(surface_counts.items()))},
        status=status,
        evidence_refs=[f"policy_version:{version.id}", f"definition:{definition.id}"],
    )
    db.add(simulation)
    db.flush()
    instance.last_simulation_id = simulation.id
    if instance.state == "DRAFT":
        instance.state = "REVIEW_REQUIRED" if definition.simulation_required else "DRAFT"
    db.flush()
    return simulation


def _latest_simulation(db: Session, *, tenant_id: str, instance: PolicyPackInstance) -> PolicyPackSimulation | None:
    if instance.last_simulation_id:
        row = db.scalar(
            select(PolicyPackSimulation).where(
                PolicyPackSimulation.tenant_id == tenant_id,
                PolicyPackSimulation.id == instance.last_simulation_id,
            )
        )
        if row is not None:
            return row
    return db.scalar(
        select(PolicyPackSimulation)
        .where(PolicyPackSimulation.tenant_id == tenant_id, PolicyPackSimulation.instance_id == instance.id)
        .order_by(PolicyPackSimulation.created_at.desc(), PolicyPackSimulation.id.desc())
    )


def _has_high_impact_templates(db: Session, *, instance: PolicyPackInstance) -> bool:
    return any(item["decision"] in {"block", "redact", "require_approval", "hold_for_approval"} for item in _templates_for_instance(db, instance=instance))


def transition_policy_pack_instance(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    target_state: str,
    actor_ref: str,
    approver_ref: str | None = None,
) -> PolicyPackInstance:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    target = _token(target_state, maximum=32).upper()
    aliases = {"MONITOR": "MONITORING", "WARN": "WARNING", "APPROVAL": "APPROVAL_ENFORCED", "ENFORCE": "ENFORCED"}
    target = aliases.get(target, target)
    if target not in PACK_INSTANCE_STATES:
        raise PolicyPackPlatformError("policy_pack_instance_state_invalid")
    if target == "ROLLED_BACK":
        return rollback_policy_pack_instance(db, tenant_id=tenant_id, instance_id=instance_id, actor_ref=actor_ref)
    allowed = {
        "DRAFT": {"SIMULATING", "MONITORING", "PAUSED"},
        "SIMULATING": {"REVIEW_REQUIRED", "MONITORING", "PAUSED"},
        "REVIEW_REQUIRED": {"MONITORING", "WARNING", "APPROVAL_ENFORCED", "ENFORCED", "PAUSED"},
        "MONITORING": {"WARNING", "APPROVAL_ENFORCED", "ENFORCED", "PAUSED"},
        "WARNING": {"APPROVAL_ENFORCED", "ENFORCED", "PAUSED"},
        "APPROVAL_ENFORCED": {"ENFORCED", "PAUSED"},
        "ENFORCED": {"PAUSED"},
        "PAUSED": {"MONITORING", "WARNING", "APPROVAL_ENFORCED", "ENFORCED"},
        "UPDATE_AVAILABLE": {"SIMULATING", "PAUSED"},
        "CONFLICTED": {"PAUSED"},
    }
    if target not in allowed.get(instance.state, set()):
        raise PolicyPackPlatformError("policy_pack_transition_not_allowed")
    definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=instance.definition_id)
    high_impact = _has_high_impact_templates(db, instance=instance)
    if target in {"APPROVAL_ENFORCED", "ENFORCED"} and high_impact:
        simulation = _latest_simulation(db, tenant_id=tenant_id, instance=instance)
        if simulation is None or simulation.status != "PASSED":
            raise PolicyPackPlatformError("policy_pack_enforcement_requires_simulation")
        if not approver_ref or _text(approver_ref) == _text(actor_ref):
            raise PolicyPackPlatformError(
                "policy_pack_enforcement_requires_separate_authorized_approver: separate authorized approver required"
            )
        approver_user_id = _text(approver_ref, maximum=255).removeprefix("user:")
        approver_role = db.scalar(
            select(UserTenantRole.role).where(
                UserTenantRole.tenant_id == tenant_id,
                UserTenantRole.user_id == approver_user_id,
            )
        )
        if approver_role not in {"owner", "admin"}:
            raise PolicyPackPlatformError("policy_pack_enforcement_requires_separate_authorized_approver: separate authorized approver required")
        capability = capability_report_for_policy_pack(
            db,
            tenant_id=tenant_id,
            definition=definition,
            selected_surfaces=instance.selected_surfaces or definition.supported_deployment_surfaces,
        )
        needed_surfaces = set(instance.selected_surfaces or definition.supported_deployment_surfaces or [])
        supported = set(capability["verified_pre_execution_block_surfaces"])
        if not needed_surfaces.issubset(supported):
            raise PolicyPackPlatformError("policy_pack_enforcement_capability_unavailable")
        instance.approver_ref = _text(approver_ref, maximum=255)
    runtime_pack = db.scalar(
        select(PolicyPack).where(PolicyPack.tenant_id == tenant_id, PolicyPack.id == instance.runtime_policy_pack_id)
    )
    if runtime_pack is None:
        raise PolicyPackPlatformError("policy_pack_runtime_pack_not_found")
    previous = instance.effective_policy_version_id
    version = _compile_policy_version(db, instance=instance, runtime_pack=runtime_pack, state=target)
    instance.previous_effective_policy_version_id = previous
    instance.effective_policy_version_id = version.id
    instance.state = target
    instance.rollout = {**(instance.rollout or {}), "state": target, "changed_by": _text(actor_ref, maximum=255)}
    runtime_pack.status = "active" if target in ACTIVE_INSTANCE_STATES else "draft"
    db.flush()
    return instance


def rollback_policy_pack_instance(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    actor_ref: str,
) -> PolicyPackInstance:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    if not instance.previous_effective_policy_version_id:
        raise PolicyPackPlatformError("policy_pack_rollback_source_not_found")
    source = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id == instance.previous_effective_policy_version_id,
        )
    )
    runtime_pack = db.scalar(
        select(PolicyPack).where(PolicyPack.tenant_id == tenant_id, PolicyPack.id == instance.runtime_policy_pack_id)
    )
    if source is None or runtime_pack is None:
        raise PolicyPackPlatformError("policy_pack_rollback_source_not_found")
    restored = PolicyVersion(
        tenant_id=tenant_id,
        pack_id=runtime_pack.id,
        version=f"rollback-{instance.id[:8]}-{int(_now().timestamp())}",
        created_by=None,
        scope=deepcopy(source.scope or {}),
        enforcement_defaults=deepcopy(source.enforcement_defaults or {}),
        guardian_contracts=deepcopy(source.guardian_contracts or []),
        contract_json={**deepcopy(source.contract_json or {}), "policy_pack_platform_rollback": {"instance_id": instance.id, "restored_from": source.id, "actor_ref": _text(actor_ref, maximum=255)}},
    )
    db.add(restored)
    db.flush()
    instance.effective_policy_version_id = restored.id
    instance.state = "ROLLED_BACK"
    instance.rollout = {**(instance.rollout or {}), "state": "ROLLED_BACK", "rollback_by": _text(actor_ref, maximum=255)}
    runtime_pack.status = "active"
    db.flush()
    return instance


def _normalize_group_rule(group_type: str, rule: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise PolicyPackPlatformError("policy_pack_group_rule_invalid")
    if group_type in {"static", "scim", "nested", "temporary_rollout"}:
        if rule:
            raise PolicyPackPlatformError("policy_pack_group_rule_not_supported")
        return {}
    if group_type in {"dynamic_attribute", "role_persona", "application_user", "privileged_user"}:
        if set(rule) != {"field", "operator", "value"}:
            raise PolicyPackPlatformError("policy_pack_group_rule_invalid")
        field = _token(rule.get("field"), maximum=64)
        if field not in GROUP_ATTRIBUTE_FIELDS:
            raise PolicyPackPlatformError("policy_pack_group_attribute_not_allowed")
        operator = _token(rule.get("operator"), maximum=16)
        if operator not in {"equals", "in"}:
            raise PolicyPackPlatformError("policy_pack_group_operator_not_allowed")
        value = _bounded_tokens(rule.get("value"), maximum=64, item_maximum=255) if operator == "in" else _token(rule.get("value"), maximum=255)
        return {"field": field, "operator": operator, "value": value}
    if group_type == "security_behavior":
        if set(rule) != {"event_type"}:
            raise PolicyPackPlatformError("policy_pack_group_rule_invalid")
        event_type = _token(rule.get("event_type"), maximum=64)
        if event_type not in GROUP_BEHAVIOUR_EVENTS:
            raise PolicyPackPlatformError("policy_pack_group_event_not_allowed")
        return {"event_type": event_type}
    raise PolicyPackPlatformError("policy_pack_group_type_invalid")


def create_policy_pack_group(
    db: Session,
    *,
    tenant_id: str,
    group_key: str,
    name: str,
    group_type: str,
    membership_rule: dict[str, Any],
    member_user_ids: list[str],
    nested_group_ids: list[str],
    actor_ref: str,
) -> PolicyPackUserGroup:
    _require_entitlement(db, tenant_id=tenant_id, needed_tier="secure")
    normalized_type = _token(group_type, maximum=32)
    rule = _normalize_group_rule(normalized_type, membership_rule)
    group = PolicyPackUserGroup(
        tenant_id=tenant_id,
        group_key=_token(group_key, maximum=128),
        name=_text(name, maximum=255),
        group_type=normalized_type,
        membership_rule=rule,
        nested_group_ids=_bounded_tokens(nested_group_ids, maximum=32, item_maximum=36),
        source_ref=_text(actor_ref, maximum=255),
        active=True,
    )
    db.add(group)
    db.flush()
    for user_id in _bounded_tokens(member_user_ids, maximum=10_000, item_maximum=36):
        exists = db.scalar(select(UserRegistry.user_id).where(UserRegistry.tenant_id == tenant_id, UserRegistry.user_id == user_id))
        if exists is None:
            role_exists = db.scalar(select(UserTenantRole.user_id).where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.user_id == user_id))
            if role_exists is None:
                raise PolicyPackPlatformError("policy_pack_group_user_not_found")
        db.add(PolicyPackGroupMembership(tenant_id=tenant_id, group_id=group.id, user_id=user_id, source=normalized_type, active=True))
    db.flush()
    return group


def update_policy_pack_group_memberships(
    db: Session,
    *,
    tenant_id: str,
    group_id: str,
    add_user_ids: list[str],
    remove_user_ids: list[str],
    actor_user_id: str,
) -> dict[str, list[str]]:
    """Idempotently manage only administrator-owned static memberships."""

    group = db.scalar(
        select(PolicyPackUserGroup).where(
            PolicyPackUserGroup.tenant_id == tenant_id,
            PolicyPackUserGroup.id == group_id,
            PolicyPackUserGroup.active.is_(True),
        )
    )
    if group is None:
        raise PolicyPackPlatformError("policy_pack_group_not_found")
    if group.group_type != "static":
        raise PolicyPackPlatformError("policy_pack_group_membership_source_managed")
    normalized_add = _bounded_tokens(add_user_ids, maximum=1_000, item_maximum=36)
    normalized_remove = _bounded_tokens(remove_user_ids, maximum=1_000, item_maximum=36)
    if set(normalized_add).intersection(normalized_remove):
        raise PolicyPackPlatformError("policy_pack_group_membership_conflict")
    requested_ids = sorted(set(normalized_add).union(normalized_remove))
    if requested_ids:
        tenant_users = {
            str(user_id)
            for user_id in db.scalars(
                select(UserTenantRole.user_id).where(
                    UserTenantRole.tenant_id == tenant_id,
                    UserTenantRole.user_id.in_(requested_ids),
                )
            ).all()
        }
        if tenant_users != set(requested_ids):
            raise PolicyPackPlatformError("policy_pack_group_user_not_found")
    existing = {
        row.user_id: row
        for row in db.scalars(
            select(PolicyPackGroupMembership).where(
                PolicyPackGroupMembership.tenant_id == tenant_id,
                PolicyPackGroupMembership.group_id == group.id,
                PolicyPackGroupMembership.user_id.in_(requested_ids),
            )
        ).all()
    } if requested_ids else {}
    added: list[str] = []
    removed: list[str] = []
    for user_id in normalized_add:
        membership = existing.get(user_id)
        if membership is None:
            db.add(
                PolicyPackGroupMembership(
                    tenant_id=tenant_id,
                    group_id=group.id,
                    user_id=user_id,
                    source="static",
                    active=True,
                )
            )
            added.append(user_id)
        elif membership.source == "static" and not membership.active:
            membership.active = True
            added.append(user_id)
    for user_id in normalized_remove:
        membership = existing.get(user_id)
        if membership is not None and membership.source == "static" and membership.active:
            membership.active = False
            removed.append(user_id)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="policy_pack.group_memberships.updated",
        resource_type="policy_pack_user_group",
        resource_id=group.id,
        payload={"added_user_ids": added, "removed_user_ids": removed},
    )
    return {"added_user_ids": added, "removed_user_ids": removed}


def _matches_group_attribute(*, rule: dict[str, Any], user_id: str, registry: UserRegistry | None, tenant_role: UserTenantRole | None) -> bool:
    field = rule.get("field")
    if field == "department":
        candidate = _token(registry.department or "", maximum=128) if registry and registry.department else ""
    elif field == "role":
        candidate = _token((registry.role if registry and registry.role else (tenant_role.role if tenant_role else "")), maximum=128) if (registry or tenant_role) else ""
    elif field == "user_id":
        candidate = user_id
    elif field == "privileged":
        candidate = "true" if tenant_role and tenant_role.role in {"admin", "owner"} else "false"
    else:
        return False
    expected = rule.get("value")
    return candidate in expected if isinstance(expected, list) else candidate == expected


def _behaviour_group_members(db: Session, *, tenant_id: str, event_type: str) -> set[str]:
    rows = list(db.scalars(select(AIAction).where(AIAction.tenant_id == tenant_id).order_by(AIAction.timestamp.desc()).limit(2_000)).all())
    members: set[str] = set()
    for row in rows:
        if not row.user_id:
            continue
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        matched = False
        if event_type == "personal_ai_account":
            matched = str(metadata.get("account_class") or "").lower() == "personal"
        elif event_type == "coding_agent":
            matched = str(metadata.get("agent_capability") or "").lower() == "coding" or str(row.source_surface or "").lower() == "runtime"
        elif event_type == "unknown_mcp_tool":
            matched = str(metadata.get("tool_trust_state") or "").lower() == "unknown"
        elif event_type == "restricted_external_destination":
            matched = str(metadata.get("data_classification") or "").lower() == "restricted" and str(metadata.get("destination_class") or "").lower() in {"external", "public"}
        elif event_type == "runtime_agent_owner":
            matched = bool(metadata.get("runtime_agent_owner"))
        elif event_type == "privileged_ai_administrator":
            role = db.scalar(select(UserTenantRole.role).where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.user_id == row.user_id))
            matched = role in {"admin", "owner"}
        if matched:
            members.add(row.user_id)
    return members


def resolve_group_member_ids(
    db: Session,
    *,
    tenant_id: str,
    group_id: str,
    _visited: set[str] | None = None,
) -> list[str]:
    """Resolve bounded membership; nested cycles are ignored, never expanded."""

    visited = set(_visited or set())
    if group_id in visited:
        return []
    if len(visited) >= 8:
        return []
    visited.add(group_id)
    group = db.scalar(
        select(PolicyPackUserGroup).where(PolicyPackUserGroup.tenant_id == tenant_id, PolicyPackUserGroup.id == group_id, PolicyPackUserGroup.active.is_(True))
    )
    if group is None:
        return []
    members = {
        row.user_id
        for row in db.scalars(
            select(PolicyPackGroupMembership).where(
                PolicyPackGroupMembership.tenant_id == tenant_id,
                PolicyPackGroupMembership.group_id == group.id,
                PolicyPackGroupMembership.active.is_(True),
            )
        ).all()
    }
    if group.group_type in {"dynamic_attribute", "role_persona", "application_user", "privileged_user"}:
        registries = {row.user_id: row for row in db.scalars(select(UserRegistry).where(UserRegistry.tenant_id == tenant_id, UserRegistry.status == "active")).all()}
        roles = {row.user_id: row for row in db.scalars(select(UserTenantRole).where(UserTenantRole.tenant_id == tenant_id)).all()}
        for user_id in sorted(set(registries) | set(roles)):
            if _matches_group_attribute(rule=group.membership_rule or {}, user_id=user_id, registry=registries.get(user_id), tenant_role=roles.get(user_id)):
                members.add(user_id)
    elif group.group_type == "security_behavior":
        members.update(_behaviour_group_members(db, tenant_id=tenant_id, event_type=str((group.membership_rule or {}).get("event_type") or "")))
    for nested_id in list(group.nested_group_ids or [])[:32]:
        members.update(resolve_group_member_ids(db, tenant_id=tenant_id, group_id=str(nested_id), _visited=visited))
    return sorted(members)


def resolve_group_refs_for_user(db: Session, *, tenant_id: str, user_id: str | None) -> list[str]:
    if not user_id:
        return []
    refs: list[str] = []
    groups = list(db.scalars(select(PolicyPackUserGroup).where(PolicyPackUserGroup.tenant_id == tenant_id, PolicyPackUserGroup.active.is_(True))).all())
    for group in groups[:200]:
        if user_id in resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id):
            refs.extend([group.id, group.group_key])
    return sorted(set(refs))


def _active_exception_rules(db: Session, *, tenant_id: str, instances: list[PolicyPackInstance], now: datetime) -> list[dict[str, Any]]:
    active_instance_ids = [item.id for item in instances]
    if not active_instance_ids:
        return []
    source_versions = {
        item.id: str(item.effective_policy_version_id)
        for item in instances
        if item.effective_policy_version_id
    }
    rows = list(
        db.scalars(
            select(PolicyPackException).where(
                PolicyPackException.tenant_id == tenant_id,
                PolicyPackException.instance_id.in_(active_instance_ids),
                PolicyPackException.status == "APPROVED",
            )
        ).all()
    )
    rules: list[dict[str, Any]] = []
    for row in rows:
        expires = row.expires_at if row.expires_at.tzinfo is not None else row.expires_at.replace(tzinfo=timezone.utc)
        if expires <= now:
            row.status = "EXPIRED"
            continue
        tree = row.scope.get("condition_tree") if isinstance(row.scope, dict) else None
        if not isinstance(tree, dict):
            continue
        rule = {
            "rule_id": f"policy_pack_exception:{row.id}",
            "enabled": True,
            "priority": 8_000,
            "condition_tree": normalize_condition_tree(tree),
            "effect": {
                "decision": "allow",
                "reason_code": f"policy_pack_exception:{row.id}",
                "explanation": "A reviewed, exact-scope policy-pack exception is active.",
                "recommended_action": "monitor_exception_expiry",
                "priority": 8_000,
            },
            "metadata": {"policy_pack_platform": {"exception_id": row.id, "expires_at": expires.isoformat(), "precedence_layer": "approved_exception"}},
        }
        source_version_id = source_versions.get(row.instance_id)
        if source_version_id:
            rule["_hawk_source_policy_version_id"] = source_version_id
        rules.append(rule)
    return rules


def active_policy_pack_exception_rules_for_runtime(db: Session, *, tenant_id: str) -> list[dict[str, Any]]:
    """Return only unexpired approved exceptions for currently active pack instances."""
    instances = list(
        db.scalars(
            select(PolicyPackInstance).where(
                PolicyPackInstance.tenant_id == tenant_id,
                PolicyPackInstance.state.in_(ACTIVE_INSTANCE_STATES),
            )
        ).all()
    )
    return _active_exception_rules(db, tenant_id=tenant_id, instances=instances, now=_now())


def active_runtime_policy_version_ids_by_pack(db: Session, *, tenant_id: str) -> dict[str, str]:
    """Return the lifecycle-selected version for each active platform runtime pack."""
    rows = db.scalars(
        select(PolicyPackInstance).where(
            PolicyPackInstance.tenant_id == tenant_id,
            PolicyPackInstance.state.in_(ACTIVE_INSTANCE_STATES),
        )
    ).all()
    return {
        str(row.runtime_policy_pack_id): str(row.effective_policy_version_id)
        for row in rows
        if row.runtime_policy_pack_id and row.effective_policy_version_id
    }


def create_policy_pack_exception(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    scope: dict[str, Any],
    reason: str,
    requested_by_ref: str,
    approved_by_ref: str,
    expires_at: datetime,
) -> PolicyPackException:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    if _text(requested_by_ref) == _text(approved_by_ref):
        raise PolicyPackPlatformError("policy_pack_exception_requires_separate_approver")
    tree = scope.get("condition_tree") if isinstance(scope, dict) else None
    if not isinstance(tree, dict):
        raise PolicyPackPlatformError("policy_pack_exception_scope_invalid")
    expiration = _now(expires_at)
    row = PolicyPackException(
        tenant_id=tenant_id,
        instance_id=instance.id,
        scope={"condition_tree": normalize_condition_tree(tree)},
        reason=_text(reason, maximum=2_000),
        requested_by_ref=_text(requested_by_ref, maximum=255),
        approved_by_ref=_text(approved_by_ref, maximum=255),
        expires_at=expiration,
        status="APPROVED" if expiration > _now() else "EXPIRED",
    )
    db.add(row)
    db.flush()
    return row


def resolve_effective_policy_explanation(
    db: Session,
    *,
    tenant_id: str,
    context: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    instances = list(
        db.scalars(
            select(PolicyPackInstance).where(
                PolicyPackInstance.tenant_id == tenant_id,
                PolicyPackInstance.state.in_(ACTIVE_INSTANCE_STATES),
            )
        ).all()
    )
    rules: list[dict[str, Any]] = []
    source_versions: list[str] = []
    for instance in instances:
        version = db.scalar(
            select(PolicyVersion).where(PolicyVersion.tenant_id == tenant_id, PolicyVersion.id == instance.effective_policy_version_id)
        )
        if version is None:
            continue
        source_versions.append(version.id)
        rules.extend(list((version.scope or {}).get("scoped_rules") or []))
    rules.extend(_active_exception_rules(db, tenant_id=tenant_id, instances=instances, now=_now(now)))
    resolution = resolve_scoped_policy_rules(
        db,
        tenant_id=tenant_id,
        policy_version_id=None,
        context=context,
        rules=normalize_scoped_rule_list(rules),
    )
    metadata = resolution.raw_rule.get("metadata", {}).get("policy_pack_platform", {}) if resolution.raw_rule else {}
    return {
        "final": {
            "decision": resolution.decision or "allow",
            "source_pack": metadata.get("source_pack"),
            "assignment_scope": metadata.get("assignment_scope"),
            "inherited_path": metadata.get("inherited_path", []),
            "customer_override": bool(metadata.get("customer_override", False)),
            "exception": metadata.get("exception_id"),
            "final_precedence": metadata.get("precedence_layer") or ("non_overridable_safety" if metadata.get("non_overridable") else None),
            "matched_control_point": metadata.get("control_point", []),
            "rule_id": resolution.rule_id,
        },
        "source_policy_versions": source_versions,
        "matched": resolution.matched,
        "explanation": resolution.explanation,
        "matched_selectors": list(resolution.matched_selectors or []),
    }


def compare_policy_pack_update(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    new_definition_id: str,
) -> dict[str, Any]:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    old_definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=instance.definition_id)
    new_definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=new_definition_id)
    if old_definition.stable_pack_id != new_definition.stable_pack_id:
        raise PolicyPackPlatformError("policy_pack_update_source_mismatch")
    old_lineage = _definition_lineage_for_instance(db, instance=instance)
    new_lineage = _resolve_definition_lineage(db, tenant_id=tenant_id, definition=new_definition)
    old_templates = {
        spec["template_id"]: spec
        for spec, _source in _definition_template_entries(
            db,
            definitions=old_lineage,
            root_definition_id=old_definition.id,
        )
    }
    new_templates = {
        spec["template_id"]: spec
        for spec, _source in _definition_template_entries(
            db,
            definitions=new_lineage,
            root_definition_id=new_definition.id,
        )
    }
    new_ids = sorted(set(new_templates) - set(old_templates))
    removed_ids = sorted(set(old_templates) - set(new_templates))
    changed_ids = sorted(
        template_id
        for template_id in set(old_templates).intersection(new_templates)
        if _json_digest(old_templates[template_id]) != _json_digest(new_templates[template_id])
    )
    overrides = sorted(set((instance.local_overrides or {}).keys()).intersection(old_templates))
    conflicts = sorted(set(overrides).intersection(set(removed_ids) | set(changed_ids)))
    comparison = {
        "previous_vendor_pack": {"stable_pack_id": old_definition.stable_pack_id, "version": old_definition.version},
        "new_vendor_pack": {"stable_pack_id": new_definition.stable_pack_id, "version": new_definition.version},
        "previous_vendor_lineage": _lineage_metadata(old_lineage, root_definition_id=old_definition.id),
        "new_vendor_lineage": _lineage_metadata(new_lineage, root_definition_id=new_definition.id),
        "new_templates": new_ids,
        "removed_or_deprecated_templates": removed_ids,
        "changed_defaults": changed_ids,
        "conflicts": conflicts,
        "customer_overrides_unchanged": overrides,
        "requires_resimulation": bool(new_ids or removed_ids or changed_ids),
    }
    update = db.scalar(
        select(PolicyPackUpdate).where(
            PolicyPackUpdate.tenant_id == tenant_id,
            PolicyPackUpdate.instance_id == instance.id,
            PolicyPackUpdate.new_definition_id == new_definition.id,
        )
    )
    if update is None:
        update = PolicyPackUpdate(
            tenant_id=tenant_id,
            instance_id=instance.id,
            previous_definition_id=old_definition.id,
            new_definition_id=new_definition.id,
            comparison=comparison,
            requires_resimulation=comparison["requires_resimulation"],
            state="CONFLICTED" if conflicts else "AVAILABLE",
        )
        db.add(update)
    else:
        update.comparison = comparison
        update.requires_resimulation = comparison["requires_resimulation"]
        update.state = "CONFLICTED" if conflicts else "AVAILABLE"
    instance.update_available = True
    if instance.state not in {"ENFORCED", "APPROVAL_ENFORCED"}:
        instance.state = "CONFLICTED" if conflicts else "UPDATE_AVAILABLE"
    db.flush()
    return comparison


def accept_policy_pack_update(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    new_definition_id: str,
    actor_ref: str,
    reason: str,
) -> PolicyPackInstance:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    comparison = compare_policy_pack_update(db, tenant_id=tenant_id, instance_id=instance_id, new_definition_id=new_definition_id)
    update = db.scalar(
        select(PolicyPackUpdate).where(
            PolicyPackUpdate.tenant_id == tenant_id,
            PolicyPackUpdate.instance_id == instance.id,
            PolicyPackUpdate.new_definition_id == new_definition_id,
        )
    )
    if update is None:
        raise PolicyPackPlatformError("policy_pack_update_not_found")
    if comparison["conflicts"]:
        raise PolicyPackPlatformError("policy_pack_update_conflicted")
    definition = _definition_for_tenant(db, tenant_id=tenant_id, definition_id=new_definition_id)
    definition_lineage = _resolve_definition_lineage(db, tenant_id=tenant_id, definition=definition)
    _effective_customer_parameters(definition_lineage, instance.customer_parameters or {})
    instance.definition_id = definition.id
    instance.source_pack_version = definition.version
    instance.lineage = {
        **(instance.lineage or {}),
        "definition_id": definition.id,
        "source_pack": definition.stable_pack_id,
        "source_version": definition.version,
        "definition_lineage": _lineage_metadata(definition_lineage, root_definition_id=definition.id),
    }
    instance.update_available = False
    instance.state = "SIMULATING" if comparison["requires_resimulation"] else "REVIEW_REQUIRED"
    update.state = "ACCEPTED"
    update.reviewed_by_ref = _text(actor_ref, maximum=255)
    update.review_reason = _text(reason, maximum=2_000)
    db.flush()
    return instance


def bulk_assign_policy_pack_instance(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
    assignments: list[dict[str, Any]],
    actor_ref: str,
) -> dict[str, int]:
    instance = _instance_for_tenant(db, tenant_id=tenant_id, instance_id=instance_id)
    _require_entitlement(db, tenant_id=tenant_id, needed_tier="secure")
    created = 0
    for raw in assignments:
        targets = _normalize_assignment_targets(raw)
        key = _json_digest(targets)
        existing = db.scalar(
            select(PolicyPackAssignment).where(
                PolicyPackAssignment.tenant_id == tenant_id,
                PolicyPackAssignment.instance_id == instance.id,
                PolicyPackAssignment.assignment_key == key,
            )
        )
        if existing is not None:
            existing.active = True
            continue
        precedence, path = _assignment_precedence(targets)
        db.add(
            PolicyPackAssignment(
                tenant_id=tenant_id,
                instance_id=instance.id,
                assignment_key=key,
                targets=targets,
                precedence_layer=precedence,
                inherited_path=path,
                active=True,
            )
        )
        created += 1
    db.flush()
    if created:
        runtime_pack = db.scalar(select(PolicyPack).where(PolicyPack.tenant_id == tenant_id, PolicyPack.id == instance.runtime_policy_pack_id))
        if runtime_pack is not None:
            previous = instance.effective_policy_version_id
            version = _compile_policy_version(db, instance=instance, runtime_pack=runtime_pack, state=instance.state)
            instance.previous_effective_policy_version_id = previous
            instance.effective_policy_version_id = version.id
    db.flush()
    return {"created": created, "total": len(_active_assignments(db, instance=instance))}
