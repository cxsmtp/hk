from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


DECISION_PRECEDENCE = ["block", "require_approval", "require_justification", "warn", "allow"]
FRAMEWORK_KEYS = ("nist_ai_rmf", "iso_42001", "eu_ai_act", "owasp_genai", "mitre_atlas")
REQUIRED_FRAMEWORK_KEYS = ("nist_ai_rmf", "iso_42001", "eu_ai_act")


def normalize_framework_mapping(raw: dict[str, Any] | None) -> dict[str, list[str]]:
    source = dict(raw or {})
    control_ids = [
        str(item).strip()
        for item in (source.get("control_ids") or [])
        if str(item).strip()
    ]
    mapping: dict[str, list[str]] = {}
    for key in FRAMEWORK_KEYS:
        values = source.get(key) or []
        rows = [str(item).strip() for item in values if str(item).strip()]
        if not rows and control_ids:
            rows = list(control_ids)
        mapping[key] = rows
    if control_ids:
        mapping["control_ids"] = control_ids
    return mapping


def framework_mapping_is_valid(raw: dict[str, Any] | None) -> bool:
    mapping = normalize_framework_mapping(raw)
    return all(bool(mapping.get(key)) for key in REQUIRED_FRAMEWORK_KEYS)


def canonical_guardian_policy(
    *,
    policy_id: str,
    policy_name: str,
    policy_version: str,
    tenant_id: str,
    scope: dict[str, Any] | None = None,
    conditions: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    enforcement: dict[str, Any] | None = None,
    governance: dict[str, Any] | None = None,
    framework_mapping: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "policy_id": str(policy_id).strip(),
        "policy_name": str(policy_name).strip() or str(policy_id).strip(),
        "policy_version": str(policy_version or "1.0").strip() or "1.0",
        "tenant_id": str(tenant_id).strip(),
        "scope": {
            "ai_system_ids": list((scope or {}).get("ai_system_ids") or ["*"]),
            "agent_ids": list((scope or {}).get("agent_ids") or ["*"]),
            "user_groups": list((scope or {}).get("user_groups") or ["*"]),
            "environments": list((scope or {}).get("environments") or ["prod", "staging", "dev"]),
        },
        "conditions": {
            "source": dict((conditions or {}).get("source") or {}),
            "destination": dict((conditions or {}).get("destination") or {}),
            "action": dict((conditions or {}).get("action") or {}),
            "data": dict((conditions or {}).get("data") or {}),
        },
        "decision": {
            "mode": str((decision or {}).get("mode") or "warn").strip().lower(),
            "confidence_threshold": float((decision or {}).get("confidence_threshold", 0.7)),
            "strictness": str((decision or {}).get("strictness") or "medium").strip().lower(),
        },
        "enforcement": {
            "fail_mode": str((enforcement or {}).get("fail_mode") or "fail_secure").strip().lower(),
            "log": bool((enforcement or {}).get("log", True)),
            "create_finding": bool((enforcement or {}).get("create_finding", True)),
            "require_evidence": bool((enforcement or {}).get("require_evidence", True)),
        },
        "governance": {
            "risk_level": str((governance or {}).get("risk_level") or "medium").strip().lower(),
            "approval_required": bool((governance or {}).get("approval_required", False)),
            "policy_owner": str((governance or {}).get("policy_owner") or "system"),
            "review_cycle_days": int((governance or {}).get("review_cycle_days") or 30),
        },
        "framework_mapping": normalize_framework_mapping(framework_mapping),
        "metadata": {
            "created_at": (metadata or {}).get("created_at"),
            "updated_at": (metadata or {}).get("updated_at"),
            "active": bool((metadata or {}).get("active", True)),
            **{
                str(k): v
                for k, v in dict(metadata or {}).items()
                if str(k) not in {"created_at", "updated_at", "active"}
            },
        },
    }


def canonical_policy_from_v2_binding(
    *,
    binding: dict[str, Any],
    tenant_id: str,
) -> dict[str, Any]:
    contract_id = str(binding.get("guardian_contract_id") or "").strip()
    framework = normalize_framework_mapping(binding.get("framework_mappings") or {})
    evidence = dict(binding.get("evidence_requirements") or {})
    if not framework.get("control_ids"):
        framework["control_ids"] = [
            str(item).strip()
            for item in (evidence.get("link_to_controls") or [])
            if str(item).strip()
        ]
    return canonical_guardian_policy(
        policy_id=contract_id,
        policy_name=str(binding.get("name") or contract_id),
        policy_version=str(binding.get("version") or "2.0"),
        tenant_id=tenant_id,
        scope={
            "ai_system_ids": [str(binding.get("ai_system_id") or "*")],
            "agent_ids": ["*"],
            "user_groups": ["*"],
            "environments": ["prod", "staging", "dev"],
        },
        conditions={
            "action": {"type": "prompt"},
            "data": {
                "patterns": [],
            },
        },
        decision={
            "mode": "block" if str(binding.get("enforcement_strength") or "").lower() in {"strict", "maximum"} else "warn",
            "confidence_threshold": float((evidence or {}).get("confidence_threshold", 0.7)),
            "strictness": "high" if str(binding.get("enforcement_strength") or "").lower() in {"strict", "maximum"} else "medium",
        },
        enforcement={
            "fail_mode": "fail_secure",
            "log": True,
            "create_finding": True,
            "require_evidence": True,
        },
        governance={
            "risk_level": "high" if str(binding.get("enforcement_strength") or "").lower() in {"strict", "maximum"} else "medium",
            "approval_required": False,
            "policy_owner": "system",
            "review_cycle_days": 30,
        },
        framework_mapping=framework,
        metadata={
            "active": bool(binding.get("enabled", True)),
            "legacy_trigger_conditions": list(binding.get("trigger_conditions") or []),
            "legacy_block_conditions": list(binding.get("block_conditions") or []),
            "legacy_mandatory_actions": dict(binding.get("mandatory_actions") or {}),
            "legacy_escalation_path": dict(binding.get("escalation_path") or {}),
            "legacy_evidence_requirements": dict(binding.get("evidence_requirements") or {}),
        },
    )


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _domain_matches(left: str | None, right: str | None) -> bool:
    a = str(left or "").strip().lower()
    b = str(right or "").strip().lower()
    if not a or not b:
        return False
    return a == b or a.endswith(f".{b}")


def _scope_match(policy: dict[str, Any], ctx: dict[str, Any]) -> bool:
    scope = dict(policy.get("scope") or {})

    def _match(values: list[str], candidate: str | None) -> bool:
        normalized = [str(item).strip() for item in values if str(item).strip()]
        if not normalized or "*" in normalized:
            return True
        if not candidate:
            return False
        return str(candidate).strip() in normalized

    return (
        _match(list(scope.get("ai_system_ids") or ["*"]), ctx.get("ai_system_id"))
        and _match(list(scope.get("agent_ids") or ["*"]), ctx.get("agent_id"))
        and _match(list(scope.get("user_groups") or ["*"]), ctx.get("user_group"))
        and _match(list(scope.get("environments") or ["*"]), ctx.get("environment"))
    )


def _condition_match(policy: dict[str, Any], ctx: dict[str, Any]) -> tuple[bool, list[str]]:
    conditions = dict(policy.get("conditions") or {})
    source = dict(conditions.get("source") or {})
    destination = dict(conditions.get("destination") or {})
    action = dict(conditions.get("action") or {})
    data = dict(conditions.get("data") or {})

    matched: list[str] = []

    source_type = str(source.get("type") or "").strip().lower()
    if source_type and source_type != str(ctx.get("source_type") or "").strip().lower():
        return False, []
    if source_type:
        matched.append("source.type")

    source_class = str(source.get("classification") or "").strip().lower()
    if source_class and source_class != str(ctx.get("source_classification") or "").strip().lower():
        return False, []
    if source_class:
        matched.append("source.classification")

    destination_type = str(destination.get("type") or "").strip().lower()
    if destination_type and destination_type != str(ctx.get("destination_type") or "").strip().lower():
        return False, []
    if destination_type:
        matched.append("destination.type")

    destination_trust = str(destination.get("trust_level") or "").strip().lower()
    if destination_trust and destination_trust != str(ctx.get("destination_trust_level") or "").strip().lower():
        return False, []
    if destination_trust:
        matched.append("destination.trust_level")

    action_type = str(action.get("type") or "").strip().lower()
    if action_type and action_type != str(ctx.get("action_type") or "").strip().lower():
        return False, []
    if action_type:
        matched.append("action.type")

    policy_tool = str(action.get("tool_name") or "").strip().lower()
    if policy_tool and policy_tool != str(ctx.get("tool_name") or "").strip().lower():
        return False, []
    if policy_tool:
        matched.append("action.tool_name")

    policy_chain_depth = action.get("chain_depth")
    if policy_chain_depth is not None:
        try:
            if int(ctx.get("chain_depth") or 0) > int(policy_chain_depth):
                return False, []
            matched.append("action.chain_depth")
        except (TypeError, ValueError):
            return False, []

    contains_sensitive = data.get("contains_sensitive")
    if contains_sensitive is not None:
        if bool(contains_sensitive) != bool(ctx.get("contains_sensitive")):
            return False, []
        matched.append("data.contains_sensitive")

    patterns = [str(item).strip() for item in (data.get("patterns") or []) if str(item).strip()]
    if patterns:
        haystack = str(ctx.get("text") or "")
        if not haystack:
            return False, []
        matched_pattern = False
        for pattern in patterns:
            try:
                if re.search(pattern, haystack, flags=re.IGNORECASE):
                    matched_pattern = True
                    break
            except re.error:
                if pattern.lower() in haystack.lower():
                    matched_pattern = True
                    break
        if not matched_pattern:
            return False, []
        matched.append("data.patterns")

    legacy_block = [
        row for row in (dict(policy.get("metadata") or {}).get("legacy_block_conditions") or [])
        if isinstance(row, dict)
    ]
    legacy_trigger = [
        row for row in (dict(policy.get("metadata") or {}).get("legacy_trigger_conditions") or [])
        if isinstance(row, dict)
    ]
    if legacy_block or legacy_trigger:
        legacy_haystack = str(ctx.get("text") or "")
        legacy_hit = False
        for row in [*legacy_block, *legacy_trigger]:
            value = _as_text(row.get("value"))
            operator = str(row.get("operator") or "").strip().lower()
            if not value:
                continue
            if operator == "regex":
                try:
                    if re.search(value, legacy_haystack, flags=re.IGNORECASE):
                        legacy_hit = True
                        break
                except re.error:
                    continue
            elif operator in {"contains", "equals", ""}:
                if value.lower() in legacy_haystack.lower():
                    legacy_hit = True
                    break
        if not legacy_hit:
            return False, []
        matched.append("metadata.legacy_conditions")

    return True, matched


@dataclass
class CanonicalDecision:
    decision: str
    reason_code: str
    explanation: str
    recommended_action: str
    severity: str
    justification_required: bool = False
    approval_required: bool = False
    policy: dict[str, Any] | None = None
    matched_conditions: list[str] | None = None


def decision_to_severity(decision: str) -> str:
    normalized = str(decision or "").strip().lower()
    if normalized in {"block", "require_approval", "require_justification"}:
        return "high"
    if normalized == "warn":
        return "med"
    return "low"


def evaluate_guardian_policies(
    *,
    policies: list[dict[str, Any]],
    context: dict[str, Any],
    default_decision: str = "allow",
) -> CanonicalDecision:
    eval_context = dict(context or {})
    eval_context.setdefault("environment", "prod")
    matched_rows: list[tuple[str, dict[str, Any], list[str]]] = []
    for row in policies:
        if not bool(dict(row.get("metadata") or {}).get("active", True)):
            continue
        if not _scope_match(row, eval_context):
            continue
        matched, matched_conditions = _condition_match(row, eval_context)
        if not matched:
            continue
        mode = str((row.get("decision") or {}).get("mode") or "warn").strip().lower()
        if mode not in {"allow", "warn", "block", "require_justification", "require_approval"}:
            mode = "warn"
        matched_rows.append((mode, row, matched_conditions))

    if not matched_rows:
        fallback = str(default_decision or "allow").strip().lower()
        if fallback not in {"allow", "warn", "block", "require_justification", "require_approval"}:
            fallback = "allow"
        return CanonicalDecision(
            decision=fallback,
            reason_code="policy_allow" if fallback == "allow" else "policy_default",
            explanation="No matching guardian policy condition.",
            recommended_action="monitor",
            severity=decision_to_severity(fallback),
            justification_required=fallback == "require_justification",
            approval_required=fallback == "require_approval",
            policy=None,
            matched_conditions=[],
        )

    def _rank(item: tuple[str, dict[str, Any], list[str]]) -> int:
        mode = item[0]
        try:
            return DECISION_PRECEDENCE.index(mode)
        except ValueError:
            return len(DECISION_PRECEDENCE)

    matched_rows.sort(key=_rank)
    chosen_mode, chosen_policy, matched_conditions = matched_rows[0]
    policy_id = str(chosen_policy.get("policy_id") or "guardian_policy")
    reason_code = f"{policy_id}_matched"
    return CanonicalDecision(
        decision=chosen_mode,
        reason_code=reason_code,
        explanation=f"Guardian policy {policy_id} matched interaction context.",
        recommended_action="route_to_governance"
        if chosen_mode in {"block", "require_approval", "require_justification"}
        else "monitor",
        severity=decision_to_severity(chosen_mode),
        justification_required=chosen_mode == "require_justification",
        approval_required=chosen_mode == "require_approval",
        policy=chosen_policy,
        matched_conditions=matched_conditions,
    )


def evaluate_data_transfer_policy(
    *,
    source_classification: str,
    source_surface: str,
    destination_surface: str,
    destination_domain: str,
    destination_ai_system_id: str | None,
    destination_discovery_status: str,
    destination_app_name: str | None,
    destination_is_external: bool,
    platform_mode: str,
    action_type: str = "copy_paste",
) -> CanonicalDecision:
    normalized_action_type = str(action_type or "copy_paste").strip().lower() or "copy_paste"
    dest_is_ai = destination_surface == "ai_tool"
    dest_is_sanctioned = bool(destination_ai_system_id) or destination_discovery_status == "approved"
    destination_app = str(destination_app_name or "").strip().lower()
    known_ai_tool = dest_is_ai or destination_app in {"chatgpt", "claude", "gemini", "copilot", "perplexity"}
    domain_lower = str(destination_domain or "").strip().lower()
    is_email = destination_surface == "email" or domain_lower in {"mail.google.com", "outlook.office.com", "outlook.live.com"}
    is_slack = destination_surface == "slack" or domain_lower in {"slack.com", "app.slack.com"}
    if not destination_is_external:
        destination_trust_level = "trusted"
    elif is_email or is_slack:
        # External collaboration channels remain untrusted for sensitive data movement,
        # even when the destination is governance-approved.
        destination_trust_level = "untrusted"
    elif dest_is_sanctioned:
        destination_trust_level = "trusted"
    else:
        destination_trust_level = "untrusted"

    policies: list[dict[str, Any]] = [
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.sensitive_file_upload_to_public_ai_block",
            policy_name="Sensitive File Upload To Public AI",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": "ai_tool", "trust_level": "untrusted"},
                "action": {"type": "file_upload"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "block", "confidence_threshold": 0.7, "strictness": "high"},
            enforcement={"fail_mode": "fail_secure", "log": True, "create_finding": True, "require_evidence": True},
            governance={"risk_level": "high", "approval_required": False, "policy_owner": "system", "review_cycle_days": 30},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001", "FILE_UPLOAD_INSPECTION"],
            },
            metadata={
                "active": True,
                "reason_code": "sensitive_file_upload",
                "finding_type": "sensitive_file_upload_attempt",
                "explanation": "Sensitive file upload to an unsanctioned public AI tool is blocked.",
                "recommended_action": "quarantine_source_and_route_to_governance",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.sensitive_file_upload_to_external_collaboration_requires_justification",
            policy_name="Sensitive File Upload To External Collaboration",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": ("email" if is_email else "slack"), "trust_level": "untrusted"},
                "action": {"type": "file_upload"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "require_justification", "confidence_threshold": 0.7, "strictness": "high"},
            enforcement={"fail_mode": "fail_secure", "log": True, "create_finding": True, "require_evidence": True},
            governance={"risk_level": "high", "approval_required": False, "policy_owner": "system", "review_cycle_days": 30},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001", "FILE_UPLOAD_INSPECTION"],
            },
            metadata={
                "active": bool(is_email or is_slack),
                "reason_code": "sensitive_file_upload_requires_justification",
                "finding_type": "sensitive_file_upload_attempt",
                "explanation": "Sensitive file upload to external collaboration requires business justification.",
                "recommended_action": "route_to_governance",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.protected_to_public_ai_block",
            policy_name="Protected Data To Public AI",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": "ai_tool", "trust_level": "untrusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "block", "confidence_threshold": 0.7, "strictness": "high"},
            enforcement={"fail_mode": "fail_secure", "log": True, "create_finding": True, "require_evidence": True},
            governance={"risk_level": "high", "approval_required": False, "policy_owner": "system", "review_cycle_days": 30},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": True,
                "reason_code": "protected_to_public_ai_block",
                "finding_type": "sensitive_data_to_public_ai_attempt",
                "explanation": "Sensitive content cannot be pasted into unsanctioned public AI tools.",
                "recommended_action": "route_to_governance",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.protected_to_ai_requires_justification",
            policy_name="Protected Data To Governed AI",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": "ai_tool", "trust_level": "trusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "require_justification", "confidence_threshold": 0.7, "strictness": "high"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": True,
                "reason_code": "protected_to_ai_requires_justification",
                "finding_type": "sensitive_data_external_transfer_attempt",
                "explanation": "Sensitive content to AI destinations requires business justification.",
                "recommended_action": "monitor",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.protected_to_external_collaboration_requires_justification",
            policy_name="Protected Data To External Collaboration",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": ("email" if is_email else "slack"), "trust_level": "untrusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "require_justification", "confidence_threshold": 0.7, "strictness": "high"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": bool(is_email or is_slack),
                "reason_code": "protected_to_external_collaboration_requires_justification",
                "finding_type": "sensitive_data_external_transfer_attempt",
                "explanation": "Sensitive content to external collaboration channels requires justification.",
                "recommended_action": "route_to_governance",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.protected_to_external_warn",
            policy_name="Protected Data To External Destination",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "protected"},
                "destination": {"type": destination_surface, "trust_level": "untrusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "warn", "confidence_threshold": 0.6, "strictness": "medium"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": True,
                "reason_code": "protected_to_external_warn",
                "finding_type": "sensitive_data_external_transfer_attempt",
                "explanation": "Sensitive content moved to external destinations should be reviewed.",
                "recommended_action": "monitor",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.unknown_source_unknown_destination_warn",
            policy_name="Unknown Source To Unknown Destination",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "unknown"},
                "destination": {"type": destination_surface, "trust_level": "untrusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": False},
            },
            decision={"mode": "warn", "confidence_threshold": 0.6, "strictness": "medium"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": True,
                "reason_code": "unknown_source_unknown_destination_warn",
                "finding_type": "sensitive_data_external_transfer_attempt",
                "explanation": "Source and destination are both unclassified; proceeding with warning.",
                "recommended_action": "monitor",
            },
        ),
        canonical_guardian_policy(
            policy_id="guardian.data_transfer.public_to_unsanctioned_ai_warn",
            policy_name="Public To Unsanctioned AI",
            policy_version="1.0.0",
            tenant_id="*",
            conditions={
                "source": {"type": source_surface, "classification": "public"},
                "destination": {"type": "ai_tool", "trust_level": "untrusted"},
                "action": {"type": "copy_paste"},
                "data": {"contains_sensitive": False},
            },
            decision={"mode": "warn", "confidence_threshold": 0.6, "strictness": "medium"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            },
            metadata={
                "active": bool(known_ai_tool),
                "reason_code": "public_to_unsanctioned_ai_warn",
                "finding_type": "sensitive_data_external_transfer_attempt",
                "explanation": "Public source to unsanctioned AI destination is permitted with warning.",
                "recommended_action": "monitor",
            },
        ),
    ]

    policy_decision = evaluate_guardian_policies(
        policies=policies,
        context={
            "source_type": source_surface,
            "source_classification": source_classification,
            "destination_type": destination_surface,
            "destination_trust_level": destination_trust_level,
            "action_type": normalized_action_type,
            "contains_sensitive": source_classification == "protected",
            "text": f"{destination_domain} {destination_app_name or ''}",
            "environment": "prod",
        },
        default_decision="allow",
    )

    decision = policy_decision.decision
    reason = str((policy_decision.policy or {}).get("metadata", {}).get("reason_code") or policy_decision.reason_code or "policy_allow")
    explanation = str((policy_decision.policy or {}).get("metadata", {}).get("explanation") or policy_decision.explanation)
    action = str((policy_decision.policy or {}).get("metadata", {}).get("recommended_action") or policy_decision.recommended_action)
    finding = str((policy_decision.policy or {}).get("metadata", {}).get("finding_type") or "").strip() or None

    if not destination_is_external and source_classification == "public":
        decision = "allow"
        reason = "public_to_internal_allow"
        explanation = "Public content to internal destination is allowed."
        action = "monitor"
        finding = None

    if platform_mode == "discovery" and decision == "block" and reason not in {"protected_to_public_ai_block", "sensitive_file_upload"}:
        decision = "warn"
        reason = f"{reason}_downgraded_discovery"
        explanation = "Discovery mode downgraded enforcement from block to warn."
        action = "monitor"

    policy = policy_decision.policy or canonical_guardian_policy(
        policy_id=f"guardian.data_transfer.{reason}",
        policy_name="Data Movement Control",
        policy_version="1.0.0",
        tenant_id="*",
        conditions={
            "source": {"type": source_surface, "classification": source_classification},
            "destination": {"type": destination_surface, "trust_level": destination_trust_level},
            "action": {"type": normalized_action_type},
            "data": {"contains_sensitive": source_classification == "protected"},
        },
        decision={"mode": decision, "confidence_threshold": 0.7, "strictness": "high" if decision == "block" else "medium"},
        framework_mapping={
            "nist_ai_rmf": ["GV.RM", "MP.AI"],
            "iso_42001": ["A.5", "A.8"],
            "eu_ai_act": ["risk_management", "data_governance"],
            "owasp_genai": ["LLM01", "LLM06"],
            "mitre_atlas": ["AML.TA0001"],
            "control_ids": ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
        },
        metadata={"active": True, "finding_type": finding},
    )

    return CanonicalDecision(
        decision=decision,
        reason_code=reason,
        explanation=explanation,
        recommended_action=action,
        severity=decision_to_severity(decision),
        justification_required=decision == "require_justification",
        policy=policy,
        matched_conditions=policy_decision.matched_conditions or ["source.classification", "destination.type"],
    )


def evaluate_agent_action_policy(
    *,
    governance_status: dict[str, str],
    platform_mode: str,
    token_valid: bool,
    token_reason: str,
    agent_matches_token: bool,
    action_scope_ok: bool,
    tool_ok: bool,
    target_ok: bool,
    chain_depth_ok: bool,
    action_type: str,
    data_classification: str,
) -> CanonicalDecision:
    state = str(governance_status.get("status") or "UNKNOWN").upper()

    decision = "allow"
    reason = "policy_allow"
    explanation = "Agent action allowed by runtime policy."
    action = "monitor"

    if state == "REJECTED":
        decision, reason, explanation, action = (
            "block",
            "governance_rejected",
            "AI system governance state is rejected; action blocked.",
            "route_to_governance",
        )
    elif state == "UNKNOWN":
        if platform_mode != "discovery":
            decision, reason, explanation, action = (
                "block",
                "unregistered_ai_system",
                "AI system is not registered in Trust Center.",
                "route_to_governance",
            )
        else:
            decision, reason, explanation, action = (
                "warn",
                "unregistered_ai_system",
                "AI system is not registered; action allowed with warning in monitor mode.",
                "route_to_governance",
            )
    elif state == "PROPOSED":
        decision, reason, explanation, action = (
            "require_approval",
            "governance_proposed_requires_approval",
            "AI system is proposed and requires governance approval for agent actions.",
            "route_to_governance",
        )

    if not token_valid:
        decision, reason, explanation, action = (
            "block",
            token_reason or "capability_token_invalid",
            "Capability token validation failed.",
            "investigate_agent_identity",
        )
    elif not agent_matches_token:
        decision, reason, explanation, action = (
            "block",
            "agent_token_mismatch",
            "Provided capability token does not belong to the requested agent identity.",
            "investigate_agent_identity",
        )
    elif not chain_depth_ok:
        decision, reason, explanation, action = (
            "block",
            "chain_depth_exceeded",
            "Requested chain depth exceeds configured maximum.",
            "tighten_policy",
        )
    elif not action_scope_ok:
        decision, reason, explanation, action = (
            "block",
            "agent_action_scope_denied",
            "Action is outside the agent action scope.",
            "tighten_policy",
        )
    elif not tool_ok:
        decision, reason, explanation, action = (
            "block",
            "tool_not_allowed",
            "Tool is outside the agent tool registry.",
            "tighten_policy",
        )
    elif not target_ok:
        decision, reason, explanation, action = (
            "block",
            "external_system_access_denied",
            "Target system is outside allowed external system access.",
            "tighten_policy",
        )

    if decision == "allow" and data_classification == "sensitive" and action_type in {"api_call", "email_send", "db_query"}:
        decision, reason, explanation, action = (
            "require_approval",
            "sensitive_agent_action_requires_approval",
            "Sensitive context detected; approval required before executing this agent action.",
            "route_to_governance",
        )

    if platform_mode == "discovery" and decision in {"block", "require_approval"}:
        if reason not in {
            "unregistered_ai_system",
            "governance_rejected",
            "capability_token_invalid",
            "token_not_found",
            "token_revoked",
            "token_expired",
        }:
            decision = "warn"
            reason = f"{reason}_downgraded_discovery"
            explanation = "Discovery mode downgraded strict decision to warn for observation."
            action = "monitor"

    policy = canonical_guardian_policy(
        policy_id=f"guardian.agent_action.{reason}",
        policy_name="Agent Action Control",
        policy_version="1.0.0",
        tenant_id="*",
        scope={"ai_system_ids": ["*"], "agent_ids": ["*"], "user_groups": ["*"], "environments": ["prod", "staging", "dev"]},
        conditions={
            "source": {"type": "agent", "classification": data_classification},
            "destination": {"type": "external_api", "trust_level": "unknown"},
            "action": {"type": "agent_action"},
            "data": {"contains_sensitive": data_classification == "sensitive"},
        },
        decision={"mode": decision, "confidence_threshold": 0.8, "strictness": "high"},
        enforcement={"fail_mode": "fail_secure", "log": True, "create_finding": True, "require_evidence": True},
        governance={"risk_level": "high", "approval_required": decision == "require_approval", "policy_owner": "system", "review_cycle_days": 30},
        framework_mapping={
            "nist_ai_rmf": ["GV.RM", "ME.AI"],
            "iso_42001": ["A.8", "A.12"],
            "eu_ai_act": ["risk_management", "human_oversight"],
            "owasp_genai": ["LLM06"],
            "mitre_atlas": ["AML.TA0004"],
            "control_ids": ["CTRL-AI-IAM-001", "CTRL-TENANT-ISO-001"],
        },
        metadata={"active": True},
    )

    return CanonicalDecision(
        decision=decision,
        reason_code=reason,
        explanation=explanation,
        recommended_action=action,
        severity=decision_to_severity(decision),
        approval_required=decision == "require_approval",
        policy=policy,
        matched_conditions=["action.type", "data.contains_sensitive"],
    )


def evaluate_browser_interaction_policy(
    *,
    prompt_preview_redacted: str,
    domain: str,
    policy_sync: Any,
    known_ai_domains: list[str],
) -> tuple[str, CanonicalDecision, list[str]]:
    text = str(prompt_preview_redacted or "")
    domain_norm = str(domain or "").strip().lower()
    reason_codes: list[str] = []
    input_signal_types: list[str] = []
    prompt_injection_variant_patterns = (
        re.compile(r"\bignore\b[^\n\r]{0,32}\binstructions?\b", re.IGNORECASE),
        re.compile(r"\b(?:reveal|show)\b[^\n\r]{0,48}\b(?:system|hidden)\s*(?:prompt|instructions?)\b", re.IGNORECASE),
    )
    prompt_decomposition_variant_patterns = (
        re.compile(
            r"\b(?:decompose|break(?:\s+down)?|split)\b[^\n\r]{0,80}\b(?:prompt|request|payload|instructions?)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:steps?|parts?|chunks?)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:step[\s-]?by[\s-]?step|one\s+step\s+at\s+a\s+time)\b[^\n\r]{0,120}\b(?:bypass|evade|avoid|circumvent|sidestep)\b[^\n\r]{0,48}\b(?:policy|guard(?:rail)?s?|filter|detection|safety)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:rephrase|rewrite)\b[^\n\r]{0,80}\b(?:forbidden|blocked|restricted)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:harmless|safe)\b[^\n\r]{0,60}\b(?:steps?|parts?)\b",
            re.IGNORECASE,
        ),
    )

    def _match_domains(collection: list[str]) -> bool:
        return any(_domain_matches(domain_norm, item) for item in collection)

    if _match_domains(list(getattr(policy_sync, "blocked_domains", []) or [])):
        reason_codes.append("domain_blocked")
        input_signal_types.append("domain_policy_mismatch")
        return "clear_positive", CanonicalDecision(
            decision="block",
            reason_code="domain_blocked",
            explanation="Destination domain is blocked by guardian policy.",
            recommended_action="route_to_governance",
            severity="high",
        ), input_signal_types

    for keyword in list((getattr(policy_sync, "interaction_rules", {}) or {}).get("blocked_keywords") or []):
        if str(keyword).strip() and str(keyword).lower() in text.lower():
            reason_codes.append("blocked_keyword_match")
            input_signal_types.append("prompt_injection")
            return "clear_positive", CanonicalDecision(
                decision="block",
                reason_code="blocked_keyword_match",
                explanation="Blocked keyword matched guardian browser policy.",
                recommended_action="route_to_governance",
                severity="high",
            ), input_signal_types

    if any(pattern.search(text) for pattern in prompt_injection_variant_patterns):
        reason_codes.append("prompt_injection_pattern")
        input_signal_types.append("prompt_injection")
        return "clear_positive", CanonicalDecision(
            decision="block",
            reason_code="prompt_injection_pattern",
            explanation="Prompt-injection variant matched guardian browser policy.",
            recommended_action="route_to_governance",
            severity="high",
        ), input_signal_types

    if any(pattern.search(text) for pattern in prompt_decomposition_variant_patterns):
        reason_codes.append("prompt_decomposition_pattern")
        input_signal_types.extend(["prompt_decomposition", "prompt_injection"])
        return "clear_positive", CanonicalDecision(
            decision="block",
            reason_code="prompt_decomposition_pattern",
            explanation="Prompt decomposition bypass pattern matched guardian browser policy.",
            recommended_action="route_to_governance",
            severity="high",
        ), list(dict.fromkeys(input_signal_types))

    for pattern in list((getattr(policy_sync, "interaction_rules", {}) or {}).get("sensitive_patterns") or []):
        pattern_text = str(pattern).strip()
        if not pattern_text:
            continue
        try:
            if re.search(pattern_text, text, flags=re.IGNORECASE):
                reason_codes.append("sensitive_data_pattern")
                input_signal_types.append("sensitive_data_pattern")
                return "clear_positive", CanonicalDecision(
                    decision="block",
                    reason_code="sensitive_data_pattern",
                    explanation="Sensitive data pattern matched guardian browser policy.",
                    recommended_action="route_to_governance",
                    severity="high",
                ), input_signal_types
        except re.error:
            continue

    domain_known = _match_domains(
        [
            *(getattr(policy_sync, "approved_domains", []) or []),
            *(getattr(policy_sync, "blocked_domains", []) or []),
            *(getattr(policy_sync, "warn_domains", []) or []),
            *(known_ai_domains or []),
        ]
    )
    if not domain_known:
        reason_codes.append("unknown_domain")
        input_signal_types.append("domain_policy_mismatch")
        mode = "block" if str(getattr(policy_sync, "unknown_domain_behavior", "")).lower() == "block" else "warn"
        tier = "clear_positive" if mode == "block" else "ambiguous"
        return tier, CanonicalDecision(
            decision=mode,
            reason_code="unknown_domain",
            explanation="Unknown destination domain under guardian policy.",
            recommended_action="route_to_governance" if mode == "block" else "monitor",
            severity=decision_to_severity(mode),
        ), input_signal_types

    if _match_domains(list(getattr(policy_sync, "warn_domains", []) or [])):
        reason_codes.append("domain_warn")
        input_signal_types.append("domain_policy_mismatch")
        return "ambiguous", CanonicalDecision(
            decision="warn",
            reason_code="domain_warn",
            explanation="Destination domain is in warn list.",
            recommended_action="monitor",
            severity="med",
        ), input_signal_types

    for term in list((getattr(policy_sync, "interaction_rules", {}) or {}).get("high_risk_terms") or []):
        if str(term).strip() and str(term).lower() in text.lower():
            reason_codes.append("high_risk_term")
            input_signal_types.append("jailbreak")
            return "ambiguous", CanonicalDecision(
                decision="warn",
                reason_code="high_risk_term",
                explanation="High-risk term matched guardian browser policy.",
                recommended_action="monitor",
                severity="med",
            ), input_signal_types

    return "clear_negative", CanonicalDecision(
        decision="allow",
        reason_code="policy_allow",
        explanation="Browser interaction allowed by guardian policy.",
        recommended_action="monitor",
        severity="low",
    ), input_signal_types
