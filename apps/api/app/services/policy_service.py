from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any

import semver
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.policy import (
    BusinessFunctionProfile,
    PolicyPack,
    PolicyVersion,
    TenantSectorProfile,
    UserBusinessFunctionMapping,
)


DEFAULT_GUARDIANS: list[dict[str, Any]] = [
    {
        "guardian_id": "prompt_injection",
        "description": "Blocks direct instruction override patterns in prompts.",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text", "context.rag"],
            "conditions": [
                {"field": "prompt.text", "operator": "regex", "value": "(?i)ignore previous instructions", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.7},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "hold_for_approval"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": True, "strategy": "restricted_template"},
            "notify": {"channels": ["slack"]},
            "create_ticket": {"system": "jira", "severity": "high"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.prompt_injection.detected",
            "link_to_controls": ["CTRL-INPUT-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.2,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 2,
        },
        "approval_workflow": {"required_roles": ["owner", "admin"], "sla_minutes": 30, "default_if_timeout": "block"},
    },
    {
        "guardian_id": "jailbreak",
        "description": "Detects jailbreak phrases aiming to bypass policy.",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {"field": "prompt.text", "operator": "contains", "value": "DAN mode", "case_sensitive": False},
                {"field": "prompt.text", "operator": "contains", "value": "jailbreak", "case_sensitive": False},
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.65},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": True, "strategy": "safe_completion"},
            "notify": {"channels": ["email"]},
            "create_ticket": {"system": "jira", "severity": "high"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.jailbreak.detected",
            "link_to_controls": ["CTRL-INPUT-002"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.15,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 1,
        },
    },
    {
        "guardian_id": "sensitive_data_leakage",
        "description": "Detects PII and secret leakage patterns.",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text", "tool.output", "response.text"],
            "conditions": [
                {"field": "prompt.text", "operator": "regex", "value": "(?i)(ssn|credit card|api key|secret)", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "hybrid", "confidence_threshold": 0.75},
        "decision": {"on_pass": "allow", "on_fail": "redact", "on_uncertain": "hold_for_approval"},
        "actions": {
            "redact": {"fields": ["prompt", "response"], "strategy": "remove"},
            "mutate_output": {"enabled": True, "strategy": "safe_completion"},
            "notify": {"channels": ["teams"]},
            "create_ticket": {"system": "servicenow", "severity": "critical"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.sensitive_data_leakage.detected",
            "link_to_controls": ["CTRL-DLP-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.25,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 2,
        },
        "approval_workflow": {"required_roles": ["owner", "admin"], "sla_minutes": 15, "default_if_timeout": "block"},
    },
    {
        "guardian_id": "tool_output_injection",
        "description": "Detects malicious tool output intended to alter agent behavior.",
        "enabled": True,
        "trigger": {
            "signal_types": ["tool.output"],
            "conditions": [
                {"field": "tool_output", "operator": "regex", "value": "(?i)<script|ignore safety|override policy", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.7},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["response"], "strategy": "mask"},
            "mutate_output": {"enabled": True, "strategy": "restricted_template"},
            "notify": {"channels": ["slack"]},
            "create_ticket": {"system": "jira", "severity": "med"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.tool_output_injection.detected",
            "link_to_controls": ["CTRL-TOOL-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.1,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 1,
        },
    },
    {
        "guardian_id": "rag_poisoning_stub",
        "description": "Stub guardian for poisoned RAG context markers.",
        "enabled": True,
        "trigger": {
            "signal_types": ["context.rag"],
            "conditions": [
                {"field": "context_summary", "operator": "contains", "value": "untrusted source override", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "model_stub", "confidence_threshold": 0.6},
        "decision": {"on_pass": "allow", "on_fail": "hold_for_approval", "on_uncertain": "hold_for_approval"},
        "actions": {
            "redact": {"fields": ["context"], "strategy": "summarize"},
            "mutate_output": {"enabled": True, "strategy": "restricted_template"},
            "notify": {"channels": ["email"]},
            "create_ticket": {"system": "servicenow", "severity": "high"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.rag_poisoning.detected",
            "link_to_controls": ["CTRL-RAG-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.2,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 2,
        },
        "approval_workflow": {"required_roles": ["owner", "admin"], "sla_minutes": 20, "default_if_timeout": "block"},
    },
    {
        "guardian_id": "cross_context_leakage_stub",
        "description": "Stub guardian for cross-tenant or cross-context leakage patterns.",
        "enabled": True,
        "trigger": {
            "signal_types": ["context.rag", "prompt.text"],
            "conditions": [
                {"field": "prompt.text", "operator": "contains", "value": "other tenant", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "hybrid", "confidence_threshold": 0.8},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "hold_for_approval"},
        "actions": {
            "redact": {"fields": ["context", "response"], "strategy": "remove"},
            "mutate_output": {"enabled": True, "strategy": "safe_completion"},
            "notify": {"channels": ["teams"]},
            "create_ticket": {"system": "jira", "severity": "critical"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.cross_context_leakage.detected",
            "link_to_controls": ["CTRL-TENANT-ISO-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.3,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 2,
        },
    },
]

PILOT_SAFE_AI_DOMAINS: list[str] = [
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "gemini.google.com",
    "perplexity.ai",
    "www.perplexity.ai",
]

PILOT_BROWSER_AUTOMATION_ALLOWED_ACTIONS: list[str] = [
    "page_view",
    "search",
    "scroll",
    "navigate",
    "read_content",
]

PILOT_BROWSER_AUTOMATION_BLOCKED_ACTIONS: list[str] = [
    "add_to_cart",
    "checkout",
    "purchase_now",
    "payment_submit",
    "submit_form",
    "upload_file",
    "send_message",
    "send_email",
    "delete_item",
    "change_settings",
    "invite_user",
    "create_api_key",
    "access_admin_console",
    "access_payment_page",
    "access_credentials_page",
    "credential_submit",
]

SUPPORTED_SECTORS = {
    "banking",
    "insurance",
    "healthcare",
    "pharma",
    "oil_and_gas",
    "retail",
    "government",
    "legal",
    "education",
    "manufacturing",
    "technology",
    "telecom",
    "defense",
    "energy",
    "generic_enterprise",
}

DEFAULT_FUNCTION_PURPOSES: dict[str, list[str]] = {
    "engineering": ["software_engineering", "security_analysis", "internal_productivity"],
    "security": ["security_analysis", "software_engineering", "internal_productivity"],
    "risk": ["risk_analysis", "fraud_aml_research", "regulatory_research", "compliance_analysis"],
    "compliance": ["compliance_analysis", "regulatory_research", "fraud_aml_research", "risk_analysis"],
    "finance": ["finance_analysis", "internal_productivity"],
    "procurement": ["procurement_business", "facilities_business", "internal_productivity"],
    "legal": ["legal_review", "regulatory_research", "internal_productivity"],
    "marketing": ["sales_marketing_approved", "internal_productivity"],
    "sales": ["sales_marketing_approved", "customer_support_drafting", "internal_productivity"],
    "customer_support": ["customer_support_drafting", "internal_productivity"],
    "operations": ["operations_support", "internal_productivity"],
    "facilities": ["facilities_business", "procurement_business", "internal_productivity"],
    "hr": ["hr_approved", "internal_productivity"],
    "executive": ["internal_productivity", "finance_analysis", "risk_analysis"],
    "unknown": [],
}

SECTOR_PURPOSES: dict[str, list[str]] = {
    "banking": [
        "sector_research",
        "regulatory_research",
        "risk_analysis",
        "compliance_analysis",
        "fraud_aml_research",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
        "approved_customer_support_drafting",
        "customer_support_drafting",
    ],
    "insurance": [
        "sector_research",
        "regulatory_research",
        "risk_analysis",
        "compliance_analysis",
        "finance_analysis",
        "customer_support_drafting",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "healthcare": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "pharma": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "oil_and_gas": [
        "sector_research",
        "regulatory_research",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "retail": [
        "sector_research",
        "sales_marketing_approved",
        "customer_support_drafting",
        "finance_analysis",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "government": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "procurement_business",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "legal": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "legal_review",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "education": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "manufacturing": [
        "sector_research",
        "regulatory_research",
        "operations_support",
        "procurement_business",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "technology": [
        "sector_research",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
        "operations_support",
        "customer_support_drafting",
    ],
    "telecom": [
        "sector_research",
        "regulatory_research",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "defense": [
        "sector_research",
        "regulatory_research",
        "compliance_analysis",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "energy": [
        "sector_research",
        "regulatory_research",
        "operations_support",
        "software_engineering",
        "security_analysis",
        "internal_productivity",
    ],
    "generic_enterprise": [
        "sector_research",
        "internal_productivity",
        "software_engineering",
        "security_analysis",
        "customer_support_drafting",
        "procurement_business",
        "finance_analysis",
        "legal_review",
        "operations_support",
    ],
}

REGULATED_DATA_TYPES: dict[str, list[str]] = {
    "banking": ["customer_account", "card_payment", "transaction", "kyc", "credit_model", "secret"],
    "insurance": ["policyholder", "claims", "underwriting", "actuarial", "member_data", "secret"],
    "healthcare": ["phi", "patient_record", "member_data", "secret"],
    "pharma": ["trial_participant", "unreleased_ip", "manufacturing_secret", "secret"],
    "oil_and_gas": ["ot_credential", "plant_diagram", "production_config", "field_data", "secret"],
    "retail": ["customer_pii", "payment_card", "loyalty_data", "supplier_contract", "secret"],
    "government": ["citizen_data", "classified_data", "law_enforcement", "identity_document", "secret"],
    "legal": ["privileged_legal_data", "legal_strategy", "client_matter", "contract_terms", "secret"],
    "education": ["student_record", "grades", "guardian_data", "admissions", "secret"],
    "manufacturing": ["plant_diagram", "supplier_contract", "production_config", "quality_data", "secret"],
    "technology": ["proprietary_source_code", "production_config", "customer_pii", "telemetry", "secret"],
    "telecom": ["subscriber_data", "call_detail_record", "network_config", "lawful_intercept", "secret"],
    "defense": ["classified_data", "export_controlled_data", "mission_data", "cleared_identity", "secret"],
    "energy": ["grid_config", "plant_diagram", "ot_credential", "production_config", "secret"],
    "generic_enterprise": ["customer_pii", "secret", "production_data"],
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _token_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    return [str(value).strip()] if str(value).strip() else []


def _strictness_decision(strictness: str, *, default: str = "review") -> str:
    normalized = _norm(strictness)
    if normalized in {"monitor"}:
        return "allow"
    if normalized in {"shadow"}:
        return "shadow_would_block"
    if normalized in {"warn"}:
        return "warn"
    if normalized in {"review"}:
        return "review"
    if normalized in {"block"}:
        return "block"
    return default


def _control_mode_for_boundary_decision(decision: str, *, source_surface: str) -> str:
    normalized = _norm(decision)
    inline = _norm(source_surface) in {"browser", "browser_extension", "gateway", "mcp", "sdk", "proxy"}
    if normalized == "block":
        return "inline_prevented" if inline else "external_required"
    if normalized == "allow":
        return "inline_allowed" if inline else "detected_only"
    if normalized == "warn":
        return "warned"
    if normalized in {"shadow", "shadow_would_block"}:
        return "shadow_would_block"
    if normalized in {"review", "require_justification", "require_approval"}:
        return "external_required"
    return "incomplete"


def _tenant_sector_profile(db: Session, *, tenant_id: str) -> TenantSectorProfile | None:
    return db.scalar(
        select(TenantSectorProfile)
        .where(TenantSectorProfile.tenant_id == tenant_id)
        .order_by(TenantSectorProfile.updated_at.desc())
    )


def ensure_business_purpose_defaults(
    db: Session,
    *,
    tenant_id: str,
    sector: str = "generic_enterprise",
    strictness: str = "review",
) -> dict[str, Any]:
    normalized_sector = _norm(sector)
    if normalized_sector not in SUPPORTED_SECTORS:
        normalized_sector = "generic_enterprise"
    profile = _tenant_sector_profile(db, tenant_id=tenant_id)
    if profile is None:
        profile = TenantSectorProfile(
            tenant_id=tenant_id,
            sector=normalized_sector,
            strictness=_norm(strictness) or "review",
            regulated_data_types=REGULATED_DATA_TYPES.get(normalized_sector, REGULATED_DATA_TYPES["generic_enterprise"]),
            approved_business_purposes=SECTOR_PURPOSES.get(normalized_sector, SECTOR_PURPOSES["generic_enterprise"]),
            blocked_business_purposes=[
                "personal_use",
                "unrelated_consumer_research",
                "shopping_purchase",
                "travel_booking_personal",
                "gambling",
                "adult_content",
                "non_business_entertainment",
                "personal_financial_advice",
                "unapproved_medical_advice",
                "unknown",
            ],
            approved_destinations=["internal", "approved_ai", "managed_gateway"],
            blocked_destinations=["public_ai_for_sensitive_data"],
            coding_policy_id="coding_sql_safe_mode/default",
            sql_policy_id="coding_sql_safe_mode/sql/default",
            exception_policy_id="business_purpose_exception/default",
        )
        db.add(profile)
    else:
        profile.sector = normalized_sector
        profile.strictness = _norm(strictness) or profile.strictness or "review"
        profile.regulated_data_types = REGULATED_DATA_TYPES.get(normalized_sector, REGULATED_DATA_TYPES["generic_enterprise"])
        profile.approved_business_purposes = SECTOR_PURPOSES.get(normalized_sector, SECTOR_PURPOSES["generic_enterprise"])

    existing_functions = {
        row.name
        for row in db.scalars(select(BusinessFunctionProfile).where(BusinessFunctionProfile.tenant_id == tenant_id)).all()
    }
    for function_name, allowed_purposes in DEFAULT_FUNCTION_PURPOSES.items():
        if function_name in existing_functions:
            continue
        db.add(
            BusinessFunctionProfile(
                tenant_id=tenant_id,
                name=function_name,
                description=f"Default {function_name.replace('_', ' ')} business function.",
                allowed_purposes=allowed_purposes,
                blocked_purposes=["personal_use", "unrelated_consumer_research", "shopping_purchase"],
                allowed_actions=["prompt_submit", "copy_output", "file_upload", "repo_context_read"],
                review_required_actions=["file_write", "create_pr", "trigger_pipeline", "terminal_command"],
                blocked_actions=["payment_submit", "purchase_now", "credential_submit", "secret_access_attempt"],
                allowed_destinations=["internal", "approved_ai", "managed_gateway"],
                blocked_destinations=["public_ai_for_sensitive_data"],
            )
        )
    db.flush()
    return {
        "sector_profile_id": profile.id,
        "sector": profile.sector,
        "strictness": profile.strictness,
        "business_function_count": len(DEFAULT_FUNCTION_PURPOSES),
    }


def _mapping_matches_claim(row: UserBusinessFunctionMapping, claims: dict[str, Any]) -> bool:
    claim_name = _norm(row.claim_name)
    claim_value = _norm(row.claim_value)
    if not claim_name or not claim_value:
        return False
    claim_payload = claims.get(claim_name)
    values = [_norm(item) for item in _token_list(claim_payload)]
    return claim_value in values


def resolve_user_business_context(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None = None,
    email: str | None = None,
    claims: dict[str, Any] | None = None,
    extension_role_hint: str | None = None,
) -> dict[str, Any]:
    normalized_email = _norm(email)
    claim_payload = claims if isinstance(claims, dict) else {}
    rows = db.scalars(
        select(UserBusinessFunctionMapping)
        .where(UserBusinessFunctionMapping.tenant_id == tenant_id, UserBusinessFunctionMapping.enabled.is_(True))
        .order_by(UserBusinessFunctionMapping.priority.desc(), UserBusinessFunctionMapping.updated_at.desc())
    ).all()

    candidates: list[UserBusinessFunctionMapping] = []
    for row in rows:
        if row.user_id and user_id and row.user_id == user_id:
            candidates.append(row)
            continue
        if row.email and normalized_email and _norm(row.email) == normalized_email:
            candidates.append(row)
            continue
        if _mapping_matches_claim(row, claim_payload):
            candidates.append(row)

    if candidates:
        selected = candidates[0]
        return {
            "user_id": user_id,
            "email": email,
            "resolved_business_function": _norm(selected.business_function) or "unknown",
            "resolved_role": selected.role_name,
            "resolved_department": selected.department,
            "resolved_policy_groups": list(selected.policy_groups or []),
            "source": selected.source,
            "confidence": "high" if selected.email or selected.user_id else "medium",
            "mapping_id": selected.id,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "fallback_used": False,
            "ignored_extension_role_hint": extension_role_hint,
            "candidate_mapping_ids": [row.id for row in candidates],
        }

    return {
        "user_id": user_id,
        "email": email,
        "resolved_business_function": "unknown",
        "resolved_role": "unknown",
        "resolved_department": None,
        "resolved_policy_groups": ["unknown"],
        "source": "default_unknown",
        "confidence": "low",
        "mapping_id": None,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "fallback_used": True,
        "ignored_extension_role_hint": extension_role_hint,
        "candidate_mapping_ids": [],
    }


def classify_code_sql_context(text: str | None) -> dict[str, Any]:
    raw = str(text or "")
    lowered = raw.lower()
    code_detected = bool(
        re.search(r"\b(def|class|function|import|const|let|var|public\s+class|select\s+.+\s+from)\b", lowered)
        or "```" in raw
    )
    sql_detected = bool(re.search(r"\b(select|insert|update|delete|drop|alter|truncate|create)\b", lowered) and " from " in f" {lowered} ")
    secrets_detected = bool(
        re.search(r"(?i)(sk-live-[a-z0-9_-]{8,}|api[_-]?key\s*[:=]|private[_ -]?key|password\s*[:=]|connectionstring|connection string)", raw)
    )
    destructive_sql = bool(re.search(r"\b(drop|truncate|delete|update|alter)\b", lowered))
    customer_sql = bool(
        sql_detected
        and re.search(r"\b(customer|account|card|kyc|transaction|recipient|claims|policyholder|patient)\w*", lowered)
    )
    production_sql = bool(sql_detected and re.search(r"\b(prod|production|live|real customer|account_number)\b", lowered))
    synthetic_sql = bool(sql_detected and re.search(r"\b(sample|synthetic|example|demo|test)\b", lowered))
    schema_only = bool(sql_detected and re.search(r"\b(create table|schema|ddl)\b", lowered) and not customer_sql)

    if secrets_detected:
        sql_type = "query_with_credentials" if sql_detected else "unknown"
    elif destructive_sql:
        sql_type = "destructive_sql"
    elif customer_sql:
        sql_type = "customer_data_sql"
    elif production_sql:
        sql_type = "production_sql"
    elif schema_only:
        sql_type = "schema_only"
    elif synthetic_sql:
        sql_type = "synthetic_sql"
    elif sql_detected:
        sql_type = "unknown"
    else:
        sql_type = "unknown"

    code_type = "unknown"
    if code_detected:
        if secrets_detected:
            code_type = "production"
        elif re.search(r"\b(prod|production|customer|internal repo|auth|payment|rbac|iam)\b", lowered):
            code_type = "production"
        elif re.search(r"\b(sample|synthetic|example|demo)\b", lowered):
            code_type = "generic"
        else:
            code_type = "generic"

    return {
        "code_detected": code_detected,
        "language": "sql" if sql_detected else ("python" if re.search(r"\bdef |import \w+", lowered) else None),
        "code_type": code_type,
        "repo_context_detected": bool(re.search(r"\b(repo|branch|pull request|\\.env|package.json|requirements.txt)\b", lowered)),
        "repo_sensitivity": "high" if re.search(r"\b(auth|payment|iam|rbac|prod|production|\\.env)\b", lowered) else "unknown",
        "sql_detected": sql_detected,
        "sql_type": sql_type,
        "secrets_detected": secrets_detected,
        "production_identifiers_detected": bool(production_sql or re.search(r"\b(prod|production|live|account_number)\b", lowered)),
        "safe_for_public_ai": not any([secrets_detected, destructive_sql, customer_sql, production_sql]),
    }


def classify_business_purpose(text: str | None, *, business_function: str = "unknown") -> dict[str, Any]:
    raw = str(text or "")
    lowered = raw.lower()
    category = "unknown"
    confidence = "low"

    if re.search(r"\b(python|javascript|typescript|sql|code|parser|debug|unit test|function|library|framework|software architecture)\b", lowered) or re.search(
        r"\bselect\s+.+\s+from\b", lowered
    ):
        category = "software_engineering"
        confidence = "high"
    if re.search(r"\b(aml|kyc|basel|regulatory|regulation|compliance|sanctions|hipaa|public sector|defense compliance)\b", lowered):
        category = "compliance_analysis"
        confidence = "high"
    if re.search(r"\b(fraud|risk|credit model|loss|anomaly|underwriting|claims|actuarial)\b", lowered):
        category = "risk_analysis"
        confidence = "high"
    if re.search(r"\b(vulnerability|security|threat|secret scanning|secure coding)\b", lowered):
        category = "security_analysis"
        confidence = "high"
    if re.search(r"\b(clinical trial|quality documentation|scientific literature|formulation)\b", lowered):
        category = "regulatory_research"
        confidence = "high"
    if re.search(r"\b(hipaa|healthcare operations|healthcare policy)\b", lowered):
        category = "compliance_analysis"
        confidence = "high"
    if re.search(r"\b(vendor|boq|bill of quantity|scope of work|sow|procurement|branch renovation|office|facility)\b", lowered):
        category = "procurement_business" if business_function == "procurement" else "facilities_business"
        confidence = "high"
    if re.search(r"\b(hse|maintenance procedure|refinery|equipment|student services|education policy|manufacturing|plant maintenance|network operations|telecom|grid maintenance|energy operations)\b", lowered):
        category = "operations_support"
        confidence = "high"
    if re.search(r"\b(merchandising|product research|inventory analytics|marketing copy)\b", lowered):
        category = "sales_marketing_approved"
        confidence = "high"
    if re.search(r"\b(nda|contract clause|legal review|legal strategy|privileged)\b", lowered):
        category = "legal_review"
        confidence = "high"
    if re.search(r"\b(internal productivity|workflow summary|productivity workflow)\b", lowered):
        category = "internal_productivity"
        confidence = "medium"
    if re.search(r"\b(customer support|reply to customer|support draft|case response)\b", lowered):
        category = "customer_support_drafting"
        confidence = "medium"
    if re.search(
        r"\b(coffee[- ]spend|spend(?:ing)? summary|transaction summary|summarize (?:my|the current customer's) (?:coffee )?spend)\b",
        lowered,
    ):
        category = "customer_support_drafting"
        confidence = "high"
    if re.search(r"\b(sofa|perfume|personal|apartment|home|holiday|vacation|shopping)\b", lowered):
        if not re.search(r"\b(branch|office|renovation|procurement|facility|vendor|boq|sow)\b", lowered):
            category = "unrelated_consumer_research"
            confidence = "high"

    purpose_status = "unknown"
    if category in {"personal_use", "unrelated_consumer_research", "shopping_purchase", "travel_booking_personal"}:
        purpose_status = "personal"
    elif category != "unknown":
        purpose_status = "approved"

    return {
        "declared_purpose": None,
        "inferred_purpose": category,
        "purpose_category": category,
        "purpose_confidence": confidence,
        "purpose_status": purpose_status,
    }


def _sensitive_data_context(text: str | None) -> dict[str, Any]:
    raw = str(text or "")
    lowered = raw.lower()
    has_card = bool(re.search(r"\b(?:\d[ -]*?){13,19}\b", raw) or "credit card" in lowered or "card " in lowered)
    has_customer = bool(re.search(r"\b(customer|client|account|kyc|transaction|recipient|policyholder|patient)\b", lowered))
    has_business_email = bool(re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", raw, re.IGNORECASE))
    return {
        "has_card_or_payment_data": has_card,
        "has_customer_data": has_customer,
        "has_business_email": has_business_email,
        "has_regulated_data": bool(has_card or (has_customer and has_business_email)),
    }


def evaluate_business_purpose_boundary(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    email: str | None,
    prompt_text: str | None,
    action_type: str,
    destination_domain: str | None,
    destination_trust_level: str | None,
    source_surface: str,
    claims: dict[str, Any] | None = None,
    extension_role_hint: str | None = None,
) -> dict[str, Any]:
    profile = _tenant_sector_profile(db, tenant_id=tenant_id)
    if profile is None:
        ensure_business_purpose_defaults(db, tenant_id=tenant_id)
        profile = _tenant_sector_profile(db, tenant_id=tenant_id)
    assert profile is not None

    role_resolution = resolve_user_business_context(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        claims=claims,
        extension_role_hint=extension_role_hint,
    )
    business_function = _norm(role_resolution.get("resolved_business_function")) or "unknown"
    purpose = classify_business_purpose(prompt_text, business_function=business_function)
    code_context = classify_code_sql_context(prompt_text)
    sensitive = _sensitive_data_context(prompt_text)
    if sensitive["has_regulated_data"]:
        code_context["safe_for_public_ai"] = False

    function_profile = db.scalar(
        select(BusinessFunctionProfile).where(
            BusinessFunctionProfile.tenant_id == tenant_id,
            BusinessFunctionProfile.name == business_function,
        )
    )
    allowed_purposes = set(_token_list(profile.approved_business_purposes))
    if function_profile is not None:
        allowed_purposes.update(_token_list(function_profile.allowed_purposes))
    purpose_category = _norm(purpose.get("purpose_category")) or "unknown"
    role_allowed = purpose_category in allowed_purposes or purpose_category == "software_engineering"
    public_destination = _norm(destination_trust_level) == "public" or _norm(destination_domain) in {
        "chatgpt.com",
        "chat.openai.com",
        "claude.ai",
        "gemini.google.com",
        "perplexity.ai",
    }

    decision = "allow"
    reason = "business_purpose_aligned"
    finding_type: str | None = None

    if role_resolution["fallback_used"]:
        decision = _strictness_decision(profile.strictness, default="review")
        if decision == "allow":
            decision = "review"
        reason = "user_role_unresolved_for_ai_policy"
        finding_type = "USER_ROLE_UNRESOLVED_FOR_AI_POLICY"
    elif code_context["secrets_detected"]:
        decision = "block"
        reason = "secret_in_code_prompt"
        finding_type = "SECRET_IN_CODE_PROMPT"
    elif public_destination and sensitive["has_regulated_data"]:
        decision = "block"
        reason = "industry_regulated_data_to_public_ai"
        finding_type = "INDUSTRY_REGULATED_DATA_TO_PUBLIC_AI"
    elif code_context["sql_type"] in {"customer_data_sql", "query_with_credentials"}:
        decision = "block"
        reason = "customer_data_sql_to_ai"
        finding_type = "CUSTOMER_DATA_SQL_TO_AI"
    elif code_context["sql_type"] in {"production_sql", "destructive_sql"}:
        decision = "block"
        reason = "production_sql_to_ai"
        finding_type = "PRODUCTION_SQL_TO_AI" if code_context["sql_type"] == "production_sql" else "DESTRUCTIVE_SQL_AI_REQUEST"
    elif purpose_category == "software_engineering" and code_context["safe_for_public_ai"]:
        decision = "allow"
        reason = "generic_coding_help_allowed"
    elif role_allowed and purpose_category != "unknown":
        decision = "allow"
        reason = "business_purpose_aligned"
    elif purpose_category in {"unrelated_consumer_research", "personal_use", "shopping_purchase", "travel_booking_personal"}:
        decision = _strictness_decision(profile.strictness, default="review")
        reason = "business_purpose_mismatch"
        finding_type = "UNRELATED_CONSUMER_RESEARCH" if purpose_category == "unrelated_consumer_research" else "UNAPPROVED_PERSONAL_AI_USE"
    elif not role_allowed:
        decision = _strictness_decision(profile.strictness, default="review")
        reason = "role_purpose_violation"
        finding_type = "ROLE_PURPOSE_VIOLATION"

    business_purpose = {
        "sector_profile_id": profile.id,
        "tenant_sector": profile.sector,
        "tenant_sub_sector": profile.sub_sector,
        "business_function": business_function,
        "resolved_role": role_resolution.get("resolved_role"),
        "declared_purpose": purpose.get("declared_purpose"),
        "inferred_purpose": purpose.get("inferred_purpose"),
        "purpose_category": purpose_category,
        "purpose_confidence": purpose.get("purpose_confidence"),
        "sector_relevance_score": 1.0 if purpose_category in allowed_purposes else 0.1,
        "business_relevance_score": 1.0 if role_allowed else 0.1,
        "purpose_status": "approved" if purpose_category in allowed_purposes or role_allowed else purpose.get("purpose_status"),
        "role_allowed": role_allowed,
        "project_allowed": True,
        "exception_id": None,
        "purpose_drift_detected": False,
    }
    if reason == "business_purpose_mismatch":
        business_purpose["purpose_status"] = "unrelated"

    return {
        "decision": decision,
        "reason": reason,
        "finding_type": finding_type,
        "control_mode": _control_mode_for_boundary_decision(decision, source_surface=source_surface),
        "policy_id": "business_purpose_boundary",
        "control_ids": ["BUSINESS_PURPOSE_BOUNDARY"],
        "role_resolution": role_resolution,
        "business_purpose": business_purpose,
        "code_context": code_context,
        "sensitive_data_context": sensitive,
        "destination": {
            "domain": destination_domain,
            "trust_level": destination_trust_level,
        },
    }

PILOT_BROWSER_AUTOMATION_BLOCKLIST: list[str] = [
    "admin.microsoft.com",
    "portal.azure.com",
    "entra.microsoft.com",
    "console.aws.amazon.com",
    "okta.com",
]


def build_intent_aware_action_control_policy(*, tenant_id: str, mode: str = "block") -> dict[str, Any]:
    return {
        "policy_id": "pilot_intent_aware_ai_action_control",
        "schema_version": "intent-aware-ai-action-control/v1",
        "name": "Pilot Intent-Aware AI Action Control",
        "category": "INTENT_AWARE_AI_ACTION_CONTROL",
        "mode": mode if mode in {"monitor", "shadow", "warn", "block"} else "block",
        "enabled": True,
        "scope": {
            "users": [],
            "groups": [],
            "tenant_id": tenant_id,
            "surfaces": ["browser_extension"],
            "applications": ["ChatGPT", "Claude", "Gemini", "Perplexity"],
            "domains": list(PILOT_SAFE_AI_DOMAINS),
            "destination_trust_levels": ["public", "unknown"],
        },
        "allowed_intents": [
            "public_research",
            "company_lookup",
            "market_research",
            "competitor_research",
            "generic_drafting",
            "drafting_generic",
            "summarization",
            "coding_help",
        ],
        "blocked_intents": [
            "credential_or_secret_handling",
            "customer_data_processing",
            "data_export",
            "purchasing_or_payment",
            "admin_or_security_change",
        ],
        "intent_action_rules": [
            {
                "intent_category": "public_research",
                "allowed_actions": ["browse", "search", "read", "view", "navigate", "summarize", "copy_output"],
                "blocked_actions": ["scrape_emails", "export_contacts", "download_output", "export_output", "share_output"],
                "input_sensitivity_threshold": "medium",
                "output_sensitivity_threshold": "medium",
                "destination_trust_level": "public",
                "decision": "block",
            },
            {
                "intent_category": "sales_outreach",
                "allowed_actions": ["draft", "rewrite", "summarize"],
                "blocked_actions": ["prompt_submit", "file_upload", "upload", "export_contacts"],
                "input_sensitivity_threshold": "medium",
                "output_sensitivity_threshold": "medium",
                "destination_trust_level": "public",
                "decision": "block",
            },
            {
                "intent_category": "credential_or_secret_handling",
                "allowed_actions": [],
                "blocked_actions": ["prompt_submit", "copy_output", "download_output", "export_output", "share_output"],
                "input_sensitivity_threshold": "low",
                "output_sensitivity_threshold": "low",
                "destination_trust_level": "public",
                "decision": "block",
            },
        ],
        "copy_export_rules": [
            {
                "output_contains": ["business_email", "customer_contact", "secret_like_value"],
                "output_sensitivity_threshold": "medium",
                "action": "copy_output",
                "decision": "block",
            },
            {
                "output_contains": ["business_email", "customer_contact", "secret_like_value"],
                "output_sensitivity_threshold": "medium",
                "action": "download_output",
                "decision": "block",
            },
            {
                "output_contains": ["business_email", "customer_contact", "secret_like_value"],
                "output_sensitivity_threshold": "medium",
                "action": "export_output",
                "decision": "block",
            },
        ],
        "alignment_rules": [
            {
                "intent_category": "public_research",
                "out_of_scope_actions": ["export_contacts", "send_email", "purchase", "payment", "credential_submit"],
                "decision": "block",
            }
        ],
    }


def _build_pilot_guardians() -> list[dict[str, Any]]:
    guardians = deepcopy(DEFAULT_GUARDIANS)
    for guardian in guardians:
        guardian_id = str(guardian.get("guardian_id") or "").strip().lower()
        decision = guardian.get("decision")
        if not isinstance(decision, dict):
            decision = {}
        if guardian_id in {"prompt_injection", "jailbreak"}:
            decision["on_fail"] = "warn"
            decision["on_uncertain"] = "warn"
        elif guardian_id == "sensitive_data_leakage":
            decision["on_fail"] = "block"
            decision["on_uncertain"] = "warn"
            trigger = guardian.get("trigger")
            if not isinstance(trigger, dict):
                trigger = {"signal_types": ["prompt.text"], "conditions": []}
            conditions = trigger.get("conditions")
            if not isinstance(conditions, list):
                conditions = []
            conditions.append(
                {
                    "field": "prompt.text",
                    "operator": "regex",
                    "value": r"(?i)(api[_\s-]?key|secret|private\s*key|token|ssn|credit\s*card)",
                    "case_sensitive": False,
                }
            )
            trigger["conditions"] = conditions
            guardian["trigger"] = trigger
        guardian["decision"] = decision
    return guardians


def build_default_policy_contract(pack_id: str, created_by: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": f"{pack_id}-v1",
        "pack_id": pack_id,
        "version": "1.0.0",
        "created_at": now,
        "created_by": created_by,
        "scope": {
            "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "applies_to_ai_system_ids": None,
            "applies_to_actor_types": ["human", "agent", "system"],
        },
        "enforcement_defaults": {
            "default_decision": "allow",
            "escalation": "notify",
        },
        "guardian_contracts": deepcopy(DEFAULT_GUARDIANS),
    }


def build_pilot_policy_contract(pack_id: str, created_by: str, tenant_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    browser_automation_control = {
        "policy_id": "pilot_browser_automation_control",
        "name": "Pilot Browser Automation Control",
        "category": "BROWSER_AUTOMATION_CONTROL",
        "mode": "block",
        "enabled": True,
        "scope": {
            "users": [],
            "groups": [],
            "tenant_id": tenant_id,
            "surfaces": ["browser_extension"],
            "domains_allowlist": list(PILOT_SAFE_AI_DOMAINS),
            "domains_blocklist": list(PILOT_BROWSER_AUTOMATION_BLOCKLIST),
            "url_patterns_allowlist": [],
            "url_patterns_blocklist": [],
        },
        "automation": {
            "detection_required": True,
            "confidence_threshold": 0.6,
            "sources": [
                "browser_visible",
                "extension_marker",
                "agentic_browser_marker",
                "scripted_input",
                "rapid_navigation",
                "automated_click_cadence",
                "suspected_local_agent",
                "unknown",
            ],
        },
        "allowed_actions": list(PILOT_BROWSER_AUTOMATION_ALLOWED_ACTIONS),
        "blocked_actions": list(PILOT_BROWSER_AUTOMATION_BLOCKED_ACTIONS),
        "action_overrides": [
            {
                "name": "Amazon Browsing Only",
                "domains": ["amazon.com", "www.amazon.com"],
                "allowed_actions": ["page_view", "search", "navigate", "read_content"],
                "blocked_actions": ["add_to_cart", "checkout", "purchase_now", "payment_submit"],
            }
        ],
        "decisions": {
            "on_allowed_browsing": "allow",
            "on_automation_detected": "warn",
            "on_blocked_domain": "block",
            "on_disallowed_domain": "warn",
            "on_blocked_action": "block",
            "on_scope_violation": "block",
            "on_unknown_automation_source": "warn",
            "on_sensitive_data_or_secret": "block",
        },
    }
    intent_aware_action_control = build_intent_aware_action_control_policy(tenant_id=tenant_id, mode="block")

    return {
        "id": f"{pack_id}-pilot",
        "pack_id": pack_id,
        "version": "1.0.0-pilot.1",
        "created_at": now,
        "created_by": created_by,
        "profile": "pilot_p0_safe_defaults",
        "scope": {
            "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "applies_to_ai_system_ids": None,
            "applies_to_actor_types": ["human", "agent", "system"],
            "browser_automation_control": browser_automation_control,
            "intent_aware_action_control": intent_aware_action_control,
        },
        "enforcement_defaults": {
            "default_decision": "allow",
            "escalation": "notify",
        },
        "guardian_contracts": _build_pilot_guardians(),
        "browser_automation_control": browser_automation_control,
        "intent_aware_action_control": intent_aware_action_control,
    }


def _policy_version_sort_key(row: PolicyVersion) -> tuple[Any, ...]:
    created_at = row.created_at
    if created_at and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    created_at = created_at or datetime.min.replace(tzinfo=timezone.utc)

    try:
        parsed = semver.VersionInfo.parse(row.version)
        semver_key = (
            parsed.major,
            parsed.minor,
            parsed.patch,
            parsed.prerelease or "",
            parsed.build or "",
        )
    except ValueError:
        semver_key = (0, 0, 0, "", row.version)

    return (created_at, *semver_key, row.id)


def get_latest_policy_for_ai_system(db: Session, tenant_id: str, ai_system: AISystem, actor_type: str) -> PolicyVersion | None:
    rows = db.scalars(
        select(PolicyVersion)
        .join(PolicyPack, PolicyVersion.pack_id == PolicyPack.id)
        .where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyPack.tenant_id == tenant_id,
            PolicyPack.status == "active",
        )
    ).all()
    rows = sorted(rows, key=_policy_version_sort_key, reverse=True)

    for row in rows:
        scope = row.scope or {}
        tiers = scope.get("applies_to_risk_tiers") or []
        ids = scope.get("applies_to_ai_system_ids")
        actors = scope.get("applies_to_actor_types")

        tier_ok = ai_system.risk_tier in tiers
        id_ok = not ids or ai_system.id in ids
        actor_ok = not actors or actor_type in actors

        if tier_ok and id_ok and actor_ok:
            return row
    return None


def _escalate_decision_mode(value: str | None, *, steps: int = 1) -> str:
    normalized = str(value or "allow").strip().lower()
    ladder = ["allow", "warn", "block"]
    if normalized == "redact":
        normalized = "warn"
    if normalized == "hold_for_approval":
        return "hold_for_approval"
    if normalized not in ladder:
        normalized = "allow"
    idx = ladder.index(normalized)
    return ladder[min(len(ladder) - 1, idx + max(1, int(steps)))]


def tighten_enforcement_for_failed_controls(
    db: Session,
    *,
    tenant_id: str,
    control_ids: list[str],
    reason: str,
    escalation_level: int = 1,
    ai_system_id: str | None = None,
) -> list[str]:
    updated_versions: list[str] = []
    escalation = max(1, min(3, int(escalation_level or 1)))

    latest_versions = db.scalars(
        select(PolicyVersion)
        .join(PolicyPack, PolicyVersion.pack_id == PolicyPack.id)
        .where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyPack.status == "active",
        )
        .order_by(desc(PolicyVersion.created_at))
    ).all()

    for version in latest_versions:
        changed = False
        scope = deepcopy(version.scope or {})
        enforcement_defaults = deepcopy(version.enforcement_defaults or {})
        guardians = deepcopy(version.guardian_contracts or [])

        current_default_decision = str(enforcement_defaults.get("default_decision") or "allow")
        next_default_decision = _escalate_decision_mode(current_default_decision, steps=escalation)
        if next_default_decision != current_default_decision:
            enforcement_defaults["default_decision"] = next_default_decision
            changed = True

        current_escalation = str(enforcement_defaults.get("escalation") or "notify").strip().lower()
        desired_escalation = "block" if escalation >= 3 else ("approval" if escalation >= 2 else "notify")
        if current_escalation != desired_escalation:
            enforcement_defaults["escalation"] = desired_escalation
            changed = True

        for guardian in guardians:
            links = ((guardian.get("evidence") or {}).get("link_to_controls") or [])
            impact = guardian.get("control_impact") or {}
            if not set(links).intersection(control_ids):
                continue
            if int(impact.get("enforcement_strictness_increase", 0)) <= 0:
                continue

            decision = guardian.get("decision") or {}
            current_on_uncertain = str(decision.get("on_uncertain") or "warn")
            desired_on_uncertain = (
                "hold_for_approval"
                if escalation >= 2
                else _escalate_decision_mode(current_on_uncertain, steps=1)
            )
            if desired_on_uncertain != current_on_uncertain:
                decision["on_uncertain"] = desired_on_uncertain
                changed = True

            current_on_fail = str(decision.get("on_fail") or "warn")
            desired_on_fail = _escalate_decision_mode(
                current_on_fail,
                steps=max(1, escalation + int(impact.get("enforcement_strictness_increase", 0)) - 1),
            )
            if desired_on_fail != current_on_fail:
                decision["on_fail"] = desired_on_fail
                changed = True

            if escalation >= 2:
                current_on_pass = str(decision.get("on_pass") or "allow")
                desired_on_pass = _escalate_decision_mode(current_on_pass, steps=1)
                if desired_on_pass != current_on_pass:
                    decision["on_pass"] = desired_on_pass
                    changed = True

            guardian["decision"] = decision

        if not changed:
            continue

        try:
            parsed = semver.VersionInfo.parse(version.version)
            next_version = str(parsed.bump_patch())
        except ValueError:
            next_version = f"{version.version}.1"

        contract = deepcopy(version.contract_json)
        contract["version"] = next_version
        contract["created_at"] = datetime.now(timezone.utc).isoformat()
        contract["guardian_contracts"] = guardians
        contract["scope"] = scope
        contract["enforcement_defaults"] = enforcement_defaults
        contract["tightened_reason"] = reason
        contract["tightening"] = {
            "escalation_level": escalation,
            "ai_system_id": ai_system_id,
            "control_ids": sorted({str(item) for item in control_ids if str(item).strip()}),
        }

        new_version = PolicyVersion(
            tenant_id=version.tenant_id,
            pack_id=version.pack_id,
            version=next_version,
            created_by=version.created_by,
            scope=scope,
            enforcement_defaults=enforcement_defaults,
            guardian_contracts=guardians,
            contract_json=contract,
        )
        db.add(new_version)
        db.flush()
        updated_versions.append(new_version.id)

    return updated_versions
