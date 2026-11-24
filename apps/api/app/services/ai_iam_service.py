from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.control_engine.canonical_action import ALLOWED_CONTROL_MODES, trusted_parameter_hash_binding
from app.core.security import token_hash
from app.db.models.ai_iam import AgentActionBaseline, AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.policy import ApprovalRequest, BusinessPurposeSession


def _normalize_dt(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalized_scope_set(values: list[str] | None) -> set[str]:
    out: set[str] = set()
    for value in values or []:
        normalized = str(value).strip().lower()
        if normalized:
            out.add(normalized)
    return out


def _reduced_scopes_for_non_inheritance(scopes: list[str]) -> list[str]:
    reduced: list[str] = []
    for scope in scopes:
        normalized = str(scope).strip()
        if not normalized:
            continue
        lower = normalized.lower()
        if lower.endswith(".read") or lower.startswith("read.") or lower == "tool.read":
            reduced.append(normalized)
    if not reduced:
        return ["tool.read"]
    return sorted(set(reduced))


def _clamp_score(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


RISK_RANK = {"low": 1, "medium": 2, "med": 2, "high": 3, "critical": 4}
HIGH_RISK_ACTION_TOKENS = {
    "add_to_cart",
    "admin",
    "checkout",
    "credential",
    "delete",
    "execute",
    "payment",
    "purchase",
    "submit",
    "upload",
    "write",
}
READ_ACTION_TOKENS = {"browse", "get", "list", "navigate", "read", "search", "view"}
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@([\w.-]+\.\w+)\b", re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"\b(?:api[_\s-]?key|secret|token|password)\b\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_\-./+=]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|ghp|xox[baprs])[_-][A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
INTERNAL_DOMAIN_TOKENS = {"internal", "intranet", "corp", "company", "localhost", "acme.ai"}
PUBLIC_EMAIL_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"}
SENSITIVITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

INTENT_CATEGORIES = {
    "public_research",
    "company_lookup",
    "market_research",
    "competitor_research",
    "drafting_generic",
    "generic_drafting",
    "summarization",
    "coding_help",
    "legal_review",
    "financial_analysis",
    "customer_support",
    "internal_data_processing",
    "customer_data_processing",
    "sales_outreach",
    "credential_or_secret_handling",
    "data_export",
    "external_communication",
    "purchasing_or_payment",
    "admin_or_security_change",
    "tool_execution",
    "unknown",
}
RESEARCH_ALLOWED_ACTIONS = {"browse", "search", "read", "view", "navigate", "summarize", "copy_output", "prompt_submit"}
RESEARCH_BLOCKED_ACTIONS = {
    "scrape_emails",
    "export_contacts",
    "download_output",
    "export_output",
    "share_output",
    "send_email",
    "email_send",
    "form_submit",
    "purchase",
    "payment",
    "checkout",
    "credential_submit",
    "upload",
    "account_create",
}
COPY_EXPORT_ACTIONS = {"copy_output", "download_output", "export_output", "share_output", "paste_output_to_external_site"}


def _lower_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalized_lower_list(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    for value in values:
        token = _lower_token(value)
        if token and token not in out:
            out.append(token)
    return out


def _normalize_policy_action(value: Any) -> str:
    action = _lower_token(value)
    if action in {"allow", "redact", "block", "step_up"}:
        return action
    if action in {"hold_for_approval", "require_approval", "require_justification"}:
        return "step_up"
    return "block"


def _overlap(left: list[str], right: list[str]) -> bool:
    return bool(set(left).intersection(set(right)))


def evaluate_need_to_know_policy(
    *,
    policy: dict[str, Any],
    identity: dict[str, Any],
    knowledge_asset: dict[str, Any],
    prompt_intent: str | None = None,
    business_context: str | None = None,
) -> dict[str, Any]:
    """Evaluate whether an identity may receive a knowledge asset in context."""
    policy_id = str(policy.get("policy_id") or policy.get("id") or "need_to_know_policy").strip()
    asset_id = str(knowledge_asset.get("asset_id") or knowledge_asset.get("id") or "").strip()
    sensitivity_domain = _lower_token(
        knowledge_asset.get("sensitivity_domain")
        or knowledge_asset.get("domain")
        or knowledge_asset.get("sensitive_knowledge_domain")
    )
    policy_domains = _normalized_lower_list(policy.get("sensitive_knowledge_domains"))
    identity_roles = _normalized_lower_list(identity.get("roles"))
    identity_groups = _normalized_lower_list(identity.get("groups"))
    identity_contexts = _normalized_lower_list(
        [
            identity.get("business_context"),
            identity.get("context"),
            identity.get("purpose"),
            business_context,
        ]
    )
    asset_roles = _normalized_lower_list(knowledge_asset.get("allowed_roles"))
    asset_groups = _normalized_lower_list(knowledge_asset.get("allowed_groups"))
    asset_contexts = _normalized_lower_list(knowledge_asset.get("allowed_contexts"))
    policy_roles = _normalized_lower_list(policy.get("allowed_roles"))
    policy_groups = _normalized_lower_list(policy.get("allowed_groups"))
    policy_contexts = _normalized_lower_list(policy.get("allowed_contexts"))
    allowed_roles = policy_roles or asset_roles
    allowed_groups = policy_groups or asset_groups
    allowed_contexts = policy_contexts or asset_contexts
    disallowed_query_types = _normalized_lower_list(policy.get("disallowed_query_types"))
    prompt_type = _lower_token(prompt_intent)
    action = _normalize_policy_action(policy.get("action"))
    reasons: list[str] = []

    if policy_domains and sensitivity_domain and sensitivity_domain not in policy_domains:
        return {
            "decision": "allow",
            "reason": "need_to_know_policy_not_applicable",
            "policy_id": policy_id,
            "sensitivity_domain": sensitivity_domain or None,
            "evidence_refs": [asset_id] if asset_id else [],
        }

    if allowed_roles or allowed_groups:
        if not _overlap(identity_roles, allowed_roles) and not _overlap(identity_groups, allowed_groups):
            reasons.append("role_or_group_not_allowed")

    if allowed_contexts and not _overlap(identity_contexts, allowed_contexts):
        reasons.append("context_not_allowed")

    if disallowed_query_types and prompt_type in disallowed_query_types:
        reasons.append("query_type_disallowed")

    if reasons:
        return {
            "decision": action,
            "reason": ",".join(reasons),
            "policy_id": policy_id,
            "sensitivity_domain": sensitivity_domain or None,
            "evidence_refs": [asset_id] if asset_id else [],
        }

    return {
        "decision": "allow",
        "reason": "need_to_know_satisfied",
        "policy_id": policy_id,
        "sensitivity_domain": sensitivity_domain or None,
        "evidence_refs": [asset_id] if asset_id else [],
    }


def _metadata_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _risk_rank(value: Any) -> int:
    return RISK_RANK.get(_lower_token(value), 0)


def _sensitivity_at_least(value: str | None, threshold: str | None) -> bool:
    return SENSITIVITY_RANK.get(_lower_token(value), 0) >= SENSITIVITY_RANK.get(_lower_token(threshold), 0)


def _email_domains(text: str) -> list[str]:
    out: list[str] = []
    for match in EMAIL_PATTERN.finditer(text or ""):
        domain = _lower_token(match.group(1))
        if domain and domain not in out:
            out.append(domain)
    return out


def _business_email_count(text: str) -> int:
    count = 0
    for domain in _email_domains(text):
        if domain not in PUBLIC_EMAIL_DOMAINS:
            count += len(re.findall(rf"\b[\w.+-]+@{re.escape(domain)}\b", text or "", flags=re.IGNORECASE))
    return count


def classify_intent_context(
    *,
    declared_intent: str | None = None,
    text: str | None = None,
    action_type: str | None = None,
    business_context: str | None = None,
    classifier_source: str = "rules",
) -> dict[str, Any]:
    source_text = " ".join(
        item for item in [declared_intent, text, action_type, business_context] if str(item or "").strip()
    )
    normalized = _lower_token(source_text)
    declared = _lower_token(declared_intent)
    action = _lower_token(action_type)
    category = "unknown"
    inferred = "unknown"
    confidence = 0.45

    explanation = "Intent could not be confidently inferred from the available browser/action context."

    if declared and any(token in declared for token in {"market research", "market analysis"}):
        category = "market_research"
        inferred = category
        confidence = 0.84
        explanation = "Declared intent references market research against public/business context."
    elif declared and any(token in declared for token in {"competitor", "competitive"}):
        category = "competitor_research"
        inferred = category
        confidence = 0.84
        explanation = "Declared intent references competitor research."
    elif declared and any(token in declared for token in {"look up", "lookup", "research", "company"}):
        category = "company_lookup" if "company" in declared or "look up" in declared or "lookup" in declared else "public_research"
        inferred = category
        confidence = 0.82
        explanation = "Declared intent is bounded to public research or company lookup."
    elif any(token in normalized for token in {"api key", "apikey", "secret", "credential", "password", "private key", "token"}):
        category = "credential_or_secret_handling"
        inferred = "secret_or_credential_handling"
        confidence = 0.86
        explanation = "Prompt/action context contains credential or secret-handling terms."
    elif any(token in normalized for token in {"admin", "permission", "create user", "security setting", "api key"}):
        category = "admin_or_security_change"
        inferred = "admin_or_security_change"
        confidence = 0.82
        explanation = "Context references administrative or security configuration actions."
    elif any(token in normalized for token in {"send email", "send this email", "email this", "post to", "share with"}):
        category = "external_communication"
        inferred = "external_communication"
        confidence = 0.82
        explanation = "Context references external communication or sharing."
    elif any(token in normalized for token in {"outreach", "prospect", "sales email", "lead list", "campaign"}):
        category = "sales_outreach"
        inferred = "sales_outreach"
        confidence = 0.82
        explanation = "Context references sales outreach, leads, prospects, or campaign activity."
    elif any(token in normalized for token in {"crm", "customer", "contact list", "email list", "client list"}):
        category = "customer_data_processing"
        inferred = "customer_data_processing"
        confidence = 0.78
        explanation = "Context references customer, CRM, contact, or client data."
    elif any(token in normalized for token in {"export", "download", "csv", "spreadsheet"}):
        category = "data_export"
        inferred = "data_export"
        confidence = 0.76
        explanation = "Context references exporting, downloading, or structured data movement."
    elif any(token in normalized for token in {"purchase", "payment", "checkout", "buy", "add to cart"}):
        category = "purchasing_or_payment"
        inferred = "purchasing_or_payment"
        confidence = 0.85
        explanation = "Context references purchasing, payment, or checkout activity."
    elif any(token in normalized for token in {"code", "debug", "function", "typescript", "python", "sql"}):
        category = "coding_help"
        inferred = "coding_help"
        confidence = 0.72
        explanation = "Context references coding, debugging, or software implementation help."
    elif any(token in normalized for token in {"legal", "contract", "terms", "msa", "nda"}):
        category = "legal_review"
        inferred = "legal_review"
        confidence = 0.74
        explanation = "Context references legal or contract review."
    elif any(token in normalized for token in {"financial analysis", "revenue", "forecast", "budget", "p&l"}):
        category = "financial_analysis"
        inferred = "financial_analysis"
        confidence = 0.74
        explanation = "Context references financial analysis or planning."
    elif any(token in normalized for token in {"support ticket", "customer support", "helpdesk"}):
        category = "customer_support"
        inferred = "customer_support"
        confidence = 0.74
        explanation = "Context references customer support workflows."
    elif any(token in normalized for token in {"market research", "market analysis"}):
        category = "market_research"
        inferred = category
        confidence = 0.78
        explanation = "Context references market research."
    elif any(token in normalized for token in {"competitor", "competitive"}):
        category = "competitor_research"
        inferred = category
        confidence = 0.78
        explanation = "Context references competitor research."
    elif any(token in normalized for token in {"look up", "lookup", "research", "company", "website", "what do they do"}):
        category = "company_lookup" if "company" in normalized or "look up" in normalized or "lookup" in normalized else "public_research"
        inferred = category
        confidence = 0.78
        explanation = "Context is bounded to public research or company lookup."
    elif any(token in normalized for token in {"summarize", "summary", "condense"}):
        category = "summarization"
        inferred = "summarization"
        confidence = 0.72
        explanation = "Context asks for summarization."
    elif any(token in normalized for token in {"draft", "rewrite", "write a", "compose"}) and "email" not in normalized:
        category = "generic_drafting"
        inferred = "generic_drafting"
        confidence = 0.68
        explanation = "Context asks for generic drafting or rewriting without sensitive workflow indicators."
    elif action in {"tool_execution", "tool.run", "api_call"}:
        category = "tool_execution"
        inferred = "tool_execution"
        confidence = 0.7
        explanation = "Action context is a generic tool execution without a clearer business intent."

    if _lower_token(declared_intent) and category == "unknown":
        category = "public_research" if "research" in _lower_token(declared_intent) else "unknown"
        inferred = category
        confidence = 0.6 if category != "unknown" else confidence
        if category != "unknown":
            explanation = "Declared intent references research but lacks more specific indicators."

    return {
        "declared_intent": declared_intent,
        "inferred_intent": inferred,
        "intent_category": category if category in INTENT_CATEGORIES else "unknown",
        "intent_confidence": round(_clamp_score(confidence), 2),
        "business_context": business_context,
        "action_alignment": "unknown",
        "classifier_source": classifier_source if classifier_source in {"rules", "local_classifier", "llm_assisted", "manual", "unknown"} else "rules",
        "explanation": explanation,
    }


def _file_text_preview_chunks(file_meta: list[dict[str, Any]] | None) -> list[str]:
    chunks: list[str] = []
    for item in file_meta or []:
        if not isinstance(item, dict):
            continue
        for field in ("text_preview", "content_preview", "extracted_text", "ocr_text", "text"):
            value = str(item.get(field) or "").strip()
            if value:
                chunks.append(value)
                break
    return chunks


def classify_input_content_context(text: str | None, *, file_meta: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    value = "\n".join(item for item in [str(text or ""), *_file_text_preview_chunks(file_meta)] if item.strip())
    lower = value.lower()
    email_domains = _email_domains(value)
    business_email_count = _business_email_count(value)
    contains_secret = any(pattern.search(value) for pattern in SECRET_PATTERNS)
    contains_api_keys = bool(re.search(r"\b(?:api[_\s-]?key)\b\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_\-./+=]{8,}", value, re.IGNORECASE))
    contains_passwords = bool(re.search(r"\bpassword\b\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_\-./+=]{8,}", value, re.IGNORECASE))
    contains_private_keys = bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", value))
    contains_internal_domain = any(token in lower for token in INTERNAL_DOMAIN_TOKENS if token != "company")
    contains_customer_data = any(token in lower for token in {"customer", "client", "crm", "contact list", "prospect"})
    file_names = [str((item or {}).get("name") or "") for item in (file_meta or []) if isinstance(item, dict)]
    csv_like_upload = any(name.lower().endswith((".csv", ".xlsx", ".xls")) for name in file_names)
    contains_crm_like_table = bool(
        re.search(r"\b(?:name|email|company|account|customer|prospect)\s*,\s*(?:name|email|company|account|customer|prospect)\b", lower)
        or (
            csv_like_upload
            and business_email_count >= 2
            and any(token in lower for token in {"company", "account", "prospect", "customer", "crm"})
        )
    )
    contains_contract_data = any(token in lower for token in {"contract", "msa", "nda", "terms and conditions", "legal review"})
    contains_financial = any(token in lower for token in {"iban", "bank account", "invoice", "credit card", "payment"})
    contains_code = bool(re.search(r"\b(?:function|class|def|import|select\s+.+\s+from|api endpoint|source code)\b", lower))
    contains_confidential = any(token in lower for token in {"confidential", "internal only", "do not disclose", "project aurora"})

    matched: list[str] = []
    if contains_secret:
        matched.append("secret_or_api_key")
    if business_email_count:
        matched.append("business_email")
    if contains_customer_data:
        matched.append("customer_data")
    if contains_internal_domain:
        matched.append("internal_domain")
    if contains_financial:
        matched.append("financial_data")
    if contains_code:
        matched.append("code_or_ip")
    if contains_confidential:
        matched.append("confidential_terms")
    if csv_like_upload or contains_crm_like_table:
        matched.append("structured_upload")

    sensitivity = "none"
    if contains_secret:
        sensitivity = "critical"
    elif csv_like_upload and (business_email_count or contains_customer_data or contains_crm_like_table):
        sensitivity = "high"
    elif contains_crm_like_table and business_email_count:
        sensitivity = "high"
    elif business_email_count >= 3 or (business_email_count and contains_customer_data):
        sensitivity = "high"
    elif business_email_count or contains_customer_data or contains_financial or contains_confidential:
        sensitivity = "medium"
    elif email_domains or contains_internal_domain or contains_code:
        sensitivity = "low"

    return {
        "contains_secrets": contains_secret,
        "contains_api_keys": contains_api_keys,
        "contains_passwords": contains_passwords,
        "contains_private_keys": contains_private_keys,
        "contains_business_emails": business_email_count > 0,
        "business_email_count": business_email_count,
        "contains_personal_emails": any(domain in PUBLIC_EMAIL_DOMAINS for domain in email_domains),
        "contains_customer_data": contains_customer_data or business_email_count >= 3 or contains_crm_like_table,
        "contains_crm_like_table": contains_crm_like_table,
        "contains_contract_data": contains_contract_data,
        "contains_internal_domain": contains_internal_domain,
        "contains_employee_data": any(token in lower for token in {"employee", "staff", "hr record"}),
        "contains_financial_data": contains_financial,
        "contains_source_code": contains_code,
        "contains_code_or_ip": contains_code,
        "contains_confidential_terms": contains_confidential,
        "sensitivity_level": sensitivity,
        "matched_indicators": sorted(set(matched)),
    }


def classify_output_context(*, output_text: str | None = None, output_ref: str | None = None) -> dict[str, Any]:
    value = str(output_text or "")
    lower = value.lower()
    business_email_count = _business_email_count(value)
    contains_secret = any(pattern.search(value) for pattern in SECRET_PATTERNS)
    contains_internal_domain = any(token in lower for token in INTERNAL_DOMAIN_TOKENS if token != "company")
    contains_customer_contact = business_email_count > 0 and any(token in lower for token in {"customer", "client", "contact", "email", "proposal"})
    contains_employee_contact = business_email_count > 0 and any(token in lower for token in {"employee", "staff", "team", "hr"})
    contains_template = any(token in lower for token in {"dear customer", "signature", "confidential", "internal template"})
    contains_proprietary_style = any(token in lower for token in {"brand voice", "proprietary style", "internal template", "signature block"})
    contains_regulated = any(token in lower for token in {"ssn", "passport", "emirates id", "credit card", "iban"})
    matched: list[str] = []
    if business_email_count:
        matched.append("business_email")
    if contains_secret:
        matched.append("secret_like_value")
    if contains_internal_domain:
        matched.append("internal_domain")
    if contains_customer_contact:
        matched.append("customer_contact")
    if contains_template:
        matched.append("confidential_style_or_template")
    if contains_regulated:
        matched.append("regulated_data")

    sensitivity = "none"
    if contains_secret or contains_regulated:
        sensitivity = "critical"
    elif contains_customer_contact or business_email_count >= 3:
        sensitivity = "high"
    elif business_email_count or contains_internal_domain or contains_template:
        sensitivity = "medium"
    elif value.strip():
        sensitivity = "low"

    return {
        "output_ref": output_ref,
        "contains_business_email": business_email_count > 0,
        "business_email_count": business_email_count,
        "contains_internal_domain": contains_internal_domain,
        "contains_customer_contact": contains_customer_contact,
        "contains_employee_contact": contains_employee_contact,
        "contains_secret_like_value": contains_secret,
        "contains_confidential_style_or_template": contains_template,
        "contains_confidential_template": contains_template,
        "contains_proprietary_style": contains_proprietary_style,
        "contains_regulated_data": contains_regulated,
        "output_sensitivity": sensitivity,
        "matched_indicators": sorted(set(matched)),
    }


def evaluate_action_alignment(
    *,
    intent_context: dict[str, Any],
    action_type: str,
    input_content_context: dict[str, Any] | None = None,
    output_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    intent_category = _lower_token((intent_context or {}).get("intent_category")) or "unknown"
    attempted_action = _lower_token(action_type) or "unknown"
    action_category = action_category_for(attempted_action)
    input_level = (input_content_context or {}).get("sensitivity_level")
    output_level = (output_context or {}).get("output_sensitivity")

    alignment = "unknown"
    reason = "insufficient_intent_context"
    recommended = "allow"

    if intent_category in {"company_lookup", "public_research", "market_research", "competitor_research"}:
        if attempted_action in RESEARCH_BLOCKED_ACTIONS or action_category in {"financial", "credential", "admin"}:
            alignment = "out_of_scope"
            reason = "research_intent_action_out_of_scope"
            recommended = "block"
        elif attempted_action in RESEARCH_ALLOWED_ACTIONS or action_category == "read":
            alignment = "aligned"
            reason = "research_intent_aligned"
        else:
            alignment = "suspicious"
            reason = "research_intent_unusual_action"
            recommended = "warn"
    elif intent_category in {"sales_outreach", "customer_data_processing"}:
        if _sensitivity_at_least(str(input_level or "none"), "high") and attempted_action in {"prompt_submit", "upload", "file_upload"}:
            alignment = "out_of_scope"
            reason = "customer_data_to_public_ai"
            recommended = "block"
        else:
            alignment = "suspicious" if attempted_action in COPY_EXPORT_ACTIONS else "aligned"
            reason = "customer_data_requires_policy"
            recommended = "warn" if alignment == "suspicious" else "allow"
    elif intent_category in {"drafting_generic", "generic_drafting", "summarization", "coding_help"}:
        if _sensitivity_at_least(str(input_level or "none"), "medium") or _sensitivity_at_least(str(output_level or "none"), "medium"):
            alignment = "suspicious"
            reason = "generic_intent_with_sensitive_content"
            recommended = "warn"
        else:
            alignment = "aligned"
            reason = "generic_intent_aligned"
    elif intent_category in {"credential_or_secret_handling", "admin_or_security_change", "purchasing_or_payment"}:
        alignment = "suspicious"
        reason = f"{intent_category}_requires_control"
        recommended = "block" if action_category in {"credential", "admin", "financial"} else "warn"
    elif intent_category in {"external_communication", "data_export"}:
        alignment = "suspicious"
        reason = f"{intent_category}_requires_review"
        recommended = "warn"
    else:
        alignment = "unknown"
        reason = "intent_unknown"
        recommended = "warn" if action_category in {"write", "execute", "admin", "credential", "financial"} else "allow"

    return {
        "declared_or_inferred_intent": (intent_context or {}).get("declared_intent")
        or (intent_context or {}).get("inferred_intent")
        or intent_category,
        "attempted_action": attempted_action,
        "alignment": alignment,
        "reason": reason,
        "recommended_decision": recommended,
    }


def evaluate_intent_aware_action_control(
    *,
    intent_context: dict[str, Any],
    input_content_context: dict[str, Any] | None,
    output_context: dict[str, Any] | None,
    action_alignment_result: dict[str, Any],
    action_type: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy_map = _metadata_dict(policy)
    mode = _lower_token(policy_map.get("mode")) or "block"
    action = _lower_token(action_type)
    input_ctx = input_content_context or {}
    output_ctx = output_context or {}
    alignment = _lower_token((action_alignment_result or {}).get("alignment"))
    recommended = _lower_token((action_alignment_result or {}).get("recommended_decision")) or "allow"
    reason = "public_research_allowed"
    finding_type: str | None = None
    base_decision = "allow"

    if input_ctx.get("contains_secrets") or output_ctx.get("contains_api_keys") or output_ctx.get("contains_secret_like_value"):
        base_decision = "block"
        reason = "secret_or_credential_detected"
        finding_type = "SECRET_OR_CREDENTIAL_TO_AI"
    elif alignment == "out_of_scope" and (action_alignment_result or {}).get("reason") == "research_intent_action_out_of_scope":
        base_decision = "block"
        reason = "research_intent_action_out_of_scope"
        finding_type = "INTENT_ACTION_SCOPE_VIOLATION"
    elif action in COPY_EXPORT_ACTIONS and (
        output_ctx.get("contains_business_email")
        or output_ctx.get("contains_customer_contact")
        or _sensitivity_at_least(str(output_ctx.get("output_sensitivity") or "none"), "high")
    ):
        base_decision = "block"
        reason = "output_copy_export_contains_business_contact_data"
        finding_type = "AI_OUTPUT_COPY_BLOCKED"
    elif input_ctx.get("contains_crm_like_table") and input_ctx.get("contains_business_emails"):
        base_decision = "block"
        reason = "crm_contact_data_to_public_ai"
        finding_type = "CRM_DATA_TO_PUBLIC_AI"
    elif input_ctx.get("contains_business_emails") or input_ctx.get("contains_customer_data"):
        if _sensitivity_at_least(str(input_ctx.get("sensitivity_level") or "none"), "medium"):
            base_decision = "block"
            reason = "business_email_or_customer_data_to_ai"
            finding_type = "BUSINESS_EMAIL_DATA_TO_AI" if input_ctx.get("contains_business_emails") else "CUSTOMER_CONTACT_DATA_TO_AI"
    elif alignment == "out_of_scope" or recommended == "block":
        base_decision = "block"
        reason = (action_alignment_result or {}).get("reason") or "intent_action_scope_violation"
        finding_type = "INTENT_ACTION_SCOPE_VIOLATION"
    elif alignment == "suspicious" or recommended == "warn":
        base_decision = "warn"
        reason = (action_alignment_result or {}).get("reason") or "intent_action_requires_review"
        finding_type = "AGENT_ACTION_OUTSIDE_DECLARED_INTENT" if "agent" in action else None

    if base_decision == "allow" and (intent_context or {}).get("intent_category") in {"company_lookup", "public_research", "market_research", "competitor_research"}:
        finding_type = "PUBLIC_RESEARCH_ALLOWED"
        reason = "public_research_allowed"

    decision = base_decision
    if mode in {"monitor", "detect", "detected_only"} and base_decision in {"block", "warn"}:
        decision = "allow"
    elif mode == "shadow" and base_decision == "block":
        decision = "allow"
        reason = f"shadow_would_block:{reason}"
    elif mode == "warn" and base_decision == "block":
        decision = "warn"

    return {
        "policy_category": "INTENT_AWARE_AI_ACTION_CONTROL",
        "decision": decision,
        "would_decision": base_decision,
        "mode": mode,
        "decision_reason": reason,
        "finding_type": finding_type,
        "intent_category": (intent_context or {}).get("intent_category"),
        "action_alignment": alignment or "unknown",
        "matched_indicators": sorted(
            {
                *[str(item) for item in input_ctx.get("matched_indicators", []) if str(item).strip()],
                *[str(item) for item in output_ctx.get("matched_indicators", []) if str(item).strip()],
            }
        ),
        "copy_export_control_applied": action in COPY_EXPORT_ACTIONS,
    }


def build_intent_aware_evidence_summary(
    *,
    intent_context: dict[str, Any] | None,
    input_content_context: dict[str, Any] | None,
    output_context: dict[str, Any] | None,
    action_alignment_result: dict[str, Any] | None,
    intent_aware_decision: dict[str, Any] | None,
    action_type: str | None,
    action_risk: str | None = None,
    destination_context: dict[str, Any] | None = None,
    policy_snapshot: dict[str, Any] | None = None,
    control_mode: str | None = None,
) -> dict[str, Any]:
    input_ctx = input_content_context or {}
    output_ctx = output_context or {}
    decision_ctx = intent_aware_decision or {}
    return {
        "input_classification_summary": {
            "sensitivity_level": input_ctx.get("sensitivity_level"),
            "contains_secrets": bool(input_ctx.get("contains_secrets")),
            "contains_business_emails": bool(input_ctx.get("contains_business_emails")),
            "contains_customer_data": bool(input_ctx.get("contains_customer_data")),
            "contains_crm_like_table": bool(input_ctx.get("contains_crm_like_table")),
            "business_email_count": int(input_ctx.get("business_email_count") or 0),
        },
        "output_classification_summary": {
            "output_sensitivity": output_ctx.get("output_sensitivity"),
            "contains_business_email": bool(output_ctx.get("contains_business_email")),
            "contains_customer_contact": bool(output_ctx.get("contains_customer_contact")),
            "contains_secret_like_value": bool(output_ctx.get("contains_secret_like_value")),
            "business_email_count": int(output_ctx.get("business_email_count") or 0),
        },
        "intent_classification": dict(intent_context or {}),
        "action_classification": {
            "action_type": _lower_token(action_type) or "unknown",
            "action_risk": _lower_token(action_risk) or "unknown",
        },
        "alignment_result": dict(action_alignment_result or {}),
        "destination_context": dict(destination_context or {}),
        "policy_snapshot": dict(policy_snapshot or {}),
        "decision": dict(decision_ctx),
        "control_mode": str(control_mode or decision_ctx.get("mode") or "").strip() or None,
        "trace": [
            "intent_classified",
            "content_classified",
            "action_alignment_evaluated",
            "policy_evaluated",
            "evidence_recorded",
        ],
    }


def action_category_for(action_type: str | None) -> str:
    normalized = _lower_token(action_type)
    if any(token in normalized for token in {"credential", "password", "secret", "token", "api_key"}):
        return "credential"
    if any(token in normalized for token in {"delete", "admin", "permission", "invite", "settings"}):
        return "admin"
    if any(token in normalized for token in {"purchase", "payment", "checkout", "add_to_cart"}):
        return "financial"
    if any(token in normalized for token in {"write", "create", "update", "submit", "upload", "send", "post"}):
        return "write"
    if any(token in normalized for token in {"execute", "run", "shell"}):
        return "execute"
    if any(token in normalized for token in READ_ACTION_TOKENS):
        return "read"
    return "unknown"


def action_risk_for(action_type: str | None, *, environment: str | None = None) -> str:
    normalized = _lower_token(action_type)
    category = action_category_for(action_type)
    if category in {"credential", "admin", "financial"}:
        return "critical" if "prod" in _lower_token(environment) and category == "admin" else "high"
    if category in {"write", "execute"}:
        return "high" if "delete" in normalized or "submit" in normalized or "upload" in normalized else "medium"
    if category == "read":
        return "low"
    return "medium"


def canonicalize_authority_host(value: Any) -> str:
    """Return the canonical DNS host used for purpose-authority comparisons."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or ""
    except ValueError:
        return ""
    host = host.rstrip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def authority_value_matches(
    value: Any,
    allowed: list[str] | tuple[str, ...] | set[str],
    *,
    allow_prefix_glob: bool = False,
) -> bool:
    """Match normalized authority values exactly, plus explicitly supported globs."""
    normalized = _lower_token(value)
    patterns = _normalized_lower_list(allowed)
    if not normalized:
        return not patterns
    for pattern in patterns:
        if pattern == "*" or normalized == pattern:
            return True
        if allow_prefix_glob and pattern.endswith("/*"):
            prefix = pattern[:-2].rstrip("/")
            if prefix and (normalized == prefix or normalized.startswith(f"{prefix}/")):
                return True
    return False


def authority_host_matches(
    value: Any,
    allowed: list[str] | tuple[str, ...] | set[str],
) -> bool:
    """Match a canonical host exactly or at a DNS subdomain boundary."""
    normalized = canonicalize_authority_host(value)
    if not normalized:
        return not _normalized_lower_list(allowed)
    for raw_pattern in allowed:
        pattern_token = _lower_token(raw_pattern)
        if pattern_token == "*":
            return True
        if pattern_token.startswith("*."):
            pattern_token = pattern_token[2:]
        pattern = canonicalize_authority_host(pattern_token)
        if pattern and (normalized == pattern or normalized.endswith(f".{pattern}")):
            return True
    return False


def narrow_authority_values(
    server_values: list[str],
    requested_values: list[str],
    *,
    kind: str = "exact",
) -> list[str]:
    """Intersect caller scope with server authority without permitting widening."""
    server = _normalized_lower_list(server_values)
    requested = _normalized_lower_list(requested_values)
    if not server or not requested:
        return []
    if requested == ["*"] or "*" in requested:
        return server
    if "*" in server:
        return requested

    def matches(value: str, patterns: list[str]) -> bool:
        if kind == "domain":
            return authority_host_matches(value, patterns)
        return authority_value_matches(value, patterns, allow_prefix_glob=(kind == "resource"))

    narrowed: list[str] = []
    for requested_value in requested:
        if matches(requested_value, server):
            narrowed.append(requested_value)
            continue
        if kind == "domain":
            for server_value in server:
                if matches(server_value, [requested_value]) and server_value not in narrowed:
                    narrowed.append(server_value)
        # A caller prefix glob may narrow to concrete server entries, but can
        # never replace those entries with its broader pattern.
        if kind == "resource" and requested_value.endswith("/*"):
            for server_value in server:
                if matches(server_value, [requested_value]) and server_value not in narrowed:
                    narrowed.append(server_value)
    return narrowed


def purpose_confirmation_required(
    permission: dict[str, Any] | None,
    *,
    action_type: str,
    action_category: str | None = None,
    action_risk: str | None = None,
) -> bool:
    constraints = _metadata_dict((permission or {}).get("constraints"))
    if bool(constraints.get("require_human_confirmation")):
        return True
    required_for = _normalized_lower_list(constraints.get("approval_required_for"))
    candidates = [
        _lower_token(action_type),
        _lower_token(action_category),
        _lower_token(action_risk),
        f"action:{_lower_token(action_type)}",
        f"category:{_lower_token(action_category)}",
        f"risk:{_lower_token(action_risk)}",
    ]
    return any(authority_value_matches(candidate, required_for) for candidate in candidates if candidate)


def evaluate_purpose_bound_permission(
    *,
    permission: dict[str, Any] | None,
    action_type: str,
    action_category: str | None = None,
    action_risk: str | None = None,
    tool_name: str | None = None,
    target_resource: str | None = None,
    domain: str | None = None,
    environment: str | None = None,
    current_action_count: int = 0,
    now: datetime | None = None,
) -> dict[str, Any]:
    resolved_category = _lower_token(action_category) or action_category_for(action_type)
    resolved_risk = _lower_token(action_risk) or action_risk_for(action_type, environment=environment)
    high_risk = _risk_rank(resolved_risk) >= _risk_rank("high") or resolved_category in {"admin", "credential", "financial"}
    current_time = _normalize_dt(now or datetime.now(timezone.utc))

    if not permission:
        return {
            "decision": "block" if high_risk else "review",
            "reason": "purpose_bound_permission_required" if high_risk else "purpose_bound_permission_missing",
            "purpose_bound_permission_id": None,
            "violations": ["missing_purpose_bound_permission"],
            "mode": "block",
            "allowed": False,
        }

    purpose = _metadata_dict(permission.get("purpose"))
    scope = _metadata_dict(permission.get("scope"))
    constraints = _metadata_dict(permission.get("constraints"))
    permission_id = str(permission.get("permission_id") or permission.get("id") or "").strip() or None
    mode = _lower_token(permission.get("mode")) or "block"
    status = _lower_token(permission.get("status")) or "active"
    violations: list[str] = []

    if status != "active":
        violations.append(f"permission_status:{status}")

    expiry_raw = constraints.get("expiry") or permission.get("expiry")
    expiry_dt = None
    if expiry_raw:
        try:
            expiry_dt = datetime.fromisoformat(str(expiry_raw).replace("Z", "+00:00"))
            expiry_dt = _normalize_dt(expiry_dt)
        except ValueError:
            violations.append("permission_expiry_invalid")
    if expiry_dt is not None and expiry_dt <= current_time:
        violations.append("permission_expired")

    max_action_count = constraints.get("max_action_count")
    if max_action_count is not None:
        try:
            if int(current_action_count or 0) > int(max_action_count):
                violations.append("max_action_count_exceeded")
        except (TypeError, ValueError):
            violations.append("max_action_count_invalid")

    max_risk_level = _lower_token(constraints.get("max_risk_level"))
    if max_risk_level and _risk_rank(resolved_risk) > _risk_rank(max_risk_level):
        violations.append(f"risk_above_permission:{resolved_risk}")

    normalized_action = _lower_token(action_type)
    allowed_actions = _normalized_lower_list(scope.get("allowed_actions") or permission.get("allowed_actions"))
    blocked_actions = _normalized_lower_list(scope.get("blocked_actions") or permission.get("blocked_actions"))
    if authority_value_matches(normalized_action, blocked_actions) or authority_value_matches(
        resolved_category,
        blocked_actions,
    ):
        violations.append(normalized_action or resolved_category)
    if allowed_actions and not authority_value_matches(normalized_action, allowed_actions) and not authority_value_matches(
        resolved_category,
        allowed_actions,
    ):
        violations.append(normalized_action or "action")

    normalized_tool = _lower_token(tool_name)
    allowed_tools = _normalized_lower_list(scope.get("allowed_tools") or permission.get("allowed_tools"))
    blocked_tools = _normalized_lower_list(scope.get("blocked_tools") or permission.get("blocked_tools"))
    if normalized_tool and (
        authority_value_matches(normalized_tool, blocked_tools)
        or (allowed_tools and not authority_value_matches(normalized_tool, allowed_tools))
    ):
        violations.append(f"tool:{normalized_tool}")

    allowed_domains = _normalized_lower_list(scope.get("allowed_domains") or permission.get("allowed_domains"))
    blocked_domains = _normalized_lower_list(scope.get("blocked_domains") or permission.get("blocked_domains"))
    normalized_domain = canonicalize_authority_host(domain)
    if normalized_domain and authority_host_matches(normalized_domain, blocked_domains):
        violations.append(f"domain:{normalized_domain}")
    if allowed_domains and not authority_host_matches(normalized_domain, allowed_domains):
        violations.append(f"domain:{normalized_domain}")

    allowed_resources = _normalized_lower_list(scope.get("allowed_resources") or permission.get("allowed_resources"))
    blocked_resources = _normalized_lower_list(scope.get("blocked_resources") or permission.get("blocked_resources"))
    normalized_resource = _lower_token(target_resource)
    if normalized_resource and authority_value_matches(
        normalized_resource,
        blocked_resources,
        allow_prefix_glob=True,
    ):
        violations.append(f"resource:{normalized_resource}")
    if allowed_resources and not authority_value_matches(
        normalized_resource,
        allowed_resources,
        allow_prefix_glob=True,
    ):
        violations.append(f"resource:{normalized_resource}")

    allowed_environments = _normalized_lower_list(scope.get("allowed_environments") or permission.get("allowed_environments"))
    normalized_environment = _lower_token(environment) or "unknown"
    if allowed_environments and not authority_value_matches(normalized_environment, allowed_environments):
        violations.append(f"environment:{normalized_environment}")

    prohibited_intents = _normalized_lower_list(purpose.get("prohibited_intents"))
    declared_intent = _lower_token(purpose.get("declared_intent") or permission.get("declared_intent"))
    if declared_intent and declared_intent in prohibited_intents:
        violations.append(f"prohibited_intent:{declared_intent}")

    unique_violations = sorted(set(item for item in violations if item))
    if unique_violations:
        decision = "shadow_would_block" if mode == "shadow" else "block"
        return {
            "decision": decision,
            "reason": "action_outside_purpose_scope",
            "purpose_bound_permission_id": permission_id,
            "violations": unique_violations,
            "mode": mode,
            "allowed": False,
        }

    return {
        "decision": "allow",
        "reason": "purpose_bound_permission_allowed",
        "purpose_bound_permission_id": permission_id,
        "violations": [],
        "mode": mode,
        "allowed": True,
    }


def resolve_persisted_purpose_bound_permission(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    agent_id: str | None,
    caller_permission: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Resolve purpose authority from persisted tenant/user state.

    Caller permission data is never an authority source. This initial adapter keeps
    legacy behavior when no purpose permission is presented and no persisted
    session exists; once purpose authority is asserted, absence of a persisted
    tenant/user binding fails closed.
    """
    supplied = bool(caller_permission)

    list_fields = {
        "allowed_actions",
        "allowed_tools",
        "allowed_domains",
        "allowed_resources",
        "allowed_data_scopes",
        "allowed_data_scope",
        "allowed_environments",
        "blocked_actions",
        "blocked_tools",
        "blocked_domains",
        "blocked_resources",
        "connected_systems",
        "approval_required_for",
    }

    def _schema_valid(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        for nested_name in ("scope", "constraints", "context"):
            if nested_name in value and not isinstance(value[nested_name], dict):
                return False
        if "purpose" in value and not isinstance(value["purpose"], dict):
            return False
        containers = [value]
        containers.extend(
            nested
            for nested in (value.get("scope"), value.get("constraints"), value.get("context"))
            if isinstance(nested, dict)
        )
        for container in containers:
            for field in list_fields.intersection(container):
                field_value = container[field]
                if not isinstance(field_value, list):
                    return False
                if any(not isinstance(item, str) or not item.strip() for item in field_value):
                    return False
        for identity_field in ("tenant_id", "user_id", "initiating_user_id", "identity_id", "agent_id"):
            if identity_field in value and (
                not isinstance(value[identity_field], str) or not value[identity_field].strip()
            ):
                return False
        context_value = value.get("context") if isinstance(value.get("context"), dict) else {}
        for identity_field in ("tenant_id", "user_id", "initiating_user_id", "identity_id", "agent_id"):
            if identity_field in context_value and (
                not isinstance(context_value[identity_field], str) or not context_value[identity_field].strip()
            ):
                return False
        constraints = value.get("constraints") if isinstance(value.get("constraints"), dict) else {}
        context = value.get("context") if isinstance(value.get("context"), dict) else {}
        if "max_action_count" in constraints and (
            isinstance(constraints["max_action_count"], bool)
            or not isinstance(constraints["max_action_count"], int)
            or constraints["max_action_count"] < 0
        ):
            return False
        if "max_chain_depth" in context and (
            isinstance(context["max_chain_depth"], bool)
            or not isinstance(context["max_chain_depth"], int)
            or context["max_chain_depth"] < 1
        ):
            return False
        if "max_risk_level" in constraints and (
            not isinstance(constraints["max_risk_level"], str)
            or _lower_token(constraints["max_risk_level"]) not in RISK_RANK
        ):
            return False
        if "require_human_confirmation" in constraints and not isinstance(
            constraints["require_human_confirmation"],
            bool,
        ):
            return False
        for field, allowed_values in (
            ("status", {"active", "inactive", "revoked", "expired"}),
            ("mode", {"block", "shadow"}),
            ("identity_type", {"agent", "user"}),
        ):
            if field in value and (
                not isinstance(value[field], str) or _lower_token(value[field]) not in allowed_values
            ):
                return False
        return True

    if caller_permission is not None and not _schema_valid(caller_permission):
        return {
            "valid": False,
            "required": True,
            "reason": "caller_purpose_permission_schema_invalid",
            "permission": None,
            "session_id": None,
        }
    caller_assertions = dict(caller_permission or {})
    caller_assertion_context = (
        dict(caller_assertions.get("context") or {})
        if isinstance(caller_assertions.get("context"), dict)
        else {}
    )
    caller_identity_assertions = (
        (tenant_id, caller_assertions.get("tenant_id")),
        (user_id, caller_assertions.get("user_id")),
        (user_id, caller_assertions.get("initiating_user_id")),
        (agent_id, caller_assertions.get("identity_id")),
        (agent_id, caller_assertions.get("agent_id")),
        (user_id, caller_assertion_context.get("user_id")),
        (user_id, caller_assertion_context.get("initiating_user_id")),
        (agent_id, caller_assertion_context.get("identity_id")),
        (agent_id, caller_assertion_context.get("agent_id")),
        (tenant_id, caller_assertion_context.get("tenant_id")),
    )
    if any(
        asserted is not None and _lower_token(asserted) != _lower_token(authoritative)
        for authoritative, asserted in caller_identity_assertions
    ):
        return {
            "valid": False,
            "required": True,
            "reason": "caller_purpose_identity_conflict",
            "permission": None,
            "session_id": None,
        }
    if agent_id and caller_assertions.get("identity_type") is not None and _lower_token(
        caller_assertions.get("identity_type")
    ) != "agent":
        return {
            "valid": False,
            "required": True,
            "reason": "caller_purpose_permission_identity_type_invalid",
            "permission": None,
            "session_id": None,
        }
    if not user_id:
        return {
            "valid": not supplied,
            "required": supplied,
            "reason": "persisted_purpose_permission_required" if supplied else "no_purpose_permission_asserted",
            "permission": None,
            "session_id": None,
        }
    rows = list(db.scalars(
        select(BusinessPurposeSession)
        .where(
            BusinessPurposeSession.tenant_id == tenant_id,
            BusinessPurposeSession.user_id == user_id,
        )
        .order_by(BusinessPurposeSession.updated_at.desc(), BusinessPurposeSession.created_at.desc())
    ).all())
    if not rows:
        return {
            "valid": not supplied,
            "required": supplied,
            "reason": "persisted_purpose_permission_required" if supplied else "no_purpose_permission_asserted",
            "permission": None,
            "session_id": None,
        }
    current_time = _normalize_dt(now or datetime.now(timezone.utc))
    failure_reason = "persisted_purpose_permission_required"
    row: BusinessPurposeSession | None = None
    persisted: dict[str, Any] = {}
    effective_expiry: datetime | None = None
    for candidate in rows:
        status = _lower_token(candidate.status)
        if status != "active":
            failure_reason = "persisted_purpose_permission_inactive"
            continue
        if not _schema_valid(candidate.approved_scope):
            failure_reason = "persisted_purpose_permission_schema_invalid"
            continue
        candidate_scope = dict(candidate.approved_scope)
        if not candidate_scope:
            failure_reason = "persisted_purpose_scope_invalid"
            continue
        if agent_id and candidate_scope.get("identity_type") is not None and _lower_token(
            candidate_scope.get("identity_type")
        ) != "agent":
            failure_reason = "persisted_purpose_permission_identity_type_invalid"
            continue
        persisted_identity_id = _lower_token(candidate_scope.get("identity_id"))
        persisted_agent_id = _lower_token(candidate_scope.get("agent_id"))
        if persisted_identity_id and persisted_agent_id and persisted_identity_id != persisted_agent_id:
            failure_reason = "persisted_purpose_permission_schema_invalid"
            continue
        bound_agent = persisted_identity_id or persisted_agent_id
        if agent_id and not bound_agent:
            failure_reason = "persisted_purpose_permission_agent_binding_required"
            continue
        if agent_id and bound_agent != _lower_token(agent_id):
            failure_reason = "persisted_purpose_permission_agent_mismatch"
            continue
        persisted_tenant = _lower_token(candidate_scope.get("tenant_id"))
        persisted_user = _lower_token(candidate_scope.get("user_id"))
        if persisted_tenant and persisted_tenant != _lower_token(tenant_id):
            failure_reason = "persisted_purpose_permission_schema_invalid"
            continue
        if persisted_user and persisted_user != _lower_token(user_id):
            failure_reason = "persisted_purpose_permission_schema_invalid"
            continue
        expiry_values: list[datetime] = []
        if candidate.expires_at is not None:
            expiry_values.append(_normalize_dt(candidate.expires_at))
        persisted_constraints = (
            dict(candidate_scope.get("constraints") or {})
            if isinstance(candidate_scope.get("constraints"), dict)
            else {}
        )
        persisted_expiry_raw = persisted_constraints.get("expiry") or candidate_scope.get("expiry")
        if persisted_expiry_raw:
            try:
                expiry_values.append(
                    _normalize_dt(datetime.fromisoformat(str(persisted_expiry_raw).replace("Z", "+00:00")))
                )
            except ValueError:
                failure_reason = "persisted_purpose_permission_expiry_invalid"
                continue
        candidate_expiry = min(expiry_values) if expiry_values else None
        if candidate_expiry is not None and candidate_expiry <= current_time:
            failure_reason = "persisted_purpose_permission_expired"
            continue
        row = candidate
        persisted = candidate_scope
        effective_expiry = candidate_expiry
        break

    if row is None:
        return {
            "valid": False,
            "required": True,
            "reason": failure_reason,
            "permission": None,
            "session_id": None,
        }

    caller = dict(caller_permission or {})
    persisted_scope = dict(persisted.get("scope") or {}) if isinstance(persisted.get("scope"), dict) else {}
    caller_scope = dict(caller.get("scope") or {}) if isinstance(caller.get("scope"), dict) else {}
    caller_context = dict(caller.get("context") or {}) if isinstance(caller.get("context"), dict) else {}

    def _values(container: dict[str, Any], nested: dict[str, Any], key: str, *aliases: str) -> list[str]:
        explicit_lists = [
            _normalized_lower_list(source[name])
            for source in (nested, container)
            for name in (key, *aliases)
            if name in source
        ]
        if not explicit_lists:
            return []
        if key.startswith("blocked_"):
            combined: list[str] = []
            for values in explicit_lists:
                for value in values:
                    if value not in combined:
                        combined.append(value)
            return combined
        effective = explicit_lists[0]
        for values in explicit_lists[1:]:
            if "*" in effective:
                effective = values
            elif "*" not in values:
                requested = set(values)
                effective = [value for value in effective if value in requested]
        return effective

    def _provided(container: dict[str, Any], nested: dict[str, Any], key: str, *aliases: str) -> bool:
        return any(name in nested or name in container for name in (key, *aliases))

    merged_scope: dict[str, Any] = {}
    allow_fields = {
        "allowed_actions": (),
        "allowed_tools": (),
        "allowed_domains": (),
        "allowed_resources": (),
        "allowed_data_scopes": ("allowed_data_scope",),
        "allowed_environments": (),
    }
    if not any(_values(persisted, persisted_scope, key, *aliases) for key, aliases in allow_fields.items()):
        return {
            "valid": False,
            "required": True,
            "reason": "persisted_purpose_scope_invalid",
            "permission": None,
            "session_id": row.id,
        }
    caller_status = _lower_token(caller.get("status"))
    if caller_status and caller_status != "active":
        return {
            "valid": False,
            "required": True,
            "reason": "caller_purpose_permission_inactive",
            "permission": None,
            "session_id": row.id,
        }
    for key, aliases in allow_fields.items():
        server_values = _values(persisted, persisted_scope, key, *aliases)
        if _provided(persisted, persisted_scope, key, *aliases) and not server_values:
            return {
                "valid": False,
                "required": True,
                "reason": "persisted_purpose_scope_invalid",
                "permission": None,
                "session_id": row.id,
            }
        if supplied and _provided(caller, caller_scope, key, *aliases):
            requested_values = _values(caller, caller_scope, key, *aliases)
            match_kind = "domain" if key == "allowed_domains" else (
                "resource" if key == "allowed_resources" else "exact"
            )
            narrowed = narrow_authority_values(
                server_values,
                requested_values,
                kind=match_kind,
            )
            if not narrowed:
                return {
                    "valid": False,
                    "required": True,
                    "reason": "caller_purpose_scope_outside_persisted_authority",
                    "permission": None,
                    "session_id": row.id,
                }
            merged_scope[key] = narrowed
        elif server_values:
            merged_scope[key] = server_values

    for key in ("blocked_actions", "blocked_tools", "blocked_domains", "blocked_resources"):
        combined = _values(persisted, persisted_scope, key)
        for item in _values(caller, caller_scope, key):
            if item not in combined:
                combined.append(item)
        if combined:
            merged_scope[key] = combined

    persisted_constraints = (
        dict(persisted.get("constraints") or {}) if isinstance(persisted.get("constraints"), dict) else {}
    )
    caller_constraints = dict(caller.get("constraints") or {}) if isinstance(caller.get("constraints"), dict) else {}
    merged_constraints = dict(persisted_constraints)
    caller_expiry_raw = caller_constraints.get("expiry") or caller.get("expiry")
    if caller_expiry_raw:
        try:
            caller_expiry = _normalize_dt(datetime.fromisoformat(str(caller_expiry_raw).replace("Z", "+00:00")))
        except ValueError:
            return {
                "valid": False,
                "required": True,
                "reason": "caller_purpose_permission_expiry_invalid",
                "permission": None,
                "session_id": row.id,
            }
        effective_expiry = min(item for item in (effective_expiry, caller_expiry) if item is not None)
    if effective_expiry is not None:
        merged_constraints["expiry"] = effective_expiry.isoformat()

    for key in ("max_action_count",):
        if caller_constraints.get(key) is not None:
            try:
                caller_limit = int(caller_constraints[key])
                server_limit = int(persisted_constraints[key]) if persisted_constraints.get(key) is not None else caller_limit
            except (TypeError, ValueError):
                return {
                    "valid": False,
                    "required": True,
                    "reason": f"caller_purpose_permission_{key}_invalid",
                    "permission": None,
                    "session_id": row.id,
                }
            merged_constraints[key] = min(server_limit, caller_limit)

    server_risk = _lower_token(persisted_constraints.get("max_risk_level"))
    caller_risk = _lower_token(caller_constraints.get("max_risk_level"))
    if server_risk or caller_risk:
        candidates = [item for item in (server_risk, caller_risk) if item]
        merged_constraints["max_risk_level"] = min(candidates, key=_risk_rank)
    if bool(persisted_constraints.get("require_human_confirmation")) or bool(
        caller_constraints.get("require_human_confirmation")
    ):
        merged_constraints["require_human_confirmation"] = True
    approval_required_for = _normalized_lower_list(persisted_constraints.get("approval_required_for"))
    for item in _normalized_lower_list(caller_constraints.get("approval_required_for")):
        if item not in approval_required_for:
            approval_required_for.append(item)
    if approval_required_for:
        merged_constraints["approval_required_for"] = approval_required_for

    server_context = dict(persisted.get("context") or {}) if isinstance(persisted.get("context"), dict) else {}
    merged_context = dict(server_context)
    server_systems = _normalized_lower_list(server_context.get("connected_systems"))
    if "connected_systems" in caller_context:
        requested_systems = set(_normalized_lower_list(caller_context.get("connected_systems")))
        narrowed_systems = [item for item in server_systems if item in requested_systems]
        if not narrowed_systems:
            return {
                "valid": False,
                "required": True,
                "reason": "caller_purpose_scope_outside_persisted_authority",
                "permission": None,
                "session_id": row.id,
            }
        merged_context["connected_systems"] = narrowed_systems
    if caller_context.get("max_chain_depth") is not None:
        try:
            caller_depth = int(caller_context["max_chain_depth"])
            server_depth = int(server_context.get("max_chain_depth", caller_depth))
        except (TypeError, ValueError):
            return {
                "valid": False,
                "required": True,
                "reason": "caller_purpose_permission_max_chain_depth_invalid",
                "permission": None,
                "session_id": row.id,
            }
        merged_context["max_chain_depth"] = min(server_depth, caller_depth)

    purpose = dict(persisted.get("purpose") or {}) if isinstance(persisted.get("purpose"), dict) else {}
    purpose.setdefault("name", row.purpose_category)
    purpose.setdefault("description", row.declared_purpose)
    persisted_mode = _lower_token(persisted.get("mode")) or "block"
    caller_mode = _lower_token(caller.get("mode"))
    effective_mode = "block" if "block" in {persisted_mode, caller_mode} else persisted_mode
    permission = {
        "permission_id": row.id,
        "identity_id": persisted.get("identity_id") or persisted.get("agent_id"),
        "identity_type": "agent" if agent_id else "user",
        "purpose": purpose,
        "scope": merged_scope,
        "constraints": merged_constraints,
        "status": "active",
        "mode": effective_mode,
        "context": merged_context,
        "allowed_actions": list(merged_scope.get("allowed_actions") or []),
        "allowed_tools": list(merged_scope.get("allowed_tools") or []),
        "allowed_data_scope": list(merged_scope.get("allowed_data_scopes") or []),
        "expiry": merged_constraints.get("expiry"),
    }
    return {
        "valid": True,
        "required": True,
        "reason": "persisted_purpose_permission_resolved",
        "permission": permission,
        "session_id": row.id,
    }


def control_mode_for_pre_action_decision(decision: str, *, inline: bool = True) -> str:
    normalized = _lower_token(decision)
    if not inline:
        return "detected_only"
    if normalized in {"block", "deny"}:
        return "inline_prevented"
    if normalized in {"warn"}:
        return "warned"
    if normalized in {"review", "require_approval", "hold_for_approval", "step_up"}:
        return "external_required"
    if normalized == "shadow_would_block":
        return "shadow_would_block"
    if normalized in {"detect_only", "detected_only"}:
        return "detected_only"
    if normalized == "allow":
        return "inline_allowed"
    return "incomplete"


def decision_badge_for_control_mode(control_mode: str) -> str:
    normalized = _lower_token(control_mode)
    return {
        "inline_prevented": "Pre-Action Blocked",
        "inline_allowed": "Allowed",
        "warned": "Review Required",
        "review_required": "Review Required",
        "shadow_would_block": "Shadow: Would Block",
        "detected_only": "Detected-Only",
        "telemetry_only": "Detected-Only",
        "external_required": "Review Required",
        "external_action_triggered": "External Action Triggered",
        "incomplete": "Incomplete",
    }.get(normalized, "Detected-Only")


STRICT_CONTROL_MODES = ALLOWED_CONTROL_MODES
_DEPLOYMENT_FAMILIES = {
    "browser",
    "endpoint",
    "runtime",
    "saas_api",
    "unknown",
}
_DEPLOYMENT_EVIDENCE_CAPABILITIES = {
    "complete",
    "partial",
    "metadata_only",
    "none",
    "unknown",
}
_DEPLOYMENT_AUTHORIZATION_PATHS = {
    "inline_pre_execution",
    "telemetry_observation",
    "external_control",
    "post_execution",
    "unknown",
}
_DEPLOYMENT_LINK_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _unknown_deployment_linkage() -> dict[str, Any]:
    return {
        "deployment_instance_id": None,
        "technical_surface_type": "unknown",
        "deployment_family": "unknown",
        "collector_id": None,
        "authorization_path": "unknown",
        "control_mode": "incomplete",
        "evidence_capability_at_decision_time": "unknown",
    }


def _trusted_deployment_linkage(value: object) -> dict[str, Any]:
    source = _metadata_dict(value)
    if source.get("verified") is not True:
        return _unknown_deployment_linkage()
    fields = {
        "deployment_instance_id": 36,
        "technical_surface_type": 64,
        "collector_id": 128,
    }
    tokens: dict[str, str] = {}
    for key, maximum in fields.items():
        raw = source.get(key)
        if (
            type(raw) is not str
            or not raw
            or len(raw) > maximum
            or _DEPLOYMENT_LINK_TOKEN.fullmatch(raw) is None
        ):
            return _unknown_deployment_linkage()
        tokens[key] = raw
    family = source.get("deployment_family")
    authorization_path = source.get("authorization_path")
    control_mode = source.get("control_mode")
    evidence_capability = source.get(
        "evidence_capability_at_decision_time"
    )
    if (
        type(family) is not str
        or family not in _DEPLOYMENT_FAMILIES
        or type(authorization_path) is not str
        or authorization_path not in _DEPLOYMENT_AUTHORIZATION_PATHS
        or type(control_mode) is not str
        or control_mode not in STRICT_CONTROL_MODES
        or type(evidence_capability) is not str
        or evidence_capability not in _DEPLOYMENT_EVIDENCE_CAPABILITIES
    ):
        return _unknown_deployment_linkage()
    return {
        **tokens,
        "deployment_family": family,
        "authorization_path": authorization_path,
        "control_mode": control_mode,
        "evidence_capability_at_decision_time": evidence_capability,
    }

INLINE_CONTROL_SURFACES = {
    "aiiam",
    "api",
    "browser",
    "developer_ide",
    "desktop_ai",
    "gateway",
    "local",
    "mcp",
    "proxy",
    "runtime_control",
    "sdk",
}

NON_INLINE_TELEMETRY_SURFACES = {
    "connector",
    "copilot",
    "google_workspace",
    "microsoft",
    "monitoring",
    "o365",
    "saas",
    "slack",
    "surface_coverage",
    "teams",
}


def _stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decision_final_decision(policy: dict[str, Any]) -> str:
    control_mode = _lower_token(policy.get("control_mode"))
    decision = _lower_token(policy.get("decision"))
    if control_mode in {"detected_only", "telemetry_only"}:
        return "detected_only"
    if control_mode == "shadow_would_block":
        return "shadow_would_block"
    if decision in {"block", "blocked", "deny", "denied"}:
        return "block"
    if decision in {"warn", "warned", "alert"}:
        return "warn"
    if decision in {
        "require_approval",
        "require_justification",
        "justification_required",
        "hold",
        "held",
        "review",
        "step_up",
    }:
        return "require_approval"
    if decision in {"allow", "allowed"}:
        return "allow"
    return decision or "unknown"


def _decision_confidence(final_decision: str, *, action_risk: str, evidence_status: str) -> str:
    if evidence_status == "incomplete":
        return "low"
    if final_decision in {"block", "shadow_would_block"} or action_risk in {"high", "critical"}:
        return "high"
    if final_decision in {"warn", "require_approval"}:
        return "medium"
    return "medium"


def _decision_safe_path(final_decision: str, factors: list[dict[str, Any]]) -> str:
    factor_types = {str(item.get("factor_type") or "").strip() for item in factors}
    if final_decision in {"allow", "detected_only"}:
        return "Continue on the approved path and avoid adding sensitive content to public AI tools."
    if "transaction" in factor_types or "approval" in factor_types:
        return "Request approval or switch to a read-only action before continuing."
    if "content" in factor_types or "output" in factor_types:
        return "Remove secrets, customer data, and business contact data before retrying."
    if "context_integrity" in factor_types:
        return "Return to the approved domain, app, or declared task context before continuing."
    if "destination" in factor_types:
        return "Use an approved internal destination or lower-sensitivity data."
    return "Review the policy decision and retry with a lower-risk action."


def _decision_plain_reason(final_decision: str, action_type: str, factors: list[dict[str, Any]]) -> str:
    labels = [str(item.get("label") or "").strip().lower() for item in factors[:3] if str(item.get("label") or "").strip()]
    if final_decision == "detected_only":
        return f"{action_type.replace('_', ' ')} was detected for visibility only; Hawk did not block the action."
    if final_decision == "shadow_would_block":
        return f"{action_type.replace('_', ' ')} was allowed in shadow mode, but the active policy would have blocked it."
    if final_decision == "allow":
        return f"{action_type.replace('_', ' ')} matched the current policy guardrails and was allowed."
    if labels:
        return f"{action_type.replace('_', ' ')} was {final_decision} because of {', '.join(labels)}."
    return f"{action_type.replace('_', ' ')} was {final_decision} by the evaluated policy."


def _append_factor(
    factors: list[dict[str, Any]],
    *,
    factor_type: str,
    label: str,
    value: Any,
    severity: str,
    effect: str,
    explanation: str,
    weight: float,
) -> None:
    factors.append(
        {
            "factor_type": factor_type,
            "label": label,
            "value": value,
            "severity": severity,
            "effect": effect,
            "weight": float(weight),
            "explanation": explanation,
        }
    )


def _decision_factors_for(ai_action: dict[str, Any]) -> list[dict[str, Any]]:
    action = _metadata_dict(ai_action.get("action"))
    context = _metadata_dict(ai_action.get("context"))
    policy = _metadata_dict(ai_action.get("policy"))
    surface = _metadata_dict(ai_action.get("surface"))
    intent = _metadata_dict(ai_action.get("intent"))
    input_context = _metadata_dict(context.get("input"))
    output_context = _metadata_dict(context.get("output"))
    destination = _metadata_dict(context.get("destination"))
    automation = _metadata_dict(context.get("automation"))
    factors: list[dict[str, Any]] = []

    action_type = _lower_token(action.get("action_type")) or "unknown"
    action_risk = _lower_token(action.get("action_risk")) or "unknown"
    final_decision = _decision_final_decision(policy)
    high_risk_action = action_risk in {"high", "critical"} or any(token in action_type for token in HIGH_RISK_ACTION_TOKENS)

    if high_risk_action:
        _append_factor(
            factors,
            factor_type="action",
            label="High-risk browser action",
            value={"action_type": action_type, "action_risk": action_risk},
            severity="high" if action_risk != "critical" else "critical",
            effect="block" if final_decision == "block" else "increase_risk",
            explanation="The attempted action can submit data, change state, or complete a transaction.",
            weight=0.8,
        )
    elif action_type and action_type != "unknown":
        _append_factor(
            factors,
            factor_type="action",
            label="Low-risk action",
            value={"action_type": action_type, "action_risk": action_risk},
            severity="low",
            effect="allow",
            explanation="The action appears read-only or informational.",
            weight=0.25,
        )

    input_sensitivity = _lower_token(input_context.get("sensitivity_level"))
    contains_secrets = bool(input_context.get("contains_secrets"))
    contains_business_emails = bool(input_context.get("contains_business_emails"))
    contains_customer_data = bool(input_context.get("contains_customer_data"))
    if contains_secrets or contains_business_emails or contains_customer_data or SENSITIVITY_RANK.get(input_sensitivity, 0) >= 3:
        _append_factor(
            factors,
            factor_type="content",
            label="Sensitive input content",
            value={
                "sensitivity_level": input_sensitivity or None,
                "contains_secrets": contains_secrets,
                "contains_business_emails": contains_business_emails,
                "contains_customer_data": contains_customer_data,
            },
            severity="critical" if contains_secrets or input_sensitivity == "critical" else "high",
            effect="block" if final_decision == "block" else "increase_risk",
            explanation="The input signal contains sensitive content classes and raw values are redacted.",
            weight=0.9,
        )

    output_sensitivity = _lower_token(output_context.get("output_sensitivity"))
    output_secret = bool(output_context.get("contains_secret_like_value"))
    output_email = bool(output_context.get("contains_business_email") or output_context.get("contains_customer_contact"))
    if output_secret or output_email or SENSITIVITY_RANK.get(output_sensitivity, 0) >= 3:
        _append_factor(
            factors,
            factor_type="output",
            label="Sensitive generated output",
            value={
                "output_sensitivity": output_sensitivity or None,
                "contains_secret_like_value": output_secret,
                "contains_business_or_customer_contact": output_email,
            },
            severity="critical" if output_secret or output_sensitivity == "critical" else "high",
            effect="block" if final_decision == "block" else "increase_risk",
            explanation="The generated output contains sensitive data classes and raw values are redacted.",
            weight=0.85,
        )

    destination_trust = _lower_token(destination.get("trust_level"))
    destination_domain = str(destination.get("domain") or surface.get("domain") or "").strip()
    if destination_trust in {"public_ai", "external", "untrusted"}:
        _append_factor(
            factors,
            factor_type="destination",
            label="Public or external destination",
            value={"trust_level": destination_trust, "domain": destination_domain or None},
            severity="medium",
            effect="increase_risk",
            explanation="The destination is outside the trusted internal surface.",
            weight=0.55,
        )

    intent_category = str(intent.get("intent_category") or "").strip()
    alignment = _lower_token(intent.get("alignment"))
    if intent_category or alignment:
        effect = "allow" if alignment in {"aligned", "allow", "in_scope"} else ("block" if alignment in {"misaligned", "out_of_scope"} else "context")
        _append_factor(
            factors,
            factor_type="intent",
            label="Intent alignment",
            value={"intent_category": intent_category or None, "alignment": alignment or None},
            severity="low" if effect == "allow" else "medium",
            effect=effect,
            explanation="The declared task intent was compared with the attempted action.",
            weight=0.45,
        )

    if bool(automation.get("suspected")):
        _append_factor(
            factors,
            factor_type="automation",
            label="Browser automation suspected",
            value={"source": automation.get("source"), "confidence": automation.get("confidence")},
            severity="medium",
            effect="increase_risk" if final_decision != "block" else "block",
            explanation="The event had browser-visible automation indicators; Hawk does not claim endpoint-level control.",
            weight=0.65,
        )

    if any(token in action_type for token in {"add_to_cart", "checkout", "payment", "purchase", "order"}):
        _append_factor(
            factors,
            factor_type="transaction",
            label="Transaction or purchase action",
            value={"action_type": action_type},
            severity="high",
            effect="require_approval" if final_decision != "block" else "block",
            explanation="The attempted action could commit a purchase or transaction.",
            weight=0.8,
        )
        _append_factor(
            factors,
            factor_type="approval",
            label="Approval required for transaction",
            value={"approval_status": "not_present"},
            severity="high",
            effect="require_approval" if final_decision != "block" else "block",
            explanation="No approving workflow evidence was attached to the transaction action.",
            weight=0.75,
        )

    reason = str(policy.get("reason") or "").strip().lower()
    if "scope" in reason or "context" in reason or alignment in {"misaligned", "out_of_scope"}:
        _append_factor(
            factors,
            factor_type="context_integrity",
            label="Context or scope drift",
            value={"reason": reason or None, "alignment": alignment or None},
            severity="high" if final_decision == "block" else "medium",
            effect="block" if final_decision == "block" else "increase_risk",
            explanation="The attempted action or destination drifted from the approved task context.",
            weight=0.8,
        )

    _append_factor(
        factors,
        factor_type="policy",
        label="Policy decision",
        value={
            "decision": policy.get("decision"),
            "control_mode": policy.get("control_mode"),
            "decision_badge": policy.get("decision_badge"),
        },
        severity="high" if final_decision == "block" else "low",
        effect=final_decision,
        explanation="This is the final policy outcome applied to the action.",
        weight=1.0,
    )
    return factors


def build_decision_explanation(ai_action: dict[str, Any]) -> dict[str, Any]:
    actor = _metadata_dict(ai_action.get("actor"))
    authority = _metadata_dict(ai_action.get("authority"))
    surface = _metadata_dict(ai_action.get("surface"))
    action = _metadata_dict(ai_action.get("action"))
    context = _metadata_dict(ai_action.get("context"))
    policy = _metadata_dict(ai_action.get("policy"))
    evidence = _metadata_dict(ai_action.get("evidence"))
    intent = _metadata_dict(ai_action.get("intent"))
    business_purpose = _metadata_dict(ai_action.get("business_purpose"))
    code_context = _metadata_dict(ai_action.get("code_context"))
    role_resolution = _metadata_dict(ai_action.get("role_resolution"))
    factors = _decision_factors_for(ai_action)
    final_decision = _decision_final_decision(policy)
    action_type = _lower_token(action.get("action_type")) or "unknown"
    action_risk = _lower_token(action.get("action_risk")) or "unknown"
    evidence_status = _lower_token(evidence.get("evidence_status")) or "incomplete"
    policy_ids = [str(item).strip() for item in list(policy.get("policy_ids") or []) if str(item).strip()]
    control_ids = [str(item).strip() for item in list(policy.get("control_ids") or []) if str(item).strip()]
    input_context = _metadata_dict(context.get("input"))
    output_context = _metadata_dict(context.get("output"))
    transaction_tokens = {"add_to_cart", "checkout", "payment", "purchase", "order"}
    raw_content_redacted = any(
        [
            bool(input_context.get("contains_secrets")),
            bool(input_context.get("contains_business_emails")),
            bool(input_context.get("contains_customer_data")),
            SENSITIVITY_RANK.get(_lower_token(input_context.get("sensitivity_level")), 0) >= 3,
            SENSITIVITY_RANK.get(_lower_token(output_context.get("output_sensitivity")), 0) >= 3,
        ]
    )
    matched_policies = []
    for policy_id in policy_ids or control_ids or ["runtime_control_policy"]:
        matched_policies.append(
            {
                "policy_id": policy_id,
                "policy_name": str(policy_id).replace("_", " ").replace("-", " ").title(),
                "policy_version": policy.get("policy_snapshot_id"),
                "policy_snapshot_id": policy.get("policy_snapshot_id"),
                "rule_id": control_ids[0] if control_ids else policy_id,
                "rule_name": (control_ids[0] if control_ids else policy_id).replace("_", " ").replace("-", " ").title(),
                "effect": final_decision,
            }
        )
    return {
        "explanation_id": f"decision-explanation:{ai_action.get('action_id')}",
        "decision_id": f"decision:{ai_action.get('action_id')}",
        "action_id": ai_action.get("action_id"),
        "tenant_id": ai_action.get("tenant_id"),
        "timestamp": ai_action.get("timestamp"),
        "decision_summary": {
            "final_decision": final_decision,
            "control_mode": policy.get("control_mode"),
            "decision_badge": policy.get("decision_badge"),
            "plain_english_reason": _decision_plain_reason(final_decision, action_type, factors),
            "recommended_safe_path": _decision_safe_path(final_decision, factors),
            "confidence": _decision_confidence(final_decision, action_risk=action_risk, evidence_status=evidence_status),
        },
        "evaluated_signals": {
            "actor_summary": {
                "identity_type": actor.get("identity_type"),
                "user_id": actor.get("user_id"),
                "email": actor.get("email"),
                "agent_id": actor.get("agent_id"),
                "machine_id": actor.get("machine_id"),
            },
            "identity_type": actor.get("identity_type"),
            "authority_type": authority.get("authority_type"),
            "surface": {
                "surface_type": surface.get("surface_type"),
                "source_surface": surface.get("source_surface"),
                "application": surface.get("application"),
                "domain": surface.get("domain"),
                "browser_type": surface.get("browser_type"),
                "trust_level": _metadata_dict(context.get("destination")).get("trust_level"),
            },
            "intent": intent,
            "business_purpose": business_purpose,
            "code_context": code_context,
            "role_resolution": role_resolution,
            "input": input_context,
            "output": output_context,
            "action": {
                "action_type": action_type,
                "action_category": action.get("action_category"),
                "action_risk": action_risk,
                "target_resource": action.get("target_resource"),
                "tool_name": action.get("tool_name"),
            },
            "automation": _metadata_dict(context.get("automation")),
            "transaction": {
                "is_transactional": any(token in action_type for token in transaction_tokens),
                "approval_required": any(token in action_type for token in transaction_tokens),
            },
            "approval": {
                "approval_status": "not_present" if any(token in action_type for token in transaction_tokens) else "not_required",
            },
            "context_integrity": {
                "alignment": intent.get("alignment"),
                "reason": policy.get("reason"),
                "evidence_status": evidence_status,
            },
            "destination": _metadata_dict(context.get("destination")),
        },
        "matched_policies": matched_policies,
        "decision_factors": factors,
        "hidden_or_redacted": {
            "raw_content_redacted": raw_content_redacted,
            "secret_values_redacted": bool(input_context.get("contains_secrets") or output_context.get("contains_secret_like_value")),
            "payment_values_redacted": any(token in action_type for token in {"checkout", "payment", "purchase", "order"}),
            "internal_policy_details_hidden": False,
        },
        "evidence": {
            "evidence_refs": list(evidence.get("evidence_refs") or []),
            "evidence_bundle_id": evidence.get("evidence_bundle_id"),
            "trace_id": evidence.get("trace_id"),
            "event_hash": evidence.get("event_hash"),
            "finding_id": ai_action.get("finding_id"),
        },
    }


def _strict_control_mode_for_runtime(
    *,
    decision: str | None,
    source_surface: str | None,
    event_type: str | None,
    metadata: dict[str, Any],
) -> str:
    source_norm = _lower_token(source_surface)

    intent_decision = _metadata_dict(metadata.get("intent_aware_decision"))
    if (
        _lower_token(intent_decision.get("would_decision")) in {"block", "deny"}
        and _lower_token(intent_decision.get("decision")) == "allow"
    ):
        return "shadow_would_block"

    current = _lower_token(metadata.get("control_mode"))
    if current in STRICT_CONTROL_MODES:
        if current in {"inline_prevented", "warned"}:
            return "external_required"
        if current == "inline_allowed":
            return "telemetry_only"
        return current

    decision_norm = _lower_token(decision or metadata.get("final_decision") or metadata.get("action_taken"))
    if ":" in decision_norm:
        decision_norm = decision_norm.split(":", 1)[0]
    if decision_norm in {"block", "blocked", "deny", "denied"}:
        return "external_required"
    if decision_norm in {"warn", "warned", "alert"}:
        return "external_required"
    if decision_norm in {"review", "require_approval", "hold", "held", "hold_for_approval", "step_up", "require_justification"}:
        return "external_required"
    if decision_norm == "shadow_would_block":
        return "shadow_would_block"
    if decision_norm in {"detect_only", "detected_only"}:
        return "detected_only"
    if decision_norm in {"allow", "allowed"}:
        event_norm = _lower_token(event_type)
        if bool(metadata.get("automation_suspected")) or event_norm.startswith("browser_automation"):
            return "detected_only"
        if source_norm == "browser":
            return "telemetry_only"
        return "telemetry_only"
    return "incomplete"


def build_ai_action_record(
    *,
    tenant_id: str,
    action_id: str,
    timestamp: str,
    source_surface: str,
    event_type: str,
    user_id: str | None = None,
    agent_id: str | None = None,
    ai_system_id: str | None = None,
    app_id: str | None = None,
    machine_id: str | None = None,
    browser_type: str | None = None,
    application: str | None = None,
    policy_version_id: str | None = None,
    decision: str | None = None,
    evidence_node_ids: list[str] | None = None,
    correlation_id: str | None = None,
    context_id: str | None = None,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    finding_id: str | None = None,
    trusted_pre_action_governance_check: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta = _metadata_dict(metadata)
    # Authority-bearing facts must arrive through an internal hook argument.
    # Caller metadata may contain a similarly named object but is never trusted.
    pre_action = _metadata_dict(trusted_pre_action_governance_check)
    pre_actor = _metadata_dict(pre_action.get("actor"))
    pre_authority = _metadata_dict(pre_action.get("authority"))
    pre_surface = _metadata_dict(pre_action.get("surface"))
    pre_action_block = _metadata_dict(pre_action.get("action"))
    pre_policy = _metadata_dict(pre_action.get("policy"))
    pre_evidence = _metadata_dict(pre_action.get("evidence"))
    deployment_linkage = _trusted_deployment_linkage(
        pre_action.get("deployment")
    )
    intent_context = _metadata_dict(meta.get("intent_context"))
    input_context = _metadata_dict(meta.get("input_content_context"))
    output_context = _metadata_dict(meta.get("output_context"))
    alignment_result = _metadata_dict(meta.get("action_alignment_result"))
    intent_decision = _metadata_dict(meta.get("intent_aware_decision"))
    destination_context = _metadata_dict(meta.get("destination_context"))
    business_boundary_decision = _metadata_dict(meta.get("business_purpose_decision"))
    business_purpose = _metadata_dict(
        business_boundary_decision.get("business_purpose") or meta.get("business_purpose")
    )
    code_context = _metadata_dict(business_boundary_decision.get("code_context") or meta.get("code_context"))
    role_resolution = _metadata_dict(
        business_boundary_decision.get("role_resolution") or meta.get("role_resolution")
    )

    normalized_decision = _lower_token(decision or meta.get("decision") or meta.get("final_decision"))
    if ":" in normalized_decision:
        normalized_decision = normalized_decision.split(":", 1)[0]
    if normalized_decision in {"blocked", "denied"}:
        normalized_decision = "block"
    elif normalized_decision == "warned":
        normalized_decision = "warn"
    elif normalized_decision == "allowed":
        normalized_decision = "allow"
    elif normalized_decision in {"held", "hold"}:
        normalized_decision = "review"
    control_mode = _strict_control_mode_for_runtime(
        decision=normalized_decision,
        source_surface=source_surface,
        event_type=event_type,
        metadata=meta,
    )
    trusted_control_mode = _lower_token(
        pre_action.get("control_mode")
        or pre_policy.get("control_mode")
        or (
            deployment_linkage.get("control_mode")
            if deployment_linkage.get("deployment_instance_id")
            else None
        )
    )
    if trusted_control_mode in STRICT_CONTROL_MODES:
        control_mode = trusted_control_mode
    action_type = (
        _lower_token(pre_action_block.get("action_type"))
        or _lower_token(meta.get("action_type"))
        or _lower_token(meta.get("action"))
        or _lower_token(event_type)
        or "unknown"
    )
    resolved_machine_id = (
        str(pre_actor.get("machine_id") or machine_id or meta.get("machine_id") or meta.get("endpoint_id") or "").strip()
        or None
    )
    resolved_browser_type = (
        str(browser_type or meta.get("browser_type") or meta.get("browser") or "").strip()
        or None
    )
    resolved_application = (
        str(pre_surface.get("application") or meta.get("destination_app_name") or application or meta.get("application") or app_id or "").strip()
        or None
    )
    automation_suspected = bool(meta.get("automation_suspected"))
    source_norm = _lower_token(source_surface)
    event_norm = _lower_token(event_type)
    if source_norm == "browser" and (automation_suspected or event_norm.startswith("browser_automation")):
        surface_type = "agentic_browser"
    else:
        surface_type = str(pre_surface.get("surface_type") or "").strip().lower()
        if not surface_type:
            if source_norm == "browser":
                surface_type = "browser"
            elif source_norm == "aiiam":
                surface_type = "agent"
            else:
                surface_type = source_norm or "unknown"
    actor_identity_type = str(pre_actor.get("identity_type") or "").strip().lower()
    if not actor_identity_type:
        actor_identity_type = "agent" if (agent_id or automation_suspected) else ("human" if user_id else "unknown")
    policy_ids = list(pre_policy.get("policy_ids") or [])
    if not policy_ids:
        policy_hint = str(meta.get("guardian_policy_id") or meta.get("policy_id") or policy_version_id or "").strip()
        if policy_hint:
            policy_ids = [policy_hint]
    boundary_policy_id = str(business_boundary_decision.get("policy_id") or "").strip()
    if boundary_policy_id and boundary_policy_id not in policy_ids:
        policy_ids.append(boundary_policy_id)
    control_ids = list(pre_policy.get("control_ids") or meta.get("triggered_controls") or meta.get("related_control_ids") or [])
    for control_id in list(business_boundary_decision.get("control_ids") or []):
        control_token = str(control_id or "").strip()
        if control_token and control_token not in control_ids:
            control_ids.append(control_token)
    evidence_refs = sorted(
        {
            *[str(item) for item in (evidence_node_ids or []) if str(item).strip()],
            *[str(item) for item in (pre_evidence.get("evidence_refs") or []) if str(item).strip()],
        }
    )
    required_values = [
        user_id or pre_actor.get("user_id") or pre_actor.get("email") or meta.get("user_email"),
        resolved_machine_id,
        resolved_application,
        normalized_decision,
        action_type,
    ]
    if source_norm == "browser":
        required_values.append(resolved_browser_type)
    evidence_status = "complete" if all(bool(value) for value in required_values) and bool(evidence_refs) else "incomplete"

    trusted_parameter_hash = str(pre_action_block.get("parameter_hash") or "").strip().lower()
    parameter_hash_binding = None
    if trusted_parameter_hash:
        try:
            parameter_hash_binding = trusted_parameter_hash_binding(
                tenant_id=tenant_id,
                action_id=str(action_id or "").strip(),
                parameter_hash=trusted_parameter_hash,
            )
        except ValueError:
            parameter_hash_binding = None

    action_record = {
        "action_id": str(action_id or "").strip(),
        "tenant_id": tenant_id,
        "timestamp": timestamp,
        "actor": {
            "identity_id": pre_actor.get("identity_id") or agent_id or user_id,
            "identity_type": actor_identity_type,
            "user_id": pre_actor.get("user_id") or user_id,
            "email": pre_actor.get("email") or meta.get("user_email"),
            "agent_id": pre_actor.get("agent_id") or agent_id,
            "agent_name": pre_actor.get("agent_name") or meta.get("agent_name"),
            "session_id": pre_actor.get("session_id") or meta.get("session_id"),
            "machine_id": resolved_machine_id,
            "acting_on_behalf_of_user_id": pre_actor.get("acting_on_behalf_of_user_id") or user_id,
        },
        "authority": {
            "authority_type": (
                (
                    "browser_session"
                    if source_norm == "browser" and _lower_token(pre_authority.get("authority_type")) == "user_session"
                    else pre_authority.get("authority_type")
                )
                or ("delegated_agent" if source_norm == "aiiam" else ("gateway_policy" if source_norm == "gateway" else "browser_session"))
            ),
            "authority_owner": pre_authority.get("authority_owner") or user_id or meta.get("user_email"),
            "authority_source": pre_authority.get("authority_source") or ("runtime_control" if source_norm == "aiiam" else source_norm),
            "auth_strength": pre_authority.get("auth_strength") or ("browser_session" if source_norm == "browser" else None),
            "standing_privilege": pre_authority.get("standing_privilege", "unknown"),
            "jit_grant_id": pre_authority.get("jit_grant_id"),
            "permission_scope": list(pre_authority.get("permission_scope") or []),
            "verified": pre_authority.get("verified") if isinstance(pre_authority.get("verified"), bool) else None,
        },
        "surface": {
            "surface_type": surface_type,
            "source_surface": source_norm,
            "application": resolved_application,
            "provider": pre_surface.get("provider") or meta.get("provider") or meta.get("model_provider"),
            "model": pre_surface.get("model") or meta.get("model_name"),
            "domain": pre_surface.get("domain") or meta.get("domain") or meta.get("destination_domain") or app_id,
            "url": pre_surface.get("url") or meta.get("url") or meta.get("current_url") or meta.get("api_endpoint"),
            "asset_id": pre_surface.get("asset_id") or ai_system_id,
            "browser_type": resolved_browser_type,
            "environment": pre_surface.get("environment") or meta.get("agent_environment") or "unknown",
            "asset_status": pre_surface.get("asset_status"),
        },
        "deployment": deployment_linkage,
        "intent": {
            "declared_intent": intent_context.get("declared_intent") or meta.get("declared_intent") or meta.get("intent"),
            "intent_category": intent_context.get("intent_category") or intent_decision.get("intent_category"),
            "intent_confidence": intent_context.get("intent_confidence"),
            "business_context": intent_context.get("business_context") or meta.get("business_context"),
            "alignment": alignment_result.get("alignment") or intent_decision.get("action_alignment"),
            "decision_reason": intent_decision.get("decision_reason") or meta.get("decision_reason"),
        },
        "action": {
            "action_type": action_type,
            "action_category": pre_action_block.get("action_category") or action_category_for(action_type),
            "operation": pre_action_block.get("operation"),
            "action_risk": _lower_token(pre_action_block.get("action_risk") or meta.get("action_risk") or action_risk_for(action_type)),
            "target_resource": pre_action_block.get("target_resource") or meta.get("target_resource") or meta.get("destination_domain"),
            "data_destination": pre_action_block.get("data_destination"),
            "tool_name": pre_action_block.get("tool_name") or meta.get("tool_name") or resolved_application,
            "tool_version": pre_action_block.get("tool_version"),
            "tool_fingerprint_id": (
                pre_action_block.get("tool_fingerprint_id")
                or pre_action_block.get("tool_fingerprint")
            ),
            "parameter_hash": pre_action_block.get("parameter_hash"),
            "expected_parameter_hash": pre_action_block.get("expected_parameter_hash"),
            "parameter_hash_binding": parameter_hash_binding,
            "side_effect_class": pre_action_block.get("side_effect_class"),
            "persistent_side_effect": pre_action_block.get("persistent_side_effect"),
            "mcp_server": pre_action_block.get("mcp_server") or meta.get("mcp_server_id"),
            "parameters_ref": pre_action_block.get("parameters_ref") or meta.get("tool_arguments_ref"),
            "input_ref": pre_action_block.get("input_ref") or meta.get("copied_text_hash") or meta.get("prompt_hash"),
            "output_ref": pre_action_block.get("output_ref") or meta.get("output_ref"),
        },
        "context": {
            "correlation_id": correlation_id,
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "input": {
                "sensitivity_level": input_context.get("sensitivity_level") or meta.get("input_sensitivity"),
                "contains_secrets": bool(input_context.get("contains_secrets")),
                "contains_business_emails": bool(input_context.get("contains_business_emails")),
                "contains_customer_data": bool(input_context.get("contains_customer_data")),
            },
            "output": {
                "output_sensitivity": output_context.get("output_sensitivity") or meta.get("output_sensitivity"),
                "contains_secret_like_value": bool(output_context.get("contains_secret_like_value")),
                "contains_business_email": bool(output_context.get("contains_business_email")),
                "contains_customer_contact": bool(output_context.get("contains_customer_contact")),
            },
            "destination": dict(destination_context),
            "automation": {
                "suspected": automation_suspected,
                "source": meta.get("automation_source"),
                "confidence": meta.get("automation_confidence"),
                "indicators": list(meta.get("automation_indicators") or []),
                "suspected_tool": meta.get("suspected_tool"),
            },
            "data_classification": meta.get("data_classification") or meta.get("source_classification_hint"),
        },
        "business_purpose": business_purpose,
        "code_context": code_context,
        "role_resolution": role_resolution,
        "policy": {
            "policy_ids": policy_ids,
            "control_ids": control_ids,
            "policy_snapshot_id": pre_policy.get("policy_snapshot_id") or policy_version_id or meta.get("policy_version"),
            "mode": pre_policy.get("mode") or intent_decision.get("mode") or meta.get("platform_mode"),
            "decision": normalized_decision or pre_policy.get("decision") or "unknown",
            "reason": pre_policy.get("reason") or meta.get("reason_code") or meta.get("reason"),
            "control_mode": control_mode,
            "decision_badge": decision_badge_for_control_mode(control_mode),
            "evaluated_at": pre_policy.get("evaluated_at") or timestamp,
        },
        "evidence": {
            "evidence_refs": evidence_refs,
            "evidence_status": evidence_status,
            "trace_id": pre_evidence.get("trace_id") or correlation_id,
            "event_hash": pre_evidence.get("event_hash"),
        },
        "finding_id": finding_id or meta.get("finding_id"),
    }
    policy_snapshot_id = str(action_record["policy"]["policy_snapshot_id"] or f"policy-snapshot:{action_id}").strip()
    policy_snapshot = {
        "policy_snapshot_id": policy_snapshot_id,
        "policy_id": (policy_ids[0] if policy_ids else None),
        "policy_name": (policy_ids[0].replace("_", " ").replace("-", " ").title() if policy_ids else "Runtime Control Policy"),
        "policy_version": policy_snapshot_id,
        "policy_category": "ai_action_control",
        "effective_mode": action_record["policy"].get("mode") or "enforce",
        "assigned_scope": {
            "surface_type": action_record["surface"].get("surface_type"),
            "source_surface": action_record["surface"].get("source_surface"),
            "application": action_record["surface"].get("application"),
            "domain": action_record["surface"].get("domain"),
        },
        "rule_hash": _stable_hash(
            {
                "policy_ids": policy_ids,
                "control_ids": control_ids,
                "decision": action_record["policy"].get("decision"),
                "reason": action_record["policy"].get("reason"),
                "mode": action_record["policy"].get("mode"),
            }
        ),
        "created_at": timestamp,
        "verification_status": "unverified_legacy",
        "canonical_authority": False,
        "display_only": True,
    }
    action_record["policy_snapshot"] = policy_snapshot
    action_record["policy"]["policy_snapshot_id"] = policy_snapshot_id

    evidence_bundle_payload = {
        "tenant_id": tenant_id,
        "related_action_ids": [action_record["action_id"]],
        "related_decision_ids": [f"decision:{action_record['action_id']}"],
        "related_policy_snapshot_ids": [policy_snapshot_id],
        "related_finding_ids": [action_record.get("finding_id")] if action_record.get("finding_id") else [],
        "related_trace_ids": [action_record["evidence"].get("trace_id")] if action_record["evidence"].get("trace_id") else [],
        "evidence_refs": evidence_refs,
        "control_mode": control_mode,
        "decision": action_record["policy"].get("decision"),
    }
    evidence_bundle_core = {
        "evidence_bundle_id": f"evidence-bundle:{action_record['action_id']}",
        **evidence_bundle_payload,
    }
    evidence_bundle_payload_sha256 = _stable_hash(evidence_bundle_core)
    legacy_evidence_bundle = {
        **evidence_bundle_core,
        "bundle_hash": evidence_bundle_payload_sha256,
        "payload_sha256": evidence_bundle_payload_sha256,
        "hash_algorithm": "sha256",
        "integrity_status": "unverified_legacy",
        "verification_status": "unverified_legacy",
        "canonical_authority": False,
        "authority_source": "legacy_display_adapter",
        "display_only": True,
        "redaction_policy": "privacy_sanitizer",
        "evidence_ref_count": len(evidence_refs),
        "related_action_count": len(evidence_bundle_payload["related_action_ids"]),
        "related_policy_snapshot_count": len(evidence_bundle_payload["related_policy_snapshot_ids"]),
        "related_finding_count": len(evidence_bundle_payload["related_finding_ids"]),
        "related_trace_count": len(evidence_bundle_payload["related_trace_ids"]),
        "created_at": timestamp,
    }
    canonical_reference = _metadata_dict(pre_evidence.get("canonical_evidence_bundle"))
    canonical_bundle_id = str(
        canonical_reference.get("evidence_bundle_id")
        or pre_evidence.get("canonical_evidence_bundle_id")
        or ""
    ).strip()
    canonical_verified = bool(
        canonical_reference.get("verified") is True
        or pre_evidence.get("canonical_evidence_bundle_verified") is True
    )
    if canonical_bundle_id and canonical_verified:
        evidence_bundle = {
            "evidence_bundle_id": canonical_bundle_id,
            "bundle_hash": canonical_reference.get("bundle_hash"),
            "manifest_id": canonical_reference.get("manifest_id"),
            "integrity_status": str(
                canonical_reference.get("integrity_status") or "verified"
            ),
            "verification_status": "verified",
            "canonical_authority": True,
            "authority_source": "canonical_evidence_bundle_verifier",
            "display_only": True,
            "evidence_refs": evidence_refs,
            "evidence_ref_count": len(evidence_refs),
        }
    else:
        evidence_bundle = legacy_evidence_bundle
    action_record["evidence_bundle"] = evidence_bundle
    action_record["evidence"]["evidence_bundle_id"] = evidence_bundle["evidence_bundle_id"]
    action_record["evidence"]["integrity_status"] = evidence_bundle["integrity_status"]
    action_record["decision_explanation"] = build_decision_explanation(action_record)
    return action_record


def build_pre_action_governance_check(
    *,
    tenant_id: str,
    action_id: str,
    source_event_id: str | None,
    actor: dict[str, Any],
    authority: dict[str, Any],
    purpose_permission: dict[str, Any] | None,
    purpose_result: dict[str, Any],
    surface: dict[str, Any],
    action: dict[str, Any],
    workflow_risk_context: dict[str, Any] | None = None,
    policy_snapshot_id: str | None = None,
    policy_ids: list[str] | None = None,
    control_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    trace_id: str | None = None,
    inline: bool = True,
) -> dict[str, Any]:
    evaluated_at = datetime.now(timezone.utc).isoformat()
    purpose = _metadata_dict((purpose_permission or {}).get("purpose"))
    scope = _metadata_dict((purpose_permission or {}).get("scope"))
    constraints = _metadata_dict((purpose_permission or {}).get("constraints"))
    purpose_id = purpose_result.get("purpose_bound_permission_id") or (purpose_permission or {}).get("permission_id")
    decision = _lower_token(purpose_result.get("decision")) or "allow"
    mode = _lower_token(purpose_result.get("mode")) or _lower_token((purpose_permission or {}).get("mode")) or "block"
    control_mode = control_mode_for_pre_action_decision(decision, inline=inline)
    return {
        "check_id": str(uuid4()),
        "tenant_id": tenant_id,
        "timestamp": evaluated_at,
        "action_id": action_id,
        "source_event_id": source_event_id,
        "actor": {
            "identity_id": actor.get("identity_id") or actor.get("agent_id") or actor.get("user_id"),
            "identity_type": actor.get("identity_type") or "unknown",
            "user_id": actor.get("user_id"),
            "email": actor.get("email"),
            "agent_id": actor.get("agent_id"),
            "agent_name": actor.get("agent_name"),
            "session_id": actor.get("session_id"),
            "machine_id": actor.get("machine_id"),
            "acting_on_behalf_of_user_id": actor.get("acting_on_behalf_of_user_id"),
        },
        "authority": {
            "authority_type": authority.get("authority_type") or "unknown",
            "authority_owner": authority.get("authority_owner"),
            "authority_source": authority.get("authority_source"),
            "auth_strength": authority.get("auth_strength"),
            "standing_privilege": authority.get("standing_privilege", "unknown"),
            "jit_grant_id": authority.get("jit_grant_id"),
            "permission_scope": list(authority.get("permission_scope") or []),
            "verified": authority.get("verified") if isinstance(authority.get("verified"), bool) else None,
        },
        "purpose": {
            "task_purpose": purpose.get("name"),
            "declared_intent": purpose.get("declared_intent") or (purpose_permission or {}).get("declared_intent"),
            "allowed_purpose": purpose.get("description"),
            "purpose_confidence": purpose.get("confidence") or (purpose_permission or {}).get("purpose_confidence"),
            "purpose_bound_permission_id": purpose_id,
            "violations": list(purpose_result.get("violations") or []),
        },
        "surface": {
            "surface_type": surface.get("surface_type") or "unknown",
            "application": surface.get("application"),
            "provider": surface.get("provider"),
            "model": surface.get("model"),
            "mcp_server_id": surface.get("mcp_server_id"),
            "domain": surface.get("domain"),
            "url": surface.get("url"),
            "asset_id": surface.get("asset_id"),
            "environment": surface.get("environment") or "unknown",
            "asset_status": surface.get("asset_status"),
        },
        "action": {
            "action_type": action.get("action_type") or "unknown",
            "action_category": action.get("action_category") or action_category_for(action.get("action_type")),
            "operation": action.get("operation"),
            "action_risk": action.get("action_risk") or action_risk_for(action.get("action_type")),
            "target_resource": action.get("target_resource"),
            "data_destination": action.get("data_destination"),
            "tool_name": action.get("tool_name"),
            "tool_version": action.get("tool_version"),
            "tool_fingerprint_id": action.get("tool_fingerprint_id"),
            "parameter_hash": action.get("parameter_hash"),
            "expected_parameter_hash": action.get("expected_parameter_hash"),
            "side_effect_class": action.get("side_effect_class"),
            "persistent_side_effect": action.get("persistent_side_effect"),
            "mcp_server": action.get("mcp_server"),
            "parameters_ref": action.get("parameters_ref"),
            "input_ref": action.get("input_ref"),
            "output_ref": action.get("output_ref"),
        },
        "scope": {
            "allowed_actions": list(scope.get("allowed_actions") or (purpose_permission or {}).get("allowed_actions") or []),
            "allowed_tools": list(scope.get("allowed_tools") or (purpose_permission or {}).get("allowed_tools") or []),
            "allowed_domains": list(scope.get("allowed_domains") or (purpose_permission or {}).get("allowed_domains") or []),
            "allowed_resources": list(scope.get("allowed_resources") or (purpose_permission or {}).get("allowed_resources") or []),
            "allowed_data_scopes": list(scope.get("allowed_data_scopes") or (purpose_permission or {}).get("allowed_data_scope") or []),
            "allowed_environments": list(scope.get("allowed_environments") or (purpose_permission or {}).get("allowed_environments") or []),
            "expiry": constraints.get("expiry") or (purpose_permission or {}).get("expiry"),
        },
        "cumulative_risk": {
            "workflow_id": (workflow_risk_context or {}).get("workflow_id"),
            "previous_action_count": int((workflow_risk_context or {}).get("previous_action_count") or 0),
            "cumulative_risk_score": float((workflow_risk_context or {}).get("cumulative_risk_score") or 0.0),
            "scope_drift_score": float((workflow_risk_context or {}).get("scope_drift_score") or 0.0),
            "privilege_escalation_score": float((workflow_risk_context or {}).get("privilege_escalation_score") or 0.0),
            "recent_violations_count": int((workflow_risk_context or {}).get("recent_violations_count") or 0),
            "risk_drivers": list((workflow_risk_context or {}).get("risk_drivers") or []),
        },
        "policy": {
            "policy_ids": list(
                policy_ids if policy_ids is not None else ["AI_ACTION_BOUNDARY_CONTROL"]
            ),
            "control_ids": list(
                control_ids if control_ids is not None else ["AI_ACTION_BOUNDARY_CONTROL"]
            ),
            "policy_snapshot_id": policy_snapshot_id,
            "mode": mode,
            "decision": decision,
            "reason": purpose_result.get("reason"),
            "evaluated_at": evaluated_at,
        },
        "control_mode": control_mode,
        "decision_badge": decision_badge_for_control_mode(control_mode),
        "evidence": {
            "evidence_refs": list(evidence_refs or []),
            "evidence_bundle_id": None,
            "trace_id": trace_id,
            "event_hash": None,
        },
    }


def mint_capability_token(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    agent_identity_id: str,
    raw_token: str,
    scopes: list[str],
    expires_minutes: int,
    chain_depth: int,
    issued_by_user_id: str | None,
) -> CapabilityToken:
    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_identity_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if not agent:
        raise ValueError("Agent not found for tenant")
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if ai_system is None:
        raise ValueError("AI system not found for tenant")
    if chain_depth > agent.max_chain_depth:
        raise ValueError("Requested token chain_depth exceeds agent max_chain_depth")

    token = CapabilityToken(
        tenant_id=tenant_id,
        agent_identity_id=agent_identity_id,
        ai_system_id=ai_system_id,
        token_hash=token_hash(raw_token),
        scopes=scopes,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        chain_depth=chain_depth,
        issued_by_user_id=issued_by_user_id,
    )
    db.add(token)
    db.flush()
    return token


def _approval_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _approval_is_within_sla(request: ApprovalRequest, *, now: datetime) -> bool:
    deadline = _approval_datetime(request.created_at) + timedelta(minutes=int(request.sla_minutes))
    if _approval_datetime(now) > deadline:
        return False
    if request.decided_at is not None and _approval_datetime(request.decided_at) > deadline:
        return False
    return True


_JIT_APPROVAL_FREE_RISK_TIERS = frozenset({"minimal", "low", "limited", "medium"})
_JIT_APPROVAL_REQUIRED_RISK_TIERS = frozenset({"high", "restricted", "critical", "prohibited"})


def jit_token_mint_requires_approval(risk_tier: str | None) -> bool:
    """Return the canonical fail-closed approval policy for JIT token minting."""
    normalized = str(risk_tier or "").strip().lower()
    if normalized in _JIT_APPROVAL_FREE_RISK_TIERS:
        return False
    if normalized in _JIT_APPROVAL_REQUIRED_RISK_TIERS:
        return True
    return True


def consume_jit_token_mint_approval(
    db: Session,
    *,
    tenant_id: str,
    approval_request_id: str,
    ai_system_id: str,
    agent_id: str,
    scopes: list[str],
    chain_depth: int,
    expires_minutes: int,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ApprovalRequest:
    """Validate and single-consume the persisted authority for a high-risk JIT mint."""
    request = db.scalar(
        select(ApprovalRequest).where(
            ApprovalRequest.id == approval_request_id,
            ApprovalRequest.tenant_id == tenant_id,
        )
    )
    if request is None:
        raise ValueError("approved token mint approval request not found")
    if request.status != "approved" or request.decision != "approve":
        raise ValueError("token mint requires an approved persisted approval request")
    if not request.decided_by or request.decided_at is None:
        raise ValueError("token mint approval request lacks authenticated approval authority")
    if request.ai_system_id != ai_system_id:
        raise ValueError("approval request does not match token mint AI system")
    payload = dict(request.request_payload or {})
    approved_expires_minutes = payload.get("expires_minutes")
    if (
        payload.get("type") != "jit_token_mint"
        or payload.get("agent_id") != agent_id
        or list(payload.get("scopes") or []) != list(scopes)
        or payload.get("chain_depth") != chain_depth
        or isinstance(approved_expires_minutes, bool)
        or not isinstance(approved_expires_minutes, int)
        or approved_expires_minutes <= 0
        or expires_minutes > approved_expires_minutes
    ):
        raise ValueError("approval request does not match token mint semantics or approved lifetime")
    clock_fn = clock or (lambda: datetime.now(timezone.utc))
    initial_now = now or clock_fn()
    if not _approval_is_within_sla(request, now=initial_now):
        raise ValueError("token mint approval request expired outside its SLA")

    deadline = _approval_datetime(request.created_at) + timedelta(minutes=int(request.sla_minutes))
    consumed = db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.id == approval_request_id,
            ApprovalRequest.tenant_id == tenant_id,
            ApprovalRequest.status == "approved",
            ApprovalRequest.decision == "approve",
        )
        .values(status="used")
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        raise ValueError("approved token mint approval request was already consumed")
    if _approval_datetime(clock_fn()) > deadline:
        db.rollback()
        raise ValueError("token mint approval request expired outside its SLA during consumption")
    db.flush()
    db.refresh(request)
    return request


def mint_capability_token_with_authority(
    db: Session,
    *,
    tenant_id: str,
    ai_system: AISystem,
    agent_identity_id: str,
    raw_token: str,
    scopes: list[str],
    expires_minutes: int,
    chain_depth: int,
    issued_by_user_id: str | None,
    approval_request_id: str | None = None,
) -> tuple[CapabilityToken, str | None]:
    """Mint a capability token and consume any required approval in one DB transaction."""
    if ai_system.tenant_id != tenant_id:
        raise ValueError("AI system not found for tenant")
    approval_id: str | None = None
    if jit_token_mint_requires_approval(ai_system.risk_tier):
        agent = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.id == agent_identity_id,
                AgentIdentity.tenant_id == tenant_id,
            )
        )
        if agent is None:
            raise ValueError("Agent not found for tenant")
        if agent.status != "active":
            raise ValueError("Agent must be active before minting a high-risk capability token")
        if not raw_token or not scopes or expires_minutes <= 0 or chain_depth < 1:
            raise ValueError("Invalid high-risk capability token arguments")
        if chain_depth > agent.max_chain_depth:
            raise ValueError("Requested token chain_depth exceeds agent max_chain_depth")
        if not approval_request_id:
            raise ValueError("high-risk token mint requires an approved persisted approval request")
        consume_jit_token_mint_approval(
            db,
            tenant_id=tenant_id,
            approval_request_id=approval_request_id,
            ai_system_id=ai_system.id,
            agent_id=agent_identity_id,
            scopes=scopes,
            chain_depth=chain_depth,
            expires_minutes=expires_minutes,
        )
        approval_id = approval_request_id
    token = mint_capability_token(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        agent_identity_id=agent_identity_id,
        raw_token=raw_token,
        scopes=scopes,
        expires_minutes=expires_minutes,
        chain_depth=chain_depth,
        issued_by_user_id=issued_by_user_id,
    )
    return token, approval_id


def validate_capability_token(
    db: Session,
    *,
    tenant_id: str,
    raw_token: str,
    required_scope: str,
    chain_depth: int,
) -> tuple[bool, str, CapabilityToken | None, AgentIdentity | None, list[str]]:
    hashed = token_hash(raw_token)
    token = db.scalar(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == tenant_id,
            CapabilityToken.token_hash == hashed,
        )
    )
    if not token:
        return False, "token_not_found", None, None, []

    if token.revoked_at is not None:
        return False, "token_revoked", token, None, []

    expires_at = _normalize_dt(token.expires_at)
    if expires_at < datetime.now(timezone.utc):
        return False, "token_expired", token, None, []

    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == token.agent_identity_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if not agent:
        return False, "agent_not_found", token, None, []

    if agent.status != "active":
        return False, "agent_inactive", token, agent, []

    if chain_depth > token.chain_depth or chain_depth > agent.max_chain_depth:
        return False, "chain_depth_exceeded", token, agent, []

    if agent.owner_attestation_expiry is not None:
        expiry = _normalize_dt(agent.owner_attestation_expiry)
        if expiry < datetime.now(timezone.utc):
            return False, "owner_attestation_expired", token, agent, []

    effective_scopes = list(token.scopes or [])
    if chain_depth > 1 and not bool(agent.capability_inheritance):
        effective_scopes = _reduced_scopes_for_non_inheritance(effective_scopes)

    normalized_required_scope = str(required_scope or "").strip().lower()
    normalized_effective_scopes = _normalized_scope_set(effective_scopes)
    if normalized_required_scope not in normalized_effective_scopes and "*" not in normalized_effective_scopes:
        denial_reason = "scope_reduced_denied" if chain_depth > 1 and not bool(agent.capability_inheritance) else "scope_denied"
        return False, denial_reason, token, agent, effective_scopes

    allowed_action_scope = _normalized_scope_set(getattr(agent, "action_scope", []) or [])
    if allowed_action_scope and normalized_required_scope not in allowed_action_scope and "*" not in allowed_action_scope:
        return False, "agent_action_scope_denied", token, agent, effective_scopes

    return True, "allow", token, agent, effective_scopes


def auto_quarantine_agent_identity(
    db: Session,
    *,
    tenant_id: str,
    discovered_agent_id: str | None,
    source_surface: str | None,
    reason_code: str,
    ai_system_id: str | None = None,
    actor_user_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    normalized_agent_id = str(discovered_agent_id or "").strip()
    if not normalized_agent_id:
        return {"created": False, "reason": "empty_agent_id", "agent": None}

    # AgentIdentity.id is String(36); fail closed for oversized external IDs.
    if len(normalized_agent_id) > 36:
        return {"created": False, "reason": "agent_id_too_long", "agent": None}

    metadata_json = dict(metadata or {})

    def _list_from_metadata(*keys: str, fallback: list[str] | None = None) -> list[str]:
        collected: list[str] = []
        for key in keys:
            values = metadata_json.get(key)
            if not isinstance(values, (list, tuple, set)):
                continue
            for item in values:
                token = str(item or "").strip()
                if token and token not in collected:
                    collected.append(token)
        if collected:
            return collected
        return list(fallback or [])

    discovered_name = str(metadata_json.get("agent_name") or "").strip()
    discovered_model = str(metadata_json.get("model_name") or "").strip()
    discovered_runtime = str(metadata_json.get("runtime_provider") or "").strip()
    discovered_environment = str(metadata_json.get("environment") or "").strip()

    tool_registry = _list_from_metadata("tools", "detected_tools")
    action_scope = _list_from_metadata("action_scope", "actions", "detected_actions", fallback=["tool.read"])
    external_access = _list_from_metadata("external_system_access", "detected_privileges", "privileges")

    description_parts = ["Automatically quarantined until admin approval"]
    if discovered_model:
        description_parts.append(f"model={discovered_model}")
    if discovered_runtime:
        description_parts.append(f"runtime={discovered_runtime}")
    if discovered_environment:
        description_parts.append(f"environment={discovered_environment}")
    description = " · ".join(description_parts)[:1000]

    def _merge_unique(existing_values: Any, incoming_values: list[str]) -> list[str]:
        merged: list[str] = []
        for item in existing_values if isinstance(existing_values, list) else []:
            token = str(item or "").strip()
            if token and token not in merged:
                merged.append(token)
        for item in incoming_values:
            token = str(item or "").strip()
            if token and token not in merged:
                merged.append(token)
        return merged

    existing = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == normalized_agent_id,
        )
    )
    if existing is not None:
        updated = False
        if discovered_name and str(existing.name or "").startswith("Auto-discovered agent"):
            existing.name = discovered_name[:255]
            updated = True
        if (tool_registry and not list(existing.tool_registry or [])):
            existing.tool_registry = _merge_unique(existing.tool_registry, tool_registry)
            updated = True
        if (action_scope and (list(existing.action_scope or []) == ["tool.read"])):
            existing.action_scope = _merge_unique(existing.action_scope, action_scope)
            updated = True
        if (external_access and not list(existing.external_system_access or [])):
            existing.external_system_access = _merge_unique(existing.external_system_access, external_access)
            updated = True
        if (
            (discovered_model or discovered_runtime or discovered_environment)
            and str(existing.description or "").strip() == "Automatically quarantined until admin approval"
        ):
            existing.description = description
            updated = True
        if updated:
            if len(list(existing.action_scope or [])) >= 3 and str(existing.autonomy_level or "") == "low":
                existing.autonomy_level = "medium"
            db.flush()
        return {"created": False, "reason": "already_registered", "agent": existing}

    row = AgentIdentity(
        id=normalized_agent_id,
        tenant_id=tenant_id,
        name=(discovered_name or f"Auto-discovered agent {normalized_agent_id[:8]}")[:255],
        description=description,
        status="quarantined",
        max_chain_depth=1,
        capability_inheritance=False,
        action_scope=action_scope,
        tool_registry=tool_registry,
        external_system_access=external_access,
        agent_type="unregistered_agent",
        autonomy_level=("medium" if len(action_scope) >= 3 else "low"),
    )
    db.add(row)
    db.flush()

    payload = {
        "agent_id": normalized_agent_id,
        "source_surface": str(source_surface or "").strip().lower() or "unknown",
        "reason_code": str(reason_code or "").strip().lower() or "auto_quarantine",
        "status": "quarantined",
        "ai_system_id": ai_system_id,
        "metadata": dict(metadata or {}),
    }

    evidence_node_id: str | None = None
    audit_log_id: str | None = None
    try:
        from app.services.evidence_service import create_evidence_node

        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="ai_iam_agent_auto_quarantine",
            signal_type="ai_iam.agent.auto_quarantine",
            label=f"Auto-quarantined agent {normalized_agent_id}",
            payload=payload,
            correlation_id=correlation_id,
        )
        evidence_node_id = evidence.id
    except Exception:
        evidence_node_id = None

    try:
        from app.services.audit_service import write_audit_log

        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system",
            action="ai_iam.agent.auto_quarantine",
            resource_type="agent_identity",
            resource_id=normalized_agent_id,
            payload={**payload, "evidence_node_id": evidence_node_id},
            correlation_id=correlation_id,
        )
        audit_log_id = audit.id
    except Exception:
        audit_log_id = None

    return {
        "created": True,
        "reason": "created",
        "agent": row,
        "evidence_node_id": evidence_node_id,
        "audit_log_id": audit_log_id,
    }


def track_behavior_anomaly(
    db: Session,
    *,
    tenant_id: str,
    agent_identity_id: str,
    action: str,
    now: datetime | None = None,
) -> dict:
    current_time = _normalize_dt(now or datetime.now(timezone.utc))
    row = db.scalar(
        select(AgentActionBaseline).where(
            AgentActionBaseline.tenant_id == tenant_id,
            AgentActionBaseline.agent_identity_id == agent_identity_id,
            AgentActionBaseline.action == action,
        )
    )

    if row is None:
        row = AgentActionBaseline(
            tenant_id=tenant_id,
            agent_identity_id=agent_identity_id,
            action=action,
            baseline_rate_per_hour=1.0,
            current_window_count=1,
            window_started_at=current_time,
            last_seen_at=current_time,
            metadata_json={},
        )
        db.add(row)
        db.flush()
        return {
            "is_anomaly": False,
            "baseline_rate_per_hour": row.baseline_rate_per_hour,
            "current_window_count": row.current_window_count,
            "spike_threshold": max(5.0, row.baseline_rate_per_hour * 3.0),
        }

    window_started = _normalize_dt(row.window_started_at)
    elapsed_seconds = max(0.0, (current_time - window_started).total_seconds())
    if elapsed_seconds >= 3600.0:
        row.baseline_rate_per_hour = max(
            1.0,
            (0.8 * float(row.baseline_rate_per_hour)) + (0.2 * float(row.current_window_count)),
        )
        row.current_window_count = 1
        row.window_started_at = current_time
    else:
        row.current_window_count = int(row.current_window_count) + 1

    row.last_seen_at = current_time
    spike_threshold = max(5.0, float(row.baseline_rate_per_hour) * 3.0)
    is_anomaly = float(row.current_window_count) > spike_threshold
    if is_anomaly:
        row.last_anomaly_at = current_time
        row.metadata_json = {
            **(row.metadata_json or {}),
            "last_anomaly_action": action,
            "last_anomaly_count": row.current_window_count,
            "spike_threshold": spike_threshold,
            "last_anomaly_at": current_time.isoformat(),
        }

    db.flush()
    return {
        "is_anomaly": is_anomaly,
        "baseline_rate_per_hour": float(row.baseline_rate_per_hour),
        "current_window_count": int(row.current_window_count),
        "spike_threshold": float(spike_threshold),
    }


def compute_agent_identity_risk_score(
    *,
    token_valid: bool,
    token_reason: str | None,
    agent_matches_token: bool,
    action_scope_ok: bool,
    tool_ok: bool,
    target_ok: bool,
    chain_depth_ok: bool,
    data_classification: str,
    behavior_anomaly: dict[str, Any] | None = None,
    prior_violation_count: int | None = None,
) -> dict[str, Any]:
    score = 0.1
    reasoning: list[str] = []

    def _bump(delta: float, reason: str) -> None:
        nonlocal score
        score += float(delta)
        reasoning.append(reason)

    if not token_valid:
        _bump(0.35, f"capability token invalid ({str(token_reason or 'unknown')})")

    if not agent_matches_token:
        _bump(0.3, "agent identity mismatch for presented capability token")

    if not action_scope_ok:
        _bump(0.18, "action scope violation detected")
    if not tool_ok:
        _bump(0.22, "tool allowlist violation detected")
    if not target_ok:
        _bump(0.18, "external target allowlist violation detected")
    if not chain_depth_ok:
        _bump(0.2, "chain depth exceeded configured maximum")

    classification = str(data_classification or "unknown").strip().lower()
    if classification in {"sensitive", "protected"}:
        _bump(0.15, "sensitive data context increases identity risk")
    elif classification in {"internal", "confidential"}:
        _bump(0.08, "internal data context increases identity risk")
    elif classification not in {"public"}:
        _bump(0.04, "unknown data classification adds uncertainty")

    anomaly = dict(behavior_anomaly or {})
    if bool(anomaly.get("is_anomaly")):
        _bump(0.24, "behavior anomaly exceeds learned baseline")
        try:
            current = float(anomaly.get("current_window_count") or 0.0)
            threshold = float(anomaly.get("spike_threshold") or 0.0)
            if threshold > 0 and current >= (threshold * 2.0):
                _bump(0.12, "anomaly magnitude is significantly above spike threshold")
        except Exception:
            pass

    violations = max(0, int(prior_violation_count or 0))
    if violations >= 3:
        _bump(min(0.18, 0.04 * float(violations - 2)), "historical violations indicate sustained identity risk")

    normalized_score = round(_clamp_score(score), 4)
    if normalized_score >= 0.85:
        risk_level = "critical"
    elif normalized_score >= 0.65:
        risk_level = "high"
    elif normalized_score >= 0.4:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "risk_reasoning": reasoning,
        "behavior_anomaly": anomaly,
    }


def revoke_capability_token(db: Session, *, tenant_id: str, token_id: str) -> CapabilityToken | None:
    token = db.scalar(
        select(CapabilityToken).where(CapabilityToken.id == token_id, CapabilityToken.tenant_id == tenant_id)
    )
    if not token:
        return None
    token.revoked_at = datetime.now(timezone.utc)
    db.flush()
    return token


def create_agent_delegation(
    db: Session,
    *,
    tenant_id: str,
    parent_agent_identity_id: str,
    child_agent_identity_id: str,
    parent_token_id: str,
    child_token_id: str,
    ai_system_id: str | None,
    action_scope: list[str],
    chain_depth: int,
    metadata: dict | None = None,
) -> AgentDelegation:
    row = AgentDelegation(
        tenant_id=tenant_id,
        parent_agent_identity_id=parent_agent_identity_id,
        child_agent_identity_id=child_agent_identity_id,
        ai_system_id=ai_system_id,
        parent_token_id=parent_token_id,
        child_token_id=child_token_id,
        action_scope=list(action_scope or []),
        chain_depth=max(1, int(chain_depth)),
        status="active",
        metadata_json=dict(metadata or {}),
    )
    db.add(row)
    db.flush()
    return row


def collect_delegation_descendant_agent_ids(
    db: Session,
    *,
    tenant_id: str,
    root_agent_identity_id: str,
) -> list[str]:
    descendants: set[str] = set()
    frontier: list[str] = [root_agent_identity_id]
    visited: set[str] = set()

    while frontier:
        current_parent = frontier.pop(0)
        if current_parent in visited:
            continue
        visited.add(current_parent)

        rows = db.scalars(
            select(AgentDelegation).where(
                AgentDelegation.tenant_id == tenant_id,
                AgentDelegation.parent_agent_identity_id == current_parent,
                AgentDelegation.status == "active",
            )
        ).all()
        for row in rows:
            child_id = str(row.child_agent_identity_id or "").strip()
            if not child_id or child_id in descendants:
                continue
            descendants.add(child_id)
            frontier.append(child_id)

    descendants.discard(root_agent_identity_id)
    return sorted(descendants)


def revoke_agent_delegations(
    db: Session,
    *,
    tenant_id: str,
    impacted_agent_identity_ids: list[str],
    revoked_at: datetime | None = None,
) -> int:
    impacted = {str(item).strip() for item in impacted_agent_identity_ids if str(item).strip()}
    if not impacted:
        return 0

    ts = _normalize_dt(revoked_at or datetime.now(timezone.utc))
    rows = db.scalars(
        select(AgentDelegation).where(
            AgentDelegation.tenant_id == tenant_id,
            AgentDelegation.status == "active",
        )
    ).all()
    updated = 0
    for row in rows:
        if row.parent_agent_identity_id in impacted or row.child_agent_identity_id in impacted:
            row.status = "revoked"
            row.revoked_at = ts
            updated += 1
    db.flush()
    return updated
