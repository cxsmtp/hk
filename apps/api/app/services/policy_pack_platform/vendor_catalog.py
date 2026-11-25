"""Data-only vendor policy library for the Policy Pack Platform.

The catalog intentionally contains typed configuration only.  It is not a
policy evaluator, does not import a provider SDK, and does not contain free
form execution.  The service persists these definitions and compiles their
condition trees through Hawk's existing deterministic policy path.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable


CATALOG_VERSION = "1.0.0"
INFORMATIVE_MAPPING_DISCLAIMER = (
    "Informative reference mapping only. It is not a certification, legal conclusion, or statement of compliance."
)

ALL_SURFACES = [
    "browser",
    "endpoint",
    "runtime",
    "saas_api",
    "provider_native_hook",
    "mcp_gateway",
    "ai_api_gateway",
    "target_service_integration",
]
BROWSER_ENDPOINT_SAAS = ["browser", "endpoint", "saas_api"]
BROWSER_RUNTIME_SAAS = ["browser", "runtime", "saas_api"]
ENDPOINT_RUNTIME = ["endpoint", "runtime"]
ENDPOINT_RUNTIME_SAAS = ["endpoint", "runtime", "saas_api"]
RUNTIME_SAAS = ["runtime", "saas_api"]

BASE_PARAMETERS = {
    "approved_ai_applications": [],
    "approved_providers": [],
    "approved_models": [],
    "approved_enterprise_workspaces": [],
    "approved_destinations": [],
    "allowed_partner_classes": [],
    "data_classifications": ["public", "internal", "confidential", "restricted"],
    "business_purposes": [],
    "human_review_role": "",
    "approval_role": "",
    "second_approval_role": "",
    "exception_expiry_hours": 8,
    "retention_days": 30,
    "restricted_account_classes": ["personal", "anonymous", "external", "unknown", "unapproved"],
    "sensitive_data_classes": ["confidential", "restricted"],
    "external_destination_classes": ["external", "public"],
    "untrusted_tool_states": ["unknown", "stale", "regressed", "unavailable"],
    "high_risk_action_classes": ["destructive_command", "credential_access", "production_change", "bulk_file_operation", "privileged_execution"],
}
BASE_CUSTOMIZATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "approved_ai_applications": {"type": "array", "items": {"type": "string"}},
        "approved_providers": {"type": "array", "items": {"type": "string"}},
        "approved_models": {"type": "array", "items": {"type": "string"}},
        "approved_enterprise_workspaces": {"type": "array", "items": {"type": "string"}},
        "approved_destinations": {"type": "array", "items": {"type": "string"}},
        "allowed_partner_classes": {"type": "array", "items": {"type": "string"}},
        "human_review_role": {"type": "string"},
        "approval_role": {"type": "string"},
        "second_approval_role": {"type": "string"},
        "exception_expiry_hours": {"type": "integer", "minimum": 1, "maximum": 168},
        "retention_days": {"type": "integer", "minimum": 1, "maximum": 3650},
        "restricted_account_classes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "sensitive_data_classes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "external_destination_classes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "untrusted_tool_states": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "high_risk_action_classes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
    },
}
BASE_BLIND_SPOTS = [
    "A pack never upgrades a surface from post-event visibility to pre-execution enforcement.",
    "Provider, account, destination, and content semantics depend on the selected healthy control point.",
]


def _reference(identifier: str, title: str, status: str) -> dict[str, str]:
    return {"id": identifier, "title": title, "status": status}


def _mappings(references: Iterable[dict[str, str]]) -> dict[str, Any]:
    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for reference in references:
        identifier = str(reference.get("id") or "")
        if identifier and identifier not in seen:
            seen.add(identifier)
            unique.append(deepcopy(reference))
    return {"references": unique, "disclaimer": INFORMATIVE_MAPPING_DISCLAIMER}


CROSS_SECTOR_REFERENCES = [
    _reference("nist-ai-rmf-1.0", "NIST AI Risk Management Framework 1.0", "CURRENT_REFERENCE"),
    _reference("nist-ai-600-1", "NIST AI 600-1 Generative AI Profile", "CURRENT_REFERENCE"),
    _reference("iso-iec-42001-2023", "ISO/IEC 42001:2023", "CURRENT_REFERENCE"),
    _reference("iso-iec-27090", "ISO/IEC 27090", "PROVISIONAL_REFERENCE"),
    _reference("eu-ai-act", "EU AI Act", "CURRENT_REFERENCE"),
    _reference("owasp-agentic-applications-top-10-2026", "OWASP Top 10 for Agentic Applications 2026", "CURRENT_REFERENCE"),
    _reference("owasp-genai-llm-top-10-2026", "OWASP GenAI LLM Top 10 2026", "CURRENT_REFERENCE"),
    _reference("uae-pdpl", "UAE Personal Data Protection Law", "REVIEW_REQUIRED"),
]

INDIA_AI_REFERENCES = [
    _reference("meity-india-ai-governance-guidelines-2025", "MeitY India AI Governance Guidelines under IndiaAI Mission", "CURRENT_REFERENCE"),
    _reference("dpdp-act-2023", "India Digital Personal Data Protection Act, 2023", "CURRENT_REFERENCE"),
    _reference("dpdp-rules-2025", "India Digital Personal Data Protection Rules, 2025", "CURRENT_REFERENCE"),
    _reference("customer-india-ai-obligations", "Customer-selected Indian AI, privacy, sectoral, and contractual obligations", "CUSTOMER_SPECIFIC"),
]

INDIA_BFSI_AI_REFERENCES = [
    _reference("rbi-free-ai-2025", "RBI FREE-AI: Framework for Responsible and Ethical Enablement of Artificial Intelligence in the Financial Sector", "CURRENT_REFERENCE"),
    _reference("rbi-it-governance-risk-controls-assurance-2023", "RBI IT Governance, Risk, Controls and Assurance Practices Directions", "CURRENT_REFERENCE"),
    _reference("rbi-it-outsourcing-2023", "RBI IT Outsourcing Directions", "CURRENT_REFERENCE"),
    _reference("customer-rbi-ai-obligations", "Customer-selected RBI, banking, NBFC, outsourcing, cyber, model-risk, and operational-resilience obligations", "CUSTOMER_SPECIFIC"),
]

INDIA_MARKETS_AI_REFERENCES = [
    _reference("sebi-ai-ml-reporting-2019", "SEBI AI/ML reporting requirements for market intermediaries", "CURRENT_REFERENCE"),
    _reference("sebi-cscrf-2024", "SEBI Cybersecurity and Cyber Resilience Framework for regulated entities", "CURRENT_REFERENCE"),
    _reference("customer-sebi-ai-obligations", "Customer-selected SEBI, exchange, intermediary, adviser, broker, and market-infrastructure obligations", "CUSTOMER_SPECIFIC"),
]

AGENTIC_AI_REFERENCES = [
    _reference("imda-agentic-ai-governance-framework-2026", "IMDA Model AI Governance Framework for Agentic AI", "CURRENT_REFERENCE"),
    _reference("imda-generative-ai-governance-framework-2024", "IMDA Model AI Governance Framework for Generative AI", "CURRENT_REFERENCE"),
]

VERTICAL_REFERENCES = {
    "bfsi": [
        _reference("cbuae-responsible-ai-ml", "CBUAE responsible AI/ML guidance for Licensed Financial Institutions", "REVIEW_REQUIRED"),
        _reference("cbuae-consumer-protection", "CBUAE Consumer Protection and enabling-technology guidance", "REVIEW_REQUIRED"),
        *INDIA_BFSI_AI_REFERENCES,
        _reference("customer-banking-obligations", "Customer-selected banking, outsourcing, model-risk, and resilience obligations", "CUSTOMER_SPECIFIC"),
    ],
    "payments": [
        _reference("cbuae-retail-payment-services", "CBUAE Retail Payment Services and Card Schemes Regulation", "REVIEW_REQUIRED"),
        _reference("pci-dss-v4-0-1", "PCI DSS v4.0.1", "CURRENT_REFERENCE"),
        _reference("customer-payment-obligations", "Customer-selected scheme, AML/CFT, and payment-network obligations", "CUSTOMER_SPECIFIC"),
    ],
    "insurance": [
        _reference("cbuae-insurance-requirements", "CBUAE financial and insurance requirements", "REVIEW_REQUIRED"),
        _reference("naic-ai-systems-bulletin", "NAIC Model Bulletin on Use of AI Systems by Insurers", "CURRENT_REFERENCE"),
        _reference("eiopa-ai-guidance", "EIOPA AI governance and risk-management guidance", "CURRENT_REFERENCE"),
        _reference("customer-insurance-obligations", "Customer-selected local insurance obligations", "CUSTOMER_SPECIFIC"),
    ],
    "telecom": [
        _reference("gsma-responsible-ai-maturity-roadmap", "GSMA Responsible AI Maturity Roadmap", "CURRENT_REFERENCE"),
        _reference("customer-telecom-obligations", "Customer-selected telecom, privacy, and critical-infrastructure obligations", "CUSTOMER_SPECIFIC"),
        _reference("itu-industry-references", "ITU and applicable industry references", "REVIEW_REQUIRED"),
    ],
    "real_estate": [
        _reference("rics-responsible-ai-surveying", "RICS Responsible Use of AI in Surveying Practice", "CURRENT_REFERENCE"),
        _reference("uae-pdpl", "UAE Personal Data Protection Law", "REVIEW_REQUIRED"),
        _reference("customer-real-estate-obligations", "Customer-selected DLD/RERA, professional, advertising, and contract obligations", "CUSTOMER_SPECIFIC"),
    ],
}


def _rule(
    rule_id: str,
    title: str,
    reason: str,
    action_class: str,
    *,
    decision: str = "require_approval",
    surfaces: list[str] | None = None,
    criticality: str = "high",
    default_mode: str = "monitor",
    recommended_mature_mode: str = "enforce",
    non_overridable: bool = False,
    condition_tree: dict[str, Any] | None = None,
    required_fields: list[str] | None = None,
    required_control_capabilities: list[str] | None = None,
    obligations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a fully typed template specification from canonical attributes."""

    tree = condition_tree or {"field": "action_class", "operator": "equals", "value": action_class}
    fields = required_fields or (["action_class"] if condition_tree is None else [])
    if not fields:
        # All catalog-provided compound trees have one explicit canonical field.
        def collect(node: dict[str, Any]) -> list[str]:
            if "field" in node:
                return [str(node["field"])]
            if "not" in node:
                return collect(node["not"])
            children = node.get("all") if isinstance(node.get("all"), list) else node.get("any", [])
            return [field for child in children if isinstance(child, dict) for field in collect(child)]

        fields = sorted(set(collect(tree)))
    if obligations is None and decision in {"require_approval", "hold_for_approval"}:
        obligations = {"approval_level": "human_review" if decision == "require_approval" else "capability_quarantine"}
    return {
        "template_id": rule_id,
        "title": title,
        "reason": reason,
        "condition_tree": tree,
        "decision": decision,
        "obligations": obligations or {},
        "applicable_surfaces": list(surfaces or RUNTIME_SAAS),
        "required_fields": fields,
        "required_control_capabilities": list(required_control_capabilities or ["pre_execution_block"]),
        "default_mode": default_mode,
        "recommended_mature_mode": recommended_mature_mode,
        "criticality": criticality,
        "override_behavior": "customer_override_allowed",
        "exception_rules": {"max_hours": 8, "requires_reason": True},
        "simulation_expectations": {"minimum_sample_count": 1},
        "evidence_requirements": ["decision_receipt", "execution_receipt"],
        "human_explanation": reason,
        "reference_mappings": _mappings(CROSS_SECTOR_REFERENCES),
        "non_overridable": non_overridable,
        "explicit_revocation": False,
    }


def _local_rule(pack_id: str, rule: dict[str, Any], *, references: list[dict[str, str]]) -> dict[str, Any]:
    template = _rule(
        f"{pack_id.removeprefix('hawk:')}:{rule['id']}",
        rule["title"],
        rule["reason"],
        rule["action"],
        decision=rule.get("decision", "require_approval"),
        surfaces=rule.get("surfaces", RUNTIME_SAAS),
        criticality=rule.get("criticality", "high"),
        default_mode=rule.get("default_mode", "monitor"),
        recommended_mature_mode=rule.get("recommended_mature_mode", "enforce"),
        non_overridable=bool(rule.get("non_overridable", False)),
        condition_tree=rule.get("condition_tree"),
        required_fields=rule.get("required_fields"),
        required_control_capabilities=rule.get("required_control_capabilities"),
        obligations=rule.get("obligations"),
    )
    template["reference_mappings"] = _mappings([*CROSS_SECTOR_REFERENCES, *references])
    return template


def _entry(
    identifier: str,
    title: str,
    reason: str,
    action: str,
    **kwargs: Any,
) -> dict[str, Any]:
    return {"id": identifier, "title": title, "reason": reason, "action": action, **kwargs}


def _pack(
    stable_pack_id: str,
    name: str,
    description: str,
    *,
    vertical: str,
    department_persona: str,
    pack_family: str,
    inherited_pack_refs: list[str] | None = None,
    rules: list[dict[str, Any]] | None = None,
    references: list[dict[str, str]] | None = None,
    surfaces: list[str] | None = None,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    local_rules = list(rules or [])
    refs = list(references or [])
    templates = [_local_rule(stable_pack_id, rule, references=refs) for rule in local_rules]
    declared_surfaces = list(surfaces or sorted({surface for template in templates for surface in template["applicable_surfaces"]}) or ALL_SURFACES)
    signals = sorted({field for template in templates for field in template["required_fields"]})
    capabilities = sorted({capability for template in templates for capability in template["required_control_capabilities"]})
    return {
        "publisher_tenant_id": None,
        "stable_pack_id": stable_pack_id,
        "version": CATALOG_VERSION,
        "name": name,
        "description": description,
        "vertical": vertical,
        "department_persona": department_persona,
        "pack_family": pack_family,
        "maturity_status": "reviewed",
        "package_entitlement": "secure",
        "applicable_jurisdictions": ["global"],
        "framework_mappings": _mappings([*CROSS_SECTOR_REFERENCES, *refs]),
        "inherited_pack_refs": list(inherited_pack_refs or []),
        "templates": templates,
        "required_signals": signals,
        "required_control_capabilities": capabilities,
        "supported_deployment_surfaces": declared_surfaces,
        "default_parameters": {**BASE_PARAMETERS, **(parameters or {})},
        "customization_schema": deepcopy(BASE_CUSTOMIZATION_SCHEMA),
        "simulation_required": True,
        "default_rollout": "MONITORING",
        "exception_guidance": "Use an approved, exact-scope, time-limited exception; a pack exception never bypasses tenant isolation or explicit revocation.",
        "known_blind_spots": list(BASE_BLIND_SPOTS),
        "owner_publisher": "hawk",
        "release_notes": "Initial data-only vertical policy library release.",
        "state": "PUBLISHED",
    }


def _universal_baseline() -> dict[str, Any]:
    templates = [
        _rule("uai-001", "Approved AI applications, providers and models", "Keep unknown or unapproved AI use visible and require review before mature restriction.", "approved_ai_boundary", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"field": "account_class", "operator": "in", "value": ["$parameter:restricted_account_classes"]}, required_fields=["account_class"]),
        _rule("uai-002", "Enterprise account boundary", "Restricted data must not use personal, anonymous, external, or unknown AI accounts without an approved exception.", "account_boundary", decision="block", surfaces=BROWSER_ENDPOINT_SAAS, default_mode="monitor", condition_tree={"field": "account_class", "operator": "in", "value": ["$parameter:restricted_account_classes"]}, required_fields=["account_class"]),
        _rule("uai-003", "Sensitive data in prompts, uploads and retrieval", "Use classification, represented subject, purpose, and destination context before sensitive data reaches an external AI destination.", "sensitive_data_transfer", decision="redact", surfaces=ALL_SURFACES, condition_tree={"all": [{"field": "data_classification", "operator": "in", "value": ["$parameter:sensitive_data_classes"]}, {"field": "destination_class", "operator": "in", "value": ["$parameter:external_destination_classes"]}]}, required_fields=["data_classification", "destination_class"]),
        _rule("uai-004", "Secrets, credentials and private keys", "Block clear credentials, tokens, private keys, and secret-bearing files from unapproved AI destinations; use secret references instead.", "secret_exposure", decision="block", surfaces=ALL_SURFACES, default_mode="block", criticality="critical", condition_tree={"field": "credential_present", "operator": "equals", "value": True}, required_fields=["credential_present"]),
        _rule("uai-005", "External sharing and destination control", "Require a controlled destination before external sharing of enterprise data or AI-generated material.", "external_sharing", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"field": "destination_class", "operator": "in", "value": ["$parameter:external_destination_classes"]}, required_fields=["destination_class"]),
        _rule("uai-006", "MCP, tool and external-capability trust", "Unknown, stale, regressed, or unavailable tools require review before use.", "tool_capability_trust", decision="hold_for_approval", surfaces=["runtime", "saas_api", "mcp_gateway", "browser", "endpoint"], condition_tree={"field": "tool_trust_state", "operator": "in", "value": ["$parameter:untrusted_tool_states"]}, required_fields=["tool_trust_state"]),
        _rule("uai-007", "High-risk commands, code and file actions", "Destructive commands, credential access, production changes, and bulk file actions require human authority.", "high_risk_command", decision="require_approval", surfaces=ENDPOINT_RUNTIME, condition_tree={"field": "action_class", "operator": "in", "value": ["$parameter:high_risk_action_classes"]}, required_fields=["action_class"]),
        _rule("uai-008", "Subject, resource and tenant isolation", "Block cross-subject, cross-resource, and cross-tenant access outside valid originating authority.", "subject_scope_violation", decision="block", surfaces=["runtime", "saas_api", "endpoint", "browser"], default_mode="block", criticality="critical", non_overridable=True, condition_tree={"field": "action_class", "operator": "equals", "value": "subject_scope_violation"}, required_fields=["action_class"]),
        _rule("uai-009", "Agent authority and delegation", "An agent or child agent must not silently expand delegated authority, tool access, or destination scope.", "delegation_expansion", decision="require_approval", surfaces=RUNTIME_SAAS, condition_tree={"field": "agent_capability", "operator": "equals", "value": "authority_expansion"}, required_fields=["agent_capability"]),
        _rule("uai-010", "Approval and material-action binding", "A change to subject, resource, tool, target, destination, value, side effect, persistence, or authority requires a new approval.", "approval_material_change", decision="require_approval", surfaces=RUNTIME_SAAS, condition_tree={"field": "action_class", "operator": "equals", "value": "material_action_change"}, required_fields=["action_class"]),
        _rule("uai-011", "Persistent side effects", "Persistent access, automation, sharing, memory, roles, jobs, and cloud resources require a bounded approval.", "persistent_side_effect", decision="require_approval", surfaces=["runtime", "endpoint", "saas_api"], condition_tree={"field": "persistence", "operator": "equals", "value": True}, required_fields=["persistence"]),
        _rule("uai-012", "RAG, retrieval and memory governance", "Retrieval and memory operations require subject, purpose, resource, and data-class context.", "retrieval_memory", decision="require_approval", surfaces=RUNTIME_SAAS, condition_tree={"field": "action_class", "operator": "in", "value": ["retrieval", "memory_write", "memory_rehydration", "embedding_export"]}, required_fields=["action_class"]),
        _rule("uai-013", "Untrusted instruction and prompt-injection handling", "Consequential behavior influenced by untrusted instructions cannot become authority without a verified source and purpose.", "untrusted_instruction", decision="block", surfaces=["browser", "runtime", "saas_api"], condition_tree={"all": [{"field": "purpose_missing", "operator": "equals", "value": True}, {"field": "side_effect", "operator": "equals", "value": True}]}, required_fields=["purpose_missing", "side_effect"]),
        _rule("uai-014", "Direct API, gateway and control-route bypass", "Direct provider or tool paths that bypass required controls are visible and can be blocked or rerouted by mature policy.", "control_route_bypass", decision="require_approval", surfaces=ENDPOINT_RUNTIME_SAAS, condition_tree={"field": "control_health", "operator": "equals", "value": "bypassed"}, required_fields=["control_health"]),
        _rule("uai-015", "Stale, regressed or unavailable control handling", "A stale, regressed, or unhealthy control cannot continue to be treated as current enforcement.", "control_degradation", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"field": "control_health", "operator": "in", "value": ["stale", "regressed", "unavailable", "unhealthy"]}, required_fields=["control_health"]),
        _rule("uai-016", "Bulk, value and quantity thresholds", "High-value or high-volume actions need stepped-up approval, quantity limits, and a rollback path.", "bulk_value_threshold", decision="require_approval", surfaces=["runtime", "endpoint", "saas_api"], condition_tree={"field": "value_amount", "operator": "gte", "value": 100000}, required_fields=["value_amount"]),
        _rule("uai-017", "Raw prompt and user-activity privacy", "Retain structured metadata by default and redact sensitive conversational content unless a privileged, time-bound reveal is approved.", "prompt_privacy", decision="redact", surfaces=ALL_SURFACES, condition_tree={"field": "personal_data_present", "operator": "equals", "value": True}, required_fields=["personal_data_present"], default_mode="metadata_only", recommended_mature_mode="redacted", criticality="high"),
        _rule("uai-018", "AI-generated external communications", "Material customer, regulatory, legal, financial, or public communications require accountable human review.", "external_communication", decision="require_approval", surfaces=BROWSER_RUNTIME_SAAS),
    ]
    return {
        **_pack(
            "hawk:universal-baseline",
            "Universal AI Safety Baseline",
            "A reusable cross-sector baseline for approved AI use, authority, data handling, tools, and consequential actions.",
            vertical="universal",
            department_persona="all",
            pack_family="universal_baseline",
            surfaces=ALL_SURFACES,
        ),
        "templates": templates,
        "required_signals": sorted({field for template in templates for field in template["required_fields"]}),
        "required_control_capabilities": sorted({capability for template in templates for capability in template["required_control_capabilities"]}),
    }


def _shared_packs() -> list[dict[str, Any]]:
    parent = ["hawk:universal-baseline"]
    return [
        _pack("hawk:common-exec", "Executive & Board", "Protect board material and require accountable review of material external statements and consequential enterprise actions.", vertical="universal", department_persona="executive_board", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("board-strategy", "Board and strategy material", "Board packs, strategy, M&A, earnings, pricing, and confidential management material require an approved enterprise workspace.", "board_strategy_material", decision="block", surfaces=BROWSER_ENDPOINT_SAAS),
            _entry("material-statement", "Material external statement", "Market, regulator, investor, and media statements require communications or legal approval.", "material_external_statement", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("consequential-action", "Consequential business action", "High-value, irreversible, or enterprise-wide actions require a second approval.", "consequential_business_action", obligations={"approval_level": "second_approval"}),
            _entry("executive-privacy", "Executive user visibility", "Security evidence remains metadata-first and does not turn the product into executive productivity monitoring.", "executive_activity_visibility", decision="redact", surfaces=ALL_SURFACES),
        ]),
        _pack("hawk:common-finance", "Finance", "Control financial source use, bank-detail changes, payments, journals, and external auditor sharing.", vertical="universal", department_persona="finance", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("reporting-source", "Financial reporting source control", "AI-generated financial figures need approved source systems and source evidence.", "financial_reporting_generation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("bank-detail", "Bank detail and beneficiary change", "Vendor or customer bank-detail changes require independent verification and a second approval.", "bank_detail_change", obligations={"approval_level": "second_approval"}),
            _entry("payment-journal", "Payment or journal action", "Payment and journal actions bind value, authority, target system, period, and supporting evidence.", "payment_or_journal_action"),
            _entry("auditor-sharing", "External auditor sharing", "Share only approved audit scope, fields, and destinations.", "external_auditor_sharing", decision="require_approval", surfaces=BROWSER_ENDPOINT_SAAS),
        ]),
        _pack("hawk:common-hr", "Human Resources", "Protect employee and candidate data and keep material employment decisions and communications accountable.", vertical="universal", department_persona="human_resources", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("employee-data", "Employee personal data", "Employee IDs, compensation, health, disciplinary, visa, and performance information require an approved AI workspace.", "employee_personal_data", decision="redact", surfaces=ALL_SURFACES),
            _entry("employment-decision", "Hiring or employment decision", "AI may assist, but material hiring, termination, promotion, and compensation decisions require human review.", "employment_decision"),
            _entry("candidate-data", "CV and candidate data", "Candidate data requires an approved provider, purpose, retention posture, and transfer path.", "candidate_data_handling", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("hr-communication", "HR communication", "Material policy, disciplinary, compensation, and termination notices require approval.", "hr_material_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:common-legal", "Legal, Compliance & Internal Audit", "Protect legal privilege and preserve accountable handling of contracts, regulatory responses, and audit evidence.", vertical="universal", department_persona="legal_compliance_audit", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("legal-privilege", "Legal privilege and confidential advice", "Privileged matters and confidential legal advice must not cross into unapproved AI workspaces or accounts.", "legal_privileged_data", decision="block", surfaces=ALL_SURFACES),
            _entry("contract-change", "Contract creation or change", "Material clauses, obligations, governing law, and counterparty terms require review.", "contract_creation_or_change", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("regulatory-response", "Regulatory response", "Regulatory responses require source evidence, legal sign-off, and a second approval before submission.", "regulatory_response", obligations={"approval_level": "second_approval"}),
            _entry("audit-evidence", "Audit-evidence integrity", "Policy, decision, execution, and validation evidence cannot be altered or deleted without authority.", "audit_evidence_alteration", decision="block", surfaces=RUNTIME_SAAS),
        ]),
        _pack("hawk:common-marketing", "Marketing & Communications", "Keep public claims, customer segmentation, generative content, and outreach reviewable and purpose-bound.", vertical="universal", department_persona="marketing_communications", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("public-claim", "Public claim and campaign content", "Regulated, comparative, pricing, investment, coverage, and network-quality claims require approval.", "public_claim_or_campaign", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("segmentation-data", "Customer list and segmentation data", "Personal data, purpose, consent, account class, and destination control apply to segmentation.", "customer_segmentation_data", decision="redact", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("external-content", "External generative content", "Use approved tools and models with human review for brand, copyright, confidential input, and disclosure rules.", "external_generative_content", surfaces=["browser", "saas_api"]),
            _entry("automated-outreach", "Automated outreach", "Consent, channel, contact preference, frequency, and approved-message requirements apply to AI-generated outreach.", "automated_outreach"),
        ]),
        _pack("hawk:common-procurement", "Procurement & Vendor Management", "Protect vendor data and keep onboarding, commitments, and third-party AI introduction accountable.", vertical="universal", department_persona="procurement_vendor_management", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("vendor-data", "Vendor confidential data", "Bids, pricing, terms, bank details, security reviews, and contracts require a controlled destination.", "vendor_confidential_data", decision="redact", surfaces=ALL_SURFACES),
            _entry("vendor-onboarding", "Vendor onboarding or approval", "AI recommendations remain advisory and preserve their evidence.", "vendor_onboarding_or_approval"),
            _entry("purchase-commitment", "Purchase commitment", "Supplier, item, quantity, amount, cost centre, and approver must be bound before a commitment.", "purchase_commitment"),
            _entry("third-party-ai", "Third-party AI or tool introduction", "New external capabilities require an owner, due diligence, data-access review, and control coverage.", "third_party_ai_introduction", decision="hold_for_approval", surfaces=ALL_SURFACES),
        ]),
        _pack("hawk:common-it-security", "IT, Engineering & Security", "Protect source code, secrets, production change, tool trust, and direct model/API routes.", vertical="universal", department_persona="it_engineering_security", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("source-code", "Source code and intellectual property", "Restricted code and proprietary repositories require approved models, accounts, routes, and destinations.", "source_code_external_transfer", decision="block", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("credentials", "Credentials and incident data", "Clear secrets and sensitive incident data are blocked outside an approved secret-reference or incident workflow.", "credential_or_incident_data", decision="block", default_mode="block", criticality="critical", surfaces=ALL_SURFACES),
            _entry("production-change", "Production command or change", "Production commands and changes bind environment, identity, ticket, resource, and rollback.", "production_command_or_change", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("tool-package", "MCP, tool, and package trust", "Unknown, stale, or regressed capabilities are quarantined until reviewed.", "tool_package_trust", decision="hold_for_approval", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("direct-model-api", "Direct model or API use", "Direct provider use must bind approved provider, key, project, and route.", "direct_model_api_use", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:common-data-ai", "Data, AI & Model Teams", "Govern training data, model and agent deployment, external runtime use, instruction changes, and consequential outputs.", vertical="universal", department_persona="data_ai_model_teams", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("training-data", "Training and evaluation data", "Training and evaluation data require approved purpose, provenance, environment, licensing, subject scope, and retention.", "training_evaluation_data", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("model-agent-deployment", "Model or agent deployment", "Model and agent deployments require owner, version, risk class, evaluation, controls, and rollback.", "model_agent_deployment"),
            _entry("external-runtime", "External model or runtime", "External model or runtime use requires an approved provider, runtime, and data route.", "external_model_runtime"),
            _entry("instruction-change", "Prompt or system instruction change", "Material instruction changes require versioned approval, evaluation, and revalidation.", "instruction_change"),
            _entry("consequential-output", "Model output used for a consequential decision", "Model confidence does not become authority; a human or verified deterministic control remains accountable.", "consequential_model_output"),
        ]),
        _pack("hawk:common-support", "Customer Service & Operations", "Keep customer data, account changes, customer answers, and outbound communications subject-bound and reviewable.", vertical="universal", department_persona="customer_service_operations", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("customer-data", "Customer data in AI conversation", "Use the minimum necessary customer information in an approved workspace.", "customer_data_in_conversation", decision="redact", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("account-change", "Account, policy, service, or contract change", "Authenticate the represented subject and bind the exact requested change before execution.", "customer_account_change"),
            _entry("customer-answer", "Customer-facing answer", "Material advice uses an approved source and escalation path.", "customer_facing_answer", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("outbound-document", "Outbound message or document", "Bind recipient, channel, data class, template, and evidence for sensitive or material content.", "outbound_customer_document"),
        ]),
        _pack("hawk:common-sales", "Sales & Relationship Management", "Protect customer and prospect data and keep offers, external commitments, and CRM bulk actions accountable.", vertical="universal", department_persona="sales_relationship_management", pack_family="shared_corporate", inherited_pack_refs=parent, rules=[
            _entry("prospect-data", "Customer or prospect confidential data", "Customer lists, proposals, pricing, and relationship notes require an approved enterprise AI workspace.", "prospect_confidential_data", decision="block", surfaces=BROWSER_ENDPOINT_SAAS),
            _entry("commercial-commitment", "Offer, quote, or commercial commitment", "AI cannot create unauthorized pricing, discount, contractual, or value commitments.", "commercial_commitment", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("external-proposal", "External proposal and communication", "Material claims use approved sources, disclaimers, and a final owner approval.", "external_proposal_communication", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("crm-bulk", "CRM update or bulk action", "Bind the account, record set, action, quantity, and owner before material CRM changes.", "crm_bulk_action"),
        ]),
    ]


def _governance_framework_packs() -> list[dict[str, Any]]:
    """Actionable framework overlays that map references to existing controls.

    These packs deliberately remain data-only and use informative reference
    mappings.  They help customers apply Draft/Monitor policy controls from a
    framework view, but they never claim certification or legal compliance.
    """

    parent = ["hawk:universal-baseline"]
    india_refs = [*INDIA_AI_REFERENCES]
    rbi_refs = [*INDIA_AI_REFERENCES, *INDIA_BFSI_AI_REFERENCES]
    sebi_refs = [*INDIA_AI_REFERENCES, *INDIA_MARKETS_AI_REFERENCES]
    agentic_refs = [*AGENTIC_AI_REFERENCES]
    return [
        _pack(
            "hawk:india-ai-governance",
            "India AI Governance — DPDP & MeitY AI Guidelines",
            "India-focused AI governance overlay for personal data, purpose, retention, transparency, human review, and high-impact AI use.",
            vertical="india",
            department_persona="all",
            pack_family="framework_overlay",
            inherited_pack_refs=parent,
            references=india_refs,
            surfaces=ALL_SURFACES,
            rules=[
                _entry("personal-data-purpose", "Personal data purpose binding", "Personal data use in AI must bind purpose, represented subject, account class, destination, and retention.", "india_personal_data_ai_use", decision="redact", surfaces=ALL_SURFACES, condition_tree={"all": [{"field": "personal_data_present", "operator": "equals", "value": True}, {"field": "business_purpose", "operator": "equals", "value": ""}]}, required_fields=["personal_data_present", "business_purpose"]),
                _entry("sensitive-data-destination", "Sensitive data destination control", "Restricted, confidential, and sensitive data classes require approved AI destinations and account boundaries.", "india_sensitive_data_destination", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"all": [{"field": "data_classification", "operator": "in", "value": ["$parameter:sensitive_data_classes"]}, {"field": "destination_class", "operator": "in", "value": ["$parameter:external_destination_classes"]}]}, required_fields=["data_classification", "destination_class"]),
                _entry("data-principal-rights", "Data principal request and audit evidence", "AI-assisted handling of data principal or privacy requests requires source evidence, owner review, and an audit trail.", "india_data_principal_request", decision="require_approval", surfaces=BROWSER_RUNTIME_SAAS),
                _entry("high-impact-human-review", "High-impact AI human review", "High-impact or consequential AI-assisted decisions require accountable human review and retained decision evidence.", "india_high_impact_ai_decision", decision="require_approval", surfaces=RUNTIME_SAAS, obligations={"approval_level": "human_review"}),
            ],
            parameters={"applicable_jurisdictions": ["india"]},
        ),
        _pack(
            "hawk:india-rbi-free-ai",
            "India BFSI — RBI FREE-AI Responsible AI Controls",
            "RBI-focused overlay for responsible, ethical, explainable, accountable, and controlled AI use by financial-sector teams.",
            vertical="india",
            department_persona="bfsi_risk_compliance_technology",
            pack_family="framework_overlay",
            inherited_pack_refs=["hawk:universal-baseline", "hawk:common-legal", "hawk:common-it-security", "hawk:common-data-ai"],
            references=rbi_refs,
            surfaces=ALL_SURFACES,
            rules=[
                _entry("model-registry", "Model and agent registry control", "Financial-sector model and agent use must bind owner, purpose, version, validation, monitoring, controls, and rollback.", "rbi_model_agent_registry", decision="require_approval", surfaces=RUNTIME_SAAS),
                _entry("outsourced-ai-control", "Outsourced AI and third-party dependency control", "External AI providers, cloud tools, MCP servers, and model APIs require owner, contract path, data route, exit posture, and control coverage.", "rbi_outsourced_ai_dependency", decision="hold_for_approval", surfaces=ENDPOINT_RUNTIME_SAAS),
                _entry("explainability-evidence", "Explainability and decision evidence", "Material financial decisions assisted by AI require source evidence, rationale traceability, and accountable human ownership.", "rbi_explainability_decision_evidence", decision="require_approval", surfaces=BROWSER_RUNTIME_SAAS),
                _entry("operational-resilience", "Operational resilience and control degradation", "Stale, regressed, or unavailable controls require restriction or approval before critical financial-sector action continues.", "rbi_operational_resilience_ai_control", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"field": "control_health", "operator": "in", "value": ["stale", "regressed", "unavailable", "unhealthy"]}, required_fields=["control_health"]),
            ],
            parameters={"applicable_jurisdictions": ["india"], "high_risk_action_classes": ["financial_decision", "production_change", "payment_or_journal_action", "credit_decision_assistance", "trade_order_execution"]},
        ),
        _pack(
            "hawk:india-sebi-ai-governance",
            "India Capital Markets — SEBI AI/ML & Cyber Resilience Controls",
            "SEBI-focused overlay for market intermediaries, investment/research communications, AI/ML reporting, cyber resilience, and market-impacting actions.",
            vertical="india",
            department_persona="capital_markets_compliance_technology",
            pack_family="framework_overlay",
            inherited_pack_refs=["hawk:universal-baseline", "hawk:common-legal", "hawk:common-it-security", "hawk:common-marketing"],
            references=sebi_refs,
            surfaces=ALL_SURFACES,
            rules=[
                _entry("ai-ml-use-register", "AI/ML use registration and owner evidence", "AI/ML use by market-facing teams must retain owner, purpose, model/tool identity, user population, and evidence references.", "sebi_ai_ml_use_register", decision="require_approval", surfaces=RUNTIME_SAAS),
                _entry("market-communication-review", "Market and investor communication review", "AI-assisted market, investor, research, promotional, or advisory communications require approved sources and compliance review.", "sebi_market_investor_communication", decision="require_approval", surfaces=BROWSER_RUNTIME_SAAS),
                _entry("client-data-boundary", "Client and trading data boundary", "Client, portfolio, order, research, and non-public market data must stay inside approved accounts, routes, and destinations.", "sebi_client_market_data_boundary", decision="block", surfaces=ALL_SURFACES),
                _entry("cyber-resilience-control", "Cyber resilience and control degradation", "Critical AI and MCP/tool controls cannot be treated as current after stale, regressed, or unvalidated status.", "sebi_cyber_resilience_ai_control", decision="require_approval", surfaces=ALL_SURFACES, condition_tree={"field": "control_health", "operator": "in", "value": ["stale", "regressed", "unvalidated", "unhealthy"]}, required_fields=["control_health"]),
            ],
            parameters={"applicable_jurisdictions": ["india"]},
        ),
        _pack(
            "hawk:agentic-ai-governance",
            "Agentic AI Governance — IMDA, OWASP Agentic & MITRE ATLAS",
            "Agentic AI overlay for delegation, tool use, MCP gateways, authority expansion, persistent effects, and autonomous or semi-autonomous actions.",
            vertical="universal",
            department_persona="agentic_ai",
            pack_family="framework_overlay",
            inherited_pack_refs=["hawk:universal-baseline", "hawk:common-data-ai", "hawk:common-it-security"],
            references=[*agentic_refs, _reference("mitre-atlas", "MITRE ATLAS", "CURRENT_REFERENCE")],
            surfaces=["runtime", "saas_api", "mcp_gateway", "endpoint", "browser"],
            rules=[
                _entry("agent-authority-boundary", "Agent authority boundary", "An agent, subagent, or delegated workflow cannot exceed originating actor authority, represented subject, tool scope, or destination scope.", "agent_authority_boundary", decision="block", surfaces=RUNTIME_SAAS, condition_tree={"field": "agent_capability", "operator": "equals", "value": "authority_expansion"}, required_fields=["agent_capability"]),
                _entry("tool-contract-change", "Tool and MCP contract change", "Tool identity, schema, fingerprint, publisher, lifecycle, or permission expansion requires review before use.", "agent_tool_contract_change", decision="hold_for_approval", surfaces=["runtime", "saas_api", "mcp_gateway", "endpoint"]),
                _entry("persistent-agent-effect", "Persistent agent side effect", "Agents creating webhooks, jobs, memory, OAuth grants, roles, external shares, or cloud resources require bound approval and rollback.", "agent_persistent_side_effect", decision="require_approval", surfaces=RUNTIME_SAAS, condition_tree={"field": "persistence", "operator": "equals", "value": True}, required_fields=["persistence"]),
                _entry("untrusted-instruction-authority", "Untrusted instruction cannot become authority", "Instructions from web, RAG, tool output, memory, or handoff context cannot authorize consequential action without verified authority.", "agent_untrusted_instruction_authority", decision="block", surfaces=["browser", "runtime", "saas_api", "mcp_gateway"], condition_tree={"all": [{"field": "purpose_missing", "operator": "equals", "value": True}, {"field": "side_effect", "operator": "equals", "value": True}]}, required_fields=["purpose_missing", "side_effect"]),
            ],
        ),
    ]


def _parents(*shared: str) -> list[str]:
    return ["hawk:universal-baseline", *shared]


def _bfsi_packs() -> list[dict[str, Any]]:
    refs = VERTICAL_REFERENCES["bfsi"]
    return [
        _pack("hawk:bfsi-retail", "BFSI — Retail & Branch Banking", "Retail and branch banking controls for customer-data scope, account changes, product advice, and branch communications.", vertical="bfsi", department_persona="retail_branch_banking", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("customer-data-boundary", "Customer-data boundary", "Customer data must not be used for another customer, an unapproved purpose, or a personal AI account.", "retail_customer_data_boundary", decision="block", surfaces=ALL_SURFACES),
            _entry("account-beneficiary-change", "Account and beneficiary changes", "Bind authenticated customer, account, beneficiary, changed fields, and expiry before a material banking change.", "retail_account_beneficiary_change"),
            _entry("product-recommendation", "Product recommendation", "Material product advice requires approved product data, source evidence, and accountable review.", "retail_product_recommendation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("branch-communication", "Branch communication", "Customer notices, complaints, and account information use an authorized recipient, channel, and template.", "retail_branch_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:bfsi-corporate", "BFSI — Corporate & SME Banking", "Corporate and SME banking controls for client documents, credit proposals, data rooms, and facility changes.", vertical="bfsi", department_persona="corporate_sme_banking", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("client-documents", "Client document handling", "Financial statements, contracts, KYB, and facility documents require an approved workspace and destination.", "corporate_client_document_handling", surfaces=ALL_SURFACES),
            _entry("credit-proposal", "Credit proposal preparation", "AI may assist with credit proposals, but authorized review owns final terms and risk conclusions.", "corporate_credit_proposal", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("data-room", "Data-room sharing", "Bind client, transaction, document set, recipient, and expiry before data-room sharing.", "corporate_data_room_sharing"),
            _entry("facility-change", "Facility or covenant change", "Limits, covenants, pricing, and security changes require a second approval.", "corporate_facility_covenant_change", obligations={"approval_level": "second_approval"}),
        ]),
        _pack("hawk:bfsi-credit", "BFSI — Credit, Lending & Collections", "Credit, lending, and collections controls for decision support, protected attributes, adverse actions, and collection activity.", vertical="bfsi", department_persona="credit_lending_collections", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("credit-decision", "Credit decision assistance", "AI may support credit decisions, but an accountable human owns the final material outcome.", "credit_decision_assistance"),
            _entry("protected-attributes", "Sensitive and protected attributes", "Sensitive or proxy attributes are restricted unless an approved, lawful use is documented.", "credit_protected_attributes", decision="require_approval"),
            _entry("adverse-action", "Adverse-action explanation", "Explanations must link to actual decision factors and evidence rather than invented rationale.", "credit_adverse_action_explanation"),
            _entry("collections", "Collection action", "Control customer identity, contact rules, amount, settlement terms, authority, and escalation.", "credit_collection_action"),
        ]),
        _pack("hawk:bfsi-treasury", "BFSI — Treasury, Markets & Trading", "Treasury and markets controls for orders, sensitive market information, limits, and external communication.", vertical="bfsi", department_persona="treasury_markets_trading", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("trade-execution", "Trade or order execution", "Block orders outside approved venue, mandate, account, or limit; bind instrument, side, quantity, price, and trader authority.", "trade_order_execution", decision="block"),
            _entry("market-sensitive", "Market-sensitive information", "Positions, orders, research, client flow, and non-public information cannot be disclosed to personal or public AI.", "market_sensitive_information", decision="block", surfaces=ALL_SURFACES),
            _entry("limit-threshold", "Limit and value threshold", "Notional, concentration, counterparty, and cumulative limit actions require second approval.", "treasury_limit_threshold", obligations={"approval_level": "second_approval"}),
            _entry("market-communication", "External market communication", "Research, commentary, client communication, and regulatory statements require approval.", "external_market_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:bfsi-wealth", "BFSI — Wealth & Private Banking", "Wealth and private banking controls for confidentiality, investment recommendations, transfers, and personal channels.", vertical="bfsi", department_persona="wealth_private_banking", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs, rules=[
            _entry("client-confidentiality", "Client confidentiality", "Portfolio, family, trust, tax, and relationship data require an approved enterprise workspace.", "wealth_client_confidentiality", decision="block", surfaces=ALL_SURFACES),
            _entry("investment-recommendation", "Investment recommendation", "Suitability evidence, client profile, mandate, product, risk, and source data remain reviewable.", "wealth_investment_recommendation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("trade-transfer", "Trade or transfer action", "Bind account, beneficiary, asset, quantity, destination, and authority before a trade or transfer.", "wealth_trade_transfer"),
            _entry("personal-channel", "Personal messaging channel", "Sensitive client activity through personal email, messaging, or AI accounts is blocked unless a scoped exception is approved.", "wealth_personal_messaging", decision="block", surfaces=["browser", "endpoint"]),
        ]),
        _pack("hawk:bfsi-payment-operations", "BFSI — Payments & Banking Operations", "Banking payment operations controls for initiation, beneficiary drift, effect closure, and reconciliation adjustments.", vertical="bfsi", department_persona="payments_banking_operations", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs, rules=[
            _entry("payment-initiation", "Payment initiation", "Bind payer, payee, account, amount, currency, purpose, and channel before payment initiation.", "banking_payment_initiation"),
            _entry("beneficiary-drift", "Beneficiary and destination drift", "A changed beneficiary, account, destination, or amount invalidates prior authorization.", "banking_beneficiary_drift", decision="block", default_mode="block", non_overridable=True),
            _entry("ambiguous-response", "Ambiguous provider response", "Recover through reservation, idempotency, and certified-no-effect evidence; do not retry an uncertain payment effect unsafely.", "banking_ambiguous_provider_response", decision="hold_for_approval"),
            _entry("reconciliation-adjustment", "Reconciliation adjustment", "Bind transaction set, ledger, amount, reason, and evidence before adjustment.", "banking_reconciliation_adjustment"),
        ]),
        _pack("hawk:bfsi-financial-crime", "BFSI — AML, Sanctions, Fraud & Financial Crime", "Financial-crime controls for case confidentiality, alert disposition, evidence-based explanations, and bulk investigation.", vertical="bfsi", department_persona="aml_sanctions_fraud", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs, rules=[
            _entry("case-confidentiality", "Case and STR confidentiality", "Investigations, alerts, SAR/STR material, and law-enforcement requests cannot be disclosed through unapproved paths.", "financial_crime_case_confidentiality", decision="block", surfaces=ALL_SURFACES),
            _entry("alert-disposition", "Alert disposition", "AI may prioritize or summarize, but must not autonomously close material cases.", "financial_crime_alert_disposition"),
            _entry("risk-explanation", "Customer-risk explanation", "Customer-risk explanations use approved factors and preserve source lineage.", "financial_crime_risk_explanation"),
            _entry("bulk-investigation", "Bulk customer investigation", "Bulk investigation binds scope, purpose, data fields, export destination, and quantity limits.", "financial_crime_bulk_investigation"),
        ]),
        _pack("hawk:bfsi-customer-service", "BFSI — Customer Service & Complaints", "BFSI customer-service controls compose the shared customer-service pack.", vertical="bfsi", department_persona="customer_service_complaints", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs),
        _pack("hawk:bfsi-risk", "BFSI — Risk, Compliance, Legal & Internal Audit", "BFSI risk and compliance controls add regulatory interpretation to the shared legal and audit pack.", vertical="bfsi", department_persona="risk_compliance_legal_audit", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs, rules=[
            _entry("regulatory-interpretation", "Regulatory interpretation", "AI output is advisory and must link to approved source material and an accountable reviewer.", "bfsi_regulatory_interpretation", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:bfsi-technology", "BFSI — Technology, Engineering & Cybersecurity", "BFSI technology controls compose shared IT, engineering, and security rules.", vertical="bfsi", department_persona="technology_engineering_cybersecurity", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs),
        _pack("hawk:bfsi-data-ai", "BFSI — Data, AI & Model Risk", "BFSI data, AI, and model-risk controls compose the shared Data and AI pack.", vertical="bfsi", department_persona="data_ai_model_risk", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs),
        _pack("hawk:bfsi-finance", "BFSI — Finance & Financial Reporting", "BFSI finance controls compose the shared Finance pack.", vertical="bfsi", department_persona="finance_financial_reporting", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs),
        _pack("hawk:bfsi-hr", "BFSI — Human Resources", "BFSI HR controls compose the shared Human Resources pack.", vertical="bfsi", department_persona="human_resources", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-hr"), references=refs),
        _pack("hawk:bfsi-marketing-sales", "BFSI — Marketing & Sales", "BFSI marketing and sales controls compose shared Marketing and Sales packs.", vertical="bfsi", department_persona="marketing_sales", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-marketing", "hawk:common-sales"), references=refs),
        _pack("hawk:bfsi-executive", "BFSI — Executive & Board", "BFSI executive and board controls compose the shared Executive & Board pack.", vertical="bfsi", department_persona="executive_board", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-exec"), references=refs),
    ]


def _insurance_packs() -> list[dict[str, Any]]:
    refs = VERTICAL_REFERENCES["insurance"]
    return [
        _pack("hawk:insurance-underwriting", "Insurance — Underwriting", "Underwriting controls for applicant data, recommendations, policyholder isolation, and external sources.", vertical="insurance", department_persona="underwriting", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("applicant-data", "Applicant and policyholder data", "Medical, financial, property, telematics, and third-party data require an approved enterprise AI purpose.", "insurance_applicant_data", decision="block", surfaces=ALL_SURFACES),
            _entry("underwriting-recommendation", "Underwriting recommendation", "AI may support underwriting, but accountable review owns final risk selection, terms, and exclusions.", "underwriting_recommendation"),
            _entry("policyholder-isolation", "Cross-policyholder isolation", "A policyholder's information cannot influence another case without approved aggregated use.", "insurance_cross_policyholder_access", decision="block", default_mode="block", non_overridable=True),
            _entry("external-source", "External data source", "Record source, licensing, freshness, permitted use, and material impact for external underwriting data.", "insurance_external_data_source"),
        ]),
        _pack("hawk:insurance-actuarial", "Insurance — Actuarial & Pricing", "Actuarial and pricing controls for model use, variables, assumptions, and generated explanations.", vertical="insurance", department_persona="actuarial_pricing", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("pricing-model", "Pricing and risk model use", "Bind product, jurisdiction, model, dataset, and validation state before model use.", "insurance_pricing_model_use"),
            _entry("proxy-variable", "Sensitive and proxy variables", "Surface variables that may create unfair or unexplained outcomes and require model-risk review.", "insurance_sensitive_proxy_variable"),
            _entry("rate-change", "Rate or assumption change", "Version assumptions, rationale, impact, and effective date before a rate change; require second approval.", "insurance_rate_assumption_change", obligations={"approval_level": "second_approval"}),
            _entry("actuarial-explanation", "Generated actuarial explanation", "Link generated explanations to source models and avoid invented calculations.", "insurance_actuarial_explanation", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:insurance-claims", "Insurance — Claims", "Claims controls for claimant evidence, decisions, payment, and customer communication.", vertical="insurance", department_persona="claims", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("claim-evidence", "Claimant data and evidence", "Medical, financial, image, repair, and legal evidence require an approved case scope.", "insurance_claim_evidence", decision="block", surfaces=ALL_SURFACES),
            _entry("claim-decision", "Claim decision or settlement", "Bind claim, coverage, evidence, amount, payee, and authority before a material outcome.", "insurance_claim_decision"),
            _entry("claim-payment", "Claim payment", "Claim payments require stepped-up identity and approval; beneficiary or amount drift is not accepted.", "insurance_claim_payment"),
            _entry("claim-communication", "Customer communication", "Denial and settlement communications use approved source material and human review.", "insurance_claim_customer_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:insurance-siu", "Insurance — Special Investigations & Fraud", "Special-investigation controls for confidentiality, referrals, bulk analysis, and evidence summaries.", vertical="insurance", department_persona="special_investigations_fraud", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs, rules=[
            _entry("investigation-confidentiality", "Investigation confidentiality", "Fraud indicators, surveillance, third-party, and law-enforcement data cannot be disclosed through unapproved AI.", "insurance_investigation_confidentiality", decision="block", surfaces=ALL_SURFACES),
            _entry("fraud-referral", "Fraud referral", "AI may prioritize but must not autonomously accuse, close, or refer a case.", "insurance_fraud_referral"),
            _entry("bulk-link-analysis", "Bulk link analysis or export", "Control people, policies, claims, destinations, fields, and quantity before bulk analysis or export.", "insurance_bulk_link_analysis"),
            _entry("evidence-summary", "Evidence summary", "Evidence summaries remain source-linked and reviewable; unsupported fraud rationale is not accepted.", "insurance_evidence_summary", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:insurance-distribution", "Insurance — Sales, Agents & Brokers", "Distribution controls for customer data, coverage claims, binding actions, and broker sharing.", vertical="insurance", department_persona="sales_agents_brokers", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs, rules=[
            _entry("quote-data", "Customer data and quote", "Prospects, quotes, policy details, and identity documents need an approved account and application.", "insurance_quote_data", decision="block", surfaces=BROWSER_ENDPOINT_SAAS),
            _entry("coverage-representation", "Coverage or premium representation", "Use approved product sources and human review to prevent unauthorized promises or misleading benefits.", "insurance_coverage_representation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("binding-issuance", "Binding or issuance action", "Bind customer, product, premium, coverage, effective date, and authority before policy binding.", "insurance_binding_issuance"),
            _entry("broker-sharing", "External broker sharing", "Use verified partner identity, purpose, data scope, and expiry before broker sharing.", "insurance_broker_sharing", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:insurance-customer-service", "Insurance — Customer Service", "Insurance customer-service controls compose the shared Customer Service & Operations pack.", vertical="insurance", department_persona="customer_service", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs),
        _pack("hawk:insurance-policy-administration", "Insurance — Policy Administration", "Policy-administration controls for changes, cancellation, documents, and bulk updates.", vertical="insurance", department_persona="policy_administration", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("policy-change", "Policy change", "Bind policyholder, policy, field, effective date, and authority before a policy change.", "insurance_policy_change"),
            _entry("cancellation-reinstatement", "Cancellation or reinstatement", "Preserve reason, notices, dates, and supporting evidence before cancellation or reinstatement.", "insurance_policy_cancellation_reinstatement"),
            _entry("document-generation", "Document generation", "Use approved templates and source data; generated documents cannot fabricate coverage terms.", "insurance_document_generation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("bulk-policy-update", "Bulk policy update", "Apply exact population, quantity controls, second approval, and rollback to bulk policy updates.", "insurance_bulk_policy_update", obligations={"approval_level": "second_approval"}),
        ]),
        _pack("hawk:insurance-reinsurance", "Insurance — Reinsurance", "Reinsurance controls for treaty data, recommendations, sharing, and commitments.", vertical="insurance", department_persona="reinsurance", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs, rules=[
            _entry("treaty-data", "Treaty and facultative data", "Exposure, pricing, loss, and contract data require an approved workspace and counterparty.", "insurance_treaty_data", decision="block", surfaces=BROWSER_ENDPOINT_SAAS),
            _entry("cession-recommendation", "Cession or placement recommendation", "Recommendations link to approved exposure and treaty information and remain human reviewed.", "insurance_cession_recommendation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("external-sharing", "External sharing", "Bind reinsurer or broker, portfolio, data fields, and purpose before external sharing.", "insurance_reinsurance_sharing"),
            _entry("contract-commitment", "Contract commitment", "Material terms and capacity commitments require a second approval.", "insurance_reinsurance_contract_commitment", obligations={"approval_level": "second_approval"}),
        ]),
        _pack("hawk:insurance-medical", "Insurance — Life, Health & Medical Review", "Life, health, and medical-review controls for medical data, eligibility support, advice, and patient isolation.", vertical="insurance", department_persona="life_health_medical_review", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("medical-data", "Medical data", "Diagnoses, tests, treatment, biometrics, and health records require a minimum-necessary approved purpose and destination.", "insurance_medical_data", decision="block", surfaces=ALL_SURFACES),
            _entry("eligibility-support", "Eligibility or underwriting support", "No autonomous material eligibility or underwriting decision occurs without accountable review.", "insurance_eligibility_support"),
            _entry("medical-advice", "Medical advice", "Material medical output uses approved source material and clinical review; it is not clinician authority.", "insurance_medical_advice", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("cross-patient", "Cross-patient boundary", "Bind the represented subject and medical resource to prevent cross-patient access.", "insurance_cross_patient_boundary", decision="block", default_mode="block", non_overridable=True),
        ]),
        _pack("hawk:insurance-risk", "Insurance — Risk, Compliance, Legal & Internal Audit", "Insurance risk and compliance controls compose the shared Legal, Compliance & Internal Audit pack.", vertical="insurance", department_persona="risk_compliance_legal_audit", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs),
        _pack("hawk:insurance-technology", "Insurance — Technology, Data, AI & Security", "Insurance technology controls compose shared IT, Security, and Data & AI packs.", vertical="insurance", department_persona="technology_data_ai_security", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security", "hawk:common-data-ai"), references=refs),
        _pack("hawk:insurance-finance", "Insurance — Finance", "Insurance finance controls compose the shared Finance pack.", vertical="insurance", department_persona="finance", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs),
        _pack("hawk:insurance-hr", "Insurance — Human Resources", "Insurance HR controls compose the shared Human Resources pack.", vertical="insurance", department_persona="human_resources", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-hr"), references=refs),
        _pack("hawk:insurance-marketing", "Insurance — Marketing & Communications", "Insurance marketing controls compose the shared Marketing & Communications pack.", vertical="insurance", department_persona="marketing_communications", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-marketing"), references=refs),
        _pack("hawk:insurance-executive", "Insurance — Executive & Board", "Insurance executive controls compose the shared Executive & Board pack.", vertical="insurance", department_persona="executive_board", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-exec"), references=refs),
    ]


def _telecom_packs() -> list[dict[str, Any]]:
    refs = VERTICAL_REFERENCES["telecom"]
    return [
        _pack("hawk:telecom-network-engineering", "Telecom — Network Planning & Engineering", "Network engineering controls for configuration, topology data, optimization, and vendor/tool use.", vertical="telecom", department_persona="network_planning_engineering", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("network-config", "Network design and configuration", "Production network configuration binds domain, device, change ticket, configuration, and rollback.", "telecom_network_configuration", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("topology-data", "Topology and configuration data", "Network diagrams, credentials, subscriber-related data, and vulnerabilities use approved models and routes.", "telecom_topology_data", decision="block", surfaces=ALL_SURFACES),
            _entry("autonomous-optimization", "Autonomous optimization", "Material optimization remains bounded by site, region, parameter, threshold, safety limit, and human approval.", "telecom_autonomous_optimization"),
            _entry("vendor-tool", "Vendor and tool use", "External vendor or tool use requires an approved capability and destination.", "telecom_vendor_tool_use", decision="hold_for_approval", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:telecom-noc", "Telecom — NOC & Service Assurance", "NOC controls for incident summarization, remediation commands, service-impact communication, and high-volume automation.", vertical="telecom", department_persona="noc_service_assurance", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("alarm-summary", "Alarm and incident summarization", "Keep source alarms, topology, and timestamps linked to the generated summary.", "telecom_alarm_incident_summary"),
            _entry("remediation-command", "Remediation command", "Bind incident, device or service, command, authority, and rollback before remediation.", "telecom_remediation_command", surfaces=ENDPOINT_RUNTIME),
            _entry("service-communication", "Service-impact communication", "Material customer or public outage statements require human approval and verified outage data.", "telecom_service_impact_communication", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("high-volume-action", "High-volume automated action", "Constrain sites, cells, customers, duration, quantity, and blast radius.", "telecom_high_volume_action"),
        ]),
        _pack("hawk:telecom-customer-care", "Telecom — Customer Care", "Customer-care controls for subscriber identity, service changes, customer answers, and outbound contact.", vertical="telecom", department_persona="customer_care", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("subscriber-data", "Subscriber identity and CPNI-like data", "Subscriber profile, usage, location, billing, and authentication data use an approved workspace and minimum necessary fields.", "telecom_subscriber_data", decision="redact", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("sim-account-change", "SIM, account, or service change", "No material service change occurs without verified subscriber authority.", "telecom_sim_account_service_change"),
            _entry("customer-answer", "Customer answer", "Use approved knowledge and escalation; do not fabricate plan, charge, coverage, or outage claims.", "telecom_customer_answer", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("outbound-contact", "Outbound contact", "Consent, channel, and frequency controls apply to AI-generated calls, messages, and notices.", "telecom_outbound_contact"),
        ]),
        _pack("hawk:telecom-billing", "Telecom — Billing, Credit & Collections", "Billing controls for adjustments, customer data, collection activity, and bulk credits or refunds.", vertical="telecom", department_persona="billing_credit_collections", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs, rules=[
            _entry("billing-adjustment", "Billing adjustment", "Bind account, charge, period, reason, value, and owner before adjustment.", "telecom_billing_adjustment"),
            _entry("billing-data", "Customer billing data", "Account, payment, usage, and contact data require redaction or an approved workspace.", "telecom_billing_customer_data", decision="redact", surfaces=ALL_SURFACES),
            _entry("collection-action", "Collection action", "Use approved channel and frequency with human review for offers, settlement, disconnection, and escalation.", "telecom_collection_action"),
            _entry("bulk-credit", "Bulk credit or refund", "Bulk credits and refunds require value and quantity limits plus second approval.", "telecom_bulk_credit_refund", obligations={"approval_level": "second_approval"}),
        ]),
        _pack("hawk:telecom-fraud", "Telecom — Fraud & Revenue Assurance", "Fraud and revenue-assurance controls for case confidentiality, suspension decisions, bulk analysis, and corrections.", vertical="telecom", department_persona="fraud_revenue_assurance", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs, rules=[
            _entry("fraud-confidentiality", "Fraud-case confidentiality", "SIM-swap, roaming, subscription, device, and partner intelligence cannot be disclosed through unapproved AI.", "telecom_fraud_case_confidentiality", decision="block", surfaces=ALL_SURFACES),
            _entry("fraud-action", "Fraud action", "AI signals remain evidence, not autonomous authority for suspension or blocking.", "telecom_fraud_action"),
            _entry("bulk-analysis", "Network and subscriber bulk analysis", "Control population, fields, destination, retention, purpose, and approval for bulk analysis.", "telecom_bulk_subscriber_analysis"),
            _entry("revenue-correction", "Revenue leakage correction", "Bind system, customer set, amount, and evidence before correction.", "telecom_revenue_leakage_correction"),
        ]),
        _pack("hawk:telecom-sales-marketing", "Telecom — Sales & Marketing", "Sales and marketing controls for segmentation, offer claims, campaigns, and enterprise proposals.", vertical="telecom", department_persona="sales_marketing", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-marketing", "hawk:common-sales"), references=refs, rules=[
            _entry("subscriber-segmentation", "Subscriber segmentation", "Use approved purpose, consent, data minimization, and controls for location, usage, demographic, and behavioral data.", "telecom_subscriber_segmentation"),
            _entry("offer-claim", "Offer or plan claim", "Use approved catalog data and human review to prevent invented coverage, speed, price, or eligibility claims.", "telecom_offer_plan_claim", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("automated-campaign", "Automated campaign", "Apply opt-in/out, channel, frequency, approval, and target-group controls.", "telecom_automated_campaign"),
            _entry("enterprise-proposal", "Enterprise proposal", "SLA and pricing commitments require human approval with customer, service, price, and terms bound.", "telecom_enterprise_proposal", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:telecom-retail", "Telecom — Retail & Channel Operations", "Retail and channel controls for subscriber verification, partner data, activation, and assistant responses.", vertical="telecom", department_persona="retail_channel_operations", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("subscriber-verification", "Subscriber verification", "Account or SIM actions require stepped-up verification of person, account, channel, and requested change.", "telecom_subscriber_verification"),
            _entry("dealer-data", "Dealer and partner data", "Sales, commission, inventory, and customer data are limited to an approved partner and scope.", "telecom_dealer_partner_data", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("device-sim-activation", "Device or SIM activation", "Activation binds identity, device, SIM, plan, location, approval, and fraud controls.", "telecom_device_sim_activation"),
            _entry("retail-response", "Retail assistant response", "Use approved product sources to avoid incorrect commitments.", "telecom_retail_assistant_response", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:telecom-product", "Telecom — Product & Digital Channels", "Product and digital-channel controls for configuration, customer journey agents, experimentation, and third-party SDKs.", vertical="telecom", department_persona="product_digital_channels", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs, rules=[
            _entry("product-config", "Product or offer configuration", "Bind catalog, price, eligibility, channel, effective date, and approval before configuration.", "telecom_product_offer_configuration"),
            _entry("journey-agent", "Customer journey agent", "Customer journey agents stay within approved actions and represented-subject authority.", "telecom_customer_journey_agent"),
            _entry("experiment-personalization", "Experiment or personalization", "Use approved data, cohort, fairness review, and customer-impact controls.", "telecom_experiment_personalization"),
            _entry("third-party-sdk", "Third-party AI SDK", "Require owner, model, data, destination, and control coverage for third-party AI SDKs.", "telecom_third_party_ai_sdk", decision="hold_for_approval", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:telecom-field", "Telecom — Field Operations", "Field-operation controls for site data, work orders, industrial commands, and contractor sharing.", vertical="telecom", department_persona="field_operations", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("site-asset-data", "Site and asset data", "Location, topology, access, photos, and maintenance details require an approved device, app, and destination.", "telecom_site_asset_data", surfaces=ENDPOINT_RUNTIME),
            _entry("work-order", "Work-order change", "Bind site, asset, action, contractor, schedule, cost, and risk threshold.", "telecom_work_order_change"),
            _entry("industrial-command", "Industrial or network command", "Uncontrolled commands to network or physical systems are blocked outside an approved isolated workflow.", "telecom_industrial_network_command", decision="block", default_mode="block", surfaces=ENDPOINT_RUNTIME),
            _entry("contractor-sharing", "External contractor sharing", "Restrict files, credentials, site access, partner identity, and time-limited scope.", "telecom_external_contractor_sharing", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:telecom-enterprise", "Telecom — Enterprise & B2B Services", "Enterprise service controls for customer network data, service commitments, managed-service actions, and partners.", vertical="telecom", department_persona="enterprise_b2b_services", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs, rules=[
            _entry("customer-network-data", "Customer network data", "Separate enterprise customers and protect network designs, tickets, and credentials in an approved workspace.", "telecom_customer_network_data", decision="block", surfaces=ALL_SURFACES),
            _entry("sla-commitment", "SLA or service commitment", "Bind customer, service, metric, price, contract, and approval before commitment.", "telecom_sla_service_commitment", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("managed-service-action", "Managed-service action", "Require customer authority and change approval before configuration action.", "telecom_managed_service_action"),
            _entry("partner-integration", "Partner integration", "Bind tenant, partner, data scope, approved API or tool, and destination.", "telecom_partner_integration"),
        ]),
        _pack("hawk:telecom-regulatory", "Telecom — Regulatory, Legal & Privacy", "Telecom regulatory controls compose the shared Legal, Compliance & Internal Audit pack.", vertical="telecom", department_persona="regulatory_legal_privacy", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs),
        _pack("hawk:telecom-technology", "Telecom — IT, Cloud, DevOps & Security", "Telecom technology controls compose the shared IT, Engineering & Security pack.", vertical="telecom", department_persona="it_cloud_devops_security", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs),
        _pack("hawk:telecom-data-ai", "Telecom — Data & AI", "Telecom Data & AI controls compose the shared Data, AI & Model Teams pack.", vertical="telecom", department_persona="data_ai", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs),
        _pack("hawk:telecom-finance-procurement", "Telecom — Finance & Procurement", "Telecom finance and procurement controls compose shared Finance and Procurement packs.", vertical="telecom", department_persona="finance_procurement", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance", "hawk:common-procurement"), references=refs),
        _pack("hawk:telecom-hr", "Telecom — Human Resources", "Telecom HR controls compose the shared Human Resources pack.", vertical="telecom", department_persona="human_resources", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-hr"), references=refs),
        _pack("hawk:telecom-executive", "Telecom — Executive & Board", "Telecom executive controls compose the shared Executive & Board pack.", vertical="telecom", department_persona="executive_board", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-exec"), references=refs),
    ]


def _payments_packs() -> list[dict[str, Any]]:
    refs = VERTICAL_REFERENCES["payments"]
    return [
        _pack("hawk:payments-merchant-onboarding", "Payments — Merchant Onboarding & KYB", "Merchant onboarding controls for documents, KYB recommendations, bank details, and credentials.", vertical="payments", department_persona="merchant_onboarding_kyb", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-procurement"), references=refs, rules=[
            _entry("merchant-documents", "Merchant documents", "Ownership, identity, bank, website, and risk documents require an approved workspace and case scope.", "payments_merchant_documents", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("kyb-recommendation", "KYB recommendation", "AI may summarize or flag, but accountable review owns onboarding or decline.", "payments_kyb_recommendation"),
            _entry("bank-detail-change", "Bank detail change", "Bind merchant, account, change source, effective date, independent verification, and second approval.", "payments_merchant_bank_detail_change", obligations={"approval_level": "second_approval"}),
            _entry("merchant-credential", "Merchant API credential", "Live keys and signing secrets use a secret-reference workflow, never prompts or unapproved tools.", "payments_merchant_api_credential", decision="block", default_mode="block", criticality="critical", surfaces=ALL_SURFACES),
        ]),
        _pack("hawk:payments-fraud", "Payments — Transaction Risk & Fraud", "Transaction risk controls for decision support, payment data, fraud-rule changes, and bulk exports.", vertical="payments", department_persona="transaction_risk_fraud", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("transaction-support", "Transaction decision support", "AI may score or explain, but material decline or hold authority must remain human or approved deterministic control.", "payments_transaction_decision_support"),
            _entry("cardholder-data", "Cardholder and payment data", "Tokenize or redact payment data and keep it inside an approved environment.", "payments_cardholder_data", decision="redact", surfaces=ALL_SURFACES),
            _entry("fraud-rule-change", "Fraud-rule change", "Version thresholds, simulate impact, and retain rollback before changing a fraud rule.", "payments_fraud_rule_change"),
            _entry("bulk-transaction-export", "Bulk transaction export", "Control data set, purpose, destination, retention, fields, and approval before export.", "payments_bulk_transaction_export"),
        ]),
        _pack("hawk:payments-operations", "Payments — Payment Operations & Routing", "Payment operations controls for routing, retries, manual action, and provider incidents.", vertical="payments", department_persona="payment_operations_routing", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs, rules=[
            _entry("routing-change", "Routing change", "Bind merchant, region, scheme or acquirer, traffic share, and rollback before routing change.", "payments_routing_change"),
            _entry("transaction-retry", "Transaction retry", "Idempotency and effect closure are required to prevent duplicate charges or effects.", "payments_transaction_retry", decision="hold_for_approval"),
            _entry("manual-transaction", "Manual transaction action", "Bind transaction, merchant, amount, reason, operator, and stepped-up authority.", "payments_manual_transaction_action"),
            _entry("provider-incident", "Provider incident action", "Use an approved runbook and blast-radius limit for failover, queue replay, and routing changes.", "payments_provider_incident_action"),
        ]),
        _pack("hawk:payments-settlement", "Payments — Settlement & Reconciliation", "Settlement controls for instructions, adjustments, payout destination drift, and report sharing.", vertical="payments", department_persona="settlement_reconciliation", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs, rules=[
            _entry("settlement-instruction", "Settlement instruction", "Bind merchant, bank, amount, currency, cycle, account, and second approval before settlement.", "payments_settlement_instruction", obligations={"approval_level": "second_approval"}),
            _entry("reconciliation-adjustment", "Reconciliation adjustment", "Preserve transaction set, ledger impact, reason, amount, and evidence.", "payments_reconciliation_adjustment"),
            _entry("payout-destination", "Payout destination change", "Payout destination drift requires independent verification and second approval.", "payments_payout_destination_change", decision="block", default_mode="block", non_overridable=True),
            _entry("settlement-report", "Settlement report sharing", "Share settlement reports only with approved recipients and redacted data scope.", "payments_settlement_report_sharing", surfaces=["browser", "saas_api"]),
        ]),
        _pack("hawk:payments-disputes", "Payments — Disputes & Chargebacks", "Dispute controls for case evidence, representment, refunds, and bulk case action.", vertical="payments", department_persona="disputes_chargebacks", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("case-evidence", "Case evidence", "Cardholder, merchant, transaction, and supporting documents remain within approved case scope and destination.", "payments_dispute_case_evidence", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("representment", "Representment response", "Representment uses approved scheme rules and evidence; no invented facts are submitted.", "payments_representment_response", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("refund-adjustment", "Refund or adjustment", "Bind transaction, amount, recipient, value threshold, and reason before refund or adjustment.", "payments_refund_adjustment"),
            _entry("bulk-case-action", "Bulk case action", "Apply quantity limits, approval, exact population, and rollback for bulk case actions.", "payments_bulk_case_action"),
        ]),
        _pack("hawk:payments-merchant-support", "Payments — Merchant Support", "Merchant-support controls compose the shared Customer Service & Operations pack.", vertical="payments", department_persona="merchant_support", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("credential-reset", "Credential reset", "Credential reset requires verified identity and a secure channel; no secret disclosure occurs in AI conversation.", "payments_credential_reset"),
        ]),
        _pack("hawk:payments-product", "Payments — Product", "Payment product controls for configuration, new AI/vendor integrations, experiments, and customer claims.", vertical="payments", department_persona="product", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs, rules=[
            _entry("product-configuration", "Payment product configuration", "Bind product, market, pricing, limit, customer impact, rollback, and approval.", "payments_product_configuration"),
            _entry("ai-vendor-integration", "New AI or vendor integration", "Require data-flow, PCI scope, provider, model, and control coverage before a new integration.", "payments_ai_vendor_integration", decision="hold_for_approval", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("routing-experiment", "Experiment or routing optimization", "Use approved cohort, guardrails, transaction, merchant, and value limits.", "payments_routing_experiment"),
            _entry("customer-claim", "Customer-facing claim", "Rates, availability, security, and regulatory statements require legal or compliance review.", "payments_customer_facing_claim", surfaces=["browser", "saas_api"]),
        ]),
        _pack("hawk:payments-engineering", "Payments — Engineering, DevOps & SRE", "Payment engineering controls compose shared IT and Security rules and add payment API schema change review.", vertical="payments", department_persona="engineering_devops_sre", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("payment-api-schema", "Payment API schema change", "Preserve compatibility, security, testing, approval, and version evidence for payment API schema changes.", "payments_api_schema_change"),
        ]),
        _pack("hawk:payments-security-pci", "Payments — Security & PCI", "Payment security controls for cardholder data, control changes, incident data, and privilege.", vertical="payments", department_persona="security_pci", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("cardholder-boundary", "Cardholder-data boundary", "Unapproved AI processing of cardholder data is blocked; use tokenization or redaction and approved environment only.", "payments_cardholder_data_boundary", decision="block", default_mode="block", surfaces=ALL_SURFACES),
            _entry("security-control-change", "Security-control change", "Version, test, validate, and second-approve security control changes before activation.", "payments_security_control_change", obligations={"approval_level": "second_approval"}),
            _entry("incident-forensic", "Incident and forensic data", "Use an approved isolated AI environment for PAN, secrets, indicators, and evidence integrity.", "payments_incident_forensic_data", decision="block", surfaces=["browser", "endpoint", "runtime"]),
            _entry("privileged-access", "Privileged access", "Record principal, purpose, resource, action, step-up, and least authority.", "payments_privileged_access", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:payments-compliance", "Payments — AML, Compliance & Legal", "Payment compliance controls compose the shared Legal, Compliance & Internal Audit pack.", vertical="payments", department_persona="aml_compliance_legal", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs),
        _pack("hawk:payments-finance", "Payments — Finance & Treasury", "Payment finance controls compose the shared Finance pack.", vertical="payments", department_persona="finance_treasury", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs),
        _pack("hawk:payments-sales", "Payments — Sales & Partnerships", "Payment sales controls compose the shared Sales & Relationship Management pack.", vertical="payments", department_persona="sales_partnerships", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs),
        _pack("hawk:payments-data-ai", "Payments — Data & AI", "Payment data and AI controls compose the shared Data, AI & Model Teams pack.", vertical="payments", department_persona="data_ai", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs),
        _pack("hawk:payments-hr", "Payments — Human Resources", "Payment HR controls compose the shared Human Resources pack.", vertical="payments", department_persona="human_resources", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-hr"), references=refs),
        _pack("hawk:payments-executive", "Payments — Executive & Board", "Payment executive controls compose the shared Executive & Board pack.", vertical="payments", department_persona="executive_board", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-exec"), references=refs),
    ]


def _real_estate_packs() -> list[dict[str, Any]]:
    refs = VERTICAL_REFERENCES["real_estate"]
    return [
        _pack("hawk:real-estate-sales", "Real Estate — Brokerage & Sales", "Brokerage and sales controls for client data, commitments, recommendations, and document sharing.", vertical="real_estate", department_persona="brokerage_sales", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-sales"), references=refs, rules=[
            _entry("client-investor-data", "Client and investor data", "IDs, budgets, preferences, offers, ownership, and contact data use an approved enterprise AI workspace.", "real_estate_client_investor_data", decision="block", surfaces=BROWSER_ENDPOINT_SAAS),
            _entry("offer-price", "Offer or price commitment", "Prevent unauthorized price, discount, yield, or contractual promises.", "real_estate_offer_price_commitment", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("property-recommendation", "Property recommendation", "Use current approved listing data and human review for property recommendations.", "real_estate_property_recommendation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("document-sharing", "External document sharing", "Bind recipient, data scope, brochure, offer, contract, and data-room access before sharing.", "real_estate_external_document_sharing", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-leasing", "Real Estate — Leasing", "Leasing controls for tenant data, lease advice, concessions, and renewal changes.", vertical="real_estate", department_persona="leasing", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("tenant-data", "Tenant data", "Identity, income, contracts, payments, and contact data use an approved workspace and minimum necessary fields.", "real_estate_tenant_data", decision="redact", surfaces=ALL_SURFACES),
            _entry("lease-advice", "Lease summary or advice", "AI may summarize but does not replace legal review of material lease clauses.", "real_estate_lease_advice", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("rent-commitment", "Rent or concession commitment", "Bind property, tenant, term, amount, and authority before a rent or concession commitment.", "real_estate_rent_concession_commitment"),
            _entry("lease-renewal", "Lease change or renewal", "Preserve old and new terms, effective date, evidence, and approval.", "real_estate_lease_change_renewal"),
        ]),
        _pack("hawk:real-estate-valuation", "Real Estate — Valuation & Appraisal", "Valuation controls for data, AI assistance, adjustments, and external reports.", vertical="real_estate", department_persona="valuation_appraisal", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("valuation-data", "Valuation data", "Client, transaction, and proprietary comparable data require approved sources and client scope.", "real_estate_valuation_data", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("ai-valuation", "AI-assisted valuation", "Record model and data source, assumptions, limitations, and accountable professional review.", "real_estate_ai_valuation"),
            _entry("valuation-adjustment", "Material valuation adjustment", "Preserve version, comparables, rationale, and approval for material adjustments.", "real_estate_valuation_adjustment"),
            _entry("valuation-report", "External valuation report", "Final reports require reviewer approval and cannot contain unsupported figures or conclusions.", "real_estate_external_valuation_report", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-property-management", "Real Estate — Property Management", "Property-management controls for tenant records, work orders, access actions, and tenant communication.", vertical="real_estate", department_persona="property_management", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs, rules=[
            _entry("tenant-owner-record", "Tenant or owner record", "Prevent cross-building or cross-client access and unnecessary personal-data use.", "real_estate_tenant_owner_record", decision="block", surfaces=ALL_SURFACES),
            _entry("work-order", "Work order", "Bind property, asset, vendor, scope, cost, schedule, and threshold before work order changes.", "real_estate_work_order"),
            _entry("access-action", "Access or credential action", "Control keys, access cards, building systems, vendor access, and stepped-up authority.", "real_estate_access_credential_action", surfaces=["runtime", "endpoint", "saas_api"]),
            _entry("tenant-communication", "Tenant communication", "Use approved source material and recipient controls for notices, payments, maintenance, and legal statements.", "real_estate_tenant_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-facilities", "Real Estate — Facilities Management", "Facilities controls for building data, operational commands, maintenance, and contractor access.", vertical="real_estate", department_persona="facilities_management", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("building-asset-data", "Building and asset data", "Floorplans, access, sensors, and maintenance data require an approved environment and destination.", "real_estate_building_asset_data", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("operational-command", "Operational command", "Uncontrolled HVAC, access, lift, fire, or industrial action is blocked outside an approved bounded workflow.", "real_estate_operational_command", decision="block", default_mode="block", surfaces=ENDPOINT_RUNTIME),
            _entry("maintenance-scheduling", "Maintenance scheduling", "Bind asset, task, vendor, time, safety, cost, and approval threshold.", "real_estate_maintenance_scheduling"),
            _entry("contractor-access", "Contractor access", "Use time-limited approved scope for files, systems, and destinations.", "real_estate_contractor_access", surfaces=ENDPOINT_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-development", "Real Estate — Development & Construction", "Development and construction controls for design data, changes, safety instructions, and consultant sharing.", vertical="real_estate", department_persona="development_construction", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs, rules=[
            _entry("bim-cad", "BIM, CAD, and design data", "Proprietary plans, models, quantities, and client data require an approved workspace and project scope.", "real_estate_bim_cad_design_data", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("design-change", "Design or specification change", "Bind project, version, discipline, impact, professional review, and authority before a design change.", "real_estate_design_specification_change"),
            _entry("safety-instruction", "Safety-critical instruction", "Autonomous site or engineering commands are blocked; human approval remains required.", "real_estate_safety_critical_instruction", decision="block", default_mode="block", surfaces=ENDPOINT_RUNTIME),
            _entry("consultant-sharing", "External consultant sharing", "Use approved party, project scope, file controls, expiry, and download permissions.", "real_estate_external_consultant_sharing", surfaces=BROWSER_ENDPOINT_SAAS),
        ]),
        _pack("hawk:real-estate-pmo", "Real Estate — Project Management", "Project-management controls for schedule and budget changes, reports, bulk tasks, and external communication.", vertical="real_estate", department_persona="project_management", pack_family="vertical_department", inherited_pack_refs=_parents(), references=refs, rules=[
            _entry("schedule-budget", "Schedule or budget update", "Baseline changes bind project, work package, date or cost, owner, and approval.", "real_estate_schedule_budget_update"),
            _entry("risk-progress", "Risk or progress report", "Reports are source-linked and human reviewed; they do not invent completion or risk status.", "real_estate_risk_progress_report", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("bulk-task", "Bulk task or work-order change", "Apply quantity limits, approval, scope, dependency, and rollback controls.", "real_estate_bulk_task_work_order_change"),
            _entry("project-communication", "External project communication", "Use approved recipient and document version controls for commercial and client information.", "real_estate_external_project_communication", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-investment", "Real Estate — Investment & Asset Management", "Investment controls for data, recommendations, transactions, and investor reports.", vertical="real_estate", department_persona="investment_asset_management", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs, rules=[
            _entry("investment-data", "Investment data", "Valuations, models, financing, tenants, and strategy use an approved enterprise AI workspace.", "real_estate_investment_data", decision="block", surfaces=ALL_SURFACES),
            _entry("acquisition-recommendation", "Acquisition or disposal recommendation", "AI remains advisory for material investment decisions and preserves source evidence.", "real_estate_acquisition_disposal_recommendation", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("transaction-action", "Offer or transaction action", "Bind asset, counterparty, price, conditions, and authority before a material transaction; require second approval.", "real_estate_offer_transaction_action", obligations={"approval_level": "second_approval"}),
            _entry("investor-report", "Investor report", "Use verified data and finance or legal approval for investor reports.", "real_estate_investor_report", surfaces=BROWSER_RUNTIME_SAAS),
        ]),
        _pack("hawk:real-estate-legal", "Real Estate — Legal & Contracts", "Real-estate legal controls compose the shared Legal, Compliance & Internal Audit pack.", vertical="real_estate", department_persona="legal_contracts", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-legal"), references=refs),
        _pack("hawk:real-estate-finance", "Real Estate — Finance", "Real-estate finance controls compose the shared Finance pack.", vertical="real_estate", department_persona="finance", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-finance"), references=refs),
        _pack("hawk:real-estate-marketing", "Real Estate — Marketing & Listings", "Marketing and listing controls for accuracy, advertising, client data, and generated content.", vertical="real_estate", department_persona="marketing_listings", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-marketing"), references=refs, rules=[
            _entry("listing-accuracy", "Listing accuracy", "Use approved property source and reviewer for price, availability, permit, features, images, and claims.", "real_estate_listing_accuracy", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("advertising-approval", "Advertising approval", "Use approved channels, broker or developer identity, listing references, and approval.", "real_estate_advertising_approval", surfaces=["browser", "saas_api"]),
            _entry("campaign-client-data", "Client data in campaigns", "Apply consent and minimum necessary controls to contact lists, preferences, and location data.", "real_estate_campaign_client_data", decision="redact", surfaces=BROWSER_RUNTIME_SAAS),
            _entry("generated-content", "Generated image or content", "Use disclosure and review according to customer policy; do not create misleading property representation.", "real_estate_generated_listing_content", surfaces=["browser", "saas_api"]),
        ]),
        _pack("hawk:real-estate-client", "Real Estate — Customer & Investor Relations", "Customer and investor relations controls compose the shared Customer Service & Operations pack.", vertical="real_estate", department_persona="customer_investor_relations", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-support"), references=refs),
        _pack("hawk:real-estate-procurement", "Real Estate — Procurement & Vendors", "Real-estate procurement controls compose the shared Procurement & Vendor Management pack.", vertical="real_estate", department_persona="procurement_vendors", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-procurement"), references=refs),
        _pack("hawk:real-estate-data-proptech", "Real Estate — Data, Analytics & PropTech", "Data, analytics, and PropTech controls for datasets, models, integrations, and exports.", vertical="real_estate", department_persona="data_analytics_proptech", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-data-ai"), references=refs, rules=[
            _entry("property-market-dataset", "Property and market dataset", "Use approved license, purpose, and destination for proprietary, personal, transaction, and location data.", "real_estate_property_market_dataset", surfaces=ENDPOINT_RUNTIME_SAAS),
            _entry("valuation-model", "Valuation or recommendation model", "Use registered model, version, data, limitations, and human review.", "real_estate_valuation_recommendation_model"),
            _entry("proptech-integration", "External PropTech integration", "Require identity, data scope, API, retention, and control coverage for external PropTech integration.", "real_estate_proptech_integration", decision="hold_for_approval"),
            _entry("data-export", "Data export", "Bind recipient, purpose, expiry, field, volume, and approval before export.", "real_estate_data_export"),
        ]),
        _pack("hawk:real-estate-technology", "Real Estate — IT & Security", "Real-estate technology controls compose the shared IT, Engineering & Security pack.", vertical="real_estate", department_persona="it_security", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-it-security"), references=refs),
        _pack("hawk:real-estate-hr", "Real Estate — Human Resources", "Real-estate HR controls compose the shared Human Resources pack.", vertical="real_estate", department_persona="human_resources", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-hr"), references=refs),
        _pack("hawk:real-estate-executive", "Real Estate — Executive & Board", "Real-estate executive controls compose the shared Executive & Board pack.", vertical="real_estate", department_persona="executive_board", pack_family="vertical_department", inherited_pack_refs=_parents("hawk:common-exec"), references=refs),
    ]


def vendor_policy_pack_specs() -> list[dict[str, Any]]:
    """Return fresh, immutable-in-practice catalog records for vendor seeding."""

    specs = [
        _universal_baseline(),
        *_shared_packs(),
        *_governance_framework_packs(),
        *_bfsi_packs(),
        *_insurance_packs(),
        *_telecom_packs(),
        *_payments_packs(),
        *_real_estate_packs(),
    ]
    stable_ids = [str(spec["stable_pack_id"]) for spec in specs]
    if len(stable_ids) != len(set(stable_ids)):
        raise ValueError("vendor_policy_pack_catalog_duplicate_stable_id")
    return deepcopy(specs)
