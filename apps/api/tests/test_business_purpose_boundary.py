from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.policy import TenantSectorProfile, UserBusinessFunctionMapping
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.ai_iam_service import build_ai_action_record
from app.services.policy_service import (
    REGULATED_DATA_TYPES,
    SECTOR_PURPOSES,
    SUPPORTED_SECTORS,
    classify_code_sql_context,
    ensure_business_purpose_defaults,
    evaluate_business_purpose_boundary,
    resolve_user_business_context,
)


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "business_purpose_boundary.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    db = testing_session_local()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _tenant(db, *, sector: str = "banking", strictness: str = "block") -> Tenant:
    row = Tenant(name="Pilot Bank", slug=f"pilot-bank-{sector}-{strictness}", platform_mode="enforce")
    db.add(row)
    db.flush()
    ensure_business_purpose_defaults(db, tenant_id=row.id, sector=sector, strictness=strictness)
    db.commit()
    return row


def _user(db, tenant_id: str, *, email: str, tenant_role: str = "viewer") -> User:
    row = User(email=email, hashed_password="hash", full_name=email.split("@", 1)[0])
    db.add(row)
    db.flush()
    db.add(UserTenantRole(user_id=row.id, tenant_id=tenant_id, role=tenant_role))
    db.commit()
    return row


def _map(
    db,
    tenant_id: str,
    *,
    email: str | None = None,
    claim_name: str | None = None,
    claim_value: str | None = None,
    business_function: str,
    role_name: str,
    priority: int,
) -> UserBusinessFunctionMapping:
    row = UserBusinessFunctionMapping(
        tenant_id=tenant_id,
        email=email,
        claim_name=claim_name,
        claim_value=claim_value,
        business_function=business_function,
        role_name=role_name,
        department=business_function.title(),
        team=f"{business_function}-team",
        policy_groups=[business_function],
        priority=priority,
        source="manual" if email else "oidc_claim",
        enabled=True,
    )
    db.add(row)
    db.commit()
    return row


def test_business_function_resolution_prefers_explicit_mapping_and_ignores_extension_role(db_session) -> None:
    tenant = _tenant(db_session)
    user = _user(db_session, tenant.id, email="dev@bank.example")
    group_mapping = _map(
        db_session,
        tenant.id,
        claim_name="groups",
        claim_value="risk-team",
        business_function="risk",
        role_name="Risk Analyst",
        priority=10,
    )
    explicit_mapping = _map(
        db_session,
        tenant.id,
        email="dev@bank.example",
        business_function="engineering",
        role_name="Backend Engineer",
        priority=100,
    )

    resolved = resolve_user_business_context(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email="dev@bank.example",
        claims={"groups": ["risk-team"]},
        extension_role_hint="procurement",
    )

    assert resolved["resolved_business_function"] == "engineering"
    assert resolved["resolved_role"] == "Backend Engineer"
    assert resolved["mapping_id"] == explicit_mapping.id
    assert resolved["source"] == "manual"
    assert resolved["confidence"] == "high"
    assert resolved["fallback_used"] is False
    assert resolved["ignored_extension_role_hint"] == "procurement"
    assert resolved["candidate_mapping_ids"] == [explicit_mapping.id, group_mapping.id]


def test_unknown_user_business_function_is_restricted(db_session) -> None:
    tenant = _tenant(db_session, strictness="review")
    user = _user(db_session, tenant.id, email="unknown@bank.example")

    result = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=user.email,
        prompt_text="Summarize this market update",
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    assert result["decision"] == "review"
    assert result["reason"] == "user_role_unresolved_for_ai_policy"
    assert result["finding_type"] == "USER_ROLE_UNRESOLVED_FOR_AI_POLICY"
    assert result["role_resolution"]["resolved_business_function"] == "unknown"
    assert result["role_resolution"]["fallback_used"] is True
    assert result["control_mode"] == "external_required"


@pytest.mark.parametrize(
    ("email", "business_function", "prompt", "expected_decision", "expected_reason"),
    [
        (
            "risk@bank.example",
            "risk",
            "What is the best sofa fabric for my apartment?",
            "block",
            "business_purpose_mismatch",
        ),
        (
            "procurement@bank.example",
            "procurement",
            "Compare fire-resistant fabric vendors for branch renovation seating.",
            "allow",
            "business_purpose_aligned",
        ),
        (
            "compliance@bank.example",
            "compliance",
            "Summarize UAE AML and KYC guidance for banking compliance.",
            "allow",
            "business_purpose_aligned",
        ),
        (
            "developer@bank.example",
            "engineering",
            "Write a Python CSV parser using synthetic sample rows.",
            "allow",
            "generic_coding_help_allowed",
        ),
    ],
)
def test_banking_business_purpose_decisions(
    db_session,
    email: str,
    business_function: str,
    prompt: str,
    expected_decision: str,
    expected_reason: str,
) -> None:
    tenant = _tenant(db_session, strictness="block")
    user = _user(db_session, tenant.id, email=email)
    _map(
        db_session,
        tenant.id,
        email=email,
        business_function=business_function,
        role_name=f"{business_function.title()} User",
        priority=100,
    )

    result = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=email,
        prompt_text=prompt,
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    assert result["decision"] == expected_decision
    assert result["reason"] == expected_reason
    assert result["business_purpose"]["business_function"] == business_function
    assert result["business_purpose"]["tenant_sector"] == "banking"
    assert result["business_purpose"]["purpose_confidence"] in {"medium", "high"}


@pytest.mark.parametrize(
    ("prompt", "expected_decision", "expected_sql_type", "expected_finding"),
    [
        (
            "Explain SELECT id, amount FROM sample_orders WHERE amount > 100 using synthetic data.",
            "allow",
            "synthetic_sql",
            None,
        ),
        (
            "Please optimize SELECT * FROM customer_accounts WHERE account_number='123456789' for prod.",
            "block",
            "customer_data_sql",
            "CUSTOMER_DATA_SQL_TO_AI",
        ),
        (
            "Debug this code: API_KEY='sk-live-1234567890abcdef' import requests",
            "block",
            "unknown",
            "SECRET_IN_CODE_PROMPT",
        ),
    ],
)
def test_coding_and_sql_safe_mode(db_session, prompt: str, expected_decision: str, expected_sql_type: str, expected_finding: str | None) -> None:
    tenant = _tenant(db_session, strictness="block")
    user = _user(db_session, tenant.id, email="developer@bank.example")
    _map(
        db_session,
        tenant.id,
        email=user.email,
        business_function="engineering",
        role_name="Backend Engineer",
        priority=100,
    )

    code_context = classify_code_sql_context(prompt)
    result = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=user.email,
        prompt_text=prompt,
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    assert code_context["sql_type"] == expected_sql_type
    assert result["decision"] == expected_decision
    assert result["code_context"]["sql_type"] == expected_sql_type
    assert result["finding_type"] == expected_finding
    if expected_decision == "block":
        assert result["control_mode"] == "inline_prevented"


def test_sensitive_banking_data_overrides_aligned_purpose(db_session) -> None:
    tenant = _tenant(db_session, strictness="block")
    user = _user(db_session, tenant.id, email="compliance@bank.example")
    _map(
        db_session,
        tenant.id,
        email=user.email,
        business_function="compliance",
        role_name="Compliance Officer",
        priority=100,
    )

    result = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=user.email,
        prompt_text="Summarize AML risk for customer card 4111 1111 1111 1111 and account ACCT-100.",
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    assert result["decision"] == "block"
    assert result["reason"] == "industry_regulated_data_to_public_ai"
    assert result["finding_type"] == "INDUSTRY_REGULATED_DATA_TO_PUBLIC_AI"
    assert result["business_purpose"]["purpose_status"] == "approved"
    assert result["code_context"]["safe_for_public_ai"] is False


def test_ai_action_record_embeds_business_purpose_and_code_context(db_session) -> None:
    tenant = _tenant(db_session)
    user = _user(db_session, tenant.id, email="developer@bank.example")
    _map(
        db_session,
        tenant.id,
        email=user.email,
        business_function="engineering",
        role_name="Backend Engineer",
        priority=100,
    )
    decision = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=user.email,
        prompt_text="Please optimize SELECT * FROM customer_accounts WHERE account_number='123456789' for prod.",
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    action = build_ai_action_record(
        tenant_id=tenant.id,
        action_id="act-business-purpose-1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_surface="browser",
        event_type="prompt_submit",
        user_id=user.id,
        machine_id="macbook-01",
        browser_type="chrome",
        application="ChatGPT",
        decision=decision["decision"],
        evidence_node_ids=["evidence-1"],
        metadata={
            "user_email": user.email,
            "domain": "chatgpt.com",
            "business_purpose_decision": decision,
            "input_content_context": {"sensitivity_level": "high", "contains_customer_data": True},
        },
    )

    assert action["business_purpose"]["business_function"] == "engineering"
    assert action["code_context"]["sql_type"] == "customer_data_sql"
    assert action["role_resolution"]["resolved_role"] == "Backend Engineer"
    assert action["policy"]["control_mode"] == "external_required"
    assert action["decision_explanation"]["evaluated_signals"]["business_purpose"]["tenant_sector"] == "banking"
    assert action["decision_explanation"]["evaluated_signals"]["code_context"]["safe_for_public_ai"] is False

    trusted_action = build_ai_action_record(
        tenant_id=tenant.id,
        action_id="act-business-purpose-trusted",
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_surface="browser",
        event_type="prompt_submit",
        user_id=user.id,
        decision=decision["decision"],
        metadata={"business_purpose_decision": decision},
        trusted_pre_action_governance_check={
            "control_mode": "inline_prevented",
        },
    )
    assert trusted_action["policy"]["control_mode"] == "inline_prevented"


def test_all_supported_sectors_have_default_business_purpose_packs(db_session) -> None:
    expected_sectors = {
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

    assert expected_sectors.issubset(SUPPORTED_SECTORS)
    assert expected_sectors.issubset(SECTOR_PURPOSES)
    assert expected_sectors.issubset(REGULATED_DATA_TYPES)

    for sector in expected_sectors:
        tenant = _tenant(db_session, sector=sector, strictness="block")
        profile = db_session.query(TenantSectorProfile).filter(TenantSectorProfile.tenant_id == tenant.id).one()

        assert profile.sector == sector
        assert profile.approved_business_purposes
        assert "software_engineering" in profile.approved_business_purposes
        assert "security_analysis" in profile.approved_business_purposes
        assert "unrelated_consumer_research" in profile.blocked_business_purposes
        assert profile.regulated_data_types


@pytest.mark.parametrize(
    ("sector", "business_function", "prompt", "expected_category"),
    [
        ("insurance", "risk", "Summarize insurance underwriting and claims risk controls.", "risk_analysis"),
        ("healthcare", "operations", "Summarize HIPAA healthcare operations policy.", "compliance_analysis"),
        ("pharma", "compliance", "Summarize clinical trial quality documentation requirements.", "regulatory_research"),
        ("oil_and_gas", "operations", "Summarize HSE maintenance procedures for refinery equipment.", "operations_support"),
        ("retail", "marketing", "Draft approved merchandising product research notes.", "sales_marketing_approved"),
        ("government", "procurement", "Summarize public sector procurement compliance policy.", "procurement_business"),
        ("legal", "legal", "Summarize NDA clause language for legal review.", "legal_review"),
        ("education", "operations", "Summarize student services education policy workflow.", "operations_support"),
        ("manufacturing", "operations", "Summarize manufacturing quality procedure for plant maintenance.", "operations_support"),
        ("technology", "engineering", "Summarize secure software architecture guidance.", "software_engineering"),
        ("telecom", "operations", "Summarize telecom network operations security guidance.", "operations_support"),
        ("defense", "security", "Summarize defense compliance guidance for security analysis.", "security_analysis"),
        ("energy", "operations", "Summarize grid maintenance and energy operations procedure.", "operations_support"),
        ("generic_enterprise", "operations", "Draft internal productivity workflow summary.", "internal_productivity"),
    ],
)
def test_sector_aligned_prompts_are_allowed_across_all_policy_packs(
    db_session,
    sector: str,
    business_function: str,
    prompt: str,
    expected_category: str,
) -> None:
    tenant = _tenant(db_session, sector=sector, strictness="block")
    email = f"{business_function}@{sector}.example"
    user = _user(db_session, tenant.id, email=email)
    _map(
        db_session,
        tenant.id,
        email=email,
        business_function=business_function,
        role_name=f"{business_function.title()} User",
        priority=100,
    )

    result = evaluate_business_purpose_boundary(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        email=email,
        prompt_text=prompt,
        action_type="prompt_submit",
        destination_domain="chatgpt.com",
        destination_trust_level="public",
        source_surface="browser",
    )

    assert result["decision"] == "allow"
    assert result["business_purpose"]["tenant_sector"] == sector
    assert result["business_purpose"]["business_function"] == business_function
    assert result["business_purpose"]["purpose_category"] == expected_category
    assert result["business_purpose"]["purpose_status"] == "approved"
