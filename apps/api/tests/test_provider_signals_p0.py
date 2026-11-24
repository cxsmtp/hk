from __future__ import annotations


def test_browser_domain_metadata_does_not_project_as_mcp_usage() -> None:
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.services.provider_signals import _runtime_tool_payload

    browser = RuntimeEvent(
        event_id="browser-not-mcp", tenant_id="tenant-a", source_surface="browser",
        event_type="prompt_submitted", app_id="chatgpt.com",
        metadata_json={"tool_name": "chatgpt.com", "mcp_server_id": "mcp.tools"},
    )
    actual = RuntimeEvent(
        event_id="actual-mcp", tenant_id="tenant-a", source_surface="mcp",
        event_type="mcp_tool_call", app_id="repo-server",
        metadata_json={"mcp_server_id": "repo-server", "mcp_tool_id": "list_pull_requests"},
    )
    assert _runtime_tool_payload(browser, browser.metadata_json) is None
    assert _runtime_tool_payload(actual, actual.metadata_json)["server_identity"] == "repo-server"

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models.provider_signal import ProviderSeatSnapshot, ProviderSignalRecord
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base
from app.services.external_capability_integrity import ExternalCapabilityIntegrityService
from app.services.provider_signals import (
    ProviderSeatSnapshotEnvelope,
    ProviderSignalEnvelope,
    build_provider_signal_workspace,
    build_provider_signal_workspace_from_records,
    ingest_provider_seat_snapshot,
    ingest_provider_signal,
    purge_expired_provider_signal_records,
)


NOW = datetime(2026, 9, 13, 12, tzinfo=UTC)


def _envelope(*, kind: str, source_record_id: str, payload: dict, tenant_id: str | None = None):
    return ProviderSignalEnvelope.model_validate(
        {
            "tenant_id": tenant_id,
            "provider": "anthropic",
            "product": "claude_code",
            "source_type": "otel",
            "source_schema_version": "1.0",
            "source_record_id": source_record_id,
            "record_kind": kind,
            "occurred_at": NOW.isoformat(),
            "evidence_quality": "OBSERVED",
            "payload": payload,
        }
    )


def test_provider_signal_contract_rejects_secrets_and_raw_prompt_content() -> None:
    with pytest.raises(ValidationError, match="secret-bearing field"):
        _envelope(
            kind="tool",
            source_record_id="tool-secret",
            payload={
                "server_identity": "github-mcp",
                "connection_state": "CONNECTED",
                "api_key": "must-not-be-stored",
            },
        )

    with pytest.raises(ValidationError, match="raw prompt content"):
        _envelope(
            kind="prompt",
            source_record_id="prompt-raw",
            payload={
                "content_level": "FULL_CONTENT_PRIVILEGED",
                "prompt_text": "do not persist me",
            },
        )


def test_provider_signal_ingestion_is_idempotent_and_rejects_tenant_mismatch() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        envelope = _envelope(
            kind="usage",
            source_record_id="usage-1",
            tenant_id="tenant-a",
            payload={
                "metric": "input_tokens",
                "value": 120,
                "unit": "tokens",
                "reconciliation_key": "request-1:input",
            },
        )
        with Session(engine) as db:
            first = ingest_provider_signal(db, tenant_id="tenant-a", envelope=envelope)
            second = ingest_provider_signal(db, tenant_id="tenant-a", envelope=envelope)
            db.commit()
            assert first.created is True
            assert second.created is False
            assert first.record.id == second.record.id
            assert len(db.scalars(select(ProviderSignalRecord)).all()) == 1

        with Session(engine) as db:
            with pytest.raises(PermissionError, match="tenant mismatch"):
                ingest_provider_signal(db, tenant_id="tenant-b", envelope=envelope)
    finally:
        engine.dispose()


def test_spend_reconciliation_prefers_billed_cost_without_double_counting_estimate() -> None:
    records = [
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="otel",
            source_schema_version="1.0",
            source_record_id="estimate-1",
            dedup_key="a" * 64,
            record_kind="spend",
            occurred_at=NOW,
            evidence_quality="OBSERVED",
            payload={
                "cost_type": "CLIENT_ESTIMATE",
                "amount": "9.75",
                "currency": "USD",
                "reconciliation_key": "claude:2026-09-13:user-1",
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="invoice",
            source_schema_version="1.0",
            source_record_id="invoice-1",
            dedup_key="b" * 64,
            record_kind="spend",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={
                "cost_type": "PROVIDER_BILLED",
                "amount": "8.50",
                "currency": "USD",
                "reconciliation_key": "claude:2026-09-13:user-1",
            },
        ),
    ]

    result = build_provider_signal_workspace_from_records(
        records, tenant_id="tenant-a", now=NOW, role="owner"
    )

    assert result["spend_utilization"]["totals_by_currency"] == {"USD": Decimal("8.50")}
    chosen = result["spend_utilization"]["records"][0]
    assert chosen["cost_type"] == "PROVIDER_BILLED"
    assert chosen["amount"] == Decimal("8.50")
    assert chosen["supplementary_cost_types"] == ["CLIENT_ESTIMATE"]


def test_mcp_configured_connected_and_used_states_remain_distinct() -> None:
    records = [
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="openai",
            product="codex",
            source_type="mcp_config",
            source_schema_version="1.0",
            source_record_id=f"mcp-{state.lower()}",
            dedup_key=character * 64,
            record_kind="tool",
            occurred_at=NOW,
            evidence_quality="OBSERVED",
            payload={
                "server_identity": f"server-{state.lower()}",
                "client": "Codex CLI",
                "configuration_scope": "USER_GLOBAL",
                "connection_state": state,
                "tool_name": "repo.read" if state == "CONNECTED" else None,
                "invocation_count": 1 if state == "USED" else 0,
            },
        )
        for state, character in (("CONFIGURED", "c"), ("CONNECTED", "d"), ("USED", "e"))
    ]

    result = build_provider_signal_workspace_from_records(
        records, tenant_id="tenant-a", now=NOW, role="owner"
    )
    summary = result["mcp_tools"]["summary"]

    assert summary["configured"] == 1
    assert summary["connected"] == 2
    assert summary["used"] == 1
    assert result["mcp_tools"]["servers"][0]["configured_at_is_last_used"] is False


def test_prompt_visibility_never_exposes_raw_content_and_viewer_is_aggregate_only() -> None:
    record = ProviderSignalRecord(
        tenant_id="tenant-a",
        provider="openai",
        product="codex",
        source_type="hook",
        source_schema_version="1.0",
        source_record_id="prompt-1",
        dedup_key="f" * 64,
        record_kind="prompt",
        occurred_at=NOW,
        user_id="user-1",
        department="Engineering",
        client="Codex CLI",
        model="gpt-5.6",
        session_ref="session-1",
        evidence_quality="OBSERVED",
        payload={
            "content_level": "REDACTED_PREVIEW",
            "prompt_category": "code_change",
            "redacted_preview": "Update [REDACTED] configuration",
            "data_classifications": ["CREDENTIAL"],
            "injection_indicators": ["disable_controls"],
            "policy_decision": "BLOCK",
        },
    )

    viewer = build_provider_signal_workspace_from_records(
        [record], tenant_id="tenant-a", now=NOW, role="viewer"
    )
    owner = build_provider_signal_workspace_from_records(
        [record], tenant_id="tenant-a", now=NOW, role="owner"
    )

    assert viewer["prompts_actions"]["items"] == []
    assert viewer["prompts_actions"]["aggregate_only"] is True
    assert owner["prompts_actions"]["items"][0]["redacted_preview"] == "Update [REDACTED] configuration"
    assert "prompt_text" not in str(owner).lower()
    assert owner["prompts_actions"]["raw_prompt_stored"] is False


def test_runtime_events_project_into_ai_tools_workspace_without_provider_admin_connector() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add(
                RuntimeEvent(
                    event_id="runtime-mcp-claude-1",
                    tenant_id="tenant-a",
                    source_surface="mcp",
                    event_type="mcp_tool_call",
                    app_id="github-pr",
                    user_id="owner@acme.ai",
                    application="Claude Desktop",
                    decision="allow",
                    confidence_tier="clear_positive",
                    metadata_json={
                        "provider": "anthropic",
                        "model": "claude-opus-5",
                        "ai_client": "Claude Desktop",
                        "mcp_server_id": "hawk-github-pr-claude",
                        "mcp_tool_id": "list_pull_requests",
                        "tool_name": "list_pull_requests",
                        "session_id": "claude-session-1",
                        "prompt_category": "github_repository_read",
                        "redacted_preview": "List open pull requests for an approved repository.",
                        "input_tokens": 120,
                        "output_tokens": 40,
                        "total_tokens": 160,
                        "estimated_cost_usd": "0.0042",
                    },
                    created_at=NOW,
                )
            )
            db.commit()

            result = build_provider_signal_workspace(db, tenant_id="tenant-a", now=NOW, role="owner")

            anthropic = next(row for row in result["providers"] if row["provider"] == "anthropic")
            assert anthropic["connection_state"] == "OBSERVED"
            assert anthropic["products"] == ["claude_desktop"]
            assert result["overview"]["providers_observed"] == 1
            assert result["overview"]["mcp_servers"] == 1
            assert result["mcp_tools"]["summary"]["used"] == 1
            assert result["mcp_tools"]["servers"][0]["server_identity"] == "hawk-github-pr-claude"
            assert result["prompts_actions"]["total"] == 1
            assert result["prompts_actions"]["items"][0]["redacted_preview"] == (
                "List open pull requests for an approved repository."
            )
            assert any(
                row["metric"] == "total_tokens"
                and row["unit"] == "tokens"
                and row["value"] == Decimal("160")
                for row in result["usage"]
            )
            assert result["spend_utilization"]["totals_by_currency"] == {"USD": Decimal("0.0042")}
            assert result["spend_utilization"]["seats"]["unavailable_reason"] == (
                "no_current_provider_admin_seat_snapshot"
            )
            readiness = result["authoritative_source_readiness"]
            assert readiness["overall_status"] == "OBSERVED_ONLY"
            assert readiness["enterprise_denominator"]["status"] == "MISSING_SOURCE"
            assert readiness["enterprise_denominator"]["required_sources"] == [
                "identity_directory",
                "device_inventory",
                "managed_browser_fleet",
                "provider_admin",
            ]
            assert readiness["provider_billed_spend"]["status"] == "MISSING_SOURCE"
            assert readiness["provider_billed_spend"]["observed_evidence"] == [
                "client_estimated_spend"
            ]
            assert readiness["provider_admin_seat_utilization"]["status"] == "MISSING_SOURCE"
            assert readiness["full_control_coverage"]["status"] == "PARTIAL_EVIDENCE"
            assert readiness["full_control_coverage"]["observed_evidence"] == [
                "runtime_activity",
                "mcp_activity",
            ]
            assert result["window"]["runtime_event_count"] == 1
    finally:
        engine.dispose()


def test_authoritative_readiness_becomes_current_with_billed_spend_seats_and_complete_control_evidence() -> None:
    records = [
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="provider_spend_api",
            source_schema_version="1.0",
            source_record_id="bill-1",
            dedup_key="q" * 64,
            record_kind="spend",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={
                "cost_type": "PROVIDER_BILLED",
                "amount": "8.50",
                "currency": "USD",
                "reconciliation_key": "anthropic:billing:2026-09",
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="provider_admin",
            source_schema_version="1.0",
            source_record_id="capability-denominator-1",
            dedup_key="r" * 64,
            record_kind="capability",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={"dimension": "enterprise_denominator", "status": "VERIFIED"},
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="provider_compliance",
            source_schema_version="1.0",
            source_record_id="capability-coverage-1",
            dedup_key="s" * 64,
            record_kind="capability",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={"dimension": "control_coverage", "status": "VERIFIED"},
        ),
    ]
    seats = [
        ProviderSeatSnapshot(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="provider_admin",
            source_schema_version="1.0",
            source_record_id="seats-1",
            dedup_key="t" * 64,
            billing_group="Claude Enterprise",
            authority_reference="provider-admin-snapshot",
            total_licensed_seats=10,
            assigned_seats=10,
            active_seats=7,
            inactive_seats=2,
            never_used_seats=1,
            unknown_activity_seats=0,
            completeness="COMPLETE",
            evidence_quality="CONFIRMED",
            observed_at=NOW,
        )
    ]

    result = build_provider_signal_workspace_from_records(
        records,
        tenant_id="tenant-a",
        now=NOW,
        role="owner",
        seat_snapshots=seats,
    )

    readiness = result["authoritative_source_readiness"]
    assert readiness["overall_status"] == "AUTHORITATIVE"
    assert readiness["enterprise_denominator"]["status"] == "AUTHORITATIVE"
    assert readiness["provider_billed_spend"]["status"] == "AUTHORITATIVE"
    assert readiness["provider_admin_seat_utilization"]["status"] == "AUTHORITATIVE"
    assert readiness["full_control_coverage"]["status"] == "AUTHORITATIVE"


def test_anthropic_source_profiles_keep_console_enterprise_and_personal_paths_distinct() -> None:
    records = [
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_api",
            source_type="provider_admin",
            source_schema_version="anthropic-usage-cost-api/1",
            source_record_id="anthropic-console-usage-1",
            dedup_key="u" * 64,
            record_kind="usage",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={
                "metric": "input_tokens",
                "value": "1000",
                "unit": "tokens",
                "reconciliation_key": "anthropic-console:messages:2026-09-13",
                "anthropic_org_type": "CONSOLE_ORG",
                "anthropic_feed": "usage_report_messages",
                "workspace_id": None,
                "api_key_id": None,
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_api",
            source_type="provider_spend_api",
            source_schema_version="anthropic-cost-report/1",
            source_record_id="anthropic-console-cost-1",
            dedup_key="v" * 64,
            record_kind="spend",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={
                "cost_type": "PROVIDER_REPORTED",
                "amount": "12.34",
                "currency": "USD",
                "reconciliation_key": "anthropic-console:cost:2026-09-13",
                "anthropic_org_type": "CONSOLE_ORG",
                "anthropic_feed": "cost_report",
                "granularity": "1d",
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_enterprise",
            source_type="provider_analytics",
            source_schema_version="anthropic-enterprise-analytics/1",
            source_record_id="anthropic-enterprise-analytics-1",
            dedup_key="w" * 64,
            record_kind="usage",
            occurred_at=NOW,
            evidence_quality="CONFIRMED",
            payload={
                "metric": "active_users",
                "value": "7",
                "unit": "users",
                "reconciliation_key": "anthropic-enterprise:2026-09-13",
                "anthropic_org_type": "ENTERPRISE_ORG",
                "anthropic_feed": "analytics_api",
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_code",
            source_type="otel",
            source_schema_version="claude-code-otel/1",
            source_record_id="anthropic-personal-otel-1",
            dedup_key="x" * 64,
            record_kind="spend",
            occurred_at=NOW,
            evidence_quality="OBSERVED",
            payload={
                "cost_type": "CLIENT_ESTIMATE",
                "amount": "0.42",
                "currency": "USD",
                "reconciliation_key": "claude-code-personal:prompt-1",
                "anthropic_org_type": "PERSONAL_OR_SELF_REPORTED",
                "anthropic_feed": "claude_code_otel",
                "prompt_id": "prompt-uuid-1",
                "tool_use_id": "tool-use-1",
            },
        ),
        ProviderSignalRecord(
            tenant_id="tenant-a",
            provider="anthropic",
            product="claude_desktop",
            source_type="hook",
            source_schema_version="desktop-local/1",
            source_record_id="anthropic-desktop-local-1",
            dedup_key="y" * 64,
            record_kind="capability",
            occurred_at=NOW,
            evidence_quality="OBSERVED",
            payload={
                "dimension": "provider_billing_telemetry",
                "status": "UNSUPPORTED",
                "anthropic_org_type": "DESKTOP_OR_CONSUMER_CHAT",
                "anthropic_feed": "none",
            },
        ),
    ]

    result = build_provider_signal_workspace_from_records(
        records, tenant_id="tenant-a", now=NOW, role="owner"
    )

    anthropic_readiness = result["provider_source_profiles"]["anthropic"]
    assert anthropic_readiness["provider"] == "anthropic"
    assert anthropic_readiness["overall_status"] == "PARTIAL"
    assert anthropic_readiness["profiles"] == [
        {
            "profile": "console_admin_api",
            "status": "ATTESTED",
            "cost_label": "provider_reported",
            "source_types": ["provider_admin", "provider_spend_api"],
            "required_credential": "Anthropic Admin API key or org-admin OAuth token",
            "notes": [
                "Admin keys are high-privilege organization credentials; do not present them as read-only scoped keys.",
                "Default workspace usage may have null workspace_id; playground API usage may have null api_key_id.",
            ],
        },
        {
            "profile": "enterprise_analytics_api",
            "status": "ATTESTED",
            "cost_label": "provider_reported",
            "source_types": ["provider_analytics"],
            "required_credential": "Claude Enterprise Analytics API key with read:analytics",
            "notes": [
                "Claude Enterprise parent organizations do not appear in Claude Console and do not use Console Admin API keys.",
            ],
        },
        {
            "profile": "personal_or_proxy",
            "status": "SELF_REPORTED",
            "cost_label": "client_estimate",
            "source_types": ["otel"],
            "required_credential": "Trinya proxy response usage or Claude Code OpenTelemetry",
            "notes": [
                "Personal-tier usage is modeled or client-reported, not provider-billed truth.",
                "Join Claude Code OTel to hook evidence with prompt_id and tool_use_id when present.",
            ],
        },
        {
            "profile": "desktop_or_consumer_chat",
            "status": "NOT_COVERED",
            "cost_label": "unavailable",
            "source_types": ["hook"],
            "required_credential": "No provider-side billing or usage API",
            "notes": [
                "Claude Desktop and consumer chat usage can be observed only through governed local surfaces; provider-billed telemetry is unavailable.",
            ],
        },
    ]
    assert result["authoritative_source_readiness"]["provider_billed_spend"]["status"] == "MISSING_SOURCE"
    assert result["authoritative_source_readiness"]["provider_billed_spend"]["observed_evidence"] == [
        "provider_reported_spend",
        "client_estimated_spend",
    ]


def test_runtime_usage_projection_accepts_provider_hook_aliases_without_treating_risk_dollars_as_spend() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add_all(
                [
                    RuntimeEvent(
                        event_id="runtime-hook-codex-usage-1",
                        tenant_id="tenant-a",
                        source_surface="hook",
                        event_type="codex_session_turn",
                        app_id="codex",
                        user_id="owner@acme.ai",
                        application="Codex CLI",
                        decision="allow",
                        confidence_tier="clear_positive",
                        metadata_json={
                            "provider": "openai",
                            "model": "gpt-5.6",
                            "ai_client": "Codex CLI",
                            "session_id": "codex-session-1",
                            "usage": {
                                "inputTokenCount": 300,
                                "outputTokenCount": 75,
                                "totalTokenCount": 375,
                                "cost": {"amount": "0.0195", "currency": "usd", "source": "client_estimate"},
                            },
                        },
                        created_at=NOW,
                    ),
                    RuntimeEvent(
                        event_id="runtime-risk-only-1",
                        tenant_id="tenant-a",
                        source_surface="connector",
                        event_type="integration.health.openai",
                        app_id="openai",
                        application="openai",
                        decision="allow",
                        confidence_tier="clear_positive",
                        metadata_json={
                            "provider": "openai",
                            "crq": {
                                "financials": {
                                    "risk_reduced_usd": 1000000,
                                    "risk_exposure_usd": 250000,
                                    "at_risk_if_ignored_usd": 1250000,
                                }
                            },
                        },
                        created_at=NOW,
                    ),
                ]
            )
            db.commit()

            result = build_provider_signal_workspace(db, tenant_id="tenant-a", now=NOW, role="owner")

            assert any(
                row["provider"] == "openai"
                and row["metric"] == "input_tokens"
                and row["value"] == Decimal("300")
                for row in result["usage"]
            )
            assert any(
                row["provider"] == "openai"
                and row["metric"] == "total_tokens"
                and row["value"] == Decimal("375")
                for row in result["usage"]
            )
            assert result["spend_utilization"]["totals_by_currency"] == {"USD": Decimal("0.0195")}
            assert all(
                row["amount"] != Decimal("1000000")
                for row in result["spend_utilization"]["records"]
            )
    finally:
        engine.dispose()


def test_runtime_client_metadata_projects_estimated_tokens_and_rate_card_spend() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add(
                RuntimeEvent(
                    event_id="runtime-browser-client-estimate-1",
                    tenant_id="tenant-a",
                    source_surface="browser",
                    event_type="prompt_submit",
                    app_id="chatgpt",
                    user_id="owner@acme.ai",
                    application="ChatGPT",
                    decision="allow",
                    confidence_tier="clear_positive",
                    metadata_json={
                        "provider": "openai",
                        "model": "gpt-5.6",
                        "ai_client": "Chrome Extension",
                        "session_id": "browser-session-1",
                        "prompt_chars": 401,
                        "output_chars": 99,
                        "prompt_category": "safe_demo",
                        "redacted_preview": "Summarize this metadata-only demo request.",
                        "rate_card": {
                            "input_usd_per_million": "2",
                            "output_usd_per_million": "10",
                            "reference": "demo-rate-card-2026-09",
                        },
                    },
                    created_at=NOW,
                )
            )
            db.commit()

            result = build_provider_signal_workspace(db, tenant_id="tenant-a", now=NOW, role="owner")

            assert any(
                row["metric"] == "input_tokens"
                and row["value"] == Decimal("101")
                for row in result["usage"]
            )
            assert any(
                row["metric"] == "output_tokens"
                and row["value"] == Decimal("25")
                for row in result["usage"]
            )
            assert any(
                row["metric"] == "total_tokens"
                and row["value"] == Decimal("126")
                for row in result["usage"]
            )
            assert result["spend_utilization"]["totals_by_currency"] == {"USD": Decimal("0.000452")}
            spend_record = result["spend_utilization"]["records"][0]
            assert spend_record["cost_type"] == "CONTRACT_RATE_CARD"
            assert spend_record["allocation_method"] == "runtime_event_rate_card_projection"
            assert spend_record["contract_reference"] == "demo-rate-card-2026-09"
    finally:
        engine.dispose()


def test_runtime_browser_metadata_aliases_project_to_workspace_tabs() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add_all(
                [
                    RuntimeEvent(
                        event_id="runtime-browser-aliases-1",
                        tenant_id="tenant-a",
                        source_surface="browser",
                        event_type="chatgpt_prompt_submitted",
                        app_id="chatgpt-web",
                        user_id="owner@acme.ai",
                        application="https://chatgpt.com/c/demo",
                        decision="warn",
                        confidence_tier="clear_positive",
                        metadata_json={
                            "model_provider": "openai",
                            "model_id": "gpt-5.6",
                            "client_name": "Chrome managed extension",
                            "session_id": "browser-session-2",
                            "account_type": "ENTERPRISE_MANAGED_USER",
                            "device_assurance": "MANAGED_COMPLIANT",
                            "department_name": "Engineering",
                            "prompt_preview_redacted": "Summarize [REDACTED] tenant metadata.",
                            "classifications": ["CONFIDENTIAL", "UAE_PERSONAL_DATA"],
                            "prompt_injection_indicators": ["instruction_override"],
                            "instruction_provenance": ["browser_dom"],
                        },
                        created_at=NOW,
                    ),
                    RuntimeEvent(
                        event_id="runtime-mcp-aliases-1",
                        tenant_id="tenant-a",
                        source_surface="gateway",
                        event_type="tool_call_blocked",
                        app_id="github-gateway",
                        user_id="owner@acme.ai",
                        application="Codex Desktop",
                        decision="block",
                        confidence_tier="clear_positive",
                        metadata_json={
                            "provider_id": "openai",
                            "model_name": "gpt-5.6",
                            "runtime_provider": "Codex Desktop",
                            "mcp_server_name": "github-enterprise",
                            "function_name": "create_pull_request",
                            "repository_scope": "github.com/personal/repo",
                            "transport": "stdio",
                        },
                        created_at=NOW,
                    ),
                ]
            )
            db.commit()

            result = build_provider_signal_workspace(db, tenant_id="tenant-a", now=NOW, role="owner")

            openai = next(row for row in result["providers"] if row["provider"] == "openai")
            assert openai["connection_state"] == "OBSERVED"
            assert set(openai["products"]) >= {"chatgpt", "codex"}
            assert result["prompts_actions"]["total"] == 1
            prompt = result["prompts_actions"]["items"][0]
            assert prompt["redacted_preview"] == "Summarize [REDACTED] tenant metadata."
            assert prompt["data_classifications"] == ["CONFIDENTIAL", "UAE_PERSONAL_DATA"]
            assert prompt["injection_indicators"] == ["instruction_override"]
            assert result["data_controls"]["classifications"] == ["CONFIDENTIAL", "UAE_PERSONAL_DATA"]
            assert result["data_controls"]["classified_prompt_events"] == 1
            assert result["mcp_tools"]["summary"]["blocked"] == 1
            assert result["mcp_tools"]["servers"][0]["server_identity"] == "github-enterprise"
            assert result["mcp_tools"]["servers"][0]["tool_name"] == "create_pull_request"
            assert result["accounts_devices"]["summary"]["observed_sessions"] == 2
            assert result["accounts_devices"]["summary"]["account_classes"] == ["ENTERPRISE_MANAGED_USER"]
            assert result["accounts_devices"]["summary"]["device_assurance"] == ["MANAGED_COMPLIANT"]
    finally:
        engine.dispose()


def test_mcp_configuration_signal_projects_inventory_only_and_is_idempotent() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        envelope = _envelope(
            kind="tool",
            source_record_id="mcp-observation-1",
            payload={
                "server_identity": "github-readonly",
                "connection_state": "USED",
                "tool_name": "list_pull_requests",
                "tool_schema_hash": "a" * 64,
                "invocation_count": 1,
            },
        )
        with Session(engine) as db:
            first = ingest_provider_signal(db, tenant_id="tenant-a", envelope=envelope)
            second = ingest_provider_signal(db, tenant_id="tenant-a", envelope=envelope)
            db.commit()

            assert first.created is True
            assert second.created is False
            projection = first.record.projection_refs
            assert projection["external_capability_id"]
            assert projection["projection_mode"] == "CONFIGURATION_INVENTORY"
            assert projection["runtime_event_id"] is None
            assert projection["activity_lineage_id"] is None
            assert projection["control_coverage_path_id"] is None
            assert projection["hmair"]["status"] == "UNRESOLVED"
    finally:
        engine.dispose()


def test_gateway_attested_used_mcp_signal_reuses_existing_gateway_event_only() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            db.add(
                RuntimeEvent(
                    event_id="gateway-mcp-authorize-1",
                    tenant_id="tenant-a",
                    source_surface="gateway",
                    event_type="mcp_authorize",
                    app_id="github-readonly",
                    decision="allow",
                    confidence_tier="clear_positive",
                    metadata_json={"mcp_server_id": "github-readonly", "tool_name": "list_pull_requests"},
                )
            )
            db.flush()
            result = ingest_provider_signal(
                db,
                tenant_id="tenant-a",
                envelope=_envelope(
                    kind="tool",
                    source_record_id="mcp-gateway-attested-1",
                    payload={
                        "server_identity": "github-readonly",
                        "connection_state": "USED",
                        "tool_name": "list_pull_requests",
                        "tool_schema_hash": "b" * 64,
                        "invocation_count": 1,
                        "observation_mode": "GATEWAY_ATTESTED_INVOCATION",
                        "gateway_event_id": "gateway-mcp-authorize-1",
                    },
                ),
            )
            db.commit()
            projection = result.record.projection_refs
            assert projection["projection_mode"] == "GATEWAY_ATTESTED_INVOCATION"
            assert projection["runtime_event_id"] == "gateway-mcp-authorize-1"
            assert projection["activity_lineage_id"]
            assert projection["control_coverage_path_id"]
    finally:
        engine.dispose()


def test_inventory_or_inferred_observation_cannot_restore_stale_trust() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        observation = {
            "configured_locator": "mcp:github-readonly",
            "server_metadata": {"name": "github-readonly", "version": "1.0"},
            "tools": [{"name": "list_pull_requests", "version": "1.0"}],
        }
        changed = {**observation, "tools": [{"name": "create_pull_request", "version": "1.0"}]}
        with Session(engine) as db:
            service = ExternalCapabilityIntegrityService()
            service.observe_mcp_capability(
                db, tenant_id="tenant-a", capability_ref="mcp:github-readonly", observation=observation,
                observed_at=NOW, evidence_quality="CONFIRMED", observation_mode="GATEWAY_ATTESTED_INVOCATION",
            )
            service.accept_current_baseline(
                db, tenant_id="tenant-a", capability_ref="mcp:github-readonly", actor_ref="owner:1",
                reason="accepted", accepted_at=NOW,
            )
            stale = service.observe_mcp_capability(
                db, tenant_id="tenant-a", capability_ref="mcp:github-readonly", observation=changed,
                observed_at=NOW + timedelta(minutes=1), evidence_quality="CONFIRMED", observation_mode="GATEWAY_ATTESTED_INVOCATION",
            )
            assert stale.trust_state == "STALE"
            still_stale = service.observe_mcp_capability(
                db, tenant_id="tenant-a", capability_ref="mcp:github-readonly", observation=observation,
                observed_at=NOW + timedelta(minutes=2), evidence_quality="OBSERVED", observation_mode="CONFIGURATION_INVENTORY",
            )
            assert still_stale.trust_state == "STALE"
            recovered = service.observe_mcp_capability(
                db, tenant_id="tenant-a", capability_ref="mcp:github-readonly", observation=observation,
                observed_at=NOW + timedelta(minutes=3), evidence_quality="CONFIRMED", observation_mode="GATEWAY_ATTESTED_INVOCATION",
            )
            assert recovered.trust_state == "TRUSTED_CURRENT"
    finally:
        engine.dispose()


def test_authoritative_seat_snapshot_requires_provider_admin_and_aggregates_latest_scope() -> None:
    with pytest.raises(ValidationError, match="provider_admin"):
        ProviderSeatSnapshotEnvelope.model_validate(
            {
                "provider": "anthropic",
                "product": "claude_code",
                "source_type": "provider_analytics",
                "source_schema_version": "1.0",
                "source_record_id": "seat-unsupported-source",
                "observed_at": NOW.isoformat(),
                "assigned_seats": 10,
                "active_seats": 7,
                "inactive_seats": 3,
                "never_used_seats": 0,
                "unknown_activity_seats": 0,
                "total_licensed_seats": 10,
                "completeness": "COMPLETE",
                "authority_reference": "anthropic-admin-export:2026-09-13",
            }
        )

    with pytest.raises(ValidationError, match="authority_reference"):
        ProviderSeatSnapshotEnvelope.model_validate(
            {
                "provider": "anthropic",
                "product": "claude_code",
                "source_type": "provider_admin",
                "source_schema_version": "1.0",
                "source_record_id": "seat-missing-authority",
                "observed_at": NOW.isoformat(),
                "assigned_seats": 1,
                "active_seats": 1,
                "inactive_seats": 0,
                "never_used_seats": 0,
                "unknown_activity_seats": 0,
                "total_licensed_seats": 1,
                "completeness": "COMPLETE",
            }
        )

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        envelope = ProviderSeatSnapshotEnvelope.model_validate(
            {
                "provider": "anthropic",
                "product": "claude_code",
                "source_type": "provider_admin",
                "source_schema_version": "1.0",
                "source_record_id": "seat-1",
                "observed_at": NOW.isoformat(),
                "billing_group": "engineering",
                "assigned_seats": 10,
                "active_seats": 7,
                "inactive_seats": 3,
                "never_used_seats": 0,
                "unknown_activity_seats": 0,
                "total_licensed_seats": 10,
                "completeness": "COMPLETE",
                "authority_reference": "anthropic-admin-export:2026-09-13",
            }
        )
        with Session(engine) as db:
            first = ingest_provider_seat_snapshot(db, tenant_id="tenant-a", envelope=envelope)
            second = ingest_provider_seat_snapshot(db, tenant_id="tenant-a", envelope=envelope)
            db.commit()
            assert first.created is True
            assert second.created is False
            result = build_provider_signal_workspace_from_records(
                [], tenant_id="tenant-a", now=NOW, role="owner", seat_snapshots=[first.record]
            )
            seats = result["spend_utilization"]["seats"]
            assert seats["assigned_seats"] == 10
            assert seats["active_seats"] == 7
            assert seats["inactive_seats"] == 3
            assert seats["total_licensed_seats"] == 10
            assert seats["unassigned_seats"] == 0
            assert seats["authoritative_snapshot_count"] == 1
            assert seats["utilization_percent"] == Decimal("70.0")
            assert len(db.scalars(select(ProviderSeatSnapshot)).all()) == 1
            partial = ProviderSeatSnapshot(
                id="seat-partial",
                tenant_id="tenant-a",
                provider="anthropic",
                product="claude_code",
                source_type="provider_admin",
                source_schema_version="1.0",
                source_record_id="seat-partial",
                dedup_key="p" * 64,
                authority_reference="anthropic-admin-export:2026-09-11",
                total_licensed_seats=12,
                assigned_seats=10,
                active_seats=6,
                inactive_seats=2,
                never_used_seats=1,
                unknown_activity_seats=1,
                completeness="PARTIAL",
                evidence_quality="CONFIRMED",
                observed_at=NOW - timedelta(days=2),
            )
            partial_workspace = build_provider_signal_workspace_from_records(
                [], tenant_id="tenant-a", now=NOW, role="owner", seat_snapshots=[partial]
            )
            partial_snapshot = partial_workspace["spend_utilization"]["seats"]["snapshots"][0]
            assert partial_snapshot["unassigned_seats"] == 2
            assert partial_snapshot["status"] == "PARTIAL"
            assert partial_snapshot["freshness"] == "STALE"
    finally:
        engine.dispose()


def test_provider_signal_retention_is_tenant_scoped_and_received_at_bounded() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        old = NOW - timedelta(days=91)
        fresh = NOW - timedelta(days=1)
        with Session(engine) as db:
            db.add_all(
                [
                    ProviderSignalRecord(
                        tenant_id="tenant-a", provider="openai", product="codex", source_type="otel",
                        source_schema_version="1.0", source_record_id="old-a", dedup_key="1" * 64,
                        record_kind="usage", occurred_at=old, received_at=old, evidence_quality="OBSERVED",
                        payload={"metric": "input_tokens", "value": "1", "unit": "tokens", "reconciliation_key": "old-a"},
                    ),
                    ProviderSignalRecord(
                        tenant_id="tenant-a", provider="openai", product="codex", source_type="otel",
                        source_schema_version="1.0", source_record_id="fresh-a", dedup_key="2" * 64,
                        record_kind="usage", occurred_at=old, received_at=fresh, evidence_quality="OBSERVED",
                        payload={"metric": "input_tokens", "value": "1", "unit": "tokens", "reconciliation_key": "fresh-a"},
                    ),
                    ProviderSignalRecord(
                        tenant_id="tenant-a", provider="openai", product="codex", source_type="otel",
                        source_schema_version="1.0", source_record_id="old-a-2", dedup_key="4" * 64,
                        record_kind="usage", occurred_at=old, received_at=old, evidence_quality="OBSERVED",
                        payload={"metric": "input_tokens", "value": "1", "unit": "tokens", "reconciliation_key": "old-a-2"},
                    ),
                    ProviderSignalRecord(
                        tenant_id="tenant-b", provider="openai", product="codex", source_type="otel",
                        source_schema_version="1.0", source_record_id="old-b", dedup_key="3" * 64,
                        record_kind="usage", occurred_at=old, received_at=old, evidence_quality="OBSERVED",
                        payload={"metric": "input_tokens", "value": "1", "unit": "tokens", "reconciliation_key": "old-b"},
                    ),
                ]
            )
            db.commit()
            preview = purge_expired_provider_signal_records(
                db, tenant_id="tenant-a", retention_days=90, now=NOW, batch_limit=10
            )
            assert preview.executed is False
            assert preview.candidate_signal_records == 2
            assert preview.deleted_signal_records == 0
            assert {row.source_record_id for row in db.scalars(select(ProviderSignalRecord)).all()} == {
                "old-a", "old-a-2", "fresh-a", "old-b"
            }
            bounded = purge_expired_provider_signal_records(
                db, tenant_id="tenant-a", retention_days=90, now=NOW, batch_limit=1, execute=True
            )
            assert bounded.deleted_signal_records == 1
            assert bounded.more_remaining is True
            db.rollback()
            assert {row.source_record_id for row in db.scalars(select(ProviderSignalRecord)).all()} == {
                "old-a", "old-a-2", "fresh-a", "old-b"
            }
            result = purge_expired_provider_signal_records(
                db,
                tenant_id="tenant-a",
                retention_days=90,
                now=NOW,
                batch_limit=10,
                execute=True,
            )
            db.commit()
            assert result.executed is True
            assert result.candidate_signal_records == 2
            assert result.deleted_signal_records == 2
            assert result.deleted_seat_snapshots == 0
            assert result.more_remaining is False
            remaining = {row.source_record_id for row in db.scalars(select(ProviderSignalRecord)).all()}
            assert remaining == {"fresh-a", "old-b"}
    finally:
        engine.dispose()
