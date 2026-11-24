from __future__ import annotations

import pytest

from app.services.native_control.chatgpt_desktop_composite import (
    AccountEvidenceSource,
    ChatGPTAccountContext,
    ChatGPTAction,
    ChatGPTCapability,
    ChatGPTCompositeEvidence,
    ChatGPTDesktopCompositeAdapter,
    ChatGPTDesktopContext,
    ChatGPTDesktopMode,
    ChatGPTRuntimeLocation,
    CompositeDecision,
    CompositeReconciliationStatus,
    CompositeVerification,
)


def _context(
    *,
    mode: ChatGPTDesktopMode = ChatGPTDesktopMode.CHAT,
    runtime: ChatGPTRuntimeLocation = ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
) -> ChatGPTDesktopContext:
    return ChatGPTDesktopContext(
        mode=mode,
        runtime_location=runtime,
        account_context=ChatGPTAccountContext.ENTERPRISE,
        account_evidence_source=AccountEvidenceSource.OPENAI_ADMIN_API,
    )


def test_contract_has_every_required_context_without_native_hook_claim() -> None:
    adapter = ChatGPTDesktopCompositeAdapter()

    assert {item.name for item in ChatGPTDesktopMode} == {
        "CHAT",
        "WORK_LOCAL",
        "WORK_CLOUD",
        "CODEX_LOCAL",
        "CODEX_REMOTE",
        "BUILT_IN_BROWSER",
        "APP_ACTION",
        "MCP_ACTION",
        "UNKNOWN_DESKTOP_MODE",
    }
    assert {item.name for item in ChatGPTRuntimeLocation} == {
        "LOCAL_ENDPOINT",
        "OPENAI_CLOUD",
        "MIXED",
        "UNKNOWN",
    }
    assert {item.name for item in ChatGPTAccountContext} == {
        "ENTERPRISE",
        "BUSINESS",
        "EDU",
        "PERSONAL",
        "UNKNOWN",
    }
    assert adapter.adapter_id == "chatgpt_desktop_composite"
    assert adapter.native_hook_available is False
    assert "chatgpt_desktop_native_hook" not in adapter.control_methods


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (AccountEvidenceSource.OPENAI_ADMIN_API, ChatGPTAccountContext.ENTERPRISE),
        (AccountEvidenceSource.OPENAI_COMPLIANCE_API, ChatGPTAccountContext.ENTERPRISE),
        (AccountEvidenceSource.SSO_WORKSPACE_BINDING, ChatGPTAccountContext.ENTERPRISE),
        (AccountEvidenceSource.HAWK_IDENTITY_BINDING, ChatGPTAccountContext.ENTERPRISE),
        (AccountEvidenceSource.APPROVED_APPLICATION_CONTEXT, ChatGPTAccountContext.ENTERPRISE),
        (AccountEvidenceSource.EMAIL_DOMAIN, ChatGPTAccountContext.UNKNOWN),
        (AccountEvidenceSource.PROCESS_NAME, ChatGPTAccountContext.UNKNOWN),
        (AccountEvidenceSource.NETWORK_DESTINATION, ChatGPTAccountContext.UNKNOWN),
        (AccountEvidenceSource.NONE, ChatGPTAccountContext.UNKNOWN),
    ],
)
def test_account_context_accepts_only_authoritative_evidence(
    source: AccountEvidenceSource,
    expected: ChatGPTAccountContext,
) -> None:
    resolved = ChatGPTDesktopCompositeAdapter().resolve_account_context(
        claimed=ChatGPTAccountContext.ENTERPRISE,
        source=source,
    )

    assert resolved.account_context is expected
    if expected is ChatGPTAccountContext.UNKNOWN:
        assert "account_evidence_not_authoritative" in resolved.reason_codes


def test_account_switch_requires_two_authoritative_observations() -> None:
    adapter = ChatGPTDesktopCompositeAdapter()
    enterprise = adapter.resolve_account_context(
        claimed=ChatGPTAccountContext.ENTERPRISE,
        source=AccountEvidenceSource.OPENAI_ADMIN_API,
    )
    personal = adapter.resolve_account_context(
        claimed=ChatGPTAccountContext.PERSONAL,
        source=AccountEvidenceSource.APPROVED_APPLICATION_CONTEXT,
    )
    untrusted = adapter.resolve_account_context(
        claimed=ChatGPTAccountContext.PERSONAL,
        source=AccountEvidenceSource.EMAIL_DOMAIN,
    )

    assert adapter.account_switch(enterprise, personal) == "enterprise_to_personal"
    assert adapter.account_switch(enterprise, untrusted) is None


@pytest.mark.parametrize(
    ("action", "mode", "runtime", "floor_ids", "semantic"),
    [
        (
            ChatGPTAction.CHAT_PROMPT,
            ChatGPTDesktopMode.CHAT,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_network"},
            set(),
        ),
        (
            ChatGPTAction.CHAT_FILE_UPLOAD,
            ChatGPTDesktopMode.CHAT,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_read", "endpoint_network"},
            {"local_semantic_proxy"},
        ),
        (
            ChatGPTAction.WORK_LOCAL_FILE_READ,
            ChatGPTDesktopMode.WORK_LOCAL,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_read"},
            set(),
        ),
        (
            ChatGPTAction.WORK_LOCAL_FILE_WRITE,
            ChatGPTDesktopMode.WORK_LOCAL,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_write"},
            set(),
        ),
        (
            ChatGPTAction.WORK_DESKTOP_APP,
            ChatGPTDesktopMode.WORK_LOCAL,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_read", "endpoint_file_write", "endpoint_process", "endpoint_network"},
            set(),
        ),
        (
            ChatGPTAction.WORK_CLOUD_ACTION,
            ChatGPTDesktopMode.WORK_CLOUD,
            ChatGPTRuntimeLocation.OPENAI_CLOUD,
            set(),
            {"openai_workspace_controls"},
        ),
        (
            ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION,
            ChatGPTDesktopMode.BUILT_IN_BROWSER,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_network"},
            {"local_semantic_proxy"},
        ),
        (
            ChatGPTAction.BUILT_IN_BROWSER_UPLOAD,
            ChatGPTDesktopMode.BUILT_IN_BROWSER,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_read", "endpoint_network"},
            {"local_semantic_proxy"},
        ),
        (
            ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD,
            ChatGPTDesktopMode.BUILT_IN_BROWSER,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_write", "endpoint_network"},
            {"local_semantic_proxy"},
        ),
        (
            ChatGPTAction.APP_ACTION,
            ChatGPTDesktopMode.APP_ACTION,
            ChatGPTRuntimeLocation.MIXED,
            {"endpoint_network"},
            {"openai_app_action_control"},
        ),
        (
            ChatGPTAction.CUSTOM_MCP_WRITE,
            ChatGPTDesktopMode.MCP_ACTION,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_network"},
            {"hawk_mcp_gateway", "openai_app_action_control"},
        ),
        (
            ChatGPTAction.CODEX_LOCAL_SHELL,
            ChatGPTDesktopMode.CODEX_LOCAL,
            ChatGPTRuntimeLocation.LOCAL_ENDPOINT,
            {"endpoint_file_read", "endpoint_file_write", "endpoint_process", "endpoint_network"},
            {"existing_codex_adapter"},
        ),
        (
            ChatGPTAction.CODEX_REMOTE_ACTION,
            ChatGPTDesktopMode.CODEX_REMOTE,
            ChatGPTRuntimeLocation.OPENAI_CLOUD,
            set(),
            {"existing_codex_runtime_control"},
        ),
    ],
)
def test_action_specific_control_requirements(
    action: ChatGPTAction,
    mode: ChatGPTDesktopMode,
    runtime: ChatGPTRuntimeLocation,
    floor_ids: set[str],
    semantic: set[str],
) -> None:
    result = ChatGPTDesktopCompositeAdapter().requirements_for(
        action,
        _context(mode=mode, runtime=runtime),
    )

    assert {item.floor_id for item in result.mandatory_enforcement_floors} == floor_ids
    assert set(result.semantic_controls) == semantic


def test_unknown_runtime_never_claims_local_endpoint_authority() -> None:
    result = ChatGPTDesktopCompositeAdapter().requirements_for(
        ChatGPTAction.UNKNOWN_ACTION,
        _context(
            mode=ChatGPTDesktopMode.UNKNOWN_DESKTOP_MODE,
            runtime=ChatGPTRuntimeLocation.UNKNOWN,
        ),
    )

    assert result.mandatory_enforcement_floors == ()
    assert result.control_assertion == "unknown"
    assert "runtime_location_unknown" in result.reason_codes


def test_provider_deny_is_monotonic() -> None:
    adapter = ChatGPTDesktopCompositeAdapter()

    assert adapter.effective_decision(False, CompositeDecision.ALLOW) is CompositeDecision.DENY
    assert adapter.effective_decision(True, CompositeDecision.DENY) is CompositeDecision.DENY
    assert adapter.effective_decision(True, CompositeDecision.REQUIRE_APPROVAL) is CompositeDecision.REQUIRE_APPROVAL
    assert adapter.effective_decision(None, CompositeDecision.ALLOW) is CompositeDecision.ALLOW


def test_capability_matrix_has_twenty_independent_rows_and_no_product_green_check() -> None:
    evidence = ChatGPTCompositeEvidence(
        endpoint_file=CompositeVerification.VERIFIED,
        endpoint_process=CompositeVerification.UNVERIFIED,
        endpoint_network=CompositeVerification.VERIFIED,
        semantic_proxy=CompositeVerification.PARTIAL,
        app_access=CompositeVerification.VERIFIED,
        app_action=CompositeVerification.PARTIAL,
        app_approval=CompositeVerification.UNKNOWN,
        custom_mcp=CompositeVerification.VERIFIED,
        compliance=CompositeVerification.VERIFIED,
        codex_local=CompositeVerification.EXPERIMENTAL,
        codex_remote=CompositeVerification.UNKNOWN,
        account_identity=CompositeVerification.VERIFIED,
    )

    matrix = ChatGPTDesktopCompositeAdapter().capability_matrix(evidence)

    assert set(matrix) == set(ChatGPTCapability)
    assert len(matrix) == 20
    assert matrix[ChatGPTCapability.BUILT_IN_BROWSER_DOM].verification is CompositeVerification.UNAVAILABLE
    assert matrix[ChatGPTCapability.BUILT_IN_BROWSER_HTTP_SEMANTICS].verification is CompositeVerification.PARTIAL
    assert matrix[ChatGPTCapability.COMPLIANCE_VISIBILITY].control_role == "evidence_only"
    # The existing Codex adapter cannot lift an unverified mandatory process floor.
    assert matrix[ChatGPTCapability.CODEX_LOCAL].verification is CompositeVerification.UNVERIFIED
    assert matrix[ChatGPTCapability.CODEX_LOCAL].control_role == "existing_codex_adapter_plus_endpoint_floor"
    assert matrix[ChatGPTCapability.WORK_CLOUD].verification is CompositeVerification.UNKNOWN
    assert matrix[ChatGPTCapability.CHAT_FILE_UPLOAD].verification is CompositeVerification.VERIFIED
    assert matrix[ChatGPTCapability.WORK_LOCAL_FILE_WRITE].verification is CompositeVerification.VERIFIED
    assert not hasattr(ChatGPTDesktopCompositeAdapter(), "protected")


@pytest.mark.parametrize(
    ("endpoint", "provider", "linked", "expected"),
    [
        ("action-1", "action-1", False, CompositeReconciliationStatus.CONFIRMED),
        ("endpoint-1", "provider-1", True, CompositeReconciliationStatus.CORRELATED),
        ("endpoint-1", None, False, CompositeReconciliationStatus.MISSING_PROVIDER_EVIDENCE),
        (None, "provider-1", False, CompositeReconciliationStatus.MISSING_ENDPOINT_EVIDENCE),
        (None, None, False, CompositeReconciliationStatus.UNKNOWN),
    ],
)
def test_compliance_reconciliation_is_evidence_only(
    endpoint: str | None,
    provider: str | None,
    linked: bool,
    expected: CompositeReconciliationStatus,
) -> None:
    row = ChatGPTDesktopCompositeAdapter().reconcile(
        endpoint_action_id=endpoint,
        provider_action_id=provider,
        supported_correlation=linked,
    )

    assert row.status is expected
    assert row.control_role == "evidence_only"
    assert row.inline_authorization is False


def test_why_controlled_explains_consequence_control_without_native_semantics() -> None:
    explanation = ChatGPTDesktopCompositeAdapter().why_controlled(
        ChatGPTAction.BUILT_IN_BROWSER_UPLOAD,
        _context(mode=ChatGPTDesktopMode.BUILT_IN_BROWSER),
        semantic_proxy_available=False,
    )

    assert explanation["semantic_native_hook"] == "unavailable"
    assert explanation["mandatory_floor"] == "hawk_endpoint"
    assert explanation["file"] == "hawk_file_authorization"
    assert explanation["network"] == "hawk_network_filter"
    assert explanation["semantic_proxy"] == "absent"
    assert "consequence" in explanation["why_selected"].lower()
