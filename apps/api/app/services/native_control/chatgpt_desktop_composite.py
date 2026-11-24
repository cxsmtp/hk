"""Action-specific control composition for the ChatGPT desktop application.

ChatGPT Desktop is treated as one discovered asset with several materially
different execution surfaces.  This module intentionally does not create or
claim a ChatGPT native hook.  It composes supported provider context, Hawk's
existing semantic controls, post-action evidence, and mandatory endpoint
consequence controls where the action is local.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    MandatoryEnforcementFloorRequirement,
    VerificationStatus,
)


class ChatGPTDesktopMode(str, Enum):
    CHAT = "chat"
    WORK_LOCAL = "work_local"
    WORK_CLOUD = "work_cloud"
    CODEX_LOCAL = "codex_local"
    CODEX_REMOTE = "codex_remote"
    BUILT_IN_BROWSER = "built_in_browser"
    APP_ACTION = "app_action"
    MCP_ACTION = "mcp_action"
    UNKNOWN_DESKTOP_MODE = "unknown_desktop_mode"


class ChatGPTRuntimeLocation(str, Enum):
    LOCAL_ENDPOINT = "local_endpoint"
    OPENAI_CLOUD = "openai_cloud"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class ChatGPTAccountContext(str, Enum):
    ENTERPRISE = "enterprise"
    BUSINESS = "business"
    EDU = "edu"
    PERSONAL = "personal"
    UNKNOWN = "unknown"


class AccountEvidenceSource(str, Enum):
    OPENAI_ADMIN_API = "openai_admin_api"
    OPENAI_COMPLIANCE_API = "openai_compliance_api"
    SSO_WORKSPACE_BINDING = "sso_workspace_binding"
    HAWK_IDENTITY_BINDING = "hawk_identity_binding"
    APPROVED_APPLICATION_CONTEXT = "approved_application_context"
    EMAIL_DOMAIN = "email_domain"
    PROCESS_NAME = "process_name"
    NETWORK_DESTINATION = "network_destination"
    NONE = "none"


_AUTHORITATIVE_ACCOUNT_SOURCES = frozenset(
    {
        AccountEvidenceSource.OPENAI_ADMIN_API,
        AccountEvidenceSource.OPENAI_COMPLIANCE_API,
        AccountEvidenceSource.SSO_WORKSPACE_BINDING,
        AccountEvidenceSource.HAWK_IDENTITY_BINDING,
        AccountEvidenceSource.APPROVED_APPLICATION_CONTEXT,
    }
)


class ChatGPTAction(str, Enum):
    CHAT_PROMPT = "chat_prompt"
    CHAT_FILE_UPLOAD = "chat_file_upload"
    WORK_LOCAL_FILE_READ = "work_local_file_read"
    WORK_LOCAL_FILE_WRITE = "work_local_file_write"
    WORK_DESKTOP_APP = "work_desktop_app"
    WORK_CLOUD_ACTION = "work_cloud_action"
    BUILT_IN_BROWSER_NAVIGATION = "built_in_browser_navigation"
    BUILT_IN_BROWSER_UPLOAD = "built_in_browser_upload"
    BUILT_IN_BROWSER_DOWNLOAD = "built_in_browser_download"
    APP_ACTION = "app_action"
    CUSTOM_MCP_WRITE = "custom_mcp_write"
    CODEX_LOCAL_SHELL = "codex_local_shell"
    CODEX_REMOTE_ACTION = "codex_remote_action"
    UNKNOWN_ACTION = "unknown_action"


class ChatGPTCapability(str, Enum):
    CHAT_NETWORK = "chat_network"
    CHAT_FILE_UPLOAD = "chat_file_upload"
    WORK_LOCAL_FILE_READ = "work_local_file_read"
    WORK_LOCAL_FILE_WRITE = "work_local_file_write"
    WORK_DESKTOP_APP = "work_desktop_app"
    WORK_CLOUD = "work_cloud"
    BUILT_IN_BROWSER_NETWORK = "built_in_browser_network"
    BUILT_IN_BROWSER_DESTINATION = "built_in_browser_destination"
    BUILT_IN_BROWSER_HTTP_SEMANTICS = "built_in_browser_http_semantics"
    BUILT_IN_BROWSER_DOM = "built_in_browser_dom"
    BUILT_IN_BROWSER_UPLOAD = "built_in_browser_upload"
    BUILT_IN_BROWSER_DOWNLOAD = "built_in_browser_download"
    APP_ACCESS = "app_access"
    APP_ACTION = "app_action"
    APP_APPROVAL = "app_approval"
    CUSTOM_MCP = "custom_mcp"
    COMPLIANCE_VISIBILITY = "compliance_visibility"
    CODEX_LOCAL = "codex_local"
    CODEX_REMOTE = "codex_remote"
    ACCOUNT_IDENTITY = "account_identity"


class CompositeVerification(str, Enum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    EXPERIMENTAL = "experimental"
    UNVERIFIED = "unverified"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CompositeDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class CompositeReconciliationStatus(str, Enum):
    CONFIRMED = "confirmed"
    CORRELATED = "correlated"
    MISSING_PROVIDER_EVIDENCE = "missing_provider_evidence"
    MISSING_ENDPOINT_EVIDENCE = "missing_endpoint_evidence"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AccountResolution:
    account_context: ChatGPTAccountContext
    evidence_source: AccountEvidenceSource
    authoritative: bool
    reason_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_context": self.account_context.value,
            "evidence_source": self.evidence_source.value,
            "authoritative": self.authoritative,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class ChatGPTDesktopContext:
    mode: ChatGPTDesktopMode
    runtime_location: ChatGPTRuntimeLocation
    account_context: ChatGPTAccountContext
    account_evidence_source: AccountEvidenceSource

    def as_dict(self) -> dict[str, str]:
        return {
            "mode": self.mode.value,
            "runtime_location": self.runtime_location.value,
            "account_context": self.account_context.value,
            "account_evidence_source": self.account_evidence_source.value,
        }


@dataclass(frozen=True, slots=True)
class ChatGPTControlRequirements:
    action: ChatGPTAction
    mandatory_enforcement_floors: tuple[MandatoryEnforcementFloorRequirement, ...]
    semantic_controls: tuple[str, ...]
    provider_context: tuple[str, ...]
    evidence_sources: tuple[str, ...]
    control_assertion: str
    reason_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "mandatory_enforcement_floors": [
                {
                    "floor_id": item.floor_id,
                    "capability": item.capability.value,
                    "minimum_level": item.minimum_level.value,
                    "allowed_methods": [method.value for method in item.allowed_methods],
                    "maximum_latency_ms": item.maximum_latency_ms,
                }
                for item in self.mandatory_enforcement_floors
            ],
            "semantic_controls": list(self.semantic_controls),
            "provider_context": list(self.provider_context),
            "evidence_sources": list(self.evidence_sources),
            "control_assertion": self.control_assertion,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class ChatGPTCompositeEvidence:
    endpoint_file: CompositeVerification = CompositeVerification.UNKNOWN
    endpoint_process: CompositeVerification = CompositeVerification.UNKNOWN
    endpoint_network: CompositeVerification = CompositeVerification.UNKNOWN
    semantic_proxy: CompositeVerification = CompositeVerification.UNKNOWN
    cloud_work: CompositeVerification = CompositeVerification.UNKNOWN
    app_access: CompositeVerification = CompositeVerification.UNKNOWN
    app_action: CompositeVerification = CompositeVerification.UNKNOWN
    app_approval: CompositeVerification = CompositeVerification.UNKNOWN
    custom_mcp: CompositeVerification = CompositeVerification.UNKNOWN
    compliance: CompositeVerification = CompositeVerification.UNKNOWN
    codex_local: CompositeVerification = CompositeVerification.UNKNOWN
    codex_remote: CompositeVerification = CompositeVerification.UNKNOWN
    account_identity: CompositeVerification = CompositeVerification.UNKNOWN
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChatGPTCapabilityRow:
    capability: ChatGPTCapability
    level: CapabilityLevel
    verification: CompositeVerification
    control_role: str
    evidence_refs: tuple[str, ...]
    blind_spots: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "level": self.level.value,
            "verification": self.verification.value,
            "control_role": self.control_role,
            "evidence_refs": list(self.evidence_refs),
            "blind_spots": list(self.blind_spots),
        }


@dataclass(frozen=True, slots=True)
class CompositeReconciliation:
    status: CompositeReconciliationStatus
    endpoint_action_id: str | None
    provider_action_id: str | None
    control_role: str = "evidence_only"
    inline_authorization: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "endpoint_action_id": self.endpoint_action_id,
            "provider_action_id": self.provider_action_id,
            "control_role": self.control_role,
            "inline_authorization": self.inline_authorization,
        }


def _floor(floor_id: str, capability: CapabilityDimension) -> MandatoryEnforcementFloorRequirement:
    return MandatoryEnforcementFloorRequirement(
        floor_id=floor_id,
        capability=capability,
        maximum_latency_ms=25,
    )


_FLOORS = {
    "read": _floor("endpoint_file_read", CapabilityDimension.FILE_READ_CONTROL),
    "write": _floor("endpoint_file_write", CapabilityDimension.FILE_WRITE_CONTROL),
    "process": _floor("endpoint_process", CapabilityDimension.PROCESS_EXEC_CONTROL),
    "network": _floor("endpoint_network", CapabilityDimension.NETWORK_CONTROL),
}


_ACTION_FLOORS: dict[ChatGPTAction, tuple[str, ...]] = {
    ChatGPTAction.CHAT_PROMPT: ("network",),
    ChatGPTAction.CHAT_FILE_UPLOAD: ("read", "network"),
    ChatGPTAction.WORK_LOCAL_FILE_READ: ("read",),
    ChatGPTAction.WORK_LOCAL_FILE_WRITE: ("write",),
    ChatGPTAction.WORK_DESKTOP_APP: ("read", "write", "process", "network"),
    ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION: ("network",),
    ChatGPTAction.BUILT_IN_BROWSER_UPLOAD: ("read", "network"),
    ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD: ("write", "network"),
    ChatGPTAction.APP_ACTION: ("network",),
    ChatGPTAction.CUSTOM_MCP_WRITE: ("network",),
    ChatGPTAction.CODEX_LOCAL_SHELL: ("read", "write", "process", "network"),
}


_ACTION_SEMANTIC: dict[ChatGPTAction, tuple[str, ...]] = {
    ChatGPTAction.CHAT_FILE_UPLOAD: ("local_semantic_proxy",),
    ChatGPTAction.WORK_CLOUD_ACTION: ("openai_workspace_controls",),
    ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION: ("local_semantic_proxy",),
    ChatGPTAction.BUILT_IN_BROWSER_UPLOAD: ("local_semantic_proxy",),
    ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD: ("local_semantic_proxy",),
    ChatGPTAction.APP_ACTION: ("openai_app_action_control",),
    ChatGPTAction.CUSTOM_MCP_WRITE: ("hawk_mcp_gateway", "openai_app_action_control"),
    ChatGPTAction.CODEX_LOCAL_SHELL: ("existing_codex_adapter",),
    ChatGPTAction.CODEX_REMOTE_ACTION: ("existing_codex_runtime_control",),
}


_CLOUD_ONLY_ACTIONS = frozenset(
    {ChatGPTAction.WORK_CLOUD_ACTION, ChatGPTAction.CODEX_REMOTE_ACTION}
)


def _combine(*values: CompositeVerification) -> CompositeVerification:
    """Return the weakest mandatory component without inflating coverage."""

    if not values:
        return CompositeVerification.UNKNOWN
    for status in (
        CompositeVerification.UNAVAILABLE,
        CompositeVerification.UNKNOWN,
        CompositeVerification.UNVERIFIED,
        CompositeVerification.EXPERIMENTAL,
        CompositeVerification.PARTIAL,
    ):
        if status in values:
            return status
    return CompositeVerification.VERIFIED


def _level(status: CompositeVerification, *, evidence_only: bool = False) -> CapabilityLevel:
    if evidence_only:
        return CapabilityLevel.OBSERVE if status is not CompositeVerification.UNAVAILABLE else CapabilityLevel.UNAVAILABLE
    return {
        CompositeVerification.VERIFIED: CapabilityLevel.INLINE_BOUND,
        CompositeVerification.PARTIAL: CapabilityLevel.INLINE,
        CompositeVerification.EXPERIMENTAL: CapabilityLevel.EXTERNAL,
        CompositeVerification.UNVERIFIED: CapabilityLevel.UNKNOWN,
        CompositeVerification.UNAVAILABLE: CapabilityLevel.UNAVAILABLE,
        CompositeVerification.UNKNOWN: CapabilityLevel.UNKNOWN,
    }[status]


class ChatGPTDesktopCompositeAdapter:
    """Conservative composition contract for ChatGPT Desktop sub-surfaces."""

    adapter_id = "chatgpt_desktop_composite"
    native_hook_available = False
    control_methods = (
        "endpoint_runtime",
        "network_external",
        "gateway_inline",
        "saas_control_api",
        "observe_only",
        "existing_codex_adapter",
    )

    def resolve_account_context(
        self,
        *,
        claimed: ChatGPTAccountContext,
        source: AccountEvidenceSource,
    ) -> AccountResolution:
        authoritative = source in _AUTHORITATIVE_ACCOUNT_SOURCES
        if not authoritative:
            return AccountResolution(
                account_context=ChatGPTAccountContext.UNKNOWN,
                evidence_source=source,
                authoritative=False,
                reason_codes=("account_evidence_not_authoritative",),
            )
        if claimed is ChatGPTAccountContext.UNKNOWN:
            return AccountResolution(
                account_context=claimed,
                evidence_source=source,
                authoritative=True,
                reason_codes=("account_claim_unknown",),
            )
        return AccountResolution(claimed, source, True, ())

    @staticmethod
    def account_switch(previous: AccountResolution, current: AccountResolution) -> str | None:
        if not previous.authoritative or not current.authoritative:
            return None
        if ChatGPTAccountContext.UNKNOWN in {previous.account_context, current.account_context}:
            return None
        if previous.account_context is current.account_context:
            return None
        return f"{previous.account_context.value}_to_{current.account_context.value}"

    def requirements_for(
        self,
        action: ChatGPTAction,
        context: ChatGPTDesktopContext,
    ) -> ChatGPTControlRequirements:
        semantic = _ACTION_SEMANTIC.get(action, ())
        reasons: list[str] = []
        floor_keys = _ACTION_FLOORS.get(action, ())

        if action in _CLOUD_ONLY_ACTIONS:
            floor_keys = ()
            reasons.append("cloud_execution_does_not_inherit_endpoint_authority")
        elif context.runtime_location is ChatGPTRuntimeLocation.OPENAI_CLOUD:
            floor_keys = ()
            reasons.append("runtime_action_conflict_no_local_authority_claimed")
        elif action is ChatGPTAction.UNKNOWN_ACTION and context.runtime_location is ChatGPTRuntimeLocation.UNKNOWN:
            floor_keys = ()
            reasons.append("runtime_location_unknown")

        floors = tuple(_FLOORS[key] for key in floor_keys)
        if floors:
            assertion = "action_specific_composite"
        elif action in _CLOUD_ONLY_ACTIONS:
            assertion = "cloud_runtime_controls_only"
        else:
            assertion = "unknown"

        provider: tuple[str, ...] = ()
        if action in {ChatGPTAction.APP_ACTION, ChatGPTAction.CUSTOM_MCP_WRITE}:
            provider = ("openai_app_action_control_monotonic_floor",)
        elif action is ChatGPTAction.WORK_CLOUD_ACTION:
            provider = ("openai_workspace_admin_context",)
        elif action is ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION:
            provider = ("openai_website_safety_context_if_supported",)

        evidence = ["endpoint_evidence"] if floors else []
        if action in {
            ChatGPTAction.WORK_CLOUD_ACTION,
            ChatGPTAction.APP_ACTION,
            ChatGPTAction.CUSTOM_MCP_WRITE,
            ChatGPTAction.CODEX_REMOTE_ACTION,
        }:
            evidence.append("openai_compliance_evidence_if_available")
        if action in {ChatGPTAction.CODEX_LOCAL_SHELL, ChatGPTAction.CODEX_REMOTE_ACTION}:
            evidence.append("codex_evidence")
        if action is ChatGPTAction.CUSTOM_MCP_WRITE:
            evidence.append("mcp_execution_evidence")

        return ChatGPTControlRequirements(
            action=action,
            mandatory_enforcement_floors=floors,
            semantic_controls=semantic,
            provider_context=provider,
            evidence_sources=tuple(evidence),
            control_assertion=assertion,
            reason_codes=tuple(reasons),
        )

    @staticmethod
    def effective_decision(
        provider_action_allowed: bool | None,
        hawk_decision: CompositeDecision,
    ) -> CompositeDecision:
        if provider_action_allowed is False:
            return CompositeDecision.DENY
        return hawk_decision

    @staticmethod
    def reconcile(
        *,
        endpoint_action_id: str | None,
        provider_action_id: str | None,
        supported_correlation: bool = False,
    ) -> CompositeReconciliation:
        endpoint = str(endpoint_action_id or "").strip() or None
        provider = str(provider_action_id or "").strip() or None
        if endpoint and provider and endpoint == provider:
            status = CompositeReconciliationStatus.CONFIRMED
        elif endpoint and provider and supported_correlation:
            status = CompositeReconciliationStatus.CORRELATED
        elif endpoint and not provider:
            status = CompositeReconciliationStatus.MISSING_PROVIDER_EVIDENCE
        elif provider and not endpoint:
            status = CompositeReconciliationStatus.MISSING_ENDPOINT_EVIDENCE
        else:
            status = CompositeReconciliationStatus.UNKNOWN
        return CompositeReconciliation(status, endpoint, provider)

    @staticmethod
    def capability_matrix(
        evidence: ChatGPTCompositeEvidence,
    ) -> dict[ChatGPTCapability, ChatGPTCapabilityRow]:
        file_network = _combine(evidence.endpoint_file, evidence.endpoint_network)
        local_desktop = _combine(
            evidence.endpoint_file,
            evidence.endpoint_process,
            evidence.endpoint_network,
        )
        codex_local = _combine(evidence.codex_local, local_desktop)
        values: dict[ChatGPTCapability, tuple[CompositeVerification, str, tuple[str, ...]]] = {
            ChatGPTCapability.CHAT_NETWORK: (evidence.endpoint_network, "endpoint_floor", ()),
            ChatGPTCapability.CHAT_FILE_UPLOAD: (file_network, "endpoint_file_plus_network", ("http_content_semantics_may_be_absent",)),
            ChatGPTCapability.WORK_LOCAL_FILE_READ: (evidence.endpoint_file, "endpoint_file_floor", ()),
            ChatGPTCapability.WORK_LOCAL_FILE_WRITE: (evidence.endpoint_file, "endpoint_file_floor", ()),
            ChatGPTCapability.WORK_DESKTOP_APP: (local_desktop, "endpoint_consequence_floor", ("exact_ui_mutation_semantics_not_claimed",)),
            ChatGPTCapability.WORK_CLOUD: (evidence.cloud_work, "cloud_runtime_control", ("local_endpoint_does_not_authorize_cloud_execution",)),
            ChatGPTCapability.BUILT_IN_BROWSER_NETWORK: (evidence.endpoint_network, "endpoint_network_floor", ()),
            ChatGPTCapability.BUILT_IN_BROWSER_DESTINATION: (evidence.endpoint_network, "endpoint_destination_control", ("dom_gesture_unknown",)),
            ChatGPTCapability.BUILT_IN_BROWSER_HTTP_SEMANTICS: (evidence.semantic_proxy, "legitimate_semantic_proxy", ("tls_or_certificate_pinning_may_limit_semantics",)),
            ChatGPTCapability.BUILT_IN_BROWSER_DOM: (CompositeVerification.UNAVAILABLE, "no_verified_official_interface", ("dom_click_and_form_field_semantics_unavailable",)),
            ChatGPTCapability.BUILT_IN_BROWSER_UPLOAD: (file_network, "endpoint_file_plus_network", ("dom_gesture_unknown",)),
            ChatGPTCapability.BUILT_IN_BROWSER_DOWNLOAD: (file_network, "endpoint_network_plus_file", ("chunk_events_are_correlated_into_one_action",)),
            ChatGPTCapability.APP_ACCESS: (evidence.app_access, "provider_context", ("capability_is_per_app",)),
            ChatGPTCapability.APP_ACTION: (evidence.app_action, "provider_monotonic_floor_plus_hawk_path", ("not_every_provider_app_exposes_action_control",)),
            ChatGPTCapability.APP_APPROVAL: (evidence.app_approval, "provider_context", ("provider_approval_does_not_imply_hawk_inline_authorization",)),
            ChatGPTCapability.CUSTOM_MCP: (evidence.custom_mcp, "hawk_mcp_gateway", ("openai_managed_apps_are_not_forced_through_fake_mcp",)),
            ChatGPTCapability.COMPLIANCE_VISIBILITY: (evidence.compliance, "evidence_only", ("compliance_is_not_inline_control",)),
            ChatGPTCapability.CODEX_LOCAL: (codex_local, "existing_codex_adapter_plus_endpoint_floor", ("does_not_apply_to_remote_codex",)),
            ChatGPTCapability.CODEX_REMOTE: (evidence.codex_remote, "existing_codex_runtime_control", ("does_not_inherit_local_endpoint_authority",)),
            ChatGPTCapability.ACCOUNT_IDENTITY: (evidence.account_identity, "authoritative_identity_context", ("process_email_domain_and_destination_are_not_authoritative",)),
        }
        rows: dict[ChatGPTCapability, ChatGPTCapabilityRow] = {}
        for capability, (verification, role, blind_spots) in values.items():
            rows[capability] = ChatGPTCapabilityRow(
                capability=capability,
                level=_level(verification, evidence_only=role == "evidence_only"),
                verification=verification,
                control_role=role,
                evidence_refs=evidence.evidence_refs,
                blind_spots=blind_spots,
            )
        return rows

    def why_controlled(
        self,
        action: ChatGPTAction,
        context: ChatGPTDesktopContext,
        *,
        semantic_proxy_available: bool,
    ) -> dict[str, str]:
        requirements = self.requirements_for(action, context)
        capabilities = {item.capability for item in requirements.mandatory_enforcement_floors}
        return {
            "action": action.value,
            "semantic_native_hook": "unavailable",
            "mandatory_floor": "hawk_endpoint" if capabilities else "not_applicable_or_unknown",
            "network": (
                "hawk_network_filter"
                if CapabilityDimension.NETWORK_CONTROL in capabilities
                else "not_required"
            ),
            "file": (
                "hawk_file_authorization"
                if capabilities
                & {CapabilityDimension.FILE_READ_CONTROL, CapabilityDimension.FILE_WRITE_CONTROL}
                else "not_required"
            ),
            "process": (
                "hawk_process_authorization"
                if CapabilityDimension.PROCESS_EXEC_CONTROL in capabilities
                else "not_required"
            ),
            "semantic_proxy": "active" if semantic_proxy_available else "absent",
            "why_selected": (
                "No verified ChatGPT-native desktop hook exists; the local action consequence "
                "crosses mandatory Hawk endpoint file, process, or network boundaries."
            ),
        }


def composite_verification_from_native(
    status: VerificationStatus,
) -> CompositeVerification:
    return {
        VerificationStatus.VERIFIED: CompositeVerification.VERIFIED,
        VerificationStatus.EXPERIMENTAL: CompositeVerification.EXPERIMENTAL,
        VerificationStatus.UNVERIFIED: CompositeVerification.UNVERIFIED,
        VerificationStatus.BROKEN: CompositeVerification.UNVERIFIED,
        VerificationStatus.REMOVED: CompositeVerification.UNAVAILABLE,
    }[status]
