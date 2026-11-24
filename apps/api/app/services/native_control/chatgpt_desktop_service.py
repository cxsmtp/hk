"""Tenant-scoped projection and control-plan service for ChatGPT Desktop."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.evidence import EvidenceNode
from app.services.endpoint_agent_service import project_endpoint_floor_status
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
    CompositeVerification,
)
from app.services.native_control.contracts import (
    ControlPointCandidate,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    SelectionContext,
)
from app.services.native_control.endpoint_floor_profiles import endpoint_floor_profiles
from app.services.native_control.openai_adapters import CodexNativeControlAdapter
from app.services.native_control.selector import TrustedControlPointSelector


CHATGPT_EVIDENCE_QUERY_LIMIT = 500
CHATGPT_COMPOSITE_SCHEMA_VERSION = "chatgpt-desktop-composite/1.0"
_RELEVANT_NODE_TYPES = (
    "endpoint_agent_evidence",
    "endpoint_agent_heartbeat",
    "openai_workspace_context",
    "openai_compliance_evidence",
    "native_control_evidence",
    "mcp_execution_evidence",
)
_CONTEXT_SOURCES = frozenset(
    {
        "approved_application_context",
        "openai_admin_api",
        "openai_compliance_api",
        "existing_codex_adapter",
        "hawk_identity_binding",
    }
)
_VERIFICATION_VALUES = {item.value: item for item in CompositeVerification}


def _aware(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=UTC)
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _text(value: object, limit: int = 512) -> str | None:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[:limit] or None


def _payload(node: Any) -> dict[str, Any]:
    value = getattr(node, "payload", {})
    return value if isinstance(value, dict) else {}


def _node_ref(node: Any) -> str | None:
    node_id = _text(getattr(node, "id", None), 64)
    return f"evidence:{node_id}" if node_id else None


def _source_proved(node: Any, payload: dict[str, Any]) -> bool:
    refs = payload.get("evidence_refs")
    return bool(
        payload.get("source_verified") is True
        and isinstance(refs, list)
        and any(isinstance(item, str) and item.strip() for item in refs)
        and getattr(node, "node_type", "")
        in {
            "openai_workspace_context",
            "openai_compliance_evidence",
            "native_control_evidence",
            "mcp_execution_evidence",
        }
    )


def _verification(value: object) -> CompositeVerification:
    return _VERIFICATION_VALUES.get(
        str(value or "").strip().lower(),
        CompositeVerification.UNKNOWN,
    )


def _floor_verification(control: object) -> CompositeVerification:
    if not isinstance(control, dict):
        return CompositeVerification.UNKNOWN
    status = str(control.get("status") or "unknown").lower()
    verification = str(control.get("verification") or "unverified").lower()
    health = str(control.get("health") or "unknown").lower()
    refs = control.get("evidence_refs") if isinstance(control.get("evidence_refs"), list) else []
    if status in {"inline", "inline_bound"} and verification == "verified" and health == "healthy" and refs:
        return CompositeVerification.VERIFIED
    if verification == "experimental":
        return CompositeVerification.EXPERIMENTAL
    if verification == "unverified" or health in {"stale", "degraded", "unhealthy"}:
        return CompositeVerification.UNVERIFIED
    if status == "unavailable":
        return CompositeVerification.UNAVAILABLE
    return CompositeVerification.UNKNOWN


def _safe_installation(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "installed": value.get("installed") is True,
        "bundle_path": _text(value.get("bundle_path")),
        "bundle_id": _text(value.get("bundle_id"), 256),
        "version": _text(value.get("version"), 128),
        "build": _text(value.get("build"), 128),
        "team_id": _text(value.get("team_id"), 128),
        "code_directory_hash": _text(value.get("code_directory_hash"), 128),
        "signature_verified": value.get("signature_verified") is True,
        "hardened_runtime": value.get("hardened_runtime") is True,
        "notarization_verified": value.get("notarization_verified") is True,
    }


def _integer(value: object, *, default: int | None = None) -> int | None:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_process(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_id": _integer(value.get("process_id"), default=0),
        "parent_process_id": (
            _integer(value["parent_process_id"])
            if value.get("parent_process_id") is not None
            else None
        ),
        "process_start_time_ns": (
            _integer(value["process_start_time_ns"])
            if value.get("process_start_time_ns") is not None
            else None
        ),
        "process_name": _text(value.get("process_name"), 128),
        "executable_path": _text(value.get("executable_path")),
        "user": _text(value.get("user"), 256),
        "identity_state": _text(value.get("identity_state"), 128) or "unknown",
    }


def _empty_endpoint_floor(endpoint_id: str) -> dict[str, Any]:
    unknown = {
        "status": "unknown",
        "verification": "unverified",
        "health": "unknown",
        "evidence_refs": [],
    }
    return {
        "endpoint_id": endpoint_id,
        "hostname": endpoint_id,
        "os_type": "unknown",
        "last_seen_at": None,
        "health": "unknown",
        "minimum_floor_satisfied": False,
        "semantic_control_available": False,
        "controls": {
            "file_control": dict(unknown),
            "process_control": dict(unknown),
            "network_control": dict(unknown),
            "semantic_proxy": dict(unknown),
        },
        "local_policy": {
            "status": "unknown",
            "freshness": "unknown",
            "policy_version": None,
            "signature_verified": False,
            "evidence_refs": [],
        },
        "reason_codes": ["endpoint_floor_evidence_missing"],
        "blind_spots": ["endpoint_floor_evidence_missing"],
        "evidence_refs": [],
    }


def _account_resolution(
    nodes: list[Any],
    adapter: ChatGPTDesktopCompositeAdapter,
) -> tuple[dict[str, Any], list[str]]:
    authoritative = []
    for node in sorted(nodes, key=lambda item: (_aware(getattr(item, "created_at", None)), str(getattr(item, "id", "")))):
        payload = _payload(node)
        if payload.get("event_type") != "chatgpt_account_context":
            continue
        if not _source_proved(node, payload):
            continue
        try:
            claimed = ChatGPTAccountContext(str(payload.get("account_context") or "unknown").lower())
        except ValueError:
            claimed = ChatGPTAccountContext.UNKNOWN
        try:
            source = AccountEvidenceSource(str(payload.get("account_evidence_source") or "none").lower())
        except ValueError:
            source = AccountEvidenceSource.NONE
        resolution = adapter.resolve_account_context(claimed=claimed, source=source)
        if resolution.authoritative:
            authoritative.append(resolution)

    if not authoritative:
        unknown = adapter.resolve_account_context(
            claimed=ChatGPTAccountContext.UNKNOWN,
            source=AccountEvidenceSource.NONE,
        )
        return {
            "context": unknown.account_context.value,
            "evidence_source": unknown.evidence_source.value,
            "authoritative": False,
            "multiple_workspaces_observed": False,
            "switch": None,
            "reason_codes": list(unknown.reason_codes),
        }, []

    latest = authoritative[-1]
    contexts = {row.account_context for row in authoritative if row.account_context is not ChatGPTAccountContext.UNKNOWN}
    switch = None
    for previous, current in zip(authoritative, authoritative[1:]):
        candidate = adapter.account_switch(previous, current)
        if candidate:
            switch = candidate
    reason_codes = []
    if len(contexts) > 1:
        reason_codes.append("multiple_workspaces_observed")
    if switch:
        reason_codes.append("supported_account_switch_observed")
    return {
        "context": latest.account_context.value,
        "evidence_source": latest.evidence_source.value,
        "authoritative": True,
        "multiple_workspaces_observed": len(contexts) > 1,
        "switch": switch,
        "reason_codes": reason_codes,
    }, [row.account_context.value for row in authoritative]


def _mode_context(nodes: list[Any]) -> tuple[list[str], str]:
    observations: list[tuple[datetime, ChatGPTDesktopMode, ChatGPTRuntimeLocation]] = []
    for node in nodes:
        payload = _payload(node)
        if payload.get("event_type") != "chatgpt_mode_context":
            continue
        source = str(payload.get("context_evidence_source") or "").strip().lower()
        if source not in _CONTEXT_SOURCES:
            continue
        try:
            mode = ChatGPTDesktopMode(str(payload.get("mode") or "").strip().lower())
            runtime = ChatGPTRuntimeLocation(str(payload.get("runtime_location") or "unknown").strip().lower())
        except ValueError:
            continue
        observations.append((_aware(getattr(node, "created_at", None)), mode, runtime))
    if not observations:
        return [], ChatGPTRuntimeLocation.UNKNOWN.value
    observations.sort(key=lambda row: row[0])
    modes = sorted({row[1].value for row in observations})
    return modes, observations[-1][2].value


def _context_verification(
    nodes: list[Any],
    event_type: str,
    field: str,
    *,
    required_control_path: str | None = None,
) -> CompositeVerification:
    for node in sorted(nodes, key=lambda item: _aware(getattr(item, "created_at", None)), reverse=True):
        payload = _payload(node)
        if payload.get("event_type") != event_type:
            continue
        if not _source_proved(node, payload):
            continue
        source = str(payload.get("evidence_source") or payload.get("context_evidence_source") or "").lower()
        if source not in _CONTEXT_SOURCES:
            continue
        if required_control_path and str(payload.get("control_path") or "").lower() != required_control_path:
            continue
        resolved = _verification(payload.get(field))
        if resolved is CompositeVerification.VERIFIED and not any(
            _text(payload.get(name), 256)
            for name in (
                "verification_receipt_id",
                "validation_receipt_id",
                "decision_receipt_id",
                "provider_configuration_id",
            )
        ):
            return CompositeVerification.UNVERIFIED
        return resolved
    return CompositeVerification.UNKNOWN


def _reconciliation(nodes: list[Any], adapter: ChatGPTDesktopCompositeAdapter) -> dict[str, Any]:
    endpoint_events: dict[str, tuple[str | None, Any]] = {}
    provider_events: dict[str, tuple[str | None, Any]] = {}
    for node in nodes:
        payload = _payload(node)
        correlation = _text(payload.get("correlation_id"), 64)
        if not correlation:
            continue
        if payload.get("event_type") == "chatgpt_endpoint_action":
            endpoint_events[correlation] = (_text(payload.get("endpoint_action_id"), 128), node)
        elif (
            payload.get("event_type") == "chatgpt_compliance_event"
            and _source_proved(node, payload)
            and _text(payload.get("provider_event_id"), 256)
        ):
            provider_events[correlation] = (_text(payload.get("provider_action_id"), 128), node)
    keys = sorted(set(endpoint_events) | set(provider_events))
    rows = []
    for correlation in keys[-50:]:
        endpoint = endpoint_events.get(correlation)
        provider = provider_events.get(correlation)
        result = adapter.reconcile(
            endpoint_action_id=endpoint[0] if endpoint else None,
            provider_action_id=provider[0] if provider else None,
            supported_correlation=bool(endpoint and provider),
        )
        rows.append({"correlation_id": correlation, **result.as_dict()})
    return {
        "control_role": "evidence_only",
        "inline_authorization": False,
        "items": rows,
        "summary": dict(Counter(row["status"] for row in rows)),
    }


def _capability_evidence(
    nodes: list[Any],
    endpoint_floor: dict[str, Any],
    account: dict[str, Any],
    modes: list[str],
) -> ChatGPTCompositeEvidence:
    controls = endpoint_floor.get("controls") if isinstance(endpoint_floor.get("controls"), dict) else {}
    refs = sorted(
        {
            ref
            for node in nodes
            for ref in (_node_ref(node),)
            if ref
        }
        | {
            str(ref)[:256]
            for ref in endpoint_floor.get("evidence_refs") or []
            if isinstance(ref, str)
        }
    )[:64]
    compliance = (
        CompositeVerification.VERIFIED
        if any(
            _payload(node).get("event_type") == "chatgpt_compliance_event"
            and _source_proved(node, _payload(node))
            and _text(_payload(node).get("provider_event_id"), 256)
            for node in nodes
        )
        else CompositeVerification.UNKNOWN
    )
    codex_status = CodexNativeControlAdapter.manifest.verification_status.value
    codex_local_observed = bool(
        ChatGPTDesktopMode.CODEX_LOCAL.value in modes
        or any(
            _payload(node).get("event_type") == "chatgpt_codex_context"
            and _source_proved(node, _payload(node))
            for node in nodes
        )
    )
    return ChatGPTCompositeEvidence(
        endpoint_file=_floor_verification(controls.get("file_control")),
        endpoint_process=_floor_verification(controls.get("process_control")),
        endpoint_network=_floor_verification(controls.get("network_control")),
        semantic_proxy=_floor_verification(controls.get("semantic_proxy")),
        cloud_work=_context_verification(nodes, "chatgpt_cloud_control_context", "verification"),
        app_access=_context_verification(nodes, "chatgpt_app_context", "app_access_verification"),
        app_action=_context_verification(nodes, "chatgpt_app_context", "app_action_verification"),
        app_approval=_context_verification(nodes, "chatgpt_app_context", "app_approval_verification"),
        custom_mcp=_context_verification(
            nodes,
            "chatgpt_mcp_context",
            "verification",
            required_control_path="hawk_mcp_gateway",
        ),
        compliance=compliance,
        codex_local=(
            _verification(codex_status)
            if codex_local_observed
            else CompositeVerification.UNKNOWN
        ),
        codex_remote=_context_verification(nodes, "chatgpt_codex_remote_context", "verification"),
        account_identity=(
            CompositeVerification.VERIFIED
            if account.get("authoritative") is True
            else CompositeVerification.UNKNOWN
        ),
        evidence_refs=tuple(refs),
    )


def _blind_spots(
    *,
    endpoint_floor: dict[str, Any],
    installation: dict[str, Any],
    observed_versions: set[str],
    account: dict[str, Any],
    modes: list[str],
    runtime: str,
    evidence: ChatGPTCompositeEvidence,
) -> list[str]:
    values = {
        "chatgpt_desktop_native_hook_unavailable",
        "built_in_browser_dom_and_form_semantics_unavailable",
        *(
            str(item)[:256]
            for item in endpoint_floor.get("blind_spots") or []
            if isinstance(item, str) and item.strip()
        ),
    }
    if not account.get("authoritative"):
        values.add("account_workspace_unknown")
    if account.get("context") == ChatGPTAccountContext.PERSONAL.value:
        values.add("personal_workspace_provider_controls_not_proven")
    if (
        installation.get("bundle_id") != "com.openai.codex"
        or installation.get("signature_verified") is not True
    ):
        values.add("alternate_or_unverified_chatgpt_installation")
    if (
        installation.get("signature_verified") is not True
        or installation.get("notarization_verified") is not True
    ):
        values.add("chatgpt_signature_or_notarization_unverified")
    if len(observed_versions) > 1:
        values.add("chatgpt_binary_version_change_observed_revalidation_required")
    if runtime == ChatGPTRuntimeLocation.UNKNOWN.value:
        values.add("local_vs_cloud_runtime_unknown")
    if ChatGPTDesktopMode.BUILT_IN_BROWSER.value not in modes:
        values.add("built_in_browser_not_observed")
    elif evidence.endpoint_network is not CompositeVerification.VERIFIED:
        values.add("built_in_browser_traffic_attribution_unverified")
        values.add("ordinary_transport_and_quic_bypass_acceptance_pending")
    if (
        ChatGPTDesktopMode.BUILT_IN_BROWSER.value in modes
        and evidence.semantic_proxy is not CompositeVerification.VERIFIED
    ):
        values.add("local_semantic_proxy_bypass_detection_unverified")
    if ChatGPTDesktopMode.CODEX_REMOTE.value in modes:
        values.add("codex_remote_transition_separate_runtime")
    if evidence.compliance is CompositeVerification.UNKNOWN:
        values.add("openai_compliance_evidence_unavailable_or_not_configured")
    if evidence.cloud_work is CompositeVerification.UNKNOWN:
        values.add("cloud_work_authorization_unknown")
    return sorted(values)


def project_chatgpt_desktop_assets(
    nodes: Iterable[Any],
    *,
    now: datetime | None = None,
    heartbeat_ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Project supported observations; never trust an aggregate protection claim."""

    observed_now = _aware(now or datetime.now(UTC))
    rows = sorted(
        list(nodes),
        key=lambda item: (_aware(getattr(item, "created_at", None)), str(getattr(item, "id", ""))),
        reverse=True,
    )[:CHATGPT_EVIDENCE_QUERY_LIMIT]
    adapter = ChatGPTDesktopCompositeAdapter()
    floor_projection = project_endpoint_floor_status(
        [row for row in rows if getattr(row, "node_type", "") == "endpoint_agent_heartbeat"],
        now=observed_now,
        heartbeat_ttl_seconds=heartbeat_ttl_seconds,
    )
    floors = {row["endpoint_id"]: row for row in floor_projection["endpoints"]}

    latest_observations: dict[str, Any] = {}
    for node in sorted(
        rows,
        key=lambda item: (_aware(getattr(item, "created_at", None)), str(getattr(item, "id", ""))),
        reverse=True,
    ):
        payload = _payload(node)
        endpoint_id = _text(payload.get("endpoint_id"), 128)
        if (
            endpoint_id
            and payload.get("event_type") == "chatgpt_desktop_observation"
            and isinstance(payload.get("chatgpt_desktop"), dict)
            and endpoint_id not in latest_observations
        ):
            latest_observations[endpoint_id] = node

    assets: list[dict[str, Any]] = []
    for endpoint_id, observation_node in sorted(latest_observations.items()):
        observation = _payload(observation_node).get("chatgpt_desktop")
        observation = observation if isinstance(observation, dict) else {}
        endpoint_nodes = [
            node for node in rows if _text(_payload(node).get("endpoint_id"), 128) == endpoint_id
        ]
        endpoint_floor = floors.get(endpoint_id, _empty_endpoint_floor(endpoint_id))
        account, account_history = _account_resolution(endpoint_nodes, adapter)
        modes, runtime = _mode_context(endpoint_nodes)
        evidence = _capability_evidence(endpoint_nodes, endpoint_floor, account, modes)
        installation = _safe_installation(observation)
        observed_versions = {
            version
            for node in endpoint_nodes
            if _payload(node).get("event_type") == "chatgpt_desktop_observation"
            and isinstance(_payload(node).get("chatgpt_desktop"), dict)
            and (
                version := _text(
                    _payload(node)["chatgpt_desktop"].get("version"),
                    128,
                )
            )
        }
        matrix = adapter.capability_matrix(evidence)
        capability_rows = [matrix[item].as_dict() for item in ChatGPTCapability]
        counts = Counter(row["verification"] for row in capability_rows)
        verified = counts.get(CompositeVerification.VERIFIED.value, 0)
        blind_spots = _blind_spots(
            endpoint_floor=endpoint_floor,
            installation=installation,
            observed_versions=observed_versions,
            account=account,
            modes=modes,
            runtime=runtime,
            evidence=evidence,
        )
        assets.append(
            {
                "asset_id": f"chatgpt-desktop:{endpoint_id}",
                "asset_type": "chatgpt_desktop_composite",
                "display_name": "ChatGPT Desktop",
                "endpoint_id": endpoint_id,
                "last_observed_at": _aware(getattr(observation_node, "created_at", None)).isoformat(),
                "installation": installation,
                "process": _safe_process(observation),
                "native_hook_available": False,
                "account": account,
                "account_history": account_history[-20:],
                "modes_observed": modes,
                "runtime_location": runtime,
                "built_in_browser": {
                    "sub_surface": "chatgpt_built_in_browser",
                    "observed": ChatGPTDesktopMode.BUILT_IN_BROWSER.value in modes,
                    "inherits_chrome_extension_coverage": False,
                    "dom_control": "unavailable",
                    "form_field_semantics": "unavailable",
                },
                "endpoint_floor": endpoint_floor,
                "capabilities": capability_rows,
                "control_coverage": {
                    "methodology": "unweighted count of 20 independently evidenced ChatGPT sub-surface dimensions",
                    "total_dimensions": len(capability_rows),
                    "verified_dimensions": verified,
                    "verified_percent": round((verified / len(capability_rows)) * 100, 1),
                    "counts": dict(sorted(counts.items())),
                    "inflation_guard": "unknown, unavailable, experimental, partial, and unverified are not counted as verified",
                },
                "compliance_reconciliation": _reconciliation(endpoint_nodes, adapter),
                "why_controlled": {
                    action.value: adapter.why_controlled(
                        action,
                        _default_context_for_action(action, account),
                        semantic_proxy_available=endpoint_floor.get("semantic_control_available") is True,
                    )
                    for action in (
                        ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION,
                        ChatGPTAction.BUILT_IN_BROWSER_UPLOAD,
                        ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD,
                    )
                },
                "blind_spots": blind_spots,
                "evidence_refs": list(evidence.evidence_refs),
            }
        )
    return {
        "schema_version": CHATGPT_COMPOSITE_SCHEMA_VERSION,
        "source": "server_projected_evidence",
        "generated_at": observed_now.isoformat(),
        "total": len(assets),
        "items": assets,
        "empty_state": (
            None
            if assets
            else {
                "status": "not_observed",
                "message": "No supported ChatGPT Desktop endpoint observation exists for this tenant.",
            }
        ),
    }


def get_chatgpt_desktop_assets(
    db: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    nodes = list(
        db.scalars(
            select(EvidenceNode)
            .where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.node_type.in_(_RELEVANT_NODE_TYPES),
            )
            .order_by(EvidenceNode.created_at.desc(), EvidenceNode.id.desc())
            .limit(CHATGPT_EVIDENCE_QUERY_LIMIT)
        ).all()
    )
    return project_chatgpt_desktop_assets(nodes, now=now)


_ACTION_CONTEXT: dict[ChatGPTAction, tuple[ChatGPTDesktopMode, ChatGPTRuntimeLocation]] = {
    ChatGPTAction.CHAT_PROMPT: (ChatGPTDesktopMode.CHAT, ChatGPTRuntimeLocation.MIXED),
    ChatGPTAction.CHAT_FILE_UPLOAD: (ChatGPTDesktopMode.CHAT, ChatGPTRuntimeLocation.MIXED),
    ChatGPTAction.WORK_LOCAL_FILE_READ: (ChatGPTDesktopMode.WORK_LOCAL, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.WORK_LOCAL_FILE_WRITE: (ChatGPTDesktopMode.WORK_LOCAL, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.WORK_DESKTOP_APP: (ChatGPTDesktopMode.WORK_LOCAL, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.WORK_CLOUD_ACTION: (ChatGPTDesktopMode.WORK_CLOUD, ChatGPTRuntimeLocation.OPENAI_CLOUD),
    ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION: (ChatGPTDesktopMode.BUILT_IN_BROWSER, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.BUILT_IN_BROWSER_UPLOAD: (ChatGPTDesktopMode.BUILT_IN_BROWSER, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD: (ChatGPTDesktopMode.BUILT_IN_BROWSER, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.APP_ACTION: (ChatGPTDesktopMode.APP_ACTION, ChatGPTRuntimeLocation.MIXED),
    ChatGPTAction.CUSTOM_MCP_WRITE: (ChatGPTDesktopMode.MCP_ACTION, ChatGPTRuntimeLocation.MIXED),
    ChatGPTAction.CODEX_LOCAL_SHELL: (ChatGPTDesktopMode.CODEX_LOCAL, ChatGPTRuntimeLocation.LOCAL_ENDPOINT),
    ChatGPTAction.CODEX_REMOTE_ACTION: (ChatGPTDesktopMode.CODEX_REMOTE, ChatGPTRuntimeLocation.OPENAI_CLOUD),
}


def _default_context_for_action(action: ChatGPTAction, account: dict[str, Any]) -> ChatGPTDesktopContext:
    mode, runtime = _ACTION_CONTEXT.get(
        action,
        (ChatGPTDesktopMode.UNKNOWN_DESKTOP_MODE, ChatGPTRuntimeLocation.UNKNOWN),
    )
    try:
        account_context = ChatGPTAccountContext(str(account.get("context") or "unknown"))
    except ValueError:
        account_context = ChatGPTAccountContext.UNKNOWN
    try:
        source = AccountEvidenceSource(str(account.get("evidence_source") or "none"))
    except ValueError:
        source = AccountEvidenceSource.NONE
    return ChatGPTDesktopContext(mode, runtime, account_context, source)


def _endpoint_floor_candidates(
    asset: dict[str, Any],
    *,
    tenant_id: str,
) -> list[ControlPointCandidate]:
    endpoint_floor = asset["endpoint_floor"]
    controls = endpoint_floor.get("controls") if isinstance(endpoint_floor.get("controls"), dict) else {}
    os_type = str(endpoint_floor.get("os_type") or "").lower()
    family = "windows" if os_type.startswith("win") else "macos"
    control_for_product = {
        f"{family}_endpoint_file": "file_control",
        f"{family}_endpoint_process": "process_control",
        f"{family}_endpoint_network": "network_control",
        f"{family}_semantic_proxy": "semantic_proxy",
    }
    local_policy = endpoint_floor.get("local_policy") if isinstance(endpoint_floor.get("local_policy"), dict) else {}
    policy_fresh = bool(
        local_policy.get("status") == "active"
        and local_policy.get("freshness") == "fresh"
        and local_policy.get("signature_verified") is True
        and local_policy.get("evidence_refs")
    )
    policy_version = str(local_policy.get("policy_version") or "unknown")[:128]
    candidates = []
    for profile in endpoint_floor_profiles():
        control_name = control_for_product.get(profile.product)
        if control_name is None:
            continue
        control = controls.get(control_name) if isinstance(controls, dict) else None
        control = control if isinstance(control, dict) else {}
        control_health = str(control.get("health") or "unknown")
        health_state = (
            HealthState.HEALTHY
            if control_health == "healthy"
            else HealthState.DEGRADED
            if control_health in {"degraded", "unhealthy", "stale"}
            else HealthState.UNVERIFIED
        )
        evidence_flowing = bool(control.get("evidence_refs"))
        validation_current = control.get("verification") == "verified"
        latency = control.get("observed_latency_ms")
        observed_latency_ms = int(latency) if isinstance(latency, (int, float)) else 60_000
        candidates.append(
            ControlPointCandidate(
                control_point_id=f"endpoint-floor:{asset['endpoint_id']}:{control_name}",
                integration_instance_id=f"endpoint-floor:{asset['endpoint_id']}",
                tenant_id=tenant_id,
                profile=profile,
                health=ControlPointHealth(
                    state=health_state,
                    callback_authenticated=evidence_flowing,
                    validation_current=validation_current,
                    evidence_flowing=evidence_flowing,
                    configuration_integrity_valid=policy_fresh,
                    policy_fresh=policy_fresh,
                    observed_latency_ms=observed_latency_ms,
                    reason_codes=tuple(str(item) for item in endpoint_floor.get("reason_codes") or []),
                ),
                provider_version=str(asset["installation"].get("version") or "unknown")[:64],
                adapter_version=profile.adapter_version,
                policy_version=policy_version,
                policy_binding_mode="signed_local_policy",
                tenant_binding_valid=True,
                exposed_lifecycle_events=("before_os_consequence", "after_os_consequence"),
                visible_action_fields=("process", "resource", "destination", "result"),
                blocking_semantics=bool(
                    control.get("status") in {"inline", "inline_bound"}
                    and control.get("verification") == "verified"
                ),
                current_degradation_mode=(
                    DegradationMode.LOCAL_POLICY_ONLY if policy_fresh else DegradationMode.FAIL_CLOSED
                ),
                response_coverage="endpoint_consequence",
            )
        )
    return candidates


def _semantic_selection(
    action: ChatGPTAction,
    asset: dict[str, Any],
) -> tuple[str | None, bool]:
    rows = {row["capability"]: row for row in asset["capabilities"]}

    def verified(capability: ChatGPTCapability) -> bool:
        return rows.get(capability.value, {}).get("verification") == "verified"

    if action is ChatGPTAction.CUSTOM_MCP_WRITE:
        return ("hawk_mcp_gateway", True) if verified(ChatGPTCapability.CUSTOM_MCP) else (None, True)
    if action is ChatGPTAction.APP_ACTION:
        return ("openai_app_action_control", True) if verified(ChatGPTCapability.APP_ACTION) else (None, True)
    if action is ChatGPTAction.WORK_CLOUD_ACTION:
        return ("openai_workspace_controls", True) if verified(ChatGPTCapability.WORK_CLOUD) else (None, True)
    if action is ChatGPTAction.CODEX_LOCAL_SHELL:
        return ("existing_codex_adapter", True) if verified(ChatGPTCapability.CODEX_LOCAL) else (None, True)
    if action is ChatGPTAction.CODEX_REMOTE_ACTION:
        return ("existing_codex_runtime_control", True) if verified(ChatGPTCapability.CODEX_REMOTE) else (None, True)
    # The semantic proxy is defense in depth for local browser/file consequences,
    # not a substitute for or mandatory prerequisite to the Endpoint Floor.
    if action in {
        ChatGPTAction.CHAT_FILE_UPLOAD,
        ChatGPTAction.BUILT_IN_BROWSER_NAVIGATION,
        ChatGPTAction.BUILT_IN_BROWSER_UPLOAD,
        ChatGPTAction.BUILT_IN_BROWSER_DOWNLOAD,
    } and verified(ChatGPTCapability.BUILT_IN_BROWSER_HTTP_SEMANTICS):
        return "local_semantic_proxy", False
    return None, False


def resolve_chatgpt_desktop_control_plan(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    action: ChatGPTAction,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    projection = get_chatgpt_desktop_assets(db, tenant_id=tenant_id, now=now)
    asset = next((row for row in projection["items"] if row["endpoint_id"] == endpoint_id), None)
    if asset is None:
        return None
    adapter = ChatGPTDesktopCompositeAdapter()
    context = _default_context_for_action(action, asset["account"])
    requirements = adapter.requirements_for(action, context)
    local_policy = asset["endpoint_floor"].get("local_policy") or {}
    policy_version = str(local_policy.get("policy_version") or "unknown")[:128]
    observed_now = _aware(now or datetime.now(UTC))
    selector_result = TrustedControlPointSelector().resolve_control_plan(
        SelectionContext(
            tenant_id=tenant_id,
            action_id=f"chatgpt-desktop:{endpoint_id}:{action.value}",
            policy_version=policy_version,
            matrix_version=CHATGPT_COMPOSITE_SCHEMA_VERSION,
            provider="openai",
            product="chatgpt_desktop_composite",
            provider_version=str(asset["installation"].get("version") or "unknown")[:64],
            adapter_version="1.0.0",
            route_binding_source="authenticated_endpoint_evidence",
            allowed_control_methods=("endpoint_runtime",),
            required_lifecycle_event="before_os_consequence",
            current_bypass_state=("unknown" if asset["blind_spots"] else "none_detected"),
            policy_fresh=bool(local_policy.get("freshness") == "fresh"),
            evaluated_at=observed_now.isoformat(),
        ),
        None,
        requirements.mandatory_enforcement_floors,
        _endpoint_floor_candidates(asset, tenant_id=tenant_id),
    ).as_dict()
    semantic_primary, semantic_required = _semantic_selection(action, asset)
    selector_result["semantic_primary_control"] = semantic_primary
    if semantic_required and semantic_primary is None:
        selector_result["control_requirement_unsatisfied"] = True
        selector_result["reason_codes"] = [
            *selector_result["reason_codes"],
            "CONTROL_REQUIREMENT_UNSATISFIED:semantic",
        ]
        selector_result["coverage_implications"]["semantic"] = "not_covered"
        selector_result["coverage_implications"]["authorization"] = "not_covered"
    elif semantic_primary:
        selector_result["coverage_implications"]["semantic"] = "covered"
    selector_result["semantic_controls_required"] = list(requirements.semantic_controls)
    return {
        "schema_version": CHATGPT_COMPOSITE_SCHEMA_VERSION,
        "source": "server_projected_evidence",
        "asset_id": asset["asset_id"],
        "endpoint_id": endpoint_id,
        "native_hook_available": False,
        "context": context.as_dict(),
        "requirements": requirements.as_dict(),
        "selection": selector_result,
        "why_controlled": adapter.why_controlled(
            action,
            context,
            semantic_proxy_available=asset["endpoint_floor"].get("semantic_control_available") is True,
        ),
        "blind_spots": asset["blind_spots"],
        "evidence_refs": asset["evidence_refs"],
    }
