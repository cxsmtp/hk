from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent as RuntimeEventRow
from app.db.models.runtime_intelligence import RuntimeGovernanceRecommendation
from app.db.models.runtime_intelligence import RuntimePattern
from app.services.runtime_intelligence.decision_impact_scoring import score_runtime_recommendation_impact
from app.services.runtime_intelligence.schemas import CorrelatedFindingCandidate, GovernanceRecommendation


RUNTIME_FINDING_TYPES = {
    "repeated_prompt_injection_attempts",
    "repeated_tool_denials",
    "unknown_ai_adoption_spike",
    "asymmetry_risk_spike",
    "repeated_sensitive_data_attempts",
    "multi_tool_data_exposure",
    "unusual_tool_sequences",
    "abnormal_agent_chains",
    "justification_trend_risk",
    "AI_SUPPLY_CHAIN_ATTACK",
    "AGENT_OVER_SCOPE_RISK",
    "AGENT_SESSION_ANOMALY",
}

_PLACEHOLDER_TOOL_VALUES = {
    "",
    "unknown",
    "unknown_tool",
    "browser_extension",
    "extension_health_status",
    "extension_status",
    "localhost",
    "127.0.0.1",
    "extension.local",
}
_LOCAL_DOMAINS = {"localhost", "127.0.0.1", "::1", "extension.local"}


def _metadata_dict(event: RuntimeEventRow) -> dict[str, Any]:
    return dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}


def _metadata_list(event: RuntimeEventRow, key: str) -> list[str]:
    meta = _metadata_dict(event)
    raw = meta.get(key)
    if isinstance(raw, list):
        return [str(item).strip().lower() for item in raw if str(item).strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip().lower()]
    return []


def _scope_match(left: RuntimeEventRow, right: RuntimeEventRow) -> bool:
    if left.ai_system_id and right.ai_system_id:
        return left.ai_system_id == right.ai_system_id
    if left.user_id and right.user_id:
        return left.user_id == right.user_id
    if left.app_id and right.app_id:
        return left.app_id == right.app_id
    return True


def _is_local_like_value(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return (
        text in _LOCAL_DOMAINS
        or text.startswith("http://localhost")
        or text.startswith("https://localhost")
        or text.startswith("http://127.0.0.1")
        or text.startswith("https://127.0.0.1")
        or text.startswith("chrome-extension://")
    )


def _is_operational_or_placeholder_event(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    event_type = str(event.event_type or meta.get("event_type") or "").strip().lower()
    if event_type in {"extension_health_status", "extension_status", "policy_sync_status", "telemetry_health"}:
        return True
    if any(bool(meta.get(flag)) for flag in ("operational_telemetry", "suppress_anomaly_detection", "suppress_ai_discovery")):
        return True

    source_surface = str(event.source_surface or meta.get("source_surface") or "").strip().lower()
    if source_surface not in {"browser", "browser_extension"}:
        return False

    tool_values = {
        str(meta.get("tool_name") or "").strip().lower(),
        str(meta.get("ai_tool") or "").strip().lower(),
        str(event.app_id or "").strip().lower(),
    }
    domain_values = [
        meta.get("domain"),
        meta.get("current_domain"),
        meta.get("api_endpoint"),
        meta.get("url"),
        meta.get("current_url"),
        meta.get("target_resource"),
    ]
    has_placeholder_tool = bool(tool_values.intersection(_PLACEHOLDER_TOOL_VALUES))
    has_local_domain = any(_is_local_like_value(value) for value in domain_values)
    return has_placeholder_tool and has_local_domain and not event.ai_system_id


def _window_start() -> datetime:
    minutes = max(5, int(settings.runtime_intelligence_correlation_window_minutes))
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _long_window_start() -> datetime:
    days = max(7, int(getattr(settings, "runtime_recommendation_long_window_days", 30)))
    return datetime.now(timezone.utc) - timedelta(days=days)


def _repeat_threshold() -> int:
    return max(2, int(settings.runtime_intelligence_repeat_threshold))


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "medium":
        return "med"
    if normalized not in {"low", "med", "high", "critical"}:
        return "low"
    return normalized


def _severity_rank(value: str | None) -> int:
    return {"low": 1, "med": 2, "high": 3, "critical": 4}.get(_normalize_severity(value), 1)


def _cross_session_snapshot(
    *,
    db: Session,
    event: RuntimeEventRow,
    candidate: CorrelatedFindingCandidate,
    pattern: RuntimePattern | None,
) -> dict[str, Any]:
    since = _long_window_start()
    recommendation_rows = db.scalars(
        select(RuntimeGovernanceRecommendation).where(
            RuntimeGovernanceRecommendation.tenant_id == event.tenant_id,
            RuntimeGovernanceRecommendation.reason_code == candidate.reason_code,
            RuntimeGovernanceRecommendation.created_at >= since,
        )
    ).all()

    filtered_rows = recommendation_rows
    if event.ai_system_id:
        scoped_rows = [row for row in recommendation_rows if str(row.ai_system_id or "").strip() == str(event.ai_system_id)]
        if scoped_rows:
            filtered_rows = scoped_rows

    frequency = max(
        int(candidate.repeated_count or 1),
        int(pattern.frequency or 0) if pattern is not None else 0,
        len(filtered_rows),
    )
    threshold = _repeat_threshold()
    escalation_level = 0
    if frequency >= threshold * 2:
        escalation_level = 1
    if frequency >= threshold * 4:
        escalation_level = 2

    return {
        "lookback_days": max(7, int(getattr(settings, "runtime_recommendation_long_window_days", 30))),
        "recent_recommendation_count": len(filtered_rows),
        "pattern_frequency": frequency,
        "escalation_level": escalation_level,
        "is_long_term_pattern": frequency >= threshold * 2,
    }


def _feedback_loop_metrics(
    *,
    db: Session,
    event: RuntimeEventRow,
    candidate: CorrelatedFindingCandidate,
) -> dict[str, Any]:
    since = _long_window_start()
    recommendation_rows = db.scalars(
        select(RuntimeGovernanceRecommendation).where(
            RuntimeGovernanceRecommendation.tenant_id == event.tenant_id,
            RuntimeGovernanceRecommendation.reason_code == candidate.reason_code,
            RuntimeGovernanceRecommendation.created_at >= since,
        )
    ).all()
    recommendation_ids = [str(row.recommendation_id) for row in recommendation_rows if str(row.recommendation_id or "").strip()]
    if not recommendation_ids:
        return {
            "sample_size": 0,
            "applied_count": 0,
            "failed_count": 0,
            "rolled_back_count": 0,
            "rejected_count": 0,
            "false_positive_rate": 0.0,
            "effectiveness_rate": 0.0,
        }

    remediation_rows = db.scalars(
        select(RemediationAction).where(
            RemediationAction.tenant_id == event.tenant_id,
            RemediationAction.source_trigger_type == "runtime_pattern",
            RemediationAction.source_trigger_id.in_(recommendation_ids),
            RemediationAction.created_at >= since,
        )
    ).all()
    total = len(remediation_rows)
    if total == 0:
        return {
            "sample_size": 0,
            "applied_count": 0,
            "failed_count": 0,
            "rolled_back_count": 0,
            "rejected_count": 0,
            "false_positive_rate": 0.0,
            "effectiveness_rate": 0.0,
        }

    applied = sum(1 for row in remediation_rows if str(row.status or "").lower() == "applied")
    failed = sum(1 for row in remediation_rows if str(row.status or "").lower() == "failed")
    rolled_back = sum(1 for row in remediation_rows if str(row.status or "").lower() == "rolled_back")
    rejected = sum(1 for row in remediation_rows if str(row.status or "").lower() == "rejected")

    false_positive_rate = round((rolled_back + rejected) / total, 4) if total else 0.0
    effectiveness_rate = round(applied / total, 4) if total else 0.0
    return {
        "sample_size": total,
        "applied_count": applied,
        "failed_count": failed,
        "rolled_back_count": rolled_back,
        "rejected_count": rejected,
        "false_positive_rate": false_positive_rate,
        "effectiveness_rate": effectiveness_rate,
    }


def _confidence_score(
    *,
    event: RuntimeEventRow,
    candidate: CorrelatedFindingCandidate,
    risk_score: int,
    cross_session: dict[str, Any],
) -> tuple[float, list[str]]:
    threshold = _repeat_threshold()
    score = 0.25
    reasoning: list[str] = ["base_signal=0.25"]

    repeated_count = int(candidate.repeated_count or 1)
    if repeated_count >= threshold:
        score += 0.20
        reasoning.append(f"repeat_count={repeated_count}")
    if repeated_count >= threshold + 2:
        score += 0.10
        reasoning.append("repeat_count_extended")

    pattern_frequency = int(cross_session.get("pattern_frequency") or repeated_count)
    if pattern_frequency >= threshold * 2:
        score += 0.15
        reasoning.append(f"cross_session_frequency={pattern_frequency}")
    if int(cross_session.get("escalation_level") or 0) >= 1:
        score += 0.05
        reasoning.append(f"cross_session_escalation={int(cross_session.get('escalation_level') or 0)}")

    if _severity_rank(candidate.severity) >= 3:
        score += 0.10
        reasoning.append(f"severity={_normalize_severity(candidate.severity)}")
    if int(risk_score or 0) >= 70:
        score += 0.10
        reasoning.append(f"risk_score={int(risk_score)}")

    if event.user_id or event.agent_id:
        score += 0.05
        reasoning.append("attribution_quality=high")
    if len([str(item).strip() for item in (event.evidence_node_ids or []) if str(item).strip()]) >= 1:
        score += 0.05
        reasoning.append("evidence_present=true")

    feedback_false_positive_rate = float(cross_session.get("feedback_false_positive_rate") or 0.0)
    if feedback_false_positive_rate >= 0.5:
        score -= 0.10
        reasoning.append(f"false_positive_rate={feedback_false_positive_rate}")
    elif feedback_false_positive_rate >= 0.3:
        score -= 0.05
        reasoning.append(f"false_positive_rate={feedback_false_positive_rate}")

    feedback_effectiveness_rate = float(cross_session.get("feedback_effectiveness_rate") or 0.0)
    feedback_sample_size = int(cross_session.get("feedback_sample_size") or 0)
    if feedback_sample_size >= 3 and feedback_effectiveness_rate >= 0.7:
        score += 0.05
        reasoning.append(f"effectiveness_rate={feedback_effectiveness_rate}")
    elif feedback_sample_size >= 3 and feedback_effectiveness_rate <= 0.3:
        score -= 0.05
        reasoning.append(f"effectiveness_rate={feedback_effectiveness_rate}")
    score = max(0.0, min(0.99, round(score, 4)))
    return score, reasoning


def _remediation_suggestions(
    *,
    candidate: CorrelatedFindingCandidate,
    cross_session: dict[str, Any],
) -> list[dict[str, str]]:
    finding_type = str(candidate.finding_type or "").strip().lower()
    out: list[dict[str, str]] = []

    if finding_type in {"repeated_prompt_injection_attempts"}:
        out.extend(
            [
                {"category": "policy_change", "action": "tighten_prompt_controls", "summary": "Increase prompt guard strictness (warn->block)."},
                {
                    "category": "system_restriction",
                    "action": "require_step_up_for_prompt_risk",
                    "summary": "Require approval for subsequent high-risk prompt flows.",
                },
            ]
        )
    if finding_type in {"repeated_tool_denials", "unusual_tool_sequences", "abnormal_agent_chains"}:
        out.extend(
            [
                {"category": "permission_reduction", "action": "reduce_agent_tool_scope", "summary": "Reduce tool permissions to least privilege."},
                {"category": "permission_reduction", "action": "enforce_tool_allowlist", "summary": "Remove non-allowlisted tools for affected agent paths."},
                {
                    "category": "policy_change",
                    "action": "tighten_tool_execution_policy",
                    "summary": "Tighten tool execution policies for denied or anomalous tool flows.",
                },
            ]
        )
    if finding_type in {"agent_over_scope_risk"}:
        out.extend(
            [
                {"category": "permission_reduction", "action": "reduce_agent_scope", "summary": "Replace broad static scope with dynamic session-bound permissions."},
                {"category": "token_control", "action": "revoke_tokens", "summary": "Revoke active high-risk agent tokens and reissue least-privilege tokens."},
                {"category": "identity_containment", "action": "disable_agent", "summary": "Disable or isolate over-scoped agent until review is complete."},
            ]
        )
    if finding_type in {"agent_session_anomaly"}:
        out.extend(
            [
                {"category": "identity_containment", "action": "invalidate_session", "summary": "Invalidate suspicious session and require a fresh user-bound agent session."},
                {"category": "token_control", "action": "revoke_tokens", "summary": "Revoke session-linked tokens to prevent replay and lateral movement."},
                {"category": "policy_change", "action": "require_step_up_for_agent_actions", "summary": "Require approval before sensitive agent actions."},
            ]
        )
    if finding_type in {"repeated_sensitive_data_attempts", "multi_tool_data_exposure", "asymmetry_risk_spike", "justification_trend_risk"}:
        out.extend(
            [
                {"category": "policy_change", "action": "tighten_data_movement_policy", "summary": "Tighten transfer and upload controls for sensitive data."},
                {"category": "system_restriction", "action": "restrict_external_destinations", "summary": "Restrict external AI destinations until review."},
            ]
        )
    if finding_type in {"unknown_ai_adoption_spike"}:
        out.extend(
            [
                {"category": "system_restriction", "action": "block_unknown_ai_usage", "summary": "Block unknown systems until Trust Center review."},
                {"category": "policy_change", "action": "require_ai_registration", "summary": "Require owner assignment and lifecycle review before allow."},
            ]
        )
    if finding_type in {"ai_supply_chain_attack"}:
        out.extend(
            [
                {"category": "identity_containment", "action": "revoke_oauth_app", "summary": "Revoke the OAuth app grant for the impacted identity."},
                {"category": "token_control", "action": "revoke_tokens", "summary": "Revoke active OAuth/session tokens linked to the app chain."},
                {"category": "secret_hygiene", "action": "rotate_secrets", "summary": "Rotate exposed API keys, client secrets, and affected credentials."},
                {"category": "identity_containment", "action": "disable_user", "summary": "Disable impacted user or service identity until triage is complete."},
            ]
        )

    if int(cross_session.get("escalation_level") or 0) >= 1:
        out.append(
            {
                "category": "system_restriction",
                "action": "escalate_to_restricted_mode",
                "summary": "Long-term repeated pattern observed; escalate to stricter runtime posture.",
            }
        )

    dedup: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in out:
        token = f"{item['category']}:{item['action']}"
        if token in seen:
            continue
        seen.add(token)
        dedup.append(item)
    return dedup


def _is_prompt_block_like(event: RuntimeEventRow) -> bool:
    metadata = _metadata_dict(event)
    event_type = str(metadata.get("event_type") or event.event_type or "").lower()
    if str(event.source_surface or "").lower() == "browser" and event_type in {
        "prompt_drafted", "policy_blocked", "policy_warned",
    }:
        return False
    decision = str(metadata.get("decision") or "").lower()
    signals = set(_metadata_list(event, "input_signal_types") + _metadata_list(event, "reason_codes"))
    promptish = "prompt" in event_type or event_type == "llm_intercept" or bool({"prompt_injection", "prompt_decomposition", "jailbreak"}.intersection(signals))
    actionish = decision in {"block", "warn", "hold_for_approval"} or str(event.severity or "").lower() in {"med", "high", "critical"}
    return promptish and actionish


def _is_tool_denial(event: RuntimeEventRow) -> bool:
    event_type = str(event.event_type or "").lower()
    meta = _metadata_dict(event)
    decision = str(meta.get("decision") or "").lower()
    reason = str(meta.get("reason") or "").lower()
    return (
        ("mcp" in event_type or "tool" in event_type)
        and (
            decision in {"block", "deny", "denied", "restricted"}
            or "denied" in reason
            or "scope_" in reason
            or "token_" in reason
        )
    )


def _is_unknown_ai_signal(event: RuntimeEventRow) -> bool:
    if _is_operational_or_placeholder_event(event):
        return False
    event_type = str(event.event_type or "").lower()
    meta = _metadata_dict(event)
    risk_category = str(meta.get("risk_category") or "").lower()
    source_ok = str(event.source_surface or "") in {"browser", "connector", "endpoint", "dns", "proxy"}
    return source_ok and (
        "unknown" in event_type
        or str(meta.get("event_type") or "").lower() == "unknown_ai_detected"
        or risk_category == "shadow_ai"
    )


def _is_asymmetry_signal(event: RuntimeEventRow) -> bool:
    event_type = str(event.event_type or "").lower()
    if "asymmetry" in event_type:
        return True
    labels = set(_metadata_list(event, "risk_labels"))
    return bool({"output_asymmetry", "agent_chain_abuse", "potential_data_exfiltration"}.intersection(labels))


def _oauth_app_id(event: RuntimeEventRow) -> str:
    meta = _metadata_dict(event)
    oauth_app = meta.get("oauth_app") if isinstance(meta.get("oauth_app"), dict) else {}
    return str(oauth_app.get("app_id") or oauth_app.get("client_id") or meta.get("oauth_app_id") or "").strip().lower()


def _oauth_scope_match(left: RuntimeEventRow, right: RuntimeEventRow) -> bool:
    left_app_id = _oauth_app_id(left)
    right_app_id = _oauth_app_id(right)
    if left_app_id and right_app_id:
        return left_app_id == right_app_id
    return _scope_match(left, right)


def _oauth_scope_tokens(event: RuntimeEventRow) -> list[str]:
    meta = _metadata_dict(event)
    oauth_app = meta.get("oauth_app") if isinstance(meta.get("oauth_app"), dict) else {}
    raw_tokens: list[str] = []
    for source in (oauth_app.get("scopes"), meta.get("scopes"), meta.get("high_privilege_scopes"), meta.get("oauth_scopes")):
        if isinstance(source, list):
            raw_tokens.extend([str(item).strip() for item in source if str(item).strip()])
        elif isinstance(source, str) and source.strip():
            raw_tokens.extend([token for token in source.replace(",", " ").split(" ") if token.strip()])
    return sorted({token.lower() for token in raw_tokens if token})


def _is_high_privilege_scope(scope: str) -> bool:
    token = str(scope or "").strip().lower()
    if not token:
        return False
    markers = (
        "directory.readwrite.all",
        "directory.read.all",
        "files.readwrite.all",
        "files.read.all",
        "sites.fullcontrol.all",
        "sites.readwrite.all",
        "mail.readwrite",
        "mail.send",
        "chatmessage.read.all",
        "channelmessage.read.all",
        "user.read.all",
        "offline_access",
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/gmail",
    )
    if any(marker in token for marker in markers):
        return True
    if ".all" in token and any(marker in token for marker in ("read", "write", "mail", "file", "site", "directory", "chat")):
        return True
    if "readwrite" in token or "fullcontrol" in token:
        return True
    return False


def _is_oauth_new_app_signal(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    if bool(meta.get("oauth_new_app")):
        return True
    if "oauth_new_app" in _metadata_list(event, "reason_codes"):
        return True
    blob = " ".join(
        [
            str(event.event_type or ""),
            str(meta.get("reason_code") or ""),
            str(meta.get("activityDisplayName") or ""),
            str(meta.get("operationType") or ""),
            str(meta.get("action") or ""),
        ]
    ).strip().lower()
    return any(
        marker in blob
        for marker in (
            "consent to application",
            "grant consent",
            "service principal created",
            "app registration",
            "add application",
            "application created",
            "install app",
        )
    )


def _is_oauth_high_risk_scope_signal(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    if bool(meta.get("oauth_high_risk_scopes")):
        return True
    if _metadata_list(event, "high_privilege_scopes"):
        return True
    return any(_is_high_privilege_scope(scope) for scope in _oauth_scope_tokens(event))


def _is_oauth_abnormal_access_signal(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    if bool(meta.get("abnormal_access_pattern")) or bool(meta.get("anomaly_flag")):
        return True
    if bool(meta.get("unprotected_secrets_accessed")):
        return True
    systems_accessed = meta.get("systems_accessed")
    if isinstance(systems_accessed, list) and len([item for item in systems_accessed if str(item).strip()]) >= 3:
        return True
    risk_blob = " ".join(
        [
            str(meta.get("riskLevel") or ""),
            str(meta.get("riskLevelDuringSignIn") or ""),
            str(meta.get("riskState") or ""),
            str(meta.get("status") or ""),
            str(meta.get("failureReason") or ""),
        ]
    ).strip().lower()
    if any(marker in risk_blob for marker in ("high", "risky", "suspicious", "anomaly", "compromised")):
        return True
    return False


def _is_sensitive_transfer_signal(event: RuntimeEventRow) -> bool:
    event_type = str(event.event_type or "").lower()
    meta = _metadata_dict(event)
    decision = str(meta.get("decision") or meta.get("action_taken") or "").lower()
    signals = set(_metadata_list(event, "input_signal_types") + _metadata_list(event, "reason_codes"))
    risk_category = str(meta.get("risk_category") or "").lower()
    sensitive_event_type = any(
        marker in event_type
        for marker in {
            "data_transfer",
            "clipboard_paste_detected",
            "file_upload_detected",
            "blocked_transfer",
            "warned_transfer",
        }
    )
    restrictive_decision = any(marker in decision for marker in {"warn", "block", "hold", "deny", "restrict", "require"})
    return (
        (
            sensitive_event_type
            or "sensitive_data_pattern" in signals
            or "sensitive_file_name_hint" in signals
            or risk_category in {"sensitive_data", "data_transfer"}
        )
        and restrictive_decision
    )


def _is_sensitive_justification_signal(event: RuntimeEventRow) -> bool:
    event_type = str(event.event_type or "").lower()
    if "data_transfer_justification" not in event_type:
        return False
    meta = _metadata_dict(event)
    justification_present = bool(meta.get("justification_present"))
    source_classification = str(meta.get("source_classification_hint") or "").lower()
    decision = str(meta.get("decision") or meta.get("action_taken") or "").lower()
    return justification_present and source_classification in {"protected", "sensitive"} and decision == "allow"


def _tool_fingerprint(event: RuntimeEventRow) -> str:
    if _is_operational_or_placeholder_event(event):
        return ""
    meta = _metadata_dict(event)
    event_type = str(event.event_type or "").strip().lower()
    invoked = bool(
        meta.get("tool_call_id") or meta.get("function_call_id")
        or meta.get("tool_invoked")
        or any(marker in event_type for marker in ("tool_call", "function_call", "mcp_authorize", "mcp_tool"))
    )
    if not invoked:
        return ""
    for value in [meta.get("mcp_tool_id"), meta.get("tool_name")]:
        text = str(value or "").strip().lower()
        if text:
            return text
    return ""


def _chain_depth(event: RuntimeEventRow) -> int | None:
    meta = _metadata_dict(event)
    value = meta.get("chain_depth")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _tool_transitions(events: list[RuntimeEventRow]) -> tuple[list[str], list[str]]:
    ordered = sorted(events, key=lambda item: item.created_at)
    tools = [_tool_fingerprint(row) for row in ordered]
    tools = [tool for tool in tools if tool]
    transitions = [f"{left}->{right}" for left, right in zip(tools, tools[1:]) if left and right and left != right]
    return tools, transitions


def _is_abnormal_agent_chain(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    depth = _chain_depth(event)
    parent_agent_id = str(meta.get("parent_agent_id") or "").strip()
    has_agent = bool(str(event.agent_id or "").strip())
    return bool(
        has_agent
        and (
            (depth is not None and depth >= 4)
            or (depth is not None and depth >= 3 and parent_agent_id)
            or ("agent_chain" in str(event.event_type or "").lower() and parent_agent_id)
        )
    )


def _is_agent_over_scope_signal(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    reason = str(meta.get("reason") or "").strip().lower()
    signal_types = set(_metadata_list(event, "input_signal_types") + _metadata_list(event, "reason_codes"))
    dynamic_permission = meta.get("dynamic_permission") if isinstance(meta.get("dynamic_permission"), dict) else {}
    allowed_tools = [
        str(item).strip().lower()
        for item in list(dynamic_permission.get("allowed_tools") or [])
        if str(item).strip()
    ]
    allowed_actions = [
        str(item).strip().lower()
        for item in list(dynamic_permission.get("allowed_actions") or [])
        if str(item).strip()
    ]
    risk_level = str(dynamic_permission.get("risk_level") or "").strip().lower()

    return bool(
        bool(meta.get("over_scoped_flag"))
        or bool(meta.get("privilege_escalation_detected"))
        or bool(meta.get("new_system_access_detected"))
        or bool(meta.get("abnormal_tool_usage_detected"))
        or "agent_over_scope_risk" in signal_types
        or any(marker in reason for marker in ("dynamic_", "privilege_escalation", "over_scope"))
        or ("*" in allowed_tools)
        or ("*" in allowed_actions)
        or risk_level in {"high", "critical"}
    )


def _is_agent_session_anomaly_signal(event: RuntimeEventRow) -> bool:
    meta = _metadata_dict(event)
    signal_types = set(_metadata_list(event, "input_signal_types") + _metadata_list(event, "reason_codes"))
    reason = str(meta.get("reason") or "").strip().lower()
    session_validation = meta.get("session_validation") if isinstance(meta.get("session_validation"), dict) else {}
    session_reason = str(session_validation.get("reason") or "").strip().lower()
    session_valid = session_validation.get("valid")

    return bool(
        ("agent_session_anomaly" in signal_types)
        or any(marker in reason for marker in ("session_required", "session_expired", "session_invalid"))
        or any(marker in session_reason for marker in ("session_required", "session_expired", "session_inactive", "session_mismatch"))
        or (session_valid is False)
    )


def correlate_runtime_event(db: Session, *, event: RuntimeEventRow) -> list[CorrelatedFindingCandidate]:
    recent_events = db.scalars(
        select(RuntimeEventRow).where(
            RuntimeEventRow.tenant_id == event.tenant_id,
            RuntimeEventRow.created_at >= _window_start(),
        )
    ).all()

    threshold = _repeat_threshold()
    candidates: list[CorrelatedFindingCandidate] = []

    prompt_actions: dict[str, RuntimeEventRow] = {}
    for row in recent_events:
        if _is_prompt_block_like(row) and _scope_match(row, event):
            prompt_actions.setdefault(str(row.correlation_id or row.event_id), row)
    prompt_matches = list(prompt_actions.values())
    if _is_prompt_block_like(event) and len(prompt_matches) >= threshold:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="repeated_prompt_injection_attempts",
                risk_category="interaction_security",
                severity="high" if len(prompt_matches) < threshold + 2 else "critical",
                reason_code="repeated_prompt_blocks",
                repeated_count=len(prompt_matches),
                related_control_ids=["CTRL-INPUT-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Repeated prompt-block pattern detected. Route to governance review and run prompt-attack simulations.",
                recommendation_types=["route_to_review", "escalate_risk_tier"],
            )
        )

    tool_denials = [row for row in recent_events if _is_tool_denial(row) and _scope_match(row, event)]
    if _is_tool_denial(event) and len(tool_denials) >= threshold:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="repeated_tool_denials",
                risk_category="agent_tooling",
                severity="high",
                reason_code="repeated_denied_tool_calls",
                repeated_count=len(tool_denials),
                related_control_ids=["CTRL-TOOL-001", "CTRL-AI-IAM-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Repeated denied tool activity detected. Validate least-privilege scopes and tool policy bindings.",
                recommendation_types=["route_to_review", "tighten_tool_permissions"],
            )
        )

    scoped_tool_events = [row for row in recent_events if _scope_match(row, event) and _tool_fingerprint(row)]
    if scoped_tool_events and _tool_fingerprint(event):
        observed_tools, observed_transitions = _tool_transitions(scoped_tool_events)
        distinct_tools = {tool for tool in observed_tools if tool}
        distinct_transitions = {transition for transition in observed_transitions if transition}
        transition_count = len(observed_transitions)
        if (
            transition_count >= max(2, threshold - 1)
            and len(distinct_tools) >= 3
            and len(distinct_transitions) >= 2
        ):
            candidates.append(
                CorrelatedFindingCandidate(
                    finding_type="unusual_tool_sequences",
                    risk_category="agent_tooling",
                    severity="high" if transition_count < threshold + 2 else "critical",
                    reason_code="unusual_tool_sequences",
                    repeated_count=transition_count,
                    related_control_ids=["CTRL-TOOL-001", "CTRL-AI-IAM-001"],
                    evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                    recommended_action=(
                        "Unusual cross-tool execution sequence detected. Review tool orchestration path and tighten workflow constraints."
                    ),
                    recommendation_types=["route_to_review", "tighten_tool_permissions"],
                )
            )

    unknown_ai_signals = [row for row in recent_events if _is_unknown_ai_signal(row)]
    unknown_ai_apps = {str(row.app_id).strip().lower() for row in unknown_ai_signals if str(row.app_id or "").strip()}
    if _is_unknown_ai_signal(event) and (len(unknown_ai_signals) >= threshold + 1 or len(unknown_ai_apps) >= 3):
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="unknown_ai_adoption_spike",
                risk_category="shadow_ai",
                severity="high",
                reason_code="unknown_ai_discovery_spike",
                repeated_count=len(unknown_ai_signals),
                related_control_ids=["CTRL-TENANT-ISO-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Unknown AI adoption spike detected. Assign ownership and route discovery results to governance.",
                recommendation_types=["assign_owner", "route_to_review"],
            )
        )

    asymmetry_events = [row for row in recent_events if _is_asymmetry_signal(row) and _scope_match(row, event)]
    if _is_asymmetry_signal(event) and len(asymmetry_events) >= 2:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="asymmetry_risk_spike",
                risk_category="output_asymmetry",
                severity="critical" if len(asymmetry_events) >= 3 else "high",
                reason_code="asymmetry_spike",
                repeated_count=len(asymmetry_events),
                related_control_ids=["CTRL-TOOL-001", "CTRL-DLP-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Asymmetry spike detected. Run data-leakage simulations and review tool-call boundaries.",
                recommendation_types=["move_to_blocked", "route_to_review"],
            )
        )

    sensitive_events = [row for row in recent_events if _is_sensitive_transfer_signal(row) and _scope_match(row, event)]
    if _is_sensitive_transfer_signal(event) and len(sensitive_events) >= threshold:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="repeated_sensitive_data_attempts",
                risk_category="sensitive_data",
                severity="high",
                reason_code="repeated_sensitive_data_uploads",
                repeated_count=len(sensitive_events),
                related_control_ids=["CTRL-DLP-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Repeated sensitive-data movement attempts detected. Tighten policy and route to governance.",
                recommendation_types=["route_to_review", "tighten_policy"],
            )
        )

    if _is_sensitive_transfer_signal(event):
        observed_tools = {tool for tool in (_tool_fingerprint(row) for row in sensitive_events) if tool}
        if len(sensitive_events) >= threshold and len(observed_tools) >= 2:
            candidates.append(
                CorrelatedFindingCandidate(
                    finding_type="multi_tool_data_exposure",
                    risk_category="sensitive_data",
                    severity="critical" if len(observed_tools) >= 3 else "high",
                    reason_code="multi_tool_data_exposure",
                    repeated_count=len(sensitive_events),
                    related_control_ids=["CTRL-DLP-001", "CTRL-TOOL-001"],
                    evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                    recommended_action="Sensitive-data activity spans multiple tools. Run data-leakage validation and tighten data movement controls.",
                    recommendation_types=["route_to_review", "escalate_risk_tier"],
                )
            )

    abnormal_chain_events = [row for row in recent_events if _is_abnormal_agent_chain(row) and _scope_match(row, event)]
    if _is_abnormal_agent_chain(event) and len(abnormal_chain_events) >= 2:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="abnormal_agent_chains",
                risk_category="agent_chain_abuse",
                severity="critical" if len(abnormal_chain_events) >= threshold else "high",
                reason_code="abnormal_agent_chains",
                repeated_count=len(abnormal_chain_events),
                related_control_ids=["CTRL-AI-IAM-001", "CTRL-TOOL-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Abnormal agent chain depth detected. Review delegation boundaries and enforce stricter chain limits.",
                recommendation_types=["move_to_blocked", "route_to_review"],
            )
        )

    over_scope_events = [row for row in recent_events if _is_agent_over_scope_signal(row) and _scope_match(row, event)]
    if _is_agent_over_scope_signal(event):
        try:
            event_anomaly_score = float(_metadata_dict(event).get("anomaly_score") or 0.0)
        except (TypeError, ValueError):
            event_anomaly_score = 0.0
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="AGENT_OVER_SCOPE_RISK",
                risk_category="ai_iam",
                severity="critical" if len(over_scope_events) >= threshold or event_anomaly_score >= 0.85 else "high",
                reason_code="agent_over_scope_risk",
                repeated_count=max(1, len(over_scope_events)),
                related_control_ids=[
                    "AI_IDENTITY_BINDING",
                    "PRIVILEGE_DRIFT_DETECTION",
                    "AGENT_ACTION_AUTHORIZATION",
                    "TOKEN_SCOPE_ENFORCEMENT",
                ],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action=(
                    "Agent over-scope risk detected. Constrain dynamic permissions, reduce tool/data scope, revoke risky tokens, and require approval for privileged actions."
                ),
                recommendation_types=["tighten_tool_permissions", "move_to_blocked", "route_to_review", "escalate_risk_tier"],
            )
        )

    session_anomaly_events = [row for row in recent_events if _is_agent_session_anomaly_signal(row) and _scope_match(row, event)]
    if _is_agent_session_anomaly_signal(event):
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="AGENT_SESSION_ANOMALY",
                risk_category="ai_iam",
                severity="critical" if len(session_anomaly_events) >= 2 else "high",
                reason_code="agent_session_anomaly",
                repeated_count=max(1, len(session_anomaly_events)),
                related_control_ids=[
                    "AI_IDENTITY_BINDING",
                    "NON_HUMAN_IDENTITY_CONTROL",
                    "CHAIN_OF_ACTION_VALIDATION",
                ],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action=(
                    "Agent session anomaly detected. Revalidate initiating identity, revoke stale sessions/tokens, and block actions until session integrity is restored."
                ),
                recommendation_types=["move_to_blocked", "route_to_review", "escalate_risk_tier"],
            )
        )

    if _oauth_app_id(event):
        oauth_new_events = [row for row in recent_events if _is_oauth_new_app_signal(row) and _oauth_scope_match(row, event)]
        oauth_high_scope_events = [row for row in recent_events if _is_oauth_high_risk_scope_signal(row) and _oauth_scope_match(row, event)]
        oauth_abnormal_events = [row for row in recent_events if _is_oauth_abnormal_access_signal(row) and _oauth_scope_match(row, event)]
        if oauth_new_events and oauth_high_scope_events and oauth_abnormal_events:
            oauth_chain_events = [*oauth_new_events, *oauth_high_scope_events, *oauth_abnormal_events]
            evidence_node_ids = sorted(
                {
                    str(node_id).strip()
                    for row in oauth_chain_events
                    for node_id in (row.evidence_node_ids or [])
                    if str(node_id).strip()
                }
            )
            repeated_count = len({str(row.event_id).strip() for row in oauth_chain_events if str(row.event_id or "").strip()})
            candidates.append(
                CorrelatedFindingCandidate(
                    finding_type="AI_SUPPLY_CHAIN_ATTACK",
                    risk_category="supply_chain",
                    severity="critical",
                    reason_code="oauth_supply_chain_attack",
                    repeated_count=max(3, repeated_count),
                    related_control_ids=["CTRL-AI-IAM-001", "CTRL-TOOL-001", "CTRL-DLP-001"],
                    evidence_node_ids=evidence_node_ids,
                    recommended_action=(
                        "OAuth supply-chain pattern detected. Revoke OAuth app, revoke tokens, rotate exposed secrets, and disable impacted user pending review."
                    ),
                    recommendation_types=["move_to_blocked", "tighten_tool_permissions", "route_to_review"],
                )
            )

    justification_events = [row for row in recent_events if _is_sensitive_justification_signal(row) and _scope_match(row, event)]
    if _is_sensitive_justification_signal(event) and len(justification_events) >= threshold:
        candidates.append(
            CorrelatedFindingCandidate(
                finding_type="justification_trend_risk",
                risk_category="sensitive_data",
                severity="high",
                reason_code="repeated_justified_sensitive_transfers",
                repeated_count=len(justification_events),
                related_control_ids=["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
                evidence_node_ids=[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
                recommended_action="Repeated sensitive transfers are being justified. Review business need and tighten transfer policy.",
                recommendation_types=["route_to_review", "tighten_policy"],
            )
        )

    unique: dict[str, CorrelatedFindingCandidate] = {}
    for candidate in candidates:
        unique[candidate.finding_type] = candidate
    return list(unique.values())


def governance_recommendations_for_candidate(
    *,
    event: RuntimeEventRow,
    candidate: CorrelatedFindingCandidate,
    db: Session | None = None,
    risk_score: int | None = None,
    pattern: RuntimePattern | None = None,
) -> list[GovernanceRecommendation]:
    event_metadata = _metadata_dict(event)
    if db is not None:
        cross_session = _cross_session_snapshot(db=db, event=event, candidate=candidate, pattern=pattern)
        feedback = _feedback_loop_metrics(db=db, event=event, candidate=candidate)
    else:
        cross_session = {
            "lookback_days": max(7, int(getattr(settings, "runtime_recommendation_long_window_days", 30))),
            "recent_recommendation_count": 0,
            "pattern_frequency": int(candidate.repeated_count or 1),
            "escalation_level": 0,
            "is_long_term_pattern": False,
        }
        feedback = {
            "sample_size": 0,
            "applied_count": 0,
            "failed_count": 0,
            "rolled_back_count": 0,
            "rejected_count": 0,
            "false_positive_rate": 0.0,
            "effectiveness_rate": 0.0,
        }
    cross_session["feedback_false_positive_rate"] = float(feedback.get("false_positive_rate") or 0.0)
    cross_session["feedback_effectiveness_rate"] = float(feedback.get("effectiveness_rate") or 0.0)
    cross_session["feedback_sample_size"] = int(feedback.get("sample_size") or 0)
    confidence_score, confidence_reasoning = _confidence_score(
        event=event,
        candidate=candidate,
        risk_score=int(risk_score or 0),
        cross_session=cross_session,
    )
    confidence_threshold = float(getattr(settings, "runtime_remediation_confidence_threshold", 0.5))
    confidence_gate_passed = confidence_score >= confidence_threshold
    if not confidence_gate_passed:
        return []

    recommendation_types = list(candidate.recommendation_types or [])
    escalation_level = int(cross_session.get("escalation_level") or 0)
    if escalation_level >= 1 and "route_to_review" not in recommendation_types:
        recommendation_types.append("route_to_review")
    if escalation_level >= 1 and "escalate_risk_tier" not in recommendation_types:
        recommendation_types.append("escalate_risk_tier")
    if escalation_level >= 2 and "move_to_blocked" not in recommendation_types:
        recommendation_types.append("move_to_blocked")

    out: list[GovernanceRecommendation] = []
    for rec_type in recommendation_types:
        candidate_type = str(candidate.finding_type or "").strip().lower()
        impact = score_runtime_recommendation_impact(
            recommendation_type=rec_type,
            severity=str(candidate.severity or "low"),
            repeated_count=int(candidate.repeated_count or 1),
            pattern_frequency=int(cross_session.get("pattern_frequency") or int(candidate.repeated_count or 1)),
            metadata={
                **event_metadata,
                "evidence_node_ids": sorted(
                    {
                        str(node_id).strip()
                        for node_id in [*list(event.evidence_node_ids or []), *list(candidate.evidence_node_ids or [])]
                        if str(node_id).strip()
                    }
                ),
                "event_created_at": event.created_at.isoformat(),
                "confidence_score": confidence_score,
                "active_attack": bool(
                    candidate_type in {
                        "repeated_prompt_injection_attempts",
                        "repeated_tool_denials",
                        "multi_tool_data_exposure",
                        "abnormal_agent_chains",
                        "ai_supply_chain_attack",
                        "agent_over_scope_risk",
                        "agent_session_anomaly",
                    }
                    or str(candidate.severity or "").lower() in {"high", "critical"}
                ),
                "active_session": bool(event.chain_id),
            },
            cross_session=cross_session,
        )

        priority = "high" if impact.decision_impact_score >= 150_000 else ("med" if impact.decision_impact_score >= 50_000 else "low")
        if escalation_level >= 2 and priority == "low":
            priority = "med"
        remediation_suggestions = _remediation_suggestions(candidate=candidate, cross_session=cross_session)
        out.append(
            GovernanceRecommendation(
                recommendation_type=rec_type,
                reason_code=candidate.reason_code,
                priority=priority,
                payload={
                    "event_id": event.event_id,
                    "finding_type": candidate.finding_type,
                    "repeated_count": candidate.repeated_count,
                    "ai_system_id": event.ai_system_id,
                    "cross_session": {
                        "lookback_days": int(cross_session.get("lookback_days") or 0),
                        "recent_recommendation_count": int(cross_session.get("recent_recommendation_count") or 0),
                        "pattern_frequency": int(cross_session.get("pattern_frequency") or 0),
                        "is_long_term_pattern": bool(cross_session.get("is_long_term_pattern")),
                        "escalation_level": escalation_level,
                    },
                    "remediation_suggestions": remediation_suggestions,
                    "confidence_score": confidence_score,
                    "confidence_threshold": confidence_threshold,
                    "confidence_reasoning": confidence_reasoning,
                    "confidence_gate_passed": confidence_gate_passed,
                    "feedback_loop": feedback,
                    "decision_impact": impact.as_dict(),
                    "decision_impact_score": round(impact.decision_impact_score, 2),
                    "estimated_risk_reduction": round(impact.estimated_risk_reduction, 2),
                    "base_risk": round(impact.base_risk, 2),
                    "urgency_multiplier": round(impact.urgency_multiplier, 2),
                    "control_effectiveness": round(impact.control_effectiveness, 4),
                },
            )
        )
    return out
