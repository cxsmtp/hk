#!/usr/bin/env python3
"""Bounded Claude Code -> Hawk MCP -> harmless child acceptance, isolated from demo state."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from isolated_hawk_lab import IsolatedHawkLab, FORBIDDEN_PORTS, validate_root

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "apps" / "api"
PROXY = ROOT / "packages" / "hawk-mcp-proxy" / "bin" / "hawk-mcp-proxy.mjs"
CHILD = ROOT / "packages" / "hawk-mcp-proxy" / "examples" / "manual-terminal" / "read-only-mcp-server.mjs"
OFFICIAL_SDK_CLIENT = CHILD.with_name("official-mcp-sdk-client.mjs")
OFFICIAL_SDK_VERSION = "1.29.0"
MAX_SDK_OUTPUT_BYTES = 4096
MAX_WIRE_PAYLOAD_BYTES = 16384
SDK_REASON_TOKENS = frozenset({"none", "hawk_block", "hawk_hold", "hawk_warn", "other", "non_mcp_error", "returned_error", *[f"gateway_{reason}" for reason in ("request_schema_invalid", "unauthenticated", "forbidden", "not_found", "conflict", "rate_limited", "service_unavailable", "internal_error", "http_error", "transport_error", "timeout", "response_invalid", "agent_session_revoked", "agent_session_expired", "agent_session_inactive", "agent_session_required", "mcp_session_authority_denied", "governance_context_blocked", "governance_fail_secure", "tool_fingerprint_unapproved", "tool_metadata_drift")]})
EVENT_REASON_TOKENS = frozenset({
    "allow", "agent_session_revoked", "agent_session_not_found", "agent_session_required", "agent_session_expired", "agent_session_inactive", "agent_session_user_mismatch", "agent_session_agent_mismatch",
    "agent_session_action_scope_denied", "agent_session_tool_scope_denied", "agent_session_data_scope_denied", "agent_session_resource_scope_denied", "agent_session_chain_depth_exceeded", "agent_session_destination_scope_denied",
    "dynamic_action_scope_denied", "dynamic_tool_scope_denied", "dynamic_data_scope_denied", "dynamic_resource_scope_denied", "dynamic_system_scope_denied", "agent_system_scope_denied", "agent_tool_registry_denied",
    "action_outside_purpose_scope", "persisted_purpose_permission_required", "purpose_confirmation_required", "agent_privilege_escalation_detected", "new_system_access_detected", "abnormal_tool_usage_detected",
    "tool_principal_binding_mismatch", "capability_token_invalid", "agent_session_invalid", "dynamic_permission_denied", "no_purpose_bound_permission_provided",
})
GUARDIAN_IDS = frozenset({"mcp_scope_guard", "agent_session_guard", "dynamic_permission_guard", "runtime_anomaly_guard", "auto_quarantine_guard", "persisted_delegation_chain_guard", "provider_surface_guard", "sensitive_data_guard", "mcp_tool_integrity_guard", "tool_principal_binding_guard"})
HASH = re.compile(r"^[0-9a-f]{64}$")
SHARED_PORTS = FORBIDDEN_PORTS
IsolatedHawkApi = IsolatedHawkLab
SESSION_CONTEXT = {"allowed_data_scope": ["internal"], "data_classification": "internal", "environment": "production"}
TOOL_NAME = "read_demo_marker"
EXACT_TOOL = "mcp__hawk_lab__read_demo_marker"
MAX_CLAUDE_STREAM_BYTES = 1_048_576
MAX_CLAUDE_STDERR_BYTES = 65_536
MAX_CLAUDE_COST_USD = 0.05
CLAUDE_MCP_CONNECT_TIMEOUT_MS = "30000"
MAX_RESULT_TEXT_CHARS = 4096
PROSE_CODES = frozenset({"tool_unavailable", "permission_or_policy", "budget_exhausted", "refusal", "prose_without_tool_call", "none"})
MAX_CODEX_STREAM_BYTES = 1_048_576
MAX_CODEX_STDERR_BYTES = 65536
CODEX_TOOL = "mcp__hawk_lab__read_demo_marker"
CLAUDE_STDERR_CATEGORIES = frozenset({"none", "authentication", "configuration", "mcp_startup_transport", "timeout", "policy", "other"})
CLAUDE_CONNECTION_STATES = frozenset({"connected", "disconnected", "failed", "pending", "connecting", "disabled", "needs_auth", "missing", "unknown"})
CLAUDE_VALUE_TYPES = frozenset({"string", "null", "boolean", "number", "list", "object"})
_CLAUDE_FAILURE_PROGRESS: dict | None = None


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def validate_isolated_api_url(url: str) -> int:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("isolated_api_must_use_literal_loopback")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_isolated_api_port") from exc
    if port is None or port <= 0 or port in SHARED_PORTS:
        raise ValueError("shared_or_unassigned_api_port")
    return port


def validate_private_paths(directory: Path, database: Path, config: Path) -> None:
    directory = validate_root(directory)
    if directory not in database.resolve().parents or directory not in config.resolve().parents:
        raise ValueError("temporary_artifact_outside_isolation")
    if database.exists() and not ((database.is_dir() and stat.S_IMODE(database.stat().st_mode) == 0o700) or (database.is_file() and stat.S_IMODE(database.stat().st_mode) == 0o600)):
        raise ValueError("temporary_artifact_not_private")
    if config.exists() and (not config.is_file() or stat.S_IMODE(config.stat().st_mode) != 0o600):
        raise ValueError("temporary_artifact_not_private")


def _no_raw_fields(value: object) -> None:
    forbidden = {"prompt", "completion", "token", "access_token", "capability_token", "raw_content", "raw_output"}
    if isinstance(value, dict):
        if forbidden.intersection(value):
            raise ValueError("raw_content_in_report")
        for child in value.values():
            _no_raw_fields(child)
    elif isinstance(value, list):
        for child in value:
            _no_raw_fields(child)


def validate_mcp_report(report: dict) -> None:
    _no_raw_fields(report)
    if report.get("client") != "claude-code" or not re.fullmatch(r"\d+\.\d+\.\d+", str(report.get("client_version", ""))):
        raise ValueError("exact_claude_client_required")
    if report.get("release_ready") is not False:
        raise ValueError("local_evidence_cannot_promote")
    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 3:
        raise ValueError("three_fresh_client_runs_required")
    ids = [run.get("run_id_hash") for run in runs]
    if len(set(ids)) != 3 or not all(isinstance(item, str) and HASH.fullmatch(item) for item in ids):
        raise ValueError("distinct_run_ids_required")
    if any(not isinstance(run.get("evidence_id_hash"), str) or not HASH.fullmatch(run["evidence_id_hash"]) for run in runs):
        raise ValueError("correlated_hawk_evidence_required")
    if [run.get("decision") for run in runs] != ["allow", "allow", "block"]:
        raise ValueError("allow_allow_revoke_decisions_required")
    if runs[2].get("reason") != "agent_session_revoked":
        raise ValueError("exact_revoked_session_denial_required")
    counts = [run.get("child_call_count") for run in runs]
    if not all(isinstance(count, int) and not isinstance(count, bool) for count in counts) or counts[0] != 1 or counts[1] != 2 or counts[2] != 2:
        raise ValueError("child_call_count_not_bound_to_revocation")
    if any(run.get("mcp_status") != "connected" or run.get("exact_tool_advertised") is not True or run.get("exact_tool_use_count") != 1 or run.get("permission_denial_count") != 0 or run.get("correlated_event") is not True or run.get("client_result_subtype") != "success" for run in runs):
        raise ValueError("client_tool_and_correlation_proof_required")
    if any(run.get("stop_reason") not in {"none", "end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal"} or run.get("prose_code") not in PROSE_CODES or run.get("is_error") is not False or isinstance(run.get("num_turns"), bool) or not isinstance(run.get("num_turns"), int) or not 0 <= run["num_turns"] <= 100 or isinstance(run.get("total_cost_usd"), bool) or not isinstance(run.get("total_cost_usd"), (int, float)) or not math.isfinite(run["total_cost_usd"]) or not 0 <= run["total_cost_usd"] <= MAX_CLAUDE_COST_USD for run in runs):
        raise ValueError("bounded_claude_result_facts_required")


def parse_official_sdk_result(data: bytes) -> dict:
    if not data or len(data) > MAX_SDK_OUTPUT_BYTES:
        raise ValueError("official_sdk_output_empty_or_oversized")
    try:
        facts = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("official_sdk_output_malformed") from exc
    required = {"client", "client_version", "connected", "exact_tool_advertised", "exact_schema", "call_status", "is_error", "mcp_error_code", "reason_token"}
    if not isinstance(facts, dict) or set(facts) != required:
        raise ValueError("official_sdk_output_schema_invalid")
    if facts["client"] != "official-mcp-typescript-sdk" or facts["client_version"] != OFFICIAL_SDK_VERSION:
        raise ValueError("exact_official_sdk_version_required")
    if any(not isinstance(facts[key], bool) for key in ("connected", "exact_tool_advertised", "exact_schema")):
        raise ValueError("official_sdk_output_schema_invalid")
    if facts["call_status"] not in {"not_called", "returned", "failed"} or facts["is_error"] is not None and not isinstance(facts["is_error"], bool):
        raise ValueError("official_sdk_output_schema_invalid")
    if facts["call_status"] == "not_called" and facts["is_error"] is not None:
        raise ValueError("official_sdk_output_schema_invalid")
    code = facts["mcp_error_code"]
    if code is not None and (isinstance(code, bool) or not isinstance(code, int) or not -32768 <= code <= 32767):
        raise ValueError("official_sdk_output_schema_invalid")
    if not isinstance(facts["reason_token"], str) or facts["reason_token"] not in SDK_REASON_TOKENS:
        raise ValueError("official_sdk_output_schema_invalid")
    return facts


def capture_gateway_authorize_wire(builder_input: dict) -> dict:
    """Capture the real JS builder/client HTTP body in memory; no network or logging."""
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node_required_for_authorize_wire_capture")
    script = """
import { readFileSync } from 'node:fs';
import { buildAuthorizePayload } from './src/policy.mjs';
import { HawkGatewayClient } from './src/hawk-client.mjs';
const input = JSON.parse(readFileSync(0, 'utf8'));
let body;
globalThis.fetch = async (_url, options) => {
  body = options.body;
  return { ok: true, text: async () => '{"decision":"allow"}' };
};
await new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:1', tenantId: 'synthetic', accessToken: 'synthetic' })
  .authorize(buildAuthorizePayload(input));
process.stdout.write(body);
"""
    result = subprocess.run([node, "--input-type=module", "-e", script], cwd=ROOT / "packages" / "hawk-mcp-proxy", input=json.dumps(builder_input).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode != 0 or not result.stdout or len(result.stdout) > MAX_WIRE_PAYLOAD_BYTES:
        raise RuntimeError("authorize_wire_capture_failed")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeError, ValueError):
        raise RuntimeError("authorize_wire_capture_malformed") from None
    if not isinstance(payload, dict) or "client_app" in payload:
        raise RuntimeError("authorize_wire_contract_invalid")
    return payload


def fixed_preflight_reason(status: int, body: dict) -> str:
    if status == 422:
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, list) and any(isinstance(item, dict) and item.get("type") == "extra_forbidden" and isinstance(item.get("loc"), list) and bool(item["loc"]) and item["loc"][-1] == "client_app" for item in detail):
            return "schema_extra_client_app"
        return "schema_validation_other"
    if status >= 500:
        return "server_error"
    if status >= 400:
        detail = body.get("detail") if isinstance(body, dict) else None
        raw = detail.get("reason_code") if isinstance(detail, dict) else None
        return raw if isinstance(raw, str) and raw in EVENT_REASON_TOKENS else "client_error_other"
    raw = body.get("reason") if isinstance(body, dict) else None
    if raw is None or raw == "":
        return "none"
    return raw if isinstance(raw, str) and raw in EVENT_REASON_TOKENS else "other"


def safe_policy_projection(body: dict) -> dict:
    def code(raw):
        return raw if isinstance(raw, str) and raw in EVENT_REASON_TOKENS else "other" if raw else "none"
    session = body.get("session") if isinstance(body, dict) and isinstance(body.get("session"), dict) else {}
    bounds = session.get("bounds_enforcement") if isinstance(session.get("bounds_enforcement"), dict) else {}
    pre = body.get("pre_action_governance_check") if isinstance(body, dict) and isinstance(body.get("pre_action_governance_check"), dict) else {}
    policy = pre.get("policy") if isinstance(pre.get("policy"), dict) else {}
    decision = policy.get("decision")
    return {"session_reason": code(session.get("reason")), "session_bounds_reason": code(bounds.get("reason")), "pre_action_reason": code(policy.get("reason")), "pre_action_decision": decision if isinstance(decision, str) and decision in {"allow", "block", "warn", "hold_for_approval"} else "other" if decision else "none"}


def sanitize_private_api_trace(raw: str) -> dict:
    """Reduce a private 500 traceback to allowlisted code location, never its text."""
    root = str(ROOT / "apps" / "api") + "/"
    frames = re.findall(r'File "([^"]+)", line (\d+), in ([A-Za-z_][A-Za-z0-9_]{0,63})', raw[-65536:])
    location = next(((path.removeprefix(root), int(line), function) for path, line, function in reversed(frames) if path.startswith(root) and path.removeprefix(root).startswith("app/") and path.endswith(".py") and int(line) <= 10000), None)
    exception_match = re.search(r'^([A-Za-z_][A-Za-z0-9_.]{0,100}):', raw[-4096:], re.MULTILINE)
    exception_class = exception_match.group(1).split(".")[-1] if exception_match else "unavailable"
    if exception_class not in {"ValidationError", "IntegrityError", "OperationalError", "ProgrammingError", "TypeError", "ValueError", "RuntimeError", "KeyError", "AttributeError"}:
        exception_class = "other"
    return {"exception_class": exception_class, "module": location[0] if location else "unavailable", "function": location[2] if location else "unavailable", "line": location[1] if location else 0}


def safe_correlated_event_diagnostic(events: list, *, tenant_id: str, session_id: str, since: datetime, seen: set[str]) -> dict:
    matches = []
    for event in events:
        actions = event.final_actions if isinstance(event.final_actions, dict) else {}
        mcp = actions.get("mcp") if isinstance(actions.get("mcp"), dict) else {}
        when = event.timestamp
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if event.tenant_id == tenant_id and event.id not in seen and when is not None and when >= since and mcp.get("session_id") == session_id and mcp.get("tool_name") == TOOL_NAME:
            matches.append(event)
    if not matches:
        return {"event_present": False, "decision": "none", "evidence_present": False, "reasons": [], "final_reason": "none", "guardian_codes": []}
    event = max(matches, key=lambda item: item.timestamp)
    decision = event.final_decision if event.final_decision in {"allow", "block", "warn", "hold_for_approval"} else "other"
    reasons = []
    guardian_codes = []
    for guardian in event.guardian_results if isinstance(event.guardian_results, list) else []:
        if not isinstance(guardian, dict):
            continue
        guardian_id = guardian.get("guardian_id")
        guardian_decision = guardian.get("decision")
        guardian_code = f"{guardian_id if isinstance(guardian_id, str) and guardian_id in GUARDIAN_IDS else 'other'}_{guardian_decision if isinstance(guardian_decision, str) and guardian_decision in {'allow', 'block', 'warn', 'hold_for_approval'} else 'other'}"
        if guardian_code not in guardian_codes:
            guardian_codes.append(guardian_code)
        for reason in guardian.get("matched_conditions", []) if isinstance(guardian.get("matched_conditions"), list) else []:
            token = reason if isinstance(reason, str) and reason in EVENT_REASON_TOKENS else "other"
            if token not in reasons:
                reasons.append(token)
    mcp = event.final_actions.get("mcp") if isinstance(event.final_actions, dict) else None
    raw_final_reason = mcp.get("reason") if isinstance(mcp, dict) else None
    final_reason = raw_final_reason if isinstance(raw_final_reason, str) and raw_final_reason in EVENT_REASON_TOKENS else "other" if raw_final_reason else "none"
    return {"event_present": True, "decision": decision, "evidence_present": bool(event.evidence_nodes_created), "reasons": reasons[:8], "final_reason": final_reason, "guardian_codes": guardian_codes[:8]}


def current_event_diagnostic(tenant_id: str, session_id: str, since: datetime, seen: set[str]) -> dict:
    from app.db.models.enforcement import EnforcementEvent
    from app.db.session import SessionLocal
    from sqlalchemy import select
    with SessionLocal() as db:
        events = db.scalars(select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id, EnforcementEvent.timestamp >= since)).all()
    return safe_correlated_event_diagnostic(events, tenant_id=tenant_id, session_id=session_id, since=since, seen=seen)


def current_failure_event_projection(tenant_id: str, session_id: str, since: datetime, seen: set[str]) -> dict:
    from app.db.models.enforcement import EnforcementEvent
    from app.db.session import SessionLocal
    from sqlalchemy import select
    with SessionLocal() as db:
        events = db.scalars(select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id, EnforcementEvent.timestamp >= since)).all()
    facts = safe_correlated_event_diagnostic(events, tenant_id=tenant_id, session_id=session_id, since=since, seen=seen)
    matches = []
    for event in events:
        actions = event.final_actions if isinstance(event.final_actions, dict) else {}
        mcp = actions.get("mcp") if isinstance(actions.get("mcp"), dict) else {}
        when = event.timestamp
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if event.id not in seen and when is not None and when >= since and mcp.get("session_id") == session_id and mcp.get("tool_name") == TOOL_NAME:
            matches.append(event)
    event = max(matches, key=lambda item: item.timestamp) if matches else None
    validation = (event.final_actions or {}).get("mcp", {}).get("session_validation", {}) if event else {}
    reason = validation.get("reason") if isinstance(validation, dict) else None
    return {
        **facts,
        "event_id_hash": digest(str(event.id)) if event else None,
        "evidence_id_hash": digest(str(event.evidence_nodes_created[0])) if event and event.evidence_nodes_created else None,
        "session_validation_reason": reason if isinstance(reason, str) and reason in EVENT_REASON_TOKENS else "other" if reason else "none",
    }


def validate_claude_failure_snapshot(snapshot: dict) -> None:
    keys = {"status", "reason", "completed_phases", "current_phase_index", "current_run_id_hash", "safe_client_facts", "safe_client_timeline", "stderr_category", "safe_correlated_event_projection", "completed_runs", "child_call_count", "release_ready"}
    if not isinstance(snapshot, dict) or set(snapshot) != keys or snapshot.get("status") != "blocked" or snapshot.get("release_ready") is not False:
        raise ValueError("claude_failure_snapshot_invalid")
    if snapshot["reason"] not in {"client_timeout", "client_stdout_oversized", "client_stderr_oversized", "client_stream_invalid", "phase_validation_failed"}:
        raise ValueError("claude_failure_snapshot_invalid")
    if not isinstance(snapshot["completed_phases"], list) or len(snapshot["completed_phases"]) > 5 or any(item not in {"isolated_api_ready", "public_preflight", "client_run_1", "client_run_2", "client_run_3"} for item in snapshot["completed_phases"]):
        raise ValueError("claude_failure_snapshot_invalid")
    index = snapshot["current_phase_index"]
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= 3:
        raise ValueError("claude_failure_snapshot_invalid")
    for value in (snapshot["current_run_id_hash"],):
        if value is not None and (not isinstance(value, str) or not HASH.fullmatch(value)):
            raise ValueError("claude_failure_snapshot_invalid")
    if snapshot["stderr_category"] not in CLAUDE_STDERR_CATEGORIES:
        raise ValueError("claude_failure_snapshot_invalid")
    facts = snapshot["safe_client_facts"]
    allowed_facts = {"exit_code", "result_subtype", "is_error", "prose_code", "stop_reason", "num_turns", "mcp_status", "exact_tool_advertised", "exact_tool_use_count", "hook_event_count", "hook_error_count", "permission_denial_count", "total_cost_usd", "stderr_category", "diagnostic_headline"}
    if not isinstance(facts, dict) or not set(facts).issubset(allowed_facts) or not {"exit_code", "result_subtype", "prose_code", "mcp_status", "exact_tool_advertised", "exact_tool_use_count", "stderr_category"}.issubset(facts):
        raise ValueError("claude_failure_snapshot_invalid")
    if facts["mcp_status"] not in CLAUDE_CONNECTION_STATES | {"other"} or facts["stderr_category"] not in CLAUDE_STDERR_CATEGORIES:
        raise ValueError("claude_failure_snapshot_invalid")
    if facts["exit_code"] != "other" and (isinstance(facts["exit_code"], bool) or not isinstance(facts["exit_code"], int) or not 0 <= facts["exit_code"] <= 255):
        raise ValueError("claude_failure_snapshot_invalid")
    if facts["result_subtype"] not in {"success", "error_max_turns", "error_during_execution", "error_max_budget_usd", "missing", "other"} or facts["prose_code"] not in PROSE_CODES | {"other"} or facts.get("stop_reason") not in {"none", "end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal", "other"}:
        raise ValueError("claude_failure_snapshot_invalid")
    if facts.get("is_error") is not None and not isinstance(facts["is_error"], bool):
        raise ValueError("claude_failure_snapshot_invalid")
    if isinstance(facts.get("num_turns"), bool) or facts.get("num_turns") != "other" and (not isinstance(facts.get("num_turns"), int) or not 0 <= facts["num_turns"] <= 10000):
        raise ValueError("claude_failure_snapshot_invalid")
    for key in ("exact_tool_use_count", "hook_event_count", "hook_error_count", "permission_denial_count"):
        if facts.get(key) != "other" and (isinstance(facts.get(key), bool) or not isinstance(facts.get(key), int) or not 0 <= facts[key] <= 10000):
            raise ValueError("claude_failure_snapshot_invalid")
    cost = facts.get("total_cost_usd")
    if cost != "other" and (isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or not 0 <= cost <= MAX_CLAUDE_COST_USD):
        raise ValueError("claude_failure_snapshot_invalid")
    if facts["exact_tool_advertised"] is not None and not isinstance(facts["exact_tool_advertised"], bool):
        raise ValueError("claude_failure_snapshot_invalid")
    if "diagnostic_headline" in facts and private_diagnostic_headline(facts["diagnostic_headline"]) != facts["diagnostic_headline"]:
        raise ValueError("claude_failure_snapshot_invalid")
    timeline = snapshot["safe_client_timeline"]
    if not isinstance(timeline, list) or len(timeline) > 16:
        raise ValueError("claude_failure_snapshot_invalid")
    previous_order = 0
    for item in timeline:
        if not isinstance(item, dict) or set(item) != {"event_order", "status", "value_type", "exact_tool_advertised"}:
            raise ValueError("claude_failure_snapshot_invalid")
        if isinstance(item["event_order"], bool) or not isinstance(item["event_order"], int) or item["event_order"] <= previous_order or item["status"] not in CLAUDE_CONNECTION_STATES or item["value_type"] not in CLAUDE_VALUE_TYPES or not isinstance(item["exact_tool_advertised"], bool):
            raise ValueError("claude_failure_snapshot_invalid")
        previous_order = item["event_order"]
    event = snapshot["safe_correlated_event_projection"]
    event_keys = {"event_present", "decision", "evidence_present", "reasons", "final_reason", "guardian_codes", "event_id_hash", "evidence_id_hash", "session_validation_reason"}
    if not isinstance(event, dict) or set(event) != event_keys or not isinstance(event["event_present"], bool) or not isinstance(event["evidence_present"], bool) or event["decision"] not in {"none", "allow", "block", "warn", "hold_for_approval", "other"} or event["final_reason"] not in EVENT_REASON_TOKENS | {"none", "other"} or event["session_validation_reason"] not in EVENT_REASON_TOKENS | {"none", "other"}:
        raise ValueError("claude_failure_snapshot_invalid")
    if not isinstance(event["reasons"], list) or len(event["reasons"]) > 8 or any(item not in EVENT_REASON_TOKENS | {"other"} for item in event["reasons"]) or not isinstance(event["guardian_codes"], list) or len(event["guardian_codes"]) > 8 or any(item not in {f"{guardian}_{decision}" for guardian in GUARDIAN_IDS | {"other"} for decision in {"allow", "block", "warn", "hold_for_approval", "other"}} for item in event["guardian_codes"]):
        raise ValueError("claude_failure_snapshot_invalid")
    for item in (event["event_id_hash"], event["evidence_id_hash"]):
        if item is not None and (not isinstance(item, str) or not HASH.fullmatch(item)):
            raise ValueError("claude_failure_snapshot_invalid")
    completed = snapshot["completed_runs"]
    if not isinstance(completed, list) or len(completed) > 3:
        raise ValueError("claude_failure_snapshot_invalid")
    for run in completed:
        run_keys = {"run_id_hash", "event_id_hash", "evidence_id_hash", "decision", "child_call_count", "client_result_subtype", "stop_reason", "num_turns", "total_cost_usd", "prose_code", "mcp_status", "exact_tool_advertised", "exact_tool_use_count", "permission_denial_count"}
        cost = run.get("total_cost_usd") if isinstance(run, dict) else None
        if not isinstance(run, dict) or set(run) != run_keys or any(not isinstance(run.get(key), str) or not HASH.fullmatch(run[key]) for key in ("run_id_hash", "event_id_hash", "evidence_id_hash")) or run["decision"] not in {"allow", "block"} or isinstance(run["child_call_count"], bool) or not isinstance(run["child_call_count"], int) or not 0 <= run["child_call_count"] <= 10000 or run["mcp_status"] != "connected" or run["exact_tool_advertised"] is not True or run["exact_tool_use_count"] != 1 or run["permission_denial_count"] != 0 or run["client_result_subtype"] != "success" or run["prose_code"] not in PROSE_CODES or run["stop_reason"] not in {"none", "end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal"} or isinstance(run["num_turns"], bool) or not isinstance(run["num_turns"], int) or not 0 <= run["num_turns"] <= 100 or isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or not 0 <= cost <= MAX_CLAUDE_COST_USD:
            raise ValueError("claude_failure_snapshot_invalid")
    count = snapshot["child_call_count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 10000:
        raise ValueError("claude_failure_snapshot_invalid")
    _no_raw_fields(snapshot)


def build_claude_failure_snapshot(*, reason: str, completed_phases: list[str], current_phase_index: int, current_run_id_hash: str | None, client: dict, completed_runs: list[dict], child_call_count: int, event_projection: dict, include_headline: bool) -> dict:
    safe_client = {**client, "include_diagnostic_headline": include_headline}
    snapshot = {
        "status": "blocked",
        "reason": reason if reason in {"client_timeout", "client_stdout_oversized", "client_stderr_oversized", "client_stream_invalid"} else "phase_validation_failed",
        "completed_phases": list(completed_phases),
        "current_phase_index": current_phase_index,
        "current_run_id_hash": current_run_id_hash,
        "safe_client_facts": safe_claude_failure_diagnostic(None, safe_client),
        "safe_client_timeline": list(client.get("connection_timeline") or []),
        "stderr_category": client.get("stderr_category") if client.get("stderr_category") in CLAUDE_STDERR_CATEGORIES else "other",
        "safe_correlated_event_projection": event_projection,
        "completed_runs": [{key: run[key] for key in ("run_id_hash", "event_id_hash", "evidence_id_hash", "decision", "child_call_count", "client_result_subtype", "stop_reason", "num_turns", "total_cost_usd", "prose_code", "mcp_status", "exact_tool_advertised", "exact_tool_use_count", "permission_denial_count")} for run in completed_runs],
        "child_call_count": child_call_count,
        "release_ready": False,
    }
    validate_claude_failure_snapshot(snapshot)
    return snapshot


def _record_claude_failure_progress(**facts) -> None:
    global _CLAUDE_FAILURE_PROGRESS
    _CLAUDE_FAILURE_PROGRESS = build_claude_failure_snapshot(**facts)


def official_sdk_command(node: str, config: Path, note: str) -> list[str]:
    if not OFFICIAL_SDK_CLIENT.is_file() or not re.fullmatch(r"[a-z0-9-]{1,40}", note):
        raise ValueError("official_sdk_client_or_note_invalid")
    return [node, str(OFFICIAL_SDK_CLIENT), str(config), note]


def run_official_sdk_bounded(command: list[str], *, cwd: Path, timeout: float = 40) -> dict:
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
    chunks: list[bytes] = []
    size = 0
    deadline = time.monotonic() + timeout
    try:
        assert process.stdout is not None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("official_sdk_client_timeout")
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 0.5))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_SDK_OUTPUT_BYTES:
                raise ValueError("official_sdk_output_empty_or_oversized")
            chunks.append(chunk)
        process.wait(timeout=max(1, deadline - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError("official_sdk_client_failed")
        return parse_official_sdk_result(b"".join(chunks))
    except (TimeoutError, subprocess.TimeoutExpired):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        raise RuntimeError("official_sdk_client_timeout") from None
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()


def validate_official_sdk_report(report: dict) -> None:
    _no_raw_fields(report)
    if set(report) != {"client", "client_version", "runs", "release_ready"} or report["client"] != "official-mcp-typescript-sdk" or report["client_version"] != OFFICIAL_SDK_VERSION or report["release_ready"] is not False:
        raise ValueError("official_sdk_report_identity_or_promotion_invalid")
    runs = report["runs"]
    if not isinstance(runs, list) or len(runs) != 3:
        raise ValueError("three_fresh_sdk_connections_required")
    if [run.get("decision") for run in runs] != ["allow", "allow", "block"] or [run.get("child_call_count") for run in runs] != [1, 2, 2]:
        raise ValueError("sdk_allow_reconnect_revoke_sequence_required")
    if runs[2].get("reason") != "agent_session_revoked":
        raise ValueError("sdk_exact_revocation_required")
    for key in ("run_id_hash", "evidence_id_hash", "event_id_hash"):
        values = [run.get(key) for run in runs]
        if any(not isinstance(value, str) or not HASH.fullmatch(value) for value in values) or len(set(values)) != 3:
            raise ValueError("sdk_distinct_correlated_evidence_required")
    for index, run in enumerate(runs):
        expected = {"run_id_hash", "evidence_id_hash", "event_id_hash", "decision", "child_call_count", "connected", "exact_tool_advertised", "exact_schema", "call_status", "is_error", "correlated_event"}
        if index == 2:
            expected.add("reason")
        if set(run) != expected or run["connected"] is not True or run["exact_tool_advertised"] is not True or run["exact_schema"] is not True or run["correlated_event"] is not True:
            raise ValueError("sdk_exact_tool_and_correlation_required")
        if index < 2 and (run["call_status"] != "returned" or run["is_error"] is not False):
            raise ValueError("sdk_allowed_call_not_proven")
        if index == 2 and not (run["call_status"] == "failed" or run["call_status"] == "returned" and run["is_error"] is True):
            raise ValueError("sdk_denied_call_not_proven")


def write_codex_private_wrapper(directory: Path, config: Path) -> Path:
    """Bridge a private MCP config to Codex without putting authority in CLI args."""
    validate_private_paths(directory, directory / "postgres-data", config)
    if not config.is_file():
        raise ValueError("private_mcp_config_required")
    wrapper = directory / "codex-mcp-wrapper.py"
    if wrapper.exists():
        raise ValueError("private_codex_wrapper_already_exists")
    source = f"""#!{sys.executable}
import json
import os
from pathlib import Path
config = json.loads(Path(__file__).with_name('private-mcp.json').read_text())
server = config['mcpServers']['hawk_lab']
environment = os.environ.copy()
environment.update(server['env'])
os.execvpe(server['command'], [server['command'], *server['args']], environment)
"""
    descriptor = os.open(wrapper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(source)
    return wrapper


def codex_other_server_names(config_home: Path) -> list[str]:
    path = config_home / "config.toml"
    if not path.is_file():
        return []
    data = tomllib.loads(path.read_text())
    servers = data.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ValueError("codex_mcp_config_invalid")
    names = list(servers)
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) for name in names):
        raise ValueError("codex_mcp_server_name_invalid")
    if "hawk_lab" in names:
        raise ValueError("saved_hawk_lab_config_collision")
    return sorted(names)


def codex_command(binary: str, *, wrapper: Path, directory: Path, note: str, other_servers: list[str]) -> list[str]:
    if not wrapper.is_file() or stat.S_IMODE(wrapper.stat().st_mode) != 0o700 or directory not in wrapper.resolve().parents or not re.fullmatch(r"[a-z0-9-]{1,40}", note):
        raise ValueError("private_codex_client_contract_invalid")
    if len(other_servers) != len(set(other_servers)) or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) or name == "hawk_lab" for name in other_servers):
        raise ValueError("codex_other_server_names_invalid")
    prompt = f'Call {CODEX_TOOL} exactly once with JSON arguments {{"note":"{note}"}}. Do not call any other tool. Return no prose.'
    command = [binary, "exec", "--ephemeral", "--json", "--sandbox", "read-only", "--skip-git-repo-check", "-C", str(directory)]
    for name in other_servers:
        command.extend(["-c", f'mcp_servers.{name}.enabled=false'])
    command.extend(["-c", f'mcp_servers.hawk_lab.command={json.dumps(sys.executable)}', "-c", f'mcp_servers.hawk_lab.args={json.dumps([str(wrapper)])}', "-c", 'mcp_servers.hawk_lab.enabled_tools=["read_demo_marker"]', "-c", "mcp_servers.hawk_lab.required=true", "-c", 'mcp_servers.hawk_lab.tools.read_demo_marker.approval_mode="approve"', prompt])
    return command


def private_diagnostic_headline(raw: object, *, known_values: tuple[str, ...] = ()) -> str:
    """One-use local diagnostic, never included in a client or product report."""
    value = raw[:4096] if isinstance(raw, str) else ""
    for secret in known_values:
        if isinstance(secret, str) and len(secret) >= 4:
            value = value.replace(secret, " REDACTED ")
    value = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value)
    value = re.sub(r"(?i)bearer\s+\S+|(?:token|key|secret|password|authorization)\s*[=:]\s*\S+", " REDACTED ", value)
    value = re.sub(r"(?i)https?://\S+|/Users/\S+|/private/\S+|[\w.+-]+@[\w.-]+|\b[A-Za-z0-9_+/=-]{24,}\b", " REDACTED ", value)
    allowed = frozenset("error failed failure invalid config configuration parse parsing override option argument usage required missing unsupported auth authentication login logged credential credentials permission denied sandbox model provider unavailable network connection timeout timed out mcp server startup tool working directory cwd could not cannot unable to load initialize issue internal request response keychain access status policy hooks hook command codex exec system api rate limit exceeded account session forbidden unauthorized expected actual format toml field value unknown type list object string bool boolean null true false redacted transport closed disconnected revoked approved blocked allowed resource read only synthetic".split())
    words = re.findall(r"[A-Za-z][A-Za-z0-9_-]*", value)[:50]
    return " ".join(word.lower() if word.lower() in allowed else "redacted" for word in words)[:240] or "none"


def safe_claude_failure_diagnostic(exit_code: object, client: dict) -> dict:
    """Project one failing Claude result to bounded facts and a safe headline."""
    bounded_exit = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) and 0 <= exit_code <= 255 else "other"
    subtype = client.get("result_subtype")
    if subtype not in {"success", "error_max_turns", "error_during_execution", "error_max_budget_usd", "missing"}:
        subtype = "other"
    is_error = client.get("is_error") if isinstance(client.get("is_error"), bool) else None
    prose = client.get("prose_code")
    if prose not in PROSE_CODES:
        prose = "other"
    mcp_status = client.get("mcp_status")
    if mcp_status not in CLAUDE_CONNECTION_STATES:
        mcp_status = "other"
    advertised = client.get("exact_tool_advertised")
    if not isinstance(advertised, bool):
        advertised = None

    def bounded_count(value: object):
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10000 else "other"

    cost = client.get("total_cost_usd")
    if isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or not 0 <= cost <= MAX_CLAUDE_COST_USD:
        cost = "other"
    else:
        cost = round(float(cost), 5)
    return {
        "exit_code": bounded_exit,
        "result_subtype": subtype,
        "is_error": is_error,
        "prose_code": prose,
        "stop_reason": client.get("stop_reason") if client.get("stop_reason") in {"none", "end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal"} else "other",
        "num_turns": bounded_count(client.get("num_turns")),
        "mcp_status": mcp_status,
        "exact_tool_advertised": advertised,
        "exact_tool_use_count": bounded_count(client.get("exact_tool_use_count")),
        "hook_event_count": bounded_count(client.get("hook_event_count")),
        "hook_error_count": bounded_count(client.get("hook_error_count")),
        "permission_denial_count": bounded_count(client.get("permission_denial_count")),
        "total_cost_usd": cost,
        "stderr_category": client.get("stderr_category") if client.get("stderr_category") in CLAUDE_STDERR_CATEGORIES else "other",
        **({"diagnostic_headline": private_diagnostic_headline(client.get("diagnostic_headline"))} if client.get("include_diagnostic_headline") is True else {}),
    }


def safe_codex_error_facts(call: dict) -> tuple[dict, str]:
    raw_error = call.get("error")
    error = raw_error if isinstance(raw_error, dict) else {}
    raw_code = error.get("code")
    code = raw_code if isinstance(raw_code, int) and not isinstance(raw_code, bool) and -32768 <= raw_code <= 32767 else None
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    hawk = next((data[key] for key in ("ai.hawk/error", "ai.hawk/governance") if isinstance(data.get(key), dict)), {})
    raw_reason = hawk.get("reason")
    reason = raw_reason if isinstance(raw_reason, str) and raw_reason in EVENT_REASON_TOKENS else "other" if raw_reason else "none"
    raw_decision = hawk.get("decision")
    decision = raw_decision if isinstance(raw_decision, str) and raw_decision in {"allow", "block", "warn", "hold_for_approval"} else "other" if raw_decision else "none"
    raw_status = hawk.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status in {"allowed", "blocked", "denied", "error", "fail_secure"} else "other" if raw_status else "none"
    correlation = hawk.get("correlation_id")
    try:
        correlation_valid = isinstance(correlation, str) and str(uuid.UUID(correlation)) == correlation.lower()
    except ValueError:
        correlation_valid = False
    message = raw_error if isinstance(raw_error, str) else error.get("message")
    return {"mcp_error_code": code, "hawk_reason": reason, "hawk_decision": decision, "hawk_status": status, "correlation_id_valid": correlation_valid}, message if isinstance(message, str) else ""


def parse_codex_stream(data: bytes) -> dict:
    if not data or len(data) > MAX_CODEX_STREAM_BYTES:
        raise ValueError("codex_stream_empty_or_oversized")
    tool_count = 0
    failed_count = 0
    turn_completed = False
    turn_failed = False
    error_facts = {"mcp_error_code": None, "hawk_reason": "none", "hawk_decision": "none", "hawk_status": "none", "correlation_id_valid": False}
    private_error_text = ""
    for line in data.splitlines():
        if not line or len(line) > 65536:
            raise ValueError("codex_stream_malformed")
        try:
            item = json.loads(line)
        except (UnicodeError, ValueError):
            raise ValueError("codex_stream_malformed") from None
        if not isinstance(item, dict) or not isinstance(item.get("type"), str):
            raise ValueError("codex_stream_malformed")
        if item["type"] == "turn.completed":
            turn_completed = True
        if item["type"] == "turn.failed":
            turn_failed = True
        if item["type"] in {"item.completed", "item.failed"}:
            call = item.get("item")
            if not isinstance(call, dict) or call.get("type") != "mcp_tool_call":
                continue
            server = call.get("server")
            tool = call.get("tool")
            if not isinstance(server, str) or not isinstance(tool, str):
                raise ValueError("codex_mcp_call_schema_invalid")
            if (server, tool) != ("hawk_lab", TOOL_NAME):
                raise ValueError("codex_unrelated_mcp_tool_called")
            tool_count += 1
            if item["type"] == "item.failed" or call.get("status") in {"failed", "error"}:
                failed_count += 1
                error_facts, private_error_text = safe_codex_error_facts(call)
    return {"exact_tool_call_count": tool_count, "failed_tool_call_count": failed_count, "turn_completed": turn_completed, "turn_failed": turn_failed, **error_facts, "diagnostic_headline": private_diagnostic_headline(private_error_text)}


def classify_codex_stderr(data: bytes) -> str:
    value = data[:MAX_CODEX_STDERR_BYTES].lower()
    phrases = (
        ("config_invalid", (b"failed to load config", b"error parsing config", b"invalid configuration", b"configuration error", b"config parse error")),
        ("auth_required", (b"authentication required", b"login required", b"not logged in", b"unauthorized")),
        ("mcp_startup_failed", (b"mcp server failed", b"failed to start mcp", b"mcp startup failed")),
        ("model_unavailable", (b"model unavailable", b"model not found")),
        ("rate_limited", (b"rate limit", b"too many requests")),
        ("permission_denied", (b"permission denied", b"not permitted")),
        ("network_unavailable", (b"network error", b"connection refused", b"dns failure")),
        ("cli_usage_error", (b"usage:", b"unrecognized option", b"unexpected argument")),
    )
    return next((category for category, markers in phrases if any(marker in value for marker in markers)), "other")


def run_codex_bounded(command: list[str], *, cwd: Path, timeout: float = 180, allow_nonzero_structured: bool = False) -> tuple[int, dict]:
    try:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        raise RuntimeError("codex_client_spawn_failed") from None
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + timeout
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("codex_client_timeout")
            ready, _, _ = select.select(list(streams), [], [], min(remaining, 0.5))
            for stream in ready:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    del streams[stream]
                    continue
                name = streams[stream]
                sizes[name] += len(chunk)
                if sizes[name] > (MAX_CODEX_STREAM_BYTES if name == "stdout" else MAX_CODEX_STDERR_BYTES):
                    raise RuntimeError(f"codex_client_{name}_oversized")
                chunks[name].append(chunk)
        code = process.wait(timeout=max(1, deadline - time.monotonic()))
        output = b"".join(chunks["stdout"])
        error_category = classify_codex_stderr(b"".join(chunks["stderr"]))
        state = "present" if output else "empty"
        if not output or code != 0 and not allow_nonzero_structured:
            raise RuntimeError(f"codex_client_exit_{code if 0 <= code <= 255 else 'other'}_stdout_{state}_stderr_{error_category}")
        try:
            facts = parse_codex_stream(output)
        except ValueError:
            raise RuntimeError(f"codex_client_exit_{code}_stdout_malformed_stderr_{error_category}") from None
        return code, facts
    except TimeoutError:
        raise RuntimeError("codex_client_exit_other_stdout_empty_stderr_timeout") from None
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def validate_codex_report(report: dict) -> None:
    _no_raw_fields(report)
    if set(report) != {"client", "client_version", "runs", "release_ready"} or report["client"] != "codex-cli" or not re.fullmatch(r"\d+\.\d+\.\d+", str(report["client_version"])) or report["release_ready"] is not False:
        raise ValueError("codex_local_report_identity_or_promotion_invalid")
    runs = report["runs"]
    if not isinstance(runs, list) or len(runs) != 3 or [run.get("decision") for run in runs] != ["allow", "allow", "block"] or [run.get("child_call_count") for run in runs] != [1, 2, 2] or runs[2].get("reason") != "agent_session_revoked":
        raise ValueError("codex_allow_reconnect_revoke_sequence_required")
    for key in ("run_id_hash", "event_id_hash", "evidence_id_hash"):
        values = [run.get(key) for run in runs]
        if any(not isinstance(value, str) or not HASH.fullmatch(value) for value in values) or len(set(values)) != 3:
            raise ValueError("codex_distinct_correlated_evidence_required")
    for index, run in enumerate(runs):
        expected = {"run_id_hash", "event_id_hash", "evidence_id_hash", "decision", "child_call_count", "exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed", "correlated_event"}
        if index == 2:
            expected.add("reason")
        if set(run) != expected or run["exact_tool_call_count"] != 1 or run["correlated_event"] is not True:
            raise ValueError("codex_exact_read_tool_and_correlation_required")
        if index < 2 and (run["failed_tool_call_count"] != 0 or run["turn_completed"] is not True or run["turn_failed"] is not False):
            raise ValueError("codex_allowed_call_not_proven")
        if index == 2 and run["failed_tool_call_count"] != 1:
            raise ValueError("codex_revoked_call_not_proven")


def classify_assistant_prose(value: str) -> str:
    text = value[:4096].lower()
    if not text.strip():
        return "none"
    if any(phrase in text for phrase in ("tool is unavailable", "tool isn't available", "tool is not available", "cannot find the tool", "don't have access to the tool", "no such tool")):
        return "tool_unavailable"
    if any(phrase in text for phrase in ("permission denied", "not permitted", "not allowed", "policy prevents", "policy restriction", "access denied")):
        return "permission_or_policy"
    if any(phrase in text for phrase in ("budget exhausted", "budget limit", "maximum cost", "cost limit", "usage limit")):
        return "budget_exhausted"
    if any(phrase in text for phrase in ("i can't help", "i cannot help", "i won't", "i cannot comply", "i'm unable to comply")):
        return "refusal"
    return "prose_without_tool_call"


def _prose_code(current: str, candidate: str) -> str:
    priority = ("none", "prose_without_tool_call", "refusal", "budget_exhausted", "permission_or_policy", "tool_unavailable")
    return candidate if priority.index(candidate) > priority.index(current) else current


def _claude_status(raw: object) -> str:
    if not isinstance(raw, str):
        return "unknown"
    status = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return status if status in CLAUDE_CONNECTION_STATES - {"missing", "unknown"} else "unknown"


def _claude_value_type(raw: object) -> str:
    if raw is None:
        return "null"
    if isinstance(raw, bool):
        return "boolean"
    if isinstance(raw, str):
        return "string"
    if isinstance(raw, (int, float)):
        return "number"
    if isinstance(raw, list):
        return "list"
    return "object"


def classify_claude_stderr(data: bytes) -> str:
    if not data:
        return "none"
    text = data[:MAX_CLAUDE_STDERR_BYTES].decode("utf-8", errors="ignore").lower()
    categories = (
        ("authentication", ("auth", "logged in", "login", "credential", "oauth", "sign in")),
        ("configuration", ("config", "settings", "invalid argument", "unknown option", "parse error")),
        ("timeout", ("timeout", "timed out")),
        ("policy", ("permission", "denied", "policy", "not allowed")),
        ("mcp_startup_transport", ("mcp", "server", "spawn", "connect", "handshake", "transport", "stdio")),
    )
    return next((category for category, tokens in categories if any(token in text for token in tokens)), "other")


def parse_claude_stream(data: bytes, *, allow_incomplete: bool = False) -> dict[str, object]:
    if not data or len(data) > MAX_CLAUDE_STREAM_BYTES:
        raise ValueError("claude_stream_empty_or_oversized")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("claude_stream_malformed") from exc
    if len(lines) > 2000:
        raise ValueError("claude_stream_oversized_event_count")
    exact_tool_count = 0
    permission_denials = 0
    result_subtype = None
    stop_reason = "none"
    turns = None
    cost_usd = None
    prose_code = "none"
    is_error = None
    mcp_status = "missing"
    exact_tool_advertised = False
    seen_tool_ids: set[str] = set()
    hook_event_count = 0
    hook_error_count = 0
    diagnostic_headline = "none"
    connection_timeline: list[dict[str, object]] = []
    for event_order, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(line) > 131_072:
            raise ValueError("claude_stream_oversized_event")
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise ValueError("claude_stream_malformed") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError("claude_stream_malformed")
        event_type = event["type"]
        if event_type == "system" and event.get("subtype") == "init":
            servers = event.get("mcp_servers", [])
            tools = event.get("tools", [])
            if not isinstance(servers, list) or not isinstance(tools, list):
                raise ValueError("claude_stream_malformed_init")
            for server in servers:
                if not isinstance(server, dict):
                    raise ValueError("claude_stream_malformed_init")
                if server.get("name") != "hawk_lab":
                    continue
                status = server.get("status")
                mcp_status = _claude_status(status)
                server_tools = server.get("tools", [])
                if not isinstance(server_tools, list):
                    raise ValueError("claude_stream_malformed_init")
                advertised = any(
                    item == EXACT_TOOL or (isinstance(item, dict) and item.get("name") == EXACT_TOOL)
                    for item in [*tools, *server_tools]
                )
                exact_tool_advertised = advertised
                connection_timeline.append({
                    "event_order": event_order,
                    "status": mcp_status,
                    "value_type": _claude_value_type(status),
                    "exact_tool_advertised": advertised,
                })
                if len(connection_timeline) > 16:
                    raise ValueError("claude_stream_oversized_connection_timeline")
            exact_tool_advertised = exact_tool_advertised or any(item == EXACT_TOOL or (isinstance(item, dict) and item.get("name") == EXACT_TOOL) for item in tools)
        elif event_type == "assistant":
            message = event.get("message") or {}
            content = message.get("content") or [] if isinstance(message, dict) else []
            if not isinstance(content, list):
                raise ValueError("claude_stream_malformed")
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    prose = block.get("text")
                    if not isinstance(prose, str):
                        raise ValueError("claude_stream_malformed_assistant_text")
                    prose_code = _prose_code(prose_code, classify_assistant_prose(prose))
                if not isinstance(block, dict) or block.get("type") != "tool_use" or block.get("name") != EXACT_TOOL:
                    continue
                tool_id = block.get("id")
                if isinstance(tool_id, str) and tool_id:
                    if tool_id in seen_tool_ids:
                        continue
                    seen_tool_ids.add(tool_id)
                exact_tool_count += 1
        elif event_type == "result":
            if result_subtype is not None:
                raise ValueError("claude_stream_duplicate_result")
            subtype = event.get("subtype")
            if not isinstance(subtype, str) or not re.fullmatch(r"[a-z_]{1,40}", subtype):
                raise ValueError("claude_stream_malformed_result")
            if subtype not in {"success", "error_max_turns", "error_during_execution", "error_max_budget_usd"}:
                raise ValueError("claude_stream_malformed_result")
            result_subtype = subtype
            is_error = event.get("is_error")
            if not isinstance(is_error, bool):
                raise ValueError("claude_stream_is_error_wrong_type")
            result_text = event.get("result", "")
            errors = event.get("errors", [])
            if not isinstance(result_text, str) or len(result_text) > MAX_RESULT_TEXT_CHARS:
                raise ValueError("claude_stream_result_text_invalid")
            if not isinstance(errors, list) or len(errors) > 16 or any(not isinstance(item, str) or len(item) > MAX_RESULT_TEXT_CHARS for item in errors) or sum(len(item) for item in errors) > MAX_RESULT_TEXT_CHARS:
                raise ValueError("claude_stream_errors_invalid")
            prose_code = _prose_code(prose_code, classify_assistant_prose(result_text))
            for item in errors:
                prose_code = _prose_code(prose_code, classify_assistant_prose(item))
            diagnostic_headline = private_diagnostic_headline(errors[0] if errors else result_text)
            raw_stop = event.get("stop_reason")
            if raw_stop is not None:
                if not isinstance(raw_stop, str) or raw_stop not in {"end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal"}:
                    raise ValueError("claude_stream_malformed_stop_reason")
                stop_reason = raw_stop
            turns = event.get("num_turns")
            if isinstance(turns, bool) or not isinstance(turns, int):
                raise ValueError("claude_stream_turns_wrong_type")
            if turns < 0:
                raise ValueError("claude_stream_turns_below_min")
            if turns > 100:
                raise ValueError("claude_stream_turns_above_max")
            cost_usd = event.get("total_cost_usd")
            if isinstance(cost_usd, bool) or not isinstance(cost_usd, (int, float)):
                raise ValueError("claude_stream_cost_wrong_type")
            if not math.isfinite(cost_usd):
                raise ValueError("claude_stream_cost_nonfinite")
            if cost_usd < 0:
                raise ValueError("claude_stream_cost_negative")
            if cost_usd > MAX_CLAUDE_COST_USD:
                raise ValueError("claude_stream_cost_above_cap")
            denials = event.get("permission_denials") or []
            if not isinstance(denials, list):
                raise ValueError("claude_stream_malformed_result")
            permission_denials += len(denials)
        elif event_type == "system" and event.get("subtype") == "permission_denial":
            permission_denials += 1
        elif event_type == "system" and event.get("subtype") in {"hook_started", "hook_response", "hook_completed", "hook_error"}:
            hook_event_count += 1
            if event.get("subtype") == "hook_error" or event.get("status") in {"error", "failed"}:
                hook_error_count += 1
    if result_subtype is None and not allow_incomplete:
        raise ValueError("claude_stream_missing_result")
    return {"result_subtype": result_subtype or "missing", "stop_reason": stop_reason, "num_turns": turns, "total_cost_usd": cost_usd, "prose_code": prose_code, "is_error": is_error, "exact_tool_use_count": exact_tool_count, "permission_denial_count": permission_denials, "mcp_status": mcp_status, "exact_tool_advertised": exact_tool_advertised, "hook_event_count": hook_event_count, "hook_error_count": hook_error_count, "diagnostic_headline": diagnostic_headline, "connection_timeline": connection_timeline}


def read_synthetic_tool_contract() -> dict:
    node = shutil.which("node")
    if not node or not CHILD.is_file():
        raise ValueError("synthetic_mcp_tool_contract_unavailable")
    try:
        result = subprocess.run([node, str(CHILD), "--print-contract"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True)
        if len(result.stdout) > 8192:
            raise ValueError
        contract = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError("synthetic_mcp_tool_contract_unavailable") from None
    return contract


def build_exact_tool_prompt(note: str) -> str:
    contract = read_synthetic_tool_contract()
    tool = contract.get("tool") if isinstance(contract, dict) else None
    schema = tool.get("inputSchema") if isinstance(tool, dict) else None
    properties = schema.get("properties") if isinstance(schema, dict) else None
    note_schema = properties.get("note") if isinstance(properties, dict) else None
    if not isinstance(tool, dict) or tool.get("name") != TOOL_NAME or not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("required") != ["note"] or schema.get("additionalProperties") is not False or list(properties or {}) != ["note"] or not isinstance(note_schema, dict) or note_schema.get("type") != "string" or note_schema.get("maxLength") != 64:
        raise ValueError("synthetic_mcp_tool_contract_invalid")
    if not isinstance(note, str) or not re.fullmatch(r"[a-z0-9-]{1,40}", note):
        raise ValueError("synthetic_mcp_note_invalid")
    arguments = json.dumps({"note": note}, separators=(",", ":"))
    return f"Call {EXACT_TOOL} exactly once with JSON arguments {arguments}. Do not call any other tool. Return no prose."


def capture_local_username() -> str:
    user_name = os.environ.get("USER")
    if not isinstance(user_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", user_name):
        raise RuntimeError("local_user_name_invalid")
    return user_name


class ClaudeClientExecutionError(RuntimeError):
    def __init__(self, reason: str, *, facts: dict, stderr_category: str, child_call_count: int):
        super().__init__(f"claude_client_{reason}")
        self.facts = facts
        self.stderr_category = stderr_category
        self.child_call_count = child_call_count


def _partial_claude_facts(data: bytes) -> dict:
    try:
        return parse_claude_stream(data, allow_incomplete=True)
    except (ValueError, TypeError):
        return {
            "result_subtype": "missing", "stop_reason": "none", "num_turns": None,
            "total_cost_usd": None, "prose_code": "none", "is_error": None,
            "exact_tool_use_count": 0, "permission_denial_count": 0, "mcp_status": "missing",
            "exact_tool_advertised": False, "hook_event_count": 0, "hook_error_count": 0,
            "diagnostic_headline": "none", "connection_timeline": [],
        }


def run_claude_bounded(command: list[str], *, cwd: Path, user_name: str, timeout: float = 120) -> tuple[int, dict]:
    if not isinstance(user_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", user_name):
        raise ValueError("local_user_name_invalid")
    child_env = os.environ.copy()
    child_env["USER"] = user_name
    child_env["MCP_CONNECTION_NONBLOCKING"] = "0"
    child_env["MCP_CONNECT_TIMEOUT_MS"] = CLAUDE_MCP_CONNECT_TIMEOUT_MS
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True, env=child_env)
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + timeout
    reason = "stream_invalid"
    try:
        assert process.stdout is not None and process.stderr is not None
        streams = {process.stdout: "stdout", process.stderr: "stderr"}
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                raise TimeoutError
            ready, _, _ = select.select(list(streams), [], [], min(remaining, 0.5))
            for stream in ready:
                name = streams[stream]
                chunk = os.read(stream.fileno(), 65_536)
                if not chunk:
                    del streams[stream]
                    continue
                limit = MAX_CLAUDE_STREAM_BYTES if name == "stdout" else MAX_CLAUDE_STDERR_BYTES
                remaining_bytes = max(0, limit - sizes[name])
                if len(chunk) > remaining_bytes:
                    if remaining_bytes:
                        chunks[name].append(chunk[:remaining_bytes])
                        sizes[name] += remaining_bytes
                    reason = f"{name}_oversized"
                    raise ValueError
                chunks[name].append(chunk)
                sizes[name] += len(chunk)
        code = process.wait(timeout=max(1, deadline - time.monotonic()))
        stdout = b"".join(chunks["stdout"])
        facts = parse_claude_stream(stdout, allow_incomplete=True)
        facts["stderr_category"] = classify_claude_stderr(b"".join(chunks["stderr"]))
        return code, facts
    except (TimeoutError, ValueError, subprocess.TimeoutExpired) as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            reason = "timeout"
        stderr_category = "timeout" if reason == "timeout" else classify_claude_stderr(b"".join(chunks["stderr"]))
        facts = _partial_claude_facts(b"".join(chunks["stdout"]))
        facts["stderr_category"] = stderr_category
        facts["include_diagnostic_headline"] = "--private-diagnostic-headline" in sys.argv[1:]
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        child_count = _child_count(cwd / "lab")
        raise ClaudeClientExecutionError(reason, facts=facts, stderr_category=stderr_category, child_call_count=child_count) from None
    except BaseException:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def claude_command(binary: str, *, prompt: str, config: Path, diagnostic_without_empty_tools: bool = False) -> list[str]:
    command = [binary, "-p", prompt, "--mcp-config", str(config), "--strict-mcp-config", "--no-session-persistence", "--max-budget-usd", "0.05", "--allowedTools", EXACT_TOOL]
    if not diagnostic_without_empty_tools:
        command.extend(["--tools", ""])
    return [*command, "--permission-mode", "dontAsk", "--output-format", "stream-json", "--verbose"]


def _required(status: int, expected: int, label: str, detail: object = None) -> None:
    if status != expected:
        code = detail.get("code") or detail.get("reason_code") if isinstance(detail, dict) else None
        safe_code = code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_:.-]{1,80}", code) else "unspecified"
        raise RuntimeError(f"{label}_failed_http_{status}_{safe_code}")


def _setup_authority(api: IsolatedHawkApi) -> tuple[dict, str, str, str, str, str]:
    from app.core.security import token_hash
    from app.db.models.ai_iam import AgentIdentity, CapabilityToken
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import BusinessPurposeSession, ToolFingerprint
    from app.db.session import SessionLocal
    from sqlalchemy import select
    from secrets import token_urlsafe

    password = "Password123!"
    status, registered = api.request("POST", "/auth/register", payload={"email": "isolated-mcp-owner@example.com", "password": password, "full_name": "Isolated MCP Owner"})
    _required(status, 200, "register")
    owner = {"tenant_id": registered["tenants"][0]["id"], "user_id": registered["user"]["id"], "access_token": registered["access_token"]}
    headers = {"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]}
    status, system = api.request("POST", "/ai-systems", headers=headers, payload={"name": "Isolated MCP Marker", "description": "synthetic only", "risk_tier": "LOW"})
    _required(status, 200, "ai_system")
    status, _ = api.request("POST", "/policies/packs", headers=headers, payload={"name": "Isolated MCP Policy", "description": "synthetic", "status": "active"})
    _required(status, 200, "policy")
    status, agent = api.request("POST", "/ai-iam/agents", headers=headers, payload={"name": "Isolated MCP Agent", "description": "synthetic", "max_chain_depth": 3, "capability_inheritance": False, "action_scope": ["file_read"], "tool_registry": [TOOL_NAME], "external_system_access": ["unknown"]})
    _required(status, 200, "agent")
    raw_capability = token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        ai_system = db.get(AISystem, system["id"])
        ai_system.status = "active"
        ai_system.metadata_json = {**dict(ai_system.metadata_json or {}), "governance_state": "APPROVED", "lifecycle_state": "ACTIVE"}
        identity = db.get(AgentIdentity, agent["id"])
        identity.owner_attested_at = now - timedelta(minutes=5)
        identity.owner_attestation_expiry = now + timedelta(hours=1)
        db.add(CapabilityToken(tenant_id=owner["tenant_id"], agent_identity_id=agent["id"], ai_system_id=system["id"], token_hash=token_hash(raw_capability), scopes=["file_read"], expires_at=now + timedelta(minutes=20), chain_depth=3, issued_by_user_id=owner["user_id"]))
        db.add(BusinessPurposeSession(tenant_id=owner["tenant_id"], user_id=owner["user_id"], declared_purpose="Synthetic local read proof", purpose_category="testing", business_function="testing", approved_scope={"identity_id": agent["id"], "identity_type": "agent", "purpose": {"name": "synthetic_read"}, "scope": {"allowed_actions": ["file_read"], "allowed_tools": [TOOL_NAME], "allowed_domains": ["unknown"], "allowed_resources": ["unknown"], "allowed_environments": ["production"], "allowed_data_scopes": ["internal"]}, "constraints": {"max_risk_level": "high"}, "context": {"max_chain_depth": 3}, "mode": "block"}, status="active", expires_at=now + timedelta(minutes=20)))
        db.commit()
    tool = read_synthetic_tool_contract()["tool"]
    scan = {"mcp_server_id": "manual-terminal-lab", "tool_name": tool["name"], "tool_version": tool["version"], "description": tool["description"], "schema": tool["inputSchema"], "examples": tool["examples"], "manifest": tool}
    status, _ = api.request("POST", "/gateway/mcp/tools/scan", headers=headers, payload=scan)
    _required(status, 200, "tool_scan")
    with SessionLocal() as db:
        fingerprint = db.scalar(select(ToolFingerprint).where(ToolFingerprint.tenant_id == owner["tenant_id"], ToolFingerprint.mcp_server_id == "manual-terminal-lab", ToolFingerprint.tool_name == TOOL_NAME))
        if fingerprint is None:
            raise RuntimeError("exact_tool_fingerprint_missing")
        fingerprint_id = fingerprint.id
        fingerprint_hash = fingerprint.manifest_hash
    status, approved = api.request("POST", f"/gateway/mcp/tools/fingerprints/{fingerprint_id}/decision", headers=headers, payload={"decision": "approve", "expected_manifest_hash": fingerprint_hash, "reason": "Approve exact synthetic read-only isolated fixture"})
    _required(status, 200, "synthetic_read_fingerprint_approval")
    if approved.get("trust_status") != "approved":
        raise RuntimeError("synthetic_read_fingerprint_not_approved")
    status, session = api.request("POST", "/gateway/mcp/sessions/open", headers=headers, payload={"ai_system_id": system["id"], "agent_id": agent["id"], "capability_token": raw_capability, "expires_minutes": 15, "session_context": SESSION_CONTEXT})
    _required(status, 201, "persisted_session_open", session.get("detail"))
    return owner, system["id"], agent["id"], raw_capability, session["session_id"], fingerprint_id


def _session_event_ids(tenant_id: str) -> set[str]:
    from app.db.models.enforcement import EnforcementEvent
    from app.db.session import SessionLocal
    from sqlalchemy import select
    with SessionLocal() as db:
        return set(db.scalars(select(EnforcementEvent.id).where(EnforcementEvent.tenant_id == tenant_id)).all())


def run_public_authorize_preflight(api: IsolatedHawkApi, *, owner: dict, system_id: str, agent_id: str, capability: str, session_id: str, fingerprint_id: str, note: str) -> dict:
    wire = capture_gateway_authorize_wire({
        "aiSystemId": system_id, "actorId": agent_id, "capabilityToken": capability,
        "mcpServerId": "manual-terminal-lab", "toolName": TOOL_NAME,
        "toolVersion": "1.0.0", "toolFingerprintId": fingerprint_id,
        "argumentsObject": {"note": note}, "chainId": None, "sessionId": session_id,
        "clientApp": None,
    })
    wire["request_id"] = str(__import__("uuid").uuid4())
    started = datetime.now(timezone.utc)
    status, body = api.request("POST", "/gateway/mcp/authorize", headers={"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]}, payload=wire)
    event = current_event_diagnostic(owner["tenant_id"], session_id, started, set())
    decision = body.get("decision") if isinstance(body, dict) else None
    safe_decision = decision if isinstance(decision, str) and decision in {"allow", "block", "warn", "hold_for_approval"} else "other"
    facts = {"stage": "public_authorize_preflight", "http_status": status, "decision": safe_decision, "reason": fixed_preflight_reason(status, body), "correlated_event": event["event_present"], "evidence_present": event["evidence_present"], "final_reason": event["final_reason"], "guardian_codes": event["guardian_codes"], "guardian_reasons": event["reasons"], **safe_policy_projection(body)}
    if status >= 500:
        log = api.root / "logs" / "api.log"
        facts["server_trace"] = sanitize_private_api_trace(log.read_text(errors="replace") if log.is_file() else "")
    return facts


def _event_for_run(tenant_id: str, session_id: str, seen: set[str], decision: str):
    from app.db.models.enforcement import EnforcementEvent
    from app.db.session import SessionLocal
    from sqlalchemy import select
    with SessionLocal() as db:
        events = db.scalars(select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id)).all()
        matches = [event for event in events if event.id not in seen and (event.final_actions or {}).get("mcp", {}).get("session_id") == session_id and (event.final_actions or {}).get("mcp", {}).get("tool_name") == TOOL_NAME and event.final_decision == decision]
        if not matches:
            raise RuntimeError(f"correlated_hawk_{decision}_evidence_missing")
        event = matches[-1]
        seen.add(event.id)
        if not event.evidence_nodes_created:
            raise RuntimeError("hawk_evidence_node_missing")
        return event.id, str(event.evidence_nodes_created[0]), (event.final_actions or {}).get("mcp", {}).get("session_validation", {})


def _child_count(lab: Path) -> int:
    log = lab / "child-events.ndjson"
    if not log.exists():
        return 0
    return sum(json.loads(line).get("method") == "tools/call" for line in log.read_text().splitlines())


def _write_config(path: Path, *, api_url: str, owner: dict, ai_system_id: str, agent_id: str, capability: str, session_id: str, lab: Path) -> None:
    node = shutil.which("node")
    if not node or not PROXY.is_file() or not CHILD.is_file():
        raise RuntimeError("installed_proxy_or_child_missing")
    config = {"mcpServers": {"hawk_lab": {"command": node, "args": [str(PROXY), "--gateway", api_url, "--tenant", owner["tenant_id"], "--ai-system-id", ai_system_id, "--actor-id", agent_id, "--server-id", "manual-terminal-lab", "--session-id", session_id, "--allowed-tools", TOOL_NAME, "--", node, str(CHILD)], "env": {"HAWK_ACCESS_TOKEN": owner["access_token"], "HAWK_CAPABILITY_TOKEN": capability, "HAWK_MCP_LAB_DIR": str(lab), "HAWK_MCP_STDIO_FRAMING": "ndjson"}}}}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(config, stream)


def main() -> int:
    global _CLAUDE_FAILURE_PROGRESS
    _CLAUDE_FAILURE_PROGRESS = None
    official_sdk = "--official-sdk" in sys.argv[1:]
    codex_cli = "--codex-cli" in sys.argv[1:]
    if official_sdk and codex_cli:
        raise ValueError("one_mcp_client_mode_required")
    claude_user_name = capture_local_username() if not official_sdk and not codex_cli else None
    if codex_cli:
        codex = shutil.which("codex")
        if not codex or Path(codex).name != "codex":
            raise RuntimeError("installed_codex_cli_required")
        version_output = subprocess.run([codex, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10, check=True).stdout.strip()
        version_match = re.fullmatch(r"codex-cli (\d+\.\d+\.\d+)", version_output)
        if not version_match:
            raise RuntimeError("exact_codex_cli_version_required")
        version = version_match.group(1)
    elif official_sdk:
        node = shutil.which("node")
        if not node or not OFFICIAL_SDK_CLIENT.is_file():
            raise RuntimeError("installed_official_sdk_client_required")
        package = ROOT / "packages" / "hawk-mcp-proxy" / "node_modules" / "@modelcontextprotocol" / "sdk" / "package.json"
        if not package.is_file() or json.loads(package.read_text()).get("version") != OFFICIAL_SDK_VERSION:
            raise RuntimeError("exact_official_sdk_version_required")
        version = OFFICIAL_SDK_VERSION
    else:
        claude = shutil.which("claude")
        if not claude or Path(claude).name != "claude":
            raise RuntimeError("installed_claude_code_cli_required")
        version = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=10, check=True).stdout.strip().split()[0]
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise RuntimeError("exact_claude_version_required")
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="hawk-mcp-terminal-lab-", dir="/private/tmp") as name:
            directory = Path(name)
            database, config, lab = directory / "postgres-data", directory / "private-mcp.json", directory / "lab"
            lab.mkdir(mode=0o700)
            validate_private_paths(directory, database, config)
            api = IsolatedHawkApi(directory, mcp_sessions=True)
            api.prepare()
            api.start()
            try:
                owner, system_id, agent_id, capability, session_id, fingerprint_id = _setup_authority(api)
                from app.db.session import SessionLocal
                from app.services.fail_secure_service import validate_governance_context
                with SessionLocal() as db:
                    healthy, _ = validate_governance_context(db, tenant_id=owner["tenant_id"], ai_system_id=system_id)
                if not healthy:
                    raise RuntimeError("isolated_governance_preflight_failed")
                if "--preflight" in sys.argv[1:]:
                    print(json.dumps({"status": "ready_for_real_client", "persisted_session": True, "isolated_api": True, "release_ready": False}, sort_keys=True))
                    return 0
                _write_config(config, api_url=api.base_url, owner=owner, ai_system_id=system_id, agent_id=agent_id, capability=capability, session_id=session_id, lab=lab)
                validate_private_paths(directory, database, config)
                preflight = run_public_authorize_preflight(api, owner=owner, system_id=system_id, agent_id=agent_id, capability=capability, session_id=session_id, fingerprint_id=fingerprint_id, note="isolated-mcp-public-preflight")
                if preflight["http_status"] != 200 or preflight["decision"] != "allow" or not preflight["correlated_event"] or not preflight["evidence_present"]:
                    trace = preflight.get("server_trace", {})
                    safe_trace = f"_{trace.get('exception_class', 'none')}_{str(trace.get('module', 'none')).replace('/', '_').replace('.', '_')}_{trace.get('function', 'none')}_{trace.get('line', 0)}" if trace else ""
                    guardians = "-".join(preflight["guardian_codes"]) or "none"
                    guardian_reasons = "-".join(preflight["guardian_reasons"]) or "none"
                    raise RuntimeError(f"public_authorize_preflight_failed_http_{preflight['http_status']}_decision_{preflight['decision']}_reason_{preflight['reason']}_session_{preflight['session_reason']}_bounds_{preflight['session_bounds_reason']}_preaction_{preflight['pre_action_decision']}_{preflight['pre_action_reason']}_final_{preflight['final_reason']}_guardians_{guardians}_guardreasons_{guardian_reasons}_event_{str(preflight['correlated_event']).lower()}_evidence_{str(preflight['evidence_present']).lower()}{safe_trace}")
                if "--public-preflight" in sys.argv[1:]:
                    print(json.dumps({**preflight, "release_ready": False}, sort_keys=True))
                    return 0
                seen: set[str] = _session_event_ids(owner["tenant_id"])
                if codex_cli:
                    wrapper = write_codex_private_wrapper(directory, config)
                    config_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
                    other_servers = codex_other_server_names(config_home)
                runs = []
                if not official_sdk and not codex_cli:
                    _record_claude_failure_progress(
                        reason="phase_validation_failed", completed_phases=["isolated_api_ready", "public_preflight"],
                        current_phase_index=1, current_run_id_hash=None, client=_partial_claude_facts(b""),
                        completed_runs=runs, child_call_count=_child_count(lab),
                        event_projection={"event_present": False, "decision": "none", "evidence_present": False, "reasons": [], "final_reason": "none", "guardian_codes": [], "event_id_hash": None, "evidence_id_hash": None, "session_validation_reason": "none"},
                        include_headline="--private-diagnostic-headline" in sys.argv[1:],
                    )
                for index in range(3):
                    run_id = f"isolated-mcp-{index}-{time.monotonic_ns()}"
                    if official_sdk:
                        run_started_at = datetime.now(timezone.utc)
                        command = official_sdk_command(node, config, run_id[:40])
                        client = run_official_sdk_bounded(command, cwd=directory)
                        exit_code = 0
                    elif codex_cli:
                        run_started_at = datetime.now(timezone.utc)
                        command = codex_command(codex, wrapper=wrapper, directory=directory, note=run_id[:40], other_servers=other_servers)
                        exit_code, client = run_codex_bounded(command, cwd=directory, allow_nonzero_structured=index == 2)
                    else:
                        prompt = build_exact_tool_prompt(run_id[:40]) if "--exact-prompt" in sys.argv[1:] else f"Call only the hawk_lab {TOOL_NAME} MCP tool exactly once with note '{run_id[:40]}'. Do not use any other tool."
                        command = claude_command(claude, prompt=prompt, config=config, diagnostic_without_empty_tools="--diagnostic-without-empty-tools" in sys.argv[1:])
                        run_started_at = datetime.now(timezone.utc)
                        try:
                            exit_code, client = run_claude_bounded(command, cwd=directory, user_name=claude_user_name)
                        except ClaudeClientExecutionError as exc:
                            projection = current_failure_event_projection(owner["tenant_id"], session_id, run_started_at, seen)
                            _record_claude_failure_progress(
                                reason=f"client_{exc.args[0].removeprefix('claude_client_')}",
                                completed_phases=["isolated_api_ready", "public_preflight", *[f"client_run_{n}" for n in range(1, len(runs) + 1)]],
                                current_phase_index=index + 1, current_run_id_hash=digest(run_id), client=exc.facts,
                                completed_runs=runs, child_call_count=exc.child_call_count,
                                event_projection=projection,
                                include_headline="--private-diagnostic-headline" in sys.argv[1:],
                            )
                            raise
                    count = _child_count(lab)
                    if not official_sdk and not codex_cli:
                        client["stderr_category"] = client.get("stderr_category") if client.get("stderr_category") in CLAUDE_STDERR_CATEGORIES else "other"
                        projection = current_failure_event_projection(owner["tenant_id"], session_id, run_started_at, seen)
                        _record_claude_failure_progress(
                            reason="phase_validation_failed",
                            completed_phases=["isolated_api_ready", "public_preflight", *[f"client_run_{n}" for n in range(1, len(runs) + 1)]],
                            current_phase_index=index + 1, current_run_id_hash=digest(run_id), client=client,
                            completed_runs=runs, child_call_count=count, event_projection=projection,
                            include_headline="--private-diagnostic-headline" in sys.argv[1:],
                        )
                    if official_sdk:
                        if client["connected"] is not True or client["exact_tool_advertised"] is not True or client["exact_schema"] is not True:
                            raise RuntimeError(f"official_sdk_run_{index}_exact_tool_not_connected_child_{count}")
                        if index < 2 and (client["call_status"] != "returned" or client["is_error"] is not False):
                            diagnostic = current_event_diagnostic(owner["tenant_id"], session_id, run_started_at, seen)
                            reasons = "-".join(diagnostic["reasons"]) or "none"
                            raise RuntimeError(f"official_sdk_run_{index}_allowed_call_failed_status_{client['call_status']}_error_{str(client['is_error']).lower()}_mcp_{client['mcp_error_code'] if client['mcp_error_code'] is not None else 'none'}_reason_{client['reason_token']}_event_{str(diagnostic['event_present']).lower()}_decision_{diagnostic['decision']}_evidence_{str(diagnostic['evidence_present']).lower()}_reasons_{reasons}_child_{count}")
                        if index == 2 and not (client["call_status"] == "failed" or client["call_status"] == "returned" and client["is_error"] is True):
                            raise RuntimeError(f"official_sdk_run_{index}_revoked_call_not_denied_child_{count}")
                    elif codex_cli:
                        if client["exact_tool_call_count"] != 1 or index < 2 and (exit_code != 0 or client["failed_tool_call_count"] != 0 or client["turn_completed"] is not True or client["turn_failed"] is not False) or index == 2 and client["failed_tool_call_count"] != 1:
                            diagnostic = current_event_diagnostic(owner["tenant_id"], session_id, run_started_at, seen)
                            if "--private-diagnostic-headline" in sys.argv[1:]:
                                print(json.dumps({"private_diagnostic_headline": client["diagnostic_headline"]}, sort_keys=True), file=sys.stderr)
                            guardians = "-".join(diagnostic["guardian_codes"]) or "none"
                            reasons = "-".join(diagnostic["reasons"]) or "none"
                            raise RuntimeError(f"codex_run_{index}_exact_read_call_unproven_exit_{exit_code if 0 <= exit_code <= 255 else 'other'}_tool_{client['exact_tool_call_count']}_failed_{client['failed_tool_call_count']}_turn_{str(client['turn_completed']).lower()}_mcp_{client['mcp_error_code'] if client['mcp_error_code'] is not None else 'none'}_hawk_{client['hawk_status']}_{client['hawk_decision']}_{client['hawk_reason']}_corrvalid_{str(client['correlation_id_valid']).lower()}_event_{str(diagnostic['event_present']).lower()}_{diagnostic['decision']}_{diagnostic['final_reason']}_evidence_{str(diagnostic['evidence_present']).lower()}_guardians_{guardians}_reasons_{reasons}_child_{count}")
                    elif exit_code != 0 or client["result_subtype"] != "success":
                        if "--private-diagnostic-headline" in sys.argv[1:]:
                            safe_diagnostic = safe_claude_failure_diagnostic(exit_code, client)
                            print(json.dumps(safe_diagnostic, sort_keys=True), file=sys.stderr)
                        raise RuntimeError(f"claude_run_{index}_client_unsuccessful_{client['result_subtype']}_child_{count}")
                    if not official_sdk and not codex_cli and client["is_error"] is True:
                        raise RuntimeError(f"claude_run_{index}_client_error_{client['prose_code']}_child_{count}")
                    if not official_sdk and not codex_cli and client["mcp_status"] != "connected":
                        raise RuntimeError(f"claude_run_{index}_hawk_lab_{client['mcp_status']}_child_{count}")
                    if not official_sdk and not codex_cli and client["exact_tool_advertised"] is not True:
                        raise RuntimeError(f"claude_run_{index}_connected_exact_tool_unadvertised_child_{count}")
                    if not official_sdk and not codex_cli and client["permission_denial_count"]:
                        raise RuntimeError(f"claude_run_{index}_exact_tool_permission_denied_child_{count}")
                    if not official_sdk and not codex_cli and client["exact_tool_use_count"] != 1:
                        if "--private-diagnostic-headline" in sys.argv[1:]:
                            print(json.dumps({"private_diagnostic_headline": client["diagnostic_headline"]}, sort_keys=True), file=sys.stderr)
                        raise RuntimeError(f"claude_run_{index}_advertised_exact_tool_not_invoked_{client['prose_code']}_turns_{client['num_turns']}_cost_{client['total_cost_usd']:.5f}_stop_{client['stop_reason']}_result_{client['result_subtype']}_error_{str(client['is_error']).lower()}_hooks_{client['hook_event_count']}_hookerrors_{client['hook_error_count']}_permissiondenials_{client['permission_denial_count']}_child_{count}")
                    expected = "allow" if index < 2 else "block"
                    event_id, evidence_id, validation = _event_for_run(owner["tenant_id"], session_id, seen, expected)
                    if index < 2 and count != index + 1:
                        raise RuntimeError("client_tool_call_not_reaching_child")
                    if index == 2 and (validation or {}).get("reason") != "agent_session_revoked":
                        raise RuntimeError("revoked_session_denial_not_proven")
                    if official_sdk:
                        runs.append({"run_id_hash": digest(run_id), "decision": expected, "evidence_id_hash": digest(evidence_id), "event_id_hash": digest(event_id), "child_call_count": count, "connected": client["connected"], "exact_tool_advertised": client["exact_tool_advertised"], "exact_schema": client["exact_schema"], "call_status": client["call_status"], "is_error": client["is_error"], "correlated_event": True, **({"reason": "agent_session_revoked"} if index == 2 else {})})
                    elif codex_cli:
                        runs.append({"run_id_hash": digest(run_id), "decision": expected, "evidence_id_hash": digest(evidence_id), "event_id_hash": digest(event_id), "child_call_count": count, **{key: client[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")}, "correlated_event": True, **({"reason": "agent_session_revoked"} if index == 2 else {})})
                    else:
                        runs.append({"run_id_hash": digest(run_id), "decision": expected, "evidence_id_hash": digest(evidence_id), "event_id_hash": digest(event_id), "child_call_count": count, "client_result_subtype": client["result_subtype"], "stop_reason": client["stop_reason"], "num_turns": client["num_turns"], "total_cost_usd": client["total_cost_usd"], "prose_code": client["prose_code"], "is_error": client["is_error"], "mcp_status": client["mcp_status"], "exact_tool_advertised": client["exact_tool_advertised"], "exact_tool_use_count": client["exact_tool_use_count"], "permission_denial_count": client["permission_denial_count"], "correlated_event": True, **({"reason": "agent_session_revoked"} if index == 2 else {})})
                    if not official_sdk and not codex_cli:
                        _record_claude_failure_progress(
                            reason="phase_validation_failed",
                            completed_phases=["isolated_api_ready", "public_preflight", *[f"client_run_{n}" for n in range(1, len(runs) + 1)]],
                            current_phase_index=min(index + 2, 3), current_run_id_hash=None, client=_partial_claude_facts(b""),
                            completed_runs=runs, child_call_count=count, event_projection=projection,
                            include_headline="--private-diagnostic-headline" in sys.argv[1:],
                        )
                    if codex_cli and index == 0 and "--first-allow-only" in sys.argv[1:]:
                        print(json.dumps({"status": "first_allow_proven", "client": "codex-cli", "child_call_count": count, "event_id_hash": digest(event_id), "evidence_id_hash": digest(evidence_id), "release_ready": False}, sort_keys=True))
                        return 0
                    if index == 0:
                        api.restart_api()
                        for artifact in (lab / "marker.json", lab / "tool-call-received.json"):
                            artifact.unlink(missing_ok=True)
                    if index == 1:
                        status, revoked = api.request("POST", f"/gateway/mcp/sessions/{session_id}/revoke", headers={"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]})
                        _required(status, 200, "persisted_session_revoke")
                        if revoked.get("status") != "revoked":
                            raise RuntimeError("persisted_session_revoke_not_recorded")
                if official_sdk:
                    report = {"client": "official-mcp-typescript-sdk", "client_version": version, "runs": runs, "release_ready": False}
                    validate_official_sdk_report(report)
                elif codex_cli:
                    report = {"client": "codex-cli", "client_version": version, "runs": runs, "release_ready": False}
                    validate_codex_report(report)
                else:
                    report = {"client": "claude-code", "client_version": version, "binary_hash": hashlib.sha256(Path(claude).read_bytes()).hexdigest(), "runs": runs, "release_ready": False}
                    validate_mcp_report(report)
                print(json.dumps(report, sort_keys=True))
                return 0
            finally:
                api.stop()
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        if _CLAUDE_FAILURE_PROGRESS is not None:
            validate_claude_failure_snapshot(_CLAUDE_FAILURE_PROGRESS)
            print(json.dumps(_CLAUDE_FAILURE_PROGRESS, sort_keys=True))
            raise SystemExit(2)
        print(json.dumps({"status": "blocked", "reason": str(exc).split(":", 1)[0], "release_ready": False}, sort_keys=True))
        raise SystemExit(2)
