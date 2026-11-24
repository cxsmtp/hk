from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from app.core.config import settings
from app.db.models.ai_orchestration import AIReasoningTrace


def build_ticket_payload(*, trace: AIReasoningTrace, system: str) -> dict[str, Any]:
    normalized_system = str(system or "jira").strip().lower()
    if normalized_system not in {"jira", "servicenow"}:
        normalized_system = "jira"

    issue_id = str(trace.issue_id)
    issue_type = str(trace.issue_type)
    guidance = trace.output_json if isinstance(trace.output_json, dict) else {}
    summary = str(guidance.get("summary") or f"Remediation guidance for {issue_type}:{issue_id}")
    root_cause = str(guidance.get("root_cause_hypothesis") or "")
    steps = guidance.get("recommended_steps") if isinstance(guidance.get("recommended_steps"), list) else []

    step_lines: list[str] = []
    for idx, row in enumerate(steps, start=1):
        if not isinstance(row, dict):
            continue
        title = str(row.get("title") or f"Step {idx}").strip()
        desc = str(row.get("description") or "").strip()
        step_lines.append(f"{idx}. {title}: {desc}")

    description = "\n".join(
        part
        for part in [
            f"Issue: {issue_type}:{issue_id}",
            f"Summary: {summary}",
            f"Root cause hypothesis: {root_cause}",
            "Recommended steps:",
            *step_lines,
            f"Trace ID: {trace.id}",
            f"Provider: {trace.provider}/{trace.model}",
            f"Routing policy: {trace.routing_policy_id}",
            f"Evidence refs: {','.join(str(item) for item in (trace.evidence_refs_json or [])) or '-'}",
        ]
        if part
    )

    return {
        "system": normalized_system,
        "title": f"[{str(trace.task_type).upper()}] {issue_type}:{issue_id}",
        "severity": "high" if str(trace.status).lower() != "completed" else "med",
        "description": description,
        "trace_id": trace.id,
        "issue_type": issue_type,
        "issue_id": issue_id,
        "provider": trace.provider,
        "model": trace.model,
        "routing_policy_id": trace.routing_policy_id,
        "policy_route_id": trace.policy_route_id,
    }


def _http_post_json(
    *,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float,
    attempts: int,
) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    last_error = ""
    for attempt in range(1, max(1, attempts) + 1):
        req = urllib_request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib_request.urlopen(req, timeout=timeout) as response:
                text = response.read().decode("utf-8") or "{}"
                return json.loads(text)
        except urllib_error.HTTPError as exc:  # noqa: PERF203
            response_text = ""
            try:
                response_text = exc.read().decode("utf-8")
            except Exception:  # noqa: BLE001
                response_text = ""
            last_error = f"HTTP {exc.code}: {response_text[:300]}"
            if 500 <= int(exc.code) < 600 and attempt < attempts:
                time.sleep(0.2)
                continue
            raise RuntimeError(last_error) from exc
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt < attempts:
                time.sleep(0.2)
                continue
            raise RuntimeError(last_error) from exc
    raise RuntimeError(last_error or "ticket adapter request failed")


def _jira_adapter_enabled() -> bool:
    return bool(
        str(settings.jira_base_url or "").strip()
        and str(settings.jira_user_email or "").strip()
        and str(settings.jira_api_token or "").strip()
    )


def _servicenow_adapter_enabled() -> bool:
    return bool(
        str(settings.servicenow_base_url or "").strip()
        and str(settings.servicenow_username or "").strip()
        and str(settings.servicenow_password or "").strip()
    )


def _create_jira_ticket(payload: dict[str, Any], *, attempts: int) -> dict[str, Any]:
    base_url = str(settings.jira_base_url or "").strip().rstrip("/")
    token = base64.b64encode(
        f"{str(settings.jira_user_email).strip()}:{str(settings.jira_api_token).strip()}".encode("utf-8")
    ).decode("ascii")
    request_payload = {
        "fields": {
            "project": {"key": str(settings.jira_project_key or "SEC").strip() or "SEC"},
            "summary": payload["title"],
            "description": payload["description"],
            "issuetype": {"name": str(settings.jira_issue_type or "Task").strip() or "Task"},
            "labels": ["hawk-ai", "orchestration"],
        }
    }
    response = _http_post_json(
        url=f"{base_url}/rest/api/3/issue",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}",
        },
        payload=request_payload,
        timeout=8.0,
        attempts=attempts,
    )
    issue_key = str(response.get("key") or "").strip()
    return {
        "ticket_id": issue_key or str(response.get("id") or ""),
        "external_url": (
            f"{base_url}/browse/{issue_key}"
            if issue_key
            else str(response.get("self") or "")
        ),
        "provider_response": response,
    }


def _create_servicenow_ticket(payload: dict[str, Any], *, attempts: int) -> dict[str, Any]:
    base_url = str(settings.servicenow_base_url or "").strip().rstrip("/")
    table = str(settings.servicenow_table or "incident").strip() or "incident"
    severity = str(payload.get("severity") or "med").lower()
    impact = "1" if severity in {"critical", "high"} else "2"
    urgency = "1" if severity in {"critical"} else "2"
    request_payload = {
        "short_description": payload["title"],
        "description": payload["description"],
        "category": "security",
        "impact": impact,
        "urgency": urgency,
    }
    auth = base64.b64encode(
        f"{str(settings.servicenow_username).strip()}:{str(settings.servicenow_password).strip()}".encode("utf-8")
    ).decode("ascii")
    response = _http_post_json(
        url=f"{base_url}/api/now/table/{table}",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        },
        payload=request_payload,
        timeout=8.0,
        attempts=attempts,
    )
    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    ticket_number = str(result.get("number") or "").strip()
    sys_id = str(result.get("sys_id") or "").strip()
    return {
        "ticket_id": ticket_number or sys_id,
        "external_url": (
            f"{base_url}/nav_to.do?uri={table}.do?sys_id={sys_id}"
            if sys_id
            else ""
        ),
        "provider_response": response,
    }


def create_ticket(
    *,
    trace: AIReasoningTrace,
    system: str,
    attempts: int = 2,
    final_seam: Callable[[Callable[[], dict[str, Any]]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = build_ticket_payload(trace=trace, system=system)
    normalized_system = payload["system"]
    base = {
        **payload,
        "status": "local_placeholder_only",
        "ticket_id": f"LOCAL-{normalized_system.upper()}-{trace.id[:8]}",
        "external_url": "",
        "error": "",
        "created_externally": False,
    }

    try:
        if normalized_system == "jira":
            if not _jira_adapter_enabled():
                return base
            callback = lambda: _create_jira_ticket(payload, attempts=attempts)
            created = final_seam(callback) if final_seam else callback()
        elif normalized_system == "servicenow":
            if not _servicenow_adapter_enabled():
                return base
            callback = lambda: _create_servicenow_ticket(payload, attempts=attempts)
            created = final_seam(callback) if final_seam else callback()
        else:
            return base
    except Exception as exc:  # noqa: BLE001
        return {
            **base,
            "status": "failed_external_create",
            "ticket_id": "",
            "error": str(exc),
        }

    return {
        **base,
        "status": "created_externally",
        "ticket_id": str(created.get("ticket_id") or ""),
        "external_url": str(created.get("external_url") or ""),
        "provider_response": created.get("provider_response"),
        "created_externally": True,
    }
