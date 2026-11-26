from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings


BROWSER_STEP_KINDS = {"browser_navigate", "browser_prompt_inject", "browser_upload_file"}

_STEP_PROFILE_CATALOG: dict[str, dict[str, str]] = {
    "llm_intercept": {
        "step_type": "intercept",
        "title": "Gateway LLM Intercept",
        "actor": "gateway",
        "target_surface": "gateway",
        "support_status": "executable_now",
        "support_reason": "Gateway interception is wired and callable.",
    },
    "mcp_authorize": {
        "step_type": "policy_eval",
        "title": "MCP Authorization",
        "actor": "ai_iam",
        "target_surface": "gateway",
        "support_status": "executable_now",
        "support_reason": "MCP authorization path is wired and callable.",
    },
    "shadow_event_ingest": {
        "step_type": "ingest",
        "title": "Shadow Event Ingest",
        "actor": "monitoring",
        "target_surface": "monitoring",
        "support_status": "executable_now",
        "support_reason": "Shadow ingest service is available in-process.",
    },
    "monitoring_signal": {
        "step_type": "ingest",
        "title": "Monitoring Signal Ingest",
        "actor": "monitoring",
        "target_surface": "monitoring",
        "support_status": "executable_now",
        "support_reason": "Monitoring ingest service is available in-process.",
    },
    "auditor_snapshot": {
        "step_type": "evaluate",
        "title": "Auditor Snapshot",
        "actor": "auditor",
        "target_surface": "auditor",
        "support_status": "executable_now",
        "support_reason": "Auditor snapshot creation is available in-process.",
    },
    "agent_action_intercept": {
        "step_type": "policy_eval",
        "title": "Agent Action Intercept",
        "actor": "ai_iam",
        "target_surface": "agent",
        "support_status": "executable_now",
        "support_reason": "Runtime agent-action control is wired and callable in-process.",
    },
    "browser_interaction_eval": {
        "step_type": "intercept",
        "title": "Browser Control Evaluation",
        "actor": "browser_extension",
        "target_surface": "browser",
        "support_status": "executable_now",
        "support_reason": (
            "Server-side browser control (the evaluation the Hawk extension calls) runs in-process; "
            "the live Chromium capture leg needs the Playwright browser executor."
        ),
    },
    "browser_navigate": {
        "step_type": "navigate",
        "title": "Browser Navigate",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "Browser executor not configured.",
    },
    "browser_prompt_inject": {
        "step_type": "inject_prompt",
        "title": "Browser Prompt Injection",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "Browser executor not configured.",
    },
    "browser_upload_file": {
        "step_type": "upload_file",
        "title": "Browser File Upload",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "Browser executor not configured.",
    },
    "connector_action": {
        "step_type": "connector_action",
        "title": "Connector Action",
        "actor": "connector",
        "target_surface": "connector",
        "support_status": "not_yet_executable",
        "support_reason": "Connector simulation executor is not implemented yet.",
    },
    "api_gateway_call": {
        "step_type": "api_call",
        "title": "API Gateway Call",
        "actor": "gateway",
        "target_surface": "api",
        "support_status": "not_yet_executable",
        "support_reason": "Dedicated API attack runner is not implemented yet.",
    },
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[5]


def _playwright_runner_script() -> Path:
    return Path(__file__).with_name("playwright_runner.mjs")


def _resolve_playwright_modules_dir() -> Path | None:
    configured = str(os.getenv("SIMULATION_PLAYWRIGHT_NODE_MODULES") or "").strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        return path if path.exists() else None

    default = _repo_root() / "extension" / "node_modules"
    return default if default.exists() else None


def _resolve_extension_dist_dir() -> Path | None:
    configured = str(os.getenv("SIMULATION_HAWK_EXTENSION_DIR") or "").strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        return path if path.exists() else None

    default = _repo_root() / "extension" / "dist"
    return default if default.exists() else None


def _configured_extension_dist_path() -> Path:
    configured = str(os.getenv("SIMULATION_HAWK_EXTENSION_DIR") or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (_repo_root() / "extension" / "dist").resolve()


def _resolve_browser_test_url() -> str:
    return str(os.getenv("SIMULATION_BROWSER_TEST_URL") or "").strip()


def _resolve_hawk_api_url() -> str:
    return str(os.getenv("SIMULATION_HAWK_API_URL") or os.getenv("HAWK_API_URL") or "").strip()


def _resolve_node_binary() -> str | None:
    configured = str(os.getenv("SIMULATION_NODE_BINARY") or "").strip()
    if configured:
        return configured
    return shutil.which("node")


def browser_executor_available() -> tuple[bool, str]:
    if not bool(getattr(settings, "simulation_browser_execution_enabled", False)):
        return False, "Browser automation runner disabled (SIMULATION_BROWSER_EXECUTION_ENABLED is false)."

    script_path = _playwright_runner_script()
    if not script_path.exists():
        return False, f"Playwright runner script missing: {script_path}"

    node_binary = _resolve_node_binary()
    if not node_binary:
        return False, "Node runtime not found in PATH."

    modules_dir = _resolve_playwright_modules_dir()
    if modules_dir is None:
        return False, "Playwright node_modules path not found."

    playwright_package = modules_dir / "playwright"
    if not playwright_package.exists():
        return False, f"Playwright package not found at {playwright_package}"

    extension_dir = _resolve_extension_dist_dir()
    configured_extension_dir = _configured_extension_dist_path()
    if extension_dir is None:
        return False, f"Hawk extension dist not found: {configured_extension_dir}"
    manifest_path = extension_dir / "manifest.json"
    if not manifest_path.exists():
        return False, f"Hawk extension dist missing manifest.json: {extension_dir}"

    api_url = _resolve_hawk_api_url()
    if not api_url:
        return False, "SIMULATION_HAWK_API_URL or HAWK_API_URL is required for browser extension execution."

    test_url = _resolve_browser_test_url()
    if not test_url:
        return False, "SIMULATION_BROWSER_TEST_URL is required for browser extension execution."

    return True, "Browser Playwright executor is available with Hawk extension preflight satisfied."


def step_execution_profile(kind: str, step_id: str) -> dict[str, str]:
    profile = dict(_STEP_PROFILE_CATALOG.get(str(kind or "").strip()) or {})
    if not profile:
        return {
            "step_type": str(kind or "unknown").strip() or "unknown",
            "title": f"Unsupported step kind ({step_id})",
            "actor": "evaluator",
            "target_surface": "unknown",
            "support_status": "not_yet_executable",
            "support_reason": f"Step kind '{kind}' has no executor in simulation orchestrator.",
        }

    if str(kind or "").strip() in BROWSER_STEP_KINDS:
        available, reason = browser_executor_available()
        profile["support_status"] = "executable_now" if available else "not_yet_executable"
        profile["support_reason"] = reason

    return profile


def build_execution_support_matrix(dsl: dict[str, Any]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for index, step in enumerate(dsl.get("steps", []), start=1):
        step_id = str(step.get("step_id") or f"step_{index}")
        kind = str(step.get("kind") or "").strip()
        profile = step_execution_profile(kind, step_id)
        matrix.append(
            {
                "step_id": step_id,
                "step_order": index,
                "step_kind": kind or "unknown",
                "step_type": profile["step_type"],
                "target_surface": profile["target_surface"],
                "support_status": profile["support_status"],
                "support_reason": profile["support_reason"],
            }
        )
    return matrix


def overall_execution_status(matrix: list[dict[str, Any]]) -> str:
    if not matrix:
        return "not_yet_executable"
    statuses = {str(item.get("support_status") or "").strip() for item in matrix}
    if statuses == {"executable_now"}:
        return "executable_now"
    if statuses.issubset({"not_yet_executable"}) or statuses == {"not_yet_executable"}:
        return "not_yet_executable"
    return "partially_executable"


def _simulation_artifacts_root() -> Path:
    configured = str(getattr(settings, "simulation_evidence_dir", "") or "").strip()
    if configured:
        root = Path(configured)
    else:
        root = Path("./evidence")
    if not root.is_absolute():
        root = (_repo_root() / root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_slug(value: str, *, fallback: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(value or "").strip())
    cleaned = cleaned.strip("_")
    return cleaned or fallback


def run_browser_step(
    *,
    kind: str,
    payload: dict[str, Any],
    tenant_id: str,
    simulation_run_id: str,
    step_id: str,
    iteration_index: int,
) -> dict[str, Any]:
    profile = step_execution_profile(kind, step_id)
    if profile["support_status"] != "executable_now":
        return {
            "execution_status": "not_yet_executable",
            "reason": profile["support_reason"],
            "step_kind": kind,
        }

    artifacts_dir = (
        _simulation_artifacts_root()
        / "simulation_steps"
        / _safe_slug(tenant_id, fallback="tenant")
        / _safe_slug(simulation_run_id, fallback="run")
        / f"iteration_{max(1, int(iteration_index))}"
        / _safe_slug(step_id, fallback="step")
    )
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    timeout_secs = max(10, int(getattr(settings, "simulation_browser_execution_timeout_seconds", 45)))
    extension_dir = _resolve_extension_dist_dir()
    api_url = _resolve_hawk_api_url()
    test_url = _resolve_browser_test_url()
    user_data_dir = artifacts_dir / "chromium-profile"
    request_payload = {
        "kind": kind,
        "payload": dict(payload or {}),
        "timeout_ms": timeout_secs * 1000,
        "artifacts_dir": str(artifacts_dir),
        "extension_dir": str(extension_dir) if extension_dir is not None else "",
        "api_url": api_url,
        "test_url": test_url,
        "user_data_dir": str(user_data_dir),
        "headless": False,
    }

    input_file = artifacts_dir / "request.json"
    input_file.write_text(json.dumps(request_payload, ensure_ascii=True), encoding="utf-8")

    node_binary = _resolve_node_binary()
    if not node_binary:
        raise RuntimeError("Node runtime not available for browser simulation execution")

    runner_script = _playwright_runner_script()
    env = os.environ.copy()
    modules_dir = _resolve_playwright_modules_dir()
    if modules_dir is not None:
        existing_node_path = str(env.get("NODE_PATH") or "").strip()
        env["NODE_PATH"] = f"{existing_node_path}{os.pathsep if existing_node_path else ''}{modules_dir}"
        playwright_package = modules_dir / "playwright"
        if playwright_package.exists():
            env["SIMULATION_PLAYWRIGHT_PACKAGE"] = str(playwright_package)

    completed = subprocess.run(
        [node_binary, str(runner_script), str(input_file)],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_secs + 10,
        check=False,
    )

    stdout_text = (completed.stdout or "").strip()
    stderr_text = (completed.stderr or "").strip()

    if completed.returncode != 0:
        raise RuntimeError(
            "Browser step execution failed "
            f"(exit={completed.returncode}, stderr={stderr_text or 'none'}, stdout={stdout_text or 'none'})"
        )

    try:
        raw_output = json.loads(stdout_text or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Playwright runner emitted invalid JSON: {stdout_text[:500]}") from exc

    if str(raw_output.get("status") or "").lower() != "ok":
        raise RuntimeError(f"Playwright runner returned non-ok status: {json.dumps(raw_output)[:800]}")

    extension_loaded = bool(raw_output.get("extension_loaded", False))
    if not extension_loaded:
        return {
            "execution_status": "not_yet_executable",
            "reason": "Hawk extension did not load in Chromium; browser simulation cannot prove extension interception.",
            "step_kind": kind,
            "extension_loaded": False,
            "extension_dir": str(raw_output.get("extension_dir") or _configured_extension_dist_path()),
            "target_url": str(raw_output.get("target_url") or ""),
            "final_url": str(raw_output.get("final_url") or ""),
            "network_summary": dict(raw_output.get("network_summary") or {}),
            "artifacts": dict(raw_output.get("artifacts") or {}),
        }

    result = {
        "execution_status": "executed",
        "step_kind": kind,
        "title": str(raw_output.get("title") or ""),
        "target_url": str(raw_output.get("target_url") or ""),
        "final_url": str(raw_output.get("final_url") or ""),
        "response_excerpt": str(raw_output.get("response_excerpt") or ""),
        "network_summary": dict(raw_output.get("network_summary") or {}),
        "artifacts": dict(raw_output.get("artifacts") or {}),
        "extension_loaded": extension_loaded,
        "extension_dir": str(raw_output.get("extension_dir") or ""),
    }
    if "upload_status" in raw_output:
        result["upload_status"] = str(raw_output.get("upload_status") or "")
    return result


def write_run_evidence_bundle(
    *,
    simulation_id: str,
    simulation_run_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    safe_sim_id = _safe_slug(simulation_id, fallback="simulation")
    safe_run_id = _safe_slug(simulation_run_id, fallback="run")

    base = _simulation_artifacts_root() / safe_sim_id
    base.mkdir(parents=True, exist_ok=True)
    output_path = base / f"run_{stamp}_{safe_run_id}.json"

    serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2)
    output_path.write_text(serialized, encoding="utf-8")
    sha = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    relative = str(output_path.relative_to(_simulation_artifacts_root()))

    return {
        "relative_path": relative,
        "sha256": sha,
    }
