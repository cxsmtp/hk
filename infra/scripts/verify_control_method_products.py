#!/usr/bin/env python3
"""Validate and boundedly execute the four approved control-method checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "infra" / "control-method-products.json"
SCHEMA = "hawk.control-method-products/1.0"
METHOD_IDS = ("browser_extension", "mcp_gateway", "llm_gateway", "endpoint_agent")
LIFECYCLE_GATES = ("clean_install", "restart", "reconnect", "allow", "deny", "approval", "revocation", "outage", "upgrade", "rollback", "evidence")
EVIDENCE_STATES = {"repository_verified", "target_required", "blocked", "not_applicable"}
ALLOWED_ENV = {"TEST_PROFILE", "DATABASE_URL", "TEST_DATABASE_URL", "PYTHONPATH", "NPM_CONFIG_CACHE"}
MAX_OUTPUT = 16_384
MAX_TIMEOUT = 300
MAX_TOTAL_TIMEOUT = 900
PROMOTION_REQUIREMENTS = {
    "required_lifecycle_gates": ["clean_install", "upgrade", "rollback", "evidence"],
    "minimum_distinct_successful_target_operations": 2,
    "intended_target_required": True,
    "distinct_current_and_previous_artifacts_required": True,
    "same_version_reinstall_counts_as_upgrade_or_rollback": False,
}
TARGET_CHECK_IDS = {
    "browser_extension": "managed_browser_acceptance",
    "mcp_gateway": "real_claude_code_mcp_acceptance",
    "llm_gateway": "real_ollama_local_acceptance",
    "endpoint_agent": "signed_enrolled_device_acceptance",
}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_./:@+=,-]+$")


class ManifestError(ValueError):
    pass


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest_unreadable") from exc
    validate_manifest(payload)
    return payload


def _safe_relative(value: Any, *, allow_dot: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ManifestError("unsafe_path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or (not allow_dot and path == Path(".")):
        raise ManifestError("unsafe_path")
    return path


def _safe_argv(argv: Any) -> list[str]:
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item or not SAFE_TOKEN.fullmatch(item) for item in argv):
        raise ManifestError("unsafe_argv")
    if any(item in {"sh", "bash", "zsh", "cmd", "powershell"} for item in argv[:1]):
        raise ManifestError("shell_argv_forbidden")
    return argv


def validate_manifest(payload: dict[str, Any]) -> None:
    if payload.get("schema") != SCHEMA or payload.get("release_ready") is not False:
        raise ManifestError("schema_or_release_gate_invalid")
    if payload.get("promotion_requirements") != PROMOTION_REQUIREMENTS:
        raise ManifestError("promotion_requirements_invalid")
    methods = payload.get("methods")
    if not isinstance(methods, list) or tuple(item.get("id") for item in methods if isinstance(item, dict)) != METHOD_IDS:
        raise ManifestError("exact_four_methods_required")
    total_timeout = 0
    for method in methods:
        if not isinstance(method, dict) or method.get("id") not in METHOD_IDS or method.get("release_ready") is not False:
            raise ManifestError("method_gate_invalid")
        method_root = ROOT / _safe_relative(method.get("root"))
        if not method_root.is_dir() or not method_root.resolve().is_relative_to(ROOT):
            raise ManifestError("root_invalid")
        lifecycle = method.get("lifecycle_gates")
        if not isinstance(lifecycle, dict) or tuple(lifecycle) != LIFECYCLE_GATES:
            raise ManifestError("lifecycle_gates_invalid")
        for gate in LIFECYCLE_GATES:
            entry = lifecycle[gate]
            if not isinstance(entry, dict) or entry.get("state") not in EVIDENCE_STATES or not isinstance(entry.get("basis_reason"), str) or not entry["basis_reason"].strip():
                raise ManifestError("lifecycle_gate_evidence_invalid")
        version_path = _safe_relative(method.get("version_source"))
        if not (ROOT / version_path).is_file() or not (ROOT / version_path).resolve().is_relative_to(ROOT):
            raise ManifestError(f"version_source_missing:{method.get('version_source')}")
        sources = method.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ManifestError("sources_required")
        if len(set(sources)) != len(sources):
            raise ManifestError("source_duplicates")
        for source in sources:
            path = _safe_relative(source)
            if not (ROOT / path).is_file() or not (ROOT / path).resolve().is_relative_to(ROOT):
                raise ManifestError(f"source_missing:{source}")
        evidence = method.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("state") not in {"repository_verified", "target_required", "blocked", "not_applicable"} or not evidence.get("unverified_reason"):
            raise ManifestError("evidence_state_invalid")
        target = method.get("target_check")
        if not isinstance(target, dict) or set(target) != {"id", "runner", "proof_scope", "intended_target", "state", "blockers"}:
            raise ManifestError("target_check_invalid")
        if target["id"] != TARGET_CHECK_IDS[method["id"]] or target["state"] != evidence["state"] or target["state"] not in {"target_required", "blocked"}:
            raise ManifestError("target_check_state_invalid")
        if any(not isinstance(target[key], str) or not target[key].strip() for key in ("proof_scope", "intended_target")):
            raise ManifestError("target_check_scope_invalid")
        if not isinstance(target["blockers"], list) or not target["blockers"] or any(not isinstance(reason, str) or not reason.strip() for reason in target["blockers"]):
            raise ManifestError("target_check_blockers_invalid")
        if method["id"] == "endpoint_agent":
            if target["runner"] is not None or target["state"] != "blocked":
                raise ManifestError("endpoint_target_must_remain_blocked")
        elif target["runner"] not in sources:
            raise ManifestError("target_runner_must_be_digested")
        if any(lifecycle[gate]["state"] == "repository_verified" for gate in ("clean_install", "upgrade", "rollback")):
            raise ManifestError("target_lifecycle_must_remain_unpromoted")
        checks = method.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ManifestError("checks_required")
        for check in checks:
            if not isinstance(check, dict) or not check.get("name"):
                raise ManifestError("check_invalid")
            cwd = ROOT / _safe_relative(check.get("cwd"))
            if not cwd.is_dir() or not cwd.resolve().is_relative_to(ROOT):
                raise ManifestError("cwd_invalid")
            _safe_argv(check.get("argv"))
            env = check.get("env", {})
            if not isinstance(env, dict) or any(key not in ALLOWED_ENV or not isinstance(value, str) or not value for key, value in env.items()):
                raise ManifestError("environment_invalid")
            timeout = check.get("timeout_seconds")
            if not isinstance(timeout, (int, float)) or not 1 <= timeout <= MAX_TIMEOUT:
                raise ManifestError("timeout_invalid")
            total_timeout += timeout
    if total_timeout > MAX_TOTAL_TIMEOUT:
        raise ManifestError("combined_timeout_invalid")


def source_digests(method: dict[str, Any]) -> dict[str, str]:
    sources = dict.fromkeys([str(MANIFEST_PATH.relative_to(ROOT)), method["version_source"], *method["sources"]])
    return {source: hashlib.sha256((ROOT / source).read_bytes()).hexdigest() for source in sources}


def run_check(check: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    cwd = ROOT / _safe_relative(check["cwd"])
    env = os.environ.copy()
    env.update(check.get("env", {}))
    try:
        result = subprocess.run(check["argv"], cwd=cwd, env=env, shell=False, capture_output=True, text=True, timeout=check["timeout_seconds"], check=False)
        output = (result.stdout or "") + (result.stderr or "")
        output = output[:MAX_OUTPUT]
        return {"name": check["name"], "status": "passed" if result.returncode == 0 else "failed", "returncode": result.returncode, "duration_seconds": round(time.monotonic() - started, 3), "output": output}
    except subprocess.TimeoutExpired as exc:
        output = (str(exc.stdout or "") + str(exc.stderr or ""))[:MAX_OUTPUT]
        return {"name": check["name"], "status": "timeout", "returncode": None, "duration_seconds": round(time.monotonic() - started, 3), "output": output}
    except (OSError, ManifestError) as exc:
        return {"name": check["name"], "status": "missing_executable", "returncode": None, "duration_seconds": round(time.monotonic() - started, 3), "output": str(exc)[:MAX_OUTPUT]}


def execute(method_id: str | None = None) -> dict[str, Any]:
    manifest = load_manifest()
    selected = [item for item in manifest["methods"] if method_id in (None, "all") or item["id"] == method_id]
    if not selected:
        raise ManifestError("unknown_method")
    results = []
    for method in selected:
        checks = [run_check(check) for check in method["checks"]]
        repository_checks_passed = all(check["status"] == "passed" for check in checks)
        results.append({"id": method["id"], "version_source": method["version_source"], "source_digests": source_digests(method), "repository_checks_passed": repository_checks_passed, "acceptance_state": method["evidence"]["state"], "lifecycle_gates": method["lifecycle_gates"], "target_check": method["target_check"], "unverified_reason": method["evidence"]["unverified_reason"], "release_ready": False, "checks": checks})
    return {"schema": SCHEMA, "release_ready": False, "promotion_requirements": manifest["promotion_requirements"], "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "methods": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate the fixed manifest")
    parser.add_argument("--method", default=None, help="run one method or all")
    args = parser.parse_args()
    try:
        manifest = load_manifest()
        if args.check:
            print(json.dumps({"schema": manifest["schema"], "methods": [item["id"] for item in manifest["methods"]], "release_ready": False}, sort_keys=True))
            return 0
        report = execute(args.method)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if all(check["status"] == "passed" for method in report["methods"] for check in method["checks"]) else 1
    except ManifestError as exc:
        print(json.dumps({"error": str(exc), "release_ready": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
