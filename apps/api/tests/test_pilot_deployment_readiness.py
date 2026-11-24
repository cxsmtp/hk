from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "pilot_deployment_readiness.py"
spec = importlib.util.spec_from_file_location("pilot_deployment_readiness", SCRIPT_PATH)
assert spec is not None
readiness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["pilot_deployment_readiness"] = readiness
spec.loader.exec_module(readiness)


def _write_good_extension(root: Path) -> None:
    (root / "dist").mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({"name": "Hawk Pilot", "version": "0.1.8"}), encoding="utf-8")
    (root / "options.html").write_text("<html></html>", encoding="utf-8")
    (root / "dist" / "service-worker.js").write_text("console.log('hawk runtime');", encoding="utf-8")
    (root / "dist" / "content-script.js").write_text("console.log('hawk content');", encoding="utf-8")
    (root / "dist" / "options.js").write_text("console.log('hawk options');", encoding="utf-8")
    (root / "build-info.json").write_text(
        json.dumps(
            {
                "build_hash": "abc123def456",
                "source_maps_included": False,
                "dev_files_included": False,
            }
        ),
        encoding="utf-8",
    )
    (root / "pilot-managed-policy.json").write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk-api.local",
                "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
                "policy_locked": True,
                "enterprise_managed": True,
                "minimum_extension_version": "0.1.8",
                "incognito_policy": "disabled",
            }
        ),
        encoding="utf-8",
    )


def test_readiness_passes_for_hardened_local_pilot_env_and_package(tmp_path: Path) -> None:
    env = {
        "ENV": "pilot",
        "PILOT_MODE": "true",
        "DEMO_MODE": "false",
        "DATABASE_URL": "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot",
        "SECRET_KEY": "x" * 64,
        "SECRET_KEY_LOCK_ENABLED": "true",
        "API_BASE_URL": "https://hawk-api.local",
        "WEB_ORIGIN": "https://hawk-ui.local",
        "CORS_ORIGINS": "https://hawk-ui.local,http://localhost:3000",
        "EXTENSION_CORS_ORIGINS": "chrome-extension://abcdefghijklmnop",
        "DISK_ENCRYPTION_CONFIRMED": "true",
        "API_NETWORK_RESTRICTION_CONFIRMED": "true",
        "BACKUP_CONFIGURED": "true",
        "EVIDENCE_RETENTION_DAYS": "90",
        "REPORT_RETENTION_DAYS": "90",
        "INCOGNITO_POLICY": "disabled",
        "FAIL_SECURE_MODE": "true",
        "GOVERNANCE_STRICT_MODE": "true",
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "true",
        "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW": "false",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "CELERY_BROKER_URL": "redis://127.0.0.1:6379/0",
        "CELERY_RESULT_BACKEND": "redis://127.0.0.1:6379/1",
    }
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)

    checks = readiness.evaluate_api_env(
        env,
        expected_api_url="https://hawk-api.local",
        expected_web_origin="https://hawk-ui.local",
    )
    checks.extend(
        readiness.evaluate_extension_package(
            extension_root,
            expected_api_url="https://hawk-api.local",
            expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        )
    )
    payload = readiness.summarize(checks)

    assert payload["status"] == "ok"
    assert payload["summary"]["failed"] == 0
    assert payload["summary"]["warning"] == 0


def test_readiness_fails_for_sqlite_demo_raw_prompt_logging_and_bad_extension(tmp_path: Path) -> None:
    env = {
        "ENV": "dev",
        "PILOT_MODE": "false",
        "DEMO_MODE": "true",
        "DATABASE_URL": "sqlite:///hawk.db",
        "SECRET_KEY": "short",
        "SECRET_KEY_LOCK_ENABLED": "false",
        "API_BASE_URL": "http://192.168.102.79:8000",
        "WEB_ORIGIN": "http://localhost:3000",
        "DISK_ENCRYPTION_CONFIRMED": "false",
        "API_NETWORK_RESTRICTION_CONFIRMED": "false",
        "BACKUP_CONFIGURED": "false",
        "EVIDENCE_RETENTION_DAYS": "0",
        "REPORT_RETENTION_DAYS": "0",
        "INCOGNITO_POLICY": "",
        "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW": "true",
    }
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)
    (extension_root / "dist" / "content-script.js.map").write_text("{}", encoding="utf-8")
    (extension_root / "src").mkdir()
    (extension_root / "src" / "content-script.ts").write_text("export {}", encoding="utf-8")

    checks = readiness.evaluate_api_env(env, expected_api_url="https://hawk-api.local")
    checks.extend(readiness.evaluate_extension_package(extension_root))
    payload = readiness.summarize(checks)
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["database_postgresql"]["status"] == "failed"
    assert by_id["demo_mode_off"]["status"] == "failed"
    assert by_id["sensitive_raw_prompt_logging_off"]["status"] == "failed"
    assert by_id["api_base_url_expected"]["status"] == "failed"
    assert by_id["no_source_or_sourcemaps"]["status"] == "failed"
    assert by_id["no_dev_dirs"]["status"] == "failed"


def test_readiness_warns_for_short_retention() -> None:
    env = {
        "ENV": "pilot",
        "PILOT_MODE": "true",
        "DEMO_MODE": "false",
        "DATABASE_URL": "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot",
        "SECRET_KEY": "x" * 64,
        "SECRET_KEY_LOCK_ENABLED": "true",
        "API_BASE_URL": "https://hawk-api.local",
        "WEB_ORIGIN": "https://hawk-ui.local",
        "CORS_ORIGINS": "https://hawk-ui.local,http://localhost:3000",
        "EXTENSION_CORS_ORIGINS": "chrome-extension://abcdefghijklmnop",
        "DISK_ENCRYPTION_CONFIRMED": "true",
        "API_NETWORK_RESTRICTION_CONFIRMED": "true",
        "BACKUP_CONFIGURED": "true",
        "EVIDENCE_RETENTION_DAYS": "7",
        "REPORT_RETENTION_DAYS": "7",
        "INCOGNITO_POLICY": "disabled",
        "FAIL_SECURE_MODE": "true",
        "GOVERNANCE_STRICT_MODE": "true",
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "true",
        "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW": "false",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "CELERY_BROKER_URL": "redis://127.0.0.1:6379/0",
        "CELERY_RESULT_BACKEND": "redis://127.0.0.1:6379/1",
    }

    checks = readiness.evaluate_api_env(env)
    payload = readiness.summarize(checks)
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "degraded"
    assert by_id["evidence_retention"]["status"] == "warning"
    assert by_id["report_retention"]["status"] == "warning"


def test_readiness_fails_for_sensitive_artifacts_and_unlocked_managed_policy(tmp_path: Path) -> None:
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)
    (extension_root / ".env").write_text("SECRET_KEY=do-not-package", encoding="utf-8")
    (extension_root / "pilot-managed-policy.json").write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk-api.local",
                "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
                "policy_locked": "false",
                "enterprise_managed": "false",
            }
        ),
        encoding="utf-8",
    )

    payload = readiness.summarize(
        readiness.evaluate_extension_package(
            extension_root,
            expected_api_url="https://hawk-api.local",
            expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        )
    )
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["no_sensitive_artifacts"]["status"] == "failed"
    assert by_id["managed_policy_locked"]["status"] == "failed"
    assert by_id["managed_minimum_extension_version"]["status"] == "failed"


def test_readiness_fails_managed_policy_without_minimum_extension_version(tmp_path: Path) -> None:
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)
    policy_path = extension_root / "pilot-managed-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy.pop("minimum_extension_version")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    payload = readiness.summarize(readiness.evaluate_extension_package(extension_root))
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["managed_minimum_extension_version"]["status"] == "failed"


def test_readiness_fails_for_weak_extension_build_hash(tmp_path: Path) -> None:
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)
    (extension_root / "build-info.json").write_text(
        json.dumps(
            {
                "build_hash": "short",
                "source_maps_included": False,
                "dev_files_included": False,
            }
        ),
        encoding="utf-8",
    )

    payload = readiness.summarize(readiness.evaluate_extension_package(extension_root))
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["build_info_hardened"]["status"] == "failed"


def test_readiness_requires_explicit_extension_cors_origins() -> None:
    env = {
        "ENV": "pilot",
        "PILOT_MODE": "true",
        "DEMO_MODE": "false",
        "DATABASE_URL": "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot",
        "SECRET_KEY": "x" * 64,
        "SECRET_KEY_LOCK_ENABLED": "true",
        "API_BASE_URL": "https://hawk-api.local",
        "WEB_ORIGIN": "https://hawk-ui.local",
        "CORS_ORIGINS": "https://hawk-ui.local,chrome-extension://*",
        "EXTENSION_CORS_ORIGINS": "chrome-extension://*",
        "DISK_ENCRYPTION_CONFIRMED": "true",
        "API_NETWORK_RESTRICTION_CONFIRMED": "true",
        "BACKUP_CONFIGURED": "true",
        "EVIDENCE_RETENTION_DAYS": "90",
        "REPORT_RETENTION_DAYS": "90",
        "INCOGNITO_POLICY": "disabled",
        "FAIL_SECURE_MODE": "true",
        "GOVERNANCE_STRICT_MODE": "true",
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "true",
        "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW": "false",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "CELERY_BROKER_URL": "redis://127.0.0.1:6379/0",
        "CELERY_RESULT_BACKEND": "redis://127.0.0.1:6379/1",
    }

    checks = readiness.evaluate_api_env(env)
    payload = readiness.summarize(checks)
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["extension_cors_origins"]["status"] == "failed"


def test_strict_50_user_readiness_fails_soft_pilot_warnings(tmp_path: Path) -> None:
    env = {
        "ENV": "pilot",
        "PILOT_MODE": "true",
        "DEMO_MODE": "false",
        "DATABASE_URL": "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot",
        "SECRET_KEY": "x" * 64,
        "SECRET_KEY_LOCK_ENABLED": "true",
        "API_BASE_URL": "http://192.168.102.35:8000",
        "WEB_ORIGIN": "http://localhost:3000",
        "CORS_ORIGINS": "http://localhost:3000",
        "EXTENSION_CORS_ORIGINS": "chrome-extension://abcdefghijklmnop",
        "DISK_ENCRYPTION_CONFIRMED": "true",
        "API_NETWORK_RESTRICTION_CONFIRMED": "true",
        "BACKUP_CONFIGURED": "true",
        "EVIDENCE_RETENTION_DAYS": "90",
        "REPORT_RETENTION_DAYS": "90",
        "INCOGNITO_POLICY": "disabled",
        "FAIL_SECURE_MODE": "false",
        "GOVERNANCE_STRICT_MODE": "false",
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "false",
        "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW": "false",
    }
    extension_root = tmp_path / "hawk-extension-pilot"
    _write_good_extension(extension_root)
    (extension_root / "pilot-managed-policy.json").unlink()

    checks = readiness.evaluate_api_env(env, strict_50_user=True)
    checks.extend(readiness.evaluate_extension_package(extension_root, strict_50_user=True))
    payload = readiness.summarize(checks)
    by_id = {item["id"]: item for item in payload["checks"]}

    assert payload["status"] == "failed"
    assert by_id["https_required"]["status"] == "failed"
    assert by_id["fail_secure"]["status"] == "failed"
    assert by_id["governance_strict"]["status"] == "failed"
    assert by_id["strict_dependency_checks"]["status"] == "failed"
    assert by_id["redis_url"]["status"] == "failed"
    assert by_id["celery_broker"]["status"] == "failed"
    assert by_id["celery_result_backend"]["status"] == "failed"
    assert by_id["managed_policy_file"]["status"] == "failed"
