from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


def _production_settings(**overrides):
    values = {
        "env": "production",
        "deployment_id": "hawk-bank-primary",
        "deployment_region": "uae-north",
        "deployment_data_location": "uae",
        "deployment_topology": "single_node_compose",
        "component_type": "api",
        "component_version": "0.1.0",
        "component_protocol_version": "1.0",
        "minimum_component_versions_json": json.dumps(
            {"api": "0.1.0", "worker": "0.1.0", "celery_beat": "0.1.0", "web": "0.1.0"}
        ),
        "database_url": "postgresql+psycopg2://hawk@db:5432/hawk",
        "redis_url": "redis://redis:6379/0",
        "celery_broker_url": "redis://redis:6379/1",
        "celery_result_backend": "redis://redis:6379/2",
        "web_origin": "https://hawk.example.test",
        "api_base_url": "https://api.hawk.example.test",
        "cors_origins": "https://hawk.example.test",
        "extension_cors_origins": "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
        "trusted_hosts": "api.hawk.example.test",
        "max_request_body_bytes": 2_097_152,
        "demo_mode": False,
        "pilot_mode": False,
        "self_registration_enabled": False,
        "gateway_intercept_minimal_mode": False,
        "control_plane_strict_dependency_checks": True,
        "fail_secure_mode": True,
        "governance_strict_mode": True,
        "secret_key_lock_enabled": True,
        "control_plane_heartbeat_max_age_seconds": 120,
        "mcp_persisted_sessions_required": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _module():
    spec = importlib.util.find_spec("app.services.production_hardening")
    assert spec is not None, "Phase 9 production hardening service is missing"
    from app.services import production_hardening

    return production_hardening


def _file_secret_sources():
    return {
        key: "file"
        for key in (
            "DATABASE_URL",
            "REDIS_URL",
            "CELERY_BROKER_URL",
            "CELERY_RESULT_BACKEND",
            "SECRET_KEY",
            "SECRET_KEY_LOCK_PEPPER",
            "CONNECTOR_SECRETS_KEY",
            "CONNECTOR_SECRETS_KDF_SALT",
            "ENFORCEMENT_PAYLOADS_KEY",
            "ONPREM_BUNDLE_SIGNING_SECRET",
        )
    }


def test_production_contract_accepts_only_the_supported_secret_referenced_topology() -> None:
    module = _module()
    report = module.validate_production_configuration(
        _production_settings(),
        secret_sources=_file_secret_sources(),
    )

    assert report.ready is True
    assert report.topology == "single_node_compose"
    assert report.deployment_id == "hawk-bank-primary"
    assert report.public_summary["deployment_region"] == "uae-north"
    assert "secret_sources" not in report.public_summary


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"database_url": "sqlite:///hawk.db"}, "postgresql_required"),
        ({"web_origin": "http://hawk.example.test"}, "https_web_origin_required"),
        ({"cors_origins": "*"}, "wildcard_cors_forbidden"),
        ({"trusted_hosts": "*"}, "wildcard_trusted_host_forbidden"),
        ({"demo_mode": True}, "demo_mode_forbidden"),
        ({"self_registration_enabled": True}, "self_registration_forbidden"),
        ({"control_plane_strict_dependency_checks": False}, "strict_dependencies_required"),
        ({"fail_secure_mode": False}, "fail_secure_required"),
        ({"mcp_persisted_sessions_required": False}, "mcp_persisted_sessions_required"),
        ({"deployment_topology": "kubernetes"}, "unsupported_topology"),
    ],
)
def test_production_contract_rejects_unsafe_or_unsupported_configuration(override, reason) -> None:
    module = _module()

    report = module.validate_production_configuration(
        _production_settings(**override),
        secret_sources=_file_secret_sources(),
    )

    assert report.ready is False
    assert reason in report.reason_codes


def test_production_example_requires_persisted_mcp_sessions() -> None:
    example = Path(__file__).resolve().parents[3] / ".env.production.example"

    assert "MCP_PERSISTED_SESSIONS_REQUIRED=true" in example.read_text(encoding="utf-8")


def test_production_contract_requires_file_references_without_reflecting_values() -> None:
    module = _module()
    sources = _file_secret_sources()
    sources["SECRET_KEY"] = "environment"

    report = module.validate_production_configuration(
        _production_settings(),
        secret_sources=sources,
    )

    assert report.ready is False
    assert "secret_reference_required:SECRET_KEY" in report.reason_codes
    rendered = json.dumps(report.to_dict())
    assert "super-secret-value" not in rendered


def test_secret_file_loader_reads_bounded_regular_file_and_never_returns_secret(tmp_path: Path) -> None:
    module = _module()
    secret_file = tmp_path / "secret-key"
    secret_file.write_text("bank-secret-material-01234567890123456789\n", encoding="utf-8")
    secret_file.chmod(0o400)
    environ = {"SECRET_KEY_FILE": str(secret_file)}

    sources = module.load_secret_file_environment(environ=environ, allowed_keys={"SECRET_KEY"})

    assert sources == {"SECRET_KEY": "file"}
    assert environ["SECRET_KEY"] == "bank-secret-material-01234567890123456789"
    assert "bank-secret-material" not in repr(sources)


def test_secret_file_loader_rejects_symlink_and_dual_source(tmp_path: Path) -> None:
    module = _module()
    target = tmp_path / "target"
    target.write_text("safe-secret-material-012345678901234567890", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="regular non-symlink"):
        module.load_secret_file_environment(
            environ={"SECRET_KEY_FILE": str(link)},
            allowed_keys={"SECRET_KEY"},
        )
    with pytest.raises(ValueError, match="both SECRET_KEY and SECRET_KEY_FILE"):
        module.load_secret_file_environment(
            environ={"SECRET_KEY": "one", "SECRET_KEY_FILE": str(target)},
            allowed_keys={"SECRET_KEY"},
        )


def test_component_compatibility_accepts_current_and_rejects_wrong_deployment_protocol_or_version() -> None:
    module = _module()
    contract = module.ComponentCompatibilityContract(
        deployment_id="hawk-bank-primary",
        protocol_version="1.0",
        minimum_versions={"worker": "0.1.0"},
    )

    compatible = contract.evaluate(
        module.ComponentHandshake(
            component_type="worker",
            component_version="0.1.1",
            protocol_version="1.0",
            deployment_id="hawk-bank-primary",
            capability_version="phase9/1.0",
        )
    )
    wrong_deployment = contract.evaluate(
        module.ComponentHandshake(
            component_type="worker",
            component_version="0.1.1",
            protocol_version="1.0",
            deployment_id="other-deployment",
            capability_version="phase9/1.0",
        )
    )
    wrong_protocol = contract.evaluate(
        module.ComponentHandshake(
            component_type="worker",
            component_version="0.1.1",
            protocol_version="2.0",
            deployment_id="hawk-bank-primary",
            capability_version="phase9/1.0",
        )
    )
    old_version = contract.evaluate(
        module.ComponentHandshake(
            component_type="worker",
            component_version="0.0.9",
            protocol_version="1.0",
            deployment_id="hawk-bank-primary",
            capability_version="phase9/1.0",
        )
    )

    assert compatible.accepted is True
    assert compatible.status == "compatible"
    assert wrong_deployment.reason_code == "deployment_mismatch"
    assert wrong_protocol.reason_code == "protocol_mismatch"
    assert old_version.reason_code == "component_version_too_old"
    assert all(result.accepted is False for result in (wrong_deployment, wrong_protocol, old_version))


def test_readiness_summary_distinguishes_critical_failure_from_optional_degradation() -> None:
    module = _module()
    critical = module.summarize_readiness(
        {
            "database": module.ProductionCheck(ok=False, critical=True, status="unavailable", detail="database unavailable"),
            "worker": module.ProductionCheck(ok=False, critical=False, status="degraded", detail="worker stale"),
        }
    )
    optional = module.summarize_readiness(
        {
            "database": module.ProductionCheck(ok=True, critical=True, status="ok", detail="database ready"),
            "worker": module.ProductionCheck(ok=False, critical=False, status="degraded", detail="worker stale"),
        }
    )

    assert critical.ready is False
    assert critical.status == "unhealthy"
    assert optional.ready is True
    assert optional.status == "degraded"


def test_component_registration_payload_is_explicit_bounded_and_secret_free() -> None:
    module = _module()
    payload = module.build_component_registration(
        _production_settings(component_type="worker")
    )

    assert payload == {
        "schema_version": "phase9/1.0",
        "deployment_id": "hawk-bank-primary",
        "component_type": "worker",
        "component_version": "0.1.0",
        "protocol_version": "1.0",
        "capability_version": "phase9/1.0",
    }
    assert not any("secret" in key or "token" in key or "password" in key for key in payload)


def test_liveness_and_readiness_are_separate_and_readiness_fails_on_critical_check(monkeypatch) -> None:
    module = _module()
    from app import main

    failing = module.summarize_readiness(
        {
            "schema": module.ProductionCheck(
                ok=False,
                critical=True,
                status="out_of_date",
                detail="schema mismatch",
            )
        }
    )
    monkeypatch.setattr(main, "_api_readiness_report", lambda: failing)
    client = TestClient(main.app)

    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "alive", "service": "api"}
    assert ready.status_code == 503
    assert ready.json()["ready"] is False
    assert ready.json()["checks"]["schema"]["status"] == "out_of_date"


def test_request_body_limit_applies_without_content_length(monkeypatch) -> None:
    from app import main

    monkeypatch.setattr(main.settings, "max_request_body_bytes", 8)
    client = TestClient(main.app)
    response = client.post(
        "/auth/login",
        content=(chunk for chunk in (b"1234", b"56789")),
        headers={"content-type": "application/octet-stream"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds configured limit."}


def test_control_plane_component_registration_is_compatible_and_wrong_deployment_is_rejected(monkeypatch) -> None:
    from app.services import control_plane_health_service

    settings_values = _production_settings(component_type="worker")
    for name, value in vars(settings_values).items():
        monkeypatch.setattr(control_plane_health_service.settings, name, value, raising=False)

    compatible_payload = {
        "schema_version": "phase9/1.0",
        "deployment_id": "hawk-bank-primary",
        "component_type": "worker",
        "component_version": "0.1.0",
        "protocol_version": "1.0",
        "capability_version": "phase9/1.0",
    }

    class RedisRegistration:
        def __init__(self, payload):
            self.payload = payload

        def get(self, _key):
            return json.dumps(self.payload)

    accepted = control_plane_health_service._check_component_registration(
        redis_client=RedisRegistration(compatible_payload),
        key="component:worker",
        expected_component_type="worker",
        strict_mode=True,
    )
    incompatible_payload = dict(compatible_payload, deployment_id="other-deployment")
    rejected = control_plane_health_service._check_component_registration(
        redis_client=RedisRegistration(incompatible_payload),
        key="component:worker",
        expected_component_type="worker",
        strict_mode=True,
    )

    assert accepted.ok is True
    assert accepted.status == "ok"
    assert rejected.ok is False
    assert rejected.status == "incompatible"
