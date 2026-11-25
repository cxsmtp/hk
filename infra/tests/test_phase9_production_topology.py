from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_production_overlay_keeps_one_service_graph_and_hardens_application_containers() -> None:
    base = yaml.safe_load((ROOT / "infra/docker-compose.demo.yml").read_text(encoding="utf-8"))
    production = yaml.safe_load((ROOT / "infra/legacy/docker-compose.production.yml").read_text(encoding="utf-8"))

    assert set(base["services"]) == set(production["services"])
    for name in ("api", "worker", "celery-beat", "web"):
        service = production["services"][name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["pids_limit"] > 0
    assert production["services"]["db"]["environment"]["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres_password"
    assert "POSTGRES_PASSWORD" not in production["services"]["db"]["environment"]
    assert "--requirepass" in " ".join(production["services"]["redis"]["command"])
    redis_healthcheck = " ".join(production["services"]["redis"]["healthcheck"]["test"])
    assert "REDISCLI_AUTH" in redis_healthcheck
    assert "/run/secrets/redis_password" in redis_healthcheck


def test_worker_healthchecks_load_secret_references_and_verify_component_registration() -> None:
    base = yaml.safe_load((ROOT / "infra/docker-compose.demo.yml").read_text(encoding="utf-8"))
    for service_name, component_type in (("worker", "worker"), ("celery-beat", "celery_beat")):
        command = " ".join(base["services"][service_name]["healthcheck"]["test"])
        assert "/workspace/infra/scripts/check_component_heartbeat.py" in command
        assert component_type in command

    checker = (ROOT / "infra/scripts/check_component_heartbeat.py").read_text(encoding="utf-8")
    assert "evaluate_component_runtime_health" in checker
    assert "from app.core.config import settings" in checker
    service = (ROOT / "apps/api/app/services/control_plane_health_service.py").read_text(encoding="utf-8")
    assert "settings.redis_url" in service


def test_read_only_production_beat_uses_bounded_writable_schedule_path() -> None:
    production = yaml.safe_load((ROOT / "infra/legacy/docker-compose.production.yml").read_text(encoding="utf-8"))
    beat = production["services"]["celery-beat"]

    assert beat["read_only"] is True
    command = beat["command"]
    assert "--schedule" in command
    schedule_index = command.index("--schedule")
    assert command[schedule_index + 1] == "/tmp/celerybeat-schedule"


def test_production_secret_files_are_mounted_only_into_backend_components() -> None:
    production = yaml.safe_load((ROOT / "infra/legacy/docker-compose.production.yml").read_text(encoding="utf-8"))
    assert "secrets" not in production["services"]["web"]
    for name in ("api", "worker", "celery-beat", "migrate", "seed-demo"):
        mounted = {item["source"] if isinstance(item, dict) else item for item in production["services"][name]["secrets"]}
        assert "database_url" in mounted
        assert "secret_key" in mounted


def test_secret_key_lock_state_is_persistent_and_never_stored_in_the_policy_channel() -> None:
    production = yaml.safe_load((ROOT / "infra/legacy/docker-compose.production.yml").read_text(encoding="utf-8"))
    for name in ("api", "worker", "celery-beat", "migrate", "seed-demo"):
        mounts = production["services"][name]["volumes"]
        assert any("hawk_runtime_state" in str(mount) and "/run/hawk" in str(mount) for mount in mounts)
    assert "hawk_runtime_state" in production["volumes"]


def test_production_admin_bootstrap_is_explicit_one_time_and_stdin_only() -> None:
    wrapper = (ROOT / "infra/scripts/hawk_demo_stack.sh").read_text(encoding="utf-8")
    bootstrap = (ROOT / "infra/scripts/production_bootstrap.py").read_text(encoding="utf-8")
    assert "bootstrap-admin" in wrapper
    assert "--password-stdin" in wrapper
    assert "HAWK_BOOTSTRAP_PASSWORD=" not in wrapper
    assert "existing_users" in bootstrap
    assert "existing_tenants" in bootstrap
    assert "production.bootstrap.initial_admin" in bootstrap

    from app.services.production_hardening import validate_initial_admin_password

    validate_initial_admin_password("A-secure-bootstrap-password-42!")
    for unsafe in ("Password123!", "short", "alllowercase-but-long-123"):
        try:
            validate_initial_admin_password(unsafe)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe bootstrap password was accepted")


def test_api_image_separates_build_toolchain_from_non_root_runtime() -> None:
    dockerfile = (ROOT / "infra/Dockerfile.api").read_text(encoding="utf-8")
    assert " AS builder" in dockerfile
    assert "python:3.11-slim@sha256:" in dockerfile
    runtime = dockerfile.split("FROM ", 2)[-1]
    assert "build-essential" not in runtime
    assert "libpq-dev" not in runtime
    assert "pip uninstall -y pytest" in runtime
    assert "/run/hawk" in runtime
    assert "USER 1000" in runtime

    web = (ROOT / "infra/Dockerfile.web.demo").read_text(encoding="utf-8")
    assert "node:20-alpine@sha256:" in web


def test_production_wrapper_uses_dedicated_env_project_and_volume_without_deleting_volumes() -> None:
    script = (ROOT / "infra/legacy/hawk_production_stack.sh").read_text(encoding="utf-8")
    assert "HAWK_ENV_FILE" in script
    assert ".env.production" in script
    assert "hawk-production" in script
    assert "hawk_production_postgres_data" in script
    assert "docker-compose.production.yml" in script
    assert "down -v" not in script
    assert "down --volumes" not in script


def test_migrations_use_serialized_runner_and_restore_verification_is_disposable() -> None:
    base = yaml.safe_load((ROOT / "infra/docker-compose.demo.yml").read_text(encoding="utf-8"))
    migrate = base["services"]["migrate"]
    assert migrate["command"] == ["python", "/workspace/infra/scripts/run_migrations.py"]

    runner = (ROOT / "infra/scripts/run_migrations.py").read_text(encoding="utf-8")
    assert "pg_advisory_lock" in runner
    assert "pg_advisory_unlock" in runner
    assert "command.upgrade" in runner

    stack = (ROOT / "infra/scripts/hawk_demo_stack.sh").read_text(encoding="utf-8")
    assert "restore-verify" in stack
    assert "createdb" in stack
    assert "pg_restore" in stack
    assert "dropdb" in stack
    assert "hawk_restore_verify_" in stack
    assert stack.count('createdb -U "$HAWK_POSTGRES_USER" "$HAWK_RESTORE_DB"') == 1


def test_migration_tree_excludes_macos_appledouble_sidecars() -> None:
    migrations = ROOT / "apps" / "api" / "app" / "db" / "migrations" / "versions"
    assert not list(migrations.glob("._*.py"))


def test_production_operations_runbook_is_bounded_and_explicit() -> None:
    runbook = (ROOT / "docs/deployment/production-single-node-compose.md").read_text(encoding="utf-8")
    for statement in (
        "Supported topology",
        "Required secret references",
        "Startup preflight",
        "Migration",
        "Readiness",
        "Backup",
        "Restore verification",
        "Upgrade",
        "Rollback limitations",
        "Unsupported deployment modes",
    ):
        assert statement in runbook


def test_local_tls_gateway_uses_the_production_network_not_host_loopback() -> None:
    gateway_compose = yaml.safe_load(
        (ROOT / "infra/docker-compose.local-production-gateway.yml").read_text(encoding="utf-8")
    )
    caddyfile = (ROOT / "infra/Caddyfile.local-production").read_text(encoding="utf-8")

    gateway = gateway_compose["services"]["gateway"]
    assert gateway["container_name"] == "hawk-local-production-gateway"
    assert gateway["ports"] == ["127.0.0.1:${HAWK_GATEWAY_HOST_PORT:-3443}:8443"]
    assert gateway["networks"] == ["hawk-production"]
    assert gateway_compose["networks"]["hawk-production"] == {
        "name": "${HAWK_NETWORK_NAME:-hawk_production_local_network}",
        "external": True,
    }
    assert "${HAWK_LOCAL_TLS_DIR:?HAWK_LOCAL_TLS_DIR is required}:/certs:ro" in gateway["volumes"]
    assert "reverse_proxy api:8000" in caddyfile
    assert "reverse_proxy web:3000" in caddyfile
    assert "host.docker.internal" not in caddyfile
