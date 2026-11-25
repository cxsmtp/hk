from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "infra" / "docker-compose.demo.yml"


def _compose() -> dict:
    assert COMPOSE_PATH.exists(), "canonical demo Compose file is missing"
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_demo_compose_declares_exact_service_graph() -> None:
    compose = _compose()
    assert set(compose["services"]) == {
        "db",
        "redis",
        "migrate",
        "seed-demo",
        "api",
        "worker",
        "celery-beat",
        "web",
    }
    assert compose["services"]["migrate"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert compose["services"]["seed-demo"]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert compose["services"]["api"]["depends_on"]["seed-demo"]["condition"] == "service_completed_successfully"
    assert compose["services"]["web"]["depends_on"]["api"]["condition"] == "service_healthy"


def test_long_running_services_restart_and_one_shot_jobs_do_not() -> None:
    services = _compose()["services"]
    for name in ("db", "redis", "api", "worker", "celery-beat", "web"):
        assert services[name]["restart"] == "unless-stopped"
    for name in ("migrate", "seed-demo"):
        assert services[name]["restart"] == "no"


def test_seed_job_can_import_the_api_package_from_its_absolute_script_path() -> None:
    seed = _compose()["services"]["seed-demo"]
    assert seed["command"] == ["python", "/workspace/infra/scripts/seed.py"]
    assert seed["environment"]["PYTHONPATH"] == "/workspace/apps/api"


def test_only_loopback_api_and_ui_ports_are_published() -> None:
    services = _compose()["services"]
    assert services["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert services["web"]["ports"] == ["127.0.0.1:3001:3000"]
    assert "ports" not in services["db"]
    assert "ports" not in services["redis"]


def test_postgres_uses_explicit_persistent_volume() -> None:
    compose = _compose()
    assert "hawk_demo_postgres_data:/var/lib/postgresql/data" in compose["services"]["db"]["volumes"]
    assert compose["volumes"]["hawk_demo_postgres_data"]["name"] == (
        "${HAWK_POSTGRES_VOLUME_NAME:-hawk_demo_postgres_data}"
    )


def test_application_services_have_no_source_bind_mounts_or_dev_commands() -> None:
    services = _compose()["services"]
    for name in ("api", "worker", "celery-beat", "web"):
        serialized = yaml.safe_dump(services[name])
        assert "../apps" not in serialized
        assert "../packages" not in serialized
        assert "npm ci" not in serialized
        assert "next dev" not in serialized
    assert "/health/ready" in yaml.safe_dump(services["api"]["healthcheck"])


def test_web_container_does_not_receive_backend_secret_environment() -> None:
    web = _compose()["services"]["web"]
    assert "env_file" not in web
    assert set(web["environment"]) == {
        "NODE_ENV",
        "NEXT_PUBLIC_API_URL",
        "NEXT_PUBLIC_CONTROL_COVERAGE_UI_ENABLED",
    }


def test_docker_context_excludes_local_state_and_secrets() -> None:
    patterns = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for expected in (
        ".env",
        ".git",
        "._*",
        "apps/api/.venv",
        "apps/web/node_modules",
        "apps/web/.next",
        "*.db",
    ):
        assert expected in patterns


def test_build_uses_a_sanitized_staging_context_on_appledouble_volumes() -> None:
    compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")
    assert compose_text.count("${HAWK_BUILD_CONTEXT:-..}") == 2
    assert "hawk_stage_build_context" in script
    assert "COPYFILE_DISABLE=1" in script
    assert "--delete-excluded" in script
    assert 'export HAWK_BUILD_CONTEXT' in script
    assert '--exclude="._*"' in script
    for excluded in ('.env*', '*.db*', '*.sqlite*', '.next*', '.DS_Store', 'tsconfig.tsbuildinfo'):
        assert f'--exclude="{excluded}"' in script


def test_api_image_packages_reviewed_native_adapter_acceptance_evidence() -> None:
    dockerfile = (ROOT / "infra" / "Dockerfile.api").read_text(encoding="utf-8")
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")

    assert "COPY docs/evidence /workspace/docs/evidence" in dockerfile
    assert '"$HAWK_REPO_ROOT/docs/evidence/" "$HAWK_BUILD_CONTEXT/docs/evidence/"' in script


def test_sanitized_build_context_includes_local_gateway_artifacts() -> None:
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")

    assert '"$HAWK_REPO_ROOT/infra/Dockerfile.local-production-gateway"' in script
    assert '"$HAWK_REPO_ROOT/infra/Caddyfile.local-production"' in script
    assert '--exclude="._*"' in script


def test_web_demo_image_builds_once_and_runs_next_production_server() -> None:
    dockerfile = (ROOT / "infra" / "Dockerfile.web.demo").read_text(encoding="utf-8")
    assert "RUN npm ci" in dockerfile
    assert "RUN npm run build" in dockerfile
    assert 'CMD ["npm", "run", "start"' in dockerfile
    assert "next dev" not in dockerfile
    assert "USER node" in dockerfile


def test_web_runtime_config_does_not_require_a_pruned_typescript_dependency() -> None:
    typescript_config = ROOT / "apps" / "web" / "next.config.ts"
    runtime_config = ROOT / "apps" / "web" / "next.config.mjs"

    assert not typescript_config.exists()
    assert runtime_config.exists()
    assert "export default nextConfig" in runtime_config.read_text(encoding="utf-8")


def test_demo_stack_wrapper_has_bounded_commands_and_no_volume_deletion() -> None:
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")
    for command in ("validate", "stage", "build", "prepare", "up", "status", "recover", "backup", "logs", "down"):
        assert f"{command})" in script
    assert "down --volumes" not in script
    assert "down -v" not in script
    assert "docker volume rm" not in script
    assert "rm -rf" not in script
    assert '--project-name "$HAWK_PROJECT_NAME"' in script


def test_demo_stack_up_waits_for_every_long_running_service_to_be_healthy() -> None:
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")
    command = (
        "hawk_compose up -d --wait --wait-timeout 180 "
        "api worker celery-beat web"
    )
    assert script.count(command) == 2


def test_demo_stack_rejects_documented_default_secrets() -> None:
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")
    assert 'hawk_require_secret "POSTGRES_PASSWORD" "postgres" 24' in script
    assert 'hawk_require_secret "SECRET_KEY" "change-me-super-secret" 32' in script
    assert (
        'hawk_require_secret "CONNECTOR_SECRETS_KEY" '
        '"replace-with-32-byte-random-value" 32'
    ) in script
    assert 'hawk_require_secret "SECRET_KEY_LOCK_PEPPER" "replace-with-distinct-lock-pepper" 32' in script
    assert 'hawk_require_secret "CONNECTOR_SECRETS_KDF_SALT" "replace-with-distinct-kdf-salt" 32' in script
    assert 'hawk_require_secret "ONPREM_BUNDLE_SIGNING_SECRET" "replace-with-distinct-signing-secret" 32' in script
    assert "hawk_require_distinct_secrets" in script


def test_demo_stack_refuses_an_unowned_existing_postgres_volume() -> None:
    script = (ROOT / "infra" / "scripts" / "hawk_demo_stack.sh").read_text(encoding="utf-8")
    assert "hawk_assert_volume_ownership" in script
    assert 'com.docker.compose.project' in script
    assert 'com.docker.compose.volume' in script
    assert 'HAWK_POSTGRES_VOLUME="${HAWK_POSTGRES_VOLUME:-hawk_demo_postgres_data}"' in script


def test_env_example_documents_every_required_demo_secret() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for key in (
        "SECRET_KEY_LOCK_PEPPER",
        "CONNECTOR_SECRETS_KDF_SALT",
        "ENFORCEMENT_PAYLOADS_KEY",
        "ONPREM_BUNDLE_SIGNING_SECRET",
    ):
        assert f"{key}=" in example


