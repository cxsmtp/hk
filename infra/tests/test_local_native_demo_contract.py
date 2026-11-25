from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_native_caddyfile_routes_gateway_to_local_processes() -> None:
    caddyfile = (ROOT / "infra" / "Caddyfile.local-native").read_text()

    assert ":3443" in caddyfile
    assert "tls infra/tls/local/hawk-local.crt infra/tls/local/hawk-local.key" in caddyfile
    assert "handle_path /api/*" in caddyfile
    assert "reverse_proxy 127.0.0.1:8000" in caddyfile
    assert "reverse_proxy 127.0.0.1:3000" in caddyfile
    assert "api:8000" not in caddyfile
    assert "web:3000" not in caddyfile


def test_native_scripts_do_not_depend_on_docker_compose() -> None:
    scripts = [
        ROOT / "infra" / "scripts" / "native-demo-env.sh",
        ROOT / "infra" / "scripts" / "native-health.sh",
        ROOT / "infra" / "scripts" / "native-stop.sh",
        ROOT / "infra" / "scripts" / "native-gateway.mjs",
        ROOT / "infra" / "scripts" / "native-up-user-services.sh",
        ROOT / "infra" / "scripts" / "native-demo-serve.sh",
        ROOT / "infra" / "scripts" / "native-postgres-user.sh",
        ROOT / "infra" / "scripts" / "native-redis-user.sh",
    ]

    for script in scripts:
        text = script.read_text()
        assert "docker compose" not in text
        assert "Docker.raw" not in text

    native_up = (ROOT / "infra" / "scripts" / "native-up.sh").read_text()
    assert "Docker.raw" not in native_up
    assert 'up -d db redis' in native_up
    assert "NATIVE_DEMO_USE_DOCKER_DATA_SERVICES" in native_up

    hybrid = (ROOT / "infra" / "scripts" / "native-up-hybrid.sh").read_text()
    assert "NATIVE_DEMO_USE_DOCKER_DATA_SERVICES=true" in hybrid
    assert "Docker.raw" not in hybrid

    helper = (ROOT / "infra" / "scripts" / "native-demo-env.sh").read_text()
    assert "infra/artifacts/native-runtime" in helper or "NATIVE_RUNTIME_DIR" in helper


def test_no_sudo_native_user_services_are_supported() -> None:
    env = (ROOT / "infra" / "scripts" / "native-demo-env.sh").read_text()
    user_up = (ROOT / "infra" / "scripts" / "native-up-user-services.sh").read_text()
    user_pg = (ROOT / "infra" / "scripts" / "native-postgres-user.sh").read_text()
    user_redis = (ROOT / "infra" / "scripts" / "native-redis-user.sh").read_text()

    assert "NATIVE_POSTGRES_BIN" in env
    assert "NATIVE_REDIS_BIN" in env
    assert "postgresql+psycopg2://${NATIVE_POSTGRES_USER}@" in env
    assert "NATIVE_POSTGRES_PORT=55432" in user_up
    assert "native-postgres-user.sh" in user_up
    assert "native-redis-user.sh" in user_up
    assert "native-active.env" in user_up
    assert "nohup" in (ROOT / "infra" / "scripts" / "native-up.sh").read_text()
    serve = (ROOT / "infra" / "scripts" / "native-demo-serve.sh").read_text()
    assert "Keep this Terminal window open" in serve
    assert "native-up-user-services.sh" in serve
    assert "native-health.sh" in serve
    assert "sudo" not in user_up
    assert "sudo" not in user_pg
    assert "sudo" not in user_redis
    assert "/private/tmp/hawk-native-demo/postgres-data" in user_pg
    assert "initdb" in user_pg
    assert "--auth=trust" in user_pg
    assert "/private/tmp/hawk-native-demo/redis-data" in user_redis


def test_native_gateway_preserves_local_tls_url_without_caddy() -> None:
    gateway = (ROOT / "infra" / "scripts" / "native-gateway.mjs").read_text()

    assert "hawk-local.crt" in gateway
    assert "hawk-local.key" in gateway
    assert "api.hawk.localhost" in gateway
    assert "/api/" in gateway
    assert '"/auth"' in gateway
    assert '"/endpoint-agent"' in gateway
    assert '"/extension"' in gateway
    assert "acceptsHtml" in gateway
    assert "!acceptsHtml(req)" in gateway
    assert "127.0.0.1" in gateway


