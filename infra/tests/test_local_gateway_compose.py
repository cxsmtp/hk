from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "infra" / "docker-compose.yml"
CADDY_PATH = ROOT / "infra" / "Caddyfile.local-production"


def _compose() -> dict:
    assert COMPOSE_PATH.exists(), "local platform Compose file is missing"
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_web_uses_tls_gateway_api_url_for_browser_runtime() -> None:
    web = _compose()["services"]["web"]

    assert web["environment"]["NEXT_PUBLIC_API_URL"] == "https://hawk.localhost:3443/api"
    assert web["environment"]["WEB_ORIGIN"] == "https://hawk.localhost:3443"
    assert web["environment"]["FRONTEND_URL"] == "https://hawk.localhost:3443"


def test_local_gateway_routes_same_origin_api_before_web() -> None:
    caddyfile = CADDY_PATH.read_text(encoding="utf-8")

    assert "handle_path /api/*" in caddyfile
    assert caddyfile.index("handle_path /api/*") < caddyfile.index("\thandle {\n\t\treverse_proxy web:3000")
    assert "@web_api host hawk.localhost path /api/*" not in caddyfile
