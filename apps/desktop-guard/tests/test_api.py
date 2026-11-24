from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.api import HawkApiClient, UnavailableApiClient
from hawk_desktop_guard.models import PromptSnapshot


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return BytesIO(self._body).read()


def test_login_builds_api_client_from_credentials(monkeypatch) -> None:
    requests = []

    def fake_urlopen(req, timeout):
        requests.append((req, timeout))
        return FakeResponse(
            {
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "selected_tenant_id": "tenant-1",
                "tenants": [{"id": "tenant-1"}],
            }
        )

    monkeypatch.setattr("hawk_desktop_guard.api.request.urlopen", fake_urlopen)

    client = HawkApiClient.login(api_url="http://127.0.0.1:8000", email="owner@example.com", password="Password123!")

    assert client.access_token == "access-1"
    assert client.tenant_id == "tenant-1"
    body = json.loads(requests[0][0].data.decode("utf-8"))
    assert body == {"email": "owner@example.com", "password": "Password123!"}


def test_unavailable_api_client_raises_clear_error() -> None:
    client = UnavailableApiClient(reason="login failed")

    try:
        client.evaluate_prompt(
            PromptSnapshot(
                application="Claude Desktop",
                desktop_app="Claude",
                prompt_text="hello",
                prompt_preview_redacted="hello",
                capture_method="test",
            )
        )
    except RuntimeError as exc:
        assert "Hawk API unavailable" in str(exc)
        assert "login failed" in str(exc)
    else:
        raise AssertionError("expected unavailable API client to raise")
