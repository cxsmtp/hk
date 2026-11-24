from __future__ import annotations

from app.main import _build_cors_allowed_origins


def test_cors_origins_include_only_explicit_extension_origins() -> None:
    origins = _build_cors_allowed_origins(
        web_origin="https://hawk-ui.local",
        cors_origins="https://admin.hawk.local,http://localhost:3000",
        extension_cors_origins="chrome-extension://abcdefghijklmnop,moz-extension://12345678-abcd",
    )

    assert "https://hawk-ui.local" in origins
    assert "https://admin.hawk.local" in origins
    assert "chrome-extension://abcdefghijklmnop" in origins
    assert "moz-extension://12345678-abcd" in origins
    assert "chrome-extension://other-extension" not in origins


def test_cors_origins_drop_wildcards_when_credentials_are_enabled() -> None:
    origins = _build_cors_allowed_origins(
        web_origin="http://localhost:3000",
        cors_origins="*,chrome-extension://*,https://hawk-ui.local",
        extension_cors_origins="moz-extension://*,edge-extension://*,chrome-extension://goodid123456",
    )

    assert "*" not in origins
    assert "chrome-extension://*" not in origins
    assert "moz-extension://*" not in origins
    assert "edge-extension://*" not in origins
    assert "https://hawk-ui.local" in origins
    assert "chrome-extension://goodid123456" in origins
