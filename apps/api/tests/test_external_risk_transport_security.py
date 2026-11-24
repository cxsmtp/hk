from __future__ import annotations

import ssl
import sys
import types

import pytest

from app.services.external_risk_intel import transport_security as ts


class _DummySSLContext:
    def __init__(self) -> None:
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE
        self.options = 0
        self.minimum_version = ssl.TLSVersion.TLSv1_2
        self.loaded_cert_chain: tuple[str, str] | None = None

    def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
        self.loaded_cert_chain = (certfile, keyfile)


def test_build_ssl_context_uses_explicit_ca_bundle_path(monkeypatch, tmp_path) -> None:
    ca_path = tmp_path / "ca-bundle.pem"
    ca_path.write_text("dummy-ca")
    captured: list[str | None] = []

    def _fake_create_default_context(*, purpose: ssl.Purpose, cafile: str | None = None) -> _DummySSLContext:
        assert purpose == ssl.Purpose.SERVER_AUTH
        captured.append(cafile)
        return _DummySSLContext()

    monkeypatch.setattr(ts.ssl, "create_default_context", _fake_create_default_context)
    ctx = ts.build_ssl_context(
        transport_policy={"minimum_tls_version": "TLSv1.3", "ca_bundle_path": str(ca_path)},
        auth_config={},
    )
    assert isinstance(ctx, _DummySSLContext)
    assert captured == [str(ca_path)]
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_build_ssl_context_rejects_invalid_explicit_ca_bundle_path() -> None:
    with pytest.raises(ValueError, match="invalid_ca_bundle_path"):
        ts.build_ssl_context(
            transport_policy={"ca_bundle_path": "/definitely/missing/ca.pem"},
            auth_config={},
        )


def test_build_ssl_context_falls_back_to_certifi_bundle(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    ca_path = tmp_path / "certifi-ca.pem"
    ca_path.write_text("dummy-ca")
    captured: list[str | None] = []

    def _fake_create_default_context(*, purpose: ssl.Purpose, cafile: str | None = None) -> _DummySSLContext:
        assert purpose == ssl.Purpose.SERVER_AUTH
        captured.append(cafile)
        return _DummySSLContext()

    fake_certifi = types.SimpleNamespace(where=lambda: str(ca_path))
    monkeypatch.setitem(sys.modules, "certifi", fake_certifi)
    monkeypatch.setattr(ts.ssl, "create_default_context", _fake_create_default_context)

    ts.build_ssl_context(
        transport_policy={},
        auth_config={},
    )
    assert captured == [str(ca_path)]


def test_build_ssl_context_uses_system_trust_store_when_requested(monkeypatch) -> None:
    fake_ctx = _DummySSLContext()
    fake_truststore = types.SimpleNamespace(SSLContext=lambda _protocol: fake_ctx)
    monkeypatch.setitem(sys.modules, "truststore", fake_truststore)

    def _fail_if_called(*, purpose: ssl.Purpose, cafile: str | None = None) -> _DummySSLContext:  # noqa: ARG001
        raise AssertionError("ssl.create_default_context should not be used when truststore is available")

    monkeypatch.setattr(ts.ssl, "create_default_context", _fail_if_called)
    ctx = ts.build_ssl_context(
        transport_policy={},
        auth_config={},
        use_system_trust_store=True,
    )
    assert ctx is fake_ctx
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_build_ssl_context_system_mode_falls_back_to_python_default(monkeypatch) -> None:
    fake_truststore = types.SimpleNamespace(SSLContext=lambda _protocol: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setitem(sys.modules, "truststore", fake_truststore)
    captured: list[str | None] = []

    def _fake_create_default_context(*, purpose: ssl.Purpose, cafile: str | None = None) -> _DummySSLContext:
        assert purpose == ssl.Purpose.SERVER_AUTH
        captured.append(cafile)
        return _DummySSLContext()

    monkeypatch.setattr(ts.ssl, "create_default_context", _fake_create_default_context)
    ts.build_ssl_context(
        transport_policy={},
        auth_config={},
        use_system_trust_store=True,
    )
    assert captured == [None]
