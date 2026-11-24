from __future__ import annotations

import importlib
import socket
import ssl
from types import SimpleNamespace
from urllib import request as urllib_request

import pytest


def _policy_module():
    try:
        return importlib.import_module("app.services.outbound_destination_policy")
    except ModuleNotFoundError as exc:  # expected RED before the policy is implemented
        pytest.fail(f"central outbound destination policy is missing: {exc}")


def _resolver(answers: dict[str, list[str]], calls: list[tuple[str, int]] | None = None):
    def resolve(hostname: str, port: int):
        if calls is not None:
            calls.append((hostname, port))
        if hostname not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return answers[hostname]

    return resolve


def _policy(*, source: str = "checkmarx", origins: tuple[str, ...] = ("https://api.example.com",), answers=None):
    policy_module = _policy_module()
    return policy_module.OutboundDestinationPolicy(
        {source: origins},
        resolver=_resolver(
            {"api.example.com": ["93.184.216.34"]} if answers is None else answers
        ),
    )


def test_policy_canonicalizes_hostname_and_default_port() -> None:
    policy = _policy()

    destination = policy.validate("HTTPS://API.EXAMPLE.COM:443/v1/findings", source="checkmarx")

    assert destination.origin == "https://api.example.com"
    assert destination.hostname == "api.example.com"
    assert destination.port == 443
    assert destination.addresses == ("93.184.216.34",)


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/v1",
        "https://user:password@api.example.com/v1",
        "https://api.example.com:bad/v1",
        "https:///missing-host",
    ],
)
def test_policy_rejects_non_https_userinfo_and_malformed_origins(url: str) -> None:
    policy_module = _policy_module()
    policy = _policy()

    with pytest.raises(policy_module.OutboundDestinationPolicyError):
        policy.validate(url, source="checkmarx")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.8",
        "169.254.10.20",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::",
    ],
)
def test_policy_rejects_unsafe_ip_literals(address: str) -> None:
    policy_module = _policy_module()
    literal = f"[{address}]" if ":" in address else address
    policy = policy_module.OutboundDestinationPolicy(
        {"monitoring:test": (f"https://{literal}",)},
        resolver=lambda _hostname, _port: pytest.fail("IP literals must not require DNS"),
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="non_public_address"):
        policy.validate(f"https://{literal}/events", source="monitoring:test")


def test_policy_rejects_mixed_public_and_private_dns_answers() -> None:
    policy_module = _policy_module()
    policy = _policy(answers={"api.example.com": ["93.184.216.34", "10.0.0.7"]})

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="non_public_address"):
        policy.validate("https://api.example.com/events", source="checkmarx")


def test_policy_fails_closed_when_dns_resolution_fails() -> None:
    policy_module = _policy_module()
    policy = _policy(answers={})

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="dns_resolution_failed"):
        policy.validate("https://api.example.com/events", source="checkmarx")


def test_policy_requires_the_source_specific_administrator_allowlist() -> None:
    policy_module = _policy_module()
    policy = _policy(
        source="monitoring:jira",
        origins=("https://admin-approved.example.com",),
        answers={"attacker.example": ["93.184.216.34"]},
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="destination_not_allowed"):
        policy.validate("https://attacker.example/api", source="monitoring:jira")


def test_httpx_request_revalidates_redirect_before_forwarding_credentials() -> None:
    policy_module = _policy_module()
    calls: list[tuple[str, int]] = []
    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://api.example.com", "https://redirect.example.com")},
        resolver=_resolver(
            {
                "api.example.com": ["93.184.216.34"],
                "redirect.example.com": ["10.0.0.9"],
            },
            calls,
        ),
    )
    response = SimpleNamespace(
        status_code=302,
        headers={"Location": "https://redirect.example.com/private"},
    )

    class FakeClient:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict]] = []

        def request(self, method: str, url: str, **kwargs):
            self.requests.append((method, url, kwargs))
            return response

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    client = FakeClient()

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="non_public_address"):
        policy_module.request_with_redirect_validation(
            "GET",
            "https://api.example.com/start",
            source="checkmarx",
            policy=policy,
            client_factory=lambda **_kwargs: client,
            headers={"Authorization": "Bearer secret"},
        )

    assert len(client.requests) == 1
    assert client.requests[0][2]["follow_redirects"] is False
    assert calls == [("api.example.com", 443), ("redirect.example.com", 443)]


def test_httpx_request_retains_credentials_only_for_relative_same_origin_redirect() -> None:
    policy_module = _policy_module()
    policy = _policy()
    responses = [
        SimpleNamespace(status_code=302, headers={"Location": "/v2/findings"}),
        SimpleNamespace(status_code=200, headers={}),
    ]

    class FakeClient:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict]] = []

        def request(self, method: str, url: str, **kwargs):
            self.requests.append((method, url, kwargs))
            return responses.pop(0)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    client = FakeClient()
    result = policy_module.request_with_redirect_validation(
        "GET",
        "https://api.example.com/v1/findings",
        source="checkmarx",
        policy=policy,
        client_factory=lambda **_kwargs: client,
        headers={"Authorization": "Bearer secret"},
    )

    assert result.status_code == 200
    assert [request[1] for request in client.requests] == [
        "https://api.example.com/v1/findings",
        "https://api.example.com/v2/findings",
    ]
    assert all(request[2]["headers"]["Authorization"] == "Bearer secret" for request in client.requests)


def test_httpx_request_rejects_independently_allowlisted_cross_origin_redirect() -> None:
    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://api.example.com", "https://other.example.com")},
        resolver=_resolver(
            {
                "api.example.com": ["93.184.216.34"],
                "other.example.com": ["93.184.216.35"],
            }
        ),
    )
    requests: list[str] = []

    class FakeClient:
        def request(self, method: str, url: str, **kwargs):  # noqa: ARG002
            requests.append(url)
            return SimpleNamespace(
                status_code=302,
                headers={"Location": "https://other.example.com/next"},
            )

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    client = FakeClient()

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="credential_redirect_origin_changed"):
        policy_module.request_with_redirect_validation(
            "GET",
            "https://api.example.com/start",
            source="checkmarx",
            policy=policy,
            client_factory=lambda **_kwargs: client,
            headers={"Authorization": "Bearer secret"},
        )
    assert requests == ["https://api.example.com/start"]


def test_httpx_request_bounds_same_origin_redirect_loop() -> None:
    policy_module = _policy_module()
    policy = _policy()
    calls = 0

    class FakeClient:
        def request(self, method: str, url: str, **kwargs):  # noqa: ARG002
            nonlocal calls
            calls += 1
            return SimpleNamespace(status_code=302, headers={"Location": "/loop"})

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    client = FakeClient()

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="too_many_redirects"):
        policy_module.request_with_redirect_validation(
            "GET",
            "https://api.example.com/loop",
            source="checkmarx",
            policy=policy,
            max_redirects=2,
            client_factory=lambda **_kwargs: client,
        )
    assert calls == 3


def test_policy_canonicalizes_idna_and_trailing_dot_before_allowlist_match() -> None:
    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"test": ("https://xn--bcher-kva.example",)},
        resolver=_resolver({"xn--bcher-kva.example": ["93.184.216.34"]}),
    )

    destination = policy.validate("https://BÜCHER.example./feed", source="test")

    assert destination.origin == "https://xn--bcher-kva.example"


def test_urllib_redirect_handler_revalidates_target_before_copying_auth_header() -> None:
    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"external-risk:github": ("https://api.example.com", "https://redirect.example.com")},
        resolver=_resolver(
            {
                "api.example.com": ["93.184.216.34"],
                "redirect.example.com": ["127.0.0.1"],
            }
        ),
    )
    handler = policy_module.ValidatingHTTPRedirectHandler(
        policy=policy,
        source="external-risk:github",
    )
    request = urllib_request.Request(
        "https://api.example.com/start",
        headers={"Authorization": "Bearer secret"},
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="non_public_address"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://redirect.example.com/private",
        )


def test_checkmarx_connector_config_cannot_authorize_its_own_custom_origins() -> None:
    policy_module = _policy_module()
    from app.services.checkmarx_one_service import create_client_from_connector_config

    policy = _policy(
        origins=("https://ast.checkmarx.net", "https://iam.checkmarx.net"),
        answers={"attacker.example": ["93.184.216.34"]},
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="destination_not_allowed"):
        create_client_from_connector_config(
            {
                "tenant_name": "acme",
                "base_url": "https://attacker.example",
                "iam_url": "https://attacker.example",
                "allowed_origins": ["https://attacker.example"],
            },
            {"client_id": "client", "client_secret": "secret"},
            destination_policy=policy,
        )


def test_external_risk_source_policy_cannot_authorize_credential_destination() -> None:
    policy_module = _policy_module()
    from app.db.models.external_risk import ExternalRiskSource
    from app.services.external_risk_intel.source_connector import fetch_source_records

    source = ExternalRiskSource(
        tenant_id="tenant-1",
        source="github",
        display_name="GitHub",
        enabled=True,
        endpoint_url="https://attacker.example/advisories",
        auth_mode="bearer",
        auth_config={"bearer_token": "secret"},
        source_trust_policy={},
        egress_policy={"allowed_origins": ["https://attacker.example"]},
        redaction_policy={},
        routing_policy={},
        transport_policy={},
        sync_schedule="0 */6 * * *",
        last_sync_status="never",
    )
    policy = _policy(
        source="external-risk:github",
        origins=("https://api.github.com",),
        answers={"attacker.example": ["93.184.216.34"]},
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="destination_not_allowed"):
        fetch_source_records(source, destination_policy=policy)


def test_external_risk_endpoint_origin_change_clears_retained_auth(monkeypatch) -> None:
    from app.services.external_risk_intel import service
    from app.services.external_risk_intel.transport_security import SecurityDecision

    existing = SimpleNamespace(
        source="github",
        display_name="GitHub",
        enabled=True,
        endpoint_url="https://api.github.com/advisories",
        auth_mode="bearer",
        auth_config={"bearer_token": "old-secret"},
        source_trust_policy={},
        egress_policy={},
        redaction_policy={},
        routing_policy={},
        transport_policy={},
        sync_schedule="0 */6 * * *",
    )

    class FakeDB:
        def scalar(self, _statement):
            return existing

        def flush(self) -> None:
            return None

    monkeypatch.setattr(
        service,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {}),
    )

    updated = service.upsert_source(
        FakeDB(),
        tenant_id="tenant-1",
        payload={
            "source": "github",
            "endpoint_url": "https://security.example.com/advisories",
        },
    )

    assert updated.auth_mode == "none"
    assert updated.auth_config == {}


def test_monitoring_validates_destination_before_decrypting_connector_secret(monkeypatch) -> None:
    policy_module = _policy_module()
    from app.services import monitoring_service

    connector = SimpleNamespace(
        tenant_id="tenant-1",
        config={
            "base_url": "https://attacker.example",
            "allowed_origins": ["https://attacker.example"],
        },
        provider_key="jira",
        connector_type="jira",
        encrypted_secrets="ciphertext",
    )
    policy = _policy(
        source="monitoring:jira",
        origins=("https://admin-approved.example.com",),
        answers={"attacker.example": ["93.184.216.34"]},
    )
    monkeypatch.setattr(
        monitoring_service,
        "decrypt_connector_secrets",
        lambda _value: pytest.fail("destination must be rejected before decrypting credentials"),
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="destination_not_allowed"):
        monitoring_service.run_connector_once(
            SimpleNamespace(),
            tenant_id="tenant-1",
            connector=connector,
            destination_policy=policy,
        )


def test_pinned_network_backend_connects_only_to_the_approved_address() -> None:
    policy_module = _policy_module()
    connected: list[tuple[str, int]] = []
    dns_answers = iter(
        [
            ("93.184.216.34",),
            ("10.0.0.9",),
        ]
    )
    resolver_calls = 0

    def resolver(_hostname, _port):  # noqa: ANN001
        nonlocal resolver_calls
        resolver_calls += 1
        return next(dns_answers)

    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://api.example.com",)},
        resolver=resolver,
    )
    destination = policy.validate("https://api.example.com/data", source="checkmarx")

    class Delegate:
        def connect_tcp(self, host, port, **_kwargs):  # noqa: ANN001
            connected.append((host, port))
            return object()

    backend = policy_module.PinnedNetworkBackend(
        expected_hostname=destination.hostname,
        approved_address=destination.approved_address,
        delegate=Delegate(),
    )

    backend.connect_tcp("api.example.com", 443)

    assert connected == [("93.184.216.34", 443)]
    assert resolver_calls == 1


def test_pinned_https_connection_preserves_original_tls_server_name(monkeypatch) -> None:
    policy_module = _policy_module()
    connected: list[tuple[str, int]] = []
    server_names: list[str] = []

    class RawSocket:
        def setsockopt(self, *_args) -> None:
            return None

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def wrap_socket(sock, *, server_hostname):  # noqa: ANN001
        server_names.append(server_hostname)
        return sock

    monkeypatch.setattr(context, "wrap_socket", wrap_socket)

    connection = policy_module.PinnedHTTPSConnection(
        "api.example.com",
        port=443,
        approved_address="93.184.216.34",
        context=context,
    )
    connection._create_connection = (  # noqa: SLF001
        lambda address, _timeout, _source_address: connected.append(address) or RawSocket()
    )

    connection.connect()

    assert connected == [("93.184.216.34", 443)]
    assert server_names == ["api.example.com"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_httpx_redirect_re_resolves_and_repins_same_origin() -> None:
    policy_module = _policy_module()
    dns_answers = iter(["93.184.216.34", "93.184.216.35"])
    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://api.example.com",)},
        resolver=lambda _hostname, _port: (next(dns_answers),),
    )
    pinned: list[str] = []
    responses = [
        SimpleNamespace(status_code=302, headers={"Location": "/next"}),
        SimpleNamespace(status_code=200, headers={}),
    ]

    class FakeClient:
        def __init__(self, *, transport, **_kwargs):  # noqa: ANN001
            pinned.append(transport.approved_address)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, _method, _url, **_kwargs):  # noqa: ANN001
            return responses.pop(0)

    result = policy_module.request_with_redirect_validation(
        "GET",
        "https://api.example.com/start",
        source="checkmarx",
        policy=policy,
        client_factory=FakeClient,
    )

    assert result.status_code == 200
    assert pinned == ["93.184.216.34", "93.184.216.35"]


def test_curl_fallback_uses_resolve_to_pin_approved_public_address(monkeypatch) -> None:
    from app.db.models.external_risk import ExternalRiskSource
    from app.services.external_risk_intel import source_connector

    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"external-risk:nvd": ("https://api.example.com",)},
        resolver=lambda _hostname, _port: ("93.184.216.34",),
    )
    source = ExternalRiskSource(source="nvd", auth_mode="none")
    request = urllib_request.Request("https://api.example.com/feed")
    commands: list[list[str]] = []
    monkeypatch.setattr(source_connector.shutil, "which", lambda _name: "/usr/bin/curl")
    monkeypatch.setattr(
        source_connector.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command)
        or SimpleNamespace(returncode=0, stdout='{"records": []}', stderr=""),
    )

    source_connector._fetch_json_via_curl(  # noqa: SLF001
        source=source,
        request=request,
        timeout_seconds=3.0,
        destination_policy=policy,
    )

    resolve_index = commands[0].index("--resolve")
    assert commands[0][resolve_index + 1] == "api.example.com:443:93.184.216.34"
    noproxy_index = commands[0].index("--noproxy")
    assert commands[0][noproxy_index + 1] == "*"
    assert "--location" not in commands[0]


def test_external_risk_opener_has_only_pinned_https_and_no_proxy_handler() -> None:
    from app.services.external_risk_intel import source_connector

    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"external-risk:nvd": ("https://api.example.com",)},
        resolver=lambda _hostname, _port: ("93.184.216.34",),
    )
    opener = source_connector._build_source_opener(  # noqa: SLF001
        policy=policy,
        source_key="external-risk:nvd",
        context=SimpleNamespace(),
    )

    assert not any(isinstance(handler, urllib_request.ProxyHandler) for handler in opener.handlers)
    assert any(isinstance(handler, policy_module.PinnedHTTPSHandler) for handler in opener.handlers)
    assert not any(type(handler) is urllib_request.HTTPSHandler for handler in opener.handlers)


def test_curl_fallback_brackets_approved_ipv6_resolve_address(monkeypatch) -> None:
    from app.db.models.external_risk import ExternalRiskSource
    from app.services.external_risk_intel import source_connector

    policy_module = _policy_module()
    policy = policy_module.OutboundDestinationPolicy(
        {"external-risk:nvd": ("https://api.example.com",)},
        resolver=lambda _hostname, _port: ("2606:4700:4700::1111",),
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(source_connector.shutil, "which", lambda _name: "/usr/bin/curl")
    monkeypatch.setattr(
        source_connector.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command)
        or SimpleNamespace(returncode=0, stdout='{"records": []}', stderr=""),
    )

    source_connector._fetch_json_via_curl(  # noqa: SLF001
        source=ExternalRiskSource(source="nvd", auth_mode="none"),
        request=urllib_request.Request("https://api.example.com/feed"),
        timeout_seconds=3.0,
        destination_policy=policy,
    )

    resolve_index = commands[0].index("--resolve")
    assert commands[0][resolve_index + 1] == "api.example.com:443:[2606:4700:4700::1111]"


def test_checkmarx_upload_requires_dedicated_admin_origin() -> None:
    policy_module = _policy_module()
    from app.services.checkmarx_one_service import CheckmarxOneClient

    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://ast.checkmarx.net",)},
        resolver=_resolver({"storage.example.com": ["93.184.216.34"]}),
    )
    client = CheckmarxOneClient(
        api_url="https://ast.checkmarx.net",
        iam_url="https://iam.checkmarx.net",
        tenant_name="tenant",
        destination_policy=policy,
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="destination_not_allowed"):
        client.upload_source("https://storage.example.com/upload", b"source-bytes")


@pytest.mark.parametrize("header_name", ["Host", "host", "hOsT"])
def test_httpx_request_rejects_caller_supplied_host_header_before_network(header_name: str) -> None:
    policy_module = _policy_module()
    policy = _policy()

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="host_header_not_allowed"):
        policy_module.request_with_redirect_validation(
            "GET",
            "https://api.example.com/data",
            source="checkmarx",
            policy=policy,
            client_factory=lambda **_kwargs: pytest.fail("Host override must fail before client creation"),
            headers={header_name: "attacker.example"},
        )


def test_urllib_pinned_handler_rejects_host_header_before_validation_or_connection() -> None:
    policy_module = _policy_module()
    from app.db.models.external_risk import ExternalRiskSource
    from app.services.external_risk_intel import source_connector

    policy = policy_module.OutboundDestinationPolicy(
        {"external-risk:github": ("https://api.example.com",)},
        resolver=lambda _hostname, _port: pytest.fail("Host override must fail before DNS validation"),
    )
    handler = policy_module.PinnedHTTPSHandler(
        policy=policy,
        source="external-risk:github",
        context=SimpleNamespace(),
    )
    handler.do_open = lambda *_args, **_kwargs: pytest.fail("Host override must fail before connection")
    source = ExternalRiskSource(
        source="github",
        auth_mode="api_key",
        auth_config={"api_key": "secret", "api_key_header": "hOsT"},
    )
    request = urllib_request.Request(
        "https://api.example.com/data",
        headers=source_connector._auth_headers(source),  # noqa: SLF001
    )

    with pytest.raises(policy_module.OutboundDestinationPolicyError, match="host_header_not_allowed"):
        handler.https_open(request)


def test_pinned_http_transport_preserves_environment_ca_configuration_without_proxy(monkeypatch) -> None:
    policy_module = _policy_module()
    destination = _policy().validate("https://api.example.com/data", source="checkmarx")
    context_calls: list[dict] = []

    def create_ssl_context(**kwargs):  # noqa: ANN003,ANN202
        context_calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(policy_module.httpx, "create_ssl_context", create_ssl_context)

    transport = policy_module.PinnedHTTPTransport(destination)

    assert context_calls == [{"verify": True, "trust_env": True}]
    assert type(transport._pool) is policy_module.httpcore.ConnectionPool  # noqa: SLF001
    assert isinstance(transport._pool._network_backend, policy_module.PinnedNetworkBackend)  # noqa: SLF001


@pytest.mark.parametrize(
    ("method", "status_code", "expected_method"),
    [
        ("PUT", 302, "GET"),
        ("HEAD", 303, "HEAD"),
        ("POST", 301, "GET"),
    ],
)
def test_httpx_redirect_method_matches_httpx_semantics(
    method: str,
    status_code: int,
    expected_method: str,
) -> None:
    policy_module = _policy_module()
    policy = _policy()
    responses = [
        SimpleNamespace(status_code=status_code, headers={"Location": "/next"}),
        SimpleNamespace(status_code=200, headers={}),
    ]
    requests: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, request_method, _url, **kwargs):  # noqa: ANN001
            requests.append((request_method, kwargs))
            return responses.pop(0)

    policy_module.request_with_redirect_validation(
        method,
        "https://api.example.com/start",
        source="checkmarx",
        policy=policy,
        client_factory=FakeClient,
        transport_factory=lambda destination, **_kwargs: SimpleNamespace(
            approved_address=destination.approved_address
        ),
        content=b"body",
        headers={
            "Authorization": "Bearer secret",
            "content-LENGTH": "4",
            "Transfer-Encoding": "chunked",
        },
    )

    assert requests[1][0] == expected_method
    if expected_method == "GET":
        assert "content" not in requests[1][1]
        redirected_headers = requests[1][1]["headers"]
        assert not any(name.lower() == "content-length" for name in redirected_headers)
        assert not any(name.lower() == "transfer-encoding" for name in redirected_headers)
        assert redirected_headers["Authorization"] == "Bearer secret"


def test_httpx_request_can_restrict_redirect_statuses_without_changing_default() -> None:
    policy_module = _policy_module()
    policy = _policy()
    requests: list[tuple[str, bytes | None]] = []

    class FakeClient:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, method, _url, **kwargs):  # noqa: ANN001
            requests.append((method, kwargs.get("content")))
            return SimpleNamespace(status_code=302, headers={"Location": "/next"})

    with pytest.raises(
        policy_module.OutboundDestinationPolicyError,
        match="redirect_status_not_allowed",
    ):
        policy_module.request_with_redirect_validation(
            "POST",
            "https://api.example.com/start",
            source="checkmarx",
            policy=policy,
            client_factory=FakeClient,
            transport_factory=lambda destination, **_kwargs: SimpleNamespace(
                approved_address=destination.approved_address
            ),
            allowed_redirect_statuses=frozenset({307, 308}),
            content=b"exact-body",
        )

    assert requests == [("POST", b"exact-body")]


def test_checkmarx_monitoring_auth_propagates_injected_destination_policy(monkeypatch) -> None:
    policy_module = _policy_module()
    from app.services import integration_connector_service
    from app.services import checkmarx_one_service

    policy = policy_module.OutboundDestinationPolicy(
        {"checkmarx": ("https://ast.checkmarx.net",)},
        resolver=lambda _hostname, _port: ("93.184.216.34",),
    )
    captured: dict[str, object] = {}

    class FakeCheckmarxClient:
        api_url = "https://ast.checkmarx.net"

        def authenticate(self) -> str:
            return "token"

    def create_client(connector_config, secrets, **kwargs):  # noqa: ANN001,ANN202
        captured.update(kwargs)
        return FakeCheckmarxClient()

    monkeypatch.setattr(checkmarx_one_service, "create_client_from_connector_config", create_client)

    base_url, headers, error = integration_connector_service._authenticate_http(  # noqa: SLF001
        integration_connector_service.PROVIDERS["checkmarx"],
        {"base_url": "https://ast.checkmarx.net"},
        {"client_id": "client", "client_secret": "secret"},
        destination_policy=policy,
    )

    assert error == ""
    assert base_url == "https://ast.checkmarx.net"
    assert headers == {"Authorization": "Bearer token"}
    assert captured["destination_policy"] is policy
