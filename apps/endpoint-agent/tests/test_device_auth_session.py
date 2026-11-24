from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
from contextlib import contextmanager
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hawk_endpoint_agent.auth.device_key import (
    DeviceKeyError,
    DeviceKeyStatus,
    EphemeralDeviceKeyProvider,
)
from hawk_endpoint_agent.auth.dpop import build_dpop_proof
from hawk_endpoint_agent.auth.session import (
    EndpointAuthSession,
    EndpointReenrollmentRequired,
)
from hawk_endpoint_agent.config import AgentConfig, load_config
from hawk_endpoint_agent.hawk_client import HawkApiError, HawkClient


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def test_dpop_proof_is_bound_to_key_method_url_and_token() -> None:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-1")
    proof = build_dpop_proof(
        provider=provider,
        public_key_pem=identity.public_key_pem,
        method="post",
        url="https://hawk.example/endpoint-agent/policy",
        access_token=b"short-lived-token",
        issued_at=1_786_000_000,
        proof_id="proof-12345678",
    )

    encoded_header, encoded_claims, encoded_signature = proof.split(".")
    header = json.loads(_b64decode(encoded_header))
    claims = json.loads(_b64decode(encoded_claims))
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert header["jwk"]["kty"] == "EC"
    assert claims == {
        "ath": base64.urlsafe_b64encode(hashlib.sha256(b"short-lived-token").digest())
        .rstrip(b"=")
        .decode("ascii"),
        "htm": "POST",
        "htu": "https://hawk.example/endpoint-agent/policy",
        "iat": 1_786_000_000,
        "jti": "proof-12345678",
    }
    signature = _b64decode(encoded_signature)
    assert len(signature) == 64
    public_key = serialization.load_pem_public_key(identity.public_key_pem.encode("ascii"))
    public_key.verify(
        encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        ),
        f"{encoded_header}.{encoded_claims}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )


class _AuthTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict, dict]] = []
        self.token_number = 0

    def __call__(self, method: str, url: str, body: dict, headers: dict) -> dict:
        self.calls.append((method, url, body, headers))
        if url.endswith("/auth/challenge"):
            return {
                "challenge_id": f"challenge-{len(self.calls)}",
                "nonce": "n" * 32,
                "expires_at": "2026-08-06T12:00:00Z",
            }
        if url.endswith("/auth/token"):
            self.token_number += 1
            return {
                "access_token": f"endpoint-token-{self.token_number}",
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": ["endpoint:policy:read"],
            }
        raise AssertionError(url)


def test_challenge_exchange_keeps_token_only_in_encrypted_vault() -> None:
    config = AgentConfig(
        api_base_url="https://hawk.example",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        security_profile="development",
        key_provider="development_ephemeral",
    )
    transport = _AuthTransport()
    session = EndpointAuthSession(
        config=config,
        provider=EphemeralDeviceKeyProvider(),
        transport=transport,
    )

    session.renew()

    assert session.status()["state"] == "healthy"
    assert session.vault.has_token
    assert b"endpoint-token-1" not in session.vault.encrypted_bytes
    challenge_call, token_call = transport.calls
    assert challenge_call[2] == {"tenant_id": "tenant-1", "endpoint_id": "endpoint-1"}
    assert "signature" in token_call[2]
    assert "access_token" not in vars(session)
    assert "endpoint-token-1" not in repr(session)


def test_session_renews_proactively_and_force_renews_once() -> None:
    now = [1_786_000_000.0]
    config = AgentConfig(
        api_base_url="https://hawk.example",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        security_profile="development",
        key_provider="development_ephemeral",
        auth_renewal_margin_seconds=30,
    )
    transport = _AuthTransport()
    session = EndpointAuthSession(
        config=config,
        provider=EphemeralDeviceKeyProvider(),
        transport=transport,
        clock=lambda: now[0],
    )
    session.renew()
    assert transport.token_number == 1
    session.renew()
    assert transport.token_number == 1
    now[0] += 275
    session.renew()
    assert transport.token_number == 2
    session.renew(force=True)
    assert transport.token_number == 3


class _UnavailableDeviceKeyProvider:
    provider_name = "macos_secure_enclave"

    def ensure_key(self, _endpoint_id):
        raise DeviceKeyError("invalid sealed reference")

    def sign(self, _payload):
        raise DeviceKeyError("invalid sealed reference")

    def status(self):
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=False,
            hardware_backed=False,
            signed_helper=False,
            detail="invalid sealed reference",
        )


def test_device_key_failure_requires_reenrollment_without_escaping_raw_provider_error() -> None:
    config = AgentConfig(
        api_base_url="https://hawk.example",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        security_profile="development",
        key_provider="macos_secure_enclave",
    )
    session = EndpointAuthSession(
        config=config,
        provider=_UnavailableDeviceKeyProvider(),
        transport=_AuthTransport(),
    )

    with pytest.raises(EndpointReenrollmentRequired):
        session.renew()

    assert session.status()["state"] == "re_enrollment_required"
    assert session.status()["last_error"] == "device_identity_unavailable"
    assert session.vault.has_token is False


class _FakeAuthSession:
    def __init__(self) -> None:
        self.header_calls: list[tuple[str, str]] = []
        self.invalidations = 0
        self.force_renewals = 0

    @contextmanager
    def authenticated_headers(self, method: str, url: str):
        self.header_calls.append((method, url))
        yield {"Authorization": "DPoP short-lived", "DPoP": "proof"}

    def invalidate(self) -> None:
        self.invalidations += 1

    def renew(self, *, force: bool = False) -> None:
        self.force_renewals += int(force)


class _Response:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return self._payload


def test_hawk_client_uses_endpoint_routes_and_retries_one_401(monkeypatch) -> None:
    auth = _FakeAuthSession()
    attempts = []

    def urlopen(request, timeout):
        attempts.append(request)
        if len(attempts) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "unauthorized",
                {},
                BytesIO(b'{"detail":"expired"}'),
            )
        return _Response({"decision": "allow"})

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    config = AgentConfig(
        api_base_url="https://hawk.example",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
    )
    client = HawkClient(config, auth_session=auth)

    assert client.intercept_llm({"prompt": "safe"}) == {"decision": "allow"}
    assert len(attempts) == 2
    assert attempts[0].full_url.endswith("/endpoint-agent/decision/llm")
    assert attempts[0].headers["Authorization"] == "DPoP short-lived"
    assert attempts[0].headers["Dpop"] == "proof"
    assert auth.invalidations == 1
    assert auth.force_renewals == 1


def test_hawk_client_never_retries_403(monkeypatch) -> None:
    auth = _FakeAuthSession()
    attempts = []

    def urlopen(request, timeout):
        attempts.append(request)
        raise urllib.error.HTTPError(
            request.full_url,
            403,
            "denied",
            {},
            BytesIO(b'{"detail":"scope denied"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=auth,
    )
    with pytest.raises(HawkApiError) as exc:
        client.authorize_mcp({"tool_name": "write"})
    assert exc.value.status == 403
    assert len(attempts) == 1
    assert auth.invalidations == 0


def test_all_control_and_telemetry_methods_use_endpoint_only_paths(monkeypatch) -> None:
    auth = _FakeAuthSession()
    paths = []

    def urlopen(request, timeout):
        paths.append(request.full_url.removeprefix("https://hawk.example"))
        if request.full_url.endswith("/endpoint-agent/decision/mcp/tools/scan"):
            return _Response({
                "request_id": "scan-1",
                "status": "completed",
                "scan_result_id": "scan-result-1",
                "tool_fingerprint_id": "fingerprint-1",
                "trust_status": "approved",
                "risk_factors": [],
                "evidence_bundle_id": "evidence-1",
                "tool_poisoning_decision": "allow",
                "idempotent_replay": False,
            })
        return _Response({"status": "ok"})

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=auth,
    )
    client.sync_policy()
    client.heartbeat({})
    client.intercept_llm({})
    client.authorize_mcp({})
    client.scan_mcp_tool({"request_id": "scan-1"})
    client.check_data_transfer({})
    client.eval_interaction({})
    client.evaluate_notetaker({})
    client.report_discovery({"event_type": "ai_tool_discovered"})
    client.report_evidence({})

    assert paths == [
        "/endpoint-agent/policy",
        "/endpoint-agent/heartbeat",
        "/endpoint-agent/decision/llm",
        "/endpoint-agent/decision/mcp",
        "/endpoint-agent/decision/mcp/tools/scan",
        "/endpoint-agent/decision/data-transfer",
        "/endpoint-agent/decision/interaction",
        "/endpoint-agent/notetaker/evaluate",
        "/endpoint-agent/telemetry",
        "/endpoint-agent/evidence",
    ]


def test_hawk_client_posts_a_metadata_only_hmair_snapshot(monkeypatch) -> None:
    paths: list[str] = []

    def urlopen(request, timeout):
        paths.append(request.full_url.removeprefix("https://hawk.example"))
        return _Response(
            {
                "scan_id": "00000000-0000-4000-8000-000000000001",
                "status": "complete",
                "observations_count": 0,
                "endpoint_denominator": 1,
                "limitations": ["coverage:single_enrolled_endpoint"],
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=_FakeAuthSession(),
    )

    assert hasattr(client, "report_hmair_snapshot")
    receipt = client.report_hmair_snapshot({"snapshot_id": "lab-snapshot-001"})

    assert paths == ["/endpoint-agent/discovery/snapshots"]
    assert receipt["scan_id"] == "00000000-0000-4000-8000-000000000001"


@pytest.mark.parametrize("constraints_enforced", [None, False])
def test_hawk_client_fails_closed_for_unenforced_mcp_scope(
    monkeypatch,
    constraints_enforced,
) -> None:
    def urlopen(_request, timeout):
        assert timeout > 0
        return _Response({
            "decision": "scope",
            "final_decision": "allow" if constraints_enforced is None else "scope",
            "control_mode": "scoped",
            "constraints_enforced": constraints_enforced,
        })

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=_FakeAuthSession(),
    )
    response = client.authorize_mcp({"tool_name": "read"})
    assert response["decision"] == "block"
    assert response["final_decision"] == "block"
    assert response["reason_code"] == "mcp_scope_constraints_unverified"


def test_hawk_client_preserves_only_explicitly_enforced_mcp_scope(monkeypatch) -> None:
    def urlopen(_request, timeout):
        assert timeout > 0
        return _Response({
            "decision": "scope",
            "control_mode": "scoped",
            "constraints_enforced": True,
        })

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=_FakeAuthSession(),
    )
    response = client.authorize_mcp({"tool_name": "read"})
    assert response["decision"] == "scope"
    assert response["constraints_enforced"] is True


def test_hawk_client_accepts_only_correlated_persistent_mcp_scan(monkeypatch) -> None:
    payload = {
        "request_id": "scan-correlated-1",
        "mcp_server_id": "server-1",
        "tool_name": "read_record",
    }

    def urlopen(_request, timeout):
        assert timeout > 0
        return _Response({
            "request_id": payload["request_id"],
            "status": "completed",
            "scan_result_id": "scan-result-1",
            "tool_fingerprint_id": "fingerprint-1",
            "trust_status": "unknown",
            "risk_factors": [],
            "evidence_bundle_id": "evidence-1",
            "tool_poisoning_decision": "allow",
            "idempotent_replay": False,
        })

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=_FakeAuthSession(),
    )
    assert client.scan_mcp_tool(payload)["scan_result_id"] == "scan-result-1"


@pytest.mark.parametrize(
    "response",
    [
        {"request_id": "wrong", "status": "completed", "scan_result_id": "s", "tool_fingerprint_id": "f", "evidence_bundle_id": "e"},
        {"request_id": "scan-correlated-1", "status": "completed", "tool_fingerprint_id": "fabricated", "evidence_bundle_id": "e"},
        {"request_id": "scan-correlated-1", "status": "failed", "scan_result_id": "s", "tool_fingerprint_id": "f", "evidence_bundle_id": "e"},
    ],
)
def test_hawk_client_rejects_uncorrelated_or_nonpersistent_mcp_scan(
    monkeypatch,
    response,
) -> None:
    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: _Response(response))
    client = HawkClient(
        AgentConfig(api_base_url="https://hawk.example", tenant_id="t", endpoint_id="e"),
        auth_session=_FakeAuthSession(),
    )
    with pytest.raises(HawkApiError):
        client.scan_mcp_tool({
            "request_id": "scan-correlated-1",
            "mcp_server_id": "server-1",
            "tool_name": "read_record",
        })


@pytest.mark.parametrize("field", ["agent_token", "operator_token", "refresh_token"])
def test_config_rejects_persisted_legacy_credentials(tmp_path, field) -> None:
    path = tmp_path / "endpoint-agent.json"
    path.write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk.example",
                "security_profile": "bank",
                field: "must-not-be-accepted",
            }
        )
    )
    with pytest.raises(ValueError, match="static endpoint credentials"):
        load_config(path)


def test_config_rejects_legacy_credential_environment(monkeypatch, tmp_path) -> None:
    path = tmp_path / "endpoint-agent.json"
    path.write_text(
        json.dumps(
            {"api_base_url": "https://hawk.example", "security_profile": "bank"}
        )
    )
    monkeypatch.setenv("HAWK_AGENT_TOKEN", "legacy")
    with pytest.raises(ValueError, match="environment variables"):
        load_config(path)


def test_bank_config_rejects_file_backed_tls_private_keys(tmp_path) -> None:
    path = tmp_path / "endpoint-agent.json"
    path.write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk.example",
                "security_profile": "bank",
                "tls_intercept_enabled": True,
            }
        )
    )
    with pytest.raises(ValueError, match="file-backed TLS"):
        load_config(path)
