import json
import ssl
import urllib.error
from io import BytesIO
from unittest.mock import patch

import pytest

from hawk_endpoint_agent.auth.device_key import DeviceKeyError, EphemeralDeviceKeyProvider
from hawk_endpoint_agent.auth.session import EndpointAuthSession, EnrollmentBundle
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.enroll import enroll, enroll_existing_config


SECRET = "never-print-enrollment-secret"
BUNDLE = EnrollmentBundle("authorization-1", SECRET, SECRET)


def run_enrollment(tmp_path, existing, session):
    path = tmp_path / "config.json"
    config = dict(api_base_url="https://hawk.example", tenant_id="tenant-1",
                  endpoint_id="endpoint-1", default_ai_system_id="system-1")
    if existing:
        path.write_text(json.dumps(config))
        report = enroll_existing_config(config_path=path, enrollment_bundle=BUNDLE,
                                        auth_session=session)
    else:
        report = enroll(api_url=config.pop("api_base_url"), **config, config_path=path,
                        enrollment_bundle=BUNDLE, auth_session=session)
    rendered = json.dumps(report.as_dict())
    assert SECRET not in rendered
    assert not report.as_dict()["ok"]
    return next(s for s in report.steps if s["step"] == "device_identity")


def real_session():
    return EndpointAuthSession(config=AgentConfig(api_base_url="https://hawk.example"),
                               provider=EphemeralDeviceKeyProvider())


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("status,body,reason", [
    (401, {"detail": "Endpoint enrollment authorization is invalid or expired",
           "enrollment_code": SECRET}, "authorization_invalid_or_expired"),
    (409, {"detail": "Endpoint already has an active identity"}, "identity_already_active"),
    (500, {"detail": SECRET}, "http_error"),
    (422, {"detail": [{"loc": ["body", "enrollment_code"], "input": SECRET,
                       "msg": SECRET, "ctx": {"error": SECRET}}]}, "request_validation_failed"),
])
def test_http_diagnostic_keeps_status_and_safe_reason(tmp_path, existing, status, body, reason):
    error = urllib.error.HTTPError("https://hawk.example/" + SECRET, status, SECRET,
                                   {}, BytesIO(json.dumps(body).encode()))
    with patch("urllib.request.urlopen", side_effect=error):
        step = run_enrollment(tmp_path, existing, real_session())
    assert step["http_status"] == status
    assert step["reason"] == reason
    assert step["failure_stage"] == "enrollment_exchange"
    assert f"HTTP {status}" in step["detail"]


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("cause,reason", [
    (ssl.SSLCertVerificationError(1, SECRET), "tls_certificate_verification_failed"),
    (TimeoutError(SECRET), "connection_timeout"),
    (ConnectionRefusedError(SECRET), "service_unavailable"),
])
def test_transport_diagnostics_do_not_echo_exception_or_url(tmp_path, existing, cause, reason):
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError(cause)):
        step = run_enrollment(tmp_path, existing, real_session())
    assert step["reason"] == reason


@pytest.mark.parametrize("existing", [False, True])
def test_key_error_uses_safe_allowlisted_reason(tmp_path, existing):
    session = real_session()
    with patch.object(session._provider, "ensure_key", side_effect=DeviceKeyError(
        "helper is unsigned or ad-hoc signed"
    )):
        step = run_enrollment(tmp_path, existing, session)
    assert step["reason"] == "identity_helper_untrusted"
    assert "signed" in step["detail"]


@pytest.mark.parametrize("existing", [False, True])
def test_unexpected_error_never_echoes_secrets(tmp_path, existing):
    session = real_session()
    with patch.object(session, "enroll", side_effect=RuntimeError(SECRET)):
        step = run_enrollment(tmp_path, existing, session)
    assert step["reason"] == "unexpected_enrollment_error"


@pytest.mark.parametrize("existing", [False, True])
def test_response_validation_is_distinct_from_exchange(tmp_path, existing):
    session = real_session()
    with patch.object(session, "enroll", return_value={"key_thumbprint": SECRET}):
        step = run_enrollment(tmp_path, existing, session)
    assert step["reason"] == "invalid_enrollment_response"
    assert step["failure_stage"] == "validate_response"


def test_config_write_failure_does_not_claim_network_failure(tmp_path):
    session = real_session()
    with patch.object(session, "enroll", return_value={"key_thumbprint": "a" * 64}), patch(
        "hawk_endpoint_agent.enroll._write_secure", side_effect=PermissionError(SECRET)
    ):
        step = run_enrollment(tmp_path, True, session)
    assert step["reason"] == "config_persistence_failed"
    assert step["failure_stage"] == "persist_config"
    assert "server" in step["detail"]
