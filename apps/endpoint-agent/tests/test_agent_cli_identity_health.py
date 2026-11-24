from __future__ import annotations

from types import SimpleNamespace

import hawk_endpoint_agent.__main__ as agent_cli


def test_verify_device_identity_cli_returns_redacted_success(monkeypatch, capsys) -> None:
    monkeypatch.setattr(agent_cli, "load_config", lambda _path: SimpleNamespace())
    monkeypatch.setattr(
        agent_cli,
        "verify_device_identity",
        lambda _config: SimpleNamespace(
            as_dict=lambda: {
                "ok": True,
                "provider": "macos_secure_enclave",
                "hardware_backed": True,
                "key_available": True,
                "key_thumbprint_matches": True,
                "signature_verified": True,
            }
        ),
    )

    result = agent_cli.main(["--config", "/private/config", "--verify-device-identity"])

    output = capsys.readouterr().out
    assert result == 0
    assert '"signature_verified": true' in output
    assert "public_key" not in output
    assert "thumbprint\"" not in output
    assert "signature\"" not in output


def test_verify_device_identity_cli_returns_stable_failure(monkeypatch, capsys) -> None:
    monkeypatch.setattr(agent_cli, "load_config", lambda _path: SimpleNamespace())

    def fail(_config):
        raise agent_cli.DeviceIdentityHealthError("sensitive native detail")

    monkeypatch.setattr(agent_cli, "verify_device_identity", fail)

    result = agent_cli.main(["--config", "/private/config", "--verify-device-identity"])

    output = capsys.readouterr().out
    assert result == 1
    assert "device_identity_verification_failed" in output
    assert "sensitive native detail" not in output

