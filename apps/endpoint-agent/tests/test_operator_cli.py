from __future__ import annotations

import json
from pathlib import Path

from hawk_endpoint_agent.config import AgentConfig
import hawk_endpoint_agent.operator_cli as operator_cli
from hawk_endpoint_agent.operator_cli import main


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "config.json"
    config = AgentConfig(
        agent_mode="monitor",
        security_profile="development",
        key_provider="development_ephemeral",
        local_operator_changes_allowed=True,
        mode_state_path=str(tmp_path / "mode.json"),
        baseline_path=str(tmp_path / "baseline.json"),
        evidence_queue_path=str(tmp_path / "queue.json"),
        ipc_socket_path=str(tmp_path / "agent.sock"),
    )
    data = config.redacted()
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_bank_mode_rejects_local_mode_change(tmp_path, capsys) -> None:
    config_path = _config(tmp_path)
    data = json.loads(config_path.read_text())
    data["security_profile"] = "bank"
    data["key_provider"] = "macos_secure_enclave"
    data["api_base_url"] = "https://hawk.example"
    config_path.write_text(json.dumps(data), encoding="utf-8")
    config_path.chmod(0o600)

    result = main(["--config", str(config_path), "mode", "enforce"])

    assert result == 2
    assert not (tmp_path / "mode.json").exists()
    assert "managed_authorization_required" in capsys.readouterr().out


def test_explicit_development_local_control_can_change_mode(tmp_path, capsys) -> None:
    config_path = _config(tmp_path)

    result = main(["--config", str(config_path), "mode", "enforce"])

    assert result == 0
    assert json.loads((tmp_path / "mode.json").read_text())["mode"] == "enforce"
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "enforce"
    assert output["status"] == "ok"


def test_status_contains_no_static_credential_fields(tmp_path, capsys) -> None:
    config_path = _config(tmp_path)

    result = main(["--config", str(config_path), "status"])

    assert result == 0
    output = capsys.readouterr().out
    assert "agent_token" not in output
    assert "operator_token" not in output
    assert json.loads(output)["mode"] == "monitor"


def test_empty_baseline_proposal_is_explicit(tmp_path, capsys) -> None:
    config_path = _config(tmp_path)

    result = main(["--config", str(config_path), "propose"])

    assert result == 0
    assert json.loads(capsys.readouterr().out)["status"] == "insufficient_evidence"


def test_manual_action_can_bind_to_specific_registered_ai_asset(tmp_path, capsys, monkeypatch) -> None:
    config_path = _config(tmp_path)
    captured: list[dict] = []

    def fake_rpc(_config, request, timeout_seconds=5):
        captured.append(request)
        return {"ok": True, "action": "allow"}

    monkeypatch.setattr(operator_cli, "_rpc", fake_rpc)
    result = main([
        "--config", str(config_path),
        "test-action", "--surface", "mcp", "--risk", "high_impact",
        "--ai-system-id", "approved-ai-system-1",
    ])

    assert result == 0
    assert captured[0]["ai_system_id"] == "approved-ai-system-1"
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_manual_action_uses_versioned_evaluate_protocol(tmp_path, capsys, monkeypatch) -> None:
    config_path = _config(tmp_path)
    captured: list[dict] = []
    monkeypatch.setattr(
        operator_cli,
        "_rpc",
        lambda _config, request, timeout_seconds=5: captured.append(request) or {"ok": True},
    )

    result = main([
        "--config", str(config_path),
        "test-action", "--surface", "mcp", "--risk", "benign",
    ])

    assert result == 0
    assert captured[0]["protocol_version"] == 1
    assert captured[0]["op"] == "evaluate"
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_manual_action_uses_bounded_extended_ipc_timeout(tmp_path, capsys, monkeypatch) -> None:
    config_path = _config(tmp_path)
    captured: list[tuple[dict, int]] = []

    def fake_rpc(_config, request, *, timeout_seconds=5):
        captured.append((request, timeout_seconds))
        return {"ok": True, "action": "allow"}

    monkeypatch.setattr(operator_cli, "_rpc", fake_rpc)

    assert main(["--config", str(config_path), "status"]) == 0
    assert main([
        "--config", str(config_path),
        "test-action", "--surface", "mcp", "--risk", "benign",
    ]) == 0

    assert captured[0][1] == 5
    assert captured[1][1] == 30
    capsys.readouterr()


def test_data_transfer_does_not_send_unsupported_ai_system_field(tmp_path, capsys, monkeypatch) -> None:
    config_path = _config(tmp_path)
    captured: list[dict] = []
    monkeypatch.setattr(
        operator_cli,
        "_rpc",
        lambda _config, request, timeout_seconds=5: captured.append(request) or {"ok": True},
    )

    result = main([
        "--config", str(config_path),
        "test-action", "--surface", "data_transfer", "--risk", "sensitive",
        "--ai-system-id", "approved-ai-system-1",
    ])

    assert result == 0
    assert "ai_system_id" not in captured[0]
