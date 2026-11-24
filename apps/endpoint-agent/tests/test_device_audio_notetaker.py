from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

from hawk_endpoint_agent.catalog import NotetakerCategory
from hawk_endpoint_agent.__main__ import build_pilot_config, run_once
from hawk_endpoint_agent.collectors.audio import (
    AudioCandidate,
    collect_platform_audio_candidates,
    parse_macos_audio_clients,
    parse_windows_audio_sessions,
)
from hawk_endpoint_agent.collectors.base import ProcessInfo
from hawk_endpoint_agent.collectors.meetings import MeetingContext
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.decision import Action, ControlMode, Decision
from hawk_endpoint_agent.enforcers.banner import BannerResult
from hawk_endpoint_agent.modules.notetaker import NotetakerController, NotetakerOutcome


def _config() -> AgentConfig:
    return AgentConfig(
        api_base_url="http://hawk.local",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        hostname="pilot-mac-1",
        os_type="darwin",
        agent_mode="enforce",
        notetaker_allow_eviction=True,
        allow_process_termination=True,
    )


def test_local_audio_notetaker_is_reported_as_endpoint_audio_signal() -> None:
    controller = NotetakerController(_config())

    detected = controller.detect(
        processes=[
            ProcessInfo(
                pid=4242,
                name="Granola",
                cmdline="/Applications/Granola.app/Contents/MacOS/Granola",
            )
        ],
        connections=[],
        audio_candidates=[AudioCandidate(pid=4242, process_name="Granola", basis="known_recorder")],
        meeting=MeetingContext(active=True, signals=["zoom"]),
    )

    assert len(detected) == 1
    item = detected[0]
    assert item.signature.id == "granola"
    assert item.signature.category == NotetakerCategory.LOCAL_RECORDER
    assert item.in_meeting is True
    assert item.local_audio is True

    signal = item.to_signal()
    assert signal.attributes["local_audio_capture"] is True

    payload = item.to_telemetry_event(_config())
    assert payload["event_type"] == "device_audio_notetaker_detected"
    assert payload["browser"] == "endpoint-agent"
    assert payload["meeting_surface"] == "endpoint_audio"
    assert payload["meeting_signal_source"] == "endpoint_audio"
    assert payload["participant_visible"] is False
    assert payload["control_mode"] == ControlMode.EXTERNAL_REQUIRED
    assert payload["raw_audio_captured"] is False
    assert payload["audio_content_captured"] is False
    assert payload["microphone_permission_state"] == "unknown"
    assert payload["microphone_revocation_available"] is False
    assert payload["microphone_control_mode"] == ControlMode.EXTERNAL_REQUIRED
    assert payload["microphone_control_authority"] == "external_admin_required"
    assert "mdm_or_tcc_profile_required" in payload["microphone_control_requirements"]
    assert payload["local_process_control_available"] is True
    assert "meeting_ai_notetaker_endpoint_audio" in payload["input_signal_types"]
    assert "notetaker_provider:granola" in payload["input_signal_types"]


def test_endpoint_audio_telemetry_preserves_os_attribution_basis() -> None:
    controller = NotetakerController(_config())

    item = controller.detect(
        processes=[ProcessInfo(pid=4242, name="Granola", cmdline="granola recorder")],
        connections=[],
        audio_candidates=[AudioCandidate(pid=4242, process_name="Granola", basis="macos_coreaudio_client")],
        meeting=MeetingContext(active=True, signals=["google_meet"]),
    )[0]

    payload = item.to_telemetry_event(_config())

    assert payload["endpoint_audio_signal_basis"] == "macos_coreaudio_client"
    assert "endpoint_audio_basis:macos_coreaudio_client" in payload["input_signal_types"]


def test_macos_audio_client_parser_uses_known_notetaker_processes_only() -> None:
    raw = """
    COMMAND     PID   USER   DEVICE
    Granola    4242  ayush  CoreAudio
    Safari     100   ayush  CoreAudio
    Jamie      5151  ayush  com.apple.audio
    """

    candidates = parse_macos_audio_clients(raw)

    assert candidates == [
        AudioCandidate(pid=4242, process_name="Granola", basis="macos_coreaudio_client"),
        AudioCandidate(pid=5151, process_name="Jamie", basis="macos_coreaudio_client"),
    ]


def test_windows_audio_session_parser_uses_known_notetaker_processes_only() -> None:
    raw = """
    ProcessId ProcessName IsRecording
    6161      fathom      True
    200       Teams       True
    7171      Read.ai     True
    8181      chrome      False
    """

    candidates = parse_windows_audio_sessions(raw)

    assert candidates == [
        AudioCandidate(pid=6161, process_name="fathom", basis="windows_audio_session"),
        AudioCandidate(pid=7171, process_name="Read.ai", basis="windows_audio_session"),
    ]


def test_platform_audio_collector_does_not_run_full_system_lsof_on_macos() -> None:
    calls: list[list[str]] = []

    def fake_runner(args: list[str], *, timeout: float = 5.0) -> str:
        calls.append(args)
        return "Granola 4242 ayush CoreAudio\nSafari 100 ayush CoreAudio\n"

    candidates = collect_platform_audio_candidates(
        [ProcessInfo(pid=5151, name="Jamie", cmdline="jamie recorder")],
        os_type="darwin",
        command_runner=fake_runner,
    )

    assert calls == []
    assert candidates == [AudioCandidate(pid=5151, process_name="Jamie", basis="known_recorder")]


def test_platform_audio_collector_uses_windows_audio_helper_when_available() -> None:
    calls: list[list[str]] = []

    def fake_runner(args: list[str], *, timeout: float = 5.0) -> str:
        calls.append(args)
        return "ProcessId ProcessName IsRecording\n6161 fathom True\n200 Teams True\n"

    candidates = collect_platform_audio_candidates(
        [],
        os_type="windows",
        command_runner=fake_runner,
    )

    assert calls
    assert calls[0] == ["hawk-windows-audio-sessions.exe", "--format", "text"]
    assert candidates == [AudioCandidate(pid=6161, process_name="fathom", basis="windows_audio_session")]


def test_platform_audio_collector_falls_back_to_packaged_windows_powershell_helper() -> None:
    calls: list[list[str]] = []

    def fake_runner(args: list[str], *, timeout: float = 5.0) -> str:
        calls.append(args)
        if args[0].startswith("hawk-windows-audio-sessions"):
            return ""
        return "ProcessId ProcessName IsRecording\n7070 Fireflies True\n100 explorer True\n"

    candidates = collect_platform_audio_candidates(
        [],
        os_type="windows",
        command_runner=fake_runner,
    )

    assert calls[0] == ["hawk-windows-audio-sessions.exe", "--format", "text"]
    assert calls[1] == ["hawk-windows-audio-sessions", "--format", "text"]
    assert calls[2][0].lower().endswith("powershell.exe")
    assert calls[2][1:5] == ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
    assert calls[2][-2:] == ["--format", "text"]
    assert candidates == [AudioCandidate(pid=7070, process_name="Fireflies", basis="windows_audio_session")]


def test_evicted_local_audio_notetaker_reports_external_action_triggered() -> None:
    controller = NotetakerController(_config())
    item = controller.detect(
        processes=[ProcessInfo(pid=5151, name="Jamie", cmdline="jamie meeting notes")],
        connections=[],
        audio_candidates=[AudioCandidate(pid=5151, process_name="Jamie", basis="known_recorder")],
        meeting=MeetingContext(active=True, signals=["teams"]),
    )[0]
    outcome = NotetakerOutcome(
        notetaker=item.signature.name,
        decision=Decision(
            action=Action.BLOCK,
            control_mode=ControlMode.INLINE_PREVENTED,
            reason="notetaker_policy",
        ),
        evicted=True,
        actions=[{"type": "terminate_process", "pid": 5151, "performed": True}],
    )

    payload = item.to_telemetry_event(_config(), outcome=outcome)

    assert payload["event_type"] == "device_audio_notetaker_control_applied"
    assert payload["action_taken"] == "block:device_audio_notetaker_control_applied"
    assert payload["control_mode"] == ControlMode.EXTERNAL_ACTION_TRIGGERED
    assert payload["raw_audio_captured"] is False
    assert payload["microphone_revocation_available"] is False
    assert payload["microphone_control_mode"] == ControlMode.EXTERNAL_REQUIRED
    assert payload["local_process_control_available"] is True
    assert "control_mode:external_action_triggered" in payload["input_signal_types"]


def test_visible_teams_notetaker_emits_external_remove_guidance() -> None:
    banner = Mock(return_value=BannerResult(shown=True, choice=None))
    controller = NotetakerController(_config(), banner_fn=banner)
    detected = controller.detect(
        processes=[ProcessInfo(pid=0, name="Read.ai", cmdline="Read.ai meeting bot")],
        connections=[],
        audio_candidates=[],
        meeting=MeetingContext(active=True, signals=["teams"]),
    )[0]

    decision = Decision(action=Action.BLOCK, control_mode=ControlMode.INLINE_PREVENTED, reason="notetaker_policy")
    outcome = controller.enforce(detected, decision)

    banner.assert_called_once()
    assert outcome.banner_shown is True

    platform_actions = [action for action in outcome.actions if action.get("type") == "remove_meeting_participant"]
    assert platform_actions
    assert platform_actions[0]["platform"] == "teams"
    assert platform_actions[0]["performed"] is False
    assert platform_actions[0]["control_mode"] == ControlMode.EXTERNAL_REQUIRED
    assert "Open the Teams participants panel" in platform_actions[0]["operator_steps"][0]
    assert outcome.evicted is False
    assert outcome.decision.control_mode == ControlMode.EXTERNAL_REQUIRED

    payload = detected.to_telemetry_event(_config(), outcome=outcome)
    assert payload["meeting_platform_control_mode"] == ControlMode.EXTERNAL_REQUIRED
    assert payload["meeting_platform_control_available"] is False
    assert payload["meeting_platforms"] == ["teams"]
    assert "meeting_platform_control:external_required" in payload["input_signal_types"]
    assert "Open the Teams participants panel" in payload["meeting_platform_operator_steps"][0]


def test_visible_teams_notetaker_plans_graph_specific_controls() -> None:
    banner = Mock(return_value=BannerResult(shown=True, choice=None))
    controller = NotetakerController(_config(), banner_fn=banner)
    detected = controller.detect(
        processes=[ProcessInfo(pid=0, name="Read.ai", cmdline="Read.ai meeting bot")],
        connections=[],
        audio_candidates=[],
        meeting=MeetingContext(active=True, signals=["microsoft teams"]),
    )[0]

    outcome = controller.enforce(
        detected,
        Decision(action=Action.BLOCK, control_mode=ControlMode.INLINE_PREVENTED, reason="notetaker_policy"),
    )

    banner.assert_called_once()
    assert outcome.banner_shown is True

    teams_actions = [action for action in outcome.actions if action.get("platform") == "teams"]
    assert {action["type"] for action in teams_actions} == {
        "remove_meeting_participant",
        "disable_meeting_transcription",
        "disable_meeting_recording",
        "harden_meeting_admission",
    }
    assert all(action["provider_control_path"] == "microsoft_graph" for action in teams_actions)
    assert all(action["control_mode"] == ControlMode.EXTERNAL_REQUIRED for action in teams_actions)
    assert all(action["performed"] is False for action in teams_actions)
    assert teams_actions[0]["reason"] == "meeting_platform_credentials_not_configured"

    payload = detected.to_telemetry_event(_config(), outcome=outcome)
    assert payload["meeting_platform_provider_paths"] == ["microsoft_graph"]
    assert "meeting_platform_provider:microsoft_graph" in payload["input_signal_types"]
    assert "Disable Teams transcription for this meeting if policy requires it." in payload["meeting_platform_operator_steps"]


def test_platform_action_triggered_is_reflected_in_telemetry() -> None:
    controller = NotetakerController(_config())
    detected = controller.detect(
        processes=[ProcessInfo(pid=0, name="Fireflies.ai", cmdline="Fireflies meeting bot")],
        connections=[],
        audio_candidates=[],
        meeting=MeetingContext(active=True, signals=["google_meet"]),
    )[0]
    outcome = NotetakerOutcome(
        notetaker=detected.signature.name,
        decision=Decision(action=Action.BLOCK, control_mode=ControlMode.EXTERNAL_ACTION_TRIGGERED, reason="notetaker_policy"),
        evicted=True,
        actions=[
            {
                "type": "remove_meeting_participant",
                "platform": "google_meet",
                "provider_control_path": "google_workspace_meet",
                "performed": True,
                "control_mode": ControlMode.EXTERNAL_ACTION_TRIGGERED,
                "mode": "api_remove_participant",
                "operator_steps": [],
            }
        ],
    )

    payload = detected.to_telemetry_event(_config(), outcome=outcome)

    assert payload["meeting_platform_control_mode"] == ControlMode.EXTERNAL_ACTION_TRIGGERED
    assert payload["meeting_platform_control_available"] is True
    assert payload["meeting_platforms"] == ["google_meet"]
    assert payload["meeting_platform_provider_paths"] == ["google_workspace_meet"]
    assert "meeting_platform_control:external_action_triggered" in payload["input_signal_types"]


def test_performed_teams_graph_action_is_reported_as_external_triggered() -> None:
    controller = NotetakerController(_config())
    detected = controller.detect(
        processes=[ProcessInfo(pid=0, name="Fireflies.ai", cmdline="Fireflies meeting bot")],
        connections=[],
        audio_candidates=[],
        meeting=MeetingContext(active=True, signals=["teams"]),
    )[0]
    outcome = NotetakerOutcome(
        notetaker=detected.signature.name,
        decision=Decision(
            action=Action.BLOCK,
            control_mode=ControlMode.EXTERNAL_ACTION_TRIGGERED,
            reason="teams_graph_remove_participant",
        ),
        evicted=True,
        actions=[
            {
                "type": "remove_meeting_participant",
                "platform": "teams",
                "provider_control_path": "microsoft_graph",
                "graph_operation": "remove_meeting_participant",
                "performed": True,
                "control_mode": ControlMode.EXTERNAL_ACTION_TRIGGERED,
                "mode": "microsoft_graph_remove_participant",
                "operator_steps": [],
            }
        ],
    )

    payload = detected.to_telemetry_event(_config(), outcome=outcome)

    assert payload["meeting_platform_control_mode"] == ControlMode.EXTERNAL_ACTION_TRIGGERED
    assert payload["meeting_platform_control_available"] is True
    assert payload["meeting_platforms"] == ["teams"]
    assert payload["meeting_platform_provider_paths"] == ["microsoft_graph"]
    assert "meeting_platform_provider:microsoft_graph" in payload["input_signal_types"]


def test_mdm_backed_endpoint_reports_microphone_revocation_capability() -> None:
    cfg = _config()
    cfg.allow_mic_revocation = True
    controller = NotetakerController(cfg)
    item = controller.detect(
        processes=[ProcessInfo(pid=6161, name="Granola", cmdline="granola recorder")],
        connections=[],
        audio_candidates=[AudioCandidate(pid=6161, process_name="Granola", basis="known_recorder")],
        meeting=MeetingContext(active=True, signals=["google_meet"]),
    )[0]
    outcome = NotetakerOutcome(
        notetaker=item.signature.name,
        decision=Decision(
            action=Action.BLOCK,
            control_mode=ControlMode.INLINE_PREVENTED,
            reason="notetaker_policy",
        ),
        evicted=True,
        actions=[
            {"type": "terminate_process", "pid": 6161, "performed": True},
            {"type": "revoke_mic", "performed": True, "mode": "revoked"},
        ],
    )

    payload = item.to_telemetry_event(cfg, outcome=outcome)

    assert payload["microphone_revocation_available"] is True
    assert payload["microphone_control_authority"] == "mdm_tcc"
    assert payload["microphone_control_mode"] == ControlMode.EXTERNAL_ACTION_TRIGGERED
    assert payload["microphone_control_requirements"] == []


def test_build_pilot_config_contains_only_non_secret_identity_metadata() -> None:
    config = build_pilot_config(
        api_url="http://192.168.102.35:8000",
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        hostname="pilot-host",
        fail_secure_mode="warn",
        security_profile="development",
        key_provider="macos_secure_enclave",
    )

    assert config["api_base_url"] == "http://192.168.102.35:8000"
    assert config["tenant_id"] == "tenant-1"
    assert config["endpoint_id"] == "endpoint-1"
    assert config["hostname"] == "pilot-host"
    assert config["fail_secure_mode"] == "warn"
    assert config["allow_mic_revocation"] is False
    assert config["allow_network_block"] is False
    assert "agent_token" not in config
    assert "operator_token" not in config
    assert config["security_profile"] == "development"


def test_run_once_reports_endpoint_notetaker_telemetry() -> None:
    cfg = _config()
    sent: list[dict] = []

    class FakeClient:
        def sync_policy(self):
            return {}

        def evaluate_notetaker(self, payload):
            return {
                "decision": "allow",
                "reason": "pilot_notetaker_policy",
                "banner": False,
                "eviction_allowed": False,
            }

        def report_discovery(self, payload):
            sent.append(payload)
            return {"status": "ok"}

    run_once(
        cfg,
        client=FakeClient(),
        processes=[ProcessInfo(pid=9191, name="Granola", cmdline="granola recorder")],
        connections=[],
        audio_candidates=[AudioCandidate(pid=9191, process_name="Granola", basis="known_recorder")],
        meeting=MeetingContext(active=True, signals=["zoom"]),
    )

    assert len(sent) == 1
    assert sent[0]["event_type"] == "device_audio_notetaker_detected"
    assert sent[0]["notetaker_provider"] == "granola"
    assert sent[0]["raw_audio_captured"] is False


def test_pilot_package_excludes_dev_artifacts(tmp_path) -> None:
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "package_pilot_agent.py"
    spec = importlib.util.spec_from_file_location("package_pilot_agent", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    package_dir = module.build_package(tmp_path)

    assert (package_dir / "pyproject.toml").exists()
    assert (package_dir / "src" / "hawk_endpoint_agent" / "__main__.py").exists()
    assert (package_dir / "src" / "hawk_endpoint_agent" / "resources" / "windows_audio_sessions.ps1").exists()
    assert (package_dir / "README_PILOT.md").exists()
    assert (package_dir / "config" / "endpoint-agent.example.json").exists()
    assert (package_dir / "scripts" / "install_macos_user.sh").exists()
    assert (package_dir / "scripts" / "build_macos_identity_helper.sh").exists()
    assert (package_dir / "scripts" / "build_bank_macos.sh").exists()
    assert (package_dir / "scripts" / "notarize_bank_macos.sh").exists()
    assert (package_dir / "scripts" / "validate_edr_coexistence.sh").exists()
    assert (package_dir / "native" / "macos" / "HawkDeviceIdentity.swift").exists()
    assert any(
        path.is_file()
        for path in (package_dir / "native" / "macos" / "network-extension").rglob("*")
    )
    assert (package_dir / "src" / "hawk_endpoint_agent" / "attestation.py").exists()
    assert (package_dir / "src" / "hawk_endpoint_agent" / "auth" / "windows_tpm.py").exists()
    assert (package_dir / "src" / "hawk_endpoint_agent" / "auth" / "linux_tpm2.py").exists()
    assert (package_dir / "src" / "hawk_endpoint_agent" / "windows" / "routing.py").exists()
    manifest = json.loads((package_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    paths = {item["path"] for item in manifest["files"]}
    assert "src/hawk_endpoint_agent/__main__.py" in paths
    assert "src/hawk_endpoint_agent/resources/windows_audio_sessions.ps1" in paths
    assert "scripts/install_macos_user.sh" in paths
    assert "scripts/build_macos_identity_helper.sh" in paths
    assert "scripts/build_bank_macos.sh" in paths
    assert "scripts/notarize_bank_macos.sh" in paths
    assert "scripts/validate_edr_coexistence.sh" in paths
    assert "native/macos/HawkDeviceIdentity.swift" in paths
    assert any(path.startswith("native/macos/network-extension/") for path in paths)
    assert "src/hawk_endpoint_agent/attestation.py" in paths
    assert "src/hawk_endpoint_agent/auth/windows_tpm.py" in paths
    assert "src/hawk_endpoint_agent/auth/linux_tpm2.py" in paths
    assert "src/hawk_endpoint_agent/windows/routing.py" in paths
    assert not any("/__pycache__/" in path or path.endswith(".pyc") for path in paths)
    assert not any(Path(path).name.startswith("._") for path in paths)
    assert not any(path.endswith((".orig", ".bak")) for path in paths)
    assert not any(path.startswith("tests/") for path in paths)

    generated_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (
            package_dir / "README_PILOT.md",
            package_dir / "MANIFEST.json",
            package_dir / "config" / "endpoint-agent.example.json",
        )
    )
    for legacy_credential in (
        "HAWK_AGENT_TOKEN",
        "HAWK_AGENT_OPERATOR_TOKEN",
        "--agent-token",
        "--operator-token",
    ):
        assert legacy_credential not in generated_text
    assert "Local broker responses are authenticated" in generated_text
    assert "Local broker response authentication is not implemented" not in generated_text

    example = json.loads(
        (package_dir / "config" / "endpoint-agent.example.json").read_text(encoding="utf-8")
    )
    assert example["security_profile"] == "bank"
    assert example["key_provider"] == "macos_secure_enclave"
    assert "agent_token" not in example
    assert "operator_token" not in example

    pilot_readme = (package_dir / "README_PILOT.md").read_text(encoding="utf-8").lower()
    assert "source availability does not establish bank readiness" in pilot_readme
    assert "gate scripts fail closed and require external signing" in pilot_readme
    assert "attestation, and edr evidence" in pilot_readme
    assert "networkextension source intentionally refuses activation" in pilot_readme
    assert "local broker responses are authenticated" in pilot_readme
    assert "pinned hardware-device public" in pilot_readme
