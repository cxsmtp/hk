from __future__ import annotations

import plistlib
from pathlib import Path

from hawk_endpoint_agent.chatgpt_desktop import (
    ChatGPTDesktopMode,
    ChatGPTRuntimeLocation,
    inspect_chatgpt_installation,
    observe_chatgpt_processes,
)
from hawk_endpoint_agent.collectors.base import ProcessInfo
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.modules.desktop_native import DesktopNativeModule


def _app(tmp_path: Path) -> Path:
    app = tmp_path / "ChatGPT.app"
    contents = app / "Contents"
    executable = contents / "MacOS" / "ChatGPT"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"signed-binary-placeholder")
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": "com.openai.codex",
                "CFBundleShortVersionString": "26.715.31925",
                "CFBundleVersion": "5551",
                "CFBundleExecutable": "ChatGPT",
            },
            handle,
        )
    return app


def _runner(args: list[str]) -> tuple[int, str, str]:
    command = " ".join(args)
    if "--verify" in args:
        return 0, "", ""
    if args[0] == "codesign":
        return 0, "", "TeamIdentifier=2DC432GLL2\nCDHash=abc123\nflags=0x10000(runtime)\nNotarization Ticket=stapled\n"
    if args[0] == "spctl":
        return 0, "", "accepted\nsource=Notarized Developer ID\n"
    raise AssertionError(f"unexpected command: {command}")


def test_supported_bundle_metadata_is_bounded_and_does_not_claim_native_hook(tmp_path: Path) -> None:
    installation = inspect_chatgpt_installation(_app(tmp_path), command_runner=_runner)

    assert installation.installed is True
    assert installation.bundle_id == "com.openai.codex"
    assert installation.version == "26.715.31925"
    assert installation.build == "5551"
    assert installation.team_id == "2DC432GLL2"
    assert installation.code_directory_hash == "abc123"
    assert installation.signature_verified is True
    assert installation.notarization_verified is True
    assert installation.native_hook_available is False
    assert "cookie" not in installation.as_dict()
    assert "token" not in installation.as_dict()


def test_same_name_process_without_bundle_path_is_not_verified_chatgpt_identity(tmp_path: Path) -> None:
    installation = inspect_chatgpt_installation(_app(tmp_path), command_runner=_runner)
    fake = ProcessInfo(
        pid=99,
        parent_pid=1,
        name="ChatGPT",
        user="user-1",
        cmdline="/tmp/ChatGPT --pretend",
        executable_path="/tmp/ChatGPT",
        process_start_time_ns=10,
    )

    observations = observe_chatgpt_processes([fake], installation)

    assert len(observations) == 1
    assert observations[0].identity_state == "name_only_unverified"
    assert observations[0].mode is ChatGPTDesktopMode.UNKNOWN_DESKTOP_MODE
    assert observations[0].runtime_location is ChatGPTRuntimeLocation.UNKNOWN


def test_signed_bundle_process_gets_process_tree_identity_but_not_inferred_chat_mode(tmp_path: Path) -> None:
    app = _app(tmp_path)
    installation = inspect_chatgpt_installation(app, command_runner=_runner)
    process = ProcessInfo(
        pid=120,
        parent_pid=1,
        name="ChatGPT",
        user="user-1",
        cmdline=str(app / "Contents" / "MacOS" / "ChatGPT"),
        executable_path=str(app / "Contents" / "MacOS" / "ChatGPT"),
        process_start_time_ns=99,
    )

    observation = observe_chatgpt_processes([process], installation)[0]

    assert observation.identity_state == "bundle_and_signature_matched"
    assert observation.process_id == 120
    assert observation.parent_process_id == 1
    assert observation.process_start_time_ns == 99
    assert observation.mode is ChatGPTDesktopMode.UNKNOWN_DESKTOP_MODE
    assert observation.account_context == "unknown"


class _Client:
    def __init__(self) -> None:
        self.discovery: list[dict] = []
        self.evidence: list[dict] = []

    def report_discovery(self, payload: dict) -> dict:
        self.discovery.append(payload)
        return {"status": "ok"}

    def report_evidence(self, payload: dict) -> dict:
        self.evidence.append(payload)
        return {"status": "ok"}


def test_desktop_module_emits_one_bounded_composite_observation(tmp_path: Path) -> None:
    app = _app(tmp_path)
    client = _Client()
    module = DesktopNativeModule(
        AgentConfig(
            tenant_id="tenant-1",
            endpoint_id="endpoint-1",
            security_profile="development",
            key_provider="development_ephemeral",
        ),
        client,  # type: ignore[arg-type]
        chatgpt_installation_path=app,
        command_runner=_runner,
    )
    process = ProcessInfo(
        pid=120,
        parent_pid=1,
        name="ChatGPT",
        user="user-1",
        cmdline=str(app / "Contents" / "MacOS" / "ChatGPT"),
        executable_path=str(app / "Contents" / "MacOS" / "ChatGPT"),
        process_start_time_ns=99,
    )

    signals = module.discover(processes=[process])
    assert len(signals) == 1
    assert module.report(signals[0]) is True

    assert client.discovery[0]["application"] == "ChatGPT Desktop"
    assert client.discovery[0]["chatgpt_desktop"]["version"] == "26.715.31925"
    assert client.evidence[0]["event_type"] == "chatgpt_desktop_observation"
    assert client.evidence[0]["chatgpt_desktop"]["native_hook_available"] is False


def test_desktop_module_caches_expensive_signature_assessment_until_bundle_changes(tmp_path: Path) -> None:
    app = _app(tmp_path)
    calls: list[tuple[str, ...]] = []

    def runner(args: list[str]) -> tuple[int, str, str]:
        calls.append(tuple(args))
        return _runner(args)

    module = DesktopNativeModule(
        AgentConfig(
            tenant_id="tenant-1",
            endpoint_id="endpoint-1",
            security_profile="development",
            key_provider="development_ephemeral",
        ),
        _Client(),  # type: ignore[arg-type]
        chatgpt_installation_path=app,
        command_runner=runner,
    )
    process = ProcessInfo(
        pid=120,
        parent_pid=1,
        name="ChatGPT",
        user="user-1",
        cmdline=str(app / "Contents" / "MacOS" / "ChatGPT"),
        executable_path=str(app / "Contents" / "MacOS" / "ChatGPT"),
        process_start_time_ns=99,
    )

    module.discover(processes=[process])
    module.discover(processes=[process])

    assert len(calls) == 3
