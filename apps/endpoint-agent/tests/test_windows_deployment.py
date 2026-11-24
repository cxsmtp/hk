from __future__ import annotations

import json
from pathlib import Path

import pytest

from hawk_endpoint_agent.windows.command import (
    CommandResult,
    CommandRunner,
    WindowsDeploymentError,
)
from hawk_endpoint_agent.windows.routing import WindowsRouting
from hawk_endpoint_agent.windows.service import WindowsService
from hawk_endpoint_agent.windows.state import InstallStateStore, WindowsInstallState
from hawk_endpoint_agent.windows.trust import WindowsTrust


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses = responses or {}

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        return self.responses.get(command, CommandResult(command, 0, "", ""))


def test_state_store_round_trips_without_token(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = InstallStateStore(path)
    state = WindowsInstallState(
        deployment_mode="user_pilot",
        proxy_host="127.0.0.1",
        proxy_port=8080,
        config_path="C:/Users/test/.hawk/agent.json",
    )

    store.save(state)

    assert store.load() == state
    serialized = path.read_text(encoding="utf-8").lower()
    assert "token" not in serialized
    assert not path.with_suffix(".json.tmp").exists()


def test_command_failure_is_structured() -> None:
    result = CommandResult(("sc.exe", "query"), 5, "", "denied")

    assert result.ok is False
    assert result.error_code == "exit_5"


def test_command_runner_rejects_unpinned_executable_name() -> None:
    with pytest.raises(ValueError, match="fixed System32"):
        CommandRunner().run(["reg.exe", "query", "HKCU\\Software"])


def test_user_routing_uses_hkcu_and_local_bypass() -> None:
    runner = FakeRunner()
    routing = WindowsRouting(runner)

    snapshot = routing.capture("user_pilot")
    routing.apply("user_pilot", "127.0.0.1", 8080)

    rendered = "\n".join(" ".join(call) for call in runner.calls)
    assert r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" in rendered
    assert "localhost;127.*;<local>" in rendered
    assert snapshot["deployment_mode"] == "user_pilot"
    assert "winhttp" not in " ".join(snapshot).lower()


def test_managed_routing_captures_and_sets_winhttp() -> None:
    netsh = r"C:\Windows\System32\netsh.exe"
    show = (netsh, "winhttp", "show", "proxy")
    dump = (netsh, "winhttp", "dump")
    runner = FakeRunner(
        {
            show: CommandResult(show, 0, "Direct access (no proxy server).\n", ""),
            dump: CommandResult(dump, 0, "pushd winhttp\nreset proxy\npopd\n", ""),
        }
    )
    routing = WindowsRouting(runner)

    snapshot = routing.capture("managed_machine")
    routing.apply("managed_machine", "127.0.0.1", 8080)

    commands = [" ".join(call).lower() for call in runner.calls]
    assert any("netsh.exe winhttp show proxy" in command for command in commands)
    assert any("netsh.exe winhttp set proxy" in command for command in commands)
    assert "winhttp_output" in snapshot


def test_managed_service_is_machine_wide() -> None:
    runner = FakeRunner()

    WindowsService(runner).install(
        "managed_machine",
        "C:/Hawk/python.exe",
        "C:/Hawk/agent.json",
    )

    sc_exe = r"C:\Windows\System32\sc.exe"
    assert runner.calls[0][:3] == (sc_exe, "create", "HawkEndpointAgent")
    assert any(call[:3] == (sc_exe, "start", "HawkEndpointAgent") for call in runner.calls)


def test_user_mode_uses_limited_scheduled_task() -> None:
    runner = FakeRunner()

    WindowsService(runner).install("user_pilot", "python.exe", "agent.json")

    command = " ".join(runner.calls[0])
    assert command.lower().startswith(
        r"c:\windows\system32\schtasks.exe /create"
    )
    assert "/RL LIMITED" in command


def test_trust_install_and_remove_use_same_thumbprint(tmp_path: Path, monkeypatch) -> None:
    certificate = tmp_path / "hawk.crt"
    certificate.write_text("test-certificate", encoding="utf-8")
    runner = FakeRunner()
    trust = WindowsTrust(runner)
    thumbprint_value = "AA" * 20
    monkeypatch.setattr(
        trust, "certificate_thumbprint", lambda _path: thumbprint_value
    )

    thumbprint = trust.install("user_pilot", certificate)
    trust.remove("user_pilot", thumbprint)

    assert runner.calls[0] == (
        r"C:\Windows\System32\certutil.exe",
        "-user",
        "-addstore",
        "Root",
        str(certificate),
    )
    assert runner.calls[1] == (
        r"C:\Windows\System32\certutil.exe",
        "-user",
        "-delstore",
        "Root",
        thumbprint_value,
    )


def test_state_json_has_only_documented_fields(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    InstallStateStore(path).save(WindowsInstallState(deployment_mode="managed_machine"))

    payload = json.loads(path.read_text(encoding="utf-8"))

    assert set(payload) == set(WindowsInstallState.__dataclass_fields__)


def test_state_store_rejects_credentials_in_rollback_snapshot(tmp_path: Path) -> None:
    state = WindowsInstallState(
        deployment_mode="managed_machine",
        routing_snapshot={
            "winhttp_output": "Proxy Server(s): operator:password@proxy.test:8080"
        },
    )

    with pytest.raises(ValueError, match="credential"):
        InstallStateStore(tmp_path / "state.json").save(state)


def test_user_routing_restore_replays_only_captured_hkcu_values() -> None:
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    responses = {
        (r"C:\Windows\System32\reg.exe", "query", key): CommandResult(
            (r"C:\Windows\System32\reg.exe", "query"),
            0,
            "    ProxyEnable    REG_DWORD    0x0\n"
            "    ProxyServer    REG_SZ    old.proxy:3128\n",
            "",
        )
    }
    runner = FakeRunner(responses)
    routing = WindowsRouting(runner)

    snapshot = routing.capture("user_pilot")
    runner.calls.clear()
    routing.restore(snapshot)

    rendered = [" ".join(call) for call in runner.calls]
    assert any("ProxyEnable /t REG_DWORD /d 0x0" in command for command in rendered)
    assert any("ProxyServer /t REG_SZ /d old.proxy:3128" in command for command in rendered)
    assert any("delete" in command and "ProxyOverride" in command for command in rendered)
    assert all(
        command.startswith(r"C:\Windows\System32\reg.exe ") and key in command
        for command in rendered
    )


def test_user_routing_restore_fails_if_absent_value_cannot_be_deleted() -> None:
    reg = r"C:\Windows\System32\reg.exe"
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    delete_override = (reg, "delete", key, "/v", "ProxyOverride", "/f")
    runner = FakeRunner(
        {
            delete_override: CommandResult(
                delete_override, 1, "", "access denied"
            )
        }
    )
    snapshot = {
        "deployment_mode": "user_pilot",
        "wininet": {
            "ProxyEnable": {"exists": True, "type": "REG_DWORD", "value": "0x0"},
            "ProxyServer": {"exists": True, "type": "REG_SZ", "value": "old:80"},
            "ProxyOverride": {"exists": False, "type": "REG_SZ", "value": ""},
        },
    }

    with pytest.raises(WindowsDeploymentError, match="restore absent"):
        WindowsRouting(runner).restore(snapshot)


def test_managed_routing_restore_resets_captured_direct_access() -> None:
    netsh = r"C:\Windows\System32\netsh.exe"
    show = (netsh, "winhttp", "show", "proxy")
    dump = (netsh, "winhttp", "dump")
    runner = FakeRunner(
        {
            show: CommandResult(
                show,
                0,
                "Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).\n",
                "",
            ),
            dump: CommandResult(dump, 0, "pushd winhttp\nreset proxy\npopd\n", ""),
        }
    )
    routing = WindowsRouting(runner)

    snapshot = routing.capture("managed_machine")
    runner.calls.clear()
    routing.restore(snapshot)

    assert runner.calls == [(netsh, "winhttp", "reset", "proxy")]


def test_managed_routing_restore_replays_safe_per_protocol_proxy() -> None:
    netsh = r"C:\Windows\System32\netsh.exe"
    show = (netsh, "winhttp", "show", "proxy")
    dump = (netsh, "winhttp", "dump")
    runner = FakeRunner(
        {
            show: CommandResult(
                show,
                0,
                "Proxy Server(s) : http=old.proxy:80;https=old.proxy:443\n"
                "Bypass List     : localhost;<local>\n",
                "",
            ),
            dump: CommandResult(
                dump,
                0,
                'pushd winhttp\nset proxy proxy-server="http=old.proxy:80;https=old.proxy:443" '
                'bypass-list="localhost;<local>"\npopd\n',
                "",
            ),
        }
    )
    routing = WindowsRouting(runner)

    snapshot = routing.capture("managed_machine")
    runner.calls.clear()
    routing.restore(snapshot)

    assert runner.calls == [
        (
            netsh,
            "winhttp",
            "set",
            "proxy",
            "proxy-server=http=old.proxy:80;https=old.proxy:443",
            "bypass-list=localhost;<local>",
        )
    ]


def test_managed_routing_refuses_credential_bearing_rollback_output() -> None:
    netsh = r"C:\Windows\System32\netsh.exe"
    show = (netsh, "winhttp", "show", "proxy")
    dump = (netsh, "winhttp", "dump")
    runner = FakeRunner(
        {
            show: CommandResult(
                show,
                0,
                "Proxy Server(s) : http://operator:password@proxy.test",
                "",
            ),
            dump: CommandResult(dump, 0, "reset proxy\n", ""),
        }
    )

    with pytest.raises(WindowsDeploymentError, match="credential"):
        WindowsRouting(runner).capture("managed_machine")


def test_managed_routing_refuses_conflicting_winhttp_dump() -> None:
    netsh = r"C:\Windows\System32\netsh.exe"
    show = (netsh, "winhttp", "show", "proxy")
    dump = (netsh, "winhttp", "dump")
    runner = FakeRunner(
        {
            show: CommandResult(show, 0, "Direct access (no proxy server).\n", ""),
            dump: CommandResult(
                dump,
                0,
                "pushd winhttp\nreset proxy\n"
                'set proxy proxy-server="other.proxy:8080"\npopd\n',
                "",
            ),
        }
    )

    with pytest.raises(WindowsDeploymentError, match="exactly one"):
        WindowsRouting(runner).capture("managed_machine")


@pytest.mark.parametrize(
    "proxy",
    [
        "ftp=old.proxy:21",
        "http=old.proxy:99999",
        "http=old.proxy:80;http=other.proxy:81",
    ],
)
def test_managed_routing_refuses_unsafe_proxy_rollback_values(proxy: str) -> None:
    snapshot = {
        "deployment_mode": "managed_machine",
        "winhttp_output": f"Proxy Server(s) : {proxy}\nBypass List : <local>\n",
        "winhttp": {"mode": "proxy", "proxy": proxy, "bypass": "<local>"},
    }

    with pytest.raises(WindowsDeploymentError, match="unsafe"):
        WindowsRouting(FakeRunner()).restore(snapshot)
