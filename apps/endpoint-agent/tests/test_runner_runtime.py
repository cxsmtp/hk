from __future__ import annotations

import errno
from types import SimpleNamespace

import hawk_endpoint_agent.__main__ as cli
import hawk_endpoint_agent.runner as runner_module
from hawk_endpoint_agent import __version__
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.control_plane import EndpointControlPlane
from hawk_endpoint_agent.runner import AgentRunner


class _HeartbeatClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.evidence_payloads: list[dict] = []

    def heartbeat(self, payload: dict) -> None:
        self.payloads.append(payload)

    def report_evidence(self, payload: dict) -> None:
        self.evidence_payloads.append(payload)


def _bare_runner(config: AgentConfig) -> AgentRunner:
    runner = object.__new__(AgentRunner)
    runner.config = config
    runner.client = _HeartbeatClient()
    runner.policy = SimpleNamespace(stale=False, module_enabled=lambda _name: True)
    runner.dispatcher = object()
    runner.control_plane = EndpointControlPlane(mode=config.agent_mode)
    runner.resource_governor = SimpleNamespace(
        sample=lambda active: SimpleNamespace(rss_mb=50.0, cpu_percent=0.2, active=active),
        evaluate=lambda sample: SimpleNamespace(
            as_dict=lambda: {
                "health": "healthy",
                "sample": {"rss_mb": sample.rss_mb, "cpu_percent": sample.cpu_percent, "active": sample.active},
                "disabled_capabilities": [],
                "reasons": [],
            }
        ),
    )
    runner._resource_state = runner.resource_governor.evaluate(
        runner.resource_governor.sample(active=False)
    )
    runner.evidence_queue = SimpleNamespace(
        stats=lambda: {"queued": 0, "dropped_monitor": 0},
        items=lambda: [],
        acknowledge=lambda _item_id: False,
    )
    runner.baseline = SimpleNamespace(snapshot=lambda: {"observation_count": 0, "path_count": 0})
    runner._proxy = None
    runner._ipc = None
    runner._proxy_error = None
    runner._network_collection = {"status": "not_collected", "error_code": None, "observed_at": None}
    runner._ipc_error = None
    runner._stop = False
    runner._legacy_secret_residue = False
    runner._windows_floor_manager = None
    runner._windows_floor_state = {
        "requested": bool(config.windows_native_enforcement_enabled),
        "reachable": False,
        "armed": False,
        "policy_version": None,
        "rule_count": 0,
        "error_code": None,
    }
    return runner


def test_normal_tick_reconciles_macos_even_without_policy_refresh(monkeypatch) -> None:
    runner = _bare_runner(AgentConfig())
    calls = []
    monkeypatch.setattr(runner, "_reconcile_macos_native", lambda: calls.append("macos"))
    monkeypatch.setattr(runner, "_reconcile_windows_floor", lambda: None)
    runner.resource_governor.evaluate = lambda sample: SimpleNamespace(disabled_capabilities=["passive_discovery"])
    monkeypatch.setattr(runner, "_safe_heartbeat", lambda **kwargs: None)
    runner.tick()
    runner.tick()
    assert calls == ["macos", "macos"]


def test_run_forever_starts_full_agent_runner(monkeypatch) -> None:
    calls: list[AgentConfig] = []

    class _Runner:
        def __init__(self, config: AgentConfig) -> None:
            calls.append(config)

        def start(self) -> None:
            calls.append("started")  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "AgentRunner", _Runner)
    config = AgentConfig()

    cli.run_forever(config)

    assert calls == [config, "started"]


def test_runtime_posture_reports_requested_proxy_start_failure(monkeypatch) -> None:
    class _UnavailableProxy:
        def __init__(self, *_args, **_kwargs) -> None:
            raise OSError(errno.EADDRINUSE, "address already in use")

    config = AgentConfig(proxy_enabled=True, ipc_enabled=False)
    config.deployment_mode = "user_pilot"
    runner = _bare_runner(config)
    monkeypatch.setattr(runner_module, "LocalProxy", _UnavailableProxy)
    monkeypatch.setattr(runner, "_build_interceptor", lambda: None)

    runner.start_local_servers()
    posture = runner.runtime_posture()

    assert posture["deployment_mode"] == "user_pilot"
    assert posture["proxy"]["requested"] is True
    assert posture["proxy"]["running"] is False
    assert posture["proxy"]["error_code"] == "EADDRINUSE"
    assert posture["control_mode"] == "incomplete"


def test_windows_native_readiness_never_becomes_floor_coverage_without_receipt() -> None:
    config = AgentConfig(
        os_type="windows",
        agent_mode="enforce",
        proxy_enabled=False,
        ipc_enabled=False,
        windows_native_enforcement_enabled=True,
    )
    runner = _bare_runner(config)
    runner._windows_floor_state = {
        "requested": True,
        "reachable": True,
        "armed": True,
        "policy_current": True,
        "identity_coverage_ready": True,
        "wfp_ready": True,
        "policy_version": "windows-policy-1",
        "rule_count": 1,
        "error_code": None,
    }

    posture = runner.runtime_posture()

    assert posture["windows_native"]["armed"] is True
    assert posture["control_mode"] == "ready"
    assert posture["endpoint_enforcement_floor"]["minimum_floor_satisfied"] is False
    assert posture["endpoint_enforcement_floor"]["controls"]["file_control"]["verification"] == "unverified"


def test_expired_armed_windows_floor_is_not_reported_ready() -> None:
    config = AgentConfig(
        os_type="windows",
        proxy_enabled=False,
        ipc_enabled=False,
        windows_native_enforcement_enabled=True,
    )
    runner = _bare_runner(config)
    runner._windows_floor_state = {
        "requested": True,
        "reachable": True,
        "armed": True,
        "policy_current": False,
        "identity_coverage_ready": False,
        "wfp_ready": False,
        "policy_version": "windows-policy-1",
        "rule_count": 1,
        "error_code": "POLICY_REJECTED",
    }

    posture = runner.runtime_posture()

    assert posture["windows_native"]["armed"] is True
    assert posture["windows_native"]["policy_current"] is False
    assert posture["control_mode"] == "incomplete"


def test_monitor_with_unexpected_armed_windows_floor_is_not_reported_ready() -> None:
    config = AgentConfig(
        os_type="windows",
        agent_mode="monitor",
        proxy_enabled=False,
        ipc_enabled=False,
        windows_native_enforcement_enabled=True,
    )
    runner = _bare_runner(config)
    runner._windows_floor_state = {
        "requested": True,
        "reachable": True,
        "armed": True,
        "policy_current": True,
        "identity_coverage_ready": True,
        "wfp_ready": True,
        "policy_version": "windows-policy-1",
        "rule_count": 1,
        "error_code": None,
    }

    posture = runner.runtime_posture()

    assert posture["agent_mode"] == "monitor"
    assert posture["control_mode"] == "incomplete"


def test_windows_floor_reconcile_uses_only_signed_policy_payload() -> None:
    config = AgentConfig(
        os_type="windows",
        windows_native_enforcement_enabled=True,
        proxy_enabled=False,
        ipc_enabled=False,
    )
    runner = _bare_runner(config)
    observed: list[tuple[dict, str]] = []

    class _Manager:
        def reconcile(self, envelope, *, mode):
            observed.append((envelope, mode))
            return SimpleNamespace(
                armed=mode == "enforce",
                policy_version="windows-policy-1",
                rule_count=2,
            )

    runner._windows_floor_manager = _Manager()
    runner.policy = SimpleNamespace(
        policy=SimpleNamespace(raw={"endpoint_floor_policy": {"key_id": "signed"}})
    )
    runner.control_plane = EndpointControlPlane(mode="enforce")

    assert runner._reconcile_windows_floor() is True
    assert observed == [({"key_id": "signed"}, "enforce")]
    assert runner._windows_floor_state["armed"] is True
    assert runner._windows_floor_state["policy_version"] == "windows-policy-1"


def test_windows_floor_poll_checks_status_without_republishing_unchanged_policy() -> None:
    config = AgentConfig(
        os_type="windows",
        windows_native_enforcement_enabled=True,
        proxy_enabled=False,
        ipc_enabled=False,
    )
    runner = _bare_runner(config)
    calls: list[str] = []

    class _Manager:
        def reconcile(self, _envelope, *, mode):
            calls.append(f"reconcile:{mode}")
            return SimpleNamespace(
                armed=True,
                policy_current=True,
                policy_version="windows-policy-1",
                generation=1,
                rule_count=2,
                allow_count=0,
                block_count=0,
                policy_reject_count=0,
                identity_coverage_ready=True,
                wfp_ready=True,
            )

        def status(self):
            calls.append("status")
            return SimpleNamespace(
                armed=True,
                policy_current=True,
                policy_loaded=True,
                generation=1,
                allow_count=3,
                block_count=1,
                policy_reject_count=0,
                identity_coverage_ready=True,
                wfp_ready=True,
            )

    runner._windows_floor_manager = _Manager()
    runner.policy = SimpleNamespace(
        policy=SimpleNamespace(raw={"endpoint_floor_policy": {"key_id": "signed"}})
    )
    runner.control_plane = EndpointControlPlane(mode="enforce")

    assert runner._reconcile_windows_floor() is True
    assert runner._reconcile_windows_floor() is True

    assert calls == ["reconcile:enforce", "status"]
    assert runner._windows_floor_state["block_count"] == 1


def test_enforce_keeps_prior_armed_floor_on_invalid_policy_for_fail_closed_expiry() -> None:
    config = AgentConfig(
        os_type="windows",
        windows_native_enforcement_enabled=True,
        proxy_enabled=False,
        ipc_enabled=False,
    )
    runner = _bare_runner(config)
    calls: list[str] = []

    class _Manager:
        def reconcile(self, _envelope, *, mode):
            assert mode == "enforce"
            raise ValueError("signed endpoint policy rejected")

        def status(self):
            calls.append("status")
            return SimpleNamespace(
                armed=True,
                policy_current=False,
                policy_loaded=True,
                generation=4,
                allow_count=7,
                block_count=2,
                policy_reject_count=1,
            )

        def disarm(self):
            calls.append("disarm")

    runner._windows_floor_manager = _Manager()
    runner.policy = SimpleNamespace(
        policy=SimpleNamespace(raw={"endpoint_floor_policy": {"key_id": "bad"}})
    )
    runner.control_plane = EndpointControlPlane(mode="enforce")

    assert runner._reconcile_windows_floor() is False
    assert calls == ["status"]
    assert runner._windows_floor_state["armed"] is True
    assert runner._windows_floor_state["policy_current"] is False
    assert runner._windows_floor_state["block_count"] == 2
    assert runner._windows_floor_state["error_code"] == "POLICY_REJECTED"


def test_heartbeat_reports_dynamic_version_and_runtime_posture() -> None:
    config = AgentConfig(proxy_enabled=True, ipc_enabled=False)
    config.deployment_mode = "managed_machine"
    runner = _bare_runner(config)
    runner._proxy = object()

    runner._safe_heartbeat()

    payload = runner.client.payloads[-1]
    assert payload["agent_version"] == __version__
    assert payload["posture"]["deployment_mode"] == "managed_machine"
    assert payload["posture"]["proxy"]["running"] is True
    assert payload["posture"]["control_mode"] == "ready"
    assert payload["posture"]["adapters"]["local_proxy"]["ready"] is True
    assert payload["posture"]["adapters"]["local_proxy"]["authorization_covered"] is False
    assert payload["posture"]["legacy_secret_residue"] is False


def test_runtime_posture_reuses_tick_resource_state_without_resampling() -> None:
    config = AgentConfig(proxy_enabled=False, ipc_enabled=False)
    runner = _bare_runner(config)

    def unexpected_sample(*, active: bool):
        del active
        raise AssertionError("heartbeat posture must not resample CPU")

    runner.resource_governor.sample = unexpected_sample

    posture = runner.runtime_posture()

    assert posture["resources"]["health"] == "healthy"


def test_successful_heartbeat_flushes_evidence_and_acknowledges_only_success() -> None:
    config = AgentConfig(proxy_enabled=False, ipc_enabled=False)
    runner = _bare_runner(config)
    queued = [
        {"id": "receipt-1", "kind": "decision_receipt", "action": "block"},
        {"id": "observation-2", "kind": "monitor_observation", "action": "allow"},
    ]
    acknowledged: list[str] = []
    runner.evidence_queue = SimpleNamespace(
        stats=lambda: {"queued": len(queued), "dropped_monitor": 0},
        items=lambda: list(queued),
        acknowledge=lambda item_id: acknowledged.append(item_id) or True,
    )

    runner._safe_heartbeat()

    assert [payload["event_type"] for payload in runner.client.evidence_payloads] == [
        "decision_receipt",
        "monitor_observation",
    ]
    assert acknowledged == ["receipt-1", "observation-2"]


def test_failed_evidence_upload_remains_queued() -> None:
    config = AgentConfig(proxy_enabled=False, ipc_enabled=False)
    runner = _bare_runner(config)
    acknowledged: list[str] = []
    runner.evidence_queue = SimpleNamespace(
        stats=lambda: {"queued": 1, "dropped_monitor": 0},
        items=lambda: [{"id": "receipt-1", "kind": "decision_receipt"}],
        acknowledge=lambda item_id: acknowledged.append(item_id) or True,
    )

    def fail(_payload: dict) -> None:
        raise runner_module.HawkUnavailable("offline")

    runner.client.report_evidence = fail
    runner._safe_heartbeat()

    assert acknowledged == []


def test_tick_skips_passive_collectors_during_resource_cooldown(monkeypatch) -> None:
    config = AgentConfig(proxy_enabled=False, ipc_enabled=False)
    runner = _bare_runner(config)

    class _LimitedState:
        disabled_capabilities = ["passive_discovery"]

        def as_dict(self):
            return {
                "health": "resource_limited",
                "sample": {"rss_mb": 50.0, "cpu_percent": 0.1, "active": False},
                "disabled_capabilities": ["passive_discovery"],
                "reasons": ["passive_discovery_cooldown"],
                "cooldown_remaining_seconds": 55.0,
            }

    runner.resource_governor = SimpleNamespace(
        sample=lambda active: SimpleNamespace(rss_mb=50.0, cpu_percent=0.1, active=active),
        evaluate=lambda _sample: _LimitedState(),
    )
    monkeypatch.setattr(
        runner_module,
        "list_processes",
        lambda: (_ for _ in ()).throw(AssertionError("passive scan must be skipped")),
    )

    summary = runner.tick()

    assert summary.processes == 0
    assert runner.client.payloads[-1]["error"] == "resource_limited"
    assert runner.client.payloads[-1]["posture"]["resources"]["cooldown_remaining_seconds"] == 55.0
