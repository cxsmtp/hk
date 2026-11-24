"""Agent runtime loop.

Continuous monitors (AI-notetaker control, shadow-AI discovery) run on the poll
interval. Event-driven controls (interaction security, data-transfer DLP, agent /
MCP authorization) are exposed as methods invoked by the local IPC / hook layer at
the moment of action, so their block/redact decisions are truly inline.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .collectors.audio import collect_platform_audio_candidates
from .collectors.meetings import detect_meeting
from .collectors.network import list_connections
from .collectors.processes import list_processes
from .baseline import BaselineStore
from .config import AgentConfig
from .auth.device_key import build_device_key_provider
from .control_plane import EndpointControlPlane
from .dispatcher import Dispatcher
from .evidence_queue import EvidenceQueue
from .endpoint_floor.runtime import configured_runtime_floor_posture, publish_signed_runtime_floor_posture
from .macos_native import MacOSNativeFloorManager
from .enforcement import EnforcementOrchestrator
from .hawk_client import HawkApiError, HawkClient, HawkUnavailable
from .hmair_snapshot import HMAIRSnapshotError, run_hmair_discovery_snapshot
from .ipc.control_server import ControlSocketServer
from .legacy_residue import cleanup_legacy_bootstrap_files
from .modules.agent_runtime import AgentRuntimeModule
from .modules.data_transfer import DataTransferModule
from .modules.desktop_native import DesktopNativeModule
from .modules.interaction_security import InteractionSecurityModule
from .modules.notetaker import NotetakerController
from .modules.shadow_ai import ShadowAIModule
from .policy import PolicyStore, endpoint_mode_for_platform_mode
from .proxy.local_proxy import LocalProxy
from .privacy import safe_failure
from .resource_governor import (
    ResourceBudget,
    ResourceGovernor,
    ResourceSample,
    ResourceState,
)
from .windows.kernel_channel import HAWK_WINDOWS_MAX_POLICY_BYTES, WindowsKernelChannel
from .windows.policy_compiler import WindowsFloorPolicyManager


@dataclass
class TickSummary:
    processes: int = 0
    notetakers_detected: int = 0
    notetakers_evicted: int = 0
    shadow_ai_reported: int = 0
    desktop_ai_reported: int = 0
    policy_stale: bool = True
    actions: list[dict[str, Any]] = field(default_factory=list)


class AgentRunner:
    def __init__(self, config: AgentConfig, *, client: HawkClient | None = None) -> None:
        self.config = config
        self._network_collection = {"status": "not_collected", "error_code": None, "observed_at": None}
        legacy_cleanup = cleanup_legacy_bootstrap_files(config.legacy_bootstrap_path)
        self._legacy_secret_residue = legacy_cleanup.residue_present
        self.client = client or HawkClient(config)
        self.policy = PolicyStore(config, self.client)
        self.control_plane = EndpointControlPlane(
            mode=config.agent_mode,
            mode_path=config.mode_state_path,
        )
        self.baseline = BaselineStore(
            config.baseline_path,
            tenant_key=config.tenant_id or config.endpoint_id or "local",
            max_paths=config.baseline_max_paths,
        )
        self.evidence_queue = EvidenceQueue(
            config.evidence_queue_path,
            max_items=config.evidence_queue_max_items,
        )
        self.resource_governor = ResourceGovernor(
            ResourceBudget(
                idle_rss_mb=config.idle_rss_limit_mb,
                active_rss_mb=config.active_rss_limit_mb,
                idle_cpu_percent=config.idle_cpu_limit_percent,
                active_cpu_percent=config.active_cpu_limit_percent,
            ),
            passive_discovery_cooldown_seconds=config.passive_discovery_cooldown_seconds,
        )
        self._resource_state = ResourceState(
            health="initializing",
            sample=ResourceSample(rss_mb=0.0, cpu_percent=0.0, active=False),
            budget=self.resource_governor.budget,
            disabled_capabilities=[],
            reasons=[],
            cooldown_remaining_seconds=0.0,
        )
        self.orchestrator = EnforcementOrchestrator(config, self.policy)
        self.notetaker = NotetakerController(config)
        self.shadow = ShadowAIModule(config, self.client)
        self.desktop = DesktopNativeModule(config, self.client)
        self.dispatcher = Dispatcher(
            config,
            client=self.client,
            policy=self.policy,
            control_plane=self.control_plane,
            baseline=self.baseline,
            evidence_queue=self.evidence_queue,
        )
        self.interaction = InteractionSecurityModule(config, self.client, self.orchestrator)
        self.data_transfer = DataTransferModule(config, self.client, self.orchestrator)
        self.agent_runtime = AgentRuntimeModule(config, self.client, self.orchestrator)
        self._proxy: LocalProxy | None = None
        self._ipc: ControlSocketServer | None = None
        self._proxy_error: str | None = None
        self._ipc_error: str | None = None
        self._windows_floor_manager: WindowsFloorPolicyManager | None = None
        self._windows_floor_envelope_fingerprint: str | None = None
        self._windows_floor_last_mode: str | None = None
        self._macos_native_manager: MacOSNativeFloorManager | None = None
        self._macos_receipt_provider = None
        self._macos_receipt_error: str | None = None
        if config.os_type in {"darwin", "macos"} and config.macos_native_enforcement_enabled:
            self._macos_receipt_provider = build_device_key_provider(
                provider_name=config.key_provider, security_profile=config.security_profile,
                helper_path=config.identity_helper_path, helper_sha256=config.identity_helper_sha256,
                key_tag=config.device_key_tag,
            )
            self._macos_native_manager = MacOSNativeFloorManager(
                policy_path=config.macos_managed_policy_path,
                config_path=config.macos_managed_config_path,
                host_app_path=config.macos_host_app_path,
                acceptance_path=config.macos_target_acceptance_path,
                acceptance_public_keys={name: base64.b64decode(value, validate=True)
                    for name, value in config.macos_target_acceptance_public_keys.items()},
                tenant_id=config.tenant_id,
                device_id=config.endpoint_id,
                policy_public_keys={name: base64.b64decode(value, validate=True)
                    for name, value in config.endpoint_floor_policy_public_keys.items()},
                routing_provider=self._macos_receipt_provider,
            )
        self._windows_floor_state: dict[str, Any] = {
            "requested": bool(config.windows_native_enforcement_enabled),
            "reachable": False,
            "armed": False,
            "policy_current": False,
            "identity_coverage_ready": False,
            "wfp_ready": False,
            "policy_version": None,
            "rule_count": 0,
            "generation": 0,
            "allow_count": 0,
            "block_count": 0,
            "policy_reject_count": 0,
            "error_code": None,
        }
        self._hmair_inventory_attempted: set[str] = set()
        self._stop = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.refresh_policy()
        self.start_local_servers()
        while not self._stop:
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - never let one tick kill the agent
                self._safe_heartbeat(error=str(exc))
            time.sleep(max(1.0, self.config.poll_interval_seconds))

    def refresh_policy(self) -> bool:
        """Refresh authenticated policy and reconcile only recognized server modes."""
        refreshed = self.policy.refresh()
        if refreshed:
            policy = self.policy.policy
            target_mode = endpoint_mode_for_platform_mode(
                policy.platform_mode if policy is not None else None
            )
            if target_mode is not None:
                self.control_plane.set_mode(target_mode)
        # A managed, signed local policy remains usable during a backend outage.
        # Its own short expiry is independently enforced by the kernel snapshot.
        self._reconcile_windows_floor()
        self._reconcile_macos_native()
        return refreshed

    def _reconcile_macos_native(self) -> bool:
        manager = getattr(self, "_macos_native_manager", None)
        if manager is None:
            return False
        status = manager.reconcile(mode=self.control_plane.mode)
        try:
            payload = manager.runtime_receipt_payload(
                tenant_id=self.config.tenant_id,
                device_id=self.config.endpoint_id,
            )
            if self._macos_receipt_provider is None:
                raise ValueError("hardware device identity is unavailable")
            publish_signed_runtime_floor_posture(
                payload=payload,
                receipt_path=self.config.endpoint_floor_receipt_path,
                provider=self._macos_receipt_provider,
                endpoint_id=self.config.endpoint_id,
                require_hardware_backed=True,
            )
            self._macos_receipt_error = None
        except (ValueError, OSError, RuntimeError) as exc:
            self._macos_receipt_error = f"runtime_receipt_unavailable:{type(exc).__name__}"
            status.reason_codes = list(dict.fromkeys([
                *status.reason_codes, self._macos_receipt_error
            ]))[:32]
            return False
        return bool(status.healthy and status.policy_current and
                    manager.posture()["display_state"] != "Needs attention")

    def _endpoint_floor_posture(self) -> dict[str, Any]:
        posture = configured_runtime_floor_posture(
            os_type=self.config.os_type,
            receipt_path=self.config.endpoint_floor_receipt_path,
            trusted_public_keys=self.config.endpoint_floor_receipt_public_keys,
            expected_tenant_id=self.config.tenant_id,
            expected_device_id=self.config.endpoint_id,
        )
        manager = getattr(self, "_macos_native_manager", None)
        if manager is not None and (
            getattr(self, "_macos_receipt_error", None) or
            manager.posture()["display_state"] == "Needs attention"
        ):
            posture["minimum_floor_satisfied"] = False
            posture["health"] = "degraded"
            posture["display_state"] = "Needs attention"
            reason = getattr(self, "_macos_receipt_error", None) or "native_control_unverified"
            posture["reason_codes"] = list(dict.fromkeys([
                *posture["reason_codes"], reason
            ]))
        return posture

    def _build_windows_floor_manager(self) -> WindowsFloorPolicyManager:
        if self.config.os_type != "windows":
            raise RuntimeError("Windows endpoint-floor requested on a non-Windows host")
        trusted_keys = {
            key_id: base64.b64decode(encoded, validate=True)
            for key_id, encoded in self.config.endpoint_floor_policy_public_keys.items()
        }
        if not trusted_keys:
            raise ValueError("Windows endpoint-floor policy trust is not configured")
        return WindowsFloorPolicyManager(
            channel=WindowsKernelChannel(
                device_path=self.config.windows_floor_device_path,
            ),
            trusted_public_keys=trusted_keys,
            tenant_id=self.config.tenant_id,
            device_id=self.config.endpoint_id,
            replay_state_path=self.config.windows_floor_replay_state_path,
        )

    def _load_windows_floor_envelope(self) -> dict[str, Any] | None:
        policy = getattr(self.policy, "policy", None)
        raw = getattr(policy, "raw", None)
        if isinstance(raw, dict) and "endpoint_floor_policy" in raw:
            envelope = raw["endpoint_floor_policy"]
            if not isinstance(envelope, dict):
                raise ValueError("Windows endpoint-floor policy envelope is invalid")
            return dict(envelope)

        configured = str(self.config.windows_floor_policy_path or "").strip()
        if not configured:
            return None
        path = Path(os.path.expandvars(configured)).expanduser()
        try:
            if path.is_symlink():
                raise ValueError("Windows endpoint-floor policy path cannot be a symlink")
            with path.open("rb") as handle:
                encoded = handle.read(HAWK_WINDOWS_MAX_POLICY_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(encoded) > HAWK_WINDOWS_MAX_POLICY_BYTES:
            raise ValueError("Windows endpoint-floor policy file is too large")
        try:
            envelope = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Windows endpoint-floor policy file is invalid") from exc
        if not isinstance(envelope, dict):
            raise ValueError("Windows endpoint-floor policy envelope is invalid")
        return envelope

    @staticmethod
    def _windows_floor_error_code(exc: Exception) -> str:
        if isinstance(exc, ValueError):
            return "POLICY_REJECTED"
        if isinstance(exc, OSError):
            return "DRIVER_UNAVAILABLE"
        if isinstance(exc, RuntimeError):
            return "DRIVER_PROTOCOL_ERROR"
        return "INTERNAL_ERROR"

    def _record_windows_floor_status(self, status: Any, *, error_code: str) -> None:
        loaded = bool(getattr(status, "policy_loaded", False))
        self._windows_floor_state.update(
            reachable=True,
            armed=bool(getattr(status, "armed", False)),
            policy_current=bool(getattr(status, "policy_current", False)),
            identity_coverage_ready=bool(
                getattr(status, "identity_coverage_ready", False)
            ),
            wfp_ready=bool(getattr(status, "wfp_ready", False)),
            policy_version=(
                self._windows_floor_state.get("policy_version") if loaded else None
            ),
            rule_count=(
                int(self._windows_floor_state.get("rule_count") or 0)
                if loaded
                else 0
            ),
            generation=int(getattr(status, "generation", 0)),
            allow_count=int(getattr(status, "allow_count", 0)),
            block_count=int(getattr(status, "block_count", 0)),
            policy_reject_count=int(
                getattr(status, "policy_reject_count", 0)
            ),
            error_code=error_code,
        )

    def _reconcile_windows_floor(self) -> bool:
        if not self.config.windows_native_enforcement_enabled:
            return False
        manager = self._windows_floor_manager
        try:
            if manager is None:
                manager = self._build_windows_floor_manager()
                self._windows_floor_manager = manager
            envelope = self._load_windows_floor_envelope()
            if envelope is None:
                status = manager.status()
                if self.control_plane.mode != "enforce" or not status.armed:
                    manager.disarm()
                    status = manager.status()
                self._record_windows_floor_status(
                    status,
                    error_code="POLICY_MISSING",
                )
                self._windows_floor_envelope_fingerprint = None
                self._windows_floor_last_mode = None
                return False
            fingerprint = hashlib.sha256(
                json.dumps(
                    envelope,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            if (
                fingerprint == getattr(self, "_windows_floor_envelope_fingerprint", None)
                and self.control_plane.mode == getattr(self, "_windows_floor_last_mode", None)
            ):
                status = manager.status()
                expected_armed = self.control_plane.mode == "enforce"
                if (
                    status.policy_loaded
                    and status.policy_current
                    and status.armed == expected_armed
                    and (
                        not expected_armed
                        or (
                            bool(getattr(status, "identity_coverage_ready", False))
                            and bool(getattr(status, "wfp_ready", False))
                        )
                    )
                ):
                    self._windows_floor_state.update(
                        reachable=True,
                        armed=bool(status.armed),
                        policy_current=True,
                        identity_coverage_ready=bool(
                            getattr(status, "identity_coverage_ready", False)
                        ),
                        wfp_ready=bool(getattr(status, "wfp_ready", False)),
                        generation=int(status.generation),
                        allow_count=int(status.allow_count),
                        block_count=int(status.block_count),
                        policy_reject_count=int(status.policy_reject_count),
                        error_code=None,
                    )
                    return True
            result = manager.reconcile(envelope, mode=self.control_plane.mode)
            self._windows_floor_state.update(
                reachable=True,
                armed=bool(result.armed),
                policy_current=bool(getattr(result, "policy_current", True)),
                identity_coverage_ready=bool(
                    getattr(result, "identity_coverage_ready", True)
                ),
                wfp_ready=bool(getattr(result, "wfp_ready", True)),
                policy_version=result.policy_version,
                rule_count=int(result.rule_count),
                generation=int(getattr(result, "generation", 0)),
                allow_count=int(getattr(result, "allow_count", 0)),
                block_count=int(getattr(result, "block_count", 0)),
                policy_reject_count=int(
                    getattr(result, "policy_reject_count", 0)
                ),
                error_code=None,
            )
            self._windows_floor_envelope_fingerprint = fingerprint
            self._windows_floor_last_mode = self.control_plane.mode
            return True
        except Exception as exc:  # noqa: BLE001 - expose only bounded error codes
            retained_status = None
            if manager is not None:
                try:
                    retained_status = manager.status()
                    if (
                        self.control_plane.mode != "enforce"
                        or not retained_status.armed
                    ):
                        manager.disarm()
                        retained_status = manager.status()
                except Exception:  # noqa: BLE001 - bounded device failure
                    retained_status = None
                    if self.control_plane.mode != "enforce":
                        try:
                            manager.disarm()
                        except Exception:  # noqa: BLE001 - device is unreachable
                            pass
            error_code = self._windows_floor_error_code(exc)
            if retained_status is not None:
                self._record_windows_floor_status(
                    retained_status,
                    error_code=error_code,
                )
            else:
                self._windows_floor_state.update(
                    reachable=False,
                    armed=False,
                    policy_current=False,
                    identity_coverage_ready=False,
                    wfp_ready=False,
                    policy_version=None,
                    rule_count=0,
                    generation=0,
                    allow_count=0,
                    block_count=0,
                    policy_reject_count=0,
                    error_code=error_code,
                )
            self._windows_floor_envelope_fingerprint = None
            self._windows_floor_last_mode = None
            return False

    def start_local_servers(self) -> None:
        """Start additive local adapters without claiming action coverage."""
        if self.config.ipc_enabled and self._ipc is None:
            try:
                self._ipc = ControlSocketServer(self.config, self.dispatcher)
                self._ipc.start()
                self._ipc_error = None
                self.control_plane.set_ready("local_ipc", True)
            except OSError as exc:
                self._ipc = None
                self._ipc_error = self._os_error_code(exc)
                self.control_plane.set_ready("local_ipc", False)
        if self.config.proxy_enabled and self._proxy is None:
            interceptor = self._build_interceptor()
            try:
                self._proxy = LocalProxy(self.config, self.dispatcher, self.policy, interceptor=interceptor)
                self._proxy.start()
                self._proxy_error = None
                self.control_plane.set_ready("local_proxy", True)
            except OSError as exc:
                self._proxy = None
                self._proxy_error = self._os_error_code(exc)
                self.control_plane.set_ready("local_proxy", False)

    @staticmethod
    def _os_error_code(exc: OSError) -> str:
        return errno.errorcode.get(exc.errno or 0, "OS_ERROR")

    def runtime_posture(self) -> dict[str, Any]:
        proxy_requested = bool(self.config.proxy_enabled)
        proxy_running = self._proxy is not None
        ipc_requested = bool(self.config.ipc_enabled)
        ipc_running = self._ipc is not None
        native_state = dict(self._windows_floor_state)
        native_requested = bool(native_state.get("requested"))
        native_ready = (
            bool(native_state.get("reachable"))
            and bool(native_state.get("policy_current"))
            and bool(native_state.get("armed"))
            == (self.control_plane.mode == "enforce")
            and (
                self.control_plane.mode != "enforce"
                or (
                    bool(native_state.get("identity_coverage_ready"))
                    and bool(native_state.get("wfp_ready"))
                )
            )
        )
        component_failed = (
            (proxy_requested and not proxy_running)
            or (ipc_requested and not ipc_running)
            or (native_requested and not native_ready)
        )
        if component_failed:
            control_mode = "incomplete"
        elif proxy_running or ipc_running or native_ready:
            control_mode = "ready"
        else:
            control_mode = "telemetry_only"

        self.control_plane.set_ready("local_proxy", proxy_running)
        self.control_plane.set_ready("local_ipc", ipc_running)
        self.control_plane.set_ready("endpoint_floor", native_ready)
        plane_posture = self.control_plane.posture()
        resource_state = self._resource_state.as_dict()

        return {
            "deployment_mode": self.config.deployment_mode,
            "control_mode": control_mode,
            "agent_mode": self.control_plane.mode,
            "legacy_secret_residue": self._legacy_secret_residue,
            "proxy": {
                "requested": proxy_requested,
                "running": proxy_running,
                "host": self.config.proxy_host,
                "port": self.config.proxy_port,
                "error_code": self._proxy_error,
            },
            "ipc": {
                "requested": ipc_requested,
                "running": ipc_running,
                "error_code": self._ipc_error,
            },
            "windows_native": native_state,
            "macos_native": (
                self._macos_native_manager.posture()
                if getattr(self, "_macos_native_manager", None) is not None
                else {"requested": False, "display_state": "Needs attention"}
            ),
            "tls_intercept": {
                "requested": bool(self.config.tls_intercept_enabled),
                "active": bool(proxy_running and self.config.tls_intercept_enabled),
            },
            "routing": {
                "requested": bool(self.config.windows_routing_enabled),
                "managed": self.config.deployment_mode == "managed_machine",
            },
            "coverage": {
                "inline_paths": [
                    path for path, state in plane_posture["adapters"].items()
                    if state["authorization_covered"]
                ],
                "limitations": [
                    "Traffic not routed through the local proxy or IPC is not inline controlled.",
                    "Certificate-pinned applications and QUIC may bypass TLS interception.",
                ],
            },
            "adapters": plane_posture["adapters"],
            "baseline": self.baseline.snapshot(),
            "network_collection": dict(self._network_collection),
            "evidence_queue": self.evidence_queue.stats(),
            "resources": resource_state,
            "endpoint_enforcement_floor": self._endpoint_floor_posture(),
        }

    def _build_interceptor(self):
        """Build the TLS interceptor if enabled and capable; else None (host-level control)."""
        if not self.config.tls_intercept_enabled:
            return None
        try:
            from .tls.certs import CertificateAuthority
            from .tls.interceptor import TlsInterceptor

            ca = CertificateAuthority(self.config.tls_ca_dir)
            if not ca.available():
                return None
            ca.ensure_ca()
            return TlsInterceptor(ca)
        except Exception:  # noqa: BLE001 - degrade to host-level TLS control
            return None

    def stop(self) -> None:
        self._stop = True
        if self._proxy is not None:
            self._proxy.stop()
            self._proxy = None
            self.control_plane.set_ready("local_proxy", False)
        if self._ipc is not None:
            self._ipc.stop()
            self._ipc = None
            self.control_plane.set_ready("local_ipc", False)

    # -- one iteration (testable) -----------------------------------------
    def tick(self) -> TickSummary:
        summary = TickSummary()
        if self.policy.stale:
            self.refresh_policy()
        else:
            self._reconcile_windows_floor()
            self._reconcile_macos_native()
        summary.policy_stale = self.policy.stale

        self._resource_state = self.resource_governor.evaluate(
            self.resource_governor.sample(active=True)
        )
        if "passive_discovery" in self._resource_state.disabled_capabilities:
            self._safe_heartbeat(summary=summary, error="resource_limited")
            return summary

        self._dispatch_hmair_metadata_inventory()

        processes = list_processes()
        connections = list_connections(processes)
        self._network_collection = {
            "status": getattr(connections, "collection_status", "unknown"),
            "error_code": getattr(connections, "error_code", None),
            "observed_at": time.time(),
            "connection_count": len(connections),
            "scope": "connections_visible_to_agent_process",
        }
        meeting = detect_meeting(processes, connections)
        audio_candidates = collect_platform_audio_candidates(processes, os_type=self.config.os_type)
        summary.processes = len(processes)

        if self.policy.module_enabled("notetaker"):
            detected = self.notetaker.detect(
                processes=processes,
                connections=connections,
                audio_candidates=audio_candidates,
                meeting=meeting,
            )
            summary.notetakers_detected = len(detected)
            for entry in detected:
                decision = self.notetaker.evaluate(entry, client=self.client, policy=self.policy)
                outcome = self.notetaker.enforce(entry, decision, mode=self.control_plane.mode)
                if outcome.evicted:
                    summary.notetakers_evicted += 1
                summary.actions.append(
                    {"notetaker": outcome.notetaker, "decision": decision.action, "evicted": outcome.evicted}
                )
                self._report_notetaker(entry, outcome)

        if self.policy.module_enabled("shadow_ai"):
            for signal in self.shadow.discover(processes=processes, connections=connections):
                if self.shadow.report(signal):
                    summary.shadow_ai_reported += 1

        if self.policy.module_enabled("desktop_native"):
            for signal in self.desktop.discover(processes=processes):
                if self.desktop.report(signal):
                    summary.desktop_ai_reported += 1

        self._safe_heartbeat(summary=summary)
        return summary

    def _dispatch_hmair_metadata_inventory(self) -> bool:
        """Run one fresh, authenticated metadata-only inventory directive.

        The directive is not persisted locally. A backend outage is intentionally
        not turned into a failure receipt because the server may have accepted
        the snapshot before the response was lost.
        """

        if self.policy.stale:
            return False
        policy = self.policy.policy
        directive = (
            policy.hmair_metadata_inventory if policy is not None else None
        )
        if not directive:
            return False
        assignment_id = directive["assignment_id"]
        if assignment_id in self._hmair_inventory_attempted:
            return False
        self._hmair_inventory_attempted.add(assignment_id)
        try:
            run_hmair_discovery_snapshot(
                self.config,
                client=self.client,
                snapshot_id=assignment_id,
                inventory_assignment_id=assignment_id,
            )
            return True
        except HawkUnavailable:
            return False
        except HMAIRSnapshotError:
            self._report_hmair_inventory_failure(assignment_id, "snapshot_rejected")
            return False
        except HawkApiError as exc:
            if 400 <= exc.status < 500:
                self._report_hmair_inventory_failure(
                    assignment_id,
                    "snapshot_rejected",
                )
            return False
        except Exception:  # noqa: BLE001 - inventory must never stop the agent
            self._report_hmair_inventory_failure(assignment_id, "scanner_unavailable")
            return False

    def _report_hmair_inventory_failure(self, assignment_id: str, code: str) -> None:
        reporter = getattr(self.client, "report_hmair_inventory_failure", None)
        if not callable(reporter):
            return
        try:
            reporter(assignment_id, code)
        except (HawkUnavailable, HawkApiError, Exception):  # noqa: BLE001
            pass

    # -- reporting ---------------------------------------------------------
    def _report_notetaker(self, entry, outcome) -> None:
        try:
            event = entry.to_telemetry_event(self.config, outcome=outcome)
            self.client.report_discovery(event)
        except (HawkUnavailable, HawkApiError, Exception):  # noqa: BLE001 - telemetry is best-effort
            pass

    def _safe_heartbeat(self, *, summary: TickSummary | None = None, error: str | None = None) -> None:
        payload = {
            "endpoint_id": self.config.endpoint_id,
            "hostname": self.config.hostname,
            "os_type": self.config.os_type,
            "os_version": self.config.os_version,
            "agent_version": __version__,
            "policy_stale": self.policy.stale,
            "modules": [m for m in self.config.enabled_modules if self.policy.module_enabled(m)],
            "posture": self.runtime_posture(),
        }
        if summary is not None:
            payload["last_tick"] = {
                "processes": summary.processes,
                "notetakers_detected": summary.notetakers_detected,
                "notetakers_evicted": summary.notetakers_evicted,
                "shadow_ai_reported": summary.shadow_ai_reported,
            }
        if error:
            payload["error"] = safe_failure(error)
        try:
            self.client.heartbeat(payload)
        except (HawkUnavailable, HawkApiError):
            pass
        else:
            self._flush_evidence()

    def _flush_evidence(self, *, limit: int = 25) -> None:
        """Upload bounded privacy-safe evidence without losing failed items."""
        for item in self.evidence_queue.items()[: max(0, int(limit))]:
            item_id = str(item.get("id") or "")
            if not item_id:
                continue
            payload = dict(item)
            payload.setdefault("event_type", str(payload.get("kind") or "endpoint_event"))
            try:
                self.client.report_evidence(payload)
            except (HawkUnavailable, HawkApiError):
                break
            self.evidence_queue.acknowledge(item_id)
