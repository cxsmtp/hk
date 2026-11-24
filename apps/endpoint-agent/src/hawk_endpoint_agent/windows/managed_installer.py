"""Transactional managed-machine installation for the Hawk Windows agent."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .native_driver import WindowsNativePackage
from .state import InstallStateStore, WindowsInstallState


@dataclass(frozen=True, slots=True)
class ManagedInstallRequest:
    package: WindowsNativePackage
    config_path: str
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    install_tls_trust: bool = False
    install_proxy_routing: bool = False
    development_only: bool = False


@dataclass(frozen=True, slots=True)
class ManagedInstallResult:
    ok: bool
    changed: bool
    detail: str
    state_json: str = ""


class WindowsManagedInstaller:
    """Legacy lab installer; production must use the signed PowerShell workflow."""

    def __init__(
        self,
        *,
        state_store: InstallStateStore,
        native_driver: Any,
        trust: Any,
        service: Any,
        routing: Any,
    ) -> None:
        self._state_store = state_store
        self._native = native_driver
        self._trust = trust
        self._service = service
        self._routing = routing

    def install(self, request: ManagedInstallRequest) -> ManagedInstallResult:
        if not request.development_only:
            return ManagedInstallResult(
                ok=False,
                changed=False,
                detail=(
                    "production managed install requires install_managed_agent.ps1 "
                    "with package, publisher, architecture, TPM-enrollment, and "
                    "disarmed-start validation"
                ),
            )
        existing = self._state_store.load()
        if existing is not None:
            return ManagedInstallResult(
                ok=True,
                changed=False,
                detail="managed Windows endpoint is already installed",
                state_json=json.dumps(asdict(existing), sort_keys=True),
            )
        if request.install_tls_trust and request.package.certificate_path is None:
            return ManagedInstallResult(
                ok=False,
                changed=False,
                detail="managed TLS trust requested but package certificate is absent",
            )

        completed: list[str] = []
        published_inf = ""
        trust_thumbprint = ""
        routing_snapshot: dict[str, Any] = {}
        try:
            native_result = self._native.install(request.package)
            published_inf = str(native_result.published_inf or "")
            completed.append("native_driver")

            if request.install_tls_trust:
                trust_thumbprint = str(
                    self._trust.install(
                        "managed_machine", request.package.certificate_path
                    )
                )
                completed.append("tls_trust")

            install_native = getattr(self._service, "install_native", None)
            if callable(install_native):
                install_native(
                    str(request.package.service_executable), request.config_path
                )
            else:
                self._service.install(
                    "managed_machine",
                    str(request.package.service_executable),
                    request.config_path,
                )
            completed.append("service")

            if request.install_proxy_routing:
                routing_snapshot = self._routing.capture("managed_machine")
                self._routing.apply(
                    "managed_machine", request.proxy_host, request.proxy_port
                )
                completed.append("routing")
        except Exception as exc:  # noqa: BLE001 - rollback must cover every adapter
            if "routing" in completed or routing_snapshot:
                try:
                    self._routing.restore(routing_snapshot)
                except Exception:
                    pass
            if "service" in completed:
                try:
                    self._service.remove("managed_machine")
                except Exception:
                    pass
            if "tls_trust" in completed:
                try:
                    self._trust.remove("managed_machine", trust_thumbprint)
                except Exception:
                    pass
            if "native_driver" in completed and published_inf:
                try:
                    self._native.remove(published_inf)
                except Exception:
                    pass
            self._state_store.remove()
            return ManagedInstallResult(
                ok=False,
                changed=bool(completed),
                detail=f"managed Windows endpoint install failed: {type(exc).__name__}",
            )

        state = WindowsInstallState(
            deployment_mode="managed_machine",
            proxy_host=request.proxy_host,
            proxy_port=request.proxy_port,
            config_path=request.config_path,
            routing_snapshot=routing_snapshot,
            trust_thumbprint=trust_thumbprint,
            autostart_installed=True,
            native_driver_installed=True,
            native_driver_published_name=published_inf,
            completed_steps=list(completed),
        )
        self._state_store.save(state)
        state_json = json.dumps(asdict(state), sort_keys=True)
        return ManagedInstallResult(
            ok=True,
            changed=True,
            detail="managed Windows endpoint installed",
            state_json=state_json,
        )

    def uninstall(self) -> ManagedInstallResult:
        state = self._state_store.load()
        if state is None:
            return ManagedInstallResult(
                ok=True,
                changed=False,
                detail="managed Windows endpoint is not installed",
            )
        failures: list[str] = []
        if "routing" in state.completed_steps and state.routing_snapshot:
            try:
                self._routing.restore(state.routing_snapshot)
            except Exception:
                failures.append("routing_restore_failed")
        if state.autostart_installed:
            try:
                self._service.remove("managed_machine")
            except Exception:
                failures.append("service_remove_failed")
        if state.trust_thumbprint:
            try:
                self._trust.remove("managed_machine", state.trust_thumbprint)
            except Exception:
                failures.append("trust_remove_failed")
        if state.native_driver_installed and state.native_driver_published_name:
            try:
                self._native.remove(state.native_driver_published_name)
            except Exception:
                failures.append("native_driver_remove_failed")
        if failures:
            return ManagedInstallResult(
                ok=False,
                changed=True,
                detail=",".join(failures),
                state_json=json.dumps(asdict(state), sort_keys=True),
            )
        self._state_store.remove()
        return ManagedInstallResult(
            ok=True,
            changed=True,
            detail="managed Windows endpoint removed and prior routing restored",
        )
