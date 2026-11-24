"""Windows machine service and limited per-user task lifecycle."""

from __future__ import annotations

import subprocess
from typing import Protocol, Sequence

from .command import (
    SCHTASKS_EXE,
    SC_EXE,
    CommandResult,
    WindowsDeploymentError,
    require_success,
)


_SERVICE_NAME = "HawkEndpointAgent"
_TASK_NAME = "HawkEndpointAgentUser"


class Runner(Protocol):
    def run(
        self, argv: Sequence[str], *, timeout: float = 30.0
    ) -> CommandResult: ...


def _mode(value: str) -> str:
    mode = str(value).strip().lower()
    if mode not in {"user_pilot", "managed_machine"}:
        raise ValueError("unsupported Windows deployment mode")
    return mode


def _safe_path(value: str, label: str) -> str:
    rendered = str(value)
    if not rendered or any(character in rendered for character in ("\x00", "\r", "\n")):
        raise ValueError(f"invalid {label}")
    return rendered


class WindowsService:
    def __init__(self, runner: Runner) -> None:
        self._runner = runner

    @staticmethod
    def _command_line(python_executable: str, config_path: str) -> str:
        return subprocess.list2cmdline(
            [
                _safe_path(python_executable, "Python executable"),
                "-m",
                "hawk_endpoint_agent",
                "--config",
                _safe_path(config_path, "agent config path"),
            ]
        )

    @staticmethod
    def _native_command_line(service_executable: str, config_path: str) -> str:
        return subprocess.list2cmdline(
            [
                _safe_path(service_executable, "service executable"),
                "--config",
                _safe_path(config_path, "agent config path"),
            ]
        )

    def install_native(self, service_executable: str, config_path: str) -> None:
        """Install the real SCM-aware launcher, never a console Python process."""
        command_line = self._native_command_line(service_executable, config_path)
        require_success(
            self._runner.run(
                [
                    SC_EXE,
                    "create",
                    _SERVICE_NAME,
                    "binPath=",
                    command_line,
                    "start=",
                    "auto",
                    "depend=",
                    "HawkEndpointFloor",
                    "DisplayName=",
                    "Hawk Endpoint Agent",
                ]
            ),
            "create Hawk Windows service",
        )
        require_success(
            self._runner.run(
                [
                    SC_EXE,
                    "failure",
                    _SERVICE_NAME,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/5000/restart/15000/none/0",
                ]
            ),
            "configure Hawk Windows service recovery",
        )
        require_success(
            self._runner.run([SC_EXE, "failureflag", _SERVICE_NAME, "1"]),
            "enable Hawk Windows non-crash recovery",
        )
        # The driver mutation device is bound to this per-service SID. Keep the
        # SID unrestricted so it is enabled in the service token without a
        # second restricted-SID ACL pass; administrators retain status-only access.
        require_success(
            self._runner.run([SC_EXE, "sidtype", _SERVICE_NAME, "unrestricted"]),
            "enable Hawk Windows service SID",
        )
        require_success(
            self._runner.run([SC_EXE, "start", _SERVICE_NAME]),
            "start Hawk Windows service",
        )

    def install(
        self, deployment_mode: str, python_executable: str, config_path: str
    ) -> None:
        mode = _mode(deployment_mode)
        command_line = self._command_line(python_executable, config_path)
        if mode == "managed_machine":
            create = self._runner.run(
                [
                    SC_EXE,
                    "create",
                    _SERVICE_NAME,
                    "binPath=",
                    command_line,
                    "start=",
                    "auto",
                    "DisplayName=",
                    "Hawk Endpoint Agent",
                ]
            )
            require_success(create, "create Hawk Windows service")
            require_success(
                self._runner.run([SC_EXE, "start", _SERVICE_NAME]),
                "start Hawk Windows service",
            )
            return
        require_success(
            self._runner.run(
                [
                    SCHTASKS_EXE,
                    "/Create",
                    "/TN",
                    _TASK_NAME,
                    "/TR",
                    command_line,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "LIMITED",
                    "/F",
                ]
            ),
            "create limited Hawk user task",
        )

    def remove(self, deployment_mode: str) -> None:
        mode = _mode(deployment_mode)
        if mode == "managed_machine":
            # A stopped service returns a non-zero status; deletion remains the
            # authoritative cleanup step and must still be attempted.
            self._runner.run([SC_EXE, "stop", _SERVICE_NAME])
            require_success(
                self._runner.run([SC_EXE, "delete", _SERVICE_NAME]),
                "delete Hawk Windows service",
            )
            return
        result = self._runner.run(
            [SCHTASKS_EXE, "/Delete", "/TN", _TASK_NAME, "/F"]
        )
        if result.returncode not in {0, 1}:
            raise WindowsDeploymentError(
                f"delete Hawk user task failed ({result.error_code})"
            )
