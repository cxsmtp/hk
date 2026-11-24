"""Supported-signal discovery for the ChatGPT desktop composite surface.

This module reads only operating-system process metadata, the public app bundle
manifest, and code-signing assessment output. It deliberately does not inspect
ChatGPT application storage, cookies, credentials, prompts, or protected internals.
"""

from __future__ import annotations

import plistlib
import re
import subprocess
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence

from .collectors.base import ProcessInfo


class ChatGPTDesktopMode(str, Enum):
    CHAT = "chat"
    WORK_LOCAL = "work_local"
    WORK_CLOUD = "work_cloud"
    CODEX_LOCAL = "codex_local"
    CODEX_REMOTE = "codex_remote"
    BUILT_IN_BROWSER = "built_in_browser"
    APP_ACTION = "app_action"
    MCP_ACTION = "mcp_action"
    UNKNOWN_DESKTOP_MODE = "unknown_desktop_mode"


class ChatGPTRuntimeLocation(str, Enum):
    LOCAL_ENDPOINT = "local_endpoint"
    OPENAI_CLOUD = "openai_cloud"
    MIXED = "mixed"
    UNKNOWN = "unknown"


CommandRunner = Callable[[list[str]], tuple[int, str, str]]
_OFFICIAL_BUNDLE_IDS = frozenset({"com.openai.codex", "com.openai.chat", "com.openai.chatgpt"})
_MAX_TEXT = 512


def _bounded(value: object, limit: int = _MAX_TEXT) -> str | None:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[:limit] or None


def _default_command_runner(args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, "", ""
    return result.returncode, result.stdout or "", result.stderr or ""


@dataclass(frozen=True, slots=True)
class ChatGPTInstallationObservation:
    installed: bool
    bundle_path: str | None
    bundle_id: str | None
    version: str | None
    build: str | None
    executable_name: str | None
    team_id: str | None
    code_directory_hash: str | None
    signature_verified: bool
    hardened_runtime: bool
    notarization_verified: bool
    native_hook_available: bool = False
    evidence_basis: str = "supported_os_bundle_and_signature_metadata"

    def as_dict(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True, slots=True)
class ChatGPTProcessObservation:
    process_id: int
    parent_process_id: int | None
    process_start_time_ns: int | None
    process_name: str
    executable_path: str | None
    user: str | None
    identity_state: str
    mode: ChatGPTDesktopMode
    runtime_location: ChatGPTRuntimeLocation
    account_context: str
    installation: ChatGPTInstallationObservation

    def as_dict(self) -> dict[str, object]:
        return {
            **self.installation.as_dict(),
            "process_id": self.process_id,
            "parent_process_id": self.parent_process_id,
            "process_start_time_ns": self.process_start_time_ns,
            "process_name": _bounded(self.process_name, 128),
            "executable_path": _bounded(self.executable_path),
            "user": _bounded(self.user, 256),
            "identity_state": self.identity_state,
            "mode": self.mode.value,
            "runtime_location": self.runtime_location.value,
            "account_context": self.account_context,
            "supported_signal_only": True,
        }


def inspect_chatgpt_installation(
    app_path: str | Path = "/Applications/ChatGPT.app",
    *,
    command_runner: CommandRunner | None = None,
) -> ChatGPTInstallationObservation:
    path = Path(app_path).expanduser()
    manifest = path / "Contents" / "Info.plist"
    if not path.is_dir() or not manifest.is_file():
        return ChatGPTInstallationObservation(False, str(path)[:_MAX_TEXT], None, None, None, None, None, None, False, False, False)
    try:
        with manifest.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        info = {}
    if not isinstance(info, dict):
        info = {}
    runner = command_runner or _default_command_runner
    verify_code, _verify_out, _verify_err = runner(["codesign", "--verify", "--deep", "--strict", str(path)])
    _detail_code, detail_out, detail_err = runner(["codesign", "-dv", "--verbose=4", str(path)])
    detail = f"{detail_out}\n{detail_err}"[:16_384]
    spctl_code, spctl_out, spctl_err = runner(["spctl", "--assess", "--type", "execute", "--verbose=4", str(path)])
    assessment = f"{spctl_out}\n{spctl_err}"[:8_192].lower()

    def capture(pattern: str) -> str | None:
        matched = re.search(pattern, detail, flags=re.IGNORECASE | re.MULTILINE)
        return _bounded(matched.group(1), 256) if matched else None

    bundle_id = _bounded(info.get("CFBundleIdentifier"), 256)
    return ChatGPTInstallationObservation(
        installed=True,
        bundle_path=str(path.resolve(strict=False))[:_MAX_TEXT],
        bundle_id=bundle_id,
        version=_bounded(info.get("CFBundleShortVersionString"), 128),
        build=_bounded(info.get("CFBundleVersion"), 128),
        executable_name=_bounded(info.get("CFBundleExecutable"), 128),
        team_id=capture(r"^TeamIdentifier=(.+)$"),
        code_directory_hash=capture(r"^CDHash=(.+)$"),
        signature_verified=bool(verify_code == 0 and bundle_id in _OFFICIAL_BUNDLE_IDS),
        hardened_runtime="runtime" in detail.lower(),
        notarization_verified=bool(
            spctl_code == 0
            and "accepted" in assessment
            and ("notarized" in assessment or "developer id" in assessment)
        ),
    )


def _inside_bundle(executable_path: str | None, bundle_path: str | None) -> bool:
    if not executable_path or not bundle_path:
        return False
    executable = Path(executable_path).expanduser().resolve(strict=False)
    bundle = Path(bundle_path).expanduser().resolve(strict=False)
    try:
        executable.relative_to(bundle)
    except ValueError:
        return False
    return True


def observe_chatgpt_processes(
    processes: Sequence[ProcessInfo],
    installation: ChatGPTInstallationObservation,
) -> list[ChatGPTProcessObservation]:
    observations: list[ChatGPTProcessObservation] = []
    for process in processes:
        executable_path = process.executable_path or (
            process.cmdline.split()[0] if process.cmdline.strip() else None
        )
        name_signal = "chatgpt" in process.name.lower()
        bundle_signal = _inside_bundle(executable_path, installation.bundle_path)
        if not name_signal and not bundle_signal:
            continue
        identity_state = (
            "bundle_and_signature_matched"
            if bundle_signal and installation.signature_verified
            else "bundle_matched_signature_unverified"
            if bundle_signal
            else "name_only_unverified"
        )
        observations.append(
            ChatGPTProcessObservation(
                process_id=max(0, int(process.pid)),
                parent_process_id=process.parent_pid,
                process_start_time_ns=process.process_start_time_ns,
                process_name=process.name,
                executable_path=executable_path,
                user=process.user or None,
                identity_state=identity_state,
                # No mode/account/runtime inference from the process or app name.
                mode=ChatGPTDesktopMode.UNKNOWN_DESKTOP_MODE,
                runtime_location=ChatGPTRuntimeLocation.UNKNOWN,
                account_context="unknown",
                installation=installation,
            )
        )
    return sorted(observations, key=lambda row: (row.process_id, row.process_name))
