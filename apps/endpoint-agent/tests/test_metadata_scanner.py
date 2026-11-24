from __future__ import annotations

import json
import os
import plistlib
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

import hawk_endpoint_agent.metadata_scanner as scanner_module
from hawk_endpoint_agent.metadata_scanner import (
    LocalFilesystemProbe,
    ScanLimits,
    ScanRoots,
    collect_endpoint_metadata,
)


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _product(report: dict, product_id: str) -> dict:
    return next(item for item in report["products"] if item["id"] == product_id)


def test_collects_only_allowlisted_metadata_from_fixed_product_locations(tmp_path: Path) -> None:
    home = tmp_path / "private-user@example.test"
    applications = tmp_path / "Applications"
    executables = tmp_path / "bin"

    _write(
        home / ".claude/settings.json",
        json.dumps(
            {
                "model": "claude-sonnet",
                "mcpServers": {
                    "approved-docs": {
                        "command": "npx",
                        "env": {"ANTHROPIC_API_KEY": "claude-secret-value"},
                    }
                },
                "accountEmail": "person@example.test",
                "promptHistory": ["never collect this prompt"],
            }
        ),
    )
    _write(
        home / ".codex/config.toml",
        """
model = "gpt-5-codex"
model_provider = "openai"
approval_policy = "on-request"
api_key = "sk-test-secret-value"

[mcp_servers.filesystem]
command = "npx"
env = { TOKEN = "mcp-secret-value" }
""",
    )
    _write(
        home / ".cursor/mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "project-docs": {
                        "command": "npx",
                        "env": {"TOKEN": "cursor-mcp-secret-value"},
                    }
                },
                "chatHistory": ["never collect this Cursor content"],
            }
        ),
    )
    _write(home / ".vscode/extensions/github.copilot-1.234.0/unused.txt", "do not read")
    _write(home / ".vscode/extensions/unrelated.publisher-9.9.9/secret.txt", "unrelated-secret")
    _write(
        home
        / ".config/google-chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/2.3.4/manifest.json",
        json.dumps(
            {
                "name": "Claude AI Assistant",
                "description": "AI assistant",
                "version": "2.3.4",
                "oauth_token": "browser-extension-secret",
            }
        ),
    )
    _write(home / ".config/google-chrome/Default/History", "browser-history-secret")
    _write(home / ".config/google-chrome/Default/Cookies", "browser-cookie-secret")
    _write(home / "Documents/private-notes.txt", "arbitrary-file-secret")

    cursor_app = applications / "Cursor.app"
    _write(
        cursor_app / "Contents/Info.plist",
        plistlib.dumps(
            {
                "CFBundleShortVersionString": "0.50.1",
                "UnapprovedSecret": "application-secret",
            }
        ),
    )
    _write(applications / "Windsurf.app/Contents/not-metadata.txt", "windsurf-secret")
    _write(executables / "claude", "#!/bin/sh\n")
    _write(executables / "codex", "#!/bin/sh\n")
    (executables / "claude").chmod(0o700)
    (executables / "codex").chmod(0o700)

    probe = _RecordingFilesystemProbe()
    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=home,
            application_roots=(applications,),
            executable_roots=(executables,),
        ),
        filesystem=probe,
    )

    assert report["schema_version"] == "hawk.endpoint_metadata.v1"
    assert report["status"] == "completed"
    assert report["collection_mode"] == "one_shot_read_only"
    assert report["network_used"] is False
    assert [item["id"] for item in report["products"]] == [
        "chatgpt_desktop", "claude_desktop", "ollama", "lm_studio",
        "claude_code",
        "codex_cli",
        "cursor",
        "windsurf",
        "copilot",
    ]
    assert _product(report, "claude_code")["presence"] == "present"
    assert _product(report, "codex_cli")["presence"] == "present"
    assert _product(report, "cursor")["version"] == "0.50.1"
    assert _product(report, "windsurf")["presence"] == "present"
    assert _product(report, "copilot")["presence"] == "present"
    assert all(item["approval_status"] == "unknown" for item in report["products"])
    assert all(
        item["account"] == {"status": "unknown", "identifiers_collected": False}
        for item in report["products"]
    )

    configs = {item["product_id"]: item for item in report["configurations"]}
    assert configs["claude_code"]["metadata"] == {
        "mcp_server_names": ["approved-docs"],
        "mcp_servers": [{"name": "approved-docs", "transport": "stdio", "executable": "npx"}],
        "model": "claude-sonnet",
    }
    assert configs["codex_cli"]["metadata"] == {
        "approval_policy": "on-request",
        "mcp_server_names": ["filesystem"],
        "mcp_servers": [{"name": "filesystem", "transport": "stdio", "executable": "npx"}],
        "model": "gpt-5-codex",
        "model_provider": "openai",
    }
    assert configs["cursor"]["metadata"] == {
        "mcp_server_names": ["project-docs"],
        "mcp_servers": [{"name": "project-docs", "transport": "stdio", "executable": "npx"}],
    }
    assert {
        (item["host"], item["id"], item["version"]) for item in report["extensions"]
    } == {
        ("vscode", "github.copilot", "1.234.0"),
        ("chrome", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "2.3.4"),
    }

    serialized = json.dumps(report, sort_keys=True)
    for forbidden in (
        "claude-secret-value",
        "sk-test-secret-value",
        "mcp-secret-value",
        "cursor-mcp-secret-value",
        "person@example.test",
        "never collect this prompt",
        "never collect this Cursor content",
        "browser-extension-secret",
        "browser-history-secret",
        "browser-cookie-secret",
        "arbitrary-file-secret",
        "application-secret",
        "windsurf-secret",
        str(home),
        "private-user@example.test",
    ):
        assert forbidden not in serialized

    read_paths = {str(path) for path in probe.read_paths}
    assert not any(path.endswith("/History") for path in read_paths)
    assert not any(path.endswith("/Cookies") for path in read_paths)
    assert not any("private-notes.txt" in path for path in read_paths)
    assert not any("unused.txt" in path for path in read_paths)
    assert not any("secret.txt" in path for path in read_paths)


def test_unverified_products_and_versions_are_unknown(tmp_path: Path) -> None:
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=tmp_path, application_roots=(), executable_roots=())
    )

    assert all(product["presence"] == "unknown" for product in report["products"])
    assert all(product["version"] == "unknown" for product in report["products"])
    assert report["extensions"] == []
    assert report["configurations"] == []


def test_non_executable_file_does_not_claim_cli_presence(tmp_path: Path) -> None:
    executables = tmp_path / "bin"
    _write(executables / "codex", "not actually an executable")

    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=tmp_path / "home",
            application_roots=(),
            executable_roots=(executables,),
        )
    )

    assert _product(report, "codex_cli")["presence"] == "unknown"


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable-mode contract")
def test_non_executable_exe_suffix_does_not_claim_cli_presence(
    tmp_path: Path,
) -> None:
    executables = tmp_path / "bin"
    _write(executables / "codex.exe", "not executable despite its suffix")
    (executables / "codex.exe").chmod(0o644)

    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=tmp_path / "home",
            application_roots=(),
            executable_roots=(executables,),
        )
    )

    assert _product(report, "codex_cli")["presence"] == "unknown"


def test_symlinked_metadata_and_executable_are_never_followed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outside = tmp_path / "outside"
    executables = tmp_path / "bin"
    _write(outside / "config.toml", 'api_key = "outside-secret"\nmodel = "gpt-5"\n')
    _write(outside / "codex", "outside-executable-secret")
    (home / ".codex").mkdir(parents=True)
    executables.mkdir(parents=True)
    os.symlink(outside / "config.toml", home / ".codex/config.toml")
    os.symlink(outside / "codex", executables / "codex")

    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=home,
            application_roots=(),
            executable_roots=(executables,),
        )
    )

    assert _product(report, "codex_cli")["presence"] == "unknown"
    assert {error["code"] for error in report["errors"]} == {"symlink_skipped"}
    serialized = json.dumps(report)
    assert "outside-secret" not in serialized
    assert str(outside) not in serialized


def test_intermediate_directory_swap_cannot_escape_allowlisted_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    outside = tmp_path / "outside"
    _write(home / ".codex/config.toml", 'model = "inside-model"\n')
    _write(outside / "config.toml", 'model = "outside-model"\n')
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        path_text = os.fspath(path)
        is_config_open = (
            (dir_fd is None and Path(path_text) == home / ".codex/config.toml")
            or (dir_fd is not None and path_text == "config.toml")
        )
        if is_config_open and not swapped:
            (home / ".codex").rename(home / ".codex-inside")
            os.symlink(outside, home / ".codex")
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner_module.os, "open", swapping_open)
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=())
    )

    assert swapped is True
    serialized = json.dumps(report, sort_keys=True)
    assert "outside-model" not in serialized
    assert str(outside) not in serialized


def test_home_root_ancestor_swap_cannot_redirect_collection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    anchor = tmp_path / "writable/anchor"
    home = anchor / "home"
    outside_anchor = tmp_path / "outside-anchor"
    _write(home / ".codex/config.toml", 'model = "inside-model"\n')
    _write(
        outside_anchor / "home/.codex/config.toml",
        'model = "outside-model"\n',
    )
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        path_text = os.fspath(path)
        is_home_root_open = (
            (dir_fd is None and Path(path_text) == home)
            or (dir_fd is not None and path_text == "home")
        )
        if is_home_root_open and not swapped:
            anchor.rename(anchor.parent / "anchor-inside")
            os.symlink(outside_anchor, anchor)
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner_module.os, "open", swapping_open)
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=())
    )

    assert swapped is True
    serialized = json.dumps(report, sort_keys=True)
    assert "outside-model" not in serialized
    assert str(outside_anchor) not in serialized


def test_executable_root_ancestor_swap_cannot_claim_outside_product(
    tmp_path: Path,
    monkeypatch,
) -> None:
    anchor = tmp_path / "writable/anchor"
    executable_root = anchor / "bin"
    outside_anchor = tmp_path / "outside-anchor"
    executable_root.mkdir(parents=True)
    _write(outside_anchor / "bin/codex", "#!/bin/sh\n")
    (outside_anchor / "bin/codex").chmod(0o700)
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        path_text = os.fspath(path)
        is_executable_root_open = (
            (dir_fd is None and Path(path_text) == executable_root)
            or (dir_fd is not None and path_text == "bin")
        )
        if is_executable_root_open and not swapped:
            anchor.rename(anchor.parent / "anchor-inside")
            os.symlink(outside_anchor, anchor)
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner_module.os, "open", swapping_open)
    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=tmp_path / "empty-home",
            application_roots=(),
            executable_roots=(executable_root,),
        )
    )

    assert swapped is True
    assert _product(report, "codex_cli")["presence"] == "unknown"


def test_relative_roots_fail_closed_without_collection(tmp_path: Path) -> None:
    relative_home = Path("relative-home")
    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=relative_home,
            application_roots=(),
            executable_roots=(),
        )
    )

    assert all(product["presence"] == "unknown" for product in report["products"])
    assert "invalid_root" in {error["code"] for error in report["errors"]}


@pytest.mark.parametrize(
    "root",
    (
        Path("/tmp/approved/../outside"),
        Path("//server/share"),
        Path("C:/Users/example"),
    ),
)
def test_ambiguous_or_drive_roots_fail_closed(root: Path) -> None:
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=root, application_roots=(), executable_roots=())
    )

    assert all(product["presence"] == "unknown" for product in report["products"])
    assert "invalid_root" in {error["code"] for error in report["errors"]}


def test_non_posix_root_traversal_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    # Override only the scanner dependency; pathlib/pytest retain the host OS.
    host_name = os.name
    simulated_os = SimpleNamespace(**vars(os))
    simulated_os.name = "nt"
    monkeypatch.setattr(scanner_module, "os", simulated_os)

    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=())
    )

    assert all(product["presence"] == "unknown" for product in report["products"])
    assert "unsupported_platform" in {
        error["code"] for error in report["errors"]
    }
    assert os.name == host_name


def test_directory_enumeration_survives_intermediate_directory_swap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    outside = tmp_path / "outside-vscode"
    _write(
        home / ".vscode/extensions/github.copilot-1.2.3/ignored.txt",
        "inside",
    )
    _write(
        outside / "extensions/github.copilot-9.9.9/ignored.txt",
        "outside",
    )
    real_scandir = os.scandir
    swapped = False

    def swapping_scandir(path):
        nonlocal swapped
        is_extension_scan = isinstance(path, int) or Path(path) == (
            home / ".vscode/extensions"
        )
        if is_extension_scan and not swapped:
            (home / ".vscode").rename(home / ".vscode-inside")
            os.symlink(outside, home / ".vscode")
            swapped = True
        return real_scandir(path)

    monkeypatch.setattr(scanner_module.os, "scandir", swapping_scandir)
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=())
    )

    assert swapped is True
    assert [
        extension["version"]
        for extension in report["extensions"]
        if extension["id"] == "github.copilot"
    ] == ["1.2.3"]


def test_oversize_secret_shaped_and_malformed_values_are_privacy_safe(tmp_path: Path) -> None:
    home = tmp_path / "home-with-private-path"
    _write(home / ".claude/settings.json", '{"model":"' + ("secret-" * 100) + '"}')
    _write(
        home / ".codex/config.toml",
        """
model = "sk-proj-super-secret-token-value"
[mcp_servers."ghp_super_secret_server_name"]
command = "never-output"
""",
    )
    _write(home / ".cursor/mcp.json", "{not valid json containing private-error-detail")

    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=()),
        limits=ScanLimits(max_file_bytes=128),
    )

    assert {error["code"] for error in report["errors"]} == {
        "malformed_metadata",
        "oversized_metadata",
    }
    codex = next(
        item for item in report["configurations"] if item["product_id"] == "codex_cli"
    )
    assert codex["metadata"] == {
        "mcp_server_names": ["redacted"],
        "model": "unknown",
    }
    serialized = json.dumps(report)
    assert "sk-proj-super-secret-token-value" not in serialized
    assert "ghp_super_secret_server_name" not in serialized
    assert "private-error-detail" not in serialized
    assert str(home) not in serialized


@pytest.mark.parametrize(
    "credential",
    (
        "AIzaSyA1234567890bcdefghijklmnopqrstuvw",
        "AKIA1234567890ABCDEF",
    ),
)
def test_google_and_aws_credential_shapes_are_never_emitted(
    tmp_path: Path,
    credential: str,
) -> None:
    home = tmp_path / "home"
    _write(
        home / ".codex/config.toml",
        f'''
model = "{credential}"
[mcp_servers."{credential}"]
command = "ignored"
''',
    )

    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=())
    )

    codex = next(
        item for item in report["configurations"] if item["product_id"] == "codex_cli"
    )
    assert codex["metadata"] == {
        "model": "unknown",
        "mcp_server_names": ["redacted"],
    }
    serialized = json.dumps(report, sort_keys=True)
    assert credential not in serialized
    assert all(credential not in json.dumps(error) for error in report["errors"])


def test_bounds_items_files_roots_and_time_without_leaking_paths(tmp_path: Path) -> None:
    home = tmp_path / "home"
    for index in range(8):
        _write(
            home / f".vscode/extensions/github.copilot-{index}.0.0/ignored.txt",
            f"secret-{index}",
        )

    ticks = iter((0.0, 0.0, 0.0, 5.0, 5.0, 5.0))
    report = collect_endpoint_metadata(
        roots=ScanRoots(
            home=home,
            application_roots=tuple(tmp_path / f"apps-{index}" for index in range(8)),
            executable_roots=(),
        ),
        limits=ScanLimits(
            max_roots=2,
            max_files=2,
            max_items=2,
            max_seconds=1.0,
        ),
        monotonic=lambda: next(ticks, 5.0),
    )

    assert len(report["products"]) == 9
    assert len(report["extensions"]) + len(report["configurations"]) <= 2
    assert {
        error["code"] for error in report["errors"]
    }.issuperset({"root_limit_reached", "time_limit_reached"})
    assert all(set(error) == {"source", "code"} for error in report["errors"])


def test_directory_enumeration_is_explicitly_bounded(tmp_path: Path) -> None:
    home = tmp_path / "home"
    for index in range(6):
        _write(
            home / f".vscode/extensions/github.copilot-{index}.0.0/ignored.txt",
            f"secret-{index}",
        )
    probe = _BoundRecordingFilesystemProbe()

    report = collect_endpoint_metadata(
        roots=ScanRoots(home=home, application_roots=(), executable_roots=()),
        limits=ScanLimits(max_directory_entries=3),
        filesystem=probe,
    )

    assert probe.requested_directory_limits
    assert all(limit == 3 for limit in probe.requested_directory_limits)
    assert "directory_entry_limit_reached" in {
        error["code"] for error in report["errors"]
    }
    assert len(report["extensions"]) <= 3


def test_collection_does_not_open_network_sockets(tmp_path: Path, monkeypatch) -> None:
    def _network_forbidden(*_args, **_kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "socket", _network_forbidden)
    report = collect_endpoint_metadata(
        roots=ScanRoots(home=tmp_path, application_roots=(), executable_roots=())
    )
    assert report["network_used"] is False


class _RecordingFilesystemProbe(LocalFilesystemProbe):
    def __init__(self) -> None:
        self.read_paths: list[Path] = []

    def read_limited(
        self,
        root: Path,
        relative: str | Path,
        max_bytes: int,
    ) -> bytes:
        self.read_paths.append(root / relative)
        return super().read_limited(root, relative, max_bytes)


class _BoundRecordingFilesystemProbe(LocalFilesystemProbe):
    def __init__(self) -> None:
        self.requested_directory_limits: list[int] = []

    def list_directory(
        self,
        root: Path,
        relative: str | Path,
        max_entries: int,
    ):
        self.requested_directory_limits.append(max_entries)
        return super().list_directory(root, relative, max_entries)
