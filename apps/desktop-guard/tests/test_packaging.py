from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_macos_app import build_app_bundle
from install_macos_launch_agent import build_launch_agent_plist
from build_macos_app import default_python_path


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_default_python_path_does_not_use_repo_venv() -> None:
    assert ".venv" not in str(default_python_path())


def test_build_macos_app_bundle_creates_clickable_structure(tmp_path) -> None:
    output_dir = tmp_path / "dist"
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    runner = venv_bin / "hawk-desktop-guard"
    runner.write_text("#!/bin/sh\n", encoding="utf-8")
    app_path = build_app_bundle(
        output_dir=output_dir,
        repo_root=REPO_ROOT,
        python_path=venv_bin / "python",
        config_path=Path("/Users/test/.hawk/desktop-guard.json"),
        compile_enter_helper=False,
    )

    assert app_path == output_dir / "Hawk Desktop Guard.app"
    assert (app_path / "Contents" / "Info.plist").exists()
    assert (app_path / "Contents" / "Resources" / "src" / "hawk_desktop_guard" / "__main__.py").exists()
    executable = app_path / "Contents" / "MacOS" / "hawk-desktop-guard"
    assert executable.exists()
    text = executable.read_text(encoding="utf-8")
    assert "PYTHONPATH=" in text
    assert "Resources/src" in text
    assert "-m hawk_desktop_guard" in text
    assert "HawkEnterGuard" in text
    assert "HawkGovernanceOverlay" in text
    assert "--endpoint-config" in text
    assert "/Users/test/.config/hawk/endpoint-agent.json" in text
    assert "--trusted-thumbprint" not in text
    assert "--dialog" in text
    assert "--config" in text
    assert "/Users/test/.hawk/desktop-guard.json" in text
    enter_path = app_path / "Contents" / "Resources" / "native" / "macos" / "HawkEnterGuard.m"
    assert enter_path.exists()
    assert "kAXTrustedCheckOptionPrompt: @NO" in enter_path.read_text(encoding="utf-8")
    overlay_source = app_path / "Contents" / "Resources" / "native" / "macos" / "HawkGovernanceOverlay.m"
    assert overlay_source.exists()
    source = overlay_source.read_text(encoding="utf-8")
    assert "Claude" in source
    assert "Codex" in source
    assert "AXUIElementCopyAttributeValue" in source
    assert "CGWindowListCopyWindowInfo" in source
    assert "SecKeyVerifySignature" in source
    assert "governance_status" in source
    assert "Disconnected" in source
    assert "Unknown" in source
    assert "method_exchangeImplementations" not in source
    assert "DYLD_INSERT_LIBRARIES" not in source


def test_build_macos_app_bundle_can_rebuild_existing_bundle(tmp_path) -> None:
    output_dir = tmp_path / "dist"

    first = build_app_bundle(
        output_dir=output_dir,
        repo_root=REPO_ROOT,
        python_path=Path("/usr/bin/python3"),
        config_path=Path("/Users/test/.hawk/desktop-guard.json"),
        compile_enter_helper=False,
    )
    second = build_app_bundle(
        output_dir=output_dir,
        repo_root=REPO_ROOT,
        python_path=Path("/usr/bin/python3"),
        config_path=Path("/Users/test/.hawk/desktop-guard.json"),
        compile_enter_helper=False,
    )

    assert second == first
    assert (second / "Contents" / "Resources" / "src" / "hawk_desktop_guard" / "__main__.py").exists()


def test_launch_agent_plist_points_to_app_executable() -> None:
    plist = build_launch_agent_plist(
        app_path=Path("/Applications/Hawk Desktop Guard.app"),
        config_path=Path("/Users/test/.hawk/desktop-guard.json"),
    )

    assert "<key>Label</key>" in plist
    assert "com.hawk.desktop-guard" in plist
    assert "/Applications/Hawk Desktop Guard.app/Contents/MacOS/hawk-desktop-guard" in plist
    assert "/Users/test/.hawk/desktop-guard.json" in plist
