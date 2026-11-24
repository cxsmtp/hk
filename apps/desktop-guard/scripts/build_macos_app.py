from __future__ import annotations

import argparse
from pathlib import Path
import plistlib
import shutil
import shlex
import subprocess
import sys


APP_NAME = "Hawk Desktop Guard"


def default_python_path() -> Path:
    system_python = Path("/usr/bin/python3")
    if system_python.exists():
        return system_python
    return Path(sys.executable)


def build_app_bundle(
    *,
    output_dir: Path,
    repo_root: Path,
    python_path: Path,
    config_path: Path,
    compile_enter_helper: bool = True,
    endpoint_config_path: Path | None = None,
) -> Path:
    app_path = output_dir / f"{APP_NAME}.app"
    contents = app_path / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    macos.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)

    info = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": "com.hawk.desktop-guard",
        "CFBundleVersion": "0.2.0",
        "CFBundleShortVersionString": "0.2.0",
        "CFBundleExecutable": "hawk-desktop-guard",
        "CFBundlePackageType": "APPL",
        "LSUIElement": True,
    }
    with (contents / "Info.plist").open("wb") as fh:
        plistlib.dump(info, fh)

    bundled_src = resources / "src"
    bundled_package = bundled_src / "hawk_desktop_guard"
    if bundled_package.exists():
        shutil.rmtree(bundled_package, ignore_errors=True)
    bundled_src.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        repo_root / "apps" / "desktop-guard" / "src" / "hawk_desktop_guard",
        bundled_package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "._*"),
    )
    native_source = repo_root / "apps" / "desktop-guard" / "native"
    bundled_native = resources / "native"
    if bundled_native.exists():
        shutil.rmtree(bundled_native, ignore_errors=True)
    shutil.copytree(
        native_source,
        bundled_native,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "._*"),
    )
    if compile_enter_helper:
        _compile_enter_helper(
            source=bundled_native / "macos" / "HawkEnterGuard.m",
            output=macos / "HawkEnterGuard",
        )
        _compile_governance_overlay(
            source=bundled_native / "macos" / "HawkGovernanceOverlay.m",
            output=macos / "HawkGovernanceOverlay",
        )

    endpoint_config_path = endpoint_config_path or (
        config_path.parent.parent / ".config" / "hawk" / "endpoint-agent.json"
        if str(config_path).startswith("/Users/")
        else Path.home() / ".config" / "hawk" / "endpoint-agent.json"
    )

    executable = macos / "hawk-desktop-guard"
    exec_line = (
        'APP_DIR="$(cd "$(dirname "$0")" && pwd)"',
        'if [ -x "$APP_DIR/HawkEnterGuard" ]; then',
        f'  "$APP_DIR/HawkEnterGuard" --config {shlex.quote(str(config_path))} '
        "--application 'Claude Desktop' --desktop-app Claude &",
        "fi",
        'if [ -x "$APP_DIR/HawkGovernanceOverlay" ]; then',
        f'  "$APP_DIR/HawkGovernanceOverlay" --endpoint-config {shlex.quote(str(endpoint_config_path))} '
        "--hawk-url 'http://localhost:3001' &",
        "fi",
        'PYTHONPATH="$APP_DIR/../Resources/src" '
        f"exec {shlex.quote(str(python_path))} -m hawk_desktop_guard "
        f"--config {shlex.quote(str(config_path))} --dialog",
    )
    executable_lines = ["#!/bin/sh", *exec_line, ""]
    executable.write_text(
        "\n".join(executable_lines),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return app_path


def _compile_enter_helper(*, source: Path, output: Path) -> None:
    clang = shutil.which("clang")
    if not clang or not source.exists():
        return
    subprocess.run(
        [
            clang,
            "-fobjc-arc",
            str(source),
            "-o",
            str(output),
            "-framework",
            "ApplicationServices",
            "-framework",
            "Cocoa",
        ],
        check=True,
    )
    output.chmod(0o755)


def _compile_governance_overlay(*, source: Path, output: Path) -> None:
    clang = shutil.which("clang")
    if not clang or not source.exists():
        return
    subprocess.run(
        [
            clang,
            "-fobjc-arc",
            str(source),
            "-o",
            str(output),
            "-framework",
            "ApplicationServices",
            "-framework",
            "Cocoa",
            "-framework",
            "Security",
        ],
        check=True,
    )
    output.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Hawk Desktop Guard macOS app bundle.")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[3]))
    parser.add_argument("--python-path", default=str(default_python_path()))
    parser.add_argument("--config", default=str(Path.home() / ".hawk" / "desktop-guard.json"))
    parser.add_argument("--endpoint-config", default=str(Path.home() / ".config" / "hawk" / "endpoint-agent.json"))
    parser.add_argument("--skip-enter-helper-compile", action="store_true")
    args = parser.parse_args()

    app_path = build_app_bundle(
        output_dir=Path(args.output_dir).expanduser().resolve(),
        repo_root=Path(args.repo_root).expanduser().resolve(),
        python_path=Path(args.python_path).expanduser(),
        config_path=Path(args.config).expanduser(),
        compile_enter_helper=not args.skip_enter_helper_compile,
        endpoint_config_path=Path(args.endpoint_config).expanduser(),
    )
    print(app_path)


if __name__ == "__main__":
    main()
