from __future__ import annotations

import argparse
from pathlib import Path
import shlex
import subprocess


LABEL = "com.hawk.desktop-guard"


def build_launch_agent_plist(*, app_path: Path, config_path: Path) -> str:
    executable = app_path / "Contents" / "MacOS" / "hawk-desktop-guard"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{_xml(str(executable))}</string>
    <string>--config</string>
    <string>{_xml(str(config_path))}</string>
    <string>--dialog</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{_xml(str(Path.home() / "Library" / "Logs" / "hawk-desktop-guard.log"))}</string>
  <key>StandardErrorPath</key>
  <string>{_xml(str(Path.home() / "Library" / "Logs" / "hawk-desktop-guard.err.log"))}</string>
</dict>
</plist>
"""


def install_launch_agent(*, app_path: Path, config_path: Path, launch_agents_dir: Path | None = None) -> Path:
    target_dir = launch_agents_dir or (Path.home() / "Library" / "LaunchAgents")
    target_dir.mkdir(parents=True, exist_ok=True)
    plist_path = target_dir / f"{LABEL}.plist"
    plist_path.write_text(build_launch_agent_plist(app_path=app_path, config_path=config_path), encoding="utf-8")
    return plist_path


def _xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install Hawk Desktop Guard LaunchAgent.")
    parser.add_argument("--app", default=str(Path.cwd() / "dist" / "Hawk Desktop Guard.app"))
    parser.add_argument("--config", default=str(Path.home() / ".hawk" / "desktop-guard.json"))
    parser.add_argument("--load", action="store_true")
    args = parser.parse_args()

    plist_path = install_launch_agent(app_path=Path(args.app).expanduser(), config_path=Path(args.config).expanduser())
    print(plist_path)
    if args.load:
        subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
        subprocess.run(["launchctl", "load", str(plist_path)], check=False)
        print(f"Loaded {shlex.quote(str(plist_path))}")


if __name__ == "__main__":
    main()
