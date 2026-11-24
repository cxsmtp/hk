"""Bridge entrypoint.

Run as the native-messaging host (invoked by the browser), or emit a host manifest
for installation:

  python -m hawk_endpoint_agent.bridge                       # run the host (stdio)
  python -m hawk_endpoint_agent.bridge --emit-manifest chrome \
      --host-path /usr/local/bin/hawk-bridge --extension-id <id>
"""

from __future__ import annotations

import argparse
import json
import sys

from ..config import load_config
from .host import run_host
from .manifest import chrome_manifest, firefox_manifest, install_location


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hawk-endpoint-agent-bridge")
    parser.add_argument("--emit-manifest", choices=["chrome", "firefox"], help="Print a native-messaging manifest and exit")
    parser.add_argument("--host-path", help="Absolute path to the bridge executable (for the manifest)")
    parser.add_argument("--extension-id", action="append", default=[], help="Allowed extension id (repeatable)")
    parser.add_argument("--install-location", help="Print the manifest install dir for BROWSER on this OS")
    args = parser.parse_args(argv)

    if args.install_location:
        import platform

        loc = install_location(platform.system().lower(), args.install_location)
        print(loc or "unknown")
        return 0

    if args.emit_manifest:
        host_path = args.host_path or sys.argv[0]
        manifest = (
            chrome_manifest(host_path, args.extension_id)
            if args.emit_manifest == "chrome"
            else firefox_manifest(host_path, args.extension_id)
        )
        print(json.dumps(manifest, indent=2))
        return 0

    return run_host(load_config())


if __name__ == "__main__":
    raise SystemExit(main())
