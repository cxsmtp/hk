"""Container health check: is the API answering and ready? Ported from CxMissionZero's scripts/healthcheck.mjs (which
asks /api/health on 127.0.0.1 with a 4-second timeout). Kept free of the application's imports so it is quick.

    python -m app.cli.healthcheck            # exit 0 when /health/ready answers 200
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    port = int(os.environ.get("HAWK_API_PORT") or 8000)
    path = sys.argv[1] if len(sys.argv) > 1 else "/health/ready"
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=4) as response:  # noqa: S310  # nosec B310 - fixed loopback http URL
            return 0 if response.status == 200 else 1
    except (urllib.error.URLError, OSError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
