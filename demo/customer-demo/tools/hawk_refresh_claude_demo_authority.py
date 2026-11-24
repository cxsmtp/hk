#!/usr/bin/env python3
import json
import sys

from refresh_demo_authority import RequestFailure, install


if __name__ == "__main__":
    try:
        print(json.dumps(install("claude"), sort_keys=True))
    except RequestFailure as exc:
        print(json.dumps({"status": "failed", "http_status": exc.status, "detail": exc.body}), file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"Authority refresh stopped safely: {exc}", file=sys.stderr)
        raise SystemExit(1)
