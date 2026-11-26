"""The API for the console's browser tests (apps/web/e2e): a fresh SQLite database every run, the schema made from the
models (as the API's own unit tests do), then uvicorn, in the first-run mode deploy/compose.yaml uses.

FIRST_RUN_ACCESS with ADMIN_EMAIL + ADMIN_PASSWORD (set by playwright.config.ts) makes the first administrator with a
known temporary password, so the tests sign in as them deterministically and go through the forced password change
and the terms of use, as a new installation does. ACCEPT_TERMS is left unset on purpose.

    python apps/web/e2e/harness/api_server.py --port 18000 --state-dir <empty or missing folder>
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
API = ROOT / "apps" / "api"
MARKER = ".hawk-e2e-state"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()

    state = args.state_dir.resolve()
    # Never a database left from an earlier run: the tests start from an empty installation. Only a folder this script
    # made (it holds the marker) or an empty one is cleared, never anything else a mistyped E2E_STATE_DIR names.
    if state.exists():
        if not (state / MARKER).is_file() and any(state.iterdir()):
            raise SystemExit(f"{state} is not empty and was not made by this script: choose another E2E_STATE_DIR.")
        shutil.rmtree(state)
    (state / "data").mkdir(parents=True, mode=0o700)
    (state / "artifacts").mkdir(mode=0o700)
    (state / MARKER).write_text("Throwaway state of the console's browser tests (apps/web/e2e); cleared at every run.\n")

    os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{state / 'hawk-e2e.sqlite3'}")
    os.environ.setdefault("HAWK_DATA_DIR", str(state / "data"))
    os.environ.setdefault("ARTIFACT_DIR", str(state / "artifacts"))
    os.environ.setdefault("SIMULATION_EVIDENCE_DIR", str(state / "simulation-evidence"))
    os.chdir(API)
    sys.path[:0] = [str(API), str(ROOT)]

    import uvicorn

    import app.main  # noqa: F401 - registers every model on Base.metadata
    from app.db.session import Base, engine

    Base.metadata.create_all(bind=engine)
    # The front proxy's headers (X-Forwarded-Proto, -Prefix) are trusted from the test proxy on this machine only.
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=args.port,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        access_log=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
