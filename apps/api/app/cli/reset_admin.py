"""Lost the administrator's password (or the first-start one scrolled out of the log)? Set a new temporary one,
printed here once. The server may be running: it picks the change up at once. The administrator chooses their own
password at the next sign-in. Two-step sign-in, when it is on, is taken off too, and a lock after wrong passwords is
cleared. Recorded in the audit log. Ported from CxMissionZero's scripts/reset-admin.mjs.

    python -m app.cli.reset_admin [email]
    docker compose exec api python -m app.cli.reset_admin [email]

Without an email: the first active owner or admin (created if there is none).
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.services import first_run_service


def main(argv: list[str] | None = None, *, session_factory: Callable[[], Session] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    wanted = args[0].strip() if args else ""
    if session_factory is None:
        from app.db.session import SessionLocal

        session_factory = SessionLocal
    with session_factory() as db:
        try:
            result = first_run_service.reset_admin(db, wanted or None)
        except LookupError as error:
            print(str(error), file=sys.stderr)
            return 1
        except first_run_service.AccessError as error:
            print(f"! {error}", file=sys.stderr)
            return 1
        except HTTPException as error:  # the activation codes' caps (app/services/activation_service.py)
            print(f"! {error.detail}", file=sys.stderr)
            return 1
        db.commit()
    print("")
    print(f"  {'Administrator created' if result.created else 'Password reset'} — sign in with:")
    print(f"      Email:    {result.email}")
    print(f"      Password: {result.password}")
    print("  They choose their own password at sign-in (also anyone already signed in as them, at their next click).")
    if result.two_step_reset:
        print("  Their two-step sign-in was taken off: they set it up again after signing in.")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
