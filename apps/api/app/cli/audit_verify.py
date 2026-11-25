"""Check every audit chain on the server (app/services/audit_chain.py): each tenant's and the system's.

    docker compose -f deploy/compose.yaml exec api python -m app.cli.audit_verify

Exits 0 when every chain is intact, 1 when an entry was edited, removed or reordered (each one named), 2 when the
check could not run.
"""

from __future__ import annotations

import sys

from app.db.session import SessionLocal
from app.services import audit_chain


def main() -> int:
    try:
        with SessionLocal() as db:
            chains = audit_chain.chains(db)
            if not chains:
                print("No audit entries are chained yet.")
                return 0
            broken = 0
            for chain in chains:
                result = audit_chain.verify(db, chain)
                state = "intact" if result["ok"] else f"{len(result['problems'])} problem(s)"
                older = f", {result['unchained']} written before the chain began" if result["unchained"] else ""
                print(f"{chain}: {result['entries']} entries, {state}{older}")
                for problem in result["problems"]:
                    print(f"  entry {problem['seq']}: {problem['problem']}")
                broken += 0 if result["ok"] else 1
            return 1 if broken else 0
    except audit_chain.AuditKeyError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
