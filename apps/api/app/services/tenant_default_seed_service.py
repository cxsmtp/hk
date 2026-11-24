from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.services.control_graph_service import ensure_canonical_controls
from app.services.guardian_contract_v2_service import seed_default_v2_contracts


def _persist_in_isolated_route_transaction(
    request_db: Session,
    *,
    seed: Callable[[Session], object],
) -> None:
    """Persist idempotent defaults without committing unrelated route work."""

    if request_db.new or request_db.dirty or request_db.deleted:
        raise RuntimeError("Tenant default seeding must run before route mutations")
    # Authentication may have opened a read snapshot. Close that snapshot
    # without committing it, then own the seed write in a separate session.
    request_db.rollback()
    with Session(bind=request_db.get_bind(), autoflush=False, expire_on_commit=False) as seed_db:
        seed(seed_db)
        seed_db.commit()
    request_db.expire_all()


def persist_tenant_guardian_defaults(request_db: Session, *, tenant_id: str) -> None:
    _persist_in_isolated_route_transaction(
        request_db,
        seed=lambda seed_db: seed_default_v2_contracts(seed_db, tenant_id=tenant_id),
    )


def persist_tenant_canonical_controls(request_db: Session, *, tenant_id: str) -> None:
    _persist_in_isolated_route_transaction(
        request_db,
        seed=lambda seed_db: ensure_canonical_controls(seed_db, tenant_id=tenant_id),
    )
