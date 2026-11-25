from __future__ import annotations

import pytest

from app.core.test_settings import apply_test_settings


apply_test_settings()


@pytest.fixture(autouse=True)
def _licence_out_of_the_way(request, monkeypatch):
    """Keep the product licence and the tenant caps (docs/activation-codes.md) out of tests about other things.

    Without this, every test would start failing after 31 January 2027, when the built-in product date passes, and
    tests that register several owners (each with a tenant of their own) would be refused for want of a tenants
    activation code. Tests marked ``real_licence`` (tests/test_activation_licence.py) exercise the real dates,
    caps and gate with an injected clock instead.
    """

    if request.node.get_closest_marker("real_licence"):
        return
    from app.services import activation_service

    monkeypatch.setattr(activation_service, "PRODUCT_DEADLINE", "9999-12-31T00:00:00.000Z")
    monkeypatch.setattr(activation_service, "licence_active", lambda now=None: True)
    monkeypatch.setattr(activation_service, "assert_may_add_tenant", lambda db: None)
    monkeypatch.setattr(activation_service, "assert_may_add_member", lambda db, tenant_id: None)


@pytest.fixture(autouse=True)
def _terms_out_of_the_way(request, monkeypatch):
    """Keep the terms-of-use gate (TERMS.md, app/core/access_gate.py) out of tests about other things.

    Without this, every signed-in route would answer 403 terms_required until an owner accepted the terms. Tests marked
    ``terms_gate`` (tests/test_first_run_access.py) exercise the real gate.
    """

    if request.node.get_closest_marker("terms_gate"):
        return
    from app.services import terms_service

    monkeypatch.setattr(terms_service, "gate_open_for", lambda db, user: True)
    monkeypatch.setattr(terms_service, "organisation_accepted", lambda db=None: True)
