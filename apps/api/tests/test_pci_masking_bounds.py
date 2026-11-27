"""Card-number masking (app/services/pci_controls.py): it stays fast on hostile input, leaves phone numbers and decimals
as they are, and also covers values written inline in an UPDATE / INSERT (``update(Model).values(...)``), which never
pass through a flush. Checkmarx PR 12 triage."""

from __future__ import annotations

import time

import pytest
from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.orm import sessionmaker

from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services import pci_controls
from app.services.pci_controls import find_pans, scrub_pan

VISA = "4111111111111111"


@pytest.mark.parametrize(
    "text",
    [
        " ".join("1" for _ in range(20_000)),  # every digit on its own: was cubic (8 KB took minutes)
        " ".join("12" for _ in range(20_000)),
        "-".join("123" for _ in range(20_000)),
        " ".join(f"{VISA} 123e4567-e89b-12d3-a456-426614174000" for _ in range(20_000)),  # many numbers among many ids
    ],
    ids=["single-digits", "two-digit-groups", "dashed-groups", "pans-among-ids"],
)
def test_masking_stays_linear_on_hostile_input(text: str) -> None:
    started = time.perf_counter()
    scrub_pan(text)
    assert time.perf_counter() - started < 5.0


def test_a_long_run_of_short_groups_still_finds_the_card_inside() -> None:
    text = "1 2 3 4 5 6 7 8 9 " * 50 + "x 4111 1111 1111 1111 y " + "9 8 7 " * 50
    assert scrub_pan(text).count("[card ending 1111]") == 1
    # Every digit spaced is how some people type it: still a card number.
    assert scrub_pan(" ".join(VISA)) == "[card ending 1111]"


@pytest.mark.parametrize(
    "text",
    [
        "Call +86 139 1067 6024 today",  # E.164 phone numbers: about one in ten passed the Luhn check
        '{"phone": "+8619148859324"}',
        "(+86 191 4885 9324)",
        "score=0.5044215558096435",  # how Python writes a float
        "latency 12.4012888888881881 ms",
    ],
)
def test_phone_numbers_and_decimals_are_left_as_they_are(text: str) -> None:
    assert scrub_pan(text) == text


@pytest.mark.parametrize(
    "text, masked",
    [
        (f"note=hello+{VISA}", "note=hello+[card ending 1111]"),  # a URL-encoded space before the number
        ("+4111 1111 1111 1111", "+[card ending 1111]"),  # 16 digits after + is no phone number
        (f"card.{VISA}", "card.[card ending 1111]"),  # a full stop after a word is no decimal point
        (f"0. {VISA}", "0. [card ending 1111]"),
    ],
)
def test_card_numbers_next_to_plus_or_a_point_are_still_masked(text: str, masked: str) -> None:
    assert scrub_pan(text) == masked


def test_find_pans_results_are_unchanged_for_ordinary_text() -> None:
    text = f"cards {VISA}, 5555-5555-5555-4444 and 3782 822463 10005; id 123e4567-e89b-12d3-a456-426614174000"
    assert [digits for _, _, digits in find_pans(text)] == [VISA, "5555555555554444", "378282246310005"]


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'pci.sqlite3'}")
    Base.metadata.create_all(bind=engine, tables=[Tenant.__table__])
    factory = sessionmaker(bind=engine)
    try:
        with factory() as db:
            yield db
    finally:
        engine.dispose()


def test_inline_update_and_insert_values_are_masked(session) -> None:
    assert pci_controls.persistence_guard_installed()
    session.add(Tenant(name="Acme", slug="acme"))
    session.commit()
    # A conditional update writes its values inline (e.g. the reason an approval was revoked): no flush sees them.
    result = session.execute(
        update(Tenant).where(Tenant.slug == "acme").values(name=f"Revoked: card {VISA}").execution_options(synchronize_session=False)
    )
    assert result.rowcount == 1
    session.execute(insert(Tenant).values(name=f"card {VISA}", slug="beta", is_active=True))
    session.commit()
    names = session.scalars(select(Tenant.name).order_by(Tenant.slug)).all()
    assert names == ["Revoked: card [card ending 1111]", "card [card ending 1111]"]
    # Values that need no masking, and SQL expressions, are written as they were.
    session.execute(update(Tenant).where(Tenant.slug == "acme").values(name=Tenant.slug + "-renamed"))
    session.commit()
    assert session.scalar(select(Tenant.name).where(Tenant.slug == "acme")) == "acme-renamed"


def test_identifiers_with_digit_runs_are_never_masked():
    """An endpoint id like ep_36d477d8344175220107336d75fb holds a Luhn-valid digit run; masking it broke lookups
    (a duplicate insert and a fail-closed gateway answer about once in a thousand ids)."""

    import hashlib
    import os

    from app.services.pci_controls import scrub_pan

    assert scrub_pan("ep_36d477d8344175220107336d75fb") == "ep_36d477d8344175220107336d75fb"
    for _ in range(20000):
        value = "ep_" + hashlib.sha256(os.urandom(8)).hexdigest()[:28]
        assert scrub_pan(value) == value
    assert scrub_pan("pan:4111111111111111") == "pan:[card ending 1111]"
    assert scrub_pan('{"pan":"4111-1111-1111-1111"}') == '{"pan":"[card ending 1111]"}'
