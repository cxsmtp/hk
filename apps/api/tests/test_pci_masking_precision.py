"""How precise card-number masking is (app/services/pci_controls.py ``find_pans`` / ``scrub_pan``), on generated corpora.

Recall: card numbers of every network (Visa, Mastercard, Amex, Discover, Diners, JCB, UnionPay, RuPay, Maestro), in
every layout a card is printed or typed in, plain and labelled, must all be masked. False positives: IBANs of the
countries Hawk AI's customers bank in (AE, SA, GB, DE, FR) written with spaces, pairs of dates, ISO timestamps, 19-digit
ids, millisecond timestamps, YYYYmmddHHMMSS, international phone numbers (+971, +91, +44, +1) and order / invoice /
reference numbers with their label must each be masked less than 0.5% of the time.

The corpora are made from a fixed seed, so a run is repeatable; ``rates()`` gives the numbers for a report.
"""

from __future__ import annotations

import datetime as dt
import json
import random
import string
import time
from collections.abc import Callable, Iterator

import pytest

from app.services import pci_controls
from app.services.pci_controls import CARD_NETWORKS, find_pans, scrub_pan, scrub_pan_value

SEED = 20261127
N = 2000
#: The highest false-positive rate allowed in any corpus.
MAX_FALSE_POSITIVES = 0.005
SEPARATORS = (" ", "-", " ", " ")


# ---- Card numbers --------------------------------------------------------------------------------------------------


def luhn_complete(prefix: str) -> str:
    for check in "0123456789":
        if pci_controls.luhn_valid(prefix + check):
            return prefix + check
    raise AssertionError(prefix)


def card(rng: random.Random, network: str, length: int) -> str:
    """A Luhn-valid number of ``network`` and ``length``, its prefix drawn from the network's ranges."""

    ranges = next(r for name, r, _ in CARD_NETWORKS if name == network)
    while True:
        low, high = rng.choice(ranges)
        prefix = str(rng.randint(low, high))
        body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
        number = luhn_complete(body)
        # The network a number is read as may be an earlier one with the same prefix (RuPay 65 is Discover's): any
        # network will do, as long as it is one.
        if pci_controls.card_network(number) and len(set(number)) > 1:
            return number


def layouts(number: str) -> Iterator[tuple[str, bool]]:
    """Every way ``number`` is written in a card layout: (text, needs a card label)."""

    n = len(number)
    yield number, n > pci_controls.UNLABELLED_CONTIGUOUS_MAX
    for layout in pci_controls.CARD_LAYOUTS:
        if sum(layout) != n:
            continue
        parts, at = [], 0
        for size in layout:
            parts.append(number[at : at + size])
            at += size
        for sep in SEPARATORS:
            yield sep.join(parts), False
    yield " ".join(number), False


#: (network, lengths) to cover: every length each network issues that a card layout or a run can carry.
NETWORK_LENGTHS = {
    "visa": (13, 16, 19),
    "mastercard": (16,),
    "amex": (15,),
    "discover": (16, 19),
    "diners": (14, 16),
    "jcb": (16, 19),
    "unionpay": (16, 19),
    "rupay": (16,),
    "maestro": (13, 15, 16, 19),
}
#: The networks' published test numbers.
PUBLISHED = (
    "4111111111111111", "4012888888881881", "4222222222222", "5555555555554444", "5105105105105100", "2223003122003222",
    "378282246310005", "371449635398431", "6011111111111117", "6011000990139424", "3056930009020004", "36227206271667",
    "3566002020360505", "3530111333300000", "6200000000000005", "6759649826438453", luhn_complete("608032100000000"),
    luhn_complete("652150000000000"), luhn_complete("817200000000000"), luhn_complete("508500000000000"),
)
CONTEXTS = ("{}", "Customer paid with {} yesterday.", "refund {}, thanks", '{{"note": "{}"}}', "line1\n{}\nline3")
LABELS = ("card: {}", "Card number {}", "PAN {}", "CC# {}", "Visa {}", '{{"card_number": "{}"}}', "debit card {}", "Mastercard: {}")


def well_formed_pans() -> list[tuple[str, str]]:
    """(text, digits): every network, every length, every layout, in a few sentences; labelled where it must be."""

    rng = random.Random(SEED)
    numbers = list(PUBLISHED)
    for network, lengths in NETWORK_LENGTHS.items():
        for length in lengths:
            numbers.extend(card(rng, network, length) for _ in range(6))
    out = []
    for number in numbers:
        for written, needs_label in layouts(number):
            if needs_label:
                out.append((rng.choice(LABELS).format(written), number))
                continue
            out.append((rng.choice(CONTEXTS).format(written), number))
    return out


def labelled_pans() -> list[tuple[str, str]]:
    rng = random.Random(SEED + 1)
    out = []
    for network, lengths in NETWORK_LENGTHS.items():
        for length in lengths:
            for _ in range(20):
                number = card(rng, network, length)
                written, _ = rng.choice(list(layouts(number)))
                out.append((rng.choice(LABELS).format(written), number))
    return out


def _masked(text: str, digits: str) -> bool:
    out = scrub_pan(text)
    return digits not in out.replace(" ", "").replace("-", "").replace(" ", "").replace(" ", "") and f"[card ending {digits[-4:]}]" in out


# ---- What is not a card number -------------------------------------------------------------------------------------

IBAN_FORMATS = {
    # country: (length, BBAN made from these: d digit, a letter)
    "AE": "ddd" + "d" * 16,
    "SA": "dd" + "d" * 18,
    "GB": "aaaa" + "dddddd" + "dddddddd",
    "DE": "d" * 8 + "d" * 10,
    "FR": "d" * 5 + "d" * 5 + "d" * 11 + "dd",
}


def iban(rng: random.Random, country: str) -> str:
    bban = "".join(rng.choice(string.digits) if c == "d" else rng.choice(string.ascii_uppercase) for c in IBAN_FORMATS[country])
    numeric = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    check = 98 - int(numeric) % 97
    return f"{country}{check:02d}{bban}"


def spaced4(value: str) -> str:
    return " ".join(value[i : i + 4] for i in range(0, len(value), 4))


def iban_corpus(rng: random.Random) -> Iterator[str]:
    from app.services.detection.structured import iban_valid

    for i in range(N):
        value = iban(rng, list(IBAN_FORMATS)[i % len(IBAN_FORMATS)])
        assert iban_valid(value)
        written = spaced4(value) if i % 4 else value
        yield rng.choice(("{}", "IBAN: {}", "Please transfer to {} today.", "Beneficiary {} (Emirates NBD)", "{}\n"))\
            .format(written)


def _date(rng: random.Random) -> dt.datetime:
    return dt.datetime(1990, 1, 1) + dt.timedelta(seconds=rng.randint(0, 110 * 365 * 86400))


def date_pair_corpus(rng: random.Random) -> Iterator[str]:
    formats = ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%d.%m.%Y", "%Y%m%d", "%m/%d/%Y")
    for _ in range(N):
        fmt = rng.choice(formats)
        yield rng.choice(("{} {}", "from {} to {}", "{} - {}", "{}  {}")).format(_date(rng).strftime(fmt), _date(rng).strftime(fmt))


def iso_corpus(rng: random.Random) -> Iterator[str]:
    for _ in range(N):
        moment = _date(rng).replace(microsecond=rng.randint(0, 999_999))
        written = rng.choice(
            (
                moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                moment.isoformat(timespec="milliseconds") + "Z",
                moment.isoformat(timespec="microseconds"),
                moment.strftime("%Y-%m-%dT%H:%M:%S") + rng.choice(("+04:00", "+05:30", "-0500")),
                moment.strftime("%Y-%m-%d %H:%M:%S.%f"),
            )
        )
        yield rng.choice(("{}", "at {} the job ran", '{{"created_at": "{}"}}', "{} {}")).format(written, written)


def id19_corpus(rng: random.Random) -> Iterator[str | dict]:
    for i in range(N):
        value = rng.randint(10**18, 10**19 - 1)
        if i % 5 == 0:
            yield {"value": value}
            continue
        yield rng.choice(("{}", "message {} was sent", "/api/items/{}", "snowflake={}", '{{"result": {}}}')).format(value)


def ms_corpus(rng: random.Random) -> Iterator[str | dict]:
    low, high = 946_684_800_000, 4_102_444_800_000  # 2000 to 2100
    for i in range(N):
        value = rng.randint(low, high)
        if i % 5 == 0:
            yield {"timestamp": value}
            continue
        yield rng.choice(("{}", "ts={}", "updated {} ms", '{{"t": {}}}', "{} {}")).format(value, rng.randint(low, high))


def compact_datetime_corpus(rng: random.Random) -> Iterator[str | dict]:
    for i in range(N):
        moment = _date(rng)
        value = moment.strftime("%Y%m%d%H%M%S") + (f"{rng.randint(0, 999):03d}" if i % 3 == 0 else "")
        if i % 5 == 0:
            yield {"build": int(value)}
            continue
        yield rng.choice(("{}", "build {}", "backup-{}.tar", "snapshot {} done", "{} {}")).format(value, moment.strftime("%Y%m%d%H%M%S"))


def phone_corpus(rng: random.Random) -> Iterator[str]:
    d = lambda n: "".join(rng.choice(string.digits) for _ in range(n))  # noqa: E731
    makers: tuple[Callable[[], str], ...] = (
        lambda: f"+971 5{rng.choice('024568')} {d(3)} {d(4)}",
        lambda: f"+9715{rng.choice('024568')}{d(7)}",
        lambda: f"+971 {rng.choice('234679')} {d(3)} {d(4)}",
        lambda: f"00971 5{rng.choice('024568')} {d(3)} {d(4)}",
        lambda: f"+91 {rng.choice('6789')}{d(4)} {d(5)}",
        lambda: f"+91-{rng.choice('6789')}{d(4)}-{d(5)}",
        lambda: f"+91 {d(2)} {d(4)} {d(4)}",
        lambda: f"+44 7{d(3)} {d(6)}",
        lambda: f"+44 20 {d(4)} {d(4)}",
        lambda: f"+447{d(9)}",
        lambda: f"+1 ({rng.randint(201, 989)}) {rng.randint(200, 999)}-{d(4)}",
        lambda: f"+1-{rng.randint(201, 989)}-{rng.randint(200, 999)}-{d(4)}",
        lambda: f"+1 {rng.randint(201, 989)} {rng.randint(200, 999)} {d(4)}",
    )
    for _ in range(N):
        first, second = rng.choice(makers)(), rng.choice(makers)()
        yield rng.choice(("{}", "Tel: {}", "call me on {} or {}", "Mobile: {} / {}", '{{"phone": "{}"}}')).format(first, second)


ORDER_LABELS = (
    "Order #{}", "Order No. {}", "Order number: {}", "Invoice No: {}", "Invoice #{}", "INV-{}", "Ref: {}", "Reference No. {}",
    "ref={}", "Account No: {}", "Acct #{}", "Txn ID: {}", "order_id={}", '{{"order_id": "{}"}}', '{{"invoiceNumber": {}}}',
    "Tracking #{}", "Booking ref: {}", "Ticket #{}", "Phone: {}", "Tel: {}", "ID: {}", "Transaction ref {}", "invoice_no: {}",
)


def order_corpus(rng: random.Random) -> Iterator[str | dict]:
    for i in range(N):
        digits = "".join(rng.choice(string.digits) for _ in range(rng.randint(13, 19)))
        digits = rng.choice("123456789") + digits[1:]
        if i % 7 == 0:
            yield {rng.choice(("order_id", "invoice_number", "ref", "account_no", "txnId")): int(digits)}
            continue
        if i % 3 == 0 and len(digits) >= 16:
            digits = spaced4(digits[:16])
        label = rng.choice(ORDER_LABELS)
        if label.startswith('{"invoiceNumber"'):
            digits = digits.replace(" ", "")
        yield label.format(digits)


FALSE_POSITIVE_CORPORA: dict[str, Callable[[random.Random], Iterator[str | dict]]] = {
    "iban_with_spaces": iban_corpus,
    "date_pairs": date_pair_corpus,
    "iso_timestamps": iso_corpus,
    "ids_19_digits": id19_corpus,
    "ms_timestamps": ms_corpus,
    "yyyymmddhhmmss": compact_datetime_corpus,
    "phone_numbers": phone_corpus,
    "labelled_order_numbers": order_corpus,
}


def _changed(sample: str | dict) -> bool:
    if isinstance(sample, dict):
        return scrub_pan_value(sample) is not sample
    return scrub_pan(sample) != sample


def rates() -> dict[str, float]:
    """The false-positive rate of each corpus and the recall on card numbers (for a report)."""

    out = {}
    for name, corpus in FALSE_POSITIVE_CORPORA.items():
        samples = list(corpus(random.Random(f"{SEED}:{name}")))
        out[name] = sum(_changed(s) for s in samples) / len(samples)
    for name, pans in (("recall_well_formed", well_formed_pans()), ("recall_labelled", labelled_pans())):
        out[name] = sum(_masked(text, digits) for text, digits in pans) / len(pans)
    return out


# ---- The tests -----------------------------------------------------------------------------------------------------


def test_every_well_formed_card_number_of_every_network_is_masked() -> None:
    pans = well_formed_pans()
    assert len(pans) > 800
    missed = [text for text, digits in pans if not _masked(text, digits)]
    assert missed == [], missed[:10]


def test_every_labelled_card_number_is_masked_in_any_layout() -> None:
    pans = labelled_pans()
    missed = [text for text, digits in pans if not _masked(text, digits)]
    assert missed == [], missed[:10]
    # Labelled, a card number is one in any grouping a person types, and 17 to 19 digits written together.
    number = card(random.Random(SEED), "visa", 19)
    assert scrub_pan(f"card {number}") == f"card [card ending {number[-4:]}]"
    assert scrub_pan(f"PAN: {number[:4]} {number[4:10]} {number[10:16]} {number[16:]}") == f"PAN: [card ending {number[-4:]}]"
    assert scrub_pan_value({"pan": int(number)}) == {"pan": f"[card ending {number[-4:]}]"}
    assert scrub_pan_value({"card_number": 4111111111111111}) == {"card_number": "[card ending 1111]"}


def test_json_numbers_follow_the_same_rules() -> None:
    # A real card number as a JSON number is masked, as before; a 19-digit id or one under an order key is not.
    assert scrub_pan_value({"amount": 4111111111111111}) == {"amount": "[card ending 1111]"}
    assert scrub_pan_value(4111111111111111) == "[card ending 1111]"
    order = {"order_id": 4111111111111111}
    assert scrub_pan_value(order) is order
    snowflake = {"id": 4111111111111111110}
    assert scrub_pan_value(snowflake) is snowflake


def test_detection_reports_every_card_number_that_is_masked_at_rest() -> None:
    """DLP detection (app/services/detection/structured.py) keeps a wider net than at-rest masking: it decides what
    may reach an AI provider, where a missed card number is a disclosure and a false alarm is a finding someone looks
    at, while masking at rest changes stored data for good. Wider means a superset: every card number masked at rest
    is also reported by detection."""

    from app.services.detection.dlp_engine import scan

    missed = [text for text, _ in well_formed_pans() + labelled_pans() if not any(f.entity_type == "credit_card" for f in scan(text).reportable())]
    assert missed == [], missed[:10]


@pytest.mark.parametrize("name", list(FALSE_POSITIVE_CORPORA))
def test_false_positives_stay_under_half_a_percent(name: str) -> None:
    samples = list(FALSE_POSITIVE_CORPORA[name](random.Random(f"{SEED}:{name}")))
    assert len(samples) == N
    wrong = [s for s in samples if _changed(s)]
    assert len(wrong) / len(samples) < MAX_FALSE_POSITIVES, (name, len(wrong), [scrub_pan(s) if isinstance(s, str) else s for s in wrong[:5]])


@pytest.mark.parametrize(
    "text",
    [
        "AE07 0331 2345 6789 0123 456",
        "IBAN GB82 WEST 1234 5698 7654 32",
        "GB82WEST12345698765432",
        "DE89 3704 0044 0532 0130 00",
        "2024-01-15 2024-02-20",
        "2024-11-15T09:30:45.123Z",
        "20241115093045",
        "Order #4111111111111111",
        "Invoice No: 5555 5555 5555 4444",
        '{"order_id": "378282246310005"}',
        "Tel: 4111111111111111",
        "ref=6011111111111117",
        "4111111111111111110",  # 19 digits together, no card label: an id
    ],
)
def test_what_is_not_a_card_number_is_left_as_it_is(text: str) -> None:
    assert scrub_pan(text) == text


@pytest.mark.parametrize(
    "text, masked",
    [
        # A card label wins over the order label and the other rules.
        ("card / order #4111111111111111", "card / order #[card ending 1111]"),
        # A bare word is not a label: the number after it is still masked (fail safe).
        ("Invoice 5555555555554444", "Invoice [card ending 4444]"),
        ("reference 378282246310005", "reference [card ending 0005]"),
        # An IBAN does not swallow a card number written after it.
        ("AE07 0331 2345 6789 0123 456 4111 1111 1111 1111", "AE07 0331 2345 6789 0123 456 [card ending 1111]"),
        # A date before a card number does not hide it.
        ("2024-01-15 4111 1111 1111 1111", "2024-01-15 [card ending 1111]"),
        # A card number with its security code after it.
        ("4111 1111 1111 1111 123", "[card ending 1111] 123"),
    ],
)
def test_card_numbers_next_to_other_things_are_still_masked(text: str, masked: str) -> None:
    assert scrub_pan(text) == masked


def test_not_a_card_unless_the_network_and_length_fit() -> None:
    # Luhn-valid but no network has this prefix, or not at this length.
    for number in ("1234567812345670", luhn_complete("999988887777666"), luhn_complete("55555555555555"), luhn_complete("3782822463100")):
        assert pci_controls.luhn_valid(number)
        assert find_pans(number) == [], number
    # Mixed separators are not one card layout.
    assert find_pans("4111 1111-1111 1111") == []
    # Groups that are no card layout (8-8, 4-2-2-...).
    assert find_pans("41111111 11111111") == []


@pytest.mark.parametrize(
    "text",
    [
        "card " + " ".join("1" for _ in range(20_000)),  # labelled: every grouping is looked at, still linear
        "Order # " + " ".join("4111" for _ in range(20_000)),
        "AE07 " * 20_000,
        "2024-01-15 " * 20_000,
    ],
    ids=["labelled-single-digits", "labelled-order-groups", "many-iban-starts", "many-dates"],
)
def test_the_new_rules_stay_linear_on_hostile_input(text: str) -> None:
    started = time.perf_counter()
    scrub_pan(text)
    assert time.perf_counter() - started < 5.0


def test_the_rates_are_reported() -> None:
    found = rates()
    assert set(found) == {*FALSE_POSITIVE_CORPORA, "recall_well_formed", "recall_labelled"}
    assert found["recall_well_formed"] == 1.0 and found["recall_labelled"] == 1.0
    assert all(found[name] < MAX_FALSE_POSITIVES for name in FALSE_POSITIVE_CORPORA), json.dumps(found)
